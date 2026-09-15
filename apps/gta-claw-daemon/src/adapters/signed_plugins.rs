//! Signed plugin discovery, activation, tool publication, and skill dispatch.

use std::collections::BTreeMap;
use std::num::NonZeroUsize;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex, PoisonError, Weak};
use std::time::{Duration, Instant};

use claw_http_api::{
    PortError, PortErrorKind, PortFuture, ToolDefinition, ToolInvocation, ToolOutcome, ToolPort,
};
use claw_plugin_api::capability::{CapabilityGrant, CapabilitySet};
use claw_plugin_api::policy::OperatorPolicy;
use claw_plugin_api::registry::DeliveryClass;
use claw_plugin_api::trust::{Ed25519Verifier, IdentityBinding, TrustPolicy};
use claw_plugin_host::services::SystemDnsResolver;
use claw_plugin_host::{
    ActivationControl, ActivationOutcome, ControlledActivationOutcome, DiscardEvents, EmptyConfig,
    HostError, HostServices, InMemoryStore, LogRecord, LogSink, OsRandom, PinnedHttpTransport,
    PinnedHttpTransportConfig, PluginHost, PluginToolInvocation, SystemClock, ToolRegistration,
    ToolSink,
};
use claw_skills::{WasmHostError, WasmHostErrorKind, WasmSkillHost, WasmSkillInvocation};
use serde_json::{Value, json};
use tokio::sync::oneshot;
use tokio_util::sync::CancellationToken;
use tokio_util::task::TaskTracker;

use super::http_api::{Diagnostics, ModelToolCatalog};

const PLUGIN_POLICY_ENV: &str = "GTA_CLAW_PLUGIN_POLICY";
const PROVIDER_TOOL_NAME_BYTES: usize = 64;
const PLUGIN_INVOCATION_GRACE: Duration = Duration::from_secs(2);
const PLUGIN_ACTIVATION_DEADLINE: Duration = Duration::from_secs(30);
const PLUGIN_ACTIVATION_CANDIDATES: usize = 1024;

/// Stable ordered startup report exposed to operators.
#[derive(Clone, Debug, Default)]
pub struct PluginActivationSummary {
    outcomes: Vec<Value>,
    activated: usize,
    failed: usize,
}

impl PluginActivationSummary {
    /// Returns a machine-readable report preserving discovery order.
    #[must_use]
    pub fn as_json(&self) -> Value {
        json!({
            "activated": self.activated,
            "failed": self.failed,
            "outcomes": self.outcomes,
        })
    }

    /// Number of active plugins.
    #[must_use]
    pub const fn activated(&self) -> usize {
        self.activated
    }
}

#[derive(Clone)]
pub(super) struct PublishedTool {
    registration: ToolRegistration,
    input_schema: Value,
    validator: Arc<jsonschema::Validator>,
    revision: u64,
}

/// Tool sink shared by the plugin host, HTTP tools, MCP, and model declarations.
pub struct PluginToolSurface {
    registrations: Arc<Mutex<BTreeMap<String, PublishedTool>>>,
    audit: std::sync::OnceLock<Arc<super::http_api::DurableSecurityAudit>>,
    next_publication: AtomicU64,
    host: Mutex<Option<Weak<Mutex<PluginHost>>>>,
    diagnostics: Arc<Diagnostics>,
    accepting: Mutex<bool>,
    tasks: TaskTracker,
    spawned: AtomicU64,
    terminated: Arc<AtomicU64>,
    active: Arc<Mutex<BTreeMap<u64, claw_plugin_host::CancellationToken>>>,
}

impl PluginToolSurface {
    pub(super) fn new(diagnostics: Arc<Diagnostics>) -> Arc<Self> {
        Arc::new(Self {
            registrations: Arc::new(Mutex::new(BTreeMap::new())),
            audit: std::sync::OnceLock::new(),
            next_publication: AtomicU64::new(0),
            host: Mutex::new(None),
            diagnostics,
            accepting: Mutex::new(true),
            tasks: TaskTracker::new(),
            spawned: AtomicU64::new(0),
            terminated: Arc::new(AtomicU64::new(0)),
            active: Arc::new(Mutex::new(BTreeMap::new())),
        })
    }

    fn attach(&self, host: &Arc<Mutex<PluginHost>>) {
        *self.host.lock().unwrap_or_else(PoisonError::into_inner) = Some(Arc::downgrade(host));
        self.registrations
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .retain(|_, tool| {
                if let Some(revision) = self.allocate_revision() {
                    tool.revision = revision;
                    true
                } else {
                    false
                }
            });
    }

    fn allocate_revision(&self) -> Option<u64> {
        self.next_publication
            .fetch_update(Ordering::AcqRel, Ordering::Acquire, |current| {
                current.checked_add(1)
            })
            .ok()
            .map(|previous| previous + 1)
    }

    pub(super) fn attach_audit(
        &self,
        audit: Arc<super::http_api::DurableSecurityAudit>,
    ) -> Result<(), String> {
        self.audit
            .set(audit)
            .map_err(|_| "plugin effect audit is already attached".to_owned())
    }

    pub(super) fn validate_arguments(
        &self,
        name: &str,
        arguments: &Value,
    ) -> Result<claw_application::ports::tool::ToolBinding, PortError> {
        let tool = self.resolve(name)?;
        let encoded = serde_json::to_vec(arguments).map_err(|_| {
            PortError::new(
                PortErrorKind::InvalidRequest,
                "plugin arguments cannot be encoded",
            )
        })?;
        if encoded.len() > 16 * 1024
            || !arguments.is_object()
            || !tool.validator.is_valid(arguments)
        {
            return Err(PortError::new(
                PortErrorKind::InvalidRequest,
                "plugin arguments do not satisfy the bounded published schema",
            ));
        }
        claw_application::ports::tool::ToolBinding::new(name, tool.revision).map_err(|_| {
            PortError::new(
                PortErrorKind::Unavailable,
                "tool publication cannot be bound",
            )
        })
    }

    fn public_name(plugin_id: &str, tool: &str) -> String {
        let mut prefix = format!("{plugin_id}_{tool}")
            .bytes()
            .filter(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-'))
            .map(char::from)
            .collect::<String>();
        let hash = Self::stable_hash(plugin_id, tool);
        let suffix = format!("_{hash:016x}");
        prefix.truncate(PROVIDER_TOOL_NAME_BYTES.saturating_sub(suffix.len()));
        if prefix.is_empty() {
            prefix.push_str("plugin_tool");
        }
        prefix.push_str(&suffix);
        prefix
    }

    fn stable_hash(plugin_id: &str, tool: &str) -> u64 {
        let mut hash = 0xcbf2_9ce4_8422_2325_u64;
        for byte in plugin_id
            .bytes()
            .chain(std::iter::once(0))
            .chain(tool.bytes())
        {
            hash ^= u64::from(byte);
            hash = hash.wrapping_mul(0x0000_0100_0000_01b3);
        }
        hash
    }

    pub(super) fn resolve(&self, name: &str) -> Result<PublishedTool, PortError> {
        self.registrations
            .lock()
            .map_err(|_| {
                PortError::new(PortErrorKind::Internal, "plugin tool catalog unavailable")
            })?
            .get(name)
            .cloned()
            .ok_or_else(|| PortError::new(PortErrorKind::NotFound, "plugin tool is not registered"))
    }

    pub(super) fn skill_target(&self, plugin_id: &str, export: &str) -> Result<String, PortError> {
        let name = Self::public_name(plugin_id, export);
        let published = self.resolve(&name)?;
        if published.registration.plugin_id != plugin_id || published.registration.name != export {
            return Err(PortError::new(
                PortErrorKind::InvalidRequest,
                "skill plugin target identity conflicts",
            ));
        }
        self.host()?;
        Ok(name)
    }

    fn host(&self) -> Result<Arc<Mutex<PluginHost>>, PortError> {
        self.host
            .lock()
            .map_err(|_| PortError::new(PortErrorKind::Internal, "plugin host link unavailable"))?
            .as_ref()
            .and_then(Weak::upgrade)
            .ok_or_else(|| PortError::new(PortErrorKind::Unavailable, "plugin host is unavailable"))
    }

    async fn shutdown_tasks(&self, budget: Duration) -> PluginInvocationReport {
        {
            let mut accepting = self
                .accepting
                .lock()
                .unwrap_or_else(PoisonError::into_inner);
            *accepting = false;
            drop(accepting);
            self.tasks.close();
        }
        let started = Instant::now();
        let grace = std::cmp::min(budget / 2, PLUGIN_INVOCATION_GRACE);
        let drained = tokio::time::timeout(grace, self.tasks.wait()).await.is_ok();
        let cancelled = if drained {
            0
        } else {
            let active = self.active.lock().unwrap_or_else(PoisonError::into_inner);
            for token in active.values() {
                token.cancel();
            }
            u64::try_from(active.len()).unwrap_or(u64::MAX)
        };
        let abandoned = !drained
            && tokio::time::timeout(budget.saturating_sub(started.elapsed()), self.tasks.wait())
                .await
                .is_err();
        PluginInvocationReport {
            spawned: self.spawned.load(Ordering::SeqCst),
            terminated: self.terminated.load(Ordering::SeqCst),
            cancelled,
            abandoned,
        }
    }
}

struct PluginInvocationGuard {
    id: u64,
    terminated: Arc<AtomicU64>,
    active: Arc<Mutex<BTreeMap<u64, claw_plugin_host::CancellationToken>>>,
}

impl Drop for PluginInvocationGuard {
    fn drop(&mut self) {
        self.active
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .remove(&self.id);
        self.terminated.fetch_add(1, Ordering::SeqCst);
    }
}

impl ToolSink for PluginToolSurface {
    fn register(&self, registration: ToolRegistration) {
        let public_name = Self::public_name(&registration.plugin_id, &registration.name);
        if registration.input_schema.len() > 32 * 1024 {
            self.unregister(&registration.plugin_id, &registration.name);
            self.diagnostics
                .record("plugin tool schema exceeds its byte limit");
            return;
        }
        match serde_json::from_str::<Value>(&registration.input_schema) {
            Ok(input_schema) if input_schema.is_object() => {
                let Ok(validator) = jsonschema::options()
                    .offline()
                    .with_pattern_options(
                        jsonschema::PatternOptions::regex()
                            .size_limit(256 * 1024)
                            .dfa_size_limit(512 * 1024),
                    )
                    .build(&input_schema)
                else {
                    self.unregister(&registration.plugin_id, &registration.name);
                    self.diagnostics.record("plugin tool schema is invalid or requires unsupported external resources or patterns");
                    return;
                };
                let Some(revision) = self.allocate_revision() else {
                    self.diagnostics
                        .record("plugin publication identity exhausted");
                    return;
                };
                self.registrations
                    .lock()
                    .unwrap_or_else(PoisonError::into_inner)
                    .insert(
                        public_name.clone(),
                        PublishedTool {
                            registration,
                            input_schema,
                            validator: Arc::new(validator),
                            revision,
                        },
                    );
                self.diagnostics
                    .record(format!("plugin tool registered: {public_name}"));
            }
            _ => {
                self.unregister(&registration.plugin_id, &registration.name);
                self.diagnostics
                    .record(format!("plugin tool schema rejected: {public_name}"));
            }
        }
    }

    fn unregister(&self, plugin_id: &str, name: &str) -> bool {
        self.registrations
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .remove(&Self::public_name(plugin_id, name))
            .is_some()
    }
}

impl ModelToolCatalog for PluginToolSurface {
    fn definitions(&self) -> Vec<ToolDefinition> {
        self.registrations
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .iter()
            .map(|(name, tool)| ToolDefinition {
                name: name.clone(),
                description: Some(tool.registration.summary.clone()),
                input_schema: tool.input_schema.clone(),
            })
            .collect()
    }
}

struct PluginCancelGuard(Option<claw_plugin_host::CancellationToken>);

impl PluginCancelGuard {
    fn disarm(&mut self) {
        self.0 = None;
    }
}

impl Drop for PluginCancelGuard {
    fn drop(&mut self) {
        if let Some(token) = self.0.take() {
            token.cancel();
        }
    }
}

impl ToolPort for PluginToolSurface {
    fn list(&self) -> PortFuture<'_, Result<Vec<ToolDefinition>, PortError>> {
        Box::pin(async move { Ok(self.definitions()) })
    }

    fn invoke(
        &self,
        mut invocation: ToolInvocation,
        cancellation: CancellationToken,
    ) -> PortFuture<'_, Result<ToolOutcome, PortError>> {
        Box::pin(async move {
            if cancellation.is_cancelled() {
                return Err(PortError::new(
                    PortErrorKind::Unavailable,
                    "plugin invocation was cancelled before execution",
                ));
            }
            let authority = invocation
                .context
                .authority
                .as_ref()
                .filter(|authority| authority.can_execute())
                .ok_or_else(|| {
                    PortError::new(
                        PortErrorKind::InvalidRequest,
                        "plugin invocation requires verified execution authority",
                    )
                })?;
            let binding = invocation.context.binding.as_ref().ok_or_else(|| {
                PortError::new(
                    PortErrorKind::InvalidRequest,
                    "plugin invocation requires an approved publication",
                )
            })?;
            if binding.identity() != invocation.name {
                return Err(PortError::new(
                    PortErrorKind::InvalidRequest,
                    "tool publication identity changed",
                ));
            }
            let (result_rx, plugin_cancel, mut cancel_guard) = {
                let accepting = self.accepting.lock().map_err(|_| {
                    PortError::new(
                        PortErrorKind::Internal,
                        "plugin invocation gate unavailable",
                    )
                })?;
                if !*accepting {
                    return Err(PortError::new(
                        PortErrorKind::Unavailable,
                        "plugin tools are shutting down",
                    ));
                }
                let tool = self.resolve(&invocation.name)?;
                if tool.revision != binding.revision() {
                    return Err(PortError::new(
                        PortErrorKind::InvalidRequest,
                        "tool publication changed after approval",
                    ));
                }
                if self.validate_arguments(&invocation.name, &invocation.arguments)? != *binding {
                    return Err(PortError::new(
                        PortErrorKind::InvalidRequest,
                        "tool publication changed during argument validation",
                    ));
                }
                if invocation.context.dry_run {
                    return Ok(ToolOutcome {
                        status: 200,
                        ok: true,
                        result: Some(json!({"wouldInvoke":invocation.name})),
                        error_type: None,
                        error_message: None,
                        requires_approval: None,
                    });
                }
                let host = self.host()?;
                let audit = self.audit.get().cloned().ok_or_else(|| {
                    PortError::new(
                        PortErrorKind::Unavailable,
                        "plugin effect audit is not attached",
                    )
                })?;
                let expected_binding = binding.clone();
                let execution_authority = authority.clone();
                let execution_cancellation = cancellation.clone();
                let registrations = Arc::clone(&self.registrations);
                tracing::debug!(tool = invocation.name, caller_source = ?authority.source(), permission_generation = authority.generation(), publication = binding.revision(), "authorized plugin invocation");
                let plugin_cancel = claw_plugin_host::CancellationToken::new();
                let cancel_guard = PluginCancelGuard(Some(plugin_cancel.clone()));
                let task_cancel = plugin_cancel.clone();
                let plugin_id = tool.registration.plugin_id;
                let tool_name = tool.registration.name;
                let parameters = std::mem::take(&mut invocation.arguments);
                let (result_tx, result_rx) = oneshot::channel();
                let id = self.spawned.fetch_add(1, Ordering::SeqCst);
                let terminated = Arc::clone(&self.terminated);
                let active = Arc::clone(&self.active);
                active
                    .lock()
                    .unwrap_or_else(PoisonError::into_inner)
                    .insert(id, plugin_cancel.clone());
                self.tasks.spawn(async move {
                    let _guard = PluginInvocationGuard {
                        id,
                        terminated,
                        active,
                    };
                    let result = tokio::task::spawn_blocking(move || {
                        let mut host = host.lock().unwrap_or_else(PoisonError::into_inner);
                        let unchanged = registrations.lock().map_err(|_| PortError::new(PortErrorKind::Unavailable, "tool catalog unavailable"))?
                            .get(expected_binding.identity()).is_some_and(|current| current.revision == expected_binding.revision());
                        if !unchanged { return Err(PortError::new(PortErrorKind::InvalidRequest, "tool publication changed before host execution")); }
                        if execution_cancellation.is_cancelled() || task_cancel.is_cancelled() || !execution_authority.can_execute() {
                            return Err(PortError::new(PortErrorKind::InvalidRequest, "plugin authority was withdrawn before execution"));
                        }
                        audit.persist_plugin_tool(&invocation, claw_application::ports::tool::InternalToolAuditPhase::Authorized)?;
                        if execution_cancellation.is_cancelled() || task_cancel.is_cancelled() || !execution_authority.can_execute() {
                            audit.persist_plugin_tool(&invocation, claw_application::ports::tool::InternalToolAuditPhase::Failed)?;
                            return Err(PortError::new(PortErrorKind::InvalidRequest, "plugin authority was withdrawn before effects"));
                        }
                        let result = host.invoke_json_tool(PluginToolInvocation {
                            plugin_id: &plugin_id,
                            tool: &tool_name,
                            parameters: &parameters,
                            cancellation: Some(&task_cancel),
                        });
                        drop(host);
                        let phase = if result.is_ok() { claw_application::ports::tool::InternalToolAuditPhase::Completed } else { claw_application::ports::tool::InternalToolAuditPhase::Failed };
                        audit.persist_plugin_tool(&invocation, phase).map_err(|_| PortError::new(PortErrorKind::OutcomeUnknown, "Plugin completion audit is unconfirmed; reconcile effects before retrying."))?;
                        result.map_err(|_| PortError::new(PortErrorKind::OutcomeUnknown, "Plugin execution failed after authorization and may have produced effects; do not repeat it automatically."))
                    })
                    .await
                    .map_err(|_| PortError::new(PortErrorKind::OutcomeUnknown, "plugin tool task did not confirm its result"))
                    .and_then(std::convert::identity);
                    let _ = result_tx.send(result);
                });
                drop(accepting);
                (result_rx, plugin_cancel, cancel_guard)
            };
            let result = tokio::select! {
                result = result_rx => result.map_err(|_| {
                    PortError::new(PortErrorKind::OutcomeUnknown, "plugin tool result disappeared; do not repeat automatically")
                })??,
                () = cancellation.cancelled() => {
                    plugin_cancel.cancel();
                    return Err(PortError::new(PortErrorKind::OutcomeUnknown, "Plugin call was interrupted; reconcile effects before retrying."));
                }
            };
            cancel_guard.disarm();
            Ok(ToolOutcome {
                status: 200,
                ok: true,
                result: Some(result),
                error_type: None,
                error_message: None,
                requires_approval: None,
            })
        })
    }
}

/// `claw-skills` Wasm bridge over the signed plugin host.
pub struct PluginWasmSkillHost {
    host: Arc<Mutex<PluginHost>>,
}

impl PluginWasmSkillHost {
    /// Creates a skill bridge over the shared host.
    #[must_use]
    pub const fn new(host: Arc<Mutex<PluginHost>>) -> Self {
        Self { host }
    }
}

impl WasmSkillHost for PluginWasmSkillHost {
    fn invoke(&mut self, invocation: WasmSkillInvocation<'_>) -> Result<Value, WasmHostError> {
        let cancellation = invocation.cancellation.map(|token| {
            claw_plugin_host::CancellationToken::from_shared_flag(token.shared_flag())
        });
        self.host
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .invoke_json_tool(PluginToolInvocation {
                plugin_id: invocation.plugin_id,
                tool: invocation.tool,
                parameters: &invocation.parameters,
                cancellation: cancellation.as_ref(),
            })
            .map_err(|error| host_wasm_error(&error))
    }
}

struct PluginLogs(Arc<Diagnostics>);

impl LogSink for PluginLogs {
    fn record(&self, record: LogRecord) {
        self.0.record(format!(
            "plugin log [{} {:?}]: {}",
            record.plugin_id, record.level, record.message
        ));
        tracing::info!(
            plugin_id = record.plugin_id,
            plugin_level = ?record.level,
            message = record.message,
            "plugin log"
        );
    }
}

/// Signed plugin runtime owned by one daemon run.
pub struct SignedPluginRuntime {
    host: Option<Arc<Mutex<PluginHost>>>,
    tools: Arc<PluginToolSurface>,
    summary: PluginActivationSummary,
    shutdown: AtomicBool,
}

impl SignedPluginRuntime {
    /// Builds the closed host, applies explicit policy, and activates discovery.
    ///
    /// # Errors
    ///
    /// Returns a safe configuration diagnostic when the policy environment is
    /// malformed or the Wasmtime host cannot be built.
    pub fn activate(
        diagnostics: &Arc<Diagnostics>,
        cancellation: claw_plugin_host::CancellationToken,
    ) -> Result<Self, String> {
        let (trust, verifier, operator) = plugin_policy_from_environment()?;
        let tools = PluginToolSurface::new(Arc::clone(diagnostics));
        let http = PinnedHttpTransport::new(PinnedHttpTransportConfig::new())
            .map_err(|error| error.to_string())?;
        let services = HostServices::deny_all()
            .with_logs(Arc::new(PluginLogs(Arc::clone(diagnostics))))
            .with_config(Arc::new(EmptyConfig))
            .with_store(Arc::new(InMemoryStore::new()))
            .with_http(Arc::new(http))
            .with_dns(Arc::new(SystemDnsResolver))
            .with_clock(Arc::new(SystemClock))
            .with_random(Arc::new(OsRandom))
            .with_tools(Arc::clone(&tools) as Arc<dyn ToolSink>)
            .with_events(Arc::new(DiscardEvents));
        diagnostics
            .record("plugin HTTP and DNS use pinned transport and bounded system resolution");
        let host = PluginHost::builder()
            .trust_policy(trust)
            .operator_policy(operator)
            .verifier(Arc::new(verifier))
            .services(services)
            .build()
            .map_err(|error| error.to_string())?;
        let host = Arc::new(Mutex::new(host));
        tools.attach(&host);
        let candidate_limit = NonZeroUsize::new(PLUGIN_ACTIVATION_CANDIDATES)
            .ok_or_else(|| "plugin activation candidate limit must be non-zero".to_owned())?;
        let control = ActivationControl::new(
            candidate_limit,
            Instant::now() + PLUGIN_ACTIVATION_DEADLINE,
            cancellation,
        )
        .map_err(|error| error.to_string())?;
        let report = host
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .activate_discovered_with_control(&control);
        let summary = activation_summary(&report, diagnostics);
        if let Some(terminal) = report.terminal() {
            let reason = controlled_terminal_label(terminal);
            let _ = host
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .shutdown();
            return Err(format!(
                "plugin activation stopped before completion: {reason}"
            ));
        }
        Ok(Self {
            host: Some(host),
            tools,
            summary,
            shutdown: AtomicBool::new(false),
        })
    }

    /// Model/HTTP tool surface fed by plugin registrations.
    #[must_use]
    pub fn tools(&self) -> Arc<PluginToolSurface> {
        Arc::clone(&self.tools)
    }

    /// Ordered activation summary.
    #[must_use]
    pub const fn summary(&self) -> &PluginActivationSummary {
        &self.summary
    }

    /// Creates a `claw-skills` Wasm adapter.
    ///
    /// Returns [`None`] after the host was abandoned during a bounded shutdown.
    #[must_use]
    pub fn wasm_skills(&self) -> Option<PluginWasmSkillHost> {
        self.host
            .as_ref()
            .map(|host| PluginWasmSkillHost::new(Arc::clone(host)))
    }

    /// Refuses new tool calls and waits for every tracked invocation.
    pub async fn drain_invocations(&self, budget: Duration) -> PluginInvocationReport {
        self.tools.shutdown_tasks(budget).await
    }

    /// Deactivates every plugin in reverse activation order.
    #[must_use]
    pub fn shutdown_host(&self) -> PluginShutdownSummary {
        if self.shutdown.swap(true, Ordering::AcqRel) {
            return PluginShutdownSummary {
                attempted: 0,
                failed: 0,
            };
        }
        let Some(host) = self.host.as_ref() else {
            return PluginShutdownSummary {
                attempted: 0,
                failed: 0,
            };
        };
        let report = host
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .shutdown();
        PluginShutdownSummary {
            attempted: report.outcomes().len(),
            failed: report
                .outcomes()
                .iter()
                .filter(|outcome| outcome.result.is_err())
                .count(),
        }
    }

    /// Drops the host without running deactivation hooks.
    ///
    /// Used only after invocation drain has already exceeded its deadline, when
    /// synchronously waiting for the host mutex would violate process shutdown.
    pub fn abandon_host(&mut self) {
        self.shutdown.store(true, Ordering::Release);
        self.tools
            .registrations
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .clear();
        *self
            .tools
            .host
            .lock()
            .unwrap_or_else(PoisonError::into_inner) = None;
        self.host.take();
    }
}

impl Drop for SignedPluginRuntime {
    fn drop(&mut self) {
        let _ = self.shutdown_host();
    }
}

/// Plugin shutdown accounting.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PluginShutdownSummary {
    /// Plugins deactivated or forgotten.
    pub attempted: usize,
    /// Plugin deactivation failures.
    pub failed: usize,
}

/// Plugin tool-task accounting at shutdown.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PluginInvocationReport {
    /// Tool tasks accepted.
    pub spawned: u64,
    /// Tool tasks that reached termination.
    pub terminated: u64,
    /// Tool tasks cancelled after the graceful interval.
    pub cancelled: u64,
    /// Whether the invocation drain exceeded its deadline.
    pub abandoned: bool,
}

fn activation_summary(
    report: &claw_plugin_host::ControlledActivationReport,
    diagnostics: &Diagnostics,
) -> PluginActivationSummary {
    let outcomes = report
        .outcomes()
        .iter()
        .map(|outcome| match outcome {
            ControlledActivationOutcome::Candidate(outcome) => {
                activation_outcome_json(outcome, diagnostics)
            }
            ControlledActivationOutcome::Cancelled => {
                diagnostics.record("plugin activation cancelled");
                json!({"outcome":"cancelled"})
            }
            ControlledActivationOutcome::DeadlineExceeded => {
                diagnostics.record("plugin activation deadline exceeded");
                json!({"outcome":"deadline_exceeded"})
            }
            ControlledActivationOutcome::CandidateLimitReached { limit } => {
                diagnostics.record(format!(
                    "plugin activation candidate limit reached: {limit}"
                ));
                json!({"outcome":"candidate_limit_reached","limit":limit.get()})
            }
        })
        .collect();
    PluginActivationSummary {
        outcomes,
        activated: report.activated_count(),
        failed: report
            .outcomes()
            .iter()
            .filter(|outcome| {
                matches!(
                    outcome,
                    ControlledActivationOutcome::Candidate(candidate)
                        if matches!(candidate.as_ref(), ActivationOutcome::Failed(_))
                ) || outcome.is_terminal()
            })
            .count(),
    }
}

fn activation_outcome_json(outcome: &ActivationOutcome, diagnostics: &Diagnostics) -> Value {
    match outcome {
        ActivationOutcome::Activated(plugin) => {
            diagnostics.record(format!("plugin activated: {}", plugin.id));
            json!({
                "outcome":"activated",
                "id":plugin.id,
                "directory":plugin.directory,
                "componentSha256":plugin.component_sha256,
                "signingKeyId":plugin.signing_key_id,
            })
        }
        ActivationOutcome::Failed(failure) => {
            diagnostics.record(format!(
                "plugin activation failed at {:?}: {}",
                failure.stage, failure.error
            ));
            json!({
                "outcome":"failed",
                "path":failure.path,
                "pluginId":failure.plugin_id,
                "stage":format!("{:?}", failure.stage).to_ascii_lowercase(),
                "error":failure.error.to_string(),
                "cleanupError":failure.cleanup_error.as_ref().map(ToString::to_string),
            })
        }
    }
}

const fn controlled_terminal_label(outcome: &ControlledActivationOutcome) -> &'static str {
    match outcome {
        ControlledActivationOutcome::Cancelled => "cancelled",
        ControlledActivationOutcome::DeadlineExceeded => "deadline exceeded",
        ControlledActivationOutcome::CandidateLimitReached { .. } => "candidate limit reached",
        ControlledActivationOutcome::Candidate(_) => "candidate",
    }
}

fn plugin_policy_from_environment() -> Result<(TrustPolicy, Ed25519Verifier, OperatorPolicy), String>
{
    let source = std::env::var_os(PLUGIN_POLICY_ENV)
        .map(|source| {
            source
                .into_string()
                .map_err(|_| format!("{PLUGIN_POLICY_ENV} is not valid Unicode"))
        })
        .transpose()?;
    plugin_policy(source.as_deref())
}

fn plugin_policy(
    source: Option<&str>,
) -> Result<(TrustPolicy, Ed25519Verifier, OperatorPolicy), String> {
    let Some(source) = source else {
        return Ok((
            TrustPolicy::deny_all(),
            Ed25519Verifier::new(),
            OperatorPolicy::deny_all(),
        ));
    };
    let value = serde_json::from_str::<Value>(source)
        .map_err(|error| format!("{PLUGIN_POLICY_ENV} is invalid JSON: {error}"))?;
    let object = value
        .as_object()
        .ok_or_else(|| format!("{PLUGIN_POLICY_ENV} must be an object"))?;
    let mut trust = TrustPolicy::deny_all()
        .require_signature(true)
        .require_identity_binding(true);
    for root in string_array(object.get("roots"), "roots")? {
        trust = trust.with_root(PathBuf::from(root));
    }
    let mut verifier = Ed25519Verifier::new();
    let keys = object
        .get("keys")
        .and_then(Value::as_object)
        .ok_or_else(|| "plugin policy keys must be an object".to_owned())?;
    for (id, encoded) in keys {
        let encoded = encoded
            .as_str()
            .ok_or_else(|| format!("plugin key `{id}` must be hex text"))?;
        let key = decode_hex_key(encoded)?;
        trust = trust.with_trusted_key_id(id.clone());
        verifier = verifier.with_key(id.clone(), key);
    }
    let identities = object
        .get("identities")
        .and_then(Value::as_array)
        .ok_or_else(|| "plugin policy identities must be an array".to_owned())?;
    let mut operator = OperatorPolicy::deny_all();
    for identity in identities {
        let identity = identity
            .as_object()
            .ok_or_else(|| "plugin identity must be an object".to_owned())?;
        let id = required_text(identity.get("id"), "identity.id")?;
        let delivery = delivery_class(required_text(
            identity.get("deliveryClass"),
            "identity.deliveryClass",
        )?)?;
        let directory = PathBuf::from(required_text(
            identity.get("directory"),
            "identity.directory",
        )?);
        let mut binding = IdentityBinding::new(id, delivery, directory);
        for key_id in string_array(identity.get("keyIds"), "identity.keyIds")? {
            binding = binding.with_key_id(key_id);
        }
        trust = trust
            .allow_delivery_class(delivery)
            .with_identity_binding(binding);
        let grants = identity
            .get("capabilities")
            .cloned()
            .unwrap_or_else(|| Value::Array(Vec::new()));
        let grants = serde_json::from_value::<Vec<CapabilityGrant>>(grants)
            .map_err(|error| format!("identity `{id}` capabilities are invalid: {error}"))?;
        let ceiling = CapabilitySet::new(grants)
            .map_err(|error| format!("identity `{id}` capabilities are invalid: {error}"))?;
        operator = operator.allow(id, ceiling);
    }
    Ok((trust, verifier, operator))
}

fn required_text<'a>(value: Option<&'a Value>, field: &str) -> Result<&'a str, String> {
    value
        .and_then(Value::as_str)
        .filter(|value| !value.is_empty())
        .ok_or_else(|| format!("{field} must be non-empty text"))
}

fn string_array(value: Option<&Value>, field: &str) -> Result<Vec<String>, String> {
    value
        .and_then(Value::as_array)
        .ok_or_else(|| format!("{field} must be an array"))?
        .iter()
        .map(|value| {
            value
                .as_str()
                .map(str::to_owned)
                .ok_or_else(|| format!("{field} entries must be text"))
        })
        .collect()
}

fn delivery_class(value: &str) -> Result<DeliveryClass, String> {
    match value {
        "core" => Ok(DeliveryClass::Core),
        "official_external" => Ok(DeliveryClass::OfficialExternal),
        "source_only_qa" => Ok(DeliveryClass::SourceOnlyQa),
        _ => Err(format!("unknown plugin delivery class `{value}`")),
    }
}

fn decode_hex_key(encoded: &str) -> Result<[u8; 32], String> {
    if encoded.len() != 64 {
        return Err("Ed25519 public keys must be 64 hexadecimal characters".to_owned());
    }
    let mut key = [0_u8; 32];
    for (index, pair) in encoded.as_bytes().as_chunks::<2>().0.iter().enumerate() {
        let pair = std::str::from_utf8(pair).map_err(|_| "plugin key is not UTF-8".to_owned())?;
        key[index] =
            u8::from_str_radix(pair, 16).map_err(|_| "plugin key is not hexadecimal".to_owned())?;
    }
    Ok(key)
}

fn host_wasm_error(error: &HostError) -> WasmHostError {
    WasmHostError::new(host_error_kind(error), error.to_string())
}

fn host_error_kind(error: &HostError) -> WasmHostErrorKind {
    match error {
        HostError::UnknownPlugin(_) => WasmHostErrorKind::PluginNotFound,
        HostError::WrongState { .. } | HostError::Faulted { .. } => {
            WasmHostErrorKind::PluginUnavailable
        }
        HostError::Guest(failure) if failure.code == "not-found" => WasmHostErrorKind::ToolNotFound,
        HostError::Denied(_)
        | HostError::Trust(_)
        | HostError::Verification(_)
        | HostError::Guest(claw_plugin_host::GuestFailure {
            code: "permission-denied",
            ..
        }) => WasmHostErrorKind::PolicyDenied,
        HostError::PayloadTooLarge { .. } => WasmHostErrorKind::PayloadTooLarge,
        HostError::Cancelled { .. } => WasmHostErrorKind::Cancelled,
        HostError::Terminated { cause, .. } => match cause {
            claw_plugin_host::TerminationCause::Cancelled => WasmHostErrorKind::Cancelled,
            claw_plugin_host::TerminationCause::Timeout => WasmHostErrorKind::Timeout,
            claw_plugin_host::TerminationCause::FuelExhausted
            | claw_plugin_host::TerminationCause::ResourceLimit => {
                WasmHostErrorKind::ResourceExhausted
            }
            claw_plugin_host::TerminationCause::StackOverflow
            | claw_plugin_host::TerminationCause::Trap => WasmHostErrorKind::Trap,
        },
        HostError::InvalidGuestResponse { .. } => WasmHostErrorKind::InvalidResponse,
        HostError::Guest(_) => WasmHostErrorKind::Trap,
        _ => WasmHostErrorKind::Internal,
    }
}

#[cfg(test)]
mod tests {
    use super::{
        PluginInvocationGuard, PluginToolSurface, PluginWasmSkillHost, delivery_class,
        host_error_kind, plugin_policy,
    };
    use claw_http_api::{ToolInvocation, ToolInvocationContext, ToolPort};
    use claw_plugin_host::{HostError, PluginHost, ToolRegistration, ToolSink};
    use claw_skills::{WasmHostErrorKind, WasmSkillHost, WasmSkillInvocation};
    use serde_json::json;
    use std::sync::atomic::Ordering;
    use std::sync::{Arc, Mutex};
    use std::time::Duration;
    use tokio_util::sync::CancellationToken;

    #[test]
    fn closed_policy_and_error_categories_are_stable() {
        assert_eq!(
            delivery_class("official_external").expect("delivery class"),
            claw_plugin_api::registry::DeliveryClass::OfficialExternal
        );
        assert_eq!(
            host_error_kind(&HostError::UnknownPlugin("missing".to_owned())),
            WasmHostErrorKind::PluginNotFound
        );
        let (_trust, _verifier, operator) = plugin_policy(None).expect("closed default policy");
        assert_eq!(operator.plugin_ids().count(), 0);
    }

    #[test]
    fn explicit_policy_constructs_trust_identity_verifier_and_operator_ceiling() {
        let source = serde_json::json!({
            "roots":["/opt/gta-claw/plugins"],
            "keys":{"release":"0000000000000000000000000000000000000000000000000000000000000000"},
            "identities":[{
                "id":"example-plugin",
                "deliveryClass":"core",
                "directory":"/opt/gta-claw/plugins/example",
                "keyIds":["release"],
                "capabilities":[],
            }],
        })
        .to_string();

        let (trust, _verifier, operator) = plugin_policy(Some(&source)).expect("policy parses");

        assert_eq!(trust.roots().len(), 1);
        let binding = trust
            .identity_binding("example-plugin")
            .expect("identity binding");
        assert_eq!(binding.key_ids().collect::<Vec<_>>(), vec!["release"]);
        assert_eq!(
            operator.plugin_ids().collect::<Vec<_>>(),
            vec!["example-plugin"]
        );
    }

    #[test]
    fn wasm_skill_bridge_maps_missing_plugins() {
        let host = PluginHost::builder().build().expect("closed host");
        let mut bridge = PluginWasmSkillHost::new(std::sync::Arc::new(std::sync::Mutex::new(host)));
        let error = bridge
            .invoke(WasmSkillInvocation {
                plugin_id: "missing",
                tool: "run",
                parameters: serde_json::json!({}),
                cancellation: None,
            })
            .expect_err("missing plugin");
        assert_eq!(error.kind(), WasmHostErrorKind::PluginNotFound);
    }

    #[test]
    fn plugin_schema_validation_is_offline_bounded_and_precedes_execution() {
        let tools =
            PluginToolSurface::new(Arc::new(crate::adapters::http_api::Diagnostics::new(8)));
        let registration = |schema: serde_json::Value| ToolRegistration {
            plugin_id: "schema-fixture".to_owned(),
            name: "lookup".to_owned(),
            summary: "Schema fixture".to_owned(),
            input_schema: schema.to_string(),
        };
        let valid = json!({"type": "object", "properties": {"path": {"type": "string", "minLength": 1}}, "required": ["path"], "additionalProperties": false});
        tools.register(registration(valid.clone()));
        let name = crate::adapters::http_api::ModelToolCatalog::definitions(&*tools)[0]
            .name
            .clone();
        assert!(
            tools
                .validate_arguments(&name, &json!({"path": "reviewed.txt"}))
                .is_ok()
        );
        for arguments in [
            json!({}),
            json!({"path": 7}),
            json!({"path": ""}),
            json!({"path": "safe", "owner": true}),
            json!({"path": "private-schema-input".repeat(1024)}),
        ] {
            let error = tools
                .validate_arguments(&name, &arguments)
                .expect_err("invalid arguments");
            assert_eq!(error.kind, claw_http_api::PortErrorKind::InvalidRequest);
            assert!(!error.message.contains("private-schema-input"));
        }
        for schema in [
            json!({"$ref": "https://example.test/private-schema"}),
            json!({"$ref": "file:///C:/private-schema"}),
            json!({"type": "not-a-type"}),
            json!({"type": "string", "pattern": "(?<=secret)value"}),
            json!({"type": "string", "pattern": "a{1000000}"}),
        ] {
            tools.register(registration(schema));
            assert!(
                crate::adapters::http_api::ModelToolCatalog::definitions(&*tools).is_empty(),
                "unsupported replacement withdraws old publication"
            );
            tools.register(registration(valid.clone()));
        }
        assert_eq!(tools.spawned.load(Ordering::SeqCst), 0);
    }

    #[test]
    fn tool_sink_publishes_and_withdraws_model_catalog_entries() {
        let tools = PluginToolSurface::new(std::sync::Arc::new(
            crate::adapters::http_api::Diagnostics::new(8),
        ));
        tools.register(ToolRegistration {
            plugin_id: "example".to_owned(),
            name: "lookup".to_owned(),
            summary: "Looks something up".to_owned(),
            input_schema: r#"{"type":"object","properties":{}}"#.to_owned(),
        });

        let definitions = crate::adapters::http_api::ModelToolCatalog::definitions(&*tools);
        assert_eq!(definitions.len(), 1);
        assert!(definitions[0].name.starts_with("example_lookup_"));
        assert!(definitions[0].name.len() <= 64);
        assert!(
            definitions[0]
                .name
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-'))
        );
        assert!(tools.unregister("example", "lookup"));
        assert!(crate::adapters::http_api::ModelToolCatalog::definitions(&*tools).is_empty());
    }

    #[tokio::test]
    async fn plugin_tool_tasks_are_accounted_and_refused_after_drain() {
        let tools =
            PluginToolSurface::new(Arc::new(crate::adapters::http_api::Diagnostics::new(8)));
        let host = Arc::new(Mutex::new(
            PluginHost::builder().build().expect("closed host"),
        ));
        tools.attach(&host);
        tools.register(ToolRegistration {
            plugin_id: "missing".to_owned(),
            name: "lookup".to_owned(),
            summary: "Looks something up".to_owned(),
            input_schema: r#"{"type":"object","properties":{}}"#.to_owned(),
        });
        let name = crate::adapters::http_api::ModelToolCatalog::definitions(&*tools)
            .pop()
            .expect("registered tool")
            .name;
        let binding = tools
            .validate_arguments(&name, &json!({}))
            .expect("test publication");
        let invocation = ToolInvocation {
            name,
            arguments: json!({}),
            action: None,
            context: ToolInvocationContext {
                authority: Some(
                    claw_application::ports::tool::InvocationAuthority::new(
                        claw_application::ports::tool::InvocationSource::Http,
                        "test-owner",
                        None,
                        claw_application::ports::tool::InvocationAccess::Owner,
                        0,
                    )
                    .expect("test authority"),
                ),
                binding: Some(binding),
                session_key: None,
                agent_id: None,
                idempotency_key: None,
                message_channel: None,
                account_id: None,
                agent_to: None,
                agent_thread_id: None,
                sender_is_owner: true,
                dry_run: false,
            },
        };

        let error = ToolPort::invoke(&*tools, invocation.clone(), CancellationToken::new())
            .await
            .expect_err("effect audit is required before task admission");
        assert_eq!(error.kind, claw_http_api::PortErrorKind::Unavailable);
        assert!(error.message.contains("audit is not attached"));
        assert_eq!(tools.spawned.load(Ordering::SeqCst), 0);
        let audit_path = std::env::temp_dir().join(format!(
            "claw-plugin-effect-audit-{}-{}.jsonl",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .expect("clock")
                .as_nanos()
        ));
        tools
            .attach_audit(Arc::new(
                crate::adapters::http_api::DurableSecurityAudit::open(
                    &audit_path,
                    Arc::new(crate::adapters::http_api::DependencyReadiness::new([
                        "audit",
                    ])),
                )
                .expect("durable effect audit"),
            ))
            .expect("attach audit");
        let error = ToolPort::invoke(&*tools, invocation.clone(), CancellationToken::new())
            .await
            .expect_err("missing plugin");
        assert_eq!(error.kind, claw_http_api::PortErrorKind::OutcomeUnknown);
        let records = std::fs::read_to_string(&audit_path).expect("plugin effect audit");
        let records: Vec<serde_json::Value> = records
            .lines()
            .map(|line| serde_json::from_str(line).expect("audit JSON"))
            .collect();
        assert_eq!(records.len(), 2);
        assert_eq!(records[0]["action"], "plugin_tool");
        assert_eq!(records[0]["phase"], "authorized");
        assert_eq!(records[1]["phase"], "failed");
        assert_eq!(records[0]["subject"], "test-owner");
        let report = tools.shutdown_tasks(Duration::from_secs(1)).await;
        assert_eq!(report.spawned, 1);
        assert_eq!(report.terminated, 1);
        assert_eq!(report.cancelled, 0);
        assert!(!report.abandoned);

        let error = ToolPort::invoke(&*tools, invocation, CancellationToken::new())
            .await
            .expect_err("draining surface rejects calls");
        assert_eq!(error.kind, claw_http_api::PortErrorKind::Unavailable);
        drop(tools);
        std::fs::remove_file(audit_path).expect("remove owned test audit");
    }

    #[tokio::test]
    async fn plugin_drain_cancels_tasks_after_the_grace_interval() {
        let tools =
            PluginToolSurface::new(Arc::new(crate::adapters::http_api::Diagnostics::new(8)));
        let token = claw_plugin_host::CancellationToken::new();
        let id = tools.spawned.fetch_add(1, Ordering::SeqCst);
        tools
            .active
            .lock()
            .expect("active invocation lock")
            .insert(id, token.clone());
        let terminated = Arc::clone(&tools.terminated);
        let active = Arc::clone(&tools.active);
        tools.tasks.spawn(async move {
            let _guard = PluginInvocationGuard {
                id,
                terminated,
                active,
            };
            while !token.is_cancelled() {
                tokio::time::sleep(Duration::from_millis(1)).await;
            }
        });

        let report = tools.shutdown_tasks(Duration::from_millis(100)).await;
        assert_eq!(report.spawned, 1);
        assert_eq!(report.terminated, 1);
        assert_eq!(report.cancelled, 1);
        assert!(!report.abandoned);
    }
}

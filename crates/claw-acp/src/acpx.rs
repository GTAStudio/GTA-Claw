//! ACPX-compatible harness runtime.

use std::{
    collections::{BTreeMap, BTreeSet},
    fmt,
    path::PathBuf,
    sync::{
        Arc, Mutex,
        atomic::{AtomicU64, Ordering},
    },
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use crate::schema_v1::{
    ContentBlock, McpServer, McpServerHttp, McpServerSse, McpServerStdio, RequestPermissionOutcome,
    RequestPermissionRequest, RequestPermissionResponse, SelectedPermissionOutcome, SessionId,
    SessionModeId,
};
use claw_mcp::registry::{ServerConfig as McpServerConfig, ServerTransportConfig};

use crate::{
    debug_client::{
        DebugClient, DebugClientConfig, DebugRunRequest, DebugRunResult, PermissionFuture,
        PermissionPolicy,
    },
    error::{AcpInteropError, Result},
};

const LEASE_ENV: &str = "GTA_CLAW_ACPX_LEASE_ID";
const SESSION_ENV: &str = "GTA_CLAW_ACPX_SESSION_KEY";

/// Permission behavior applied to an ACPX harness.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
#[non_exhaustive]
pub enum HarnessPermissionMode {
    /// Cancel every permission request.
    #[default]
    Deny,
    /// Select the first option offered by the agent.
    ApproveFirst,
    /// Select the first option whose identifier is explicitly allowed.
    AllowOptions(BTreeSet<String>),
}

impl PermissionPolicy for HarnessPermissionMode {
    fn decide<'a>(&'a self, request: RequestPermissionRequest) -> PermissionFuture<'a> {
        Box::pin(async move {
            let selected = match self {
                Self::Deny => None,
                Self::ApproveFirst => request.options.first(),
                Self::AllowOptions(allowed) => request
                    .options
                    .iter()
                    .find(|option| allowed.contains(option.option_id.0.as_ref())),
            };
            Ok(RequestPermissionResponse::new(match selected {
                Some(option) => RequestPermissionOutcome::Selected(SelectedPermissionOutcome::new(
                    option.option_id.clone(),
                )),
                None => RequestPermissionOutcome::Cancelled,
            }))
        })
    }
}

/// Named ACP agent harness and its aliases.
#[derive(Clone)]
pub struct HarnessConfig {
    /// Canonical harness name.
    pub name: String,
    /// Additional case-insensitive aliases.
    pub aliases: Vec<String>,
    /// Child-process configuration.
    pub client: DebugClientConfig,
    /// Permission behavior for the child.
    pub permissions: HarnessPermissionMode,
    /// MCP bridges forwarded to every new or loaded session.
    pub mcp_servers: Vec<McpServer>,
}

impl fmt::Debug for HarnessConfig {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("HarnessConfig")
            .field("name", &self.name)
            .field("aliases", &self.aliases)
            .field("client", &self.client)
            .field("permissions", &self.permissions)
            .field("mcp_server_count", &self.mcp_servers.len())
            .finish()
    }
}

impl HarnessConfig {
    /// Creates a harness with deny-by-default permissions.
    #[must_use]
    pub fn new(name: impl Into<String>, client: DebugClientConfig) -> Self {
        Self {
            name: name.into(),
            aliases: Vec::new(),
            client,
            permissions: HarnessPermissionMode::Deny,
            mcp_servers: Vec::new(),
        }
    }

    fn validate(&self) -> Result<()> {
        normalize_name(&self.name)?;
        if self.client.command.as_os_str().is_empty() {
            return Err(AcpInteropError::Configuration(format!(
                "harness {} has an empty command",
                self.name
            )));
        }
        if self.client.timeout.is_zero() {
            return Err(AcpInteropError::Configuration(format!(
                "harness {} has a zero timeout",
                self.name
            )));
        }
        for alias in &self.aliases {
            normalize_name(alias)?;
        }
        Ok(())
    }
}

/// Session reuse behavior for an ACPX turn.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
#[non_exhaustive]
pub enum RuntimeSessionMode {
    /// Reuse the ACP session identifier on later turns.
    #[default]
    Persistent,
    /// Create and close a fresh session for this turn.
    OneShot,
}

/// Lifecycle state of one external-process lease.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum LeaseState {
    /// The child interaction is active.
    Open,
    /// The child interaction finished successfully.
    Closed,
    /// The child interaction failed or timed out.
    Failed,
}

/// Durable process lease associated with one ACPX turn.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProcessLease {
    /// Unique lease identifier.
    pub lease_id: String,
    /// Canonical harness name.
    pub harness: String,
    /// GTA-Claw session key.
    pub session_key: String,
    /// Lease start time.
    pub started_at: SystemTime,
    /// Lease completion time.
    pub ended_at: Option<SystemTime>,
    /// Current lifecycle state.
    pub state: LeaseState,
}

/// Persistence and exclusivity port for ACPX process leases.
pub trait ProcessLeaseStore: Send + Sync + 'static {
    /// Acquires a lease, rejecting another open lease for the same session.
    fn acquire(&self, lease: ProcessLease) -> Result<()>;
    /// Marks an open lease complete.
    fn finish(&self, lease_id: &str, state: LeaseState) -> Result<ProcessLease>;
    /// Lists all lease records.
    fn list(&self) -> Result<Vec<ProcessLease>>;
}

/// In-memory process lease store.
#[derive(Debug, Default)]
pub struct MemoryProcessLeaseStore {
    leases: Mutex<BTreeMap<String, ProcessLease>>,
}

impl ProcessLeaseStore for MemoryProcessLeaseStore {
    fn acquire(&self, lease: ProcessLease) -> Result<()> {
        let mut leases = self
            .leases
            .lock()
            .map_err(|_| AcpInteropError::Lifecycle("process lease lock poisoned".into()))?;
        if leases.values().any(|candidate| {
            candidate.session_key == lease.session_key && candidate.state == LeaseState::Open
        }) {
            return Err(AcpInteropError::Lifecycle(format!(
                "ACP session already has an open process lease: {}",
                lease.session_key
            )));
        }
        leases.insert(lease.lease_id.clone(), lease);
        Ok(())
    }

    fn finish(&self, lease_id: &str, state: LeaseState) -> Result<ProcessLease> {
        if state == LeaseState::Open {
            return Err(AcpInteropError::Lifecycle(
                "a completed lease cannot remain open".into(),
            ));
        }
        let mut leases = self
            .leases
            .lock()
            .map_err(|_| AcpInteropError::Lifecycle("process lease lock poisoned".into()))?;
        let lease = leases.get_mut(lease_id).ok_or_else(|| {
            AcpInteropError::Lifecycle(format!("process lease does not exist: {lease_id}"))
        })?;
        if lease.state != LeaseState::Open {
            return Err(AcpInteropError::Lifecycle(format!(
                "process lease is already complete: {lease_id}"
            )));
        }
        lease.state = state;
        lease.ended_at = Some(SystemTime::now());
        Ok(lease.clone())
    }

    fn list(&self) -> Result<Vec<ProcessLease>> {
        self.leases
            .lock()
            .map_err(|_| AcpInteropError::Lifecycle("process lease lock poisoned".into()))
            .map(|leases| leases.values().cloned().collect())
    }
}

/// Persistence port for ACP session identifiers.
pub trait AcpxSessionStore: Send + Sync + 'static {
    /// Loads the ACP session for a GTA-Claw session key.
    fn load(&self, session_key: &str) -> Result<Option<StoredSession>>;
    /// Saves the ACP session for later turns.
    fn save(&self, session_key: &str, session: StoredSession) -> Result<()>;
    /// Removes a persisted session.
    fn delete(&self, session_key: &str) -> Result<()>;
}

/// Persisted ACPX session identity.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct StoredSession {
    /// Canonical harness name used to create the session.
    pub harness: String,
    /// Agent-assigned ACP session identifier.
    pub session_id: SessionId,
}

/// In-memory ACPX session store.
#[derive(Debug, Default)]
pub struct MemoryAcpxSessionStore {
    sessions: Mutex<BTreeMap<String, StoredSession>>,
}

impl AcpxSessionStore for MemoryAcpxSessionStore {
    fn load(&self, session_key: &str) -> Result<Option<StoredSession>> {
        self.sessions
            .lock()
            .map_err(|_| AcpInteropError::Lifecycle("ACPX session lock poisoned".into()))
            .map(|sessions| sessions.get(session_key).cloned())
    }

    fn save(&self, session_key: &str, session: StoredSession) -> Result<()> {
        self.sessions
            .lock()
            .map_err(|_| AcpInteropError::Lifecycle("ACPX session lock poisoned".into()))?
            .insert(session_key.to_owned(), session);
        Ok(())
    }

    fn delete(&self, session_key: &str) -> Result<()> {
        self.sessions
            .lock()
            .map_err(|_| AcpInteropError::Lifecycle("ACPX session lock poisoned".into()))?
            .remove(session_key);
        Ok(())
    }
}

/// One ACPX prompt turn.
#[derive(Clone, Debug)]
pub struct AcpxTurn {
    /// Harness name or alias.
    pub harness: String,
    /// Stable GTA-Claw session key.
    pub session_key: String,
    /// Working directory.
    pub cwd: PathBuf,
    /// ACP prompt blocks.
    pub prompt: Vec<ContentBlock>,
    /// Optional ACP mode selected before the prompt.
    pub mode: Option<SessionModeId>,
    /// Persistent or one-shot session behavior.
    pub session_mode: RuntimeSessionMode,
    /// Optional client-driven cancellation delay.
    pub cancel_after: Option<Duration>,
    /// Additional MCP bridges for this turn.
    pub mcp_servers: Vec<McpServer>,
}

/// Successful result of one ACPX turn.
#[derive(Clone, Debug)]
pub struct AcpxTurnResult {
    /// Completed process lease.
    pub lease: ProcessLease,
    /// ACP debug lifecycle result.
    pub debug: DebugRunResult,
}

/// Doctor result for one configured harness.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct HarnessDoctorReport {
    /// Canonical harness name.
    pub harness: String,
    /// Whether static configuration is valid.
    pub healthy: bool,
    /// Diagnostic message.
    pub message: String,
}

/// Rust-native ACPX harness runtime.
pub struct AcpxRuntime {
    harnesses: BTreeMap<String, Arc<HarnessConfig>>,
    leases: Arc<dyn ProcessLeaseStore>,
    sessions: Arc<dyn AcpxSessionStore>,
    lease_counter: AtomicU64,
}

struct ActiveProcessLease {
    store: Arc<dyn ProcessLeaseStore>,
    lease_id: String,
    completed: bool,
}

impl ActiveProcessLease {
    fn new(store: Arc<dyn ProcessLeaseStore>, lease_id: String) -> Self {
        Self {
            store,
            lease_id,
            completed: false,
        }
    }

    fn finish(&mut self, state: LeaseState) -> Result<ProcessLease> {
        let lease = self.store.finish(&self.lease_id, state)?;
        self.completed = true;
        Ok(lease)
    }

    fn fail_with(&mut self, cause: AcpInteropError) -> AcpInteropError {
        match self.finish(LeaseState::Failed) {
            Ok(_) => cause,
            Err(cleanup) => AcpInteropError::Lifecycle(format!(
                "{cause}; additionally failed to mark process lease {} as failed: {cleanup}",
                self.lease_id
            )),
        }
    }
}

impl Drop for ActiveProcessLease {
    fn drop(&mut self) {
        if !self.completed {
            let _ = self.store.finish(&self.lease_id, LeaseState::Failed);
        }
    }
}

impl fmt::Debug for AcpxRuntime {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("AcpxRuntime")
            .field("aliases", &self.harnesses.keys().collect::<Vec<_>>())
            .finish_non_exhaustive()
    }
}

impl AcpxRuntime {
    /// Creates a runtime and rejects duplicate normalized aliases.
    pub fn new(
        configs: Vec<HarnessConfig>,
        leases: Arc<dyn ProcessLeaseStore>,
        sessions: Arc<dyn AcpxSessionStore>,
    ) -> Result<Self> {
        let mut harnesses = BTreeMap::new();
        for config in configs {
            config.validate()?;
            let config = Arc::new(config);
            let names = std::iter::once(&config.name).chain(config.aliases.iter());
            for name in names {
                let normalized = normalize_name(name)?;
                if harnesses
                    .insert(normalized.clone(), config.clone())
                    .is_some()
                {
                    return Err(AcpInteropError::Configuration(format!(
                        "duplicate ACP harness alias: {normalized}"
                    )));
                }
            }
        }
        Ok(Self {
            harnesses,
            leases,
            sessions,
            lease_counter: AtomicU64::new(1),
        })
    }

    /// Resolves an alias to its canonical harness configuration.
    pub fn resolve(&self, alias: &str) -> Result<Arc<HarnessConfig>> {
        let normalized = normalize_name(alias)?;
        self.harnesses
            .get(&normalized)
            .cloned()
            .ok_or_else(|| AcpInteropError::UnknownHarness(alias.to_owned()))
    }

    /// Runs one turn with lease acquisition and guaranteed lease completion.
    pub async fn run_turn(&self, turn: AcpxTurn) -> Result<AcpxTurnResult> {
        if turn.session_key.trim().is_empty() {
            return Err(AcpInteropError::Configuration(
                "ACPX session key must not be empty".into(),
            ));
        }
        let harness = self.resolve(&turn.harness)?;
        let lease = ProcessLease {
            lease_id: self.next_lease_id(),
            harness: harness.name.clone(),
            session_key: turn.session_key.clone(),
            started_at: SystemTime::now(),
            ended_at: None,
            state: LeaseState::Open,
        };
        self.leases.acquire(lease.clone())?;
        let mut active_lease = ActiveProcessLease::new(self.leases.clone(), lease.lease_id.clone());

        let mut client_config = harness.client.clone();
        client_config
            .environment
            .insert(LEASE_ENV.into(), lease.lease_id.clone());
        client_config
            .environment
            .insert(SESSION_ENV.into(), turn.session_key.clone());
        let client = DebugClient::new(client_config, Arc::new(harness.permissions.clone()));
        let stored = match turn.session_mode {
            RuntimeSessionMode::Persistent => self.sessions.load(&turn.session_key),
            RuntimeSessionMode::OneShot => Ok(None),
        };
        let stored = match stored {
            Ok(stored) => stored,
            Err(error) => {
                return Err(active_lease.fail_with(error));
            }
        };
        if let Some(stored) = stored.as_ref()
            && stored.harness != harness.name
        {
            let error = AcpInteropError::Lifecycle(format!(
                "session {} belongs to harness {}, not {} (lease {})",
                turn.session_key, stored.harness, harness.name, lease.lease_id
            ));
            return Err(active_lease.fail_with(error));
        }

        let mut request = DebugRunRequest::new(turn.cwd, turn.prompt);
        request.load_session = stored.map(|session| session.session_id);
        request.mode = turn.mode;
        request.cancel_after = turn.cancel_after;
        request.close_session = turn.session_mode == RuntimeSessionMode::OneShot;
        request.mcp_servers = harness
            .mcp_servers
            .iter()
            .chain(turn.mcp_servers.iter())
            .cloned()
            .collect();

        match client.run(request).await {
            Ok(debug) => {
                let persistence = if turn.session_mode == RuntimeSessionMode::Persistent {
                    self.sessions.save(
                        &turn.session_key,
                        StoredSession {
                            harness: harness.name.clone(),
                            session_id: debug.session_id.clone(),
                        },
                    )
                } else {
                    self.sessions.delete(&turn.session_key)
                };
                if let Err(error) = persistence {
                    return Err(active_lease.fail_with(error));
                }
                let lease = match active_lease.finish(LeaseState::Closed) {
                    Ok(lease) => lease,
                    Err(close_error) => {
                        return Err(match active_lease.finish(LeaseState::Failed) {
                            Ok(_) => AcpInteropError::Lifecycle(format!(
                                "failed to close ACPX lease `{}`; reconciled it as failed: {close_error}",
                                lease.lease_id
                            )),
                            Err(reconcile_error) => AcpInteropError::Lifecycle(format!(
                                "failed to close ACPX lease `{}`: {close_error}; also failed to reconcile it as failed: {reconcile_error}",
                                lease.lease_id
                            )),
                        });
                    }
                };
                Ok(AcpxTurnResult { lease, debug })
            }
            Err(error) => Err(active_lease.fail_with(error)),
        }
    }

    /// Clears persistent session state after ensuring no lease is open.
    pub fn reset_session(&self, session_key: &str) -> Result<()> {
        if self
            .leases
            .list()?
            .iter()
            .any(|lease| lease.session_key == session_key && lease.state == LeaseState::Open)
        {
            return Err(AcpInteropError::Lifecycle(format!(
                "cannot reset session with an open process lease: {session_key}"
            )));
        }
        self.sessions.delete(session_key)
    }

    /// Validates every configured canonical harness.
    pub fn doctor(&self) -> Vec<HarnessDoctorReport> {
        let mut seen = BTreeSet::new();
        let mut reports = Vec::new();
        for harness in self.harnesses.values() {
            if !seen.insert(harness.name.clone()) {
                continue;
            }
            reports.push(match harness.validate() {
                Ok(()) => HarnessDoctorReport {
                    harness: harness.name.clone(),
                    healthy: true,
                    message: "configuration is valid".into(),
                },
                Err(error) => HarnessDoctorReport {
                    harness: harness.name.clone(),
                    healthy: false,
                    message: error.to_string(),
                },
            });
        }
        reports
    }

    fn next_lease_id(&self) -> String {
        let sequence = self.lease_counter.fetch_add(1, Ordering::Relaxed);
        let epoch = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis();
        format!("acpx-{epoch}-{sequence}")
    }
}

/// Converts a configured `claw-mcp` server into the ACP session bridge shape.
pub fn mcp_bridge_from_registry(config: &McpServerConfig) -> Result<McpServer> {
    let server = match &config.transport {
        ServerTransportConfig::Stdio {
            command,
            arguments,
            environment,
        } => McpServer::Stdio(
            McpServerStdio::new(&config.name, command)
                .args(arguments.clone())
                .env(
                    environment
                        .iter()
                        .map(|(name, value)| crate::schema_v1::EnvVariable::new(name, value))
                        .collect(),
                ),
        ),
        ServerTransportConfig::Http { url } => {
            McpServer::Http(McpServerHttp::new(&config.name, url))
        }
        ServerTransportConfig::Sse { url } => McpServer::Sse(McpServerSse::new(&config.name, url)),
        _ => {
            return Err(AcpInteropError::Configuration(
                "unsupported MCP transport for ACP bridge".into(),
            ));
        }
    };
    Ok(server)
}

fn normalize_name(value: &str) -> Result<String> {
    let normalized = value.trim().to_ascii_lowercase();
    if normalized.is_empty() {
        return Err(AcpInteropError::Configuration(
            "ACP harness name or alias must not be empty".into(),
        ));
    }
    Ok(normalized)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::schema_v1::{
        PermissionOption, PermissionOptionId, PermissionOptionKind, ToolCall, ToolCallId,
    };

    fn harness() -> HarnessConfig {
        let mut harness = HarnessConfig::new("Codex", DebugClientConfig::new("fixture-agent"));
        harness.aliases = vec!["code".into()];
        harness
    }

    #[test]
    fn aliases_are_normalized_and_duplicates_fail() {
        let runtime = AcpxRuntime::new(
            vec![harness()],
            Arc::new(MemoryProcessLeaseStore::default()),
            Arc::new(MemoryAcpxSessionStore::default()),
        )
        .expect("runtime created");
        assert_eq!(
            runtime.resolve(" CODE ").expect("alias resolves").name,
            "Codex"
        );

        let mut duplicate = harness();
        duplicate.name = "code".into();
        let error = AcpxRuntime::new(
            vec![harness(), duplicate],
            Arc::new(MemoryProcessLeaseStore::default()),
            Arc::new(MemoryAcpxSessionStore::default()),
        )
        .expect_err("duplicate alias must fail");
        assert_eq!(
            error.to_string(),
            "ACP configuration is invalid: duplicate ACP harness alias: code"
        );
    }

    #[tokio::test]
    async fn permission_policy_is_fail_closed_and_allowlisted() {
        let tool_call = ToolCall::new(ToolCallId::new("call-1"), "write file");
        let request = RequestPermissionRequest::new(
            SessionId::new("session-1"),
            tool_call.into(),
            vec![
                PermissionOption::new(
                    PermissionOptionId::new("deny"),
                    "Deny",
                    PermissionOptionKind::RejectOnce,
                ),
                PermissionOption::new(
                    PermissionOptionId::new("allow"),
                    "Allow",
                    PermissionOptionKind::AllowOnce,
                ),
            ],
        );

        let denied = HarnessPermissionMode::Deny
            .decide(request.clone())
            .await
            .expect("decision succeeds");
        assert_eq!(denied.outcome, RequestPermissionOutcome::Cancelled);

        let allowed = HarnessPermissionMode::AllowOptions(BTreeSet::from(["allow".into()]))
            .decide(request)
            .await
            .expect("decision succeeds");
        assert_eq!(
            allowed.outcome,
            RequestPermissionOutcome::Selected(SelectedPermissionOutcome::new(
                PermissionOptionId::new("allow")
            ))
        );
    }

    #[test]
    fn process_leases_enforce_exclusivity_and_completion() {
        let store = MemoryProcessLeaseStore::default();
        let lease = ProcessLease {
            lease_id: "lease-1".into(),
            harness: "fixture".into(),
            session_key: "session-1".into(),
            started_at: UNIX_EPOCH,
            ended_at: None,
            state: LeaseState::Open,
        };
        store.acquire(lease.clone()).expect("lease acquired");
        let conflict = ProcessLease {
            lease_id: "lease-2".into(),
            ..lease
        };
        assert_eq!(
            store
                .acquire(conflict)
                .expect_err("open session lease must conflict")
                .to_string(),
            "ACP lifecycle conflict: ACP session already has an open process lease: session-1"
        );

        let finished = store
            .finish("lease-1", LeaseState::Closed)
            .expect("lease completed");
        assert_eq!(finished.state, LeaseState::Closed);
        assert!(finished.ended_at.is_some());
    }
}

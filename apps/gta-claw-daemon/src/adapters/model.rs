//! Provider, tool and context stand-ins.
//!
//! The registry is the piece that matters most for correctness. It resolves a
//! provider name to a [`ProviderBinding`] by passing the configured URL through
//! the [`EgressGuard`], so the binding carries the addresses that were actually
//! checked. Everything downstream connects to those addresses and never sees a
//! hostname it could look up again.

use std::collections::BTreeMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, RwLock};

use claw_application::composition::{
    AssembledContext, BoxFuture, Capability, CapabilitySet, ContextAssemblyPort, CredentialName,
    EgressGuard, Grant, ModelName, ProviderBinding, ProviderCall, ProviderName,
    ProviderRegistryPort, ProviderReply, ProviderTransportPort, ResolvedSession, SubsystemError,
    ToolBinding, ToolCall, ToolName, ToolOutcome, ToolRequest, ToolSurfacePort, well_known,
};

/// How a provider is configured before it has been resolved.
#[derive(Clone, Debug)]
pub struct ProviderConfig {
    name: ProviderName,
    url: String,
    credential: CredentialName,
    models: Vec<ModelName>,
}

impl ProviderConfig {
    /// Declares a provider reachable at `url`.
    #[must_use]
    pub fn new(
        name: ProviderName,
        url: impl Into<String>,
        credential: CredentialName,
        models: Vec<ModelName>,
    ) -> Self {
        Self {
            name,
            url: url.into(),
            credential,
            models,
        }
    }

    /// Returns the configured name.
    #[must_use]
    pub const fn name(&self) -> &ProviderName {
        &self.name
    }

    /// Returns the configured URL, which has not been checked yet.
    #[must_use]
    pub fn url(&self) -> &str {
        &self.url
    }
}

/// Resolves configured providers through the egress guard.
#[derive(Debug)]
pub struct GuardedProviderRegistry {
    configured: Vec<ProviderConfig>,
    guard: Arc<EgressGuard>,
    resolutions: AtomicU64,
}

impl GuardedProviderRegistry {
    /// Creates a registry over `configured`, checking every destination with
    /// `guard`.
    #[must_use]
    pub fn new(configured: Vec<ProviderConfig>, guard: Arc<EgressGuard>) -> Self {
        Self {
            configured,
            guard,
            resolutions: AtomicU64::new(0),
        }
    }

    /// Returns how many times a destination has been resolved.
    ///
    /// Resolution happens per turn rather than once at start-up, which is what
    /// keeps a binding from outliving the policy that allowed it.
    #[must_use]
    pub fn resolutions(&self) -> u64 {
        self.resolutions.load(Ordering::SeqCst)
    }

    async fn bind(&self, config: &ProviderConfig) -> Result<ProviderBinding, SubsystemError> {
        self.resolutions.fetch_add(1, Ordering::SeqCst);

        let origin = self
            .guard
            .resolve_url(&config.url)
            .await
            .map_err(|denial| SubsystemError::invalid(well_known::egress(), denial.to_string()))?;

        Ok(ProviderBinding::new(
            config.name.clone(),
            origin,
            config.credential.clone(),
            config.models.clone(),
        ))
    }
}

impl ProviderRegistryPort for GuardedProviderRegistry {
    fn bindings(&self) -> BoxFuture<'_, Result<Vec<ProviderBinding>, SubsystemError>> {
        Box::pin(async move {
            let mut bindings = Vec::with_capacity(self.configured.len());

            for config in &self.configured {
                bindings.push(self.bind(config).await?);
            }

            Ok(bindings)
        })
    }

    fn resolve(
        &self,
        provider: &ProviderName,
        model: &ModelName,
    ) -> BoxFuture<'_, Result<ProviderBinding, SubsystemError>> {
        let provider = provider.clone();
        let model = model.clone();

        Box::pin(async move {
            let config = self
                .configured
                .iter()
                .find(|candidate| candidate.name == provider)
                .ok_or_else(|| {
                    SubsystemError::not_found(
                        well_known::providers(),
                        format!("no provider named {provider}"),
                    )
                })?;

            if !config.models.contains(&model) {
                return Err(SubsystemError::not_found(
                    well_known::providers(),
                    format!("{provider} does not offer {model}"),
                ));
            }

            self.bind(config).await
        })
    }
}

/// What one provider call did.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RecordedCall {
    /// The authority the call was sent to, taken from the resolved endpoint.
    pub authority: String,
    /// The addresses the transport would have connected to.
    pub addresses: Vec<std::net::IpAddr>,
    /// The prompt that was sent.
    pub prompt: String,
    /// The credential material that was presented.
    pub secret: String,
    /// How many context items were attached.
    pub context_items: usize,
}

/// A transport that answers from a script and records what it was asked to do.
///
/// It connects to nothing, but it records the endpoint's addresses rather than
/// its hostname, which is what a real transport must use.
#[derive(Debug, Default)]
pub struct ScriptedTransport {
    replies: Mutex<Vec<ProviderReply>>,
    calls: Mutex<Vec<RecordedCall>>,
}

impl ScriptedTransport {
    /// Creates a transport that echoes the prompt back.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Queues a reply, used before the echo fallback and in order.
    pub fn push_reply(&self, reply: ProviderReply) {
        self.replies.lock().expect("uncontended").push(reply);
    }

    /// Returns everything the transport was asked to send.
    #[must_use]
    pub fn calls(&self) -> Vec<RecordedCall> {
        self.calls.lock().expect("uncontended").clone()
    }
}

impl ProviderTransportPort for ScriptedTransport {
    fn send(
        &self,
        call: Grant<ProviderCall>,
    ) -> BoxFuture<'_, Result<ProviderReply, SubsystemError>> {
        Box::pin(async move {
            let call = call
                .redeem()
                .map_err(|denial| SubsystemError::denied(well_known::providers(), &denial))?;

            let endpoint = call.binding().origin();
            self.calls.lock().expect("uncontended").push(RecordedCall {
                authority: endpoint.authority(),
                addresses: endpoint.addresses().to_vec(),
                prompt: call.prompt().to_owned(),
                secret: call.credential().expose().to_owned(),
                context_items: call.context().items().len(),
            });

            let mut replies = self.replies.lock().expect("uncontended");

            if replies.is_empty() {
                return Ok(ProviderReply::new(
                    format!("echo: {}", call.prompt()),
                    Vec::new(),
                ));
            }

            Ok(replies.remove(0))
        })
    }
}

/// A tool that returns a fixed answer.
#[derive(Clone, Debug)]
pub struct FakeTool {
    binding: ToolBinding,
    answer: String,
    fails: bool,
}

impl FakeTool {
    /// Declares a tool that succeeds with `answer`.
    #[must_use]
    pub fn succeeding(name: ToolName, required: CapabilitySet, answer: impl Into<String>) -> Self {
        Self {
            binding: ToolBinding::new(name, "a deterministic stand-in".to_owned(), required),
            answer: answer.into(),
            fails: false,
        }
    }

    /// Declares a tool that runs and reports failure.
    #[must_use]
    pub fn failing(name: ToolName, required: CapabilitySet, answer: impl Into<String>) -> Self {
        Self {
            binding: ToolBinding::new(name, "a deterministic stand-in".to_owned(), required),
            answer: answer.into(),
            fails: true,
        }
    }
}

/// A tool surface whose catalogue can change between turns.
#[derive(Debug, Default)]
pub struct MemoryToolSurface {
    tools: RwLock<BTreeMap<String, FakeTool>>,
    invocations: Mutex<Vec<(String, String)>>,
}

impl MemoryToolSurface {
    /// Creates a surface offering `tools`.
    #[must_use]
    pub fn new(tools: impl IntoIterator<Item = FakeTool>) -> Self {
        Self {
            tools: RwLock::new(
                tools
                    .into_iter()
                    .map(|tool| (tool.binding.name().as_str().to_owned(), tool))
                    .collect(),
            ),
            invocations: Mutex::new(Vec::new()),
        }
    }

    /// Removes a tool, so the next turn's catalogue differs from this one's.
    pub fn withdraw(&self, name: &ToolName) {
        self.tools
            .write()
            .expect("uncontended")
            .remove(name.as_str());
    }

    /// Returns every invocation as a name and argument pair.
    #[must_use]
    pub fn invocations(&self) -> Vec<(String, String)> {
        self.invocations.lock().expect("uncontended").clone()
    }
}

impl ToolSurfacePort for MemoryToolSurface {
    fn catalogue(
        &self,
        _session: &ResolvedSession,
    ) -> BoxFuture<'_, Result<Vec<ToolBinding>, SubsystemError>> {
        Box::pin(async move {
            Ok(self
                .tools
                .read()
                .expect("uncontended")
                .values()
                .map(|tool| tool.binding.clone())
                .collect())
        })
    }

    fn invoke(&self, call: Grant<ToolCall>) -> BoxFuture<'_, Result<ToolOutcome, SubsystemError>> {
        Box::pin(async move {
            let call = call
                .redeem()
                .map_err(|denial| SubsystemError::denied(well_known::tools(), &denial))?;

            let name = call.binding().name().clone();
            let tool = self
                .tools
                .read()
                .expect("uncontended")
                .get(name.as_str())
                .cloned()
                .ok_or_else(|| {
                    SubsystemError::not_found(
                        well_known::tools(),
                        format!("{name} was withdrawn before it could run"),
                    )
                })?;

            self.invocations
                .lock()
                .expect("uncontended")
                .push((name.as_str().to_owned(), call.arguments().to_owned()));

            Ok(if tool.fails {
                ToolOutcome::failure(name, tool.answer)
            } else {
                ToolOutcome::success(name, tool.answer)
            })
        })
    }
}

/// Context assembled from a fixed set of notes plus the session identity.
#[derive(Debug, Default)]
pub struct NoteContext {
    notes: RwLock<Vec<String>>,
}

impl NoteContext {
    /// Creates an assembler serving `notes`.
    #[must_use]
    pub fn new(notes: impl IntoIterator<Item = String>) -> Self {
        Self {
            notes: RwLock::new(notes.into_iter().collect()),
        }
    }

    /// Adds a note that later turns will see.
    pub fn remember(&self, note: impl Into<String>) {
        self.notes.write().expect("uncontended").push(note.into());
    }
}

impl ContextAssemblyPort for NoteContext {
    fn assemble(
        &self,
        session: &ResolvedSession,
        prompt: &str,
        budget: usize,
    ) -> BoxFuture<'_, Result<AssembledContext, SubsystemError>> {
        let header = format!("session {} revision {}", session.id(), session.revision());
        let prompt = prompt.to_owned();

        Box::pin(async move {
            let mut items = vec![header];
            let mut used = items[0].len();
            let mut truncated = false;

            for note in self.notes.read().expect("uncontended").iter() {
                if used + note.len() > budget {
                    truncated = true;
                    break;
                }

                used += note.len();
                items.push(note.clone());
            }

            if used + prompt.len() <= budget {
                items.push(prompt);
            } else {
                truncated = true;
            }

            Ok(AssembledContext::new(items, truncated))
        })
    }
}

/// Builds the tool request a scripted reply uses to ask for a tool.
#[must_use]
pub fn request_tool(name: &ToolName, arguments: &str) -> ToolRequest {
    ToolRequest::new(name.clone(), arguments.to_owned())
}

/// Returns the capability set a workspace-reading tool needs.
#[must_use]
pub fn reading_workspace() -> CapabilitySet {
    CapabilitySet::from_capabilities([Capability::ReadWorkspace])
}

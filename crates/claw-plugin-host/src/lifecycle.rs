//! Discovery, loading, validation and the full plugin lifecycle.

use std::cmp::Ordering;
use std::collections::{BTreeMap, BinaryHeap};
use std::num::NonZeroUsize;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Instant;

use claw_plugin_api::abi::{ABI_VERSION, Version, check_compatibility};
use claw_plugin_api::cancellation::CancellationToken;
use claw_plugin_api::capability::{Capability, CapabilityDenial, CapabilitySet};
use claw_plugin_api::limits::ResourceLimits;
use claw_plugin_api::manifest::PluginManifest;
use claw_plugin_api::policy::{OperatorPolicy, Withheld};
use claw_plugin_api::trust::{
    RejectAllSignatures, SignatureVerifier, TrustDecision, TrustPolicy, VerificationRequest,
    component_sha256,
};
use wasmtime::Store;
use wasmtime::component::Component;

use crate::bindings::Plugin;
use crate::bindings::exports::gta_claw::plugin::guest::EventResponse as WitEventResponse;
use crate::engine::{CANCELLATION_POLL_MS, PluginEngine, epoch_ticks_for};
use crate::error::{GuestFailure, HostError, TerminationCause};
use crate::host_impl::wit_event;
use crate::limiter::HostCallGate;
use crate::services::{HostCallControl, HostCallStop, HostEvent, HostServices};
use crate::state::{LifecyclePhase, PluginState, PluginStateConfig, ViolationPolicy};

/// Whether a lifecycle transition withdraws the plugin's tools.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Purge {
    /// Withdraw only when the transition did not succeed.
    OnFailure,
    /// Withdraw whatever the outcome.
    Always,
}

/// Everything one lifecycle transition does apart from calling the guest.
///
/// Keeping the shape of a transition in one value is what lets `activate` and
/// `deactivate` differ in exactly the places they are meant to differ - the
/// phase the guest runs in, the phase it is left in, and whether its tools
/// survive - rather than in a long positional argument list where two of those
/// could be swapped without anyone noticing.
#[derive(Clone, Copy, Debug)]
struct Transition {
    /// The operation name reported in `WrongState` errors.
    operation: &'static str,
    /// The states this transition may start from.
    allowed: &'static [LifecycleState],
    /// The state reached when the guest call succeeds.
    next: LifecycleState,
    /// The capability phase the guest call itself runs in.
    during: LifecyclePhase,
    /// The phase the instance is left in after a successful call.
    after_success: LifecyclePhase,
    /// Whether the plugin's tools are withdrawn even on success.
    purge: Purge,
}

/// `activate`: reachable from `loaded` or `inactive`, runs with the full grant
/// set, and keeps its tools only if the guest actually activated.
const ACTIVATE: Transition = Transition {
    operation: "activate",
    allowed: &[LifecycleState::Loaded, LifecycleState::Inactive],
    next: LifecycleState::Active,
    during: LifecyclePhase::Active,
    after_success: LifecyclePhase::Active,
    purge: Purge::OnFailure,
};

/// `deactivate`: reachable only from `active`, runs with the cleanup grants
/// alone, and withdraws every tool whether or not the guest cooperates.
const DEACTIVATE: Transition = Transition {
    operation: "deactivate",
    allowed: &[LifecycleState::Active],
    next: LifecycleState::Inactive,
    during: LifecyclePhase::Deactivating,
    after_success: LifecyclePhase::Inactive,
    purge: Purge::Always,
};

/// The file every plugin directory must contain.
pub const MANIFEST_FILE_NAME: &str = "plugin.json";

/// The only component imports this host will ever satisfy.
///
/// A component that imports anything else is rejected before instantiation, so
/// an attempt to reach `wasi:filesystem`, `wasi:sockets` or any other ambient
/// interface fails as a load error rather than at some later call.
pub const ALLOWED_IMPORTS: [&str; 10] = [
    "gta-claw:plugin/host-clock@1.0.0",
    "gta-claw:plugin/host-config@1.0.0",
    "gta-claw:plugin/host-events@1.0.0",
    "gta-claw:plugin/host-fs@1.0.0",
    "gta-claw:plugin/host-http@1.0.0",
    "gta-claw:plugin/host-log@1.0.0",
    "gta-claw:plugin/host-random@1.0.0",
    "gta-claw:plugin/host-store@1.0.0",
    "gta-claw:plugin/host-tools@1.0.0",
    "gta-claw:plugin/types@1.0.0",
];

/// Where a plugin is in its lifecycle.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum LifecycleState {
    /// Instantiated and validated, but `activate` has not been called.
    Loaded,
    /// `activate` returned successfully.
    Active,
    /// `deactivate` returned successfully.
    Inactive,
    /// A guest call was terminated by the sandbox. The instance is gone and
    /// only `unload` or `reload` are allowed.
    Faulted(TerminationCause),
}

impl LifecycleState {
    /// Stable, machine-readable name.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Loaded => "loaded",
            Self::Active => "active",
            Self::Inactive => "inactive",
            Self::Faulted(_) => "faulted",
        }
    }
}

/// What a discovery pass found in one directory.
#[derive(Debug)]
pub struct Discovered {
    /// The directory that was scanned.
    pub directory: PathBuf,
    /// The parsed manifest, or why it could not be used.
    pub manifest: Result<PluginManifest, HostError>,
}

/// Stage at which discovery failed.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DiscoveryStage {
    /// The trusted root could not be enumerated.
    Root,
    /// A plugin manifest could not be read or parsed.
    Manifest,
}

/// One deterministic discovery result.
#[derive(Debug)]
pub enum DiscoveryRecord {
    /// A validated manifest is ready for load-time trust checks.
    Candidate {
        /// Plugin directory.
        directory: PathBuf,
        /// Parsed manifest.
        manifest: Box<PluginManifest>,
    },
    /// One root or manifest failed without aborting the rest of the scan.
    Failed {
        /// Root or plugin directory that failed.
        path: PathBuf,
        /// Discovery stage that failed.
        stage: DiscoveryStage,
        /// Actionable failure.
        error: HostError,
    },
}

/// Stage at which automatic activation failed.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ActivationStage {
    /// A trusted root could not be scanned.
    Discovery,
    /// A manifest could not be read or validated.
    Manifest,
    /// Trust, signature, component validation, or instantiation failed.
    Load,
    /// The guest rejected or failed activation.
    Activate,
}

/// One component that automatic activation made ready for dispatch.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ActivatedPlugin {
    /// Plugin directory.
    pub directory: PathBuf,
    /// Manifest identity.
    pub id: String,
    /// Digest computed from the bytes that were instantiated.
    pub component_sha256: String,
    /// Trusted key id, absent only when policy explicitly allowed unsigned input.
    pub signing_key_id: Option<String>,
}

/// One activation failure, retained alongside successful siblings.
#[derive(Debug)]
pub struct ActivationFailure {
    /// Root or plugin directory that failed.
    pub path: PathBuf,
    /// Manifest identity when parsing got far enough to establish it.
    pub plugin_id: Option<String>,
    /// Stage that refused the plugin.
    pub stage: ActivationStage,
    /// Primary operator-facing failure.
    pub error: HostError,
    /// Cleanup failure after an activation error, if cleanup itself failed.
    pub cleanup_error: Option<HostError>,
}

/// Ordered result for one discovered entry.
#[derive(Debug)]
pub enum ActivationOutcome {
    /// A signed or explicitly allowed unsigned component is active.
    Activated(ActivatedPlugin),
    /// This entry failed while later entries were still attempted.
    Failed(ActivationFailure),
}

/// Deterministic, partial-success result of discovery and activation.
#[derive(Debug, Default)]
pub struct ActivationReport {
    outcomes: Vec<ActivationOutcome>,
}

/// Hard bounds and interruption state for one discovered activation pass.
#[derive(Clone, Debug)]
pub struct ActivationControl {
    max_candidates: NonZeroUsize,
    deadline: Instant,
    cancellation: CancellationToken,
}

/// Largest candidate cap accepted by [`ActivationControl`].
pub const MAX_ACTIVATION_CANDIDATES: usize = 4096;

/// A controlled activation bound was unusable.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ActivationControlError {
    requested: usize,
}

impl ActivationControlError {
    /// Rejected candidate cap.
    #[must_use]
    pub const fn requested(&self) -> usize {
        self.requested
    }
}

impl core::fmt::Display for ActivationControlError {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(
            formatter,
            "activation candidate limit {} exceeds the hard maximum {MAX_ACTIVATION_CANDIDATES}",
            self.requested
        )
    }
}

impl core::error::Error for ActivationControlError {}

impl ActivationControl {
    /// Creates a bounded activation control.
    ///
    /// # Errors
    ///
    /// Returns [`ActivationControlError`] when `max_candidates` exceeds
    /// [`MAX_ACTIVATION_CANDIDATES`].
    pub fn new(
        max_candidates: NonZeroUsize,
        deadline: Instant,
        cancellation: CancellationToken,
    ) -> Result<Self, ActivationControlError> {
        if max_candidates.get() > MAX_ACTIVATION_CANDIDATES {
            return Err(ActivationControlError {
                requested: max_candidates.get(),
            });
        }
        Ok(Self {
            max_candidates,
            deadline,
            cancellation,
        })
    }

    /// Maximum manifest-bearing or unreadable plugin entries to attempt.
    #[must_use]
    pub const fn max_candidates(&self) -> NonZeroUsize {
        self.max_candidates
    }

    /// Overall absolute deadline for discovery, loading, and activation.
    #[must_use]
    pub const fn deadline(&self) -> Instant {
        self.deadline
    }

    /// Cancellation signal shared with the caller.
    #[must_use]
    pub const fn cancellation(&self) -> &CancellationToken {
        &self.cancellation
    }

    fn check(&self) -> Result<(), HostCallStop> {
        self.host_call_control().check()
    }

    fn host_call_control(&self) -> HostCallControl {
        HostCallControl::new(self.deadline, Some(self.cancellation.clone()))
    }
}

/// One ordered event from a controlled discovered activation pass.
#[derive(Debug)]
pub enum ControlledActivationOutcome {
    /// Result for one candidate in discovery order.
    Candidate(Box<ActivationOutcome>),
    /// The caller cancelled before the next stage began or while guest code ran.
    Cancelled,
    /// The overall activation deadline was reached.
    DeadlineExceeded,
    /// Another candidate existed after the hard candidate cap was consumed.
    CandidateLimitReached {
        /// Configured hard cap.
        limit: NonZeroUsize,
    },
}

impl ControlledActivationOutcome {
    /// Candidate result, when this is not a terminal event.
    #[must_use]
    pub fn candidate(&self) -> Option<&ActivationOutcome> {
        match self {
            Self::Candidate(outcome) => Some(outcome),
            Self::Cancelled | Self::DeadlineExceeded | Self::CandidateLimitReached { .. } => None,
        }
    }

    /// Whether this event stops the pass.
    #[must_use]
    pub const fn is_terminal(&self) -> bool {
        !matches!(self, Self::Candidate(_))
    }
}

/// Bounded, ordered result of controlled discovery and activation.
#[derive(Debug, Default)]
pub struct ControlledActivationReport {
    outcomes: Vec<ControlledActivationOutcome>,
}

impl ControlledActivationReport {
    /// Candidate and terminal events in deterministic discovery order.
    #[must_use]
    pub fn outcomes(&self) -> &[ControlledActivationOutcome] {
        &self.outcomes
    }

    /// Number of plugins that reached the active state.
    #[must_use]
    pub fn activated_count(&self) -> usize {
        self.outcomes
            .iter()
            .filter(|outcome| matches!(outcome.candidate(), Some(ActivationOutcome::Activated(_))))
            .count()
    }

    /// Final terminal event, absent when every discovered entry was attempted.
    #[must_use]
    pub fn terminal(&self) -> Option<&ControlledActivationOutcome> {
        self.outcomes.last().filter(|outcome| outcome.is_terminal())
    }
}

impl ActivationReport {
    /// Every outcome in trusted-root order, then lexical directory order.
    #[must_use]
    pub fn outcomes(&self) -> &[ActivationOutcome] {
        &self.outcomes
    }

    /// Number of plugins that reached the active state.
    #[must_use]
    pub fn activated_count(&self) -> usize {
        self.outcomes
            .iter()
            .filter(|outcome| matches!(outcome, ActivationOutcome::Activated(_)))
            .count()
    }

    /// Number of entries that failed without stopping the pass.
    #[must_use]
    pub fn failure_count(&self) -> usize {
        self.outcomes.len().saturating_sub(self.activated_count())
    }
}

/// Typed JSON invocation routed to one active plugin tool.
#[derive(Clone, Copy, Debug)]
pub struct PluginToolInvocation<'a> {
    /// Installed plugin identity.
    pub plugin_id: &'a str,
    /// Plugin-local tool name.
    pub tool: &'a str,
    /// Already typed JSON parameters.
    pub parameters: &'a serde_json::Value,
    /// Optional cooperative cancellation signal.
    pub cancellation: Option<&'a CancellationToken>,
}

/// Result of disposing one plugin during a host shutdown.
#[derive(Debug)]
pub struct DisposalOutcome {
    /// Plugin identity.
    pub plugin_id: String,
    /// Deactivation result. The plugin is forgotten even when this is an error.
    pub result: Result<(), HostError>,
}

/// Reverse-activation-order shutdown report.
#[derive(Debug, Default)]
pub struct DisposalReport {
    outcomes: Vec<DisposalOutcome>,
}

impl DisposalReport {
    /// Every disposal outcome in the order attempted.
    #[must_use]
    pub fn outcomes(&self) -> &[DisposalOutcome] {
        &self.outcomes
    }

    /// Whether every plugin deactivated cleanly.
    #[must_use]
    pub fn is_clean(&self) -> bool {
        self.outcomes.iter().all(|outcome| outcome.result.is_ok())
    }
}

/// A guest's answer to an event.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EventOutcome {
    /// Whether the plugin consumed the event.
    pub handled: bool,
    /// Optional JSON annotation from the plugin.
    pub note: Option<String>,
}

/// What an instance actually consumed while it was alive.
///
/// The values survive a fault, so an operator can still see that a plugin was
/// killed for growing past its memory ceiling after its store has been dropped.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct ResourceUsage {
    /// Highest linear-memory size the instance reached, in bytes.
    pub peak_memory_bytes: usize,
    /// Whether the limiter refused a memory growth request.
    pub hit_memory_ceiling: bool,
    /// Whether the limiter refused a table growth request.
    pub hit_table_ceiling: bool,
    /// Denials dropped because the bounded audit buffer was full.
    pub dropped_denials: u64,
}

impl ResourceUsage {
    const fn of(state: &PluginState) -> Self {
        Self {
            peak_memory_bytes: state.peak_memory_bytes(),
            hit_memory_ceiling: state.hit_memory_ceiling(),
            hit_table_ceiling: state.hit_table_ceiling(),
            dropped_denials: state.dropped_denials(),
        }
    }
}

impl From<WitEventResponse> for EventOutcome {
    fn from(response: WitEventResponse) -> Self {
        Self {
            handled: response.handled,
            note: response.note,
        }
    }
}

struct Instance {
    store: Store<PluginState>,
    bindings: Plugin,
}

struct Loaded {
    manifest: PluginManifest,
    directory: PathBuf,
    component_path: PathBuf,
    digest: String,
    signing_key_id: Option<String>,
    state: LifecycleState,
    withheld: Vec<Withheld>,
    narrowed: Vec<Capability>,
    instance: Option<Instance>,
    last_denials: Vec<CapabilityDenial>,
    last_usage: ResourceUsage,
}

#[derive(Debug)]
struct CandidatePath {
    path: PathBuf,
    metadata_error: Option<HostError>,
}

impl PartialEq for CandidatePath {
    fn eq(&self, other: &Self) -> bool {
        self.path == other.path
    }
}

impl Eq for CandidatePath {}

impl PartialOrd for CandidatePath {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for CandidatePath {
    fn cmp(&self, other: &Self) -> Ordering {
        self.path.cmp(&other.path)
    }
}

/// Builds a [`PluginHost`].
///
/// Everything starts closed: [`TrustPolicy::deny_all`], a verifier that only
/// accepts unsigned manifests, services that hold nothing, and
/// [`ViolationPolicy::ReturnError`].
pub struct PluginHostBuilder {
    trust: TrustPolicy,
    operator_policy: OperatorPolicy,
    verifier: Arc<dyn SignatureVerifier>,
    services: HostServices,
    policy: ViolationPolicy,
    gate: Option<HostCallGate>,
    max_host_call_concurrency: u32,
}

impl core::fmt::Debug for PluginHostBuilder {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("PluginHostBuilder")
            .field("trust", &self.trust)
            .field("operator_policy", &self.operator_policy)
            .field("policy", &self.policy)
            .field("max_host_call_concurrency", &self.max_host_call_concurrency)
            .finish_non_exhaustive()
    }
}

impl Default for PluginHostBuilder {
    fn default() -> Self {
        Self {
            trust: TrustPolicy::deny_all(),
            operator_policy: OperatorPolicy::deny_all(),
            verifier: Arc::new(RejectAllSignatures),
            services: HostServices::deny_all(),
            policy: ViolationPolicy::ReturnError,
            gate: None,
            max_host_call_concurrency: 8,
        }
    }
}

impl PluginHostBuilder {
    /// A fully closed builder.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Sets the trust policy.
    #[must_use]
    pub fn trust_policy(mut self, policy: TrustPolicy) -> Self {
        self.trust = policy;
        self
    }

    /// Sets the operator capability policy.
    ///
    /// This is the ceiling. A manifest's requested capabilities are intersected
    /// with it, so a manifest can only ever ask for *less* than the operator
    /// already decided to allow. The default, [`OperatorPolicy::deny_all`],
    /// grants nothing to anyone.
    #[must_use]
    pub fn operator_policy(mut self, policy: OperatorPolicy) -> Self {
        self.operator_policy = policy;
        self
    }

    /// Installs a signature verifier.
    #[must_use]
    pub fn verifier(mut self, verifier: Arc<dyn SignatureVerifier>) -> Self {
        self.verifier = verifier;
        self
    }

    /// Installs the host services granted capabilities may reach.
    #[must_use]
    pub fn services(mut self, services: HostServices) -> Self {
        self.services = services;
        self
    }

    /// Chooses what happens when a plugin calls something it was not granted.
    #[must_use]
    pub const fn violation_policy(mut self, policy: ViolationPolicy) -> Self {
        self.policy = policy;
        self
    }

    /// Sets the host-wide ceiling on concurrent host calls.
    #[must_use]
    pub const fn max_host_call_concurrency(mut self, max: u32) -> Self {
        self.max_host_call_concurrency = max;
        self
    }

    /// Shares an existing host-wide host-call gate with this host.
    ///
    /// Takes precedence over [`PluginHostBuilder::max_host_call_concurrency`].
    /// Sharing one gate across hosts is how an embedder bounds total host-call
    /// concurrency for a whole process rather than per host.
    #[must_use]
    pub fn host_call_gate(mut self, gate: HostCallGate) -> Self {
        self.gate = Some(gate);
        self
    }

    /// Builds the host, which also builds the engine and starts its ticker.
    ///
    /// # Errors
    ///
    /// Returns [`HostError::Instantiate`] when Wasmtime refuses the engine
    /// configuration - the component model, fuel metering and epoch
    /// interruption must all be available - or when the world's host functions
    /// cannot be added to the linker.
    pub fn build(self) -> Result<PluginHost, HostError> {
        let gate = self
            .gate
            .unwrap_or_else(|| HostCallGate::new(self.max_host_call_concurrency));
        Ok(PluginHost {
            engine: PluginEngine::new()?,
            trust: self.trust,
            operator_policy: self.operator_policy,
            verifier: self.verifier,
            services: self.services,
            policy: self.policy,
            gate,
            plugins: BTreeMap::new(),
            activation_order: Vec::new(),
        })
    }
}

/// Runs GTA-Claw plugin components inside a deny-by-default sandbox.
pub struct PluginHost {
    engine: PluginEngine,
    trust: TrustPolicy,
    operator_policy: OperatorPolicy,
    verifier: Arc<dyn SignatureVerifier>,
    services: HostServices,
    policy: ViolationPolicy,
    gate: HostCallGate,
    plugins: BTreeMap<String, Loaded>,
    activation_order: Vec<String>,
}

impl core::fmt::Debug for PluginHost {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("PluginHost")
            .field("loaded", &self.plugins.keys().collect::<Vec<_>>())
            .field("policy", &self.policy)
            .finish_non_exhaustive()
    }
}

impl PluginHost {
    /// A builder with everything closed.
    #[must_use]
    pub fn builder() -> PluginHostBuilder {
        PluginHostBuilder::new()
    }

    /// The trust policy in force.
    #[must_use]
    pub const fn trust_policy(&self) -> &TrustPolicy {
        &self.trust
    }

    /// The operator capability ceiling in force.
    #[must_use]
    pub const fn operator_policy(&self) -> &OperatorPolicy {
        &self.operator_policy
    }

    /// The capabilities a plugin asked for and did not get.
    ///
    /// Empty when the operator ceiling covered everything the manifest
    /// requested, which is also the case for a plugin that asked for nothing.
    #[must_use]
    pub fn withheld_capabilities(&self, id: &str) -> Option<&[Withheld]> {
        self.plugins
            .get(id)
            .map(|plugin| plugin.withheld.as_slice())
    }

    /// The capabilities a plugin got, but with a scope narrower than it asked
    /// for.
    #[must_use]
    pub fn narrowed_capabilities(&self, id: &str) -> Option<&[Capability]> {
        self.plugins
            .get(id)
            .map(|plugin| plugin.narrowed.as_slice())
    }

    /// The capabilities a plugin's live instance actually holds.
    #[must_use]
    pub fn effective_capabilities(&self, id: &str) -> Option<&CapabilitySet> {
        self.plugins
            .get(id)
            .and_then(|plugin| plugin.instance.as_ref())
            .map(|instance| instance.store.data().capabilities())
    }

    /// Which part of the lifecycle a plugin's live instance is executing.
    #[must_use]
    pub fn phase(&self, id: &str) -> Option<LifecyclePhase> {
        self.plugins
            .get(id)
            .and_then(|plugin| plugin.instance.as_ref())
            .map(|instance| instance.store.data().phase())
    }

    /// The tools a plugin's live instance currently holds, sorted.
    #[must_use]
    pub fn registered_tools(&self, id: &str) -> Option<Vec<String>> {
        self.plugins
            .get(id)
            .and_then(|plugin| plugin.instance.as_ref())
            .map(|instance| instance.store.data().registered_tools())
    }

    /// The ids of every loaded plugin, sorted.
    #[must_use]
    pub fn loaded_ids(&self) -> Vec<&str> {
        self.plugins.keys().map(String::as_str).collect()
    }

    /// The lifecycle state of one plugin.
    #[must_use]
    pub fn state(&self, id: &str) -> Option<LifecycleState> {
        self.plugins.get(id).map(|plugin| plugin.state)
    }

    /// The manifest a plugin was loaded from.
    #[must_use]
    pub fn manifest(&self, id: &str) -> Option<&PluginManifest> {
        self.plugins.get(id).map(|plugin| &plugin.manifest)
    }

    /// The component digest the host actually computed at load time.
    #[must_use]
    pub fn component_digest(&self, id: &str) -> Option<&str> {
        self.plugins.get(id).map(|plugin| plugin.digest.as_str())
    }

    /// Trusted signing key id established at load time.
    #[must_use]
    pub fn signing_key_id(&self, id: &str) -> Option<&str> {
        self.plugins
            .get(id)
            .and_then(|plugin| plugin.signing_key_id.as_deref())
    }

    /// Every host call this plugin's live instance has had refused.
    ///
    /// After a fault or an unload the instance is gone; the denials recorded
    /// before it died are retained here so an operator can still see them.
    #[must_use]
    pub fn denials(&self, id: &str) -> Vec<CapabilityDenial> {
        let Some(plugin) = self.plugins.get(id) else {
            return Vec::new();
        };
        plugin.instance.as_ref().map_or_else(
            || plugin.last_denials.clone(),
            |instance| instance.store.data().denials().to_vec(),
        )
    }

    /// What a plugin's instance consumed, retained across a fault.
    #[must_use]
    pub fn resource_usage(&self, id: &str) -> Option<ResourceUsage> {
        let plugin = self.plugins.get(id)?;
        Some(
            plugin
                .instance
                .as_ref()
                .map_or(plugin.last_usage, |i| ResourceUsage::of(i.store.data())),
        )
    }

    /// Scans every trusted root for plugin directories.
    ///
    /// A directory qualifies when it directly contains a
    /// [`MANIFEST_FILE_NAME`]. Unreadable roots are skipped; unreadable or
    /// invalid manifests are reported per directory rather than aborting the
    /// scan, so one broken plugin cannot hide the rest.
    #[must_use]
    pub fn discover(&self) -> Vec<Discovered> {
        self.discover_detailed()
            .into_iter()
            .filter_map(|record| match record {
                DiscoveryRecord::Candidate {
                    directory,
                    manifest,
                } => Some(Discovered {
                    directory,
                    manifest: Ok(*manifest),
                }),
                DiscoveryRecord::Failed {
                    path,
                    stage: DiscoveryStage::Manifest,
                    error,
                } => Some(Discovered {
                    directory: path,
                    manifest: Err(error),
                }),
                DiscoveryRecord::Failed {
                    stage: DiscoveryStage::Root,
                    ..
                } => None,
            })
            .collect()
    }

    /// Scans trusted roots without hiding root or directory-read failures.
    ///
    /// Records are ordered by configured root order and lexical plugin
    /// directory order. A bad root or manifest becomes one failure record and
    /// does not prevent later roots or directories from being examined.
    #[must_use]
    pub fn discover_detailed(&self) -> Vec<DiscoveryRecord> {
        let mut found = Vec::new();
        for root in self.trust.roots() {
            let entries = match std::fs::read_dir(root) {
                Ok(entries) => entries,
                Err(error) => {
                    found.push(DiscoveryRecord::Failed {
                        path: root.clone(),
                        stage: DiscoveryStage::Root,
                        error: HostError::io(root, &error),
                    });
                    continue;
                }
            };
            let mut directories: Vec<(PathBuf, Option<HostError>)> = Vec::new();
            let mut entry_failures = Vec::new();
            for entry in entries {
                match entry {
                    Ok(entry) => {
                        let path = entry.path();
                        if let Some(candidate) = inspect_candidate_path(path) {
                            directories.push((candidate.path, candidate.metadata_error));
                        }
                    }
                    Err(error) => entry_failures.push(DiscoveryRecord::Failed {
                        path: root.clone(),
                        stage: DiscoveryStage::Root,
                        error: HostError::io(root, &error),
                    }),
                }
            }
            found.extend(entry_failures);
            directories.sort_by(|(left, _), (right, _)| left.cmp(right));
            for (directory, metadata_error) in directories {
                if let Some(error) = metadata_error {
                    found.push(DiscoveryRecord::Failed {
                        path: directory,
                        stage: DiscoveryStage::Manifest,
                        error,
                    });
                    continue;
                }
                match read_manifest(&directory) {
                    Ok(manifest) => found.push(DiscoveryRecord::Candidate {
                        directory,
                        manifest: Box::new(manifest),
                    }),
                    Err(error) => found.push(DiscoveryRecord::Failed {
                        path: directory,
                        stage: DiscoveryStage::Manifest,
                        error,
                    }),
                }
            }
        }
        found
    }

    /// Discovers, loads, and activates every candidate with partial success.
    ///
    /// The report preserves discovery order. A failed activation is unloaded
    /// before the next candidate is attempted, so no half-activated instance or
    /// stale tool registration survives in the host.
    #[must_use]
    pub fn activate_discovered(&mut self) -> ActivationReport {
        let records = self.discover_detailed();
        let mut outcomes = Vec::with_capacity(records.len());
        for record in records {
            match record {
                DiscoveryRecord::Failed { path, stage, error } => {
                    outcomes.push(ActivationOutcome::Failed(ActivationFailure {
                        path,
                        plugin_id: None,
                        stage: match stage {
                            DiscoveryStage::Root => ActivationStage::Discovery,
                            DiscoveryStage::Manifest => ActivationStage::Manifest,
                        },
                        error,
                        cleanup_error: None,
                    }));
                }
                DiscoveryRecord::Candidate {
                    directory,
                    manifest,
                } => {
                    let plugin_id = manifest.id.clone();
                    let id = match self.load_manifest(&directory, *manifest) {
                        Ok(id) => id,
                        Err(error) => {
                            outcomes.push(ActivationOutcome::Failed(ActivationFailure {
                                path: directory,
                                plugin_id: Some(plugin_id),
                                stage: ActivationStage::Load,
                                error,
                                cleanup_error: None,
                            }));
                            continue;
                        }
                    };
                    if let Err(error) = self.activate(&id) {
                        let cleanup_error = self.unload(&id).err();
                        outcomes.push(ActivationOutcome::Failed(ActivationFailure {
                            path: directory,
                            plugin_id: Some(id),
                            stage: ActivationStage::Activate,
                            error,
                            cleanup_error,
                        }));
                        continue;
                    }
                    let Some(plugin) = self.plugins.get(&id) else {
                        outcomes.push(ActivationOutcome::Failed(ActivationFailure {
                            path: directory,
                            plugin_id: Some(id.clone()),
                            stage: ActivationStage::Activate,
                            error: HostError::UnknownPlugin(id),
                            cleanup_error: None,
                        }));
                        continue;
                    };
                    outcomes.push(ActivationOutcome::Activated(ActivatedPlugin {
                        directory,
                        component_sha256: plugin.digest.clone(),
                        signing_key_id: plugin.signing_key_id.clone(),
                        id,
                    }));
                }
            }
        }
        ActivationReport { outcomes }
    }

    /// Discovers and activates plugins under hard count, deadline, and
    /// cancellation bounds.
    ///
    /// Candidate paths are retained in a bounded heap and then processed in
    /// lexical order, so the report is deterministic without first allocating
    /// an unbounded discovery catalog. A terminal event is appended exactly
    /// where processing stopped. Any plugin loaded but not reported active is
    /// synchronously forgotten and its registered tools are withdrawn.
    #[must_use]
    pub fn activate_discovered_with_control(
        &mut self,
        control: &ActivationControl,
    ) -> ControlledActivationReport {
        let mut outcomes = Vec::new();
        let mut candidates_seen = 0_usize;
        let roots = self.trust.roots().to_vec();

        for root in roots {
            if let Err(stop) = control.check() {
                outcomes.push(controlled_terminal(stop));
                return ControlledActivationReport { outcomes };
            }

            let entries = match std::fs::read_dir(&root) {
                Ok(entries) => entries,
                Err(error) => {
                    let error = HostError::io(&root, &error);
                    outcomes.push(controlled_candidate(ActivationOutcome::Failed(
                        ActivationFailure {
                            path: root,
                            plugin_id: None,
                            stage: ActivationStage::Discovery,
                            error,
                            cleanup_error: None,
                        },
                    )));
                    continue;
                }
            };

            let remaining = control
                .max_candidates()
                .get()
                .saturating_sub(candidates_seen);
            let selection_cap = remaining.saturating_add(1).max(1);
            let mut selected = BinaryHeap::with_capacity(selection_cap);
            let mut root_error = None;

            for entry in entries {
                if let Err(stop) = control.check() {
                    outcomes.push(controlled_terminal(stop));
                    return ControlledActivationReport { outcomes };
                }
                let entry = match entry {
                    Ok(entry) => entry,
                    Err(error) => {
                        root_error = Some(HostError::io(&root, &error));
                        break;
                    }
                };
                if let Some(candidate) = inspect_candidate_path(entry.path()) {
                    retain_smallest_candidate(&mut selected, selection_cap, candidate);
                }
            }

            if let Some(error) = root_error {
                outcomes.push(controlled_candidate(ActivationOutcome::Failed(
                    ActivationFailure {
                        path: root,
                        plugin_id: None,
                        stage: ActivationStage::Discovery,
                        error,
                        cleanup_error: None,
                    },
                )));
            }

            for candidate in selected.into_sorted_vec() {
                if let Err(stop) = control.check() {
                    outcomes.push(controlled_terminal(stop));
                    return ControlledActivationReport { outcomes };
                }
                if candidates_seen == control.max_candidates().get() {
                    outcomes.push(ControlledActivationOutcome::CandidateLimitReached {
                        limit: control.max_candidates(),
                    });
                    return ControlledActivationReport { outcomes };
                }
                candidates_seen = candidates_seen.saturating_add(1);

                let directory = candidate.path;
                let record = candidate
                    .metadata_error
                    .map_or_else(|| read_manifest(&directory).map(Box::new), Err);

                if let Err(stop) = control.check() {
                    outcomes.push(controlled_terminal(stop));
                    return ControlledActivationReport { outcomes };
                }

                let manifest = match record {
                    Ok(manifest) => manifest,
                    Err(error) => {
                        outcomes.push(controlled_candidate(ActivationOutcome::Failed(
                            ActivationFailure {
                                path: directory,
                                plugin_id: None,
                                stage: ActivationStage::Manifest,
                                error,
                                cleanup_error: None,
                            },
                        )));
                        continue;
                    }
                };

                match self.activate_candidate_with_control(directory, *manifest, control) {
                    Ok(outcome) => outcomes.push(controlled_candidate(outcome)),
                    Err(stop) => {
                        outcomes.push(controlled_terminal(stop));
                        return ControlledActivationReport { outcomes };
                    }
                }
            }
        }

        if let Err(stop) = control.check() {
            outcomes.push(controlled_terminal(stop));
        }
        ControlledActivationReport { outcomes }
    }

    fn activate_candidate_with_control(
        &mut self,
        directory: PathBuf,
        manifest: PluginManifest,
        control: &ActivationControl,
    ) -> Result<ActivationOutcome, HostCallStop> {
        control.check()?;
        let plugin_id = manifest.id.clone();
        let host_control = control.host_call_control();
        let id = match self.load_manifest_with_control(&directory, manifest, Some(&host_control)) {
            Ok(id) => id,
            Err(error) => {
                control.check()?;
                return Ok(ActivationOutcome::Failed(ActivationFailure {
                    path: directory,
                    plugin_id: Some(plugin_id),
                    stage: ActivationStage::Load,
                    error,
                    cleanup_error: None,
                }));
            }
        };

        if let Err(stop) = control.check() {
            self.discard_plugin(&id);
            return Err(stop);
        }

        if let Err(error) = self.activate_with_control(&id, &host_control) {
            if let Err(stop) = control.check() {
                self.discard_plugin(&id);
                return Err(stop);
            }
            let cleanup_error = self.unload(&id).err();
            return Ok(ActivationOutcome::Failed(ActivationFailure {
                path: directory,
                plugin_id: Some(id),
                stage: ActivationStage::Activate,
                error,
                cleanup_error,
            }));
        }

        if let Err(stop) = control.check() {
            self.discard_plugin(&id);
            return Err(stop);
        }

        let Some(plugin) = self.plugins.get(&id) else {
            return Ok(ActivationOutcome::Failed(ActivationFailure {
                path: directory,
                plugin_id: Some(id.clone()),
                stage: ActivationStage::Activate,
                error: HostError::UnknownPlugin(id),
                cleanup_error: None,
            }));
        };
        Ok(ActivationOutcome::Activated(ActivatedPlugin {
            directory,
            component_sha256: plugin.digest.clone(),
            signing_key_id: plugin.signing_key_id.clone(),
            id,
        }))
    }

    /// Loads, validates and instantiates the plugin in `directory`.
    ///
    /// The order is deliberate: schema, limits, capabilities and ABI are
    /// checked before the trust policy resolves any path, the digest and
    /// signature are checked before the bytes reach the compiler, and the
    /// component's imports are checked before it is instantiated.
    ///
    /// # Errors
    ///
    /// Returns the first check that refuses the plugin, in the order above:
    ///
    /// * [`HostError::Io`] when `plugin.json` or the component file cannot be
    ///   read, or a granted filesystem root does not exist.
    /// * [`HostError::Manifest`], [`HostError::CapabilitySet`],
    ///   [`HostError::Limits`] or [`HostError::Version`] when the manifest is
    ///   not schema-valid, asks for a capability set that cannot be built,
    ///   states limits outside the allowed range, or carries a malformed
    ///   version.
    /// * [`HostError::Abi`] when the manifest, or the component's own
    ///   `describe`, declares an ABI this host cannot run.
    /// * [`HostError::DuplicatePlugin`] when a plugin with this id is loaded.
    /// * [`HostError::Trust`] when the directory is outside every trusted root,
    ///   the delivery class is not allowed, or the identity binding does not
    ///   match.
    /// * [`HostError::ComponentTooLarge`], [`HostError::DigestMismatch`] or
    ///   [`HostError::Verification`] when the component file is bigger than the
    ///   manifest allows, does not hash to the pinned digest, is not the size
    ///   the manifest pins, or fails the signature check.
    /// * [`HostError::Instantiate`] when the bytes are not a valid component,
    ///   Wasmtime refuses to compile them, or instantiation itself fails.
    /// * [`HostError::UnsatisfiedImport`] when the component imports anything
    ///   outside [`ALLOWED_IMPORTS`], which for this host always means an
    ///   attempt at ambient authority such as `wasi:filesystem`.
    /// * [`HostError::Terminated`] when the component's start function or its
    ///   `describe` exhausts fuel, runs past the wall-clock deadline, exceeds a
    ///   memory or table ceiling, overflows its stack or traps. Note that no
    ///   host call is reachable in either window, so a host call attempted
    ///   there is refused and, under [`ViolationPolicy::Trap`], terminates the
    ///   load.
    /// * [`HostError::Guest`] when `describe` returns an ABI error, and
    ///   [`HostError::IdentityMismatch`] when it reports an id, version or ABI
    ///   version the manifest does not claim.
    pub fn load(&mut self, directory: &Path) -> Result<String, HostError> {
        let manifest = read_manifest(directory)?;
        self.load_manifest(directory, manifest)
    }

    fn load_manifest(
        &mut self,
        directory: &Path,
        manifest: PluginManifest,
    ) -> Result<String, HostError> {
        self.load_manifest_with_control(directory, manifest, None)
    }

    fn load_manifest_with_control(
        &mut self,
        directory: &Path,
        manifest: PluginManifest,
        control: Option<&HostCallControl>,
    ) -> Result<String, HostError> {
        ensure_host_control(control, "plugin load")?;
        if self.plugins.contains_key(&manifest.id) {
            return Err(HostError::DuplicatePlugin(manifest.id));
        }

        manifest.limits.validate()?;
        let requested = CapabilitySet::new(manifest.capabilities.iter().cloned())?;
        let declared_abi = Version::parse(&manifest.abi_version)?;
        check_compatibility(ABI_VERSION, declared_abi)?;
        let manifest_version = Version::parse(&manifest.version)?;

        // The manifest states what the plugin *wants*. What it gets is that
        // request intersected with the operator's ceiling for this exact
        // plugin id, so a validly signed but hostile manifest can only ever
        // narrow its own reach, never widen it.
        let effective = self.operator_policy.effective(&manifest.id, &requested);
        let capabilities = effective.granted().clone();
        let withheld = effective.withheld().to_vec();
        let narrowed = effective.narrowed().to_vec();

        let decision: TrustDecision = self.trust.authorize(directory, &manifest)?;
        let signing_key_id = decision.signing_key_id().map(str::to_owned);

        ensure_host_control(control, "plugin load")?;
        let metadata = std::fs::metadata(decision.component_path())
            .map_err(|error| HostError::io(decision.component_path(), &error))?;
        if metadata.len() > manifest.limits.max_component_bytes {
            return Err(HostError::ComponentTooLarge {
                actual: metadata.len(),
                limit: manifest.limits.max_component_bytes,
            });
        }
        if metadata.len() != manifest.component.size_bytes {
            return Err(HostError::DigestMismatch {
                expected: format!("{} bytes", manifest.component.size_bytes),
                actual: format!("{} bytes", metadata.len()),
            });
        }

        ensure_host_control(control, "plugin load")?;
        let bytes = std::fs::read(decision.component_path())
            .map_err(|error| HostError::io(decision.component_path(), &error))?;
        let digest = component_sha256(&bytes);
        if digest != manifest.component.sha256 {
            return Err(HostError::DigestMismatch {
                expected: manifest.component.sha256,
                actual: digest,
            });
        }
        self.verifier.verify(&VerificationRequest {
            manifest: &manifest,
            component_sha256: &digest,
        })?;

        let (read_roots, write_roots) = canonical_roots(&capabilities)?;

        ensure_host_control(control, "plugin compilation")?;
        let component = Component::new(self.engine.engine(), &bytes)
            .map_err(|error| HostError::Instantiate(format!("{error:#}")))?;
        ensure_host_control(control, "plugin compilation")?;
        reject_foreign_imports(self.engine.engine(), &component)?;

        let state = PluginState::new(PluginStateConfig {
            plugin_id: manifest.id.clone(),
            capabilities,
            limits: manifest.limits,
            services: self.services.clone(),
            shared_gate: self.gate.clone(),
            policy: self.policy,
            read_roots,
            write_roots,
        });
        let mut store = self.engine.new_store(state)?;
        arm_call(&mut store, &manifest.limits, control);
        let raw = Plugin::instantiate(&mut store, &component, self.engine.linker());
        let raw = observe_interruption(&mut store, raw);
        let bindings = raw.map_err(|error| classify_instantiation(&error, store.data()));
        disarm_call(&mut store);
        let bindings = bindings?;

        // Instantiation ran the component's start function and `describe` is
        // about to run, both before the host has established that this really
        // is the plugin the manifest names. The store is still in
        // `LifecyclePhase::Starting`, so neither can reach a host effect.
        debug_assert_eq!(store.data().phase(), LifecyclePhase::Starting);
        arm_call(&mut store, &manifest.limits, control);
        let info = bindings.gta_claw_plugin_guest().call_describe(&mut store);
        let info =
            observe_interruption(&mut store, info).map_err(|error| classify(&error, store.data()));
        disarm_call(&mut store);
        let info = info?;

        ensure_host_control(control, "plugin description")?;
        check_payload("component identity", info.id.as_bytes(), &manifest.limits)?;
        if info.id != manifest.id {
            return Err(HostError::IdentityMismatch {
                field: "id",
                manifest: manifest.id.clone(),
                component: info.id,
            });
        }
        let reported_version =
            Version::new(info.version.major, info.version.minor, info.version.patch);
        if reported_version != manifest_version {
            return Err(HostError::IdentityMismatch {
                field: "version",
                manifest: manifest_version.to_string(),
                component: reported_version.to_string(),
            });
        }
        let reported_abi = Version::new(
            info.abi_version.major,
            info.abi_version.minor,
            info.abi_version.patch,
        );
        check_compatibility(ABI_VERSION, reported_abi)?;
        if reported_abi != declared_abi {
            return Err(HostError::IdentityMismatch {
                field: "abi_version",
                manifest: declared_abi.to_string(),
                component: reported_abi.to_string(),
            });
        }

        let id = manifest.id.clone();
        // Identity is now established, so the instance leaves the closed
        // starting phase. It is still not activated, and `Loaded` permits
        // nothing either.
        store.data_mut().set_phase(LifecyclePhase::Loaded);
        self.plugins.insert(
            id.clone(),
            Loaded {
                manifest,
                directory: directory.to_path_buf(),
                component_path: decision.component_path().to_path_buf(),
                digest,
                signing_key_id,
                withheld,
                narrowed,
                state: LifecycleState::Loaded,
                instance: Some(Instance { store, bindings }),
                last_denials: Vec::new(),
                last_usage: ResourceUsage::default(),
            },
        );
        Ok(id)
    }

    /// Calls `activate` on a loaded or deactivated plugin.
    ///
    /// # Errors
    ///
    /// * [`HostError::UnknownPlugin`] when no plugin with this id is loaded.
    /// * [`HostError::Faulted`] when a previous call trapped, so the instance
    ///   no longer exists and the plugin must be reloaded first.
    /// * [`HostError::WrongState`] when the plugin is already active.
    /// * [`HostError::Guest`] when `activate` returned an ABI error. The
    ///   plugin stays in the state it was in and its tools are withdrawn.
    /// * [`HostError::Terminated`] when `activate` exhausted its fuel, ran past
    ///   its wall-clock deadline, exceeded a memory or table ceiling, overflowed
    ///   its stack, trapped, or was trapped by a host call refused under
    ///   [`ViolationPolicy::Trap`]. The instance is destroyed and the plugin is
    ///   left faulted.
    pub fn activate(&mut self, id: &str) -> Result<(), HostError> {
        self.transition(id, &ACTIVATE, None, |bindings, store| {
            bindings.gta_claw_plugin_guest().call_activate(store)
        })
    }

    fn activate_with_control(
        &mut self,
        id: &str,
        control: &HostCallControl,
    ) -> Result<(), HostError> {
        self.transition(id, &ACTIVATE, Some(control), |bindings, store| {
            bindings.gta_claw_plugin_guest().call_activate(store)
        })
    }

    /// Calls `deactivate` on an active plugin.
    ///
    /// Capabilities are revoked *before* the guest is invoked: only
    /// [`LifecyclePhase::CLEANUP`] remains reachable for the duration of the
    /// call, and nothing at all afterwards. Every tool the plugin registered is
    /// withdrawn synchronously whether or not the guest cooperates.
    ///
    /// # Errors
    ///
    /// * [`HostError::UnknownPlugin`] when no plugin with this id is loaded.
    /// * [`HostError::Faulted`] when a previous call trapped, so there is no
    ///   instance left to deactivate.
    /// * [`HostError::WrongState`] when the plugin is not active.
    /// * [`HostError::Guest`] when `deactivate` returned an ABI error.
    /// * [`HostError::Terminated`] when `deactivate` exhausted its fuel, ran
    ///   past its wall-clock deadline, exceeded a memory or table ceiling,
    ///   overflowed its stack, trapped, or was trapped by a host call refused
    ///   under [`ViolationPolicy::Trap`]. The instance is destroyed and the
    ///   plugin is left faulted; its tools are withdrawn either way.
    pub fn deactivate(&mut self, id: &str) -> Result<(), HostError> {
        self.transition(id, &DEACTIVATE, None, |bindings, store| {
            bindings.gta_claw_plugin_guest().call_deactivate(store)
        })
    }

    fn transition(
        &mut self,
        id: &str,
        transition: &Transition,
        control: Option<&HostCallControl>,
        call: impl FnOnce(
            &Plugin,
            &mut Store<PluginState>,
        ) -> wasmtime::Result<
            Result<(), crate::bindings::gta_claw::plugin::types::Error>,
        >,
    ) -> Result<(), HostError> {
        ensure_host_control(control, transition.operation)?;
        let limits = {
            let plugin = self
                .plugins
                .get(id)
                .ok_or_else(|| HostError::UnknownPlugin(id.to_owned()))?;
            if let LifecycleState::Faulted(cause) = plugin.state {
                return Err(HostError::Faulted {
                    id: id.to_owned(),
                    cause,
                });
            }
            if !transition.allowed.contains(&plugin.state) {
                return Err(HostError::WrongState {
                    id: id.to_owned(),
                    actual: plugin.state.as_str(),
                    expected: transition.operation,
                });
            }
            plugin.manifest.limits
        };

        let (outcome, previous_phase) = {
            let plugin = self
                .plugins
                .get_mut(id)
                .ok_or_else(|| HostError::UnknownPlugin(id.to_owned()))?;
            let instance = plugin
                .instance
                .as_mut()
                .ok_or_else(|| HostError::WrongState {
                    id: id.to_owned(),
                    actual: "unloaded",
                    expected: transition.operation,
                })?;
            let previous_phase = instance.store.data().phase();
            instance.store.data_mut().set_phase(transition.during);
            arm_call(&mut instance.store, &limits, control);
            let raw = call(&instance.bindings, &mut instance.store);
            let raw = observe_interruption(&mut instance.store, raw);
            disarm_call(&mut instance.store);
            (
                raw.map_err(|error| classify(&error, instance.store.data())),
                previous_phase,
            )
        };

        // The phase is restored before anything else can observe the instance,
        // so a guest that fails its own activation never keeps the capabilities
        // that activation would have given it.
        let succeeded = matches!(outcome, Ok(Ok(())));
        if outcome.is_ok() {
            let phase = if succeeded {
                transition.after_success
            } else {
                previous_phase
            };
            if let Some(instance) = self
                .plugins
                .get_mut(id)
                .and_then(|plugin| plugin.instance.as_mut())
            {
                instance.store.data_mut().set_phase(phase);
            }
        }
        if matches!(transition.purge, Purge::Always) || !succeeded {
            self.purge_tools(id);
        }

        match outcome {
            Ok(Ok(())) => {
                if let Some(plugin) = self.plugins.get_mut(id) {
                    plugin.state = transition.next;
                }
                self.activation_order.retain(|active| active != id);
                if transition.next == LifecycleState::Active {
                    self.activation_order.push(id.to_owned());
                }
                Ok(())
            }
            Ok(Err(error)) => Err(guest_error(&error, &limits)),
            Err(error) => {
                self.fault(id, &error);
                Err(error)
            }
        }
    }

    /// Delivers one event to an active plugin.
    ///
    /// # Errors
    ///
    /// * [`HostError::UnknownPlugin`] when no plugin with this id is loaded.
    /// * [`HostError::Faulted`] when a previous call trapped and the plugin has
    ///   not been reloaded.
    /// * [`HostError::WrongState`] when the plugin is loaded or inactive rather
    ///   than active.
    /// * [`HostError::Guest`] when `handle-event` returns an ABI error.
    /// * [`HostError::Terminated`] when the call exhausts its fuel, runs past
    ///   its wall-clock deadline, exceeds a memory or table ceiling, overflows
    ///   its stack, traps, or makes a host call that is refused while
    ///   [`ViolationPolicy::Trap`] is in force. The instance is destroyed and
    ///   the plugin is left faulted.
    pub fn handle_event(&mut self, id: &str, event: &HostEvent) -> Result<EventOutcome, HostError> {
        let limits = self.require_active(id, "handle-event")?;
        check_payload("event source", event.source.as_bytes(), &limits)?;
        check_payload("event payload", event.payload.as_bytes(), &limits)?;
        let wit = wit_event(event);
        let outcome = {
            let plugin = self
                .plugins
                .get_mut(id)
                .ok_or_else(|| HostError::UnknownPlugin(id.to_owned()))?;
            let instance = plugin
                .instance
                .as_mut()
                .ok_or_else(|| HostError::WrongState {
                    id: id.to_owned(),
                    actual: "unloaded",
                    expected: "handle-event",
                })?;
            arm_call(&mut instance.store, &limits, None);
            let raw = instance
                .bindings
                .gta_claw_plugin_guest()
                .call_handle_event(&mut instance.store, &wit);
            let raw = observe_interruption(&mut instance.store, raw);
            disarm_call(&mut instance.store);
            raw.map_err(|error| classify(&error, instance.store.data()))
        };
        match outcome {
            Ok(Ok(response)) => {
                if let Some(note) = &response.note {
                    check_payload("event response note", note.as_bytes(), &limits)?;
                }
                Ok(EventOutcome::from(response))
            }
            Ok(Err(error)) => Err(guest_error(&error, &limits)),
            Err(error) => {
                self.fault(id, &error);
                Err(error)
            }
        }
    }

    /// Invokes one of an active plugin's tools.
    ///
    /// # Errors
    ///
    /// * [`HostError::UnknownPlugin`] when no plugin with this id is loaded.
    /// * [`HostError::Faulted`] when a previous call trapped and the plugin has
    ///   not been reloaded.
    /// * [`HostError::WrongState`] when the plugin is not active.
    /// * [`HostError::Guest`] when the guest rejects the call, which is also
    ///   how an unknown tool name and invalid input are reported: the host does
    ///   not keep a tool table of its own to answer from.
    /// * [`HostError::Terminated`] when the call exhausts its fuel, runs past
    ///   its wall-clock deadline, exceeds a memory or table ceiling, overflows
    ///   its stack, traps, or makes a host call that is refused while
    ///   [`ViolationPolicy::Trap`] is in force. The instance is destroyed and
    ///   the plugin is left faulted.
    pub fn invoke_tool(&mut self, id: &str, name: &str, input: &str) -> Result<String, HostError> {
        self.invoke_tool_inner(id, name, input, None)
    }

    /// Invokes a plugin tool while observing caller cancellation.
    ///
    /// Cancellation requested before dispatch returns without touching the
    /// plugin. Cancellation observed in-flight interrupts Wasm and faults only
    /// this plugin because unwound guest state cannot be resumed safely.
    ///
    /// # Errors
    ///
    /// Returns the same failures as [`PluginHost::invoke_tool`], plus
    /// [`HostError::Cancelled`] before dispatch or
    /// [`TerminationCause::Cancelled`] for an in-flight interruption.
    pub fn invoke_tool_cancellable(
        &mut self,
        id: &str,
        name: &str,
        input: &str,
        cancellation: &CancellationToken,
    ) -> Result<String, HostError> {
        self.invoke_tool_inner(id, name, input, Some(cancellation))
    }

    /// Serializes typed parameters, invokes the component, and decodes typed
    /// JSON output.
    ///
    /// This is the bridge expected by `claw-skills`: callers never need to
    /// construct or parse the string representation used by the WIT ABI.
    ///
    /// # Errors
    ///
    /// Returns [`HostError::InvalidToolInput`] if JSON encoding fails,
    /// [`HostError::InvalidGuestResponse`] if the guest returns non-JSON, or any
    /// dispatch error documented by [`PluginHost::invoke_tool_cancellable`].
    pub fn invoke_json_tool(
        &mut self,
        invocation: PluginToolInvocation<'_>,
    ) -> Result<serde_json::Value, HostError> {
        let input = serde_json::to_string(invocation.parameters).map_err(|error| {
            HostError::InvalidToolInput {
                plugin_id: invocation.plugin_id.to_owned(),
                tool: invocation.tool.to_owned(),
                message: error.to_string(),
            }
        })?;
        let output = self.invoke_tool_inner(
            invocation.plugin_id,
            invocation.tool,
            &input,
            invocation.cancellation,
        )?;
        serde_json::from_str(&output).map_err(|error| HostError::InvalidGuestResponse {
            plugin_id: invocation.plugin_id.to_owned(),
            tool: invocation.tool.to_owned(),
            message: error.to_string(),
        })
    }

    fn invoke_tool_inner(
        &mut self,
        id: &str,
        name: &str,
        input: &str,
        cancellation: Option<&CancellationToken>,
    ) -> Result<String, HostError> {
        if cancellation.is_some_and(CancellationToken::is_cancelled) {
            return Err(HostError::Cancelled {
                operation: "tool invocation",
            });
        }
        let limits = self.require_active(id, "invoke-tool")?;
        check_payload("tool name", name.as_bytes(), &limits)?;
        check_payload("tool input", input.as_bytes(), &limits)?;
        let call_control = cancellation.map(|token| {
            HostCallControl::new(Instant::now() + limits.timeout(), Some(token.clone()))
        });
        let outcome = {
            let plugin = self
                .plugins
                .get_mut(id)
                .ok_or_else(|| HostError::UnknownPlugin(id.to_owned()))?;
            let instance = plugin
                .instance
                .as_mut()
                .ok_or_else(|| HostError::WrongState {
                    id: id.to_owned(),
                    actual: "unloaded",
                    expected: "invoke-tool",
                })?;
            arm_call(&mut instance.store, &limits, call_control.as_ref());
            let raw = instance.bindings.gta_claw_plugin_guest().call_invoke_tool(
                &mut instance.store,
                name,
                input,
            );
            let raw = observe_interruption(&mut instance.store, raw);
            disarm_call(&mut instance.store);
            raw.map_err(|error| classify(&error, instance.store.data()))
        };
        match outcome {
            Ok(Ok(value)) => {
                check_payload("tool output", value.as_bytes(), &limits)?;
                Ok(value)
            }
            Ok(Err(error)) => Err(guest_error(&error, &limits)),
            Err(error) => {
                self.fault(id, &error);
                Err(error)
            }
        }
    }

    fn require_active(
        &self,
        id: &str,
        operation: &'static str,
    ) -> Result<ResourceLimits, HostError> {
        let plugin = self
            .plugins
            .get(id)
            .ok_or_else(|| HostError::UnknownPlugin(id.to_owned()))?;
        if let LifecycleState::Faulted(cause) = plugin.state {
            return Err(HostError::Faulted {
                id: id.to_owned(),
                cause,
            });
        }
        if plugin.state != LifecycleState::Active {
            return Err(HostError::WrongState {
                id: id.to_owned(),
                actual: plugin.state.as_str(),
                expected: operation,
            });
        }
        Ok(plugin.manifest.limits)
    }

    /// Marks a plugin faulted and destroys its instance.
    ///
    /// Only this plugin's store is dropped. Every other plugin keeps running
    /// on its own store, which is what makes a trap non-contagious. The tools
    /// the plugin had advertised are withdrawn first, so a trapped plugin
    /// cannot leave callable entry points behind it.
    fn fault(&mut self, id: &str, error: &HostError) {
        self.purge_tools(id);
        self.activation_order.retain(|active| active != id);
        let cause = error.termination().unwrap_or(TerminationCause::Trap);
        if let Some(plugin) = self.plugins.get_mut(id) {
            if let Some(instance) = plugin.instance.take() {
                plugin.last_denials = instance.store.data().denials().to_vec();
                plugin.last_usage = ResourceUsage::of(instance.store.data());
            }
            plugin.state = LifecycleState::Faulted(cause);
        }
    }

    /// Withdraws every tool the live instance still holds.
    ///
    /// The names come from the instance's own ledger rather than from the
    /// sink, so one plugin can never purge another's registrations.
    fn purge_tools(&mut self, id: &str) {
        let names = self
            .plugins
            .get_mut(id)
            .and_then(|plugin| plugin.instance.as_mut())
            .map(|instance| instance.store.data_mut().take_registered_tools())
            .unwrap_or_default();
        for name in names {
            self.services.tools.unregister(id, &name);
        }
    }

    fn discard_plugin(&mut self, id: &str) {
        self.purge_tools(id);
        self.plugins.remove(id);
        self.activation_order.retain(|active| active != id);
    }

    /// Drops a plugin's instance and forgets it.
    ///
    /// Deactivation is attempted first for an active plugin, but a guest that
    /// refuses to deactivate cannot keep itself loaded, and its tools are
    /// withdrawn either way.
    ///
    /// # Errors
    ///
    /// Returns [`HostError::UnknownPlugin`] when no such plugin is loaded, or
    /// the guest's deactivation failure after the instance has still been
    /// removed and all of its tools withdrawn.
    pub fn unload(&mut self, id: &str) -> Result<(), HostError> {
        if !self.plugins.contains_key(id) {
            return Err(HostError::UnknownPlugin(id.to_owned()));
        }
        let deactivation_error = if self.state(id) == Some(LifecycleState::Active) {
            self.deactivate(id).err()
        } else {
            None
        };
        self.purge_tools(id);
        self.plugins.remove(id);
        self.activation_order.retain(|active| active != id);
        deactivation_error.map_or(Ok(()), Err)
    }

    /// Unloads a plugin and loads it again from the directory it came from.
    ///
    /// The manifest is re-read and every check is re-run, so a component that
    /// changed on disk is re-validated rather than trusted from a cache. A
    /// faulted plugin can be recovered this way.
    ///
    /// # Errors
    ///
    /// Returns [`HostError`] when the plugin is unknown or fails to reload.
    /// Every load error listed on [`PluginHost::load`] is possible here,
    /// because the component is re-validated from scratch: a component that
    /// changed on disk now fails its digest check, and a manifest that changed
    /// is re-checked against the operator ceiling.
    pub fn reload(&mut self, id: &str) -> Result<String, HostError> {
        let directory = self
            .plugins
            .get(id)
            .map(|plugin| plugin.directory.clone())
            .ok_or_else(|| HostError::UnknownPlugin(id.to_owned()))?;
        self.unload(id)?;
        self.load(&directory)
    }

    /// Deactivates and forgets every plugin in reverse activation order.
    ///
    /// Every plugin is attempted even when an earlier guest refuses to
    /// deactivate. Each failed plugin is still removed and its tools are
    /// withdrawn, and the returned report retains the original error.
    #[must_use]
    pub fn shutdown(&mut self) -> DisposalReport {
        let mut ids: Vec<String> = self.activation_order.iter().rev().cloned().collect();
        for id in self.plugins.keys() {
            if !ids.contains(id) {
                ids.push(id.clone());
            }
        }
        let outcomes = ids
            .into_iter()
            .map(|plugin_id| {
                let result = self.unload(&plugin_id);
                DisposalOutcome { plugin_id, result }
            })
            .collect();
        DisposalReport { outcomes }
    }

    /// The path the component was loaded from.
    #[must_use]
    pub fn component_path(&self, id: &str) -> Option<&Path> {
        self.plugins
            .get(id)
            .map(|plugin| plugin.component_path.as_path())
    }
}

impl Drop for PluginHost {
    fn drop(&mut self) {
        let ids: Vec<String> = self.plugins.keys().cloned().collect();
        for id in ids {
            self.purge_tools(&id);
        }
    }
}

fn controlled_candidate(outcome: ActivationOutcome) -> ControlledActivationOutcome {
    ControlledActivationOutcome::Candidate(Box::new(outcome))
}

const fn controlled_terminal(stop: HostCallStop) -> ControlledActivationOutcome {
    match stop {
        HostCallStop::Cancelled => ControlledActivationOutcome::Cancelled,
        HostCallStop::DeadlineExceeded => ControlledActivationOutcome::DeadlineExceeded,
    }
}

fn retain_smallest_candidate(
    selected: &mut BinaryHeap<CandidatePath>,
    capacity: usize,
    candidate: CandidatePath,
) {
    if selected.len() < capacity {
        selected.push(candidate);
    } else if selected
        .peek()
        .is_some_and(|largest| candidate.path < largest.path)
    {
        selected.pop();
        selected.push(candidate);
    }
}

fn inspect_candidate_path(path: PathBuf) -> Option<CandidatePath> {
    match std::fs::metadata(&path) {
        Ok(metadata) if metadata.is_dir() => {
            let manifest_path = path.join(MANIFEST_FILE_NAME);
            match std::fs::symlink_metadata(&manifest_path) {
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => None,
                Err(error) => Some(CandidatePath {
                    path,
                    metadata_error: Some(HostError::io(&manifest_path, &error)),
                }),
                Ok(_) => match std::fs::metadata(&manifest_path) {
                    Ok(_) => Some(CandidatePath {
                        path,
                        metadata_error: None,
                    }),
                    Err(error) => Some(CandidatePath {
                        path,
                        metadata_error: Some(HostError::io(&manifest_path, &error)),
                    }),
                },
            }
        }
        Ok(_) => None,
        Err(error) => Some(CandidatePath {
            path: path.clone(),
            metadata_error: Some(HostError::io(path, &error)),
        }),
    }
}

fn read_manifest(directory: &Path) -> Result<PluginManifest, HostError> {
    let path = directory.join(MANIFEST_FILE_NAME);
    let bytes = std::fs::read(&path).map_err(|error| HostError::io(&path, &error))?;
    Ok(PluginManifest::parse(&bytes)?)
}

/// Canonicalises every filesystem root once, at load time, so no call-time
/// path resolution ever has to trust a root that might have moved.
fn canonical_roots(
    capabilities: &CapabilitySet,
) -> Result<(Vec<PathBuf>, Vec<PathBuf>), HostError> {
    let resolve = |roots: &[PathBuf]| -> Result<Vec<PathBuf>, HostError> {
        roots
            .iter()
            .map(|root| std::fs::canonicalize(root).map_err(|error| HostError::io(root, &error)))
            .collect()
    };
    let read = capabilities
        .filesystem_read()
        .map_or_else(|| Ok(Vec::new()), |grant| resolve(&grant.roots))?;
    let write = capabilities
        .filesystem_write()
        .map_or_else(|| Ok(Vec::new()), |grant| resolve(&grant.roots))?;
    Ok((read, write))
}

/// Refuses a component that imports anything outside this world.
fn reject_foreign_imports(
    engine: &wasmtime::Engine,
    component: &Component,
) -> Result<(), HostError> {
    let component_type = component.component_type();
    for (name, _) in component_type.imports(engine) {
        if !ALLOWED_IMPORTS.contains(&name) {
            return Err(HostError::UnsatisfiedImport(name.to_owned()));
        }
    }
    Ok(())
}

/// Gives a call its own fuel, epoch deadline and host-call deadline.
///
/// Every guest entry point - the component start function, `describe`,
/// `activate`, `deactivate`, `handle-event` and `invoke-tool` - is armed
/// immediately before it runs, so a budget is per call rather than per
/// instance and a plugin cannot bank the fuel it did not spend last time.
fn arm_call(
    store: &mut Store<PluginState>,
    limits: &ResourceLimits,
    control: Option<&HostCallControl>,
) {
    // Every store this host runs came from `PluginEngine::new_store`, whose
    // engine always has fuel metering enabled, so this cannot fail. Even if it
    // somehow did, the two lines below still bound the call in wall-clock time:
    // the guest is never left with no bound at all.
    let armed = store.set_fuel(limits.fuel);
    debug_assert!(
        armed.is_ok(),
        "a store from `PluginEngine::new_store` always meters fuel"
    );
    // `ResourceLimits::validate` caps `wall_clock_timeout_ms` at ten minutes
    // and `load` runs it before any instance exists, so this addition cannot
    // overflow even for a manifest written by a hostile author.
    let plugin_deadline = Instant::now() + limits.timeout();
    let deadline = control.map_or(plugin_deadline, |control| {
        plugin_deadline.min(control.deadline())
    });
    let cancellation = control.and_then(HostCallControl::cancellation).cloned();
    store.data_mut().arm_call(deadline, cancellation);
    let first_check = store.data().next_interrupt_check_ms(CANCELLATION_POLL_MS);
    store.set_epoch_deadline(epoch_ticks_for(first_check));
}

fn disarm_call(store: &mut Store<PluginState>) {
    store.data_mut().disarm_call();
}

fn observe_interruption<T>(
    store: &mut Store<PluginState>,
    outcome: wasmtime::Result<T>,
) -> wasmtime::Result<T> {
    if outcome.is_ok()
        && let Some(cause) = store.data_mut().poll_interruption()
    {
        return Err(wasmtime::Error::msg(format!(
            "plugin invocation interrupted ({cause})"
        )));
    }
    outcome
}

fn ensure_host_control(
    control: Option<&HostCallControl>,
    operation: &'static str,
) -> Result<(), HostError> {
    let Some(control) = control else {
        return Ok(());
    };
    control
        .check()
        .map_err(|stop| host_control_error(stop, operation))
}

fn host_control_error(stop: HostCallStop, operation: &'static str) -> HostError {
    match stop {
        HostCallStop::Cancelled => HostError::Cancelled { operation },
        HostCallStop::DeadlineExceeded => HostError::Terminated {
            cause: TerminationCause::Timeout,
            detail: format!("{operation} exceeded the overall activation deadline"),
        },
    }
}

fn check_payload(
    field: &'static str,
    bytes: &[u8],
    limits: &ResourceLimits,
) -> Result<(), HostError> {
    if u64::try_from(bytes.len()).unwrap_or(u64::MAX) > u64::from(limits.max_payload_bytes) {
        return Err(HostError::PayloadTooLarge {
            field,
            actual: bytes.len(),
            limit: limits.max_payload_bytes,
        });
    }
    Ok(())
}

fn guest_error(
    error: &crate::bindings::gta_claw::plugin::types::Error,
    limits: &ResourceLimits,
) -> HostError {
    use crate::bindings::gta_claw::plugin::types::ErrorCode;

    if let Err(error) = check_payload("guest error message", error.message.as_bytes(), limits) {
        return error;
    }
    let code = match error.code {
        ErrorCode::InvalidInput => "invalid-input",
        ErrorCode::PermissionDenied => "permission-denied",
        ErrorCode::NotFound => "not-found",
        ErrorCode::Conflict => "conflict",
        ErrorCode::ResourceExhausted => "resource-exhausted",
        ErrorCode::Unsupported => "unsupported",
        ErrorCode::Internal => "internal",
    };
    HostError::Guest(GuestFailure {
        code,
        message: error.message.clone(),
    })
}

/// Turns a Wasmtime error into a host error, naming why the guest stopped.
fn classify(error: &wasmtime::Error, state: &PluginState) -> HostError {
    let detail = format!("{error:#}");
    let cause =
        state
            .interruption()
            .unwrap_or_else(|| match error.downcast_ref::<wasmtime::Trap>() {
                Some(wasmtime::Trap::Interrupt) => TerminationCause::Timeout,
                Some(wasmtime::Trap::OutOfFuel) => TerminationCause::FuelExhausted,
                Some(wasmtime::Trap::StackOverflow) => TerminationCause::StackOverflow,
                Some(_) | None => {
                    if state.hit_resource_ceiling_during_call() {
                        TerminationCause::ResourceLimit
                    } else {
                        TerminationCause::Trap
                    }
                }
            });
    HostError::Terminated { cause, detail }
}

fn classify_instantiation(error: &wasmtime::Error, state: &PluginState) -> HostError {
    if error.downcast_ref::<wasmtime::Trap>().is_some()
        || state.interruption().is_some()
        || state.hit_resource_ceiling_during_call()
    {
        classify(error, state)
    } else {
        HostError::Instantiate(format!("{error:#}"))
    }
}

#[cfg(test)]
mod tests {
    use super::{ALLOWED_IMPORTS, LifecycleState, MANIFEST_FILE_NAME, PluginHost};
    use crate::error::TerminationCause;

    #[test]
    fn the_allowed_import_list_is_exactly_this_world() {
        let mut sorted = ALLOWED_IMPORTS;
        sorted.sort_unstable();
        assert_eq!(sorted, ALLOWED_IMPORTS, "keep the list sorted");
        assert_eq!(ALLOWED_IMPORTS.len(), 10);
        for name in ALLOWED_IMPORTS {
            assert!(
                name.starts_with("gta-claw:plugin/"),
                "{name} is not part of this world"
            );
            assert!(name.ends_with("@1.0.0"), "{name} is not version pinned");
        }
        assert!(
            !ALLOWED_IMPORTS.iter().any(|name| name.starts_with("wasi:")),
            "the host must never satisfy a wasi import"
        );
    }

    #[test]
    fn the_manifest_file_name_is_fixed() {
        assert_eq!(MANIFEST_FILE_NAME, "plugin.json");
    }

    #[test]
    fn lifecycle_state_names_are_stable() {
        assert_eq!(LifecycleState::Loaded.as_str(), "loaded");
        assert_eq!(LifecycleState::Active.as_str(), "active");
        assert_eq!(LifecycleState::Inactive.as_str(), "inactive");
        assert_eq!(
            LifecycleState::Faulted(TerminationCause::Timeout).as_str(),
            "faulted"
        );
    }

    #[test]
    fn a_fresh_host_knows_nothing_and_discovers_nothing() {
        let host = PluginHost::builder().build().expect("host");
        assert_eq!(host.loaded_ids(), Vec::<&str>::new());
        assert_eq!(host.state("anything"), None);
        assert_eq!(host.manifest("anything"), None);
        assert_eq!(host.denials("anything"), Vec::new());
        assert!(host.discover().is_empty());
        assert!(host.trust_policy().roots().is_empty());
    }

    #[test]
    fn operations_on_an_unknown_plugin_name_that_plugin() {
        let mut host = PluginHost::builder().build().expect("host");
        for error in [
            host.activate("ghost").unwrap_err(),
            host.deactivate("ghost").unwrap_err(),
            host.unload("ghost").unwrap_err(),
            host.reload("ghost").unwrap_err(),
        ] {
            match error {
                crate::error::HostError::UnknownPlugin(id) => assert_eq!(id, "ghost"),
                other => panic!("expected an unknown-plugin error, got {other}"),
            }
        }
    }
}

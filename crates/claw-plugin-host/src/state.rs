//! Per-instance host state and the capability gate every host call runs through.

use std::collections::BTreeSet;
use std::path::PathBuf;
use std::time::Instant;

use claw_plugin_api::capability::{Capability, CapabilityDenial, CapabilitySet};
use claw_plugin_api::limits::ResourceLimits;

use crate::bindings::gta_claw::plugin::types::{Error as WitError, ErrorCode};
use crate::limiter::{HostCallGate, HostCallPermits, InstanceLimiter};
use crate::services::HostServices;

/// How the host reacts when a plugin calls something it was not granted.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum ViolationPolicy {
    /// Return `permission-denied` to the guest and let it continue.
    #[default]
    ReturnError,
    /// Trap the instance immediately. The plugin is marked faulted and must be
    /// reloaded; other plugins are unaffected.
    Trap,
}

/// The number of denials one instance keeps before it starts dropping the
/// oldest, so a plugin cannot exhaust host memory by failing in a loop.
pub(crate) const MAX_AUDIT_ENTRIES: usize = 1024;

/// Which part of the lifecycle an instance is currently executing.
///
/// Capabilities are not a property of a plugin, they are a property of a
/// plugin *while it is activated*. An instance is created before its component
/// has been instantiated and it is still alive after it has been deactivated,
/// and guest code runs in both of those windows: a component start function
/// runs during instantiation, `describe` runs before the host has decided the
/// component is even the plugin it claims to be, and `deactivate` runs after
/// the host has decided to stop it. None of those windows may reach a host
/// effect.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum LifecyclePhase {
    /// Instantiation and `describe`. Nothing is reachable: the component has
    /// not yet been proven to be the plugin the manifest names, so anything it
    /// did here would be attributed to an identity it has not established.
    #[default]
    Starting,
    /// Validated but not activated. Nothing is reachable.
    Loaded,
    /// `activate`, `handle-event` and `invoke-tool`. The full grant set is
    /// reachable.
    Active,
    /// `deactivate`. Only [`LifecyclePhase::CLEANUP`] is reachable.
    Deactivating,
    /// Deactivated. Nothing is reachable.
    Inactive,
}

impl LifecyclePhase {
    /// The only capabilities a plugin may still use while it is shutting down.
    ///
    /// `log` lets a plugin report why it stopped and `store` lets it persist
    /// its own quota-bounded, plugin-scoped state. Everything with outward
    /// reach - the filesystem, the network, tool registration, event
    /// publication, configuration, the clock and randomness - is already
    /// revoked by the time `deactivate` is entered.
    pub const CLEANUP: [Capability; 2] = [Capability::Log, Capability::Store];

    /// Stable, machine-readable name.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Starting => "starting",
            Self::Loaded => "loaded",
            Self::Active => "active",
            Self::Deactivating => "deactivating",
            Self::Inactive => "inactive",
        }
    }

    /// Whether `capability` may be exercised in this phase.
    #[must_use]
    pub const fn permits(self, capability: Capability) -> bool {
        match self {
            Self::Active => true,
            Self::Deactivating => matches!(capability, Capability::Log | Capability::Store),
            Self::Starting | Self::Loaded | Self::Inactive => false,
        }
    }
}

/// Per-instance host state. One of these lives in each plugin's own
/// [`wasmtime::Store`], which is what keeps plugins isolated from one another.
pub struct PluginState {
    plugin_id: String,
    capabilities: CapabilitySet,
    limits: ResourceLimits,
    services: HostServices,
    shared_gate: HostCallGate,
    instance_gate: HostCallGate,
    policy: ViolationPolicy,
    phase: LifecyclePhase,
    read_roots: Vec<PathBuf>,
    write_roots: Vec<PathBuf>,
    limiter: InstanceLimiter,
    denials: Vec<CapabilityDenial>,
    registered_tools: BTreeSet<String>,
    dropped_denials: u64,
    sequence: u64,
    deadline: Option<Instant>,
}

impl core::fmt::Debug for PluginState {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("PluginState")
            .field("plugin_id", &self.plugin_id)
            .field("capabilities", &self.capabilities)
            .field("phase", &self.phase)
            .field("policy", &self.policy)
            .field("denials", &self.denials.len())
            .finish_non_exhaustive()
    }
}

/// Everything an instance needs before its first host call.
pub(crate) struct PluginStateConfig {
    /// The plugin identity host calls are attributed to.
    pub(crate) plugin_id: String,
    /// The capabilities granted by the manifest and the trust policy.
    pub(crate) capabilities: CapabilitySet,
    /// The resource ceilings for this instance.
    pub(crate) limits: ResourceLimits,
    /// The host services capability checks are allowed to reach.
    pub(crate) services: HostServices,
    /// The host-wide concurrency gate shared with every other plugin.
    pub(crate) shared_gate: HostCallGate,
    /// What a refused host call does to the guest.
    pub(crate) policy: ViolationPolicy,
    /// Canonical roots readable through `host-fs`.
    pub(crate) read_roots: Vec<PathBuf>,
    /// Canonical roots writable through `host-fs`.
    pub(crate) write_roots: Vec<PathBuf>,
}

impl PluginState {
    pub(crate) fn new(config: PluginStateConfig) -> Self {
        let PluginStateConfig {
            plugin_id,
            capabilities,
            limits,
            services,
            shared_gate,
            policy,
            read_roots,
            write_roots,
        } = config;
        let instance_gate = HostCallGate::new(limits.max_host_call_concurrency);
        Self {
            plugin_id,
            capabilities,
            limits,
            services,
            shared_gate,
            instance_gate,
            policy,
            // An instance is created before its component is instantiated, and
            // the start function runs inside that window, so the closed phase
            // has to be the initial value rather than something the caller
            // opts into.
            phase: LifecyclePhase::Starting,
            read_roots,
            write_roots,
            limiter: InstanceLimiter::new(limits),
            denials: Vec::new(),
            registered_tools: BTreeSet::new(),
            dropped_denials: 0,
            sequence: 0,
            deadline: None,
        }
    }

    /// The plugin this state belongs to.
    #[must_use]
    pub fn plugin_id(&self) -> &str {
        &self.plugin_id
    }

    /// The capabilities this instance was granted.
    ///
    /// This is the operator ceiling intersected with the manifest's requests,
    /// never the manifest's requests alone.
    #[must_use]
    pub const fn capabilities(&self) -> &CapabilitySet {
        &self.capabilities
    }

    /// Which part of the lifecycle this instance is currently executing.
    #[must_use]
    pub const fn phase(&self) -> LifecyclePhase {
        self.phase
    }

    /// The tools this instance currently has registered, sorted.
    #[must_use]
    pub fn registered_tools(&self) -> Vec<String> {
        self.registered_tools.iter().cloned().collect()
    }

    pub(crate) const fn set_phase(&mut self, phase: LifecyclePhase) {
        self.phase = phase;
    }

    pub(crate) fn note_tool_registered(&mut self, name: String) {
        self.registered_tools.insert(name);
    }

    pub(crate) fn note_tool_unregistered(&mut self, name: &str) {
        self.registered_tools.remove(name);
    }

    pub(crate) fn take_registered_tools(&mut self) -> Vec<String> {
        core::mem::take(&mut self.registered_tools)
            .into_iter()
            .collect()
    }

    /// The refused host calls recorded so far, oldest first.
    #[must_use]
    pub fn denials(&self) -> &[CapabilityDenial] {
        &self.denials
    }

    /// How many denials were dropped because the audit buffer was full.
    #[must_use]
    pub const fn dropped_denials(&self) -> u64 {
        self.dropped_denials
    }

    /// Highest linear-memory size this instance ever reached, in bytes.
    #[must_use]
    pub const fn peak_memory_bytes(&self) -> usize {
        self.limiter.peak_memory_bytes()
    }

    /// Whether a memory growth request was refused by the limiter.
    #[must_use]
    pub const fn hit_memory_ceiling(&self) -> bool {
        self.limiter.hit_memory_ceiling()
    }

    /// Whether a table growth request was refused by the limiter.
    #[must_use]
    pub const fn hit_table_ceiling(&self) -> bool {
        self.limiter.hit_table_ceiling()
    }

    pub(crate) const fn limiter_mut(&mut self) -> &mut InstanceLimiter {
        &mut self.limiter
    }

    pub(crate) const fn limits(&self) -> &ResourceLimits {
        &self.limits
    }

    pub(crate) const fn services(&self) -> &HostServices {
        &self.services
    }

    pub(crate) fn read_roots(&self) -> &[PathBuf] {
        &self.read_roots
    }

    pub(crate) fn write_roots(&self) -> &[PathBuf] {
        &self.write_roots
    }

    pub(crate) fn set_deadline(&mut self, deadline: Option<Instant>) {
        self.deadline = deadline;
    }

    pub(crate) fn next_sequence(&mut self) -> u64 {
        self.sequence = self.sequence.saturating_add(1);
        self.sequence
    }

    /// Opens a host call: checks the lifecycle phase, the grant, the deadline
    /// and the concurrency gate before any effect is reachable.
    pub(crate) fn enter(
        &mut self,
        capability: Capability,
        operation: &'static str,
    ) -> Result<HostCallPermits, CapabilityDenial> {
        // The phase is checked first and independently of the grant set, so a
        // capability that was granted for the active window is still refused
        // outside it. This is what keeps a component start function, a
        // `describe` call and a `deactivate` call from reaching host effects.
        if !self.phase.permits(capability) {
            return Err(CapabilityDenial::wrong_phase(
                capability,
                operation,
                format!(
                    "capability `{capability}` is not reachable while this plugin is `{}`",
                    self.phase.as_str()
                ),
            ));
        }
        if !self.capabilities.contains(capability) {
            return Err(CapabilityDenial::not_granted(capability, operation));
        }
        if let Some(deadline) = self.deadline
            && Instant::now() >= deadline
        {
            return Err(CapabilityDenial::quota_exceeded(
                capability,
                operation,
                "the wall-clock budget for this call is already exhausted",
            ));
        }
        let shared = self.shared_gate.try_acquire().ok_or_else(|| {
            CapabilityDenial::quota_exceeded(
                capability,
                operation,
                format!(
                    "at most {} host calls may run at once across this host",
                    self.shared_gate.max()
                ),
            )
        })?;
        let instance = self.instance_gate.try_acquire().ok_or_else(|| {
            CapabilityDenial::quota_exceeded(
                capability,
                operation,
                format!(
                    "at most {} host calls may run at once for this plugin",
                    self.instance_gate.max()
                ),
            )
        })?;
        Ok(HostCallPermits::new(shared, instance))
    }

    pub(crate) fn record(&mut self, denial: CapabilityDenial) {
        if self.denials.len() >= MAX_AUDIT_ENTRIES {
            self.denials.remove(0);
            self.dropped_denials = self.dropped_denials.saturating_add(1);
        }
        self.denials.push(denial);
    }

    /// Records a refused call and turns it into the guest-visible outcome that
    /// the configured [`ViolationPolicy`] demands.
    pub(crate) fn deny<T>(
        &mut self,
        denial: CapabilityDenial,
    ) -> wasmtime::Result<Result<T, WitError>> {
        let message = denial.to_string();
        self.record(denial);
        match self.policy {
            ViolationPolicy::ReturnError => Ok(Err(WitError {
                code: ErrorCode::PermissionDenied,
                message,
            })),
            ViolationPolicy::Trap => Err(wasmtime::Error::msg(message)),
        }
    }
}

/// Builds a non-capability host failure.
pub(crate) fn wit_error(code: ErrorCode, message: impl Into<String>) -> WitError {
    WitError {
        code,
        message: message.into(),
    }
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeSet;

    use claw_plugin_api::capability::{
        Capability, CapabilityGrant, CapabilitySet, DenialReason, EventKind, EventsGrant, LogGrant,
        LogLevel,
    };
    use claw_plugin_api::limits::ResourceLimits;

    use super::{
        LifecyclePhase, MAX_AUDIT_ENTRIES, PluginState, PluginStateConfig, ViolationPolicy,
    };
    use crate::bindings::gta_claw::plugin::types::ErrorCode;
    use crate::limiter::HostCallGate;
    use crate::services::HostServices;

    fn state_with_limits(
        policy: ViolationPolicy,
        gate: HostCallGate,
        limits: ResourceLimits,
    ) -> PluginState {
        let capabilities = CapabilitySet::new([
            CapabilityGrant::Log(LogGrant {
                min_level: LogLevel::Info,
                max_message_bytes: 128,
            }),
            CapabilityGrant::Events(EventsGrant {
                emit_kinds: BTreeSet::from([EventKind::Heartbeat]),
                max_payload_bytes: 128,
            }),
        ])
        .expect("valid grants");
        let mut state = PluginState::new(PluginStateConfig {
            plugin_id: "fixture".to_owned(),
            capabilities,
            limits,
            services: HostServices::deny_all(),
            shared_gate: gate,
            policy,
            read_roots: Vec::new(),
            write_roots: Vec::new(),
        });
        // These tests are about the grant, deadline and gate checks, all of
        // which sit behind the phase check, so the instance is put in the one
        // phase that lets a call through. `the_phase_gate_*` tests below cover
        // the phase check itself.
        state.set_phase(LifecyclePhase::Active);
        state
    }

    fn state(policy: ViolationPolicy, gate: HostCallGate) -> PluginState {
        state_with_limits(policy, gate, ResourceLimits::default())
    }

    #[test]
    fn entering_an_ungranted_capability_is_refused_without_taking_a_slot() {
        let gate = HostCallGate::new(4);
        let mut state = state(ViolationPolicy::ReturnError, gate.clone());
        let denial = state
            .enter(Capability::Http, "send")
            .expect_err("http was never granted");
        assert_eq!(denial.capability(), Capability::Http);
        assert_eq!(denial.operation(), "send");
        assert_eq!(denial.reason(), &DenialReason::NotGranted);
        assert_eq!(gate.in_flight(), 0);
    }

    #[test]
    fn a_granted_capability_is_still_refused_outside_the_active_window() {
        let gate = HostCallGate::new(4);
        let mut state = state(ViolationPolicy::ReturnError, gate.clone());
        // `log` is unambiguously granted; only the phase changes below.
        assert!(state.capabilities().contains(Capability::Log));
        for phase in [
            LifecyclePhase::Starting,
            LifecyclePhase::Loaded,
            LifecyclePhase::Inactive,
        ] {
            state.set_phase(phase);
            let denial = state
                .enter(Capability::Log, "log")
                .expect_err("no host effect is reachable outside the active window");
            assert_eq!(denial.capability(), Capability::Log);
            assert_eq!(
                denial.reason(),
                &DenialReason::WrongPhase(format!(
                    "capability `log` is not reachable while this plugin is `{}`",
                    phase.as_str()
                ))
            );
            assert_eq!(gate.in_flight(), 0, "a refused call must not take a slot");
        }
        state.set_phase(LifecyclePhase::Active);
        let permit = state.enter(Capability::Log, "log").expect("active permits");
        assert_eq!(gate.in_flight(), 1);
        drop(permit);
    }

    #[test]
    fn deactivation_permits_only_the_cleanup_capabilities() {
        let gate = HostCallGate::new(4);
        let mut state = state(ViolationPolicy::ReturnError, gate);
        state.set_phase(LifecyclePhase::Deactivating);

        let permit = state
            .enter(Capability::Log, "log")
            .expect("log is a cleanup capability");
        drop(permit);

        // `events` is granted to this fixture and is deliberately not in the
        // cleanup set, so the refusal can only come from the phase.
        assert!(state.capabilities().contains(Capability::Events));
        let denial = state
            .enter(Capability::Events, "emit")
            .expect_err("publishing is not cleanup");
        assert_eq!(
            denial.reason(),
            &DenialReason::WrongPhase(
                "capability `events` is not reachable while this plugin is `deactivating`"
                    .to_owned()
            )
        );
    }

    #[test]
    fn the_cleanup_set_is_exactly_log_and_store() {
        for capability in [
            Capability::Clock,
            Capability::Config,
            Capability::Events,
            Capability::FilesystemRead,
            Capability::FilesystemWrite,
            Capability::Http,
            Capability::Log,
            Capability::Random,
            Capability::Store,
            Capability::Tools,
        ] {
            let expected = capability == Capability::Log || capability == Capability::Store;
            assert_eq!(
                LifecyclePhase::Deactivating.permits(capability),
                expected,
                "`{capability}` is on the wrong side of the cleanup set"
            );
            assert_eq!(
                LifecyclePhase::CLEANUP.contains(&capability),
                expected,
                "`{capability}` disagrees with the documented cleanup constant"
            );
        }
    }

    #[test]
    fn the_default_phase_reaches_nothing() {
        assert_eq!(LifecyclePhase::default(), LifecyclePhase::Starting);
        for capability in [
            Capability::Clock,
            Capability::Config,
            Capability::Events,
            Capability::FilesystemRead,
            Capability::FilesystemWrite,
            Capability::Http,
            Capability::Log,
            Capability::Random,
            Capability::Store,
            Capability::Tools,
        ] {
            for phase in [
                LifecyclePhase::Starting,
                LifecyclePhase::Loaded,
                LifecyclePhase::Inactive,
            ] {
                assert!(
                    !phase.permits(capability),
                    "`{capability}` must not be reachable while `{}`",
                    phase.as_str()
                );
            }
            assert!(
                LifecyclePhase::Active.permits(capability),
                "`{capability}` must be reachable while active"
            );
        }
    }

    #[test]
    fn entering_a_granted_capability_takes_and_returns_a_host_wide_slot() {
        let gate = HostCallGate::new(1);
        let mut state = state(ViolationPolicy::ReturnError, gate.clone());
        let permit = state.enter(Capability::Log, "log").expect("granted");
        assert_eq!(gate.in_flight(), 1);
        let denial = state
            .enter(Capability::Events, "emit")
            .expect_err("the host-wide gate is full");
        assert_eq!(
            denial.reason(),
            &DenialReason::QuotaExceeded(
                "at most 1 host calls may run at once across this host".to_owned()
            )
        );
        drop(permit);
        assert_eq!(gate.in_flight(), 0);
        assert!(state.enter(Capability::Events, "emit").is_ok());
    }

    #[test]
    fn the_per_plugin_gate_binds_even_when_the_host_gate_is_wide_open() {
        let gate = HostCallGate::new(64);
        let limits = ResourceLimits {
            max_host_call_concurrency: 1,
            ..ResourceLimits::default()
        };
        let mut state = state_with_limits(ViolationPolicy::ReturnError, gate.clone(), limits);
        let permit = state.enter(Capability::Log, "log").expect("granted");
        assert_eq!(gate.in_flight(), 1);
        let denial = state
            .enter(Capability::Events, "emit")
            .expect_err("the per-plugin gate is full");
        assert_eq!(
            denial.reason(),
            &DenialReason::QuotaExceeded(
                "at most 1 host calls may run at once for this plugin".to_owned()
            )
        );
        // The host-wide slot taken by the refused call must have been released.
        assert_eq!(gate.in_flight(), 1);
        drop(permit);
        assert_eq!(gate.in_flight(), 0);
    }

    #[test]
    fn a_denial_under_the_return_policy_produces_permission_denied() {
        let mut state = state(ViolationPolicy::ReturnError, HostCallGate::new(2));
        let denial = state
            .enter(Capability::Store, "get")
            .expect_err("ungranted");
        let outcome: Result<u32, _> = state.deny(denial).expect("no trap");
        let error = outcome.expect_err("permission denied");
        assert_eq!(error.code, ErrorCode::PermissionDenied);
        assert_eq!(
            error.message,
            "`get` requires capability `store`, which is not granted"
        );
        assert_eq!(state.denials().len(), 1);
        assert_eq!(state.denials()[0].capability(), Capability::Store);
    }

    #[test]
    fn a_denial_under_the_trap_policy_produces_a_trap_and_is_still_audited() {
        let mut state = state(ViolationPolicy::Trap, HostCallGate::new(2));
        let denial = state
            .enter(Capability::FilesystemRead, "read-file")
            .expect_err("ungranted");
        let outcome: wasmtime::Result<Result<u32, _>> = state.deny(denial);
        let trap = outcome.expect_err("the instance must trap");
        assert_eq!(
            trap.to_string(),
            "`read-file` requires capability `filesystem-read`, which is not granted"
        );
        assert_eq!(state.denials().len(), 1);
        assert_eq!(state.denials()[0].capability(), Capability::FilesystemRead);
    }

    #[test]
    fn the_audit_buffer_is_bounded_and_counts_what_it_dropped() {
        let mut state = state(ViolationPolicy::ReturnError, HostCallGate::new(2));
        for _ in 0..(MAX_AUDIT_ENTRIES + 5) {
            let denial = state
                .enter(Capability::Clock, "now-ms")
                .expect_err("ungranted");
            state.record(denial);
        }
        assert_eq!(state.denials().len(), MAX_AUDIT_ENTRIES);
        assert_eq!(state.dropped_denials(), 5);
    }

    #[test]
    fn sequence_numbers_are_monotonic_from_one() {
        let mut state = state(ViolationPolicy::ReturnError, HostCallGate::new(2));
        assert_eq!(state.next_sequence(), 1);
        assert_eq!(state.next_sequence(), 2);
        assert_eq!(state.next_sequence(), 3);
    }

    #[test]
    fn an_expired_deadline_refuses_even_a_granted_capability() {
        let mut state = state(ViolationPolicy::ReturnError, HostCallGate::new(2));
        state.set_deadline(Some(
            std::time::Instant::now() - std::time::Duration::from_millis(1),
        ));
        let denial = state.enter(Capability::Log, "log").expect_err("expired");
        assert_eq!(denial.capability(), Capability::Log);
        assert_eq!(
            denial.reason(),
            &DenialReason::QuotaExceeded(
                "the wall-clock budget for this call is already exhausted".to_owned()
            )
        );
    }
}

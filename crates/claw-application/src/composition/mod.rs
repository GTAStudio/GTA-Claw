//! The composition layer: how a running GTA Claw daemon is assembled from ports.
//!
//! Every subsystem of GTA Claw lives in its own crate and is delivered by its own
//! team. This module is the seam that lets those crates be plugged together
//! without any of them knowing about each other. It owns three things:
//!
//! 1. the [`Subsystem`] lifecycle and the [`CompositionPlan`] that orders it,
//! 2. the port traits each subsystem crate must implement, and
//! 3. the two safety mechanisms described below, which are structural rather
//!    than advisory.
//!
//! # Rule 1: authorization is never reused
//!
//! Audits of four sibling crates found the same defect four times: a security
//! decision taken once and then reused for every later action. A grant whose
//! expiry was compared against the timestamp captured when it was minted, a
//! capability installed before instantiation and left live through teardown, a
//! connection authorized at handshake and trusted for the rest of its life.
//!
//! The composition layer makes that shape unrepresentable. A privileged action
//! consumes a [`Grant<T>`], and a `Grant` can only be produced by
//! [`GrantIssuer::issue`], which calls [`AuthorityPort::authorize`] at that
//! moment. `Grant` is neither `Clone` nor `Copy`, [`Grant::redeem`] takes
//! `self` by value, and redemption re-checks the expiry against the clock
//! reading taken at redemption time and against the current [`RunEpoch`]. A
//! grant minted while the daemon was running is dead the instant the daemon
//! begins draining, so no capability survives teardown.
//!
//! Because the port returns an [`Authorization`] and not a `Grant`, a subsystem
//! that implements `AuthorityPort` cannot mint a long-lived capability even if
//! it wants to. Minting is the composition layer's privilege alone.
//!
//! # Rule 2: validated objects cross boundaries, never names
//!
//! The same audits found three separate server-side request forgery bugs with
//! one shared cause: code validated a *name*, then performed the action against
//! the name a second time, re-resolving it and losing the validation.
//!
//! Nothing in this layer accepts a re-resolvable identifier for a privileged
//! action. A destination is parsed and checked exactly once by
//! [`EgressGuard::resolve`], which returns a [`ResolvedEndpoint`] carrying the
//! concrete [`IpAddr`](std::net::IpAddr) values that were checked. Transports
//! connect to those addresses; they never receive the hostname as something to
//! look up again, so a second DNS answer cannot change where the bytes go.
//! [`ProviderBinding`], [`ToolBinding`] and [`ResolvedSession`] play the same
//! role for providers, tools and sessions.
//!
//! # Dependency direction
//!
//! This module depends on no async runtime. Futures cross ports as
//! [`BoxFuture`], and everything a runtime would supply — spawning, cancellation
//! and time — is itself a port ([`TaskSpawner`], [`ShutdownSignal`], [`Clock`]).
//! `apps/gta-claw-daemon` supplies the tokio implementations.

use std::future::Future;
use std::pin::Pin;

pub mod authority;
pub mod clock;
pub mod egress;
pub mod error;
pub mod graph;
pub mod host;
pub mod id;
pub mod lifecycle;
pub mod ports;
pub mod service;
pub mod session;
pub mod subsystem;

pub use authority::{
    Action, ActionRequest, AuthorityPort, Authorization, CapabilityAuthority, Denial, Grant,
    GrantIssuer, GrantReceipt, GrantSerial, Principal,
};
pub use clock::{Clock, MonotonicInstant, ProcessClock};
pub use egress::{
    DEFAULT_MAX_RESOLUTION_AGE, DnsPort, EgressDenial, EgressGuard, EgressPolicy, EndpointRequest,
    HostPattern, RedactedUrl, ResolvedEndpoint, Scheme,
};
pub use error::{CompositionError, SubsystemError, SubsystemErrorKind};
pub use graph::CompositionPlan;
pub use host::{ShutdownReport, SubsystemHost};
pub use id::{SubsystemId, well_known};
pub use lifecycle::{EpochGate, Lifecycle, LifecyclePhase, PhaseTransitionError, RunEpoch};
pub use ports::{
    AutomationPort, BridgePort, ChannelPort, ConfigPort, ContextAssemblyPort, CredentialRequest,
    GatewayDispatch, GatewayPort, HttpApiPort, HttpRoute, ObservabilityPort, PersistencePort,
    PersistenceTransaction, PluginHostPort, ProviderRegistryPort, ProviderTransportPort,
    SecretStorePort, SecretTransaction, SessionEnginePort, ToolSurfacePort, TurnEventSink,
};
pub use service::{
    DiscardEvents, METHOD_SESSION_DESCRIBE, METHOD_SESSION_PROMPT, SessionService,
    SessionServiceBuilder, TurnCapabilities, TurnReport,
};
pub use session::{
    AssembledContext, Capability, CapabilitySet, CredentialLease, CredentialName, GatewayRequest,
    GatewayResponse, InvalidName, ModelName, ObservedEvent, PluginActivation, PluginInstance,
    ProviderBinding, ProviderCall, ProviderName, ProviderReply, ResolvedSession, RuntimeSettings,
    SessionRecord, Severity, ToolBinding, ToolCall, ToolName, ToolOutcome, ToolRequest, TurnEvent,
    TurnRecord, TurnRequest, TurnSummary,
};
pub use subsystem::{
    DrainReport, ServiceHandle, StartContext, Subsystem, SubsystemDescriptor, SubsystemKind,
    TaskSpawner,
};

/// A boxed future returned across a composition port.
///
/// Ports are used as trait objects so the daemon can hold a heterogeneous set of
/// subsystems, which rules out `async fn` in traits. Every port method returns
/// this alias instead.
pub type BoxFuture<'a, T> = Pin<Box<dyn Future<Output = T> + Send + 'a>>;

/// A signal that the daemon has been asked to stop.
///
/// The daemon implements this over a `tokio_util::sync::CancellationToken`;
/// tests implement it over a plain flag. Subsystems must treat a triggered
/// signal as a request to stop accepting new work, not as permission to abandon
/// work already in flight — draining is driven separately by
/// [`Subsystem::drain`].
pub trait ShutdownSignal: Send + Sync + 'static {
    /// Returns whether shutdown has already been requested.
    fn is_triggered(&self) -> bool;

    /// Resolves once shutdown has been requested.
    ///
    /// Resolves immediately when shutdown was requested before this was called.
    fn triggered(&self) -> BoxFuture<'_, ()>;
}

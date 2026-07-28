//! A Wasmtime Component Model host for GTA-Claw plugins.
//!
//! # Threat model
//!
//! A plugin is hostile until proven otherwise. The host therefore assumes the
//! guest will try to read files it was not given, reach the network, measure
//! time precisely enough to build a side channel, exhaust memory or CPU, or
//! take the process down with it. Every one of those is addressed structurally
//! rather than by convention:
//!
//! * **No ambient authority.** The linker built by [`PluginEngine`] contains
//!   exactly the nine interfaces of `gta-claw:plugin@1.0.0`. There is no WASI
//!   of any kind - the `wasmtime` dependency is compiled without the WASI
//!   crates at all - so there is no ambient filesystem, process, socket,
//!   environment or high-resolution clock. On top of that, the host refuses to
//!   even instantiate a component whose imports are not on [`ALLOWED_IMPORTS`].
//! * **Capabilities are per plugin and enforced at the boundary.** Imports are
//!   always *linked*, but every host function first proves the calling plugin
//!   holds the capability and that the concrete arguments are inside the
//!   grant's scope. A plugin with `filesystem-read` on one root still cannot
//!   read another.
//! * **Resource limits are enforced by the engine, not by the guest.** Fuel
//!   bounds instructions, an epoch ticker bounds wall-clock time, a
//!   [`wasmtime::ResourceLimiter`] bounds memory, tables and instances, and a
//!   bounded gate caps how many host calls may run at once.
//! * **Crash isolation.** Every plugin owns its own [`wasmtime::Store`]. A
//!   trap destroys that store and marks that plugin faulted; no other plugin
//!   and no host state is touched.
//!
//! # What is *not* here
//!
//! This crate is the host and the ABI. It does not contain ports of the 137
//! upstream plugins in the frozen inventory - see
//! [`claw_plugin_api::registry`], where every descriptor is honestly reported
//! as [`claw_plugin_api::registry::ImplementationStatus::RegistrationOnly`].
//! [`describe_registry`] renders that state so an operator can see it without
//! reading the source, and [`describe_compatibility`] renders the per-contract
//! install and compatibility decisions behind it.

pub(crate) mod bindings;
pub mod convert;
pub mod engine;
pub mod error;
pub mod host_impl;
pub mod http;
pub mod inventory;
pub mod lifecycle;
pub mod limiter;
pub mod services;
pub mod state;

pub use claw_plugin_api::cancellation::CancellationToken;
pub use engine::{EPOCH_TICK, PluginEngine};
pub use error::{GuestFailure, HostError, TerminationCause};
pub use http::{
    PinnedHttpError, PinnedHttpTransport, PinnedHttpTransportBuildError, PinnedHttpTransportConfig,
};
pub use inventory::{
    CompatibilityReport, DeliveryClassSummary, RegistryReport, describe_compatibility,
    describe_registry,
};
pub use lifecycle::{
    ALLOWED_IMPORTS, ActivatedPlugin, ActivationControl, ActivationControlError, ActivationFailure,
    ActivationOutcome, ActivationReport, ActivationStage, ControlledActivationOutcome,
    ControlledActivationReport, Discovered, DiscoveryRecord, DiscoveryStage, DisposalOutcome,
    DisposalReport, EventOutcome, LifecycleState, MANIFEST_FILE_NAME, MAX_ACTIVATION_CANDIDATES,
    PluginHost, PluginHostBuilder, PluginToolInvocation, ResourceUsage,
};
pub use limiter::{HostCallGate, HostCallPermit, HostCallPermits};
pub use services::{
    Clock, ConfigProvider, DenyAllHttp, DiscardEvents, DiscardLogs, DiscardTools, EmptyConfig,
    EventSink, FixedClock, HostCallControl, HostCallStop, HostEvent, HostServices, HttpTransport,
    InMemoryConfig, InMemoryStore, InboundResponse, LogRecord, LogSink, NullStore, OsRandom,
    OutboundRequest, RandomSource, RecordingSink, StoreBackend, SystemClock, ToolRegistration,
    ToolSink, UnavailableRandom,
};
pub use state::{PluginState, ViolationPolicy};

/// The ABI version this host implements.
pub const HOST_ABI_VERSION: claw_plugin_api::abi::Version = claw_plugin_api::abi::ABI_VERSION;

/// The WIT world text this host was generated from.
pub const WIT_WORLD: &str = claw_plugin_api::WIT_WORLD;

#[cfg(test)]
mod tests {
    use super::{HOST_ABI_VERSION, WIT_WORLD};

    #[test]
    fn the_host_implements_the_contract_crate_abi_version() {
        assert_eq!(HOST_ABI_VERSION, claw_plugin_api::abi::ABI_VERSION);
        assert_eq!(HOST_ABI_VERSION.major, 1);
        assert_eq!(HOST_ABI_VERSION.minor, 0);
        assert_eq!(HOST_ABI_VERSION.patch, 0);
    }

    #[test]
    fn the_host_and_the_contract_crate_share_one_wit_world() {
        assert_eq!(WIT_WORLD, claw_plugin_api::WIT_WORLD);
        assert!(WIT_WORLD.contains("package gta-claw:plugin@1.0.0;"));
    }
}

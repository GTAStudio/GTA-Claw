//! UI-independent iOS client core for GTA Claw.
//!
//! # There is no iOS user interface in this crate, and that is deliberate
//!
//! This crate contains no Slint code, no `include_modules!`, and no binary
//! target. The base-owned trusted supply-chain policy in
//! `.github/trusted/desktop-supply-chain-policy` refuses a Slint dependency
//! anywhere a root workspace member can put it:
//!
//! * `FORBIDDEN_GUI_NAMES` bans `slint`, `slint-build` and `winit` in every
//!   dependency table of every root member, including `[target.'cfg(...)']`
//!   tables and `package = "..."` renames, and additionally bans them by name
//!   in the root `Cargo.lock`.
//! * A separate excluded workspace is not available either: `workspace.exclude`
//!   is pinned to exactly `["desktop"]`, the lockfile inventory is pinned to
//!   exactly three paths, and the manifest inventory is pinned to the root
//!   members plus the desktop and trusted manifests.
//! * The trusted policy validates each root member manifest separately. This
//!   iOS member must use `[lints] workspace = true`, so it inherits the root
//!   `unsafe_code = "forbid"`. Exceptions are explicit, path/package-bound
//!   audited policy, currently including `claw-config`'s generated-code lint
//!   table with `unsafe_code = "deny"`; they do not make the root lint table
//!   authoritative for every member. Slint's generated item-tree macros need a
//!   local `allow(unsafe_code)`, which this member's `forbid` cannot grant. The
//!   `desktop/` workspace uses `deny` instead of `forbid` for precisely this
//!   reason and says so in its own manifest comment.
//!
//! Lifting those three restrictions is a change to `.github/trusted/**`, which
//! is byte-frozen and cannot authorise itself. Until that lands, the honest
//! shape of an iOS client in this repository is the part below the UI.
//!
//! # What this crate does provide
//!
//! Everything an iOS Slint front end would sit on top of:
//!
//! * [`GatewayEndpoint`] — user-entered endpoint intake that rejects
//!   credential-bearing URLs, unsupported schemes, and remote plaintext
//!   WebSocket endpoints before any network operation.
//! * [`IosCredential`] — bounded credential intake with a redacting `Debug`.
//! * [`IosClientIdentity`] — Gateway v4 client metadata for
//!   [`ClientId::Ios`](claw_protocol::gateway::ClientId::Ios), built from an
//!   observation port rather than from guesses.
//! * [`IosGatewayProfile`] — assembles a
//!   [`GatewayClientConfig`](claw_gateway_client::GatewayClientConfig) that
//!   `claw-gateway-client` accepts, with explicit bounded mobile timeouts and
//!   retries from [`IosConnectionPolicy`].
//! * [`IosSessionModel`] — foreground/background and network-path coordination,
//!   generation-scoped transport observations, and a cached revisioned
//!   [`IosViewSnapshot`] a UI can bind to, with authorization reported *only*
//!   from what the server actually confirmed.
//! * [`HostAppDeclarations`] — the `Info.plist` declarations local-network
//!   discovery depends on, plus structured [`DiscoveryDiagnostic`] recovery
//!   actions, so a missing declaration is reported rather than rendered as an
//!   empty result set.
//! * [`HostCredentialStore`] and [`HostDiscoveryProvider`] — validated ports a
//!   future host application can implement with Keychain and system DNS-SD
//!   without putting Apple-framework or unsafe code in this crate.
//! * [`ClientTransport`] — a written record of which Gateway transports iOS can
//!   carry and, for those it cannot, why.
//!
//! # Recorded platform gaps
//!
//! Three surfaces in the frozen upstream contract have no working iOS form in
//! this crate, and each is recorded rather than substituted:
//!
//! * **Bonjour and DNS-SD discovery** needs `NSLocalNetworkUsageDescription`
//!   and `NSBonjourServices` in the host application bundle. This crate cannot
//!   read the bundle, so [`HostAppDeclarations`] treats an unconfirmed
//!   declaration exactly as strictly as a missing one. The provider port exists;
//!   no DNS-SD implementation does.
//! * **Tailscale** needs an app-accessible `LocalAPI` Unix socket or a loopback
//!   proxy, which a stock sandboxed iOS deployment may expose neither of. No
//!   alternative transport is offered in its place.
//! * **SSH** needs caller-provisioned sandbox paths for key material and
//!   `known_hosts`. The protected-storage port exists, but there is no Keychain
//!   or Secure Enclave implementation here and no plaintext fallback.
//!
//! # Composition
//!
//! The crate composes against the ports that exist. `claw_application` exports
//! exactly one port, [`SystemProbe`](claw_application::SystemProbe); there is no
//! `claw_application::composition` module in this workspace. [`IosClientCore`]
//! holds an [`Application`](claw_application::Application) over that port and
//! uses `claw_platform`'s adapter, rather than reaching into subsystem crates
//! for runtime identity.
//!
//! # What has and has not been executed
//!
//! The Rust core has been built and tested as a macOS arm64 host binary. It has
//! never built or run for an iOS target, simulator, or device, and it has never
//! completed a Gateway handshake against a real server. Device and simulator
//! target checks stop in `ring` — a mandatory transitive dependency of
//! `claw-gateway-client` — because the available Command Line Tools installation
//! has no iPhoneOS or iPhoneSimulator SDK. See the crate README for exact checks.

mod connection_policy;
mod credential;
mod device;
mod endpoint;
mod host_app;
mod host_facilities;
mod identity;
mod profile;
mod session;
mod transport;

pub use connection_policy::{
    ConnectionPolicyError, IosConnectionPolicy, IosRetryPolicy, IosTimeoutPolicy,
};
pub use credential::{CredentialError, IosCredential, IosCredentialKind};
pub use device::{DeclaredDeviceProbe, IosDeviceProbe, UnobservedDeviceProbe};
pub use endpoint::{EndpointError, EndpointSummary, GatewayEndpoint};
pub use host_app::{
    AppRunState, BonjourServiceType, DeclarationStatus, DiscoveryDiagnostic, DiscoveryMechanism,
    DiscoveryPermit, DiscoveryRemediation, DiscoveryUnavailable, EmptyResultDiagnosis,
    EntitlementStatus, GatewayMdnsBackend, HostAppDeclaration, HostAppDeclarations,
    HostAppEntitlement, LocalDiscoveryBackend, LocalNetworkPrivacy, ServiceTypeError,
    diagnose_empty_result,
};
pub use host_facilities::{
    CredentialKey, CredentialKeyError, DiscoveredGateway, DiscoveryCompletion, DiscoveryEvent,
    DiscoveryEventSink, DiscoveryRequest, DiscoveryScanPolicy, DiscoveryScanPolicyError,
    DiscoveryStartBlocked, HostCredentialError, HostCredentialStore, HostDiscoveryProvider,
    HostDiscoverySession, PersistedCredentialKind, delete_host_credential, load_host_credential,
    save_host_credential,
};
pub use identity::{IdentityError, IosClientIdentity};
pub use profile::{IosClientCore, IosGatewayProfile};
pub use session::{
    AttemptRejected, AuthorizationDenied, AuthorizedAction, ConnectionAttempt, IosAction,
    IosNetworkInterface, IosNetworkPath, IosNetworkRoute, IosSessionModel, IosStatusKind,
    IosViewSnapshot, ObservationResult, ObservedAuthorization, TransportDirective,
    TransportResumeReason, TransportStopReason,
};
pub use transport::{ClientTransport, IosTransportRecord, IosTransportStatus};

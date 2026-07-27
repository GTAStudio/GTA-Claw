//! Ports for facilities that only an iOS host application can provide.
//!
//! This crate does not call Keychain, Network.framework, or DNS-SD APIs. A
//! future Swift or audited platform adapter implements these traits while this
//! module keeps validation, redaction, lifecycle gating, and resource bounds in
//! the UI-independent core.

use std::error::Error;
use std::fmt::{self, Debug, Display, Formatter};
use std::sync::Arc;
use std::time::Duration;

use secrecy::SecretString;

use crate::credential::{CredentialError, IosCredential, IosCredentialKind};
use crate::endpoint::{EndpointSummary, GatewayEndpoint};
use crate::host_app::{
    AppRunState, DiscoveryDiagnostic, DiscoveryPermit, DiscoveryRemediation, LocalDiscoveryBackend,
};
use crate::session::{IosNetworkInterface, IosNetworkPath, IosNetworkRoute};

const MAX_CREDENTIAL_KEY_BYTES: usize = 256;
const MAX_DISCOVERY_TIMEOUT: Duration = Duration::from_secs(15);
const MAX_DISCOVERY_RESULTS: usize = 64;

/// Opaque account identity used by a host-provided credential store.
///
/// The value is intentionally redacted in [`Debug`]. Keychain account names can
/// contain endpoint, tenant, or user information even when the credential
/// itself is stored separately.
#[derive(Clone, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct CredentialKey(String);

impl CredentialKey {
    /// Validates a host-generated Keychain account identity.
    ///
    /// # Errors
    ///
    /// Returns [`CredentialKeyError`] when the key is blank, oversized, or
    /// contains a control character.
    pub fn parse(input: &str) -> Result<Self, CredentialKeyError> {
        let trimmed = input.trim();
        if trimmed.is_empty() {
            return Err(CredentialKeyError::Empty);
        }
        if trimmed.len() > MAX_CREDENTIAL_KEY_BYTES {
            return Err(CredentialKeyError::TooLong {
                actual: trimmed.len(),
                limit: MAX_CREDENTIAL_KEY_BYTES,
            });
        }
        if trimmed.chars().any(char::is_control) {
            return Err(CredentialKeyError::ControlCharacter);
        }
        Ok(Self(trimmed.to_owned()))
    }

    /// Returns the account identity to the host credential adapter.
    ///
    /// UI and logging code should not call this method; it exists for the
    /// Keychain boundary.
    #[must_use]
    pub fn expose_to_host(&self) -> &str {
        &self.0
    }
}

impl Debug for CredentialKey {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("CredentialKey")
            .field("value", &"[REDACTED]")
            .field("bytes", &self.0.len())
            .finish()
    }
}

/// Invalid host credential account identity.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CredentialKeyError {
    /// The key was blank.
    Empty,
    /// The key exceeded the accepted byte limit.
    TooLong {
        /// Supplied UTF-8 byte length.
        actual: usize,
        /// Maximum accepted byte length.
        limit: usize,
    },
    /// The key contained a control character.
    ControlCharacter,
}

impl Display for CredentialKeyError {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        match self {
            Self::Empty => formatter.write_str("credential account key is empty"),
            Self::TooLong { actual, limit } => write!(
                formatter,
                "credential account key is {actual} bytes, which exceeds the {limit}-byte limit"
            ),
            Self::ControlCharacter => {
                formatter.write_str("credential account key contains a control character")
            }
        }
    }
}

impl Error for CredentialKeyError {}

/// Credential kinds the core permits a host app to persist.
///
/// Bootstrap tokens are deliberately absent: they are one-time enrollment
/// material and must not become a durable Keychain entry by accident.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum PersistedCredentialKind {
    /// Shared Gateway token.
    Token,
    /// Shared Gateway password.
    Password,
    /// Previously issued device token.
    DeviceToken,
}

impl PersistedCredentialKind {
    const fn ios_kind(self) -> IosCredentialKind {
        match self {
            Self::Token => IosCredentialKind::Token,
            Self::Password => IosCredentialKind::Password,
            Self::DeviceToken => IosCredentialKind::DeviceToken,
        }
    }

    const fn from_ios(kind: IosCredentialKind) -> Option<Self> {
        match kind {
            IosCredentialKind::Token => Some(Self::Token),
            IosCredentialKind::Password => Some(Self::Password),
            IosCredentialKind::DeviceToken => Some(Self::DeviceToken),
            IosCredentialKind::None | IosCredentialKind::BootstrapToken => None,
        }
    }
}

/// Keychain-like facility supplied by the host application.
///
/// Secrets remain wrapped in [`SecretString`] across the port. Implementations
/// must use an explicit secrecy exposure operation only at the platform API
/// boundary and must not include the value in errors.
pub trait HostCredentialStore: Send + Sync {
    /// Redaction-safe adapter failure.
    type Error: Error + Send + Sync + 'static;

    /// Loads one secret from protected host storage.
    ///
    /// # Errors
    ///
    /// Returns the adapter's redaction-safe storage failure.
    fn load_secret(
        &self,
        key: &CredentialKey,
        kind: PersistedCredentialKind,
    ) -> Result<Option<SecretString>, Self::Error>;

    /// Replaces one secret in protected host storage.
    ///
    /// # Errors
    ///
    /// Returns the adapter's redaction-safe storage failure.
    fn save_secret(
        &self,
        key: &CredentialKey,
        kind: PersistedCredentialKind,
        secret: &SecretString,
    ) -> Result<(), Self::Error>;

    /// Removes one secret from protected host storage.
    ///
    /// # Errors
    ///
    /// Returns the adapter's redaction-safe storage failure.
    fn delete_secret(
        &self,
        key: &CredentialKey,
        kind: PersistedCredentialKind,
    ) -> Result<(), Self::Error>;
}

/// Loads and validates a credential supplied by a host Keychain adapter.
///
/// # Errors
///
/// Returns [`HostCredentialError::Facility`] for an adapter failure or
/// [`HostCredentialError::InvalidStoredCredential`] when protected storage
/// returned a value this client would reject at manual intake.
pub fn load_host_credential<S: HostCredentialStore>(
    store: &S,
    key: &CredentialKey,
    kind: PersistedCredentialKind,
) -> Result<Option<IosCredential>, HostCredentialError<S::Error>> {
    let Some(secret) = store
        .load_secret(key, kind)
        .map_err(HostCredentialError::Facility)?
    else {
        return Ok(None);
    };
    IosCredential::from_secret(kind.ios_kind(), &secret)
        .map(Some)
        .map_err(HostCredentialError::InvalidStoredCredential)
}

/// Saves a persistable credential through the host Keychain adapter.
///
/// # Errors
///
/// Returns [`HostCredentialError::NotPersistable`] for an absent or bootstrap
/// credential, or [`HostCredentialError::Facility`] for an adapter failure.
pub fn save_host_credential<S: HostCredentialStore>(
    store: &S,
    key: &CredentialKey,
    credential: &IosCredential,
) -> Result<(), HostCredentialError<S::Error>> {
    let Some(kind) = PersistedCredentialKind::from_ios(credential.kind()) else {
        return Err(HostCredentialError::NotPersistable(credential.kind()));
    };
    let Some(secret) = credential.secret_value() else {
        return Err(HostCredentialError::NotPersistable(credential.kind()));
    };
    store
        .save_secret(key, kind, secret)
        .map_err(HostCredentialError::Facility)
}

/// Deletes a credential through the host Keychain adapter.
///
/// # Errors
///
/// Returns the redaction-safe adapter error.
pub fn delete_host_credential<S: HostCredentialStore>(
    store: &S,
    key: &CredentialKey,
    kind: PersistedCredentialKind,
) -> Result<(), S::Error> {
    store.delete_secret(key, kind)
}

/// Failure at the validated host credential boundary.
#[derive(Debug)]
pub enum HostCredentialError<E> {
    /// The host facility failed without exposing secret material.
    Facility(E),
    /// Protected storage contained a value the normal intake path refuses.
    InvalidStoredCredential(CredentialError),
    /// The caller tried to persist absent or one-time material.
    NotPersistable(IosCredentialKind),
}

impl<E: Display> Display for HostCredentialError<E> {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        match self {
            Self::Facility(error) => write!(formatter, "host credential facility failed: {error}"),
            Self::InvalidStoredCredential(error) => {
                write!(formatter, "stored credential is invalid: {error}")
            }
            Self::NotPersistable(kind) => {
                write!(
                    formatter,
                    "{} is not a persistable credential",
                    kind.label()
                )
            }
        }
    }
}

impl<E: Error + 'static> Error for HostCredentialError<E> {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Facility(error) => Some(error),
            Self::InvalidStoredCredential(error) => Some(error),
            Self::NotPersistable(_) => None,
        }
    }
}

/// Bounds for one foreground local-discovery browse.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DiscoveryScanPolicy {
    timeout: Duration,
    max_results: usize,
}

impl DiscoveryScanPolicy {
    /// Creates a finite discovery scan policy.
    ///
    /// # Errors
    ///
    /// Returns [`DiscoveryScanPolicyError`] when the timeout or result count is
    /// zero or exceeds the mobile limits.
    pub fn new(timeout: Duration, max_results: usize) -> Result<Self, DiscoveryScanPolicyError> {
        if timeout.is_zero() {
            return Err(DiscoveryScanPolicyError::ZeroTimeout);
        }
        if timeout > MAX_DISCOVERY_TIMEOUT {
            return Err(DiscoveryScanPolicyError::TimeoutTooLong {
                actual: timeout,
                limit: MAX_DISCOVERY_TIMEOUT,
            });
        }
        if max_results == 0 {
            return Err(DiscoveryScanPolicyError::ZeroResults);
        }
        if max_results > MAX_DISCOVERY_RESULTS {
            return Err(DiscoveryScanPolicyError::TooManyResults {
                actual: max_results,
                limit: MAX_DISCOVERY_RESULTS,
            });
        }
        Ok(Self {
            timeout,
            max_results,
        })
    }

    /// Returns the maximum scan duration.
    #[must_use]
    pub const fn timeout(self) -> Duration {
        self.timeout
    }

    /// Returns the maximum number of unique results retained.
    #[must_use]
    pub const fn max_results(self) -> usize {
        self.max_results
    }
}

impl Default for DiscoveryScanPolicy {
    fn default() -> Self {
        Self {
            timeout: Duration::from_secs(4),
            max_results: 16,
        }
    }
}

/// Invalid local-discovery work bounds.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DiscoveryScanPolicyError {
    /// A scan could return immediately without giving DNS-SD time to answer.
    ZeroTimeout,
    /// A scan could keep the radio active too long.
    TimeoutTooLong {
        /// Supplied timeout.
        actual: Duration,
        /// Maximum accepted timeout.
        limit: Duration,
    },
    /// A scan could not retain any result.
    ZeroResults,
    /// A scan could retain too much host-provided data.
    TooManyResults {
        /// Supplied result count.
        actual: usize,
        /// Maximum accepted result count.
        limit: usize,
    },
}

impl Display for DiscoveryScanPolicyError {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        match self {
            Self::ZeroTimeout => formatter.write_str("discovery timeout must be greater than zero"),
            Self::TimeoutTooLong { actual, limit } => write!(
                formatter,
                "discovery timeout of {actual:?} exceeds the iOS limit of {limit:?}"
            ),
            Self::ZeroResults => {
                formatter.write_str("discovery result limit must be greater than zero")
            }
            Self::TooManyResults { actual, limit } => write!(
                formatter,
                "discovery result limit {actual} exceeds the iOS limit of {limit}"
            ),
        }
    }
}

impl Error for DiscoveryScanPolicyError {}

/// One discovery request proven ready for a specific backend and network route.
pub struct DiscoveryRequest<B: LocalDiscoveryBackend> {
    permit: DiscoveryPermit<B>,
    policy: DiscoveryScanPolicy,
    route: IosNetworkRoute,
}

impl<B: LocalDiscoveryBackend> DiscoveryRequest<B> {
    /// Binds a declaration permit to active foreground and local-network state.
    ///
    /// # Errors
    ///
    /// Returns [`DiscoveryStartBlocked`] when the app is not active, the network
    /// is unavailable, or the usable route cannot reach the local link.
    pub fn new(
        permit: DiscoveryPermit<B>,
        policy: DiscoveryScanPolicy,
        run_state: AppRunState,
        network_path: IosNetworkPath,
    ) -> Result<Self, DiscoveryStartBlocked> {
        if run_state != AppRunState::Foreground {
            return Err(DiscoveryStartBlocked::AppNotForeground { run_state });
        }
        let Some(route) = network_path.route() else {
            return Err(DiscoveryStartBlocked::NetworkUnavailable { network_path });
        };
        if !route.local_network_available() {
            return Err(DiscoveryStartBlocked::NoLocalNetwork {
                interface: route.interface(),
            });
        }
        Ok(Self {
            permit,
            policy,
            route,
        })
    }

    /// Returns the checked backend permit.
    #[must_use]
    pub const fn permit(&self) -> &DiscoveryPermit<B> {
        &self.permit
    }

    /// Returns the finite scan bounds.
    #[must_use]
    pub const fn policy(&self) -> DiscoveryScanPolicy {
        self.policy
    }

    /// Returns the route generation on which this scan was admitted.
    #[must_use]
    pub const fn route(&self) -> IosNetworkRoute {
        self.route
    }

    /// Consumes the request into the backend permit, bounds, and route context.
    #[must_use]
    pub fn into_parts(self) -> (DiscoveryPermit<B>, DiscoveryScanPolicy, IosNetworkRoute) {
        (self.permit, self.policy, self.route)
    }
}

impl<B: LocalDiscoveryBackend> Debug for DiscoveryRequest<B> {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("DiscoveryRequest")
            .field("permit", &self.permit)
            .field("policy", &self.policy)
            .field("route", &self.route)
            .finish()
    }
}

/// Runtime host state that prevents an otherwise configured discovery scan.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DiscoveryStartBlocked {
    /// The app cannot present or finish a Local Network consent alert.
    AppNotForeground {
        /// Lifecycle state supplied by the host.
        run_state: AppRunState,
    },
    /// No usable path exists.
    NetworkUnavailable {
        /// Path state supplied by the host.
        network_path: IosNetworkPath,
    },
    /// A route exists but cannot reach the local link.
    NoLocalNetwork {
        /// Interface carrying that route.
        interface: IosNetworkInterface,
    },
}

impl DiscoveryStartBlocked {
    /// Returns structured user recovery content.
    #[must_use]
    pub fn diagnostic(self) -> DiscoveryDiagnostic {
        match self {
            Self::AppNotForeground { run_state } => DiscoveryDiagnostic::new(
                "Discovery needs the foreground",
                format!(
                    "Local discovery did not start because the app is {}. Return to the active \
                     foreground so iOS can present or complete the Local Network prompt.",
                    run_state.label()
                ),
                DiscoveryRemediation::BringAppToForeground,
            ),
            Self::NetworkUnavailable { network_path } => DiscoveryDiagnostic::new(
                "No usable network for discovery",
                format!(
                    "Local discovery did not start because the network is {network_path}. The scan \
                     remains paused instead of polling while no route is available."
                ),
                DiscoveryRemediation::WaitForUsableNetwork,
            ),
            Self::NoLocalNetwork { interface } => DiscoveryDiagnostic::new(
                "Current path cannot reach the local network",
                format!(
                    "The active {interface} path is usable for a direct Gateway connection but the \
                     host did not confirm local-link reachability, so Bonjour discovery was not \
                     started."
                ),
                DiscoveryRemediation::ConnectToLocalNetwork,
            ),
        }
    }
}

impl Display for DiscoveryStartBlocked {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.diagnostic().explanation())
    }
}

impl Error for DiscoveryStartBlocked {}

/// One redaction-safe Gateway result supplied by a host discovery adapter.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DiscoveredGateway {
    endpoint: GatewayEndpoint,
}

impl DiscoveredGateway {
    /// Creates a result from an endpoint that passed normal user-intake policy.
    #[must_use]
    pub const fn new(endpoint: GatewayEndpoint) -> Self {
        Self { endpoint }
    }

    /// Returns redaction-safe endpoint display text.
    #[must_use]
    pub fn endpoint_summary(&self) -> EndpointSummary {
        self.endpoint.summary()
    }

    /// Consumes the discovery result into a connectable endpoint.
    #[must_use]
    pub fn into_endpoint(self) -> GatewayEndpoint {
        self.endpoint
    }
}

/// Terminal state of one bounded host discovery scan.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum DiscoveryCompletion {
    /// The backend completed before the timeout.
    Finished,
    /// The bounded scan window elapsed.
    TimedOut,
    /// Lifecycle, network, or user action cancelled the scan.
    Cancelled,
}

/// Event delivered by a host discovery adapter.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum DiscoveryEvent {
    /// One unique validated endpoint was found.
    Found(DiscoveredGateway),
    /// The scan reached a terminal state.
    Completed(DiscoveryCompletion),
}

/// Callback surface a host discovery adapter uses to deliver bounded results.
pub trait DiscoveryEventSink: Send + Sync {
    /// Delivers one event without retaining any platform-owned object.
    fn on_discovery_event(&self, event: DiscoveryEvent);
}

/// Cancellable scan handle owned by the host application.
pub trait HostDiscoverySession: Send + Sync {
    /// Cancels the scan. Implementations must make repeated calls harmless.
    fn cancel(&self);
}

/// Bonjour or DNS-SD facility supplied by the host application.
///
/// Implementations must honor [`DiscoveryScanPolicy`], emit at most one
/// terminal event, and stop on cancellation. The shell must cancel the returned
/// session when the app leaves the foreground or when the network route ID no
/// longer matches [`DiscoveryRequest::route`].
pub trait HostDiscoveryProvider<B: LocalDiscoveryBackend>: Send + Sync {
    /// Redaction-safe adapter failure.
    type Error: Error + Send + Sync + 'static;
    /// Cancellable host scan.
    type Session: HostDiscoverySession;

    /// Starts one previously gated and bounded scan.
    ///
    /// # Errors
    ///
    /// Returns a redaction-safe platform adapter failure when the scan cannot
    /// be created after the core preconditions passed.
    fn start(
        &self,
        request: DiscoveryRequest<B>,
        sink: Arc<dyn DiscoveryEventSink>,
    ) -> Result<Self::Session, Self::Error>;
}

#[cfg(test)]
mod tests {
    use std::convert::Infallible;
    use std::sync::Mutex;
    use std::time::Duration;

    use secrecy::{ExposeSecret, SecretString};

    use super::{
        CredentialKey, DiscoveryRequest, DiscoveryScanPolicy, DiscoveryScanPolicyError,
        DiscoveryStartBlocked, HostCredentialError, HostCredentialStore, PersistedCredentialKind,
        load_host_credential, save_host_credential,
    };
    use crate::credential::{CredentialError, IosCredential};
    use crate::host_app::{
        AppRunState, BonjourServiceType, DeclarationStatus, DiscoveryMechanism, EntitlementStatus,
        HostAppDeclarations, HostAppEntitlement, LocalDiscoveryBackend,
    };
    use crate::session::{IosNetworkInterface, IosNetworkPath, IosNetworkRoute};

    #[derive(Debug)]
    enum SystemDnsSdFixture {}

    impl LocalDiscoveryBackend for SystemDnsSdFixture {
        const MECHANISM: DiscoveryMechanism = DiscoveryMechanism::SystemDnsSd;
        const DNS_SD_SERVICE_TYPE: &'static str = "_openclaw-gw._tcp.local.";
    }

    #[derive(Default)]
    struct MemoryCredentialStore {
        value: Mutex<Option<String>>,
    }

    impl HostCredentialStore for MemoryCredentialStore {
        type Error = Infallible;

        fn load_secret(
            &self,
            _key: &CredentialKey,
            _kind: PersistedCredentialKind,
        ) -> Result<Option<SecretString>, Self::Error> {
            Ok(self
                .value
                .lock()
                .expect("test store lock")
                .clone()
                .map(SecretString::from))
        }

        fn save_secret(
            &self,
            _key: &CredentialKey,
            _kind: PersistedCredentialKind,
            secret: &SecretString,
        ) -> Result<(), Self::Error> {
            *self.value.lock().expect("test store lock") = Some(secret.expose_secret().to_owned());
            Ok(())
        }

        fn delete_secret(
            &self,
            _key: &CredentialKey,
            _kind: PersistedCredentialKind,
        ) -> Result<(), Self::Error> {
            *self.value.lock().expect("test store lock") = None;
            Ok(())
        }
    }

    fn permit() -> crate::host_app::DiscoveryPermit<SystemDnsSdFixture> {
        let required =
            BonjourServiceType::parse("_openclaw-gw._tcp").expect("fixture type is valid");
        HostAppDeclarations::new()
            .with_local_network_usage(DeclarationStatus::Declared)
            .with_bonjour_services(DeclarationStatus::Declared, [required])
            .with_entitlement(
                HostAppEntitlement::MulticastNetworking,
                EntitlementStatus::Unknown,
            )
            .discovery_precondition::<SystemDnsSdFixture>()
            .expect("system DNS-SD needs no multicast entitlement")
    }

    fn local_path() -> IosNetworkPath {
        IosNetworkPath::Satisfied(
            IosNetworkRoute::new(7, IosNetworkInterface::Wifi).with_local_network_available(true),
        )
    }

    #[test]
    fn credential_account_debug_is_redacted() {
        let key = CredentialKey::parse("tenant/alice@gateway.example").expect("key is valid");
        let rendered = format!("{key:?}");

        assert!(!rendered.contains("alice"));
        assert!(rendered.contains("[REDACTED]"));
    }

    #[test]
    fn host_credentials_cross_the_port_without_entering_debug_output() {
        let key = CredentialKey::parse("gateway-token").expect("key is valid");
        let store = MemoryCredentialStore::default();
        let credential = IosCredential::token("super-secret").expect("token is valid");

        save_host_credential(&store, &key, &credential).expect("save succeeds");
        let loaded = load_host_credential(&store, &key, PersistedCredentialKind::Token)
            .expect("load succeeds")
            .expect("credential exists");

        assert_eq!(loaded.kind(), crate::IosCredentialKind::Token);
        assert!(!format!("{loaded:?}").contains("super-secret"));
    }

    #[test]
    fn invalid_keychain_material_is_revalidated() {
        let key = CredentialKey::parse("gateway-token").expect("key is valid");
        let store = MemoryCredentialStore {
            value: Mutex::new(Some("abc\u{7}def".to_owned())),
        };
        let error = load_host_credential(&store, &key, PersistedCredentialKind::Token)
            .expect_err("control characters remain invalid after Keychain load");

        assert!(matches!(
            error,
            HostCredentialError::InvalidStoredCredential(CredentialError::ControlCharacter)
        ));
    }

    #[test]
    fn bootstrap_tokens_cannot_be_persisted_through_the_port() {
        let key = CredentialKey::parse("bootstrap").expect("key is valid");
        let store = MemoryCredentialStore::default();
        let credential =
            IosCredential::bootstrap_token("one-time").expect("bootstrap token is valid");
        let error = save_host_credential(&store, &key, &credential)
            .expect_err("bootstrap material must stay ephemeral");

        assert!(matches!(
            error,
            HostCredentialError::NotPersistable(crate::IosCredentialKind::BootstrapToken)
        ));
    }

    #[test]
    fn discovery_permit_is_owned_and_survives_its_declaration_record() {
        let request = DiscoveryRequest::new(
            permit(),
            DiscoveryScanPolicy::default(),
            AppRunState::Foreground,
            local_path(),
        )
        .expect("foreground local discovery is ready");

        assert_eq!(
            request.permit().service_type().as_str(),
            "_openclaw-gw._tcp"
        );
        assert_eq!(request.route().id(), 7);
    }

    #[test]
    fn discovery_never_starts_in_background_or_on_a_nonlocal_path() {
        let background = DiscoveryRequest::new(
            permit(),
            DiscoveryScanPolicy::default(),
            AppRunState::Background,
            local_path(),
        )
        .expect_err("background discovery is blocked");
        assert!(matches!(
            background,
            DiscoveryStartBlocked::AppNotForeground { .. }
        ));

        let cellular =
            IosNetworkPath::Satisfied(IosNetworkRoute::new(8, IosNetworkInterface::Cellular));
        let nonlocal = DiscoveryRequest::new(
            permit(),
            DiscoveryScanPolicy::default(),
            AppRunState::Foreground,
            cellular,
        )
        .expect_err("a nonlocal path is blocked");
        assert!(matches!(
            nonlocal,
            DiscoveryStartBlocked::NoLocalNetwork {
                interface: IosNetworkInterface::Cellular
            }
        ));
    }

    #[test]
    fn discovery_work_is_strictly_bounded() {
        assert_eq!(
            DiscoveryScanPolicy::new(Duration::from_secs(16), 1),
            Err(DiscoveryScanPolicyError::TimeoutTooLong {
                actual: Duration::from_secs(16),
                limit: Duration::from_secs(15),
            })
        );
        assert_eq!(
            DiscoveryScanPolicy::new(Duration::from_secs(1), 65),
            Err(DiscoveryScanPolicyError::TooManyResults {
                actual: 65,
                limit: 64,
            })
        );
    }
}

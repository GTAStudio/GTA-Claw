use std::collections::BTreeMap;
use std::error::Error;
use std::fmt::{self, Debug, Display, Formatter};
use std::sync::Arc;
use std::time::Duration;

use claw_protocol::gateway::{
    AUTHENTICATED_MAX_FRAME_BYTES, ClientId, ClientMode, GATEWAY_PROTOCOL_VERSION, Name,
    ProtocolVersion,
};
use claw_security::authorization::{Role, ScopeSet};
use claw_security::identity::DeviceIdentity;
use secrecy::SecretString;
use url::{Host, Url};

/// One unambiguous Gateway authentication credential.
pub enum GatewayCredential {
    /// No shared credential; device policy still applies.
    None,
    /// Shared Gateway token.
    Token(SecretString),
    /// Shared Gateway password.
    Password(SecretString),
    /// One-time bootstrap token.
    BootstrapToken(SecretString),
    /// Previously issued device token.
    DeviceToken(SecretString),
}

/// How strictly a successful hello must match the requested authorization.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub enum AuthorizationExpectation {
    /// Preserve generic Gateway behavior: require the requested role and accept any closed scopes.
    #[default]
    RequestedRole,
    /// Require the effective hello role and scope set to equal the request exactly.
    ExactRequested,
}

impl Debug for GatewayCredential {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        match self {
            Self::None => formatter.write_str("GatewayCredential::None"),
            Self::Token(_) => formatter.write_str("GatewayCredential::Token([REDACTED])"),
            Self::Password(_) => formatter.write_str("GatewayCredential::Password([REDACTED])"),
            Self::BootstrapToken(_) => {
                formatter.write_str("GatewayCredential::BootstrapToken([REDACTED])")
            }
            Self::DeviceToken(_) => {
                formatter.write_str("GatewayCredential::DeviceToken([REDACTED])")
            }
        }
    }
}

/// Typed Gateway client metadata included in every authenticated connection.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ClientMetadata {
    /// Closed client product identifier.
    pub id: ClientId,
    /// Optional display name.
    pub display_name: Option<Name>,
    /// Application version.
    pub version: Name,
    /// Runtime platform.
    pub platform: Name,
    /// Optional device-family metadata.
    pub device_family: Option<Name>,
    /// Optional model identifier.
    pub model_identifier: Option<Name>,
    /// Closed client mode.
    pub mode: ClientMode,
    /// Optional process or installation identity.
    pub instance_id: Option<Name>,
}

impl Default for ClientMetadata {
    fn default() -> Self {
        Self {
            id: ClientId::GatewayClient,
            display_name: None,
            version: Name::new(env!("CARGO_PKG_VERSION"), 64)
                .expect("package version is non-empty"),
            platform: Name::new(std::env::consts::OS, 64).expect("target OS is non-empty"),
            device_family: None,
            model_identifier: None,
            mode: ClientMode::Backend,
            instance_id: None,
        }
    }
}

/// Caller-controlled bounded resource limits.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ClientLimits {
    /// Maximum simultaneously pending RPC requests.
    pub max_in_flight_requests: usize,
    /// Maximum commands waiting for the single socket task.
    pub command_queue_capacity: usize,
    /// Maximum cumulative encoded request bytes retained by the command queue.
    pub outbound_queue_bytes: usize,
    /// Maximum delivered events waiting for the caller.
    pub event_queue_capacity: usize,
    /// Maximum cumulative encoded bytes retained by the event queue.
    pub event_queue_bytes: usize,
    /// Maximum unique request identifiers admitted on one connection.
    pub completed_id_capacity: usize,
}

impl Default for ClientLimits {
    fn default() -> Self {
        Self {
            max_in_flight_requests: 64,
            command_queue_capacity: 64,
            outbound_queue_bytes: AUTHENTICATED_MAX_FRAME_BYTES,
            event_queue_capacity: 256,
            event_queue_bytes: AUTHENTICATED_MAX_FRAME_BYTES,
            completed_id_capacity: 256,
        }
    }
}

/// Bounded timeout policy for connection lifecycle operations.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ClientTimeouts {
    /// TCP, TLS, and WebSocket opening timeout.
    pub connect: Duration,
    /// Challenge/connect/hello timeout.
    pub authentication: Duration,
    /// Default request response timeout.
    pub request: Duration,
    /// Close-handshake and task shutdown timeout.
    pub shutdown: Duration,
}

impl Default for ClientTimeouts {
    fn default() -> Self {
        Self {
            connect: Duration::from_secs(10),
            authentication: Duration::from_secs(10),
            request: Duration::from_secs(30),
            shutdown: Duration::from_secs(3),
        }
    }
}

/// Caller policy for reconnecting after transient transport failures.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ReconnectPolicy {
    /// Stop after the first connection loss.
    Never,
    /// Retry transient transport failures with bounded exponential backoff.
    Bounded {
        /// Maximum attempts after a failed connection.
        max_attempts: u32,
        /// Delay before the first retry.
        initial_delay: Duration,
        /// Upper bound before jitter.
        max_delay: Duration,
        /// Maximum additive jitter supplied by the runtime RNG.
        max_jitter: Duration,
    },
}

impl Default for ReconnectPolicy {
    fn default() -> Self {
        Self::Bounded {
            max_attempts: 5,
            initial_delay: Duration::from_millis(250),
            max_delay: Duration::from_secs(8),
            max_jitter: Duration::from_millis(250),
        }
    }
}

/// Complete configuration for one reconnecting Gateway client.
pub struct GatewayClientConfig {
    /// WebSocket endpoint. Only `ws` and `wss` are accepted.
    pub url: Url,
    /// Caller-supplied in-memory device identity.
    pub identity: Arc<DeviceIdentity>,
    /// Explicit credential mode.
    pub credential: GatewayCredential,
    /// Requested ordinary Gateway role.
    pub role: Role,
    /// Requested closed operator scopes.
    pub scopes: ScopeSet,
    /// Validation applied to the effective authorization returned by hello.
    pub authorization_expectation: AuthorizationExpectation,
    /// Lowest protocol accepted by the caller.
    pub min_protocol: ProtocolVersion,
    /// Highest protocol accepted by the caller.
    pub max_protocol: ProtocolVersion,
    /// Client identity metadata.
    pub client: ClientMetadata,
    /// Optional capability declarations.
    pub capabilities: Vec<Name>,
    /// Optional node command declarations.
    pub commands: Option<Vec<Name>>,
    /// Optional node permission declarations.
    pub permissions: Option<BTreeMap<Name, bool>>,
    /// Resource bounds.
    pub limits: ClientLimits,
    /// Lifecycle timeouts.
    pub timeouts: ClientTimeouts,
    /// Reconnect policy.
    pub reconnect: ReconnectPolicy,
    /// Explicit break-glass opt-in for non-loopback plaintext WebSockets.
    pub allow_insecure_remote_ws: bool,
}

impl GatewayClientConfig {
    /// Creates secure defaults for a typed endpoint and caller-owned identity.
    #[must_use]
    pub fn new(url: Url, identity: Arc<DeviceIdentity>) -> Self {
        Self {
            url,
            identity,
            credential: GatewayCredential::None,
            role: Role::Operator,
            scopes: ScopeSet::EMPTY,
            authorization_expectation: AuthorizationExpectation::RequestedRole,
            min_protocol: GATEWAY_PROTOCOL_VERSION,
            max_protocol: GATEWAY_PROTOCOL_VERSION,
            client: ClientMetadata::default(),
            capabilities: Vec::new(),
            commands: None,
            permissions: None,
            limits: ClientLimits::default(),
            timeouts: ClientTimeouts::default(),
            reconnect: ReconnectPolicy::default(),
            allow_insecure_remote_ws: false,
        }
    }

    pub(crate) fn validate(&self) -> Result<(), ConfigurationError> {
        match self.url.scheme() {
            "ws" | "wss" => {}
            _ => return Err(ConfigurationError::UnsupportedScheme),
        }
        if !self.url.username().is_empty()
            || self.url.password().is_some()
            || self.url.query().is_some()
            || self.url.fragment().is_some()
        {
            return Err(ConfigurationError::CredentialBearingUrl);
        }
        if self.url.scheme() == "ws"
            && !self.allow_insecure_remote_ws
            && !is_loopback_host(self.url.host())
        {
            return Err(ConfigurationError::InsecureRemoteWebSocket);
        }
        if self.role == Role::Worker
            || self.client.id == ClientId::Worker
            || self.client.mode == ClientMode::Worker
        {
            return Err(ConfigurationError::WorkerProtocolUnsupported);
        }
        if self.min_protocol.get() > self.max_protocol.get() {
            return Err(ConfigurationError::InvalidProtocolRange);
        }
        for value in [
            self.limits.max_in_flight_requests,
            self.limits.command_queue_capacity,
            self.limits.outbound_queue_bytes,
            self.limits.event_queue_capacity,
            self.limits.event_queue_bytes,
            self.limits.completed_id_capacity,
        ] {
            if value == 0 || value > AUTHENTICATED_MAX_FRAME_BYTES {
                return Err(ConfigurationError::InvalidResourceLimit);
            }
        }
        for timeout in [
            self.timeouts.connect,
            self.timeouts.authentication,
            self.timeouts.request,
            self.timeouts.shutdown,
        ] {
            if timeout.is_zero() {
                return Err(ConfigurationError::InvalidTimeout);
            }
        }
        if let ReconnectPolicy::Bounded {
            max_attempts,
            initial_delay,
            max_delay,
            ..
        } = self.reconnect
            && (max_attempts == 0
                || initial_delay.is_zero()
                || max_delay.is_zero()
                || initial_delay > max_delay)
        {
            return Err(ConfigurationError::InvalidReconnectPolicy);
        }
        Ok(())
    }
}

impl Debug for GatewayClientConfig {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("GatewayClientConfig")
            .field("endpoint", &self.url.host_str().unwrap_or("<unknown>"))
            .field("secure", &(self.url.scheme() == "wss"))
            .field("identity", &self.identity)
            .field("credential", &self.credential)
            .field("role", &self.role)
            .field("scopes", &self.scopes)
            .field("authorization_expectation", &self.authorization_expectation)
            .field("min_protocol", &self.min_protocol)
            .field("max_protocol", &self.max_protocol)
            .field("client", &self.client)
            .field("capability_count", &self.capabilities.len())
            .field("limits", &self.limits)
            .field("timeouts", &self.timeouts)
            .field("reconnect", &self.reconnect)
            .field("allow_insecure_remote_ws", &self.allow_insecure_remote_ws)
            .finish()
    }
}

fn is_loopback_host(host: Option<Host<&str>>) -> bool {
    match host {
        Some(Host::Domain("localhost")) => true,
        Some(Host::Ipv4(address)) => address.is_loopback(),
        Some(Host::Ipv6(address)) => address.is_loopback(),
        Some(Host::Domain(_)) => false,
        None => false,
    }
}

/// Invalid client configuration rejected before any network operation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ConfigurationError {
    /// Endpoint scheme is not `ws` or `wss`.
    UnsupportedScheme,
    /// Credentials, query data, or fragments are forbidden in endpoint URLs.
    CredentialBearingUrl,
    /// Remote plaintext WebSocket requires explicit break-glass opt-in.
    InsecureRemoteWebSocket,
    /// Worker clients use a separate protocol not implemented by this crate.
    WorkerProtocolUnsupported,
    /// Minimum protocol is greater than maximum protocol.
    InvalidProtocolRange,
    /// A queue or map bound is zero or exceeds the authenticated protocol byte cap.
    InvalidResourceLimit,
    /// Lifecycle timeouts must be positive.
    InvalidTimeout,
    /// Bounded reconnect parameters are inconsistent.
    InvalidReconnectPolicy,
}

impl Display for ConfigurationError {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::UnsupportedScheme => "Gateway endpoint must use ws or wss",
            Self::CredentialBearingUrl => "Gateway endpoint URL must not contain credentials",
            Self::InsecureRemoteWebSocket => {
                "remote plaintext Gateway WebSocket requires explicit opt-in"
            }
            Self::WorkerProtocolUnsupported => {
                "worker clients use an unsupported independent protocol"
            }
            Self::InvalidProtocolRange => "Gateway protocol range is invalid",
            Self::InvalidResourceLimit => "Gateway client resource limit is invalid",
            Self::InvalidTimeout => "Gateway client timeout must be positive",
            Self::InvalidReconnectPolicy => "Gateway reconnect policy is invalid",
        })
    }
}

impl Error for ConfigurationError {}

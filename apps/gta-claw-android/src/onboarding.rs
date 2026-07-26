//! Portable Android onboarding state, independent of Slint and of Android itself.
//!
//! Everything in this module compiles and runs on the development host, so the
//! connection state machine, the input policy, and the redaction rules are
//! exercised by ordinary `cargo test` rather than only on a device.

use std::fmt::{self, Debug, Display, Formatter};
use std::time::Duration;

use claw_gateway_client::{
    ConfigurationError, ConnectionInfo, ConnectionState, GatewayClientError, ProtocolFailure,
    TransportFailure,
};
use claw_protocol::gateway::ConnectErrorDetailCode;
use secrecy::SecretString;
use url::{Host, Url};

/// Largest accepted endpoint text, in bytes.
pub const MAX_ENDPOINT_BYTES: usize = 2048;

/// Largest accepted Gateway token, in bytes.
pub const MAX_TOKEN_BYTES: usize = 4096;

/// Scheme applied when the operator types a bare host.
const DEFAULT_SCHEME: &str = "wss";

/// Why one submission never reached the Gateway transport.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SubmissionRejection {
    /// The endpoint field was blank.
    EmptyEndpoint,
    /// The endpoint text exceeded the accepted byte budget.
    EndpointTooLong,
    /// The endpoint text is not a URL.
    MalformedEndpoint,
    /// The endpoint scheme is neither `ws` nor `wss`.
    UnsupportedScheme,
    /// The endpoint has no host component.
    MissingHost,
    /// The endpoint embeds a userinfo, query, or fragment component.
    CredentialBearingEndpoint,
    /// Plaintext `ws` to a non-loopback host without the explicit opt-in.
    InsecureRemoteEndpoint,
    /// The token exceeded the accepted byte budget.
    TokenTooLong,
}

impl SubmissionRejection {
    /// Returns the operator-facing message and the corrective action.
    #[must_use]
    pub const fn user_error(self) -> (&'static str, &'static str) {
        match self {
            Self::EmptyEndpoint => (
                "Enter a Gateway address.",
                "Example: wss://gateway.example.com:8443",
            ),
            Self::EndpointTooLong => (
                "That Gateway address is too long.",
                "Addresses are limited to 2048 bytes.",
            ),
            Self::MalformedEndpoint => (
                "That Gateway address could not be parsed.",
                "Check for typing errors, then try again.",
            ),
            Self::UnsupportedScheme => (
                "Only ws:// and wss:// addresses are supported.",
                "Remove the scheme to default to wss://.",
            ),
            Self::MissingHost => (
                "That Gateway address has no host.",
                "Include a host name or IP address.",
            ),
            Self::CredentialBearingEndpoint => (
                "Gateway addresses must not carry credentials.",
                "Remove any user info, query string, or #fragment and use the token field.",
            ),
            Self::InsecureRemoteEndpoint => (
                "Plaintext ws:// to a remote host is refused.",
                "Use wss://, or turn on \"Allow plaintext to this host\" to accept the risk.",
            ),
            Self::TokenTooLong => (
                "That token is too long.",
                "Tokens are limited to 4096 bytes.",
            ),
        }
    }
}

impl Display for SubmissionRejection {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.user_error().0)
    }
}

/// One validated connection request.
///
/// Both the endpoint and the token are treated as credential-bearing. A URL can
/// carry a bearer value in its path even after userinfo, query, and fragment are
/// rejected, so no `Debug` output reproduces more than the scheme and authority.
pub struct ConnectRequest {
    url: Url,
    token: Option<SecretString>,
    allow_insecure_remote_ws: bool,
}

/// What the transport will actually do with the prepared endpoint.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TransportPosture {
    /// `wss://` — TLS.
    Encrypted,
    /// `ws://` to a loopback address, which never leaves the device.
    PlaintextLoopback,
    /// `ws://` to a remote host, accepted only by explicit operator opt-in.
    PlaintextRemote,
}

impl TransportPosture {
    /// Returns the sentence shown to the operator.
    #[must_use]
    pub const fn notice(self) -> &'static str {
        match self {
            Self::Encrypted => "Encrypted wss://. Traffic to this server is protected by TLS.",
            Self::PlaintextLoopback => {
                "Plaintext ws:// to a loopback address. Traffic does not leave this device."
            }
            Self::PlaintextRemote => {
                "Plaintext ws:// to a remote host, accepted by explicit opt-in. \
                 Traffic, including the token, is NOT encrypted."
            }
        }
    }
}

impl ConnectRequest {
    /// Validates raw operator input against the same policy the transport applies.
    ///
    /// `allow_insecure_remote_ws` is the operator's explicit opt-in. It is
    /// carried through to [`Self::allow_insecure_remote_ws`] and is the single
    /// value the Gateway configuration is built from, so the checkbox in the UI
    /// and the transport decision can never disagree.
    pub fn prepare(
        endpoint: &str,
        token: &str,
        allow_insecure_remote_ws: bool,
    ) -> Result<Self, SubmissionRejection> {
        let endpoint = endpoint.trim();
        if endpoint.is_empty() {
            return Err(SubmissionRejection::EmptyEndpoint);
        }
        if endpoint.len() > MAX_ENDPOINT_BYTES {
            return Err(SubmissionRejection::EndpointTooLong);
        }
        let token = token.trim();
        if token.len() > MAX_TOKEN_BYTES {
            return Err(SubmissionRejection::TokenTooLong);
        }

        let candidate = if endpoint.contains("://") {
            endpoint.to_owned()
        } else {
            format!("{DEFAULT_SCHEME}://{endpoint}")
        };
        let url = Url::parse(&candidate).map_err(|_| SubmissionRejection::MalformedEndpoint)?;
        match url.scheme() {
            "ws" | "wss" => {}
            _ => return Err(SubmissionRejection::UnsupportedScheme),
        }
        if url.host().is_none() {
            return Err(SubmissionRejection::MissingHost);
        }
        if !url.username().is_empty()
            || url.password().is_some()
            || url.query().is_some()
            || url.fragment().is_some()
        {
            return Err(SubmissionRejection::CredentialBearingEndpoint);
        }
        if url.scheme() == "ws" && !allow_insecure_remote_ws && !is_loopback(url.host()) {
            return Err(SubmissionRejection::InsecureRemoteEndpoint);
        }

        Ok(Self {
            url,
            token: (!token.is_empty()).then(|| SecretString::from(token.to_owned())),
            allow_insecure_remote_ws,
        })
    }

    /// Returns the scheme and authority, which is what the operator is shown.
    ///
    /// The path is withheld deliberately: it is operator-supplied and can carry
    /// a secret, and the authority is already enough to identify the server.
    #[must_use]
    pub fn endpoint_display(&self) -> String {
        endpoint_authority(&self.url)
    }

    /// Returns whether the operator explicitly accepted plaintext to a remote host.
    #[must_use]
    pub const fn allow_insecure_remote_ws(&self) -> bool {
        self.allow_insecure_remote_ws
    }

    /// Returns whether a shared token accompanies the request.
    #[must_use]
    pub const fn has_token(&self) -> bool {
        self.token.is_some()
    }

    /// Returns what the transport will actually do, not what the operator asked for.
    ///
    /// The plaintext checkbox is an *permission*, not a description: ticking it
    /// and then connecting to `wss://` still yields an encrypted connection.
    /// Reporting the checkbox as though it described the connection would tell
    /// the operator their traffic is in the clear when it is not, so the posture
    /// is read off the URL that will be dialled.
    #[must_use]
    pub fn transport_posture(&self) -> TransportPosture {
        if self.url.scheme() == "wss" {
            TransportPosture::Encrypted
        } else if is_loopback(self.url.host()) {
            TransportPosture::PlaintextLoopback
        } else {
            TransportPosture::PlaintextRemote
        }
    }

    /// Consumes the request into the exact values the transport configuration needs.
    #[must_use]
    pub fn into_parts(self) -> (Url, Option<SecretString>, bool) {
        (self.url, self.token, self.allow_insecure_remote_ws)
    }
}

impl Debug for ConnectRequest {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ConnectRequest")
            .field("endpoint", &endpoint_authority(&self.url))
            .field("path", &"[REDACTED]")
            .field("secure", &(self.url.scheme() == "wss"))
            .field(
                "token",
                &if self.token.is_some() {
                    "[REDACTED]"
                } else {
                    "None"
                },
            )
            .field("allow_insecure_remote_ws", &self.allow_insecure_remote_ws)
            .finish()
    }
}

fn endpoint_authority(url: &Url) -> String {
    let host = url.host_str().unwrap_or("<unknown>");
    match url.port() {
        Some(port) => format!("{}://{host}:{port}", url.scheme()),
        None => format!("{}://{host}", url.scheme()),
    }
}

fn is_loopback(host: Option<Host<&str>>) -> bool {
    match host {
        Some(Host::Domain("localhost")) => true,
        Some(Host::Ipv4(address)) => address.is_loopback(),
        Some(Host::Ipv6(address)) => address.is_loopback(),
        Some(Host::Domain(_)) | None => false,
    }
}

/// A non-secret summary of one authenticated Gateway connection.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ReadySummary {
    protocol: u64,
    server_version: String,
    role: String,
    scopes: Vec<String>,
    max_payload_bytes: usize,
}

impl ReadySummary {
    /// Projects the transport's validated hello summary onto display values.
    #[must_use]
    pub fn from_info(info: &ConnectionInfo) -> Self {
        Self {
            protocol: info.protocol.get(),
            server_version: info.server_version.clone(),
            role: info.role.clone(),
            scopes: info.scopes.to_vec(),
            max_payload_bytes: info.max_payload_bytes,
        }
    }

    /// Returns the negotiated protocol version.
    #[must_use]
    pub const fn protocol(&self) -> u64 {
        self.protocol
    }

    /// Returns the server version text reported by the peer.
    #[must_use]
    pub fn server_version(&self) -> &str {
        &self.server_version
    }

    /// Returns the effective role the Gateway granted.
    #[must_use]
    pub fn role(&self) -> &str {
        &self.role
    }

    /// Returns the effective scopes the Gateway granted.
    #[must_use]
    pub fn scopes(&self) -> &[String] {
        &self.scopes
    }

    /// Returns the connection payload cap in bytes.
    #[must_use]
    pub const fn max_payload_bytes(&self) -> usize {
        self.max_payload_bytes
    }
}

/// An operator-facing failure with a concrete corrective action.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct UserError {
    message: String,
    action: String,
}

impl UserError {
    /// Creates an error from an already operator-facing pair.
    #[must_use]
    pub fn new(message: impl Into<String>, action: impl Into<String>) -> Self {
        Self {
            message: message.into(),
            action: action.into(),
        }
    }

    /// Translates a rejected submission.
    #[must_use]
    pub fn from_rejection(rejection: SubmissionRejection) -> Self {
        let (message, action) = rejection.user_error();
        Self::new(message, action)
    }

    /// Translates a transport failure without reproducing any secret material.
    #[must_use]
    pub fn from_gateway(error: &GatewayClientError) -> Self {
        match error {
            GatewayClientError::Configuration(configuration) => {
                Self::from_configuration(*configuration)
            }
            GatewayClientError::Transport(transport) => Self::from_transport(*transport),
            GatewayClientError::Authentication(failure) => {
                Self::from_authentication(failure.detail_code(), failure.device_retry_recommended())
            }
            GatewayClientError::Protocol(protocol) => Self::from_protocol(protocol),
            GatewayClientError::Backpressure(_) => Self::new(
                "The app is sending faster than this connection allows.",
                "Wait a moment, then retry.",
            ),
            GatewayClientError::NotReady | GatewayClientError::DisconnectedNotReplayed => {
                Self::new(
                    "The connection is not ready.",
                    "Reconnect before sending requests.",
                )
            }
            GatewayClientError::Cancelled => {
                Self::new("The connection was stopped.", "Connect again when ready.")
            }
            GatewayClientError::ConnectionChanged { .. } => Self::new(
                "The connection was replaced before this request completed.",
                "Retry on the current connection.",
            ),
            GatewayClientError::RequestTimedOut(_) => {
                Self::new("The Gateway did not answer in time.", "Retry the request.")
            }
            GatewayClientError::ShutdownTimedOut => Self::new(
                "Shutting the connection down took too long.",
                "The app released it anyway; reconnect when ready.",
            ),
            GatewayClientError::ReconnectExhausted => Self::new(
                "Reconnect attempts ran out.",
                "Check the network and the Gateway address, then connect again.",
            ),
        }
    }

    /// Translates a rejected handshake into a remedy the operator can act on.
    ///
    /// Taken as the two accessors of `AuthenticationFailure` rather than the
    /// failure itself: that type has no public constructor, so this is the only
    /// shape in which the mapping can be tested at all.
    ///
    /// The structured detail code wins over `device_retry_recommended` whenever
    /// the server supplied one. A server may recommend a device-token retry
    /// alongside, say, a Tailscale rejection, and following that advice would
    /// loop forever — the specific reason is always the more useful one.
    ///
    /// The match is deliberately exhaustive. `ConnectErrorDetailCode` mirrors a
    /// frozen upstream registry; if it ever grows a variant this crate stops
    /// compiling instead of quietly giving an operator advice invented for a
    /// different failure.
    #[must_use]
    pub fn from_authentication(
        detail: Option<ConnectErrorDetailCode>,
        device_retry_recommended: bool,
    ) -> Self {
        let Some(detail) = detail else {
            return if device_retry_recommended {
                Self::new(
                    "The Gateway rejected this device.",
                    "The server asked for a fresh device token. Reconnect to request one.",
                )
            } else {
                Self::new(
                    "The Gateway rejected this device.",
                    "Check the token, then try again.",
                )
            };
        };

        match detail {
            // Tailscale identity cannot be produced by this client on Android.
            // Telling the operator to check the token would send them around a
            // loop that cannot terminate, so the platform limit is stated.
            ConnectErrorDetailCode::AuthTailscaleIdentityMissing
            | ConnectErrorDetailCode::AuthTailscaleProxyMissing
            | ConnectErrorDetailCode::AuthTailscaleWhoisFailed
            | ConnectErrorDetailCode::AuthTailscaleIdentityMismatch => Self::new(
                "This Gateway authenticates callers through Tailscale.",
                "This Android build cannot present a Tailscale identity, so it cannot connect to \
                 this server. Use a Gateway that accepts token or device authentication.",
            ),
            ConnectErrorDetailCode::PairingRequired => Self::new(
                "This Gateway requires the device to be paired first.",
                "This build has no pairing screen, so the pairing has to be completed from \
                 another client before this device can connect.",
            ),
            ConnectErrorDetailCode::AuthRateLimited => Self::new(
                "The Gateway is rate limiting authentication attempts.",
                "Wait before trying again. Repeated attempts usually extend the limit.",
            ),
            ConnectErrorDetailCode::AuthRequired | ConnectErrorDetailCode::AuthTokenMissing => {
                Self::new(
                    "This Gateway requires a token and none was sent.",
                    "Enter the Gateway token, then connect again.",
                )
            }
            ConnectErrorDetailCode::AuthTokenMismatch
            | ConnectErrorDetailCode::AuthBootstrapTokenInvalid => Self::new(
                "The Gateway did not accept this token.",
                "Check the token for a typo or an expiry, then connect again.",
            ),
            ConnectErrorDetailCode::AuthTokenNotConfigured => Self::new(
                "This Gateway is not configured to accept tokens.",
                "Ask whoever runs the Gateway which authentication it expects.",
            ),
            ConnectErrorDetailCode::AuthPasswordMissing
            | ConnectErrorDetailCode::AuthPasswordMismatch
            | ConnectErrorDetailCode::AuthPasswordNotConfigured => Self::new(
                "This Gateway expects password authentication.",
                "This build only sends a token, so it cannot authenticate here. Use a Gateway \
                 that accepts token or device authentication.",
            ),
            ConnectErrorDetailCode::AuthScopeMismatch => Self::new(
                "The Gateway would not grant the permissions this app asked for.",
                "This app requests read-only operator access. Ask for that grant on the Gateway, \
                 then connect again.",
            ),
            ConnectErrorDetailCode::AuthDeviceTokenMismatch => Self::new(
                "The Gateway did not recognise this device's token.",
                if device_retry_recommended {
                    "The server asked for a fresh device token. Reconnect to request one."
                } else {
                    "The device registration may have been revoked. Re-register it on the \
                     Gateway, then connect again."
                },
            ),
            // This client creates a new identity every launch, so a rejected or
            // unknown identity is expected rather than a corruption to repair.
            ConnectErrorDetailCode::DeviceIdentityRequired
            | ConnectErrorDetailCode::ControlUiDeviceIdentityRequired
            | ConnectErrorDetailCode::DeviceAuthInvalid
            | ConnectErrorDetailCode::DeviceAuthDeviceIdMismatch
            | ConnectErrorDetailCode::DeviceAuthPublicKeyInvalid
            | ConnectErrorDetailCode::DeviceAuthSignatureInvalid => Self::new(
                "The Gateway rejected this device's identity.",
                "This app generates a new identity each time it starts, so a Gateway that only \
                 admits known devices will refuse it until this one is registered.",
            ),
            ConnectErrorDetailCode::DeviceAuthSignatureExpired => Self::new(
                "The Gateway judged this device's signature to be out of date.",
                "Check that the phone's clock and time zone are correct, then connect again.",
            ),
            ConnectErrorDetailCode::DeviceAuthNonceRequired
            | ConnectErrorDetailCode::DeviceAuthNonceMismatch => Self::new(
                "The Gateway's authentication challenge did not match the reply.",
                "Connect again to start a fresh challenge.",
            ),
            ConnectErrorDetailCode::ProtocolMismatch
            | ConnectErrorDetailCode::ClientVersionMismatch => Self::new(
                "This app and the Gateway do not speak a common protocol version.",
                "Update whichever of the app and the Gateway is older.",
            ),
            // Emitted for browser Control UI callers. This client is not one, so
            // seeing it means the Gateway took us for something we are not.
            ConnectErrorDetailCode::ControlUiOriginNotAllowed => Self::new(
                "The Gateway answered as though this app were a web page.",
                "Check that the address points at a Gateway endpoint and not at a Control UI one.",
            ),
            ConnectErrorDetailCode::AuthUnauthorized => Self::new(
                "The Gateway refused this connection.",
                "Check the token and that this device is allowed to connect, then try again.",
            ),
        }
    }

    fn from_configuration(error: ConfigurationError) -> Self {
        match error {
            ConfigurationError::UnsupportedScheme => {
                Self::from_rejection(SubmissionRejection::UnsupportedScheme)
            }
            ConfigurationError::CredentialBearingUrl => {
                Self::from_rejection(SubmissionRejection::CredentialBearingEndpoint)
            }
            ConfigurationError::InsecureRemoteWebSocket => {
                Self::from_rejection(SubmissionRejection::InsecureRemoteEndpoint)
            }
            ConfigurationError::WorkerProtocolUnsupported => Self::new(
                "Worker connections are not supported by this app.",
                "Use an operator Gateway address.",
            ),
            ConfigurationError::InvalidProtocolRange
            | ConfigurationError::InvalidResourceLimit
            | ConfigurationError::InvalidTimeout
            | ConfigurationError::InvalidReconnectPolicy => Self::new(
                "The app built an invalid connection configuration.",
                "This is a bug in the app; please report it.",
            ),
        }
    }

    fn from_transport(error: TransportFailure) -> Self {
        match error {
            TransportFailure::Connect => Self::new(
                "Could not reach the Gateway.",
                "Check the address and this device's network, then retry.",
            ),
            TransportFailure::TimedOut => Self::new(
                "The Gateway did not respond in time.",
                "Check the network, then retry.",
            ),
            TransportFailure::PeerClosed { .. } | TransportFailure::Closed => Self::new(
                "The Gateway closed the connection.",
                "Connect again when the server is available.",
            ),
            TransportFailure::Read | TransportFailure::Write => Self::new(
                "The connection dropped mid-transfer.",
                "Retry; mobile networks drop sockets when the app is backgrounded.",
            ),
            TransportFailure::UnsupportedExtension => Self::new(
                "The Gateway negotiated an unsupported WebSocket extension.",
                "Upgrade the Gateway or this app.",
            ),
        }
    }

    fn from_protocol(error: &ProtocolFailure) -> Self {
        match error {
            ProtocolFailure::HelloProtocol { .. } => Self::new(
                "This app and the Gateway do not share a protocol version.",
                "Upgrade whichever side is older.",
            ),
            ProtocolFailure::HandshakeRejected(_)
            | ProtocolFailure::HelloAuthenticationMismatch => Self::new(
                "The Gateway refused the handshake.",
                "Check the token and this device's authorization.",
            ),
            ProtocolFailure::ResyncRequired(_) => Self::new(
                "Event continuity was lost.",
                "Reconnect to rebuild state from a fresh snapshot.",
            ),
            _ => Self::new(
                "The Gateway sent something this app could not accept.",
                "Reconnect; if it repeats, report the Gateway version.",
            ),
        }
    }

    /// Returns the operator-facing message.
    #[must_use]
    pub fn message(&self) -> &str {
        &self.message
    }

    /// Returns the corrective action.
    #[must_use]
    pub fn action(&self) -> &str {
        &self.action
    }
}

/// One observation about the single in-flight connection attempt.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum AttemptUpdate {
    /// A session device identity was generated.
    IdentityCreated(String),
    /// The socket is being established.
    Connecting,
    /// The challenge/connect/hello exchange is running.
    Authenticating,
    /// The connection is authenticated.
    Ready(ReadySummary),
    /// A bounded retry is pending.
    Reconnecting {
        /// One-based retry attempt.
        attempt: u32,
        /// Selected backoff including jitter.
        delay: Duration,
    },
    /// The attempt stopped for a reason the operator must act on.
    Failed(UserError),
    /// The attempt stopped at the operator's request.
    Stopped,
}

impl AttemptUpdate {
    /// Projects one transport lifecycle state onto an operator-facing update.
    #[must_use]
    pub fn from_connection_state(state: &ConnectionState) -> Self {
        match state {
            ConnectionState::Starting | ConnectionState::Connecting => Self::Connecting,
            ConnectionState::Authenticating => Self::Authenticating,
            ConnectionState::Ready(ready) => Self::Ready(ReadySummary::from_info(&ready.info)),
            ConnectionState::Reconnecting { attempt, delay } => Self::Reconnecting {
                attempt: *attempt,
                delay: *delay,
            },
            ConnectionState::ResyncRequired(reason) => Self::Failed(UserError::from_gateway(
                &GatewayClientError::Protocol(ProtocolFailure::ResyncRequired(*reason)),
            )),
            ConnectionState::AuthenticationFailed(failure) => Self::Failed(
                UserError::from_gateway(&GatewayClientError::Authentication(*failure)),
            ),
            ConnectionState::ProtocolFailed { category } => Self::Failed(UserError::from_gateway(
                &GatewayClientError::Protocol(ProtocolFailure::WebSocketProtocol(category)),
            )),
            ConnectionState::ReconnectExhausted => Self::Failed(UserError::from_gateway(
                &GatewayClientError::ReconnectExhausted,
            )),
            ConnectionState::Stopped => Self::Stopped,
        }
    }
}

/// The coarse phase the operator sees.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum StatusKind {
    /// Nothing is happening.
    Neutral,
    /// An operation is running.
    Info,
    /// The connection is authenticated.
    Success,
    /// A recoverable interruption.
    Warning,
    /// A terminal failure.
    Danger,
}

#[derive(Clone, Debug, Eq, PartialEq)]
enum Phase {
    Idle,
    Connecting,
    Authenticating,
    Ready(Box<ReadySummary>),
    Reconnecting { attempt: u32, delay: Duration },
    Failed(UserError),
    Stopped,
}

/// The onboarding view state for exactly one Gateway connection at a time.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ViewModel {
    generation: u64,
    phase: Phase,
    endpoint: String,
    identity: Option<String>,
    token_offered: bool,
    posture: Option<TransportPosture>,
}

impl Default for ViewModel {
    fn default() -> Self {
        Self::new()
    }
}

impl ViewModel {
    /// Creates the initial idle state.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            generation: 0,
            phase: Phase::Idle,
            endpoint: String::new(),
            identity: None,
            token_offered: false,
            posture: None,
        }
    }

    /// Returns whether a new attempt may start now.    #[must_use]
    pub const fn can_start_connection(&self) -> bool {
        matches!(self.phase, Phase::Idle | Phase::Failed(_) | Phase::Stopped)
    }

    /// Starts a new attempt and returns the generation that owns it.
    ///
    /// Every later [`Self::apply`] carrying an older generation is discarded, so
    /// a late update from an abandoned attempt cannot overwrite the live one.
    pub fn begin(&mut self, request: &ConnectRequest) -> u64 {
        self.generation = self.generation.wrapping_add(1);
        self.phase = Phase::Connecting;
        self.endpoint = request.endpoint_display();
        self.identity = None;
        self.token_offered = request.has_token();
        self.posture = Some(request.transport_posture());
        self.generation
    }

    /// Returns the generation currently owning the view.
    #[must_use]
    pub const fn generation(&self) -> u64 {
        self.generation
    }

    /// Applies one update, ignoring any update from a superseded attempt.
    ///
    /// Returns whether the update was accepted.
    pub fn apply(&mut self, generation: u64, update: AttemptUpdate) -> bool {
        if generation != self.generation {
            return false;
        }
        match update {
            AttemptUpdate::IdentityCreated(identity) => self.identity = Some(identity),
            AttemptUpdate::Connecting => self.phase = Phase::Connecting,
            AttemptUpdate::Authenticating => self.phase = Phase::Authenticating,
            AttemptUpdate::Ready(summary) => self.phase = Phase::Ready(Box::new(summary)),
            AttemptUpdate::Reconnecting { attempt, delay } => {
                self.phase = Phase::Reconnecting { attempt, delay };
            }
            AttemptUpdate::Failed(error) => self.phase = Phase::Failed(error),
            AttemptUpdate::Stopped => self.phase = Phase::Stopped,
        }
        true
    }

    /// Marks the attempt stopped without waiting for the transport to report it.
    pub fn request_stop(&mut self) {
        self.generation = self.generation.wrapping_add(1);
        self.phase = Phase::Stopped;
    }

    /// Renders the current state for the UI layer.
    #[must_use]
    pub fn snapshot(&self) -> ViewSnapshot {
        let (title, detail, status_label, status_kind) = match &self.phase {
            Phase::Idle => (
                "Not connected".to_owned(),
                "Enter a Gateway address to begin.".to_owned(),
                "Idle".to_owned(),
                StatusKind::Neutral,
            ),
            Phase::Connecting => (
                "Connecting".to_owned(),
                format!("Opening a socket to {}.", self.endpoint),
                "Connecting".to_owned(),
                StatusKind::Info,
            ),
            Phase::Authenticating => (
                "Authenticating".to_owned(),
                "Proving this device to the Gateway.".to_owned(),
                "Authenticating".to_owned(),
                StatusKind::Info,
            ),
            Phase::Ready(summary) => (
                "Connected".to_owned(),
                format!(
                    "Gateway {} accepted this device as {}.",
                    summary.server_version(),
                    summary.role()
                ),
                "Connected".to_owned(),
                StatusKind::Success,
            ),
            Phase::Reconnecting { attempt, delay } => (
                "Reconnecting".to_owned(),
                format!("Attempt {attempt} starts in {} ms.", delay.as_millis()),
                "Reconnecting".to_owned(),
                StatusKind::Warning,
            ),
            Phase::Failed(error) => (
                "Connection failed".to_owned(),
                error.message().to_owned(),
                "Failed".to_owned(),
                StatusKind::Danger,
            ),
            Phase::Stopped => (
                "Disconnected".to_owned(),
                "The connection was stopped.".to_owned(),
                "Stopped".to_owned(),
                StatusKind::Neutral,
            ),
        };

        let ready = match &self.phase {
            Phase::Ready(summary) => Some(summary.as_ref()),
            _ => None,
        };

        ViewSnapshot {
            title,
            detail,
            status_label,
            status_kind,
            endpoint_summary: if self.endpoint.is_empty() {
                "No Gateway selected".to_owned()
            } else {
                self.endpoint.clone()
            },
            server_summary: ready
                .map_or_else(|| "—".to_owned(), |ready| ready.server_version().to_owned()),
            protocol_summary: ready
                .map_or_else(|| "—".to_owned(), |ready| format!("v{}", ready.protocol())),
            role_summary: ready.map_or_else(|| "—".to_owned(), |ready| ready.role().to_owned()),
            scopes_summary: ready.map_or_else(
                || "—".to_owned(),
                |ready| {
                    if ready.scopes().is_empty() {
                        "none granted".to_owned()
                    } else {
                        ready.scopes().join(", ")
                    }
                },
            ),
            identity_summary: self
                .identity
                .clone()
                .unwrap_or_else(|| "not generated".to_owned()),
            credential_notice: CREDENTIAL_NOTICE.to_owned(),
            transport_notice: self.posture.map_or_else(
                || "No connection has been attempted yet.".to_owned(),
                |posture| posture.notice().to_owned(),
            ),
            token_offered: self.token_offered,
            busy: matches!(
                self.phase,
                Phase::Connecting | Phase::Authenticating | Phase::Reconnecting { .. }
            ),
            can_connect: self.can_start_connection(),
            can_disconnect: matches!(
                self.phase,
                Phase::Connecting
                    | Phase::Authenticating
                    | Phase::Ready(_)
                    | Phase::Reconnecting { .. }
            ),
            error: match &self.phase {
                Phase::Failed(error) => Some(error.clone()),
                _ => None,
            },
        }
    }
}

/// Stated plainly because this app implements no credential storage at all.
///
/// `GatewayClient::take_issued_device_tokens` hands back device tokens, and this
/// app deliberately drops them. Claiming anything else here would be a fabricated
/// summary of a policy that no code enforces.
pub const CREDENTIAL_NOTICE: &str = "Session only. No token or device key is written to this device, so every launch \
     re-authenticates from scratch.";

/// An immutable projection of [`ViewModel`] for the UI layer.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ViewSnapshot {
    title: String,
    detail: String,
    status_label: String,
    status_kind: StatusKind,
    endpoint_summary: String,
    server_summary: String,
    protocol_summary: String,
    role_summary: String,
    scopes_summary: String,
    identity_summary: String,
    credential_notice: String,
    transport_notice: String,
    token_offered: bool,
    busy: bool,
    can_connect: bool,
    can_disconnect: bool,
    error: Option<UserError>,
}

macro_rules! snapshot_string_accessors {
    ($($field:ident),* $(,)?) => {
        impl ViewSnapshot {
            $(
                /// Returns the rendered value for this field.
                #[must_use]
                pub fn $field(&self) -> &str {
                    &self.$field
                }
            )*
        }
    };
}

snapshot_string_accessors!(
    title,
    detail,
    status_label,
    endpoint_summary,
    server_summary,
    protocol_summary,
    role_summary,
    scopes_summary,
    identity_summary,
    credential_notice,
    transport_notice,
);

impl ViewSnapshot {
    /// Returns the coarse status phase.
    #[must_use]
    pub const fn status_kind(&self) -> StatusKind {
        self.status_kind
    }

    /// Returns whether the attempt was made with a shared token.
    #[must_use]
    pub const fn token_offered(&self) -> bool {
        self.token_offered
    }

    /// Returns whether an operation is running.
    #[must_use]
    pub const fn busy(&self) -> bool {
        self.busy
    }

    /// Returns whether the connect control is enabled.
    #[must_use]
    pub const fn can_connect(&self) -> bool {
        self.can_connect
    }

    /// Returns whether the disconnect control is enabled.
    #[must_use]
    pub const fn can_disconnect(&self) -> bool {
        self.can_disconnect
    }

    /// Returns the current operator-facing failure, when there is one.
    #[must_use]
    pub const fn error(&self) -> Option<&UserError> {
        self.error.as_ref()
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use claw_gateway_client::{ConnectionInfo, ConnectionState};
    use claw_protocol::gateway::{ConnectErrorDetailCode, ProtocolVersion};

    use super::{
        AttemptUpdate, ConnectRequest, ReadySummary, StatusKind, SubmissionRejection,
        TransportPosture, UserError, ViewModel,
    };

    /// Every detail code the frozen registry can carry.
    ///
    /// Listed by hand so that adding a variant upstream fails the exhaustive
    /// match in `from_authentication` *and* leaves this list visibly short.
    const ALL_DETAIL_CODES: &[ConnectErrorDetailCode] = &[
        ConnectErrorDetailCode::AuthRequired,
        ConnectErrorDetailCode::AuthUnauthorized,
        ConnectErrorDetailCode::AuthTokenMissing,
        ConnectErrorDetailCode::AuthTokenMismatch,
        ConnectErrorDetailCode::AuthTokenNotConfigured,
        ConnectErrorDetailCode::AuthPasswordMissing,
        ConnectErrorDetailCode::AuthPasswordMismatch,
        ConnectErrorDetailCode::AuthPasswordNotConfigured,
        ConnectErrorDetailCode::AuthBootstrapTokenInvalid,
        ConnectErrorDetailCode::AuthDeviceTokenMismatch,
        ConnectErrorDetailCode::AuthScopeMismatch,
        ConnectErrorDetailCode::AuthRateLimited,
        ConnectErrorDetailCode::AuthTailscaleIdentityMissing,
        ConnectErrorDetailCode::AuthTailscaleProxyMissing,
        ConnectErrorDetailCode::AuthTailscaleWhoisFailed,
        ConnectErrorDetailCode::AuthTailscaleIdentityMismatch,
        ConnectErrorDetailCode::ControlUiOriginNotAllowed,
        ConnectErrorDetailCode::ProtocolMismatch,
        ConnectErrorDetailCode::ControlUiDeviceIdentityRequired,
        ConnectErrorDetailCode::DeviceIdentityRequired,
        ConnectErrorDetailCode::DeviceAuthInvalid,
        ConnectErrorDetailCode::DeviceAuthDeviceIdMismatch,
        ConnectErrorDetailCode::DeviceAuthSignatureExpired,
        ConnectErrorDetailCode::DeviceAuthNonceRequired,
        ConnectErrorDetailCode::DeviceAuthNonceMismatch,
        ConnectErrorDetailCode::DeviceAuthSignatureInvalid,
        ConnectErrorDetailCode::DeviceAuthPublicKeyInvalid,
        ConnectErrorDetailCode::PairingRequired,
        ConnectErrorDetailCode::ClientVersionMismatch,
    ];

    /// Codes describing something this Android build structurally cannot do.
    const UNSUPPORTABLE_ON_ANDROID: &[ConnectErrorDetailCode] = &[
        ConnectErrorDetailCode::AuthTailscaleIdentityMissing,
        ConnectErrorDetailCode::AuthTailscaleProxyMissing,
        ConnectErrorDetailCode::AuthTailscaleWhoisFailed,
        ConnectErrorDetailCode::AuthTailscaleIdentityMismatch,
        ConnectErrorDetailCode::PairingRequired,
        ConnectErrorDetailCode::AuthPasswordMissing,
        ConnectErrorDetailCode::AuthPasswordMismatch,
        ConnectErrorDetailCode::AuthPasswordNotConfigured,
    ];

    fn ready_info(role: &str, scopes: &[&str]) -> ConnectionInfo {
        ConnectionInfo {
            protocol: ProtocolVersion::new(4).expect("protocol 4 is positive"),
            server_version: "2026.7.2".to_owned(),
            connection_id: "conn-1".to_owned(),
            role: role.to_owned(),
            scopes: scopes
                .iter()
                .map(|scope| (*scope).to_owned())
                .collect::<Vec<_>>()
                .into(),
            advertised_method_count: 12,
            advertised_event_count: 5,
            max_payload_bytes: 64 * 1024,
        }
    }

    #[test]
    fn bare_host_defaults_to_encrypted_websocket() {
        let request = ConnectRequest::prepare("gateway.example.com:8443", "", false)
            .expect("a bare host must be accepted");

        assert_eq!(
            request.endpoint_display(),
            "wss://gateway.example.com:8443",
            "bare hosts must default to wss, got {:?}",
            request
        );
    }

    #[test]
    fn remote_plaintext_is_refused_without_the_explicit_opt_in() {
        let rejection = ConnectRequest::prepare("ws://gateway.example.com", "", false)
            .expect_err("remote ws:// must be refused");

        assert_eq!(
            rejection,
            SubmissionRejection::InsecureRemoteEndpoint,
            "remote plaintext must be refused with the insecure-endpoint reason, got {rejection:?}"
        );
    }

    #[test]
    fn remote_plaintext_opt_in_is_recorded_rather_than_discarded() {
        let request = ConnectRequest::prepare("ws://gateway.example.com", "", true)
            .expect("the explicit opt-in must be honoured");

        assert!(
            request.allow_insecure_remote_ws(),
            "the opt-in must survive validation so the transport config can enforce it, got {request:?}"
        );
        let (url, _token, allow) = request.into_parts();
        assert!(
            allow,
            "into_parts must carry the opt-in to the transport, url scheme was {:?}",
            url.scheme()
        );
    }

    #[test]
    fn the_transport_notice_describes_the_scheme_not_the_checkbox() {
        // Ticking the plaintext box and then connecting over TLS must not tell
        // the operator their traffic is in the clear. The checkbox is a
        // permission; the posture is what the transport will actually do.
        let request = ConnectRequest::prepare("wss://gateway.example.com", "", true)
            .expect("wss must be accepted regardless of the plaintext opt-in");

        let posture = request.transport_posture();

        assert_eq!(
            posture,
            TransportPosture::Encrypted,
            "an opted-in wss:// request must still report an encrypted posture, got {posture:?} for {request:?}"
        );
        assert!(
            request.allow_insecure_remote_ws(),
            "the permission itself must still be recorded, got {request:?}"
        );
        assert!(
            !posture.notice().contains("NOT encrypted"),
            "an encrypted connection must not be described as unencrypted, notice was {:?}",
            posture.notice()
        );
    }

    #[test]
    fn each_plaintext_posture_is_distinguished() {
        let remote = ConnectRequest::prepare("ws://gateway.example.com", "", true)
            .expect("opted-in remote plaintext must be accepted")
            .transport_posture();
        assert_eq!(
            remote,
            TransportPosture::PlaintextRemote,
            "remote ws:// must report the remote plaintext posture, got {remote:?}"
        );
        assert!(
            remote.notice().contains("NOT encrypted"),
            "remote plaintext must say so plainly, notice was {:?}",
            remote.notice()
        );

        let loopback = ConnectRequest::prepare("ws://127.0.0.1:9000", "", false)
            .expect("loopback plaintext needs no opt-in")
            .transport_posture();
        assert_eq!(
            loopback,
            TransportPosture::PlaintextLoopback,
            "loopback ws:// must be distinguished from remote plaintext, got {loopback:?}"
        );
    }

    #[test]
    fn the_transport_notice_is_absent_before_any_attempt() {
        let model = ViewModel::new();

        let snapshot = model.snapshot();

        assert_eq!(
            snapshot.transport_notice(),
            "No connection has been attempted yet.",
            "an untried model must not describe a transport it has not chosen, got {:?}",
            snapshot.transport_notice()
        );
    }

    #[test]
    fn loopback_plaintext_needs_no_opt_in() {
        let request = ConnectRequest::prepare("ws://127.0.0.1:9000", "", false)
            .expect("loopback plaintext is allowed by the transport policy");

        assert_eq!(
            request.endpoint_display(),
            "ws://127.0.0.1:9000",
            "loopback plaintext must be preserved verbatim, got {request:?}"
        );
        assert!(
            !request.allow_insecure_remote_ws(),
            "loopback must not silently set the remote opt-in, got {request:?}"
        );
    }

    #[test]
    fn credential_bearing_endpoints_are_refused() {
        for endpoint in [
            "wss://user@gateway.example.com",
            "wss://user:secret@gateway.example.com",
            "wss://gateway.example.com/?token=abc",
            "wss://gateway.example.com/#token",
        ] {
            let rejection = ConnectRequest::prepare(endpoint, "", false)
                .err()
                .unwrap_or_else(|| panic!("{endpoint} must be refused"));

            assert_eq!(
                rejection,
                SubmissionRejection::CredentialBearingEndpoint,
                "{endpoint} must be refused as credential-bearing, got {rejection:?}"
            );
        }
    }

    #[test]
    fn unsupported_schemes_are_refused() {
        let rejection = ConnectRequest::prepare("https://gateway.example.com", "", false)
            .expect_err("https must be refused");

        assert_eq!(
            rejection,
            SubmissionRejection::UnsupportedScheme,
            "https must be refused for an unsupported scheme, got {rejection:?}"
        );
    }

    #[test]
    fn oversized_input_is_refused_before_any_parsing() {
        let endpoint = format!("wss://{}", "a".repeat(super::MAX_ENDPOINT_BYTES));
        let rejection = ConnectRequest::prepare(&endpoint, "", false)
            .expect_err("an oversized endpoint must be refused");
        assert_eq!(
            rejection,
            SubmissionRejection::EndpointTooLong,
            "endpoint of {} bytes must be refused as too long, got {rejection:?}",
            endpoint.len()
        );

        let token = "t".repeat(super::MAX_TOKEN_BYTES + 1);
        let rejection = ConnectRequest::prepare("wss://gateway.example.com", &token, false)
            .expect_err("an oversized token must be refused");
        assert_eq!(
            rejection,
            SubmissionRejection::TokenTooLong,
            "token of {} bytes must be refused as too long, got {rejection:?}",
            token.len()
        );
    }

    #[test]
    fn debug_output_never_reproduces_the_token_or_the_path() {
        let request = ConnectRequest::prepare(
            "wss://gateway.example.com:8443/tenant/9f3c-secret-path",
            "super-secret-token",
            false,
        )
        .expect("a valid request");

        let rendered = format!("{request:?}");

        assert!(
            !rendered.contains("super-secret-token"),
            "Debug leaked the token: {rendered}"
        );
        assert!(
            !rendered.contains("9f3c-secret-path"),
            "Debug leaked the endpoint path: {rendered}"
        );
        assert!(
            rendered.contains("wss://gateway.example.com:8443"),
            "Debug must still identify the server authority: {rendered}"
        );
    }

    #[test]
    fn endpoint_display_withholds_the_path() {
        let request = ConnectRequest::prepare("wss://gateway.example.com/tenant/secret", "", false)
            .expect("a valid request");

        assert_eq!(
            request.endpoint_display(),
            "wss://gateway.example.com",
            "endpoint_display must show only scheme and authority, got {request:?}"
        );
    }

    #[test]
    fn stale_updates_from_a_superseded_attempt_are_discarded() {
        let mut model = ViewModel::new();
        let first = model
            .begin(&ConnectRequest::prepare("wss://one.example.com", "", false).expect("valid"));
        let second = model
            .begin(&ConnectRequest::prepare("wss://two.example.com", "", false).expect("valid"));

        let accepted = model.apply(
            first,
            AttemptUpdate::Ready(ReadySummary::from_info(&ready_info("operator", &["read"]))),
        );

        assert!(
            !accepted,
            "generation {first} is superseded by {second} and must be discarded; snapshot was {:?}",
            model.snapshot()
        );
        assert_eq!(
            model.snapshot().status_kind(),
            StatusKind::Info,
            "the live attempt must stay in its connecting phase, snapshot was {:?}",
            model.snapshot()
        );
        assert_eq!(
            model.snapshot().endpoint_summary(),
            "wss://two.example.com",
            "the live attempt's endpoint must be shown, snapshot was {:?}",
            model.snapshot()
        );
    }

    #[test]
    fn ready_snapshot_reports_the_scopes_the_gateway_actually_granted() {
        let mut model = ViewModel::new();
        let generation = model.begin(
            &ConnectRequest::prepare("wss://gateway.example.com", "token", false).expect("valid"),
        );
        // The Gateway granted fewer scopes than a caller might request. The UI
        // must report the granted set, never the requested one.
        let accepted = model.apply(
            generation,
            AttemptUpdate::Ready(ReadySummary::from_info(&ready_info(
                "operator",
                &["operator:read"],
            ))),
        );
        assert!(accepted, "the live generation must be accepted");

        let snapshot = model.snapshot();

        assert_eq!(
            snapshot.scopes_summary(),
            "operator:read",
            "the snapshot must mirror the granted scopes, snapshot was {snapshot:?}"
        );
        assert_eq!(
            snapshot.role_summary(),
            "operator",
            "the snapshot must mirror the granted role, snapshot was {snapshot:?}"
        );
        assert_eq!(
            snapshot.status_kind(),
            StatusKind::Success,
            "a ready connection is a success phase, snapshot was {snapshot:?}"
        );
        assert!(
            snapshot.token_offered(),
            "the snapshot must record that a token was supplied, snapshot was {snapshot:?}"
        );
    }

    #[test]
    fn empty_granted_scopes_are_stated_rather_than_implied() {
        let mut model = ViewModel::new();
        let generation = model.begin(
            &ConnectRequest::prepare("wss://gateway.example.com", "", false).expect("valid"),
        );
        model.apply(
            generation,
            AttemptUpdate::Ready(ReadySummary::from_info(&ready_info("operator", &[]))),
        );

        let snapshot = model.snapshot();

        assert_eq!(
            snapshot.scopes_summary(),
            "none granted",
            "an empty grant must be stated explicitly, snapshot was {snapshot:?}"
        );
    }

    #[test]
    fn credential_notice_states_that_nothing_is_persisted() {
        let snapshot = ViewModel::new().snapshot();

        assert_eq!(
            snapshot.credential_notice(),
            super::CREDENTIAL_NOTICE,
            "the snapshot must carry the storage notice verbatim, snapshot was {snapshot:?}"
        );
        assert!(
            snapshot.credential_notice().contains("Session only"),
            "the notice must say nothing is stored, got {:?}",
            snapshot.credential_notice()
        );
    }

    #[test]
    fn transient_states_map_onto_operator_facing_phases() {
        let cases = [
            (ConnectionState::Starting, AttemptUpdate::Connecting),
            (ConnectionState::Connecting, AttemptUpdate::Connecting),
            (
                ConnectionState::Authenticating,
                AttemptUpdate::Authenticating,
            ),
            (ConnectionState::Stopped, AttemptUpdate::Stopped),
            (
                ConnectionState::Reconnecting {
                    attempt: 2,
                    delay: std::time::Duration::from_millis(500),
                },
                AttemptUpdate::Reconnecting {
                    attempt: 2,
                    delay: std::time::Duration::from_millis(500),
                },
            ),
        ];

        for (state, expected) in cases {
            let actual = AttemptUpdate::from_connection_state(&state);
            assert_eq!(
                actual, expected,
                "state {state:?} must map to {expected:?}, got {actual:?}"
            );
        }
    }

    #[test]
    fn exhausted_reconnects_become_an_actionable_failure() {
        let update = AttemptUpdate::from_connection_state(&ConnectionState::ReconnectExhausted);

        let AttemptUpdate::Failed(error) = update else {
            panic!("ReconnectExhausted must map to a failure, got {update:?}");
        };
        assert_eq!(
            error,
            UserError::new(
                "Reconnect attempts ran out.",
                "Check the network and the Gateway address, then connect again."
            ),
            "the failure text must tell the operator what to do, got {error:?}"
        );
    }

    #[test]
    fn a_failed_attempt_can_be_retried_but_a_live_one_cannot() {
        let mut model = ViewModel::new();
        let generation = model.begin(
            &ConnectRequest::prepare("wss://gateway.example.com", "", false).expect("valid"),
        );
        assert!(
            !model.can_start_connection(),
            "a live attempt must block a second one, snapshot was {:?}",
            model.snapshot()
        );

        model.apply(
            generation,
            AttemptUpdate::Failed(UserError::new("boom", "retry")),
        );

        assert!(
            model.can_start_connection(),
            "a failed attempt must be retryable, snapshot was {:?}",
            model.snapshot()
        );
        assert!(
            model.snapshot().can_connect(),
            "the snapshot must enable the connect control, snapshot was {:?}",
            model.snapshot()
        );
    }

    #[test]
    fn requesting_a_stop_supersedes_the_running_attempt() {
        let mut model = ViewModel::new();
        let generation = model.begin(
            &ConnectRequest::prepare("wss://gateway.example.com", "", false).expect("valid"),
        );

        model.request_stop();
        let accepted = model.apply(
            generation,
            AttemptUpdate::Ready(ReadySummary::from_info(&ready_info("operator", &["read"]))),
        );

        assert!(
            !accepted,
            "a stopped attempt must not be resurrected by a late Ready, snapshot was {:?}",
            model.snapshot()
        );
        assert_eq!(
            model.snapshot().status_kind(),
            StatusKind::Neutral,
            "a stopped model is neutral, snapshot was {:?}",
            model.snapshot()
        );
    }

    #[test]
    fn scopes_are_projected_from_the_shared_connection_info() {
        let info = ready_info("operator", &["operator:read", "operator:write"]);
        let summary = ReadySummary::from_info(&info);

        assert_eq!(
            summary.scopes(),
            ["operator:read".to_owned(), "operator:write".to_owned()],
            "the summary must copy the granted scopes, info scopes were {:?}",
            Arc::clone(&info.scopes)
        );
        assert_eq!(
            summary.protocol(),
            4,
            "the summary must copy the negotiated protocol, got {summary:?}"
        );
        assert_eq!(
            summary.max_payload_bytes(),
            64 * 1024,
            "the summary must copy the payload cap, got {summary:?}"
        );
    }
    #[test]
    fn a_tailscale_rejection_states_the_platform_limit_instead_of_blaming_the_token() {
        for code in UNSUPPORTABLE_ON_ANDROID {
            let error = UserError::from_authentication(Some(*code), false);
            let action = error.action().to_lowercase();

            assert!(
                !action.contains("check the token"),
                "{code:?} cannot be fixed by checking the token, but the advice was {:?}",
                error.action()
            );
            assert!(
                !action.contains("try again") && !action.contains("connect again"),
                "{code:?} is not fixable on this platform, so retrying is not advice; got {:?}",
                error.action()
            );
        }
    }

    #[test]
    fn a_server_recommended_device_retry_cannot_override_an_unfixable_reason() {
        // A Gateway may set the device-retry hint alongside a Tailscale
        // rejection. Following it would loop forever.
        let error = UserError::from_authentication(
            Some(ConnectErrorDetailCode::AuthTailscaleProxyMissing),
            true,
        );

        assert!(
            !error.action().contains("fresh device token"),
            "a device-token retry cannot satisfy Tailscale, but the advice was {:?}",
            error.action()
        );
    }

    #[test]
    fn rate_limiting_is_not_answered_with_retry_now() {
        let error =
            UserError::from_authentication(Some(ConnectErrorDetailCode::AuthRateLimited), false);
        let action = error.action().to_lowercase();

        assert!(
            action.contains("wait"),
            "rate limiting must advise waiting, got {:?}",
            error.action()
        );
    }

    /// `PairingRequired` is the one code whose advice cannot be recovered from
    /// by retrying: this build ships no pairing screen, so an operator told to
    /// wait or to retry will do so indefinitely. The other codes are covered by
    /// the property assertions above, which hold for any correct message; this
    /// one binds the code to its advice, because a message swapped in from a
    /// neighbouring arm satisfies every property and is still wrong.
    #[test]
    fn pairing_required_directs_the_operator_to_another_client() {
        let error =
            UserError::from_authentication(Some(ConnectErrorDetailCode::PairingRequired), false);
        let action = error.action().to_lowercase();

        assert!(
            action.contains("pairing") || action.contains("pair"),
            "PairingRequired must name pairing as the remedy, got {:?}",
            error.action()
        );
        assert!(
            !action.contains("wait"),
            "this build has no pairing screen, so advising the operator to wait leaves them \
             stuck indefinitely; got {:?}",
            error.action()
        );
    }

    #[test]
    fn every_detail_code_produces_a_non_empty_remedy() {
        for code in ALL_DETAIL_CODES {
            let error = UserError::from_authentication(Some(*code), false);

            assert!(
                !error.message().trim().is_empty(),
                "{code:?} produced an empty message"
            );
            assert!(
                !error.action().trim().is_empty(),
                "{code:?} produced an empty action"
            );
        }
    }

    #[test]
    fn an_absent_detail_code_still_honours_the_device_retry_hint() {
        let hinted = UserError::from_authentication(None, true);
        let plain = UserError::from_authentication(None, false);

        assert!(
            hinted.action().contains("fresh device token"),
            "the server hint must reach the operator, got {:?}",
            hinted.action()
        );
        assert_ne!(
            hinted.action(),
            plain.action(),
            "the hint must change the advice, but both said {:?}",
            plain.action()
        );
    }

    #[test]
    fn no_remedy_reproduces_a_credential() {
        for code in ALL_DETAIL_CODES {
            let error = UserError::from_authentication(Some(*code), true);
            let rendered = format!("{} {} {error:?}", error.message(), error.action());

            for secret in ["hunter2", "wss://", "Bearer "] {
                assert!(
                    !rendered.contains(secret),
                    "{code:?} rendered {secret:?} into operator-facing text: {rendered}"
                );
            }
        }
    }
}

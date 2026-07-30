use std::fmt::{self, Debug, Formatter};

use claw_gateway_client::{
    AuthenticationFailure, BackpressureError, ConnectionInfo, GatewayClientError, ProtocolFailure,
    TransportFailure,
};
use claw_protocol::gateway::ConnectErrorDetailCode;
use secrecy::SecretString;
use url::{Host, Url};

const MAX_ENDPOINT_INPUT_BYTES: usize = 2_048;
const MAX_ENDPOINT_DISPLAY_CHARS: usize = 256;
const MAX_TOKEN_BYTES: usize = 4_096;
const MAX_PRESENTATION_CHARS: usize = 240;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum UiStatusKind {
    Neutral,
    Success,
    Warning,
    Danger,
    Info,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum OnboardingPhase {
    Disconnected,
    Connecting,
    Authenticating,
    PairingRequired,
    Reconnecting,
    HealthChecking,
    Ready,
    Failed,
    Disconnecting,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum UserErrorKind {
    Input,
    Transport,
    Authentication,
    Pairing,
    Protocol,
    Backpressure,
    Shutdown,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct UserError {
    kind: UserErrorKind,
    code: &'static str,
    message: String,
    action: String,
}

impl UserError {
    fn new(
        kind: UserErrorKind,
        code: &'static str,
        message: impl Into<String>,
        action: impl Into<String>,
    ) -> Self {
        Self {
            kind,
            code,
            message: bounded_text(message.into(), MAX_PRESENTATION_CHARS),
            action: bounded_text(action.into(), MAX_PRESENTATION_CHARS),
        }
    }

    pub(crate) fn input(
        code: &'static str,
        message: impl Into<String>,
        action: impl Into<String>,
    ) -> Self {
        Self::new(UserErrorKind::Input, code, message, action)
    }

    pub(crate) fn from_gateway(error: &GatewayClientError) -> Self {
        match error {
            GatewayClientError::Configuration(_) => Self::new(
                UserErrorKind::Input,
                "gateway.configuration",
                "This Gateway address is not allowed by the desktop security policy.",
                "Use wss:// for remote Gateways, or ws:// for a loopback address.",
            ),
            GatewayClientError::Transport(transport) => Self::transport(*transport),
            GatewayClientError::Authentication(authentication) => {
                Self::authentication(*authentication)
            }
            GatewayClientError::Protocol(protocol) => Self::protocol(protocol),
            GatewayClientError::Backpressure(backpressure) => Self::backpressure(*backpressure),
            GatewayClientError::NotReady => Self::new(
                UserErrorKind::Transport,
                "gateway.not-ready",
                "The Gateway stopped being ready before the health check completed.",
                "Wait for reconnection or retry the connection.",
            ),
            GatewayClientError::Cancelled => Self::new(
                UserErrorKind::Shutdown,
                "gateway.cancelled",
                "The connection attempt was cancelled.",
                "Start a new connection when ready.",
            ),
            GatewayClientError::DisconnectedNotReplayed => Self::new(
                UserErrorKind::Transport,
                "gateway.disconnected",
                "The health check was cancelled when the connection changed.",
                "A fresh health check will run after reconnection.",
            ),
            GatewayClientError::ConnectionChanged { .. } => Self::new(
                UserErrorKind::Transport,
                "gateway.connection-changed",
                "The Gateway connection changed before this health check completed.",
                "A fresh health check will run on the new authenticated connection.",
            ),
            GatewayClientError::RequestTimedOut(_) => Self::new(
                UserErrorKind::Transport,
                "gateway.health-timeout",
                "The Gateway did not answer the health check in time.",
                "Check the Gateway and retry. No request was replayed.",
            ),
            GatewayClientError::ShutdownTimedOut => Self::new(
                UserErrorKind::Shutdown,
                "gateway.shutdown-timeout",
                "The Gateway connection did not close within the safety bound.",
                "The attempt was abandoned; retry only after checking the Gateway.",
            ),
            GatewayClientError::ReconnectExhausted => Self::new(
                UserErrorKind::Transport,
                "gateway.reconnect-exhausted",
                "The bounded diagnostic reconnect attempts were exhausted.",
                "Check the address and Gateway availability, then retry manually.",
            ),
        }
    }

    fn transport(error: TransportFailure) -> Self {
        let (code, message) = match error {
            TransportFailure::Connect => (
                "gateway.transport-connect",
                "The desktop could not open the Gateway transport.",
            ),
            TransportFailure::Read => (
                "gateway.transport-read",
                "The Gateway transport stopped while receiving data.",
            ),
            TransportFailure::Write => (
                "gateway.transport-write",
                "The Gateway transport stopped while sending data.",
            ),
            TransportFailure::Closed | TransportFailure::PeerClosed { .. } => (
                "gateway.transport-closed",
                "The Gateway closed the diagnostic connection.",
            ),
            TransportFailure::TimedOut => (
                "gateway.transport-timeout",
                "The Gateway transport exceeded its bounded timeout.",
            ),
            TransportFailure::UnsupportedExtension => (
                "gateway.transport-extension",
                "The Gateway selected an unsupported WebSocket extension.",
            ),
        };
        Self::new(
            UserErrorKind::Transport,
            code,
            message,
            "Check the Gateway address and availability, then retry.",
        )
    }

    fn authentication(error: AuthenticationFailure) -> Self {
        let pairing = matches!(
            error.detail_code(),
            Some(
                ConnectErrorDetailCode::PairingRequired
                    | ConnectErrorDetailCode::ControlUiDeviceIdentityRequired
                    | ConnectErrorDetailCode::DeviceIdentityRequired
            )
        );
        if pairing {
            Self::new(
                UserErrorKind::Pairing,
                "gateway.pairing-required",
                "This session-only device identity requires Gateway pairing approval.",
                "Approve the device on the Gateway, then retry. A new app session creates a new identity.",
            )
        } else {
            Self::new(
                UserErrorKind::Authentication,
                "gateway.authentication",
                "The Gateway rejected the supplied session credential or device proof.",
                "Verify the token and Gateway policy, then retry.",
            )
        }
    }

    fn protocol(error: &ProtocolFailure) -> Self {
        let (code, message) = match error {
            ProtocolFailure::HelloProtocol { .. }
            | ProtocolFailure::HandshakeRejected(ConnectErrorDetailCode::ProtocolMismatch) => (
                "gateway.protocol-version",
                "The Gateway does not support the required pinned protocol version.",
            ),
            ProtocolFailure::HelloAuthenticationMismatch
            | ProtocolFailure::WebSocketProtocol("hello authentication mismatch") => (
                "gateway.protocol-scope",
                "The Gateway returned role or scope claims that did not match the request.",
            ),
            ProtocolFailure::ResyncRequired(_) => (
                "gateway.protocol-resync",
                "Gateway event continuity was lost and the diagnostic view must reconnect.",
            ),
            _ => (
                "gateway.protocol",
                "The Gateway response did not satisfy the pinned protocol contract.",
            ),
        };
        Self::new(
            UserErrorKind::Protocol,
            code,
            message,
            "Check Gateway compatibility before retrying.",
        )
    }

    fn backpressure(error: BackpressureError) -> Self {
        let code = match error {
            BackpressureError::InFlightLimit => "gateway.pressure-in-flight",
            BackpressureError::CommandQueueSaturated => "gateway.pressure-command-queue",
            BackpressureError::CommandBytesSaturated => "gateway.pressure-command-bytes",
            BackpressureError::SerializationSaturated => "gateway.pressure-serialization",
            BackpressureError::IdentifierCapacity => "gateway.pressure-identifiers",
        };
        Self::new(
            UserErrorKind::Backpressure,
            code,
            "The bounded Gateway diagnostic queue is busy.",
            "Wait for the current operation or cancel it before retrying.",
        )
    }

    pub(crate) const fn kind(&self) -> UserErrorKind {
        self.kind
    }

    #[cfg(test)]
    pub(crate) const fn code(&self) -> &'static str {
        self.code
    }

    pub(crate) fn message(&self) -> &str {
        &self.message
    }

    pub(crate) fn action(&self) -> &str {
        &self.action
    }
}

pub(crate) struct GatewayEndpoint {
    url: Url,
    input: String,
    display: String,
}

impl GatewayEndpoint {
    fn parse(input: &str) -> Result<Self, EndpointRejection> {
        if input.is_empty()
            || input.len() > MAX_ENDPOINT_INPUT_BYTES
            || input.trim() != input
            || input.chars().any(char::is_control)
        {
            return Err(EndpointRejection::invalid(None, None));
        }

        let url = Url::parse(input).map_err(|_| EndpointRejection::invalid(None, None))?;
        if !matches!(url.scheme(), "ws" | "wss") || url.host().is_none() {
            return Err(EndpointRejection::invalid(None, None));
        }
        let input = sanitize_url(&url);
        let display = bounded_text(input.clone(), MAX_ENDPOINT_DISPLAY_CHARS);
        if !url.username().is_empty()
            || url.password().is_some()
            || url.query().is_some()
            || url.fragment().is_some()
        {
            return Err(EndpointRejection {
                input: Some(input),
                display: Some(display),
                error: UserError::input(
                    "endpoint.credentials",
                    "Gateway addresses cannot contain user information, query values, or fragments.",
                    "Enter credentials only in the session token field.",
                ),
            });
        }
        if url.scheme() == "ws" && !is_loopback(url.host().as_ref()) {
            return Err(EndpointRejection {
                input: Some(input),
                display: Some(display),
                error: UserError::input(
                    "endpoint.insecure-remote",
                    "Remote plaintext WebSocket connections are disabled.",
                    "Use a wss:// Gateway address, or ws:// on localhost.",
                ),
            });
        }
        Ok(Self {
            url,
            input,
            display,
        })
    }

    pub(crate) fn into_url(self) -> Url {
        self.url
    }

    pub(crate) fn display(&self) -> &str {
        &self.display
    }

    pub(crate) fn input(&self) -> &str {
        &self.input
    }
}

impl Debug for GatewayEndpoint {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("GatewayEndpoint")
            .field("display", &self.display)
            .finish_non_exhaustive()
    }
}

fn sanitize_url(url: &Url) -> String {
    let mut sanitized = url.clone();
    let _ = sanitized.set_username("");
    let _ = sanitized.set_password(None);
    sanitized.set_query(None);
    sanitized.set_fragment(None);
    sanitized.to_string()
}

fn is_loopback(host: Option<&Host<&str>>) -> bool {
    match host {
        Some(Host::Domain("localhost")) => true,
        Some(Host::Ipv4(address)) => address.is_loopback(),
        Some(Host::Ipv6(address)) => address.is_loopback(),
        Some(Host::Domain(_)) | None => false,
    }
}

struct EndpointRejection {
    input: Option<String>,
    display: Option<String>,
    error: UserError,
}

impl EndpointRejection {
    fn invalid(input: Option<String>, display: Option<String>) -> Self {
        Self {
            input,
            display,
            error: UserError::input(
                "endpoint.invalid",
                "Enter a complete ws:// or wss:// Gateway address.",
                "Use wss:// for remote Gateways or ws://localhost for local diagnostics.",
            ),
        }
    }
}

pub(crate) struct ConnectRequest {
    endpoint: GatewayEndpoint,
    token: Option<SecretString>,
}

impl ConnectRequest {
    pub(crate) fn prepare(
        endpoint: &str,
        token: String,
        consent: bool,
    ) -> Result<Self, SubmissionRejection> {
        let token_len = token.len();
        let token = if token.is_empty() {
            None
        } else {
            Some(SecretString::from(token))
        };
        let endpoint =
            GatewayEndpoint::parse(endpoint).map_err(|rejection| SubmissionRejection {
                endpoint_input: rejection.input,
                endpoint_display: rejection.display,
                error: rejection.error,
            })?;
        if token_len > MAX_TOKEN_BYTES {
            return Err(SubmissionRejection {
                endpoint_input: Some(endpoint.input().to_owned()),
                endpoint_display: Some(endpoint.display().to_owned()),
                error: UserError::input(
                    "token.too-long",
                    "The session token exceeds the desktop safety bound.",
                    "Use a valid bounded Gateway token.",
                ),
            });
        }
        if !consent {
            return Err(SubmissionRejection {
                endpoint_input: Some(endpoint.input().to_owned()),
                endpoint_display: Some(endpoint.display().to_owned()),
                error: UserError::input(
                    "identity.consent-required",
                    "Consent is required before creating an ephemeral device identity.",
                    "Review the pairing notice and select the consent checkbox.",
                ),
            });
        }
        Ok(Self { endpoint, token })
    }

    pub(crate) fn endpoint_display(&self) -> &str {
        self.endpoint.display()
    }

    pub(crate) fn endpoint_input(&self) -> &str {
        self.endpoint.input()
    }

    pub(crate) fn into_parts(self) -> (Url, Option<SecretString>) {
        (self.endpoint.into_url(), self.token)
    }
}

impl Debug for ConnectRequest {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ConnectRequest")
            .field("endpoint", &self.endpoint)
            .field("token", &self.token.as_ref().map(|_| "[REDACTED]"))
            .finish()
    }
}

#[derive(Debug)]
pub(crate) struct SubmissionRejection {
    pub(crate) endpoint_input: Option<String>,
    pub(crate) endpoint_display: Option<String>,
    pub(crate) error: UserError,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct SafeSummary {
    endpoint: String,
    server: String,
    protocol: String,
    role: String,
    scopes: String,
    health: String,
    identity: String,
}

impl Default for SafeSummary {
    fn default() -> Self {
        Self {
            endpoint: "Not selected".to_owned(),
            server: "Not connected".to_owned(),
            protocol: "Not negotiated".to_owned(),
            role: "Not authenticated".to_owned(),
            scopes: "No effective scopes".to_owned(),
            health: "Not checked".to_owned(),
            identity: "Created only after consent".to_owned(),
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct OnboardingModel {
    generation: u64,
    phase: OnboardingPhase,
    summary: SafeSummary,
    error: Option<UserError>,
    reconnect_attempt: Option<u32>,
    identity_active: bool,
    reset_consent: bool,
}

impl Default for OnboardingModel {
    fn default() -> Self {
        Self {
            generation: 0,
            phase: OnboardingPhase::Disconnected,
            summary: SafeSummary::default(),
            error: None,
            reconnect_attempt: None,
            identity_active: false,
            reset_consent: false,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) enum AttemptUpdate {
    Connecting,
    Authenticating,
    Reconnecting { attempt: u32 },
    IdentityCreated(String),
    Ready(ConnectionInfo),
    Healthy,
    Failed(UserError),
}

impl OnboardingModel {
    pub(crate) const fn can_start_connection(&self) -> bool {
        matches!(
            self.phase,
            OnboardingPhase::Disconnected
                | OnboardingPhase::Failed
                | OnboardingPhase::PairingRequired
        )
    }

    pub(crate) fn begin(&mut self, endpoint_display: String) -> u64 {
        self.generation = self.generation.wrapping_add(1);
        self.phase = OnboardingPhase::Connecting;
        self.summary = SafeSummary {
            endpoint: bounded_text(endpoint_display, MAX_ENDPOINT_DISPLAY_CHARS),
            ..SafeSummary::default()
        };
        self.error = None;
        self.reconnect_attempt = None;
        self.reset_consent = false;
        self.generation
    }

    pub(crate) fn reject_submission(&mut self, endpoint_display: Option<String>, error: UserError) {
        self.reset_consent = false;
        self.generation = self.generation.wrapping_add(1);
        if let Some(endpoint) = endpoint_display {
            self.summary.endpoint = endpoint;
        }
        self.phase = if error.kind() == UserErrorKind::Pairing {
            OnboardingPhase::PairingRequired
        } else {
            OnboardingPhase::Failed
        };
        self.error = Some(error);
        self.reconnect_attempt = None;
    }

    pub(crate) fn apply(&mut self, generation: u64, update: AttemptUpdate) -> bool {
        if generation != self.generation {
            return false;
        }
        self.reset_consent = false;
        match update {
            AttemptUpdate::Connecting => self.phase = OnboardingPhase::Connecting,
            AttemptUpdate::Authenticating => self.phase = OnboardingPhase::Authenticating,
            AttemptUpdate::Reconnecting { attempt } => {
                self.phase = OnboardingPhase::Reconnecting;
                self.reconnect_attempt = Some(attempt);
                "Waiting for a fresh connection".clone_into(&mut self.summary.health);
            }
            AttemptUpdate::IdentityCreated(identity) => {
                self.summary.identity = bounded_text(identity, 96);
                self.identity_active = true;
                self.reset_consent = false;
            }
            AttemptUpdate::Ready(info) => {
                self.phase = OnboardingPhase::HealthChecking;
                self.summary.server = bounded_safe_field(info.server_version, 96);
                self.summary.protocol = format!("Gateway v{}", info.protocol.get());
                self.summary.role = bounded_safe_field(info.role, 64);
                self.summary.scopes = if info.scopes.is_empty() {
                    "No effective scopes".to_owned()
                } else {
                    bounded_safe_field(info.scopes.join(", "), 160)
                };
                "Checking with safe health RPC".clone_into(&mut self.summary.health);
                self.error = None;
                self.reconnect_attempt = None;
            }
            AttemptUpdate::Healthy => {
                self.phase = OnboardingPhase::Ready;
                "Healthy - safe RPC completed".clone_into(&mut self.summary.health);
                self.error = None;
            }
            AttemptUpdate::Failed(error) => {
                self.phase = if error.kind() == UserErrorKind::Pairing {
                    OnboardingPhase::PairingRequired
                } else {
                    OnboardingPhase::Failed
                };
                "Not connected".clone_into(&mut self.summary.server);
                "Not negotiated".clone_into(&mut self.summary.protocol);
                "Not authenticated".clone_into(&mut self.summary.role);
                "No effective scopes".clone_into(&mut self.summary.scopes);
                "Not healthy - connection failed".clone_into(&mut self.summary.health);
                self.error = Some(error);
                self.reconnect_attempt = None;
            }
        }
        true
    }

    pub(crate) fn start_disconnect(&mut self) -> u64 {
        self.reset_consent = false;
        self.generation = self.generation.wrapping_add(1);
        self.phase = OnboardingPhase::Disconnecting;
        self.error = None;
        self.reconnect_attempt = None;
        self.generation
    }

    pub(crate) fn finish_disconnect(&mut self, generation: u64) -> bool {
        if generation != self.generation {
            return false;
        }
        self.phase = OnboardingPhase::Disconnected;
        "Not connected".clone_into(&mut self.summary.server);
        "Not negotiated".clone_into(&mut self.summary.protocol);
        "Not authenticated".clone_into(&mut self.summary.role);
        "No effective scopes".clone_into(&mut self.summary.scopes);
        "Disconnected".clone_into(&mut self.summary.health);
        let discarded_identity = self.identity_active;
        if discarded_identity {
            "Discarded on disconnect".clone_into(&mut self.summary.identity);
        } else {
            "No session identity created".clone_into(&mut self.summary.identity);
        }
        self.reset_consent = discarded_identity;
        self.identity_active = false;
        true
    }

    pub(crate) fn snapshot(&self) -> ViewSnapshot {
        let (status_kind, status_label, status_icon, title, detail) = match self.phase {
            OnboardingPhase::Disconnected => (
                UiStatusKind::Neutral,
                "Status",
                "-",
                "Connect to your Gateway",
                "Run a real bounded challenge, authentication, and health diagnostic.",
            ),
            OnboardingPhase::Connecting => (
                UiStatusKind::Info,
                "Information",
                "i",
                "Opening secure transport",
                "Connecting without blocking the desktop event loop.",
            ),
            OnboardingPhase::Authenticating => (
                UiStatusKind::Info,
                "Information",
                "i",
                "Authenticating this session",
                "Completing challenge, device proof, connect, and hello.",
            ),
            OnboardingPhase::PairingRequired => (
                UiStatusKind::Warning,
                "Warning",
                "!",
                "Pairing approval required",
                "Approve this ephemeral device on the Gateway, then retry.",
            ),
            OnboardingPhase::Reconnecting => (
                UiStatusKind::Warning,
                "Warning",
                "!",
                "Reconnecting diagnostic",
                "A bounded transient retry is in progress. Requests are not replayed.",
            ),
            OnboardingPhase::HealthChecking => (
                UiStatusKind::Info,
                "Information",
                "i",
                "Checking Gateway health",
                "Authentication succeeded; one safe read-only health RPC is running.",
            ),
            OnboardingPhase::Ready => (
                UiStatusKind::Success,
                "Success",
                "OK",
                "Gateway diagnostic passed",
                "The read-only health probe passed. Product actions remain unavailable.",
            ),
            OnboardingPhase::Failed => (
                UiStatusKind::Danger,
                "Error",
                "X",
                "Connection needs attention",
                "Review the bounded diagnostic and retry after correcting the issue.",
            ),
            OnboardingPhase::Disconnecting => (
                UiStatusKind::Info,
                "Information",
                "i",
                "Disconnecting safely",
                "Cancelling requests and joining Gateway tasks within the shutdown bound.",
            ),
        };
        let status_text = match (self.phase, self.reconnect_attempt) {
            (OnboardingPhase::Reconnecting, Some(attempt)) => {
                format!("Reconnect attempt {attempt}")
            }
            _ => title.to_owned(),
        };
        ViewSnapshot {
            phase: self.phase,
            status_kind,
            status_label,
            status_icon,
            status_text,
            title,
            detail,
            endpoint: self.summary.endpoint.clone(),
            server: self.summary.server.clone(),
            protocol: self.summary.protocol.clone(),
            role: self.summary.role.clone(),
            scopes: self.summary.scopes.clone(),
            health: self.summary.health.clone(),
            identity: self.summary.identity.clone(),
            error: self.error.clone(),
            reset_consent: self.reset_consent,
        }
    }

    pub(crate) fn take_snapshot(&mut self) -> ViewSnapshot {
        let snapshot = self.snapshot();
        self.reset_consent = false;
        snapshot
    }

    #[cfg(test)]
    const fn generation(&self) -> u64 {
        self.generation
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct ViewSnapshot {
    phase: OnboardingPhase,
    status_kind: UiStatusKind,
    status_label: &'static str,
    status_icon: &'static str,
    status_text: String,
    title: &'static str,
    detail: &'static str,
    endpoint: String,
    server: String,
    protocol: String,
    role: String,
    scopes: String,
    health: String,
    identity: String,
    error: Option<UserError>,
    reset_consent: bool,
}

impl ViewSnapshot {
    #[cfg(test)]
    pub(crate) const fn phase(&self) -> OnboardingPhase {
        self.phase
    }

    pub(crate) const fn status_kind(&self) -> UiStatusKind {
        self.status_kind
    }

    pub(crate) const fn status_label(&self) -> &'static str {
        self.status_label
    }

    pub(crate) const fn status_icon(&self) -> &'static str {
        self.status_icon
    }

    pub(crate) fn status_text(&self) -> &str {
        &self.status_text
    }

    pub(crate) const fn title(&self) -> &'static str {
        self.title
    }

    pub(crate) const fn detail(&self) -> &'static str {
        self.detail
    }

    pub(crate) fn endpoint(&self) -> &str {
        &self.endpoint
    }

    pub(crate) fn server(&self) -> &str {
        &self.server
    }

    pub(crate) fn protocol(&self) -> &str {
        &self.protocol
    }

    pub(crate) fn role(&self) -> &str {
        &self.role
    }

    pub(crate) fn scopes(&self) -> &str {
        &self.scopes
    }

    pub(crate) fn health(&self) -> &str {
        &self.health
    }

    pub(crate) fn identity(&self) -> &str {
        &self.identity
    }

    pub(crate) const fn error(&self) -> Option<&UserError> {
        self.error.as_ref()
    }

    pub(crate) const fn reset_consent(&self) -> bool {
        self.reset_consent
    }

    pub(crate) const fn busy(&self) -> bool {
        matches!(
            self.phase,
            OnboardingPhase::Connecting
                | OnboardingPhase::Authenticating
                | OnboardingPhase::Reconnecting
                | OnboardingPhase::HealthChecking
                | OnboardingPhase::Disconnecting
        )
    }

    pub(crate) const fn can_connect(&self) -> bool {
        matches!(
            self.phase,
            OnboardingPhase::Disconnected
                | OnboardingPhase::Failed
                | OnboardingPhase::PairingRequired
        )
    }

    pub(crate) const fn can_cancel(&self) -> bool {
        matches!(
            self.phase,
            OnboardingPhase::Connecting
                | OnboardingPhase::Authenticating
                | OnboardingPhase::Reconnecting
                | OnboardingPhase::HealthChecking
        )
    }

    pub(crate) fn can_disconnect(&self) -> bool {
        self.phase == OnboardingPhase::Ready
    }

    pub(crate) const fn can_retry(&self) -> bool {
        matches!(
            self.phase,
            OnboardingPhase::Failed | OnboardingPhase::PairingRequired
        )
    }
}

fn bounded_safe_field(value: String, maximum: usize) -> String {
    let filtered = if value.chars().any(char::is_control) {
        value
            .chars()
            .map(|character| {
                if character.is_control() {
                    '\u{fffd}'
                } else {
                    character
                }
            })
            .collect()
    } else {
        value
    };
    bounded_text(filtered, maximum)
}

fn bounded_text(value: String, maximum: usize) -> String {
    if value.chars().count() <= maximum {
        return value;
    }
    let mut bounded = value
        .chars()
        .take(maximum.saturating_sub(3))
        .collect::<String>();
    bounded.push_str("...");
    bounded
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use claw_gateway_client::{
        ClientLimits, ConfigurationError, GatewayClientConfig, GatewayCredential,
    };
    use claw_protocol::gateway::ProtocolVersion;
    use claw_security::identity::DeviceIdentity;
    use getrandom::{SysRng, rand_core::UnwrapErr};
    use secrecy::ExposeSecret;

    use super::*;

    fn connection_info() -> ConnectionInfo {
        ConnectionInfo {
            protocol: ProtocolVersion::new(4).expect("protocol"),
            server_version: "test-gateway".to_owned(),
            connection_id: "connection-1".to_owned(),
            role: "operator".to_owned(),
            scopes: Arc::from(["operator.read".to_owned()]),
            advertised_method_count: 1,
            advertised_event_count: 1,
            max_payload_bytes: 1024,
        }
    }

    #[test]
    fn reducer_covers_connect_auth_health_ready_disconnect() {
        let mut model = OnboardingModel::default();
        let generation = model.begin("wss://gateway.example/".to_owned());
        assert_eq!(model.snapshot().phase(), OnboardingPhase::Connecting);

        assert!(model.apply(generation, AttemptUpdate::Authenticating));
        assert_eq!(model.snapshot().phase(), OnboardingPhase::Authenticating);
        assert!(model.apply(
            generation,
            AttemptUpdate::IdentityCreated("claw-device-v1:public".to_owned())
        ));
        assert!(model.apply(generation, AttemptUpdate::Ready(connection_info())));
        assert_eq!(model.snapshot().phase(), OnboardingPhase::HealthChecking);
        assert!(model.apply(generation, AttemptUpdate::Healthy));
        let ready = model.snapshot();
        assert_eq!(ready.phase(), OnboardingPhase::Ready);
        assert_eq!(ready.server(), "test-gateway");
        assert_eq!(ready.protocol(), "Gateway v4");
        assert_eq!(ready.role(), "operator");
        assert_eq!(ready.scopes(), "operator.read");
        assert!(!ready.reset_consent());

        let disconnect_generation = model.start_disconnect();
        assert_eq!(model.snapshot().phase(), OnboardingPhase::Disconnecting);
        assert!(model.finish_disconnect(disconnect_generation));
        let stopped = model.snapshot();
        assert_eq!(stopped.phase(), OnboardingPhase::Disconnected);
        assert_eq!(stopped.identity(), "Discarded on disconnect");
        assert!(stopped.reset_consent());
    }

    #[test]
    fn generation_blocks_late_mutation_after_cancel_and_new_attempt() {
        let mut model = OnboardingModel::default();
        let old = model.begin("ws://localhost:1000/".to_owned());
        let cancel = model.start_disconnect();
        assert!(model.finish_disconnect(cancel));
        let current = model.begin("ws://localhost:2000/".to_owned());

        assert!(!model.apply(old, AttemptUpdate::Ready(connection_info())));
        assert_eq!(model.generation(), current);
        assert_eq!(model.snapshot().endpoint(), "ws://localhost:2000/");
        assert_eq!(model.snapshot().phase(), OnboardingPhase::Connecting);
    }

    #[test]
    fn terminal_failure_clears_every_authenticated_summary() {
        let mut model = OnboardingModel::default();
        let generation = model.begin("wss://gateway.example/".to_owned());
        assert!(model.apply(generation, AttemptUpdate::Ready(connection_info())));
        assert!(model.apply(generation, AttemptUpdate::Healthy));
        assert!(model.apply(
            generation,
            AttemptUpdate::Failed(UserError::transport(TransportFailure::Closed))
        ));

        let failed = model.snapshot();
        assert_eq!(failed.phase(), OnboardingPhase::Failed);
        assert_eq!(failed.endpoint(), "wss://gateway.example/");
        assert_eq!(failed.server(), "Not connected");
        assert_eq!(failed.protocol(), "Not negotiated");
        assert_eq!(failed.role(), "Not authenticated");
        assert_eq!(failed.scopes(), "No effective scopes");
        assert_eq!(failed.health(), "Not healthy - connection failed");
        assert!(!failed.health().contains("Healthy"));
    }

    #[test]
    fn endpoint_display_strips_credentials_query_and_fragment_before_rejection() {
        let rejection = ConnectRequest::prepare(
            "wss://alice:secret@gateway.example/path?token=hidden#private",
            "session-secret".to_owned(),
            true,
        )
        .expect_err("credential-bearing endpoint rejected");
        assert_eq!(
            rejection.endpoint_display.as_deref(),
            Some("wss://gateway.example/path")
        );
        assert_eq!(
            rejection.endpoint_input.as_deref(),
            Some("wss://gateway.example/path")
        );
        let rendered = format!("{:?}", rejection.error);
        assert!(!rendered.contains("secret"));
        assert!(!rendered.contains("hidden"));
        assert!(!rendered.contains("private"));

        let rejection =
            ConnectRequest::prepare("data:text/plain,SESSION_TOKEN", String::new(), true)
                .expect_err("unsupported opaque scheme rejected");
        assert_eq!(rejection.endpoint_input, None);
        assert_eq!(rejection.endpoint_display, None);
        assert!(!format!("{rejection:?}").contains("SESSION_TOKEN"));
    }

    #[test]
    fn long_endpoint_keeps_full_canonical_input_and_bounds_only_summary() {
        let path = "a".repeat(400);
        let endpoint = format!("wss://gateway.example/{path}");
        let request =
            ConnectRequest::prepare(&endpoint, String::new(), true).expect("valid endpoint");
        assert_eq!(request.endpoint_input(), endpoint);
        assert!(request.endpoint_display().chars().count() <= MAX_ENDPOINT_DISPLAY_CHARS);
        assert!(request.endpoint_display().ends_with("..."));
    }

    #[test]
    fn session_token_is_bounded_and_debug_redacted() {
        let request =
            ConnectRequest::prepare("ws://localhost:18789", "never-print-this".to_owned(), true)
                .expect("valid request");
        let rendered = format!("{request:?}");
        assert!(rendered.contains("REDACTED"));
        assert!(!rendered.contains("never-print-this"));
        let (_, token) = request.into_parts();
        assert_eq!(token.expect("token").expose_secret(), "never-print-this");

        let rejection = ConnectRequest::prepare(
            "ws://localhost:18789",
            "x".repeat(MAX_TOKEN_BYTES + 1),
            true,
        )
        .expect_err("oversized token");
        assert_eq!(rejection.error.code(), "token.too-long");
        assert_eq!(
            rejection.endpoint_input.as_deref(),
            Some("ws://localhost:18789/")
        );
    }

    #[test]
    fn consent_is_fail_closed_before_identity_creation() {
        let rejection = ConnectRequest::prepare("ws://localhost:18789", String::new(), false)
            .expect_err("consent required");
        assert_eq!(rejection.error.code(), "identity.consent-required");
        assert_eq!(
            rejection.endpoint_input.as_deref(),
            Some("ws://localhost:18789/")
        );

        let rejection = ConnectRequest::prepare(
            "not-a-gateway token=must-not-survive ",
            String::new(),
            false,
        )
        .expect_err("malformed endpoint rejected before consent");
        assert_eq!(rejection.error.code(), "endpoint.invalid");
        assert_eq!(rejection.endpoint_input, None);
    }

    #[test]
    fn consent_reset_is_emitted_only_after_identity_discard() {
        let mut no_identity = OnboardingModel::default();
        let empty_disconnect = no_identity.start_disconnect();
        assert!(no_identity.finish_disconnect(empty_disconnect));
        assert!(
            !no_identity.take_snapshot().reset_consent(),
            "disconnect without an identity has no consent to reset"
        );
        assert_eq!(
            no_identity.snapshot().identity(),
            "No session identity created"
        );

        let mut model = OnboardingModel::default();
        assert!(!model.snapshot().reset_consent());
        let generation = model.begin("ws://localhost:18789/".to_owned());
        assert!(model.apply(
            generation,
            AttemptUpdate::IdentityCreated("session-device".to_owned())
        ));
        assert!(model.apply(
            generation,
            AttemptUpdate::Failed(UserError::transport(TransportFailure::Closed))
        ));
        assert!(
            !model.snapshot().reset_consent(),
            "retry retains the same session identity and its consent"
        );

        let disconnect = model.start_disconnect();
        assert!(model.finish_disconnect(disconnect));
        assert!(model.take_snapshot().reset_consent());
        assert!(
            !model.snapshot().reset_consent(),
            "publishing consumes the identity-discard reset directive"
        );

        let retry = model.begin("ws://localhost:18789/".to_owned());
        assert!(
            !model.snapshot().reset_consent(),
            "a new attempt clears the one-shot reset directive"
        );
        assert!(model.apply(
            retry,
            AttemptUpdate::IdentityCreated("new-session-device".to_owned())
        ));
        assert!(!model.snapshot().reset_consent());
    }

    #[test]
    fn invalid_submission_after_rechecking_consent_does_not_replay_consumed_reset() {
        let mut model = OnboardingModel::default();
        let generation = model.begin("ws://localhost:18789/".to_owned());
        assert!(model.apply(
            generation,
            AttemptUpdate::IdentityCreated("session-device".to_owned())
        ));
        let disconnect = model.start_disconnect();
        assert!(model.finish_disconnect(disconnect));
        assert!(model.take_snapshot().reset_consent());

        model.reject_submission(
            None,
            UserError::input(
                "endpoint.invalid",
                "Enter a complete Gateway address.",
                "Correct the address and retry.",
            ),
        );
        assert!(
            !model.take_snapshot().reset_consent(),
            "the invalid submission must not replay the prior identity-discard reset"
        );
    }

    #[test]
    fn reconnect_pairing_auth_protocol_transport_and_pressure_are_typed() {
        let mut model = OnboardingModel::default();
        let generation = model.begin("ws://localhost/".to_owned());
        assert!(model.apply(generation, AttemptUpdate::Reconnecting { attempt: 2 }));
        assert_eq!(model.snapshot().status_text(), "Reconnect attempt 2");

        let categories = [
            UserError::transport(TransportFailure::TimedOut),
            UserError::new(
                UserErrorKind::Authentication,
                "auth",
                "Authentication failed",
                "Retry",
            ),
            UserError::new(
                UserErrorKind::Pairing,
                "pairing",
                "Pairing required",
                "Approve",
            ),
            UserError::protocol(&ProtocolFailure::ExpectedChallenge),
            UserError::backpressure(BackpressureError::CommandQueueSaturated),
        ];
        assert_eq!(categories[0].kind(), UserErrorKind::Transport);
        assert_eq!(categories[1].kind(), UserErrorKind::Authentication);
        assert_eq!(categories[2].kind(), UserErrorKind::Pairing);
        assert_eq!(categories[3].kind(), UserErrorKind::Protocol);
        assert_eq!(categories[4].kind(), UserErrorKind::Backpressure);
    }

    #[test]
    fn errors_and_safe_fields_are_bounded_and_control_free() {
        let error = UserError::input("bounded", "x".repeat(500), "y".repeat(500));
        assert!(error.message().chars().count() <= MAX_PRESENTATION_CHARS);
        assert!(error.action().chars().count() <= MAX_PRESENTATION_CHARS);

        let mut model = OnboardingModel::default();
        let generation = model.begin("ws://localhost/".to_owned());
        let mut info = connection_info();
        info.server_version = format!("server\n{}", "z".repeat(300));
        assert!(model.apply(generation, AttemptUpdate::Ready(info)));
        let server = model.snapshot().server().to_owned();
        assert!(server.chars().count() <= 96);
        assert!(!server.contains('\n'));
    }

    #[test]
    fn gateway_configuration_debug_does_not_expose_token() {
        let mut rng = UnwrapErr(SysRng);
        let identity = Arc::new(DeviceIdentity::generate(&mut rng));
        let endpoint = Url::parse("ws://localhost:18789").expect("url");
        let mut config = GatewayClientConfig::new(endpoint, identity);
        config.credential =
            GatewayCredential::Token(SecretString::from("never-log-token".to_owned()));
        config.limits = ClientLimits::default();
        let debug = format!("{config:?}");
        assert!(!debug.contains("never-log-token"));
        assert!(debug.contains("REDACTED"));
        let error = GatewayClientError::Configuration(ConfigurationError::UnsupportedScheme);
        assert_eq!(UserError::from_gateway(&error).kind(), UserErrorKind::Input);
    }
}

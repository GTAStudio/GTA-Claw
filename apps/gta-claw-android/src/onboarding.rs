//! Portable Android onboarding state, independent of Slint and of Android itself.
//!
//! Everything in this module compiles and runs on the development host, so the
//! connection state machine, the input policy, and the redaction rules are
//! exercised by ordinary `cargo test` rather than only on a device.

use std::fmt::{self, Debug, Display, Formatter};
use std::time::Duration;

use claw_gateway_client::{
    ConfigurationError, ConnectionInfo, ConnectionState, GatewayClientError, ProtocolFailure,
    ReadyConnection, TransportFailure,
};
use claw_protocol::gateway::ConnectErrorDetailCode;
use secrecy::{ExposeSecret, SecretString};
use url::{Host, Url};

use crate::platform::{
    AppLifecycle, ConnectionBlocker, IdentityFailure, IdentityPersistence, NetworkStatus,
    PlatformCapabilities,
};

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

    const fn diagnostic(self) -> (DiagnosticCode, RemedyKind) {
        match self {
            Self::EmptyEndpoint => (DiagnosticCode::EndpointRequired, RemedyKind::EnterEndpoint),
            Self::EndpointTooLong
            | Self::MalformedEndpoint
            | Self::UnsupportedScheme
            | Self::MissingHost
            | Self::CredentialBearingEndpoint => {
                (DiagnosticCode::EndpointInvalid, RemedyKind::EditEndpoint)
            }
            Self::InsecureRemoteEndpoint => {
                (DiagnosticCode::EndpointInsecure, RemedyKind::EditEndpoint)
            }
            Self::TokenTooLong => (DiagnosticCode::TokenInvalid, RemedyKind::EditToken),
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
    ///
    /// # Errors
    ///
    /// Returns the [`SubmissionRejection`] naming the first policy the input
    /// broke, checked in this order: a blank endpoint
    /// ([`EmptyEndpoint`](SubmissionRejection::EmptyEndpoint)), an endpoint
    /// over [`MAX_ENDPOINT_BYTES`]
    /// ([`EndpointTooLong`](SubmissionRejection::EndpointTooLong)), a token
    /// over [`MAX_TOKEN_BYTES`]
    /// ([`TokenTooLong`](SubmissionRejection::TokenTooLong)), text `url::Url`
    /// cannot parse ([`MalformedEndpoint`](SubmissionRejection::MalformedEndpoint)),
    /// a scheme other than `ws` or `wss`
    /// ([`UnsupportedScheme`](SubmissionRejection::UnsupportedScheme)), a URL
    /// with no host ([`MissingHost`](SubmissionRejection::MissingHost)), a URL
    /// carrying userinfo, a password, a query string or a fragment
    /// ([`CredentialBearingEndpoint`](SubmissionRejection::CredentialBearingEndpoint)),
    /// and plaintext `ws://` to a non-loopback host without the opt-in
    /// ([`InsecureRemoteEndpoint`](SubmissionRejection::InsecureRemoteEndpoint)).
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
        if url.scheme() == "ws" && !allow_insecure_remote_ws && !is_loopback(&url) {
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
        } else if is_loopback(&self.url) {
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

    /// Copies the request into a fresh transport attempt.
    ///
    /// The controller retains the original request while an Android activity is
    /// backgrounded or a network is unavailable. `SecretString` deliberately
    /// does not implement `Clone`, so the copy is explicit and remains wrapped
    /// before and after this boundary.
    #[must_use]
    pub(crate) fn transport_parts(&self) -> (Url, Option<SecretString>, bool) {
        (
            self.url.clone(),
            self.token
                .as_ref()
                .map(|token| SecretString::from(token.expose_secret().to_owned())),
            self.allow_insecure_remote_ws,
        )
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
    let scheme = url.scheme();
    let host = url.host_str().unwrap_or("<unknown>");
    url.port().map_or_else(
        || format!("{scheme}://{host}"),
        |port| format!("{scheme}://{host}:{port}"),
    )
}

fn is_loopback(url: &Url) -> bool {
    match url.host() {
        Some(Host::Domain("localhost")) => true,
        Some(Host::Ipv4(address)) => address.is_loopback(),
        Some(Host::Ipv6(address)) => address.is_loopback(),
        Some(Host::Domain(_)) | None => false,
    }
}

/// A non-secret summary of one authenticated Gateway connection.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ReadySummary {
    connection_epoch: u64,
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
            connection_epoch: 0,
            protocol: info.protocol.get(),
            server_version: info.server_version.clone(),
            role: info.role.clone(),
            scopes: info.scopes.to_vec(),
            max_payload_bytes: info.max_payload_bytes,
        }
    }

    /// Projects an authenticated lifecycle, including its process-local epoch.
    #[must_use]
    pub fn from_connection(connection: &ReadyConnection) -> Self {
        let mut summary = Self::from_info(&connection.info);
        summary.connection_epoch = connection.epoch.get();
        summary
    }

    /// Returns the process-local connection epoch.
    ///
    /// A value of zero is used only by [`Self::from_info`], whose input predates
    /// lifecycle epochs. Live controller snapshots always carry a non-zero value.
    #[must_use]
    pub const fn connection_epoch(&self) -> u64 {
        self.connection_epoch
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

/// Stable diagnostic identity for one operator-facing condition.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DiagnosticCode {
    /// A caller supplied an unclassified custom error.
    Unknown,
    /// No Gateway endpoint was supplied.
    EndpointRequired,
    /// The Gateway endpoint is malformed or unsupported.
    EndpointInvalid,
    /// A remote plaintext endpoint needs explicit handling.
    EndpointInsecure,
    /// The supplied token is invalid for local input policy.
    TokenInvalid,
    /// The controller command queue is saturated.
    ControllerBusy,
    /// The controller task has stopped.
    ControllerStopped,
    /// The platform cannot supply an identity.
    IdentityUnavailable,
    /// Device-backed identity storage is locked.
    IdentityLocked,
    /// Android invalidated the stored identity.
    IdentityInvalidated,
    /// No usable network is available.
    NetworkUnavailable,
    /// Android has not validated Internet access.
    ///
    /// This is diagnostic only: an isolated local network may still carry a
    /// reachable Gateway.
    NetworkUnvalidated,
    /// The app is backgrounded.
    AppBackgrounded,
    /// The Gateway cannot be reached.
    GatewayUnreachable,
    /// A connection lifecycle operation timed out.
    GatewayTimeout,
    /// The live socket dropped.
    ConnectionDropped,
    /// The Gateway closed the connection.
    GatewayClosed,
    /// Authentication needs a token.
    AuthenticationRequired,
    /// Authentication was rejected.
    AuthenticationRejected,
    /// Authentication is rate limited.
    AuthenticationRateLimited,
    /// The Gateway requires an authentication mode this client cannot provide.
    UnsupportedAuthentication,
    /// Pairing must be completed elsewhere.
    PairingRequired,
    /// The requested read-only authorization was not granted.
    AuthorizationMismatch,
    /// The device must be registered.
    DeviceRegistrationRequired,
    /// The phone clock is outside the accepted signature window.
    ClockIncorrect,
    /// The app and Gateway protocol versions do not overlap.
    ProtocolMismatch,
    /// A protocol rule was violated.
    ProtocolFailure,
    /// Event continuity was lost.
    ResyncRequired,
    /// Local bounded queues are saturated.
    Backpressure,
    /// A request was made without a ready connection.
    NotReady,
    /// A request exceeded its response timeout.
    RequestTimeout,
    /// Bounded shutdown expired.
    ShutdownTimeout,
    /// The bounded reconnect budget is exhausted.
    ReconnectExhausted,
    /// A request belonged to a superseded connection.
    ConnectionChanged,
    /// The app constructed an invalid client configuration.
    ClientConfiguration,
    /// The operation was cancelled.
    Cancelled,
    /// The peer selected an unsupported WebSocket extension.
    UnsupportedExtension,
}

/// Concrete action a shell can bind to a remedy affordance.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RemedyKind {
    /// No operator action is required.
    None,
    /// Enter a Gateway endpoint.
    EnterEndpoint,
    /// Edit the endpoint.
    EditEndpoint,
    /// Edit or replace the token.
    EditToken,
    /// Check connectivity or captive-portal state.
    CheckNetwork,
    /// Wait before another attempt.
    Wait,
    /// Retry the retained connection request.
    Retry,
    /// Update the app or Gateway.
    UpdateSoftware,
    /// Ask the Gateway administrator to change configuration or authorization.
    ContactAdministrator,
    /// Register this device on the Gateway.
    RegisterDevice,
    /// Complete pairing from another client.
    PairElsewhere,
    /// Correct the phone clock.
    CheckClock,
    /// Restart the application.
    RestartApp,
    /// Bring the application to the foreground.
    BringToForeground,
    /// Report an application defect.
    ReportBug,
}

/// An operator-facing failure with a concrete corrective action.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct UserError {
    diagnostic: DiagnosticCode,
    remedy: RemedyKind,
    message: String,
    action: String,
}

impl UserError {
    /// Creates an error from an already operator-facing pair.
    #[must_use]
    pub fn new(message: impl Into<String>, action: impl Into<String>) -> Self {
        Self::diagnostic(DiagnosticCode::Unknown, RemedyKind::Retry, message, action)
    }

    /// Creates a classified operator-facing error.
    #[must_use]
    pub fn diagnostic(
        diagnostic: DiagnosticCode,
        remedy: RemedyKind,
        message: impl Into<String>,
        action: impl Into<String>,
    ) -> Self {
        Self {
            diagnostic,
            remedy,
            message: message.into(),
            action: action.into(),
        }
    }

    /// Translates a rejected submission.
    #[must_use]
    pub fn from_rejection(rejection: SubmissionRejection) -> Self {
        let (message, action) = rejection.user_error();
        let (diagnostic, remedy) = rejection.diagnostic();
        Self::diagnostic(diagnostic, remedy, message, action)
    }

    /// Translates a closed platform identity failure.
    #[must_use]
    pub fn from_identity_failure(error: IdentityFailure) -> Self {
        match error {
            IdentityFailure::RandomnessUnavailable | IdentityFailure::Unavailable => {
                Self::diagnostic(
                    DiagnosticCode::IdentityUnavailable,
                    RemedyKind::RestartApp,
                    "This device could not provide a secure identity.",
                    "Restart the app. If it keeps failing, this device cannot connect safely.",
                )
            }
            IdentityFailure::StorageLocked => Self::diagnostic(
                DiagnosticCode::IdentityLocked,
                RemedyKind::Retry,
                "The device identity is temporarily locked.",
                "Unlock the device, then retry.",
            ),
            IdentityFailure::StorageInvalidated => Self::diagnostic(
                DiagnosticCode::IdentityInvalidated,
                RemedyKind::RegisterDevice,
                "Android invalidated this app's stored identity.",
                "Create a new device identity, register it on the Gateway, then retry.",
            ),
        }
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
            GatewayClientError::Backpressure(_) => Self::diagnostic(
                DiagnosticCode::Backpressure,
                RemedyKind::Wait,
                "The app is sending faster than this connection allows.",
                "Wait a moment, then retry.",
            ),
            GatewayClientError::NotReady | GatewayClientError::DisconnectedNotReplayed => {
                Self::diagnostic(
                    DiagnosticCode::NotReady,
                    RemedyKind::Retry,
                    "The connection is not ready.",
                    "Reconnect before sending requests.",
                )
            }
            GatewayClientError::Cancelled => Self::diagnostic(
                DiagnosticCode::Cancelled,
                RemedyKind::Retry,
                "The connection was stopped.",
                "Connect again when ready.",
            ),
            GatewayClientError::ConnectionChanged { .. } => Self::diagnostic(
                DiagnosticCode::ConnectionChanged,
                RemedyKind::Retry,
                "The connection was replaced before this request completed.",
                "Retry on the current connection.",
            ),
            GatewayClientError::RequestTimedOut(_) => Self::diagnostic(
                DiagnosticCode::RequestTimeout,
                RemedyKind::Retry,
                "The Gateway did not answer in time.",
                "Retry the request.",
            ),
            GatewayClientError::ShutdownTimedOut => Self::diagnostic(
                DiagnosticCode::ShutdownTimeout,
                RemedyKind::Retry,
                "Shutting the connection down took too long.",
                "The app released it anyway; reconnect when ready.",
            ),
            GatewayClientError::ReconnectExhausted => Self::diagnostic(
                DiagnosticCode::ReconnectExhausted,
                RemedyKind::CheckNetwork,
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
                Self::diagnostic(
                    DiagnosticCode::AuthenticationRejected,
                    RemedyKind::Retry,
                    "The Gateway rejected this device.",
                    "The server asked for a fresh device token. Reconnect to request one.",
                )
            } else {
                Self::diagnostic(
                    DiagnosticCode::AuthenticationRejected,
                    RemedyKind::EditToken,
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
            | ConnectErrorDetailCode::AuthTailscaleIdentityMismatch => Self::diagnostic(
                DiagnosticCode::UnsupportedAuthentication,
                RemedyKind::ContactAdministrator,
                "This Gateway authenticates callers through Tailscale.",
                "This Android build cannot present a Tailscale identity, so it cannot connect to \
                 this server. Use a Gateway that accepts token or device authentication.",
            ),
            ConnectErrorDetailCode::PairingRequired => Self::diagnostic(
                DiagnosticCode::PairingRequired,
                RemedyKind::PairElsewhere,
                "This Gateway requires the device to be paired first.",
                "This build has no pairing screen, so the pairing has to be completed from \
                 another client before this device can connect.",
            ),
            ConnectErrorDetailCode::AuthRateLimited => Self::diagnostic(
                DiagnosticCode::AuthenticationRateLimited,
                RemedyKind::Wait,
                "The Gateway is rate limiting authentication attempts.",
                "Wait before trying again. Repeated attempts usually extend the limit.",
            ),
            ConnectErrorDetailCode::AuthRequired | ConnectErrorDetailCode::AuthTokenMissing => {
                Self::diagnostic(
                    DiagnosticCode::AuthenticationRequired,
                    RemedyKind::EditToken,
                    "This Gateway requires a token and none was sent.",
                    "Enter the Gateway token, then connect again.",
                )
            }
            ConnectErrorDetailCode::AuthTokenMismatch
            | ConnectErrorDetailCode::AuthBootstrapTokenInvalid => Self::diagnostic(
                DiagnosticCode::AuthenticationRejected,
                RemedyKind::EditToken,
                "The Gateway did not accept this token.",
                "Check the token for a typo or an expiry, then connect again.",
            ),
            ConnectErrorDetailCode::AuthTokenNotConfigured => Self::diagnostic(
                DiagnosticCode::UnsupportedAuthentication,
                RemedyKind::ContactAdministrator,
                "This Gateway is not configured to accept tokens.",
                "Ask whoever runs the Gateway which authentication it expects.",
            ),
            ConnectErrorDetailCode::AuthPasswordMissing
            | ConnectErrorDetailCode::AuthPasswordMismatch
            | ConnectErrorDetailCode::AuthPasswordNotConfigured => Self::diagnostic(
                DiagnosticCode::UnsupportedAuthentication,
                RemedyKind::ContactAdministrator,
                "This Gateway expects password authentication.",
                "This build only sends a token, so it cannot authenticate here. Use a Gateway \
                 that accepts token or device authentication.",
            ),
            ConnectErrorDetailCode::AuthScopeMismatch => Self::diagnostic(
                DiagnosticCode::AuthorizationMismatch,
                RemedyKind::ContactAdministrator,
                "The Gateway would not grant the permissions this app asked for.",
                "This app requests read-only operator access. Ask for that grant on the Gateway, \
                 then connect again.",
            ),
            ConnectErrorDetailCode::AuthDeviceTokenMismatch => Self::diagnostic(
                DiagnosticCode::AuthenticationRejected,
                if device_retry_recommended {
                    RemedyKind::Retry
                } else {
                    RemedyKind::RegisterDevice
                },
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
            | ConnectErrorDetailCode::DeviceAuthSignatureInvalid => Self::diagnostic(
                DiagnosticCode::DeviceRegistrationRequired,
                RemedyKind::RegisterDevice,
                "The Gateway rejected this device's identity.",
                "This app generates a new identity each time it starts, so a Gateway that only \
                 admits known devices will refuse it until this one is registered.",
            ),
            ConnectErrorDetailCode::DeviceAuthSignatureExpired => Self::diagnostic(
                DiagnosticCode::ClockIncorrect,
                RemedyKind::CheckClock,
                "The Gateway judged this device's signature to be out of date.",
                "Check that the phone's clock and time zone are correct, then connect again.",
            ),
            ConnectErrorDetailCode::DeviceAuthNonceRequired
            | ConnectErrorDetailCode::DeviceAuthNonceMismatch => Self::diagnostic(
                DiagnosticCode::AuthenticationRejected,
                RemedyKind::Retry,
                "The Gateway's authentication challenge did not match the reply.",
                "Connect again to start a fresh challenge.",
            ),
            ConnectErrorDetailCode::ProtocolMismatch
            | ConnectErrorDetailCode::ClientVersionMismatch => Self::diagnostic(
                DiagnosticCode::ProtocolMismatch,
                RemedyKind::UpdateSoftware,
                "This app and the Gateway do not speak a common protocol version.",
                "Update whichever of the app and the Gateway is older.",
            ),
            // Emitted for browser Control UI callers. This client is not one, so
            // seeing it means the Gateway took us for something we are not.
            ConnectErrorDetailCode::ControlUiOriginNotAllowed => Self::diagnostic(
                DiagnosticCode::EndpointInvalid,
                RemedyKind::EditEndpoint,
                "The Gateway answered as though this app were a web page.",
                "Check that the address points at a Gateway endpoint and not at a Control UI one.",
            ),
            ConnectErrorDetailCode::AuthUnauthorized => Self::diagnostic(
                DiagnosticCode::AuthenticationRejected,
                RemedyKind::ContactAdministrator,
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
            ConfigurationError::WorkerProtocolUnsupported => Self::diagnostic(
                DiagnosticCode::ClientConfiguration,
                RemedyKind::ReportBug,
                "Worker connections are not supported by this app.",
                "Use an operator Gateway address.",
            ),
            ConfigurationError::InvalidProtocolRange
            | ConfigurationError::InvalidResourceLimit
            | ConfigurationError::InvalidTimeout
            | ConfigurationError::InvalidReconnectPolicy => Self::diagnostic(
                DiagnosticCode::ClientConfiguration,
                RemedyKind::ReportBug,
                "The app built an invalid connection configuration.",
                "This is a bug in the app; please report it.",
            ),
        }
    }

    fn from_transport(error: TransportFailure) -> Self {
        match error {
            TransportFailure::Connect => Self::diagnostic(
                DiagnosticCode::GatewayUnreachable,
                RemedyKind::CheckNetwork,
                "Could not reach the Gateway.",
                "Check the address and this device's network, then retry.",
            ),
            TransportFailure::TimedOut => Self::diagnostic(
                DiagnosticCode::GatewayTimeout,
                RemedyKind::CheckNetwork,
                "The Gateway did not respond in time.",
                "Check the network, then retry.",
            ),
            TransportFailure::PeerClosed { .. } | TransportFailure::Closed => Self::diagnostic(
                DiagnosticCode::GatewayClosed,
                RemedyKind::Retry,
                "The Gateway closed the connection.",
                "Connect again when the server is available.",
            ),
            TransportFailure::Read | TransportFailure::Write => Self::diagnostic(
                DiagnosticCode::ConnectionDropped,
                RemedyKind::CheckNetwork,
                "The connection dropped mid-transfer.",
                "Retry; mobile networks drop sockets when the app is backgrounded.",
            ),
            TransportFailure::UnsupportedExtension => Self::diagnostic(
                DiagnosticCode::UnsupportedExtension,
                RemedyKind::UpdateSoftware,
                "The Gateway negotiated an unsupported WebSocket extension.",
                "Upgrade the Gateway or this app.",
            ),
        }
    }

    fn from_protocol(error: &ProtocolFailure) -> Self {
        match error {
            ProtocolFailure::HelloProtocol { .. } => Self::diagnostic(
                DiagnosticCode::ProtocolMismatch,
                RemedyKind::UpdateSoftware,
                "This app and the Gateway do not share a protocol version.",
                "Upgrade whichever side is older.",
            ),
            ProtocolFailure::HandshakeRejected(_)
            | ProtocolFailure::HelloAuthenticationMismatch => Self::diagnostic(
                DiagnosticCode::AuthenticationRejected,
                RemedyKind::ContactAdministrator,
                "The Gateway refused the handshake.",
                "Check the token and this device's authorization.",
            ),
            ProtocolFailure::ResyncRequired(_) => Self::diagnostic(
                DiagnosticCode::ResyncRequired,
                RemedyKind::Retry,
                "Event continuity was lost.",
                "Reconnect to rebuild state from a fresh snapshot.",
            ),
            _ => Self::diagnostic(
                DiagnosticCode::ProtocolFailure,
                RemedyKind::Retry,
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

    /// Returns the stable diagnostic identity.
    #[must_use]
    pub const fn diagnostic_code(&self) -> DiagnosticCode {
        self.diagnostic
    }

    /// Returns the action category a shell can bind to.
    #[must_use]
    pub const fn remedy_kind(&self) -> RemedyKind {
        self.remedy
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
            ConnectionState::Ready(ready) => Self::Ready(ReadySummary::from_connection(ready)),
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

/// Stable connection phase suitable for direct shell binding.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ConnectionPhase {
    /// No connection has been requested.
    Idle,
    /// A request is retained until the app returns to the foreground.
    Suspended,
    /// A request is retained until Android reports usable connectivity.
    WaitingForNetwork,
    /// A socket is opening.
    Connecting,
    /// The Gateway handshake is running.
    Authenticating,
    /// The connection is authenticated.
    Ready,
    /// The transport is inside its bounded reconnect policy.
    Reconnecting,
    /// The attempt stopped with an actionable failure.
    Failed,
    /// The operator explicitly disconnected.
    Disconnected,
}

#[derive(Clone, Debug, Eq, PartialEq)]
enum Phase {
    Idle,
    Blocked(ConnectionBlocker),
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
    revision: u64,
    phase: Phase,
    endpoint: String,
    identity: Option<String>,
    token_offered: bool,
    posture: Option<TransportPosture>,
    request_retained: bool,
    lifecycle: AppLifecycle,
    network: NetworkStatus,
    platform_capabilities: PlatformCapabilities,
}

impl Default for ViewModel {
    fn default() -> Self {
        Self::new()
    }
}

impl ViewModel {
    /// Creates the initial idle state.
    #[must_use]
    pub fn new() -> Self {
        Self::with_platform(PlatformCapabilities::default())
    }

    /// Creates idle state with explicit platform capability facts.
    #[must_use]
    pub const fn with_platform(platform_capabilities: PlatformCapabilities) -> Self {
        Self {
            generation: 0,
            revision: 0,
            phase: Phase::Idle,
            endpoint: String::new(),
            identity: None,
            token_offered: false,
            posture: None,
            request_retained: false,
            lifecycle: AppLifecycle::Foreground,
            network: NetworkStatus::Unknown,
            platform_capabilities,
        }
    }

    /// Returns whether a new attempt may start now.
    #[must_use]
    pub const fn can_start_connection(&self) -> bool {
        matches!(self.phase, Phase::Idle | Phase::Failed(_) | Phase::Stopped)
    }

    /// Starts a new attempt and returns the generation that owns it.
    ///
    /// Every later [`Self::apply`] carrying an older generation is discarded, so
    /// a late update from an abandoned attempt cannot overwrite the live one.
    pub fn begin(&mut self, request: &ConnectRequest) -> u64 {
        self.prepare_attempt(request, Phase::Connecting);
        self.generation
    }

    /// Retains a request that cannot run until a platform blocker clears.
    pub fn defer(&mut self, request: &ConnectRequest, blocker: ConnectionBlocker) -> u64 {
        self.prepare_attempt(request, Phase::Blocked(blocker));
        self.generation
    }

    /// Supersedes a live attempt and renders why its retained request is paused.
    pub fn suspend(&mut self, blocker: ConnectionBlocker) {
        self.generation = self.generation.wrapping_add(1);
        self.phase = Phase::Blocked(blocker);
        self.touch();
    }

    fn prepare_attempt(&mut self, request: &ConnectRequest, phase: Phase) {
        self.generation = self.generation.wrapping_add(1);
        self.phase = phase;
        self.endpoint = request.endpoint_display();
        self.identity = None;
        self.token_offered = request.has_token();
        self.posture = Some(request.transport_posture());
        self.request_retained = true;
        self.touch();
    }

    /// Returns the generation currently owning the view.
    #[must_use]
    pub const fn generation(&self) -> u64 {
        self.generation
    }

    /// Updates platform environment facts, returning whether binding state changed.
    pub fn set_environment(&mut self, lifecycle: AppLifecycle, network: NetworkStatus) -> bool {
        if self.lifecycle == lifecycle && self.network == network {
            return false;
        }
        self.lifecycle = lifecycle;
        self.network = network;
        self.touch();
        true
    }

    /// Returns the current lifecycle fact.
    #[must_use]
    pub const fn lifecycle(&self) -> AppLifecycle {
        self.lifecycle
    }

    /// Returns the current connectivity fact.
    #[must_use]
    pub const fn network(&self) -> NetworkStatus {
        self.network
    }

    /// Updates platform capability facts, returning whether binding state changed.
    pub fn set_platform_capabilities(&mut self, capabilities: PlatformCapabilities) -> bool {
        if self.platform_capabilities == capabilities {
            return false;
        }
        self.platform_capabilities = capabilities;
        self.touch();
        true
    }

    /// Applies one update, ignoring any update from a superseded attempt.
    ///
    /// Returns whether the update changed binding state. Duplicate live updates
    /// and every stale update return `false`.
    pub fn apply(&mut self, generation: u64, update: AttemptUpdate) -> bool {
        if generation != self.generation {
            return false;
        }
        let changed = match update {
            AttemptUpdate::IdentityCreated(identity) => {
                if self.identity.as_deref() == Some(identity.as_str()) {
                    false
                } else {
                    self.identity = Some(identity);
                    true
                }
            }
            AttemptUpdate::Connecting => self.replace_phase(Phase::Connecting),
            AttemptUpdate::Authenticating => self.replace_phase(Phase::Authenticating),
            AttemptUpdate::Ready(summary) => self.replace_phase(Phase::Ready(Box::new(summary))),
            AttemptUpdate::Reconnecting { attempt, delay } => {
                self.replace_phase(Phase::Reconnecting { attempt, delay })
            }
            AttemptUpdate::Failed(error) => self.replace_phase(Phase::Failed(error)),
            AttemptUpdate::Stopped => self.replace_phase(Phase::Stopped),
        };
        if changed {
            self.touch();
        }
        changed
    }

    /// Marks the attempt stopped without waiting for the transport to report it.
    ///
    /// Returns whether binding state changed.
    pub fn request_stop(&mut self) -> bool {
        if matches!(self.phase, Phase::Stopped) && !self.request_retained {
            return false;
        }
        self.generation = self.generation.wrapping_add(1);
        self.phase = Phase::Stopped;
        self.request_retained = false;
        self.touch();
        true
    }

    fn replace_phase(&mut self, phase: Phase) -> bool {
        if self.phase == phase {
            false
        } else {
            self.phase = phase;
            true
        }
    }

    const fn touch(&mut self) {
        self.revision = self.revision.wrapping_add(1);
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
            Phase::Blocked(ConnectionBlocker::Background) => (
                "Connection paused".to_owned(),
                "The app is in the background. The retained connection will resume in the \
                 foreground."
                    .to_owned(),
                "Paused".to_owned(),
                StatusKind::Warning,
            ),
            Phase::Blocked(ConnectionBlocker::NetworkUnavailable) => (
                "Waiting for network".to_owned(),
                "The retained connection will resume when Android reports a usable network."
                    .to_owned(),
                "Offline".to_owned(),
                StatusKind::Warning,
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
        let retry = match self.phase {
            Phase::Reconnecting { attempt, delay } => Some(RetrySnapshot::new(attempt, delay)),
            _ => None,
        };
        let remedy = match &self.phase {
            Phase::Blocked(ConnectionBlocker::Background) => Some(RemedySnapshot::new(
                DiagnosticCode::AppBackgrounded,
                RemedyKind::BringToForeground,
                "Return to the app to resume the connection.",
            )),
            Phase::Blocked(ConnectionBlocker::NetworkUnavailable) => Some(RemedySnapshot::new(
                DiagnosticCode::NetworkUnavailable,
                RemedyKind::CheckNetwork,
                "Connect this device to Wi-Fi or cellular data.",
            )),
            Phase::Reconnecting { .. } => Some(RemedySnapshot::new(
                DiagnosticCode::ConnectionDropped,
                RemedyKind::Wait,
                "The app is retrying automatically within a bounded budget.",
            )),
            Phase::Failed(error) => Some(RemedySnapshot::from_error(error)),
            Phase::Idle
            | Phase::Connecting
            | Phase::Authenticating
            | Phase::Ready(_)
            | Phase::Stopped => None,
        };
        let phase = match self.phase {
            Phase::Idle => ConnectionPhase::Idle,
            Phase::Blocked(ConnectionBlocker::Background) => ConnectionPhase::Suspended,
            Phase::Blocked(ConnectionBlocker::NetworkUnavailable) => {
                ConnectionPhase::WaitingForNetwork
            }
            Phase::Connecting => ConnectionPhase::Connecting,
            Phase::Authenticating => ConnectionPhase::Authenticating,
            Phase::Ready(_) => ConnectionPhase::Ready,
            Phase::Reconnecting { .. } => ConnectionPhase::Reconnecting,
            Phase::Failed(_) => ConnectionPhase::Failed,
            Phase::Stopped => ConnectionPhase::Disconnected,
        };
        let pending_connection = matches!(
            self.phase,
            Phase::Blocked(_)
                | Phase::Connecting
                | Phase::Authenticating
                | Phase::Ready(_)
                | Phase::Reconnecting { .. }
        );

        ViewSnapshot {
            revision: self.revision,
            phase,
            title,
            detail,
            status_label,
            status_kind,
            lifecycle: self.lifecycle,
            network: self.network,
            network_summary: self.network.summary(),
            platform_capabilities: self.platform_capabilities,
            platform_notice: self.platform_capabilities.notice(),
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
            connection_epoch: ready
                .map(ReadySummary::connection_epoch)
                .filter(|epoch| *epoch != 0),
            identity_summary: self
                .identity
                .clone()
                .unwrap_or_else(|| "not generated".to_owned()),
            credential_notice: credential_notice(self.platform_capabilities).to_owned(),
            transport_notice: self.posture.map_or_else(
                || "No connection has been attempted yet.".to_owned(),
                |posture| posture.notice().to_owned(),
            ),
            pending_connection,
            token_offered: self.token_offered,
            busy: matches!(
                self.phase,
                Phase::Connecting | Phase::Authenticating | Phase::Reconnecting { .. }
            ),
            can_connect: self.can_start_connection(),
            can_disconnect: pending_connection,
            can_retry: self.request_retained && matches!(self.phase, Phase::Failed(_)),
            retry,
            remedy,
            error: match &self.phase {
                Phase::Failed(error) => Some(error.clone()),
                _ => None,
            },
        }
    }
}

/// Portable default for a core with no platform identity store.
///
/// `GatewayClient::take_issued_device_tokens` hands back device tokens, and this
/// core deliberately drops them even when a shell supplies a durable identity.
pub const CREDENTIAL_NOTICE: &str = "Session only. No token or device key is written to this device, so every launch \
     re-authenticates from scratch.";

const DEVICE_BACKED_CREDENTIAL_NOTICE: &str = "The platform retains the device identity. Shared and issued Gateway \
     tokens remain in memory only.";

const fn credential_notice(capabilities: PlatformCapabilities) -> &'static str {
    match capabilities.identity_persistence() {
        IdentityPersistence::SessionOnly => CREDENTIAL_NOTICE,
        IdentityPersistence::DeviceBacked => DEVICE_BACKED_CREDENTIAL_NOTICE,
    }
}

/// Structured bounded-retry state.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RetrySnapshot {
    attempt: u32,
    delay_millis: u64,
}

impl RetrySnapshot {
    fn new(attempt: u32, delay: Duration) -> Self {
        Self {
            attempt,
            delay_millis: u64::try_from(delay.as_millis()).unwrap_or(u64::MAX),
        }
    }

    /// Returns the one-based retry attempt.
    #[must_use]
    pub const fn attempt(self) -> u32 {
        self.attempt
    }

    /// Returns the selected retry delay in milliseconds.
    #[must_use]
    pub const fn delay_millis(self) -> u64 {
        self.delay_millis
    }
}

/// Structured operator remedy suitable for binding to an action.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RemedySnapshot {
    diagnostic: DiagnosticCode,
    kind: RemedyKind,
    action: String,
}

impl RemedySnapshot {
    fn new(diagnostic: DiagnosticCode, kind: RemedyKind, action: impl Into<String>) -> Self {
        Self {
            diagnostic,
            kind,
            action: action.into(),
        }
    }

    fn from_error(error: &UserError) -> Self {
        Self::new(error.diagnostic_code(), error.remedy_kind(), error.action())
    }

    /// Returns the stable diagnostic identity.
    #[must_use]
    pub const fn diagnostic_code(&self) -> DiagnosticCode {
        self.diagnostic
    }

    /// Returns the action category.
    #[must_use]
    pub const fn kind(&self) -> RemedyKind {
        self.kind
    }

    /// Returns the operator-facing action text.
    #[must_use]
    pub fn action(&self) -> &str {
        &self.action
    }
}

/// An immutable projection of [`ViewModel`] for the UI layer.
#[derive(Clone, Debug, Eq, PartialEq)]
#[expect(
    clippy::struct_excessive_bools,
    reason = "these are independent facts a toolkit binds directly to controls and indicators; \
              they are derived from the closed phase rather than forming another state machine"
)]
pub struct ViewSnapshot {
    revision: u64,
    phase: ConnectionPhase,
    title: String,
    detail: String,
    status_label: String,
    status_kind: StatusKind,
    lifecycle: AppLifecycle,
    network: NetworkStatus,
    network_summary: String,
    platform_capabilities: PlatformCapabilities,
    platform_notice: String,
    endpoint_summary: String,
    server_summary: String,
    protocol_summary: String,
    role_summary: String,
    scopes_summary: String,
    connection_epoch: Option<u64>,
    identity_summary: String,
    credential_notice: String,
    transport_notice: String,
    pending_connection: bool,
    token_offered: bool,
    busy: bool,
    can_connect: bool,
    can_disconnect: bool,
    can_retry: bool,
    retry: Option<RetrySnapshot>,
    remedy: Option<RemedySnapshot>,
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
    network_summary,
    platform_notice,
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
    /// Returns the monotonically changing binding revision.
    #[must_use]
    pub const fn revision(&self) -> u64 {
        self.revision
    }

    /// Returns the stable connection phase.
    #[must_use]
    pub const fn phase(&self) -> ConnectionPhase {
        self.phase
    }

    /// Returns the coarse status phase.
    #[must_use]
    pub const fn status_kind(&self) -> StatusKind {
        self.status_kind
    }

    /// Returns the latest application lifecycle fact.
    #[must_use]
    pub const fn lifecycle(&self) -> AppLifecycle {
        self.lifecycle
    }

    /// Returns the latest connectivity fact.
    #[must_use]
    pub const fn network(&self) -> NetworkStatus {
        self.network
    }

    /// Returns the platform capabilities in effect.
    #[must_use]
    pub const fn platform_capabilities(&self) -> PlatformCapabilities {
        self.platform_capabilities
    }

    /// Returns the process-local ready epoch, when authenticated.
    #[must_use]
    pub const fn connection_epoch(&self) -> Option<u64> {
        self.connection_epoch
    }

    /// Returns whether a connection intent is retained.
    #[must_use]
    pub const fn pending_connection(&self) -> bool {
        self.pending_connection
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

    /// Returns whether the retained request can be retried without re-entering it.
    #[must_use]
    pub const fn can_retry(&self) -> bool {
        self.can_retry
    }

    /// Returns bounded retry details, when the transport is backing off.
    #[must_use]
    pub const fn retry(&self) -> Option<RetrySnapshot> {
        self.retry
    }

    /// Returns the current structured remedy.
    #[must_use]
    pub const fn remedy(&self) -> Option<&RemedySnapshot> {
        self.remedy.as_ref()
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
        AttemptUpdate, ConnectRequest, ConnectionPhase, DiagnosticCode, ReadySummary, RemedyKind,
        StatusKind, SubmissionRejection, TransportPosture, UserError, ViewModel,
    };
    use crate::platform::{
        AppLifecycle, ConnectionBlocker, DiscoveryReadiness, IdentityFailure, IdentityPersistence,
        NetworkStatus, PlatformCapabilities,
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
            "bare hosts must default to wss, got {request:?}"
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
    fn duplicate_live_updates_do_not_advance_the_binding_revision() {
        let mut model = ViewModel::new();
        let generation = model.begin(
            &ConnectRequest::prepare("wss://gateway.example.com", "", false).expect("valid"),
        );
        let revision = model.snapshot().revision();

        let changed = model.apply(generation, AttemptUpdate::Connecting);

        assert!(
            !changed,
            "the model already begins in Connecting, so a duplicate update must be coalesced"
        );
        assert_eq!(
            model.snapshot().revision(),
            revision,
            "a duplicate update must not trigger shell rebinding"
        );
        assert!(
            model.apply(generation, AttemptUpdate::Authenticating),
            "a real phase change must be accepted"
        );
        assert_eq!(
            model.snapshot().revision(),
            revision + 1,
            "one real phase change must advance the revision exactly once"
        );
    }

    #[test]
    fn a_network_blocker_supersedes_the_socket_and_exposes_a_typed_remedy() {
        let mut model = ViewModel::new();
        let generation = model.begin(
            &ConnectRequest::prepare("wss://gateway.example.com", "", false).expect("valid"),
        );
        model.set_environment(AppLifecycle::Foreground, NetworkStatus::Unavailable);
        model.suspend(ConnectionBlocker::NetworkUnavailable);

        let snapshot = model.snapshot();

        assert_eq!(snapshot.phase(), ConnectionPhase::WaitingForNetwork);
        assert_eq!(snapshot.network(), NetworkStatus::Unavailable);
        assert!(
            snapshot.pending_connection() && snapshot.can_disconnect() && !snapshot.busy(),
            "an offline request is retained and cancellable without claiming network work: \
             {snapshot:?}"
        );
        let remedy = snapshot
            .remedy()
            .expect("waiting for a network must expose a remedy");
        assert_eq!(remedy.diagnostic_code(), DiagnosticCode::NetworkUnavailable);
        assert_eq!(remedy.kind(), RemedyKind::CheckNetwork);
        assert!(
            !model.apply(
                generation,
                AttemptUpdate::Ready(ReadySummary::from_info(&ready_info("operator", &["read"])))
            ),
            "the superseded socket must not overwrite the offline snapshot"
        );
    }

    #[test]
    fn reconnect_backoff_is_available_without_parsing_rendered_text() {
        let mut model = ViewModel::new();
        let generation = model.begin(
            &ConnectRequest::prepare("wss://gateway.example.com", "", false).expect("valid"),
        );
        model.apply(
            generation,
            AttemptUpdate::Reconnecting {
                attempt: 2,
                delay: std::time::Duration::from_millis(1_250),
            },
        );

        let snapshot = model.snapshot();
        let retry = snapshot.retry().expect("reconnect state must carry timing");

        assert_eq!(snapshot.phase(), ConnectionPhase::Reconnecting);
        assert_eq!(retry.attempt(), 2);
        assert_eq!(retry.delay_millis(), 1_250);
        assert_eq!(
            snapshot.remedy().map(super::RemedySnapshot::kind),
            Some(RemedyKind::Wait)
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
    fn device_backed_platform_facts_change_the_notice_without_claiming_token_storage() {
        let capabilities =
            PlatformCapabilities::new(IdentityPersistence::DeviceBacked, DiscoveryReadiness::Ready);
        let mut model = ViewModel::new();
        let revision = model.snapshot().revision();
        assert!(
            model.set_platform_capabilities(capabilities),
            "changed platform facts must trigger binding"
        );
        assert!(
            !model.set_platform_capabilities(capabilities),
            "duplicate platform facts must be coalesced"
        );
        let snapshot = model.snapshot();

        assert_eq!(snapshot.platform_capabilities(), capabilities);
        assert_eq!(snapshot.revision(), revision + 1);
        assert!(
            snapshot
                .credential_notice()
                .contains("retains the device identity"),
            "the shell must not describe a device-backed identity as session-only: {snapshot:?}"
        );
        assert!(
            snapshot
                .credential_notice()
                .contains("tokens remain in memory only"),
            "identity persistence must not imply token persistence: {snapshot:?}"
        );
    }

    #[test]
    fn platform_identity_failures_have_distinct_non_secret_remedies() {
        let locked = UserError::from_identity_failure(IdentityFailure::StorageLocked);
        let invalidated = UserError::from_identity_failure(IdentityFailure::StorageInvalidated);

        assert_eq!(locked.diagnostic_code(), DiagnosticCode::IdentityLocked);
        assert_eq!(locked.remedy_kind(), RemedyKind::Retry);
        assert_eq!(
            invalidated.diagnostic_code(),
            DiagnosticCode::IdentityInvalidated
        );
        assert_eq!(invalidated.remedy_kind(), RemedyKind::RegisterDevice);
        assert!(
            !format!("{locked:?} {invalidated:?}").contains("key material"),
            "closed platform errors must not reproduce facility internals"
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
            UserError::diagnostic(
                DiagnosticCode::ReconnectExhausted,
                RemedyKind::CheckNetwork,
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

        assert!(
            model.request_stop(),
            "the first stop must supersede the live attempt"
        );
        let stopped_revision = model.snapshot().revision();
        assert!(
            !model.request_stop(),
            "a duplicate stop must not trigger another binding update"
        );
        assert_eq!(model.snapshot().revision(), stopped_revision);
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

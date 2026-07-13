use std::error::Error;
use std::fmt::{self, Display, Formatter};

use serde::{Deserialize, Deserializer, Serialize};

use super::{
    ClientMode, Codec, CodecError, ConnectChallenge, ConnectParams, Frame,
    GATEWAY_PROTOCOL_VERSION, HelloOk, MIN_GENERAL_PROTOCOL_VERSION, MIN_NODE_PROTOCOL_VERSION,
    MIN_PROBE_PROTOCOL_VERSION, Name, OperatorScope, RequestId, Role, TransportPhase,
};

fn deserialize_optional_non_null<'de, D, T>(deserializer: D) -> Result<Option<T>, D::Error>
where
    D: Deserializer<'de>,
    T: Deserialize<'de>,
{
    T::deserialize(deserializer).map(Some)
}

/// Structured connect-error detail code registry from `connect-error-details.ts`.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum ConnectErrorDetailCode {
    /// Authentication is required.
    AuthRequired,
    /// Authentication was not authorized.
    AuthUnauthorized,
    /// Token missing.
    AuthTokenMissing,
    /// Token mismatch.
    AuthTokenMismatch,
    /// Token authentication is not configured.
    AuthTokenNotConfigured,
    /// Password missing.
    AuthPasswordMissing,
    /// Password mismatch.
    AuthPasswordMismatch,
    /// Password authentication is not configured.
    AuthPasswordNotConfigured,
    /// Bootstrap token invalid.
    AuthBootstrapTokenInvalid,
    /// Device token mismatch.
    AuthDeviceTokenMismatch,
    /// Authenticated scopes mismatch.
    AuthScopeMismatch,
    /// Authentication is rate limited.
    AuthRateLimited,
    /// Tailscale identity missing.
    AuthTailscaleIdentityMissing,
    /// Tailscale proxy metadata missing.
    AuthTailscaleProxyMissing,
    /// Tailscale whois failed.
    AuthTailscaleWhoisFailed,
    /// Tailscale identity mismatch.
    AuthTailscaleIdentityMismatch,
    /// Browser Control UI origin is not allowed.
    ControlUiOriginNotAllowed,
    /// Client protocol range is incompatible.
    ProtocolMismatch,
    /// Control UI requires device identity.
    ControlUiDeviceIdentityRequired,
    /// Device identity is required.
    DeviceIdentityRequired,
    /// Device authentication is invalid.
    DeviceAuthInvalid,
    /// Derived device ID mismatch.
    DeviceAuthDeviceIdMismatch,
    /// Device signature expired.
    DeviceAuthSignatureExpired,
    /// Challenge nonce missing.
    DeviceAuthNonceRequired,
    /// Challenge nonce mismatch.
    DeviceAuthNonceMismatch,
    /// Signature verification failed.
    DeviceAuthSignatureInvalid,
    /// Device public key is invalid.
    DeviceAuthPublicKeyInvalid,
    /// Device pairing or an upgrade is required.
    PairingRequired,
    /// Released client version is incompatible.
    ClientVersionMismatch,
}

impl ConnectErrorDetailCode {
    /// All 29 pinned detail codes in source order.
    pub const ALL: [Self; 29] = [
        Self::AuthRequired,
        Self::AuthUnauthorized,
        Self::AuthTokenMissing,
        Self::AuthTokenMismatch,
        Self::AuthTokenNotConfigured,
        Self::AuthPasswordMissing,
        Self::AuthPasswordMismatch,
        Self::AuthPasswordNotConfigured,
        Self::AuthBootstrapTokenInvalid,
        Self::AuthDeviceTokenMismatch,
        Self::AuthScopeMismatch,
        Self::AuthRateLimited,
        Self::AuthTailscaleIdentityMissing,
        Self::AuthTailscaleProxyMissing,
        Self::AuthTailscaleWhoisFailed,
        Self::AuthTailscaleIdentityMismatch,
        Self::ControlUiOriginNotAllowed,
        Self::ProtocolMismatch,
        Self::ControlUiDeviceIdentityRequired,
        Self::DeviceIdentityRequired,
        Self::DeviceAuthInvalid,
        Self::DeviceAuthDeviceIdMismatch,
        Self::DeviceAuthSignatureExpired,
        Self::DeviceAuthNonceRequired,
        Self::DeviceAuthNonceMismatch,
        Self::DeviceAuthSignatureInvalid,
        Self::DeviceAuthPublicKeyInvalid,
        Self::PairingRequired,
        Self::ClientVersionMismatch,
    ];

    /// Returns the exact wire identity.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::AuthRequired => "AUTH_REQUIRED",
            Self::AuthUnauthorized => "AUTH_UNAUTHORIZED",
            Self::AuthTokenMissing => "AUTH_TOKEN_MISSING",
            Self::AuthTokenMismatch => "AUTH_TOKEN_MISMATCH",
            Self::AuthTokenNotConfigured => "AUTH_TOKEN_NOT_CONFIGURED",
            Self::AuthPasswordMissing => "AUTH_PASSWORD_MISSING",
            Self::AuthPasswordMismatch => "AUTH_PASSWORD_MISMATCH",
            Self::AuthPasswordNotConfigured => "AUTH_PASSWORD_NOT_CONFIGURED",
            Self::AuthBootstrapTokenInvalid => "AUTH_BOOTSTRAP_TOKEN_INVALID",
            Self::AuthDeviceTokenMismatch => "AUTH_DEVICE_TOKEN_MISMATCH",
            Self::AuthScopeMismatch => "AUTH_SCOPE_MISMATCH",
            Self::AuthRateLimited => "AUTH_RATE_LIMITED",
            Self::AuthTailscaleIdentityMissing => "AUTH_TAILSCALE_IDENTITY_MISSING",
            Self::AuthTailscaleProxyMissing => "AUTH_TAILSCALE_PROXY_MISSING",
            Self::AuthTailscaleWhoisFailed => "AUTH_TAILSCALE_WHOIS_FAILED",
            Self::AuthTailscaleIdentityMismatch => "AUTH_TAILSCALE_IDENTITY_MISMATCH",
            Self::ControlUiOriginNotAllowed => "CONTROL_UI_ORIGIN_NOT_ALLOWED",
            Self::ProtocolMismatch => "PROTOCOL_MISMATCH",
            Self::ControlUiDeviceIdentityRequired => "CONTROL_UI_DEVICE_IDENTITY_REQUIRED",
            Self::DeviceIdentityRequired => "DEVICE_IDENTITY_REQUIRED",
            Self::DeviceAuthInvalid => "DEVICE_AUTH_INVALID",
            Self::DeviceAuthDeviceIdMismatch => "DEVICE_AUTH_DEVICE_ID_MISMATCH",
            Self::DeviceAuthSignatureExpired => "DEVICE_AUTH_SIGNATURE_EXPIRED",
            Self::DeviceAuthNonceRequired => "DEVICE_AUTH_NONCE_REQUIRED",
            Self::DeviceAuthNonceMismatch => "DEVICE_AUTH_NONCE_MISMATCH",
            Self::DeviceAuthSignatureInvalid => "DEVICE_AUTH_SIGNATURE_INVALID",
            Self::DeviceAuthPublicKeyInvalid => "DEVICE_AUTH_PUBLIC_KEY_INVALID",
            Self::PairingRequired => "PAIRING_REQUIRED",
            Self::ClientVersionMismatch => "CLIENT_VERSION_MISMATCH",
        }
    }

    /// Parses an exact, case-sensitive detail-code identity.
    #[must_use]
    pub fn from_identity(identity: &str) -> Option<Self> {
        Self::ALL
            .iter()
            .copied()
            .find(|code| code.as_str() == identity)
    }
}

/// Pairing-specific reason registry.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum PairingRequiredReason {
    /// Device is not approved.
    NotPaired,
    /// Device requests a higher role.
    RoleUpgrade,
    /// Device requests additional scopes.
    ScopeUpgrade,
    /// Device identity metadata changed.
    MetadataUpgrade,
}

impl PairingRequiredReason {
    /// All four pairing reasons in source order.
    pub const ALL: [Self; 4] = [
        Self::NotPaired,
        Self::RoleUpgrade,
        Self::ScopeUpgrade,
        Self::MetadataUpgrade,
    ];

    /// Returns the exact wire identity.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::NotPaired => "not-paired",
            Self::RoleUpgrade => "role-upgrade",
            Self::ScopeUpgrade => "scope-upgrade",
            Self::MetadataUpgrade => "metadata-upgrade",
        }
    }
}

/// Literal code required by pairing-required detail objects.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub enum PairingRequiredCode {
    /// `PAIRING_REQUIRED`.
    #[serde(rename = "PAIRING_REQUIRED")]
    PairingRequired,
}

/// Suggested recovery action carried by pairing error details.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ConnectRecoveryNextStep {
    /// Retry using the device token.
    RetryWithDeviceToken,
    /// Update configured authentication.
    UpdateAuthConfiguration,
    /// Update supplied credentials.
    UpdateAuthCredentials,
    /// Wait and retry.
    WaitThenRetry,
    /// Review authentication configuration.
    ReviewAuthConfiguration,
}

/// Structured pairing-required details.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct PairingRequiredDetails {
    /// Literal pairing-required detail code.
    pub code: PairingRequiredCode,
    /// Optional pairing reason.
    #[serde(
        default,
        deserialize_with = "deserialize_optional_non_null",
        skip_serializing_if = "Option::is_none"
    )]
    pub reason: Option<PairingRequiredReason>,
    /// Optional pairing request ID.
    #[serde(
        default,
        deserialize_with = "deserialize_optional_non_null",
        skip_serializing_if = "Option::is_none"
    )]
    pub request_id: Option<String>,
    /// Optional user remediation hint.
    #[serde(
        default,
        deserialize_with = "deserialize_optional_non_null",
        skip_serializing_if = "Option::is_none"
    )]
    pub remediation_hint: Option<String>,
    /// Optional recommended recovery.
    #[serde(
        default,
        deserialize_with = "deserialize_optional_non_null",
        skip_serializing_if = "Option::is_none"
    )]
    pub recommended_next_step: Option<ConnectRecoveryNextStep>,
    /// Optional retry flag.
    #[serde(
        default,
        deserialize_with = "deserialize_optional_non_null",
        skip_serializing_if = "Option::is_none"
    )]
    pub retryable: Option<bool>,
    /// Optional reconnect pause flag.
    #[serde(
        default,
        deserialize_with = "deserialize_optional_non_null",
        skip_serializing_if = "Option::is_none"
    )]
    pub pause_reconnect: Option<bool>,
    /// Optional device identity.
    #[serde(
        default,
        deserialize_with = "deserialize_optional_non_null",
        skip_serializing_if = "Option::is_none"
    )]
    pub device_id: Option<String>,
    /// Optional requested role.
    #[serde(
        default,
        deserialize_with = "deserialize_optional_non_null",
        skip_serializing_if = "Option::is_none"
    )]
    pub requested_role: Option<String>,
    /// Optional requested scopes.
    #[serde(
        default,
        deserialize_with = "deserialize_optional_non_null",
        skip_serializing_if = "Option::is_none"
    )]
    pub requested_scopes: Option<Vec<String>>,
    /// Optional approved roles.
    #[serde(
        default,
        deserialize_with = "deserialize_optional_non_null",
        skip_serializing_if = "Option::is_none"
    )]
    pub approved_roles: Option<Vec<String>>,
    /// Optional approved scopes.
    #[serde(
        default,
        deserialize_with = "deserialize_optional_non_null",
        skip_serializing_if = "Option::is_none"
    )]
    pub approved_scopes: Option<Vec<String>>,
}

/// Protocol compatibility path selected before authentication.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CompatibilityMode {
    /// Client range includes protocol v4.
    Current,
    /// Authenticated probe admitted through the v3 N-1 exception.
    LegacyProbe,
    /// Authenticated node admitted through the v3 N-1 exception.
    LegacyNode,
}

/// Authentication port's device-proof result.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DeviceProofDecision {
    /// A supplied proof was verified externally.
    Verified,
    /// External policy explicitly allowed no device proof.
    NotRequired,
}

/// Typed handshake rejection supplied by authentication/pairing policy.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct HandshakeRejection {
    code: ConnectErrorDetailCode,
    message: String,
    pairing: Option<PairingRequiredDetails>,
}

impl HandshakeRejection {
    /// Creates a typed rejection.
    #[must_use]
    pub fn new(code: ConnectErrorDetailCode, message: impl Into<String>) -> Self {
        Self {
            code,
            message: message.into(),
            pairing: None,
        }
    }

    /// Creates a pairing-required rejection.
    #[must_use]
    pub fn pairing(message: impl Into<String>, details: PairingRequiredDetails) -> Self {
        Self {
            code: ConnectErrorDetailCode::PairingRequired,
            message: message.into(),
            pairing: Some(details),
        }
    }

    /// Returns the structured detail code.
    #[must_use]
    pub const fn code(&self) -> ConnectErrorDetailCode {
        self.code
    }

    /// Returns the rejection message.
    #[must_use]
    pub fn message(&self) -> &str {
        &self.message
    }

    /// Returns pairing details when this is a pairing rejection.
    #[must_use]
    pub const fn pairing_details(&self) -> Option<&PairingRequiredDetails> {
        self.pairing.as_ref()
    }
}

/// External authentication result consumed by the pure reducer.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum AuthenticationDecision {
    /// Authentication, role, scopes, and device policy succeeded.
    Accepted {
        /// Authenticated role.
        role: Role,
        /// Effective closed operator scopes.
        scopes: Vec<OperatorScope>,
        /// External device-proof result.
        device_proof: DeviceProofDecision,
    },
    /// Authentication or pairing rejected the connection.
    Rejected(HandshakeRejection),
}

/// Read-only request passed to an external authentication implementation.
#[derive(Clone, Copy, Debug)]
pub struct AuthenticationRequest<'a> {
    challenge: &'a ConnectChallenge,
    params: &'a ConnectParams,
    compatibility: CompatibilityMode,
    requested_role: Role,
}

impl AuthenticationRequest<'_> {
    /// Returns the challenge that must be covered by any device proof.
    #[must_use]
    pub const fn challenge(&self) -> &ConnectChallenge {
        self.challenge
    }

    /// Returns the strictly decoded connect parameters.
    #[must_use]
    pub const fn params(&self) -> &ConnectParams {
        self.params
    }

    /// Returns the selected protocol compatibility path.
    #[must_use]
    pub const fn compatibility(&self) -> CompatibilityMode {
        self.compatibility
    }

    /// Returns the requested ordinary Gateway role.
    #[must_use]
    pub const fn requested_role(&self) -> Role {
        self.requested_role
    }
}

/// Port implemented by callers that authenticate credentials and verify device proofs.
pub trait AuthenticationPort {
    /// Authenticates one strictly decoded connect attempt.
    fn authenticate(&self, request: AuthenticationRequest<'_>) -> AuthenticationDecision;
}

/// Observable phase of the pure handshake reducer.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum NegotiationState {
    /// Challenge has been sent; exactly one connect request is expected first.
    ChallengeSent,
    /// A strict connect request was received.
    ConnectReceived,
    /// Protocol was accepted and external authentication is required.
    AwaitingAuthentication,
    /// Authentication and device policy succeeded.
    Authenticated,
    /// A v4 hello payload was prepared.
    HelloPrepared,
    /// The hello response was sent.
    HelloSent,
    /// Connection is ready for ordinary frames.
    Ready,
    /// Negotiation ended in a typed rejection.
    Rejected,
}

/// Pure Gateway connection negotiation reducer.
#[derive(Debug)]
pub struct Negotiation {
    state: NegotiationState,
    challenge: ConnectChallenge,
    connect_id: Option<RequestId>,
    params: Option<ConnectParams>,
    compatibility: Option<CompatibilityMode>,
    requested_role: Option<Role>,
    authenticated_role: Option<Role>,
    authenticated_scopes: Vec<OperatorScope>,
    hello: Option<HelloOk>,
    rejection: Option<HandshakeRejection>,
}

impl Negotiation {
    /// Starts immediately after the typed challenge has been sent.
    #[must_use]
    pub fn challenge_sent(challenge: ConnectChallenge) -> Self {
        Self {
            state: NegotiationState::ChallengeSent,
            challenge,
            connect_id: None,
            params: None,
            compatibility: None,
            requested_role: None,
            authenticated_role: None,
            authenticated_scopes: Vec::new(),
            hello: None,
            rejection: None,
        }
    }

    /// Returns the current phase.
    #[must_use]
    pub const fn state(&self) -> NegotiationState {
        self.state
    }

    /// Returns the connect request ID once received.
    #[must_use]
    pub const fn connect_id(&self) -> Option<&RequestId> {
        self.connect_id.as_ref()
    }

    /// Returns the selected compatibility path once checked.
    #[must_use]
    pub const fn compatibility(&self) -> Option<CompatibilityMode> {
        self.compatibility
    }

    /// Returns the terminal typed rejection, if any.
    #[must_use]
    pub const fn rejection(&self) -> Option<&HandshakeRejection> {
        self.rejection.as_ref()
    }

    /// Receives the first frame and requires it to be a strict `req/connect`.
    pub fn receive_first(&mut self, frame: Frame, codec: &Codec) -> Result<(), NegotiationError> {
        self.require_state(NegotiationState::ChallengeSent, "receive first frame")?;
        if codec.phase() != TransportPhase::PreAuthentication {
            return Err(NegotiationError::PreAuthenticationCodecRequired);
        }
        codec.encode(&frame)?;
        let Frame::Request(request) = frame else {
            return Err(NegotiationError::FirstFrameMustBeConnect);
        };
        let params = codec.decode_connect(&request)?;
        self.connect_id = Some(request.id().clone());
        self.params = Some(params);
        self.state = NegotiationState::ConnectReceived;
        Ok(())
    }

    /// Applies the exact v4/general and conditional v3 node/probe predicates.
    pub fn check_protocol(&mut self) -> Result<CompatibilityMode, NegotiationError> {
        self.require_state(NegotiationState::ConnectReceived, "check protocol")?;
        let params = self
            .params
            .as_ref()
            .ok_or(NegotiationError::MissingReducerData("connect params"))?;
        let min = params.min_protocol.get();
        let max = params.max_protocol.get();
        let supports_current =
            max >= GATEWAY_PROTOCOL_VERSION.get() && min <= MIN_GENERAL_PROTOCOL_VERSION.get();
        let requests_node = params.role.as_ref().map(Name::as_str) == Some("node");
        let compatibility = if supports_current {
            CompatibilityMode::Current
        } else if params.client.mode == ClientMode::Probe
            && max >= MIN_PROBE_PROTOCOL_VERSION.get()
            && min <= GATEWAY_PROTOCOL_VERSION.get()
        {
            CompatibilityMode::LegacyProbe
        } else if requests_node
            && params.client.mode == ClientMode::Node
            && max >= MIN_NODE_PROTOCOL_VERSION.get()
            && min <= MIN_NODE_PROTOCOL_VERSION.get()
        {
            CompatibilityMode::LegacyNode
        } else {
            return self.reject(HandshakeRejection::new(
                ConnectErrorDetailCode::ProtocolMismatch,
                format!("unsupported protocol range {min}..={max}; current protocol is 4"),
            ));
        };
        let requested_role = match params.role.as_ref() {
            None => Role::Operator,
            Some(role) => match Role::from_identity(role.as_str()) {
                Some(Role::Operator) => Role::Operator,
                Some(Role::Node) => Role::Node,
                Some(Role::Worker) | None => {
                    return self.reject(HandshakeRejection::new(
                        ConnectErrorDetailCode::AuthUnauthorized,
                        format!("unsupported gateway role `{}`", role.as_str()),
                    ));
                }
            },
        };
        self.compatibility = Some(compatibility);
        self.requested_role = Some(requested_role);
        self.state = NegotiationState::AwaitingAuthentication;
        Ok(compatibility)
    }

    /// Runs a caller-provided authentication/device verifier port.
    pub fn authenticate_with<P: AuthenticationPort>(
        &mut self,
        port: &P,
    ) -> Result<(), NegotiationError> {
        self.require_state(
            NegotiationState::AwaitingAuthentication,
            "authenticate connection",
        )?;
        let request = AuthenticationRequest {
            challenge: &self.challenge,
            params: self
                .params
                .as_ref()
                .ok_or(NegotiationError::MissingReducerData("connect params"))?,
            compatibility: self
                .compatibility
                .ok_or(NegotiationError::MissingReducerData("compatibility"))?,
            requested_role: self
                .requested_role
                .ok_or(NegotiationError::MissingReducerData("requested role"))?,
        };
        self.apply_authentication(port.authenticate(request))
    }

    /// Applies an explicit external authentication/device-proof decision.
    pub fn apply_authentication(
        &mut self,
        decision: AuthenticationDecision,
    ) -> Result<(), NegotiationError> {
        self.require_state(
            NegotiationState::AwaitingAuthentication,
            "apply authentication",
        )?;
        let (role, scopes, device_proof) = match decision {
            AuthenticationDecision::Accepted {
                role,
                scopes,
                device_proof,
            } => (role, scopes, device_proof),
            AuthenticationDecision::Rejected(rejection) => return self.reject(rejection),
        };
        let requested_role = self
            .requested_role
            .ok_or(NegotiationError::MissingReducerData("requested role"))?;
        if role != requested_role || role == Role::Worker {
            return self.reject(HandshakeRejection::new(
                ConnectErrorDetailCode::AuthUnauthorized,
                "authenticated role does not match requested role",
            ));
        }
        let has_device = self
            .params
            .as_ref()
            .ok_or(NegotiationError::MissingReducerData("connect params"))?
            .device
            .is_some();
        if role == Role::Node && !has_device {
            return self.reject(HandshakeRejection::new(
                ConnectErrorDetailCode::DeviceIdentityRequired,
                "node role requires device identity",
            ));
        }
        if has_device && device_proof != DeviceProofDecision::Verified {
            return self.reject(HandshakeRejection::new(
                ConnectErrorDetailCode::DeviceAuthInvalid,
                "supplied device proof was not verified",
            ));
        }
        if !has_device && device_proof == DeviceProofDecision::Verified {
            return self.reject(HandshakeRejection::new(
                ConnectErrorDetailCode::DeviceAuthInvalid,
                "device proof was verified without supplied device identity",
            ));
        }
        if self.compatibility == Some(CompatibilityMode::LegacyNode) && role != Role::Node {
            return self.reject(HandshakeRejection::new(
                ConnectErrorDetailCode::AuthUnauthorized,
                "legacy node window requires node authentication",
            ));
        }
        self.authenticated_role = Some(role);
        self.authenticated_scopes = scopes;
        self.state = NegotiationState::Authenticated;
        Ok(())
    }

    /// Validates and stores the successful hello payload.
    pub fn prepare_hello(&mut self, hello: HelloOk) -> Result<(), NegotiationError> {
        self.require_state(NegotiationState::Authenticated, "prepare hello")?;
        if hello.protocol != GATEWAY_PROTOCOL_VERSION {
            return Err(NegotiationError::HelloProtocolMustBeCurrent {
                received: hello.protocol.get(),
            });
        }
        let role = self
            .authenticated_role
            .ok_or(NegotiationError::MissingReducerData("authenticated role"))?;
        if hello.auth.role.as_str() != role.as_str() {
            return Err(NegotiationError::HelloAuthenticationMismatch);
        }
        let hello_scopes = hello
            .auth
            .scopes
            .iter()
            .map(|scope| OperatorScope::from_identity(scope.as_str()))
            .collect::<Option<Vec<_>>>()
            .ok_or(NegotiationError::HelloAuthenticationMismatch)?;
        if hello_scopes != self.authenticated_scopes {
            return Err(NegotiationError::HelloAuthenticationMismatch);
        }
        self.hello = Some(hello);
        self.state = NegotiationState::HelloPrepared;
        Ok(())
    }

    /// Marks the prepared hello response as sent.
    pub fn mark_hello_sent(&mut self) -> Result<(), NegotiationError> {
        self.require_state(NegotiationState::HelloPrepared, "mark hello sent")?;
        self.state = NegotiationState::HelloSent;
        Ok(())
    }

    /// Completes negotiation after hello transmission.
    pub fn mark_ready(&mut self) -> Result<(), NegotiationError> {
        self.require_state(NegotiationState::HelloSent, "mark ready")?;
        self.state = NegotiationState::Ready;
        Ok(())
    }

    /// Returns the prepared hello payload.
    #[must_use]
    pub const fn hello(&self) -> Option<&HelloOk> {
        self.hello.as_ref()
    }

    fn require_state(
        &self,
        expected: NegotiationState,
        action: &'static str,
    ) -> Result<(), NegotiationError> {
        if self.state == expected {
            Ok(())
        } else {
            Err(NegotiationError::IllegalTransition {
                state: self.state,
                expected,
                action,
            })
        }
    }

    fn reject<T>(&mut self, rejection: HandshakeRejection) -> Result<T, NegotiationError> {
        self.state = NegotiationState::Rejected;
        self.rejection = Some(rejection.clone());
        Err(NegotiationError::Rejected(Box::new(rejection)))
    }
}

/// A reducer transition, decoding, or typed handshake rejection.
#[derive(Debug)]
pub enum NegotiationError {
    /// A method was called outside its legal phase.
    IllegalTransition {
        /// Current phase.
        state: NegotiationState,
        /// Required phase.
        expected: NegotiationState,
        /// Attempted action.
        action: &'static str,
    },
    /// The first frame was not a request.
    FirstFrameMustBeConnect,
    /// Strict frame/DTO decoding failed.
    Codec(CodecError),
    /// Handshake frame validation requires the proven pre-authentication codec.
    PreAuthenticationCodecRequired,
    /// Authentication or negotiation produced a typed rejection.
    Rejected(Box<HandshakeRejection>),
    /// Successful hello must always announce protocol four.
    HelloProtocolMustBeCurrent {
        /// Received protocol.
        received: u64,
    },
    /// Hello auth role/scopes differed from the authenticated result.
    HelloAuthenticationMismatch,
    /// Internal reducer data was unexpectedly absent.
    MissingReducerData(&'static str),
}

impl From<CodecError> for NegotiationError {
    fn from(error: CodecError) -> Self {
        Self::Codec(error)
    }
}

impl Display for NegotiationError {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        match self {
            Self::IllegalTransition {
                state,
                expected,
                action,
            } => write!(
                formatter,
                "cannot {action} in {state:?}; expected {expected:?}"
            ),
            Self::FirstFrameMustBeConnect => {
                formatter.write_str("first frame must be a connect request")
            }
            Self::Codec(error) => Display::fmt(error, formatter),
            Self::PreAuthenticationCodecRequired => {
                formatter.write_str("handshake requires a pre-authentication codec")
            }
            Self::Rejected(rejection) => formatter.write_str(rejection.message()),
            Self::HelloProtocolMustBeCurrent { received } => {
                write!(
                    formatter,
                    "successful hello protocol must be 4, received {received}"
                )
            }
            Self::HelloAuthenticationMismatch => {
                formatter.write_str("hello authentication differs from negotiated authentication")
            }
            Self::MissingReducerData(field) => write!(formatter, "missing reducer data: {field}"),
        }
    }
}

impl Error for NegotiationError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Codec(error) => Some(error),
            _ => None,
        }
    }
}

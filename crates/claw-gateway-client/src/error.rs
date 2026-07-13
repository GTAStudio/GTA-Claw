use std::error::Error;
use std::fmt::{self, Debug, Display, Formatter};
use std::sync::Arc;
use std::time::Duration;

use claw_protocol::gateway::{
    CodecError, ConnectErrorDetailCode, EventFrame, EventSequence, ProtocolVersion, RequestId,
};
use secrecy::SecretString;
use tokio::sync::OwnedSemaphorePermit;

use crate::config::ConfigurationError;

/// Broad failure class controlling reconnect behavior.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum FailureClass {
    /// A connection may be retried under caller policy.
    TransientTransport,
    /// Credentials or pairing policy require caller action.
    Authentication,
    /// Peer data violated the pinned protocol and is not retried.
    Protocol,
    /// Local configuration cannot succeed without caller changes.
    PermanentConfiguration,
}

/// Redacted transport failure category.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TransportFailure {
    /// TCP, TLS, or WebSocket opening failed.
    Connect,
    /// Reading from the WebSocket failed.
    Read,
    /// Writing to the WebSocket failed.
    Write,
    /// Peer closed the connection.
    Closed,
    /// Connection operation exceeded its configured timeout.
    TimedOut,
    /// Peer negotiated an unsupported WebSocket extension.
    UnsupportedExtension,
}

impl Display for TransportFailure {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::Connect => "Gateway transport connection failed",
            Self::Read => "Gateway transport read failed",
            Self::Write => "Gateway transport write failed",
            Self::Closed => "Gateway transport closed",
            Self::TimedOut => "Gateway transport operation timed out",
            Self::UnsupportedExtension => "Gateway negotiated an unsupported WebSocket extension",
        })
    }
}

impl Error for TransportFailure {}

/// Authentication failure with only structured, non-secret diagnostics.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AuthenticationFailure {
    detail_code: Option<ConnectErrorDetailCode>,
}

impl AuthenticationFailure {
    pub(crate) const fn new(detail_code: Option<ConnectErrorDetailCode>) -> Self {
        Self { detail_code }
    }

    /// Returns the pinned structured detail code when the peer supplied one.
    #[must_use]
    pub const fn detail_code(self) -> Option<ConnectErrorDetailCode> {
        self.detail_code
    }
}

impl Display for AuthenticationFailure {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        match self.detail_code {
            Some(code) => write!(
                formatter,
                "Gateway authentication rejected ({})",
                code.as_str()
            ),
            None => formatter.write_str("Gateway authentication rejected"),
        }
    }
}

impl Error for AuthenticationFailure {}

/// Sequence discontinuity requiring the caller to rebuild state from a snapshot.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ResyncRequired {
    /// One or more sequenced broadcasts were skipped.
    Gap {
        /// Expected next sequence.
        expected: u64,
        /// Received sequence.
        received: u64,
    },
    /// The peer repeated the last accepted sequence.
    Duplicate {
        /// Repeated sequence.
        sequence: u64,
    },
    /// The peer moved backwards in the sequence.
    Regression {
        /// Last accepted sequence.
        last: u64,
        /// Received lower sequence.
        received: u64,
    },
    /// The caller did not drain the bounded event queue.
    EventQueueSaturated,
}

impl Display for ResyncRequired {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        match self {
            Self::Gap { expected, received } => {
                write!(
                    formatter,
                    "event resync required: expected {expected}, received {received}"
                )
            }
            Self::Duplicate { sequence } => {
                write!(
                    formatter,
                    "event resync required: duplicate sequence {sequence}"
                )
            }
            Self::Regression { last, received } => write!(
                formatter,
                "event resync required: sequence regressed from {last} to {received}"
            ),
            Self::EventQueueSaturated => {
                formatter.write_str("event resync required: bounded event queue saturated")
            }
        }
    }
}

impl Error for ResyncRequired {}

/// Pinned protocol violation detected by the client.
#[derive(Debug)]
pub enum ProtocolFailure {
    /// Strict P02a codec rejection.
    Codec(CodecError),
    /// The first application frame was not `connect.challenge`.
    ExpectedChallenge,
    /// A successful hello did not negotiate protocol v4.
    HelloProtocol {
        /// Received protocol.
        received: u64,
    },
    /// Hello authentication role or scopes did not match the request.
    HelloAuthenticationMismatch,
    /// Connect negotiation was rejected for a pinned protocol reason.
    HandshakeRejected(ConnectErrorDetailCode),
    /// Binary application data is unsupported.
    BinaryMessage,
    /// A complete message exceeded the phase-specific transport cap.
    InboundMessageTooLarge {
        /// Active cap.
        limit: usize,
    },
    /// A text message was not valid UTF-8 after fragment reassembly.
    InvalidUtf8,
    /// Fragment sequence violated RFC 6455.
    InvalidFragmentation,
    /// WebSocket framing violated RFC 6455.
    WebSocketProtocol(&'static str),
    /// Server sent a request to this client transport.
    UnexpectedServerRequest,
    /// Encoded request exceeds the server-advertised payload policy.
    OutboundMessageTooLarge {
        /// Encoded bytes.
        actual: usize,
        /// Server-advertised cap.
        limit: usize,
    },
    /// A response did not correspond to any pending request.
    UnknownResponse(RequestId),
    /// A response identifier was already completed on this connection.
    DuplicateResponse(RequestId),
    /// The same request identifier is already pending.
    DuplicateRequest(RequestId),
    /// Event continuity was lost and state must be rebuilt.
    ResyncRequired(ResyncRequired),
}

impl Display for ProtocolFailure {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        match self {
            Self::Codec(error) => Display::fmt(error, formatter),
            Self::ExpectedChallenge => {
                formatter.write_str("first Gateway frame must be connect.challenge")
            }
            Self::HelloProtocol { received } => {
                write!(
                    formatter,
                    "Gateway hello negotiated protocol {received}; expected 4"
                )
            }
            Self::HelloAuthenticationMismatch => {
                formatter.write_str("Gateway hello authentication claims do not match")
            }
            Self::HandshakeRejected(code) => {
                write!(formatter, "Gateway handshake rejected ({})", code.as_str())
            }
            Self::BinaryMessage => {
                formatter.write_str("Gateway binary application messages are unsupported")
            }
            Self::InboundMessageTooLarge { limit } => {
                write!(formatter, "Gateway message exceeded the {limit}-byte cap")
            }
            Self::InvalidUtf8 => formatter.write_str("Gateway text message is not valid UTF-8"),
            Self::InvalidFragmentation => {
                formatter.write_str("Gateway WebSocket fragmentation is invalid")
            }
            Self::WebSocketProtocol(category) => {
                write!(
                    formatter,
                    "Gateway WebSocket framing violated RFC 6455 ({category})"
                )
            }
            Self::UnexpectedServerRequest => {
                formatter.write_str("Gateway server sent an unexpected request frame")
            }
            Self::OutboundMessageTooLarge { actual, limit } => {
                write!(
                    formatter,
                    "Gateway request is {actual} bytes; server limit is {limit}"
                )
            }
            Self::UnknownResponse(id) => write!(formatter, "unknown Gateway response id `{id}`"),
            Self::DuplicateResponse(id) => {
                write!(formatter, "duplicate Gateway response id `{id}`")
            }
            Self::DuplicateRequest(id) => write!(formatter, "duplicate Gateway request id `{id}`"),
            Self::ResyncRequired(reason) => Display::fmt(reason, formatter),
        }
    }
}

impl Error for ProtocolFailure {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Codec(error) => Some(error),
            Self::ResyncRequired(error) => Some(error),
            _ => None,
        }
    }
}

/// Explicit bounded-queue or in-flight rejection.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum BackpressureError {
    /// Maximum simultaneously pending requests is already reached.
    InFlightLimit,
    /// The bounded socket command queue is full.
    CommandQueueSaturated,
    /// The bounded per-connection unique identifier budget is exhausted.
    IdentifierCapacity,
}

impl Display for BackpressureError {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::InFlightLimit => "Gateway in-flight request limit reached",
            Self::CommandQueueSaturated => "Gateway command queue saturated",
            Self::IdentifierCapacity => {
                "Gateway per-connection request identifier capacity reached"
            }
        })
    }
}

impl Error for BackpressureError {}

/// One request or lifecycle operation failed.
#[derive(Debug)]
pub enum GatewayClientError {
    /// Configuration was rejected before connecting.
    Configuration(ConfigurationError),
    /// Transient transport failure.
    Transport(TransportFailure),
    /// Structured authentication rejection.
    Authentication(AuthenticationFailure),
    /// Pinned protocol violation.
    Protocol(ProtocolFailure),
    /// Explicit bounded backpressure.
    Backpressure(BackpressureError),
    /// Client is not currently authenticated and ready.
    NotReady,
    /// Pending request was cancelled by deterministic shutdown.
    Cancelled,
    /// Pending request was failed on disconnect and was not replayed.
    DisconnectedNotReplayed,
    /// Request exceeded its caller timeout.
    RequestTimedOut(RequestId),
    /// Bounded shutdown did not complete.
    ShutdownTimedOut,
    /// Reconnect attempts were exhausted.
    ReconnectExhausted,
}

impl GatewayClientError {
    /// Returns the reconnect-relevant class.
    #[must_use]
    pub const fn class(&self) -> FailureClass {
        match self {
            Self::Transport(_) | Self::DisconnectedNotReplayed | Self::ReconnectExhausted => {
                FailureClass::TransientTransport
            }
            Self::Authentication(_) => FailureClass::Authentication,
            Self::Protocol(_) => FailureClass::Protocol,
            Self::Configuration(_) => FailureClass::PermanentConfiguration,
            Self::Backpressure(_)
            | Self::NotReady
            | Self::Cancelled
            | Self::RequestTimedOut(_)
            | Self::ShutdownTimedOut => FailureClass::PermanentConfiguration,
        }
    }
}

impl Display for GatewayClientError {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        match self {
            Self::Configuration(error) => Display::fmt(error, formatter),
            Self::Transport(error) => Display::fmt(error, formatter),
            Self::Authentication(error) => Display::fmt(error, formatter),
            Self::Protocol(error) => Display::fmt(error, formatter),
            Self::Backpressure(error) => Display::fmt(error, formatter),
            Self::NotReady => formatter.write_str("Gateway client is not ready"),
            Self::Cancelled => formatter.write_str("Gateway operation cancelled"),
            Self::DisconnectedNotReplayed => {
                formatter.write_str("Gateway request cancelled on disconnect and not replayed")
            }
            Self::RequestTimedOut(id) => write!(formatter, "Gateway request `{id}` timed out"),
            Self::ShutdownTimedOut => formatter.write_str("Gateway client shutdown timed out"),
            Self::ReconnectExhausted => formatter.write_str("Gateway reconnect attempts exhausted"),
        }
    }
}

impl Error for GatewayClientError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Configuration(error) => Some(error),
            Self::Transport(error) => Some(error),
            Self::Authentication(error) => Some(error),
            Self::Protocol(error) => Some(error),
            Self::Backpressure(error) => Some(error),
            _ => None,
        }
    }
}

impl From<CodecError> for GatewayClientError {
    fn from(error: CodecError) -> Self {
        Self::Protocol(ProtocolFailure::Codec(error))
    }
}

/// Non-secret summary of a validated server hello.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ConnectionInfo {
    /// Negotiated protocol.
    pub protocol: ProtocolVersion,
    /// Server version text.
    pub server_version: String,
    /// Server connection identifier.
    pub connection_id: String,
    /// Authenticated role identity.
    pub role: String,
    /// Authenticated scope identities.
    pub scopes: Arc<[String]>,
    /// Number of advertised methods.
    pub advertised_method_count: usize,
    /// Number of advertised events.
    pub advertised_event_count: usize,
    /// Effective inbound/outbound payload cap for this connection.
    pub max_payload_bytes: usize,
}

/// One secret device credential issued by a successful Gateway hello.
pub struct IssuedDeviceToken {
    token: SecretString,
    role: String,
    scopes: Arc<[String]>,
    issued_at_unix_millis: Option<u64>,
}

impl IssuedDeviceToken {
    pub(crate) fn new(
        token: SecretString,
        role: String,
        scopes: Arc<[String]>,
        issued_at_unix_millis: Option<u64>,
    ) -> Self {
        Self {
            token,
            role,
            scopes,
            issued_at_unix_millis,
        }
    }

    /// Returns the secrecy-wrapped credential.
    #[must_use]
    pub const fn token(&self) -> &SecretString {
        &self.token
    }

    /// Returns the role bound to the credential.
    #[must_use]
    pub fn role(&self) -> &str {
        &self.role
    }

    /// Returns the scopes bound to the credential.
    #[must_use]
    pub fn scopes(&self) -> &[String] {
        &self.scopes
    }

    /// Returns the server issuance timestamp when supplied.
    #[must_use]
    pub const fn issued_at_unix_millis(&self) -> Option<u64> {
        self.issued_at_unix_millis
    }
}

impl Debug for IssuedDeviceToken {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("IssuedDeviceToken")
            .field("token", &"[REDACTED]")
            .field("role", &self.role)
            .field("scopes", &self.scopes)
            .field("issued_at_unix_millis", &self.issued_at_unix_millis)
            .finish()
    }
}

/// Observable state of the single reconnecting client task.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ConnectionState {
    /// No network operation has started.
    Starting,
    /// TCP/TLS/WebSocket connection is in progress.
    Connecting,
    /// Challenge/connect/hello authentication is in progress.
    Authenticating,
    /// Connection is authenticated and accepting requests.
    Ready(ConnectionInfo),
    /// Waiting before a caller-authorized transient retry.
    Reconnecting {
        /// One-based retry attempt.
        attempt: u32,
        /// Selected deterministic backoff plus jitter.
        delay: Duration,
    },
    /// Sequence or event-delivery continuity was lost.
    ResyncRequired(ResyncRequired),
    /// Authentication permanently stopped reconnect.
    AuthenticationFailed(AuthenticationFailure),
    /// Protocol failure permanently stopped reconnect.
    ProtocolFailed,
    /// Retry policy was exhausted.
    ReconnectExhausted,
    /// Caller requested deterministic shutdown.
    Stopped,
}

/// One redaction-safe event delivered through the bounded event queue.
pub struct GatewayEvent {
    frame: EventFrame,
    _byte_permit: OwnedSemaphorePermit,
}

impl GatewayEvent {
    pub(crate) const fn new(frame: EventFrame, byte_permit: OwnedSemaphorePermit) -> Self {
        Self {
            frame,
            _byte_permit: byte_permit,
        }
    }

    /// Returns the strict P02a event frame.
    #[must_use]
    pub const fn frame(&self) -> &EventFrame {
        &self.frame
    }

    /// Consumes the wrapper and returns the strict event frame.
    #[must_use]
    pub fn into_frame(self) -> EventFrame {
        self.frame
    }
}

impl Debug for GatewayEvent {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        let payload_bytes = self
            .frame
            .payload()
            .value()
            .map_or(0, claw_protocol::gateway::OpaqueJson::encoded_len);
        formatter
            .debug_struct("GatewayEvent")
            .field("event", &self.frame.event().as_str())
            .field("sequence", &self.frame.sequence().map(EventSequence::get))
            .field("state_version", &self.frame.state_version())
            .field("payload_bytes", &payload_bytes)
            .finish()
    }
}

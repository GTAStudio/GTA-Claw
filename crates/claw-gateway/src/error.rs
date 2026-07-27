//! Typed server-side failures and WebSocket close classifications.

use std::error::Error;
use std::fmt::{self, Display, Formatter};
use std::io;
use std::net::SocketAddr;

use claw_protocol::gateway::{
    AuthorizationError, CodecError, NegotiationError, StringValidationError,
};

/// A failure raised while accepting or upgrading an inbound connection.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum HandshakeError {
    /// The peer sent more upgrade bytes than the fixed handshake budget allows.
    RequestTooLarge {
        /// Configured maximum HTTP upgrade byte budget.
        limit: usize,
    },
    /// The peer closed the socket before completing the HTTP upgrade request.
    UnexpectedEof,
    /// The upgrade bytes were not a syntactically valid HTTP/1.1 request.
    MalformedRequest,
    /// The request method was not `GET`.
    MethodNotAllowed,
    /// The request did not use HTTP/1.1.
    UnsupportedHttpVersion,
    /// `Upgrade: websocket` was absent or wrong.
    MissingWebSocketUpgrade,
    /// `Connection: Upgrade` was absent or wrong.
    MissingConnectionUpgrade,
    /// `Sec-WebSocket-Version` was not exactly `13`.
    UnsupportedWebSocketVersion,
    /// `Sec-WebSocket-Key` was absent, not base64, or not sixteen bytes.
    InvalidWebSocketKey,
    /// The peer requested a WebSocket extension; none are negotiated.
    ExtensionRequested,
    /// A duplicate occurrence of a single-valued handshake header.
    DuplicateHeader,
    /// The handshake did not complete inside the configured window.
    TimedOut,
}

impl HandshakeError {
    /// Returns the HTTP status line sent before the socket is dropped.
    #[must_use]
    pub const fn http_status(self) -> (u16, &'static str) {
        match self {
            Self::RequestTooLarge { .. } => (431, "Request Header Fields Too Large"),
            Self::MethodNotAllowed => (405, "Method Not Allowed"),
            Self::UnsupportedHttpVersion => (505, "HTTP Version Not Supported"),
            Self::UnsupportedWebSocketVersion => (426, "Upgrade Required"),
            Self::TimedOut => (408, "Request Timeout"),
            Self::UnexpectedEof
            | Self::MalformedRequest
            | Self::MissingWebSocketUpgrade
            | Self::MissingConnectionUpgrade
            | Self::InvalidWebSocketKey
            | Self::ExtensionRequested
            | Self::DuplicateHeader => (400, "Bad Request"),
        }
    }
}

impl Display for HandshakeError {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        match self {
            Self::RequestTooLarge { limit } => {
                write!(formatter, "HTTP upgrade request exceeds {limit} bytes")
            }
            Self::UnexpectedEof => formatter.write_str("HTTP upgrade request ended early"),
            Self::MalformedRequest => formatter.write_str("malformed HTTP upgrade request"),
            Self::MethodNotAllowed => formatter.write_str("HTTP upgrade must use GET"),
            Self::UnsupportedHttpVersion => formatter.write_str("HTTP upgrade must use HTTP/1.1"),
            Self::MissingWebSocketUpgrade => formatter.write_str("missing `Upgrade: websocket`"),
            Self::MissingConnectionUpgrade => formatter.write_str("missing `Connection: Upgrade`"),
            Self::UnsupportedWebSocketVersion => {
                formatter.write_str("`Sec-WebSocket-Version` must be 13")
            }
            Self::InvalidWebSocketKey => formatter.write_str("invalid `Sec-WebSocket-Key`"),
            Self::ExtensionRequested => {
                formatter.write_str("no WebSocket extension is negotiated by this server")
            }
            Self::DuplicateHeader => {
                formatter.write_str("duplicate single-valued WebSocket handshake header")
            }
            Self::TimedOut => formatter.write_str("HTTP upgrade timed out"),
        }
    }
}

impl Error for HandshakeError {}

/// A WebSocket framing or message-level violation observed by the server.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum WireError {
    /// The peer sent a message larger than the current phase cap.
    MessageTooLarge {
        /// Active byte cap for the connection phase.
        limit: usize,
        /// Observed size that violated the cap.
        actual: usize,
    },
    /// The peer sent a binary message; the Gateway protocol is JSON text only.
    BinaryMessage,
    /// The peer sent invalid UTF-8 inside a text message.
    InvalidUtf8,
    /// The peer violated RFC 6455 framing rules.
    Protocol(&'static str),
    /// The transport ended without a close handshake.
    Closed,
    /// A socket read failed.
    Read,
    /// A socket write failed.
    Write,
}

impl Display for WireError {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        match self {
            Self::MessageTooLarge { limit, actual } => {
                write!(
                    formatter,
                    "inbound message of {actual} bytes exceeds the {limit} byte cap"
                )
            }
            Self::BinaryMessage => formatter.write_str("binary messages are not accepted"),
            Self::InvalidUtf8 => formatter.write_str("text message is not valid UTF-8"),
            Self::Protocol(detail) => write!(formatter, "WebSocket protocol violation: {detail}"),
            Self::Closed => formatter.write_str("transport closed"),
            Self::Read => formatter.write_str("transport read failed"),
            Self::Write => formatter.write_str("transport write failed"),
        }
    }
}

impl Error for WireError {}

/// The reason one connection stopped, mapped onto an RFC 6455 close code.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ConnectionClose {
    /// The peer completed a close handshake.
    PeerClosed,
    /// The server is shutting down.
    ServerShutdown,
    /// The negotiation reducer rejected the connection.
    HandshakeRejected(String),
    /// The negotiation did not complete inside the configured window.
    HandshakeTimeout,
    /// The peer exceeded a phase byte cap.
    MessageTooLarge {
        /// Active byte cap.
        limit: usize,
    },
    /// The peer violated the frame contract.
    ProtocolViolation(String),
    /// The subscriber could not keep up with the bounded event fan-out.
    SlowConsumer {
        /// Number of events the bus had to drop for this subscriber.
        dropped: u64,
    },
    /// The peer stopped answering server pings.
    Unresponsive,
    /// The device's authorization changed or was withdrawn while it was
    /// connected, so the connection may no longer act on its old snapshot.
    AuthorizationRevoked {
        /// Device wire identity whose authorization no longer admits this
        /// connection.
        device_id: String,
    },
    /// The transport failed.
    Transport(WireError),
}

impl ConnectionClose {
    /// Returns the RFC 6455 close code sent to the peer.
    #[must_use]
    pub const fn close_code(&self) -> u16 {
        match self {
            Self::PeerClosed => 1000,
            Self::ServerShutdown => 1001,
            Self::ProtocolViolation(_) => 1002,
            Self::AuthorizationRevoked { .. } => 1008,
            Self::MessageTooLarge { .. } => 1009,
            Self::HandshakeRejected(_) | Self::HandshakeTimeout | Self::Transport(_) => 1011,
            Self::SlowConsumer { .. } | Self::Unresponsive => 1013,
        }
    }

    /// Returns the short close reason sent alongside the close code.
    #[must_use]
    pub const fn close_reason(&self) -> &str {
        match self {
            Self::PeerClosed => "peer closed",
            Self::ServerShutdown => "server shutdown",
            Self::HandshakeRejected(_) => "handshake rejected",
            Self::HandshakeTimeout => "handshake timeout",
            Self::MessageTooLarge { .. } => "message too large",
            Self::ProtocolViolation(_) => "protocol violation",
            Self::SlowConsumer { .. } => "event backlog exceeded",
            Self::Unresponsive => "peer unresponsive",
            Self::AuthorizationRevoked { .. } => "authorization revoked",
            Self::Transport(_) => "transport failure",
        }
    }
}

impl Display for ConnectionClose {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        match self {
            Self::PeerClosed => formatter.write_str("peer completed the close handshake"),
            Self::ServerShutdown => formatter.write_str("server is shutting down"),
            Self::HandshakeRejected(message) => write!(formatter, "handshake rejected: {message}"),
            Self::HandshakeTimeout => formatter.write_str("handshake exceeded its window"),
            Self::MessageTooLarge { limit } => {
                write!(formatter, "inbound message exceeded {limit} bytes")
            }
            Self::ProtocolViolation(detail) => write!(formatter, "protocol violation: {detail}"),
            Self::SlowConsumer { dropped } => {
                write!(formatter, "dropped {dropped} events for a slow consumer")
            }
            Self::Unresponsive => formatter.write_str("peer stopped answering pings"),
            Self::AuthorizationRevoked { device_id } => write!(
                formatter,
                "authorization for device `{device_id}` no longer admits this connection"
            ),
            Self::Transport(error) => Display::fmt(error, formatter),
        }
    }
}

impl Error for ConnectionClose {}

/// A failure raised while starting or running the accept loop.
#[derive(Debug)]
pub enum ServerError {
    /// Binding the TCP listener failed.
    Bind(io::Error),
    /// Reading the bound local address failed.
    LocalAddress(io::Error),
    /// The accept loop failed irrecoverably.
    Accept(io::Error),
    /// The supplied configuration is not internally consistent.
    Configuration(ConfigurationError),
    /// Installing a handler on the frozen method catalog failed.
    Registry(DispatchError),
    /// A non-loopback address was requested while the server is configured to
    /// serve plaintext WebSocket on loopback only.
    NonLoopbackBindRefused {
        /// The routable address that was refused.
        address: SocketAddr,
    },
}

impl Display for ServerError {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        match self {
            Self::Bind(error) => write!(formatter, "failed to bind Gateway listener: {error}"),
            Self::LocalAddress(error) => {
                write!(
                    formatter,
                    "failed to read Gateway listener address: {error}"
                )
            }
            Self::Accept(error) => write!(formatter, "Gateway accept loop failed: {error}"),
            Self::Configuration(error) => Display::fmt(error, formatter),
            Self::Registry(error) => {
                write!(formatter, "failed to install method handlers: {error}")
            }
            Self::NonLoopbackBindRefused { address } => write!(
                formatter,
                "refusing to bind `{address}`: this Gateway serves plaintext WebSocket, so a \
                 routable address would expose authenticated sessions to on-path injection; bind \
                 a loopback address, or set `Exposure::TlsTerminatedByFrontend` once a TLS \
                 terminator is in front of it"
            ),
        }
    }
}

impl Error for ServerError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Bind(error) | Self::LocalAddress(error) | Self::Accept(error) => Some(error),
            Self::Configuration(error) => Some(error),
            Self::Registry(error) => Some(error),
            Self::NonLoopbackBindRefused { .. } => None,
        }
    }
}

impl From<DispatchError> for ServerError {
    fn from(error: DispatchError) -> Self {
        Self::Registry(error)
    }
}

/// An invalid server configuration rejected before the listener is bound.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ConfigurationError {
    /// A queue, connection, or byte bound was zero.
    ZeroLimit(&'static str),
    /// A byte bound exceeded the proven authenticated transport cap.
    LimitAboveTransportCap(&'static str),
    /// A timeout was zero.
    ZeroTimeout(&'static str),
    /// The advertised server version was empty or oversized.
    InvalidServerVersion,
}

impl Display for ConfigurationError {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        match self {
            Self::ZeroLimit(name) => write!(formatter, "server limit `{name}` must be positive"),
            Self::LimitAboveTransportCap(name) => write!(
                formatter,
                "server limit `{name}` exceeds the authenticated transport cap"
            ),
            Self::ZeroTimeout(name) => {
                write!(formatter, "server timeout `{name}` must be positive")
            }
            Self::InvalidServerVersion => {
                formatter.write_str("advertised server version must be a non-empty bounded name")
            }
        }
    }
}

impl Error for ConfigurationError {}

impl From<ConfigurationError> for ServerError {
    fn from(error: ConfigurationError) -> Self {
        Self::Configuration(error)
    }
}

/// A dispatch-time failure that is rendered as a Gateway `res` error payload.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum DispatchError {
    /// The method identity is absent from the frozen catalog.
    UnknownMethod(String),
    /// The method is catalogued but this server ships no behavior for it.
    NotImplemented {
        /// Exact catalogued method identity.
        method: String,
        /// Frozen authorization classification rendered as its wire identity.
        scope: &'static str,
    },
    /// Role or scope authorization denied the call.
    Unauthorized(AuthorizationError),
    /// The request parameters failed strict validation.
    InvalidParams {
        /// Exact method identity.
        method: String,
        /// Machine-stable validation detail.
        detail: String,
    },
    /// A referenced resource does not exist.
    NotFound {
        /// Resource kind.
        kind: &'static str,
        /// Resource identity.
        id: String,
    },
    /// A bounded server resource was exhausted.
    ResourceExhausted {
        /// Exhausted resource name.
        resource: &'static str,
        /// Configured bound.
        limit: usize,
    },
    /// The persistence port failed.
    Store(StoreError),
    /// The connection attempted to re-run the handshake.
    HandshakeAlreadyComplete,
}

impl DispatchError {
    /// Returns the Gateway wire error code for this failure.
    #[must_use]
    pub const fn wire_code(&self) -> &'static str {
        match self {
            Self::UnknownMethod(_) => "METHOD_NOT_FOUND",
            Self::NotImplemented { .. } => "NOT_IMPLEMENTED",
            Self::Unauthorized(_) => "UNAUTHORIZED",
            Self::InvalidParams { .. }
            | Self::HandshakeAlreadyComplete
            | Self::Store(StoreError::Conflict { .. }) => "INVALID_REQUEST",
            Self::NotFound { .. } => "NOT_FOUND",
            Self::ResourceExhausted { .. }
            | Self::Store(StoreError::CapacityExceeded { .. } | StoreError::Backend(_)) => {
                "UNAVAILABLE"
            }
        }
    }

    /// Reports whether a client may retry the identical request later.
    ///
    /// A duplicate primary key is caller-supplied and never becomes valid on a
    /// retry, so it is deliberately excluded.
    #[must_use]
    pub const fn retryable(&self) -> bool {
        matches!(
            self,
            Self::ResourceExhausted { .. }
                | Self::Store(StoreError::CapacityExceeded { .. } | StoreError::Backend(_))
        )
    }
}

impl Display for DispatchError {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        match self {
            Self::UnknownMethod(method) => write!(formatter, "unknown gateway method `{method}`"),
            Self::NotImplemented { method, scope } => write!(
                formatter,
                "gateway method `{method}` ({scope}) is catalogued but not implemented by this server"
            ),
            Self::Unauthorized(error) => Display::fmt(error, formatter),
            Self::InvalidParams { method, detail } => {
                write!(formatter, "invalid params for `{method}`: {detail}")
            }
            Self::NotFound { kind, id } => write!(formatter, "{kind} `{id}` does not exist"),
            Self::ResourceExhausted { resource, limit } => {
                write!(formatter, "{resource} limit of {limit} is exhausted")
            }
            Self::Store(error) => Display::fmt(error, formatter),
            Self::HandshakeAlreadyComplete => {
                formatter.write_str("`connect` is only valid once, before the hello response")
            }
        }
    }
}

impl Error for DispatchError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Unauthorized(error) => Some(error),
            Self::Store(error) => Some(error),
            _ => None,
        }
    }
}

impl From<AuthorizationError> for DispatchError {
    fn from(error: AuthorizationError) -> Self {
        Self::Unauthorized(error)
    }
}

impl From<StoreError> for DispatchError {
    fn from(error: StoreError) -> Self {
        Self::Store(error)
    }
}

/// A persistence-port failure surfaced by an adapter.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum StoreError {
    /// The adapter refused a write because a bounded capacity is full.
    CapacityExceeded {
        /// Bounded collection name.
        collection: &'static str,
        /// Configured bound.
        limit: usize,
    },
    /// The adapter rejected a duplicate primary key.
    Conflict {
        /// Conflicting identity.
        id: String,
    },
    /// The adapter reported an implementation-defined backend failure.
    Backend(String),
}

impl Display for StoreError {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        match self {
            Self::CapacityExceeded { collection, limit } => write!(
                formatter,
                "persistence collection `{collection}` is limited to {limit} records"
            ),
            Self::Conflict { id } => write!(formatter, "persistence conflict on `{id}`"),
            Self::Backend(detail) => write!(formatter, "persistence backend failure: {detail}"),
        }
    }
}

impl Error for StoreError {}

/// A failure raised while building a protocol frame from server data.
#[derive(Clone, Debug)]
pub enum EncodeError {
    /// A bounded protocol string could not be constructed.
    String(StringValidationError),
    /// Serializing a handler payload to JSON failed.
    Json(String),
    /// The strict codec refused the constructed frame.
    Codec(String),
}

impl Display for EncodeError {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        match self {
            Self::String(error) => Display::fmt(error, formatter),
            Self::Json(detail) => write!(formatter, "payload serialization failed: {detail}"),
            Self::Codec(detail) => write!(formatter, "frame encoding failed: {detail}"),
        }
    }
}

impl Error for EncodeError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::String(error) => Some(error),
            _ => None,
        }
    }
}

impl From<StringValidationError> for EncodeError {
    fn from(error: StringValidationError) -> Self {
        Self::String(error)
    }
}

impl From<serde_json::Error> for EncodeError {
    fn from(error: serde_json::Error) -> Self {
        Self::Json(error.to_string())
    }
}

impl From<CodecError> for EncodeError {
    fn from(error: CodecError) -> Self {
        Self::Codec(error.to_string())
    }
}

impl From<NegotiationError> for EncodeError {
    fn from(error: NegotiationError) -> Self {
        Self::Codec(error.to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Every close classification this server can produce.
    fn all_closes() -> Vec<ConnectionClose> {
        vec![
            ConnectionClose::PeerClosed,
            ConnectionClose::ServerShutdown,
            ConnectionClose::HandshakeRejected("nope".to_owned()),
            ConnectionClose::HandshakeTimeout,
            ConnectionClose::MessageTooLarge { limit: 64 },
            ConnectionClose::ProtocolViolation("bad frame".to_owned()),
            ConnectionClose::SlowConsumer { dropped: 3 },
            ConnectionClose::Unresponsive,
            ConnectionClose::AuthorizationRevoked {
                device_id: "device-a".to_owned(),
            },
            ConnectionClose::Transport(WireError::Read),
        ]
    }

    #[test]
    fn a_revoked_authorization_closes_with_the_policy_violation_code() {
        let close = ConnectionClose::AuthorizationRevoked {
            device_id: "device-a".to_owned(),
        };
        assert_eq!(close.close_code(), 1008);
        assert_eq!(close.close_reason(), "authorization revoked");
        assert_eq!(
            close.to_string(),
            "authorization for device `device-a` no longer admits this connection"
        );
    }

    #[test]
    fn revocation_does_not_reuse_another_classifications_close_code() {
        let revoked = ConnectionClose::AuthorizationRevoked {
            device_id: "device-a".to_owned(),
        };
        for other in all_closes() {
            if other == revoked {
                continue;
            }
            assert_ne!(
                other.close_code(),
                revoked.close_code(),
                "`{other}` shares a close code with a revoked authorization"
            );
            assert_ne!(
                other.close_reason(),
                revoked.close_reason(),
                "`{other}` shares a close reason with a revoked authorization"
            );
        }
    }

    #[test]
    fn every_close_reason_stays_inside_the_rfc6455_control_frame_budget() {
        for close in all_closes() {
            let reason = close.close_reason();
            assert!(
                reason.len() <= 123,
                "`{reason}` does not fit in a close control frame"
            );
            assert!(!reason.is_empty());
        }
    }

    #[test]
    fn a_refused_routable_bind_names_the_address_and_the_way_out() {
        let address: SocketAddr = "0.0.0.0:8080".parse().expect("the fixture address parses");
        let error = ServerError::NonLoopbackBindRefused { address };
        let rendered = error.to_string();
        assert!(
            rendered.contains("0.0.0.0:8080"),
            "the refusal must name the address that was refused: {rendered}"
        );
        assert!(
            rendered.contains("Exposure::TlsTerminatedByFrontend"),
            "the refusal must name the explicit opt-in: {rendered}"
        );
        assert!(
            Error::source(&error).is_none(),
            "the refusal is this server's own decision, not a wrapped OS failure"
        );
    }
}

use std::collections::{BTreeMap, BTreeSet};
use std::error::Error;
use std::fmt::{self, Debug, Display, Formatter};

use subtle::ConstantTimeEq;

/// Exact Chrome extension identity admitted by a relay endpoint.
#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct ExtensionId(String);

impl ExtensionId {
    /// Parses a canonical 32-character Chrome extension ID.
    pub fn new(value: impl Into<String>) -> Result<Self, EndpointError> {
        let value = value.into();
        if value.len() == 32 && value.bytes().all(|byte| (b'a'..=b'p').contains(&byte)) {
            Ok(Self(value))
        } else {
            Err(EndpointError::InvalidExtensionId)
        }
    }

    /// Returns the exact extension identity.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// Fixed-size host-local relay authentication token.
#[derive(Clone)]
pub struct RelayToken([u8; 32]);

impl RelayToken {
    /// Decodes the exact 64-lowercase-hex token format used by upstream pairing.
    pub fn from_hex(value: &str) -> Result<Self, EndpointError> {
        if value.len() != 64 {
            return Err(EndpointError::InvalidToken);
        }
        let mut bytes = [0_u8; 32];
        for (index, pair) in value.as_bytes().chunks_exact(2).enumerate() {
            let high = decode_hex(pair[0]).ok_or(EndpointError::InvalidToken)?;
            let low = decode_hex(pair[1]).ok_or(EndpointError::InvalidToken)?;
            bytes[index] = (high << 4) | low;
        }
        Ok(Self(bytes))
    }

    fn matches_hex(&self, candidate: &str) -> bool {
        let Ok(candidate) = Self::from_hex(candidate) else {
            return false;
        };
        bool::from(self.0.ct_eq(&candidate.0))
    }
}

impl Debug for RelayToken {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter.write_str("RelayToken([REDACTED])")
    }
}

fn decode_hex(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        _ => None,
    }
}

/// Relay peer selected by the WebSocket path.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PeerKind {
    /// Paired Chrome extension at `/extension`.
    Extension,
    /// Local CDP automation client at `/cdp`.
    Cdp,
}

/// Complete security metadata from one WebSocket upgrade.
#[derive(Clone, Eq, PartialEq)]
pub struct UpgradeRequest {
    /// Requested path, without a query string.
    pub path: String,
    /// HTTP Host header.
    pub host: String,
    /// Origin header, when supplied.
    pub origin: Option<String>,
    /// Ordered WebSocket subprotocol list.
    pub subprotocols: Vec<String>,
    /// Bearer or Basic-password token already extracted by the HTTP adapter.
    pub authorization_token: Option<String>,
}

impl Debug for UpgradeRequest {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("UpgradeRequest")
            .field("path", &self.path)
            .field("host", &self.host)
            .field("origin", &self.origin)
            .field("subprotocols", &"[REDACTED]")
            .field("authorization_token", &"[REDACTED]")
            .finish()
    }
}

/// Authenticated relay connection identity.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct ConnectionId(u64);

impl ConnectionId {
    /// Returns the process-local connection ordinal.
    #[must_use]
    pub const fn get(self) -> u64 {
        self.0
    }
}

/// Deny-by-default WebSocket upgrade endpoint.
#[derive(Debug)]
pub struct RelayEndpoint {
    token: RelayToken,
    allowed_extensions: BTreeSet<ExtensionId>,
    max_frame_bytes: usize,
    max_connections: usize,
    next_connection: u64,
    connections: BTreeMap<ConnectionId, PeerKind>,
}

impl RelayEndpoint {
    /// Creates an endpoint with explicit extension allowlist and resource bounds.
    pub fn new(
        token: RelayToken,
        allowed_extensions: impl IntoIterator<Item = ExtensionId>,
        max_frame_bytes: usize,
        max_connections: usize,
    ) -> Result<Self, EndpointError> {
        let allowed_extensions = allowed_extensions.into_iter().collect::<BTreeSet<_>>();
        if allowed_extensions.is_empty() {
            return Err(EndpointError::EmptyExtensionAllowlist);
        }
        if max_frame_bytes == 0 || max_connections == 0 {
            return Err(EndpointError::InvalidBound);
        }
        Ok(Self {
            token,
            allowed_extensions,
            max_frame_bytes,
            max_connections,
            next_connection: 1,
            connections: BTreeMap::new(),
        })
    }

    /// Authenticates and admits one upgrade.
    pub fn accept(&mut self, request: &UpgradeRequest) -> Result<ConnectionId, EndpointError> {
        if !is_loopback_host_header(&request.host) {
            return Err(EndpointError::NonLoopbackHost);
        }
        if self.connections.len() == self.max_connections {
            return Err(EndpointError::ConnectionLimit);
        }
        let peer = match request.path.as_str() {
            "/extension" => {
                self.authorize_extension(request)?;
                PeerKind::Extension
            }
            "/cdp" => {
                self.authorize_cdp(request)?;
                PeerKind::Cdp
            }
            _ => return Err(EndpointError::UnknownPath),
        };
        let id = ConnectionId(self.next_connection);
        self.next_connection = self
            .next_connection
            .checked_add(1)
            .ok_or(EndpointError::ConnectionIdExhausted)?;
        self.connections.insert(id, peer);
        Ok(id)
    }

    /// Returns the authenticated peer kind for an active connection.
    #[must_use]
    pub fn peer(&self, id: ConnectionId) -> Option<PeerKind> {
        self.connections.get(&id).copied()
    }

    /// Removes one connection without affecting any other connection.
    pub fn close(&mut self, id: ConnectionId) -> Result<(), EndpointError> {
        self.connections
            .remove(&id)
            .map(|_| ())
            .ok_or(EndpointError::UnknownConnection)
    }

    /// Returns the configured complete-frame byte limit.
    #[must_use]
    pub const fn max_frame_bytes(&self) -> usize {
        self.max_frame_bytes
    }

    /// Returns the number of independently tracked active connections.
    #[must_use]
    pub fn connection_count(&self) -> usize {
        self.connections.len()
    }

    fn authorize_extension(&self, request: &UpgradeRequest) -> Result<(), EndpointError> {
        let origin = request
            .origin
            .as_deref()
            .ok_or(EndpointError::MissingExtensionOrigin)?;
        let extension_id = parse_extension_origin(origin)?;
        if !self.allowed_extensions.contains(&extension_id) {
            return Err(EndpointError::UnknownExtension);
        }
        if !request
            .subprotocols
            .iter()
            .any(|protocol| protocol == "openclaw-extension-relay")
        {
            return Err(EndpointError::MissingRelaySubprotocol);
        }
        let candidate = request
            .subprotocols
            .iter()
            .find_map(|protocol| protocol.strip_prefix("openclaw-extension-token."))
            .ok_or(EndpointError::AuthenticationFailed)?;
        if self.token.matches_hex(candidate) {
            Ok(())
        } else {
            Err(EndpointError::AuthenticationFailed)
        }
    }

    fn authorize_cdp(&self, request: &UpgradeRequest) -> Result<(), EndpointError> {
        if request.origin.is_some() {
            return Err(EndpointError::CdpOriginForbidden);
        }
        let candidate = request
            .authorization_token
            .as_deref()
            .ok_or(EndpointError::AuthenticationFailed)?;
        if self.token.matches_hex(candidate) {
            Ok(())
        } else {
            Err(EndpointError::AuthenticationFailed)
        }
    }
}

fn parse_extension_origin(origin: &str) -> Result<ExtensionId, EndpointError> {
    let id = origin
        .strip_prefix("chrome-extension://")
        .ok_or(EndpointError::ForgedOrigin)?;
    if id.contains(['/', '?', '#', ':']) {
        return Err(EndpointError::ForgedOrigin);
    }
    ExtensionId::new(id.to_owned()).map_err(|_| EndpointError::ForgedOrigin)
}

fn is_loopback_host_header(host: &str) -> bool {
    let host = host.trim();
    if host.eq_ignore_ascii_case("localhost") {
        return true;
    }
    if let Some(port) = host.strip_prefix("localhost:") {
        return valid_port(port);
    }
    if host == "127.0.0.1" || host == "[::1]" {
        return true;
    }
    if let Some(port) = host.strip_prefix("127.0.0.1:") {
        return valid_port(port);
    }
    if let Some(port) = host.strip_prefix("[::1]:") {
        return valid_port(port);
    }
    false
}

fn valid_port(value: &str) -> bool {
    value.parse::<u16>().is_ok_and(|port| port != 0)
}

/// Upgrade authentication or endpoint lifecycle failure.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum EndpointError {
    /// Extension ID was not canonical.
    InvalidExtensionId,
    /// Pairing token was not canonical lowercase hex.
    InvalidToken,
    /// At least one known extension ID is required.
    EmptyExtensionAllowlist,
    /// Resource bounds must be positive.
    InvalidBound,
    /// Host header was not loopback.
    NonLoopbackHost,
    /// Requested path is not a relay endpoint.
    UnknownPath,
    /// Extension Origin header is mandatory.
    MissingExtensionOrigin,
    /// Origin was not an exact Chrome extension origin.
    ForgedOrigin,
    /// Chrome extension ID is not allowlisted.
    UnknownExtension,
    /// Required relay protocol was absent.
    MissingRelaySubprotocol,
    /// Pairing token did not match.
    AuthenticationFailed,
    /// Browser origins may not connect to the CDP endpoint.
    CdpOriginForbidden,
    /// Endpoint connection bound was reached.
    ConnectionLimit,
    /// Process-local connection ordinal was exhausted.
    ConnectionIdExhausted,
    /// Connection is not active.
    UnknownConnection,
}

impl Display for EndpointError {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::InvalidExtensionId => "invalid Chrome extension ID",
            Self::InvalidToken => "invalid relay token",
            Self::EmptyExtensionAllowlist => "extension allowlist must not be empty",
            Self::InvalidBound => "relay bounds must be positive",
            Self::NonLoopbackHost => "relay Host header must be loopback",
            Self::UnknownPath => "unknown relay path",
            Self::MissingExtensionOrigin => "extension Origin header is required",
            Self::ForgedOrigin => "extension Origin header is invalid",
            Self::UnknownExtension => "Chrome extension ID is not allowed",
            Self::MissingRelaySubprotocol => "relay WebSocket subprotocol is required",
            Self::AuthenticationFailed => "relay authentication failed",
            Self::CdpOriginForbidden => "browser origins cannot connect to CDP",
            Self::ConnectionLimit => "relay connection limit reached",
            Self::ConnectionIdExhausted => "relay connection ID exhausted",
            Self::UnknownConnection => "relay connection is not active",
        })
    }
}

impl Error for EndpointError {}

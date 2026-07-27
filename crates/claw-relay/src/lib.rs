//! Authenticated Chrome extension relay and policy-bounded CDP bridge.
//!
//! The crate is transport independent: an HTTP/WebSocket acceptor supplies
//! upgrade metadata and complete text frames, while this crate owns
//! authentication, strict framing, connection isolation, CDP policy, routing,
//! and lifecycle. It never exposes filesystem or process capabilities.

mod bridge;
mod discovery;
mod endpoint;
mod pairing;
mod protocol;

pub use bridge::{
    BridgeEffect, BridgeError, BrowserIdentity, CdpBridge, CdpError, CdpErrorObject, CdpEvent,
    CdpResponse, ExtensionCommand, TargetInfo,
};
pub use discovery::{
    DiscoveryRequest, DiscoveryResponse, NOT_PAIRED_MESSAGE, VersionInfo, serve_discovery,
};
pub use endpoint::{
    AcceptedUpgrade, ConnectionId, EndpointError, ExtensionId, PeerKind, RelayEndpoint, RelayToken,
    UpgradeRequest, credential_from_authorization,
};
pub use pairing::{
    EXTENSION_PATH, ExtensionPairing, MINIMUM_CHROME_VERSION, Mv3Manifest, PairingError,
    PairingOffer, RELAY_SUBPROTOCOL, RELAY_TOKEN_SUBPROTOCOL_PREFIX,
};
pub use protocol::{
    CdpRequest, ExtensionMessage, FrameError, RelayTab, decode_cdp_frame, decode_extension_frame,
};

/// Upstream-compatible relay frame limit.
pub const MAX_FRAME_BYTES: usize = 64 * 1024 * 1024;

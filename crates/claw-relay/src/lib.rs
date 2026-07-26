//! Authenticated Chrome extension relay and policy-bounded CDP bridge.
//!
//! The crate is transport independent: an HTTP/WebSocket acceptor supplies
//! upgrade metadata and complete text frames, while this crate owns
//! authentication, strict framing, connection isolation, CDP policy, routing,
//! and lifecycle. It never exposes filesystem or process capabilities.

mod bridge;
mod endpoint;
mod protocol;

pub use bridge::{
    BridgeEffect, BridgeError, CdpBridge, CdpError, CdpErrorObject, CdpEvent, CdpResponse,
    ExtensionCommand, TargetInfo,
};
pub use endpoint::{
    EndpointError, ExtensionId, PeerKind, RelayEndpoint, RelayToken, UpgradeRequest,
};
pub use protocol::{
    CdpRequest, ExtensionMessage, FrameError, RelayTab, decode_cdp_frame, decode_extension_frame,
};

/// Upstream-compatible relay frame limit.
pub const MAX_FRAME_BYTES: usize = 64 * 1024 * 1024;

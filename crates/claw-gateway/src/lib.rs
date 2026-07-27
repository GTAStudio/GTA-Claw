//! Gateway v4 WebSocket server.
//!
//! This crate is the server counterpart to [`claw_protocol::gateway`] (the
//! transport-independent wire contract and pure reducers) and
//! `claw-gateway-client` (the Rust client). It owns everything the wire
//! contract deliberately leaves out:
//!
//! * a real WebSocket transport with an HTTP upgrade, phase-aware frame size
//!   limits, ping/pong liveness, and graceful close,
//! * connection lifecycle driving [`claw_protocol::gateway::Negotiation`],
//!   including the authenticated node/probe protocol v3 N-1 window,
//! * a dispatch registry covering every frozen core method,
//! * an event bus with per-connection monotonic sequence numbers, bounded
//!   fan-out, gap detection, and scope-filtered subscriptions,
//! * role/scope authorization enforced on both method calls and event delivery.
//!
//! # Scope of the frozen contract
//!
//! `compat/upstream/inventories/gateway-protocol.json` freezes method and event
//! *identities*, their authorization classification, and whether they are
//! advertised. It does **not** freeze request or response payload schemas.
//! Consequently the payload shapes used by the handlers in [`methods`] are this
//! crate's own design, documented per handler, and are not claimed to be
//! byte-compatible with upstream payloads. Every catalogued method that this
//! crate does not really implement is still registered and answers with a
//! typed [`error::DispatchError::NotImplemented`] rather than being absent.
//!
//! # Persistence
//!
//! [`store::GatewayStore`] is a narrow persistence port owned by this crate.
//! [`store::InMemoryGatewayStore`] is the shipped adapter. Durable adapters live
//! outside this crate; what one has to cope with that the in-memory adapter
//! never exercises is written down on [`store`] itself, and
//! `tests/store_port.rs` holds a second, deliberately hostile in-crate adapter
//! that fails after committing, answers from stale snapshots, and loses
//! everything between calls.

pub mod auth;
pub mod authority;
pub mod clock;
pub mod config;
pub mod connection;
pub mod directory;
pub mod dispatch;
pub mod error;
pub mod events;
pub mod methods;
pub mod server;
pub mod store;
pub mod transport;

pub use auth::{CredentialPolicy, Grant, StaticAuthenticator, issue_challenge};
pub use authority::{AuthorizationSource, DeviceDirectory};
pub use clock::{Clock, ManualClock, SystemClock};
pub use config::{Exposure, GatewayServerConfig, ServerLimits, ServerTimeouts, ValidatedConfig};
pub use connection::ConnectionServices;
pub use directory::{ConnectionDirectory, ConnectionInfo, compatibility_identity};
pub use dispatch::{
    DynamicScopeResolver, MethodContext, MethodHandler, MethodRegistry, StaticDynamicScopes,
    scope_identity,
};
pub use error::{
    ConfigurationError, ConnectionClose, DispatchError, EncodeError, HandshakeError, ServerError,
    StoreError, WireError,
};
pub use events::{
    ConnectionId, Delivery, EventAudience, EventBus, EventDraft, EventEnvelope, EventError,
    EventSubscription, EventVisibility, TopicFilter, TopicGroup, event_catalog, event_visibility,
};
pub use server::{BoundServer, GatewayServer, ServerHandle};
pub use store::{
    GatewayStore, HeartbeatRecord, InMemoryGatewayStore, PendingInvocation, SessionDraft,
    SessionPatch, SessionRecord,
};

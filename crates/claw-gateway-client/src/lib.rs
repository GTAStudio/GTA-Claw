//! Bounded pure-Rust OpenClaw Gateway WebSocket/WSS client.
//!
//! This crate implements transport and lifecycle only. It deliberately provides
//! no Gateway server, RPC handlers, provider session, or GUI integration.

mod client;
mod config;
mod error;
mod runtime;
mod transport;

pub use client::{GatewayClient, GatewayEventStream};
pub use config::{
    ClientLimits, ClientMetadata, ClientTimeouts, ConfigurationError, GatewayClientConfig,
    GatewayCredential, ReconnectPolicy,
};
pub use error::{
    AuthenticationFailure, BackpressureError, ConnectionInfo, ConnectionState, FailureClass,
    GatewayClientError, GatewayEvent, IssuedDeviceToken, ProtocolFailure, ResyncRequired,
    TransportFailure,
};
pub use runtime::{ClientRuntime, SystemRuntime};

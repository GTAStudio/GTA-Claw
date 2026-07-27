//! Gateway HTTP probe surface and watch-node transport.
//!
//! This crate implements two frozen upstream surfaces as one reusable,
//! dependency-light component that a Gateway composition root can mount:
//!
//! - `gateway.http.probes` — `/health`, `/healthz`, `/ready` and `/readyz`,
//!   whose whole point is that they disagree while the process drains. See
//!   [`probes`].
//! - `gateway.http.watch-node` — the five-route long-poll transport a watch
//!   node uses in place of a duplex connection. See [`watch`].
//!
//! Both surfaces are plain [`axum::Router`] values over cloneable, `Send +
//! Sync` state, so they can be merged into a larger router, served on their own
//! listener, or driven directly as a `tower` service without a socket.
//!
//! ```no_run
//! use std::sync::Arc;
//!
//! use claw_gateway_http::{
//!     GatewayLifecycle, InMemoryResultSink, ProbeSurface, ReadinessFlag, WatchLimits,
//!     WatchNodeRegistry, WatchNodeTransport, gateway_http_router,
//! };
//!
//! let lifecycle = GatewayLifecycle::serving();
//! let store = ReadinessFlag::new("store", true);
//! let probes = ProbeSurface::new(lifecycle.clone()).with_check(store);
//!
//! let registry = WatchNodeRegistry::new();
//! registry.register("watch-1", b"shared-secret".to_vec());
//! let transport =
//!     WatchNodeTransport::new(WatchLimits::default(), registry, InMemoryResultSink::new());
//!
//! let router = gateway_http_router(probes, transport.clone());
//!
//! // Graceful shutdown: readiness turns 503 immediately, liveness stays 200
//! // until the drain finishes.
//! lifecycle.begin_draining();
//! ```

mod http_util;
mod lifecycle;
mod probes;
mod watch;

use std::io;

use axum::Router;
use tokio::net::TcpListener;

pub use crate::lifecycle::{GatewayLifecycle, ReadinessCheck, ReadinessFlag, ServingState};
pub use crate::probes::{
    LIVENESS_PATHS, ProbeSurface, READINESS_PATHS, READINESS_RETRY_AFTER_SECONDS, Readiness,
    probe_router,
};
pub use crate::watch::{
    EnqueueOutcome, InMemoryResultSink, WATCH_CHALLENGE_PATH, WATCH_CONNECT_PATH,
    WATCH_DISCONNECT_PATH, WATCH_NODE_ENDPOINTS, WATCH_POLL_PATH, WATCH_RESULT_PATH,
    WatchCommandResult, WatchLimits, WatchNodeRegistry, WatchNodeTransport, WatchResultSink,
    sign_challenge, watch_router,
};

/// Method and path of every route this crate registers, in inventory order.
pub const GATEWAY_HTTP_ENDPOINTS: [(&str, &str); 9] = [
    ("GET", LIVENESS_PATHS[0]),
    ("GET", LIVENESS_PATHS[1]),
    ("GET", READINESS_PATHS[0]),
    ("GET", READINESS_PATHS[1]),
    ("GET", WATCH_CHALLENGE_PATH),
    ("POST", WATCH_CONNECT_PATH),
    ("POST", WATCH_DISCONNECT_PATH),
    ("POST", WATCH_POLL_PATH),
    ("POST", WATCH_RESULT_PATH),
];

/// Builds the probe routes and the watch-node routes as one router.
pub fn gateway_http_router(probes: ProbeSurface, watch: WatchNodeTransport) -> Router {
    probe_router(probes).merge(watch_router(watch))
}

/// Serves a router on an already-bound listener.
///
/// # Errors
///
/// Returns the underlying [`io::Error`] when the listener fails.
pub async fn serve(router: Router, listener: TcpListener) -> io::Result<()> {
    axum::serve(listener, router).await
}

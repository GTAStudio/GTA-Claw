//! The Gateway ingress that owns a real listener.
//!
//! [`LoopbackGateway`] proved the composition's shape without opening a socket,
//! and said so honestly by reporting [`ServiceHandle::inert`]. This subsystem is
//! what that comment was waiting for: it owns a [`GatewayServer`] from
//! `claw-gateway`, binds a real `TcpListener`, and reports
//! [`ServiceHandle::listening`] with the address the operating system actually
//! gave it — which is not in general the address that was requested, because a
//! requested port of `0` becomes a real one only at bind time.
//!
//! # Two paths, deliberately
//!
//! The wire path and the in-process path are *not* the same catalogue, and this
//! type does not pretend otherwise.
//!
//! - The **wire path** serves the frozen Gateway v4 protocol: 278 catalogued
//!   methods, device pairing, roles and operator scopes, over WebSocket.
//! - The **in-process path** ([`GatewayIngress::handle`]) is the existing
//!   [`GatewayDispatch`] seam, which today resolves exactly two names,
//!   `session.prompt` and `session.describe`.
//!
//! Neither of those two names appears in the frozen protocol inventory, so
//! there is no method a wire client could call that would reach
//! `GatewayDispatch` today. Bridging them needs a protocol-level name mapping
//! decision, and inventing one silently here would be worse than leaving the
//! seam visible. Until that decision is made both paths are served by the one
//! Gateway subsystem, and both are quiesced, drained and stopped together.
//!
//! # Task accounting
//!
//! `claw-gateway` spawns its acceptor and its heartbeat ticker internally, so
//! they are *not* visible to the daemon's [`TaskLedger`](crate::runtime::TaskLedger).
//! That is a real gap in the ledger's coverage and is stated here rather than
//! hidden: a leak of those two tasks would not move the spawn/termination
//! counts. It is closed by construction instead —
//! [`ServerHandle::shutdown`] awaits both join handles and the acceptor drains
//! its per-connection `JoinSet` before returning — and the joint shutdown test
//! asserts the consequence directly, by proving the port stops accepting, rather
//! than by trusting the ledger as a proxy for it.

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use claw_application::composition::{
    BoxFuture, DrainReport, GatewayDispatch, GatewayPort, GatewayRequest, GatewayResponse,
    ServiceHandle, StartContext, Subsystem, SubsystemDescriptor, SubsystemError, well_known,
};
use claw_gateway::{BoundServer, GatewayServer, ServerHandle};
use tokio::sync::Mutex as AsyncMutex;

use crate::adapters::ingress::LoopbackGateway;

/// Where the owned server currently is in its one-way lifecycle.
///
/// `claw-gateway` moves the server through each step by value, which makes
/// starting twice or shutting down twice unrepresentable. [`Subsystem`] takes
/// `&self` for every step, so the move-based API is preserved here behind a
/// lock and a `mem::replace` rather than weakened at the source.
enum Stage {
    /// Constructed, no socket yet.
    Unbound(Box<GatewayServer>),
    /// Listener open, not accepting.
    Bound(Box<BoundServer>),
    /// Accepting.
    Running(ServerHandle),
    /// Terminal. Reached from any earlier stage, because `Subsystem::shutdown`
    /// runs even when start-up failed part-way.
    Stopped,
}

impl Stage {
    const fn label(&self) -> &'static str {
        match self {
            Self::Unbound(_) => "unbound",
            Self::Bound(_) => "bound",
            Self::Running(_) => "running",
            Self::Stopped => "stopped",
        }
    }
}

/// A Gateway v4 ingress backed by a real WebSocket server.
pub struct GatewayIngress {
    stage: AsyncMutex<Stage>,
    /// Read by [`GatewayPort::bound`], which is synchronous and therefore
    /// cannot take the async stage lock.
    bound: std::sync::Mutex<Vec<SocketAddr>>,
    method_count: usize,
    drain_grace: Duration,
    loopback: LoopbackGateway,
}

impl GatewayIngress {
    /// Wraps `server`, serving `dispatch` on the in-process path.
    ///
    /// `drain_grace` bounds how long [`Subsystem::drain`] waits for requests
    /// that were already being served when the ingress was quiesced.
    #[must_use]
    pub fn new(
        server: GatewayServer,
        dispatch: Arc<dyn GatewayDispatch>,
        drain_grace: Duration,
    ) -> Self {
        let method_count = server.registry().len();

        Self {
            stage: AsyncMutex::new(Stage::Unbound(Box::new(server))),
            bound: std::sync::Mutex::new(Vec::new()),
            method_count,
            drain_grace,
            loopback: LoopbackGateway::new(dispatch),
        }
    }

    /// Returns how many requests the in-process path served.
    #[must_use]
    pub fn served(&self) -> u64 {
        self.loopback.served()
    }

    /// Returns how many requests the in-process path refused because the
    /// ingress had stopped accepting.
    #[must_use]
    pub fn refused(&self) -> u64 {
        self.loopback.refused()
    }

    /// Returns how many wire requests the server answered.
    ///
    /// Zero before the server starts and after it stops, because the count
    /// lives in the server rather than in this wrapper.
    pub async fn wire_requests_completed(&self) -> u64 {
        match &*self.stage.lock().await {
            Stage::Running(handle) => handle.completed_requests(),
            Stage::Unbound(_) | Stage::Bound(_) | Stage::Stopped => 0,
        }
    }

    /// Returns how many peers are connected over the wire right now.
    pub async fn wire_connections(&self) -> usize {
        match &*self.stage.lock().await {
            Stage::Running(handle) => handle.connection_count(),
            Stage::Unbound(_) | Stage::Bound(_) | Stage::Stopped => 0,
        }
    }

    /// Handles one request on the in-process path.
    ///
    /// # Errors
    ///
    /// Returns a [`SubsystemError`] when the ingress is not accepting work, or
    /// whatever the dispatcher returned.
    pub async fn handle(&self, request: GatewayRequest) -> Result<GatewayResponse, SubsystemError> {
        self.loopback.handle(request).await
    }

    fn publish_bound(&self, addresses: Vec<SocketAddr>) {
        let mut slot = self
            .bound
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        *slot = addresses;
    }
}

impl Subsystem for GatewayIngress {
    fn descriptor(&self) -> SubsystemDescriptor {
        self.loopback.descriptor()
    }

    fn initialize<'a>(
        &'a self,
        context: &'a StartContext,
    ) -> BoxFuture<'a, Result<(), SubsystemError>> {
        Box::pin(async move {
            let address = *context.settings().listen().first().ok_or_else(|| {
                SubsystemError::internal(
                    well_known::gateway(),
                    "the gateway was given no address to listen on",
                )
            })?;

            let mut stage = self.stage.lock().await;
            let Stage::Unbound(server) = std::mem::replace(&mut *stage, Stage::Stopped) else {
                return Err(SubsystemError::internal(
                    well_known::gateway(),
                    "the gateway was initialized more than once",
                ));
            };

            let bound = server.bind(address).await.map_err(|error| {
                SubsystemError::internal(
                    well_known::gateway(),
                    format!("the gateway could not bind {address}: {error}"),
                )
            })?;

            // Bound, but not yet published: nothing is accepting on it until
            // `start` runs, and advertising it now would be the exact claim
            // `LoopbackGateway` refused to make.
            *stage = Stage::Bound(Box::new(bound));
            Ok(())
        })
    }

    fn start<'a>(
        &'a self,
        context: &'a StartContext,
    ) -> BoxFuture<'a, Result<ServiceHandle, SubsystemError>> {
        Box::pin(async move {
            let mut stage = self.stage.lock().await;
            let Stage::Bound(bound) = std::mem::replace(&mut *stage, Stage::Stopped) else {
                return Err(SubsystemError::internal(
                    well_known::gateway(),
                    format!("the gateway cannot start from the {} stage", stage.label()),
                ));
            };

            let handle = bound.start();
            let address = handle.local_address();
            *stage = Stage::Running(handle);
            drop(stage);

            self.publish_bound(vec![address]);
            self.loopback.start(context).await?;

            // The address comes from the listener, never from the request. A
            // requested port of zero is a different number by the time it gets
            // here, which is what makes this handle worth more than the
            // settings it was derived from.
            Ok(
                ServiceHandle::listening(well_known::gateway(), vec![address]).with_detail(
                    format!("{} protocol methods over websocket", self.method_count),
                ),
            )
        })
    }

    fn quiesce<'a>(&'a self) -> BoxFuture<'a, Result<(), SubsystemError>> {
        Box::pin(async move {
            self.loopback.quiesce().await?;

            if let Stage::Running(handle) = &*self.stage.lock().await {
                // Refuses new peers while every connection already established
                // keeps being served, which is what makes the following drain
                // finite instead of merely timed.
                handle.stop_accepting().await;
            }

            Ok(())
        })
    }

    fn drain<'a>(&'a self) -> BoxFuture<'a, Result<DrainReport, SubsystemError>> {
        Box::pin(async move {
            let in_process = self.loopback.drain().await?;

            let (wire_completed, wire_abandoned) = match &*self.stage.lock().await {
                Stage::Running(handle) => {
                    let abandoned = handle.drain_requests(self.drain_grace).await;
                    (handle.completed_requests(), abandoned)
                }
                Stage::Unbound(_) | Stage::Bound(_) | Stage::Stopped => (0, 0),
            };

            let completed = in_process
                .completed()
                .saturating_add(u32::try_from(wire_completed).unwrap_or(u32::MAX));
            let abandoned = in_process
                .abandoned()
                .saturating_add(u32::try_from(wire_abandoned).unwrap_or(u32::MAX));

            Ok(if abandoned == 0 {
                DrainReport::clean(well_known::gateway(), completed)
            } else {
                DrainReport::partial(well_known::gateway(), completed, abandoned)
            })
        })
    }

    fn shutdown<'a>(&'a self) -> BoxFuture<'a, Result<(), SubsystemError>> {
        Box::pin(async move {
            self.loopback.shutdown().await?;

            let stage = std::mem::replace(&mut *self.stage.lock().await, Stage::Stopped);
            if let Stage::Running(handle) = stage {
                // Awaits the acceptor and the ticker, and the acceptor closes
                // every live connection before it returns.
                handle.shutdown().await;
            }

            // Nothing is accepting any more, so nothing may still be
            // advertised. A stale address here would outlive the listener and
            // send a reconnecting client at a closed port forever.
            self.publish_bound(Vec::new());
            Ok(())
        })
    }
}

impl GatewayPort for GatewayIngress {
    fn registered_methods(&self) -> usize {
        self.method_count
    }

    fn bound(&self) -> Vec<SocketAddr> {
        self.bound
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .clone()
    }
}

impl std::fmt::Debug for GatewayIngress {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("GatewayIngress")
            .field("methods", &self.method_count)
            .field("bound", &self.bound())
            .field("served", &self.served())
            .field("refused", &self.refused())
            .finish_non_exhaustive()
    }
}

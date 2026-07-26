//! Accept loop, connection admission control, and graceful shutdown.
//!
//! The listener owns exactly three bounded resources: a hard cap on
//! simultaneously served connections (enforced with a semaphore *before* the
//! WebSocket upgrade is attempted, so a flood cannot allocate handshake
//! buffers), a monotonic connection-identity counter, and a single broadcast
//! `tick` publisher shared by every subscriber.

use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

use claw_protocol::gateway::{
    AuthenticationPort, Name, NonNegativeInteger, ShutdownEvent, TickEvent,
};
use tokio::net::TcpListener;
use tokio::sync::{Semaphore, watch};
use tokio::task::{JoinHandle, JoinSet};
use tokio::time::{Instant, MissedTickBehavior, interval_at, timeout};

use crate::authority::AuthorizationSource;
use crate::clock::{Clock, SystemClock};
use crate::config::{GatewayServerConfig, ValidatedConfig};
use crate::connection::{self, ConnectionServices};
use crate::directory::ConnectionDirectory;
use crate::dispatch::MethodRegistry;
use crate::error::ServerError;
use crate::events::{ConnectionId, EventBus, EventDraft};
use crate::meter::RequestMeter;
use crate::methods;
use crate::store::{GatewayStore, InMemoryGatewayStore};

/// Maximum UTF-8 byte length of the shutdown reason placed on the wire.
const MAX_SHUTDOWN_REASON_BYTES: usize = 128;
/// Reason announced by the broadcast `shutdown` event.
const SHUTDOWN_REASON: &str = "gateway is shutting down";

/// An unbound Gateway server and its collaborators.
pub struct GatewayServer {
    config: Arc<ValidatedConfig>,
    registry: Arc<MethodRegistry>,
    store: Arc<dyn GatewayStore>,
    events: EventBus,
    clock: Arc<dyn Clock>,
    directory: ConnectionDirectory,
    authenticator: Arc<dyn AuthenticationPort + Send + Sync>,
    authorization: Arc<dyn AuthorizationSource>,
    meter: RequestMeter,
}

impl std::fmt::Debug for GatewayServer {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("GatewayServer")
            .field("config", &self.config)
            .field("methods", &self.registry.len())
            .field("connections", &self.directory.len())
            .finish_non_exhaustive()
    }
}

impl GatewayServer {
    /// Creates a server with the in-memory persistence adapter and system clock.
    ///
    /// `authorization` is required, not optional: it is where the server asks
    /// whether a device is *still* allowed to act, which it must do before
    /// every request and every event delivery. Passing
    /// [`crate::auth::StaticAuthenticator::devices`] wires the handshake and
    /// the live re-checks to one source of truth.
    ///
    /// # Errors
    ///
    /// Returns [`ServerError::Configuration`] when a limit or timeout is
    /// outside its proven bound, or [`ServerError::Registry`] when a handler
    /// cannot be installed on the frozen catalog.
    pub fn new(
        config: GatewayServerConfig,
        authenticator: Arc<dyn AuthenticationPort + Send + Sync>,
        authorization: Arc<dyn AuthorizationSource>,
    ) -> Result<Self, ServerError> {
        let config = config.validate()?;
        let limits = *config.limits();
        let store = InMemoryGatewayStore::new(limits.max_sessions, limits.max_pending_per_node);
        Ok(Self {
            registry: Arc::new(methods::registry()?),
            store: Arc::new(store),
            events: EventBus::new(limits.event_queue_capacity, limits.event_queue_bytes),
            clock: Arc::new(SystemClock),
            directory: ConnectionDirectory::new(),
            config: Arc::new(config),
            authenticator,
            authorization,
            meter: RequestMeter::new(),
        })
    }

    /// Replaces the persistence adapter behind the narrow store port.
    #[must_use]
    pub fn with_store(mut self, store: Arc<dyn GatewayStore>) -> Self {
        self.store = store;
        self
    }

    /// Replaces the wall-clock port.
    #[must_use]
    pub fn with_clock(mut self, clock: Arc<dyn Clock>) -> Self {
        self.clock = clock;
        self
    }

    /// Returns the event bus so embedders can publish catalogued events.
    #[must_use]
    pub const fn events(&self) -> &EventBus {
        &self.events
    }

    /// Returns the live authenticated connection directory.
    #[must_use]
    pub const fn directory(&self) -> &ConnectionDirectory {
        &self.directory
    }

    /// Returns the installed method registry.
    #[must_use]
    pub fn registry(&self) -> &MethodRegistry {
        &self.registry
    }

    fn services(&self) -> ConnectionServices {
        ConnectionServices {
            config: Arc::clone(&self.config),
            registry: Arc::clone(&self.registry),
            store: Arc::clone(&self.store),
            events: self.events.clone(),
            clock: Arc::clone(&self.clock),
            directory: self.directory.clone(),
            authenticator: Arc::clone(&self.authenticator),
            authorization: Arc::clone(&self.authorization),
            meter: self.meter.clone(),
        }
    }

    /// Binds the listener without accepting yet, so tests can learn the port.
    ///
    /// # Errors
    ///
    /// Returns [`ServerError::NonLoopbackBindRefused`] when `address` is not a
    /// loopback address and the configured [`crate::config::Exposure`] does not
    /// permit routable binds, or [`ServerError::Bind`] /
    /// [`ServerError::LocalAddress`] when the operating system refuses the
    /// socket.
    pub async fn bind(self, address: SocketAddr) -> Result<BoundServer, ServerError> {
        if !self.config.exposure().admits(&address) {
            return Err(ServerError::NonLoopbackBindRefused { address });
        }
        let listener = TcpListener::bind(address)
            .await
            .map_err(ServerError::Bind)?;
        let local_address = listener.local_addr().map_err(ServerError::LocalAddress)?;
        Ok(BoundServer {
            listener,
            local_address,
            server: self,
        })
    }
}

/// A listener that is bound but not yet accepting.
#[derive(Debug)]
pub struct BoundServer {
    listener: TcpListener,
    local_address: SocketAddr,
    server: GatewayServer,
}

impl BoundServer {
    /// Returns the address the listener actually bound to.
    #[must_use]
    pub const fn local_address(&self) -> SocketAddr {
        self.local_address
    }

    /// Returns the event bus of the server about to start.
    #[must_use]
    pub const fn events(&self) -> &EventBus {
        self.server.events()
    }

    /// Returns the connection directory of the server about to start.
    #[must_use]
    pub const fn directory(&self) -> &ConnectionDirectory {
        self.server.directory()
    }

    /// Starts the accept loop and the broadcast tick publisher.
    #[must_use]
    pub fn start(self) -> ServerHandle {
        let Self {
            listener,
            local_address,
            server,
        } = self;
        let limits = *server.config.limits();
        let timeouts = *server.config.timeouts();
        let services = server.services();
        let events = server.events.clone();
        let directory = server.directory.clone();
        let permits = Arc::new(Semaphore::new(limits.max_connections));
        let meter = server.meter.clone();
        let (shutdown, shutdown_rx) = watch::channel(false);
        // Quiescing and shutting down are different events and must not share a
        // signal. Quiescing releases the listener while every established
        // connection keeps serving; shutting down closes those connections. A
        // composition root stops its ingress before it drains the subsystems
        // behind it, so the server has to be able to do the first without the
        // second.
        let (quiesce, quiesce_rx) = watch::channel(false);
        // Reported *by* the accept loop once the listener is released, so that
        // `stop_accepting` can be awaited to a definite state instead of
        // returning while the socket is still accepting.
        let (accepting_tx, accepting) = watch::channel(true);

        let tick_clock = Arc::clone(&server.clock);
        let tick_events = events.clone();
        let mut tick_shutdown = shutdown_rx.clone();
        let ticker = tokio::spawn(async move {
            let mut timer = interval_at(
                Instant::now() + timeouts.tick_interval,
                timeouts.tick_interval,
            );
            timer.set_missed_tick_behavior(MissedTickBehavior::Delay);
            loop {
                tokio::select! {
                    biased;
                    changed = tick_shutdown.changed() => {
                        if changed.is_err() || *tick_shutdown.borrow() {
                            return;
                        }
                    }
                    _ = timer.tick() => {
                        let payload = TickEvent {
                            ts: NonNegativeInteger::new(tick_clock.unix_millis()),
                        };
                        if let Ok(draft) = EventDraft::broadcast("tick", &payload) {
                            tick_events.publish(draft);
                        }
                    }
                }
            }
        });

        let accept_permits = Arc::clone(&permits);
        let accept_shutdown = shutdown_rx.clone();
        let acceptor = tokio::spawn(accept_loop(
            listener,
            services,
            accept_permits,
            quiesce_rx,
            accept_shutdown,
            accepting_tx,
            timeouts.close,
        ));

        ServerHandle {
            local_address,
            shutdown,
            quiesce,
            accepting,
            events,
            directory,
            permits,
            meter,
            max_connections: limits.max_connections,
            acceptor,
            ticker,
        }
    }
}

async fn accept_loop(
    listener: TcpListener,
    services: ConnectionServices,
    permits: Arc<Semaphore>,
    mut quiesce: watch::Receiver<bool>,
    mut shutdown: watch::Receiver<bool>,
    accepting: watch::Sender<bool>,
    grace: std::time::Duration,
) {
    let next_id = AtomicU64::new(1);
    let mut connections = JoinSet::new();
    // Distinguishes the two ways of leaving the accept phase: a shutdown goes
    // straight to the bounded drain, a quiesce keeps serving first.
    let shutting_down = loop {
        tokio::select! {
            biased;
            changed = shutdown.changed() => {
                if changed.is_err() || *shutdown.borrow() {
                    break true;
                }
            }
            changed = quiesce.changed() => {
                if changed.is_err() || *quiesce.borrow() {
                    break false;
                }
            }
            Some(_) = connections.join_next(), if !connections.is_empty() => {}
            accepted = listener.accept() => {
                let Ok((stream, _peer)) = accepted else {
                    // A per-connection accept failure must not kill the listener.
                    continue;
                };
                let Ok(permit) = Arc::clone(&permits).try_acquire_owned() else {
                    // At the cap: drop the socket immediately, before any
                    // handshake buffer is allocated for it.
                    drop(stream);
                    continue;
                };
                let id = ConnectionId::new(next_id.fetch_add(1, Ordering::Relaxed));
                let services = services.clone();
                let connection_shutdown = shutdown.clone();
                connections.spawn(async move {
                    let outcome =
                        connection::serve(stream, id, services, connection_shutdown).await;
                    drop(permit);
                    outcome
                });
            }
        }
    };
    drop(listener);
    // Published only after the listener is gone, so an awaited `stop_accepting`
    // cannot return while the port would still complete a TCP handshake.
    let _ = accepting.send(false);

    if !shutting_down {
        // Quiesced: refuse new work, but let established connections finish
        // their in-flight requests until an actual shutdown arrives.
        loop {
            tokio::select! {
                biased;
                changed = shutdown.changed() => {
                    if changed.is_err() || *shutdown.borrow() {
                        break;
                    }
                }
                Some(_) = connections.join_next(), if !connections.is_empty() => {}
            }
        }
    }

    let drain = async { while connections.join_next().await.is_some() {} };
    if timeout(grace, drain).await.is_err() {
        connections.shutdown().await;
    }
}

/// A running server with graceful shutdown.
#[derive(Debug)]
pub struct ServerHandle {
    local_address: SocketAddr,
    shutdown: watch::Sender<bool>,
    quiesce: watch::Sender<bool>,
    accepting: watch::Receiver<bool>,
    events: EventBus,
    directory: ConnectionDirectory,
    permits: Arc<Semaphore>,
    meter: RequestMeter,
    max_connections: usize,
    acceptor: JoinHandle<()>,
    ticker: JoinHandle<()>,
}

impl ServerHandle {
    /// Returns the address the listener bound to.
    #[must_use]
    pub const fn local_address(&self) -> SocketAddr {
        self.local_address
    }

    /// Returns the event bus so embedders can publish catalogued events.
    #[must_use]
    pub const fn events(&self) -> &EventBus {
        &self.events
    }

    /// Returns the live authenticated connection directory.
    #[must_use]
    pub const fn directory(&self) -> &ConnectionDirectory {
        &self.directory
    }

    /// Returns how many connection slots are currently occupied.
    #[must_use]
    pub fn connection_count(&self) -> usize {
        self.max_connections
            .saturating_sub(self.permits.available_permits())
    }

    /// Releases the listener while every established connection keeps serving.
    ///
    /// This is the ingress half of a graceful stop: after it returns, the port
    /// no longer completes a TCP handshake, so a new client is refused at
    /// connect time, but connections that were already established continue to
    /// answer requests until [`shutdown`](Self::shutdown) closes them. A
    /// composition root uses it to stop the edges before draining the
    /// subsystems behind them.
    ///
    /// It awaits the acceptor's acknowledgement rather than only signalling, so
    /// when it returns the listener is definitely gone. It is idempotent.
    pub async fn stop_accepting(&self) {
        let _ = self.quiesce.send(true);
        let mut accepting = self.accepting.clone();
        while *accepting.borrow_and_update() {
            if accepting.changed().await.is_err() {
                // The acceptor is gone, which means it is no longer accepting.
                break;
            }
        }
    }

    /// Waits up to `grace` for every request already being served to finish.
    ///
    /// This is the middle step of a graceful stop: it belongs *after*
    /// [`stop_accepting`](Self::stop_accepting), which is what makes the set of
    /// outstanding requests finite, and *before* [`shutdown`](Self::shutdown),
    /// which closes the connections regardless. Returns how many requests were
    /// still running when it stopped waiting, so a caller can report the work
    /// it cut off rather than claiming a clean stop it did not achieve.
    pub async fn drain_requests(&self, grace: std::time::Duration) -> u64 {
        self.meter.drain(grace).await
    }

    /// Returns how many requests are being served at this instant.
    #[must_use]
    pub fn in_flight_requests(&self) -> u64 {
        self.meter.in_flight()
    }

    /// Returns how many requests have been answered since the server started.
    #[must_use]
    pub fn completed_requests(&self) -> u64 {
        self.meter.completed()
    }

    /// Announces shutdown, stops accepting, and waits for the accept loop.
    ///
    /// The broadcast `shutdown` event is published *before* the cancellation
    /// signal so subscribers that are still keeping up observe it, then every
    /// live connection closes with RFC 6455 code 1001.
    pub async fn shutdown(self) {
        if let Ok(reason) = Name::new(SHUTDOWN_REASON, MAX_SHUTDOWN_REASON_BYTES) {
            let payload = ShutdownEvent {
                reason,
                restart_expected_ms: None,
            };
            if let Ok(draft) = EventDraft::broadcast("shutdown", &payload) {
                self.events.publish(draft);
            }
        }
        let _ = self.shutdown.send(true);
        let _ = self.ticker.await;
        let _ = self.acceptor.await;
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use claw_protocol::gateway::Role;

    use super::*;
    use crate::auth::{CredentialPolicy, StaticAuthenticator};
    use crate::clock::ManualClock;

    fn server(max_connections: usize) -> GatewayServer {
        let mut config = GatewayServerConfig::default();
        config.limits.max_connections = max_connections;
        let clock = Arc::new(ManualClock::new(1_700_000_000_000));
        let authenticator = StaticAuthenticator::new(CredentialPolicy::None, clock.clone());
        let devices = authenticator.devices();
        GatewayServer::new(config, Arc::new(authenticator), Arc::new(devices))
            .expect("the default configuration is valid")
            .with_clock(clock)
    }

    #[tokio::test]
    async fn binding_to_port_zero_reports_the_assigned_port() {
        let bound = server(4)
            .bind("127.0.0.1:0".parse().expect("loopback address parses"))
            .await
            .expect("loopback bind succeeds");
        assert_ne!(bound.local_address().port(), 0);
        assert!(bound.local_address().ip().is_loopback());
        let handle = bound.start();
        assert_eq!(handle.connection_count(), 0);
        handle.shutdown().await;
    }

    /// Builds a server with an explicit exposure policy.
    fn server_exposed(exposure: crate::config::Exposure) -> GatewayServer {
        let config = GatewayServerConfig {
            exposure,
            ..GatewayServerConfig::default()
        };
        let clock = Arc::new(ManualClock::new(1_700_000_000_000));
        let authenticator = StaticAuthenticator::new(CredentialPolicy::None, clock.clone());
        let devices = authenticator.devices();
        GatewayServer::new(config, Arc::new(authenticator), Arc::new(devices))
            .expect("the default configuration is valid")
            .with_clock(clock)
    }

    #[tokio::test]
    async fn the_default_policy_refuses_a_wildcard_bind_before_opening_a_socket() {
        let address: SocketAddr = "0.0.0.0:0".parse().expect("the wildcard address parses");
        let error = server_exposed(crate::config::Exposure::LoopbackOnly)
            .bind(address)
            .await
            .expect_err("a wildcard address is not loopback and must be refused by default");

        match error {
            ServerError::NonLoopbackBindRefused { address: refused } => {
                assert_eq!(refused, address);
            }
            other => panic!("expected a refused bind, got {other}"),
        }
    }

    #[tokio::test]
    async fn the_default_policy_refuses_a_routable_ipv6_bind() {
        let address: SocketAddr = "[::]:0".parse().expect("the ipv6 wildcard parses");
        let error = server_exposed(crate::config::Exposure::LoopbackOnly)
            .bind(address)
            .await
            .expect_err("the ipv6 wildcard is not loopback");
        assert!(matches!(error, ServerError::NonLoopbackBindRefused { .. }));
    }

    #[tokio::test]
    async fn the_ipv6_loopback_is_admitted_by_the_default_policy() {
        let bound = server_exposed(crate::config::Exposure::LoopbackOnly)
            .bind("[::1]:0".parse().expect("the ipv6 loopback parses"))
            .await
            .expect("::1 is loopback");
        assert!(bound.local_address().ip().is_loopback());
        bound.start().shutdown().await;
    }

    #[tokio::test]
    async fn opting_into_front_end_tls_admits_a_wildcard_bind() {
        let bound = server_exposed(crate::config::Exposure::TlsTerminatedByFrontend)
            .bind("127.0.0.1:0".parse().expect("loopback address parses"))
            .await
            .expect("the opt-in policy admits every address the OS accepts");
        assert_ne!(bound.local_address().port(), 0);
        bound.start().shutdown().await;
    }

    /// The `278` here is transcribed from the frozen inventory's
    /// `counts.methods`, so it is an independent expectation rather than one
    /// derived from the registry. Note this is the *registered* total; the
    /// smaller *advertised* subset (258) is checked in `tests/frozen_catalog.rs`.
    #[tokio::test]
    async fn a_started_server_registers_the_whole_frozen_method_catalog() {
        let server = server(2);
        assert_eq!(server.registry().len(), 278);
        assert_eq!(server.directory().len(), 0);
        assert_eq!(server.events().subscriber_count(), 0);
    }

    #[tokio::test]
    async fn shutdown_publishes_the_catalogued_shutdown_event_to_live_subscribers() {
        let bound = server(2)
            .bind("127.0.0.1:0".parse().expect("loopback address parses"))
            .await
            .expect("loopback bind succeeds");
        let events = bound.events().clone();
        let handle = bound.start();
        let filter = Arc::new(std::sync::Mutex::new(crate::events::TopicFilter::default()));
        let mut subscription = events.subscribe(
            ConnectionId::new(9_001),
            Role::Operator,
            vec![claw_protocol::gateway::OperatorScope::Read],
            filter,
        );
        handle.shutdown().await;
        match subscription.recv().await {
            crate::events::Delivery::Event(envelope) => {
                assert_eq!(envelope.name(), "shutdown");
            }
            other => panic!("expected the shutdown event, observed {other:?}"),
        }
    }

    #[tokio::test]
    async fn the_connection_cap_refuses_sockets_past_the_configured_limit() {
        let bound = server(1)
            .bind("127.0.0.1:0".parse().expect("loopback address parses"))
            .await
            .expect("loopback bind succeeds");
        let address = bound.local_address();
        let handle = bound.start();

        let first = tokio::net::TcpStream::connect(address)
            .await
            .expect("the first connection is admitted");
        // Wait until the accept loop has taken the only permit.
        for _ in 0..200 {
            if handle.connection_count() == 1 {
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(5)).await;
        }
        assert_eq!(handle.connection_count(), 1);

        let mut second = tokio::net::TcpStream::connect(address)
            .await
            .expect("the kernel still completes the TCP handshake");
        let mut buffer = [0_u8; 1];
        let read = tokio::io::AsyncReadExt::read(&mut second, &mut buffer).await;
        assert_eq!(read.expect("the refused socket reports EOF"), 0);
        assert_eq!(handle.connection_count(), 1);

        drop(first);
        handle.shutdown().await;
    }
}

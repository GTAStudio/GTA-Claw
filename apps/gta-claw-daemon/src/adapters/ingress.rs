//! Subsystem wrappers: the things that hold resources and the things that
//! accept work from outside.
//!
//! Two shapes live here.
//!
//! [`PortSubsystem`] wraps a port that has no lifecycle of its own — a
//! configuration source, a store, a registry — so that it still appears in the
//! composition plan and still gets initialized in dependency order. That matters
//! for ordering even when the body of `start` is empty: the plan is what
//! guarantees persistence exists before the engine tries to use it.
//!
//! [`GatewayIngress`] and [`LoopbackHttpApi`] are ingress. The Gateway owns the
//! real WebSocket server plus the in-process dispatch seam used by composition
//! tests; the HTTP stand-in only owns its dispatch seam. Both refuse new work
//! the moment they are quiesced. They are the reason [`SubsystemKind::Ingress`]
//! exists: the composition stops the edges before it drains the middle.

use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, RwLock};

use claw_application::composition::{
    BoxFuture, DrainReport, GatewayDispatch, GatewayPort, GatewayRequest, GatewayResponse,
    HttpApiPort, HttpRoute, ServiceHandle, StartContext, Subsystem, SubsystemDescriptor,
    SubsystemError, SubsystemId, SubsystemKind, well_known,
};
use claw_gateway::{
    BoundServer, CredentialPolicy, DeviceDirectory, GatewayServer, GatewayServerConfig,
    ServerHandle, StaticAuthenticator, SystemClock,
};
use tokio::sync::{mpsc, oneshot};

/// Wraps a port with no lifecycle so it takes part in the composition plan.
pub struct PortSubsystem {
    descriptor: SubsystemDescriptor,
    initialized: AtomicU64,
    started: AtomicU64,
    stopped: AtomicU64,
}

impl PortSubsystem {
    /// Declares a capability subsystem with the given dependencies.
    #[must_use]
    pub fn new(id: SubsystemId, dependencies: &[SubsystemId]) -> Self {
        let mut descriptor = SubsystemDescriptor::new(id, SubsystemKind::Capability);

        for dependency in dependencies {
            descriptor = descriptor.depends_on(dependency.clone());
        }

        Self {
            descriptor,
            initialized: AtomicU64::new(0),
            started: AtomicU64::new(0),
            stopped: AtomicU64::new(0),
        }
    }

    /// Returns how many times each lifecycle step ran, which must be one each
    /// after a complete run.
    #[must_use]
    pub fn steps(&self) -> (u64, u64, u64) {
        (
            self.initialized.load(Ordering::SeqCst),
            self.started.load(Ordering::SeqCst),
            self.stopped.load(Ordering::SeqCst),
        )
    }
}

impl Subsystem for PortSubsystem {
    fn descriptor(&self) -> SubsystemDescriptor {
        self.descriptor.clone()
    }

    fn initialize<'a>(
        &'a self,
        _context: &'a StartContext,
    ) -> BoxFuture<'a, Result<(), SubsystemError>> {
        Box::pin(async move {
            self.initialized.fetch_add(1, Ordering::SeqCst);
            Ok(())
        })
    }

    fn start<'a>(
        &'a self,
        _context: &'a StartContext,
    ) -> BoxFuture<'a, Result<ServiceHandle, SubsystemError>> {
        Box::pin(async move {
            self.started.fetch_add(1, Ordering::SeqCst);
            Ok(ServiceHandle::inert(self.descriptor.id().clone()))
        })
    }

    fn shutdown<'a>(&'a self) -> BoxFuture<'a, Result<(), SubsystemError>> {
        Box::pin(async move {
            self.stopped.fetch_add(1, Ordering::SeqCst);
            Ok(())
        })
    }
}

impl std::fmt::Debug for PortSubsystem {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("PortSubsystem")
            .field("id", self.descriptor.id())
            .field("steps", &self.steps())
            .finish()
    }
}

/// Shared ingress behaviour: accept while running, refuse once quiesced.
struct IngressGate {
    accepting: AtomicBool,
    in_flight: AtomicU64,
    served: AtomicU64,
    refused: AtomicU64,
}

impl IngressGate {
    const fn new() -> Self {
        Self {
            accepting: AtomicBool::new(false),
            in_flight: AtomicU64::new(0),
            served: AtomicU64::new(0),
            refused: AtomicU64::new(0),
        }
    }
}

/// The daemon-owned Gateway v4 ingress.
///
/// The real [`GatewayServer`] owns every bound socket and wire connection. The
/// in-process dispatch method remains available for focused composition tests,
/// but network clients always reach the real protocol server directly.
pub struct GatewayIngress {
    dispatch: Arc<dyn GatewayDispatch>,
    gate: IngressGate,
    server_config: GatewayServerConfig,
    devices: DeviceDirectory,
    pending: Mutex<Vec<BoundServer>>,
    control: Mutex<Option<mpsc::UnboundedSender<GatewayCommand>>>,
    bound: Arc<RwLock<Vec<SocketAddr>>>,
    listener_configured: AtomicBool,
    registered_methods: AtomicUsize,
}

enum GatewayCommand {
    StopAccepting(oneshot::Sender<()>),
    Shutdown(oneshot::Sender<()>),
}

impl GatewayIngress {
    /// Creates a gateway serving `dispatch` with an initially empty pairing
    /// directory.
    #[must_use]
    pub fn new(dispatch: Arc<dyn GatewayDispatch>) -> Self {
        Self {
            dispatch,
            gate: IngressGate::new(),
            server_config: GatewayServerConfig::default(),
            devices: DeviceDirectory::new(),
            pending: Mutex::new(Vec::new()),
            control: Mutex::new(None),
            bound: Arc::new(RwLock::new(Vec::new())),
            listener_configured: AtomicBool::new(false),
            registered_methods: AtomicUsize::new(0),
        }
    }

    /// Returns how many requests were served.
    #[must_use]
    pub fn served(&self) -> u64 {
        self.gate.served.load(Ordering::SeqCst)
    }

    /// Returns how many requests were refused because the ingress had stopped
    /// accepting.
    #[must_use]
    pub fn refused(&self) -> u64 {
        self.gate.refused.load(Ordering::SeqCst)
    }

    /// Returns the live pairing directory used by every bound Gateway server.
    #[must_use]
    pub fn devices(&self) -> DeviceDirectory {
        self.devices.clone()
    }

    /// Handles one request.
    ///
    /// # Errors
    ///
    /// Returns a [`SubsystemError`] when the ingress is not accepting work, or
    /// whatever the dispatcher returned.
    pub async fn handle(&self, request: GatewayRequest) -> Result<GatewayResponse, SubsystemError> {
        if !self.gate.accepting.load(Ordering::SeqCst) {
            self.gate.refused.fetch_add(1, Ordering::SeqCst);
            return Err(SubsystemError::unavailable(
                well_known::gateway(),
                "the gateway has stopped accepting requests",
            ));
        }

        self.gate.in_flight.fetch_add(1, Ordering::SeqCst);
        let outcome = self.dispatch.dispatch(request).await;
        self.gate.in_flight.fetch_sub(1, Ordering::SeqCst);

        if outcome.is_ok() {
            self.gate.served.fetch_add(1, Ordering::SeqCst);
        }

        outcome
    }
}

impl Subsystem for GatewayIngress {
    fn descriptor(&self) -> SubsystemDescriptor {
        SubsystemDescriptor::new(well_known::gateway(), SubsystemKind::Ingress)
            .depends_on(well_known::engine())
            .depends_on(well_known::observability())
    }

    fn initialize<'a>(
        &'a self,
        context: &'a StartContext,
    ) -> BoxFuture<'a, Result<(), SubsystemError>> {
        Box::pin(async move {
            let listener_configured = !context.settings().listen().is_empty();
            self.listener_configured
                .store(listener_configured, Ordering::SeqCst);
            if !listener_configured {
                self.registered_methods.store(0, Ordering::SeqCst);
                self.pending
                    .lock()
                    .expect("the Gateway pending-server lock is not poisoned")
                    .clear();
                return Ok(());
            }

            let clock = Arc::new(SystemClock);
            let mut pending = Vec::with_capacity(context.settings().listen().len());
            let mut registered_methods = None;

            for address in context.settings().listen() {
                let authenticator = StaticAuthenticator::with_devices(
                    CredentialPolicy::None,
                    clock.clone(),
                    self.devices.clone(),
                );
                let authorization = authenticator.devices();
                let server = GatewayServer::new(
                    self.server_config.clone(),
                    Arc::new(authenticator),
                    Arc::new(authorization),
                )
                .map_err(|error| {
                    SubsystemError::internal(
                        well_known::gateway(),
                        format!("could not construct Gateway server: {error}"),
                    )
                })?;
                registered_methods = Some(server.registry().len());
                let bound = server.bind(*address).await.map_err(|error| {
                    SubsystemError::unavailable(
                        well_known::gateway(),
                        format!("could not bind Gateway listener at {address}: {error}"),
                    )
                })?;
                pending.push(bound);
            }

            self.registered_methods
                .store(registered_methods.unwrap_or(0), Ordering::SeqCst);
            *self
                .pending
                .lock()
                .expect("the Gateway pending-server lock is not poisoned") = pending;
            Ok(())
        })
    }

    fn start<'a>(
        &'a self,
        context: &'a StartContext,
    ) -> BoxFuture<'a, Result<ServiceHandle, SubsystemError>> {
        Box::pin(async move {
            if !self.listener_configured.load(Ordering::SeqCst) {
                self.gate.accepting.store(true, Ordering::SeqCst);
                return Ok(ServiceHandle::inert(well_known::gateway())
                    .with_detail("Gateway disabled: no listen addresses configured"));
            }

            let pending = std::mem::take(
                &mut *self
                    .pending
                    .lock()
                    .expect("the Gateway pending-server lock is not poisoned"),
            );
            if pending.is_empty() {
                return Err(SubsystemError::internal(
                    well_known::gateway(),
                    "Gateway start was called without initialized listeners",
                ));
            }

            let bound: Vec<SocketAddr> = pending.iter().map(BoundServer::local_address).collect();
            let (control, commands) = mpsc::unbounded_channel();
            let (started, ready) = oneshot::channel();
            *self
                .control
                .lock()
                .expect("the Gateway control lock is not poisoned") = Some(control);

            let bound_state = Arc::clone(&self.bound);
            if let Err(error) = context.spawner().spawn(
                "gateway-server",
                Box::pin(run_gateway_servers(
                    pending,
                    commands,
                    started,
                    bound.clone(),
                    bound_state,
                )),
            ) {
                self.control
                    .lock()
                    .expect("the Gateway control lock is not poisoned")
                    .take();
                return Err(error);
            }

            ready.await.map_err(|_| {
                SubsystemError::internal(
                    well_known::gateway(),
                    "the Gateway server task ended before reporting readiness",
                )
            })?;
            self.gate.accepting.store(true, Ordering::SeqCst);

            Ok(
                ServiceHandle::listening(well_known::gateway(), bound).with_detail(format!(
                    "{} Gateway v4 methods",
                    self.registered_methods.load(Ordering::SeqCst)
                )),
            )
        })
    }

    fn quiesce<'a>(&'a self) -> BoxFuture<'a, Result<(), SubsystemError>> {
        Box::pin(async move {
            self.gate.accepting.store(false, Ordering::SeqCst);
            if !self.listener_configured.load(Ordering::SeqCst) {
                return Ok(());
            }

            let control = self
                .control
                .lock()
                .expect("the Gateway control lock is not poisoned")
                .clone()
                .ok_or_else(|| {
                    SubsystemError::internal(
                        well_known::gateway(),
                        "the Gateway server task has no control channel",
                    )
                })?;
            let (completed, completion) = oneshot::channel();
            control
                .send(GatewayCommand::StopAccepting(completed))
                .map_err(|_| {
                    SubsystemError::internal(
                        well_known::gateway(),
                        "the Gateway server task ended before quiescing",
                    )
                })?;
            completion.await.map_err(|_| {
                SubsystemError::internal(
                    well_known::gateway(),
                    "the Gateway server task did not acknowledge quiescing",
                )
            })
        })
    }

    fn drain<'a>(&'a self) -> BoxFuture<'a, Result<DrainReport, SubsystemError>> {
        Box::pin(async move {
            let abandoned =
                u32::try_from(self.gate.in_flight.load(Ordering::SeqCst)).unwrap_or(u32::MAX);
            let completed =
                u32::try_from(self.gate.served.load(Ordering::SeqCst)).unwrap_or(u32::MAX);

            Ok(if abandoned == 0 {
                DrainReport::clean(well_known::gateway(), completed)
            } else {
                DrainReport::partial(well_known::gateway(), completed, abandoned)
            })
        })
    }

    fn shutdown<'a>(&'a self) -> BoxFuture<'a, Result<(), SubsystemError>> {
        Box::pin(async move {
            self.gate.accepting.store(false, Ordering::SeqCst);
            self.pending
                .lock()
                .expect("the Gateway pending-server lock is not poisoned")
                .clear();
            let control = self
                .control
                .lock()
                .expect("the Gateway control lock is not poisoned")
                .clone();
            let Some(control) = control else {
                return Ok(());
            };

            let (completed, completion) = oneshot::channel();
            control
                .send(GatewayCommand::Shutdown(completed))
                .map_err(|_| {
                    SubsystemError::internal(
                        well_known::gateway(),
                        "the Gateway server task ended before shutdown",
                    )
                })?;
            completion.await.map_err(|_| {
                SubsystemError::internal(
                    well_known::gateway(),
                    "the Gateway server task did not acknowledge shutdown",
                )
            })?;
            self.control
                .lock()
                .expect("the Gateway control lock is not poisoned")
                .take();
            Ok(())
        })
    }
}

async fn run_gateway_servers(
    pending: Vec<BoundServer>,
    mut commands: mpsc::UnboundedReceiver<GatewayCommand>,
    started: oneshot::Sender<()>,
    addresses: Vec<SocketAddr>,
    bound: Arc<RwLock<Vec<SocketAddr>>>,
) {
    let mut running: Vec<ServerHandle> = pending.into_iter().map(BoundServer::start).collect();
    *bound
        .write()
        .expect("the Gateway bound-address lock is not poisoned") = addresses;
    let _ = started.send(());

    while let Some(command) = commands.recv().await {
        match command {
            GatewayCommand::StopAccepting(completed) => {
                for server in &running {
                    server.stop_accepting().await;
                }
                bound
                    .write()
                    .expect("the Gateway bound-address lock is not poisoned")
                    .clear();
                let _ = completed.send(());
            }
            GatewayCommand::Shutdown(completed) => {
                for server in std::mem::take(&mut running) {
                    server.shutdown().await;
                }
                bound
                    .write()
                    .expect("the Gateway bound-address lock is not poisoned")
                    .clear();
                let _ = completed.send(());
                return;
            }
        }
    }

    for server in running {
        server.shutdown().await;
    }
    bound
        .write()
        .expect("the Gateway bound-address lock is not poisoned")
        .clear();
}

impl GatewayPort for GatewayIngress {
    fn registered_methods(&self) -> usize {
        self.registered_methods.load(Ordering::SeqCst)
    }

    /// Returns addresses taken from the live listeners, never requested port
    /// zero values.
    fn bound(&self) -> Vec<SocketAddr> {
        self.bound
            .read()
            .expect("the Gateway bound-address lock is not poisoned")
            .clone()
    }
}

impl std::fmt::Debug for GatewayIngress {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("GatewayIngress")
            .field("bound", &self.bound())
            .field(
                "listener_configured",
                &self.listener_configured.load(Ordering::SeqCst),
            )
            .field("registered_methods", &self.registered_methods())
            .field("served", &self.served())
            .field("refused", &self.refused())
            .finish_non_exhaustive()
    }
}

/// An in-process HTTP and server-sent-event ingress.
pub struct LoopbackHttpApi {
    dispatch: Arc<dyn GatewayDispatch>,
    routes: Vec<HttpRoute>,
    gate: IngressGate,
}

impl LoopbackHttpApi {
    /// Creates an HTTP surface serving `dispatch` on `routes`.
    #[must_use]
    pub fn new(dispatch: Arc<dyn GatewayDispatch>, routes: Vec<HttpRoute>) -> Self {
        Self {
            dispatch,
            routes,
            gate: IngressGate::new(),
        }
    }

    /// Returns how many requests were served.
    #[must_use]
    pub fn served(&self) -> u64 {
        self.gate.served.load(Ordering::SeqCst)
    }

    /// Handles one request against a declared route.
    ///
    /// The route is looked up and the *matched route object* decides what
    /// happens next; the path string is not consulted again afterwards.
    ///
    /// # Errors
    ///
    /// Returns a [`SubsystemError`] when the route is unknown or the surface is
    /// not accepting work.
    pub async fn handle(
        &self,
        method: &str,
        path: &str,
        request: GatewayRequest,
    ) -> Result<(HttpRoute, GatewayResponse), SubsystemError> {
        if !self.gate.accepting.load(Ordering::SeqCst) {
            self.gate.refused.fetch_add(1, Ordering::SeqCst);
            return Err(SubsystemError::unavailable(
                well_known::http_api(),
                "the HTTP surface has stopped accepting requests",
            ));
        }

        let route = self
            .routes
            .iter()
            .find(|candidate| candidate.method() == method && candidate.path() == path)
            .cloned()
            .ok_or_else(|| {
                SubsystemError::not_found(
                    well_known::http_api(),
                    format!("no route for {method} {path}"),
                )
            })?;

        self.gate.in_flight.fetch_add(1, Ordering::SeqCst);
        let response = self.dispatch.dispatch(request).await;
        self.gate.in_flight.fetch_sub(1, Ordering::SeqCst);

        let response = response?;
        self.gate.served.fetch_add(1, Ordering::SeqCst);

        Ok((route, response))
    }
}

impl Subsystem for LoopbackHttpApi {
    fn descriptor(&self) -> SubsystemDescriptor {
        SubsystemDescriptor::new(well_known::http_api(), SubsystemKind::Ingress)
            .depends_on(well_known::engine())
            .depends_on(well_known::observability())
    }

    fn initialize<'a>(
        &'a self,
        _context: &'a StartContext,
    ) -> BoxFuture<'a, Result<(), SubsystemError>> {
        Box::pin(async { Ok(()) })
    }

    fn start<'a>(
        &'a self,
        _context: &'a StartContext,
    ) -> BoxFuture<'a, Result<ServiceHandle, SubsystemError>> {
        Box::pin(async move {
            self.gate.accepting.store(true, Ordering::SeqCst);

            // `inert` for the same reason as the gateway above: nothing is
            // bound here, so nothing may be advertised as bound.
            Ok(ServiceHandle::inert(well_known::http_api())
                .with_detail(format!("{} routes, in-process only", self.routes.len())))
        })
    }

    fn quiesce<'a>(&'a self) -> BoxFuture<'a, Result<(), SubsystemError>> {
        Box::pin(async move {
            self.gate.accepting.store(false, Ordering::SeqCst);
            Ok(())
        })
    }

    fn drain<'a>(&'a self) -> BoxFuture<'a, Result<DrainReport, SubsystemError>> {
        Box::pin(async move {
            let completed =
                u32::try_from(self.gate.served.load(Ordering::SeqCst)).unwrap_or(u32::MAX);

            Ok(DrainReport::clean(well_known::http_api(), completed))
        })
    }

    fn shutdown<'a>(&'a self) -> BoxFuture<'a, Result<(), SubsystemError>> {
        Box::pin(async move { Ok(()) })
    }
}

impl HttpApiPort for LoopbackHttpApi {
    fn routes(&self) -> Vec<HttpRoute> {
        self.routes.clone()
    }

    /// Always empty: this ingress binds no socket.
    fn bound(&self) -> Vec<SocketAddr> {
        Vec::new()
    }
}

impl std::fmt::Debug for LoopbackHttpApi {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("LoopbackHttpApi")
            .field("routes", &self.routes.len())
            .field("served", &self.served())
            .finish_non_exhaustive()
    }
}

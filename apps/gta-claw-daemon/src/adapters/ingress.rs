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
//! [`LoopbackGateway`] and [`LoopbackHttpApi`] are ingress. They own a
//! [`GatewayDispatch`], accept requests through a bounded queue, and refuse new
//! work the moment they are quiesced. They are the reason
//! [`SubsystemKind::Ingress`] exists: the composition stops the edges before it
//! drains the middle.

use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};

use claw_application::composition::{
    BoxFuture, DrainReport, GatewayDispatch, GatewayPort, GatewayRequest, GatewayResponse,
    HttpApiPort, HttpRoute, ServiceHandle, StartContext, Subsystem, SubsystemDescriptor,
    SubsystemError, SubsystemId, SubsystemKind, well_known,
};

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

/// An in-process Gateway v4 ingress.
///
/// It speaks no wire protocol, but it enforces the part of the contract the
/// composition cares about: a request is served only while the ingress is
/// accepting, and every request is dispatched through the shared
/// [`GatewayDispatch`] rather than through any decision this ingress made
/// earlier.
pub struct LoopbackGateway {
    dispatch: Arc<dyn GatewayDispatch>,
    gate: IngressGate,
    bound: std::sync::Mutex<Vec<SocketAddr>>,
}

impl LoopbackGateway {
    /// Creates a gateway serving `dispatch`.
    #[must_use]
    pub fn new(dispatch: Arc<dyn GatewayDispatch>) -> Self {
        Self {
            dispatch,
            gate: IngressGate::new(),
            bound: std::sync::Mutex::new(Vec::new()),
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

impl Subsystem for LoopbackGateway {
    fn descriptor(&self) -> SubsystemDescriptor {
        SubsystemDescriptor::new(well_known::gateway(), SubsystemKind::Ingress)
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
        context: &'a StartContext,
    ) -> BoxFuture<'a, Result<ServiceHandle, SubsystemError>> {
        Box::pin(async move {
            let bound = context.settings().listen().to_vec();
            *self.bound.lock().expect("uncontended") = bound.clone();
            self.gate.accepting.store(true, Ordering::SeqCst);

            Ok(ServiceHandle::listening(well_known::gateway(), bound)
                .with_detail(format!("{} methods", self.dispatch.methods().len())))
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
            self.bound.lock().expect("uncontended").clear();
            Ok(())
        })
    }
}

impl GatewayPort for LoopbackGateway {
    fn registered_methods(&self) -> usize {
        self.dispatch.methods().len()
    }

    fn bound(&self) -> Vec<SocketAddr> {
        self.bound.lock().expect("uncontended").clone()
    }
}

impl std::fmt::Debug for LoopbackGateway {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("LoopbackGateway")
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
    bound: std::sync::Mutex<Vec<SocketAddr>>,
}

impl LoopbackHttpApi {
    /// Creates an HTTP surface serving `dispatch` on `routes`.
    #[must_use]
    pub fn new(dispatch: Arc<dyn GatewayDispatch>, routes: Vec<HttpRoute>) -> Self {
        Self {
            dispatch,
            routes,
            gate: IngressGate::new(),
            bound: std::sync::Mutex::new(Vec::new()),
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
        context: &'a StartContext,
    ) -> BoxFuture<'a, Result<ServiceHandle, SubsystemError>> {
        Box::pin(async move {
            let bound = context.settings().listen().to_vec();
            *self.bound.lock().expect("uncontended") = bound.clone();
            self.gate.accepting.store(true, Ordering::SeqCst);

            Ok(ServiceHandle::listening(well_known::http_api(), bound)
                .with_detail(format!("{} routes", self.routes.len())))
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
        Box::pin(async move {
            self.bound.lock().expect("uncontended").clear();
            Ok(())
        })
    }
}

impl HttpApiPort for LoopbackHttpApi {
    fn routes(&self) -> Vec<HttpRoute> {
        self.routes.clone()
    }

    fn bound(&self) -> Vec<SocketAddr> {
        self.bound.lock().expect("uncontended").clone()
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

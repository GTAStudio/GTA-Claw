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
//! [`GatewayDispatch`], accept requests only while they are running, and refuse
//! new work the moment they are quiesced. They are the reason
//! [`SubsystemKind::Ingress`] exists: the composition stops the edges before it
//! drains the middle.
//!
//! Both are stand-ins. Neither binds a socket, neither speaks a wire protocol,
//! and neither bounds how many requests may be in flight at once — a real
//! ingress has to do all three. What they do implement for real is the part the
//! composition is responsible for: the accept/refuse gate, and the count of
//! what was still running when the drain arrived.

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

    fn shutdown(&self) -> BoxFuture<'_, Result<(), SubsystemError>> {
        Box::pin(async move {
            self.stopped.fetch_add(1, Ordering::SeqCst);
            Ok(())
        })
    }
}

impl std::fmt::Debug for PortSubsystem {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let (initialized, started, stopped) = self.steps();

        formatter
            .debug_struct("PortSubsystem")
            .field("id", self.descriptor.id())
            .field("initialized", &initialized)
            .field("started", &started)
            .field("stopped", &stopped)
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

    /// Reports what the drain found: everything served, and everything still
    /// running at the moment the drain was asked for.
    ///
    /// Shared by both ingresses deliberately. This accounting was written out
    /// twice and the second copy omitted the in-flight check, so the HTTP
    /// surface reported every shutdown as a clean drain even with requests
    /// still in flight — and a clean drain is what the daemon's exit status is
    /// derived from.
    fn drain_report(&self, subsystem: SubsystemId) -> DrainReport {
        let abandoned = narrowed(self.in_flight.load(Ordering::SeqCst));
        let completed = narrowed(self.served.load(Ordering::SeqCst));

        if abandoned == 0 {
            DrainReport::clean(subsystem, completed)
        } else {
            DrainReport::partial(subsystem, completed, abandoned)
        }
    }
}

/// Narrows a request count to the width [`DrainReport`] uses.
///
/// Saturating rather than wrapping: a single ingress with more than four
/// billion requests in one run is already beyond what this stand-in models, and
/// `u32::MAX` keeps "there was work" true where wrapping to zero would report a
/// clean drain for the busiest possible daemon.
fn narrowed(count: u64) -> u32 {
    u32::try_from(count).unwrap_or(u32::MAX)
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
}

impl LoopbackGateway {
    /// Creates a gateway serving `dispatch`.
    #[must_use]
    pub fn new(dispatch: Arc<dyn GatewayDispatch>) -> Self {
        Self {
            dispatch,
            gate: IngressGate::new(),
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
        _context: &'a StartContext,
    ) -> BoxFuture<'a, Result<ServiceHandle, SubsystemError>> {
        Box::pin(async move {
            self.gate.accepting.store(true, Ordering::SeqCst);

            // Deliberately `inert`, not `listening`. This ingress binds no
            // socket, and a handle that reported the *requested* addresses
            // would advertise a service nothing is accepting on. Only a
            // subsystem that owns a real listener may report `listening`, with
            // addresses taken from the listener itself.
            Ok(
                ServiceHandle::inert(well_known::gateway()).with_detail(format!(
                    "{} methods, in-process only",
                    self.dispatch.methods().len()
                )),
            )
        })
    }

    fn quiesce(&self) -> BoxFuture<'_, Result<(), SubsystemError>> {
        Box::pin(async move {
            self.gate.accepting.store(false, Ordering::SeqCst);
            Ok(())
        })
    }

    fn drain(&self) -> BoxFuture<'_, Result<DrainReport, SubsystemError>> {
        Box::pin(async move { Ok(self.gate.drain_report(well_known::gateway())) })
    }

    fn shutdown(&self) -> BoxFuture<'_, Result<(), SubsystemError>> {
        Box::pin(async move { Ok(()) })
    }
}

impl GatewayPort for LoopbackGateway {
    fn registered_methods(&self) -> usize {
        self.dispatch.methods().len()
    }

    /// Always empty: this ingress binds no socket.
    fn bound(&self) -> Vec<SocketAddr> {
        Vec::new()
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

    fn quiesce(&self) -> BoxFuture<'_, Result<(), SubsystemError>> {
        Box::pin(async move {
            self.gate.accepting.store(false, Ordering::SeqCst);
            Ok(())
        })
    }

    fn drain(&self) -> BoxFuture<'_, Result<DrainReport, SubsystemError>> {
        Box::pin(async move { Ok(self.gate.drain_report(well_known::http_api())) })
    }

    fn shutdown(&self) -> BoxFuture<'_, Result<(), SubsystemError>> {
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

#[cfg(test)]
mod tests {
    use std::sync::Arc;
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::time::Duration;

    use claw_application::composition::{
        BoxFuture, CapabilitySet, Clock, GatewayDispatch, GatewayRequest, GatewayResponse,
        HttpRoute, ModelName, Principal, ProcessClock, ProviderName, RuntimeSettings, StartContext,
        Subsystem, SubsystemError, well_known,
    };
    use claw_domain::SessionId;
    use tokio::sync::Notify;

    use super::{LoopbackGateway, LoopbackHttpApi};
    use crate::runtime::RuntimeHost;

    /// A dispatcher that parks every request until it is released.
    ///
    /// Parking is the only way to observe a request that is genuinely in
    /// flight while the drain runs, which is the state both ingresses have to
    /// account for and one of them used to ignore.
    #[derive(Debug, Default)]
    struct ParkedDispatch {
        entered: AtomicU64,
        release: Notify,
    }

    impl ParkedDispatch {
        fn entered(&self) -> u64 {
            self.entered.load(Ordering::SeqCst)
        }

        fn release(&self) {
            self.release.notify_one();
        }
    }

    impl GatewayDispatch for ParkedDispatch {
        fn dispatch(
            &self,
            _request: GatewayRequest,
        ) -> BoxFuture<'_, Result<GatewayResponse, SubsystemError>> {
            Box::pin(async move {
                self.entered.fetch_add(1, Ordering::SeqCst);
                self.release.notified().await;

                Ok(GatewayResponse::new("served".to_owned(), 0))
            })
        }

        fn methods(&self) -> Vec<String> {
            vec!["session.prompt".to_owned()]
        }
    }

    fn request() -> GatewayRequest {
        GatewayRequest::new(
            "session.prompt".to_owned(),
            Principal::new("operator", CapabilitySet::all()),
            SessionId::new("ingress").expect("the literal is a usable session id"),
            "hello".to_owned(),
        )
    }

    /// The context a subsystem is started with, built the way the composition
    /// builds it so that `start` runs its real path rather than a shortcut.
    fn start_context(runtime: &RuntimeHost) -> StartContext {
        let settings = Arc::new(RuntimeSettings::new(
            Vec::new(),
            ProviderName::new("primary").expect("the literal satisfies the grammar"),
            ModelName::new("standard").expect("the literal satisfies the grammar"),
            4,
            Duration::from_mins(1),
            Duration::from_secs(5),
        ));

        StartContext::new(
            well_known::gateway(),
            settings,
            runtime.spawner(),
            runtime.shutdown_signal(),
            Arc::new(ProcessClock) as Arc<dyn Clock>,
        )
    }

    /// Yields until `condition` holds, so the test never sleeps for a fixed
    /// time and never spins forever.
    async fn settled(condition: impl Fn() -> bool + Send + Sync) {
        tokio::time::timeout(Duration::from_secs(5), async {
            while !condition() {
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("the request reached the dispatcher");
    }

    #[tokio::test]
    async fn a_gateway_request_still_in_flight_is_reported_as_abandoned() {
        let runtime = RuntimeHost::new();
        let dispatch = Arc::new(ParkedDispatch::default());
        let gateway = Arc::new(LoopbackGateway::new(
            Arc::clone(&dispatch) as Arc<dyn GatewayDispatch>
        ));

        gateway
            .start(&start_context(&runtime))
            .await
            .expect("the ingress starts");

        let parked = tokio::spawn({
            let gateway = Arc::clone(&gateway);
            async move { gateway.handle(request()).await }
        });
        settled(|| dispatch.entered() == 1).await;

        let report = gateway.drain().await.expect("the drain reports");

        assert_eq!(
            report.abandoned(),
            1,
            "an in-flight request was not counted"
        );
        assert_eq!(report.completed(), 0);
        assert!(!report.is_clean());

        dispatch.release();
        parked
            .await
            .expect("the parked request finishes")
            .expect("the request is served");
    }

    /// The same must hold for the HTTP surface.
    ///
    /// It did not: its drain only reported what it had served, so a shutdown
    /// with requests still running was reported as clean, and the daemon's
    /// `clean=true` summary — and its exit status — were derived from that.
    #[tokio::test]
    async fn an_http_request_still_in_flight_is_reported_as_abandoned() {
        let runtime = RuntimeHost::new();
        let dispatch = Arc::new(ParkedDispatch::default());
        let http = Arc::new(LoopbackHttpApi::new(
            Arc::clone(&dispatch) as Arc<dyn GatewayDispatch>,
            vec![HttpRoute::unary("POST", "/v1/sessions")],
        ));

        http.start(&start_context(&runtime))
            .await
            .expect("the ingress starts");

        let parked = tokio::spawn({
            let http = Arc::clone(&http);
            async move { http.handle("POST", "/v1/sessions", request()).await }
        });
        settled(|| dispatch.entered() == 1).await;

        let report = http.drain().await.expect("the drain reports");

        assert_eq!(
            report.abandoned(),
            1,
            "an in-flight request was not counted"
        );
        assert_eq!(report.completed(), 0);
        assert!(!report.is_clean());

        dispatch.release();
        parked
            .await
            .expect("the parked request finishes")
            .expect("the request is served");
    }

    /// An idle ingress drains clean, so the assertions above mean something.
    #[tokio::test]
    async fn an_idle_ingress_drains_clean_after_serving_its_requests() {
        let runtime = RuntimeHost::new();
        let dispatch = Arc::new(ParkedDispatch::default());
        let http = Arc::new(LoopbackHttpApi::new(
            Arc::clone(&dispatch) as Arc<dyn GatewayDispatch>,
            vec![HttpRoute::unary("POST", "/v1/sessions")],
        ));

        http.start(&start_context(&runtime))
            .await
            .expect("the ingress starts");
        dispatch.release();
        http.handle("POST", "/v1/sessions", request())
            .await
            .expect("the request is served");

        let report = http.drain().await.expect("the drain reports");

        assert_eq!(report.completed(), 1);
        assert_eq!(report.abandoned(), 0);
        assert!(report.is_clean());
        assert_eq!(http.served(), 1);
    }
}

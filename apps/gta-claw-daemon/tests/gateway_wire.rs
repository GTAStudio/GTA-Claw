//! The joint property: a real Gateway v4 server inside a real `Daemon`.
//!
//! Every other test in this crate drives the composition through an in-process
//! seam. This one is the only place where the two shipped halves of the product
//! meet: the real `claw-gateway` server, seated in the real composition root,
//! driven by the real `claw-gateway-client` — the same client the desktop GUI
//! depends on.
//!
//! # Why one test and not three
//!
//! "The Gateway stops accepting, in-flight work drains, the HTTP surface stops
//! accepting, and the stop is clean" is a statement about *ordering between
//! subsystems*. Three tests, one per subsystem, would each prove their own
//! behaviour and none of them would prove the conjunction — a composition that
//! stopped the Gateway after it had already reported a clean stop would pass all
//! three. An ordering can only be observed by something that watches more than
//! one participant, so the conjunction is asserted once, from outside, against a
//! single stop.

use std::io::ErrorKind;
use std::sync::Arc;
use std::time::Duration;

use claw_application::composition::{
    BoxFuture, Capability, CapabilitySet, Clock, CompositionError, DrainReport, GatewayDispatch,
    GatewayPort, GatewayRequest, GatewayResponse, LifecyclePhase, ModelName, Principal,
    ProviderName, RuntimeSettings, ServiceHandle, StartContext, Subsystem, SubsystemDescriptor,
    SubsystemError, SubsystemErrorKind, SubsystemId, SubsystemKind, well_known,
};
use claw_domain::SessionId;
use claw_gateway::store::StoreFuture;
use claw_gateway::{
    AuthorizationSource, CredentialPolicy, GatewayServer, GatewayServerConfig, GatewayStore, Grant,
    HeartbeatRecord, InMemoryGatewayStore, PendingInvocation, RequestGuard, RequestMeter,
    SessionDraft, SessionPatch, SessionRecord, StaticAuthenticator,
};
use claw_gateway_client::{GatewayClient, GatewayClientConfig, ReconnectPolicy};
use claw_protocol::gateway::{
    AuthenticationPort, GatewayMethodName, OperatorScope, PREAUTH_MAX_FRAME_BYTES, ProtocolVersion,
    RequestId, Role, resolve_core_method,
};
use claw_security::authorization::{Role as SecurityRole, Scope, ScopeSet};
use claw_security::identity::DeviceIdentity;
use gta_claw_daemon::adapters::gateway::GatewayIngress;
use gta_claw_daemon::adapters::support::SteppedClock;
use gta_claw_daemon::compose::Daemon;
use gta_claw_daemon::runtime::RuntimeHost;
use rand_chacha::ChaCha20Rng;
use rand_chacha::rand_core::SeedableRng;
use serde_json::{Value, json};
use tokio::net::TcpStream;
use url::Url;

fn device(seed: u8) -> Arc<DeviceIdentity> {
    let mut rng = ChaCha20Rng::from_seed([seed; 32]);
    Arc::new(DeviceIdentity::generate(&mut rng))
}

fn request_id(value: &str) -> RequestId {
    RequestId::new(value, PREAUTH_MAX_FRAME_BYTES).expect("the request identity is bounded")
}

fn method(name: &str) -> GatewayMethodName {
    GatewayMethodName::Core(resolve_core_method(name).expect("the method is catalogued"))
}

fn payload(frame: &claw_protocol::gateway::ResponseFrame) -> Value {
    let opaque = frame
        .payload()
        .value()
        .expect("a successful response carries a payload");
    serde_json::from_str(opaque.as_json()).expect("the payload is valid JSON")
}

fn operator() -> Principal {
    Principal::new("operator", CapabilitySet::all())
}

/// Watches the Gateway port from inside the stop, during the one window where
/// quiesce is distinguishable from shutdown.
///
/// `SubsystemHost` quiesces *every* subsystem before it drains *any* of them,
/// and drains every one before it shuts down any. A subsystem's `drain` therefore
/// runs strictly after the Gateway quiesced and strictly before the Gateway shut
/// down. That is the only moment at which "stopped accepting" is a claim about
/// quiescing rather than about closing the listener, so it is where the claim is
/// checked.
///
/// Without this, a composition whose `quiesce` did nothing would still pass every
/// post-stop assertion, because the shutdown closes the listener anyway.
#[derive(Debug, Default)]
struct QuiesceWitness {
    /// Filled by the test once the daemon has bound, since the witness has to
    /// be handed to the builder before any port exists.
    watching: std::sync::Mutex<Option<std::net::SocketAddr>>,
    /// `Some(true)` when a fresh connection was refused during the window.
    refused_mid_stop: std::sync::Mutex<Option<bool>>,
}

impl QuiesceWitness {
    fn watch(&self, address: std::net::SocketAddr) {
        *self.watching.lock().expect("uncontended") = Some(address);
    }

    fn refused_mid_stop(&self) -> Option<bool> {
        *self.refused_mid_stop.lock().expect("uncontended")
    }
}

impl Subsystem for QuiesceWitness {
    fn descriptor(&self) -> SubsystemDescriptor {
        SubsystemDescriptor::new(
            SubsystemId::new("quiesce-witness").expect("the literal satisfies the grammar"),
            SubsystemKind::Capability,
        )
        .depends_on(well_known::gateway())
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
        Box::pin(async move { Ok(ServiceHandle::inert(self.descriptor().id().clone())) })
    }

    fn drain<'a>(&'a self) -> BoxFuture<'a, Result<DrainReport, SubsystemError>> {
        Box::pin(async move {
            let address = *self.watching.lock().expect("uncontended");
            if let Some(address) = address {
                let refused = TcpStream::connect(address).await.is_err();
                *self.refused_mid_stop.lock().expect("uncontended") = Some(refused);
            }

            Ok(DrainReport::clean(self.descriptor().id().clone(), 0))
        })
    }

    fn shutdown<'a>(&'a self) -> BoxFuture<'a, Result<(), SubsystemError>> {
        Box::pin(async { Ok(()) })
    }
}

fn client_config(
    address: std::net::SocketAddr,
    identity: Arc<DeviceIdentity>,
    scopes: &[Scope],
) -> GatewayClientConfig {
    let endpoint = Url::parse(&format!("ws://127.0.0.1:{}/", address.port()))
        .expect("the loopback endpoint parses");
    let mut config = GatewayClientConfig::new(endpoint, identity);
    config.role = SecurityRole::Operator;
    config.scopes = ScopeSet::from_scopes(scopes.iter().copied());
    config.reconnect = ReconnectPolicy::Never;
    config.timeouts.request = Duration::from_secs(5);
    config
}

/// The whole assignment, asserted once.
///
/// A real client completes the v4 handshake against the daemon's own listener,
/// calls catalogued methods, and then the daemon is stopped. After that single
/// stop, every part of the joint property is checked against the same run.
#[tokio::test]
async fn a_real_client_is_served_by_the_daemon_and_the_stop_closes_every_ingress_cleanly() {
    let identity = device(97);
    let wire_id = identity.device_id().gateway_wire_id();
    let witness = Arc::new(QuiesceWitness::default());

    let mut daemon = Daemon::builder()
        .clock(Arc::new(SteppedClock::new()) as Arc<dyn Clock>)
        .listen(vec!["127.0.0.1:0".parse().expect("a valid address")])
        .gateway_device(
            wire_id.clone(),
            Grant::new(Role::Operator, [OperatorScope::Read]),
        )
        .with_subsystem(Arc::clone(&witness) as Arc<dyn Subsystem>)
        .build()
        .expect("the composition is orderable");

    daemon.start().await.expect("every subsystem comes up");
    assert_eq!(daemon.phase(), LifecyclePhase::Running);

    // The address comes from the composition, not from the test. Nothing here
    // knows a port number until the daemon has bound one.
    let bound = daemon.gateway().bound();
    assert_eq!(bound.len(), 1, "the daemon bound exactly one gateway port");
    let address = bound[0];
    assert_ne!(address.port(), 0);
    witness.watch(address);

    // A fresh peer can reach the port while the daemon is running, so the
    // witness's later refusal is the quiesce doing something rather than the
    // port never having been reachable.
    TcpStream::connect(address)
        .await
        .expect("the gateway accepts connections while the daemon runs");

    // ---- The real client, against the real server, inside the real daemon.
    let (client, _events) = GatewayClient::start(client_config(
        address,
        Arc::clone(&identity),
        &[Scope::OperatorRead],
    ))
    .expect("the client configuration is valid");
    let ready = client
        .wait_ready()
        .await
        .expect("the v4 handshake completes against the daemon's gateway");

    assert_eq!(ready.info.protocol, ProtocolVersion::new(4).unwrap());
    assert_eq!(ready.info.role, "operator");
    assert_eq!(ready.info.scopes.as_ref(), ["operator.read".to_owned()]);
    assert_eq!(ready.info.advertised_event_count, 33);

    let response = client
        .request(request_id("daemon-health"), method("health"), &json!({}))
        .await
        .expect("the daemon answers a health call over the wire");
    assert!(response.ok());
    assert_eq!(payload(&response)["protocol"], json!(4));

    let response = client
        .request(
            request_id("daemon-identity"),
            method("gateway.identity.get"),
            &json!({}),
        )
        .await
        .expect("the daemon answers an identity call over the wire");
    assert!(response.ok());
    assert_eq!(payload(&response)["deviceId"], json!(wire_id));

    assert_eq!(daemon.gateway().wire_connections().await, 1);
    assert_eq!(daemon.gateway().wire_requests_completed().await, 2);

    // One request on the in-process path too, so the drain has to account for
    // both vocabularies rather than only the one it was built around.
    daemon
        .call_gateway(GatewayRequest::new(
            "session.prompt".to_owned(),
            operator(),
            SessionId::new("wire-and-engine").expect("a usable session id"),
            "hello".to_owned(),
        ))
        .await
        .expect("the in-process path still serves while running");

    // ---- One stop. Everything below is about that stop.
    let summary = daemon.stop().await.expect("the daemon stops");

    // 1. It is clean: no subsystem errored, no subsystem abandoned work, every
    //    spawned task terminated, and the phase agrees.
    assert!(
        summary.is_clean(),
        "the stop was not clean: {:?}",
        summary.shutdown()
    );
    assert_eq!(summary.phase(), LifecyclePhase::Stopped);
    assert_eq!(summary.shutdown().abandoned(), 0);
    assert!(summary.tasks().is_settled());

    // 2. The drain counted the work that really happened, on both paths. Two
    //    wire requests plus one in-process request; a drain that observed
    //    nothing would report zero here and still be "clean", which is exactly
    //    the vacuous report this assertion exists to rule out.
    let gateway_drain = summary
        .shutdown()
        .drains()
        .iter()
        .find(|drain| drain.subsystem().as_str() == "gateway")
        .expect("the gateway reported a drain");
    assert_eq!(gateway_drain.completed(), 3);
    assert_eq!(gateway_drain.abandoned(), 0);

    // 3. The Gateway stopped accepting new ingress when it was *quiesced*, not
    //    merely when the listener was finally dropped. The witness ran inside
    //    the stop, after every quiesce and before any shutdown, so this is the
    //    ordering claim and not a restatement of point 4.
    assert_eq!(
        witness.refused_mid_stop(),
        Some(true),
        "a new peer was still accepted between quiesce and shutdown, so quiescing \
         the gateway did not stop ingress"
    );

    // 4. And after the stop, the port is gone entirely.
    let refused = TcpStream::connect(address)
        .await
        .err()
        .map(|error| error.kind());
    assert!(
        matches!(
            refused,
            Some(ErrorKind::ConnectionRefused | ErrorKind::ConnectionReset | ErrorKind::TimedOut)
        ),
        "a new peer reached the stopped gateway at {address}: {refused:?}"
    );
    assert!(daemon.gateway().bound().is_empty());

    // 5. The connection that was open is closed, so the client cannot keep
    //    using a session the daemon believes it has torn down.
    client
        .request(
            request_id("daemon-after-stop"),
            method("health"),
            &json!({}),
        )
        .await
        .expect_err("the gateway closed the connection when the daemon stopped");

    // 6. The in-process gateway path refuses too.
    let refused = daemon
        .call_gateway(GatewayRequest::new(
            "session.prompt".to_owned(),
            operator(),
            SessionId::new("after-stop").expect("a usable session id"),
            "too late".to_owned(),
        ))
        .await
        .expect_err("the in-process gateway path is closed once the daemon has stopped");
    assert_eq!(refused.kind(), SubsystemErrorKind::Unavailable);

    // 7. And the HTTP surface stopped accepting, in the same stop.
    let refused = daemon
        .call_http(
            "POST",
            "/v1/sessions/stream",
            GatewayRequest::new(
                "session.prompt".to_owned(),
                operator(),
                SessionId::new("after-stop").expect("a usable session id"),
                "too late".to_owned(),
            ),
        )
        .await
        .expect_err("the http surface is closed once the daemon has stopped");
    assert_eq!(refused.kind(), SubsystemErrorKind::Unavailable);

    client.shutdown().await.ok();
}

/// A device the daemon was never told about cannot get in.
///
/// The composition pairs devices explicitly and starts with none, so this is
/// the default posture rather than a configured one. Without it, "a real client
/// connects" above would be evidence that the door is open rather than evidence
/// that the door works.
#[tokio::test]
async fn a_device_the_daemon_never_paired_is_refused_by_its_gateway() {
    let paired = device(98);
    let stranger = device(99);
    assert_ne!(
        paired.device_id().gateway_wire_id(),
        stranger.device_id().gateway_wire_id()
    );

    let mut daemon = Daemon::builder()
        .clock(Arc::new(SteppedClock::new()) as Arc<dyn Clock>)
        .listen(vec!["127.0.0.1:0".parse().expect("a valid address")])
        .gateway_device(
            paired.device_id().gateway_wire_id(),
            Grant::new(Role::Operator, [OperatorScope::Read]),
        )
        .build()
        .expect("the composition is orderable");
    daemon.start().await.expect("every subsystem comes up");

    let address = daemon.gateway().bound()[0];
    let (client, _events) = GatewayClient::start(client_config(
        address,
        Arc::clone(&stranger),
        &[Scope::OperatorRead],
    ))
    .expect("the client configuration is valid");

    client
        .wait_ready()
        .await
        .expect_err("an unpaired device must not be admitted");
    assert_eq!(daemon.gateway().wire_requests_completed().await, 0);

    client.shutdown().await.ok();
    assert!(daemon.stop().await.expect("the daemon stops").is_clean());
}

/// The drain the daemon performs is bounded, and says so when it gives up.
///
/// Asserted against the same [`RequestMeter`] type the gateway subsystem drains,
/// because the alternative — wedging a real handler mid-request from outside the
/// crate — is not reachable through the public API. What this pins down is the
/// property the daemon depends on: a drain that runs out of time reports the
/// work it abandoned instead of reporting success, which is what stops
/// `is_clean()` from being true after an incomplete stop.
#[tokio::test]
async fn a_bounded_drain_reports_the_work_it_gave_up_on() {
    let meter = RequestMeter::new();
    let stuck: RequestGuard = meter.begin();

    assert_eq!(meter.drain(Duration::from_millis(50)).await, 1);

    drop(stuck);
    assert_eq!(meter.drain(Duration::from_millis(50)).await, 0);
}

/// The packaged shape: no listen address, therefore no socket at all.
///
/// This is the configuration the shipped `systemd` unit runs, and it is the
/// default rather than an opt-out. `gta-claw-daemon.service` is hardened with
/// `RestrictAddressFamilies=AF_UNIX` and `IPAddressDeny=any`, so a composition
/// that bound a TCP listener unconditionally would fail its own start-up under
/// its own packaging — invisibly, because `Type=simple` reports a successful
/// start for a process that dies immediately afterwards.
///
/// The in-process path must keep working, so that "the wire is off" is not
/// quietly "the gateway is broken", and the whole catalogue must still be
/// registered, so that turning the wire on is a configuration change rather than
/// a different build.
#[tokio::test]
async fn a_daemon_given_no_listen_address_opens_no_socket() {
    let mut daemon = Daemon::builder()
        .clock(Arc::new(SteppedClock::new()) as Arc<dyn Clock>)
        .build()
        .expect("the composition is orderable");

    let handles = daemon.start().await.expect("every subsystem comes up");

    assert!(
        !daemon.gateway().serves_the_wire().await,
        "the gateway opened a socket nobody asked it for"
    );
    assert!(daemon.gateway().bound().is_empty());
    assert_eq!(daemon.gateway().registered_methods(), 278);

    // Nothing advertises an address, so no health check can be sent at one.
    let advertised: Vec<&ServiceHandle> = handles
        .iter()
        .filter(|handle| !handle.bound().is_empty())
        .collect();
    assert!(
        advertised.is_empty(),
        "a socketless daemon advertised {advertised:?}"
    );

    // The in-process path is unaffected, which is what makes this "the wire is
    // off" rather than "the gateway did not start".
    let served = daemon
        .call_gateway(GatewayRequest::new(
            "session.prompt".to_owned(),
            operator(),
            SessionId::new("socketless").expect("a usable session id"),
            "hello".to_owned(),
        ))
        .await
        .expect("the in-process gateway path serves without a socket");
    assert_eq!(served.body(), "echo: hello");
    assert_eq!(daemon.gateway().served(), 1);

    assert!(daemon.stop().await.expect("the daemon stops").is_clean());
}

/// A gateway that cannot bind must fail the whole start, not come up half-served.
///
/// This is the link that makes the socketless default matter rather than merely
/// being tidy: a bind failure is fatal to `start`, `serve` propagates it, and the
/// process exits non-zero. Under the packaged unit the refusal arrives from the
/// kernel — `AF_INET` is not an address family the service is allowed to use —
/// and it is reproduced here with an address that is genuinely unbindable
/// because something else already holds it.
///
/// Without this, "the daemon would crash-loop under its own unit" would be an
/// inference about systemd rather than a proved property of this composition.
#[tokio::test]
async fn a_gateway_that_cannot_bind_fails_the_whole_start() {
    let occupied = std::net::TcpListener::bind("127.0.0.1:0").expect("a port is available");
    let address = occupied.local_addr().expect("the listener has an address");

    let mut daemon = Daemon::builder()
        .clock(Arc::new(SteppedClock::new()) as Arc<dyn Clock>)
        .listen(vec![address])
        .build()
        .expect("the composition is orderable");

    let error = daemon
        .start()
        .await
        .expect_err("a gateway that cannot bind must not report a started daemon");

    let CompositionError::SubsystemFailed(failure) = error else {
        panic!("the composition reported {error:?} rather than a subsystem failure");
    };
    assert_eq!(failure.kind(), SubsystemErrorKind::Internal);
    assert_eq!(failure.subsystem(), &well_known::gateway());
    assert!(!daemon.is_started());

    // The port really was the obstacle: it is still held by this test, and the
    // daemon advertises nothing it failed to open.
    assert!(daemon.gateway().bound().is_empty());
    assert_eq!(
        occupied.local_addr().expect("the listener has an address"),
        address
    );
    drop(occupied);
}

/// The capability set the gateway principal carries is the full one, so the
/// refusals above are the ingress refusing rather than authorization refusing.
#[test]
fn the_test_principal_is_not_itself_the_reason_a_request_is_refused() {
    for capability in [
        Capability::ReadWorkspace,
        Capability::WriteWorkspace,
        Capability::Network,
        Capability::SpawnProcess,
        Capability::ReadEnvironment,
    ] {
        assert!(operator().capabilities().contains(capability));
    }
}

/// A store that parks `create_session` until the test releases it.
///
/// Every other method delegates, so the only thing this changes about the
/// server is *when* one catalogued method returns. That is what puts a genuine
/// request in flight across a drain deadline; nothing else in this crate can,
/// because every shipped handler answers immediately.
#[derive(Debug)]
struct ParkedStore {
    inner: InMemoryGatewayStore,
    /// Zero permits until the test grants one, so the handler parks.
    gate: tokio::sync::Semaphore,
}

impl ParkedStore {
    fn new() -> Self {
        Self {
            inner: InMemoryGatewayStore::new(16, 16),
            gate: tokio::sync::Semaphore::new(0),
        }
    }

    /// Lets one parked handler through.
    fn release(&self) {
        self.gate.add_permits(1);
    }
}

impl GatewayStore for ParkedStore {
    fn create_session<'a>(&'a self, draft: SessionDraft) -> StoreFuture<'a, SessionRecord> {
        Box::pin(async move {
            let permit = self.gate.acquire().await.expect("the gate stays open");
            permit.forget();
            self.inner.create_session(draft).await
        })
    }

    fn get_session<'a>(&'a self, id: &'a str) -> StoreFuture<'a, Option<SessionRecord>> {
        self.inner.get_session(id)
    }

    fn list_sessions(&self) -> StoreFuture<'_, Vec<SessionRecord>> {
        self.inner.list_sessions()
    }

    fn patch_session<'a>(
        &'a self,
        id: &'a str,
        patch: SessionPatch,
    ) -> StoreFuture<'a, Option<SessionRecord>> {
        self.inner.patch_session(id, patch)
    }

    fn delete_session<'a>(&'a self, id: &'a str) -> StoreFuture<'a, bool> {
        self.inner.delete_session(id)
    }

    fn record_heartbeat(&self, record: HeartbeatRecord) -> StoreFuture<'_, ()> {
        self.inner.record_heartbeat(record)
    }

    fn last_heartbeat(&self) -> StoreFuture<'_, Option<HeartbeatRecord>> {
        self.inner.last_heartbeat()
    }

    fn set_heartbeats_enabled(&self, enabled: bool) -> StoreFuture<'_, bool> {
        self.inner.set_heartbeats_enabled(enabled)
    }

    fn heartbeats_enabled(&self) -> StoreFuture<'_, bool> {
        self.inner.heartbeats_enabled()
    }

    fn enqueue_pending<'a>(
        &'a self,
        node_id: &'a str,
        invocation: PendingInvocation,
    ) -> StoreFuture<'a, usize> {
        self.inner.enqueue_pending(node_id, invocation)
    }

    fn pull_pending<'a>(
        &'a self,
        node_id: &'a str,
        max: usize,
    ) -> StoreFuture<'a, Vec<PendingInvocation>> {
        self.inner.pull_pending(node_id, max)
    }

    fn ack_pending<'a>(
        &'a self,
        node_id: &'a str,
        invocation_id: &'a str,
    ) -> StoreFuture<'a, bool> {
        self.inner.ack_pending(node_id, invocation_id)
    }

    fn drain_pending<'a>(&'a self, node_id: &'a str) -> StoreFuture<'a, Vec<PendingInvocation>> {
        self.inner.drain_pending(node_id)
    }
}

/// The in-process dispatcher is not what this test is about, so it answers
/// nothing and its drain contributes zero.
#[derive(Debug)]
struct SilentDispatch;

impl GatewayDispatch for SilentDispatch {
    fn dispatch(
        &self,
        _request: GatewayRequest,
    ) -> BoxFuture<'_, Result<GatewayResponse, SubsystemError>> {
        Box::pin(async { Ok(GatewayResponse::new(String::new(), 0)) })
    }

    fn methods(&self) -> Vec<String> {
        Vec::new()
    }
}

/// Waits until `ingress` reports `want` wire requests in flight.
async fn wait_for_in_flight(ingress: &GatewayIngress, want: u64) {
    for _ in 0..400 {
        if ingress.wire_requests_in_flight().await == want {
            return;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    panic!(
        "the gateway never reached {want} in-flight wire requests; it is at {}",
        ingress.wire_requests_in_flight().await
    );
}

/// A drain that gives up on wire work must report it, not call the stop clean.
///
/// The subsystem's `drain` folds two counts together: the in-process path's, and
/// the wire's. Every other test in this crate leaves the wire idle at drain time
/// — the shipped handlers answer immediately — so the wire's contribution is
/// always zero and a `drain` that reported the wire as *always* zero would pass
/// all of them. That is not a hypothetical: replacing the wire's abandoned count
/// with a literal `0` leaves this crate green, which means a daemon that
/// silently discarded in-flight wire requests would still report `is_clean()`.
///
/// So here one real request from the real client is parked inside a real
/// catalogued handler, the ingress is quiesced, and the drain is given less
/// grace than the request needs. The report has to name the work it cut off.
#[tokio::test]
async fn a_drain_that_gives_up_on_a_wire_request_reports_it_as_abandoned() {
    let identity = device(41);
    let authenticator =
        StaticAuthenticator::new(CredentialPolicy::None, Arc::new(claw_gateway::SystemClock))
            .with_paired_device(
                identity.device_id().gateway_wire_id(),
                Grant::new(Role::Operator, [OperatorScope::Write]),
            );
    let devices = authenticator.devices();
    let store = Arc::new(ParkedStore::new());

    let server = GatewayServer::new(
        GatewayServerConfig::default(),
        Arc::new(authenticator) as Arc<dyn AuthenticationPort + Send + Sync>,
        Arc::new(devices) as Arc<dyn AuthorizationSource>,
    )
    .expect("the configuration and registry are valid")
    .with_store(Arc::clone(&store) as Arc<dyn GatewayStore>);

    // Shorter than the request will take, so the drain is forced to give up
    // rather than merely being slow.
    let ingress = GatewayIngress::new(
        server,
        Arc::new(SilentDispatch) as Arc<dyn GatewayDispatch>,
        Duration::from_millis(150),
    );

    let runtime = RuntimeHost::new();
    let context = StartContext::new(
        well_known::gateway(),
        Arc::new(RuntimeSettings::new(
            vec!["127.0.0.1:0".parse().expect("loopback address parses")],
            ProviderName::new("primary").expect("the literal satisfies the grammar"),
            ModelName::new("standard").expect("the literal satisfies the grammar"),
            4,
            Duration::from_secs(60),
            Duration::from_secs(30),
        )),
        runtime.spawner(),
        runtime.shutdown_signal(),
        Arc::new(SteppedClock::new()) as Arc<dyn Clock>,
    );

    ingress
        .initialize(&context)
        .await
        .expect("the gateway binds an ephemeral loopback port");
    let handle = ingress.start(&context).await.expect("the gateway starts");
    let address = *handle
        .bound()
        .first()
        .expect("a started gateway advertises the port it opened");

    let (client, _events) = GatewayClient::start(client_config(
        address,
        Arc::clone(&identity),
        &[Scope::OperatorWrite],
    ))
    .expect("the client configuration is valid");
    client
        .wait_ready()
        .await
        .expect("the v4 handshake completes");

    // Fired but not awaited: the handler parks in the store, so this request is
    // still being served when the drain runs.
    let calling = tokio::spawn(async move {
        client
            .request(
                request_id("parked-create"),
                method("sessions.create"),
                &json!({ "id": "parked", "agentId": "agent" }),
            )
            .await
    });
    wait_for_in_flight(&ingress, 1).await;

    ingress.quiesce().await.expect("the gateway quiesces");
    let report = ingress.drain().await.expect("the gateway reports a drain");

    assert_eq!(
        report.subsystem(),
        &well_known::gateway(),
        "the report must be attributed to the gateway"
    );
    assert_eq!(
        report.abandoned(),
        1,
        "the drain gave up on a request it did not report"
    );
    assert_eq!(
        report.completed(),
        0,
        "nothing was answered, so nothing may be counted as answered"
    );

    // And the request really was still alive rather than having failed earlier:
    // released, it completes against the same store.
    store.release();
    let response = tokio::time::timeout(Duration::from_secs(5), calling)
        .await
        .expect("the released request finishes")
        .expect("the calling task did not panic")
        .expect("the server answers the released request");
    assert!(response.ok());
    assert_eq!(payload(&response)["id"], json!("parked"));

    ingress.shutdown().await.expect("the gateway shuts down");
}

/// The interface, not the port, is what the gateway refuses.
///
/// The Gateway server speaks RFC 6455 over plain TCP and terminates no TLS, so
/// `Exposure::LoopbackOnly` — its default — refuses any address that is not
/// loopback, and a wildcard such as `0.0.0.0` is explicitly *not* loopback. That
/// refusal is the composition's, not the operating system's: a wildcard bind is
/// something the kernel would happily grant.
///
/// This matters at the subsystem boundary rather than inside `claw-gateway`. The
/// daemon hosts more than one ingress, and a sibling ingress that defaults to a
/// routable interface would put the two subsystems in disagreement about what
/// the same daemon is willing to expose. Encoding the refusal here makes that
/// disagreement a failed start rather than a quietly reachable port.
///
/// The same port is used twice so the interface is the only variable: refused on
/// the wildcard, accepted on loopback. Without the second half, "refused" would
/// be compatible with the port simply being unavailable.
#[tokio::test]
async fn the_gateway_refuses_a_routable_interface_but_accepts_the_same_port_on_loopback() {
    // A port the operating system has just confirmed is free, released again so
    // both halves below can ask for it.
    let port = {
        let probe = std::net::TcpListener::bind("127.0.0.1:0").expect("a port is available");
        probe
            .local_addr()
            .expect("the probe listener has an address")
            .port()
    };

    let wildcard = std::net::SocketAddr::from((std::net::Ipv4Addr::UNSPECIFIED, port));
    let mut exposed = Daemon::builder()
        .clock(Arc::new(SteppedClock::new()) as Arc<dyn Clock>)
        .listen(vec![wildcard])
        .build()
        .expect("the composition is orderable");

    let error = exposed
        .start()
        .await
        .expect_err("a wildcard interface must not be served in plaintext");

    let CompositionError::SubsystemFailed(failure) = error else {
        panic!("the composition reported {error:?} rather than a subsystem failure");
    };
    assert_eq!(failure.kind(), SubsystemErrorKind::Internal);
    assert_eq!(failure.subsystem(), &well_known::gateway());
    assert!(!exposed.is_started());
    assert!(
        exposed.gateway().bound().is_empty(),
        "a refused gateway advertised an address anyway"
    );

    // The same port on loopback comes up, so the refusal above was about the
    // interface. A wildcard bind is something the kernel grants freely; only the
    // composition refuses it.
    let loopback = std::net::SocketAddr::from((std::net::Ipv4Addr::LOCALHOST, port));
    let mut permitted = Daemon::builder()
        .clock(Arc::new(SteppedClock::new()) as Arc<dyn Clock>)
        .listen(vec![loopback])
        .build()
        .expect("the composition is orderable");

    permitted
        .start()
        .await
        .expect("the same port on loopback is served");
    assert_eq!(
        permitted.gateway().bound(),
        vec![loopback],
        "the gateway bound something other than the loopback address it was given"
    );
    assert!(permitted.gateway().serves_the_wire().await);

    assert!(permitted.stop().await.expect("the daemon stops").is_clean());
}

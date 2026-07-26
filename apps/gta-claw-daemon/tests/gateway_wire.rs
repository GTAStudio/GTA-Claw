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
    BoxFuture, Capability, CapabilitySet, Clock, DrainReport, GatewayPort, GatewayRequest,
    LifecyclePhase, Principal, ServiceHandle, StartContext, Subsystem, SubsystemDescriptor,
    SubsystemError, SubsystemErrorKind, SubsystemId, SubsystemKind, well_known,
};
use claw_domain::SessionId;
use claw_gateway::{Grant, RequestGuard, RequestMeter};
use claw_gateway_client::{GatewayClient, GatewayClientConfig, ReconnectPolicy};
use claw_protocol::gateway::{
    GatewayMethodName, OperatorScope, PREAUTH_MAX_FRAME_BYTES, ProtocolVersion, RequestId, Role,
    resolve_core_method,
};
use claw_security::authorization::{Role as SecurityRole, Scope, ScopeSet};
use claw_security::identity::DeviceIdentity;
use gta_claw_daemon::adapters::support::SteppedClock;
use gta_claw_daemon::compose::Daemon;
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
) -> GatewayClientConfig {
    let endpoint = Url::parse(&format!("ws://127.0.0.1:{}/", address.port()))
        .expect("the loopback endpoint parses");
    let mut config = GatewayClientConfig::new(endpoint, identity);
    config.role = SecurityRole::Operator;
    config.scopes = ScopeSet::from_scopes([Scope::OperatorRead]);
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
    let (client, _events) = GatewayClient::start(client_config(address, Arc::clone(&identity)))
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
    let (client, _events) = GatewayClient::start(client_config(address, Arc::clone(&stranger)))
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

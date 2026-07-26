//! End-to-end tests of the composition.
//!
//! These start the real composition root, drive a session through it, and stop
//! it. Nothing here is mocked at the boundary being tested: the subsystem
//! implementations are stand-ins, but the plan, the lifecycle, the
//! authorization flow, the event stream, the persistence transaction and the
//! task tracker are the production ones.

use std::sync::{Arc, Mutex};
use std::time::Duration;

use claw_application::composition::{
    BoxFuture, Capability, CapabilitySet, Clock, ConfigPort, GatewayPort, GatewayRequest,
    HttpApiPort, LifecyclePhase, ObservabilityPort, Principal, ProviderReply, ServiceHandle,
    Severity, StartContext, Subsystem, SubsystemDescriptor, SubsystemError, SubsystemId,
    SubsystemKind, ToolName, TurnEvent, TurnEventSink, well_known,
};
use claw_domain::SessionId;
use claw_gateway::Grant;
use claw_gateway_client::{GatewayClient, GatewayClientConfig, ReconnectPolicy};
use claw_protocol::gateway::{OperatorScope, ProtocolVersion, Role};
use claw_security::{
    authorization::{Role as SecurityRole, Scope, ScopeSet},
    identity::DeviceIdentity,
};
use gta_claw_daemon::adapters::model::request_tool;
use gta_claw_daemon::adapters::support::SteppedClock;
use gta_claw_daemon::compose::Daemon;
use rand_chacha::ChaCha20Rng;
use rand_chacha::rand_core::SeedableRng;
use tokio::net::TcpStream;
use url::Url;

/// Collects every event a turn emitted, in arrival order.
#[derive(Debug, Default)]
struct RecordingSink(Mutex<Vec<TurnEvent>>);

impl RecordingSink {
    fn events(&self) -> Vec<TurnEvent> {
        self.0.lock().expect("uncontended").clone()
    }

    fn sequences(&self) -> Vec<u64> {
        self.events()
            .iter()
            .map(claw_application::composition::TurnEvent::sequence)
            .collect()
    }
}

impl TurnEventSink for RecordingSink {
    fn emit(&self, event: TurnEvent) {
        self.0.lock().expect("uncontended").push(event);
    }
}

fn operator() -> Principal {
    Principal::new("operator", CapabilitySet::all())
}

fn session(name: &str) -> SessionId {
    SessionId::new(name).expect("the literal is a usable session id")
}

fn read_tool() -> ToolName {
    ToolName::new("workspace.read").expect("the literal satisfies the grammar")
}

async fn started(clock: Arc<SteppedClock>) -> Daemon {
    let mut daemon = Daemon::builder()
        .clock(clock as Arc<dyn Clock>)
        .listen(vec![
            "127.0.0.1:0"
                .parse()
                .expect("the loopback listener address is valid"),
        ])
        .build()
        .expect("the composition is orderable");

    daemon.start().await.expect("every subsystem comes up");
    daemon
}

#[tokio::test]
async fn the_default_process_topology_opens_no_ip_listener() {
    let mut daemon = Daemon::builder()
        .clock(Arc::new(SteppedClock::new()))
        .build()
        .expect("the default composition is orderable");

    assert_eq!(daemon.settings().listen(), &[]);
    let handles = daemon.start().await.expect("the default daemon starts");
    let gateway = handles
        .iter()
        .find(|handle| handle.subsystem() == &well_known::gateway())
        .expect("the Gateway reports its inert network state");

    assert_eq!(gateway.bound(), &[]);
    assert_eq!(
        gateway.detail(),
        Some("Gateway disabled: no listen addresses configured")
    );
    assert_eq!(daemon.gateway().bound(), Vec::new());
    assert_eq!(daemon.gateway().registered_methods(), 0);

    let summary = daemon.stop().await.expect("the default daemon stops");
    assert!(summary.is_clean());
    assert_eq!(summary.tasks().spawned(), 0);
    assert_eq!(summary.tasks().terminated(), 0);
}

#[tokio::test]
async fn the_daemon_exposes_the_real_gateway_and_releases_its_listener_on_shutdown() {
    let mut daemon = started(Arc::new(SteppedClock::new())).await;
    let bound = daemon.gateway().bound();

    assert_eq!(
        bound.len(),
        1,
        "the daemon must report exactly one address from a real Gateway listener"
    );
    let address = bound[0];
    assert!(address.ip().is_loopback());
    assert_ne!(address.port(), 0);

    let mut rng = ChaCha20Rng::from_seed([71; 32]);
    let identity = Arc::new(DeviceIdentity::generate(&mut rng));
    daemon.gateway().devices().pair(
        identity.device_id().gateway_wire_id(),
        Grant::new(Role::Operator, [OperatorScope::Read]),
    );
    let mut client_config = GatewayClientConfig::new(
        Url::parse(&format!("ws://{address}/")).expect("the bound address is a valid endpoint"),
        identity,
    );
    client_config.role = SecurityRole::Operator;
    client_config.scopes = ScopeSet::from_scopes([Scope::OperatorRead]);
    client_config.reconnect = ReconnectPolicy::Never;
    client_config.timeouts.connect = Duration::from_secs(2);
    client_config.timeouts.authentication = Duration::from_secs(2);

    let (client, _events) =
        GatewayClient::start(client_config).expect("the client configuration is valid");
    let ready = client
        .wait_ready()
        .await
        .expect("the real Gateway authenticates its paired client");
    assert_eq!(ready.info.protocol, ProtocolVersion::new(4).unwrap());
    assert_eq!(ready.info.server_version, "0.1.0");
    assert_eq!(ready.info.role, "operator");
    assert_eq!(ready.info.scopes.as_ref(), ["operator.read".to_owned()]);
    assert_eq!(ready.info.advertised_method_count, 258);
    assert_eq!(ready.info.advertised_event_count, 33);
    assert_eq!(ready.info.max_payload_bytes, 26_214_400);
    assert_eq!(daemon.gateway().registered_methods(), 278);

    let summary = daemon.stop().await.expect("the daemon stops");
    assert!(summary.is_clean());
    assert_eq!(summary.phase(), LifecyclePhase::Stopped);
    assert_eq!(summary.shutdown().abandoned(), 0);
    assert_eq!(summary.tasks().spawned(), 1);
    assert_eq!(summary.tasks().terminated(), 1);
    assert!(summary.tasks().is_settled());

    let refused = TcpStream::connect(address)
        .await
        .expect_err("the stopped daemon must release the Gateway listener");
    assert_eq!(
        refused.kind(),
        std::io::ErrorKind::ConnectionRefused,
        "shutdown must close the listener rather than reject a later handshake"
    );
    client.shutdown().await.expect("the client stops cleanly");
}

#[tokio::test]
async fn a_startup_failure_rolls_back_the_bound_gateway_listener() {
    let reservation =
        std::net::TcpListener::bind("127.0.0.1:0").expect("an ephemeral port is available");
    let address = reservation
        .local_addr()
        .expect("the reservation has an address");
    drop(reservation);

    let mut daemon = Daemon::builder()
        .clock(Arc::new(SteppedClock::new()))
        .listen(vec![address])
        .build()
        .expect("the composition is orderable");
    daemon.dns().set("models.example.test", Vec::new());

    daemon
        .start()
        .await
        .expect_err("credential provisioning fails without a provider address");

    assert_eq!(daemon.phase(), LifecyclePhase::Stopped);
    assert!(!daemon.is_started());
    assert!(daemon.gateway().bound().is_empty());
    let refused = TcpStream::connect(address)
        .await
        .expect_err("failed startup must release the Gateway listener");
    assert_eq!(refused.kind(), std::io::ErrorKind::ConnectionRefused);
}

#[tokio::test]
async fn the_plan_brings_dependencies_up_before_the_things_that_need_them() {
    let daemon = started(Arc::new(SteppedClock::new())).await;
    let order = daemon.start_order();

    let position = |name: &str| {
        order
            .iter()
            .position(|id| id == name)
            .unwrap_or_else(|| panic!("{name} is missing from {order:?}"))
    };

    assert_eq!(order.len(), 12, "every declared subsystem is in the plan");
    assert_eq!(order[0], "observability");
    assert!(position("config") < position("persistence"));
    assert!(position("persistence") < position("secrets"));
    assert!(position("secrets") < position("providers"));
    assert!(position("egress") < position("providers"));
    assert!(position("providers") < position("engine"));
    assert!(position("tools") < position("engine"));
    assert!(position("memory") < position("engine"));
    assert!(position("plugin-host") < position("engine"));
    assert!(position("engine") < position("gateway"));
    assert!(position("engine") < position("http-api"));

    assert_eq!(
        daemon.quiesce_order(),
        vec!["http-api".to_owned(), "gateway".to_owned()],
        "only ingress is quiesced, newest first"
    );
}

#[tokio::test]
async fn a_turn_runs_through_every_subsystem_and_is_recorded_once() {
    let clock = Arc::new(SteppedClock::new());
    let mut daemon = started(Arc::clone(&clock)).await;
    let sink = RecordingSink::default();
    let id = session("end-to-end");

    daemon.transport().push_reply(ProviderReply::new(
        "consulting the workspace".to_owned(),
        vec![request_tool(&read_tool(), "{\"path\":\".\"}")],
    ));
    daemon.transport().push_reply(ProviderReply::new(
        "one crate is present".to_owned(),
        Vec::new(),
    ));

    let report = daemon
        .run_turn(&operator(), &id, "what is in the workspace", &sink)
        .await
        .expect("the turn completes");

    assert_eq!(report.summary().response(), "one crate is present");
    assert_eq!(report.summary().provider().as_str(), "primary");
    assert_eq!(report.summary().model().as_str(), "standard");
    assert_eq!(report.summary().tool_calls(), 1);
    assert_eq!(report.revision(), 1);
    assert_eq!(report.provider_calls(), 2);
    assert_eq!(report.tool_calls(), 1);

    // Started, one ToolCompleted, four deltas for "one crate is present", Finished.
    assert_eq!(report.events(), 7);
    assert_eq!(sink.sequences(), vec![0, 1, 2, 3, 4, 5, 6]);

    let events = sink.events();
    assert!(matches!(events[0], TurnEvent::Started { sequence: 0 }));

    match &events[1] {
        TurnEvent::ToolCompleted { sequence, outcome } => {
            assert_eq!(*sequence, 1);
            assert_eq!(outcome.tool().as_str(), "workspace.read");
            assert_eq!(outcome.output(), "the workspace contains one crate");
            assert!(!outcome.failed());
        }
        other => panic!("expected a completed tool, got {other:?}"),
    }

    let deltas: Vec<String> = events[2..6]
        .iter()
        .map(|event| match event {
            TurnEvent::AssistantDelta { text, .. } => text.clone(),
            other => panic!("expected assistant text, got {other:?}"),
        })
        .collect();
    assert_eq!(deltas.concat(), "one crate is present");

    match &events[6] {
        TurnEvent::Finished { sequence, summary } => {
            assert_eq!(*sequence, 6);
            assert_eq!(summary.response(), "one crate is present");
        }
        other => panic!("expected the turn to finish, got {other:?}"),
    }

    let calls = daemon.transport().calls();
    assert_eq!(calls.len(), 2);
    assert_eq!(calls[0].authority, "models.example.test:443");
    assert_eq!(
        calls[0].addresses,
        vec!["203.0.113.10".parse::<std::net::IpAddr>().expect("literal")],
        "the transport is handed checked addresses, not a hostname to look up"
    );
    assert!(
        calls[0].presented_secret_is("token-for-primary"),
        "the credential filed for the primary provider is the one that was presented"
    );
    assert_eq!(calls[0].prompt, "what is in the workspace");
    assert_eq!(
        calls[1].prompt,
        "what is in the workspace|workspace.read=the workspace contains one crate;"
    );

    assert_eq!(
        daemon.tools().invocations(),
        vec![("workspace.read".to_owned(), "{\"path\":\".\"}".to_owned())]
    );

    let stored = daemon.persistence().turns_for(&id);
    assert_eq!(stored.len(), 1);
    assert_eq!(stored[0].ordinal(), 1);
    assert_eq!(stored[0].prompt(), "what is in the workspace");
    assert_eq!(stored[0].response(), "one crate is present");
    assert_eq!(daemon.persistence().commits(), 1);
    assert_eq!(daemon.persistence().rollbacks(), 0);

    let summary = daemon.stop().await.expect("the daemon stops");
    assert!(summary.is_clean());
}

#[tokio::test]
async fn a_second_turn_advances_the_revision_rather_than_replacing_it() {
    let clock = Arc::new(SteppedClock::new());
    let mut daemon = started(Arc::clone(&clock)).await;
    let id = session("two-turns");

    let first = daemon
        .run_turn(&operator(), &id, "first", &RecordingSink::default())
        .await
        .expect("the first turn completes");
    let second = daemon
        .run_turn(&operator(), &id, "second", &RecordingSink::default())
        .await
        .expect("the second turn completes");

    assert_eq!(first.revision(), 1);
    assert_eq!(second.revision(), 2);
    assert_eq!(first.summary().response(), "echo: first");
    assert_eq!(second.summary().response(), "echo: second");

    let stored = daemon.persistence().turns_for(&id);
    assert_eq!(stored.len(), 2);
    assert_eq!(stored[0].ordinal(), 1);
    assert_eq!(stored[1].ordinal(), 2);
    assert_eq!(stored[1].prompt(), "second");

    assert!(daemon.stop().await.expect("the daemon stops").is_clean());
}

#[tokio::test]
async fn the_in_process_dispatch_seam_reaches_the_application_service() {
    let clock = Arc::new(SteppedClock::new());
    let mut daemon = started(Arc::clone(&clock)).await;

    let response = daemon
        .call_gateway(GatewayRequest::new(
            "session.prompt".to_owned(),
            operator(),
            session("via-gateway"),
            "hello".to_owned(),
        ))
        .await
        .expect("the in-process seam serves the application action");

    assert_eq!(response.body(), "echo: hello");
    assert_eq!(
        response.events(),
        4,
        "started, two deltas for \"echo: hello\", finished"
    );
    assert_eq!(daemon.gateway().served(), 1);
    assert_eq!(daemon.gateway().refused(), 0);

    let described = daemon
        .call_gateway(GatewayRequest::new(
            "session.describe".to_owned(),
            operator(),
            session("via-gateway"),
            String::new(),
        ))
        .await
        .expect("the in-process seam describes the session");

    assert_eq!(described.body(), "via-gateway revision 1 turns 1");

    assert!(daemon.stop().await.expect("the daemon stops").is_clean());
}

#[tokio::test]
async fn the_http_surface_answers_on_a_matched_route_and_refuses_an_unknown_one() {
    let clock = Arc::new(SteppedClock::new());
    let mut daemon = started(Arc::clone(&clock)).await;

    let (route, response) = daemon
        .call_http(
            "POST",
            "/v1/sessions/stream",
            GatewayRequest::new(
                "session.prompt".to_owned(),
                operator(),
                session("via-http"),
                "stream me".to_owned(),
            ),
        )
        .await
        .expect("the surface serves the route");

    assert_eq!(route.path(), "/v1/sessions/stream");
    assert!(route.is_streaming());
    assert_eq!(response.body(), "echo: stream me");

    let error = daemon
        .call_http(
            "POST",
            "/v1/sessions/../v1/sessions",
            GatewayRequest::new(
                "session.prompt".to_owned(),
                operator(),
                session("via-http"),
                "traversal".to_owned(),
            ),
        )
        .await
        .expect_err("an unmatched path is not served");

    assert_eq!(
        error.kind(),
        claw_application::composition::SubsystemErrorKind::NotFound
    );
    assert_eq!(daemon.http().served(), 1);

    assert!(daemon.stop().await.expect("the daemon stops").is_clean());
}

#[tokio::test]
async fn shutdown_stops_ingress_first_and_joins_every_spawned_task() {
    let clock = Arc::new(SteppedClock::new());
    let mut daemon = started(Arc::clone(&clock)).await;

    // Work that outlives the request that started it, so the tracker has
    // something real to join.
    let spawner = daemon.runtime().spawner();
    let signal = daemon.runtime().shutdown_signal();
    for _ in 0..8 {
        let signal = Arc::clone(&signal);
        spawner
            .spawn(
                "background",
                Box::pin(async move {
                    signal.triggered().await;
                }),
            )
            .expect("the daemon is running");
    }

    daemon
        .run_turn(
            &operator(),
            &session("shutdown"),
            "hi",
            &RecordingSink::default(),
        )
        .await
        .expect("the turn completes");

    assert_eq!(daemon.phase(), LifecyclePhase::Running);

    let summary = daemon.stop().await.expect("the daemon stops");

    assert_eq!(summary.phase(), LifecyclePhase::Stopped);
    assert!(summary.shutdown().is_clean());
    assert_eq!(summary.shutdown().abandoned(), 0);
    assert_eq!(summary.tasks().spawned(), 9);
    assert_eq!(
        summary.tasks().terminated(),
        9,
        "every spawned task ran to termination"
    );
    assert_eq!(summary.tasks().outstanding(), 0);
    assert!(summary.tasks().is_settled());
    assert!(summary.is_clean());

    let refused = daemon
        .call_gateway(GatewayRequest::new(
            "session.prompt".to_owned(),
            operator(),
            session("shutdown"),
            "too late".to_owned(),
        ))
        .await
        .expect_err("ingress is closed once the daemon has stopped");

    assert_eq!(
        refused.kind(),
        claw_application::composition::SubsystemErrorKind::Unavailable
    );
    assert_eq!(daemon.gateway().refused(), 1);
}

#[tokio::test]
async fn every_subsystem_is_initialized_started_and_stopped_exactly_once() {
    let clock = Arc::new(SteppedClock::new());
    let mut daemon = started(Arc::clone(&clock)).await;

    assert!(daemon.is_started());
    daemon.stop().await.expect("the daemon stops");
    assert!(!daemon.is_started());

    // The gateway has released its real listener and the HTTP stand-in never
    // bound one.
    assert_eq!(daemon.gateway().bound().len(), 0);
    assert_eq!(daemon.http().bound().len(), 0);
}

/// The Gateway must advertise addresses read back from its real listeners, not
/// requested port-zero placeholders. The HTTP stand-in must still advertise
/// nothing.
#[tokio::test]
async fn only_the_real_gateway_advertises_addresses_it_actually_bound() {
    let requested: Vec<std::net::SocketAddr> = vec![
        "127.0.0.1:0".parse().expect("a valid address"),
        "127.0.0.1:0".parse().expect("a valid address"),
    ];
    let mut daemon = Daemon::builder()
        .clock(Arc::new(SteppedClock::new()))
        .listen(requested.clone())
        .build()
        .expect("the composition builds");

    let handles = daemon.start().await.expect("the daemon starts");

    let gateway_handle = handles
        .iter()
        .find(|handle| handle.subsystem() == &well_known::gateway())
        .expect("the Gateway reports readiness");
    let bound = daemon.gateway().bound();
    assert_eq!(bound.len(), 2);
    assert_eq!(gateway_handle.bound(), bound.as_slice());
    assert!(bound.iter().all(|address| address.ip().is_loopback()));
    assert!(bound.iter().all(|address| address.port() != 0));
    assert!(daemon.http().bound().is_empty());

    // Requested values remain available as configuration; readiness uses the
    // listener-derived values above.
    assert_eq!(daemon.settings().listen(), requested.as_slice());

    daemon.stop().await.expect("the daemon stops");
}

#[tokio::test]
async fn observability_records_the_start_and_each_completed_turn() {
    let clock = Arc::new(SteppedClock::new());
    let mut daemon = started(Arc::clone(&clock)).await;

    clock.advance(25);
    daemon
        .run_turn(
            &operator(),
            &session("observed"),
            "hello",
            &RecordingSink::default(),
        )
        .await
        .expect("the turn completes");

    let events = daemon.observability().events();
    let messages: Vec<&str> = events
        .iter()
        .map(claw_application::composition::ObservedEvent::message)
        .collect();

    assert_eq!(
        messages,
        vec![
            "started 12 subsystems",
            "turn in observed completed at revision 1"
        ]
    );
    assert_eq!(events[0].at().since_origin(), Duration::ZERO);
    assert_eq!(events[1].at().since_origin(), Duration::from_millis(25));
    assert_eq!(daemon.observability().count_at(Severity::Error), 0);
    assert_eq!(daemon.observability().dropped(), 0);

    assert!(daemon.stop().await.expect("the daemon stops").is_clean());
}

#[tokio::test]
async fn a_tool_that_reports_failure_does_not_fail_the_turn() {
    let clock = Arc::new(SteppedClock::new());
    let mut daemon = started(Arc::clone(&clock)).await;
    let write = ToolName::new("workspace.write").expect("the literal satisfies the grammar");

    daemon.transport().push_reply(ProviderReply::new(
        "writing".to_owned(),
        vec![request_tool(&write, "{}")],
    ));
    daemon.transport().push_reply(ProviderReply::new(
        "I could not write".to_owned(),
        Vec::new(),
    ));

    let sink = RecordingSink::default();
    let report = daemon
        .run_turn(&operator(), &session("failing-tool"), "write a file", &sink)
        .await
        .expect("a failed tool is not a failed turn");

    assert_eq!(report.summary().response(), "I could not write");
    assert_eq!(report.tool_calls(), 1);

    let completed = sink
        .events()
        .into_iter()
        .find_map(|event| match event {
            TurnEvent::ToolCompleted { outcome, .. } => Some(outcome),
            _ => None,
        })
        .expect("the tool reported an outcome");

    assert!(completed.failed());
    assert_eq!(
        completed.output(),
        "the workspace is read only in this composition"
    );

    assert!(daemon.stop().await.expect("the daemon stops").is_clean());
}

#[tokio::test]
async fn a_tool_withdrawn_between_turns_is_no_longer_offered() {
    let clock = Arc::new(SteppedClock::new());
    let mut daemon = started(Arc::clone(&clock)).await;
    let id = session("withdrawn");

    daemon.transport().push_reply(ProviderReply::new(
        "reading".to_owned(),
        vec![request_tool(&read_tool(), "{}")],
    ));
    daemon
        .transport()
        .push_reply(ProviderReply::new("read it".to_owned(), Vec::new()));

    daemon
        .run_turn(&operator(), &id, "first", &RecordingSink::default())
        .await
        .expect("the first turn uses the tool");

    daemon.tools().withdraw(&read_tool());

    daemon.transport().push_reply(ProviderReply::new(
        "reading again".to_owned(),
        vec![request_tool(&read_tool(), "{}")],
    ));

    let error = daemon
        .run_turn(&operator(), &id, "second", &RecordingSink::default())
        .await
        .expect_err("the catalogue is re-read for every turn");

    assert_eq!(
        error.kind(),
        claw_application::composition::SubsystemErrorKind::NotFound
    );
    assert_eq!(
        error.detail(),
        "workspace.read is not available to this turn"
    );

    assert_eq!(daemon.tools().invocations().len(), 1);
    assert_eq!(daemon.persistence().turns_for(&id).len(), 1);

    assert!(daemon.stop().await.expect("the daemon stops").is_clean());
}

#[tokio::test]
async fn a_principal_without_a_capability_cannot_run_the_tool_that_needs_it() {
    let clock = Arc::new(SteppedClock::new());
    let mut daemon = started(Arc::clone(&clock)).await;
    let reader = Principal::new(
        "reader",
        CapabilitySet::from_capabilities([Capability::Network, Capability::ReadWorkspace]),
    );
    let write = ToolName::new("workspace.write").expect("the literal satisfies the grammar");

    daemon.transport().push_reply(ProviderReply::new(
        "writing".to_owned(),
        vec![request_tool(&write, "{}")],
    ));

    let error = daemon
        .run_turn(
            &reader,
            &session("no-write"),
            "write",
            &RecordingSink::default(),
        )
        .await
        .expect_err("the write capability was never held");

    assert_eq!(
        error.kind(),
        claw_application::composition::SubsystemErrorKind::Denied
    );
    assert_eq!(daemon.tools().invocations().len(), 0);

    assert!(daemon.stop().await.expect("the daemon stops").is_clean());
}

#[tokio::test]
async fn context_assembly_sees_the_session_revision_of_the_turn_it_is_serving() {
    let clock = Arc::new(SteppedClock::new());
    let mut daemon = started(Arc::clone(&clock)).await;
    let id = session("context");

    daemon
        .run_turn(&operator(), &id, "first", &RecordingSink::default())
        .await
        .expect("the first turn completes");
    daemon
        .run_turn(&operator(), &id, "second", &RecordingSink::default())
        .await
        .expect("the second turn completes");

    let calls = daemon.transport().calls();
    assert_eq!(calls.len(), 2);
    assert_eq!(calls[0].context_items, 3, "header, one note and the prompt");
    assert_eq!(calls[1].context_items, 3);

    daemon.context().remember("the operator likes tables");

    daemon
        .run_turn(&operator(), &id, "third", &RecordingSink::default())
        .await
        .expect("the third turn completes");

    assert_eq!(daemon.transport().calls()[2].context_items, 4);

    assert!(daemon.stop().await.expect("the daemon stops").is_clean());
}

#[tokio::test]
async fn a_provider_destination_is_resolved_for_every_turn_rather_than_once() {
    let clock = Arc::new(SteppedClock::new());
    let mut daemon = started(Arc::clone(&clock)).await;
    let id = session("resolutions");

    // One resolution happened while provisioning the credential at start-up.
    assert_eq!(daemon.providers().resolutions(), 1);

    daemon
        .run_turn(&operator(), &id, "first", &RecordingSink::default())
        .await
        .expect("the first turn completes");
    assert_eq!(daemon.providers().resolutions(), 2);

    daemon
        .run_turn(&operator(), &id, "second", &RecordingSink::default())
        .await
        .expect("the second turn completes");
    assert_eq!(daemon.providers().resolutions(), 3);

    assert!(daemon.stop().await.expect("the daemon stops").is_clean());
}

#[tokio::test]
async fn stopping_a_daemon_that_never_started_is_rejected_rather_than_silently_accepted() {
    let mut daemon = Daemon::builder()
        .clock(Arc::new(SteppedClock::new()) as Arc<dyn Clock>)
        .build()
        .expect("the composition is orderable");

    assert_eq!(daemon.phase(), LifecyclePhase::Created);

    let error = daemon
        .stop()
        .await
        .expect_err("there is nothing to quiesce");

    assert_eq!(
        error.to_string(),
        "illegal lifecycle transition: created -> draining"
    );
    assert_eq!(daemon.phase(), LifecyclePhase::Created);
}

#[tokio::test]
async fn the_turn_deadline_comes_from_configuration_read_at_the_start_of_the_turn() {
    let clock = Arc::new(SteppedClock::new());
    let mut daemon = started(Arc::clone(&clock)).await;

    let before = daemon.config().generation();
    daemon
        .config()
        .replace(claw_application::composition::RuntimeSettings::new(
            Vec::new(),
            claw_application::composition::ProviderName::new("primary").expect("literal"),
            claw_application::composition::ModelName::new("standard").expect("literal"),
            1,
            Duration::from_secs(1),
            Duration::from_millis(50),
        ));

    assert_eq!(daemon.config().generation(), before + 1);

    daemon
        .run_turn(
            &operator(),
            &session("reconfigured"),
            "hi",
            &RecordingSink::default(),
        )
        .await
        .expect("the turn uses the new settings without a restart");

    assert!(daemon.stop().await.expect("the daemon stops").is_clean());
}

/// A subsystem supplied from outside the daemon, standing in for a real
/// ingress that owns a bound socket.
///
/// Records every lifecycle callback so the test can prove the daemon drove it,
/// and spawns one background task through the context's spawner so the task
/// ledger has something to account for.
#[derive(Debug, Default)]
struct ExternalIngress {
    events: Mutex<Vec<&'static str>>,
}

impl ExternalIngress {
    fn id() -> SubsystemId {
        SubsystemId::new("external-ingress").expect("a valid subsystem id")
    }

    fn record(&self, event: &'static str) {
        self.events
            .lock()
            .expect("the recorder is usable")
            .push(event);
    }

    fn events(&self) -> Vec<&'static str> {
        self.events.lock().expect("the recorder is usable").clone()
    }
}

impl Subsystem for ExternalIngress {
    fn descriptor(&self) -> SubsystemDescriptor {
        // Declares an edge on the engine, so the plan must place it last even
        // though it is added to the builder before start is ever called.
        SubsystemDescriptor::new(Self::id(), SubsystemKind::Ingress)
            .depends_on(well_known::engine())
    }

    fn initialize<'a>(
        &'a self,
        _context: &'a StartContext,
    ) -> BoxFuture<'a, Result<(), SubsystemError>> {
        Box::pin(async move {
            self.record("initialize");
            Ok(())
        })
    }

    fn start<'a>(
        &'a self,
        context: &'a StartContext,
    ) -> BoxFuture<'a, Result<ServiceHandle, SubsystemError>> {
        Box::pin(async move {
            self.record("start");

            let shutdown = context.shutdown();
            context.spawner().spawn(
                "external-ingress",
                Box::pin(async move {
                    shutdown.triggered().await;
                }),
            )?;

            Ok(ServiceHandle::inert(Self::id()))
        })
    }

    fn shutdown<'a>(&'a self) -> BoxFuture<'a, Result<(), SubsystemError>> {
        Box::pin(async move {
            self.record("shutdown");
            Ok(())
        })
    }
}

/// A caller must be able to add a subsystem the daemon does not build itself.
///
/// This is the seam an HTTP server that owns a real listener plugs into: the
/// daemon starts it, orders it by its declared dependencies, counts its task,
/// and shuts it down with everything else.
#[tokio::test]
async fn an_externally_supplied_subsystem_is_started_ordered_and_shut_down() {
    let ingress = Arc::new(ExternalIngress::default());
    let mut daemon = Daemon::builder()
        .clock(Arc::new(SteppedClock::new()))
        .with_subsystem(Arc::clone(&ingress) as Arc<dyn Subsystem>)
        .build()
        .expect("the composition builds with an added subsystem");

    let order = daemon.start_order();
    let position = order
        .iter()
        .position(|id| id == "external-ingress")
        .expect("the added subsystem is in the plan");
    let engine = order
        .iter()
        .position(|id| id == well_known::engine().as_str())
        .expect("the engine is in the plan");

    assert!(
        engine < position,
        "the declared dependency did not order the added subsystem: {order:?}"
    );

    let handles = daemon.start().await.expect("the daemon starts");
    assert!(
        handles
            .iter()
            .any(|handle| handle.subsystem().as_str() == "external-ingress"),
        "the added subsystem reported no service handle"
    );
    assert_eq!(ingress.events(), vec!["initialize", "start"]);

    let summary = daemon.stop().await.expect("the daemon stops");

    assert_eq!(ingress.events(), vec!["initialize", "start", "shutdown"]);
    assert_eq!(
        summary.tasks().terminated(),
        summary.tasks().spawned(),
        "the added subsystem's task was not joined"
    );
    assert!(
        summary.tasks().spawned() > 0,
        "no task was spawned, so the join assertion above proves nothing"
    );
}

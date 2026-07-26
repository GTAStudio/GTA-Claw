//! End-to-end tests that drive this server through the real `claw-gateway-client`.

use std::io::ErrorKind;
use std::sync::Arc;
use std::time::Duration;

use claw_gateway::{
    CredentialPolicy, DeviceDirectory, Exposure, GatewayServer, GatewayServerConfig, Grant,
    ServerHandle, ServerLimits, ServerTimeouts, StaticAuthenticator,
};
use claw_gateway_client::{
    GatewayClient, GatewayClientConfig, GatewayClientError, ProtocolFailure, ReconnectPolicy,
};
use claw_protocol::gateway::{
    ClientId, ClientMode, ConnectErrorDetailCode, GatewayMethodName, OperatorScope,
    PREAUTH_MAX_FRAME_BYTES, ProtocolVersion, RequestId, Role, resolve_core_method,
};
use claw_security::authorization::{Role as SecurityRole, Scope, ScopeSet};
use claw_security::identity::DeviceIdentity;
use rand_chacha::ChaCha20Rng;
use rand_chacha::rand_core::SeedableRng;
use serde_json::{Value, json};
use tokio::net::TcpStream;
use url::Url;

/// Deterministically derives one in-memory device identity from a seed byte.
fn device(seed: u8) -> Arc<DeviceIdentity> {
    let mut rng = ChaCha20Rng::from_seed([seed; 32]);
    Arc::new(DeviceIdentity::generate(&mut rng))
}

/// Server configuration with a fast tick so event tests do not idle.
fn config() -> GatewayServerConfig {
    GatewayServerConfig {
        server_version: "test-gateway".to_owned(),
        limits: ServerLimits::default(),
        timeouts: ServerTimeouts {
            tick_interval: Duration::from_millis(60),
            ..ServerTimeouts::default()
        },
        exposure: Exposure::LoopbackOnly,
    }
}

async fn start(authenticator: StaticAuthenticator) -> ServerHandle {
    start_with_devices(authenticator).await.0
}

/// Starts a server whose closing grace is short enough that a test can outlive
/// it, which is what makes quiescing distinguishable from a deferred shutdown.
async fn start_with_close_grace(
    authenticator: StaticAuthenticator,
    close: Duration,
) -> ServerHandle {
    let devices = authenticator.devices();
    let mut configuration = config();
    configuration.timeouts.close = close;
    GatewayServer::new(configuration, Arc::new(authenticator), Arc::new(devices))
        .expect("the configuration and registry are valid")
        .bind("127.0.0.1:0".parse().expect("loopback address parses"))
        .await
        .expect("an ephemeral loopback port is available")
        .start()
}

/// Starts a server and also hands back the live device directory, so a test can
/// change a pairing while a connection is open.
async fn start_with_devices(authenticator: StaticAuthenticator) -> (ServerHandle, DeviceDirectory) {
    let devices = authenticator.devices();
    let handle = GatewayServer::new(config(), Arc::new(authenticator), Arc::new(devices.clone()))
        .expect("the configuration and registry are valid")
        .bind("127.0.0.1:0".parse().expect("loopback address parses"))
        .await
        .expect("an ephemeral loopback port is available")
        .start();
    (handle, devices)
}

fn endpoint(handle: &ServerHandle) -> Url {
    Url::parse(&format!(
        "ws://127.0.0.1:{}/",
        handle.local_address().port()
    ))
    .expect("the loopback endpoint parses")
}

fn client_config(
    handle: &ServerHandle,
    identity: Arc<DeviceIdentity>,
    role: SecurityRole,
    scopes: &[Scope],
) -> GatewayClientConfig {
    let mut config = GatewayClientConfig::new(endpoint(handle), identity);
    config.role = role;
    config.scopes = ScopeSet::from_scopes(scopes.iter().copied());
    config.reconnect = ReconnectPolicy::Never;
    config.timeouts.request = Duration::from_secs(5);
    config
}

/// Decodes a successful response payload into plain JSON.
fn payload(frame: &claw_protocol::gateway::ResponseFrame) -> Value {
    let opaque = frame
        .payload()
        .value()
        .expect("a successful response carries a payload");
    serde_json::from_str(opaque.as_json()).expect("the payload is valid JSON")
}

fn request_id(value: &str) -> RequestId {
    RequestId::new(value, PREAUTH_MAX_FRAME_BYTES).expect("the request identity is bounded")
}

fn method(name: &str) -> GatewayMethodName {
    GatewayMethodName::Core(resolve_core_method(name).expect("the method is catalogued"))
}

#[tokio::test]
async fn an_operator_completes_the_v4_handshake_and_calls_health() {
    let identity = device(11);
    let wire_id = identity.device_id().gateway_wire_id();
    let handle = start(
        StaticAuthenticator::new(CredentialPolicy::None, Arc::new(claw_gateway::SystemClock))
            .with_paired_device(
                wire_id.clone(),
                Grant::new(Role::Operator, [OperatorScope::Read]),
            ),
    )
    .await;

    let (client, _events) = GatewayClient::start(client_config(
        &handle,
        Arc::clone(&identity),
        SecurityRole::Operator,
        &[Scope::OperatorRead],
    ))
    .expect("the client configuration is valid");
    let ready = client.wait_ready().await.expect("the handshake succeeds");

    assert_eq!(ready.info.protocol, ProtocolVersion::new(4).unwrap());
    assert_eq!(ready.info.server_version, "test-gateway");
    assert_eq!(ready.info.role, "operator");
    assert_eq!(ready.info.scopes.as_ref(), ["operator.read".to_owned()]);
    assert_eq!(ready.info.advertised_method_count, 258);
    assert_eq!(ready.info.advertised_event_count, 33);
    assert_eq!(ready.info.max_payload_bytes, 26_214_400);

    let response = client
        .request(request_id("health-1"), method("health"), &json!({}))
        .await
        .expect("the health call completes");
    assert!(response.ok());
    assert_eq!(response.error(), None);
    let body = payload(&response);
    assert_eq!(body["ok"], json!(true));
    assert_eq!(body["protocol"], json!(4));
    assert_eq!(body["version"], json!("test-gateway"));

    let response = client
        .request(
            request_id("identity-1"),
            method("gateway.identity.get"),
            &json!({}),
        )
        .await
        .expect("the identity call completes");
    assert!(response.ok());
    let body = payload(&response);
    assert_eq!(body["role"], json!("operator"));
    assert_eq!(body["scopes"], json!(["operator.read"]));
    assert_eq!(body["deviceId"], json!(wire_id));

    client.shutdown().await.expect("the client stops cleanly");
    handle.shutdown().await;
}

#[tokio::test]
async fn a_node_is_admitted_on_the_protocol_v3_compatibility_window() {
    let identity = device(12);
    let handle = start(
        StaticAuthenticator::new(CredentialPolicy::None, Arc::new(claw_gateway::SystemClock))
            .with_paired_device(
                identity.device_id().gateway_wire_id(),
                Grant::new(Role::Node, []),
            ),
    )
    .await;

    let mut config = client_config(&handle, Arc::clone(&identity), SecurityRole::Node, &[]);
    config.client.id = ClientId::NodeHost;
    config.client.mode = ClientMode::Node;
    config.min_protocol = ProtocolVersion::new(3).unwrap();
    config.max_protocol = ProtocolVersion::new(3).unwrap();

    let (client, _events) = GatewayClient::start(config).expect("the configuration is valid");
    let ready = client
        .wait_ready()
        .await
        .expect("a v3 node is inside the compatibility window");
    assert_eq!(ready.info.role, "node");
    assert_eq!(ready.info.protocol, ProtocolVersion::new(4).unwrap());

    let response = client
        .request(request_id("node-health"), method("health"), &json!({}))
        .await
        .expect("health is reachable from a node");
    assert!(response.ok());

    let response = client
        .request(
            request_id("node-denied"),
            method("system-presence"),
            &json!({}),
        )
        .await
        .expect("the server answers with a typed error");
    assert!(!response.ok());
    let error = response.error().expect("a denial carries an error shape");
    assert_eq!(error.code.as_str(), "UNAUTHORIZED");

    client.shutdown().await.expect("the client stops cleanly");
    handle.shutdown().await;
}

#[tokio::test]
async fn a_probe_is_admitted_on_the_protocol_v3_compatibility_window() {
    let identity = device(13);
    let handle = start(
        StaticAuthenticator::new(CredentialPolicy::None, Arc::new(claw_gateway::SystemClock))
            .with_paired_device(
                identity.device_id().gateway_wire_id(),
                Grant::new(Role::Operator, [OperatorScope::Read]),
            ),
    )
    .await;

    let mut config = client_config(
        &handle,
        Arc::clone(&identity),
        SecurityRole::Operator,
        &[Scope::OperatorRead],
    );
    config.client.id = ClientId::Probe;
    config.client.mode = ClientMode::Probe;
    config.min_protocol = ProtocolVersion::new(3).unwrap();
    config.max_protocol = ProtocolVersion::new(3).unwrap();

    let (client, _events) = GatewayClient::start(config).expect("the configuration is valid");
    let ready = client
        .wait_ready()
        .await
        .expect("a v3 probe is inside the compatibility window");
    assert_eq!(ready.info.role, "operator");

    client.shutdown().await.expect("the client stops cleanly");
    handle.shutdown().await;
}

#[tokio::test]
async fn a_general_client_is_refused_the_node_window_version() {
    let identity = device(25);
    let handle = start(
        StaticAuthenticator::new(CredentialPolicy::None, Arc::new(claw_gateway::SystemClock))
            .with_paired_device(
                identity.device_id().gateway_wire_id(),
                Grant::new(Role::Operator, [OperatorScope::Read]),
            ),
    )
    .await;

    let mut config = client_config(
        &handle,
        Arc::clone(&identity),
        SecurityRole::Operator,
        &[Scope::OperatorRead],
    );
    config.min_protocol = ProtocolVersion::new(3).unwrap();
    config.max_protocol = ProtocolVersion::new(3).unwrap();

    let (client, _events) = GatewayClient::start(config).expect("the configuration is valid");
    let error = client
        .wait_ready()
        .await
        .expect_err("v3 is reserved for authenticated node and probe clients");
    match error {
        GatewayClientError::Protocol(ProtocolFailure::WebSocketProtocol(category)) => {
            assert_eq!(category, "handshake rejected");
        }
        other => panic!("expected a rejected handshake, got {other}"),
    }

    handle.shutdown().await;
}

#[tokio::test]
async fn claiming_the_node_role_without_node_client_mode_cannot_enter_the_v3_window() {
    let identity = device(26);
    let handle = start(
        StaticAuthenticator::new(CredentialPolicy::None, Arc::new(claw_gateway::SystemClock))
            .with_paired_device(
                identity.device_id().gateway_wire_id(),
                Grant::new(Role::Node, []),
            ),
    )
    .await;

    let mut config = client_config(&handle, Arc::clone(&identity), SecurityRole::Node, &[]);
    config.client.id = ClientId::Test;
    config.client.mode = ClientMode::Test;
    config.min_protocol = ProtocolVersion::new(3).unwrap();
    config.max_protocol = ProtocolVersion::new(3).unwrap();

    let (client, _events) = GatewayClient::start(config).expect("the configuration is valid");
    let error = client
        .wait_ready()
        .await
        .expect_err("the v3 window requires genuine node client mode, not just the node role");
    match error {
        GatewayClientError::Protocol(ProtocolFailure::WebSocketProtocol(category)) => {
            assert_eq!(category, "handshake rejected");
        }
        other => panic!("expected a rejected handshake, got {other}"),
    }

    handle.shutdown().await;
}

#[tokio::test]
async fn a_client_below_the_window_is_rejected_as_a_protocol_mismatch() {
    let identity = device(14);
    let handle = start(
        StaticAuthenticator::new(CredentialPolicy::None, Arc::new(claw_gateway::SystemClock))
            .with_paired_device(
                identity.device_id().gateway_wire_id(),
                Grant::new(Role::Operator, [OperatorScope::Read]),
            ),
    )
    .await;

    let mut config = client_config(
        &handle,
        Arc::clone(&identity),
        SecurityRole::Operator,
        &[Scope::OperatorRead],
    );
    config.min_protocol = ProtocolVersion::new(2).unwrap();
    config.max_protocol = ProtocolVersion::new(2).unwrap();

    let (client, _events) = GatewayClient::start(config).expect("the configuration is valid");
    let error = client
        .wait_ready()
        .await
        .expect_err("protocol 2 is outside the N-1 window");
    match error {
        GatewayClientError::Protocol(ProtocolFailure::WebSocketProtocol(category)) => {
            assert_eq!(category, "handshake rejected");
        }
        other => panic!("expected a rejected handshake, got {other}"),
    }

    handle.shutdown().await;
}

#[tokio::test]
async fn an_unpaired_device_is_told_that_pairing_is_required() {
    let handle = start(StaticAuthenticator::new(
        CredentialPolicy::None,
        Arc::new(claw_gateway::SystemClock),
    ))
    .await;

    let (client, _events) = GatewayClient::start(client_config(
        &handle,
        device(15),
        SecurityRole::Operator,
        &[Scope::OperatorRead],
    ))
    .expect("the configuration is valid");
    let error = client
        .wait_ready()
        .await
        .expect_err("an unpaired device cannot authenticate");
    match error {
        GatewayClientError::Authentication(failure) => {
            assert_eq!(
                failure.detail_code(),
                Some(ConnectErrorDetailCode::PairingRequired)
            );
            assert!(!failure.device_retry_recommended());
        }
        other => panic!("expected an authentication failure, got {other}"),
    }

    handle.shutdown().await;
}

#[tokio::test]
async fn requesting_scopes_beyond_the_grant_is_rejected() {
    let identity = device(16);
    let handle = start(
        StaticAuthenticator::new(CredentialPolicy::None, Arc::new(claw_gateway::SystemClock))
            .with_paired_device(
                identity.device_id().gateway_wire_id(),
                Grant::new(Role::Operator, [OperatorScope::Read]),
            ),
    )
    .await;

    let (client, _events) = GatewayClient::start(client_config(
        &handle,
        Arc::clone(&identity),
        SecurityRole::Operator,
        &[Scope::OperatorRead, Scope::OperatorAdmin],
    ))
    .expect("the configuration is valid");
    let error = client
        .wait_ready()
        .await
        .expect_err("scope escalation must not be granted");
    match error {
        GatewayClientError::Authentication(failure) => {
            assert_eq!(
                failure.detail_code(),
                Some(ConnectErrorDetailCode::AuthScopeMismatch)
            );
        }
        other => panic!("expected an authentication failure, got {other}"),
    }

    handle.shutdown().await;
}

#[tokio::test]
async fn a_read_only_operator_cannot_reach_write_or_admin_methods() {
    let identity = device(17);
    let handle = start(
        StaticAuthenticator::new(CredentialPolicy::None, Arc::new(claw_gateway::SystemClock))
            .with_paired_device(
                identity.device_id().gateway_wire_id(),
                Grant::new(Role::Operator, [OperatorScope::Read]),
            ),
    )
    .await;

    let (client, _events) = GatewayClient::start(client_config(
        &handle,
        Arc::clone(&identity),
        SecurityRole::Operator,
        &[Scope::OperatorRead],
    ))
    .expect("the configuration is valid");
    client.wait_ready().await.expect("the handshake succeeds");

    for (id, name) in [
        ("deny-write", "sessions.create"),
        ("deny-admin", "sessions.delete"),
        ("deny-config", "config.set"),
    ] {
        let response = client
            .request(
                request_id(id),
                method(name),
                &json!({ "id": "s1", "agentId": "a1" }),
            )
            .await
            .expect("the server answers");
        assert!(!response.ok(), "`{name}` must be denied");
        let error = response.error().expect("a denial carries an error shape");
        assert_eq!(error.code.as_str(), "UNAUTHORIZED");
        assert_eq!(error.retryable, Some(false));
    }

    client.shutdown().await.expect("the client stops cleanly");
    handle.shutdown().await;
}

#[tokio::test]
async fn a_catalogued_method_without_behavior_answers_not_implemented() {
    let identity = device(18);
    let handle = start(
        StaticAuthenticator::new(CredentialPolicy::None, Arc::new(claw_gateway::SystemClock))
            .with_paired_device(
                identity.device_id().gateway_wire_id(),
                Grant::new(Role::Operator, [OperatorScope::Admin]),
            ),
    )
    .await;

    let (client, _events) = GatewayClient::start(client_config(
        &handle,
        Arc::clone(&identity),
        SecurityRole::Operator,
        &[Scope::OperatorAdmin],
    ))
    .expect("the configuration is valid");
    client.wait_ready().await.expect("the handshake succeeds");

    let response = client
        .request(
            request_id("unimplemented-1"),
            method("diagnostics.stability"),
            &json!({}),
        )
        .await
        .expect("the server answers");
    assert!(!response.ok());
    let error = response.error().expect("a typed error is returned");
    assert_eq!(error.code.as_str(), "NOT_IMPLEMENTED");
    assert_eq!(error.retryable, Some(false));
    let details: Value = serde_json::from_str(
        error
            .details
            .value()
            .expect("the unimplemented error carries details")
            .as_json(),
    )
    .expect("details are valid JSON");
    assert_eq!(details["method"], json!("diagnostics.stability"));
    assert_eq!(details["scope"], json!("operator.read"));
    assert_eq!(details["catalogued"], json!(true));

    client.shutdown().await.expect("the client stops cleanly");
    handle.shutdown().await;
}

#[tokio::test]
async fn sessions_round_trip_through_create_get_patch_list_and_delete() {
    let identity = device(19);
    let handle = start(
        StaticAuthenticator::new(CredentialPolicy::None, Arc::new(claw_gateway::SystemClock))
            .with_paired_device(
                identity.device_id().gateway_wire_id(),
                Grant::new(Role::Operator, [OperatorScope::Admin]),
            ),
    )
    .await;

    let (client, _events) = GatewayClient::start(client_config(
        &handle,
        Arc::clone(&identity),
        SecurityRole::Operator,
        &[Scope::OperatorAdmin],
    ))
    .expect("the configuration is valid");
    client.wait_ready().await.expect("the handshake succeeds");

    let created = client
        .request(
            request_id("create"),
            method("sessions.create"),
            &json!({ "id": "session-a", "agentId": "agent-a", "title": "first" }),
        )
        .await
        .expect("create completes");
    assert!(created.ok());
    let created = payload(&created);
    assert_eq!(created["id"], json!("session-a"));
    assert_eq!(created["agentId"], json!("agent-a"));
    assert_eq!(created["title"], json!("first"));
    assert_eq!(created["revision"], json!(1));
    assert_eq!(created["archived"], json!(false));

    let duplicate = client
        .request(
            request_id("create-duplicate"),
            method("sessions.create"),
            &json!({ "id": "session-a", "agentId": "agent-a" }),
        )
        .await
        .expect("the server answers");
    assert!(!duplicate.ok());
    let error = duplicate.error().expect("a duplicate carries an error");
    assert_eq!(error.code.as_str(), "INVALID_REQUEST");
    assert_eq!(error.retryable, Some(false));
    let details: Value = serde_json::from_str(
        error
            .details
            .value()
            .expect("a conflict carries details")
            .as_json(),
    )
    .expect("details are valid JSON");
    assert_eq!(details, json!({ "conflict": "session-a" }));

    let patched = client
        .request(
            request_id("patch"),
            method("sessions.patch"),
            &json!({ "id": "session-a", "title": "second", "archived": true }),
        )
        .await
        .expect("patch completes");
    assert!(patched.ok());
    let patched = payload(&patched);
    assert_eq!(patched["title"], json!("second"));
    assert_eq!(patched["archived"], json!(true));
    assert_eq!(patched["revision"], json!(2));

    let listed = client
        .request(request_id("list"), method("sessions.list"), &json!({}))
        .await
        .expect("list completes");
    let listed = payload(&listed);
    assert_eq!(listed["count"], json!(1));
    assert_eq!(listed["sessions"][0]["id"], json!("session-a"));

    let deleted = client
        .request(
            request_id("delete"),
            method("sessions.delete"),
            &json!({ "id": "session-a" }),
        )
        .await
        .expect("delete completes");
    assert!(deleted.ok());

    let missing = client
        .request(
            request_id("get-missing"),
            method("sessions.get"),
            &json!({ "id": "session-a" }),
        )
        .await
        .expect("the server answers");
    assert!(missing.ok());
    assert_eq!(payload(&missing), json!({ "session": Value::Null }));

    let described = client
        .request(
            request_id("describe-missing"),
            method("sessions.describe"),
            &json!({ "id": "session-a" }),
        )
        .await
        .expect("the server answers");
    assert!(!described.ok());
    let error = described.error().expect("a miss carries an error shape");
    assert_eq!(error.code.as_str(), "NOT_FOUND");
    let details: Value = serde_json::from_str(
        error
            .details
            .value()
            .expect("a not-found error carries details")
            .as_json(),
    )
    .expect("details are valid JSON");
    assert_eq!(details, json!({ "kind": "session", "id": "session-a" }));

    client.shutdown().await.expect("the client stops cleanly");
    handle.shutdown().await;
}

#[tokio::test]
async fn broadcast_events_carry_strictly_consecutive_per_connection_sequences() {
    let first_identity = device(20);
    let second_identity = device(21);
    let handle = start(
        StaticAuthenticator::new(CredentialPolicy::None, Arc::new(claw_gateway::SystemClock))
            .with_paired_device(
                first_identity.device_id().gateway_wire_id(),
                Grant::new(Role::Operator, [OperatorScope::Admin]),
            )
            .with_paired_device(
                second_identity.device_id().gateway_wire_id(),
                Grant::new(Role::Operator, [OperatorScope::Admin]),
            ),
    )
    .await;

    let (first, mut first_events) = GatewayClient::start(client_config(
        &handle,
        Arc::clone(&first_identity),
        SecurityRole::Operator,
        &[Scope::OperatorAdmin],
    ))
    .expect("the configuration is valid");
    first.wait_ready().await.expect("the handshake succeeds");

    // The second connection joins after the first has already been serving, so
    // its sequence must still restart at one.
    let (second, mut second_events) = GatewayClient::start(client_config(
        &handle,
        Arc::clone(&second_identity),
        SecurityRole::Operator,
        &[Scope::OperatorAdmin],
    ))
    .expect("the configuration is valid");
    second.wait_ready().await.expect("the handshake succeeds");

    for index in 0_u32..3 {
        let response = first
            .request(
                request_id(&format!("create-{index}")),
                method("sessions.create"),
                &json!({ "id": format!("session-{index}"), "agentId": "agent" }),
            )
            .await
            .expect("create completes");
        assert!(response.ok());
    }

    let mut names = Vec::new();
    let mut sequences = Vec::new();
    while sequences.len() < 3 {
        let event = tokio::time::timeout(Duration::from_secs(5), first_events.recv())
            .await
            .expect("events arrive promptly")
            .expect("the event stream stays open");
        let frame = event.into_frame();
        sequences.push(
            frame
                .sequence()
                .expect("broadcast events carry a sequence")
                .get(),
        );
        names.push(frame.event().as_str().to_owned());
    }
    assert_eq!(sequences, vec![1, 2, 3]);
    assert!(
        names.iter().any(|name| name == "sessions.changed"),
        "expected the session lifecycle events, saw {names:?}"
    );

    let event = tokio::time::timeout(Duration::from_secs(5), second_events.recv())
        .await
        .expect("events arrive promptly")
        .expect("the event stream stays open");
    assert_eq!(
        event
            .frame()
            .sequence()
            .expect("broadcast events carry a sequence")
            .get(),
        1,
        "each connection numbers its own broadcast stream from one"
    );

    first.shutdown().await.expect("the client stops cleanly");
    second.shutdown().await.expect("the client stops cleanly");
    handle.shutdown().await;
}

#[tokio::test]
async fn presence_reports_every_live_authenticated_connection() {
    let operator = device(22);
    let node = device(23);
    let handle = start(
        StaticAuthenticator::new(CredentialPolicy::None, Arc::new(claw_gateway::SystemClock))
            .with_paired_device(
                operator.device_id().gateway_wire_id(),
                Grant::new(Role::Operator, [OperatorScope::Read]),
            )
            .with_paired_device(
                node.device_id().gateway_wire_id(),
                Grant::new(Role::Node, []),
            ),
    )
    .await;

    let (operator_client, _operator_events) = GatewayClient::start(client_config(
        &handle,
        Arc::clone(&operator),
        SecurityRole::Operator,
        &[Scope::OperatorRead],
    ))
    .expect("the configuration is valid");
    operator_client
        .wait_ready()
        .await
        .expect("the operator handshake succeeds");

    let mut node_config = client_config(&handle, Arc::clone(&node), SecurityRole::Node, &[]);
    node_config.client.id = ClientId::NodeHost;
    node_config.client.mode = ClientMode::Node;
    let (node_client, _node_events) =
        GatewayClient::start(node_config).expect("the configuration is valid");
    node_client
        .wait_ready()
        .await
        .expect("the node handshake succeeds");

    let response = operator_client
        .request(
            request_id("presence"),
            method("system-presence"),
            &json!({}),
        )
        .await
        .expect("presence completes");
    let body = payload(&response);
    let entries = body["entries"]
        .as_array()
        .expect("presence returns an array")
        .clone();
    assert_eq!(entries.len(), 2);

    let mut roles: Vec<String> = entries
        .iter()
        .map(|entry| {
            entry["role"]
                .as_str()
                .expect("presence entries carry a role")
                .to_owned()
        })
        .collect();
    roles.sort();
    assert_eq!(roles, vec!["node".to_owned(), "operator".to_owned()]);

    let device_ids: Vec<String> = entries
        .iter()
        .map(|entry| {
            entry["deviceId"]
                .as_str()
                .expect("presence entries carry a device id")
                .to_owned()
        })
        .collect();
    assert!(device_ids.contains(&operator.device_id().gateway_wire_id()));
    assert!(device_ids.contains(&node.device_id().gateway_wire_id()));

    let info = operator_client
        .request(request_id("info"), method("system.info"), &json!({}))
        .await
        .expect("system.info completes");
    let info = payload(&info);
    assert_eq!(info["connections"], json!(2));
    assert_eq!(info["nodes"], json!(1));
    assert_eq!(info["operators"], json!(1));

    operator_client
        .shutdown()
        .await
        .expect("the client stops cleanly");
    node_client
        .shutdown()
        .await
        .expect("the client stops cleanly");
    handle.shutdown().await;
}

#[tokio::test]
async fn a_shared_token_policy_refuses_a_client_that_presents_none() {
    let identity = device(24);
    let handle = start(
        StaticAuthenticator::new(
            CredentialPolicy::Token(secrecy::SecretString::from("correct horse".to_owned())),
            Arc::new(claw_gateway::SystemClock),
        )
        .with_paired_device(
            identity.device_id().gateway_wire_id(),
            Grant::new(Role::Operator, [OperatorScope::Read]),
        ),
    )
    .await;

    let (client, _events) = GatewayClient::start(client_config(
        &handle,
        Arc::clone(&identity),
        SecurityRole::Operator,
        &[Scope::OperatorRead],
    ))
    .expect("the configuration is valid");
    let error = client
        .wait_ready()
        .await
        .expect_err("a missing shared token is refused");
    match error {
        GatewayClientError::Authentication(failure) => assert_eq!(
            failure.detail_code(),
            Some(ConnectErrorDetailCode::AuthTokenMissing)
        ),
        other => panic!("expected an authentication failure, got {other}"),
    }

    handle.shutdown().await;
}
// ---------------------------------------------------------------------------
// Authorization is re-evaluated at the moment of every action, not snapshotted
// at the handshake and trusted forever.
// ---------------------------------------------------------------------------

#[tokio::test]
async fn withdrawing_a_pairing_closes_an_already_open_connection() {
    let identity = device(27);
    let wire_id = identity.device_id().gateway_wire_id();
    let (handle, devices) = start_with_devices(
        StaticAuthenticator::new(CredentialPolicy::None, Arc::new(claw_gateway::SystemClock))
            .with_paired_device(
                wire_id.clone(),
                Grant::new(Role::Operator, [OperatorScope::Admin]),
            ),
    )
    .await;

    let (client, _events) = GatewayClient::start(client_config(
        &handle,
        Arc::clone(&identity),
        SecurityRole::Operator,
        &[Scope::OperatorAdmin],
    ))
    .expect("the configuration is valid");
    let ready = client.wait_ready().await.expect("the handshake succeeds");
    let live_epoch = ready.epoch.get();

    // Prove the connection really is privileged before anything is withdrawn.
    let response = client
        .request(
            request_id("before-revoke"),
            method("sessions.create"),
            &json!({ "id": "s-live", "agentId": "a-1" }),
        )
        .await
        .expect("the server answers");
    assert!(response.ok(), "the admin grant must work before revocation");

    assert!(
        devices.revoke(&wire_id),
        "the fixture device really was paired"
    );

    // The socket is already authenticated; nothing about it changed. Only the
    // directory did, and that alone must end the connection's ability to act.
    let outcome = client
        .request(
            request_id("after-revoke"),
            method("sessions.create"),
            &json!({ "id": "s-dead", "agentId": "a-1" }),
        )
        .await;
    match outcome {
        Err(GatewayClientError::ConnectionChanged { expected }) => assert_eq!(
            expected.get(),
            live_epoch,
            "the torn-down connection must be the one that held the revoked grant"
        ),
        Err(
            GatewayClientError::DisconnectedNotReplayed
            | GatewayClientError::NotReady
            | GatewayClientError::Cancelled
            | GatewayClientError::Transport(_),
        ) => {}
        Err(other) => panic!(
            "the connection must end because authorization was withdrawn, not for another reason: \
             {other}"
        ),
        Ok(response) => panic!(
            "a revoked device was still served: ok={} error={:?}",
            response.ok(),
            response.error()
        ),
    }

    handle.shutdown().await;
}

#[tokio::test]
async fn narrowing_a_grant_takes_the_lost_scope_away_from_an_open_connection() {
    let identity = device(28);
    let wire_id = identity.device_id().gateway_wire_id();
    let (handle, devices) = start_with_devices(
        StaticAuthenticator::new(CredentialPolicy::None, Arc::new(claw_gateway::SystemClock))
            .with_paired_device(
                wire_id.clone(),
                Grant::new(
                    Role::Operator,
                    [
                        OperatorScope::Read,
                        OperatorScope::Write,
                        OperatorScope::Admin,
                    ],
                ),
            ),
    )
    .await;

    let (client, _events) = GatewayClient::start(client_config(
        &handle,
        Arc::clone(&identity),
        SecurityRole::Operator,
        &[
            Scope::OperatorRead,
            Scope::OperatorWrite,
            Scope::OperatorAdmin,
        ],
    ))
    .expect("the configuration is valid");
    client.wait_ready().await.expect("the handshake succeeds");

    let response = client
        .request(
            request_id("admin-before"),
            method("sessions.delete"),
            &json!({ "id": "s-absent" }),
        )
        .await
        .expect("the server answers");
    let before = response
        .error()
        .map(|error| error.code.as_str().to_owned())
        .unwrap_or_else(|| "OK".to_owned());
    assert_ne!(
        before, "UNAUTHORIZED",
        "the admin-classified method must be reachable before narrowing"
    );

    // Same device, same role, strictly fewer scopes.
    devices.pair(
        wire_id.clone(),
        Grant::new(Role::Operator, [OperatorScope::Read]),
    );

    let response = client
        .request(
            request_id("admin-after"),
            method("sessions.delete"),
            &json!({ "id": "s-absent" }),
        )
        .await
        .expect("narrowing must not close the connection");
    assert!(!response.ok());
    assert_eq!(
        response
            .error()
            .expect("a denial carries an error shape")
            .code
            .as_str(),
        "UNAUTHORIZED"
    );

    // The scope it kept still works, so this narrowed rather than severed.
    let response = client
        .request(request_id("read-after"), method("health"), &json!({}))
        .await
        .expect("the connection is still usable");
    assert!(response.ok());

    client.shutdown().await.expect("the client stops cleanly");
    handle.shutdown().await;
}

#[tokio::test]
async fn widening_a_grant_never_promotes_an_already_open_connection() {
    let identity = device(29);
    let wire_id = identity.device_id().gateway_wire_id();
    let (handle, devices) = start_with_devices(
        StaticAuthenticator::new(CredentialPolicy::None, Arc::new(claw_gateway::SystemClock))
            .with_paired_device(
                wire_id.clone(),
                Grant::new(Role::Operator, [OperatorScope::Read]),
            ),
    )
    .await;

    let (client, _events) = GatewayClient::start(client_config(
        &handle,
        Arc::clone(&identity),
        SecurityRole::Operator,
        &[Scope::OperatorRead],
    ))
    .expect("the configuration is valid");
    client.wait_ready().await.expect("the handshake succeeds");

    // Grant the device far more than it proved at connect time.
    devices.pair(
        wire_id.clone(),
        Grant::new(
            Role::Operator,
            [
                OperatorScope::Read,
                OperatorScope::Write,
                OperatorScope::Admin,
            ],
        ),
    );

    // Re-checking authorization must never be a promotion path: this
    // connection presented `operator.read` and signed for `operator.read`, so
    // that is all it may ever exercise, however generous the directory becomes.
    for (id, name) in [
        ("widen-write", "sessions.create"),
        ("widen-admin", "sessions.delete"),
        ("widen-config", "config.set"),
    ] {
        let response = client
            .request(
                request_id(id),
                method(name),
                &json!({ "id": "s-widen", "agentId": "a-1" }),
            )
            .await
            .expect("the server answers");
        assert!(
            !response.ok(),
            "`{name}` was reached with a scope the connection never presented"
        );
        assert_eq!(
            response
                .error()
                .expect("a denial carries an error shape")
                .code
                .as_str(),
            "UNAUTHORIZED",
            "`{name}` must stay denied"
        );
    }

    client.shutdown().await.expect("the client stops cleanly");
    handle.shutdown().await;
}

#[tokio::test]
async fn changing_a_device_role_closes_its_open_operator_connection() {
    let identity = device(30);
    let wire_id = identity.device_id().gateway_wire_id();
    let (handle, devices) = start_with_devices(
        StaticAuthenticator::new(CredentialPolicy::None, Arc::new(claw_gateway::SystemClock))
            .with_paired_device(
                wire_id.clone(),
                Grant::new(Role::Operator, [OperatorScope::Admin]),
            ),
    )
    .await;

    let (client, _events) = GatewayClient::start(client_config(
        &handle,
        Arc::clone(&identity),
        SecurityRole::Operator,
        &[Scope::OperatorAdmin],
    ))
    .expect("the configuration is valid");
    let ready = client.wait_ready().await.expect("the handshake succeeds");
    let live_epoch = ready.epoch.get();

    devices.pair(wire_id.clone(), Grant::new(Role::Node, []));

    let outcome = client
        .request(
            request_id("after-role-change"),
            method("health"),
            &json!({}),
        )
        .await;
    match outcome {
        Err(GatewayClientError::ConnectionChanged { expected }) => assert_eq!(
            expected.get(),
            live_epoch,
            "the torn-down connection must be the operator connection that was re-roled"
        ),
        Err(
            GatewayClientError::DisconnectedNotReplayed
            | GatewayClientError::NotReady
            | GatewayClientError::Cancelled
            | GatewayClientError::Transport(_),
        ) => {}
        Err(other) => panic!("expected the connection to be cut off, got {other}"),
        Ok(response) => panic!(
            "a device re-roled underneath a live operator connection was still served: ok={}",
            response.ok()
        ),
    }

    handle.shutdown().await;
}

/// Quiescing is the ingress half of a graceful stop. The composition root stops
/// its edges before it drains the subsystems behind them, so the server has to
/// release the listener while every connection established beforehand keeps
/// answering. A server that closed live connections here, or one that kept
/// accepting, would each be unusable for that ordering in a different way, so
/// this asserts both halves against one running server.
#[tokio::test]
async fn quiescing_refuses_new_peers_while_an_established_connection_keeps_serving() {
    let identity = device(41);
    let wire_id = identity.device_id().gateway_wire_id();
    let handle = start(
        StaticAuthenticator::new(CredentialPolicy::None, Arc::new(claw_gateway::SystemClock))
            .with_paired_device(
                wire_id.clone(),
                Grant::new(Role::Operator, [OperatorScope::Read]),
            ),
    )
    .await;
    let port = handle.local_address().port();

    let (client, _events) = GatewayClient::start(client_config(
        &handle,
        Arc::clone(&identity),
        SecurityRole::Operator,
        &[Scope::OperatorRead],
    ))
    .expect("the client configuration is valid");
    client.wait_ready().await.expect("the handshake succeeds");

    // Establishes that the refusal below is caused by quiescing and not by the
    // port never having been connectable in the first place.
    let before = TcpStream::connect(("127.0.0.1", port))
        .await
        .expect("the listener completes a TCP handshake before quiescing");
    drop(before);

    handle.stop_accepting().await;

    let refused = TcpStream::connect(("127.0.0.1", port))
        .await
        .expect_err("a quiesced server must not complete a TCP handshake");
    assert_eq!(
        refused.kind(),
        ErrorKind::ConnectionRefused,
        "the listener must be released, not merely ignoring the connection"
    );

    let response = client
        .request(
            request_id("health-after-quiesce"),
            method("health"),
            &json!({}),
        )
        .await
        .expect("a connection established before quiescing still serves");
    assert!(response.ok());
    assert_eq!(response.error(), None);
    assert_eq!(payload(&response)["protocol"], json!(4));

    client.shutdown().await.expect("the client stops cleanly");
    handle.shutdown().await;
}

/// Quiescing must not become a way to keep a connection alive forever: the
/// shutdown that follows still has to close what quiescing deliberately spared.
#[tokio::test]
async fn shutting_down_a_quiesced_server_still_closes_the_connections_it_spared() {
    let identity = device(42);
    let wire_id = identity.device_id().gateway_wire_id();
    let handle = start(
        StaticAuthenticator::new(CredentialPolicy::None, Arc::new(claw_gateway::SystemClock))
            .with_paired_device(
                wire_id.clone(),
                Grant::new(Role::Operator, [OperatorScope::Read]),
            ),
    )
    .await;

    let (client, _events) = GatewayClient::start(client_config(
        &handle,
        Arc::clone(&identity),
        SecurityRole::Operator,
        &[Scope::OperatorRead],
    ))
    .expect("the client configuration is valid");
    client.wait_ready().await.expect("the handshake succeeds");

    handle.stop_accepting().await;
    let spared = client
        .request(request_id("health-spared"), method("health"), &json!({}))
        .await
        .expect("quiescing spares an established connection");
    assert!(spared.ok());

    handle.shutdown().await;

    let outcome = client
        .request(
            request_id("health-after-stop"),
            method("health"),
            &json!({}),
        )
        .await;
    match outcome {
        Err(
            GatewayClientError::ConnectionChanged { .. }
            | GatewayClientError::DisconnectedNotReplayed
            | GatewayClientError::NotReady
            | GatewayClientError::Cancelled
            | GatewayClientError::Transport(_)
            | GatewayClientError::RequestTimedOut(_),
        ) => {}
        Err(other) => panic!("the connection must end because the server stopped: {other}"),
        Ok(response) => panic!(
            "a shut-down server answered anyway: ok={} error={:?}",
            response.ok(),
            response.error()
        ),
    }
}

/// A composition root may quiesce an ingress it has already quiesced, because
/// shutdown can be reached from more than one path. The second call must return
/// rather than wait for a state change that has already happened.
#[tokio::test]
async fn quiescing_twice_is_idempotent_and_still_refuses_new_peers() {
    let handle = start(StaticAuthenticator::new(
        CredentialPolicy::None,
        Arc::new(claw_gateway::SystemClock),
    ))
    .await;
    let port = handle.local_address().port();

    handle.stop_accepting().await;
    handle.stop_accepting().await;

    let refused = TcpStream::connect(("127.0.0.1", port))
        .await
        .expect_err("the server is still quiesced after a repeated call");
    assert_eq!(refused.kind(), ErrorKind::ConnectionRefused);

    handle.shutdown().await;
}

/// Quiescing must not put a deadline on the connections it spared.
///
/// The accept loop's closing grace bounds a real shutdown's drain. If quiescing
/// entered that same bounded drain, a spared connection would still be aborted
/// once the grace elapsed — a shutdown merely deferred, not a quiesce. The two
/// are indistinguishable to any test that acts immediately after quiescing,
/// which is why this one deliberately outlives the grace before asking. That
/// difference is invisible with the default three-second grace, so this server
/// is built with a short one.
#[tokio::test]
async fn a_connection_spared_by_quiescing_outlives_the_closing_grace() {
    let grace = Duration::from_millis(150);
    let identity = device(43);
    let wire_id = identity.device_id().gateway_wire_id();
    let handle = start_with_close_grace(
        StaticAuthenticator::new(CredentialPolicy::None, Arc::new(claw_gateway::SystemClock))
            .with_paired_device(
                wire_id.clone(),
                Grant::new(Role::Operator, [OperatorScope::Read]),
            ),
        grace,
    )
    .await;

    let (client, _events) = GatewayClient::start(client_config(
        &handle,
        Arc::clone(&identity),
        SecurityRole::Operator,
        &[Scope::OperatorRead],
    ))
    .expect("the client configuration is valid");
    client.wait_ready().await.expect("the handshake succeeds");

    handle.stop_accepting().await;
    tokio::time::sleep(grace * 4).await;

    let response = client
        .request(
            request_id("health-outlives-grace"),
            method("health"),
            &json!({}),
        )
        .await
        .expect("quiescing spares a connection indefinitely, not until the closing grace");
    assert!(response.ok());
    assert_eq!(response.error(), None);
    assert_eq!(payload(&response)["protocol"], json!(4));

    client.shutdown().await.expect("the client stops cleanly");
    handle.shutdown().await;
}

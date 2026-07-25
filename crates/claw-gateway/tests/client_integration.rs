//! End-to-end tests that drive this server through the real `claw-gateway-client`.

use std::sync::Arc;
use std::time::Duration;

use claw_gateway::{
    CredentialPolicy, GatewayServer, GatewayServerConfig, Grant, ServerHandle, ServerLimits,
    ServerTimeouts, StaticAuthenticator,
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
    }
}

async fn start(authenticator: StaticAuthenticator) -> ServerHandle {
    GatewayServer::new(config(), Arc::new(authenticator))
        .expect("the configuration and registry are valid")
        .bind("127.0.0.1:0".parse().expect("loopback address parses"))
        .await
        .expect("an ephemeral loopback port is available")
        .start()
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

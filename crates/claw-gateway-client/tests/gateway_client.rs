//! Real in-process WebSocket coverage for the bounded Gateway client.

mod support;

use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::time::Duration;

use claw_gateway_client::{
    BackpressureError, ClientLimits, ClientMetadata, ClientRuntime, ClientTimeouts,
    ConnectionState, GatewayClient, GatewayClientConfig, GatewayClientError, GatewayCredential,
    ProtocolFailure, ReconnectPolicy, ResyncRequired, SystemRuntime,
};
use claw_protocol::gateway::{
    AUTHENTICATED_MAX_FRAME_BYTES, ClientId, ClientMode, Codec, CodecError, GatewayMethodName,
    ProtocolVersion, RequestId, TransportPhase, resolve_core_method,
};
use claw_security::authorization::{Role, Scope, ScopeSet};
use claw_security::identity::DeviceIdentity;
use fastwebsockets::{Frame, OpCode, Payload};
use rand_chacha::ChaCha20Rng;
use rand_chacha::rand_core::SeedableRng;
use secrecy::{ExposeSecret, SecretString};
use serde::Serialize;
use serde::ser::{SerializeSeq, Serializer};
use serde_json::json;
use tokio::sync::{Mutex, Notify, Semaphore, oneshot};
use url::Url;

use support::{
    TestGateway, complete_handshake, complete_handshake_with_tick_interval, handler,
    raw_stalled_server, receive_connect, receive_request, send_challenge, send_connect_error,
    send_connect_error_details, send_hello_with_device_token, send_hello_with_tick_interval,
    send_json, send_raw_text, send_response, wait_for_close,
};

fn identity() -> Arc<DeviceIdentity> {
    let mut rng = ChaCha20Rng::from_seed([19_u8; 32]);
    Arc::new(DeviceIdentity::generate(&mut rng))
}

fn config(url: Url) -> GatewayClientConfig {
    let mut config = GatewayClientConfig::new(url, identity());
    config.credential =
        GatewayCredential::Token(SecretString::from("test-shared-secret".to_owned()));
    config.scopes = ScopeSet::from_scopes([Scope::OperatorRead]);
    config.reconnect = ReconnectPolicy::Never;
    config.timeouts = ClientTimeouts {
        connect: Duration::from_secs(2),
        authentication: Duration::from_secs(2),
        request: Duration::from_secs(2),
        shutdown: Duration::from_secs(1),
    };
    config
}

fn request_id(value: &str) -> RequestId {
    RequestId::new(value, AUTHENTICATED_MAX_FRAME_BYTES).expect("request id")
}

fn health_method() -> GatewayMethodName {
    GatewayMethodName::Core(resolve_core_method("health").expect("health registry"))
}

fn side_effect_method() -> GatewayMethodName {
    GatewayMethodName::Core(resolve_core_method("config.set").expect("config.set registry"))
}

struct WriteGateRuntime {
    system: SystemRuntime,
    gate_next: AtomicBool,
    entered: Notify,
    release: Arc<Semaphore>,
}

impl WriteGateRuntime {
    fn new() -> Arc<Self> {
        Arc::new(Self {
            system: SystemRuntime::default(),
            gate_next: AtomicBool::new(true),
            entered: Notify::new(),
            release: Arc::new(Semaphore::new(0)),
        })
    }

    async fn wait_until_blocked(&self) {
        tokio::time::timeout(Duration::from_secs(2), self.entered.notified())
            .await
            .expect("writer reached deterministic gate");
    }

    fn unblock(&self) {
        self.release.add_permits(1);
    }
}

impl ClientRuntime for WriteGateRuntime {
    fn unix_millis(&self) -> u64 {
        self.system.unix_millis()
    }

    fn sleep(&self, duration: Duration) -> Pin<Box<dyn Future<Output = ()> + Send + 'static>> {
        self.system.sleep(duration)
    }

    fn jitter(&self, maximum: Duration) -> Duration {
        self.system.jitter(maximum)
    }

    fn before_application_write(&self) -> Pin<Box<dyn Future<Output = ()> + Send + 'static>> {
        if self.gate_next.swap(false, Ordering::SeqCst) {
            self.entered.notify_one();
            let release = Arc::clone(&self.release);
            Box::pin(async move {
                release
                    .acquire_owned()
                    .await
                    .expect("write gate remains open")
                    .forget();
            })
        } else {
            Box::pin(async {})
        }
    }
}

async fn wait_for_state(
    client: &GatewayClient,
    predicate: impl Fn(&ConnectionState) -> bool,
) -> ConnectionState {
    let mut states = client.subscribe_state();
    tokio::time::timeout(Duration::from_secs(3), async {
        loop {
            let state = states.borrow().clone();
            if predicate(&state) {
                return state;
            }
            states.changed().await.expect("state channel");
        }
    })
    .await
    .expect("state timeout")
}

#[tokio::test]
async fn authenticates_correlates_concurrent_requests_handles_fragments_and_shuts_down() {
    let gateway = TestGateway::spawn(handler(|mut socket, _| async move {
        complete_handshake(&mut socket, AUTHENTICATED_MAX_FRAME_BYTES).await;
        let event = serde_json::to_vec(&json!({
            "type": "event",
            "event": "tick",
            "payload": {"ts": 7},
            "seq": 1
        }))
        .expect("event");
        let split = event.len() / 2;
        socket
            .write_frame(Frame::new(
                false,
                OpCode::Text,
                None,
                Payload::Owned(event[..split].to_vec()),
            ))
            .await
            .expect("fragment one");
        socket
            .write_frame(Frame::new(
                true,
                OpCode::Ping,
                None,
                Payload::Owned(b"control".to_vec()),
            ))
            .await
            .expect("ping");
        socket
            .write_frame(Frame::new(
                true,
                OpCode::Continuation,
                None,
                Payload::Owned(event[split..].to_vec()),
            ))
            .await
            .expect("fragment two");
        socket.flush().await.expect("flush fragments");

        let first = receive_request(&mut socket).await;
        let second = receive_request(&mut socket).await;
        send_response(&mut socket, second.id().as_str(), 2).await;
        send_response(&mut socket, first.id().as_str(), 1).await;
        wait_for_close(&mut socket).await;
    }))
    .await;
    let (client, mut events) = GatewayClient::start(config(gateway.url.clone())).expect("start");
    let info = client.wait_ready().await.expect("ready");
    assert_eq!(info.protocol.get(), 4);
    assert_eq!(info.server_version, "test-gateway");

    let params_one = json!({"request": 1});
    let params_two = json!({"request": 2});
    let (first, second) = tokio::join!(
        client.request(request_id("request-one"), health_method(), &params_one),
        client.request(request_id("request-two"), health_method(), &params_two),
    );
    let codec = Codec::authenticated();
    let first: serde_json::Value = codec
        .decode_opaque(
            first
                .expect("first response")
                .payload()
                .value()
                .expect("payload"),
        )
        .expect("first payload");
    let second: serde_json::Value = codec
        .decode_opaque(
            second
                .expect("second response")
                .payload()
                .value()
                .expect("payload"),
        )
        .expect("second payload");
    assert_eq!(first["marker"], 1);
    assert_eq!(second["marker"], 2);
    let event = events.recv().await.expect("fragmented event");
    assert_eq!(event.frame().event().as_str(), "tick");
    assert_eq!(event.frame().sequence().expect("sequence").get(), 1);

    client.shutdown().await.expect("clean shutdown");
    gateway.shutdown().await;
}

#[tokio::test]
async fn accepts_closed_effective_scopes_reported_by_server_hello() {
    let gateway = TestGateway::spawn(handler(|mut socket, _| async move {
        send_challenge(&mut socket).await;
        let (request, params) = receive_connect(&mut socket).await;
        support::verify_connect_proof(&params);
        send_json(
            &mut socket,
            json!({
                "type": "res",
                "id": request.id().as_str(),
                "ok": true,
                "payload": {
                    "type": "hello-ok",
                    "protocol": 4,
                    "server": {"version": "test-gateway", "connId": "effective-scopes"},
                    "features": {"methods": ["health"], "events": ["tick"]},
                    "snapshot": {
                        "presence": [],
                        "health": {},
                        "stateVersion": {"presence": 0, "health": 0},
                        "uptimeMs": 1
                    },
                    "auth": {
                        "role": "operator",
                        "scopes": ["operator.admin", "operator.read"]
                    },
                    "policy": {
                        "maxPayload": AUTHENTICATED_MAX_FRAME_BYTES,
                        "maxBufferedBytes": AUTHENTICATED_MAX_FRAME_BYTES,
                        "tickIntervalMs": 1000
                    }
                }
            }),
        )
        .await;
        wait_for_close(&mut socket).await;
    }))
    .await;
    let (client, _) = GatewayClient::start(config(gateway.url.clone())).expect("start");
    let info = client
        .wait_ready()
        .await
        .expect("effective scopes accepted");
    assert_eq!(
        info.scopes.as_ref(),
        ["operator.admin".to_owned(), "operator.read".to_owned()]
    );
    client.shutdown().await.expect("shutdown");
    gateway.shutdown().await;
}

#[tokio::test]
async fn admits_only_the_p02a_v3_node_and_probe_windows() {
    async fn connect_legacy(mut config: GatewayClientConfig) {
        let gateway = TestGateway::spawn(handler(|mut socket, _| async move {
            complete_handshake(&mut socket, AUTHENTICATED_MAX_FRAME_BYTES).await;
            wait_for_close(&mut socket).await;
        }))
        .await;
        config.url = gateway.url.clone();
        let (client, _) = GatewayClient::start(config).expect("start legacy");
        assert_eq!(
            client
                .wait_ready()
                .await
                .expect("legacy ready")
                .protocol
                .get(),
            4
        );
        client.shutdown().await.expect("shutdown");
        gateway.shutdown().await;
    }

    let mut node = config(Url::parse("ws://127.0.0.1:1").expect("placeholder"));
    node.role = Role::Node;
    node.scopes = ScopeSet::EMPTY;
    node.client = ClientMetadata {
        id: ClientId::NodeHost,
        mode: ClientMode::Node,
        ..ClientMetadata::default()
    };
    node.min_protocol = ProtocolVersion::new(3).expect("v3");
    node.max_protocol = ProtocolVersion::new(3).expect("v3");
    connect_legacy(node).await;

    let mut probe = config(Url::parse("ws://127.0.0.1:1").expect("placeholder"));
    probe.client = ClientMetadata {
        id: ClientId::Probe,
        mode: ClientMode::Probe,
        ..ClientMetadata::default()
    };
    probe.min_protocol = ProtocolVersion::new(3).expect("v3");
    probe.max_protocol = ProtocolVersion::new(3).expect("v3");
    connect_legacy(probe).await;
}

#[tokio::test]
async fn rejects_protocol_mismatch_and_permanent_auth_without_reconnect() {
    for (detail, expected_auth) in [("PROTOCOL_MISMATCH", false), ("AUTH_TOKEN_MISMATCH", true)] {
        let gateway = TestGateway::spawn(handler(move |mut socket, _| async move {
            send_challenge(&mut socket).await;
            let (request, _) = receive_connect(&mut socket).await;
            send_connect_error(&mut socket, request.id(), detail).await;
        }))
        .await;
        let mut client_config = config(gateway.url.clone());
        client_config.reconnect = ReconnectPolicy::Bounded {
            max_attempts: 3,
            initial_delay: Duration::from_millis(10),
            max_delay: Duration::from_millis(20),
            max_jitter: Duration::ZERO,
        };
        let (client, _) = GatewayClient::start(client_config).expect("start");
        let state = wait_for_state(&client, |state| {
            matches!(
                state,
                ConnectionState::AuthenticationFailed(_) | ConnectionState::ProtocolFailed { .. }
            )
        })
        .await;
        assert_eq!(
            matches!(state, ConnectionState::AuthenticationFailed(_)),
            expected_auth
        );
        tokio::time::sleep(Duration::from_millis(100)).await;
        assert_eq!(gateway.connections.load(Ordering::SeqCst), 1);
        client.shutdown().await.expect("shutdown");
        gateway.shutdown().await;
    }
}

#[tokio::test]
async fn shared_token_uses_one_server_hinted_device_token_correction_and_rotates() {
    const SHARED: &str = "shared-token-before-rotation";
    const FIRST_DEVICE: &str = "first-issued-device-token";
    const ROTATED_DEVICE: &str = "rotated-device-token";
    let gateway = TestGateway::spawn(handler(|mut socket, index| async move {
        send_challenge(&mut socket).await;
        let (request, params) = receive_connect(&mut socket).await;
        support::verify_connect_proof(&params);
        match index {
            0 => {
                assert_eq!(
                    params.auth.as_ref().and_then(|auth| auth.token.as_deref()),
                    Some(SHARED)
                );
                send_hello_with_device_token(
                    &mut socket,
                    request.id(),
                    &params,
                    AUTHENTICATED_MAX_FRAME_BYTES,
                    Some(FIRST_DEVICE),
                )
                .await;
                socket
                    .write_frame(Frame::close(1012, b"shared token rotated"))
                    .await
                    .expect("transient close");
                socket.flush().await.expect("flush");
            }
            1 => {
                let auth = params.auth.as_ref().expect("shared auth");
                assert_eq!(auth.token.as_deref(), Some(SHARED));
                assert_eq!(auth.device_token, None);
                send_connect_error_details(
                    &mut socket,
                    request.id(),
                    json!({
                        "code": "AUTH_TOKEN_MISMATCH",
                        "canRetryWithDeviceToken": true,
                        "recommendedNextStep": "retry_with_device_token"
                    }),
                )
                .await;
                wait_for_close(&mut socket).await;
            }
            2 => {
                let auth = params.auth.as_ref().expect("corrective device auth");
                assert_eq!(auth.token.as_deref(), Some(FIRST_DEVICE));
                assert_eq!(auth.device_token.as_deref(), Some(FIRST_DEVICE));
                send_hello_with_device_token(
                    &mut socket,
                    request.id(),
                    &params,
                    AUTHENTICATED_MAX_FRAME_BYTES,
                    Some(ROTATED_DEVICE),
                )
                .await;
                wait_for_close(&mut socket).await;
            }
            _ => panic!("unexpected arbitrary corrective retry"),
        }
    }))
    .await;
    let mut client_config = config(gateway.url.clone());
    client_config.credential = GatewayCredential::Token(SecretString::from(SHARED.to_owned()));
    client_config.reconnect = ReconnectPolicy::Bounded {
        max_attempts: 3,
        initial_delay: Duration::from_millis(10),
        max_delay: Duration::from_millis(10),
        max_jitter: Duration::ZERO,
    };
    let (client, _) = GatewayClient::start(client_config).expect("start");
    client.wait_ready().await.expect("initial shared auth");
    wait_for_state(&client, |state| {
        matches!(state, ConnectionState::Ready(_))
            && gateway.connections.load(Ordering::SeqCst) == 3
    })
    .await;
    let issued = client.take_issued_device_tokens().await;
    assert_eq!(issued[0].token().expose_secret(), ROTATED_DEVICE);
    assert!(!format!("{issued:?}").contains(ROTATED_DEVICE));
    client.shutdown().await.expect("shutdown");
    gateway.shutdown().await;
}

#[tokio::test]
async fn wrong_device_retry_hint_is_terminal_and_redacted() {
    const SHARED: &str = "wrong-hint-shared-secret";
    const DEVICE: &str = "wrong-hint-device-secret";
    let gateway = TestGateway::spawn(handler(|mut socket, index| async move {
        send_challenge(&mut socket).await;
        let (request, params) = receive_connect(&mut socket).await;
        support::verify_connect_proof(&params);
        if index == 0 {
            send_hello_with_device_token(
                &mut socket,
                request.id(),
                &params,
                AUTHENTICATED_MAX_FRAME_BYTES,
                Some(DEVICE),
            )
            .await;
            tokio::time::sleep(Duration::from_millis(50)).await;
            socket
                .write_frame(Frame::close(1012, b"retry auth"))
                .await
                .expect("close");
            socket.flush().await.expect("flush");
        } else {
            send_connect_error_details(
                &mut socket,
                request.id(),
                json!({
                    "code": "AUTH_TOKEN_MISMATCH",
                    "retryable": true,
                    "recommendedNextStep": "wait_then_retry"
                }),
            )
            .await;
            wait_for_close(&mut socket).await;
        }
    }))
    .await;
    let mut client_config = config(gateway.url.clone());
    client_config.credential = GatewayCredential::Token(SecretString::from(SHARED.to_owned()));
    client_config.reconnect = ReconnectPolicy::Bounded {
        max_attempts: 3,
        initial_delay: Duration::from_millis(10),
        max_delay: Duration::from_millis(10),
        max_jitter: Duration::ZERO,
    };
    let (client, _) = GatewayClient::start(client_config).expect("start");
    client.wait_ready().await.expect("initial ready");
    let state = wait_for_state(&client, |state| {
        matches!(state, ConnectionState::AuthenticationFailed(_))
    })
    .await;
    let rendered = format!("{state:?}");
    assert!(!rendered.contains(SHARED));
    assert!(!rendered.contains(DEVICE));
    tokio::time::sleep(Duration::from_millis(50)).await;
    assert_eq!(gateway.connections.load(Ordering::SeqCst), 2);
    client.shutdown().await.expect("shutdown");
    gateway.shutdown().await;
}

#[tokio::test]
async fn second_device_token_correction_failure_is_terminal() {
    const SHARED: &str = "single-correction-shared";
    const DEVICE: &str = "single-correction-device";
    let gateway = TestGateway::spawn(handler(|mut socket, index| async move {
        send_challenge(&mut socket).await;
        let (request, params) = receive_connect(&mut socket).await;
        support::verify_connect_proof(&params);
        if index == 0 {
            send_hello_with_device_token(
                &mut socket,
                request.id(),
                &params,
                AUTHENTICATED_MAX_FRAME_BYTES,
                Some(DEVICE),
            )
            .await;
            tokio::time::sleep(Duration::from_millis(50)).await;
            socket
                .write_frame(Frame::close(1012, b"rotate"))
                .await
                .expect("close");
            socket.flush().await.expect("flush");
        } else {
            send_connect_error_details(
                &mut socket,
                request.id(),
                json!({
                    "code": "AUTH_TOKEN_MISMATCH",
                    "canRetryWithDeviceToken": true,
                    "recommendedNextStep": "retry_with_device_token"
                }),
            )
            .await;
            wait_for_close(&mut socket).await;
        }
    }))
    .await;
    let mut client_config = config(gateway.url.clone());
    client_config.credential = GatewayCredential::Token(SecretString::from(SHARED.to_owned()));
    client_config.reconnect = ReconnectPolicy::Bounded {
        max_attempts: 4,
        initial_delay: Duration::from_millis(10),
        max_delay: Duration::from_millis(10),
        max_jitter: Duration::ZERO,
    };
    let (client, _) = GatewayClient::start(client_config).expect("start");
    client.wait_ready().await.expect("initial ready");
    wait_for_state(&client, |state| {
        matches!(state, ConnectionState::AuthenticationFailed(_))
    })
    .await;
    tokio::time::sleep(Duration::from_millis(50)).await;
    assert_eq!(gateway.connections.load(Ordering::SeqCst), 3);
    client.shutdown().await.expect("shutdown");
    gateway.shutdown().await;
}

#[tokio::test]
async fn retries_pinned_retryable_startup_unavailable_response() {
    let gateway = TestGateway::spawn(handler(|mut socket, index| async move {
        if index == 0 {
            send_challenge(&mut socket).await;
            let (request, _) = receive_connect(&mut socket).await;
            send_json(
                &mut socket,
                json!({
                    "type": "res",
                    "id": request.id().as_str(),
                    "ok": false,
                    "error": {
                        "code": "UNAVAILABLE",
                        "message": "gateway starting",
                        "details": {"reason": "startup-sidecars"},
                        "retryable": true,
                        "retryAfterMs": 1
                    }
                }),
            )
            .await;
        } else {
            complete_handshake(&mut socket, AUTHENTICATED_MAX_FRAME_BYTES).await;
            wait_for_close(&mut socket).await;
        }
    }))
    .await;
    let mut client_config = config(gateway.url.clone());
    client_config.reconnect = ReconnectPolicy::Bounded {
        max_attempts: 2,
        initial_delay: Duration::from_millis(10),
        max_delay: Duration::from_millis(10),
        max_jitter: Duration::ZERO,
    };
    let (client, _) = GatewayClient::start(client_config).expect("start");
    client.wait_ready().await.expect("retry reached ready");
    assert_eq!(gateway.connections.load(Ordering::SeqCst), 2);
    client.shutdown().await.expect("shutdown");
    gateway.shutdown().await;
}

#[tokio::test]
async fn retries_only_explicitly_retryable_pairing_recovery() {
    let gateway = TestGateway::spawn(handler(|mut socket, index| async move {
        if index == 0 {
            send_challenge(&mut socket).await;
            let (request, _) = receive_connect(&mut socket).await;
            send_json(
                &mut socket,
                json!({
                    "type": "res",
                    "id": request.id().as_str(),
                    "ok": false,
                    "error": {
                        "code": "NOT_PAIRED",
                        "message": "pairing pending",
                        "details": {
                            "code": "PAIRING_REQUIRED",
                            "retryable": true,
                            "pauseReconnect": false,
                            "recommendedNextStep": "wait_then_retry"
                        },
                        "retryable": true,
                        "retryAfterMs": 1
                    }
                }),
            )
            .await;
        } else {
            complete_handshake(&mut socket, AUTHENTICATED_MAX_FRAME_BYTES).await;
            wait_for_close(&mut socket).await;
        }
    }))
    .await;
    let mut client_config = config(gateway.url.clone());
    client_config.reconnect = ReconnectPolicy::Bounded {
        max_attempts: 2,
        initial_delay: Duration::from_millis(10),
        max_delay: Duration::from_millis(10),
        max_jitter: Duration::ZERO,
    };
    let (client, _) = GatewayClient::start(client_config).expect("start");
    client
        .wait_ready()
        .await
        .expect("pairing retry reached ready");
    assert_eq!(gateway.connections.load(Ordering::SeqCst), 2);
    client.shutdown().await.expect("shutdown");
    gateway.shutdown().await;
}

#[tokio::test]
async fn rejects_malformed_duplicate_keys_before_and_after_authentication() {
    let preauth = TestGateway::spawn(handler(|mut socket, _| async move {
        send_raw_text(
            &mut socket,
            br#"{"type":"event","event":"connect.challenge","event":"tick","payload":{"nonce":"n","ts":1}}"#
                .to_vec(),
        )
        .await;
        wait_for_close(&mut socket).await;
    }))
    .await;
    let (client, _) = GatewayClient::start(config(preauth.url.clone())).expect("start");
    wait_for_state(&client, |state| {
        matches!(state, ConnectionState::ProtocolFailed { .. })
    })
    .await;
    client.shutdown().await.expect("shutdown");
    preauth.shutdown().await;

    let postauth = TestGateway::spawn(handler(|mut socket, _| async move {
        complete_handshake(&mut socket, AUTHENTICATED_MAX_FRAME_BYTES).await;
        send_raw_text(
            &mut socket,
            br#"{"type":"event","event":"tick","event":"shutdown","payload":{"ts":1},"seq":1}"#
                .to_vec(),
        )
        .await;
        wait_for_close(&mut socket).await;
    }))
    .await;
    let (client, _) = GatewayClient::start(config(postauth.url.clone())).expect("start");
    wait_for_state(&client, |state| {
        matches!(state, ConnectionState::ProtocolFailed { .. })
    })
    .await;
    client.shutdown().await.expect("shutdown");
    postauth.shutdown().await;
}

#[tokio::test]
async fn enforces_pre_and_post_authentication_inbound_caps() {
    let preauth = TestGateway::spawn(handler(|mut socket, _| async move {
        let first_len = 40 * 1024;
        socket
            .write_frame(Frame::new(
                false,
                OpCode::Text,
                None,
                Payload::Owned(vec![b'x'; first_len]),
            ))
            .await
            .expect("first oversize fragment");
        socket
            .write_frame(Frame::new(
                true,
                OpCode::Continuation,
                None,
                Payload::Owned(vec![
                    b'x';
                    claw_protocol::gateway::PREAUTH_MAX_FRAME_BYTES + 1
                        - first_len
                ]),
            ))
            .await
            .expect("second oversize fragment");
        socket.flush().await.expect("flush fragments");
        wait_for_close(&mut socket).await;
    }))
    .await;
    let (client, _) = GatewayClient::start(config(preauth.url.clone())).expect("start");
    wait_for_state(&client, |state| {
        matches!(state, ConnectionState::ProtocolFailed { .. })
    })
    .await;
    client.shutdown().await.expect("shutdown");
    preauth.shutdown().await;

    let postauth = TestGateway::spawn(handler(|mut socket, _| async move {
        complete_handshake(&mut socket, AUTHENTICATED_MAX_FRAME_BYTES).await;
        send_raw_text(&mut socket, vec![b'x'; AUTHENTICATED_MAX_FRAME_BYTES + 1]).await;
        wait_for_close(&mut socket).await;
    }))
    .await;
    let (client, _) = GatewayClient::start(config(postauth.url.clone())).expect("start");
    wait_for_state(&client, |state| {
        matches!(state, ConnectionState::ProtocolFailed { .. })
    })
    .await;
    client.shutdown().await.expect("shutdown");
    postauth.shutdown().await;
}

#[tokio::test]
async fn rejects_invalid_utf8_text_frames() {
    let gateway = TestGateway::spawn(handler(|mut socket, _| async move {
        complete_handshake(&mut socket, AUTHENTICATED_MAX_FRAME_BYTES).await;
        socket
            .write_frame(Frame::text(Payload::Owned(vec![0xff, 0xfe])))
            .await
            .expect("invalid text frame");
        socket.flush().await.expect("flush");
        wait_for_close(&mut socket).await;
    }))
    .await;
    let (client, _) = GatewayClient::start(config(gateway.url.clone())).expect("start");
    wait_for_state(&client, |state| {
        matches!(state, ConnectionState::ProtocolFailed { .. })
    })
    .await;
    client.shutdown().await.expect("shutdown");
    gateway.shutdown().await;
}

#[tokio::test]
async fn rejects_malformed_and_oversized_control_frames() {
    let cases = [
        Frame::close_raw(Payload::Owned(1005_u16.to_be_bytes().to_vec())),
        Frame::close_raw(Payload::Owned(vec![0x03, 0xf0, 0xff])),
        Frame::pong(Payload::Owned(vec![0_u8; 126])),
        Frame::new(true, OpCode::Ping, None, Payload::Owned(vec![0_u8; 126])),
        Frame::close_raw(Payload::Owned(vec![0_u8; 126])),
    ];
    for frame in cases {
        let frame = Arc::new(Mutex::new(Some(frame)));
        let frame_for_server = Arc::clone(&frame);
        let gateway = TestGateway::spawn(handler(move |mut socket, _| {
            let frame = Arc::clone(&frame_for_server);
            async move {
                complete_handshake(&mut socket, AUTHENTICATED_MAX_FRAME_BYTES).await;
                socket
                    .write_frame(frame.lock().await.take().expect("one frame"))
                    .await
                    .expect("write malformed control");
                socket.flush().await.expect("flush");
                wait_for_close(&mut socket).await;
            }
        }))
        .await;
        let (client, _) = GatewayClient::start(config(gateway.url.clone())).expect("start");
        wait_for_state(&client, |state| {
            matches!(state, ConnectionState::ProtocolFailed { .. })
        })
        .await;
        client.shutdown().await.expect("shutdown");
        gateway.shutdown().await;
    }
}

#[tokio::test]
async fn auth_policy_close_is_terminal_but_service_restart_close_reconnects() {
    let policy_gateway = TestGateway::spawn(handler(|mut socket, _| async move {
        complete_handshake(&mut socket, AUTHENTICATED_MAX_FRAME_BYTES).await;
        socket
            .write_frame(Frame::close(1008, b"authentication policy"))
            .await
            .expect("policy close");
        socket.flush().await.expect("flush");
        wait_for_close(&mut socket).await;
    }))
    .await;
    let mut client_config = config(policy_gateway.url.clone());
    client_config.reconnect = ReconnectPolicy::Bounded {
        max_attempts: 3,
        initial_delay: Duration::from_millis(5),
        max_delay: Duration::from_millis(5),
        max_jitter: Duration::ZERO,
    };
    let (client, _) = GatewayClient::start(client_config).expect("start");
    wait_for_state(&client, |state| {
        matches!(state, ConnectionState::ProtocolFailed { .. })
    })
    .await;
    tokio::time::sleep(Duration::from_millis(30)).await;
    assert_eq!(policy_gateway.connections.load(Ordering::SeqCst), 1);
    client.shutdown().await.expect("shutdown");
    policy_gateway.shutdown().await;

    let transient_gateway = TestGateway::spawn(handler(|mut socket, index| async move {
        complete_handshake(&mut socket, AUTHENTICATED_MAX_FRAME_BYTES).await;
        if index == 0 {
            socket
                .write_frame(Frame::close(1012, b"service restart"))
                .await
                .expect("restart close");
            socket.flush().await.expect("flush");
        } else {
            wait_for_close(&mut socket).await;
        }
    }))
    .await;
    let mut client_config = config(transient_gateway.url.clone());
    client_config.reconnect = ReconnectPolicy::Bounded {
        max_attempts: 2,
        initial_delay: Duration::from_millis(5),
        max_delay: Duration::from_millis(5),
        max_jitter: Duration::ZERO,
    };
    let (client, _) = GatewayClient::start(client_config).expect("start");
    wait_for_state(&client, |state| {
        matches!(state, ConnectionState::Ready(_))
            && transient_gateway.connections.load(Ordering::SeqCst) == 2
    })
    .await;
    client.shutdown().await.expect("shutdown");
    transient_gateway.shutdown().await;
}

#[tokio::test]
async fn max_controls_remain_legal_near_fragmented_data_cap() {
    const SERVER_LIMIT: usize = 4096;
    let gateway = TestGateway::spawn(handler(|mut socket, _| async move {
        complete_handshake(&mut socket, SERVER_LIMIT).await;
        let event = serde_json::to_vec(&json!({
            "type": "event",
            "event": "tick",
            "payload": {"data": "x".repeat(3900)},
            "seq": 1
        }))
        .expect("event");
        assert!(event.len() < SERVER_LIMIT);
        let split = event.len() - 10;
        socket
            .write_frame(Frame::new(
                false,
                OpCode::Text,
                None,
                Payload::Owned(event[..split].to_vec()),
            ))
            .await
            .expect("fragment");
        socket
            .write_frame(Frame::new(
                true,
                OpCode::Ping,
                None,
                Payload::Owned(vec![7_u8; 125]),
            ))
            .await
            .expect("max ping");
        socket
            .write_frame(Frame::pong(Payload::Owned(vec![8_u8; 125])))
            .await
            .expect("max pong");
        socket
            .write_frame(Frame::new(
                true,
                OpCode::Continuation,
                None,
                Payload::Owned(event[split..].to_vec()),
            ))
            .await
            .expect("continuation");
        socket.flush().await.expect("flush");
        let pong = socket.read_frame().await.expect("client pong");
        assert_eq!(pong.opcode, OpCode::Pong);
        assert_eq!(pong.payload.len(), 125);
        wait_for_close(&mut socket).await;
    }))
    .await;
    let (client, mut events) = GatewayClient::start(config(gateway.url.clone())).expect("start");
    client.wait_ready().await.expect("ready");
    let event = tokio::time::timeout(Duration::from_secs(2), events.recv())
        .await
        .expect("event timeout")
        .expect("event");
    assert_eq!(event.frame().sequence().expect("sequence").get(), 1);
    client.shutdown().await.expect("shutdown");
    gateway.shutdown().await;
}

#[tokio::test]
async fn max_close_remains_legal_near_fragmented_data_cap() {
    const SERVER_LIMIT: usize = 4096;
    let gateway = TestGateway::spawn(handler(|mut socket, _| async move {
        complete_handshake(&mut socket, SERVER_LIMIT).await;
        socket
            .write_frame(Frame::new(
                false,
                OpCode::Text,
                None,
                Payload::Owned(vec![b'x'; SERVER_LIMIT - 10]),
            ))
            .await
            .expect("near-cap fragment");
        socket
            .write_frame(Frame::close(1000, &[b'z'; 123]))
            .await
            .expect("max close");
        socket.flush().await.expect("flush");
        wait_for_close(&mut socket).await;
    }))
    .await;
    let (client, _) = GatewayClient::start(config(gateway.url.clone())).expect("start");
    wait_for_state(&client, |state| matches!(state, ConnectionState::Stopped)).await;
    client.shutdown().await.expect("shutdown");
    gateway.shutdown().await;
}

struct RepeatedChunk<'a> {
    chunk: &'a str,
    repetitions: usize,
    serialized: Arc<AtomicUsize>,
}

impl Serialize for RepeatedChunk<'_> {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let mut sequence = serializer.serialize_seq(Some(self.repetitions))?;
        for _ in 0..self.repetitions {
            self.serialized.fetch_add(1, Ordering::SeqCst);
            sequence.serialize_element(self.chunk)?;
        }
        sequence.end()
    }
}

#[tokio::test]
async fn rejects_outbound_oversize_during_bounded_serialization() {
    let gateway = TestGateway::spawn(handler(|mut socket, _| async move {
        complete_handshake(&mut socket, AUTHENTICATED_MAX_FRAME_BYTES).await;
        wait_for_close(&mut socket).await;
    }))
    .await;
    let (client, _) = GatewayClient::start(config(gateway.url.clone())).expect("start");
    client.wait_ready().await.expect("ready");
    let chunk = "x".repeat(1024 * 1024);
    let serialized = Arc::new(AtomicUsize::new(0));
    let params = RepeatedChunk {
        chunk: &chunk,
        repetitions: 100,
        serialized: Arc::clone(&serialized),
    };
    let error = client
        .request(request_id("oversize"), health_method(), &params)
        .await
        .expect_err("oversize rejected");
    assert!(matches!(
        error,
        GatewayClientError::Protocol(ProtocolFailure::Codec(CodecError::FrameTooLarge {
            phase: TransportPhase::Authenticated,
            ..
        }))
    ));
    assert!(serialized.load(Ordering::SeqCst) < params.repetitions);
    client.shutdown().await.expect("shutdown");
    gateway.shutdown().await;
}

#[tokio::test]
async fn enforces_server_outbound_policy_without_killing_connection() {
    let gateway = TestGateway::spawn(handler(|mut socket, _| async move {
        complete_handshake(&mut socket, 1024).await;
        wait_for_close(&mut socket).await;
    }))
    .await;
    let (client, _) = GatewayClient::start(config(gateway.url.clone())).expect("start");
    client.wait_ready().await.expect("ready");
    let params = json!({"large": "x".repeat(2048)});
    let error = client
        .request(request_id("server-cap"), health_method(), &params)
        .await
        .expect_err("server cap");
    assert!(matches!(
        error,
        GatewayClientError::Protocol(ProtocolFailure::OutboundMessageTooLarge { limit: 1024, .. })
    ));
    assert!(matches!(client.state(), ConnectionState::Ready(_)));
    client.shutdown().await.expect("shutdown");
    gateway.shutdown().await;
}

async fn assert_sequence_failure(sequences: Vec<u64>, expected: ResyncRequired) {
    let gateway = TestGateway::spawn(handler(move |mut socket, _| {
        let sequences = sequences.clone();
        async move {
            complete_handshake(&mut socket, AUTHENTICATED_MAX_FRAME_BYTES).await;
            for sequence in sequences {
                send_json(
                    &mut socket,
                    json!({
                        "type": "event",
                        "event": "tick",
                        "payload": {"ts": sequence},
                        "seq": sequence
                    }),
                )
                .await;
            }
            wait_for_close(&mut socket).await;
        }
    }))
    .await;
    let (client, _) = GatewayClient::start(config(gateway.url.clone())).expect("start");
    let state = wait_for_state(&client, |state| {
        matches!(state, ConnectionState::ResyncRequired(_))
    })
    .await;
    assert_eq!(state, ConnectionState::ResyncRequired(expected));
    client.shutdown().await.expect("shutdown");
    gateway.shutdown().await;
}

#[tokio::test]
async fn surfaces_sequence_gap_duplicate_and_regression_as_resync_required() {
    assert_sequence_failure(
        vec![1, 3],
        ResyncRequired::Gap {
            expected: 2,
            received: 3,
        },
    )
    .await;
    assert_sequence_failure(vec![1, 1], ResyncRequired::Duplicate { sequence: 1 }).await;
    assert_sequence_failure(
        vec![1, 2, 1],
        ResyncRequired::Regression {
            last: 2,
            received: 1,
        },
    )
    .await;
}

#[tokio::test]
async fn event_queue_saturation_requires_resync() {
    let gateway = TestGateway::spawn(handler(|mut socket, _| async move {
        complete_handshake(&mut socket, AUTHENTICATED_MAX_FRAME_BYTES).await;
        for sequence in 1..=2 {
            send_json(
                &mut socket,
                json!({
                    "type": "event",
                    "event": "tick",
                    "payload": {"ts": sequence},
                    "seq": sequence
                }),
            )
            .await;
        }
        wait_for_close(&mut socket).await;
    }))
    .await;
    let mut client_config = config(gateway.url.clone());
    client_config.limits.event_queue_capacity = 1;
    let (client, _events) = GatewayClient::start(client_config).expect("start");
    let state = wait_for_state(&client, |state| {
        matches!(state, ConnectionState::ResyncRequired(_))
    })
    .await;
    assert_eq!(
        state,
        ConnectionState::ResyncRequired(ResyncRequired::EventQueueSaturated)
    );
    client.shutdown().await.expect("shutdown");
    gateway.shutdown().await;
}

#[tokio::test]
async fn event_queue_enforces_a_cumulative_byte_budget() {
    let gateway = TestGateway::spawn(handler(|mut socket, _| async move {
        complete_handshake(&mut socket, AUTHENTICATED_MAX_FRAME_BYTES).await;
        send_json(
            &mut socket,
            json!({
                "type": "event",
                "event": "tick",
                "payload": {"data": "x".repeat(1024)},
                "seq": 1
            }),
        )
        .await;
        wait_for_close(&mut socket).await;
    }))
    .await;
    let mut client_config = config(gateway.url.clone());
    client_config.limits.event_queue_bytes = 128;
    let (client, _events) = GatewayClient::start(client_config).expect("start");
    let state = wait_for_state(&client, |state| {
        matches!(state, ConnectionState::ResyncRequired(_))
    })
    .await;
    assert_eq!(
        state,
        ConnectionState::ResyncRequired(ResyncRequired::EventQueueSaturated)
    );
    client.shutdown().await.expect("shutdown");
    gateway.shutdown().await;
}

#[tokio::test]
async fn rejects_unknown_and_duplicate_responses() {
    let unknown = TestGateway::spawn(handler(|mut socket, _| async move {
        complete_handshake(&mut socket, AUTHENTICATED_MAX_FRAME_BYTES).await;
        let _ = receive_request(&mut socket).await;
        send_response(&mut socket, "not-pending", 1).await;
    }))
    .await;
    let (client, _) = GatewayClient::start(config(unknown.url.clone())).expect("start");
    client.wait_ready().await.expect("ready");
    let params = json!({});
    let request = client.request(request_id("known"), health_method(), &params);
    let state = wait_for_state(&client, |state| {
        matches!(state, ConnectionState::ProtocolFailed { .. })
    });
    let (_, observed) = tokio::join!(request, state);
    assert!(matches!(observed, ConnectionState::ProtocolFailed { .. }));
    client.shutdown().await.expect("shutdown");
    unknown.shutdown().await;

    let duplicate = TestGateway::spawn(handler(|mut socket, _| async move {
        complete_handshake(&mut socket, AUTHENTICATED_MAX_FRAME_BYTES).await;
        let request = receive_request(&mut socket).await;
        send_response(&mut socket, request.id().as_str(), 1).await;
        send_response(&mut socket, request.id().as_str(), 1).await;
    }))
    .await;
    let (client, _) = GatewayClient::start(config(duplicate.url.clone())).expect("start");
    client.wait_ready().await.expect("ready");
    client
        .request(request_id("duplicate"), health_method(), &json!({}))
        .await
        .expect("first response");
    wait_for_state(&client, |state| {
        matches!(state, ConnectionState::ProtocolFailed { .. })
    })
    .await;
    client.shutdown().await.expect("shutdown");
    duplicate.shutdown().await;
}

#[tokio::test]
async fn discards_one_late_response_after_request_timeout() {
    let gateway = TestGateway::spawn(handler(|mut socket, _| async move {
        complete_handshake(&mut socket, AUTHENTICATED_MAX_FRAME_BYTES).await;
        let timed_out = receive_request(&mut socket).await;
        tokio::time::sleep(Duration::from_millis(250)).await;
        send_response(&mut socket, timed_out.id().as_str(), 1).await;
        let next = receive_request(&mut socket).await;
        send_response(&mut socket, next.id().as_str(), 2).await;
        wait_for_close(&mut socket).await;
    }))
    .await;
    let mut client_config = config(gateway.url.clone());
    client_config.timeouts.request = Duration::from_millis(50);
    let (client, _) = GatewayClient::start(client_config).expect("start");
    client.wait_ready().await.expect("ready");
    assert!(matches!(
        client
            .request(request_id("will-time-out"), health_method(), &json!({}))
            .await,
        Err(GatewayClientError::RequestTimedOut(_))
    ));
    tokio::time::sleep(Duration::from_millis(250)).await;
    assert!(matches!(client.state(), ConnectionState::Ready(_)));
    let response = client
        .request(request_id("after-timeout"), health_method(), &json!({}))
        .await
        .expect("connection remains usable");
    let payload: serde_json::Value = Codec::authenticated()
        .decode_opaque(response.payload().value().expect("payload"))
        .expect("decode");
    assert_eq!(payload["marker"], 2);
    client.shutdown().await.expect("shutdown");
    gateway.shutdown().await;
}

#[tokio::test]
async fn bounds_in_flight_requests_and_cancels_pending_on_shutdown() {
    let (received_tx, received_rx) = oneshot::channel();
    let received_tx = Arc::new(Mutex::new(Some(received_tx)));
    let gateway = TestGateway::spawn(handler(move |mut socket, _| {
        let received_tx = Arc::clone(&received_tx);
        async move {
            complete_handshake(&mut socket, AUTHENTICATED_MAX_FRAME_BYTES).await;
            let _ = receive_request(&mut socket).await;
            if let Some(sender) = received_tx.lock().await.take() {
                let _ = sender.send(());
            }
            wait_for_close(&mut socket).await;
        }
    }))
    .await;
    let mut client_config = config(gateway.url.clone());
    client_config.limits = ClientLimits {
        max_in_flight_requests: 1,
        command_queue_capacity: 1,
        outbound_queue_bytes: AUTHENTICATED_MAX_FRAME_BYTES,
        event_queue_capacity: 8,
        event_queue_bytes: AUTHENTICATED_MAX_FRAME_BYTES,
        completed_id_capacity: 8,
    };
    let (client, _) = GatewayClient::start(client_config).expect("start");
    client.wait_ready().await.expect("ready");
    let first_client = client.clone();
    let first = tokio::spawn(async move {
        first_client
            .request(request_id("held"), health_method(), &json!({}))
            .await
    });
    received_rx.await.expect("server received request");
    let error = client
        .request(request_id("saturated"), health_method(), &json!({}))
        .await
        .expect_err("in-flight bound");
    assert!(matches!(
        error,
        GatewayClientError::Backpressure(BackpressureError::InFlightLimit)
    ));
    client.shutdown().await.expect("shutdown");
    assert!(matches!(
        first.await.expect("request task"),
        Err(GatewayClientError::Cancelled)
    ));
    gateway.shutdown().await;
}

#[tokio::test]
async fn command_queue_saturation_is_explicit_backpressure() {
    let gateway = TestGateway::spawn(handler(|mut socket, _| async move {
        complete_handshake(&mut socket, AUTHENTICATED_MAX_FRAME_BYTES).await;
        let request = receive_request(&mut socket).await;
        send_response(&mut socket, request.id().as_str(), 1).await;
        wait_for_close(&mut socket).await;
    }))
    .await;
    let mut client_config = config(gateway.url.clone());
    client_config.limits = ClientLimits {
        max_in_flight_requests: 2,
        command_queue_capacity: 1,
        outbound_queue_bytes: AUTHENTICATED_MAX_FRAME_BYTES,
        event_queue_capacity: 8,
        event_queue_bytes: AUTHENTICATED_MAX_FRAME_BYTES,
        completed_id_capacity: 8,
    };
    let (client, _) = GatewayClient::start(client_config).expect("start");
    client.wait_ready().await.expect("ready");
    let first_params = json!({"request": 1});
    let second_params = json!({"request": 2});
    let (first, second) = tokio::join!(
        client.request(request_id("queue-one"), health_method(), &first_params),
        client.request(request_id("queue-two"), health_method(), &second_params),
    );
    assert!(first.is_ok());
    assert!(matches!(
        second,
        Err(GatewayClientError::Backpressure(
            BackpressureError::CommandQueueSaturated
        ))
    ));
    client.shutdown().await.expect("shutdown");
    gateway.shutdown().await;
}

#[tokio::test]
async fn cumulative_outbound_bytes_bound_multiple_requests_behind_stalled_writer() {
    const LARGE_BYTES: usize = 20 * 1024 * 1024;
    let gateway = TestGateway::spawn(handler(|mut socket, _| async move {
        complete_handshake_with_tick_interval(&mut socket, AUTHENTICATED_MAX_FRAME_BYTES, 10_000)
            .await;
        let request = receive_request(&mut socket).await;
        assert_eq!(request.id().as_str(), "large-held");
        send_response(&mut socket, request.id().as_str(), 1).await;
        wait_for_close(&mut socket).await;
    }))
    .await;
    let mut client_config = config(gateway.url.clone());
    client_config.limits.max_in_flight_requests = 4;
    client_config.limits.command_queue_capacity = 4;
    client_config.limits.outbound_queue_bytes = 21 * 1024 * 1024;
    client_config.timeouts.request = Duration::from_secs(5);
    let runtime = WriteGateRuntime::new();
    let (client, _) = GatewayClient::start_with_runtime(
        client_config,
        Arc::clone(&runtime) as Arc<dyn ClientRuntime>,
    )
    .expect("start");
    client.wait_ready().await.expect("ready");
    let large = json!({"value": "x".repeat(LARGE_BYTES)});
    let held_client = client.clone();
    let held = tokio::spawn(async move {
        held_client
            .request(request_id("large-held"), side_effect_method(), &large)
            .await
    });
    runtime.wait_until_blocked().await;
    for id in ["large-rejected-one", "large-rejected-two"] {
        let large = json!({"value": "y".repeat(LARGE_BYTES)});
        let result = client
            .request(request_id(id), side_effect_method(), &large)
            .await;
        assert!(
            matches!(
                result,
                Err(GatewayClientError::Backpressure(
                    BackpressureError::CommandBytesSaturated
                ))
            ),
            "unexpected aggregate-budget result: {result:?}"
        );
    }
    runtime.unblock();
    held.await
        .expect("held request task")
        .expect("held request response");
    client.shutdown().await.expect("shutdown");
    gateway.shutdown().await;
}

#[tokio::test]
async fn expired_queued_side_effect_is_never_transmitted_and_releases_budgets() {
    const LARGE_BYTES: usize = 20 * 1024 * 1024;
    let (no_expired_tx, no_expired_rx) = oneshot::channel();
    let no_expired_tx = Arc::new(Mutex::new(Some(no_expired_tx)));
    let gateway = TestGateway::spawn(handler(move |mut socket, _| {
        let no_expired_tx = Arc::clone(&no_expired_tx);
        async move {
            complete_handshake(&mut socket, AUTHENTICATED_MAX_FRAME_BYTES).await;
            let first = receive_request(&mut socket).await;
            assert_eq!(first.id().as_str(), "blocking-write");
            send_response(&mut socket, first.id().as_str(), 1).await;
            assert!(
                tokio::time::timeout(Duration::from_millis(150), receive_request(&mut socket))
                    .await
                    .is_err(),
                "expired side-effect request reached the server"
            );
            if let Some(sender) = no_expired_tx.lock().await.take() {
                let _ = sender.send(());
            }
            let third = receive_request(&mut socket).await;
            assert_eq!(third.id().as_str(), "after-expired");
            send_response(&mut socket, third.id().as_str(), 3).await;
            wait_for_close(&mut socket).await;
        }
    }))
    .await;
    let mut client_config = config(gateway.url.clone());
    client_config.limits.max_in_flight_requests = 3;
    client_config.limits.command_queue_capacity = 3;
    client_config.limits.outbound_queue_bytes = AUTHENTICATED_MAX_FRAME_BYTES;
    client_config.timeouts.request = Duration::from_secs(3);
    let runtime = WriteGateRuntime::new();
    let (client, _) = GatewayClient::start_with_runtime(
        client_config,
        Arc::clone(&runtime) as Arc<dyn ClientRuntime>,
    )
    .expect("start");
    client.wait_ready().await.expect("ready");
    let large = json!({"value": "x".repeat(LARGE_BYTES)});
    let first_client = client.clone();
    let first = tokio::spawn(async move {
        first_client
            .request_with_timeout(
                request_id("blocking-write"),
                side_effect_method(),
                &large,
                Duration::from_secs(3),
            )
            .await
    });
    runtime.wait_until_blocked().await;
    assert!(matches!(
        client
            .request_with_timeout(
                request_id("must-not-send"),
                side_effect_method(),
                &json!({"value": "side-effect"}),
                Duration::from_millis(50),
            )
            .await,
        Err(GatewayClientError::RequestTimedOut(_))
    ));
    runtime.unblock();
    first
        .await
        .expect("blocking request task")
        .expect("blocking request response");
    no_expired_rx.await.expect("server checked expired request");
    client
        .request(
            request_id("after-expired"),
            side_effect_method(),
            &json!({"value": "still-usable"}),
        )
        .await
        .expect("all permits released");
    client.shutdown().await.expect("shutdown");
    gateway.shutdown().await;
}

#[tokio::test]
async fn unique_request_identifier_budget_is_bounded_without_eviction() {
    let gateway = TestGateway::spawn(handler(|mut socket, _| async move {
        complete_handshake(&mut socket, AUTHENTICATED_MAX_FRAME_BYTES).await;
        let request = receive_request(&mut socket).await;
        send_response(&mut socket, request.id().as_str(), 1).await;
        wait_for_close(&mut socket).await;
    }))
    .await;
    let mut client_config = config(gateway.url.clone());
    client_config.limits.completed_id_capacity = 1;
    let (client, _) = GatewayClient::start(client_config).expect("start");
    client.wait_ready().await.expect("ready");
    client
        .request(request_id("only-id"), health_method(), &json!({}))
        .await
        .expect("first identifier");
    assert!(matches!(
        client
            .request(request_id("over-budget"), health_method(), &json!({}))
            .await,
        Err(GatewayClientError::Backpressure(
            BackpressureError::IdentifierCapacity
        ))
    ));
    assert!(matches!(client.state(), ConnectionState::Ready(_)));
    client.shutdown().await.expect("shutdown");
    gateway.shutdown().await;
}

#[tokio::test]
async fn cancellation_is_safe_during_connect_auth_and_reconnect() {
    let (url, raw_cancel, raw_tasks) = raw_stalled_server().await;
    let (client, _) = GatewayClient::start(config(url)).expect("start");
    tokio::time::sleep(Duration::from_millis(30)).await;
    client.shutdown().await.expect("cancel connect");
    raw_cancel.cancel();
    raw_tasks.close();
    raw_tasks.wait().await;

    let auth = TestGateway::spawn(handler(|mut socket, _| async move {
        send_challenge(&mut socket).await;
        let _ = receive_connect(&mut socket).await;
        wait_for_close(&mut socket).await;
    }))
    .await;
    let (client, _) = GatewayClient::start(config(auth.url.clone())).expect("start");
    wait_for_state(&client, |state| {
        matches!(state, ConnectionState::Authenticating)
    })
    .await;
    client.shutdown().await.expect("cancel auth");
    auth.shutdown().await;

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("reserve port");
    let address = listener.local_addr().expect("address");
    drop(listener);
    let mut reconnecting = config(Url::parse(&format!("ws://{address}")).expect("url"));
    reconnecting.reconnect = ReconnectPolicy::Bounded {
        max_attempts: 3,
        initial_delay: Duration::from_secs(5),
        max_delay: Duration::from_secs(5),
        max_jitter: Duration::ZERO,
    };
    let (client, _) = GatewayClient::start(reconnecting).expect("start");
    wait_for_state(&client, |state| {
        matches!(state, ConnectionState::Reconnecting { .. })
    })
    .await;
    client.shutdown().await.expect("cancel reconnect");
}

#[tokio::test]
async fn transient_reconnect_reauthenticates_and_never_replays_requests() {
    let second_ready = Arc::new(Notify::new());
    let second_ready_handler = Arc::clone(&second_ready);
    let gateway = TestGateway::spawn(handler(move |mut socket, index| {
        let second_ready = Arc::clone(&second_ready_handler);
        async move {
            complete_handshake(&mut socket, AUTHENTICATED_MAX_FRAME_BYTES).await;
            if index == 0 {
                let request = receive_request(&mut socket).await;
                assert_eq!(request.id().as_str(), "not-replayed");
                socket
                    .write_frame(Frame::close(1012, b"transient restart"))
                    .await
                    .expect("close");
                socket.flush().await.expect("flush");
            } else {
                tokio::time::sleep(Duration::from_millis(150)).await;
                second_ready.notify_one();
                let request = receive_request(&mut socket).await;
                assert_eq!(request.id().as_str(), "after-reconnect");
                send_response(&mut socket, request.id().as_str(), 9).await;
                wait_for_close(&mut socket).await;
            }
        }
    }))
    .await;
    let mut client_config = config(gateway.url.clone());
    client_config.reconnect = ReconnectPolicy::Bounded {
        max_attempts: 3,
        initial_delay: Duration::from_millis(10),
        max_delay: Duration::from_millis(20),
        max_jitter: Duration::ZERO,
    };
    let (client, _) = GatewayClient::start(client_config).expect("start");
    client.wait_ready().await.expect("first ready");
    let first = client
        .request(request_id("not-replayed"), health_method(), &json!({}))
        .await;
    assert!(matches!(
        first,
        Err(GatewayClientError::DisconnectedNotReplayed)
    ));
    wait_for_state(&client, |state| {
        matches!(state, ConnectionState::Ready(_))
            && gateway.connections.load(Ordering::SeqCst) >= 2
    })
    .await;
    second_ready.notified().await;
    let response = client
        .request(request_id("after-reconnect"), health_method(), &json!({}))
        .await
        .expect("new request");
    let payload: serde_json::Value = Codec::authenticated()
        .decode_opaque(response.payload().value().expect("payload"))
        .expect("decode");
    assert_eq!(payload["marker"], 9);
    client.shutdown().await.expect("shutdown");
    gateway.shutdown().await;
}

#[tokio::test]
async fn negotiated_tick_watchdog_detects_silent_connection() {
    let gateway = TestGateway::spawn(handler(|mut socket, _| async move {
        send_challenge(&mut socket).await;
        let (request, params) = receive_connect(&mut socket).await;
        support::verify_connect_proof(&params);
        send_hello_with_tick_interval(
            &mut socket,
            request.id(),
            &params,
            AUTHENTICATED_MAX_FRAME_BYTES,
            20,
        )
        .await;
        wait_for_close(&mut socket).await;
    }))
    .await;
    let (client, _) = GatewayClient::start(config(gateway.url.clone())).expect("start");
    client.wait_ready().await.expect("ready");
    wait_for_state(&client, |state| {
        matches!(state, ConnectionState::ReconnectExhausted)
    })
    .await;
    client.shutdown().await.expect("shutdown");
    gateway.shutdown().await;
}

#[tokio::test]
async fn bootstrap_token_is_surfaced_and_rotated_for_reconnect() {
    const ISSUED_TOKEN: &str = "issued-device-token";
    let gateway = TestGateway::spawn(handler(|mut socket, index| async move {
        send_challenge(&mut socket).await;
        let (request, params) = receive_connect(&mut socket).await;
        support::verify_connect_proof(&params);
        if index == 0 {
            let auth = params.auth.as_ref().expect("bootstrap auth");
            assert_eq!(auth.bootstrap_token.as_deref(), Some("one-time-bootstrap"));
            send_hello_with_device_token(
                &mut socket,
                request.id(),
                &params,
                AUTHENTICATED_MAX_FRAME_BYTES,
                Some(ISSUED_TOKEN),
            )
            .await;
            tokio::time::sleep(Duration::from_millis(100)).await;
            socket
                .write_frame(Frame::close(1012, b"rotate credential"))
                .await
                .expect("close");
            socket.flush().await.expect("flush");
        } else {
            let auth = params.auth.as_ref().expect("device auth");
            assert_eq!(auth.token.as_deref(), Some(ISSUED_TOKEN));
            assert_eq!(auth.device_token.as_deref(), Some(ISSUED_TOKEN));
            send_hello_with_device_token(
                &mut socket,
                request.id(),
                &params,
                AUTHENTICATED_MAX_FRAME_BYTES,
                None,
            )
            .await;
            wait_for_close(&mut socket).await;
        }
    }))
    .await;
    let mut client_config = config(gateway.url.clone());
    client_config.credential =
        GatewayCredential::BootstrapToken(SecretString::from("one-time-bootstrap".to_owned()));
    client_config.reconnect = ReconnectPolicy::Bounded {
        max_attempts: 2,
        initial_delay: Duration::from_millis(10),
        max_delay: Duration::from_millis(10),
        max_jitter: Duration::ZERO,
    };
    let (client, _) = GatewayClient::start(client_config).expect("start");
    client.wait_ready().await.expect("bootstrap ready");
    let issued = client.take_issued_device_tokens().await;
    assert_eq!(issued.len(), 2);
    assert_eq!(issued[0].token().expose_secret(), ISSUED_TOKEN);
    assert_eq!(issued[1].token().expose_secret(), "secondary-device-token");
    assert_eq!(issued[1].role(), "node");
    wait_for_state(&client, |state| {
        matches!(state, ConnectionState::Ready(_))
            && gateway.connections.load(Ordering::SeqCst) >= 2
    })
    .await;
    client.shutdown().await.expect("shutdown");
    gateway.shutdown().await;
}

#[tokio::test]
async fn issued_token_delivery_replaces_old_reconnect_state_at_fixed_bound() {
    const CONNECTIONS: usize = 5;
    let gateway = TestGateway::spawn(handler(|mut socket, index| async move {
        send_challenge(&mut socket).await;
        let (request, params) = receive_connect(&mut socket).await;
        support::verify_connect_proof(&params);
        let auth = params.auth.as_ref().expect("auth");
        if index == 0 {
            assert_eq!(auth.bootstrap_token.as_deref(), Some("bounded-bootstrap"));
        } else {
            let expected = format!("bounded-device-{}", index - 1);
            assert_eq!(auth.device_token.as_deref(), Some(expected.as_str()));
        }
        let issued = format!("bounded-device-{index}");
        send_hello_with_device_token(
            &mut socket,
            request.id(),
            &params,
            AUTHENTICATED_MAX_FRAME_BYTES,
            Some(&issued),
        )
        .await;
        if index + 1 < CONNECTIONS {
            socket
                .write_frame(Frame::close(1012, b"rotate again"))
                .await
                .expect("close");
            socket.flush().await.expect("flush");
        } else {
            wait_for_close(&mut socket).await;
        }
    }))
    .await;
    let mut client_config = config(gateway.url.clone());
    client_config.credential =
        GatewayCredential::BootstrapToken(SecretString::from("bounded-bootstrap".to_owned()));
    client_config.reconnect = ReconnectPolicy::Bounded {
        max_attempts: 2,
        initial_delay: Duration::from_millis(5),
        max_delay: Duration::from_millis(5),
        max_jitter: Duration::ZERO,
    };
    let (client, _) = GatewayClient::start(client_config).expect("start");
    client.wait_ready().await.expect("first ready");
    wait_for_state(&client, |state| {
        matches!(state, ConnectionState::Ready(_))
            && gateway.connections.load(Ordering::SeqCst) == CONNECTIONS
    })
    .await;
    let issued = client.take_issued_device_tokens().await;
    assert_eq!(issued.len(), 2);
    assert_eq!(
        issued[0].token().expose_secret(),
        format!("bounded-device-{}", CONNECTIONS - 1)
    );
    assert_eq!(issued[1].token().expose_secret(), "secondary-device-token");
    client.shutdown().await.expect("shutdown");
    gateway.shutdown().await;
}

#[tokio::test]
async fn unsupported_compression_is_rejected_fail_closed() {
    let gateway =
        TestGateway::spawn_with_extensions(handler(|_socket, _| async move {}), true).await;
    let (client, _) = GatewayClient::start(config(gateway.url.clone())).expect("start");
    wait_for_state(&client, |state| {
        matches!(state, ConnectionState::ReconnectExhausted)
    })
    .await;
    client.shutdown().await.expect("shutdown");
    gateway.shutdown().await;
}

#[test]
fn secrets_are_redacted_from_all_client_debug_and_errors() {
    let secret = "never-print-this-token";
    let credential = GatewayCredential::Token(SecretString::from(secret.to_owned()));
    let mut client_config = GatewayClientConfig::new(
        Url::parse("wss://gateway.example.test/socket").expect("url"),
        identity(),
    );
    client_config.credential = GatewayCredential::Token(SecretString::from(secret.to_owned()));
    for rendered in [
        format!("{credential:?}"),
        format!("{client_config:?}"),
        GatewayClientError::Cancelled.to_string(),
    ] {
        assert!(!rendered.contains(secret));
    }
}

#[test]
fn plaintext_guard_does_not_treat_dns_names_starting_with_127_as_loopback() {
    let config = GatewayClientConfig::new(
        Url::parse("ws://127.example.test/socket").expect("url"),
        identity(),
    );
    assert!(matches!(
        GatewayClient::start(config),
        Err(GatewayClientError::Configuration(
            claw_gateway_client::ConfigurationError::InsecureRemoteWebSocket
        ))
    ));
}

#[tokio::test]
async fn ipv6_loopback_is_accepted_without_plaintext_break_glass() {
    let config =
        GatewayClientConfig::new(Url::parse("ws://[::1]:9/socket").expect("url"), identity());
    let (client, _) = GatewayClient::start(config).expect("IPv6 loopback accepted");
    client.shutdown().await.expect("shutdown");
}

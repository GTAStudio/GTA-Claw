//! Adversarial transport, handshake, and backpressure tests over a raw socket.
//!
//! These tests deliberately bypass `claw-gateway-client` so they can send bytes
//! a well-behaved client never would.

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use claw_gateway::{
    DeviceDirectory, Exposure, GatewayServer, GatewayServerConfig, ServerHandle, ServerLimits,
    ServerTimeouts,
};
use claw_protocol::gateway::{
    AuthenticationDecision, AuthenticationPort, AuthenticationRequest, ConnectErrorDetailCode,
    DeviceProofDecision, HandshakeRejection, OperatorScope, Role,
};
use fastwebsockets::{Frame, OpCode, Payload, Role as WsRole, WebSocket};
use serde_json::{Value, json};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

/// Authentication port that admits any well-formed operator connect request.
///
/// Device-proof policy is exercised by `tests/client_integration.rs`; these
/// tests are about the transport, so the port is deliberately permissive.
#[derive(Debug)]
struct AdmitOperator {
    scopes: Vec<OperatorScope>,
}

impl AuthenticationPort for AdmitOperator {
    fn authenticate(&self, request: AuthenticationRequest<'_>) -> AuthenticationDecision {
        if request.requested_role() == Role::Operator {
            AuthenticationDecision::Accepted {
                role: Role::Operator,
                scopes: self.scopes.clone(),
                device_proof: DeviceProofDecision::NotRequired,
            }
        } else {
            AuthenticationDecision::Rejected(HandshakeRejection::new(
                ConnectErrorDetailCode::AuthUnauthorized,
                "this fixture admits operators only",
            ))
        }
    }
}

async fn start(config: GatewayServerConfig) -> ServerHandle {
    let authenticator = AdmitOperator {
        scopes: vec![OperatorScope::Admin],
    };
    GatewayServer::new(
        config,
        Arc::new(authenticator),
        Arc::new(DeviceDirectory::new()),
    )
    .expect("the configuration and registry are valid")
    .bind("127.0.0.1:0".parse().expect("loopback address parses"))
    .await
    .expect("an ephemeral loopback port is available")
    .start()
}

fn fast_config() -> GatewayServerConfig {
    GatewayServerConfig {
        server_version: "adversarial".to_owned(),
        limits: ServerLimits::default(),
        timeouts: ServerTimeouts {
            // Long enough that a healthy handshake never races the timer.
            tick_interval: Duration::from_hours(1),
            ..ServerTimeouts::default()
        },
        exposure: Exposure::LoopbackOnly,
    }
}

/// Sends raw upgrade bytes and returns the HTTP response head, or `None` on EOF.
async fn upgrade_head(address: SocketAddr, request: &str) -> (TcpStream, Option<String>) {
    let mut stream = TcpStream::connect(address)
        .await
        .expect("the listener accepts loopback connections");
    stream
        .write_all(request.as_bytes())
        .await
        .expect("the upgrade request is written");
    let mut head = Vec::new();
    let mut byte = [0_u8; 1];
    while stream.read_exact(&mut byte).await.is_ok() {
        head.push(byte[0]);
        if head.ends_with(b"\r\n\r\n") {
            break;
        }
    }
    if head.is_empty() {
        return (stream, None);
    }
    (
        stream,
        Some(String::from_utf8(head).expect("the response head is ASCII")),
    )
}

fn status_code(head: &str) -> u16 {
    head.split_whitespace()
        .nth(1)
        .expect("the status line has a code")
        .parse()
        .expect("the status code is numeric")
}

const VALID_UPGRADE: &str = concat!(
    "GET /gateway HTTP/1.1\r\n",
    "Host: localhost\r\n",
    "Upgrade: websocket\r\n",
    "Connection: Upgrade\r\n",
    "Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n",
    "Sec-WebSocket-Version: 13\r\n\r\n"
);

/// Completes the HTTP upgrade and returns a raw client-role WebSocket.
async fn connect(address: SocketAddr) -> WebSocket<TcpStream> {
    let (stream, head) = upgrade_head(address, VALID_UPGRADE).await;
    let head = head.expect("the server answers the upgrade");
    assert_eq!(status_code(&head), 101, "{head}");
    let mut socket = WebSocket::after_handshake(stream, WsRole::Client);
    socket.set_auto_close(false);
    socket.set_auto_pong(false);
    socket
}

/// Reads the next text message, ignoring control frames.
async fn next_text(socket: &mut WebSocket<TcpStream>) -> Value {
    loop {
        let frame = socket
            .read_frame()
            .await
            .expect("the server keeps the socket readable");
        match frame.opcode {
            OpCode::Text => {
                let text = String::from_utf8(frame.payload.to_vec())
                    .expect("gateway frames are UTF-8 text");
                return serde_json::from_str(&text).expect("gateway frames are JSON");
            }
            OpCode::Ping | OpCode::Pong => {}
            OpCode::Close => panic!("the server closed while a text frame was expected"),
            OpCode::Binary | OpCode::Continuation => {
                panic!("the server sent a non-text data frame")
            }
        }
    }
}

/// Reads until the server closes, returning the close code and reason.
async fn next_close(socket: &mut WebSocket<TcpStream>) -> (u16, String) {
    loop {
        let frame = match socket.read_frame().await {
            Ok(frame) => frame,
            Err(error) => panic!("expected a close frame, got {error}"),
        };
        if frame.opcode == OpCode::Close {
            let payload = frame.payload.to_vec();
            assert!(payload.len() >= 2, "a close frame carries a status code");
            let code = u16::from_be_bytes([payload[0], payload[1]]);
            let reason =
                String::from_utf8(payload[2..].to_vec()).expect("the close reason is UTF-8");
            return (code, reason);
        }
    }
}

async fn send_text(socket: &mut WebSocket<TcpStream>, text: String) {
    socket
        .write_frame(Frame::text(Payload::Owned(text.into_bytes())))
        .await
        .expect("the client can write");
}

fn connect_request(role: &str, scopes: &[&str], min: u64, max: u64) -> String {
    json!({
        "type": "req",
        "id": "connect-1",
        "method": "connect",
        "params": {
            "minProtocol": min,
            "maxProtocol": max,
            "client": {
                "id": "test",
                "version": "0.0.1",
                "platform": "test",
                "mode": "test",
            },
            "role": role,
            "scopes": scopes,
        },
    })
    .to_string()
}

/// Drives the raw socket through a complete handshake and returns the hello.
async fn handshake(socket: &mut WebSocket<TcpStream>) -> Value {
    let challenge = next_text(socket).await;
    assert_eq!(challenge["type"], json!("event"));
    assert_eq!(challenge["event"], json!("connect.challenge"));
    assert!(
        challenge["payload"]["nonce"]
            .as_str()
            .expect("the challenge carries a nonce")
            .len()
            >= 43,
        "a 32-byte nonce encodes to at least 43 base64url characters"
    );

    send_text(
        socket,
        connect_request("operator", &["operator.admin"], 4, 4),
    )
    .await;
    let hello = next_text(socket).await;
    assert_eq!(hello["type"], json!("res"));
    assert_eq!(hello["id"], json!("connect-1"));
    assert_eq!(hello["ok"], json!(true));
    hello
}

#[tokio::test]
async fn an_upgrade_without_the_websocket_headers_is_refused() {
    let handle = start(fast_config()).await;
    let (_stream, head) = upgrade_head(
        handle.local_address(),
        "GET / HTTP/1.1\r\nHost: localhost\r\n\r\n",
    )
    .await;
    assert_eq!(status_code(&head.expect("the server answers")), 400);
    handle.shutdown().await;
}

#[tokio::test]
async fn an_unsupported_websocket_version_is_refused_with_upgrade_required() {
    let handle = start(fast_config()).await;
    let request = VALID_UPGRADE.replace("Sec-WebSocket-Version: 13", "Sec-WebSocket-Version: 8");
    let (_stream, head) = upgrade_head(handle.local_address(), &request).await;
    assert_eq!(status_code(&head.expect("the server answers")), 426);
    handle.shutdown().await;
}

#[tokio::test]
async fn a_non_get_upgrade_is_refused_with_method_not_allowed() {
    let handle = start(fast_config()).await;
    let request = VALID_UPGRADE.replace("GET /gateway", "POST /gateway");
    let (_stream, head) = upgrade_head(handle.local_address(), &request).await;
    assert_eq!(status_code(&head.expect("the server answers")), 405);
    handle.shutdown().await;
}

#[tokio::test]
async fn a_short_websocket_key_is_refused() {
    let handle = start(fast_config()).await;
    let request = VALID_UPGRADE.replace(
        "Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==",
        "Sec-WebSocket-Key: c2hvcnQ=",
    );
    let (_stream, head) = upgrade_head(handle.local_address(), &request).await;
    assert_eq!(status_code(&head.expect("the server answers")), 400);
    handle.shutdown().await;
}

#[tokio::test]
async fn a_requested_websocket_extension_is_refused() {
    let handle = start(fast_config()).await;
    let request = VALID_UPGRADE.replace(
        "Sec-WebSocket-Version: 13\r\n\r\n",
        "Sec-WebSocket-Version: 13\r\nSec-WebSocket-Extensions: permessage-deflate\r\n\r\n",
    );
    let (_stream, head) = upgrade_head(handle.local_address(), &request).await;
    assert_eq!(status_code(&head.expect("the server answers")), 400);
    handle.shutdown().await;
}

#[tokio::test]
async fn an_oversized_upgrade_request_is_refused_before_the_socket_is_upgraded() {
    let mut config = fast_config();
    config.limits.max_http_upgrade_bytes = 512;
    let handle = start(config).await;

    // Deliberately unterminated: the server must refuse on the byte budget
    // rather than waiting for a header terminator that never arrives. The
    // request stays small enough that the server consumes all of it, so the
    // refusal is delivered instead of being lost to a TCP reset.
    let padding = "x".repeat(600);
    let request =
        format!("GET /gateway HTTP/1.1\r\nHost: localhost\r\nX-Padding: {padding}\r\nUpgrade: web");
    assert!(request.len() > 512);
    assert!(request.len() < 1024);
    let (_stream, head) = upgrade_head(handle.local_address(), &request).await;
    assert_eq!(status_code(&head.expect("the server answers")), 431);
    handle.shutdown().await;
}

#[tokio::test]
async fn an_oversized_preauthentication_message_closes_with_message_too_big() {
    let handle = start(fast_config()).await;
    let mut socket = connect(handle.local_address()).await;
    let challenge = next_text(&mut socket).await;
    assert_eq!(challenge["event"], json!("connect.challenge"));

    // 64 KiB is the pre-authentication cap. The message is fragmented so the
    // server has to accumulate across frames: every fragment is consumed, and
    // the final small one is what pushes the total past the cap.
    let chunk = vec![b'a'; 1024];
    socket
        .write_frame(Frame::new(
            false,
            OpCode::Text,
            None,
            Payload::Owned(chunk.clone()),
        ))
        .await
        .expect("the client can write");
    for _ in 0..63 {
        socket
            .write_frame(Frame::new(
                false,
                OpCode::Continuation,
                None,
                Payload::Owned(chunk.clone()),
            ))
            .await
            .expect("the client can write");
    }
    socket
        .write_frame(Frame::new(
            true,
            OpCode::Continuation,
            None,
            Payload::Owned(vec![b'a'; 100]),
        ))
        .await
        .expect("the client can write");

    let (code, reason) = next_close(&mut socket).await;
    assert_eq!(code, 1009);
    assert_eq!(reason, "message too large");
    handle.shutdown().await;
}

#[tokio::test]
async fn a_binary_message_is_refused_as_a_protocol_violation() {
    let handle = start(fast_config()).await;
    let mut socket = connect(handle.local_address()).await;
    let challenge = next_text(&mut socket).await;
    assert_eq!(challenge["event"], json!("connect.challenge"));

    socket
        .write_frame(Frame::binary(Payload::Owned(vec![0x01, 0x02, 0x03])))
        .await
        .expect("the client can write");

    let (code, reason) = next_close(&mut socket).await;
    assert_eq!(code, 1002);
    assert_eq!(reason, "protocol violation");
    handle.shutdown().await;
}

#[tokio::test]
async fn a_first_frame_that_is_not_a_connect_request_is_refused() {
    let handle = start(fast_config()).await;
    let mut socket = connect(handle.local_address()).await;
    let challenge = next_text(&mut socket).await;
    assert_eq!(challenge["event"], json!("connect.challenge"));

    send_text(
        &mut socket,
        json!({ "type": "res", "id": "x", "ok": true }).to_string(),
    )
    .await;

    let (code, reason) = next_close(&mut socket).await;
    assert_eq!(code, 1002);
    assert_eq!(reason, "protocol violation");
    handle.shutdown().await;
}

#[tokio::test]
async fn a_control_frame_before_the_connect_request_is_refused() {
    let handle = start(fast_config()).await;
    let mut socket = connect(handle.local_address()).await;
    let challenge = next_text(&mut socket).await;
    assert_eq!(challenge["event"], json!("connect.challenge"));

    socket
        .write_frame(Frame::new(true, OpCode::Ping, None, Payload::Owned(vec![])))
        .await
        .expect("the client can write");

    let (code, reason) = next_close(&mut socket).await;
    assert_eq!(code, 1002);
    assert_eq!(reason, "protocol violation");
    handle.shutdown().await;
}

#[tokio::test]
async fn an_idle_peer_is_closed_when_the_handshake_window_expires() {
    let mut config = fast_config();
    config.timeouts.handshake = Duration::from_millis(150);
    let handle = start(config).await;
    let mut socket = connect(handle.local_address()).await;
    let challenge = next_text(&mut socket).await;
    assert_eq!(challenge["event"], json!("connect.challenge"));

    let (code, reason) = next_close(&mut socket).await;
    assert_eq!(code, 1011);
    assert_eq!(reason, "handshake timeout");
    handle.shutdown().await;
}

#[tokio::test]
async fn the_hello_advertises_the_frozen_catalog_and_the_negotiated_policy() {
    let handle = start(fast_config()).await;
    let mut socket = connect(handle.local_address()).await;
    let hello = handshake(&mut socket).await;

    let payload = &hello["payload"];
    assert_eq!(payload["type"], json!("hello-ok"));
    assert_eq!(payload["protocol"], json!(4));
    assert_eq!(payload["server"]["version"], json!("adversarial"));
    assert_eq!(payload["auth"]["role"], json!("operator"));
    assert_eq!(payload["auth"]["scopes"], json!(["operator.admin"]));
    assert_eq!(
        payload["features"]["methods"]
            .as_array()
            .expect("the hello advertises methods")
            .len(),
        258
    );
    assert_eq!(
        payload["features"]["events"]
            .as_array()
            .expect("the hello advertises events")
            .len(),
        33
    );
    assert_eq!(payload["policy"]["maxPayload"], json!(26_214_400));

    handle.shutdown().await;
}

#[tokio::test]
async fn the_server_answers_an_authenticated_ping_with_a_pong() {
    let handle = start(fast_config()).await;
    let mut socket = connect(handle.local_address()).await;
    handshake(&mut socket).await;

    socket
        .write_frame(Frame::new(
            true,
            OpCode::Ping,
            None,
            Payload::Owned(b"liveness".to_vec()),
        ))
        .await
        .expect("the client can write");

    loop {
        let frame = socket
            .read_frame()
            .await
            .expect("the socket stays readable");
        if frame.opcode == OpCode::Pong {
            assert_eq!(frame.payload.to_vec(), b"liveness".to_vec());
            break;
        }
        assert_ne!(frame.opcode, OpCode::Close, "the server must not close");
    }

    handle.shutdown().await;
}

#[tokio::test]
async fn a_second_connect_request_after_the_hello_is_rejected() {
    let handle = start(fast_config()).await;
    let mut socket = connect(handle.local_address()).await;
    handshake(&mut socket).await;

    send_text(
        &mut socket,
        connect_request("operator", &["operator.admin"], 4, 4),
    )
    .await;
    let response = next_text(&mut socket).await;
    assert_eq!(response["type"], json!("res"));
    assert_eq!(response["ok"], json!(false));
    assert_eq!(response["error"]["code"], json!("INVALID_REQUEST"));

    handle.shutdown().await;
}

#[tokio::test]
async fn a_request_burst_larger_than_the_inbound_queue_is_answered_in_wire_order() {
    const REQUESTS: usize = 64;

    let handle = start(fast_config()).await;
    let mut socket = connect(handle.local_address()).await;
    handshake(&mut socket).await;

    for index in 0..REQUESTS {
        send_text(
            &mut socket,
            json!({
                "type": "req",
                "id": format!("burst-{index}"),
                "method": "health",
                "params": {},
            })
            .to_string(),
        )
        .await;
    }

    for index in 0..REQUESTS {
        let response = next_text(&mut socket).await;
        assert_eq!(response["type"], json!("res"));
        assert_eq!(response["id"], json!(format!("burst-{index}")));
        assert_eq!(response["ok"], json!(true));
        assert_eq!(response["payload"]["protocol"], json!(4));
    }

    handle.shutdown().await;
}

#[tokio::test]
async fn a_slow_consumer_is_closed_once_its_bounded_queue_overflows() {
    let mut config = fast_config();
    config.limits.event_queue_capacity = 4;
    let handle = start(config).await;
    let mut socket = connect(handle.local_address()).await;
    handshake(&mut socket).await;

    // The current-thread runtime cannot run the connection task while this
    // synchronous burst is executing, so the bounded queue is guaranteed to
    // overflow rather than racing the reader.
    for index in 0_u32..32 {
        let draft = claw_gateway::EventDraft::broadcast(
            "heartbeat",
            &json!({ "source": "burst", "observedAtMs": index }),
        )
        .expect("heartbeat is catalogued");
        handle.events().publish(draft);
    }

    let mut delivered = 0_usize;
    let (code, reason) = loop {
        let frame = socket
            .read_frame()
            .await
            .expect("the socket stays readable");
        match frame.opcode {
            OpCode::Text => delivered += 1,
            OpCode::Close => {
                let payload = frame.payload.to_vec();
                let code = u16::from_be_bytes([payload[0], payload[1]]);
                break (
                    code,
                    String::from_utf8(payload[2..].to_vec()).expect("the reason is UTF-8"),
                );
            }
            OpCode::Ping | OpCode::Pong | OpCode::Binary | OpCode::Continuation => {}
        }
    };

    assert_eq!(code, 1013);
    assert_eq!(reason, "event backlog exceeded");
    assert!(
        delivered <= 5,
        "a capacity-4 queue must not deliver {delivered} events"
    );
    assert!(delivered > 0, "queued events are drained before the close");

    handle.shutdown().await;
}

#[tokio::test]
async fn the_connection_cap_refuses_sockets_beyond_the_limit() {
    let mut config = fast_config();
    config.limits.max_connections = 1;
    let handle = start(config).await;

    let mut first = connect(handle.local_address()).await;
    let challenge = next_text(&mut first).await;
    assert_eq!(challenge["event"], json!("connect.challenge"));
    assert_eq!(handle.connection_count(), 1);

    let (_stream, head) = upgrade_head(handle.local_address(), VALID_UPGRADE).await;
    assert_eq!(
        head, None,
        "a socket beyond the cap is dropped without an HTTP response"
    );
    assert_eq!(handle.connection_count(), 1);

    handle.shutdown().await;
}

#[tokio::test]
async fn shutdown_announces_the_shutdown_event_then_closes_with_going_away() {
    let handle = start(fast_config()).await;
    let mut socket = connect(handle.local_address()).await;
    handshake(&mut socket).await;

    let shutdown = tokio::spawn(async move { handle.shutdown().await });

    let event = next_text(&mut socket).await;
    assert_eq!(event["type"], json!("event"));
    assert_eq!(event["event"], json!("shutdown"));
    assert_eq!(event["seq"], json!(1));
    assert_eq!(
        event["payload"]["reason"],
        json!("gateway is shutting down")
    );

    let (code, reason) = next_close(&mut socket).await;
    assert_eq!(code, 1001);
    assert_eq!(reason, "server shutdown");

    shutdown.await.expect("the shutdown task completes");
}

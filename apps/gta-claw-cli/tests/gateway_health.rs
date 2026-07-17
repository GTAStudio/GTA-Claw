//! Process-level Gateway health diagnostic coverage over a real WebSocket.

#[allow(dead_code)]
#[path = "../../../crates/claw-gateway-client/tests/support/mod.rs"]
mod support;

use std::ffi::OsString;
use std::process::{Output, Stdio};
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::{Duration, Instant};

use claw_protocol::gateway::{
    AUTHENTICATED_MAX_FRAME_BYTES, ClientId, ClientMode, Codec, ConnectParams, RequestId,
};
use serde_json::{Value, json};
use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
use tokio::process::{Child, Command};
use tokio::sync::watch;

use support::{
    TestGateway, handler, receive_connect, receive_request, send_challenge, send_connect_error,
    send_json, send_raw_text, wait_for_close,
};

const TOKEN: &str = "stdin-only-diagnostic-token";
const TOKEN_WRAPPED: &str = "prefix-stdin-only-diagnostic-token-suffix";

#[derive(Clone, Debug)]
enum GatewayBehavior {
    Healthy {
        server_version: &'static str,
        expected_token: Option<&'static str>,
    },
    AuthenticationFailure,
    PairingRequired,
    HelloProtocol(u64),
    HealthNegative,
    HealthRpcFailure,
    HealthTimeout,
    HealthThenClose,
    MalformedResponse,
    OversizedResponse,
    ImmediateClose {
        close_flushed: watch::Sender<bool>,
    },
    HelloClaims {
        role: &'static str,
        scopes: &'static [&'static str],
    },
}

async fn spawn_gateway(behavior: GatewayBehavior, request_count: Arc<AtomicUsize>) -> TestGateway {
    TestGateway::spawn(handler(move |mut socket, _| {
        let behavior = behavior.clone();
        let request_count = Arc::clone(&request_count);
        async move {
            send_challenge(&mut socket).await;
            let (connect, params) = receive_connect(&mut socket).await;
            support::verify_connect_proof(&params);
            if matches!(
                behavior,
                GatewayBehavior::AuthenticationFailure | GatewayBehavior::PairingRequired
            ) {
                let code = if matches!(behavior, GatewayBehavior::PairingRequired) {
                    "PAIRING_REQUIRED"
                } else {
                    "AUTH_TOKEN_MISMATCH"
                };
                send_connect_error(&mut socket, connect.id(), code).await;
                return;
            }
            let expected_token = match behavior {
                GatewayBehavior::Healthy { expected_token, .. } => expected_token,
                _ => Some(TOKEN),
            };
            if !connect_matches(&params, expected_token) {
                send_connect_error(&mut socket, connect.id(), "AUTH_TOKEN_MISMATCH").await;
                return;
            }

            let (server_version, protocol, max_payload) = match behavior {
                GatewayBehavior::Healthy { server_version, .. } => {
                    (server_version, 4, AUTHENTICATED_MAX_FRAME_BYTES)
                }
                GatewayBehavior::HelloProtocol(protocol) => {
                    ("test-gateway", protocol, AUTHENTICATED_MAX_FRAME_BYTES)
                }
                GatewayBehavior::OversizedResponse => ("test-gateway", 4, 1_024),
                _ => ("test-gateway", 4, AUTHENTICATED_MAX_FRAME_BYTES),
            };
            let (hello_role, hello_scopes) = match behavior {
                GatewayBehavior::HelloClaims { role, scopes } => (role, scopes),
                _ => ("operator", &["operator.read"][..]),
            };
            send_hello(
                &mut socket,
                connect.id(),
                server_version,
                protocol,
                max_payload,
                hello_role,
                hello_scopes,
            )
            .await;
            if matches!(behavior, GatewayBehavior::HelloProtocol(_)) {
                return;
            }
            if let GatewayBehavior::ImmediateClose { close_flushed } = &behavior {
                socket
                    .write_frame(fastwebsockets::Frame::close(1000, b"diagnostic close"))
                    .await
                    .expect("send immediate close");
                socket.flush().await.expect("flush immediate close");
                close_flushed.send_replace(true);
                count_requests_until_close(&mut socket, &request_count).await;
                return;
            }
            if matches!(behavior, GatewayBehavior::HelloClaims { .. }) {
                count_requests_until_close(&mut socket, &request_count).await;
                return;
            }

            let request = receive_request(&mut socket).await;
            request_count.fetch_add(1, Ordering::SeqCst);
            let params_are_empty = request
                .params()
                .value()
                .and_then(|value| Codec::authenticated().decode_opaque::<Value>(value).ok())
                .is_some_and(|value| value == json!({}));
            if request.method().as_str() != "health" || !params_are_empty {
                send_json(
                    &mut socket,
                    json!({
                        "type": "res",
                        "id": request.id().as_str(),
                        "ok": false,
                        "error": {
                            "code": "INVALID_REQUEST",
                            "message": "unexpected diagnostic request"
                        }
                    }),
                )
                .await;
                wait_for_close(&mut socket).await;
                return;
            }
            match behavior {
                GatewayBehavior::Healthy { .. } => {
                    send_health(&mut socket, request.id().as_str(), true).await;
                    wait_for_close(&mut socket).await;
                }
                GatewayBehavior::HealthNegative => {
                    send_health(&mut socket, request.id().as_str(), false).await;
                    wait_for_close(&mut socket).await;
                }
                GatewayBehavior::HealthRpcFailure => {
                    send_json(
                        &mut socket,
                        json!({
                            "type": "res",
                            "id": request.id().as_str(),
                            "ok": false,
                            "error": {
                                "code": "UNAVAILABLE",
                                "message": format!("upstream exposed {TOKEN}")
                            }
                        }),
                    )
                    .await;
                    wait_for_close(&mut socket).await;
                }
                GatewayBehavior::HealthTimeout => wait_for_close(&mut socket).await,
                GatewayBehavior::HealthThenClose => {
                    send_health(&mut socket, request.id().as_str(), true).await;
                    socket
                        .write_frame(fastwebsockets::Frame::close(1000, b"response complete"))
                        .await
                        .expect("send close after health");
                    socket.flush().await.expect("flush response close");
                    count_requests_until_close(&mut socket, &request_count).await;
                }
                GatewayBehavior::MalformedResponse => {
                    send_raw_text(&mut socket, b"{not-json".to_vec()).await;
                    tokio::time::sleep(Duration::from_millis(500)).await;
                }
                GatewayBehavior::OversizedResponse => {
                    send_raw_text(&mut socket, vec![b'x'; 1_025]).await;
                    tokio::time::sleep(Duration::from_millis(500)).await;
                }
                GatewayBehavior::AuthenticationFailure
                | GatewayBehavior::PairingRequired
                | GatewayBehavior::HelloProtocol(_)
                | GatewayBehavior::ImmediateClose { .. }
                | GatewayBehavior::HelloClaims { .. } => unreachable!("handled before health"),
            }
        }
    }))
    .await
}

fn connect_matches(params: &ConnectParams, expected_token: Option<&str>) -> bool {
    let auth_matches = match (expected_token, params.auth.as_ref()) {
        (None, None) => true,
        (Some(expected), Some(auth)) => {
            auth.token.as_deref() == Some(expected)
                && auth.bootstrap_token.is_none()
                && auth.device_token.is_none()
                && auth.password.is_none()
                && auth.approval_runtime_token.is_none()
                && auth.agent_runtime_identity_token.is_none()
        }
        (None, Some(_)) | (Some(_), None) => false,
    };
    params.min_protocol.get() == 4
        && params.max_protocol.get() == 4
        && params.client.id == ClientId::Probe
        && params
            .client
            .display_name
            .as_ref()
            .map(|name| name.as_str())
            == Some("GTA Claw Gateway diagnostic")
        && params.client.version.as_str() == env!("CARGO_PKG_VERSION")
        && params.client.platform.as_str() == std::env::consts::OS
        && params.client.device_family.is_none()
        && params.client.model_identifier.is_none()
        && params.client.mode == ClientMode::Probe
        && params.client.instance_id.is_none()
        && params.caps.as_ref().is_some_and(Vec::is_empty)
        && params.commands.is_none()
        && params.permissions.is_none()
        && params.path_env.is_none()
        && params.role.as_ref().map(|role| role.as_str()) == Some("operator")
        && params
            .scopes
            .as_ref()
            .is_some_and(|scopes| scopes.len() == 1 && scopes[0].as_str() == "operator.read")
        && params
            .device
            .as_ref()
            .is_some_and(|device| device.nonce.as_str() == "test-nonce")
        && auth_matches
        && params.locale.is_none()
        && params.user_agent.is_none()
}

async fn send_hello(
    socket: &mut support::TestSocket,
    id: &RequestId,
    server_version: &str,
    protocol: u64,
    max_payload: usize,
    role: &str,
    scopes: &[&str],
) {
    send_json(
        socket,
        json!({
            "type": "res",
            "id": id.as_str(),
            "ok": true,
            "payload": {
                "type": "hello-ok",
                "protocol": protocol,
                "server": {"version": server_version, "connId": "test-connection"},
                "features": {
                    "methods": ["health"],
                    "events": ["connect.challenge", "tick"]
                },
                "snapshot": {
                    "presence": [],
                    "health": {},
                    "stateVersion": {"presence": 0, "health": 0},
                    "uptimeMs": 1,
                    "authMode": "token"
                },
                "auth": {"role": role, "scopes": scopes},
                "policy": {
                    "maxPayload": max_payload,
                    "maxBufferedBytes": max_payload,
                    "tickIntervalMs": 1000
                }
            }
        }),
    )
    .await;
}

async fn count_requests_until_close(socket: &mut support::TestSocket, request_count: &AtomicUsize) {
    loop {
        match socket.read_frame().await {
            Ok(frame) if frame.opcode == fastwebsockets::OpCode::Text => {
                request_count.fetch_add(1, Ordering::SeqCst);
            }
            Ok(frame) if frame.opcode == fastwebsockets::OpCode::Close => return,
            Ok(_) => {}
            Err(_) => return,
        }
    }
}

async fn send_health(socket: &mut support::TestSocket, id: &str, ok: bool) {
    send_json(
        socket,
        json!({
            "type": "res",
            "id": id,
            "ok": true,
            "payload": {
                "ok": ok,
                "ts": 1_700_000_000_123_u64,
                "durationMs": 17,
                "channels": {
                    "not-rendered": {
                        "secret": TOKEN,
                        "control": "line\nforgery"
                    }
                }
            }
        }),
    )
    .await;
}

async fn run_cli(arguments: Vec<OsString>, stdin: Option<&str>) -> Output {
    let mut command = Command::new(env!("CARGO_BIN_EXE_gta-claw-cli"));
    command
        .args(arguments)
        .stdin(if stdin.is_some() {
            Stdio::piped()
        } else {
            Stdio::null()
        })
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .kill_on_drop(true);
    let mut child = command.spawn().expect("CLI process starts");
    if let Some(input) = stdin {
        let mut pipe = child.stdin.take().expect("piped stdin");
        pipe.write_all(input.as_bytes())
            .await
            .expect("write token stdin");
        drop(pipe);
    }
    collect_child_output(child, Duration::from_secs(8), "CLI process").await
}

async fn run_cli_with_open_stdin(arguments: Vec<OsString>) -> (Output, Duration) {
    let mut command = Command::new(env!("CARGO_BIN_EXE_gta-claw-cli"));
    command
        .args(arguments)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .kill_on_drop(true);
    let mut child = command.spawn().expect("CLI process starts");
    let open_stdin = child.stdin.take().expect("open stdin pipe");
    let started = Instant::now();
    let output =
        collect_child_output(child, Duration::from_secs(3), "invalid-input CLI process").await;
    let elapsed = started.elapsed();
    drop(open_stdin);
    (output, elapsed)
}

async fn collect_child_output(mut child: Child, limit: Duration, label: &str) -> Output {
    let mut stdout = child.stdout.take().expect("piped stdout");
    let mut stderr = child.stderr.take().expect("piped stderr");
    let stdout_task = tokio::spawn(async move {
        let mut bytes = Vec::new();
        stdout.read_to_end(&mut bytes).await.expect("read stdout");
        bytes
    });
    let stderr_task = tokio::spawn(async move {
        let mut bytes = Vec::new();
        stderr.read_to_end(&mut bytes).await.expect("read stderr");
        bytes
    });
    let status = match tokio::time::timeout(limit, child.wait()).await {
        Ok(status) => status.expect("CLI process status"),
        Err(_) => {
            child.start_kill().expect("terminate timed-out CLI");
            let status = tokio::time::timeout(Duration::from_secs(2), child.wait())
                .await
                .expect("reap timed-out CLI")
                .expect("timed-out CLI status");
            let stdout = stdout_task.await.expect("stdout task");
            let stderr = stderr_task.await.expect("stderr task");
            panic!(
                "{label} exceeded {limit:?}: status={status} stdout={} stderr={}",
                String::from_utf8_lossy(&stdout),
                String::from_utf8_lossy(&stderr)
            );
        }
    };
    Output {
        status,
        stdout: stdout_task.await.expect("stdout task"),
        stderr: stderr_task.await.expect("stderr task"),
    }
}

fn gateway_arguments(url: &str) -> Vec<OsString> {
    let url = url.strip_suffix('/').unwrap_or(url);
    [
        "gateway",
        "health",
        "--endpoint",
        url,
        "--ephemeral-device",
        "--token-stdin",
        "--json",
    ]
    .into_iter()
    .map(OsString::from)
    .collect()
}

fn parse_json(output: &Output) -> Value {
    assert!(
        output.stderr.is_empty(),
        "unexpected stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    serde_json::from_slice(&output.stdout).expect("one JSON summary")
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn successful_hello_health_is_redacted_deterministic_and_closes_once() {
    let request_count = Arc::new(AtomicUsize::new(0));
    let gateway = spawn_gateway(
        GatewayBehavior::Healthy {
            server_version: "网关-v4",
            expected_token: Some(TOKEN),
        },
        Arc::clone(&request_count),
    )
    .await;
    let arguments = gateway_arguments(gateway.url.as_str());
    assert!(
        arguments
            .iter()
            .all(|argument| argument.to_string_lossy() != TOKEN),
        "token must not appear in argv"
    );
    let output = run_cli(arguments, Some(&format!("{TOKEN}\n"))).await;
    assert_eq!(output.status.code(), Some(0));
    let summary = parse_json(&output);
    let keys = summary
        .as_object()
        .expect("JSON object")
        .keys()
        .map(String::as_str)
        .collect::<Vec<_>>();
    assert_eq!(
        keys,
        [
            "category",
            "command",
            "elapsed_ms",
            "endpoint",
            "health",
            "identity",
            "message",
            "pairing_entry_possible",
            "protocol",
            "role",
            "schema_version",
            "scopes",
            "server",
            "status",
        ]
    );
    assert_eq!(summary["category"], "success");
    assert_eq!(summary["schema_version"], 2);
    assert_eq!(summary["status"], "healthy");
    assert_eq!(
        summary["endpoint"],
        gateway.url.origin().ascii_serialization()
    );
    assert_eq!(summary["protocol"], 4);
    assert_eq!(summary["role"], "operator");
    assert_eq!(summary["scopes"], json!(["operator.read"]));
    assert_eq!(summary["server"]["version"], Value::Null);
    assert_eq!(summary["server"]["version_status"], "redacted_peer_value");
    assert_eq!(summary["health"]["ok"], true);
    assert_eq!(summary["health"]["timestamp_ms"], 1_700_000_000_123_u64);
    assert_eq!(summary["health"]["duration_ms"], 17);
    assert_eq!(summary["identity"], "ephemeral");
    assert_eq!(summary["pairing_entry_possible"], true);
    let captured = format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(!captured.contains(TOKEN));
    assert!(!captured.contains("not-rendered"));
    assert_eq!(request_count.load(Ordering::SeqCst), 1);
    gateway.shutdown().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn peer_version_never_reflects_credentials_separators_or_bidi() {
    for peer_version in [
        TOKEN,
        TOKEN_WRAPPED,
        "gateway\u{2028}forged",
        "gateway\u{2029}forged",
        "gateway\u{202e}forged",
    ] {
        for json_output in [true, false] {
            let gateway = spawn_gateway(
                GatewayBehavior::Healthy {
                    server_version: peer_version,
                    expected_token: Some(TOKEN),
                },
                Arc::new(AtomicUsize::new(0)),
            )
            .await;
            let mut arguments = gateway_arguments(gateway.url.as_str());
            if !json_output {
                arguments.retain(|argument| argument != "--json");
            }
            let output = run_cli(arguments, Some(&format!("{TOKEN}\n"))).await;
            assert_eq!(output.status.code(), Some(0));
            let captured = format!(
                "{}{}",
                String::from_utf8_lossy(&output.stdout),
                String::from_utf8_lossy(&output.stderr)
            );
            assert!(!captured.contains(TOKEN));
            assert!(!captured.contains(peer_version));
            assert!(!captured.contains('\u{2028}'));
            assert!(!captured.contains('\u{2029}'));
            assert!(!captured.contains('\u{202e}'));
            if json_output {
                let summary = parse_json(&output);
                assert_eq!(summary["server"]["version"], Value::Null);
                assert_eq!(summary["server"]["version_status"], "redacted_peer_value");
            } else {
                assert!(captured.contains("server_version: [redacted peer value]"));
            }
            gateway.shutdown().await;
        }
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn authentication_and_pairing_failures_have_stable_category() {
    for (behavior, status) in [
        (
            GatewayBehavior::AuthenticationFailure,
            "authentication_failed",
        ),
        (GatewayBehavior::PairingRequired, "pairing_required"),
    ] {
        let gateway = spawn_gateway(behavior.clone(), Arc::new(AtomicUsize::new(0))).await;
        let output = run_cli(
            gateway_arguments(gateway.url.as_str()),
            Some(&format!("{TOKEN}\n")),
        )
        .await;
        assert_eq!(output.status.code(), Some(4));
        let summary = parse_json(&output);
        assert_eq!(summary["category"], "authentication_pairing");
        assert_eq!(summary["status"], status);
        gateway.shutdown().await;
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn no_token_is_explicit_and_wrong_token_is_rejected_by_the_server() {
    let gateway = spawn_gateway(
        GatewayBehavior::Healthy {
            server_version: "no-token-gateway",
            expected_token: None,
        },
        Arc::new(AtomicUsize::new(0)),
    )
    .await;
    let arguments = [
        "gateway",
        "health",
        "--endpoint",
        gateway
            .url
            .as_str()
            .strip_suffix('/')
            .expect("root endpoint"),
        "--ephemeral-device",
        "--json",
    ]
    .into_iter()
    .map(OsString::from)
    .collect();
    let output = run_cli(arguments, None).await;
    assert_eq!(output.status.code(), Some(0));
    assert_eq!(parse_json(&output)["status"], "healthy");
    gateway.shutdown().await;

    let gateway = spawn_gateway(
        GatewayBehavior::Healthy {
            server_version: "token-gateway",
            expected_token: Some(TOKEN),
        },
        Arc::new(AtomicUsize::new(0)),
    )
    .await;
    let wrong_token = "wrong-stdin-token";
    let output = run_cli(
        gateway_arguments(gateway.url.as_str()),
        Some(&format!("{wrong_token}\n")),
    )
    .await;
    assert_eq!(output.status.code(), Some(4));
    let captured = format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(!captured.contains(wrong_token));
    gateway.shutdown().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn immediate_post_hello_disconnect_is_stably_transport_failure() {
    for iteration in 0..100 {
        let (close_flushed, mut close_flushed_rx) = watch::channel(false);
        let request_count = Arc::new(AtomicUsize::new(0));
        let gateway = spawn_gateway(
            GatewayBehavior::ImmediateClose { close_flushed },
            Arc::clone(&request_count),
        )
        .await;
        let token_input = format!("{TOKEN}\n");
        let close_proof = async {
            tokio::time::timeout(
                Duration::from_secs(2),
                close_flushed_rx.wait_for(|flushed| *flushed),
            )
            .await
            .map(|result| result.map(|_| ()))
        };
        let (output, close_proof) = tokio::join!(
            run_cli(gateway_arguments(gateway.url.as_str()), Some(&token_input)),
            close_proof
        );
        gateway.shutdown().await;
        close_proof
            .unwrap_or_else(|_| panic!("iteration {iteration} timed out before close flush"))
            .unwrap_or_else(|_| panic!("iteration {iteration} lost close-flush publisher"));
        assert_eq!(output.status.code(), Some(3));
        let summary = parse_json(&output);
        assert_eq!(summary["category"], "transport_transient");
        assert_eq!(summary["status"], "transport_failure");
        assert!(
            request_count.load(Ordering::SeqCst) <= 1,
            "iteration {iteration} replayed health after close"
        );
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn health_response_wins_a_following_close_without_replay() {
    for _ in 0..25 {
        let request_count = Arc::new(AtomicUsize::new(0));
        let gateway =
            spawn_gateway(GatewayBehavior::HealthThenClose, Arc::clone(&request_count)).await;
        let output = run_cli(
            gateway_arguments(gateway.url.as_str()),
            Some(&format!("{TOKEN}\n")),
        )
        .await;
        assert_eq!(output.status.code(), Some(0));
        assert_eq!(parse_json(&output)["status"], "healthy");
        gateway.shutdown().await;
        assert_eq!(request_count.load(Ordering::SeqCst), 1);
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn unexpected_hello_role_or_scopes_are_protocol_failures_without_health_rpc() {
    for (role, scopes) in [
        ("operator", &[][..]),
        ("operator", &["operator.admin"][..]),
        ("operator", &["operator.read", "operator.admin"][..]),
        ("node", &["operator.read"][..]),
    ] {
        let request_count = Arc::new(AtomicUsize::new(0));
        let gateway = spawn_gateway(
            GatewayBehavior::HelloClaims { role, scopes },
            Arc::clone(&request_count),
        )
        .await;
        let output = run_cli(
            gateway_arguments(gateway.url.as_str()),
            Some(&format!("{TOKEN}\n")),
        )
        .await;
        assert_eq!(output.status.code(), Some(5));
        assert_eq!(parse_json(&output)["category"], "protocol");
        gateway.shutdown().await;
        assert_eq!(request_count.load(Ordering::SeqCst), 0);
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn protocol_version_control_text_malformed_and_oversized_are_rejected() {
    for behavior in [
        GatewayBehavior::HelloProtocol(3),
        GatewayBehavior::MalformedResponse,
        GatewayBehavior::OversizedResponse,
    ] {
        let gateway = spawn_gateway(behavior.clone(), Arc::new(AtomicUsize::new(0))).await;
        let output = run_cli(
            gateway_arguments(gateway.url.as_str()),
            Some(&format!("{TOKEN}\n")),
        )
        .await;
        assert_eq!(
            output.status.code(),
            Some(5),
            "behavior {behavior:?}: stdout={} stderr={}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
        let summary = parse_json(&output);
        assert_eq!(summary["category"], "protocol");
        gateway.shutdown().await;
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn health_negative_and_rpc_failure_are_exit_six_without_server_text() {
    for behavior in [
        GatewayBehavior::HealthNegative,
        GatewayBehavior::HealthRpcFailure,
    ] {
        let gateway = spawn_gateway(behavior, Arc::new(AtomicUsize::new(0))).await;
        let output = run_cli(
            gateway_arguments(gateway.url.as_str()),
            Some(&format!("{TOKEN}\n")),
        )
        .await;
        assert_eq!(output.status.code(), Some(6));
        let summary = parse_json(&output);
        assert_eq!(summary["category"], "health_negative");
        assert_eq!(summary["status"], "unhealthy");
        assert!(!String::from_utf8_lossy(&output.stdout).contains(TOKEN));
        gateway.shutdown().await;
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn command_timeout_cancels_health_and_closes_without_late_rpc() {
    let request_count = Arc::new(AtomicUsize::new(0));
    let gateway = spawn_gateway(GatewayBehavior::HealthTimeout, Arc::clone(&request_count)).await;
    let mut arguments = gateway_arguments(gateway.url.as_str());
    arguments.extend([OsString::from("--timeout-ms"), OsString::from("300")]);
    let output = run_cli(arguments, Some(&format!("{TOKEN}\n"))).await;
    assert_eq!(output.status.code(), Some(7));
    let summary = parse_json(&output);
    assert_eq!(summary["category"], "timeout_cancel");
    assert_eq!(summary["status"], "timeout");
    assert_eq!(request_count.load(Ordering::SeqCst), 1);
    gateway.shutdown().await;
    assert_eq!(request_count.load(Ordering::SeqCst), 1);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn unreachable_and_remote_plaintext_are_distinct_stable_failures() {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("reserve port");
    let address = listener.local_addr().expect("local address");
    drop(listener);
    let unreachable = format!("ws://{address}");
    let output = run_cli(gateway_arguments(&unreachable), Some(&format!("{TOKEN}\n"))).await;
    assert_eq!(output.status.code(), Some(3));
    assert_eq!(parse_json(&output)["category"], "transport_transient");

    let output = run_cli(
        gateway_arguments("ws://192.0.2.1:18789"),
        Some(&format!("{TOKEN}\n")),
    )
    .await;
    assert_eq!(output.status.code(), Some(2));
    let summary = parse_json(&output);
    assert_eq!(summary["category"], "usage_config");
    assert_eq!(summary["status"], "insecure_remote_ws");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn invalid_or_insecure_endpoints_exit_before_reading_stdin() {
    for endpoint in [
        "not-a-url",
        " ws://127.0.0.1:9",
        "ws://exa\u{200b}mple.com",
        "ws://exa\u{2060}mple.com",
        "ws://exa\u{feff}mple.com",
        "WS://127.0.0.1:9",
        "ws://LOCALHOST:9",
        "wss://例え.COM/socket",
        "wss://ｅxample.com",
        "wss://example。com",
        "ws://[0:0:0:0:0:0:0:1]:9",
        "wss://example.com:0443",
        "wss://example.com:0",
        "wss://example.com/a/../b",
        "wss://example.com/%62",
        "wss://example.com.",
        "wss://example..com",
        "wss://_foo.example",
        "ws://192.0.2.1:18789",
    ] {
        let (output, elapsed) = run_cli_with_open_stdin(gateway_arguments(endpoint)).await;
        assert_eq!(output.status.code(), Some(2), "endpoint {endpoint:?}");
        assert!(elapsed < Duration::from_secs(1), "endpoint {endpoint:?}");
        assert_eq!(parse_json(&output)["category"], "usage_config");
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn non_resolving_dns_cannot_hold_the_process_past_its_bound() {
    let mut arguments = gateway_arguments("wss://never-resolves.invalid");
    arguments.extend([OsString::from("--timeout-ms"), OsString::from("300")]);
    let started = Instant::now();
    let output = run_cli(arguments, Some(&format!("{TOKEN}\n"))).await;
    assert!(
        matches!(output.status.code(), Some(3) | Some(7)),
        "stdout={} stderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(started.elapsed() < Duration::from_secs(2));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn endpoint_credentials_query_and_fragment_are_never_rendered() {
    let endpoint = "ws://operator:argv-secret@127.0.0.1:9/path?token=query-secret#fragment-secret";
    let (output, elapsed) = run_cli_with_open_stdin(gateway_arguments(endpoint)).await;
    assert_eq!(output.status.code(), Some(2));
    assert!(elapsed < Duration::from_secs(1));
    let summary = parse_json(&output);
    assert_eq!(summary["category"], "usage_config");
    assert_eq!(summary["status"], "credential_bearing_endpoint");
    assert_eq!(summary["endpoint"], "ws://127.0.0.1:9");
    let captured = String::from_utf8_lossy(&output.stdout);
    for secret in ["argv-secret", "query-secret", "fragment-secret"] {
        assert!(!captured.contains(secret));
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn stdin_errors_and_token_file_fail_closed_before_network() {
    let output = run_cli(
        gateway_arguments("ws://127.0.0.1:9"),
        Some("two lines\nare rejected\n"),
    )
    .await;
    assert_eq!(output.status.code(), Some(2));
    assert_eq!(parse_json(&output)["status"], "secret_invalid");

    let arguments = [
        "gateway".into(),
        "health".into(),
        "--endpoint".into(),
        "ws://127.0.0.1:9".into(),
        "--ephemeral-device".into(),
        "--token-file".into(),
        "token.txt".into(),
        "--json".into(),
    ]
    .to_vec();
    let output = run_cli(arguments, None).await;
    assert_eq!(output.status.code(), Some(2));
    assert_eq!(parse_json(&output)["status"], "token_file_unsupported");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn timeout_terminates_an_open_stdin_secret_source() {
    let mut command = Command::new(env!("CARGO_BIN_EXE_gta-claw-cli"));
    command
        .args([
            "gateway",
            "health",
            "--endpoint",
            "ws://127.0.0.1:9",
            "--ephemeral-device",
            "--token-stdin",
            "--timeout-ms",
            "300",
            "--json",
        ])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .kill_on_drop(true);
    let mut child = command.spawn().expect("CLI process starts");
    let open_stdin = child.stdin.take().expect("open stdin pipe");
    let output = tokio::time::timeout(Duration::from_secs(3), child.wait_with_output())
        .await
        .expect("CLI must not hang on open stdin")
        .expect("CLI output");
    drop(open_stdin);
    assert_eq!(output.status.code(), Some(7));
    let summary = parse_json(&output);
    assert_eq!(summary["category"], "timeout_cancel");
    assert_eq!(summary["status"], "timeout");
}

#[cfg(unix)]
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn sigint_cancels_and_joins_the_gateway_task() {
    let request_count = Arc::new(AtomicUsize::new(0));
    let gateway = spawn_gateway(GatewayBehavior::HealthTimeout, Arc::clone(&request_count)).await;
    let mut command = Command::new(env!("CARGO_BIN_EXE_gta-claw-cli"));
    command
        .args(gateway_arguments(gateway.url.as_str()))
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .kill_on_drop(true);
    let mut child = command.spawn().expect("CLI process starts");
    let mut stdin = child.stdin.take().expect("token stdin");
    stdin
        .write_all(format!("{TOKEN}\n").as_bytes())
        .await
        .expect("write token");
    drop(stdin);
    tokio::time::timeout(Duration::from_secs(3), async {
        while request_count.load(Ordering::SeqCst) == 0 {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .expect("health request observed");
    let pid = child.id().expect("child process id");
    let signal = Command::new("kill")
        .args(["-INT", &pid.to_string()])
        .status()
        .await
        .expect("send SIGINT");
    assert!(signal.success());
    let output = tokio::time::timeout(Duration::from_secs(5), child.wait_with_output())
        .await
        .expect("cancelled CLI timeout")
        .expect("cancelled CLI output");
    assert_eq!(output.status.code(), Some(7));
    let summary = parse_json(&output);
    assert_eq!(summary["category"], "timeout_cancel");
    assert_eq!(summary["status"], "cancelled");
    gateway.shutdown().await;
    assert_eq!(request_count.load(Ordering::SeqCst), 1);
}

//! Process-level Gateway health diagnostic coverage over a real WebSocket.

#[expect(
    dead_code,
    reason = "the Gateway test double is shared with claw-gateway-client, which owns the file; \
              this binary exercises only the subset the CLI diagnostic needs"
)]
#[path = "../../../crates/claw-gateway-client/tests/support/mod.rs"]
mod support;

use std::ffi::OsString;
use std::fs;
use std::path::PathBuf;
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
            .map(claw_protocol::gateway::Name::as_str)
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
        && params
            .role
            .as_ref()
            .map(claw_protocol::gateway::Name::as_str)
            == Some("operator")
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
        .env_remove("GTA_CLAW_LOG")
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
    let Ok(status) = tokio::time::timeout(limit, child.wait()).await else {
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
    };
    let status = status.expect("CLI process status");
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
    // Field order is now the declaration order of the summary struct rather
    // than an alphabetical accident, so the diagnostic reads top-down: what ran,
    // how it went, then the connection facts behind that verdict.
    assert_eq!(
        keys,
        [
            "schema_version",
            "command",
            "status",
            "category",
            "message",
            "endpoint",
            "protocol",
            "role",
            "scopes",
            "server",
            "health",
            "elapsed_ms",
            "identity",
            "pairing_entry_possible",
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
        matches!(output.status.code(), Some(3 | 7)),
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

/// Runs `gateway health` against one healthy Gateway once per argument set.
async fn run_healthy(runs: &[&[&str]]) -> Vec<Output> {
    let request_count = Arc::new(AtomicUsize::new(0));
    let gateway = spawn_gateway(
        GatewayBehavior::Healthy {
            server_version: "diag-v1",
            expected_token: Some(TOKEN),
        },
        Arc::clone(&request_count),
    )
    .await;
    let mut outputs = Vec::with_capacity(runs.len());
    for extra in runs {
        let mut arguments = gateway_arguments(gateway.url.as_str());
        arguments.extend(extra.iter().copied().map(OsString::from));
        let output = run_cli(arguments, Some(&format!("{TOKEN}\n"))).await;
        assert_eq!(
            output.status.code(),
            Some(0),
            "stderr={}",
            String::from_utf8_lossy(&output.stderr)
        );
        outputs.push(output);
    }
    gateway.shutdown().await;
    outputs
}

/// Parses the summary without the "stderr is empty" precondition `parse_json` enforces.
fn summary_of(output: &Output) -> Value {
    serde_json::from_slice(&output.stdout).expect("one JSON summary")
}

/// Replaces the one non-deterministic field so two runs can be compared byte for byte.
fn normalize(output: &Output) -> Value {
    let mut summary = summary_of(output);
    summary["elapsed_ms"] = json!(0);
    summary
}

/// Parses the `claw-observability` JSON records the subscriber writes.
///
/// The shape is the shared layer's, not this binary's: `level`, `target`, and a
/// redacted `fields` map. Asserting on it here proves the diagnostics really do
/// travel through the installed subscriber rather than a private writer.
fn diagnostic_lines(output: &Output) -> Vec<Value> {
    records(&String::from_utf8(output.stderr.clone()).expect("diagnostics are UTF-8"))
}

/// Parses the JSON records the installed subscriber wrote, from either sink.
fn records(text: &str) -> Vec<Value> {
    text.lines()
        .map(|line| {
            let record: Value = serde_json::from_str(line)
                .unwrap_or_else(|error| panic!("diagnostics are JSON lines: {error}: {line}"));
            assert!(
                record["fields"]["action"].is_string(),
                "every diagnostic line is one of this binary's events: {line}"
            );
            assert!(
                record["target"]
                    .as_str()
                    .expect("target")
                    .starts_with("gta_claw_cli"),
                "no dependency may share this stream: {line}"
            );
            record
        })
        .collect()
}

/// A path under Cargo's per-target temporary directory, cleared of any leftover.
///
/// The file is opened in append mode, so a stale run must not be able to add
/// records to the ones this test asserts on.
fn log_path(name: &str) -> PathBuf {
    let path = PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join(name);
    let _ = fs::remove_file(&path);
    path
}

fn fields(record: &Value) -> &Value {
    &record["fields"]
}

fn find<'a>(records: &'a [Value], action: &str) -> Option<&'a Value> {
    records
        .iter()
        .find(|record| record["fields"]["action"] == action)
}

fn actions(records: &[Value]) -> Vec<String> {
    records
        .iter()
        .map(|record| {
            record["fields"]["action"]
                .as_str()
                .expect("action")
                .to_owned()
        })
        .collect()
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn verbose_diagnostics_are_additive_and_leave_the_json_contract_untouched() {
    let outputs = run_healthy(&[&[], &["--verbose"]]).await;
    let (quiet, verbose) = (&outputs[0], &outputs[1]);
    assert!(
        quiet.stderr.is_empty(),
        "the default run must stay silent: {}",
        String::from_utf8_lossy(&quiet.stderr)
    );
    assert_eq!(
        normalize(quiet),
        normalize(verbose),
        "verbosity must not alter the schema-version-2 object"
    );
    assert_eq!(
        String::from_utf8_lossy(&quiet.stdout)
            .split("\"elapsed_ms\"")
            .next(),
        String::from_utf8_lossy(&verbose.stdout)
            .split("\"elapsed_ms\"")
            .next(),
        "key order must be byte-identical up to the elapsed measurement"
    );

    let records = diagnostic_lines(verbose);
    let observed = actions(&records);
    for expected in [
        "endpoint.resolve",
        "credential.read",
        "identity.generate",
        "client.start",
        "connection.ready",
        "authorization.grant",
        "rpc.response",
        "client.shutdown",
        "diagnostic.complete",
    ] {
        assert!(
            observed.iter().any(|action| action == expected),
            "missing {expected} in {observed:?}"
        );
    }
    assert!(
        !observed.iter().any(|action| action == "rpc.request"),
        "correlation detail belongs to -vv only: {observed:?}"
    );
    for record in &records {
        assert_eq!(record["level"], "DEBUG", "stage events are the -v level");
        if fields(record)["action"] != "telemetry.install" {
            assert_eq!(
                fields(record)["endpoint"],
                summary_of(verbose)["endpoint"],
                "every event after resolution names the endpoint the verdict names"
            );
        }
        for (key, value) in fields(record).as_object().expect("field map") {
            // Nothing here is a secret, so a redacted value means a field was
            // named badly and silently lost its content.
            assert_ne!(
                value, "[REDACTED]",
                "{key} is redacted by its own name; rename it"
            );
        }
    }
    let ready = find(&records, "connection.ready").expect("connection.ready");
    assert_eq!(fields(ready)["protocol.negotiated"], 4);
    let grant = find(&records, "authorization.grant").expect("authorization.grant");
    assert_eq!(fields(grant)["outcome"], "success");
    assert_eq!(fields(grant)["role.granted"], "operator");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn diagnostics_never_carry_the_token_and_detail_is_opt_in() {
    let outputs = run_healthy(&[&["-vv"]]).await;
    let verbose = &outputs[0];
    let stderr = String::from_utf8(verbose.stderr.clone()).expect("diagnostics are UTF-8");
    assert!(
        !stderr.contains(TOKEN),
        "the stdin token must never reach the diagnostic stream"
    );
    assert!(
        !stderr.contains(TOKEN_WRAPPED),
        "no substring form of the token may appear either"
    );
    let records = diagnostic_lines(verbose);
    let observed = actions(&records);
    for expected in ["rpc.request", "connection.epoch", "command.bounds"] {
        assert!(
            observed.iter().any(|action| action == expected),
            "missing {expected} in {observed:?}"
        );
    }
    let install = find(&records, "telemetry.install").expect("telemetry.install");
    assert_eq!(
        fields(install)["telemetry.default_filter"],
        "gta_claw_cli=trace",
        "a bare level would put bridged dependency `log` records on this stream"
    );
    assert!(
        records
            .iter()
            .any(|record| record["level"] == "TRACE" && record["level"] != "DEBUG"),
        "-vv opens the trace level: {observed:?}"
    );
    let credential = find(&records, "credential.read").expect("credential.read");
    assert_eq!(fields(credential)["auth.source"], "stdin");
    assert!(
        fields(credential)
            .as_object()
            .expect("field map")
            .values()
            .all(|value| value != TOKEN),
        "no field may carry the secret verbatim"
    );
    assert!(
        fields(credential)["message"].as_str().unwrap_or_default() != TOKEN,
        "message text bypasses redaction, so it must never carry the secret"
    );
    assert_eq!(
        String::from_utf8_lossy(&verbose.stdout)
            .matches('\n')
            .count(),
        1,
        "diagnostics must never be written to stdout"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_rejected_hello_names_the_stage_that_failed() {
    let request_count = Arc::new(AtomicUsize::new(0));
    let gateway = spawn_gateway(
        GatewayBehavior::HelloClaims {
            role: "node",
            scopes: &["operator.read"],
        },
        Arc::clone(&request_count),
    )
    .await;
    let mut arguments = gateway_arguments(gateway.url.as_str());
    arguments.push(OsString::from("--verbose"));
    let output = run_cli(arguments, Some(&format!("{TOKEN}\n"))).await;
    gateway.shutdown().await;
    assert_eq!(output.status.code(), Some(5));
    assert_eq!(request_count.load(Ordering::SeqCst), 0);

    let records = diagnostic_lines(&output);
    let observed = actions(&records);
    assert!(
        !observed.iter().any(|action| action == "rpc.response"),
        "the RPC never ran, so it must not be reported: {observed:?}"
    );
    let ready = find(&records, "connection.ready")
        .unwrap_or_else(|| panic!("connection.ready in {observed:?}"));
    assert_eq!(
        fields(ready)["outcome"],
        "failure",
        "the stage that failed must say so"
    );
    assert_eq!(fields(ready)["failure.category"], "protocol");
    assert_eq!(fields(ready)["failure.exit_code"], 5);
    let complete = find(&records, "diagnostic.complete").expect("diagnostic.complete");
    assert_eq!(fields(complete)["failure.category"], "protocol");
    assert_eq!(fields(complete)["failure.exit_code"], 5);
    assert_eq!(
        fields(complete)["failure.status"],
        summary_of(&output)["status"]
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_log_file_takes_every_record_and_leaves_standard_error_clean() {
    let path = log_path("cli-diagnostics.jsonl");
    let flag = path.to_str().expect("UTF-8 path").to_owned();
    let outputs = run_healthy(&[&[], &["--verbose"], &["--verbose", "--log-file", &flag]]).await;
    let (quiet, to_stderr, to_file) = (&outputs[0], &outputs[1], &outputs[2]);

    // The default is unchanged: without the flag the records are still on
    // standard error, and the flag is the only thing that moves them.
    let on_stderr = diagnostic_lines(to_stderr);
    assert!(
        !on_stderr.is_empty(),
        "-v alone still writes to standard error"
    );
    assert!(
        to_file.stderr.is_empty(),
        "the file is the destination, so standard error stays a clean stream: {}",
        String::from_utf8_lossy(&to_file.stderr)
    );
    assert_eq!(
        normalize(quiet),
        normalize(to_file),
        "a destination must not alter the schema-version-2 object"
    );

    let text = fs::read_to_string(&path).expect("the requested log file was written");
    let written = records(&text);
    assert_eq!(
        actions(&written),
        actions(&on_stderr),
        "the same records, only somewhere else"
    );
    let install = find(&written, "telemetry.install").expect("telemetry.install");
    assert_eq!(
        fields(install)["telemetry.output"],
        Value::from(path.display().to_string()),
        "the installed destination is reported as the file, not stderr"
    );
    assert!(
        !text.contains(TOKEN),
        "the stdin token must never reach the diagnostic file either"
    );
    fs::remove_file(&path).expect("remove the log file");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn an_unopenable_log_file_fails_the_command_without_falling_back_to_stderr() {
    let directory = PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join("no-such-cli-directory");
    let path = directory.join("run.jsonl");
    let flag = path.to_str().expect("UTF-8 path");
    // Nothing is contacted and standard input is never read: the destination is
    // resolved before the Gateway path starts, so this endpoint never answers.
    let mut json_arguments = gateway_arguments("ws://127.0.0.1:1");
    json_arguments.extend(
        ["--verbose", "--log-file", flag]
            .into_iter()
            .map(OsString::from),
    );
    let json_run = run_cli(json_arguments, None).await;

    assert_eq!(
        json_run.status.code(),
        Some(2),
        "an unusable destination is a usage failure, not a silent redirect"
    );
    let summary = parse_json(&json_run);
    assert_eq!(summary["schema_version"], 2);
    assert_eq!(summary["status"], "log_file_unusable");
    assert_eq!(summary["category"], "usage_config");
    assert_eq!(
        summary["message"],
        "diagnostic log file directory does not exist"
    );
    assert_eq!(summary["endpoint"], "ws://127.0.0.1:1");

    let mut text_arguments: Vec<OsString> = [
        "gateway",
        "health",
        "--endpoint",
        "ws://127.0.0.1:1",
        "--ephemeral-device",
    ]
    .into_iter()
    .map(OsString::from)
    .collect();
    text_arguments.extend(["-vv", "--log-file", flag].into_iter().map(OsString::from));
    let text_run = run_cli(text_arguments, None).await;

    assert_eq!(text_run.status.code(), Some(2));
    assert!(text_run.stdout.is_empty());
    let text = String::from_utf8(text_run.stderr).expect("UTF-8 failure text");
    assert!(
        text.starts_with(
            "Gateway health failed: diagnostic log file directory does not exist (usage_config)\n"
        ),
        "{text}"
    );
    assert!(
        text.contains("\nnext: point --log-file at a writable path"),
        "{text}"
    );
    assert!(text.contains("\nexit code: 2 (usage_config)\n"), "{text}");
    assert!(
        !text.contains("gta_claw_cli"),
        "not one diagnostic record may fall back to standard error: {text}"
    );
    assert!(!path.exists(), "a failed open creates nothing");
    assert!(!directory.exists(), "and never creates the directory");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_log_file_without_verbosity_stays_silent_and_opens_nothing() {
    let path = log_path("cli-quiet.jsonl");
    let flag = path.to_str().expect("UTF-8 path").to_owned();
    let outputs = run_healthy(&[&[], &["--log-file", &flag]]).await;

    assert_eq!(
        normalize(&outputs[0]),
        normalize(&outputs[1]),
        "a destination without -v changes nothing"
    );
    assert!(outputs[1].stderr.is_empty());
    assert!(
        !path.exists(),
        "no verbosity means no destination, so the file is never opened"
    );
}

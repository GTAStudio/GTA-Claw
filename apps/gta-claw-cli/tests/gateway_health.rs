//! Process-level Gateway health diagnostic coverage over a real WebSocket.

#[allow(dead_code)]
#[path = "../../../crates/claw-gateway-client/tests/support/mod.rs"]
mod support;

use std::ffi::OsString;
use std::fs;
use std::process::{Output, Stdio};
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use claw_protocol::gateway::{AUTHENTICATED_MAX_FRAME_BYTES, ConnectParams, RequestId};
use serde_json::{Value, json};
use tokio::io::AsyncWriteExt as _;
use tokio::process::Command;

use support::{
    TestGateway, handler, receive_connect, receive_request, send_challenge, send_connect_error,
    send_json, send_raw_text, wait_for_close,
};

const TOKEN: &str = "stdin-only-diagnostic-token";

#[derive(Clone, Debug)]
enum GatewayBehavior {
    Healthy { server_version: &'static str },
    AuthenticationFailure,
    PairingRequired,
    HelloProtocol(u64),
    HealthNegative,
    HealthRpcFailure,
    HealthTimeout,
    MalformedResponse,
    OversizedResponse,
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

            let (server_version, protocol, max_payload) = match behavior {
                GatewayBehavior::Healthy { server_version } => {
                    (server_version, 4, AUTHENTICATED_MAX_FRAME_BYTES)
                }
                GatewayBehavior::HelloProtocol(protocol) => {
                    ("test-gateway", protocol, AUTHENTICATED_MAX_FRAME_BYTES)
                }
                GatewayBehavior::OversizedResponse => ("test-gateway", 4, 1_024),
                _ => ("test-gateway", 4, AUTHENTICATED_MAX_FRAME_BYTES),
            };
            send_hello(
                &mut socket,
                connect.id(),
                &params,
                server_version,
                protocol,
                max_payload,
            )
            .await;
            if matches!(behavior, GatewayBehavior::HelloProtocol(_)) {
                return;
            }
            if server_version.chars().any(char::is_control) {
                wait_for_close(&mut socket).await;
                return;
            }

            let request = receive_request(&mut socket).await;
            request_count.fetch_add(1, Ordering::SeqCst);
            assert_eq!(request.method().as_str(), "health");
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
                | GatewayBehavior::HelloProtocol(_) => unreachable!("handled before health"),
            }
        }
    }))
    .await
}

async fn send_hello(
    socket: &mut support::TestSocket,
    id: &RequestId,
    params: &ConnectParams,
    server_version: &str,
    protocol: u64,
    max_payload: usize,
) {
    let role = params
        .role
        .as_ref()
        .map_or("operator", |role| role.as_str());
    let scopes = params.scopes.as_ref().map_or_else(Vec::new, |scopes| {
        scopes
            .iter()
            .map(|scope| scope.as_str())
            .collect::<Vec<_>>()
    });
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
    tokio::time::timeout(Duration::from_secs(8), child.wait_with_output())
        .await
        .expect("CLI process timeout")
        .expect("CLI process output")
}

fn gateway_arguments(url: &str) -> Vec<OsString> {
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
    assert_eq!(summary["status"], "healthy");
    assert_eq!(
        summary["endpoint"],
        gateway.url.origin().ascii_serialization()
    );
    assert_eq!(summary["protocol"], 4);
    assert_eq!(summary["role"], "operator");
    assert_eq!(summary["scopes"], json!(["operator.read"]));
    assert_eq!(summary["server"]["version"], "网关-v4");
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
async fn protocol_version_control_text_malformed_and_oversized_are_rejected() {
    for behavior in [
        GatewayBehavior::HelloProtocol(3),
        GatewayBehavior::Healthy {
            server_version: "gateway\nforged",
        },
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
        assert!(!String::from_utf8_lossy(&output.stdout).contains("forged"));
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
async fn endpoint_credentials_query_and_fragment_are_never_rendered() {
    let endpoint = "ws://operator:argv-secret@127.0.0.1:9/path?token=query-secret#fragment-secret";
    let output = run_cli(gateway_arguments(endpoint), Some(&format!("{TOKEN}\n"))).await;
    assert_eq!(output.status.code(), Some(2));
    let summary = parse_json(&output);
    assert_eq!(summary["endpoint"], "ws://127.0.0.1:9");
    let captured = String::from_utf8_lossy(&output.stdout);
    for secret in ["argv-secret", "query-secret", "fragment-secret", TOKEN] {
        assert!(!captured.contains(secret));
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn stdin_and_file_contract_errors_fail_before_network() {
    let output = run_cli(
        gateway_arguments("ws://127.0.0.1:9"),
        Some("two lines\nare rejected\n"),
    )
    .await;
    assert_eq!(output.status.code(), Some(2));
    assert_eq!(parse_json(&output)["status"], "secret_invalid");

    let missing = unique_temp_path("missing");
    let arguments = [
        "gateway".into(),
        "health".into(),
        "--endpoint".into(),
        "ws://127.0.0.1:9".into(),
        "--ephemeral-device".into(),
        "--token-file".into(),
        missing.into_os_string(),
        "--json".into(),
    ]
    .to_vec();
    let output = run_cli(arguments, None).await;
    assert_eq!(output.status.code(), Some(2));
    assert_eq!(parse_json(&output)["status"], "secret_file_error");

    let oversized = unique_temp_path("oversized");
    fs::write(&oversized, vec![b'x'; 4_097]).expect("write oversized token");
    secure_test_file(&oversized);
    let arguments = [
        "gateway".into(),
        "health".into(),
        "--endpoint".into(),
        "ws://127.0.0.1:9".into(),
        "--ephemeral-device".into(),
        "--token-file".into(),
        oversized.clone().into_os_string(),
        "--json".into(),
    ]
    .to_vec();
    let output = run_cli(arguments, None).await;
    fs::remove_file(oversized).expect("remove oversized token");
    assert_eq!(output.status.code(), Some(2));
    assert_eq!(parse_json(&output)["status"], "secret_too_large");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn token_file_can_drive_a_successful_probe_without_an_argv_secret() {
    let gateway = spawn_gateway(
        GatewayBehavior::Healthy {
            server_version: "file-token-gateway",
        },
        Arc::new(AtomicUsize::new(0)),
    )
    .await;
    let token_file = unique_temp_path("secure-token");
    fs::write(&token_file, TOKEN).expect("write token file");
    secure_test_file(&token_file);
    let arguments = [
        "gateway".into(),
        "health".into(),
        "--endpoint".into(),
        gateway.url.as_str().into(),
        "--ephemeral-device".into(),
        "--token-file".into(),
        token_file.clone().into_os_string(),
        "--json".into(),
    ]
    .to_vec();
    assert!(
        arguments
            .iter()
            .all(|argument: &OsString| argument.to_string_lossy() != TOKEN)
    );
    let output = run_cli(arguments, None).await;
    fs::remove_file(token_file).expect("remove token file");
    assert_eq!(output.status.code(), Some(0));
    assert_eq!(parse_json(&output)["status"], "healthy");
    gateway.shutdown().await;
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
async fn insecure_and_symlinked_unix_token_files_are_rejected() {
    use std::os::unix::fs::{PermissionsExt as _, symlink};

    let token = unique_temp_path("token");
    fs::write(&token, TOKEN).expect("write token");
    fs::set_permissions(&token, fs::Permissions::from_mode(0o644)).expect("set insecure mode");
    let mut arguments: Vec<OsString> = [
        "gateway",
        "health",
        "--endpoint",
        "ws://127.0.0.1:9",
        "--ephemeral-device",
        "--token-file",
    ]
    .into_iter()
    .map(OsString::from)
    .collect();
    arguments.extend([token.clone().into_os_string(), "--json".into()]);
    let output = run_cli(arguments, None).await;
    assert_eq!(output.status.code(), Some(2));
    assert_eq!(parse_json(&output)["status"], "secret_file_permissions");

    fs::set_permissions(&token, fs::Permissions::from_mode(0o600)).expect("set secure mode");
    let alias = unique_temp_path("alias");
    symlink(&token, &alias).expect("create token symlink");
    let mut arguments: Vec<OsString> = [
        "gateway",
        "health",
        "--endpoint",
        "ws://127.0.0.1:9",
        "--ephemeral-device",
        "--token-file",
    ]
    .into_iter()
    .map(OsString::from)
    .collect();
    arguments.extend([alias.clone().into_os_string(), "--json".into()]);
    let output = run_cli(arguments, None).await;
    fs::remove_file(alias).expect("remove alias");
    fs::remove_file(token).expect("remove token");
    assert_eq!(output.status.code(), Some(2));
    assert_eq!(parse_json(&output)["status"], "secret_file_alias");

    let fifo = unique_temp_path("fifo");
    let created = Command::new("mkfifo")
        .arg(&fifo)
        .status()
        .await
        .expect("create FIFO");
    assert!(created.success());
    let mut arguments: Vec<OsString> = [
        "gateway",
        "health",
        "--endpoint",
        "ws://127.0.0.1:9",
        "--ephemeral-device",
        "--token-file",
    ]
    .into_iter()
    .map(OsString::from)
    .collect();
    arguments.extend([fifo.clone().into_os_string(), "--json".into()]);
    let output = run_cli(arguments, None).await;
    fs::remove_file(fifo).expect("remove FIFO");
    assert_eq!(output.status.code(), Some(2));
    assert_eq!(parse_json(&output)["status"], "secret_file_type");
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

fn unique_temp_path(label: &str) -> std::path::PathBuf {
    let nonce = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system clock")
        .as_nanos();
    std::path::PathBuf::from(format!(
        "gta-claw-cli-{label}-{}-{nonce}",
        std::process::id()
    ))
}

fn secure_test_file(path: &std::path::Path) {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        fs::set_permissions(path, fs::Permissions::from_mode(0o600))
            .expect("secure test file mode");
    }
    #[cfg(not(unix))]
    let _ = path;
}

//! Process-level acceptance coverage for the bound production composition.

use std::io::{BufRead, BufReader, Read, Write};
use std::net::{SocketAddr, TcpStream};
use std::path::{Path, PathBuf};
use std::process::{Child, ChildStdin, Command, Stdio};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::mpsc::{self, Receiver};
use std::thread;
use std::time::Duration;

use claw_config::{migrate_legacy_environment, to_json5};

static NEXT_ROOT: AtomicU64 = AtomicU64::new(0);

struct Running {
    child: Child,
    stdin: ChildStdin,
    stdout: Receiver<String>,
    root: PathBuf,
    config: PathBuf,
    http: SocketAddr,
    legacy: SocketAddr,
}

struct StartupChildGuard(Child, PathBuf);

impl Drop for StartupChildGuard {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
        let _ = std::fs::remove_dir_all(&self.1);
    }
}

impl Running {
    fn start(model: &str) -> Self {
        Self::start_with_channels(model, false, false)
    }

    fn start_with_channels(model: &str, teams: bool, whatsapp: bool) -> Self {
        Self::start_fixture(model, teams, whatsapp, "https://example.test/role")
    }

    fn start_with_role(model: &str, role_url: &str) -> Self {
        Self::start_fixture(model, false, false, role_url)
    }

    fn start_fixture(model: &str, teams: bool, whatsapp: bool, role_url: &str) -> Self {
        let root = std::env::temp_dir().join(format!(
            "gta-claw-production-composition-{}-{}",
            std::process::id(),
            NEXT_ROOT.fetch_add(1, Ordering::Relaxed)
        ));
        std::fs::create_dir_all(&root).expect("temporary root is created");
        let config = root.join("config.json5");
        write_config_fixture(&config, model, role_url, teams, whatsapp);

        let mut command = Command::new(env!("CARGO_BIN_EXE_gta-claw-daemon"));
        command.env_clear();
        let mut child = command
            .args([
                "--smoke",
                "--config",
                config.to_str().expect("temporary path is UTF-8"),
                "--listen",
                "127.0.0.1:0",
                "--legacy-listen",
                "127.0.0.1:0",
                "--gateway-listen",
                "127.0.0.1:0",
                "--mcp-listen",
                "127.0.0.1:0",
                "--state-dir",
                root.to_str().expect("temporary path is UTF-8"),
            ])
            .env("GITHUB_TOKEN", "test")
            .env("ADMIN_TOKEN", "operator-token")
            .env("MicrosoftAppId", "teams-app")
            .env("MicrosoftAppPassword", "teams-password")
            .env("WHATSAPP_VERIFY_TOKEN", "verify-token")
            .env("WHATSAPP_ACCESS_TOKEN", "access-token")
            .env("WHATSAPP_PHONE_NUMBER_ID", "phone-id")
            .env("GTA_CLAW_LOG", "off")
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()
            .expect("daemon process starts");
        let stdin = child.stdin.take().expect("control channel is piped");
        let child_stdout = child.stdout.take().expect("stdout is piped");
        let (lines_tx, stdout) = mpsc::channel();
        thread::spawn(move || {
            for line in BufReader::new(child_stdout).lines() {
                let Ok(line) = line else {
                    break;
                };
                if lines_tx.send(line).is_err() {
                    break;
                }
            }
        });
        let mut running = Self {
            child,
            stdin,
            stdout,
            root,
            config,
            http: "127.0.0.1:0".parse().expect("placeholder address parses"),
            legacy: "127.0.0.1:0".parse().expect("placeholder address parses"),
        };

        let ready = running.read_line();
        assert_eq!(ready, "ready protocol=1");
        assert!(running.read_line().starts_with("healthy runtime="));
        let service = running.read_line();
        running.http = field(&service, "http")
            .parse()
            .expect("reported HTTP address parses");
        running.legacy = field(&service, "legacy")
            .parse()
            .expect("reported legacy address parses");
        running
    }

    fn control(&mut self, command: &str) -> String {
        writeln!(self.stdin, "{command}").expect("control command is written");
        self.stdin.flush().expect("control command is flushed");
        self.read_line()
    }

    fn read_line(&self) -> String {
        self.stdout
            .recv_timeout(Duration::from_secs(10))
            .expect("daemon reports before the process-test deadline")
    }

    fn stop(mut self) {
        let stopped = self.control("shutdown");
        assert!(
            stopped.starts_with("stopped reason=control clean=true"),
            "unexpected stop summary: {stopped}"
        );
        let status = self.child.wait().expect("daemon exits");
        assert!(status.success(), "daemon exited with {status}");
        let _ = std::fs::remove_dir_all(&self.root);
    }
}

impl Drop for Running {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
        let _ = std::fs::remove_dir_all(&self.root);
    }
}

#[test]
fn telemetry_file_open_failure_is_fatal_before_readiness() {
    let root = std::env::temp_dir().join(format!(
        "gta-claw-telemetry-output-{}-{}",
        std::process::id(),
        NEXT_ROOT.fetch_add(1, Ordering::Relaxed)
    ));
    std::fs::create_dir_all(&root).expect("temporary root is created");
    let config = root.join("config.json5");
    let log_file = root.join("missing-parent/daemon.log");
    write_config(&config, "gpt-4o");

    let mut command = Command::new(env!("CARGO_BIN_EXE_gta-claw-daemon"));
    command.env_clear();
    let output = command
        .args([
            "--smoke",
            "--config",
            config.to_str().expect("temporary path is UTF-8"),
            "--state-dir",
            root.to_str().expect("temporary path is UTF-8"),
            "--log-file",
            log_file.to_str().expect("temporary path is UTF-8"),
        ])
        .output()
        .expect("daemon process runs");
    let stdout = String::from_utf8_lossy(&output.stdout).into_owned();
    let stderr = String::from_utf8_lossy(&output.stderr).into_owned();
    std::fs::remove_dir_all(&root).expect("temporary root is removed");

    assert!(!output.status.success(), "daemon unexpectedly started");
    assert!(!stdout.contains("ready protocol=1"), "{stdout}");
    assert!(
        stderr.contains("cannot open telemetry output"),
        "missing typed telemetry diagnostic: {stderr}"
    );
    assert!(
        stderr.contains("missing-parent/daemon.log"),
        "missing telemetry path: {stderr}"
    );
}

#[test]
fn bound_http_is_ready_and_dispatches_to_the_composed_provider() {
    let daemon = Running::start("gpt-4o");

    let health = request(daemon.http, "GET", "/health", None, None);
    assert!(health.starts_with("HTTP/1.1 200"), "{health}");
    assert!(health.contains(r#""status":"live""#), "{health}");

    let ready = request(daemon.http, "GET", "/ready", None, None);
    assert!(ready.starts_with("HTTP/1.1 200"), "{ready}");
    assert!(ready.contains(r#""ready":true"#), "{ready}");

    let legacy_health = request(daemon.legacy, "GET", "/health", None, None);
    assert!(legacy_health.starts_with("HTTP/1.1 200"), "{legacy_health}");
    assert!(
        legacy_health.contains(r#""status":"ok""#),
        "{legacy_health}"
    );
    assert!(
        legacy_health.contains(r#""authenticated":true"#),
        "{legacy_health}"
    );
    let legacy_chat = request(
        daemon.legacy,
        "POST",
        "/chat",
        None,
        Some(r#"{"message":"legacy hello","conversation_id":"legacy-1"}"#),
    );
    assert!(legacy_chat.starts_with("HTTP/1.1 200"), "{legacy_chat}");
    assert!(legacy_chat.contains("smoke: legacy hello"), "{legacy_chat}");
    let legacy_system = request(
        daemon.legacy,
        "GET",
        "/admin/system",
        Some("operator-token"),
        None,
    );
    assert!(legacy_system.starts_with("HTTP/1.1 200"), "{legacy_system}");
    assert!(legacy_system.contains(r#""platform":"#), "{legacy_system}");
    let legacy_exec = request(
        daemon.legacy,
        "POST",
        "/admin/exec",
        Some("operator-token"),
        Some(r#"{"action":"hostname"}"#),
    );
    assert!(legacy_exec.starts_with("HTTP/1.1 200"), "{legacy_exec}");
    assert!(legacy_exec.contains(r#""success":true"#), "{legacy_exec}");

    let models = request(
        daemon.http,
        "GET",
        "/v1/models",
        Some("operator-token"),
        None,
    );
    assert!(models.starts_with("HTTP/1.1 200"), "{models}");
    assert!(models.contains(r#""id":"openclaw""#), "{models}");

    let status = request(
        daemon.http,
        "POST",
        "/api/v1/admin/rpc",
        Some("operator-token"),
        Some(r#"{"method":"status"}"#),
    );
    assert!(status.starts_with("HTTP/1.1 200"), "{status}");
    assert!(
        status.contains(r#""recoveryGuidance":"recover_from_baseline""#),
        "{status}"
    );
    assert!(
        status.contains(r#""layers":["built_in","workspace","environment"]"#),
        "{status}"
    );
    let status_body: serde_json::Value =
        serde_json::from_str(response_body(&status)).expect("status body is JSON");
    assert_eq!(status_body["payload"]["plugins"]["activated"], 0);
    assert_eq!(status_body["payload"]["plugins"]["failed"], 0);
    assert_eq!(
        status_body["payload"]["plugins"]["outcomes"],
        serde_json::json!([])
    );
    assert_eq!(
        status_body["payload"]["runtime"]["memory"]["insertRefusals"],
        0
    );
    assert_eq!(
        status_body["payload"]["runtime"]["goals"]["unlockFailures"],
        0
    );
    let pairing_body = r#"{"method":"device.pair.list","params":{}}"#;
    let pairing = request(
        daemon.http,
        "POST",
        "/api/v1/admin/rpc",
        Some("operator-token"),
        Some(pairing_body),
    );
    assert!(pairing.starts_with("HTTP/1.1 200"), "{pairing}");
    assert!(pairing.contains(r#""pending":[]"#), "{pairing}");
    assert!(pairing.contains(r#""paired":[]"#), "{pairing}");
    let goal = request(
        daemon.http,
        "POST",
        "/tools/invoke",
        Some("operator-token"),
        Some(
            r#"{"name":"update_goal","sessionKey":"goal-e2e","args":{"action":"set","objective":"finish composition"}}"#,
        ),
    );
    assert!(goal.starts_with("HTTP/1.1 200"), "{goal}");
    assert!(
        goal.contains("finish composition") || goal.contains("goal goal-e2e:"),
        "{goal}"
    );

    let update = request(
        daemon.http,
        "POST",
        "/api/v1/admin/rpc",
        Some("operator-token"),
        Some(r#"{"method":"update.status"}"#),
    );
    assert!(update.starts_with("HTTP/1.1 200"), "{update}");
    assert!(
        update.contains(r#""retryOwner":"gta-claw-updater""#),
        "{update}"
    );
    assert!(
        update.contains(r#""installCleanup":"updater_owned""#),
        "{update}"
    );
    assert!(update.contains(r#""daemonMutation":false"#), "{update}");

    let chat = request(
        daemon.http,
        "POST",
        "/v1/chat/completions",
        Some("operator-token"),
        Some(r#"{"model":"openclaw","messages":[{"role":"user","content":"hello"}]}"#),
    );
    assert!(chat.starts_with("HTTP/1.1 200"), "{chat}");
    assert!(chat.contains("smoke: user: hello"), "{chat}");

    let first = request(
        daemon.http,
        "POST",
        "/v1/responses",
        Some("operator-token"),
        Some(r#"{"model":"openclaw","input":"first"}"#),
    );
    assert!(first.starts_with("HTTP/1.1 200"), "{first}");
    let first_body: serde_json::Value =
        serde_json::from_str(response_body(&first)).expect("first response body is JSON");
    let first_id = first_body["id"].as_str().expect("first response has an id");
    let continuation_body =
        format!(r#"{{"model":"openclaw","input":"second","previous_response_id":"{first_id}"}}"#);
    let continuation = request(
        daemon.http,
        "POST",
        "/v1/responses",
        Some("operator-token"),
        Some(&continuation_body),
    );
    assert!(continuation.starts_with("HTTP/1.1 200"), "{continuation}");
    assert!(continuation.contains("first"), "{continuation}");
    assert!(continuation.contains("second"), "{continuation}");

    daemon.stop();
}

#[test]
fn legacy_conditional_channel_routes_use_composed_adapters() {
    let daemon = Running::start_with_channels("gpt-4o", true, true);

    let teams = request(
        daemon.legacy,
        "POST",
        "/api/messages",
        None,
        Some(
            r#"{"type":"message","text":"from teams","conversation":{"id":"teams-1"},"from":{"name":"Ada"}}"#,
        ),
    );
    assert!(
        teams.starts_with("HTTP/1.1 500"),
        "unauthenticated Teams activity must be refused: {teams}"
    );
    let health = request(daemon.legacy, "GET", "/health", None, None);
    assert!(health.contains(r#""teams":true"#), "{health}");
    assert!(health.contains(r#""whatsapp":true"#), "{health}");
    assert!(health.contains(r#""sessions":0"#), "{health}");

    let verified = request(
        daemon.legacy,
        "GET",
        "/whatsapp/webhook?hub.mode=subscribe&hub.verify_token=verify-token&hub.challenge=challenge-1",
        None,
        None,
    );
    assert!(verified.starts_with("HTTP/1.1 200"), "{verified}");
    assert!(verified.ends_with("challenge-1"), "{verified}");
    let empty_webhook = request(
        daemon.legacy,
        "POST",
        "/whatsapp/webhook",
        None,
        Some(r#"{"entry":[]}"#),
    );
    assert!(empty_webhook.starts_with("HTTP/1.1 200"), "{empty_webhook}");
    assert!(empty_webhook.contains(r#""ok":true"#), "{empty_webhook}");

    daemon.stop();
}

#[test]
fn legacy_admin_reload_uses_the_shared_role_transaction() {
    let role_server =
        std::net::TcpListener::bind("127.0.0.1:0").expect("role fixture binds to loopback");
    let role_address = role_server.local_addr().expect("role address is available");
    let server = thread::spawn(move || {
        for body in [
            r#"{"content":"reloaded role","model":"gpt-4.1"}"#,
            r#"{"content":"default model role"}"#,
        ] {
            let (mut stream, _) = role_server.accept().expect("daemon requests the role");
            let mut request = [0_u8; 2048];
            let _ = stream.read(&mut request).expect("role request is readable");
            write!(
                stream,
                "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                body.len()
            )
            .expect("role response is written");
            stream.flush().expect("role response is flushed");
        }
    });
    let mut daemon = Running::start_with_role("gpt-4o", &format!("http://{role_address}/role"));
    let before = request(
        daemon.legacy,
        "POST",
        "/chat",
        None,
        Some(r#"{"message":"before reload","conversation_id":"reload-session"}"#),
    );
    assert!(before.contains("before reload"), "{before}");

    let reloaded = request(
        daemon.legacy,
        "POST",
        "/admin/reload",
        Some("operator-token"),
        Some("{}"),
    );
    assert!(reloaded.starts_with("HTTP/1.1 200"), "{reloaded}");
    assert!(reloaded.contains(r#""message":"Reloaded""#), "{reloaded}");
    assert!(reloaded.contains(r#""model":"gpt-4.1""#), "{reloaded}");
    let status = daemon.control("status");
    assert!(status.contains("model=gpt-4.1"), "{status}");
    let after = request(
        daemon.legacy,
        "POST",
        "/chat",
        None,
        Some(r#"{"message":"after reload","conversation_id":"reload-session"}"#),
    );
    assert!(after.contains("after reload"), "{after}");
    assert!(!after.contains("before reload"), "{after}");
    let reset = request(
        daemon.legacy,
        "POST",
        "/admin/reload",
        Some("operator-token"),
        Some("{}"),
    );
    assert!(reset.starts_with("HTTP/1.1 200"), "{reset}");
    assert!(reset.contains(r#""model":"gpt-4o""#), "{reset}");
    let status = daemon.control("status");
    assert!(status.contains("model=gpt-4o"), "{status}");

    daemon.stop();
    server.join().expect("role fixture exits");
}

#[test]
fn device_flow_mode_serves_legacy_onboarding_before_provider_authentication() {
    let role_server =
        std::net::TcpListener::bind("127.0.0.1:0").expect("role fixture binds to loopback");
    let role_address = role_server.local_addr().expect("role address is available");
    let server = thread::spawn(move || {
        let (mut stream, _) = role_server.accept().expect("daemon requests the role");
        let mut request = [0_u8; 2048];
        let _ = stream.read(&mut request).expect("role request is readable");
        let body = r#"{"content":"device flow role"}"#;
        write!(
            stream,
            "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
            body.len()
        )
        .expect("role response is written");
        stream.flush().expect("role response is flushed");
    });
    let root = std::env::temp_dir().join(format!(
        "gta-claw-device-flow-composition-{}-{}",
        std::process::id(),
        NEXT_ROOT.fetch_add(1, Ordering::Relaxed)
    ));
    std::fs::create_dir_all(&root).expect("temporary root is created");
    let config = root.join("config.json5");
    write_device_config(&config, &format!("http://{role_address}/role"));

    let mut command = Command::new(env!("CARGO_BIN_EXE_gta-claw-daemon"));
    command.env_clear();
    let mut child = command
        .args([
            "--config",
            config.to_str().expect("temporary path is UTF-8"),
            "--listen",
            "127.0.0.1:0",
            "--legacy-listen",
            "127.0.0.1:0",
            "--gateway-listen",
            "127.0.0.1:0",
            "--mcp-listen",
            "127.0.0.1:0",
            "--state-dir",
            root.to_str().expect("temporary path is UTF-8"),
        ])
        .env("ADMIN_TOKEN", "operator-token")
        .env("GTA_CLAW_LOG", "off")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .expect("daemon process starts");
    let mut stdin = child.stdin.take().expect("control channel is piped");
    let stdout = child.stdout.take().expect("stdout is piped");
    let mut child = StartupChildGuard(child, root);
    let mut stdout = BufReader::new(stdout);
    assert_eq!(read_buffered_line(&mut stdout), "ready protocol=1");
    assert!(read_buffered_line(&mut stdout).starts_with("healthy runtime="));
    let service = read_buffered_line(&mut stdout);
    let legacy: SocketAddr = field(&service, "legacy")
        .parse()
        .expect("legacy address parses");

    let health = request(legacy, "GET", "/health", None, None);
    assert!(health.starts_with("HTTP/1.1 200"), "{health}");
    assert!(health.contains(r#""authenticated":false"#), "{health}");
    assert!(health.contains(r#""deviceFlowEnabled":true"#), "{health}");
    let ready = request(legacy, "GET", "/ready", Some("operator-token"), None);
    assert!(ready.starts_with("HTTP/1.1 503"), "{ready}");
    assert!(ready.contains(r#""provider""#), "{ready}");

    writeln!(stdin, "shutdown").expect("shutdown is written");
    stdin.flush().expect("shutdown is flushed");
    let stopped = read_buffered_line(&mut stdout);
    assert!(
        stopped.starts_with("stopped reason=control clean=true"),
        "{stopped}"
    );
    let status = child.0.wait().expect("daemon exits");
    assert!(status.success(), "daemon exited with {status}");
    server.join().expect("role fixture exits");
}

#[test]
fn reload_commits_a_live_model_and_rolls_back_a_bad_candidate() {
    let mut daemon = Running::start("gpt-4o");

    write_config(&daemon.config, "gpt-4.1");
    #[cfg(unix)]
    let applied = {
        let signalled = Command::new("kill")
            .arg("-HUP")
            .arg(daemon.child.id().to_string())
            .status()
            .expect("kill is available");
        assert!(signalled.success());
        daemon.read_line()
    };
    #[cfg(not(unix))]
    let applied = daemon.control("reload");
    assert_eq!(applied, "reloaded generation=1 changed=copilot");
    let status = daemon.control("status");
    assert!(status.contains("model=gpt-4.1"), "{status}");
    assert!(status.contains("config_generation=1"), "{status}");

    std::fs::write(&daemon.config, "{ this is not json5").expect("invalid candidate is written");
    let rejected = daemon.control("reload");
    assert!(
        rejected.starts_with("reload rejected generation=1 reason=reload:"),
        "{rejected}"
    );
    let status = daemon.control("status");
    assert!(status.contains("model=gpt-4.1"), "{status}");
    assert!(status.contains("config_generation=1"), "{status}");

    daemon.stop();
}

#[cfg(unix)]
#[test]
fn a_termination_during_dependency_startup_cancels_before_readiness() {
    use std::time::Instant;

    let root = std::env::temp_dir().join(format!(
        "gta-claw-startup-termination-{}-{}",
        std::process::id(),
        NEXT_ROOT.fetch_add(1, Ordering::Relaxed)
    ));
    std::fs::create_dir_all(&root).expect("temporary root is created");
    let role_server =
        std::net::TcpListener::bind("127.0.0.1:0").expect("role fixture binds to loopback");
    let role_address = role_server.local_addr().expect("role address is available");
    let (accepted_tx, accepted_rx) = mpsc::channel();
    let (release_tx, release_rx) = mpsc::channel();
    thread::spawn(move || {
        let (_stream, _) = role_server.accept().expect("daemon requests the role");
        accepted_tx.send(()).expect("acceptance is reported");
        let _ = release_rx.recv_timeout(Duration::from_secs(10));
    });
    let config = root.join("config.json5");
    write_config_with_role(&config, "gpt-4o", &format!("http://{role_address}/role"));

    let mut command = Command::new(env!("CARGO_BIN_EXE_gta-claw-daemon"));
    command.env_clear();
    let child = command
        .args([
            "--config",
            config.to_str().expect("temporary path is UTF-8"),
            "--listen",
            "127.0.0.1:0",
            "--legacy-listen",
            "127.0.0.1:0",
            "--gateway-listen",
            "127.0.0.1:0",
            "--mcp-listen",
            "127.0.0.1:0",
            "--state-dir",
            root.to_str().expect("temporary path is UTF-8"),
        ])
        .env("GITHUB_TOKEN", "test")
        .env("ADMIN_TOKEN", "operator-token")
        .env("GTA_CLAW_LOG", "off")
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .expect("daemon process starts");
    let mut child = StartupChildGuard(child, root);
    let stdout = child.0.stdout.take().expect("stdout is piped");
    let (line_tx, line_rx) = mpsc::channel();
    thread::spawn(move || {
        for line in BufReader::new(stdout).lines() {
            let Ok(line) = line else {
                break;
            };
            if line_tx.send(line).is_err() {
                break;
            }
        }
    });
    accepted_rx
        .recv_timeout(Duration::from_secs(5))
        .expect("startup reaches the deliberately stalled dependency");

    let signalled = Command::new("kill")
        .arg("-TERM")
        .arg(child.0.id().to_string())
        .status()
        .expect("kill is available");
    assert!(signalled.success());

    let stopped = line_rx
        .recv_timeout(Duration::from_secs(5))
        .expect("daemon reports its startup stop");
    assert!(
        stopped.starts_with(
            "stopped reason=terminate clean=true drained=0 completed=0 abandoned=0 tasks=0/0"
        ),
        "unexpected startup stop: {stopped}"
    );
    let deadline = Instant::now() + Duration::from_secs(5);
    let status = loop {
        if let Some(status) = child.0.try_wait().expect("child status is available") {
            break status;
        }
        assert!(
            Instant::now() < deadline,
            "daemon did not exit after startup stop"
        );
        thread::sleep(Duration::from_millis(10));
    };
    release_tx.send(()).expect("role fixture is released");
    assert!(status.success(), "daemon exited with {status}");
}

fn write_config(path: &Path, model: &str) {
    write_config_with_channels(path, model, false, false);
}

fn write_config_with_channels(path: &Path, model: &str, teams: bool, whatsapp: bool) {
    write_config_fixture(path, model, "https://example.test/role", teams, whatsapp);
}

fn write_config_with_role(path: &Path, model: &str, role_url: &str) {
    write_config_fixture(path, model, role_url, false, false);
}

fn write_config_fixture(path: &Path, model: &str, role_url: &str, teams: bool, whatsapp: bool) {
    let migrated = migrate_legacy_environment([
        ("GITHUB_TOKEN", "test"),
        ("ADMIN_TOKEN", "operator-token"),
        ("ENABLE_TEAMS", if teams { "true" } else { "false" }),
        ("MicrosoftAppId", "teams-app"),
        ("MicrosoftAppPassword", "teams-password"),
        ("ENABLE_TELEGRAM", "false"),
        ("ENABLE_DISCORD", "false"),
        ("ENABLE_WHATSAPP", if whatsapp { "true" } else { "false" }),
        ("WHATSAPP_VERIFY_TOKEN", "verify-token"),
        ("WHATSAPP_ACCESS_TOKEN", "access-token"),
        ("WHATSAPP_PHONE_NUMBER_ID", "phone-id"),
        ("COPILOT_MODEL", model),
        ("AGENT_ROLE_URL", role_url),
    ])
    .expect("fixture configuration migrates");
    std::fs::write(
        path,
        to_json5(&migrated.config).expect("fixture configuration serializes"),
    )
    .expect("fixture configuration is written");
}

fn write_device_config(path: &Path, role_url: &str) {
    let migrated = migrate_legacy_environment([
        ("DEVICE_FLOW_ENABLED", "true"),
        ("GITHUB_CLIENT_ID", "device-client"),
        ("ADMIN_TOKEN", "operator-token"),
        ("ENABLE_TEAMS", "false"),
        ("ENABLE_TELEGRAM", "false"),
        ("ENABLE_DISCORD", "false"),
        ("ENABLE_WHATSAPP", "false"),
        ("AGENT_ROLE_URL", role_url),
    ])
    .expect("device configuration migrates");
    std::fs::write(
        path,
        to_json5(&migrated.config).expect("device configuration serializes"),
    )
    .expect("device configuration is written");
}

fn request(
    address: SocketAddr,
    method: &str,
    path: &str,
    bearer: Option<&str>,
    body: Option<&str>,
) -> String {
    let mut stream = TcpStream::connect(address).expect("HTTP listener accepts");
    stream
        .set_read_timeout(Some(Duration::from_secs(5)))
        .expect("read timeout is set");
    stream
        .set_write_timeout(Some(Duration::from_secs(5)))
        .expect("write timeout is set");
    let body = body.unwrap_or_default();
    write!(
        stream,
        "{method} {path} HTTP/1.1\r\nHost: {address}\r\nConnection: close\r\nContent-Length: {}\r\n",
        body.len()
    )
    .expect("request head is written");
    if let Some(bearer) = bearer {
        write!(stream, "Authorization: Bearer {bearer}\r\n").expect("authorization is written");
    }
    if !body.is_empty() {
        write!(stream, "Content-Type: application/json\r\n").expect("content type is written");
    }
    write!(stream, "\r\n{body}").expect("request body is written");
    stream.flush().expect("request is flushed");

    let mut response = String::new();
    stream
        .read_to_string(&mut response)
        .expect("response is read");
    response
}

fn field<'a>(line: &'a str, name: &str) -> &'a str {
    line.split_whitespace()
        .find_map(|field| {
            let (key, value) = field.split_once('=')?;
            (key == name).then_some(value)
        })
        .unwrap_or_else(|| panic!("missing {name} in {line:?}"))
}

fn response_body(response: &str) -> &str {
    response.split_once("\r\n\r\n").map_or_else(
        || panic!("response has no body separator: {response:?}"),
        |(_, body)| body,
    )
}

fn read_buffered_line(reader: &mut impl BufRead) -> String {
    let mut line = String::new();
    reader.read_line(&mut line).expect("line is readable");
    assert!(!line.is_empty(), "daemon closed stdout before reporting");
    line.trim_end().to_owned()
}

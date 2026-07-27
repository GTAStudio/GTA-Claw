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
        let root = std::env::temp_dir().join(format!(
            "gta-claw-production-composition-{}-{}",
            std::process::id(),
            NEXT_ROOT.fetch_add(1, Ordering::Relaxed)
        ));
        std::fs::create_dir_all(&root).expect("temporary root is created");
        let config = root.join("config.json5");
        write_config(&config, model);

        let mut command = Command::new(env!("CARGO_BIN_EXE_gta-claw-daemon"));
        command.env_clear();
        let mut child = command
            .args([
                "--smoke",
                "--config",
                config.to_str().expect("temporary path is UTF-8"),
                "--listen",
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
        };

        let ready = running.read_line();
        assert_eq!(ready, "ready protocol=1");
        assert!(running.read_line().starts_with("healthy runtime="));
        let service = running.read_line();
        running.http = field(&service, "http")
            .parse()
            .expect("reported HTTP address parses");
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
fn bound_http_is_ready_and_dispatches_to_the_composed_provider() {
    let daemon = Running::start("gpt-4o");

    let health = request(daemon.http, "GET", "/health", None, None);
    assert!(health.starts_with("HTTP/1.1 200"), "{health}");
    assert!(health.contains(r#""status":"live""#), "{health}");

    let ready = request(daemon.http, "GET", "/ready", None, None);
    assert!(ready.starts_with("HTTP/1.1 200"), "{ready}");
    assert!(ready.contains(r#""ready":true"#), "{ready}");

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
    write_config_with_role(path, model, "https://example.test/role");
}

fn write_config_with_role(path: &Path, model: &str, role_url: &str) {
    let migrated = migrate_legacy_environment([
        ("GITHUB_TOKEN", "test"),
        ("ADMIN_TOKEN", "operator-token"),
        ("ENABLE_TEAMS", "false"),
        ("ENABLE_TELEGRAM", "false"),
        ("ENABLE_DISCORD", "false"),
        ("ENABLE_WHATSAPP", "false"),
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

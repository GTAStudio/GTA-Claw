//! Process-level checks that the daemon binary is an HTTP server.
//!
//! Every assertion here drives the real binary over a real socket. A unit test
//! of a handler cannot show that the shipped process binds a port, so nothing
//! in this file constructs an in-process router.
//!
//! The signal-driven shutdown checks are POSIX-only. Delivering a Windows
//! console control event requires `GenerateConsoleCtrlEvent`, and this
//! workspace forbids `unsafe_code`, so the shutdown path is exercised on Linux
//! and macOS while Windows covers serving and the startup failure path.

use std::io::{BufRead, BufReader, Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::process::{Child, ChildStderr, Command, Stdio};
#[cfg(unix)]
use std::thread;
use std::time::Duration;

/// Every audited legacy variable, including aliases, cleared so that an
/// inherited environment cannot change what the daemon under test loads.
const LEGACY_ENVIRONMENT: &[&str] = &[
    "ADMIN_TOKEN",
    "AGENT_ROLE_URL",
    "ALLOWED_SKILL_DOMAINS",
    "APP_LANG",
    "AUTO_UPDATE",
    "COPILOT_CLI_PATH",
    "COPILOT_CLI_VERSION",
    "COPILOT_MODEL",
    "DEVICE_FLOW_ENABLED",
    "DISCORD_BOT_TOKEN",
    "DISCORD_GATEWAY_INTENTS",
    "DISCORD_GATEWAY_URL",
    "DOCKERHUB_IMAGE",
    "DOCKERHUB_TOKEN",
    "DOCKERHUB_USERNAME",
    "DOCKER_IMAGE",
    "DOMAIN",
    "ENABLED_SKILLS",
    "ENABLE_DISCORD",
    "ENABLE_TEAMS",
    "ENABLE_TELEGRAM",
    "ENABLE_WHATSAPP",
    "GITHUB_CLIENT_ID",
    "GITHUB_TOKEN",
    "HTTPS_PROXY",
    "HTTP_PROXY",
    "LOG_LEVEL",
    "MAX_SESSIONS",
    "MicrosoftAppId",
    "MicrosoftAppPassword",
    "NODE_ENV",
    "PORT",
    "RATE_LIMIT_PER_MIN",
    "SDK_REQUEST_TIMEOUT_MS",
    "SESSION_TTL_MS",
    "SKILL_EXEC_TIMEOUT_MS",
    "TELEGRAM_BOT_TOKEN",
    "TELEGRAM_POLL_INTERVAL_MS",
    "TRUST_PROXY",
    "WHATSAPP_ACCESS_TOKEN",
    "WHATSAPP_PHONE_NUMBER_ID",
    "WHATSAPP_VERIFY_TOKEN",
    "WHATSAPP_WEBHOOK_PATH",
    "all_proxy",
    "https_proxy",
];

/// Deadlines that only the signal-driven shutdown checks need.
#[cfg(unix)]
const EXIT_DEADLINE: Duration = Duration::from_secs(20);
#[cfg(unix)]
const LINE_DEADLINE: Duration = Duration::from_secs(20);
const SOCKET_TIMEOUT: Duration = Duration::from_secs(15);

struct Daemon {
    child: Child,
    #[cfg(unix)]
    stdout: Option<Box<dyn BufRead + Send>>,
    stderr: Option<ChildStderr>,
    address: SocketAddr,
}

impl Drop for Daemon {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

impl Daemon {
    /// Starts the daemon on a port nothing else is using.
    ///
    /// A reserved port can be taken between reservation and startup, so a lost
    /// race retries instead of reporting a failure the daemon did not cause.
    fn start() -> Self {
        let mut last = String::new();
        for _ in 0..8 {
            match Self::try_start(reserve_port()) {
                Ok(daemon) => return daemon,
                Err(failure) => last = failure,
            }
        }
        panic!("daemon never bound a free port: {last}");
    }

    fn try_start(port: u16) -> Result<Self, String> {
        let mut command = base_command();
        command
            .env("PORT", port.to_string())
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        let mut child = command.spawn().expect("daemon process starts");
        let mut stdout = BufReader::new(child.stdout.take().expect("daemon stdout is piped"));
        let stderr = child.stderr.take().expect("daemon stderr is piped");

        let mut announced = Vec::new();
        for _ in 0..5 {
            let mut line = String::new();
            let read = stdout
                .read_line(&mut line)
                .expect("daemon stdout is readable");
            if read == 0 {
                let mut daemon = Self {
                    child,
                    #[cfg(unix)]
                    stdout: None,
                    stderr: Some(stderr),
                    address: local(port),
                };
                return Err(format!(
                    "daemon exited before announcing readiness: {}",
                    daemon.drain_stderr()
                ));
            }
            announced.push(line);
        }

        assert_eq!(announced[0], "ready protocol=1\n");
        assert!(
            announced[1].starts_with("healthy runtime="),
            "unexpected health announcement: {}",
            announced[1]
        );
        assert_eq!(
            announced[2],
            format!("listening address=0.0.0.0:{port} domain=localhost\n"),
            "unexpected listening announcement"
        );
        assert!(
            announced[3].starts_with("unconfigured dependencies="),
            "startup did not name the unconfigured dependencies: {}",
            announced[3]
        );
        assert!(
            announced[4].starts_with("protected routes closed:"),
            "startup did not name the closed protected surface: {}",
            announced[4]
        );

        Ok(Self {
            child,
            #[cfg(unix)]
            stdout: Some(Box::new(stdout)),
            stderr: Some(stderr),
            address: local(port),
        })
    }

    fn drain_stderr(&mut self) -> String {
        let Some(mut stderr) = self.stderr.take() else {
            return String::new();
        };
        let mut captured = String::new();
        let _ = stderr.read_to_string(&mut captured);
        captured
    }

    /// Reads one further stdout line without letting a stalled daemon hang the
    /// test harness, which has no timeout of its own.
    #[cfg(unix)]
    fn next_line(&mut self) -> Option<String> {
        let mut reader = self.stdout.take().expect("daemon stdout is available");
        let (sender, receiver) = std::sync::mpsc::channel();
        thread::spawn(move || {
            let mut line = String::new();
            let read = reader.read_line(&mut line);
            let _ = sender.send(read.map(|count| (count, line, reader)));
        });
        let received = receiver
            .recv_timeout(LINE_DEADLINE)
            .expect("daemon produced further output");
        let (count, line, reader) = received.expect("daemon stdout is readable");
        self.stdout = Some(reader);
        (count > 0).then_some(line)
    }

    #[cfg(unix)]
    fn wait_for_exit(&mut self) -> std::process::ExitStatus {
        let started = std::time::Instant::now();
        loop {
            if let Some(status) = self.child.try_wait().expect("daemon status is available") {
                return status;
            }
            assert!(
                started.elapsed() < EXIT_DEADLINE,
                "daemon did not exit within {EXIT_DEADLINE:?}"
            );
            thread::sleep(Duration::from_millis(25));
        }
    }
}

struct HttpResponse {
    status: u16,
    headers: Vec<(String, String)>,
    body: String,
}

impl HttpResponse {
    fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|(header, _)| header == name)
            .map(|(_, value)| value.as_str())
    }
}

fn base_command() -> Command {
    let mut command = Command::new(env!("CARGO_BIN_EXE_gta-claw-daemon"));
    for name in LEGACY_ENVIRONMENT {
        command.env_remove(name);
    }
    command
        .env("AGENT_ROLE_URL", "https://roles.example.com/role.json")
        .env("ENABLE_TEAMS", "false")
        .env("GITHUB_TOKEN", "integration-token");
    command
}

fn local(port: u16) -> SocketAddr {
    SocketAddr::from(([127, 0, 0, 1], port))
}

fn reserve_port() -> u16 {
    let listener = TcpListener::bind(("127.0.0.1", 0)).expect("reserve an ephemeral port");
    listener
        .local_addr()
        .expect("reserved port is readable")
        .port()
}

fn get(address: SocketAddr, path: &str) -> HttpResponse {
    let mut stream = TcpStream::connect_timeout(&address, SOCKET_TIMEOUT).expect("connect");
    stream
        .set_read_timeout(Some(SOCKET_TIMEOUT))
        .expect("read timeout is supported");
    stream
        .set_write_timeout(Some(SOCKET_TIMEOUT))
        .expect("write timeout is supported");
    write!(
        stream,
        "GET {path} HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n"
    )
    .expect("send request");
    stream.flush().expect("flush request");

    let mut raw = Vec::new();
    stream.read_to_end(&mut raw).expect("read response");
    parse(&raw)
}

fn parse(raw: &[u8]) -> HttpResponse {
    let text = String::from_utf8(raw.to_vec()).expect("response is UTF-8");
    let (head, body) = text
        .split_once("\r\n\r\n")
        .unwrap_or_else(|| panic!("response has no header terminator: {text:?}"));
    let mut lines = head.split("\r\n");
    let status_line = lines.next().expect("response has a status line");
    let status = status_line
        .split(' ')
        .nth(1)
        .and_then(|code| code.parse().ok())
        .unwrap_or_else(|| panic!("unparsable status line: {status_line:?}"));
    let headers = lines
        .filter_map(|line| line.split_once(':'))
        .map(|(name, value)| (name.trim().to_ascii_lowercase(), value.trim().to_owned()))
        .collect();

    HttpResponse {
        status,
        headers,
        body: body.to_owned(),
    }
}

#[test]
fn daemon_binds_a_real_port_and_answers_health() {
    let mut daemon = Daemon::start();

    let health = get(daemon.address, "/health");

    assert_eq!(health.status, 200);
    assert_eq!(
        health.header("content-type"),
        Some("application/json; charset=utf-8"),
        "unexpected headers: {:?}",
        health.headers
    );
    assert_eq!(health.header("cache-control"), Some("no-store"));
    assert_eq!(health.body, r#"{"ok":true,"status":"live"}"#);

    assert!(
        daemon
            .child
            .try_wait()
            .expect("daemon status is available")
            .is_none(),
        "daemon exited instead of continuing to serve"
    );
}

#[test]
fn readiness_reports_the_dependencies_this_process_cannot_serve() {
    let daemon = Daemon::start();

    let ready = get(daemon.address, "/ready");

    assert_eq!(
        ready.status, 503,
        "readiness must not claim dependencies that are absent"
    );
    assert_eq!(ready.body, r#"{"ready":false}"#);
    assert_eq!(ready.header("cache-control"), Some("no-store"));
}

#[test]
fn protected_routes_reject_unauthenticated_callers() {
    let daemon = Daemon::start();

    let models = get(daemon.address, "/v1/models");

    assert_eq!(
        models.status, 401,
        "protected surfaces must stay closed while no credential can be configured"
    );
}

#[test]
fn invalid_configuration_stops_startup_before_any_readiness_claim() {
    let output = base_command()
        .env("PORT", "not-a-port")
        .stdin(Stdio::null())
        .output()
        .expect("daemon process starts");

    assert!(
        !output.status.success(),
        "daemon started with invalid configuration"
    );
    let stdout = String::from_utf8(output.stdout).expect("stdout is UTF-8");
    assert!(
        !stdout.contains("ready protocol="),
        "daemon claimed readiness while misconfigured: {stdout}"
    );
    let stderr = String::from_utf8(output.stderr).expect("stderr is UTF-8");
    assert!(
        stderr.contains("configuration is invalid, refusing to start half-configured"),
        "operator message missing: {stderr}"
    );
    assert!(
        stderr.contains("PORT"),
        "operator message omitted the failing variable: {stderr}"
    );
}

#[test]
fn missing_credentials_stop_startup_before_any_readiness_claim() {
    let output = base_command()
        .env_remove("GITHUB_TOKEN")
        .stdin(Stdio::null())
        .output()
        .expect("daemon process starts");

    assert!(
        !output.status.success(),
        "daemon started without any GitHub credential"
    );
    let stdout = String::from_utf8(output.stdout).expect("stdout is UTF-8");
    assert!(
        !stdout.contains("ready protocol="),
        "daemon claimed readiness while unauthenticated: {stdout}"
    );
    let stderr = String::from_utf8(output.stderr).expect("stderr is UTF-8");
    assert!(
        stderr.contains("core.auth.github.pat"),
        "operator message missing: {stderr}"
    );
}

/// Reads one `key=value` field out of the stop line.
///
/// Deliberately hand-written rather than shared with the production formatter,
/// so a formatter that changed shape would fail this rather than agree with it.
#[cfg(unix)]
fn stop_field<'a>(line: &'a str, key: &str) -> &'a str {
    line.split_whitespace()
        .find_map(|field| field.strip_prefix(&format!("{key}=")))
        .unwrap_or_else(|| panic!("stop line has no {key}: {line:?}"))
}

/// Asserts the joined property: after a stop signal the HTTP surface stops
/// accepting **and** the composition reports a clean stop.
///
/// Neither half implies the other. A clean `StopSummary` counts task joins and
/// cannot observe a file descriptor, so a leaked listener would still report
/// clean; and a refused connection says nothing about whether in-flight work
/// was abandoned.
///
/// The daemon is started with standard input closed, which is also what a
/// systemd service inherits unless its unit says otherwise. That makes this the
/// regression test for a `select!` that stops observing signals once the
/// control channel reaches end of file.
#[cfg(unix)]
fn shutdown_by(signal: &str, expected: &str) {
    let mut daemon = Daemon::start();

    assert_eq!(get(daemon.address, "/health").status, 200);

    let delivered = Command::new("kill")
        .args([signal, &daemon.child.id().to_string()])
        .status()
        .expect("signal is delivered");
    assert!(delivered.success(), "kill {signal} failed");

    let stopped = daemon
        .next_line()
        .expect("daemon reported a stop line before exiting");
    assert!(
        stopped.starts_with("stopped "),
        "daemon did not report a graceful stop: {stopped:?}"
    );
    assert_eq!(
        stop_field(&stopped, "reason"),
        expected,
        "unexpected stop reason: {stopped:?}"
    );
    assert_eq!(
        stop_field(&stopped, "clean"),
        "true",
        "the composition did not report a clean stop: {stopped:?}"
    );
    assert_eq!(
        stop_field(&stopped, "abandoned"),
        "0",
        "work was abandoned during shutdown: {stopped:?}"
    );
    let tasks = stop_field(&stopped, "tasks");
    let (terminated, spawned) = tasks
        .split_once('/')
        .unwrap_or_else(|| panic!("unparsable task ledger: {tasks:?}"));
    assert_eq!(
        terminated, spawned,
        "a spawned task was not joined: {stopped:?}"
    );

    let status = daemon.wait_for_exit();
    assert_eq!(
        status.code(),
        Some(0),
        "daemon did not exit cleanly after {expected}, raw status {status:?}"
    );

    // The listening socket is gone, not merely idle: a fresh bind to the same
    // address would fail with EADDRINUSE while any listener survived.
    let released = TcpListener::bind(daemon.address);
    assert!(
        released.is_ok(),
        "the listening socket outlived shutdown: {:?}",
        released.err()
    );
}

#[cfg(unix)]
#[test]
fn sigterm_drains_and_exits_zero() {
    shutdown_by("-TERM", "terminate");
}

#[cfg(unix)]
#[test]
fn sigint_drains_and_exits_zero() {
    shutdown_by("-INT", "interrupt");
}

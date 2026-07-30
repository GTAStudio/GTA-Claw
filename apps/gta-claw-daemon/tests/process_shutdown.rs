//! Process-level checks that a real daemon process shuts down cleanly.
//!
//! These run the actual binary rather than the composition in-process, so they
//! prove the whole path: build the composition, start four bound ingress services, print
//! the ready contract, receive a stop signal from outside the process, drain,
//! and join every task before exiting.

#[cfg(unix)]
use std::io::Read;
use std::io::{BufRead, BufReader, Write};
use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::sync::atomic::{AtomicU64, Ordering};
use std::thread;
use std::time::Duration;

use claw_config::{migrate_legacy_environment, to_json5};

/// How long a drained daemon is given to leave the process table.
///
/// Generous on purpose: the point is to tell "exits promptly" apart from "never
/// exits", not to time the teardown.
#[cfg(unix)]
const EXIT_BUDGET: Duration = Duration::from_secs(5);
static NEXT_STATE: AtomicU64 = AtomicU64::new(0);

/// Kills the child if an assertion unwinds before the test gets to stop it.
struct ChildGuard(Child, PathBuf);

impl Drop for ChildGuard {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
        let _ = std::fs::remove_dir_all(&self.1);
    }
}

/// One parsed `stopped ...` summary line.
#[derive(Debug, Eq, PartialEq)]
struct StopLine {
    reason: String,
    clean: bool,
    drained: u32,
    completed: u32,
    abandoned: u32,
    joined: u32,
    spawned: u32,
    telemetry: String,
    deadline_expired: bool,
}

impl StopLine {
    /// Parses the summary line by hand.
    ///
    /// Deliberately not shared with the production formatter: a test that
    /// rendered the expected value with the code under test would pass for any
    /// format at all.
    fn parse(line: &str) -> Self {
        let rest = line
            .strip_prefix("stopped ")
            .unwrap_or_else(|| panic!("not a stop line: {line:?}"));
        let mut fields = std::collections::BTreeMap::new();

        for field in rest.split_whitespace() {
            let (key, value) = field
                .split_once('=')
                .unwrap_or_else(|| panic!("field without a value: {field:?}"));
            fields.insert(key.to_owned(), value.to_owned());
        }

        let take = |key: &str| -> String {
            fields
                .get(key)
                .unwrap_or_else(|| panic!("missing field {key:?} in {line:?}"))
                .clone()
        };
        let number = |text: &str| -> u32 {
            text.parse()
                .unwrap_or_else(|error| panic!("{text:?} is not a number: {error}"))
        };

        let tasks = take("tasks");
        let (joined, spawned) = tasks
            .split_once('/')
            .unwrap_or_else(|| panic!("tasks is not a ratio: {tasks:?}"));

        Self {
            reason: take("reason"),
            clean: take("clean") == "true",
            drained: number(&take("drained")),
            completed: number(&take("completed")),
            abandoned: number(&take("abandoned")),
            joined: number(joined),
            spawned: number(spawned),
            telemetry: take("telemetry"),
            deadline_expired: take("deadline_expired") == "true",
        }
    }
}

/// Spawns the daemon with a writable control channel and waits for readiness.
fn started() -> (ChildGuard, BufReader<std::process::ChildStdout>) {
    let state = std::env::temp_dir().join(format!(
        "gta-claw-process-shutdown-{}-{}",
        std::process::id(),
        NEXT_STATE.fetch_add(1, Ordering::Relaxed)
    ));
    let mut command = Command::new(env!("CARGO_BIN_EXE_gta-claw-daemon"));
    command.env_clear();
    let child = command
        .args([
            "--smoke",
            "--listen",
            "127.0.0.1:0",
            "--legacy-listen",
            "127.0.0.1:0",
            "--gateway-listen",
            "127.0.0.1:0",
            "--mcp-listen",
            "127.0.0.1:0",
        ])
        .env("GITHUB_TOKEN", "test")
        .env("ENABLE_TEAMS", "false")
        .env("ENABLE_TELEGRAM", "false")
        .env("ENABLE_DISCORD", "false")
        .env("ENABLE_WHATSAPP", "false")
        .env("COPILOT_MODEL", "gpt-4o")
        .env("AGENT_ROLE_URL", "https://example.test/role")
        .env("GTA_CLAW_ADMIN_TOKEN", "test")
        .env("GTA_CLAW_LOG", "off")
        .env("GTA_CLAW_STATE_DIR", &state)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .expect("daemon process starts");
    let mut child = ChildGuard(child, state);
    let stdout = child.0.stdout.take().expect("daemon stdout is piped");
    let mut reader = BufReader::new(stdout);

    let mut ready = String::new();
    reader
        .read_line(&mut ready)
        .expect("daemon readiness is readable");
    assert_eq!(ready, "ready protocol=1\n");

    let mut health = String::new();
    reader
        .read_line(&mut health)
        .expect("daemon health is readable");
    assert!(
        health.starts_with("healthy runtime="),
        "unexpected health line: {health:?}"
    );

    let mut service = String::new();
    reader
        .read_line(&mut service)
        .expect("daemon service endpoints are readable");
    assert!(
        service.starts_with("service http=127.0.0.1:"),
        "unexpected service line: {service:?}"
    );

    (child, reader)
}

/// Reads the summary line and waits for the process to exit.
fn stopped(child: &mut ChildGuard, reader: &mut BufReader<std::process::ChildStdout>) -> StopLine {
    let mut summary = String::new();
    reader
        .read_line(&mut summary)
        .expect("daemon stop summary is readable");

    let status = child.0.wait().expect("daemon exits");
    assert!(status.success(), "daemon exited with {status:?}");

    StopLine::parse(summary.trim_end())
}

#[test]
fn the_control_channel_shuts_a_real_process_down_with_every_task_joined() {
    let (mut child, mut reader) = started();

    {
        let stdin = child.0.stdin.as_mut().expect("daemon stdin is piped");
        stdin
            .write_all(b"shutdown\n")
            .expect("the control word is writable");
        stdin.flush().expect("the control channel flushes");
    }

    let summary = stopped(&mut child, &mut reader);

    assert_eq!(summary.reason, "control");
    assert!(
        summary.clean,
        "the daemon did not stop cleanly: {summary:?}"
    );
    assert_eq!(summary.abandoned, 0, "a subsystem was left running");
    assert_eq!(
        summary.drained, 4,
        "not every ingress service was drained on the way down"
    );
    assert_eq!(
        summary.completed, 0,
        "an idle daemon reported in-flight work"
    );
    assert_eq!(
        summary.joined, summary.spawned,
        "a spawned task was not joined"
    );
    assert_eq!(summary.telemetry, "clean");
}

#[test]
fn an_unrecognised_control_line_does_not_stop_the_process() {
    let (mut child, mut reader) = started();

    {
        let stdin = child.0.stdin.as_mut().expect("daemon stdin is piped");
        stdin
            .write_all(b"not-a-command\n")
            .expect("the control line is writable");
        stdin.flush().expect("the control channel flushes");
    }

    let mut ignored = String::new();
    reader
        .read_line(&mut ignored)
        .expect("ignored control response is readable");
    assert_eq!(ignored, "control ignored\n");

    std::thread::sleep(Duration::from_millis(150));
    assert!(
        child
            .0
            .try_wait()
            .expect("daemon status is available")
            .is_none(),
        "the daemon stopped on a line that is not the shutdown word"
    );

    {
        let stdin = child.0.stdin.as_mut().expect("daemon stdin is piped");
        stdin
            .write_all(b"SHUTDOWN\n")
            .expect("the control word is writable");
        stdin.flush().expect("the control channel flushes");
    }

    let summary = stopped(&mut child, &mut reader);

    assert_eq!(summary.reason, "control");
    assert!(summary.clean);
    assert_eq!(summary.joined, summary.spawned);
}

/// A real operating-system interrupt, not a simulated one.
///
/// Restricted to unix because Windows has no way to deliver `CTRL_C_EVENT` to
/// another process's console group without `unsafe` FFI, and the workspace
/// forbids `unsafe_code`. The control-channel tests above cover the same drain
/// path on every platform.
#[cfg(unix)]
#[test]
fn an_operating_system_interrupt_shuts_a_real_process_down_cleanly() {
    let (mut child, mut reader) = started();
    let pid = child.0.id().to_string();

    let signalled = Command::new("kill")
        .arg("-INT")
        .arg(&pid)
        .status()
        .expect("kill is available");
    assert!(signalled.success(), "could not signal pid {pid}");

    let summary = stopped(&mut child, &mut reader);

    assert_eq!(summary.reason, "interrupt");
    assert!(
        summary.clean,
        "the daemon did not stop cleanly: {summary:?}"
    );
    assert_eq!(summary.abandoned, 0);
    assert_eq!(summary.drained, 4);
    assert_eq!(summary.joined, summary.spawned);
}

/// `SIGTERM` is the signal production actually sends.
///
/// `packaging/linux/systemd/gta-claw-daemon.service` sets `KillSignal=SIGTERM`,
/// and `docker stop` and `kubectl delete` send it too. Handling only `SIGINT`
/// would leave every one of those paths hitting the default disposition: the
/// process would die at exit 143 with no drain, no stop line, and no evidence
/// that a task had been abandoned. The interrupt test above cannot catch that,
/// because it sends the one signal the old code handled.
#[cfg(unix)]
#[test]
fn a_supervisor_termination_shuts_a_real_process_down_cleanly() {
    let (mut child, mut reader) = started();
    let pid = child.0.id().to_string();

    let signalled = Command::new("kill")
        .arg("-TERM")
        .arg(&pid)
        .status()
        .expect("kill is available");
    assert!(signalled.success(), "could not signal pid {pid}");

    let summary = stopped(&mut child, &mut reader);

    assert_eq!(
        summary.reason, "terminate",
        "a SIGTERM must be reported as a termination, not as an interrupt"
    );
    assert!(
        summary.clean,
        "the daemon did not stop cleanly: {summary:?}"
    );
    assert_eq!(summary.abandoned, 0);
    assert_eq!(summary.drained, 4);
    assert_eq!(
        summary.joined, summary.spawned,
        "a spawned task was not joined on a supervisor termination"
    );
}

#[cfg(unix)]
#[test]
fn stop_handling_is_live_before_configuration_io_can_finish() {
    let root = std::env::temp_dir().join(format!(
        "gta-claw-early-signal-{}-{}",
        std::process::id(),
        NEXT_STATE.fetch_add(1, Ordering::Relaxed)
    ));
    std::fs::create_dir_all(&root).expect("temporary root is created");
    let config = root.join("config.fifo");
    let created = Command::new("mkfifo")
        .arg(&config)
        .status()
        .expect("mkfifo is available");
    assert!(created.success());
    let mut fifo = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open(&config)
        .expect("test holds both FIFO ends");
    let child = Command::new(env!("CARGO_BIN_EXE_gta-claw-daemon"))
        .args(["--smoke", "--config"])
        .arg(&config)
        .args(["--state-dir"])
        .arg(&root)
        .env_clear()
        .env("GTA_CLAW_LOG", "off")
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .expect("daemon process starts");
    let mut child = ChildGuard(child, root);
    let stdout = child.0.stdout.take().expect("daemon stdout is piped");
    let mut stdout = BufReader::new(stdout);
    std::thread::sleep(Duration::from_millis(100));

    let signalled = Command::new("kill")
        .arg("-TERM")
        .arg(child.0.id().to_string())
        .status()
        .expect("kill is available");
    assert!(signalled.success());
    let snapshot = migrate_legacy_environment([
        ("GITHUB_TOKEN", "test"),
        ("ENABLE_TEAMS", "false"),
        ("ENABLE_TELEGRAM", "false"),
        ("ENABLE_DISCORD", "false"),
        ("ENABLE_WHATSAPP", "false"),
        ("COPILOT_MODEL", "gpt-4o"),
        ("AGENT_ROLE_URL", "https://example.test/role"),
    ])
    .expect("configuration fixture migrates")
    .config;
    fifo.write_all(
        to_json5(&snapshot)
            .expect("configuration fixture serializes")
            .as_bytes(),
    )
    .expect("configuration FIFO is released");
    fifo.flush().expect("configuration FIFO flushes");
    drop(fifo);

    let mut line = String::new();
    stdout
        .read_line(&mut line)
        .expect("early stop summary is readable");
    let summary = StopLine::parse(line.trim_end());
    assert_eq!(summary.reason, "terminate");
    assert_ne!(
        (summary.joined, summary.spawned),
        (0, 0),
        "configuration work vanished from startup accounting"
    );
    assert_eq!(summary.joined, summary.spawned);
    assert!(child.0.wait().expect("daemon exits").success());
}

#[cfg(unix)]
#[test]
fn pre_start_deadline_expiry_is_reported_unclean() {
    let root = std::env::temp_dir().join(format!(
        "gta-claw-startup-deadline-{}-{}",
        std::process::id(),
        NEXT_STATE.fetch_add(1, Ordering::Relaxed)
    ));
    std::fs::create_dir_all(&root).expect("temporary root is created");
    let config = root.join("config.fifo");
    assert!(
        Command::new("mkfifo")
            .arg(&config)
            .status()
            .expect("mkfifo is available")
            .success()
    );
    let fifo = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open(&config)
        .expect("test holds the configuration FIFO open");
    let child = Command::new(env!("CARGO_BIN_EXE_gta-claw-daemon"))
        .args(["--smoke", "--config"])
        .arg(&config)
        .args(["--state-dir"])
        .arg(&root)
        .env_clear()
        .env("GTA_CLAW_LOG", "off")
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .expect("daemon process starts");
    let mut child = ChildGuard(child, root);
    let stdout = child.0.stdout.take().expect("daemon stdout is piped");
    let mut stdout = BufReader::new(stdout);
    std::thread::sleep(Duration::from_millis(100));
    assert!(
        Command::new("kill")
            .arg("-TERM")
            .arg(child.0.id().to_string())
            .status()
            .expect("kill is available")
            .success()
    );

    let started = std::time::Instant::now();
    let mut line = String::new();
    stdout
        .read_line(&mut line)
        .expect("deadline stop summary is readable");
    let summary = StopLine::parse(line.trim_end());
    assert!(
        started.elapsed() >= Duration::from_secs(9),
        "startup did not consume its bounded settlement deadline"
    );
    assert!(!summary.clean, "{summary:?}");
    assert!(summary.abandoned > 0, "{summary:?}");
    assert!(summary.deadline_expired, "{summary:?}");
    drop(fifo);
}

#[cfg(unix)]
#[test]
fn reload_received_during_config_io_is_applied_before_readiness() {
    let root = std::env::temp_dir().join(format!(
        "gta-claw-early-reload-config-{}-{}",
        std::process::id(),
        NEXT_STATE.fetch_add(1, Ordering::Relaxed)
    ));
    std::fs::create_dir_all(&root).expect("temporary root is created");
    let config = root.join("config.fifo");
    assert!(
        Command::new("mkfifo")
            .arg(&config)
            .status()
            .expect("mkfifo is available")
            .success()
    );
    let mut fifo = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open(&config)
        .expect("test holds both FIFO ends");
    let child = Command::new(env!("CARGO_BIN_EXE_gta-claw-daemon"))
        .args(["--smoke", "--config"])
        .arg(&config)
        .args(["--state-dir"])
        .arg(&root)
        .env_clear()
        .env("GTA_CLAW_LOG", "off")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .expect("daemon process starts");
    let mut child = ChildGuard(child, root);
    let stdout = child.0.stdout.take().expect("daemon stdout is piped");
    let mut stdout = BufReader::new(stdout);
    std::thread::sleep(Duration::from_millis(100));
    assert!(
        Command::new("kill")
            .arg("-HUP")
            .arg(child.0.id().to_string())
            .status()
            .expect("kill is available")
            .success()
    );
    let snapshot = migrate_legacy_environment([
        ("GITHUB_TOKEN", "test"),
        ("ENABLE_TEAMS", "false"),
        ("ENABLE_TELEGRAM", "false"),
        ("ENABLE_DISCORD", "false"),
        ("ENABLE_WHATSAPP", "false"),
        ("COPILOT_MODEL", "gpt-4o"),
        ("AGENT_ROLE_URL", "https://example.test/role"),
    ])
    .expect("configuration fixture migrates")
    .config;
    let source = to_json5(&snapshot).expect("configuration fixture serializes");
    fifo.write_all(source.as_bytes())
        .expect("configuration FIFO is released");
    std::fs::remove_file(&config).expect("configuration FIFO is unlinked");
    std::fs::write(&config, &source).expect("reloadable configuration file is installed");
    drop(fifo);

    let mut line = String::new();
    stdout.read_line(&mut line).expect("deferred reload is readable");
    assert_eq!(line.trim_end(), "reload deferred phase=starting");
    line.clear();
    stdout.read_line(&mut line).expect("applied reload is readable");
    assert_eq!(line.trim_end(), "reloaded generation=0 changed=none");
    line.clear();
    stdout.read_line(&mut line).expect("readiness is readable");
    assert_eq!(line, "ready protocol=1\n");
    child
        .0
        .stdin
        .as_mut()
        .expect("control channel is piped")
        .write_all(b"shutdown\n")
        .expect("shutdown is written");
    line.clear();
    while !line.starts_with("stopped ") {
        line.clear();
        stdout.read_line(&mut line).expect("stop summary is readable");
    }
    assert!(child.0.wait().expect("daemon exits").success());
}

#[cfg(unix)]
#[test]
fn telemetry_startup_io_is_cancelled_joined_and_reported() {
    let root = std::env::temp_dir().join(format!(
        "gta-claw-telemetry-signal-{}-{}",
        std::process::id(),
        NEXT_STATE.fetch_add(1, Ordering::Relaxed)
    ));
    std::fs::create_dir_all(&root).expect("temporary root is created");
    let config = root.join("config.fifo");
    let log = root.join("telemetry.fifo");
    for fifo in [&config, &log] {
        let created = Command::new("mkfifo")
            .arg(fifo)
            .status()
            .expect("mkfifo is available");
        assert!(created.success());
    }
    let snapshot = migrate_legacy_environment([
        ("GITHUB_TOKEN", "test"),
        ("ENABLE_TEAMS", "false"),
        ("ENABLE_TELEGRAM", "false"),
        ("ENABLE_DISCORD", "false"),
        ("ENABLE_WHATSAPP", "false"),
        ("COPILOT_MODEL", "gpt-4o"),
        ("AGENT_ROLE_URL", "https://example.test/role"),
    ])
    .expect("configuration fixture migrates")
    .config;
    let source = to_json5(&snapshot).expect("configuration fixture serializes");
    let child = Command::new(env!("CARGO_BIN_EXE_gta-claw-daemon"))
        .args(["--smoke", "--config"])
        .arg(&config)
        .args(["--log-file"])
        .arg(&log)
        .args(["--state-dir"])
        .arg(&root)
        .env_clear()
        .env("GITHUB_TOKEN", "test")
        .env("ENABLE_TEAMS", "false")
        .env("ENABLE_TELEGRAM", "false")
        .env("ENABLE_DISCORD", "false")
        .env("ENABLE_WHATSAPP", "false")
        .env("COPILOT_MODEL", "gpt-4o")
        .env("AGENT_ROLE_URL", "https://example.test/role")
        .env("GTA_CLAW_LOG", "off")
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("daemon process starts");
    let mut child = ChildGuard(child, root);
    let stdout = child.0.stdout.take().expect("daemon stdout is piped");
    let (line_tx, line_rx) = std::sync::mpsc::channel();
    std::thread::spawn(move || {
        for line in BufReader::new(stdout).lines() {
            let Ok(line) = line else {
                break;
            };
            if line_tx.send(line).is_err() {
                break;
            }
        }
    });
    let mut config_writer = std::fs::OpenOptions::new()
        .write(true)
        .open(&config)
        .expect("configuration writer meets the installed reader");
    config_writer
        .write_all(source.as_bytes())
        .expect("configuration fixture is written");
    drop(config_writer);
    std::thread::sleep(Duration::from_millis(250));

    let signalled = Command::new("kill")
        .arg("-TERM")
        .arg(child.0.id().to_string())
        .status()
        .expect("kill is available");
    assert!(signalled.success());
    let _log_guard = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open(&log)
        .expect("opening the reader releases telemetry startup");

    let stopped = loop {
        let line = line_rx.recv_timeout(EXIT_BUDGET).unwrap_or_else(|error| {
            let status = child.0.wait().expect("daemon status is available");
            let mut stderr = String::new();
            child
                .0
                .stderr
                .take()
                .expect("daemon stderr is piped")
                .read_to_string(&mut stderr)
                .expect("daemon stderr is readable");
            panic!("daemon stopped without a summary: {error}; status={status}; stderr={stderr:?}");
        });
        if line.starts_with("stopped ") {
            break line;
        }
    };
    let summary = StopLine::parse(&stopped);
    assert_eq!(summary.reason, "terminate");
    assert!(summary.clean, "{summary:?}");
    assert_eq!(summary.telemetry, "clean");
    assert_ne!((summary.joined, summary.spawned), (0, 0));
    assert_eq!(summary.joined, summary.spawned);
    assert!(child.0.wait().expect("daemon exits").success());
}

#[cfg(unix)]
#[test]
fn reload_received_during_telemetry_io_is_applied_before_readiness() {
    let root = std::env::temp_dir().join(format!(
        "gta-claw-early-reload-telemetry-{}-{}",
        std::process::id(),
        NEXT_STATE.fetch_add(1, Ordering::Relaxed)
    ));
    std::fs::create_dir_all(&root).expect("temporary root is created");
    let config = root.join("config.json5");
    let log = root.join("telemetry.fifo");
    assert!(
        Command::new("mkfifo")
            .arg(&log)
            .status()
            .expect("mkfifo is available")
            .success()
    );
    let snapshot = migrate_legacy_environment([
        ("GITHUB_TOKEN", "test"),
        ("ENABLE_TEAMS", "false"),
        ("ENABLE_TELEGRAM", "false"),
        ("ENABLE_DISCORD", "false"),
        ("ENABLE_WHATSAPP", "false"),
        ("COPILOT_MODEL", "gpt-4o"),
        ("AGENT_ROLE_URL", "https://example.test/role"),
    ])
    .expect("configuration fixture migrates")
    .config;
    std::fs::write(
        &config,
        to_json5(&snapshot).expect("configuration fixture serializes"),
    )
    .expect("configuration fixture is written");
    let child = Command::new(env!("CARGO_BIN_EXE_gta-claw-daemon"))
        .args(["--smoke", "--config"])
        .arg(&config)
        .args(["--log-file"])
        .arg(&log)
        .args(["--state-dir"])
        .arg(&root)
        .env_clear()
        .env("GTA_CLAW_LOG", "off")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .expect("daemon process starts");
    let mut child = ChildGuard(child, root);
    let stdout = child.0.stdout.take().expect("daemon stdout is piped");
    let mut stdout = BufReader::new(stdout);
    std::thread::sleep(Duration::from_millis(250));
    assert!(
        Command::new("kill")
            .arg("-HUP")
            .arg(child.0.id().to_string())
            .status()
            .expect("kill is available")
            .success()
    );
    let _log_guard = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open(&log)
        .expect("opening the reader releases telemetry startup");

    let mut line = String::new();
    stdout.read_line(&mut line).expect("deferred reload is readable");
    assert_eq!(line.trim_end(), "reload deferred phase=starting");
    line.clear();
    stdout.read_line(&mut line).expect("applied reload is readable");
    assert_eq!(line.trim_end(), "reloaded generation=0 changed=none");
    line.clear();
    stdout.read_line(&mut line).expect("readiness is readable");
    assert_eq!(line, "ready protocol=1\n");
    child
        .0
        .stdin
        .as_mut()
        .expect("control channel is piped")
        .write_all(b"shutdown\n")
        .expect("shutdown is written");
    line.clear();
    while !line.starts_with("stopped ") {
        line.clear();
        stdout.read_line(&mut line).expect("stop summary is readable");
    }
    assert!(child.0.wait().expect("daemon exits").success());
}

#[cfg(unix)]
#[test]
fn rejected_deferred_reload_never_opens_serving_or_readiness() {
    let root = std::env::temp_dir().join(format!(
        "gta-claw-rejected-early-reload-{}-{}",
        std::process::id(),
        NEXT_STATE.fetch_add(1, Ordering::Relaxed)
    ));
    std::fs::create_dir_all(&root).expect("temporary root is created");
    let config = root.join("config.json5");
    let log = root.join("telemetry.fifo");
    assert!(
        Command::new("mkfifo")
            .arg(&log)
            .status()
            .expect("mkfifo is available")
            .success()
    );
    let snapshot = migrate_legacy_environment([
        ("GITHUB_TOKEN", "test"),
        ("ENABLE_TEAMS", "false"),
        ("ENABLE_TELEGRAM", "false"),
        ("ENABLE_DISCORD", "false"),
        ("ENABLE_WHATSAPP", "false"),
        ("COPILOT_MODEL", "gpt-4o"),
        ("AGENT_ROLE_URL", "https://example.test/role"),
    ])
    .expect("configuration fixture migrates")
    .config;
    std::fs::write(
        &config,
        to_json5(&snapshot).expect("configuration fixture serializes"),
    )
    .expect("configuration fixture is written");
    let child = Command::new(env!("CARGO_BIN_EXE_gta-claw-daemon"))
        .args(["--smoke", "--config"])
        .arg(&config)
        .args(["--log-file"])
        .arg(&log)
        .args(["--state-dir"])
        .arg(&root)
        .env_clear()
        .env("GTA_CLAW_LOG", "off")
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .expect("daemon process starts");
    let mut child = ChildGuard(child, root);
    let stdout = child.0.stdout.take().expect("daemon stdout is piped");
    let mut stdout = BufReader::new(stdout);
    std::thread::sleep(Duration::from_millis(250));
    std::fs::write(&config, "{ invalid reload").expect("invalid candidate is installed");
    assert!(
        Command::new("kill")
            .arg("-HUP")
            .arg(child.0.id().to_string())
            .status()
            .expect("kill is available")
            .success()
    );
    let _log_guard = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open(&log)
        .expect("opening the reader releases telemetry startup");

    let mut lines = Vec::new();
    loop {
        let mut line = String::new();
        stdout.read_line(&mut line).expect("daemon output is readable");
        if line.is_empty() {
            break;
        }
        let stopped = line.starts_with("stopped ");
        lines.push(line);
        if stopped {
            break;
        }
    }
    assert!(
        lines
            .iter()
            .any(|line| line.starts_with("reload rejected generation=0")),
        "{lines:?}"
    );
    assert!(
        lines.iter().all(|line| line != "ready protocol=1\n"),
        "readiness escaped before deferred reload commit: {lines:?}"
    );
    assert!(
        lines
            .last()
            .is_some_and(|line| line.starts_with("stopped reason=runtime clean=false")),
        "{lines:?}"
    );
    assert!(
        !child.0.wait().expect("daemon exits").success(),
        "rejected startup reload must fail the process"
    );
}

#[cfg(unix)]
#[test]
fn queued_stop_wins_before_startup_can_publish_readiness() {
    let root = std::env::temp_dir().join(format!(
        "gta-claw-queued-stop-{}-{}",
        std::process::id(),
        NEXT_STATE.fetch_add(1, Ordering::Relaxed)
    ));
    std::fs::create_dir_all(&root).expect("temporary root is created");
    let config = root.join("config.json5");
    let log = root.join("telemetry.fifo");
    assert!(
        Command::new("mkfifo")
            .arg(&log)
            .status()
            .expect("mkfifo is available")
            .success()
    );
    let snapshot = migrate_legacy_environment([
        ("GITHUB_TOKEN", "test"),
        ("ENABLE_TEAMS", "false"),
        ("ENABLE_TELEGRAM", "false"),
        ("ENABLE_DISCORD", "false"),
        ("ENABLE_WHATSAPP", "false"),
        ("COPILOT_MODEL", "gpt-4o"),
        ("AGENT_ROLE_URL", "https://example.test/role"),
    ])
    .expect("configuration fixture migrates")
    .config;
    std::fs::write(
        &config,
        to_json5(&snapshot).expect("configuration fixture serializes"),
    )
    .expect("configuration fixture is written");
    let child = Command::new(env!("CARGO_BIN_EXE_gta-claw-daemon"))
        .args(["--smoke", "--config"])
        .arg(&config)
        .args(["--log-file"])
        .arg(&log)
        .args(["--state-dir"])
        .arg(&root)
        .env_clear()
        .env("GTA_CLAW_LOG", "off")
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .expect("daemon process starts");
    let mut child = ChildGuard(child, root);
    let stdout = child.0.stdout.take().expect("daemon stdout is piped");
    let mut stdout = BufReader::new(stdout);
    thread::sleep(Duration::from_millis(250));
    for signal in ["-HUP", "-TERM"] {
        assert!(
            Command::new("kill")
                .arg(signal)
                .arg(child.0.id().to_string())
                .status()
                .expect("kill is available")
                .success()
        );
    }
    let _log_guard = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open(&log)
        .expect("opening the reader releases telemetry startup");

    let mut lines = Vec::new();
    loop {
        let mut line = String::new();
        stdout.read_line(&mut line).expect("daemon output is readable");
        if line.is_empty() {
            break;
        }
        let stopped = line.starts_with("stopped ");
        lines.push(line);
        if stopped {
            break;
        }
    }
    assert!(
        lines.iter().all(|line| line != "ready protocol=1\n"),
        "readiness won a simultaneous lifecycle race: {lines:?}"
    );
    assert!(
        lines
            .last()
            .is_some_and(|line| line.starts_with("stopped reason=terminate")),
        "{lines:?}"
    );
}

/// A terminated daemon must exit for its own reasons, not be killed.
///
/// Distinguishes a real drain from the failure this whole path exists to
/// prevent: an unhandled `SIGTERM` leaves the process killed by signal 15, so
/// asserting the stop line alone would not prove the handler ran.
#[cfg(unix)]
#[test]
fn a_terminated_daemon_exits_successfully_rather_than_being_killed() {
    use std::os::unix::process::ExitStatusExt;

    let (mut child, mut reader) = started();
    let pid = child.0.id().to_string();

    let signalled = Command::new("kill")
        .arg("-TERM")
        .arg(&pid)
        .status()
        .expect("kill is available");
    assert!(signalled.success(), "could not signal pid {pid}");

    let summary = stopped(&mut child, &mut reader);
    assert_eq!(summary.reason, "terminate");

    let status = child.0.wait().expect("the daemon process is waitable");

    assert_eq!(
        status.signal(),
        None,
        "the daemon was killed by a signal instead of draining"
    );
    assert!(
        status.success(),
        "the daemon exited unsuccessfully: {status:?}"
    );
}

/// A daemon that has drained must exit even though the pipe on its control
/// channel is still open.
///
/// This is the failure the other tests in this file cannot see. `Child::wait`
/// drops the parent's end of stdin before it waits, so every test that stops a
/// daemon through the `stopped` helper closes the control channel on the way
/// out, and a daemon that only exits because its stdin reached end-of-file
/// still looks healthy. A supervisor does not do that: systemd, `docker` and a
/// shell pipeline all hold the child's stdin open until the child is gone. This
/// keeps the handle and polls instead, so it fails if the process needs the pipe
/// closed to finish exiting.
#[cfg(unix)]
#[test]
fn a_drained_daemon_exits_while_its_control_channel_is_still_held_open() {
    use std::time::Instant;

    let (mut child, mut reader) = started();
    let pid = child.0.id().to_string();

    let signalled = Command::new("kill")
        .arg("-TERM")
        .arg(&pid)
        .status()
        .expect("kill is available");
    assert!(signalled.success(), "could not signal pid {pid}");

    let mut summary = String::new();
    reader
        .read_line(&mut summary)
        .expect("daemon stop summary is readable");
    let summary = StopLine::parse(summary.trim_end());
    assert_eq!(summary.reason, "terminate");
    assert!(
        summary.clean,
        "the daemon did not stop cleanly: {summary:?}"
    );

    // Deliberately polled rather than waited on: `wait` would close the very
    // pipe this test is holding open.
    let deadline = Instant::now() + EXIT_BUDGET;
    let status = loop {
        if let Some(status) = child.0.try_wait().expect("daemon status is available") {
            break status;
        }

        assert!(
            Instant::now() < deadline,
            "the daemon printed its stop summary but was still running {EXIT_BUDGET:?} later, \
             with its control channel still open"
        );

        std::thread::sleep(Duration::from_millis(10));
    };

    assert!(
        status.success(),
        "the daemon exited unsuccessfully: {status:?}"
    );
}

/// Repeating the stop signal must not deadlock the drain or cut it short.
///
/// A supervisor that has not seen a process exit yet sends the signal again,
/// and an operator holding down `Ctrl-C` does the same. The handlers stay
/// installed for the life of the process, so each repeat is caught rather than
/// falling through to the default disposition that would kill the daemon
/// mid-drain; every subsystem must still be drained and every task still
/// joined.
#[cfg(unix)]
#[test]
fn repeating_the_stop_signal_neither_deadlocks_the_drain_nor_skips_the_cleanup() {
    use std::os::unix::process::ExitStatusExt;

    let (mut child, mut reader) = started();
    let pid = child.0.id().to_string();

    // Only ever `SIGTERM`, so the reason below stays deterministic. The first
    // one starts the drain; the rest land during it or after the process is
    // already gone, which is why their exit status is ignored.
    for _ in 0..5 {
        let _ = Command::new("kill")
            .arg("-TERM")
            .arg(&pid)
            .stderr(Stdio::null())
            .status();
    }

    let summary = stopped(&mut child, &mut reader);

    assert_eq!(
        summary.reason, "terminate",
        "a repeated termination changed the reason the daemon reported"
    );
    assert!(
        summary.clean,
        "repeating the signal left the shutdown incomplete: {summary:?}"
    );
    assert_eq!(summary.abandoned, 0);
    assert_eq!(
        summary.drained, 4,
        "a repeated signal cut the drain short: {summary:?}"
    );
    assert_eq!(
        summary.joined, summary.spawned,
        "a repeated signal left a task unjoined"
    );

    let status = child.0.wait().expect("the daemon process is waitable");
    assert_eq!(
        status.signal(),
        None,
        "a repeated signal killed the daemon instead of being handled"
    );
}

#[cfg(unix)]
#[test]
fn a_full_supervisor_pipe_cannot_hold_the_process_open() {
    use std::os::unix::process::ExitStatusExt;
    use std::time::Instant;

    let (mut child, _unread_stdout) = started();
    let statuses = "status\n".repeat(2_000);
    if let Some(stdin) = child.0.stdin.as_mut() {
        let _ = stdin.write_all(statuses.as_bytes());
        let _ = stdin.flush();
    }
    std::thread::sleep(Duration::from_millis(750));
    let pid = child.0.id().to_string();
    let _ = Command::new("kill")
        .arg("-TERM")
        .arg(&pid)
        .stderr(Stdio::null())
        .status();

    let deadline = Instant::now() + EXIT_BUDGET;
    let status = loop {
        if let Some(status) = child.0.try_wait().expect("daemon status is available") {
            break status;
        }
        assert!(
            Instant::now() < deadline,
            "a full stdout pipe held the daemon open past {EXIT_BUDGET:?}"
        );
        std::thread::sleep(Duration::from_millis(10));
    };

    assert_eq!(
        status.signal(),
        None,
        "the bounded output path left SIGTERM at its default disposition"
    );
}

#[test]
fn the_stop_line_parser_reads_every_field_independently() {
    let parsed = StopLine::parse(
        "stopped reason=control clean=true drained=12 completed=3 abandoned=1 tasks=7/9 telemetry=clean deadline_expired=false",
    );

    assert_eq!(
        parsed,
        StopLine {
            reason: "control".to_owned(),
            clean: true,
            drained: 12,
            completed: 3,
            abandoned: 1,
            joined: 7,
            spawned: 9,
            telemetry: "clean".to_owned(),
            deadline_expired: false,
        }
    );
}

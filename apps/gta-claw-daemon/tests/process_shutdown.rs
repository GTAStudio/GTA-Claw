//! Process-level checks that a real daemon process shuts down cleanly.
//!
//! These run the actual binary rather than the composition in-process, so they
//! prove the whole path: build the composition, start twelve subsystems, print
//! the ready contract, receive a stop signal from outside the process, drain,
//! and join every task before exiting.

use std::io::{BufRead, BufReader, Write};
use std::process::{Child, Command, Stdio};
use std::time::Duration;

/// Kills the child if an assertion unwinds before the test gets to stop it.
struct ChildGuard(Child);

impl Drop for ChildGuard {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
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
        }
    }
}

/// Spawns the daemon with a writable control channel and waits for readiness.
///
/// The daemon now loads configuration at startup and refuses to run
/// half-configured, so a test that starts it must configure it. This supplies
/// the smallest environment the frozen contract accepts — a role source, a
/// GitHub credential, and Teams disabled — which is exactly what
/// `src/config.ts` demands of the legacy product today. Every assertion below
/// is about lifecycle, not configuration, and none of them is relaxed by it.
fn started() -> (ChildGuard, BufReader<std::process::ChildStdout>) {
    let child = Command::new(env!("CARGO_BIN_EXE_gta-claw-daemon"))
        .env("AGENT_ROLE_URL", "https://roles.example.com/role.json")
        .env("ENABLE_TEAMS", "false")
        .env("GITHUB_TOKEN", "lifecycle-token")
        .env("PORT", reserved_port().to_string())
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .expect("daemon process starts");
    let mut child = ChildGuard(child);
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

    // The daemon now also announces its bound address and the surfaces that are
    // closed. Consume them here so the stop line remains the next thing every
    // caller reads, exactly as before.
    let mut startup = String::new();
    while !startup.starts_with("protected routes closed:") {
        startup.clear();
        let read = reader
            .read_line(&mut startup)
            .expect("daemon startup lines are readable");
        assert!(read > 0, "daemon exited during startup");
    }

    (child, reader)
}

/// Returns a port that is free at this instant.
fn reserved_port() -> u16 {
    std::net::TcpListener::bind(("127.0.0.1", 0))
        .expect("reserve an ephemeral port")
        .local_addr()
        .expect("reserved port is readable")
        .port()
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
        // Twelve composed subsystems plus the HTTP ingress that owns the real
        // listening socket.
        summary.drained,
        13,
        "not every subsystem was drained on the way down"
    );
    assert_eq!(
        summary.completed, 0,
        "an idle daemon reported in-flight work"
    );
    assert_eq!(
        summary.joined, summary.spawned,
        "a spawned task was not joined"
    );
}

#[test]
fn an_unrecognised_control_line_does_not_stop_the_process() {
    let (mut child, mut reader) = started();

    {
        let stdin = child.0.stdin.as_mut().expect("daemon stdin is piped");
        stdin
            .write_all(b"status\nreload\n")
            .expect("the control lines are writable");
        stdin.flush().expect("the control channel flushes");
    }

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
    assert_eq!(summary.drained, 13);
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
    assert_eq!(summary.drained, 13);
    assert_eq!(
        summary.joined, summary.spawned,
        "a spawned task was not joined on a supervisor termination"
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

#[test]
fn the_stop_line_parser_reads_every_field_independently() {
    let parsed = StopLine::parse(
        "stopped reason=control clean=true drained=12 completed=3 abandoned=1 tasks=7/9",
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
        }
    );
}

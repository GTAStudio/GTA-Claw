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
fn started() -> (ChildGuard, BufReader<std::process::ChildStdout>) {
    let child = Command::new(env!("CARGO_BIN_EXE_gta-claw-daemon"))
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
        summary.drained, 12,
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
    assert_eq!(summary.drained, 12);
    assert_eq!(summary.joined, summary.spawned);
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

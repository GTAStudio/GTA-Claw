//! Process-level checks for daemon lifecycle modes.

use std::io::{BufRead, BufReader};
use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::sync::atomic::{AtomicU64, Ordering};
use std::thread;
use std::time::Duration;

static NEXT_STATE: AtomicU64 = AtomicU64::new(0);

struct ChildGuard {
    child: Child,
    state: PathBuf,
}

impl Drop for ChildGuard {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
        let _ = std::fs::remove_dir_all(&self.state);
    }
}

fn command() -> (Command, PathBuf) {
    let state = std::env::temp_dir().join(format!(
        "gta-claw-process-lifecycle-{}-{}",
        std::process::id(),
        NEXT_STATE.fetch_add(1, Ordering::Relaxed)
    ));
    let mut command = Command::new(env!("CARGO_BIN_EXE_gta-claw-daemon"));
    command.env_clear();
    command
        .args([
            "--smoke",
            "--listen",
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
        .env("GTA_CLAW_STATE_DIR", &state);
    (command, state)
}

#[test]
fn normal_mode_remains_running_until_terminated() {
    let (mut command, state) = command();
    let child = command
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .expect("daemon process starts");
    let mut child = ChildGuard { child, state };
    let stdout = child.child.stdout.take().expect("daemon stdout is piped");
    let mut reader = BufReader::new(stdout);
    let mut readiness = String::new();

    reader
        .read_line(&mut readiness)
        .expect("daemon readiness is readable");
    assert_eq!(readiness, "ready protocol=1\n");

    thread::sleep(Duration::from_millis(100));

    assert!(
        child
            .child
            .try_wait()
            .expect("daemon status is available")
            .is_none(),
        "normal daemon mode exited instead of supervising"
    );
}

#[test]
fn one_shot_probe_exits_successfully() {
    let output = Command::new(env!("CARGO_BIN_EXE_gta-claw-daemon"))
        .arg("--probe")
        .output()
        .expect("daemon probe starts");

    assert!(output.status.success());

    let output = String::from_utf8(output.stdout).expect("stdout is UTF-8");
    assert!(output.starts_with("healthy runtime="));
    assert!(!output.contains("ready protocol="));
}

#[test]
fn an_unsupported_argument_is_refused_with_the_usage_line() {
    let output = Command::new(env!("CARGO_BIN_EXE_gta-claw-daemon"))
        .arg("--reload")
        .output()
        .expect("daemon starts");

    assert_eq!(
        output.status.code(),
        Some(1),
        "an unsupported argument must be a plain start-up failure"
    );

    let message = String::from_utf8(output.stderr).expect("stderr is UTF-8");
    assert!(
        message.contains("usage: gta-claw-daemon"),
        "an operator was not told how to invoke the daemon: {message:?}"
    );
}

/// An argument that is not valid Unicode must be refused, not panic.
///
/// `std::env::args` panics part way through iteration on an argument like this,
/// which would turn a mistyped invocation into exit 101 and a panic message
/// naming a std internal — telling an operator nothing about what to fix, and
/// indistinguishable from a defect in the daemon. Restricted to unix because
/// Windows arguments are UTF-16 and cannot carry this byte.
#[cfg(unix)]
#[test]
fn an_argument_that_is_not_valid_unicode_is_refused_rather_than_panicking() {
    use std::ffi::OsStr;
    use std::os::unix::ffi::OsStrExt;
    use std::os::unix::process::ExitStatusExt;

    let output = Command::new(env!("CARGO_BIN_EXE_gta-claw-daemon"))
        .arg(OsStr::from_bytes(b"--pro\xffbe"))
        .output()
        .expect("daemon starts");

    assert_eq!(
        output.status.signal(),
        None,
        "the daemon died by signal on a malformed argument"
    );
    assert_eq!(
        output.status.code(),
        Some(1),
        "a malformed argument must be a start-up failure, not a panic (101): {:?}",
        String::from_utf8_lossy(&output.stderr)
    );

    let message = String::from_utf8_lossy(&output.stderr);
    assert!(
        message.contains("usage: gta-claw-daemon"),
        "an operator was not told how to invoke the daemon: {message:?}"
    );
    assert!(
        !message.contains("panicked"),
        "a malformed argument panicked instead of being refused: {message:?}"
    );
}

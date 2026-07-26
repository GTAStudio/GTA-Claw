//! Process-level checks for daemon lifecycle modes.

use std::io::{BufRead, BufReader};
use std::net::TcpListener;
use std::process::{Child, Command, Stdio};
use std::thread;
use std::time::Duration;

struct ChildGuard(Child);

impl Drop for ChildGuard {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

/// Returns a port that is free at this instant.
fn reserve_port() -> u16 {
    let listener = TcpListener::bind(("127.0.0.1", 0)).expect("reserve an ephemeral port");
    listener
        .local_addr()
        .expect("reserved port is readable")
        .port()
}

/// Builds a daemon invocation with the smallest configuration the frozen
/// contract accepts, so an inherited environment cannot decide the outcome.
fn daemon() -> Command {
    let mut command = Command::new(env!("CARGO_BIN_EXE_gta-claw-daemon"));
    command
        .env("AGENT_ROLE_URL", "https://roles.example.com/role.json")
        .env("ENABLE_TEAMS", "false")
        .env("GITHUB_TOKEN", "lifecycle-token")
        .env_remove("DEVICE_FLOW_ENABLED")
        .env_remove("DOMAIN")
        .env_remove("GITHUB_CLIENT_ID")
        .env_remove("HTTPS_PROXY")
        .env_remove("HTTP_PROXY")
        .env_remove("LOG_LEVEL")
        .env_remove("NODE_ENV")
        .env_remove("all_proxy")
        .env_remove("https_proxy");
    command
}

#[test]
fn normal_mode_remains_running_until_terminated() {
    let child = daemon()
        .env("PORT", reserve_port().to_string())
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .expect("daemon process starts");
    let mut child = ChildGuard(child);
    let stdout = child.0.stdout.take().expect("daemon stdout is piped");
    let mut reader = BufReader::new(stdout);
    let mut readiness = String::new();

    reader
        .read_line(&mut readiness)
        .expect("daemon readiness is readable");
    assert_eq!(readiness, "ready protocol=1\n");

    thread::sleep(Duration::from_millis(100));

    assert!(
        child
            .0
            .try_wait()
            .expect("daemon status is available")
            .is_none(),
        "normal daemon mode exited instead of supervising"
    );
}

#[test]
fn one_shot_probe_exits_successfully() {
    let output = daemon()
        .arg("--probe")
        .output()
        .expect("daemon probe starts");

    assert!(output.status.success());

    let output = String::from_utf8(output.stdout).expect("stdout is UTF-8");
    assert!(output.starts_with("healthy runtime="));
    assert!(!output.contains("ready protocol="));
}

//! Process-level checks for daemon lifecycle modes.

use std::io::{BufRead, BufReader, Read, Write};
use std::net::{Shutdown, TcpListener, TcpStream};
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

#[test]
fn normal_mode_remains_running_until_terminated() {
    let address = available_address();
    let child = Command::new(env!("CARGO_BIN_EXE_gta-claw-daemon"))
        .env("GTA_CLAW_BIND", &address)
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
fn http_probe_checks_the_running_daemon_endpoint() {
    let address = available_address();
    let child = Command::new(env!("CARGO_BIN_EXE_gta-claw-daemon"))
        .env("GTA_CLAW_BIND", &address)
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

    let probe = Command::new(env!("CARGO_BIN_EXE_gta-claw-daemon"))
        .arg("--probe-http")
        .env("GTA_CLAW_BIND", &address)
        .output()
        .expect("HTTP probe starts");

    assert!(probe.status.success());
    assert!(
        String::from_utf8(probe.stdout)
            .expect("probe output is UTF-8")
            .starts_with("healthy endpoint=http://")
    );
}

#[test]
fn slow_client_does_not_starve_the_http_probe() {
    let address = available_address();
    let child = Command::new(env!("CARGO_BIN_EXE_gta-claw-daemon"))
        .env("GTA_CLAW_BIND", &address)
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

    let mut slow_client = TcpStream::connect(&address).expect("slow client connects");
    slow_client
        .write_all(b"GET /health HTTP/1.1\r\nHost: localhost\r\n")
        .expect("slow client writes incomplete headers");
    thread::sleep(Duration::from_millis(100));

    let probe = Command::new(env!("CARGO_BIN_EXE_gta-claw-daemon"))
        .arg("--probe-http")
        .env("GTA_CLAW_BIND", &address)
        .output()
        .expect("HTTP probe starts");

    assert!(
        probe.status.success(),
        "slow client starved health probe: {}",
        String::from_utf8_lossy(&probe.stderr)
    );
}

#[test]
fn saturated_listener_returns_service_unavailable() {
    let address = available_address();
    let child = Command::new(env!("CARGO_BIN_EXE_gta-claw-daemon"))
        .env("GTA_CLAW_BIND", &address)
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

    let mut blockers = Vec::new();
    for _ in 0..32 {
        let mut stream = TcpStream::connect(&address).expect("blocking client connects");
        stream
            .write_all(b"GET /health HTTP/1.1\r\nHost: localhost\r\n")
            .expect("blocking client writes incomplete headers");
        blockers.push(stream);
    }
    thread::sleep(Duration::from_millis(500));

    let mut overloaded = TcpStream::connect(&address).expect("overload client connects");
    overloaded
        .set_read_timeout(Some(Duration::from_secs(1)))
        .expect("overload read timeout is set");
    let padding = "a".repeat(7 * 1024);
    let request = format!(
        "GET /health HTTP/1.1\r\nHost: localhost\r\nX-Padding: {padding}\r\nConnection: close\r\n\r\n"
    );
    overloaded
        .write_all(request.as_bytes())
        .expect("overload request is written");
    overloaded
        .shutdown(Shutdown::Write)
        .expect("overload request write side closes");
    let mut response = String::new();
    overloaded
        .read_to_string(&mut response)
        .expect("overload response is readable");

    assert!(
        response.starts_with("HTTP/1.1 503 Service Unavailable\r\n"),
        "unexpected overload response: {response:?}"
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

fn available_address() -> String {
    let listener = TcpListener::bind("127.0.0.1:0").expect("reserve daemon port");
    let address = listener.local_addr().expect("reserved daemon address");
    drop(listener);
    address.to_string()
}

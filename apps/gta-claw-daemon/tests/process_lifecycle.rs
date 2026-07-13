//! Process-level checks for daemon lifecycle modes.

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
    let child = Command::new(env!("CARGO_BIN_EXE_gta-claw-daemon"))
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("daemon process starts");
    let mut child = ChildGuard(child);

    thread::sleep(Duration::from_millis(500));

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
    let output = Command::new(env!("CARGO_BIN_EXE_gta-claw-daemon"))
        .arg("--probe")
        .output()
        .expect("daemon probe starts");

    assert!(output.status.success());

    let output = String::from_utf8(output.stdout).expect("stdout is UTF-8");
    assert!(output.starts_with("healthy runtime="));
    assert!(!output.contains("ready protocol="));
}

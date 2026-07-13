//! Process-level checks for unsupported CLI commands.

use std::process::Command;

#[test]
fn send_exits_nonzero_without_claiming_acceptance() {
    let output = Command::new(env!("CARGO_BIN_EXE_gta-claw-cli"))
        .args(["send", "session-9", "hello"])
        .output()
        .expect("CLI process starts");

    assert!(!output.status.success());
    assert!(output.stdout.is_empty());

    let error = String::from_utf8(output.stderr).expect("stderr is UTF-8");
    assert!(error.contains("unsupported operation: message transport is not configured"));
    assert!(!error.contains("accepted"));
}

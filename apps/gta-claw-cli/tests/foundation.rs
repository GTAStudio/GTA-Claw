//! Compatibility checks for the pre-Gateway CLI foundation.

use std::process::Command;

#[test]
fn version_remains_a_successful_bounded_command() {
    let output = Command::new(env!("CARGO_BIN_EXE_gta-claw-cli"))
        .arg("--version")
        .output()
        .expect("CLI process starts");

    assert!(output.status.success());
    assert_eq!(
        String::from_utf8(output.stdout).expect("UTF-8 stdout"),
        format!("gta-claw-cli {}\n", env!("CARGO_PKG_VERSION"))
    );
    assert!(output.stderr.is_empty());
}

#[test]
fn local_health_foundation_remains_separate() {
    let output = Command::new(env!("CARGO_BIN_EXE_gta-claw-cli"))
        .arg("health")
        .output()
        .expect("CLI process starts");

    assert!(output.status.success());
    assert!(
        String::from_utf8(output.stdout)
            .expect("UTF-8 stdout")
            .starts_with("healthy runtime=")
    );
    assert!(output.stderr.is_empty());
}

#[test]
fn unknown_commands_remain_fail_closed() {
    let output = Command::new(env!("CARGO_BIN_EXE_gta-claw-cli"))
        .arg("definitely-unknown")
        .output()
        .expect("CLI process starts");

    assert_eq!(output.status.code(), Some(2));
    assert!(output.stdout.is_empty());
    assert_eq!(
        String::from_utf8(output.stderr).expect("UTF-8 stderr"),
        "error: unknown command\n"
    );
}

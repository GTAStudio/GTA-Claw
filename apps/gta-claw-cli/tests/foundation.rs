//! Compatibility checks for the pre-Gateway CLI foundation.

use std::io::Write as _;
#[cfg(unix)]
use std::io::{BufRead as _, Read as _};
use std::process::{Command, ExitStatus, Stdio};
use std::time::{Duration, Instant};
#[cfg(unix)]
use std::time::{SystemTime, UNIX_EPOCH};

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

#[test]
fn documentation_never_places_literal_secrets_in_command_arguments() {
    let documentation = include_str!("../README.md");
    assert!(documentation.contains("trap 'restore_tty' 0"));
    assert!(documentation.contains("trap 'exit 130' 2"));
    assert!(documentation.contains("stty -echo"));
    assert!(documentation.contains("IFS= read -r GTA_CLAW_TOKEN"));
    assert!(!documentation.contains("read -r -s"));
    assert!(documentation.contains("Read-Host \"Gateway token\" -AsSecureString"));
    assert!(documentation.contains("version_status: \"redacted_peer_value\""));
    assert!(!documentation.contains("example-automation-token"));
    assert!(!documentation.contains("replace-with-token"));
    assert!(!documentation.lines().any(|line| {
        let line = line.trim_start();
        line.starts_with("printf ") || line.starts_with("echo ")
    }));
}

#[cfg(unix)]
#[test]
fn posix_hidden_input_sequence_runs_in_sh_and_dash_and_restores_echo() {
    assert_posix_hidden_input("sh");
    #[cfg(target_os = "linux")]
    assert_posix_hidden_input("dash");
}

#[cfg(unix)]
fn assert_posix_hidden_input(shell: &str) {
    let script = r#"
stty() { command printf '%s\n' "$1" >&2; }
restore_tty() { stty echo; }
trap 'restore_tty' 0
trap 'exit 129' 1
trap 'exit 130' 2
trap 'exit 131' 3
trap 'exit 143' 15
stty -echo
IFS= read -r GTA_CLAW_TOKEN
stty echo
trap - 0 1 2 3 15
"$1" <<EOF
$GTA_CLAW_TOKEN
EOF
"#;
    let sentinel = format!(
        "shell-input-{}-{}",
        std::process::id(),
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("system clock")
            .as_nanos()
    );
    assert!(!script.contains(&sentinel));
    let mut child = Command::new(shell)
        .args(["-c", script, "posix-doc-test", "cat"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("POSIX shell starts");
    let mut input = child.stdin.take().expect("shell stdin");
    input
        .write_all(format!("{sentinel}\n").as_bytes())
        .expect("write simulated hidden input");
    drop(input);
    let output = child.wait_with_output().expect("shell output");
    assert!(
        output.status.success(),
        "{shell}: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(
        String::from_utf8(output.stdout).expect("shell stdout"),
        format!("{sentinel}\n")
    );
    assert_eq!(output.stderr, b"-echo\necho\n");
}

#[cfg(unix)]
#[test]
fn posix_signal_path_restores_echo_and_terminates() {
    let script = r#"
stty() {
  command printf '%s\n' "$1" >&2
  test "$1" != "-echo" || command printf 'ready\n'
}
restore_tty() { stty echo; }
trap 'restore_tty' 0
trap 'exit 129' 1
trap 'exit 130' 2
trap 'exit 131' 3
trap 'exit 143' 15
stty -echo
IFS= read -r GTA_CLAW_TOKEN
exit 99
"#;
    let mut child = Command::new("sh")
        .args(["-c", script])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("POSIX shell starts");
    let mut stdout = std::io::BufReader::new(child.stdout.take().expect("shell stdout"));
    let mut ready = String::new();
    stdout.read_line(&mut ready).expect("read readiness");
    assert_eq!(ready, "ready\n");
    let signal = Command::new("kill")
        .args(["-TERM", &child.id().to_string()])
        .status()
        .expect("send TERM");
    assert!(signal.success());
    drop(child.stdin.take());
    let status = child.wait().expect("signal helper exits");
    assert_eq!(status.code(), Some(143));
    let mut stderr = Vec::new();
    child
        .stderr
        .take()
        .expect("shell stderr")
        .read_to_end(&mut stderr)
        .expect("read stty trace");
    assert_eq!(stderr, b"-echo\necho\n");
}

#[test]
fn saturated_stdout_cannot_hold_process_exit() {
    let (reader, writer) = os_pipe::pipe().expect("output pipe");
    let mut filler_writer = writer.try_clone().expect("clone output writer");
    let filler = std::thread::spawn(move || {
        let block = [b'x'; 8 * 1024];
        while filler_writer.write_all(&block).is_ok() {}
    });
    std::thread::sleep(Duration::from_millis(250));

    let child = Command::new(env!("CARGO_BIN_EXE_gta-claw-cli"))
        .arg("--help")
        .stdin(Stdio::null())
        .stdout(Stdio::from(writer))
        .stderr(Stdio::null())
        .spawn()
        .expect("CLI process starts");
    let started = Instant::now();
    let status = wait_bounded(child);
    assert_eq!(status.code(), Some(8));
    assert!(started.elapsed() < Duration::from_secs(2));
    drop(reader);
    filler.join().expect("filler exits after reader closes");
}

#[test]
fn broken_stdout_and_stderr_are_typed_internal_failures() {
    for (argument, break_stdout) in [("--help", true), ("definitely-unknown", false)] {
        let (reader, writer) = os_pipe::pipe().expect("broken output pipe");
        drop(reader);
        let mut command = Command::new(env!("CARGO_BIN_EXE_gta-claw-cli"));
        command
            .arg(argument)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null());
        if break_stdout {
            command.stdout(Stdio::from(writer));
        } else {
            command.stderr(Stdio::from(writer));
        }
        let status = wait_bounded(command.spawn().expect("CLI process starts"));
        assert_eq!(status.code(), Some(8));
    }
}

fn wait_bounded(mut child: std::process::Child) -> ExitStatus {
    let started = Instant::now();
    loop {
        if let Some(status) = child.try_wait().expect("CLI process status") {
            return status;
        }
        if started.elapsed() >= Duration::from_secs(2) {
            child.kill().expect("terminate hung CLI");
            panic!("CLI process exceeded its hard output bound");
        }
        std::thread::sleep(Duration::from_millis(10));
    }
}

//! What an operator sees when they invoke the binary directly.
//!
//! The parser tests next to `CommandLine::parse` cover the mapping from
//! arguments to a mode. They cannot observe the three things an operator
//! actually experiences: the exit status, which stream carries the text, and
//! the exact bytes on it. `--help` exiting 1 with `Error: Custom { .. }` on
//! standard error passed every parser test in this workspace, because no test
//! ran the process.
//!
//! Assertions here compare whole streams rather than prefixes. A prefix check
//! would still pass if the usage text were truncated, duplicated, or followed
//! by stray output, and truncated usage is exactly the kind of regression a
//! reader of these tests would expect them to catch.

use std::process::{Command, Output};
use std::sync::atomic::{AtomicU64, Ordering};

use gta_claw_daemon::production::USAGE;

static NEXT_STATE: AtomicU64 = AtomicU64::new(0);

fn run(arguments: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_gta-claw-daemon"))
        .args(arguments)
        .output()
        .expect("daemon process starts")
}

fn stdout_of(output: &Output) -> String {
    String::from_utf8(output.stdout.clone()).expect("UTF-8 stdout")
}

fn stderr_of(output: &Output) -> String {
    String::from_utf8(output.stderr.clone()).expect("UTF-8 stderr")
}

/// The complete successful answer: usage on stdout, nothing on stderr.
fn assert_is_the_help_answer(output: &Output, invocation: &[&str]) {
    assert_eq!(
        output.status.code(),
        Some(0),
        "{invocation:?} must succeed, stderr was {:?}",
        stderr_of(output)
    );
    assert_eq!(
        stdout_of(output),
        format!("{USAGE}\n"),
        "{invocation:?} must print exactly the usage text"
    );
    assert_eq!(
        stderr_of(output),
        "",
        "{invocation:?} must leave stderr untouched"
    );
}

#[test]
fn both_help_aliases_print_exactly_the_usage_text() {
    for alias in ["--help", "-h"] {
        let invocation = [alias];
        assert_is_the_help_answer(&run(&invocation), &invocation);
    }
}

#[test]
fn help_is_answered_wherever_it_appears() {
    // `--config --help` is the case that matters most: before the scan was
    // hoisted out of the argument loop, the value-taking flag consumed
    // `--help` and the daemon reported that a file named `--help` could not be
    // read. The request was not refused, it was silently reinterpreted.
    let orderings: [&[&str]; 8] = [
        &["--help", "--nonsense"],
        &["--nonsense", "--help"],
        &["--nonsense", "-h"],
        &["--config", "--help"],
        &["--listen", "-h"],
        &["--state-dir", "--help"],
        &["--log-file", "-h"],
        &["--probe", "--smoke", "--help"],
    ];

    for ordering in orderings {
        assert_is_the_help_answer(&run(ordering), ordering);
    }
}

#[test]
fn an_unsupported_flag_fails_with_the_usage_text_on_stderr() {
    let output = run(&["--nonsense-flag"]);

    assert_eq!(output.status.code(), Some(1));
    assert_eq!(
        stdout_of(&output),
        "",
        "a rejection must not write to stdout"
    );
    // The original defect rendered this as
    // `Error: Custom { kind: InvalidInput, error: "usage: ..." }`, so the
    // whole stream is compared rather than searched for a substring.
    assert_eq!(stderr_of(&output), format!("gta-claw-daemon: {USAGE}\n"));
}

#[test]
fn a_flag_missing_its_value_names_what_it_needed() {
    // The whole-command-line help scan must not turn an incomplete invocation
    // into a help request, and the diagnostic has to say which flag and what
    // kind of value, not merely restate the usage line.
    let expectations = [
        ("--config", "--config requires a path"),
        ("--listen", "--listen requires an address"),
        ("--state-dir", "--state-dir requires a path"),
        ("--log-file", "--log-file requires a path"),
    ];

    for (flag, reason) in expectations {
        let output = run(&[flag]);

        assert_eq!(output.status.code(), Some(1), "{flag} alone must fail");
        assert_eq!(stdout_of(&output), "", "{flag} must not write to stdout");
        assert_eq!(
            stderr_of(&output),
            format!("gta-claw-daemon: {reason}\n{USAGE}\n"),
            "{flag} must name the flag and the value it needed"
        );
    }
}

#[test]
fn check_config_rejects_an_unusable_state_destination_without_mutating_it() {
    let root = std::env::temp_dir().join(format!(
        "gta-claw-check-state-{}-{}",
        std::process::id(),
        NEXT_STATE.fetch_add(1, Ordering::Relaxed)
    ));
    std::fs::create_dir_all(&root).expect("temporary root is created");
    let state_file = root.join("not-a-directory");
    std::fs::write(&state_file, "sentinel").expect("sentinel state file is written");

    let output = Command::new(env!("CARGO_BIN_EXE_gta-claw-daemon"))
        .env_clear()
        .args(["--check-config", "--state-dir"])
        .arg(&state_file)
        .env("GITHUB_TOKEN", "test")
        .env("ENABLE_TEAMS", "false")
        .env("ENABLE_TELEGRAM", "false")
        .env("ENABLE_DISCORD", "false")
        .env("ENABLE_WHATSAPP", "false")
        .env("COPILOT_MODEL", "gpt-4o")
        .env("AGENT_ROLE_URL", "https://example.test/role")
        .output()
        .expect("configuration check runs");

    assert_eq!(output.status.code(), Some(1), "{output:?}");
    assert!(stdout_of(&output).is_empty(), "{output:?}");
    assert!(
        stderr_of(&output).contains("is not a directory"),
        "{output:?}"
    );
    assert_eq!(
        std::fs::read_to_string(&state_file).expect("sentinel remains readable"),
        "sentinel",
        "configuration checking mutated the state destination"
    );
    std::fs::remove_dir_all(root).expect("temporary root is removed");
}

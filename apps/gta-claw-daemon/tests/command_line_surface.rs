//! What an operator sees when they invoke the binary directly.
//!
//! The parser tests next to `CommandLine::parse` cover the mapping from
//! arguments to a mode. They cannot observe the two things an operator
//! actually experiences: the exit status, and which stream carries the text.
//! `--help` exiting 1 with `Error: Custom { .. }` on standard error passed
//! every parser test in this workspace, because no test ran the process.

use std::process::{Command, Output};

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

#[test]
fn help_succeeds_and_writes_only_to_stdout() {
    for flag in ["--help", "-h"] {
        let output = run(&[flag]);

        assert_eq!(output.status.code(), Some(0), "{flag} must succeed");
        assert!(
            stdout_of(&output).starts_with("usage: gta-claw-daemon"),
            "{flag} must print the invocation on stdout, got {:?}",
            stdout_of(&output)
        );
        assert!(
            stderr_of(&output).is_empty(),
            "{flag} must leave stderr empty, got {:?}",
            stderr_of(&output)
        );
    }
}

#[test]
fn help_is_answered_wherever_it_appears() {
    // `--config --help` is the case that matters most: before the scan was
    // hoisted, the value-taking flag consumed `--help` and the daemon reported
    // that a file named `--help` could not be read.
    let orderings: [&[&str]; 5] = [
        &["--help", "--nonsense"],
        &["--nonsense", "--help"],
        &["--config", "--help"],
        &["--listen", "-h"],
        &["--probe", "--smoke", "--help"],
    ];

    for ordering in orderings {
        let output = run(ordering);

        assert_eq!(
            output.status.code(),
            Some(0),
            "{ordering:?} must succeed, stderr was {:?}",
            stderr_of(&output)
        );
        assert!(
            stdout_of(&output).starts_with("usage: gta-claw-daemon"),
            "{ordering:?} must print the invocation"
        );
    }
}

#[test]
fn an_unsupported_flag_fails_on_stderr_without_a_debug_wrapper() {
    let output = run(&["--nonsense-flag"]);
    let stderr = stderr_of(&output);

    assert_eq!(
        output.status.code(),
        Some(1),
        "a rejected command line fails"
    );
    assert!(
        stdout_of(&output).is_empty(),
        "a rejection must not write to stdout, got {:?}",
        stdout_of(&output)
    );
    assert!(
        stderr.starts_with("gta-claw-daemon: usage:"),
        "the message must name the program and the invocation, got {stderr:?}"
    );
    // The original defect: `main` returned `Result`, so the message arrived
    // wrapped in the `Debug` rendering of the error type.
    assert!(
        !stderr.contains("Error:") && !stderr.contains("Custom {"),
        "the message must not be a Debug-formatted wrapper, got {stderr:?}"
    );
}

#[test]
fn a_flag_missing_its_value_is_still_rejected() {
    // The whole-command-line help scan must not turn an incomplete invocation
    // into a help request.
    for flag in ["--config", "--listen", "--state-dir"] {
        let output = run(&[flag]);

        assert_eq!(output.status.code(), Some(1), "{flag} alone must fail");
        assert!(
            stderr_of(&output).starts_with("gta-claw-daemon: "),
            "{flag} must explain itself on stderr"
        );
    }
}

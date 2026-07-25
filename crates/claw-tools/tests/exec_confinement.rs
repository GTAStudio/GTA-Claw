//! Process-execution confinement: argv fidelity, environment stripping,
//! working-directory confinement, deadlines, and whole-tree termination.
//!
//! The suite re-executes this very test binary as its child process, which
//! keeps everything inside the workspace and off the network while still
//! exercising real operating-system process semantics.

mod common;

use std::fs;
use std::path::PathBuf;
use std::process::{Command, Stdio};
use std::thread;
use std::time::{Duration, Instant};

use claw_tools::audit::InMemoryAuditSink;
use claw_tools::exec::{CancellationToken, EnvPolicy, ExecPolicy, ExecutionError, ProcessExecTool};
use claw_tools::permission::{Approval, Capability, GrantLedger, GrantRequest, GrantScope};
use claw_tools::registry::ToolRegistry;
use claw_tools::sandbox::{Sandbox, SandboxLimits};
use claw_tools::tool::ToolContext;
use serde_json::{Value, json};

use common::TempTree;

/// Selects the behaviour of a re-executed copy of this binary.
const ROLE_VAR: &str = "CLAW_TOOLS_EXEC_ROLE";
/// Directory the helper writes its markers into.
const DIR_VAR: &str = "CLAW_TOOLS_EXEC_DIR";
/// Separator used to round-trip an argument vector through one file.
const ARGV_SEPARATOR: char = '\u{1}';

const NOW: u64 = 1_700_000_000_000;

/// Harness arguments that make a re-executed copy run only the helper.
fn helper_arguments() -> Vec<String> {
    [
        "--exact",
        "exec_helper_entry",
        "--ignored",
        "--test-threads",
        "1",
    ]
    .into_iter()
    .map(str::to_owned)
    .collect()
}

/// The helper process entry point.
///
/// It is a `#[test]` only so the test binary can re-execute itself; a normal
/// run skips it because it is ignored, and an ignored run without the role
/// variable returns immediately.
#[test]
#[ignore = "re-executed helper process, not an assertion"]
fn exec_helper_entry() {
    let Ok(role) = std::env::var(ROLE_VAR) else {
        return;
    };
    let directory = PathBuf::from(
        std::env::var(DIR_VAR).expect("the helper always receives its marker directory"),
    );
    match role.as_str() {
        "argv" => {
            let recorded: Vec<String> = std::env::args().collect();
            fs::write(
                directory.join("argv.txt"),
                recorded.join(&ARGV_SEPARATOR.to_string()),
            )
            .expect("the helper can write its marker");
        }
        "env" => {
            let mut names: Vec<String> = std::env::vars()
                .map(|(name, value)| format!("{name}={value}"))
                .collect();
            names.sort();
            fs::write(directory.join("env.txt"), names.join("\n"))
                .expect("the helper can write its marker");
        }
        "cwd" => {
            let current = std::env::current_dir().expect("a working directory exists");
            fs::write(
                directory.join("cwd.txt"),
                current.to_string_lossy().as_ref(),
            )
            .expect("the helper can write its marker");
        }
        "sleep" => {
            thread::sleep(Duration::from_secs(30));
        }
        "parent" => {
            let executable = std::env::current_exe().expect("the helper knows its own path");
            let mut child = Command::new(executable)
                .args(helper_arguments())
                .env(ROLE_VAR, "grandchild")
                .env(DIR_VAR, &directory)
                .stdin(Stdio::null())
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .spawn()
                .expect("the grandchild spawns");
            fs::write(directory.join("parent_started"), "1")
                .expect("the helper can write its marker");
            thread::sleep(Duration::from_secs(60));
            // Unreachable in practice: the tree kill arrives first. It is here
            // so the helper never leaves a zombie if a test is interrupted.
            let _ = child.kill();
            let _ = child.wait();
        }
        "grandchild" => {
            fs::write(directory.join("grandchild_started"), "1")
                .expect("the helper can write its marker");
            thread::sleep(Duration::from_secs(20));
            fs::write(directory.join("grandchild_survived"), "1")
                .expect("the helper can write its marker");
        }
        other => panic!("unknown helper role {other}"),
    }
}

struct Harness {
    tree: TempTree,
    sandbox: Sandbox,
    ledger: GrantLedger,
    audit: InMemoryAuditSink,
}

impl Harness {
    fn new(label: &str) -> Self {
        let tree = TempTree::new(label);
        tree.dir("workspace/sub");
        tree.dir("markers");
        let sandbox = Sandbox::new(&tree.join("workspace"), SandboxLimits::default())
            .expect("workspace root is adoptable");
        let mut ledger = GrantLedger::new();
        ledger.grant(GrantRequest {
            capability: Capability::ProcessExecute,
            scope: GrantScope::Program("helper".to_owned()),
            expires_unix_millis: None,
            max_uses: None,
            approval: Approval::Explicit,
        });
        Self {
            tree,
            sandbox,
            ledger,
            audit: InMemoryAuditSink::new(),
        }
    }

    fn markers(&self) -> PathBuf {
        self.tree.join("markers")
    }

    fn policy(&self, role: &str) -> ExecPolicy {
        let mut env = EnvPolicy::empty()
            .with_platform_minimum()
            .expect("the platform minimum is valid");
        env.set(ROLE_VAR, role).expect("the role name is valid");
        env.set(
            DIR_VAR,
            self.markers().to_str().expect("temporary paths are UTF-8"),
        )
        .expect("the marker directory is valid");
        let mut policy = ExecPolicy::deny_all()
            .with_env(env)
            .with_timeout(Duration::from_secs(45));
        policy
            .allow_program(
                "helper",
                std::env::current_exe().expect("the test binary knows its own path"),
            )
            .expect("the test binary is an acceptable program");
        policy
    }

    fn run(
        &mut self,
        tool: ProcessExecTool,
        arguments: &Value,
    ) -> Result<claw_tools::tool::ToolOutput, claw_tools::error::ToolError> {
        let mut registry = ToolRegistry::new();
        registry
            .register(Box::new(tool))
            .expect("process_exec registers");
        let context = ToolContext {
            sandbox: &self.sandbox,
            unix_millis: NOW,
        };
        registry.invoke(
            "process_exec",
            arguments,
            &context,
            &mut self.ledger,
            &mut self.audit,
        )
    }

    fn marker(&self, name: &str) -> Option<String> {
        fs::read_to_string(self.markers().join(name)).ok()
    }
}

#[test]
fn argument_vectors_reach_the_child_verbatim_without_shell_interpretation() {
    let mut harness = Harness::new("exec-argv");
    let payload = [
        "alpha && whoami",
        "$(id)",
        "; rm -rf /tmp/definitely-not-real",
        "| more",
        "beta`whoami`",
        "%SYSTEMROOT%",
        "with \"quotes\" and \\backslashes\\",
        "trailing\\",
    ];
    let mut args = helper_arguments();
    args.extend(payload.iter().map(|entry| (*entry).to_owned()));

    let tool = ProcessExecTool::new(harness.policy("argv"));
    harness
        .run(tool, &json!({ "program": "helper", "args": args }))
        .expect("the helper runs");

    let recorded = harness
        .marker("argv.txt")
        .expect("the helper recorded its argument vector");
    let observed: Vec<&str> = recorded.split(ARGV_SEPARATOR).collect();
    assert_eq!(
        &observed[observed.len() - payload.len()..],
        &payload[..],
        "the child observed a different argument vector than the one supplied"
    );
    assert!(
        !harness.tree.exists("markers/definitely-not-real"),
        "no shell may have interpreted the payload"
    );
}

#[test]
fn the_child_environment_contains_only_what_the_operator_allowed() {
    let mut harness = Harness::new("exec-env");
    let tool = ProcessExecTool::new(harness.policy("env"));
    harness
        .run(
            tool,
            &json!({ "program": "helper", "args": helper_arguments() }),
        )
        .expect("the helper runs");

    let recorded = harness
        .marker("env.txt")
        .expect("the helper recorded its environment");
    // Windows preserves whatever case a variable was created with, so the
    // comparison is made on lowercased names.
    let names: Vec<String> = recorded
        .lines()
        .filter_map(|line| line.split('=').next())
        .map(str::to_ascii_lowercase)
        .collect();
    let mut expected: Vec<String> =
        vec![DIR_VAR.to_ascii_lowercase(), ROLE_VAR.to_ascii_lowercase()];
    if cfg!(windows) {
        expected.push("systemroot".to_owned());
        expected.push("windir".to_owned());
    }
    expected.sort();
    let mut observed = names.clone();
    observed.sort();
    observed.dedup();
    assert_eq!(
        observed, expected,
        "the child inherited variables the operator never allowed"
    );
    assert!(
        !names.iter().any(|name| name == "path"),
        "PATH must never reach an allowlisted child: {names:?}"
    );
}

#[test]
fn the_working_directory_is_confined_to_the_workspace() {
    let mut harness = Harness::new("exec-cwd");
    let tool = ProcessExecTool::new(harness.policy("cwd"));
    harness
        .run(
            tool,
            &json!({ "program": "helper", "args": helper_arguments(), "cwd": "sub" }),
        )
        .expect("the helper runs");

    let recorded = harness
        .marker("cwd.txt")
        .expect("the helper recorded its working directory");
    assert_eq!(
        fs::canonicalize(recorded).expect("canonicalizable"),
        fs::canonicalize(harness.tree.join("workspace/sub")).expect("canonicalizable")
    );
}

#[test]
fn a_working_directory_outside_the_workspace_is_refused() {
    let mut harness = Harness::new("exec-cwd-escape");
    let tool = ProcessExecTool::new(harness.policy("cwd"));
    let error = harness
        .run(
            tool,
            &json!({ "program": "helper", "args": helper_arguments(), "cwd": "../markers" }),
        )
        .expect_err("traversal in the working directory is refused");
    assert_eq!(
        error.sandbox(),
        Some(claw_tools::sandbox::SandboxError::ParentTraversalForbidden)
    );
    assert!(
        harness.marker("cwd.txt").is_none(),
        "the refused invocation must not have spawned anything"
    );
}

#[test]
fn a_program_outside_the_allowlist_never_spawns() {
    let mut harness = Harness::new("exec-allowlist");
    let tool = ProcessExecTool::new(harness.policy("argv"));
    let error = harness
        .run(
            tool,
            &json!({ "program": "curl", "args": ["https://example.com"] }),
        )
        .expect_err("an unlisted program is refused");
    assert_eq!(
        error.execution(),
        Some(&ExecutionError::ProgramNotAllowed),
        "unexpected error {error:?}"
    );
}

#[test]
fn a_program_path_supplied_by_the_model_is_rejected_as_a_name() {
    let mut harness = Harness::new("exec-pathname");
    for candidate in [
        "/bin/sh",
        "C:\\Windows\\System32\\cmd.exe",
        "../helper",
        "-helper",
        "helper argument",
    ] {
        let tool = ProcessExecTool::new(harness.policy("argv"));
        let error = harness
            .run(tool, &json!({ "program": candidate, "args": [] }))
            .expect_err("a path is never a program name");
        assert!(
            matches!(
                error.execution(),
                Some(&ExecutionError::ProgramNameRejected)
                    | Some(&ExecutionError::ProgramNotAllowed)
            ),
            "unexpected error {error:?} for {candidate:?}"
        );
    }
}

#[test]
fn a_deadline_terminates_a_hung_child() {
    let mut harness = Harness::new("exec-timeout");
    let tool = ProcessExecTool::new(harness.policy("sleep"));
    let started = Instant::now();
    let error = harness
        .run(
            tool,
            &json!({
                "program": "helper",
                "args": helper_arguments(),
                "timeout_ms": 1_500,
            }),
        )
        .expect_err("the child outlives its deadline");
    assert_eq!(error.execution(), Some(&ExecutionError::TimedOut));
    assert!(
        started.elapsed() < Duration::from_secs(25),
        "the deadline did not actually interrupt the child"
    );
}

#[test]
fn cancellation_kills_the_whole_process_tree_not_just_the_child() {
    let mut harness = Harness::new("exec-tree");
    let token = CancellationToken::new();
    let tool = ProcessExecTool::new(harness.policy("parent")).with_cancellation(token.clone());

    // Cancel only once the grandchild has demonstrably started, so the test
    // can never pass vacuously by cancelling before the tree exists.
    let markers = harness.markers();
    let watcher = thread::spawn(move || {
        let deadline = Instant::now() + Duration::from_secs(30);
        let mut observed = false;
        while Instant::now() < deadline {
            if markers.join("grandchild_started").exists() {
                observed = true;
                break;
            }
            thread::sleep(Duration::from_millis(25));
        }
        token.cancel();
        observed
    });

    let error = harness
        .run(
            tool,
            &json!({ "program": "helper", "args": helper_arguments() }),
        )
        .expect_err("a cancelled invocation fails");
    let observed = watcher.join().expect("the watcher thread finishes");

    assert!(
        observed,
        "the grandchild never started, so this test proved nothing"
    );
    assert_eq!(error.execution(), Some(&ExecutionError::Cancelled));
    assert!(
        harness.marker("grandchild_started").is_some(),
        "the grandchild must have run"
    );

    // The grandchild sleeps for 20 seconds before writing its survival
    // marker; if the tree kill worked, that marker never appears.
    thread::sleep(Duration::from_secs(5));
    assert!(
        harness.marker("grandchild_survived").is_none(),
        "a grandchild outlived the cancelled invocation"
    );
}

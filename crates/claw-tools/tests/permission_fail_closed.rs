//! Proof that every dangerous operation fails closed.
//!
//! These tests drive the real registry against a real workspace. An operation
//! that was not granted must not merely return an error — the side effect must
//! be absent from the filesystem afterwards.

mod common;

use claw_tools::audit::{AuditOutcome, AuditPhase, AuditReason, InMemoryAuditSink};
use claw_tools::clock::FixedClock;
use claw_tools::error::ToolError;
use claw_tools::fs::{FsListTool, FsReadTool, FsWriteTool};
use claw_tools::permission::{
    Approval, Capability, DenialReason, DenyAllBroker, GrantLedger, GrantRequest, GrantScope,
    PermissionBroker, PermissionDecision, PermissionRequest, Resource,
};
use claw_tools::registry::ToolRegistry;
use claw_tools::sandbox::{Sandbox, SandboxLimits};
use claw_tools::tool::ToolContext;
use serde_json::json;

use common::TempTree;

const NOW: u64 = 1_700_000_000_000;

/// A secret with no punctuation, no digits-and-letters mix and no length that
/// any entropy heuristic would flag. It must still never be recorded.
const SHORT_SECRET: &str = "correcthorse";

fn registry() -> ToolRegistry {
    let mut registry = ToolRegistry::new();
    registry
        .register(Box::new(FsReadTool))
        .expect("fs_read registers");
    registry
        .register(Box::new(FsWriteTool))
        .expect("fs_write registers");
    registry
        .register(Box::new(FsListTool))
        .expect("fs_list registers");
    registry
}

fn workspace() -> (TempTree, Sandbox) {
    let tree = TempTree::new("permission");
    tree.dir("workspace/src");
    tree.write("workspace/src/lib.rs", "original content\n");
    let sandbox = Sandbox::new(&tree.join("workspace"), SandboxLimits::default())
        .expect("workspace root is adoptable");
    (tree, sandbox)
}

const fn read_grant() -> GrantRequest {
    GrantRequest {
        capability: Capability::FilesystemRead,
        scope: GrantScope::PathPrefix(String::new()),
        expires_unix_millis: None,
        max_uses: None,
        approval: Approval::Implicit,
    }
}

fn write_grant(prefix: &str) -> GrantRequest {
    GrantRequest {
        capability: Capability::FilesystemWrite,
        scope: GrantScope::PathPrefix(prefix.to_owned()),
        expires_unix_millis: None,
        max_uses: None,
        approval: Approval::Explicit,
    }
}

#[test]
fn an_empty_ledger_authorizes_nothing_and_leaves_no_trace() {
    let (tree, sandbox) = workspace();
    let registry = registry();
    let context = ToolContext {
        sandbox: &sandbox,
        clock: &FixedClock::new(NOW),
    };
    let mut ledger = GrantLedger::new();
    let mut audit = InMemoryAuditSink::new();

    let error = registry
        .invoke(
            "fs_write",
            &json!({ "path": "src/planted.rs", "content": "pwned" }),
            &context,
            &mut ledger,
            &mut audit,
        )
        .expect_err("an ungranted write must fail");
    let permission = error.permission().expect("a permission refusal");
    assert_eq!(permission.tool, "fs_write");
    assert_eq!(permission.capability, Capability::FilesystemWrite);
    assert_eq!(permission.reason, DenialReason::NoMatchingGrant);

    assert!(
        !tree.exists("workspace/src/planted.rs"),
        "a denied write must not create the file"
    );
    let records = audit.records();
    assert_eq!(records.len(), 1, "exactly one refusal record");
    assert_eq!(records[0].phase, AuditPhase::Completed);
    assert_eq!(records[0].outcome, AuditOutcome::Denied);
    assert_eq!(records[0].reason, AuditReason::PolicyRejected);
    assert_eq!(records[0].denial, Some(DenialReason::NoMatchingGrant));
    assert_eq!(records[0].grant, None);
    assert_eq!(
        records[0].resource,
        Some(Resource::Path("src/planted.rs".to_owned()))
    );
}

#[test]
fn a_deny_all_broker_refuses_even_a_read() {
    let (_tree, sandbox) = workspace();
    let registry = registry();
    let context = ToolContext {
        sandbox: &sandbox,
        clock: &FixedClock::new(NOW),
    };
    let mut audit = InMemoryAuditSink::new();
    let error = registry
        .invoke(
            "fs_read",
            &json!({ "path": "src/lib.rs" }),
            &context,
            &mut DenyAllBroker,
            &mut audit,
        )
        .expect_err("the deny-all broker refuses everything");
    assert_eq!(
        error.permission().expect("a permission refusal").reason,
        DenialReason::BrokerDeniesAll
    );
    assert_eq!(audit.records().len(), 1);
}

#[test]
fn a_read_grant_never_authorizes_a_write() {
    let (tree, sandbox) = workspace();
    let registry = registry();
    let context = ToolContext {
        sandbox: &sandbox,
        clock: &FixedClock::new(NOW),
    };
    let mut ledger = GrantLedger::new();
    ledger.grant(read_grant());
    let mut audit = InMemoryAuditSink::new();

    registry
        .invoke(
            "fs_read",
            &json!({ "path": "src/lib.rs" }),
            &context,
            &mut ledger,
            &mut audit,
        )
        .expect("the read is granted");

    let error = registry
        .invoke(
            "fs_write",
            &json!({ "path": "src/lib.rs", "content": "clobbered", "mode": "overwrite" }),
            &context,
            &mut ledger,
            &mut audit,
        )
        .expect_err("a read grant must not cover a write");
    assert_eq!(
        error.permission().expect("a permission refusal").reason,
        DenialReason::NoMatchingGrant
    );
    assert_eq!(
        tree.read("workspace/src/lib.rs"),
        "original content\n",
        "the file must be byte-for-byte unchanged"
    );
}

#[test]
fn a_path_scoped_grant_does_not_leak_to_a_sibling_prefix() {
    let tree = TempTree::new("scoped");
    tree.dir("workspace/src");
    tree.dir("workspace/srcs");
    let sandbox = Sandbox::new(&tree.join("workspace"), SandboxLimits::default())
        .expect("workspace root is adoptable");
    let registry = registry();
    let context = ToolContext {
        sandbox: &sandbox,
        clock: &FixedClock::new(NOW),
    };
    let mut ledger = GrantLedger::new();
    ledger.grant(write_grant("src"));
    let mut audit = InMemoryAuditSink::new();

    registry
        .invoke(
            "fs_write",
            &json!({ "path": "src/allowed.rs", "content": "ok" }),
            &context,
            &mut ledger,
            &mut audit,
        )
        .expect("a write inside the granted prefix succeeds");
    assert_eq!(tree.read("workspace/src/allowed.rs"), "ok");

    let error = registry
        .invoke(
            "fs_write",
            &json!({ "path": "srcs/denied.rs", "content": "pwned" }),
            &context,
            &mut ledger,
            &mut audit,
        )
        .expect_err("`src` must not match `srcs`");
    assert_eq!(
        error.permission().expect("a permission refusal").reason,
        DenialReason::NoMatchingGrant
    );
    assert!(!tree.exists("workspace/srcs/denied.rs"));
}

#[test]
fn revocation_takes_effect_on_the_very_next_invocation() {
    let (tree, sandbox) = workspace();
    let registry = registry();
    let context = ToolContext {
        sandbox: &sandbox,
        clock: &FixedClock::new(NOW),
    };
    let mut ledger = GrantLedger::new();
    let id = ledger.grant(write_grant(""));
    let mut audit = InMemoryAuditSink::new();

    registry
        .invoke(
            "fs_write",
            &json!({ "path": "first.txt", "content": "one" }),
            &context,
            &mut ledger,
            &mut audit,
        )
        .expect("the first write is granted");
    assert_eq!(tree.read("workspace/first.txt"), "one");

    assert!(ledger.revoke(id), "the grant existed");
    assert!(!ledger.revoke(id), "revocation is idempotent");

    let error = registry
        .invoke(
            "fs_write",
            &json!({ "path": "second.txt", "content": "two" }),
            &context,
            &mut ledger,
            &mut audit,
        )
        .expect_err("a revoked grant authorizes nothing");
    assert_eq!(
        error.permission().expect("a permission refusal").reason,
        DenialReason::NoMatchingGrant
    );
    assert!(!tree.exists("workspace/second.txt"));
}

#[test]
fn an_expired_grant_fails_closed_with_its_own_reason() {
    let (tree, sandbox) = workspace();
    let registry = registry();
    let mut ledger = GrantLedger::new();
    ledger.grant(GrantRequest {
        expires_unix_millis: Some(NOW),
        ..write_grant("")
    });
    let mut audit = InMemoryAuditSink::new();
    let context = ToolContext {
        sandbox: &sandbox,
        clock: &FixedClock::new(NOW),
    };
    let error = registry
        .invoke(
            "fs_write",
            &json!({ "path": "expired.txt", "content": "x" }),
            &context,
            &mut ledger,
            &mut audit,
        )
        .expect_err("expiry is inclusive of the expiry instant");
    assert_eq!(
        error.permission().expect("a permission refusal").reason,
        DenialReason::GrantExpired
    );
    assert!(!tree.exists("workspace/expired.txt"));
    assert_eq!(ledger.active(NOW).count(), 0);
    assert_eq!(ledger.active(NOW - 1).count(), 1);
}

#[test]
fn a_use_bounded_grant_is_exhausted_after_its_budget() {
    let (tree, sandbox) = workspace();
    let registry = registry();
    let mut ledger = GrantLedger::new();
    ledger.grant(GrantRequest {
        max_uses: Some(2),
        ..write_grant("")
    });
    let mut audit = InMemoryAuditSink::new();
    let context = ToolContext {
        sandbox: &sandbox,
        clock: &FixedClock::new(NOW),
    };
    for index in 0..2 {
        registry
            .invoke(
                "fs_write",
                &json!({ "path": format!("budget{index}.txt"), "content": "x" }),
                &context,
                &mut ledger,
                &mut audit,
            )
            .expect("the budgeted writes succeed");
    }
    let error = registry
        .invoke(
            "fs_write",
            &json!({ "path": "budget2.txt", "content": "x" }),
            &context,
            &mut ledger,
            &mut audit,
        )
        .expect_err("the budget is exhausted");
    assert_eq!(
        error.permission().expect("a permission refusal").reason,
        DenialReason::GrantExhausted
    );
    assert!(tree.exists("workspace/budget0.txt"));
    assert!(tree.exists("workspace/budget1.txt"));
    assert!(!tree.exists("workspace/budget2.txt"));
}

#[test]
fn an_implicit_grant_cannot_satisfy_a_tool_that_demands_approval() {
    let (tree, sandbox) = workspace();
    let registry = registry();
    let mut ledger = GrantLedger::new();
    ledger.grant(GrantRequest {
        approval: Approval::Implicit,
        ..write_grant("")
    });
    let mut audit = InMemoryAuditSink::new();
    let context = ToolContext {
        sandbox: &sandbox,
        clock: &FixedClock::new(NOW),
    };
    let error = registry
        .invoke(
            "fs_write",
            &json!({ "path": "unapproved.txt", "content": "x" }),
            &context,
            &mut ledger,
            &mut audit,
        )
        .expect_err("fs_write demands an approval-backed grant");
    assert_eq!(
        error.permission().expect("a permission refusal").reason,
        DenialReason::ApprovalRequired
    );
    assert!(!tree.exists("workspace/unapproved.txt"));
}

#[test]
fn the_broker_sees_the_exact_resource_the_tool_will_touch() {
    struct Recording {
        seen: Vec<PermissionRequest>,
    }

    impl PermissionBroker for Recording {
        fn evaluate(&mut self, request: &PermissionRequest) -> PermissionDecision {
            self.seen.push(request.clone());
            PermissionDecision::Denied(DenialReason::NoMatchingGrant)
        }
    }

    let (_tree, sandbox) = workspace();
    let registry = registry();
    let context = ToolContext {
        sandbox: &sandbox,
        clock: &FixedClock::new(NOW),
    };
    let mut broker = Recording { seen: Vec::new() };
    let mut audit = InMemoryAuditSink::new();
    // Backslashes and mixed separators must be normalized before the broker
    // decides, or a grant could be evaluated against a different string than
    // the one the tool later uses.
    let _ = registry.invoke(
        "fs_read",
        &json!({ "path": "src\\lib.rs" }),
        &context,
        &mut broker,
        &mut audit,
    );
    assert_eq!(broker.seen.len(), 1);
    assert_eq!(broker.seen[0].tool, "fs_read");
    assert_eq!(broker.seen[0].capability, Capability::FilesystemRead);
    assert_eq!(
        broker.seen[0].resource,
        Resource::Path("src/lib.rs".to_owned())
    );
    assert!(!broker.seen[0].requires_approval);
    assert_eq!(broker.seen[0].unix_millis, NOW);
}

#[test]
fn a_sandbox_refusal_is_reported_before_any_grant_is_consumed() {
    let (tree, sandbox) = workspace();
    let registry = registry();
    let mut ledger = GrantLedger::new();
    ledger.grant(GrantRequest {
        max_uses: Some(1),
        ..write_grant("")
    });
    let mut audit = InMemoryAuditSink::new();
    let context = ToolContext {
        sandbox: &sandbox,
        clock: &FixedClock::new(NOW),
    };
    let error = registry
        .invoke(
            "fs_write",
            &json!({ "path": "../escape.txt", "content": "x" }),
            &context,
            &mut ledger,
            &mut audit,
        )
        .expect_err("traversal is refused");
    assert_eq!(
        error.sandbox(),
        Some(claw_tools::sandbox::SandboxError::ParentTraversalForbidden)
    );
    assert!(!tree.exists("escape.txt"));
    assert_eq!(audit.records()[0].reason, AuditReason::SandboxRejected);

    // The grant budget was untouched, so a legitimate write still works.
    registry
        .invoke(
            "fs_write",
            &json!({ "path": "legit.txt", "content": "x" }),
            &context,
            &mut ledger,
            &mut audit,
        )
        .expect("the single remaining use is still available");
}

#[test]
fn an_unknown_tool_is_audited_with_a_sanitized_name() {
    let (_tree, sandbox) = workspace();
    let registry = registry();
    let mut audit = InMemoryAuditSink::new();
    let context = ToolContext {
        sandbox: &sandbox,
        clock: &FixedClock::new(NOW),
    };
    let error = registry
        .invoke(
            "../../bin/sh\n",
            &json!({}),
            &context,
            &mut DenyAllBroker,
            &mut audit,
        )
        .expect_err("an unregistered tool is refused");
    assert!(
        matches!(error, ToolError::UnknownTool),
        "unexpected error {error:?}"
    );
    assert_eq!(audit.records().len(), 1);
    assert_eq!(audit.records()[0].tool, "....binsh");
    assert_eq!(audit.records()[0].reason, AuditReason::UnknownTool);
    assert_eq!(audit.records()[0].capability, None);
}

#[test]
fn secrets_in_arguments_never_reach_the_audit_log() {
    let (_tree, sandbox) = workspace();
    let registry = registry();
    let mut ledger = GrantLedger::new();
    ledger.grant(write_grant(""));
    let mut audit = InMemoryAuditSink::new();
    let context = ToolContext {
        sandbox: &sandbox,
        clock: &FixedClock::new(NOW),
    };
    let _ = registry.invoke(
        "fs_write",
        &json!({
            "path": "creds.txt",
            "content": "ghp_0123456789abcdefghijklmnopqrstuvwxyz",
            "api_key": "super-secret-value",
        }),
        &context,
        &mut ledger,
        &mut audit,
    );
    let recorded = &audit.records()[0].arguments;
    assert_eq!(
        recorded["content"]["withheld"],
        serde_json::Value::Bool(true)
    );
    assert_eq!(recorded["[unknown]"], json!(["api_key"]));
    assert_eq!(recorded["path"], "creds.txt");
    let serialized = serde_json::to_string(recorded).expect("serializable");
    assert!(
        !serialized.contains("super-secret-value"),
        "the audit payload leaked a secret: {serialized}"
    );
    assert!(
        !serialized.contains("ghp_0123456789abcdefghijklmnopqrstuvwxyz"),
        "the audit payload leaked a token: {serialized}"
    );
}

#[test]
fn a_granted_invocation_writes_both_audit_phases() {
    let (_tree, sandbox) = workspace();
    let registry = registry();
    let mut ledger = GrantLedger::new();
    let id = ledger.grant(read_grant());
    let mut audit = InMemoryAuditSink::new();
    let context = ToolContext {
        sandbox: &sandbox,
        clock: &FixedClock::new(NOW),
    };
    registry
        .invoke(
            "fs_read",
            &json!({ "path": "src/lib.rs" }),
            &context,
            &mut ledger,
            &mut audit,
        )
        .expect("the read succeeds");
    let records = audit.records();
    assert_eq!(records.len(), 2);
    assert_eq!(records[0].phase, AuditPhase::Authorized);
    assert_eq!(records[0].outcome, AuditOutcome::Allowed);
    assert_eq!(records[0].grant, Some(id));
    assert_eq!(records[1].phase, AuditPhase::Completed);
    assert_eq!(records[1].outcome, AuditOutcome::Allowed);
    assert_eq!(records[1].reason, AuditReason::PolicySatisfied);
}

#[test]
fn schema_violations_are_refused_before_the_broker_is_consulted() {
    let (_tree, sandbox) = workspace();
    let registry = registry();
    let mut ledger = GrantLedger::new();
    ledger.grant(write_grant(""));
    let mut audit = InMemoryAuditSink::new();
    let context = ToolContext {
        sandbox: &sandbox,
        clock: &FixedClock::new(NOW),
    };
    let error = registry
        .invoke(
            "fs_write",
            &json!({ "path": "x.txt", "content": "y", "unexpected": true }),
            &context,
            &mut ledger,
            &mut audit,
        )
        .expect_err("the schema is closed");
    assert!(error.schema().is_some(), "expected a schema refusal");
    assert_eq!(audit.records()[0].reason, AuditReason::ValidationRejected);
    assert_eq!(audit.records()[0].grant, None);
}

#[test]
fn a_short_secret_without_a_recognizable_shape_is_still_withheld() {
    // The audited weakness was heuristic redaction: a short, single-class
    // token reads as ordinary prose. Allowlisting makes the shape irrelevant.
    let (_tree, sandbox) = workspace();
    let registry = registry();
    let mut ledger = GrantLedger::new();
    ledger.grant(write_grant(""));
    let mut audit = InMemoryAuditSink::new();
    let context = ToolContext {
        sandbox: &sandbox,
        clock: &FixedClock::new(NOW),
    };
    let _ = registry.invoke(
        "fs_write",
        &json!({ "path": "notes.txt", "content": SHORT_SECRET }),
        &context,
        &mut ledger,
        &mut audit,
    );
    assert!(!audit.records().is_empty(), "nothing was audited");
    for record in audit.records() {
        let serialized = serde_json::to_string(&record.arguments).expect("serializable");
        assert!(
            !serialized.contains(SHORT_SECRET),
            "phase {:?} leaked a short secret: {serialized}",
            record.phase
        );
    }
}

#[test]
fn a_denied_invocation_does_not_persist_the_payload_it_was_denied_for() {
    // Denial records were the other leak: the request was rejected and its
    // arguments were stored anyway.
    let (_tree, sandbox) = workspace();
    let registry = registry();
    let mut ledger = GrantLedger::new();
    let mut audit = InMemoryAuditSink::new();
    let context = ToolContext {
        sandbox: &sandbox,
        clock: &FixedClock::new(NOW),
    };
    let error = registry
        .invoke(
            "fs_write",
            &json!({ "path": "creds.txt", "content": SHORT_SECRET }),
            &context,
            &mut ledger,
            &mut audit,
        )
        .expect_err("an ungranted write must fail closed");
    assert!(error.permission().is_some(), "unexpected error {error:?}");
    assert_eq!(audit.records().len(), 1);
    let record = &audit.records()[0];
    assert_eq!(record.outcome, AuditOutcome::Denied);
    let serialized = serde_json::to_string(&record.arguments).expect("serializable");
    assert!(
        !serialized.contains(SHORT_SECRET),
        "a denial record kept the payload: {serialized}"
    );
    assert_eq!(record.arguments["path"], "creds.txt");
}

#[test]
fn an_unknown_tool_record_keeps_no_argument_values_at_all() {
    let (_tree, sandbox) = workspace();
    let registry = registry();
    let mut ledger = GrantLedger::new();
    let mut audit = InMemoryAuditSink::new();
    let context = ToolContext {
        sandbox: &sandbox,
        clock: &FixedClock::new(NOW),
    };
    let _ = registry.invoke(
        "not_a_tool",
        &json!({
            "args": ["--token", SHORT_SECRET],
            "url": "http://host.example/?key=leaked-query-value",
        }),
        &context,
        &mut ledger,
        &mut audit,
    );
    assert_eq!(audit.records().len(), 1);
    let serialized = serde_json::to_string(&audit.records()[0].arguments).expect("serializable");
    for leaked in [
        SHORT_SECRET,
        "--token",
        "leaked-query-value",
        "host.example",
    ] {
        assert!(
            !serialized.contains(leaked),
            "an unknown-tool record leaked {leaked}: {serialized}"
        );
    }
}

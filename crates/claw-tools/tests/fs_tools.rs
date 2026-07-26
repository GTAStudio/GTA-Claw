//! Filesystem tools exercised end to end through the registry choke point.
//!
//! Every case runs against a real temporary directory tree with real grants
//! and a real audit sink, so a refusal here means the shipped path refuses.

mod common;

use claw_tools::audit::{AuditOutcome, AuditPhase, AuditReason, InMemoryAuditSink};
use claw_tools::clock::FixedClock;
use claw_tools::fs::{FsGlobTool, FsListTool, FsPatchTool, FsReadTool, FsSearchTool, FsWriteTool};
use claw_tools::permission::{
    Approval, Capability, GrantLedger, GrantRequest, GrantScope, Resource,
};
use claw_tools::registry::ToolRegistry;
use claw_tools::sandbox::{Sandbox, SandboxError, SandboxLimits};
use claw_tools::tool::{ToolContext, ToolOutput};
use common::TempTree;
use serde_json::{Value, json};

const NOW: u64 = 1_700_000_000_000;

fn workspace() -> (TempTree, Sandbox) {
    let tree = TempTree::new("fs-tools");
    tree.dir("workspace/src/tools");
    tree.dir("workspace/docs");
    tree.write("workspace/README.md", "GTA Claw\nreadme body\n");
    tree.write(
        "workspace/src/main.rs",
        "fn main() {\n    println!(\"hello\");\n}\n",
    );
    tree.write(
        "workspace/src/tools/mod.rs",
        "pub mod alpha;\n// TODO: hostile input\npub mod bravo;\n",
    );
    tree.write(
        "workspace/docs/guide.md",
        "# Guide\nTODO: write the guide\n",
    );
    let sandbox = Sandbox::new(&tree.join("workspace"), SandboxLimits::default())
        .expect("the workspace is adoptable");
    (tree, sandbox)
}

fn registry() -> ToolRegistry {
    let mut registry = ToolRegistry::new();
    for tool in [
        Box::new(FsReadTool) as Box<dyn claw_tools::tool::Tool>,
        Box::new(FsWriteTool),
        Box::new(FsListTool),
        Box::new(FsGlobTool),
        Box::new(FsSearchTool),
        Box::new(FsPatchTool),
    ] {
        registry.register(tool).expect("each tool name is unique");
    }
    registry
}

/// Grants unrestricted read and write over the workspace.
fn ledger() -> GrantLedger {
    let mut ledger = GrantLedger::new();
    for capability in [Capability::FilesystemRead, Capability::FilesystemWrite] {
        ledger.grant(GrantRequest {
            capability,
            scope: GrantScope::PathPrefix(String::new()),
            expires_unix_millis: None,
            max_uses: None,
            approval: Approval::Explicit,
        });
    }
    ledger
}

fn call(
    registry: &ToolRegistry,
    sandbox: &Sandbox,
    ledger: &mut GrantLedger,
    audit: &mut InMemoryAuditSink,
    name: &str,
    arguments: Value,
) -> Result<ToolOutput, claw_tools::error::ToolError> {
    let context = ToolContext {
        sandbox,
        clock: &FixedClock::new(NOW),
    };
    registry.invoke(name, &arguments, &context, ledger, audit)
}

#[test]
fn read_returns_the_requested_line_window_and_reports_the_total() {
    let (_tree, sandbox) = workspace();
    let registry = registry();
    let mut ledger = ledger();
    let mut audit = InMemoryAuditSink::new();

    let whole = call(
        &registry,
        &sandbox,
        &mut ledger,
        &mut audit,
        "fs_read",
        json!({ "path": "src/main.rs" }),
    )
    .expect("the file is readable");
    assert_eq!(whole.content, "fn main() {\n    println!(\"hello\");\n}");
    assert_eq!(
        whole.structured,
        json!({
            "path": "src/main.rs",
            "total_lines": 3,
            "start_line": 1,
            "returned_lines": 3,
        })
    );
    assert!(!whole.truncated);

    let window = call(
        &registry,
        &sandbox,
        &mut ledger,
        &mut audit,
        "fs_read",
        json!({ "path": "src/main.rs", "start_line": 2, "line_count": 1 }),
    )
    .expect("the window is readable");
    assert_eq!(window.content, "    println!(\"hello\");");
    assert_eq!(window.structured["start_line"], 2);
    assert_eq!(window.structured["returned_lines"], 1);
    assert!(window.truncated);
}

#[test]
fn write_creates_then_refuses_to_clobber_without_an_explicit_overwrite() {
    let (tree, sandbox) = workspace();
    let registry = registry();
    let mut ledger = ledger();
    let mut audit = InMemoryAuditSink::new();

    let created = call(
        &registry,
        &sandbox,
        &mut ledger,
        &mut audit,
        "fs_write",
        json!({ "path": "docs/notes.md", "content": "first" }),
    )
    .expect("a new file is writable");
    assert_eq!(
        created.structured,
        json!({
            "path": "docs/notes.md",
            "bytes_written": 5,
            "mode": "create",
        })
    );
    assert_eq!(tree.read("workspace/docs/notes.md"), "first");

    let clobbered = call(
        &registry,
        &sandbox,
        &mut ledger,
        &mut audit,
        "fs_write",
        json!({ "path": "docs/notes.md", "content": "second" }),
    )
    .expect_err("an implicit clobber must be refused");
    assert_eq!(clobbered.sandbox(), Some(SandboxError::AlreadyExists));
    assert_eq!(tree.read("workspace/docs/notes.md"), "first");

    call(
        &registry,
        &sandbox,
        &mut ledger,
        &mut audit,
        "fs_write",
        json!({ "path": "docs/notes.md", "content": "second", "mode": "overwrite" }),
    )
    .expect("an explicit overwrite is allowed");
    assert_eq!(tree.read("workspace/docs/notes.md"), "second");
}

#[test]
fn write_cannot_create_a_missing_parent_directory() {
    let (tree, sandbox) = workspace();
    let registry = registry();
    let mut ledger = ledger();
    let mut audit = InMemoryAuditSink::new();

    let error = call(
        &registry,
        &sandbox,
        &mut ledger,
        &mut audit,
        "fs_write",
        json!({ "path": "brand/new/tree.md", "content": "x" }),
    )
    .expect_err("the parent does not exist");
    assert_eq!(error.sandbox(), Some(SandboxError::NotFound));
    assert!(!tree.exists("workspace/brand"));
}

#[test]
fn list_reports_entries_without_following_anything() {
    let (_tree, sandbox) = workspace();
    let registry = registry();
    let mut ledger = ledger();
    let mut audit = InMemoryAuditSink::new();

    let root = call(
        &registry,
        &sandbox,
        &mut ledger,
        &mut audit,
        "fs_list",
        json!({}),
    )
    .expect("the root is listable");
    let entries: Vec<(&str, &str)> = root.structured["entries"]
        .as_array()
        .expect("an array of entries")
        .iter()
        .map(|entry| {
            (
                entry["path"].as_str().expect("a path"),
                entry["kind"].as_str().expect("a kind"),
            )
        })
        .collect();
    assert_eq!(
        entries,
        vec![
            ("README.md", "file"),
            ("docs", "directory"),
            ("src", "directory"),
        ]
    );
    assert_eq!(root.structured["total_entries"], 3);
    assert_eq!(root.structured["entries"][0]["size_bytes"], 21);

    let limited = call(
        &registry,
        &sandbox,
        &mut ledger,
        &mut audit,
        "fs_list",
        json!({ "max_entries": 1 }),
    )
    .expect("the root is listable");
    assert_eq!(
        limited.structured["entries"]
            .as_array()
            .expect("an array")
            .len(),
        1
    );
    assert!(limited.truncated);
}

#[test]
fn glob_walks_the_workspace_and_never_leaves_it() {
    let (_tree, sandbox) = workspace();
    let registry = registry();
    let mut ledger = ledger();
    let mut audit = InMemoryAuditSink::new();

    let rust = call(
        &registry,
        &sandbox,
        &mut ledger,
        &mut audit,
        "fs_glob",
        json!({ "pattern": "**/*.rs" }),
    )
    .expect("the glob runs");
    assert_eq!(
        rust.structured["matches"],
        json!(["src/main.rs", "src/tools/mod.rs"])
    );
    assert_eq!(rust.structured["total_matches"], 2);
    assert_eq!(rust.structured["root"], "");

    let scoped = call(
        &registry,
        &sandbox,
        &mut ledger,
        &mut audit,
        "fs_glob",
        json!({ "pattern": "*.md", "path": "docs" }),
    )
    .expect("the scoped glob runs");
    assert_eq!(scoped.structured["matches"], json!(["docs/guide.md"]));
    assert_eq!(scoped.structured["root"], "docs");

    // A pattern is not a path: it can never be used to walk out of the root.
    let escape = call(
        &registry,
        &sandbox,
        &mut ledger,
        &mut audit,
        "fs_glob",
        json!({ "pattern": "../**/*" }),
    )
    .expect_err("a traversal pattern must be refused");
    assert_eq!(escape.sandbox(), Some(SandboxError::AbsolutePathForbidden));
}

#[test]
fn search_finds_matches_with_line_numbers_and_honours_case_sensitivity() {
    let (_tree, sandbox) = workspace();
    let registry = registry();
    let mut ledger = ledger();
    let mut audit = InMemoryAuditSink::new();

    let sensitive = call(
        &registry,
        &sandbox,
        &mut ledger,
        &mut audit,
        "fs_search",
        json!({ "query": "TODO" }),
    )
    .expect("the search runs");
    assert_eq!(
        sensitive.structured["matches"],
        json!([
            {
                "path": "docs/guide.md",
                "line": 2,
                "text": "TODO: write the guide",
            },
            {
                "path": "src/tools/mod.rs",
                "line": 2,
                "text": "// TODO: hostile input",
            },
        ])
    );
    assert_eq!(sensitive.structured["total_matches"], 2);
    assert_eq!(sensitive.structured["skipped_files"], 0);

    let lowercase = call(
        &registry,
        &sandbox,
        &mut ledger,
        &mut audit,
        "fs_search",
        json!({ "query": "todo" }),
    )
    .expect("the search runs");
    assert_eq!(lowercase.structured["total_matches"], 0);

    let insensitive = call(
        &registry,
        &sandbox,
        &mut ledger,
        &mut audit,
        "fs_search",
        json!({ "query": "todo", "case_sensitive": false }),
    )
    .expect("the search runs");
    assert_eq!(insensitive.structured["total_matches"], 2);

    let capped = call(
        &registry,
        &sandbox,
        &mut ledger,
        &mut audit,
        "fs_search",
        json!({ "query": "TODO", "max_results": 1 }),
    )
    .expect("the search runs");
    assert_eq!(capped.structured["total_matches"], 2);
    assert_eq!(
        capped.structured["matches"]
            .as_array()
            .expect("an array")
            .len(),
        1
    );
    assert!(capped.truncated);
}

#[test]
fn patch_applies_a_unified_diff_and_leaves_the_file_untouched_on_failure() {
    let (tree, sandbox) = workspace();
    let registry = registry();
    let mut ledger = ledger();
    let mut audit = InMemoryAuditSink::new();

    let applied = call(
        &registry,
        &sandbox,
        &mut ledger,
        &mut audit,
        "fs_patch",
        json!({
            "path": "README.md",
            "patch": "--- a/README.md\n+++ b/README.md\n@@ -1,2 +1,3 @@\n GTA Claw\n-readme body\n+rewritten body\n+new line\n",
        }),
    )
    .expect("a clean patch applies");
    assert_eq!(
        applied.structured,
        json!({
            "path": "README.md",
            "hunks": 1,
            "bytes_written": 33,
        })
    );
    assert_eq!(
        tree.read("workspace/README.md"),
        "GTA Claw\nrewritten body\nnew line\n"
    );

    let rejected = call(
        &registry,
        &sandbox,
        &mut ledger,
        &mut audit,
        "fs_patch",
        json!({
            "path": "README.md",
            "patch": "--- a/README.md\n+++ b/README.md\n@@ -1,2 +1,2 @@\n GTA Claw\n-content that is not there\n+anything\n",
        }),
    )
    .expect_err("mismatched context must be refused");
    assert!(rejected.patch().is_some(), "unexpected error {rejected:?}");
    assert_eq!(
        tree.read("workspace/README.md"),
        "GTA Claw\nrewritten body\nnew line\n",
        "a rejected patch must not modify the file"
    );

    // A patch header naming a different file is refused before any write.
    let foreign = call(
        &registry,
        &sandbox,
        &mut ledger,
        &mut audit,
        "fs_patch",
        json!({
            "path": "README.md",
            "patch": "--- a/other.md\n+++ b/other.md\n@@ -1,1 +1,1 @@\n-GTA Claw\n+owned\n",
        }),
    )
    .expect_err("a foreign patch header must be refused");
    assert!(foreign.patch().is_some(), "unexpected error {foreign:?}");
}

#[test]
fn the_size_limit_stops_a_large_write_before_it_touches_the_disk() {
    let tree = TempTree::new("fs-limit");
    tree.dir("workspace");
    let limits = SandboxLimits {
        max_file_bytes: 64,
        ..SandboxLimits::default()
    };
    let sandbox = Sandbox::new(&tree.join("workspace"), limits).expect("adoptable");
    let registry = registry();
    let mut ledger = ledger();
    let mut audit = InMemoryAuditSink::new();

    let error = call(
        &registry,
        &sandbox,
        &mut ledger,
        &mut audit,
        "fs_write",
        json!({ "path": "big.txt", "content": "x".repeat(65) }),
    )
    .expect_err("an oversized write must be refused");
    assert_eq!(error.sandbox(), Some(SandboxError::FileTooLarge));
    assert!(!tree.exists("workspace/big.txt"));

    call(
        &registry,
        &sandbox,
        &mut ledger,
        &mut audit,
        "fs_write",
        json!({ "path": "small.txt", "content": "x".repeat(64) }),
    )
    .expect("a write at the limit is allowed");
    assert_eq!(tree.read("workspace/small.txt").len(), 64);
}

#[test]
fn every_filesystem_invocation_is_audited_with_its_exact_resource() {
    let (_tree, sandbox) = workspace();
    let registry = registry();
    let mut ledger = ledger();
    let mut audit = InMemoryAuditSink::new();

    call(
        &registry,
        &sandbox,
        &mut ledger,
        &mut audit,
        "fs_read",
        json!({ "path": "src/main.rs" }),
    )
    .expect("the read succeeds");

    let records = audit.records();
    assert_eq!(records.len(), 2);
    assert_eq!(records[0].phase, AuditPhase::Authorized);
    assert_eq!(records[0].tool, "fs_read");
    assert_eq!(records[0].capability, Some(Capability::FilesystemRead));
    assert_eq!(
        records[0].resource,
        Some(Resource::Path("src/main.rs".to_owned()))
    );
    assert!(records[0].grant.is_some());
    assert_eq!(records[0].denial, None);
    assert_eq!(records[0].unix_millis, NOW);

    assert_eq!(records[1].phase, AuditPhase::Completed);
    assert_eq!(records[1].outcome, AuditOutcome::Allowed);
    assert_eq!(records[1].reason, AuditReason::PolicySatisfied);
    assert_eq!(records[1].grant, records[0].grant);
    assert_eq!(records[1].arguments, json!({ "path": "src/main.rs" }));
}

#[test]
fn a_backslash_path_is_normalized_before_the_broker_sees_it() {
    let (_tree, sandbox) = workspace();
    let registry = registry();
    let mut ledger = GrantLedger::new();
    // The grant covers only `src`, expressed with forward slashes.
    ledger.grant(GrantRequest {
        capability: Capability::FilesystemRead,
        scope: GrantScope::PathPrefix("src/tools".to_owned()),
        expires_unix_millis: None,
        max_uses: None,
        approval: Approval::Explicit,
    });
    let mut audit = InMemoryAuditSink::new();

    // A Windows-style separator must resolve to the same normalized resource,
    // so the grant applies and no second identity exists for the same file.
    call(
        &registry,
        &sandbox,
        &mut ledger,
        &mut audit,
        "fs_read",
        json!({ "path": "src\\tools\\mod.rs" }),
    )
    .expect("the grant covers the normalized path");
    assert_eq!(
        audit.records()[0].resource,
        Some(Resource::Path("src/tools/mod.rs".to_owned()))
    );

    // A sibling outside the granted prefix is still refused.
    let refused = call(
        &registry,
        &sandbox,
        &mut ledger,
        &mut audit,
        "fs_read",
        json!({ "path": "src\\main.rs" }),
    )
    .expect_err("the grant does not reach outside its prefix");
    assert!(
        refused.permission().is_some(),
        "unexpected refusal {refused:?}"
    );
}

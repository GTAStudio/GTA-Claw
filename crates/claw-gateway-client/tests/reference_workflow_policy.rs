//! Static policy checks for the frozen, Rust-only upstream reference workflow.

use std::fs;
use std::path::PathBuf;

#[test]
fn reference_workflow_is_rust_only_and_uses_frozen_contracts() {
    let workspace = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(std::path::Path::parent)
        .expect("crate is under workspace/crates")
        .to_path_buf();
    let workflow_path = workspace.join(".github/workflows/upstream-gateway-reference.yml");
    let workflow = fs::read_to_string(&workflow_path)
        .expect("read pinned reference workflow")
        .replace("\r\n", "\n");

    assert_eq!(
        workflow.matches("persist-credentials: false").count(),
        1,
        "the repository checkout must reject persisted GitHub credentials"
    );
    for required in [
        "on:\n  pull_request:\n  workflow_dispatch:",
        "permissions:\n  contents: read",
        "Verify frozen compatibility snapshot",
        "./compat/upstream/validate.ps1",
        "Reject JavaScript toolchain artifacts",
        "--package claw-repo-policy",
        "--test repository_policy",
        "Test protocol and Gateway client against frozen contracts",
        "--package claw-protocol",
        "--package claw-gateway-client",
    ] {
        assert!(
            workflow.contains(required),
            "missing reference policy: {required}"
        );
    }
    for forbidden in [
        "actions/setup-node",
        "corepack",
        "node_modules",
        "openclaw.mjs",
        "persist-credentials: true",
    ] {
        assert!(
            !workflow.contains(forbidden),
            "forbidden JavaScript toolchain/credential pattern: {forbidden}"
        );
    }
    let lower = workflow.to_ascii_lowercase();
    for command in ["node", "npm", "npx", "pnpm", "yarn", "bun", "deno"] {
        assert!(
            !contains_word(&lower, command),
            "forbidden JavaScript runtime/package command token: {command}"
        );
    }
}

fn contains_word(text: &str, word: &str) -> bool {
    text.split(|character: char| !(character.is_ascii_alphanumeric() || character == '_'))
        .any(|token| token == word)
}

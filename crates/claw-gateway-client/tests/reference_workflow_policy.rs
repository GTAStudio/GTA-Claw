//! Static policy checks for the protected upstream parity workflow.

use std::fs;
use std::path::PathBuf;

#[test]
fn reference_workflow_uses_protected_validator_and_candidate_data() {
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
        2,
        "both repository checkouts must reject persisted GitHub credentials"
    );
    for required in [
        "on:\n  pull_request_target:",
        "permissions:\n  contents: read",
        "Checkout exact protected base",
        "ref: ${{ github.event.pull_request.base.sha }}",
        "path: parity-checkouts/trusted",
        "Checkout exact immutable candidate",
        "repository: ${{ github.event.pull_request.head.repo.full_name }}",
        "ref: ${{ github.event.pull_request.head.sha }}",
        "path: parity-checkouts/candidate",
        "Validate candidate parity as bounded data",
        "compat/upstream/validate.ps1",
        "-ContractRoot",
        "-RepositoryRoot",
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
        "cancel-in-progress:",
        "cargo test",
        "& (Join-Path $candidate",
        "./compat/upstream/validate.ps1",
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

//! Static policy checks for the isolated pinned-upstream workflow.

use std::fs;
use std::path::PathBuf;

#[test]
fn reference_workflow_disables_credentials_and_network_lifecycle_downloads() {
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
        "both checkouts must reject persisted GitHub credentials"
    );
    for required in [
        "permissions:\n  contents: read",
        "Verify checkout credential isolation",
        "NPM_CONFIG_IGNORE_SCRIPTS: \"true\"",
        "pnpm install --frozen-lockfile --ignore-scripts",
        "pnpm config get ignore-scripts",
        "matrix-sdk-crypto-nodejs",
        "unverified Matrix native lifecycle artifact was downloaded",
    ] {
        assert!(
            workflow.contains(required),
            "missing reference policy: {required}"
        );
    }
    for forbidden in [
        "curl ",
        "curl|",
        "wget ",
        "wget|",
        "persist-credentials: true",
    ] {
        assert!(
            !workflow.contains(forbidden),
            "forbidden mutable download/credential pattern: {forbidden}"
        );
    }
}

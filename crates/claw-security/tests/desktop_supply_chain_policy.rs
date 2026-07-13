//! Static policy checks for the isolated desktop dependency graph.

use std::collections::BTreeSet;
use std::fs;
use std::path::{Path, PathBuf};

fn workspace_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(Path::parent)
        .expect("crate is under workspace/crates")
        .to_path_buf()
}

fn read(path: &Path) -> String {
    fs::read_to_string(path).unwrap_or_else(|error| panic!("read {}: {error}", path.display()))
}

fn package_names(lockfile: &str) -> BTreeSet<&str> {
    lockfile
        .split("[[package]]")
        .filter_map(|package| {
            package
                .lines()
                .find_map(|line| line.trim().strip_prefix("name = \""))
                .and_then(|name| name.strip_suffix('"'))
        })
        .collect()
}

fn slint_features(manifest: &str) -> BTreeSet<&str> {
    let (_, dependency) = manifest
        .split_once("slint = {")
        .expect("desktop manifest has a Slint dependency");
    let (_, features) = dependency
        .split_once("features = [")
        .expect("Slint dependency has explicit features");
    let (features, _) = features
        .split_once(']')
        .expect("Slint feature list is closed");

    features
        .lines()
        .filter_map(|line| {
            line.trim()
                .trim_end_matches(',')
                .strip_prefix('"')
                .and_then(|feature| feature.strip_suffix('"'))
        })
        .collect()
}

#[test]
fn hosted_supply_chain_policy_audits_both_lockfiles_fail_closed() {
    let root = workspace_root();
    let workflow = read(&root.join(".github/workflows/rust.yml")).replace("\r\n", "\n");

    assert_eq!(
        workflow
            .matches("uses: rustsec/audit-check@69366f33c96575abad1ee0dba8212993eecbe998")
            .count(),
        2,
        "raw RustSec action must audit root and desktop lockfiles"
    );
    assert_eq!(
        workflow.matches("working-directory: desktop").count(),
        1,
        "exactly one raw audit must target the desktop workspace"
    );
    assert!(
        workflow.contains("- name: Audit root lockfile")
            && workflow.contains("- name: Audit desktop lockfile"),
        "both raw audits must remain explicit"
    );
    assert!(
        !workflow.contains("\n          ignore:"),
        "hosted audits must not ignore advisories"
    );

    let checkout_count = workflow.matches("uses: actions/checkout@").count();
    assert_eq!(
        checkout_count,
        workflow.matches("persist-credentials: false").count(),
        "every Rust workflow checkout must disable persisted credentials"
    );
    for line in workflow.lines().map(str::trim) {
        if let Some(action) = line.strip_prefix("uses: ") {
            let (_, revision) = action
                .rsplit_once('@')
                .unwrap_or_else(|| panic!("action is not revision pinned: {action}"));
            assert!(
                revision.len() == 40 && revision.bytes().all(|byte| byte.is_ascii_hexdigit()),
                "action is not pinned to an immutable commit: {action}"
            );
        }
        assert!(
            !line.starts_with("arguments:") || !line.contains("--config"),
            "cargo-deny 0.19.8 rejects top-level --config: {line}"
        );
    }

    assert_eq!(
        workflow
            .matches(
                "command-arguments: --config desktop/deny.toml --warn unmaintained advisories licenses sources",
            )
            .count(),
        2,
        "both target policies must load the desktop config after the check subcommand"
    );
    for arguments in [
        "arguments: --target x86_64-pc-windows-msvc",
        "arguments: --target aarch64-apple-darwin",
    ] {
        assert_eq!(
            workflow.matches(arguments).count(),
            1,
            "missing exact desktop policy target: {arguments}"
        );
    }
    for required in [
        "Desktop rejects Linux",
        "gta-claw-desktop supports only Windows and macOS",
    ] {
        assert!(
            workflow.contains(required),
            "missing desktop source policy: {required}"
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
            "forbidden mutable download or credential pattern: {forbidden}"
        );
    }
}

#[test]
fn desktop_uses_real_winit_without_wayland_or_root_leakage() {
    let root = workspace_root();
    let desktop = root.join("desktop");
    let desktop_manifest = read(&desktop.join("Cargo.toml"));
    let app_manifest = read(&desktop.join("apps/gta-claw-desktop/Cargo.toml"));
    let features = slint_features(&app_manifest);

    assert!(features.contains("backend-winit-x11"));
    assert!(!features.contains("backend-winit"));
    assert!(!features.contains("backend-winit-wayland"));
    assert!(
        !desktop_manifest.contains("[patch.crates-io]") && !desktop_manifest.contains("vendor/"),
        "desktop must use only released registry dependencies"
    );

    let desktop_lock = read(&desktop.join("Cargo.lock"));
    let desktop_packages = package_names(&desktop_lock);
    for required in ["slint", "i-slint-backend-winit", "winit"] {
        assert!(
            desktop_packages.contains(required),
            "desktop lost real GUI backend package: {required}"
        );
    }
    let forbidden = desktop_packages
        .iter()
        .filter(|name| {
            **name == "quick-xml"
                || name.contains("wayland")
                || name.starts_with("smithay")
                || matches!(
                    **name,
                    "calloop-wayland-source" | "sctk-adwaita" | "smithay-clipboard"
                )
        })
        .copied()
        .collect::<Vec<_>>();
    assert!(
        forbidden.is_empty(),
        "desktop lock contains unused Wayland dependency chain: {forbidden:?}"
    );

    let root_lock = read(&root.join("Cargo.lock"));
    let root_packages = package_names(&root_lock);
    let root_slint = root_packages
        .iter()
        .filter(|name| **name == "slint" || **name == "slint-build" || name.starts_with("i-slint"))
        .copied()
        .collect::<Vec<_>>();
    assert!(
        root_slint.is_empty(),
        "root runtime lock contains Slint packages: {root_slint:?}"
    );
}

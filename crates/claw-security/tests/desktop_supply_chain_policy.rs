//! Static policy checks for the desktop dependency security backport.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt::Write as _;
use std::fs;
use std::path::{Path, PathBuf};

use serde_json::Value;
use sha2::{Digest, Sha256};

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

fn sha256(path: &Path) -> String {
    let bytes = fs::read(path).unwrap_or_else(|error| panic!("read {}: {error}", path.display()));
    let digest = Sha256::digest(bytes);
    let mut encoded = String::with_capacity(digest.len() * 2);
    for byte in digest {
        write!(encoded, "{byte:02x}").expect("writing to a string cannot fail");
    }
    encoded
}

fn json_string<'a>(value: &'a Value, pointer: &str) -> &'a str {
    value
        .pointer(pointer)
        .and_then(Value::as_str)
        .unwrap_or_else(|| panic!("missing JSON string at {pointer}"))
}

fn collect_files(directory: &Path, root: &Path, files: &mut BTreeSet<String>) {
    for entry in fs::read_dir(directory)
        .unwrap_or_else(|error| panic!("read directory {}: {error}", directory.display()))
    {
        let path = entry.expect("read directory entry").path();
        if path.is_dir() {
            if path.file_name().is_some_and(|name| name == "target") {
                continue;
            }
            collect_files(&path, root, files);
        } else {
            let relative = path
                .strip_prefix(root)
                .expect("file is below vendor root")
                .to_string_lossy()
                .replace('\\', "/");
            files.insert(relative);
        }
    }
}

fn package_block<'a>(lockfile: &'a str, package: &str) -> &'a str {
    lockfile
        .split("[[package]]")
        .find(|block| {
            block
                .lines()
                .any(|line| line.trim() == format!("name = \"{package}\""))
        })
        .unwrap_or_else(|| panic!("missing {package} package"))
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
        workflow.contains("CARGO_TARGET_DIR: ${{ runner.temp }}/wayland-scanner-target"),
        "focused vendor tests must not write build outputs into the verified source tree"
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
        let Some(action) = line.strip_prefix("uses: ") else {
            continue;
        };
        let Some((_, revision)) = action.rsplit_once('@') else {
            panic!("action is not revision pinned: {action}");
        };
        assert!(
            revision.len() == 40 && revision.bytes().all(|byte| byte.is_ascii_hexdigit()),
            "action is not pinned to an immutable commit: {action}"
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
fn desktop_patch_matches_registry_provenance_and_security_floor() {
    let root = workspace_root();
    let desktop = root.join("desktop");
    let vendor = desktop.join("vendor/wayland-scanner-0.31.10");
    let provenance: Value = serde_json::from_str(&read(
        &desktop.join("vendor/wayland-scanner-0.31.10.provenance.json"),
    ))
    .expect("parse vendor provenance");
    let checksums: Value = serde_json::from_str(&read(&vendor.join(".cargo-checksum.json")))
        .expect("parse Cargo checksum manifest");
    let attributes = read(&root.join(".gitattributes"));
    assert!(
        attributes.contains("desktop/vendor/wayland-scanner-0.31.10/** text eol=lf"),
        "vendor bytes must remain stable on Windows and Unix checkouts"
    );

    assert_eq!(provenance["schema"], 1);
    assert_eq!(
        json_string(&provenance, "/upstream/repository"),
        "https://github.com/Smithay/wayland-rs"
    );
    assert_eq!(
        json_string(&provenance, "/upstream/base_package/crates_io_sha256"),
        json_string(&checksums, "/package")
    );
    assert_eq!(
        json_string(&provenance, "/upstream/base_package/vcs_commit"),
        "a3d7927d87799b2955bf491b51c7c2a3a82da661"
    );
    assert_eq!(
        json_string(&provenance, "/upstream/security_commit/sha"),
        "d07c4f91f28b42e5a485823ffd9d8d5a210b1053"
    );
    assert_eq!(
        json_string(&provenance, "/upstream/security_commit/parent"),
        "41d6f7ffb0b39f2479eaa3f8c2826371e951f3d2"
    );
    assert_eq!(
        json_string(&provenance, "/upstream/security_commit/tree"),
        "802cdc245c2e82e2234436198fb7485d7dc0aa03"
    );
    assert_eq!(
        json_string(&provenance, "/upstream/compatibility_commit/sha"),
        "ec2d932855593d48aa83c76820f3efbcfea86d39"
    );
    assert_eq!(
        json_string(&provenance, "/upstream/compatibility_commit/parent"),
        "429a1bc200a0a2d73d89902a6f3499dcb19e5490"
    );
    assert_eq!(
        json_string(&provenance, "/upstream/compatibility_commit/tree"),
        "3fdac40d2cc1632641cbbb3bc63cf43f19cc1ae5"
    );
    assert_eq!(
        sha256(&vendor.join(".cargo-checksum.json")),
        json_string(&provenance, "/vendored/cargo_checksum_manifest_sha256")
    );

    let deltas = provenance["allowed_delta"]
        .as_array()
        .expect("allowed_delta is an array");
    let mut allowed = BTreeMap::new();
    for delta in deltas {
        let path = json_string(delta, "/path").to_owned();
        let previous = allowed.insert(
            path,
            (
                json_string(delta, "/original_sha256").to_owned(),
                json_string(delta, "/patched_sha256").to_owned(),
            ),
        );
        assert!(previous.is_none(), "duplicate allowed delta");
    }
    assert_eq!(
        allowed.keys().map(String::as_str).collect::<Vec<_>>(),
        [
            "Cargo.lock",
            "Cargo.toml",
            "Cargo.toml.orig",
            "src/parse.rs"
        ]
    );

    let expected = checksums["files"]
        .as_object()
        .expect("Cargo checksum files is an object");
    let mut actual_files = BTreeSet::new();
    collect_files(&vendor, &vendor, &mut actual_files);
    actual_files.remove(".cargo-checksum.json");
    assert_eq!(
        actual_files,
        expected.keys().cloned().collect(),
        "vendored files must exactly match the registry artifact"
    );

    for (relative, expected_hash) in expected {
        let registry_hash = expected_hash.as_str().expect("checksum is a string");
        let actual_hash = sha256(&vendor.join(relative));
        if let Some((original_hash, patched_hash)) = allowed.get(relative) {
            assert_eq!(registry_hash, original_hash);
            assert_eq!(&actual_hash, patched_hash);
        } else {
            assert_eq!(actual_hash, registry_hash, "unexpected delta in {relative}");
        }
    }
    assert_eq!(
        sha256(&vendor.join("LICENSE.txt")),
        json_string(&provenance, "/vendored/license/sha256")
    );

    let desktop_manifest = read(&desktop.join("Cargo.toml"));
    assert!(
        desktop_manifest
            .contains("wayland-scanner = { path = \"vendor/wayland-scanner-0.31.10\" }")
    );
    let app_manifest = read(&desktop.join("apps/gta-claw-desktop/Cargo.toml"));
    assert!(
        app_manifest.contains("\"backend-winit\""),
        "Windows and macOS must retain the real Slint window backend"
    );

    let desktop_lock = read(&desktop.join("Cargo.lock"));
    let quick_xml = package_block(&desktop_lock, "quick-xml");
    let versions = desktop_lock
        .split("[[package]]")
        .filter(|block| {
            block
                .lines()
                .any(|line| line.trim() == "name = \"quick-xml\"")
        })
        .filter_map(|block| {
            block
                .lines()
                .find_map(|line| line.trim().strip_prefix("version = \""))
                .and_then(|version| version.strip_suffix('"'))
        })
        .collect::<Vec<_>>();
    assert!(!versions.is_empty(), "desktop lock must contain quick-xml");
    for version in versions {
        let mut parts = version.split('.');
        let major: u64 = parts.next().expect("major").parse().expect("numeric major");
        let minor: u64 = parts.next().expect("minor").parse().expect("numeric minor");
        assert!(
            major > 0 || minor >= 41,
            "desktop lock contains vulnerable quick-xml {version}"
        );
    }
    assert!(quick_xml.contains("version = \"0.41.0\""));
    assert!(quick_xml.contains(
        "checksum = \"e660451e55124f798a69a5af3f49ccfbefbd41910eefd25caf2393e1f3473ec1\""
    ));
    let scanner = package_block(&desktop_lock, "wayland-scanner");
    assert!(scanner.contains("version = \"0.31.10\""));
    assert!(
        !scanner.contains("source = "),
        "wayland-scanner must resolve to the bounded local patch"
    );

    let root_lock = read(&root.join("Cargo.lock"));
    for forbidden in [
        "name = \"slint\"",
        "name = \"slint-build\"",
        "name = \"wayland-scanner\"",
        "name = \"quick-xml\"",
        "name = \"i-slint",
    ] {
        assert!(
            !root_lock.contains(forbidden),
            "root runtime lock gained desktop dependency: {forbidden}"
        );
    }
}

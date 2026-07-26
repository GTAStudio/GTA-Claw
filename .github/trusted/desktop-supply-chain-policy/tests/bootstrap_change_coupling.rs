//! Integration tests for the per-path Bootstrap change-coupling invariant.
//!
//! These tests call [`validate_bootstrap_change_coupling`] directly against hand-built trusted
//! and candidate fixtures so that Synchronize/Preserve mechanics can be exercised without also
//! satisfying the unrelated `validate_protected_files` freeze on the whole trusted directory
//! (a real trust-root-update pull request is the only place these two states legitimately
//! diverge; see the trusted README's "Trust-root updates" section). One full
//! [`validate_request`] test at the bottom proves residual placement: a pre-existing failure
//! still returns its own exact diagnostic even when an unresolved Bootstrap-managed path
//! change is also present.

use std::env;
use std::fs;
use std::io;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

use desktop_supply_chain_policy::bootstrap_coupling::{
    BOOTSTRAP_SNAPSHOT_PATH, LEDGER_PATH, POLICY_SOURCE_PATH, parse_ledger,
    validate_bootstrap_change_coupling,
};
use desktop_supply_chain_policy::changes::{ChangeManifest, ChangedPath};
use desktop_supply_chain_policy::input::{SafeRoot, sha256};
use desktop_supply_chain_policy::metadata::MetadataTools;
use desktop_supply_chain_policy::policy::{
    BootstrapSnapshotArchive, archive_semantic_fingerprint, expected_bootstrap_fingerprint,
};
use desktop_supply_chain_policy::validation::{ValidationRequest, validate_request};
use desktop_supply_chain_policy::workflows::ActionlintTool;

static NEXT_TEMP: AtomicU64 = AtomicU64::new(0);

fn repo_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(Path::parent)
        .and_then(Path::parent)
        .expect("trusted crate is under repository/.github/trusted")
        .to_path_buf()
}

struct TempTree {
    path: PathBuf,
}

impl TempTree {
    fn new(label: &str) -> Self {
        let unique = NEXT_TEMP.fetch_add(1, Ordering::Relaxed);
        let path = env::temp_dir().join(format!(
            "gta-claw-coupling-{label}-{}-{unique}",
            std::process::id()
        ));
        if path.exists() {
            fs::remove_dir_all(&path).expect("remove prior temporary coupling tree");
        }
        fs::create_dir_all(&path).expect("create temporary coupling tree");
        Self { path }
    }

    fn join(&self, relative: impl AsRef<Path>) -> PathBuf {
        self.path.join(relative)
    }
}

impl Drop for TempTree {
    fn drop(&mut self) {
        if self.path.exists() {
            fs::remove_dir_all(&self.path).expect("remove temporary coupling tree");
        }
    }
}

fn copy_directory(source: &Path, destination: &Path) -> io::Result<()> {
    fs::create_dir_all(destination)?;
    let mut entries = fs::read_dir(source)?.collect::<Result<Vec<_>, _>>()?;
    entries.sort_by_key(fs::DirEntry::file_name);
    for entry in entries {
        let name = entry.file_name();
        if name == ".git" || name == "target" {
            continue;
        }
        let metadata = fs::symlink_metadata(entry.path())?;
        let destination = destination.join(name);
        if metadata.is_dir() {
            copy_directory(&entry.path(), &destination)?;
        } else if metadata.is_file() {
            if let Some(parent) = destination.parent() {
                fs::create_dir_all(parent)?;
            }
            fs::copy(entry.path(), destination)?;
        } else {
            return Err(io::Error::other(
                "repository fixture contains a non-regular entry",
            ));
        }
    }
    Ok(())
}

fn copy_repo(label: &str) -> TempTree {
    let tree = TempTree::new(label);
    copy_directory(&repo_root(), &tree.path).expect("copy repository fixture");
    tree
}

/// Builds a fresh checkout at the exact immutable Bootstrap fingerprint: every one of the 28
/// canonical `BOOTSTRAP_FILES` paths is materialized byte-for-byte from the committed archive,
/// and the complete trust root (archive, ledger, validator source) is copied alongside it.
fn bootstrap_tree(label: &str) -> TempTree {
    let tree = TempTree::new(label);
    let snapshot = fs::read(
        repo_root().join(".github/trusted/desktop-supply-chain-policy/policy/bootstrap.snapshot"),
    )
    .expect("read immutable bootstrap snapshot");
    let archive =
        BootstrapSnapshotArchive::parse(&snapshot).expect("parse immutable bootstrap snapshot");
    assert_eq!(archive.entries().len(), 28);
    for (path, payload) in archive.entries() {
        let destination = tree.join(path);
        fs::create_dir_all(destination.parent().expect("snapshot path parent"))
            .expect("create snapshot parent");
        fs::write(destination, payload).expect("write snapshot file");
    }
    copy_directory(
        &repo_root().join(".github/trusted/desktop-supply-chain-policy"),
        &tree.join(".github/trusted/desktop-supply-chain-policy"),
    )
    .expect("copy protected trust root into bootstrap fixture");
    tree
}

fn write_from_policy(tree: &TempTree, source: &str, destination: &str) {
    let source = repo_root()
        .join(".github/trusted/desktop-supply-chain-policy/policy/final")
        .join(source);
    let destination = tree.join(destination);
    fs::create_dir_all(destination.parent().expect("fixture destination parent"))
        .expect("create fixture destination");
    fs::copy(source, destination).expect("copy final policy overlay");
}

/// Builds a complete final P04f checkout layered on top of a live repository copy.
fn final_tree(label: &str) -> TempTree {
    let tree = copy_repo(label);
    for (source, destination) in [
        (".github/workflows/rust.yml", ".github/workflows/rust.yml"),
        (
            ".github/workflows/macos-packaging.yml",
            ".github/workflows/macos-packaging.yml",
        ),
        ("root-deny.toml.fixture", "deny.toml"),
        ("desktop/Cargo.toml.fixture", "desktop/Cargo.toml"),
        ("desktop/Cargo.lock.fixture", "desktop/Cargo.lock"),
        (
            "desktop/apps/gta-claw-desktop/Cargo.toml.fixture",
            "desktop/apps/gta-claw-desktop/Cargo.toml",
        ),
        (
            "desktop/apps/gta-claw-desktop/tests/macos_winit_smoke.rs",
            "desktop/apps/gta-claw-desktop/tests/macos_winit_smoke.rs",
        ),
        ("desktop/deny.toml.fixture", "desktop/deny.toml"),
        (
            ".github/fixtures/cargo-audit/unmaintained/Cargo.lock.fixture",
            ".github/fixtures/cargo-audit/unmaintained/Cargo.lock.fixture",
        ),
        (
            ".github/fixtures/cargo-audit/vulnerable/Cargo.lock.fixture",
            ".github/fixtures/cargo-audit/vulnerable/Cargo.lock.fixture",
        ),
        (
            ".github/fixtures/security-tools/bash-env-poison.sh",
            ".github/fixtures/security-tools/bash-env-poison.sh",
        ),
        (
            ".github/fixtures/security-tools/shadow-bin/sha256sum",
            ".github/fixtures/security-tools/shadow-bin/sha256sum",
        ),
        (
            ".github/fixtures/security-tools/shadow-bin/tar",
            ".github/fixtures/security-tools/shadow-bin/tar",
        ),
    ] {
        write_from_policy(&tree, source, destination);
    }
    tree
}

fn replace(path: &Path, from: &str, to: &str) {
    let text = fs::read_to_string(path).expect("read mutation input");
    assert!(text.contains(from), "mutation source missing: {from:?}");
    fs::write(path, text.replacen(from, to, 1)).expect("write mutation");
}

fn local_metadata_tools() -> MetadataTools {
    let cargo = PathBuf::from(env::var_os("CARGO").expect("Cargo exposes CARGO to tests"));
    let rustc_name = if cfg!(windows) { "rustc.exe" } else { "rustc" };
    let rustc = cargo.parent().expect("Cargo has a parent").join(rustc_name);
    MetadataTools {
        cargo_sha256: sha256(&fs::read(&cargo).expect("read local Cargo")),
        rustc_sha256: sha256(&fs::read(&rustc).expect("read local rustc")),
        cargo,
        rustc,
    }
}

fn local_actionlint() -> Option<ActionlintTool> {
    let path = PathBuf::from(env::var_os("ACTIONLINT_BIN")?);
    Some(ActionlintTool {
        sha256: sha256(&fs::read(&path).expect("read local actionlint")),
        path,
    })
}

const WORKFLOW_PATH: &str = ".github/workflows/upstream-gateway-reference.yml";
const RATIONALE: &str = "Intentionally preserved for a covered historical scenario.";

fn manifest_of(entries: &[(char, &str)]) -> ChangeManifest {
    ChangeManifest {
        base: "1111111111111111111111111111111111111111".to_owned(),
        head: "2222222222222222222222222222222222222222".to_owned(),
        paths: entries
            .iter()
            .map(|(status, path)| ChangedPath {
                status: *status,
                path: (*path).to_owned(),
            })
            .collect(),
    }
}

fn root(tree: &TempTree) -> SafeRoot {
    SafeRoot::new(&tree.path).expect("open coupling fixture root")
}

fn read_archive(tree: &TempTree) -> BootstrapSnapshotArchive {
    let bytes = fs::read(tree.join(BOOTSTRAP_SNAPSHOT_PATH)).expect("read candidate archive");
    BootstrapSnapshotArchive::parse(&bytes).expect("parse candidate archive")
}

fn write_ledger(tree: &TempTree, body: &str) {
    fs::write(tree.join(LEDGER_PATH), body).expect("write preservation ledger");
}

fn ledger_record_toml(
    sequence: u64,
    path: &str,
    base_sha256: &str,
    candidate_sha256: &str,
    archive_payload_sha256: &str,
    archive_fingerprint: &str,
    rationale: &str,
) -> String {
    format!(
        "[[record]]\nsequence = {sequence}\npath = \"{path}\"\nbase_sha256 = \"{base_sha256}\"\ncandidate_sha256 = \"{candidate_sha256}\"\narchive_payload_sha256 = \"{archive_payload_sha256}\"\narchive_fingerprint = \"{archive_fingerprint}\"\nrationale = \"{rationale}\"\n"
    )
}

#[test]
fn unchanged_and_non_bootstrap_changes_pass_without_any_decision() {
    let trusted = bootstrap_tree("baseline-a");
    let candidate = bootstrap_tree("baseline-b");
    validate_bootstrap_change_coupling(&root(&trusted), &root(&candidate), &manifest_of(&[]))
        .expect("no changed paths never requires a decision");
    validate_bootstrap_change_coupling(
        &root(&trusted),
        &root(&candidate),
        &manifest_of(&[('M', "crates/claw-domain/src/lib.rs")]),
    )
    .expect("a non-Bootstrap-managed changed path never requires a decision");
}

#[test]
fn reproducing_the_hash50_class_untouched_archive_fingerprint_and_ledger_rejects() {
    let trusted = bootstrap_tree("hash50-trusted");
    let candidate = bootstrap_tree("hash50-candidate");
    let workflow = candidate.join(WORKFLOW_PATH);
    let text = fs::read_to_string(&workflow).expect("read live workflow fixture");
    fs::write(
        &workflow,
        format!("{text}\n# setup-node/npm/pnpm style live drift\n"),
    )
    .expect("mutate live workflow fixture");

    let error = validate_bootstrap_change_coupling(
        &root(&trusted),
        &root(&candidate),
        &manifest_of(&[('M', WORKFLOW_PATH)]),
    )
    .expect_err("an untouched archive/fingerprint/ledger must not silently cover a live change");
    assert!(
        error.to_string().contains("companion decision"),
        "unexpected diagnostic: {error}"
    );
}

fn synchronize_candidate(candidate: &TempTree, mutated_workflow_bytes: &[u8]) {
    fs::write(candidate.join(WORKFLOW_PATH), mutated_workflow_bytes)
        .expect("write mutated live workflow");
    let archive = BootstrapSnapshotArchive::from_root(&root(candidate))
        .expect("regenerate canonical archive from mutated live checkout");
    let serialized = archive.serialize().expect("serialize regenerated archive");
    fs::write(candidate.join(BOOTSTRAP_SNAPSHOT_PATH), &serialized)
        .expect("write regenerated archive");
    let fingerprint =
        archive_semantic_fingerprint(&archive).expect("compute regenerated archive fingerprint");
    let policy_path = candidate.join(POLICY_SOURCE_PATH);
    replace(
        &policy_path,
        &format!("\"{}\"", expected_bootstrap_fingerprint()),
        &format!("\"{fingerprint}\""),
    );
}

#[test]
fn mechanically_synchronized_archive_and_fingerprint_passes() {
    let trusted = bootstrap_tree("sync-trusted");
    let candidate = bootstrap_tree("sync-candidate");
    synchronize_candidate(
        &candidate,
        b"name: Upstream gateway reference\non:\n  push: {}\n",
    );

    validate_bootstrap_change_coupling(
        &root(&trusted),
        &root(&candidate),
        &manifest_of(&[
            ('M', WORKFLOW_PATH),
            ('M', BOOTSTRAP_SNAPSHOT_PATH),
            ('M', POLICY_SOURCE_PATH),
        ]),
    )
    .expect("a fully synchronized archive, fingerprint, and manifest coverage must pass");
}

#[test]
fn synchronize_cannot_smuggle_fabricated_entries_for_untouched_paths() {
    // A candidate legitimately synchronizes the touched workflow path, but also tampers with
    // the archive entry for an entirely different, untouched Bootstrap-managed path, then
    // recomputes the declared fingerprint over that tampered archive. Without tying the
    // archive fingerprint to a fresh digest of the complete live checkout, this would pass
    // because the fingerprint only had to agree with itself.
    let trusted = bootstrap_tree("smuggle-trusted");
    let candidate = bootstrap_tree("smuggle-candidate");
    fs::write(
        candidate.join(WORKFLOW_PATH),
        b"name: Upstream gateway reference\non:\n  push: {}\n",
    )
    .expect("write mutated live workflow");
    let mut archive = BootstrapSnapshotArchive::from_root(&root(&candidate))
        .expect("regenerate canonical archive from mutated live checkout");
    // Corrupt the archived payload for an untouched path so it no longer matches the
    // candidate's own live bytes for that path.
    let corrupted = archive
        .entries()
        .map(|(path, payload)| {
            if path == ".gitattributes" {
                (
                    path.to_owned(),
                    b"forged unrelated archive payload".to_vec(),
                )
            } else {
                (path.to_owned(), payload.to_vec())
            }
        })
        .collect::<std::collections::BTreeMap<_, _>>();
    archive = BootstrapSnapshotArchive::parse(&{
        let mut raw = Vec::new();
        raw.extend_from_slice(b"GTABOOT1");
        raw.extend_from_slice(&(corrupted.len() as u32).to_le_bytes());
        for (path, payload) in &corrupted {
            raw.extend_from_slice(&(path.len() as u32).to_le_bytes());
            raw.extend_from_slice(&(payload.len() as u64).to_le_bytes());
            raw.extend_from_slice(path.as_bytes());
            raw.extend_from_slice(payload);
        }
        raw
    })
    .expect("parse hand-built corrupted archive");
    let serialized = archive.serialize().expect("serialize corrupted archive");
    fs::write(candidate.join(BOOTSTRAP_SNAPSHOT_PATH), &serialized)
        .expect("write corrupted archive");
    let fingerprint =
        archive_semantic_fingerprint(&archive).expect("compute corrupted archive fingerprint");
    replace(
        &candidate.join(POLICY_SOURCE_PATH),
        &format!("\"{}\"", expected_bootstrap_fingerprint()),
        &format!("\"{fingerprint}\""),
    );

    let error = validate_bootstrap_change_coupling(
        &root(&trusted),
        &root(&candidate),
        &manifest_of(&[
            ('M', WORKFLOW_PATH),
            ('M', BOOTSTRAP_SNAPSHOT_PATH),
            ('M', POLICY_SOURCE_PATH),
        ]),
    )
    .expect_err(
        "a self-consistent but live-tree-disagreeing archive/fingerprint must not satisfy Synchronize",
    );
    assert!(
        error
            .to_string()
            .contains("matches neither the trusted archive"),
        "unexpected diagnostic: {error}"
    );
}

#[test]
fn archive_only_synchronization_without_the_fingerprint_source_change_fails() {
    let trusted = bootstrap_tree("sync-archive-only-trusted");
    let candidate = bootstrap_tree("sync-archive-only-candidate");
    synchronize_candidate(
        &candidate,
        b"name: Upstream gateway reference\non:\n  push: {}\n",
    );

    // Manifest omits the fingerprint-bearing source path even though it was in fact updated:
    // Synchronize requires the diff to directly show both companion files changing.
    let error = validate_bootstrap_change_coupling(
        &root(&trusted),
        &root(&candidate),
        &manifest_of(&[('M', WORKFLOW_PATH), ('M', BOOTSTRAP_SNAPSHOT_PATH)]),
    )
    .expect_err("archive-only manifest coverage must not satisfy Synchronize");
    assert!(error.to_string().contains("companion decision"));
}

#[test]
fn policy_only_synchronization_without_the_archive_change_fails() {
    let trusted = bootstrap_tree("sync-policy-only-trusted");
    let candidate = bootstrap_tree("sync-policy-only-candidate");
    synchronize_candidate(
        &candidate,
        b"name: Upstream gateway reference\non:\n  push: {}\n",
    );

    let error = validate_bootstrap_change_coupling(
        &root(&trusted),
        &root(&candidate),
        &manifest_of(&[('M', WORKFLOW_PATH), ('M', POLICY_SOURCE_PATH)]),
    )
    .expect_err("policy-only manifest coverage must not satisfy Synchronize");
    assert!(error.to_string().contains("companion decision"));
}

#[test]
fn exact_bound_preservation_record_passes() {
    let trusted = bootstrap_tree("preserve-trusted");
    let candidate = bootstrap_tree("preserve-candidate");
    let original = fs::read(trusted.join(WORKFLOW_PATH)).expect("read original workflow bytes");
    let mutated = b"name: Upstream gateway reference\non:\n  push: {}\n".to_vec();
    fs::write(candidate.join(WORKFLOW_PATH), &mutated).expect("write mutated live workflow");

    let archive = read_archive(&candidate);
    let base_sha256 = sha256(&original);
    let candidate_sha256 = sha256(&mutated);
    let archive_payload_sha256 = sha256(archive.payload(WORKFLOW_PATH).expect("archived payload"));
    let archive_fingerprint =
        archive_semantic_fingerprint(&archive).expect("archive semantic fingerprint");

    write_ledger(
        &candidate,
        &format!(
            "version = 1\n{}",
            ledger_record_toml(
                1,
                WORKFLOW_PATH,
                &base_sha256,
                &candidate_sha256,
                &archive_payload_sha256,
                &archive_fingerprint,
                RATIONALE,
            )
        ),
    );

    validate_bootstrap_change_coupling(
        &root(&trusted),
        &root(&candidate),
        &manifest_of(&[('M', WORKFLOW_PATH), ('M', LEDGER_PATH)]),
    )
    .expect("an exact bound preservation record must satisfy the coupling invariant");
}

fn preserved_workflow_fixture(
    label: &str,
) -> (TempTree, TempTree, Vec<u8>, Vec<u8>, String, String) {
    let trusted = bootstrap_tree(&format!("{label}-trusted"));
    let candidate = bootstrap_tree(&format!("{label}-candidate"));
    let original = fs::read(trusted.join(WORKFLOW_PATH)).expect("read original workflow bytes");
    let mutated = b"name: Upstream gateway reference\non:\n  push: {}\n".to_vec();
    fs::write(candidate.join(WORKFLOW_PATH), &mutated).expect("write mutated live workflow");
    let archive = read_archive(&candidate);
    let archive_payload_sha256 = sha256(archive.payload(WORKFLOW_PATH).expect("archived payload"));
    let archive_fingerprint =
        archive_semantic_fingerprint(&archive).expect("archive semantic fingerprint");
    (
        trusted,
        candidate,
        original,
        mutated,
        archive_payload_sha256,
        archive_fingerprint,
    )
}

#[test]
fn stale_base_hash_in_a_preservation_record_is_rejected() {
    let (trusted, candidate, _original, mutated, archive_payload_sha256, archive_fingerprint) =
        preserved_workflow_fixture("stale-base");
    let candidate_sha256 = sha256(&mutated);
    write_ledger(
        &candidate,
        &format!(
            "version = 1\n{}",
            ledger_record_toml(
                1,
                WORKFLOW_PATH,
                &"0".repeat(64),
                &candidate_sha256,
                &archive_payload_sha256,
                &archive_fingerprint,
                RATIONALE,
            )
        ),
    );
    let error = validate_bootstrap_change_coupling(
        &root(&trusted),
        &root(&candidate),
        &manifest_of(&[('M', WORKFLOW_PATH)]),
    )
    .expect_err("a stale base hash must not satisfy Preserve");
    assert!(error.to_string().contains("companion decision"));
}

#[test]
fn stale_candidate_hash_in_a_preservation_record_is_rejected() {
    let (trusted, candidate, original, _mutated, archive_payload_sha256, archive_fingerprint) =
        preserved_workflow_fixture("stale-candidate");
    let base_sha256 = sha256(&original);
    write_ledger(
        &candidate,
        &format!(
            "version = 1\n{}",
            ledger_record_toml(
                1,
                WORKFLOW_PATH,
                &base_sha256,
                &"0".repeat(64),
                &archive_payload_sha256,
                &archive_fingerprint,
                RATIONALE,
            )
        ),
    );
    let error = validate_bootstrap_change_coupling(
        &root(&trusted),
        &root(&candidate),
        &manifest_of(&[('M', WORKFLOW_PATH)]),
    )
    .expect_err("a stale candidate hash must not satisfy Preserve");
    assert!(error.to_string().contains("companion decision"));
}

#[test]
fn wrong_archive_payload_hash_in_a_preservation_record_is_rejected() {
    let (trusted, candidate, original, mutated, _archive_payload_sha256, archive_fingerprint) =
        preserved_workflow_fixture("wrong-payload");
    write_ledger(
        &candidate,
        &format!(
            "version = 1\n{}",
            ledger_record_toml(
                1,
                WORKFLOW_PATH,
                &sha256(&original),
                &sha256(&mutated),
                &"0".repeat(64),
                &archive_fingerprint,
                RATIONALE,
            )
        ),
    );
    let error = validate_bootstrap_change_coupling(
        &root(&trusted),
        &root(&candidate),
        &manifest_of(&[('M', WORKFLOW_PATH)]),
    )
    .expect_err("a wrong archive payload hash must not satisfy Preserve");
    assert!(error.to_string().contains("companion decision"));
}

#[test]
fn wrong_archive_fingerprint_in_a_preservation_record_is_rejected() {
    let (trusted, candidate, original, mutated, archive_payload_sha256, _archive_fingerprint) =
        preserved_workflow_fixture("wrong-fingerprint");
    write_ledger(
        &candidate,
        &format!(
            "version = 1\n{}",
            ledger_record_toml(
                1,
                WORKFLOW_PATH,
                &sha256(&original),
                &sha256(&mutated),
                &archive_payload_sha256,
                &"0".repeat(64),
                RATIONALE,
            )
        ),
    );
    let error = validate_bootstrap_change_coupling(
        &root(&trusted),
        &root(&candidate),
        &manifest_of(&[('M', WORKFLOW_PATH)]),
    )
    .expect_err("a wrong archive fingerprint must not satisfy Preserve");
    assert!(error.to_string().contains("companion decision"));
}

#[test]
fn ledger_schema_bound_and_hash_format_violations_fail_closed() {
    let hex = "0".repeat(64);
    // Missing rationale key.
    assert!(
        parse_ledger(
            format!(
                "version = 1\n[[record]]\nsequence = 1\npath = \".gitattributes\"\nbase_sha256 = \"{hex}\"\ncandidate_sha256 = \"{hex}\"\narchive_payload_sha256 = \"{hex}\"\narchive_fingerprint = \"{hex}\"\n"
            )
            .as_bytes()
        )
        .is_err()
    );
    // Extraneous unexpected key.
    assert!(
        parse_ledger(
            format!(
                "version = 1\n[[record]]\nsequence = 1\npath = \".gitattributes\"\nbase_sha256 = \"{hex}\"\ncandidate_sha256 = \"{hex}\"\narchive_payload_sha256 = \"{hex}\"\narchive_fingerprint = \"{hex}\"\nrationale = \"reviewed intentionally kept\"\nextra = \"nope\"\n"
            )
            .as_bytes()
        )
        .is_err()
    );
    // Rationale too short.
    assert!(
        parse_ledger(
            format!(
                "version = 1\n{}",
                ledger_record_toml(1, ".gitattributes", &hex, &hex, &hex, &hex, "short")
            )
            .as_bytes()
        )
        .is_err()
    );
    // Rationale too long.
    assert!(
        parse_ledger(
            format!(
                "version = 1\n{}",
                ledger_record_toml(
                    1,
                    ".gitattributes",
                    &hex,
                    &hex,
                    &hex,
                    &hex,
                    &"x".repeat(501)
                )
            )
            .as_bytes()
        )
        .is_err()
    );
    // Uppercase hash rejected.
    let mixed_hex = "a".repeat(64);
    assert!(
        parse_ledger(
            format!(
                "version = 1\n{}",
                ledger_record_toml(
                    1,
                    ".gitattributes",
                    &mixed_hex.to_uppercase(),
                    &hex,
                    &hex,
                    &hex,
                    RATIONALE
                )
            )
            .as_bytes()
        )
        .is_err()
    );
    // Path outside the canonical 28-entry Bootstrap inventory rejected.
    assert!(
        parse_ledger(
            format!(
                "version = 1\n{}",
                ledger_record_toml(
                    1,
                    "not/a/bootstrap/path.txt",
                    &hex,
                    &hex,
                    &hex,
                    &hex,
                    RATIONALE
                )
            )
            .as_bytes()
        )
        .is_err()
    );
    // Duplicate records rejected.
    let duplicate = format!(
        "version = 1\n{}{}",
        ledger_record_toml(1, ".gitattributes", &hex, &hex, &hex, &hex, RATIONALE),
        ledger_record_toml(2, ".gitattributes", &hex, &hex, &hex, &hex, RATIONALE),
    );
    assert!(parse_ledger(duplicate.as_bytes()).is_err());
    // Unsorted / non-contiguous sequence rejected.
    let unsorted = format!(
        "version = 1\n{}",
        ledger_record_toml(2, ".gitattributes", &hex, &hex, &hex, &hex, RATIONALE)
    );
    assert!(parse_ledger(unsorted.as_bytes()).is_err());
}

#[test]
fn editing_an_existing_ledger_record_is_rejected() {
    let (trusted, candidate, original, mutated, archive_payload_sha256, archive_fingerprint) =
        preserved_workflow_fixture("edit-record");
    let base_sha256 = sha256(&original);
    let candidate_sha256 = sha256(&mutated);
    let genuine = format!(
        "version = 1\n{}",
        ledger_record_toml(
            1,
            WORKFLOW_PATH,
            &base_sha256,
            &candidate_sha256,
            &archive_payload_sha256,
            &archive_fingerprint,
            RATIONALE,
        )
    );
    write_ledger(&trusted, &genuine);
    // Candidate keeps the same sequence and hashes but edits the rationale text.
    write_ledger(
        &candidate,
        &format!(
            "version = 1\n{}",
            ledger_record_toml(
                1,
                WORKFLOW_PATH,
                &base_sha256,
                &candidate_sha256,
                &archive_payload_sha256,
                &archive_fingerprint,
                "This rationale text was edited after the fact.",
            )
        ),
    );
    let error = validate_bootstrap_change_coupling(
        &root(&trusted),
        &root(&candidate),
        &manifest_of(&[('M', WORKFLOW_PATH)]),
    )
    .expect_err("editing an existing protected ledger record must fail closed");
    assert!(error.to_string().contains("edited"));
}

#[test]
fn deleting_an_existing_ledger_record_is_rejected() {
    let (trusted, candidate, original, mutated, archive_payload_sha256, archive_fingerprint) =
        preserved_workflow_fixture("delete-record");
    let genuine = format!(
        "version = 1\n{}",
        ledger_record_toml(
            1,
            WORKFLOW_PATH,
            &sha256(&original),
            &sha256(&mutated),
            &archive_payload_sha256,
            &archive_fingerprint,
            RATIONALE,
        )
    );
    write_ledger(&trusted, &genuine);
    write_ledger(&candidate, "version = 1\nrecord = []\n");
    let error = validate_bootstrap_change_coupling(
        &root(&trusted),
        &root(&candidate),
        &manifest_of(&[('M', WORKFLOW_PATH)]),
    )
    .expect_err("deleting an existing protected ledger record must fail closed");
    assert!(error.to_string().contains("removed or edited"));
}

#[test]
fn extraneous_ledger_record_unrelated_to_any_changed_path_is_rejected() {
    let (trusted, candidate, original, mutated, archive_payload_sha256, archive_fingerprint) =
        preserved_workflow_fixture("extraneous-record");
    let base_sha256 = sha256(&original);
    let candidate_sha256 = sha256(&mutated);
    // Two new records: one genuinely matches the touched path, one is unrelated and unused.
    write_ledger(
        &candidate,
        &format!(
            "version = 1\n{}{}",
            ledger_record_toml(
                1,
                WORKFLOW_PATH,
                &base_sha256,
                &candidate_sha256,
                &archive_payload_sha256,
                &archive_fingerprint,
                RATIONALE,
            ),
            ledger_record_toml(
                2,
                ".gitattributes",
                &"1".repeat(64),
                &"2".repeat(64),
                &"3".repeat(64),
                &"4".repeat(64),
                RATIONALE,
            )
        ),
    );
    let error = validate_bootstrap_change_coupling(
        &root(&trusted),
        &root(&candidate),
        &manifest_of(&[('M', WORKFLOW_PATH)]),
    )
    .expect_err("an unconsumed extraneous ledger record must fail closed");
    assert!(error.to_string().contains("extraneous"));
}

#[test]
fn a_second_change_to_the_same_path_cannot_reuse_the_first_preservation_record() {
    // Round 1: base -> first candidate state, preserved with a genuine record.
    let base = bootstrap_tree("reuse-base");
    let first = bootstrap_tree("reuse-first");
    let base_bytes = fs::read(base.join(WORKFLOW_PATH)).expect("read base bytes");
    let first_bytes = b"name: Upstream gateway reference\non:\n  push: {}\n".to_vec();
    fs::write(first.join(WORKFLOW_PATH), &first_bytes).expect("write first mutation");
    let first_archive = read_archive(&first);
    let first_record = format!(
        "version = 1\n{}",
        ledger_record_toml(
            1,
            WORKFLOW_PATH,
            &sha256(&base_bytes),
            &sha256(&first_bytes),
            &sha256(
                first_archive
                    .payload(WORKFLOW_PATH)
                    .expect("archived payload")
            ),
            &archive_semantic_fingerprint(&first_archive).expect("fingerprint"),
            RATIONALE,
        )
    );
    write_ledger(&first, &first_record);
    validate_bootstrap_change_coupling(
        &root(&base),
        &root(&first),
        &manifest_of(&[('M', WORKFLOW_PATH)]),
    )
    .expect("round one preservation must pass");

    // Round 2: first -> second candidate state changes the same path again.
    let second = bootstrap_tree("reuse-second");
    write_ledger(&second, &first_record); // reuses the stale record, no new one appended
    let second_bytes =
        b"name: Upstream gateway reference\non:\n  push:\n    branches: [main]\n".to_vec();
    fs::write(second.join(WORKFLOW_PATH), &second_bytes).expect("write second mutation");

    let error = validate_bootstrap_change_coupling(
        &root(&first),
        &root(&second),
        &manifest_of(&[('M', WORKFLOW_PATH)]),
    )
    .expect_err(
        "a stale record from a prior decision must not cover a new change to the same path",
    );
    assert!(error.to_string().contains("companion decision"));

    // Appending a genuine new record (sequence 2) for the new base/candidate hashes passes.
    let second_archive = read_archive(&second);
    let second_record = ledger_record_toml(
        2,
        WORKFLOW_PATH,
        &sha256(&first_bytes),
        &sha256(&second_bytes),
        &sha256(
            second_archive
                .payload(WORKFLOW_PATH)
                .expect("archived payload"),
        ),
        &archive_semantic_fingerprint(&second_archive).expect("fingerprint"),
        RATIONALE,
    );
    write_ledger(&second, &format!("{first_record}{second_record}"));
    validate_bootstrap_change_coupling(
        &root(&first),
        &root(&second),
        &manifest_of(&[('M', WORKFLOW_PATH)]),
    )
    .expect("a fresh preservation record for the new hashes must pass");
}

#[test]
fn multiple_paths_may_mix_synchronize_and_preserve_in_one_pull_request() {
    let trusted = bootstrap_tree("mixed-trusted");
    let candidate = bootstrap_tree("mixed-candidate");

    // Path one: Synchronize the live workflow with a regenerated archive and fingerprint.
    synchronize_candidate(
        &candidate,
        b"name: Upstream gateway reference\non:\n  push: {}\n",
    );

    // Path two: Preserve a changed .gitattributes entry with a bound ledger record.
    let original_attrs = fs::read(trusted.join(".gitattributes")).expect("read original attrs");
    let mutated_attrs = b"*.rs text eol=lf\n*.extra text eol=lf\n".to_vec();
    fs::write(candidate.join(".gitattributes"), &mutated_attrs).expect("write mutated attrs");
    let archive = read_archive(&candidate);
    write_ledger(
        &candidate,
        &format!(
            "version = 1\n{}",
            ledger_record_toml(
                1,
                ".gitattributes",
                &sha256(&original_attrs),
                &sha256(&mutated_attrs),
                &sha256(archive.payload(".gitattributes").expect("archived payload")),
                &archive_semantic_fingerprint(&archive).expect("fingerprint"),
                RATIONALE,
            )
        ),
    );

    validate_bootstrap_change_coupling(
        &root(&trusted),
        &root(&candidate),
        &manifest_of(&[
            ('M', WORKFLOW_PATH),
            ('M', BOOTSTRAP_SNAPSHOT_PATH),
            ('M', POLICY_SOURCE_PATH),
            ('M', ".gitattributes"),
            ('M', LEDGER_PATH),
        ]),
    )
    .expect("mixed Synchronize and Preserve decisions across two paths must both pass");
}

#[test]
fn a_type_change_on_a_bootstrap_managed_path_always_fails_closed() {
    let trusted = bootstrap_tree("type-change-trusted");
    let candidate = bootstrap_tree("type-change-candidate");
    let error = validate_bootstrap_change_coupling(
        &root(&trusted),
        &root(&candidate),
        &manifest_of(&[('T', WORKFLOW_PATH)]),
    )
    .expect_err("a type change on a Bootstrap-managed path is never permitted");
    assert!(error.to_string().contains("type change"));
}

#[test]
fn residual_placement_lets_a_preexisting_diagnostic_fire_before_the_new_rule() {
    let Some(actionlint) = local_actionlint() else {
        eprintln!("ACTIONLINT_BIN is not set; hosted bootstrap requires and runs this test");
        return;
    };
    let trusted = final_tree("residual-trusted");
    let candidate = final_tree("residual-candidate");
    // Break an existing, already-covered final-policy invariant.
    replace(
        &candidate.join("deny.toml"),
        "Apache-2.0 WITH LLVM-exception",
        "Apache-2.0",
    );
    // Also touch a Bootstrap-managed path with no companion decision at all. If the new
    // residual rule ran first it would report its own diagnostic instead.
    let workflow = candidate.join(WORKFLOW_PATH);
    let text = fs::read_to_string(&workflow).expect("read candidate workflow");
    fs::write(&workflow, format!("{text}\n# unrelated live drift\n"))
        .expect("mutate candidate workflow");

    let artifacts = TempTree::new("residual-artifacts");
    let changes = artifacts.join("changes.json");
    desktop_supply_chain_policy::changes::write_manifest(
        &changes,
        &manifest_of(&[('M', WORKFLOW_PATH), ('M', "deny.toml")]),
    )
    .expect("write trusted manifest fixture");

    let error = validate_request(&ValidationRequest {
        trusted_root: trusted.path.clone(),
        candidate_root: candidate.path.clone(),
        changes,
        metadata_tools: local_metadata_tools(),
        actionlint,
        isolation_root: artifacts.join("isolation"),
    })
    .expect_err("the preexisting deny.toml diagnostic must still fire first");
    let message = error.to_string();
    assert!(
        message.contains("deny.toml"),
        "residual placement was violated; got: {message}"
    );
    assert!(!message.contains("companion decision"));
}

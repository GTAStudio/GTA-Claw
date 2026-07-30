use std::env;
use std::ffi::OsStr;
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

use desktop_supply_chain_policy::bootstrap_decisions::{
    BOOTSTRAP_FINGERPRINT_SOURCE_PATH, BOOTSTRAP_SNAPSHOT_PATH, BOOTSTRAP_SOURCE_DECISIONS_PATH,
    BootstrapSourceDecisionEvidence, validate_bootstrap_source_decisions,
};
use desktop_supply_chain_policy::changes::{ChangeManifest, ChangedPath};
use desktop_supply_chain_policy::input::{SafeRoot, sha256};
use desktop_supply_chain_policy::policy::{
    BootstrapSnapshotArchive, WINDOWS_FILE_ID_ADMISSION_BASE_OID, bootstrap_fingerprint,
    bootstrap_snapshot,
};
use desktop_supply_chain_policy::workflows::{
    AUTHORITATIVE_PATH as AUTHORITATIVE_WORKFLOW_PATH, BOOTSTRAP_PATH as BOOTSTRAP_WORKFLOW_PATH,
    validate_protected_files,
};

const UPSTREAM_WORKFLOW: &str = ".github/workflows/upstream-gateway-reference.yml";
const RUSTFMT: &str = "rustfmt.toml";
const ROOT_LOCK: &str = "Cargo.lock";
const ROOT_MANIFEST: &str = "Cargo.toml";
const SECURITY_MANIFEST: &str = "crates/claw-security/Cargo.toml";
const PROTECTED_TREE: &str = ".github/trusted/desktop-supply-chain-policy";
const CODEOWNERS: &str = ".github/CODEOWNERS";
const FINGERPRINT_PREFIX: &str = "const BOOTSTRAP_FINGERPRINT: &str =\n    \"";
const PHASE_A1_BASE_FINGERPRINT: &str =
    "96e8c3dabd6d341133ddae8732e90fe088c62f5dc78d1f579eeeac5f9e8497d3";
const PHASE_A1_BASE_CODEOWNERS: &[u8] = b"# Security-critical desktop supply-chain ownership.\n\
/.github/CODEOWNERS @aizhihuxiao\n\
/.github/workflows/bootstrap-desktop-supply-chain-policy.yml @aizhihuxiao\n\
/.github/workflows/trusted-desktop-supply-chain-policy.yml @aizhihuxiao\n\
/.github/trusted/desktop-supply-chain-policy/** @aizhihuxiao\n\
/.github/workflows/rust.yml @aizhihuxiao\n\
/.github/workflows/macos-packaging.yml @aizhihuxiao\n\
/.github/fixtures/cargo-audit/** @aizhihuxiao\n\
/.github/fixtures/security-tools/** @aizhihuxiao\n\
/.gitattributes @aizhihuxiao\n\
/.cargo/audit.toml @aizhihuxiao\n\
/deny.toml @aizhihuxiao\n\
rust-toolchain @aizhihuxiao\n\
/rust-toolchain.toml @aizhihuxiao\n\
/rustfmt.toml @aizhihuxiao\n\
/desktop/Cargo.toml @aizhihuxiao\n\
/desktop/Cargo.lock @aizhihuxiao\n\
/desktop/deny.toml @aizhihuxiao\n\
/desktop/apps/gta-claw-desktop/Cargo.toml @aizhihuxiao\n\
/desktop/apps/gta-claw-desktop/tests/macos_winit_smoke.rs @aizhihuxiao\n\
/crates/claw-security/tests/desktop_supply_chain_policy.rs @aizhihuxiao\n\
/crates/claw-security/tests/fixtures/desktop_supply_chain_policy/** @aizhihuxiao\n";

/// Bootstrap sources that carry no standing preservation and therefore stay fully coupled.
const FULLY_COUPLED_SOURCES: [&str; 13] = [
    ".cargo/audit.toml",
    ".gitattributes",
    CODEOWNERS,
    BOOTSTRAP_WORKFLOW_PATH,
    ".github/workflows/docker-publish.yml",
    ".github/workflows/linux-packaging.yml",
    ".github/workflows/macos-packaging.yml",
    ".github/workflows/rust.yml",
    AUTHORITATIVE_WORKFLOW_PATH,
    UPSTREAM_WORKFLOW,
    ".github/workflows/windows-packaging.yml",
    "rust-toolchain.toml",
    RUSTFMT,
];

static NEXT_TEMP: AtomicU64 = AtomicU64::new(0);

struct TempTree {
    path: PathBuf,
}

impl TempTree {
    fn new(label: &str) -> Self {
        let unique = NEXT_TEMP.fetch_add(1, Ordering::Relaxed);
        let path = env::temp_dir().join(format!(
            "gta-claw-bootstrap-decisions-{label}-{}-{unique}",
            std::process::id()
        ));
        if path.exists() {
            fs::remove_dir_all(&path).expect("remove prior Bootstrap decision fixture");
        }
        fs::create_dir_all(&path).expect("create Bootstrap decision fixture");
        Self { path }
    }

    fn join(&self, relative: impl AsRef<Path>) -> PathBuf {
        self.path.join(relative)
    }
}

impl Drop for TempTree {
    fn drop(&mut self) {
        if self.path.exists() {
            fs::remove_dir_all(&self.path).expect("remove Bootstrap decision fixture");
        }
    }
}

#[derive(Clone)]
struct TestDecision {
    id: usize,
    path: String,
    base_oid: String,
    base_live_sha256: String,
    candidate_live_sha256: String,
    snapshot_payload_sha256: String,
    snapshot_fingerprint: String,
    rationale: String,
}

fn repo_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(Path::parent)
        .and_then(Path::parent)
        .expect("trusted crate is under repository/.github/trusted")
        .to_path_buf()
}

fn write_file(tree: &TempTree, relative: &str, bytes: impl AsRef<[u8]>) {
    let destination = tree.join(relative);
    fs::create_dir_all(destination.parent().expect("fixture file parent"))
        .expect("create fixture file parent");
    fs::write(destination, bytes).expect("write fixture file");
}

fn snapshot_fixture(label: &str) -> TempTree {
    let tree = TempTree::new(label);
    let snapshot = fs::read(repo_root().join(BOOTSTRAP_SNAPSHOT_PATH))
        .expect("read committed Bootstrap snapshot");
    let archive =
        BootstrapSnapshotArchive::parse(&snapshot).expect("parse committed Bootstrap snapshot");
    archive
        .validate_bootstrap_contents()
        .expect("committed Bootstrap snapshot inventory");
    for (path, payload) in archive.entries() {
        write_file(&tree, path, payload);
    }
    for path in [
        BOOTSTRAP_SNAPSHOT_PATH,
        BOOTSTRAP_FINGERPRINT_SOURCE_PATH,
        BOOTSTRAP_SOURCE_DECISIONS_PATH,
    ] {
        write_file(
            &tree,
            path,
            fs::read(repo_root().join(path)).expect("read trusted fixture input"),
        );
    }
    tree
}

fn normalize_text(bytes: &[u8]) -> Vec<u8> {
    let mut normalized = Vec::with_capacity(bytes.len());
    let mut index = 0;
    while index < bytes.len() {
        if bytes[index..].starts_with(b"\r\n") {
            normalized.push(b'\n');
            index += 2;
        } else {
            normalized.push(bytes[index]);
            index += 1;
        }
    }
    normalized
}

fn manifest(entries: impl IntoIterator<Item = (char, &'static str)>) -> ChangeManifest {
    let mut paths = entries
        .into_iter()
        .map(|(status, path)| ChangedPath {
            status,
            path: path.to_owned(),
        })
        .collect::<Vec<_>>();
    paths.sort_by(|left, right| {
        left.path
            .cmp(&right.path)
            .then(left.status.cmp(&right.status))
    });
    ChangeManifest {
        base: "1111111111111111111111111111111111111111".to_owned(),
        head: "2222222222222222222222222222222222222222".to_owned(),
        paths,
    }
}

fn validate(
    trusted: &TempTree,
    candidate: &TempTree,
    manifest: &ChangeManifest,
) -> Result<BootstrapSourceDecisionEvidence, String> {
    validate_bootstrap_source_decisions(
        &SafeRoot::new(&trusted.path).expect("open trusted fixture"),
        &SafeRoot::new(&candidate.path).expect("open candidate fixture"),
        manifest,
    )
    .map_err(|error| error.to_string())
}

fn append_bytes(tree: &TempTree, path: &str, suffix: &[u8]) {
    let destination = tree.join(path);
    let mut bytes = fs::read(&destination).expect("read mutation input");
    bytes.extend_from_slice(suffix);
    fs::write(destination, bytes).expect("write mutation");
}

fn replace_fingerprint(tree: &TempTree, fingerprint: &str) {
    let path = tree.join(BOOTSTRAP_FINGERPRINT_SOURCE_PATH);
    let mut source = fs::read_to_string(&path).expect("read fingerprint source");
    let declaration = source
        .find(FINGERPRINT_PREFIX)
        .expect("find exact fingerprint declaration");
    let hash_start = declaration + FINGERPRINT_PREFIX.len();
    let hash_end = hash_start + 64;
    assert_eq!(&source[hash_end..hash_end + 2], "\";");
    source.replace_range(hash_start..hash_end, fingerprint);
    fs::write(path, source).expect("write fingerprint source");
}

fn synchronize_snapshot(tree: &TempTree) {
    let root = SafeRoot::new(&tree.path).expect("open snapshot materialization");
    let snapshot = bootstrap_snapshot(&root).expect("generate synchronized snapshot");
    let fingerprint = bootstrap_fingerprint(&root).expect("generate synchronized fingerprint");
    let archive =
        BootstrapSnapshotArchive::parse(&snapshot).expect("parse generated synchronized snapshot");
    assert_eq!(archive.semantic_fingerprint(), fingerprint);
    fs::write(tree.join(BOOTSTRAP_SNAPSHOT_PATH), snapshot).expect("write synchronized snapshot");
    replace_fingerprint(tree, &fingerprint);
}

fn decision_for(trusted: &TempTree, candidate: &TempTree, path: &str, id: usize) -> TestDecision {
    let snapshot = fs::read(candidate.join(BOOTSTRAP_SNAPSHOT_PATH))
        .expect("read candidate Bootstrap snapshot");
    let archive = BootstrapSnapshotArchive::parse(&snapshot)
        .expect("parse candidate Bootstrap snapshot for decision");
    let base_live = normalize_text(&fs::read(trusted.join(path)).expect("read base live source"));
    let candidate_live =
        normalize_text(&fs::read(candidate.join(path)).expect("read candidate live source"));
    TestDecision {
        id,
        path: path.to_owned(),
        base_oid: "1111111111111111111111111111111111111111".to_owned(),
        base_live_sha256: sha256(&base_live),
        candidate_live_sha256: sha256(&candidate_live),
        snapshot_payload_sha256: sha256(
            archive
                .payload(path)
                .expect("snapshot contains decision path"),
        ),
        snapshot_fingerprint: archive.semantic_fingerprint(),
        rationale: "Keep the reviewed historical Bootstrap payload while Final advances."
            .to_owned(),
    }
}

fn quote(value: &str) -> String {
    format!("\"{}\"", value.replace('\\', "\\\\").replace('"', "\\\""))
}

fn render_ledger(decisions: &[TestDecision]) -> String {
    if decisions.is_empty() {
        return "schema_version = 1\ndecisions = []\n".to_owned();
    }
    let mut output = String::from("schema_version = 1\n");
    for decision in decisions {
        output.push_str("\n[[decisions]]\n");
        output.push_str(&format!("id = {}\n", decision.id));
        for (field, value) in [
            ("path", decision.path.as_str()),
            ("base_oid", decision.base_oid.as_str()),
            ("base_live_sha256", decision.base_live_sha256.as_str()),
            (
                "candidate_live_sha256",
                decision.candidate_live_sha256.as_str(),
            ),
            (
                "snapshot_payload_sha256",
                decision.snapshot_payload_sha256.as_str(),
            ),
            (
                "snapshot_fingerprint",
                decision.snapshot_fingerprint.as_str(),
            ),
            ("rationale", decision.rationale.as_str()),
        ] {
            output.push_str(field);
            output.push_str(" = ");
            output.push_str(&quote(value));
            output.push('\n');
        }
    }
    output
}

fn write_ledger(tree: &TempTree, decisions: &[TestDecision]) {
    fs::write(
        tree.join(BOOTSTRAP_SOURCE_DECISIONS_PATH),
        render_ledger(decisions),
    )
    .expect("write decision ledger");
}

fn placeholder_decision(id: usize, path: &str) -> TestDecision {
    TestDecision {
        id,
        path: path.to_owned(),
        base_oid: "1111111111111111111111111111111111111111".to_owned(),
        base_live_sha256: "1".repeat(64),
        candidate_live_sha256: "2".repeat(64),
        snapshot_payload_sha256: "3".repeat(64),
        snapshot_fingerprint: "4".repeat(64),
        rationale: "Previously reviewed preservation decision.".to_owned(),
    }
}

/// Returns the committed archive, which every fixture tree materializes verbatim.
fn committed_archive() -> BootstrapSnapshotArchive {
    let snapshot = fs::read(repo_root().join(BOOTSTRAP_SNAPSHOT_PATH))
        .expect("read committed Bootstrap snapshot");
    BootstrapSnapshotArchive::parse(&snapshot).expect("parse committed Bootstrap snapshot")
}

/// Appends one syntactically perfect standing preservation to a fixture ledger.
///
/// Ids stay consecutive and paths stay strictly ascending because every caller appends a
/// path that sorts after the seeded dependency-graph entries.
fn append_standing(tree: &TempTree, path: &str, payload_sha256: &str, fingerprint: &str) {
    let ledger = tree.join(BOOTSTRAP_SOURCE_DECISIONS_PATH);
    let mut text = fs::read_to_string(&ledger).expect("read fixture ledger");
    let next_id = text.matches("\n[[standing]]\n").count() + 1;
    text.push_str(&format!(
        "\n[[standing]]\nid = {next_id}\npath = {}\nbase_oid = {}\nsnapshot_payload_sha256 = {}\nsnapshot_fingerprint = {}\nrationale = {}\n",
        quote(path),
        quote("988c6d64b6ec61adbfb7f04d39b83155e025de6c"),
        quote(payload_sha256),
        quote(fingerprint),
        quote("Fixture standing preservation."),
    ));
    fs::write(ledger, text).expect("write fixture ledger");
}

fn copy_directory(source: &Path, destination: &Path) {
    fs::create_dir_all(destination).expect("create fixture directory");
    for entry in fs::read_dir(source).expect("read fixture directory") {
        let entry = entry.expect("fixture directory entry");
        // `target` is Git-ignored build output and is never present in a CI checkout.
        if entry.file_name() == OsStr::new("target") {
            continue;
        }
        let target = destination.join(entry.file_name());
        if entry.file_type().expect("fixture entry type").is_dir() {
            copy_directory(&entry.path(), &target);
        } else {
            fs::copy(entry.path(), target).expect("copy fixture file");
        }
    }
}

/// Materializes the complete surface that `validate_protected_files` compares.
fn protected_surface_fixture(label: &str) -> TempTree {
    let tree = TempTree::new(label);
    copy_directory(
        &repo_root().join(PROTECTED_TREE),
        &tree.join(PROTECTED_TREE),
    );
    for path in [
        CODEOWNERS,
        AUTHORITATIVE_WORKFLOW_PATH,
        BOOTSTRAP_WORKFLOW_PATH,
    ] {
        write_file(
            &tree,
            path,
            fs::read(repo_root().join(path)).expect("read protected workflow input"),
        );
    }
    tree
}

fn expect_error(
    trusted: &TempTree,
    candidate: &TempTree,
    manifest: &ChangeManifest,
    expected: &str,
) {
    let error = validate(trusted, candidate, manifest)
        .expect_err("invalid Bootstrap decision fixture unexpectedly passed");
    assert!(
        error.contains(expected),
        "expected error containing {expected:?}, found {error:?}"
    );
}

#[test]
fn unchanged_and_non_bootstrap_changes_need_no_decision() {
    let trusted = snapshot_fixture("baseline-trusted");
    let candidate = snapshot_fixture("baseline-candidate");
    assert_eq!(
        validate(&trusted, &candidate, &manifest([])).expect("unchanged baseline"),
        BootstrapSourceDecisionEvidence {
            changed_paths: 0,
            synchronized_paths: 0,
            preserved_paths: 0,
        }
    );

    write_file(&trusted, "docs/decision-example.txt", b"before\n");
    write_file(&candidate, "docs/decision-example.txt", b"after\n");
    assert_eq!(
        validate(
            &trusted,
            &candidate,
            &manifest([('M', "docs/decision-example.txt")]),
        )
        .expect("non-Bootstrap source change"),
        BootstrapSourceDecisionEvidence {
            changed_paths: 0,
            synchronized_paths: 0,
            preserved_paths: 0,
        }
    );
}

#[test]
fn phase_a1_rotates_only_codeowners_and_preserves_exact_root_inputs() {
    let trusted = snapshot_fixture("phase-a1-trusted");
    let candidate = snapshot_fixture("phase-a1-candidate");

    write_file(&trusted, CODEOWNERS, PHASE_A1_BASE_CODEOWNERS);
    replace_fingerprint(&trusted, PHASE_A1_BASE_FINGERPRINT);
    let trusted_snapshot =
        bootstrap_snapshot(&SafeRoot::new(&trusted.path).expect("open Phase-A1 protected base"))
            .expect("generate Phase-A1 protected snapshot");
    fs::write(trusted.join(BOOTSTRAP_SNAPSHOT_PATH), trusted_snapshot)
        .expect("write Phase-A1 protected snapshot");

    let candidate_ledger = fs::read_to_string(candidate.join(BOOTSTRAP_SOURCE_DECISIONS_PATH))
        .expect("read Phase-A1 candidate ledger");
    let standing = candidate_ledger
        .find("\n[[standing]]\n")
        .expect("candidate ledger retains standing decisions");
    fs::write(
        trusted.join(BOOTSTRAP_SOURCE_DECISIONS_PATH),
        format!(
            "schema_version = 1\ndecisions = []\n{}",
            &candidate_ledger[standing..]
        ),
    )
    .expect("write Phase-A1 protected ledger");

    for path in [ROOT_LOCK, ROOT_MANIFEST] {
        write_file(
            &candidate,
            path,
            fs::read(repo_root().join(path)).expect("read admitted root input"),
        );
    }

    let before = BootstrapSnapshotArchive::parse(
        &fs::read(trusted.join(BOOTSTRAP_SNAPSHOT_PATH)).expect("read protected snapshot"),
    )
    .expect("parse protected snapshot");
    let after = BootstrapSnapshotArchive::parse(
        &fs::read(candidate.join(BOOTSTRAP_SNAPSHOT_PATH)).expect("read admitted snapshot"),
    )
    .expect("parse admitted snapshot");
    let changed = before
        .entries()
        .filter_map(|(path, payload)| (after.payload(path) != Some(payload)).then_some(path))
        .collect::<Vec<_>>();
    assert_eq!(changed, [CODEOWNERS]);
    assert_eq!(
        after.payload(CODEOWNERS),
        Some(
            normalize_text(
                &fs::read(repo_root().join(CODEOWNERS)).expect("read admitted CODEOWNERS")
            )
            .as_slice()
        )
    );

    let mut phase_a1_manifest = manifest([
        ('M', CODEOWNERS),
        ('M', ROOT_LOCK),
        ('M', ROOT_MANIFEST),
        ('M', BOOTSTRAP_SNAPSHOT_PATH),
        ('M', BOOTSTRAP_FINGERPRINT_SOURCE_PATH),
        ('M', BOOTSTRAP_SOURCE_DECISIONS_PATH),
    ]);
    phase_a1_manifest.base = WINDOWS_FILE_ID_ADMISSION_BASE_OID.to_owned();
    assert_eq!(
        validate(&trusted, &candidate, &phase_a1_manifest)
            .expect("accept exact Phase-A1 synchronized/preserved inputs"),
        BootstrapSourceDecisionEvidence {
            changed_paths: 3,
            synchronized_paths: 1,
            preserved_paths: 2,
        }
    );
}

#[test]
fn live_upstream_workflow_change_without_a_companion_reproduces_issue_50_class() {
    let trusted = snapshot_fixture("issue-50-trusted");
    let candidate = snapshot_fixture("issue-50-candidate");
    let live = fs::read(repo_root().join(UPSTREAM_WORKFLOW)).expect("read live upstream workflow");
    write_file(&trusted, UPSTREAM_WORKFLOW, &live);
    write_file(&candidate, UPSTREAM_WORKFLOW, &live);
    append_bytes(
        &candidate,
        UPSTREAM_WORKFLOW,
        b"\n# otherwise-valid live workflow source change\n",
    );

    expect_error(
        &trusted,
        &candidate,
        &manifest([('M', UPSTREAM_WORKFLOW)]),
        &format!(
            "Bootstrap source change requires synchronized snapshot/fingerprint or a new bound preservation decision: {UPSTREAM_WORKFLOW}"
        ),
    );
}

#[test]
fn synchronized_and_bound_preservation_branches_both_pass() {
    let synchronized_trusted = snapshot_fixture("synchronized-trusted");
    let synchronized_candidate = snapshot_fixture("synchronized-candidate");
    append_bytes(
        &synchronized_candidate,
        UPSTREAM_WORKFLOW,
        b"\n# synchronized reviewed change\n",
    );
    synchronize_snapshot(&synchronized_candidate);
    assert_eq!(
        validate(
            &synchronized_trusted,
            &synchronized_candidate,
            &manifest([
                ('M', UPSTREAM_WORKFLOW),
                ('M', BOOTSTRAP_SNAPSHOT_PATH),
                ('M', BOOTSTRAP_FINGERPRINT_SOURCE_PATH),
            ]),
        )
        .expect("mechanically synchronized Bootstrap source"),
        BootstrapSourceDecisionEvidence {
            changed_paths: 1,
            synchronized_paths: 1,
            preserved_paths: 0,
        }
    );

    let preserved_trusted = snapshot_fixture("preserved-trusted");
    let preserved_candidate = snapshot_fixture("preserved-candidate");
    append_bytes(
        &preserved_candidate,
        UPSTREAM_WORKFLOW,
        b"\n# preserve historical payload\n",
    );
    let decision = decision_for(
        &preserved_trusted,
        &preserved_candidate,
        UPSTREAM_WORKFLOW,
        1,
    );
    write_ledger(&preserved_candidate, &[decision]);
    assert_eq!(
        validate(
            &preserved_trusted,
            &preserved_candidate,
            &manifest([
                ('M', UPSTREAM_WORKFLOW),
                ('M', BOOTSTRAP_SOURCE_DECISIONS_PATH),
            ]),
        )
        .expect("hash-bound Bootstrap preservation"),
        BootstrapSourceDecisionEvidence {
            changed_paths: 1,
            synchronized_paths: 0,
            preserved_paths: 1,
        }
    );
}

#[test]
fn multiple_paths_support_one_synchronized_and_one_preserved_decision() {
    let trusted = snapshot_fixture("mixed-trusted");
    let candidate = snapshot_fixture("mixed-candidate");
    append_bytes(
        &candidate,
        UPSTREAM_WORKFLOW,
        b"\n# synchronized in mixed update\n",
    );
    synchronize_snapshot(&candidate);
    append_bytes(&candidate, RUSTFMT, b"\n# preserved in mixed update\n");
    let decision = decision_for(&trusted, &candidate, RUSTFMT, 1);
    write_ledger(&candidate, &[decision]);

    assert_eq!(
        validate(
            &trusted,
            &candidate,
            &manifest([
                ('M', UPSTREAM_WORKFLOW),
                ('M', RUSTFMT),
                ('M', BOOTSTRAP_SNAPSHOT_PATH),
                ('M', BOOTSTRAP_FINGERPRINT_SOURCE_PATH),
                ('M', BOOTSTRAP_SOURCE_DECISIONS_PATH),
            ]),
        )
        .expect("mixed synchronized and preserved decisions"),
        BootstrapSourceDecisionEvidence {
            changed_paths: 2,
            synchronized_paths: 1,
            preserved_paths: 1,
        }
    );
}

#[test]
fn stale_or_incomplete_preservation_bindings_fail_closed() {
    for field in [
        "base_oid",
        "base_live_sha256",
        "candidate_live_sha256",
        "snapshot_payload_sha256",
        "snapshot_fingerprint",
        "rationale",
    ] {
        let trusted = snapshot_fixture(&format!("{field}-trusted"));
        let candidate = snapshot_fixture(&format!("{field}-candidate"));
        append_bytes(
            &candidate,
            UPSTREAM_WORKFLOW,
            b"\n# preservation binding mutation\n",
        );
        let mut decision = decision_for(&trusted, &candidate, UPSTREAM_WORKFLOW, 1);
        match field {
            "base_oid" => decision.base_oid = "3333333333333333333333333333333333333333".to_owned(),
            "base_live_sha256" => decision.base_live_sha256 = "a".repeat(64),
            "candidate_live_sha256" => decision.candidate_live_sha256 = "b".repeat(64),
            "snapshot_payload_sha256" => decision.snapshot_payload_sha256 = "c".repeat(64),
            "snapshot_fingerprint" => decision.snapshot_fingerprint = "d".repeat(64),
            "rationale" => decision.rationale.clear(),
            _ => unreachable!(),
        }
        write_ledger(&candidate, &[decision]);
        expect_error(
            &trusted,
            &candidate,
            &manifest([
                ('M', UPSTREAM_WORKFLOW),
                ('M', BOOTSTRAP_SOURCE_DECISIONS_PATH),
            ]),
            if field == "rationale" {
                "Bootstrap source decision rationale"
            } else {
                field
            },
        );
    }
}

#[test]
fn malformed_schema_hash_duplicate_unsorted_and_noncanonical_ledgers_fail() {
    let cases = [
        (
            "schema",
            "schema_version = 2\ndecisions = []\n".to_owned(),
            "schema_version must be 1",
        ),
        (
            "malformed-hash",
            {
                let mut decision = placeholder_decision(1, UPSTREAM_WORKFLOW);
                decision.base_live_sha256 = "ABC".to_owned();
                render_ledger(&[decision])
            },
            "must be a lowercase full SHA-256",
        ),
        (
            "duplicate",
            render_ledger(&[
                placeholder_decision(1, UPSTREAM_WORKFLOW),
                placeholder_decision(1, RUSTFMT),
            ]),
            "not strictly sorted with consecutive ids",
        ),
        (
            "duplicate-stable-key",
            render_ledger(&[
                placeholder_decision(1, UPSTREAM_WORKFLOW),
                placeholder_decision(2, UPSTREAM_WORKFLOW),
            ]),
            "stable key is duplicated",
        ),
        (
            "unsorted",
            render_ledger(&[
                placeholder_decision(2, UPSTREAM_WORKFLOW),
                placeholder_decision(1, RUSTFMT),
            ]),
            "not strictly sorted with consecutive ids",
        ),
        (
            "noncanonical",
            "schema_version = 1\n\ndecisions = []\n".to_owned(),
            "is not canonical",
        ),
    ];
    for (label, ledger, expected) in cases {
        let trusted = snapshot_fixture(&format!("{label}-trusted"));
        let candidate = snapshot_fixture(&format!("{label}-candidate"));
        fs::write(candidate.join(BOOTSTRAP_SOURCE_DECISIONS_PATH), ledger)
            .expect("write malformed candidate ledger");
        expect_error(
            &trusted,
            &candidate,
            &manifest([('M', BOOTSTRAP_SOURCE_DECISIONS_PATH)]),
            expected,
        );
    }
}

#[test]
fn existing_decisions_are_immutable_and_new_decisions_cannot_be_extraneous() {
    let historical = placeholder_decision(1, UPSTREAM_WORKFLOW);

    let deleted_trusted = snapshot_fixture("deleted-trusted");
    let deleted_candidate = snapshot_fixture("deleted-candidate");
    write_ledger(&deleted_trusted, std::slice::from_ref(&historical));
    expect_error(
        &deleted_trusted,
        &deleted_candidate,
        &manifest([('M', BOOTSTRAP_SOURCE_DECISIONS_PATH)]),
        "deleted existing record id 1",
    );

    let edited_trusted = snapshot_fixture("edited-trusted");
    let edited_candidate = snapshot_fixture("edited-candidate");
    write_ledger(&edited_trusted, std::slice::from_ref(&historical));
    let mut edited = historical.clone();
    edited.rationale = "Edited historical rationale.".to_owned();
    write_ledger(&edited_candidate, &[edited]);
    expect_error(
        &edited_trusted,
        &edited_candidate,
        &manifest([('M', BOOTSTRAP_SOURCE_DECISIONS_PATH)]),
        "edited existing record id 1",
    );

    let extra_trusted = snapshot_fixture("extra-trusted");
    let extra_candidate = snapshot_fixture("extra-candidate");
    write_ledger(
        &extra_candidate,
        &[placeholder_decision(1, UPSTREAM_WORKFLOW)],
    );
    expect_error(
        &extra_trusted,
        &extra_candidate,
        &manifest([('M', BOOTSTRAP_SOURCE_DECISIONS_PATH)]),
        "extraneous Bootstrap preservation decision id 1",
    );
}

#[test]
fn a_second_change_to_the_same_path_cannot_reuse_the_first_record() {
    let first_trusted = snapshot_fixture("replay-first-trusted");
    let first_candidate = snapshot_fixture("replay-first-candidate");
    append_bytes(
        &first_candidate,
        UPSTREAM_WORKFLOW,
        b"\n# first preserved transition\n",
    );
    let historical = decision_for(&first_trusted, &first_candidate, UPSTREAM_WORKFLOW, 1);

    let second_trusted = snapshot_fixture("replay-second-trusted");
    let second_candidate = snapshot_fixture("replay-second-candidate");
    let first_candidate_bytes =
        fs::read(first_candidate.join(UPSTREAM_WORKFLOW)).expect("read first candidate source");
    write_file(&second_trusted, UPSTREAM_WORKFLOW, &first_candidate_bytes);
    write_file(&second_candidate, UPSTREAM_WORKFLOW, &first_candidate_bytes);
    append_bytes(
        &second_candidate,
        UPSTREAM_WORKFLOW,
        b"\n# second preserved transition\n",
    );
    write_ledger(&second_trusted, std::slice::from_ref(&historical));
    write_ledger(&second_candidate, std::slice::from_ref(&historical));

    expect_error(
        &second_trusted,
        &second_candidate,
        &manifest([('M', UPSTREAM_WORKFLOW)]),
        "requires synchronized snapshot/fingerprint or a new bound preservation decision",
    );

    let mut copied = historical.clone();
    copied.id = 2;
    write_ledger(&second_candidate, &[historical, copied]);
    expect_error(
        &second_trusted,
        &second_candidate,
        &manifest([
            ('M', UPSTREAM_WORKFLOW),
            ('M', BOOTSTRAP_SOURCE_DECISIONS_PATH),
        ]),
        "stable key is duplicated",
    );
}

#[test]
fn archive_only_or_policy_source_only_companions_do_not_satisfy_synchronization() {
    let archive_trusted = snapshot_fixture("archive-only-trusted");
    let archive_candidate = snapshot_fixture("archive-only-candidate");
    append_bytes(
        &archive_candidate,
        UPSTREAM_WORKFLOW,
        b"\n# archive-only companion\n",
    );
    synchronize_snapshot(&archive_candidate);
    fs::copy(
        archive_trusted.join(BOOTSTRAP_FINGERPRINT_SOURCE_PATH),
        archive_candidate.join(BOOTSTRAP_FINGERPRINT_SOURCE_PATH),
    )
    .expect("restore unchanged fingerprint source");
    expect_error(
        &archive_trusted,
        &archive_candidate,
        &manifest([('M', UPSTREAM_WORKFLOW), ('M', BOOTSTRAP_SNAPSHOT_PATH)]),
        "requires synchronized snapshot/fingerprint or a new bound preservation decision",
    );

    let policy_trusted = snapshot_fixture("policy-only-trusted");
    let policy_candidate = snapshot_fixture("policy-only-candidate");
    append_bytes(
        &policy_candidate,
        UPSTREAM_WORKFLOW,
        b"\n# policy-source-only companion\n",
    );
    append_bytes(
        &policy_candidate,
        BOOTSTRAP_FINGERPRINT_SOURCE_PATH,
        b"\n// reviewed source comment without a snapshot update\n",
    );
    expect_error(
        &policy_trusted,
        &policy_candidate,
        &manifest([
            ('M', UPSTREAM_WORKFLOW),
            ('M', BOOTSTRAP_FINGERPRINT_SOURCE_PATH),
        ]),
        "requires synchronized snapshot/fingerprint or a new bound preservation decision",
    );
}

#[test]
fn archive_and_fingerprint_recording_paths_cannot_change_by_themselves() {
    let archive_trusted = snapshot_fixture("standalone-archive-trusted");
    let archive_candidate = snapshot_fixture("standalone-archive-candidate");
    append_bytes(
        &archive_candidate,
        UPSTREAM_WORKFLOW,
        b"\n# snapshot-only payload\n",
    );
    synchronize_snapshot(&archive_candidate);
    fs::copy(
        archive_trusted.join(UPSTREAM_WORKFLOW),
        archive_candidate.join(UPSTREAM_WORKFLOW),
    )
    .expect("restore unchanged live source");
    fs::copy(
        archive_trusted.join(BOOTSTRAP_FINGERPRINT_SOURCE_PATH),
        archive_candidate.join(BOOTSTRAP_FINGERPRINT_SOURCE_PATH),
    )
    .expect("restore unchanged fingerprint source");
    expect_error(
        &archive_trusted,
        &archive_candidate,
        &manifest([('M', BOOTSTRAP_SNAPSHOT_PATH)]),
        &format!(
            "candidate Bootstrap snapshot changed without a synchronized live source decision: {UPSTREAM_WORKFLOW}"
        ),
    );

    let fingerprint_trusted = snapshot_fixture("standalone-fingerprint-trusted");
    let fingerprint_candidate = snapshot_fixture("standalone-fingerprint-candidate");
    replace_fingerprint(&fingerprint_candidate, &"0".repeat(64));
    expect_error(
        &fingerprint_trusted,
        &fingerprint_candidate,
        &manifest([('M', BOOTSTRAP_FINGERPRINT_SOURCE_PATH)]),
        "candidate Bootstrap snapshot fingerprint does not match BOOTSTRAP_FINGERPRINT",
    );
}

#[test]
fn unavailable_add_delete_and_type_change_statuses_fail_closed() {
    for status in ['A', 'D', 'T'] {
        let trusted = snapshot_fixture(&format!("status-{status}-trusted"));
        let candidate = snapshot_fixture(&format!("status-{status}-candidate"));
        expect_error(
            &trusted,
            &candidate,
            &manifest([(status, UPSTREAM_WORKFLOW)]),
            &format!("live bytes are unavailable: {UPSTREAM_WORKFLOW} status={status}"),
        );
    }
}

#[test]
fn active_fingerprint_declaration_decoys_are_rejected_without_matching_comments() {
    let trusted = snapshot_fixture("decoy-trusted");
    let candidate = snapshot_fixture("decoy-candidate");
    let fingerprint = BootstrapSnapshotArchive::parse(
        &fs::read(candidate.join(BOOTSTRAP_SNAPSHOT_PATH)).expect("read candidate snapshot"),
    )
    .expect("parse candidate snapshot")
    .semantic_fingerprint();
    append_bytes(
        &candidate,
        BOOTSTRAP_FINGERPRINT_SOURCE_PATH,
        format!("\nconst BOOTSTRAP_FINGERPRINT: &str =\n    \"{fingerprint}\";\n").as_bytes(),
    );
    expect_error(
        &trusted,
        &candidate,
        &manifest([('M', BOOTSTRAP_FINGERPRINT_SOURCE_PATH)]),
        "Bootstrap fingerprint declaration",
    );

    let comment_candidate = snapshot_fixture("comment-decoy-candidate");
    append_bytes(
        &comment_candidate,
        BOOTSTRAP_FINGERPRINT_SOURCE_PATH,
        format!("\n// const BOOTSTRAP_FINGERPRINT: &str =\n//     \"{fingerprint}\";\n").as_bytes(),
    );
    validate(
        &trusted,
        &comment_candidate,
        &manifest([('M', BOOTSTRAP_FINGERPRINT_SOURCE_PATH)]),
    )
    .expect("commented declaration is not an active decoy");

    let gated_candidate = snapshot_fixture("gated-decoy-candidate");
    let policy_path = gated_candidate.join(BOOTSTRAP_FINGERPRINT_SOURCE_PATH);
    let source = fs::read_to_string(&policy_path).expect("read gated fingerprint source");
    fs::write(
        policy_path,
        source.replacen(
            FINGERPRINT_PREFIX,
            &format!("#[cfg(any())]\n{FINGERPRINT_PREFIX}"),
            1,
        ),
    )
    .expect("write attribute-gated fingerprint decoy");
    expect_error(
        &trusted,
        &gated_candidate,
        &manifest([('M', BOOTSTRAP_FINGERPRINT_SOURCE_PATH)]),
        "must not be attribute-gated or prefixed",
    );
}

#[test]
fn standing_preservations_admit_dependency_changes_without_writing_the_protected_tree() {
    let trusted = snapshot_fixture("standing-trusted");
    let candidate = snapshot_fixture("standing-candidate");
    append_bytes(&candidate, ROOT_LOCK, b"\n# resolved a new dependency\n");
    append_bytes(
        &candidate,
        SECURITY_MANIFEST,
        b"\n# declared a new dependency\n",
    );

    assert_eq!(
        fs::read(trusted.join(BOOTSTRAP_SOURCE_DECISIONS_PATH)).expect("read base ledger"),
        fs::read(candidate.join(BOOTSTRAP_SOURCE_DECISIONS_PATH)).expect("read candidate ledger"),
        "an ordinary dependency change must not write the protected decision ledger",
    );
    assert_eq!(
        fs::read(trusted.join(BOOTSTRAP_SNAPSHOT_PATH)).expect("read base snapshot"),
        fs::read(candidate.join(BOOTSTRAP_SNAPSHOT_PATH)).expect("read candidate snapshot"),
        "an ordinary dependency change must not rewrite the historical archive",
    );

    assert_eq!(
        validate(
            &trusted,
            &candidate,
            &manifest([('M', ROOT_LOCK), ('M', SECURITY_MANIFEST)]),
        )
        .expect("standing preservations cover the dependency-graph surface"),
        BootstrapSourceDecisionEvidence {
            changed_paths: 2,
            synchronized_paths: 0,
            preserved_paths: 2,
        }
    );
}

#[test]
fn sources_without_a_standing_preservation_stay_fully_coupled() {
    let trusted = snapshot_fixture("coupled-trusted");
    for path in FULLY_COUPLED_SOURCES {
        let label = path.replace(['/', '.'], "-");
        let candidate = snapshot_fixture(&format!("coupled-{label}"));
        append_bytes(&candidate, path, b"\n# uncovered live source change\n");
        expect_error(
            &trusted,
            &candidate,
            &manifest([('M', path)]),
            &format!(
                "Bootstrap source change requires synchronized snapshot/fingerprint or a new bound preservation decision: {path}"
            ),
        );
    }
}

#[test]
fn a_candidate_cannot_mint_its_own_standing_preservation() {
    let trusted = snapshot_fixture("minted-trusted");
    let candidate = snapshot_fixture("minted-candidate");
    let archive = committed_archive();
    append_bytes(&candidate, RUSTFMT, b"\n# self-authorized live change\n");
    // A perfectly formed, correctly bound entry: the only thing wrong with it is that the
    // protected base does not carry it.
    append_standing(
        &candidate,
        RUSTFMT,
        &sha256(archive.payload(RUSTFMT).expect("archived rustfmt payload")),
        &archive.semantic_fingerprint(),
    );
    expect_error(
        &trusted,
        &candidate,
        &manifest([('M', RUSTFMT), ('M', BOOTSTRAP_SOURCE_DECISIONS_PATH)]),
        &format!(
            "Bootstrap source change requires synchronized snapshot/fingerprint or a new bound preservation decision: {RUSTFMT}"
        ),
    );
}

#[test]
fn a_candidate_cannot_keep_coverage_it_edits_or_drops() {
    let archive = committed_archive();
    let payload = sha256(archive.payload(RUSTFMT).expect("archived rustfmt payload"));
    let fingerprint = archive.semantic_fingerprint();

    for label in ["edited", "dropped"] {
        let trusted = snapshot_fixture(&format!("{label}-standing-trusted"));
        let candidate = snapshot_fixture(&format!("{label}-standing-candidate"));
        append_standing(&trusted, RUSTFMT, &payload, &fingerprint);
        if label == "edited" {
            append_standing(&candidate, RUSTFMT, &payload, &fingerprint);
            let ledger = candidate.join(BOOTSTRAP_SOURCE_DECISIONS_PATH);
            let text = fs::read_to_string(&ledger).expect("read candidate ledger");
            fs::write(
                ledger,
                text.replace(
                    "rationale = \"Fixture standing preservation.\"",
                    "rationale = \"Widened fixture standing preservation.\"",
                ),
            )
            .expect("write edited candidate ledger");
        }
        append_bytes(&candidate, RUSTFMT, b"\n# uncovered live change\n");
        expect_error(
            &trusted,
            &candidate,
            &manifest([('M', RUSTFMT), ('M', BOOTSTRAP_SOURCE_DECISIONS_PATH)]),
            &format!(
                "Bootstrap source change requires synchronized snapshot/fingerprint or a new bound preservation decision: {RUSTFMT}"
            ),
        );
    }
}

#[test]
fn a_standing_preservation_is_void_once_the_archive_it_names_moves() {
    let archive = committed_archive();

    // The named historical payload must be the one that is actually archived.
    let payload_trusted = snapshot_fixture("void-payload-trusted");
    let payload_candidate = snapshot_fixture("void-payload-candidate");
    for tree in [&payload_trusted, &payload_candidate] {
        append_standing(
            tree,
            RUSTFMT,
            &"a".repeat(64),
            &archive.semantic_fingerprint(),
        );
    }
    append_bytes(&payload_candidate, RUSTFMT, b"\n# live change\n");
    expect_error(
        &payload_trusted,
        &payload_candidate,
        &manifest([('M', RUSTFMT)]),
        &format!(
            "Bootstrap standing preservation no longer binds the frozen historical payload: {RUSTFMT}"
        ),
    );

    // Rewriting any archived payload moves the semantic fingerprint, which voids every
    // standing preservation at once.
    let fingerprint_trusted = snapshot_fixture("void-fingerprint-trusted");
    let fingerprint_candidate = snapshot_fixture("void-fingerprint-candidate");
    append_bytes(
        &fingerprint_candidate,
        UPSTREAM_WORKFLOW,
        b"\n# rewrites the archive\n",
    );
    synchronize_snapshot(&fingerprint_candidate);
    append_bytes(
        &fingerprint_candidate,
        ROOT_LOCK,
        b"\n# resolved a dependency\n",
    );
    expect_error(
        &fingerprint_trusted,
        &fingerprint_candidate,
        &manifest([
            ('M', ROOT_LOCK),
            ('M', UPSTREAM_WORKFLOW),
            ('M', BOOTSTRAP_SNAPSHOT_PATH),
            ('M', BOOTSTRAP_FINGERPRINT_SOURCE_PATH),
        ]),
        &format!(
            "Bootstrap standing preservation no longer binds the candidate Bootstrap archive fingerprint: {ROOT_LOCK}"
        ),
    );
}

#[test]
fn every_protected_file_including_the_decision_ledger_is_still_byte_pinned() {
    let trusted = protected_surface_fixture("protected-surface-trusted");
    let baseline = protected_surface_fixture("protected-surface-baseline");
    validate_protected_files(
        &SafeRoot::new(&trusted.path).expect("open protected base"),
        &SafeRoot::new(&baseline.path).expect("open protected candidate"),
    )
    .expect("identical protected surfaces pass");

    let mutations = [
        ("ledger", "policy/bootstrap-source-decisions.toml"),
        ("snapshot", "policy/bootstrap.snapshot"),
        ("validator", "src/bootstrap_decisions.rs"),
        ("fixture", "policy/final/desktop/Cargo.lock.fixture"),
        ("script", "scripts/run-candidate-gates.sh"),
    ];
    for (label, relative) in mutations {
        // A size-changing edit is caught by the inventory; a same-size edit is caught by the
        // byte comparison. The decision ledger is deliberately in this list: nothing about
        // standing preservations exempts it from either check.
        for (kind, expected) in [
            ("grown", "protected tree inventory changed"),
            ("flipped", "protected trust-root file changed"),
        ] {
            let candidate = protected_surface_fixture(&format!("protected-{label}-{kind}"));
            let target = candidate.join(PROTECTED_TREE).join(relative);
            let mut bytes = fs::read(&target).expect("read protected file");
            if kind == "grown" {
                bytes.extend_from_slice(b"\n# unauthorised protected-tree edit\n");
            } else {
                let last = bytes.last_mut().expect("non-empty protected file");
                *last = last.wrapping_add(1);
            }
            fs::write(&target, bytes).expect("mutate protected file");
            let error = validate_protected_files(
                &SafeRoot::new(&trusted.path).expect("open protected base"),
                &SafeRoot::new(&candidate.path).expect("open mutated candidate"),
            )
            .expect_err("unauthorised protected-tree edit unexpectedly passed");
            assert!(
                error.to_string().contains(expected),
                "unexpected refusal for {kind} {label}: {error}"
            );
        }
    }

    let added = protected_surface_fixture("protected-addition");
    write_file(
        &added,
        &format!("{PROTECTED_TREE}/src/smuggled.rs"),
        b"// smuggled validator source\n",
    );
    assert!(
        validate_protected_files(
            &SafeRoot::new(&trusted.path).expect("open protected base"),
            &SafeRoot::new(&added.path).expect("open extended candidate"),
        )
        .is_err(),
        "an added protected-tree file must be refused"
    );

    let codeowners = protected_surface_fixture("protected-codeowners");
    append_bytes(&codeowners, CODEOWNERS, b"\n* @attacker\n");
    let error = validate_protected_files(
        &SafeRoot::new(&trusted.path).expect("open protected base"),
        &SafeRoot::new(&codeowners.path).expect("open codeowners candidate"),
    )
    .expect_err("unauthorised CODEOWNERS edit unexpectedly passed");
    assert!(
        error.to_string().contains("protected workflow changed"),
        "unexpected CODEOWNERS refusal: {error}"
    );
}

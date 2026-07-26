use std::env;
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
    BootstrapSnapshotArchive, bootstrap_fingerprint, bootstrap_snapshot,
};

const UPSTREAM_WORKFLOW: &str = ".github/workflows/upstream-gateway-reference.yml";
const RUSTFMT: &str = "rustfmt.toml";
const FINGERPRINT_PREFIX: &str = "const BOOTSTRAP_FINGERPRINT: &str =\n    \"";

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

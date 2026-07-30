use std::env;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use std::sync::atomic::{AtomicU64, Ordering};

use desktop_supply_chain_policy::policy::BootstrapSnapshotArchive;

const EXPECTED_FINGERPRINT: &str =
    "57315d1c0b87b7e1c323c723b330f894fcec4f651a6786314532ddc8b3104394";
const SNAPSHOT_PATH: &str = ".github/trusted/desktop-supply-chain-policy/policy/bootstrap.snapshot";
const UPSTREAM_WORKFLOW: &str = ".github/workflows/upstream-gateway-reference.yml";

static NEXT_TEMP: AtomicU64 = AtomicU64::new(0);

struct TempTree {
    path: PathBuf,
}

impl TempTree {
    fn new(label: &str) -> Self {
        let unique = NEXT_TEMP.fetch_add(1, Ordering::Relaxed);
        let path = env::temp_dir().join(format!(
            "gta-claw-bootstrap-fingerprint-{label}-{}-{unique}",
            std::process::id()
        ));
        if path.exists() {
            fs::remove_dir_all(&path).expect("remove prior fingerprint fixture");
        }
        fs::create_dir_all(&path).expect("create fingerprint fixture");
        Self { path }
    }

    fn join(&self, relative: impl AsRef<Path>) -> PathBuf {
        self.path.join(relative)
    }
}

impl Drop for TempTree {
    fn drop(&mut self) {
        if self.path.exists() {
            fs::remove_dir_all(&self.path).expect("remove fingerprint fixture");
        }
    }
}

fn repo_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(Path::parent)
        .and_then(Path::parent)
        .expect("trusted crate is under repository/.github/trusted")
        .to_path_buf()
}

fn snapshot_path() -> PathBuf {
    repo_root()
        .join(SNAPSHOT_PATH)
        .canonicalize()
        .expect("canonical committed Bootstrap snapshot")
}

fn materialized_bootstrap(label: &str) -> TempTree {
    let tree = TempTree::new(label);
    let archive = BootstrapSnapshotArchive::parse(
        &fs::read(snapshot_path()).expect("read committed Bootstrap snapshot"),
    )
    .expect("parse committed Bootstrap snapshot");
    archive
        .validate_bootstrap_contents()
        .expect("validate committed Bootstrap contents");
    for (path, payload) in archive.entries() {
        let destination = tree.join(path);
        fs::create_dir_all(destination.parent().expect("Bootstrap entry parent"))
            .expect("create Bootstrap entry parent");
        fs::write(destination, payload).expect("write Bootstrap entry");
    }
    tree
}

fn fingerprint_command(arguments: &[(&str, &Path)]) -> Output {
    let mut command = Command::new(env!("CARGO_BIN_EXE_desktop-supply-chain-policy"));
    command.arg("bootstrap-fingerprint");
    for (option, value) in arguments {
        command.arg(option).arg(value);
    }
    command.output().expect("run Bootstrap fingerprint CLI")
}

fn text(bytes: &[u8]) -> String {
    String::from_utf8(bytes.to_vec()).expect("CLI output is UTF-8")
}

fn assert_refusal(output: &Output, expected: &str) {
    assert!(
        !output.status.success(),
        "unsafe fingerprint command passed"
    );
    assert!(
        output.stdout.is_empty(),
        "refusal emitted plausible stdout: {}",
        text(&output.stdout)
    );
    let stderr = text(&output.stderr);
    assert!(
        stderr.contains(expected),
        "refusal did not name expected mismatch {expected:?}: {stderr}"
    );
    assert!(
        stderr.contains("bootstrap-fingerprint --snapshot"),
        "refusal did not instruct snapshot mode: {stderr}"
    );
    assert!(
        !stderr.to_ascii_lowercase().contains("regenerat")
            && !stderr.to_ascii_lowercase().contains("update the constant"),
        "refusal suggested mutating historical authority: {stderr}"
    );
    assert!(
        stderr.lines().all(|line| {
            let line = line.trim();
            line.len() != 64
                || !line
                    .bytes()
                    .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        }),
        "refusal emitted a bare fingerprint: {stderr}"
    );
}

#[test]
fn snapshot_mode_labels_the_committed_archive_and_root_only_mode_refuses() {
    let snapshot = snapshot_path();
    let output = fingerprint_command(&[("--snapshot", snapshot.as_path())]);
    assert!(
        output.status.success(),
        "snapshot mode failed: {}",
        text(&output.stderr)
    );
    assert!(output.stderr.is_empty());
    assert_eq!(
        text(&output.stdout),
        format!(
            "bootstrap archive {} fingerprint {EXPECTED_FINGERPRINT}\n",
            snapshot.display()
        )
    );

    let root = repo_root();
    let output = fingerprint_command(&[("--root", root.as_path())]);
    assert_refusal(
        &output,
        "live/Final roots must not be fingerprinted directly",
    );
}

#[test]
fn current_final_root_refuses_while_exact_archive_materialization_succeeds() {
    let snapshot = snapshot_path();
    let root = repo_root();
    let output = fingerprint_command(&[
        ("--root", root.as_path()),
        ("--snapshot", snapshot.as_path()),
    ]);
    assert_refusal(&output, "is not an exact materialization");
    assert!(text(&output.stderr).contains("live/Final repository roots"));

    let materialized = materialized_bootstrap("exact");
    let output = fingerprint_command(&[
        ("--root", materialized.path.as_path()),
        ("--snapshot", snapshot.as_path()),
    ]);
    assert!(
        output.status.success(),
        "exact materialization failed: {}",
        text(&output.stderr)
    );
    assert!(output.stderr.is_empty());
    assert_eq!(
        text(&output.stdout),
        format!(
            "verified materialized Bootstrap root {} against bootstrap archive {} fingerprint {EXPECTED_FINGERPRINT}\n",
            materialized
                .path
                .canonicalize()
                .expect("canonical materialized root")
                .display(),
            snapshot.display()
        )
    );
}

#[test]
fn changed_missing_and_extra_materialized_entries_refuse_without_bare_fingerprints() {
    let snapshot = snapshot_path();

    let changed = materialized_bootstrap("changed");
    let mut payload = fs::read(changed.join(UPSTREAM_WORKFLOW)).expect("read changed entry");
    payload.extend_from_slice(b"\n# changed\n");
    fs::write(changed.join(UPSTREAM_WORKFLOW), payload).expect("write changed entry");
    let output = fingerprint_command(&[
        ("--root", changed.path.as_path()),
        ("--snapshot", snapshot.as_path()),
    ]);
    assert_refusal(&output, UPSTREAM_WORKFLOW);
    assert!(text(&output.stderr).contains("expected payload SHA-256"));

    let missing = materialized_bootstrap("missing");
    fs::remove_file(missing.join("rustfmt.toml")).expect("remove required Bootstrap entry");
    let output = fingerprint_command(&[
        ("--root", missing.path.as_path()),
        ("--snapshot", snapshot.as_path()),
    ]);
    assert_refusal(&output, "missing \"rustfmt.toml\"");

    let extra = materialized_bootstrap("extra");
    let extra_path = extra.join("extra/Cargo.toml");
    fs::create_dir_all(extra_path.parent().expect("extra entry parent"))
        .expect("create extra entry parent");
    fs::write(extra_path, "[package]\nname = \"extra\"\n").expect("write extra entry");
    let output = fingerprint_command(&[
        ("--root", extra.path.as_path()),
        ("--snapshot", snapshot.as_path()),
    ]);
    assert_refusal(&output, "found unexpected \"extra/Cargo.toml\"");
}

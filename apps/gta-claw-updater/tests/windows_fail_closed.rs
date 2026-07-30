//! The contract that holds where the updater's durability primitives are absent.
//!
//! This crate deliberately refuses to run on Windows: a directory entry cannot
//! be forced to disk from here, so the ordering every crash-recovery guarantee
//! depends on cannot be enforced, and telling one filesystem object from
//! another is blocked by the same wall. The library therefore refuses at its
//! public boundary instead of performing work it cannot make durable.
//!
//! What matters is not only *that* it refuses but *when*: before the network,
//! before the anti-rollback floor, before staging, and before the installed
//! target is touched. Each of those is asserted below.
#![cfg(windows)]

use std::fmt::Write as _;
use std::path::PathBuf;
use std::process::Command;
use std::sync::atomic::{AtomicUsize, Ordering};

use ed25519_dalek::SigningKey;
use gta_claw_updater::{InstallMode, InstallTarget, UpdateOutcome, Updater};
use semver::Version;
use url::Url;

const FIXTURE: &str = env!("CARGO_BIN_EXE_gta-claw-updater-fixture");
const CURRENT_VERSION: &str = "1.0.0";

/// A port nothing listens on. Reaching the network at all is a test failure, so
/// the manifest URL is one that could only ever fail to connect: if the refusal
/// ever moved *after* the request, the assertion below would see a transport
/// error instead of the refusal and fail.
const UNREACHABLE_MANIFEST: &str = "http://127.0.0.1:1/manifest.json";

static TEMP_SEQUENCE: AtomicUsize = AtomicUsize::new(1);

struct TestDir {
    path: PathBuf,
}

impl TestDir {
    fn new(label: &str) -> Self {
        let sequence = TEMP_SEQUENCE.fetch_add(1, Ordering::SeqCst);
        let path = std::env::temp_dir().join(format!(
            "gta-claw-updater-closed-{label}-{}-{sequence}",
            std::process::id()
        ));
        if path.exists() {
            std::fs::remove_dir_all(&path).expect("remove stale test directory");
        }
        std::fs::create_dir(&path).expect("create isolated test directory");
        Self { path }
    }

    fn state(&self) -> PathBuf {
        self.path.join("updater-state")
    }

    fn target(&self) -> PathBuf {
        self.path.join("gta-claw")
    }

    fn stage(&self) -> PathBuf {
        self.path.join(".gta-claw.gta-claw-stage")
    }
}

impl Drop for TestDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.path);
    }
}

fn public_key_hex() -> String {
    let key = SigningKey::from_bytes(&[37_u8; 32]);
    let mut encoded = String::with_capacity(64);
    for byte in key.verifying_key().to_bytes() {
        write!(encoded, "{byte:02x}").expect("format into String");
    }
    encoded
}

fn fixture(mode: &str, directory: &TestDir) -> Command {
    let mut command = Command::new(FIXTURE);
    command
        .arg(mode)
        .arg("--state")
        .arg(directory.state())
        .arg("--target")
        .arg(directory.target())
        .arg("--manifest")
        .arg(UNREACHABLE_MANIFEST)
        .arg("--current")
        .arg(CURRENT_VERSION)
        .arg("--public-key")
        .arg(public_key_hex());
    command
}

fn run(command: &mut Command) -> String {
    let output = command.output().expect("run the updater fixture");
    let mut combined = String::from_utf8_lossy(&output.stdout).into_owned();
    combined.push_str(&String::from_utf8_lossy(&output.stderr));
    combined
}

/// Refusing before any state exists is the whole point, so this asserts the
/// absence of every artefact an attempted install would have left behind.
fn assert_nothing_was_touched(directory: &TestDir, reported: &str) {
    assert!(
        reported.contains("this platform cannot store updater state safely"),
        "the updater must refuse where its durability primitives are absent: {reported}"
    );
    assert!(
        !directory.state().exists(),
        "refusing must precede creating the anti-rollback state tree: {reported}"
    );
    assert!(
        !directory.stage().exists(),
        "refusing must precede creating the staging directory: {reported}"
    );
    // The restart contract, in its strongest form: with no staging directory
    // there is no staged path to report, and nothing on disk a later run could
    // install without downloading and verifying the release itself.
    assert!(
        !reported.contains(".gta-claw-stage"),
        "a refusal must never name a staging path back to the caller: {reported}"
    );
}

#[test]
fn check_refuses_before_the_network_and_before_any_state_exists() {
    let directory = TestDir::new("check");

    let reported = run(&mut fixture("check", &directory));

    // A transport error here would mean the request was made before the
    // refusal, which is exactly the ordering this asserts against.
    assert!(
        !reported.contains("connect") && !reported.contains("refused"),
        "the refusal must come before the manifest is ever requested: {reported}"
    );
    assert_nothing_was_touched(&directory, &reported);
}

#[test]
fn download_refuses_before_staging_anything() {
    let directory = TestDir::new("download");

    let reported = run(&mut fixture("download", &directory));

    assert_nothing_was_touched(&directory, &reported);
}

#[test]
fn install_refuses_and_leaves_an_existing_installation_exactly_as_it_was() {
    let directory = TestDir::new("install");
    std::fs::write(directory.target(), b"previous install").expect("write previous install");

    let reported = run(&mut fixture("install", &directory));

    assert_nothing_was_touched(&directory, &reported);
    assert_eq!(
        std::fs::read(directory.target()).expect("read the installed target"),
        b"previous install",
        "a refused install must leave the installation byte for byte as it was"
    );
    assert!(
        !directory.path.join(".gta-claw.gta-claw.rollback").exists(),
        "a refused install must not move the installation aside: {reported}"
    );
}

/// The remaining two public entry points, driven directly rather than through
/// the fixture.
///
/// `check_manifest_bytes` and `execute` are refusals with no filesystem work at
/// all, so a child process buys nothing here: calling them in-process is both
/// deterministic and a stricter check, because the assertion can inspect the
/// returned error rather than a printed string.
fn updater(directory: &TestDir) -> Updater {
    Updater::with_public_key_and_state(
        SigningKey::from_bytes(&[37_u8; 32]).verifying_key().to_bytes(),
        "x86_64-fixture-target",
        directory.state(),
    )
    .expect("build an updater")
}

#[test]
fn check_manifest_bytes_refuses_before_it_inspects_the_bytes() {
    let directory = TestDir::new("manifest-bytes");

    // Deliberately not a valid signed manifest. The refusal has to come first,
    // so the bytes are never even parsed — reaching signature verification
    // would report a different error and fail this assertion.
    let error = updater(&directory)
        .check_manifest_bytes(b"not a manifest", &Version::new(1, 0, 0))
        .expect_err("the platform cannot store the anti-rollback floor");

    assert_eq!(
        error.to_string(),
        "this platform cannot store updater state safely; nothing was changed"
    );
    assert!(
        !directory.state().exists(),
        "refusing must precede persisting any anti-rollback state"
    );
}

#[tokio::test]
async fn execute_refuses_before_the_network_and_leaves_the_target_alone() {
    let directory = TestDir::new("execute");
    std::fs::write(directory.target(), b"previous install").expect("write previous install");
    let target = InstallTarget::new(directory.target(), InstallMode::Executable)
        .expect("executable target");

    let error = updater(&directory)
        .execute(
            &Url::parse(UNREACHABLE_MANIFEST).expect("manifest URL"),
            &Version::new(1, 0, 0),
            &target,
        )
        .await
        .expect_err("the full flow refuses at its first step");

    assert_eq!(
        error.to_string(),
        "this platform cannot store updater state safely; nothing was changed"
    );
    assert!(!directory.state().exists(), "no state was persisted");
    assert!(!directory.stage().exists(), "nothing was staged");
    assert_eq!(
        std::fs::read(directory.target()).expect("read the installed target"),
        b"previous install",
        "a refused run must leave the installation exactly as it was"
    );
}

/// A Linux package target is system-managed and returns before the refusal,
/// which is the one public path that still succeeds here.
#[tokio::test]
async fn a_system_managed_target_is_still_reported_without_touching_anything() {
    let directory = TestDir::new("system-managed");
    let target = InstallTarget::new(directory.target(), InstallMode::LinuxPackage)
        .expect("package target");

    let outcome = updater(&directory)
        .execute(
            &Url::parse(UNREACHABLE_MANIFEST).expect("manifest URL"),
            &Version::new(1, 0, 0),
            &target,
        )
        .await
        .expect("a system-managed target is not an error");

    assert_eq!(outcome, UpdateOutcome::SystemManaged);
    assert!(!directory.state().exists(), "no state was persisted");
}

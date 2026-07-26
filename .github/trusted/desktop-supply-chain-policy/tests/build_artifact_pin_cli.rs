use std::env;
use std::fs;
use std::path::PathBuf;
use std::process::{Command, Output};
use std::sync::atomic::{AtomicU64, Ordering};

use desktop_supply_chain_policy::input::sha256;
use desktop_supply_chain_policy::policy::{
    MAX_BUILD_ARTIFACT_BYTES, ResolvedBuildArtifactPin, verify_local_build_artifact,
};

const DEVICE_TARGET: &str = "aarch64-apple-ios";
const SIM_TARGET: &str = "aarch64-apple-ios-sim";
const PACKAGE: &str = "skia-bindings";
const VERSION: &str = "0.99.0";
const DEVICE_URL: &str = "https://github.com/rust-skia/skia-binaries/releases/download/0.99.0/skia-binaries-a25a0fdb7d90429aa2d1-aarch64-apple-ios-gl-jpegd-jpege-metal-pdf-textlayout.tar.gz";
const DEVICE_DIGEST: &str = "15e20f3265dfddd658f9ef0d0e30d50a73afccb88787812f65fb5e6cf4ec55c8";
const SIM_URL: &str = "https://github.com/rust-skia/skia-binaries/releases/download/0.99.0/skia-binaries-a25a0fdb7d90429aa2d1-aarch64-apple-ios-sim-gl-jpegd-jpege-metal-pdf-textlayout.tar.gz";
const SIM_DIGEST: &str = "ade5b153818d9b7b81240f106df148a9c4b92fb3aba566f942a713b93914e11e";

static NEXT_TEMP: AtomicU64 = AtomicU64::new(0);

struct TempFile {
    path: PathBuf,
}

impl TempFile {
    fn write(label: &str, bytes: &[u8]) -> Self {
        let unique = NEXT_TEMP.fetch_add(1, Ordering::Relaxed);
        let path = env::temp_dir().join(format!(
            "gta-claw-build-artifact-pin-{label}-{}-{unique}.bin",
            std::process::id()
        ));
        fs::write(&path, bytes).expect("write build-artifact pin fixture file");
        Self { path }
    }
}

impl Drop for TempFile {
    fn drop(&mut self) {
        let _ = fs::remove_file(&self.path);
    }
}

fn resolve_command(arguments: &[(&str, &str)]) -> Output {
    let mut command = Command::new(env!("CARGO_BIN_EXE_desktop-supply-chain-policy"));
    command.arg("resolve-build-artifact-pin");
    for (option, value) in arguments {
        command.arg(option).arg(value);
    }
    command
        .output()
        .expect("run build-artifact pin resolver CLI")
}

fn text(bytes: &[u8]) -> String {
    String::from_utf8(bytes.to_vec()).expect("CLI output is UTF-8")
}

fn assert_refusal(output: &Output, expected: &str) {
    assert!(!output.status.success(), "unsafe resolver command passed");
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
}

/// The two reviewed pin rows resolve to exactly the URL and digest facts the task's own
/// specification names, and to nothing else — this is the resolver-backed equivalent of asserting
/// the raw production `PINNED_BUILD_ARTIFACTS` table directly, which is `pub(crate)` and therefore
/// unreachable from this external integration-test crate.
#[test]
fn resolves_the_reviewed_device_and_simulator_pins_exactly() {
    let device = resolve_command(&[
        ("--package", PACKAGE),
        ("--version", VERSION),
        ("--target", DEVICE_TARGET),
    ]);
    assert!(
        device.status.success(),
        "device resolution failed: {}",
        text(&device.stderr)
    );
    assert!(device.stderr.is_empty());
    assert_eq!(
        text(&device.stdout),
        format!(
            "resolved-build-artifact-pin package={PACKAGE} version={VERSION} target={DEVICE_TARGET} url={DEVICE_URL} sha256={DEVICE_DIGEST}\n"
        )
    );

    let sim = resolve_command(&[
        ("--package", PACKAGE),
        ("--version", VERSION),
        ("--target", SIM_TARGET),
    ]);
    assert!(
        sim.status.success(),
        "simulator resolution failed: {}",
        text(&sim.stderr)
    );
    assert!(sim.stderr.is_empty());
    assert_eq!(
        text(&sim.stdout),
        format!(
            "resolved-build-artifact-pin package={PACKAGE} version={VERSION} target={SIM_TARGET} url={SIM_URL} sha256={SIM_DIGEST}\n"
        )
    );

    // Bidirectional: neither row's URL or digest is the other's, so a prefix-collision between
    // `aarch64-apple-ios` and `aarch64-apple-ios-sim` cannot have resolved either target to the
    // wrong archive.
    assert_ne!(DEVICE_URL, SIM_URL);
    assert_ne!(DEVICE_DIGEST, SIM_DIGEST);
}

#[test]
fn rejects_unknown_package_version_and_target() {
    assert_refusal(
        &resolve_command(&[
            ("--package", "not-a-real-package"),
            ("--version", VERSION),
            ("--target", DEVICE_TARGET),
        ]),
        "no reviewed build-artifact pin matches",
    );
    assert_refusal(
        &resolve_command(&[
            ("--package", PACKAGE),
            ("--version", "9.9.9"),
            ("--target", DEVICE_TARGET),
        ]),
        "no reviewed build-artifact pin matches",
    );
    assert_refusal(
        &resolve_command(&[
            ("--package", PACKAGE),
            ("--version", VERSION),
            ("--target", "x86_64-apple-ios"),
        ]),
        "no reviewed build-artifact pin matches",
    );
}

#[test]
fn rejects_a_target_that_only_shares_a_prefix_with_an_admitted_target() {
    // `aarch64-apple-ios` is a proper prefix of `aarch64-apple-ios-sim`; appending garbage after
    // the device name must not be treated as a fuzzy match onto either admitted row.
    assert_refusal(
        &resolve_command(&[
            ("--package", PACKAGE),
            ("--version", VERSION),
            ("--target", "aarch64-apple-ios-extra"),
        ]),
        "no reviewed build-artifact pin matches",
    );
}

#[test]
fn rejects_missing_and_duplicate_and_unknown_options() {
    assert_refusal(
        &resolve_command(&[("--package", PACKAGE), ("--version", VERSION)]),
        "missing required option --target",
    );
    assert_refusal(
        &resolve_command(&[
            ("--package", PACKAGE),
            ("--package", PACKAGE),
            ("--version", VERSION),
            ("--target", DEVICE_TARGET),
        ]),
        "duplicate command option: --package",
    );
    assert_refusal(
        &resolve_command(&[
            ("--package", PACKAGE),
            ("--version", VERSION),
            ("--target", DEVICE_TARGET),
            ("--bogus", "value"),
        ]),
        "unknown command options",
    );
}

#[test]
fn verify_local_against_the_wrong_archive_fails_closed_and_redacts_the_actual_digest() {
    let wrong_bytes = b"this is not the real skia-bindings 0.99.0 ios archive";
    let wrong_file = TempFile::write("wrong-archive", wrong_bytes);
    let wrong_digest = sha256(wrong_bytes);

    let output = resolve_command(&[
        ("--package", PACKAGE),
        ("--version", VERSION),
        ("--target", DEVICE_TARGET),
        (
            "--verify-local",
            wrong_file.path.to_str().expect("utf8 path"),
        ),
    ]);
    assert!(!output.status.success(), "wrong local archive was accepted");
    assert!(output.stdout.is_empty());
    let stderr = text(&output.stderr);
    assert!(
        stderr.contains(DEVICE_DIGEST),
        "refusal must still name the expected reviewed digest: {stderr}"
    );
    assert!(
        !stderr.contains(&wrong_digest),
        "refusal must never echo the untrusted local file's actual digest: {stderr}"
    );
}

#[test]
fn verify_local_rejects_a_file_over_the_requested_byte_bound() {
    let bytes = vec![0u8; 4096];
    let big_file = TempFile::write("oversize", &bytes);
    let output = resolve_command(&[
        ("--package", PACKAGE),
        ("--version", VERSION),
        ("--target", DEVICE_TARGET),
        ("--verify-local", big_file.path.to_str().expect("utf8 path")),
        ("--max-bytes", "16"),
    ]);
    assert_refusal(&output, "exceeds 16 bytes");
}

/// The default `--max-bytes` the CLI applies when the flag is omitted is the same bound
/// `MAX_BUILD_ARTIFACT_BYTES` documents, exercised here directly against the library function with
/// a synthetic pin (the two real reviewed archives are tens of megabytes each and are not
/// materialized in this test).
#[test]
fn library_verify_local_build_artifact_succeeds_on_an_exact_digest_and_size_match() {
    let bytes = b"synthetic build artifact contents for local verification";
    let file = TempFile::write("synthetic-match", bytes);
    let pin = ResolvedBuildArtifactPin {
        package: "synthetic-package",
        version: "1.2.3",
        target: "aarch64-apple-ios",
        url: "https://example.invalid/synthetic.tar.gz",
        sha256: Box::leak(sha256(bytes).into_boxed_str()),
    };
    let verified = verify_local_build_artifact(&pin, &file.path, MAX_BUILD_ARTIFACT_BYTES)
        .expect("exact digest and size match must verify");
    assert_eq!(verified, bytes.len() as u64);
}

#[test]
fn library_verify_local_build_artifact_rejects_a_digest_mismatch_without_leaking_the_real_digest() {
    let bytes = b"synthetic build artifact contents that will not match";
    let file = TempFile::write("synthetic-mismatch", bytes);
    let actual_digest = sha256(bytes);
    let pin = ResolvedBuildArtifactPin {
        package: "synthetic-package",
        version: "1.2.3",
        target: "aarch64-apple-ios",
        url: "https://example.invalid/synthetic.tar.gz",
        sha256: Box::leak("0".repeat(64).into_boxed_str()),
    };
    let error = verify_local_build_artifact(&pin, &file.path, MAX_BUILD_ARTIFACT_BYTES)
        .expect_err("digest mismatch must fail closed");
    let message = error.to_string();
    assert!(
        message.contains(pin.sha256),
        "must name the expected digest: {message}"
    );
    assert!(
        !message.contains(&actual_digest),
        "must never echo the untrusted file's actual digest: {message}"
    );
}

//! Git pack-directory storage rules.
//!
//! `verify_pack_storage` went red at random because Git writes a new pack to `tmp_pack_XXXXXX`
//! before renaming it into place, and that name carries no extension. Whether the gate passed
//! depended on whether a write was in flight while the checkout was inspected, which is a security
//! control failing on timing rather than on content.
//!
//! These cases pin the narrow admission and, more importantly, pin everything it must still
//! reject. A flake fix that quietly widened the rule would look exactly like a flake fix.

use std::fs;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

use desktop_supply_chain_policy::changes::validate_pack_directory;

static COUNTER: AtomicU64 = AtomicU64::new(0);

struct TempDir {
    path: PathBuf,
}

impl TempDir {
    fn new(label: &str) -> Self {
        let unique = COUNTER.fetch_add(1, Ordering::Relaxed);
        let path = std::env::temp_dir().join(format!(
            "gta-claw-pack-{label}-{}-{unique}",
            std::process::id()
        ));
        let _ = fs::remove_dir_all(&path);
        fs::create_dir_all(&path).expect("create pack fixture");
        Self { path }
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.path);
    }
}

fn write(dir: &Path, name: &str, bytes: &[u8]) {
    fs::write(dir.join(name), bytes).expect("write pack fixture entry");
}

#[test]
fn a_pack_write_in_flight_does_not_fail_the_gate() {
    let dir = TempDir::new("in-flight");
    write(&dir.path, "pack-abc.pack", b"pack");
    write(&dir.path, "pack-abc.idx", b"idx");
    write(&dir.path, "pack-abc.rev", b"rev");
    validate_pack_directory(&dir.path).expect("a settled pack directory is valid");

    // Git's own transient write, mid-rename. This is the case that made the gate flaky.
    write(&dir.path, "tmp_pack_a1b2c3", b"partial");
    validate_pack_directory(&dir.path)
        .expect("a pack write in flight must not fail a security gate");
}

#[test]
fn the_transient_allowance_does_not_widen_the_rule() {
    for (label, name) in [
        ("no extension", "loose-object"),
        ("wrong extension", "notes.txt"),
        ("near miss without the separator", "tmp_packet"),
        ("near miss on the prefix", "tmp-pack-a1b2c3"),
        ("prefix not at the start", "evil-tmp_pack_a1b2c3"),
        ("extensionless keep file", "pack-abc.keep"),
    ] {
        let dir = TempDir::new("reject");
        write(&dir.path, "pack-abc.pack", b"pack");
        write(&dir.path, name, b"payload");
        let error = validate_pack_directory(&dir.path)
            .expect_err(&format!("{label} must still be rejected: {name}"));
        assert!(
            error
                .to_string()
                .starts_with("Git pack directory contains an unexpected entry"),
            "{label} was rejected by an unrelated rule: {error}"
        );
    }
}

#[test]
fn a_directory_named_like_a_transient_write_is_still_rejected() {
    let dir = TempDir::new("directory");
    write(&dir.path, "pack-abc.pack", b"pack");
    fs::create_dir(dir.path.join("tmp_pack_a1b2c3")).expect("create directory entry");
    let error = validate_pack_directory(&dir.path)
        .expect_err("a directory must not pass because its name looks transient");
    assert!(
        error
            .to_string()
            .starts_with("Git pack directory contains an unexpected entry"),
        "unexpected rejection: {error}"
    );
}

#[test]
fn a_missing_pack_directory_still_fails_closed() {
    let dir = TempDir::new("missing");
    let error = validate_pack_directory(&dir.path.join("absent"))
        .expect_err("an absent pack directory must fail closed");
    assert!(
        error
            .to_string()
            .starts_with("Git pack directory is unavailable"),
        "unexpected rejection: {error}"
    );
}

#[test]
fn transient_writes_still_count_toward_the_storage_ceiling() {
    // The admission must not exempt the entry from the bounds it would have been subject to
    // under its final name, or a large in-flight write could evade the ceiling entirely.
    let dir = TempDir::new("ceiling");
    for index in 0..80 {
        write(&dir.path, &format!("tmp_pack_{index:04}"), b"partial");
    }
    let error =
        validate_pack_directory(&dir.path).expect_err("transient writes must still be bounded");
    assert!(
        error
            .to_string()
            .starts_with("Git pack storage exceeds fixed bounds"),
        "unexpected rejection: {error}"
    );
}

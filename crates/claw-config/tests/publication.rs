//! Public guarded-publication contract tests.

mod common;

use claw_config::{CompareOutcome, PublicationLock};

#[test]
fn lock_set_is_canonical_ordered_and_deduplicates_aliases() {
    let directory = common::TestDirectory::create();
    let first = directory.path().join("a.json");
    let second = directory.path().join("b.json");
    let first_alias = directory.path().join(".").join("a.json");

    let locks = PublicationLock::acquire_all([&second, &first_alias, &first])
        .expect("acquire ordered lock set");

    assert_eq!(locks.len(), 2);
    assert!(locks[0].destination() < locks[1].destination());
    assert_eq!(
        locks[0].destination(),
        directory.path().join("a.json").as_path()
    );
    assert_eq!(
        locks[1].destination(),
        directory.path().join("b.json").as_path()
    );
}

#[test]
fn snapshot_exposes_raw_bytes_and_absence_for_guarded_writes() {
    let directory = common::TestDirectory::create();
    let path = directory.path().join("state.json");
    let lock = PublicationLock::acquire(&path).expect("acquire publication lock");
    let absent = lock.snapshot().expect("snapshot absence");
    assert!(absent.is_absent());
    assert_eq!(absent.bytes(), None);
    assert!(matches!(
        lock.compare_remove(&absent)
            .expect("remove matching absence"),
        CompareOutcome::Applied(_)
    ));

    let CompareOutcome::Applied(outcome) = lock
        .compare_write(&absent, b"first")
        .expect("publish into absence")
    else {
        panic!("absent generation must accept its first write");
    };
    assert!(outcome.warnings.is_empty());

    let present = lock.snapshot().expect("snapshot present bytes");
    assert!(present.is_present());
    assert_eq!(present.bytes(), Some(b"first".as_slice()));

    let CompareOutcome::Applied(outcome) = lock
        .compare_write(&present, b"second")
        .expect("replace exact present generation")
    else {
        panic!("exact present generation must accept replacement");
    };
    assert!(outcome.warnings.is_empty());

    let CompareOutcome::Conflict(conflict) = lock
        .compare_write(&absent, b"stale")
        .expect("stale absence is a typed conflict")
    else {
        panic!("stale absence must not overwrite present bytes");
    };
    assert_eq!(conflict.actual().bytes(), Some(b"second".as_slice()));
    assert_eq!(std::fs::read(&path).expect("read live bytes"), b"second");
}

#[test]
fn conditional_remove_reports_conflict_then_applies_exact_snapshot() {
    let directory = common::TestDirectory::create();
    let path = directory.path().join("state.json");
    std::fs::write(&path, b"first").expect("write initial bytes");
    let lock = PublicationLock::acquire(&path).expect("acquire publication lock");
    let first = lock.snapshot().expect("snapshot first generation");

    publish_external(&path, b"second");
    let CompareOutcome::Conflict(conflict) = lock
        .compare_remove(&first)
        .expect("stale removal is a typed conflict")
    else {
        panic!("stale removal must not remove the replacement");
    };
    assert_eq!(conflict.actual().bytes(), Some(b"second".as_slice()));
    assert_eq!(std::fs::read(&path).expect("read replacement"), b"second");

    let second = lock.snapshot().expect("snapshot second generation");
    let CompareOutcome::Applied(outcome) = lock
        .compare_remove(&second)
        .expect("remove exact generation")
    else {
        panic!("exact generation must be removable");
    };
    assert!(outcome.warnings.is_empty());
    assert!(!path.exists());
}

#[test]
fn snapshots_cannot_be_reused_for_another_target() {
    let directory = common::TestDirectory::create();
    let first = directory.path().join("first.json");
    let second = directory.path().join("second.json");
    let locks =
        PublicationLock::acquire_all([&first, &second]).expect("acquire both publication locks");
    let first_snapshot = locks[0].snapshot().expect("snapshot first target");

    let error = locks[1]
        .compare_write(&first_snapshot, b"wrong target")
        .expect_err("cross-target snapshot must fail closed");

    assert!(
        error
            .to_string()
            .contains("snapshot belongs to a different destination")
    );
    assert!(!second.exists());
}

fn publish_external(destination: &std::path::Path, bytes: &[u8]) {
    let staging = destination.with_extension("external");
    std::fs::write(&staging, bytes).expect("stage external bytes");
    #[cfg(windows)]
    std::fs::remove_file(destination).expect("remove old Windows destination");
    std::fs::rename(staging, destination).expect("publish external bytes");
}

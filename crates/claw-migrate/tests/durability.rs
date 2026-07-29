//! Durability, compare-and-swap and crash-recovery evidence for `claw-migrate`.
//!
//! Every crash here is a real `apply` interrupted by a path-scoped failpoint —
//! no receipt is hand-edited and no expected digest is seeded — and each one
//! asserts that the public target is either the old object or the new one at the
//! instant of the crash, before a restart is allowed to observe anything.

mod common;

use std::fs;
use std::path::Path;
use std::sync::atomic::{AtomicU64, Ordering};

use claw_migrate::{
    ApplyContext, CodexMigrationProvider, HostPlatform, MigrationError, MigrationPlan,
    MigrationProvider, PlanContext, test_publish_failpoint,
};

use common::{MemorySecretStore, TestDir, paths, read, signer, write};

static CONFLICT_SEQUENCE: AtomicU64 = AtomicU64::new(0);

/// Every crash point exercised by the publication tests, in publication order.
const PUBLISH_CHECKPOINTS: [&str; 3] = [
    "after_staging_write",
    "after_target_moved",
    "after_target_published",
];

fn codex_plan(root: &TestDir, source: &Path, target: &Path, overwrite: bool) -> MigrationPlan {
    let platform_paths = paths(root, HostPlatform::Linux);
    let signer = signer();
    CodexMigrationProvider
        .plan(&PlanContext {
            paths: &platform_paths,
            source: Some(source),
            target_root: target,
            overwrite,
            signer: &signer,
        })
        .expect("plan Codex migration")
}

fn apply(
    target: &Path,
    backup_root: &Path,
    overwrite: bool,
    secrets: &mut MemorySecretStore,
    plan: &MigrationPlan,
) -> Result<(), MigrationError> {
    let mut context = ApplyContext {
        target_root: target,
        backup_root,
        overwrite,
        secret_store: secrets,
    };
    CodexMigrationProvider.apply(&mut context, plan).map(|_| ())
}

/// Durable receipts under `backup_root`, oldest first.
fn receipts(backup_root: &Path) -> Vec<serde_json::Value> {
    let Ok(entries) = fs::read_dir(backup_root) else {
        return Vec::new();
    };
    let mut directories = entries
        .flatten()
        .map(|entry| entry.path())
        .collect::<Vec<_>>();
    directories.sort();
    directories
        .into_iter()
        .filter_map(|directory| {
            let receipt = directory.join("receipt.json");
            receipt
                .is_file()
                .then(|| serde_json::from_str(&read(&receipt)).expect("parse durable receipt"))
        })
        .collect()
}

/// Exact copies preserved under every backup directory's conflict store.
fn preserved_conflicts(backup_root: &Path) -> Vec<String> {
    let Ok(entries) = fs::read_dir(backup_root) else {
        return Vec::new();
    };
    let mut found = Vec::new();
    for entry in entries.flatten() {
        let conflicts = entry.path().join("conflicts");
        let Ok(items) = fs::read_dir(&conflicts) else {
            continue;
        };
        for item in items.flatten() {
            if item.path().is_file() {
                found.push(read(&item.path()));
            }
        }
    }
    found.sort();
    found
}

/// A crash in any publication phase leaves the target old-or-new, and a restart
/// rebuilds the pre-apply state and then completes the migration.
///
/// The receipt is written by the migration itself: nothing in this test tells
/// the engine what digest the staged bytes have, which is the whole point. A
/// crash between the atomic displacement and the parent-directory sync used to
/// leave `expected_new_sha256` null, and recovery then read the migration's own
/// output as a foreign edit and refused to roll it back.
#[test]
fn crash_in_every_publication_phase_leaves_old_or_new_then_restarts_cleanly() {
    for checkpoint in PUBLISH_CHECKPOINTS {
        let root = TestDir::new(&format!("publish-crash-{checkpoint}"));
        let source = root.join("codex-home");
        let target = root.join("target");
        let backup_root = root.join("backup");
        let published = target
            .join("config")
            .join("migrations")
            .join("codex")
            .join("config.toml");
        write(&source.join("config.toml"), "api_key = \"fresh-secret\"\n");
        write(&published, "api_key = \"old-value\"\n");
        let old_bytes = read(&published);

        let mut secrets = MemorySecretStore::default();
        let plan = codex_plan(&root, &source, &target, true);
        let crash = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let _guard = test_publish_failpoint::set_for(checkpoint, &published);
            let _ = apply(&target, &backup_root, true, &mut secrets, &plan);
        }));
        assert!(crash.is_err(), "apply must crash at {checkpoint}");

        // Immediately before restart the public target must be a whole object:
        // either exactly what was there before, or exactly what was published.
        let observed = read(&published);
        assert!(
            observed == old_bytes || observed.contains("keyring://gta-claw/"),
            "target must be old-or-new at {checkpoint}, found: {observed}"
        );
        assert!(
            !observed.contains("fresh-secret"),
            "no publication phase may expose plaintext at {checkpoint}"
        );

        let states = receipts(&backup_root)
            .into_iter()
            .map(|receipt| receipt["state"].as_str().expect("state").to_owned())
            .collect::<Vec<_>>();
        assert_eq!(
            states,
            vec!["pending".to_owned()],
            "the interrupted transaction must stay pending at {checkpoint}"
        );

        // Restart. Recovery restores the pre-apply bytes and the migration then
        // runs to completion.
        let restart = codex_plan(&root, &source, &target, true);
        apply(&target, &backup_root, true, &mut secrets, &restart)
            .unwrap_or_else(|error| panic!("restart after {checkpoint}: {error}"));
        let migrated = read(&published);
        assert!(migrated.contains("keyring://gta-claw/"));
        assert!(!migrated.contains("fresh-secret"));

        // A second restart must be a no-op rather than a second recovery.
        let again = codex_plan(&root, &source, &target, true);
        apply(&target, &backup_root, true, &mut secrets, &again)
            .unwrap_or_else(|error| panic!("idempotent restart after {checkpoint}: {error}"));
        assert_eq!(read(&published), migrated);
    }
}

/// A writer that lands *after* every digest check and immediately before the
/// atomic displacement must not lose its bytes.
///
/// The pre-publication digest comparison proves nothing on its own: two applies
/// can both observe the same prior bytes, and the second rename would then
/// destroy whatever the first one published. Binding the comparison to the
/// exchange makes the object that is inspected the object that was displaced.
#[test]
fn a_write_landing_between_the_digest_check_and_publication_is_preserved() {
    const CONCURRENT: &str = "api_key = \"second-writer-value\"\n";

    let root = TestDir::new("publish-cas-barrier");
    let source = root.join("codex-home");
    let target = root.join("target");
    let backup_root = root.join("backup");
    let published = target
        .join("config")
        .join("migrations")
        .join("codex")
        .join("config.toml");
    write(&source.join("config.toml"), "api_key = \"third-secret\"\n");
    write(&published, "api_key = \"first-value\"\n");

    let plan = codex_plan(&root, &source, &target, true);
    let mut secrets = MemorySecretStore::default();
    let _barrier = test_publish_failpoint::set_barrier("before_publish", &published, |path| {
        // A cooperating apply already verified the digest above; this write is
        // the concurrent publication the compare-and-swap has to defend.
        let sequence = CONFLICT_SEQUENCE.fetch_add(1, Ordering::Relaxed);
        let staging = path.with_file_name(format!(".concurrent-writer.{sequence}"));
        fs::write(&staging, CONCURRENT).expect("stage concurrent bytes");
        fs::rename(&staging, path).expect("publish concurrent bytes");
    });

    let error = apply(&target, &backup_root, true, &mut secrets, &plan)
        .expect_err("publication over foreign bytes must be refused");
    let MigrationError::ApplyFailed { cause, .. } = &error else {
        panic!("expected a wrapped apply failure, got {error}");
    };
    let MigrationError::Conflict(preserved) = cause.as_ref() else {
        panic!("expected a conflict, got {cause}");
    };
    assert_eq!(
        read(preserved),
        CONCURRENT,
        "the displaced bytes must be preserved exactly"
    );
    assert!(
        preserved.starts_with(&backup_root),
        "the conflict copy must be durable under the backup root: {}",
        preserved.display()
    );
    assert_eq!(
        read(&published),
        CONCURRENT,
        "the concurrent writer's bytes must survive at the target"
    );
    assert!(!read(&published).contains("third-secret"));
}

/// A non-empty directory can be replaced, crashed through, restarted and rolled
/// back — none of which a plain `rename` can do at all.
#[test]
fn non_empty_directory_targets_publish_crash_restart_and_roll_back() {
    let root = TestDir::new("directory-overwrite");
    let source = root.join("codex-home");
    let target = root.join("target");
    let backup_root = root.join("backup");
    let skill = target.join("workspace").join("skills").join("audit");
    write(&source.join("config.toml"), "model = \"gpt-5\"\n");
    write(
        &source.join("skills").join("audit").join("SKILL.md"),
        "---\nname: audit\ndescription: New audit.\n---\n",
    );
    write(&skill.join("SKILL.md"), "old skill\n");
    write(&skill.join("nested").join("NOTES.md"), "old notes\n");

    // Overwrite: the existing non-empty directory is replaced wholesale.
    let mut secrets = MemorySecretStore::default();
    let plan = codex_plan(&root, &source, &target, true);
    let receipt = {
        let mut context = ApplyContext {
            target_root: &target,
            backup_root: &backup_root,
            overwrite: true,
            secret_store: &mut secrets,
        };
        CodexMigrationProvider
            .apply(&mut context, &plan)
            .expect("replace a non-empty directory target")
    };
    assert_eq!(
        read(&skill.join("SKILL.md")),
        "---\nname: audit\ndescription: New audit.\n---\n"
    );
    assert!(
        !skill.join("nested").exists(),
        "the replaced directory must not retain the previous tree"
    );

    // Rollback: the previous non-empty tree comes back byte for byte.
    {
        let mut context = ApplyContext {
            target_root: &target,
            backup_root: &backup_root,
            overwrite: true,
            secret_store: &mut secrets,
        };
        CodexMigrationProvider
            .rollback(&mut context, &receipt)
            .expect("restore a non-empty directory target");
    }
    assert_eq!(read(&skill.join("SKILL.md")), "old skill\n");
    assert_eq!(read(&skill.join("nested").join("NOTES.md")), "old notes\n");

    // Crash mid-exchange: the directory is a whole object either way.
    let crash_plan = codex_plan(&root, &source, &target, true);
    let crash = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let _guard = test_publish_failpoint::set_for("after_target_moved", &skill);
        let _ = apply(&target, &backup_root, true, &mut secrets, &crash_plan);
    }));
    assert!(crash.is_err(), "apply must crash during the exchange");
    let interrupted = read(&skill.join("SKILL.md"));
    assert!(
        interrupted == "old skill\n"
            || interrupted == "---\nname: audit\ndescription: New audit.\n---\n",
        "directory target must be old-or-new, found: {interrupted}"
    );

    // Restart: recovery rebuilds the previous tree, then republishes.
    let restart = codex_plan(&root, &source, &target, true);
    apply(&target, &backup_root, true, &mut secrets, &restart).expect("restart after crash");
    assert_eq!(
        read(&skill.join("SKILL.md")),
        "---\nname: audit\ndescription: New audit.\n---\n"
    );
    assert!(!skill.join("nested").exists());
}

/// Recovery from `files_published` must prove the files before committing the
/// secrets that belong to them.
#[test]
fn files_published_recovery_verifies_every_target_before_committing_secrets() {
    const EDITED: &str = "api_key = \"hand-edited\"\n";

    let root = TestDir::new("files-published-verify");
    let source = root.join("codex-home");
    let target = root.join("target");
    let backup_root = root.join("backup");
    let published = target
        .join("config")
        .join("migrations")
        .join("codex")
        .join("config.toml");
    write(&source.join("config.toml"), "api_key = \"routed-secret\"\n");

    let mut secrets = MemorySecretStore::default();
    let plan = codex_plan(&root, &source, &target, false);
    let crash = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let _guard = test_publish_failpoint::set_for("after_files_published", &target);
        let _ = apply(&target, &backup_root, false, &mut secrets, &plan);
    }));
    assert!(crash.is_err(), "apply must crash before committing secrets");
    assert!(
        secrets.committed.is_empty(),
        "no transaction may be committed before the crash"
    );
    let states = receipts(&backup_root)
        .into_iter()
        .map(|receipt| receipt["state"].as_str().expect("state").to_owned())
        .collect::<Vec<_>>();
    assert_eq!(states, vec!["files_published".to_owned()]);

    // A foreign edit after publication means the configuration the staged
    // credential belongs to no longer exists.
    fs::write(&published, EDITED).expect("edit the published target");

    let restart = codex_plan(&root, &source, &target, true);
    let error = apply(&target, &backup_root, true, &mut secrets, &restart)
        .expect_err("recovery must refuse to finalize over an edited target");
    let MigrationError::Conflict(preserved) = &error else {
        panic!("expected a conflict, got {error}");
    };
    assert_eq!(read(preserved), EDITED);
    assert!(
        secrets.committed.is_empty(),
        "secrets must not be committed when a published file no longer matches"
    );
    let states = receipts(&backup_root)
        .into_iter()
        .map(|receipt| receipt["state"].as_str().expect("state").to_owned())
        .collect::<Vec<_>>();
    assert_eq!(
        states,
        vec!["files_published".to_owned()],
        "the receipt must not advance to committed"
    );
    assert_eq!(read(&published), EDITED, "the edit itself is left alone");
    assert_eq!(preserved_conflicts(&backup_root), vec![EDITED.to_owned()]);
}

/// The same interruption with untouched files does finish the transaction.
#[test]
fn files_published_recovery_commits_when_every_target_still_matches() {
    let root = TestDir::new("files-published-commit");
    let source = root.join("codex-home");
    let target = root.join("target");
    let backup_root = root.join("backup");
    write(&source.join("config.toml"), "api_key = \"routed-secret\"\n");

    let mut secrets = MemorySecretStore::default();
    let plan = codex_plan(&root, &source, &target, false);
    let crash = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let _guard = test_publish_failpoint::set_for("after_files_published", &target);
        let _ = apply(&target, &backup_root, false, &mut secrets, &plan);
    }));
    assert!(crash.is_err(), "apply must crash before committing secrets");
    assert!(secrets.committed.is_empty());

    let restart = codex_plan(&root, &source, &target, true);
    apply(&target, &backup_root, true, &mut secrets, &restart).expect("restart completes");
    assert_eq!(
        secrets.committed.len(),
        2,
        "the recovered transaction and the restart's own must both commit"
    );
    assert!(
        receipts(&backup_root)
            .iter()
            .any(|receipt| receipt["state"] == "committed")
    );
}

/// Trailing comments hide inline-table entries from any line scan, so secret
/// identifiers are derived from the document's structure instead.
///
/// The previous line-driven queue skipped a commented `env = { ... }` line
/// entirely, which shifted every later identifier by one entry and eventually
/// fell through to a single shared fallback that overwrote each credential with
/// the next one routed.
#[test]
fn commented_inline_tables_keep_shape_and_route_each_secret_to_its_own_entry() {
    let root = TestDir::new("commented-inline-toml");
    let source = root.join("codex-home");
    let target = root.join("target");
    write(
        &source.join("config.toml"),
        r#"model = "gpt-5-codex"
[mcp_servers.docs]
command = "docs-server"
env = { DOCS_TOKEN = "docs-token-plaintext", REGION = "region-plaintext" } # trailing note
headers = { Authorization = "authorization-plaintext", X_TRACE = "trace-plaintext" } # another note
[mcp_servers.build]
provider = { api_key = "nested-direct-plaintext" }
"#,
    );
    let plan = codex_plan(&root, &source, &target, false);
    let mut secrets = MemorySecretStore::default();
    apply(&target, &root.join("backup"), false, &mut secrets, &plan).expect("apply migration");

    let migrated = read(
        &target
            .join("config")
            .join("migrations")
            .join("codex")
            .join("config.toml"),
    );

    // The rewritten document is still valid TOML with the same table shape and
    // the same comments.
    let parsed = migrated
        .parse::<toml_edit::DocumentMut>()
        .expect("migrated TOML must still parse");
    assert!(migrated.contains("# trailing note"));
    assert!(migrated.contains("# another note"));
    assert!(migrated.contains("env = { DOCS_TOKEN = "));
    assert!(migrated.contains("headers = { Authorization = "));
    assert!(migrated.contains("provider = { api_key = "));

    for plaintext in [
        "docs-token-plaintext",
        "region-plaintext",
        "authorization-plaintext",
        "trace-plaintext",
        "nested-direct-plaintext",
    ] {
        assert!(
            !migrated.contains(plaintext),
            "{plaintext} must not survive in the migrated document"
        );
        assert!(
            secrets.holds(plaintext),
            "{plaintext} must be stored in the secret store"
        );
    }

    // Every reference is distinct, so no entry overwrote another's credential.
    let servers = &parsed["mcp_servers"];
    let references = [
        servers["docs"]["env"]["DOCS_TOKEN"]
            .as_str()
            .expect("DOCS_TOKEN"),
        servers["docs"]["env"]["REGION"].as_str().expect("REGION"),
        servers["docs"]["headers"]["Authorization"]
            .as_str()
            .expect("Authorization"),
        servers["docs"]["headers"]["X_TRACE"]
            .as_str()
            .expect("X_TRACE"),
        servers["build"]["provider"]["api_key"]
            .as_str()
            .expect("nested api_key"),
    ];
    let mut unique = references.to_vec();
    unique.sort_unstable();
    unique.dedup();
    assert_eq!(
        unique.len(),
        references.len(),
        "each secret must get its own reference: {references:?}"
    );
    assert_eq!(secrets.values.len(), references.len());

    // Each reference resolves to the value that was written at that key.
    for (reference, expected) in references.iter().zip([
        "docs-token-plaintext",
        "region-plaintext",
        "authorization-plaintext",
        "trace-plaintext",
        "nested-direct-plaintext",
    ]) {
        let id = reference
            .strip_prefix("keyring://gta-claw/")
            .expect("opaque keyring reference");
        assert_eq!(secrets.plaintext(id).as_deref(), Some(expected));
    }
}

/// Reads the durable receipts' recorded post-publication digest for one target.
fn recorded_new_digest(backup_root: &Path, target: &Path) -> Option<String> {
    receipts(backup_root).into_iter().find_map(|receipt| {
        receipt["backups"].as_array()?.iter().find_map(|entry| {
            (entry["target"].as_str()? == target.to_string_lossy())
                .then(|| entry["expected_new_sha256"].as_str().map(ToOwned::to_owned))
                .flatten()
        })
    })
}

fn sha256_hex(bytes: &[u8]) -> String {
    use sha2::{Digest, Sha256};

    let digest = Sha256::digest(bytes);
    digest.iter().fold(String::new(), |mut encoded, byte| {
        use std::fmt::Write as _;
        let _ = write!(encoded, "{byte:02x}");
        encoded
    })
}

/// The receipt records what this migration staged, never what a live read of the
/// target happens to return afterwards.
///
/// A writer that lands in the window between the atomic exchange and the moment
/// the receipt is finished would otherwise have its bytes recorded as this
/// migration's own output: rollback would then overwrite them as if they were
/// ours, and the secret transaction would be committed for a configuration that
/// no longer exists.
#[test]
fn a_write_landing_after_publication_is_not_recorded_as_this_migrations_output() {
    const FOREIGN: &str = "api_key = \"landed-after-publication\"\n";

    // Control run: what the migration actually publishes, with nothing interfering.
    let control_root = TestDir::new("post-publish-control");
    let control_source = control_root.join("codex-home");
    let control_target = control_root.join("target");
    write(
        &control_source.join("config.toml"),
        "api_key = \"post-publish-secret\"\n",
    );
    let control_plan = codex_plan(&control_root, &control_source, &control_target, false);
    let mut control_secrets = MemorySecretStore::default();
    apply(
        &control_target,
        &control_root.join("backup"),
        false,
        &mut control_secrets,
        &control_plan,
    )
    .expect("control apply");
    let published_bytes = fs::read(
        control_target
            .join("config")
            .join("migrations")
            .join("codex")
            .join("config.toml"),
    )
    .expect("read control output");
    let published_digest = sha256_hex(&published_bytes);
    assert_ne!(published_digest, sha256_hex(FOREIGN.as_bytes()));

    let root = TestDir::new("post-publish-window");
    let source = root.join("codex-home");
    let target = root.join("target");
    let backup_root = root.join("backup");
    let published = target
        .join("config")
        .join("migrations")
        .join("codex")
        .join("config.toml");
    write(
        &source.join("config.toml"),
        "api_key = \"post-publish-secret\"\n",
    );

    let plan = codex_plan(&root, &source, &target, false);
    let mut secrets = MemorySecretStore::default();
    let _barrier = test_publish_failpoint::set_barrier("after_publish", &published, |path| {
        // The compare-and-swap already committed; this write lands in the
        // cleanup and directory-sync window that follows it.
        let sequence = CONFLICT_SEQUENCE.fetch_add(1, Ordering::Relaxed);
        let staging = path.with_file_name(format!(".post-publish-writer.{sequence}"));
        fs::write(&staging, FOREIGN).expect("stage foreign bytes");
        fs::rename(&staging, path).expect("publish foreign bytes");
    });
    let error = apply(&target, &backup_root, false, &mut secrets, &plan)
        .expect_err("a target replaced after publication must not be accepted");

    // The receipt keeps the digest of what was staged and published.
    assert_eq!(
        recorded_new_digest(&backup_root, &published).as_deref(),
        Some(published_digest.as_str()),
        "the receipt must retain the staged digest, not adopt the foreign one"
    );

    // The foreign bytes are preserved, reported, and left where their writer put them.
    let MigrationError::ApplyFailed { cause, .. } = &error else {
        panic!("expected a wrapped apply failure, got {error}");
    };
    let MigrationError::Conflict(preserved) = cause.as_ref() else {
        panic!("expected a conflict, got {cause}");
    };
    assert_eq!(read(preserved), FOREIGN);
    assert!(preserved.starts_with(&backup_root));
    assert_eq!(read(&published), FOREIGN);
    assert!(
        secrets.committed.is_empty(),
        "no secret transaction may commit when a published file was replaced"
    );
    let states = receipts(&backup_root)
        .into_iter()
        .map(|receipt| receipt["state"].as_str().expect("state").to_owned())
        .collect::<Vec<_>>();
    assert_eq!(
        states,
        vec!["pending".to_owned()],
        "the transaction must not be recorded as a clean abort or a commit"
    );

    // Restart: recovery reports the same conflict, preserves the bytes again and
    // still commits nothing.
    let restart = codex_plan(&root, &source, &target, true);
    let restart_error = apply(&target, &backup_root, true, &mut secrets, &restart)
        .expect_err("recovery must refuse to roll over the foreign bytes");
    let MigrationError::Conflict(recovered) = &restart_error else {
        panic!("expected a conflict on restart, got {restart_error}");
    };
    assert_eq!(read(recovered), FOREIGN);
    assert_eq!(read(&published), FOREIGN);
    assert!(secrets.committed.is_empty());
}

/// When the platform refuses to undo a displacement, the displaced object must
/// survive at both the durable copy and the retained staging path.
///
/// This is the one window in which the staging path holds the only copy of what
/// the target contained. Cleanup used to run anyway and delete it, leaving the
/// new object at the target and no trace of what it replaced.
#[test]
fn a_refused_restore_never_deletes_the_only_copy_of_the_displaced_object() {
    const CONCURRENT: &str = "api_key = \"displaced-and-unrestorable\"\n";

    let root = TestDir::new("refused-restore");
    let source = root.join("codex-home");
    let target = root.join("target");
    let backup_root = root.join("backup");
    let published = target
        .join("config")
        .join("migrations")
        .join("codex")
        .join("config.toml");
    write(&source.join("config.toml"), "api_key = \"fresh\"\n");
    write(&published, "api_key = \"first-value\"\n");

    let plan = codex_plan(&root, &source, &target, true);
    let mut secrets = MemorySecretStore::default();
    let _barrier = test_publish_failpoint::set_barrier("before_publish", &published, |path| {
        let sequence = CONFLICT_SEQUENCE.fetch_add(1, Ordering::Relaxed);
        let staging = path.with_file_name(format!(".concurrent-unrestorable.{sequence}"));
        fs::write(&staging, CONCURRENT).expect("stage concurrent bytes");
        fs::rename(&staging, path).expect("publish concurrent bytes");
    });
    let _refuse = test_publish_failpoint::fail_restore_for(&published);

    let error = apply(&target, &backup_root, true, &mut secrets, &plan)
        .expect_err("a refused restore must not look like success");
    let message = error.to_string();
    assert!(
        message.contains("restore concurrently changed migration target"),
        "the error must say the displacement was not undone: {message}"
    );
    assert!(
        message.contains("the target still holds the newly published object"),
        "the error must name the state the target was left in: {message}"
    );

    // Both surviving copies are named, and both really exist after every
    // destructor has had its chance to run.
    let retained = named_path(&message, "retained at ");
    assert_eq!(
        read(&retained),
        CONCURRENT,
        "the retained staging path must still hold the displaced bytes"
    );
    let preserved = named_path(&message, "copied to ");
    assert_eq!(
        read(&preserved),
        CONCURRENT,
        "the durable copy must hold the displaced bytes exactly"
    );
    assert!(preserved.starts_with(&backup_root));
    assert!(
        !read(&published).contains("displaced-and-unrestorable"),
        "the target is explicitly reported as holding the newly published object"
    );
    assert!(
        secrets.committed.is_empty(),
        "no secret transaction may commit behind a refused restore"
    );
}

/// Extracts a path the failure message names after `marker`.
fn named_path(message: &str, marker: &str) -> std::path::PathBuf {
    let rest = message
        .split_once(marker)
        .unwrap_or_else(|| panic!("message must contain {marker:?}: {message}"))
        .1;
    let end = rest.find(" and ").unwrap_or(rest.len());
    std::path::PathBuf::from(rest[..end].trim_end_matches(['.', ';']))
}

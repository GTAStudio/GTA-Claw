//! Transaction behaviour of the [`SecretStore`] port.
//!
//! The durability test in this file kills a real child process with
//! [`std::process::abort`] partway through a transaction and then recovers from
//! whatever survived on disk, rather than simulating the failure by calling the
//! recovery entry point directly.

use std::collections::HashMap;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::atomic::{AtomicBool, AtomicU32, Ordering};
use std::sync::{Arc, Barrier, Mutex};
use std::time::{SystemTime, UNIX_EPOCH};

use claw_provider_sdk::secret::{
    CredentialKey, FileSecretStore, MemorySecretStore, RecoveryOutcome, SecretStore,
    SecretStoreError, SecretString, TRANSACTION_SERVICE, TransactionId,
};

/// Environment variable that turns the ignored helper below into a crashing
/// child process.
const CRASH_DIR: &str = "CLAW_TXN_CRASH_DIR";

const OLD_VALUE: &str = "sk-old-value-4a1f9c2b";
const NEW_VALUE: &str = "sk-new-value-77e3d081";

fn key(account: &str) -> CredentialKey {
    CredentialKey::new("gta-claw", account).expect("a valid credential key")
}

fn unique_dir(label: &str) -> PathBuf {
    static COUNTER: AtomicU32 = AtomicU32::new(0);
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("a clock after the epoch")
        .as_nanos();
    let path = std::env::temp_dir().join(format!(
        "claw-txn-{label}-{}-{nanos}-{}",
        std::process::id(),
        COUNTER.fetch_add(1, Ordering::Relaxed)
    ));
    fs::create_dir_all(&path).expect("the temporary directory is created");
    path
}

fn manifest_accounts(store: &dyn SecretStore) -> Vec<String> {
    let mut accounts: Vec<String> = store
        .accounts(TRANSACTION_SERVICE)
        .expect("the backend enumerates")
        .into_iter()
        .filter(|account| account.starts_with("manifest."))
        .collect();
    accounts.sort();
    accounts
}

fn read_manifest(store: &dyn SecretStore) -> String {
    let accounts = manifest_accounts(store);
    assert_eq!(accounts.len(), 1, "expected exactly one manifest");
    let manifest_key =
        CredentialKey::new(TRANSACTION_SERVICE, accounts[0].clone()).expect("a valid manifest key");
    store
        .get(&manifest_key)
        .expect("the manifest is readable")
        .expect("the manifest is present")
        .expose()
        .to_owned()
}

// ---------------------------------------------------------------------------
// Durability against a real process kill
// ---------------------------------------------------------------------------

/// Helper body executed in a child process. Never runs during a normal test
/// pass: it is `#[ignore]`d and additionally requires [`CRASH_DIR`].
#[test]
#[ignore = "spawned as a child process by a_killed_process_leaves_a_recoverable_transaction"]
fn crash_child_writes_then_aborts() {
    let Ok(root) = std::env::var(CRASH_DIR) else {
        panic!("{CRASH_DIR} must be set for this helper to run");
    };
    let store = FileSecretStore::new(&root).expect("the credential directory opens");
    let transaction = store.begin_transaction().expect("a transaction starts");
    store
        .put(&transaction, &key("openai"), &SecretString::new(NEW_VALUE))
        .expect("the transactional write lands");

    // Die between `put` and `commit`, with no unwinding and no destructors, so
    // only what already reached the filesystem survives.
    std::process::abort();
}

#[test]
fn a_killed_process_leaves_a_recoverable_transaction() {
    let root = unique_dir("crash");
    let store = FileSecretStore::new(&root).expect("the credential directory opens");
    store
        .set(&key("openai"), &SecretString::new(OLD_VALUE))
        .expect("the pre-existing credential is stored");

    let status = Command::new(std::env::current_exe().expect("the test binary path is known"))
        .args(["--exact", "crash_child_writes_then_aborts", "--ignored"])
        .env(CRASH_DIR, &root)
        .output()
        .expect("the child process runs");
    assert!(
        !status.status.success(),
        "the child was supposed to die, but exited with {:?}",
        status.status
    );

    // A brand-new store over the same directory: nothing is inherited from the
    // dead process except the bytes it left behind.
    let recovered_store = FileSecretStore::new(&root).expect("the credential directory reopens");

    assert_eq!(
        recovered_store
            .get(&key("openai"))
            .expect("the credential is readable"),
        Some(SecretString::new(NEW_VALUE)),
        "the half-applied write should still be visible before recovery"
    );
    assert_eq!(
        manifest_accounts(&recovered_store).len(),
        1,
        "the dead process should have left exactly one pending manifest"
    );

    let manifest = read_manifest(&recovered_store);
    assert!(
        !manifest.contains(OLD_VALUE) && !manifest.contains(NEW_VALUE),
        "the manifest must not carry secret material, got {manifest}"
    );
    assert!(
        manifest.contains("\"state\":\"pending\""),
        "the surviving manifest should be pending, got {manifest}"
    );

    let resolved = recovered_store
        .recover_pending()
        .expect("recovery completes");
    assert_eq!(
        resolved.len(),
        1,
        "one transaction should have been resolved"
    );
    assert_eq!(resolved[0].outcome, RecoveryOutcome::RolledBack);

    assert_eq!(
        recovered_store
            .get(&key("openai"))
            .expect("the credential is readable"),
        Some(SecretString::new(OLD_VALUE)),
        "recovery must restore the value the dead process overwrote"
    );
    assert_eq!(
        recovered_store
            .accounts(TRANSACTION_SERVICE)
            .expect("the backend enumerates"),
        Vec::<String>::new(),
        "recovery must leave no bookkeeping behind"
    );

    assert_eq!(
        recovered_store
            .recover_pending()
            .expect("a second recovery completes"),
        Vec::new(),
        "recovery must be idempotent"
    );

    fs::remove_dir_all(&root).expect("the temporary directory is removed");
}

#[test]
fn no_file_on_disk_outside_the_store_holds_the_previous_value() {
    let root = unique_dir("ondisk");
    let store = FileSecretStore::new(&root).expect("the credential directory opens");
    store
        .set(&key("openai"), &SecretString::new(OLD_VALUE))
        .expect("the pre-existing credential is stored");

    let transaction = store.begin_transaction().expect("a transaction starts");
    store
        .put(&transaction, &key("openai"), &SecretString::new(NEW_VALUE))
        .expect("the transactional write lands");

    // Every file the transaction created must either be a credential owned by
    // the backend, or bookkeeping that holds no secret material.
    let mut inspected = 0;
    for entry in fs::read_dir(&root).expect("the directory lists") {
        let path = entry.expect("a directory entry").path();
        let name = path
            .file_name()
            .and_then(|name| name.to_str())
            .expect("a UTF-8 file name")
            .to_owned();
        let body = fs::read_to_string(&path).expect("the file reads");
        inspected += 1;
        if name.starts_with("gta-claw.secret-transaction~manifest.") {
            assert!(
                !body.contains(OLD_VALUE) && !body.contains(NEW_VALUE),
                "manifest {name} leaked secret material"
            );
        }
    }
    assert!(
        inspected >= 3,
        "expected credential, shadow and manifest files, saw {inspected}"
    );

    // The previous value is held only under the reserved namespace, which is the
    // same permission-strict backend that owns every other credential here.
    let shadows: Vec<String> = store
        .accounts(TRANSACTION_SERVICE)
        .expect("the backend enumerates")
        .into_iter()
        .filter(|account| account.starts_with("shadow."))
        .collect();
    assert_eq!(
        shadows.len(),
        1,
        "expected one shadow entry, got {shadows:?}"
    );
    let shadow_key =
        CredentialKey::new(TRANSACTION_SERVICE, shadows[0].clone()).expect("a valid shadow key");
    assert_eq!(
        store.get(&shadow_key).expect("the shadow is readable"),
        Some(SecretString::new(OLD_VALUE))
    );

    fs::remove_dir_all(&root).expect("the temporary directory is removed");
}

#[test]
fn the_transaction_identifier_is_the_only_thing_a_caller_must_persist() {
    let root = unique_dir("receipt");
    let store = FileSecretStore::new(&root).expect("the credential directory opens");
    store
        .set(&key("openai"), &SecretString::new(OLD_VALUE))
        .expect("the pre-existing credential is stored");

    let transaction = store.begin_transaction().expect("a transaction starts");
    store
        .put(&transaction, &key("openai"), &SecretString::new(NEW_VALUE))
        .expect("the transactional write lands");

    // This is everything a caller's own journal needs to hold.
    let receipt = transaction.to_string();
    assert_eq!(receipt.len(), 32);
    assert!(!receipt.contains(OLD_VALUE) && !receipt.contains(NEW_VALUE));
    drop(transaction);

    // Rebuild the handle from the receipt alone and finish the job.
    let restored = TransactionId::parse(&receipt).expect("the receipt parses");
    store.rollback(&restored).expect("the rollback completes");
    assert_eq!(
        store
            .get(&key("openai"))
            .expect("the credential is readable"),
        Some(SecretString::new(OLD_VALUE))
    );

    fs::remove_dir_all(&root).expect("the temporary directory is removed");
}

// ---------------------------------------------------------------------------
// Semantics
// ---------------------------------------------------------------------------

#[test]
fn commit_keeps_the_new_values_and_clears_the_bookkeeping() {
    let store = MemorySecretStore::new();
    store
        .set(&key("openai"), &SecretString::new(OLD_VALUE))
        .expect("the pre-existing credential is stored");

    let transaction = store.begin_transaction().expect("a transaction starts");
    store
        .put(&transaction, &key("openai"), &SecretString::new(NEW_VALUE))
        .expect("the transactional write lands");
    store
        .put(
            &transaction,
            &key("anthropic"),
            &SecretString::new("sk-ant-new"),
        )
        .expect("the second transactional write lands");
    store.commit(&transaction).expect("the commit completes");

    assert_eq!(
        store
            .get(&key("openai"))
            .expect("the credential is readable"),
        Some(SecretString::new(NEW_VALUE))
    );
    assert_eq!(
        store
            .get(&key("anthropic"))
            .expect("the credential is readable"),
        Some(SecretString::new("sk-ant-new"))
    );
    assert_eq!(
        store
            .accounts(TRANSACTION_SERVICE)
            .expect("the backend enumerates"),
        Vec::<String>::new(),
        "a committed transaction must leave no shadows or manifest"
    );
    assert_eq!(
        store.len(),
        2,
        "only the two real credentials should remain"
    );
}

#[test]
fn rollback_restores_old_values_and_removes_keys_that_did_not_exist() {
    let store = MemorySecretStore::new();
    store
        .set(&key("openai"), &SecretString::new(OLD_VALUE))
        .expect("the pre-existing credential is stored");
    store
        .set(&key("groq"), &SecretString::new("gsk-old"))
        .expect("the pre-existing credential is stored");

    let transaction = store.begin_transaction().expect("a transaction starts");
    store
        .put(&transaction, &key("openai"), &SecretString::new(NEW_VALUE))
        .expect("the overwrite lands");
    store
        .put(
            &transaction,
            &key("brand-new"),
            &SecretString::new("sk-fresh"),
        )
        .expect("the creation lands");
    let removed = store
        .remove(&transaction, &key("groq"))
        .expect("the removal lands");
    assert!(removed, "groq existed, so remove should report true");

    assert_eq!(
        store.get(&key("groq")).expect("the credential is readable"),
        None,
        "the removal should be visible before rollback"
    );

    store
        .rollback(&transaction)
        .expect("the rollback completes");

    assert_eq!(
        store
            .get(&key("openai"))
            .expect("the credential is readable"),
        Some(SecretString::new(OLD_VALUE)),
        "an overwritten key must be restored"
    );
    assert_eq!(
        store.get(&key("groq")).expect("the credential is readable"),
        Some(SecretString::new("gsk-old")),
        "a removed key must be restored"
    );
    assert_eq!(
        store
            .get(&key("brand-new"))
            .expect("the credential is readable"),
        None,
        "a key created inside the transaction must be gone"
    );
    assert_eq!(
        store.len(),
        2,
        "only the two original credentials should remain"
    );
}

#[test]
fn the_first_snapshot_wins_so_rollback_restores_the_original_value() {
    let store = MemorySecretStore::new();
    store
        .set(&key("openai"), &SecretString::new(OLD_VALUE))
        .expect("the pre-existing credential is stored");

    let transaction = store.begin_transaction().expect("a transaction starts");
    store
        .put(
            &transaction,
            &key("openai"),
            &SecretString::new("sk-intermediate"),
        )
        .expect("the first write lands");
    store
        .put(&transaction, &key("openai"), &SecretString::new(NEW_VALUE))
        .expect("the second write lands");
    store
        .rollback(&transaction)
        .expect("the rollback completes");

    assert_eq!(
        store
            .get(&key("openai"))
            .expect("the credential is readable"),
        Some(SecretString::new(OLD_VALUE)),
        "rollback must restore the value from before the transaction, not the intermediate one"
    );
}

#[test]
fn a_committed_transaction_cannot_be_rolled_back_or_extended() {
    let store = MemorySecretStore::new();
    let transaction = store.begin_transaction().expect("a transaction starts");
    store
        .put(&transaction, &key("openai"), &SecretString::new(NEW_VALUE))
        .expect("the transactional write lands");
    store.commit(&transaction).expect("the commit completes");

    assert_eq!(
        store.rollback(&transaction),
        Err(SecretStoreError::UnknownTransaction),
        "a fully cleaned-up transaction is no longer known"
    );
    assert_eq!(
        store.put(&transaction, &key("groq"), &SecretString::new("gsk")),
        Err(SecretStoreError::UnknownTransaction)
    );
    assert_eq!(
        store
            .get(&key("openai"))
            .expect("the credential is readable"),
        Some(SecretString::new(NEW_VALUE)),
        "the committed value must survive the refused rollback"
    );
}

#[test]
fn an_unknown_transaction_is_rejected_rather_than_ignored() {
    let store = MemorySecretStore::new();
    let ghost = TransactionId::parse("0123456789abcdef0123456789abcdef").expect("a valid id");

    assert_eq!(
        store.snapshot(&ghost, &key("openai")),
        Err(SecretStoreError::UnknownTransaction)
    );
    assert_eq!(
        store.commit(&ghost),
        Err(SecretStoreError::UnknownTransaction)
    );
    assert_eq!(
        store.rollback(&ghost),
        Err(SecretStoreError::UnknownTransaction)
    );
}

#[test]
fn transactions_refuse_to_operate_on_the_reserved_namespace() {
    let store = MemorySecretStore::new();
    let transaction = store.begin_transaction().expect("a transaction starts");
    let reserved =
        CredentialKey::new(TRANSACTION_SERVICE, "manifest.deadbeef").expect("a valid reserved key");

    assert_eq!(
        store.put(&transaction, &reserved, &SecretString::new("x")),
        Err(SecretStoreError::InvalidKey)
    );
    assert_eq!(
        store.remove(&transaction, &reserved),
        Err(SecretStoreError::InvalidKey)
    );
    assert_eq!(
        store.snapshot(&transaction, &reserved),
        Err(SecretStoreError::InvalidKey)
    );
}

// ---------------------------------------------------------------------------
// Concurrency
// ---------------------------------------------------------------------------

#[test]
fn two_transactions_on_the_same_key_are_rejected_not_interleaved() {
    let store = MemorySecretStore::new();
    store
        .set(&key("openai"), &SecretString::new(OLD_VALUE))
        .expect("the pre-existing credential is stored");

    let first = store
        .begin_transaction()
        .expect("the first transaction starts");
    let second = store
        .begin_transaction()
        .expect("the second transaction starts");

    store
        .put(&first, &key("openai"), &SecretString::new(NEW_VALUE))
        .expect("the first write lands");
    assert_eq!(
        store.put(&second, &key("openai"), &SecretString::new("sk-other")),
        Err(SecretStoreError::TransactionConflict),
        "the second transaction must not be allowed to touch the held key"
    );

    // A different key is unaffected.
    store
        .put(&second, &key("groq"), &SecretString::new("gsk-new"))
        .expect("an unrelated key is still writable");

    // Once the holder finishes, the key is available again.
    store
        .rollback(&first)
        .expect("the first rollback completes");
    store
        .put(&second, &key("openai"), &SecretString::new("sk-other"))
        .expect("the key is free once the holder finishes");
    store.commit(&second).expect("the second commit completes");

    assert_eq!(
        store
            .get(&key("openai"))
            .expect("the credential is readable"),
        Some(SecretString::new("sk-other"))
    );
}

#[test]
fn concurrent_threads_contending_for_one_key_produce_exactly_one_winner() {
    let store = Arc::new(MemorySecretStore::new());
    store
        .set(&key("openai"), &SecretString::new(OLD_VALUE))
        .expect("the pre-existing credential is stored");

    let threads = 8;
    let start = Arc::new(Barrier::new(threads));
    // Every transaction must still be unresolved while the others are claiming,
    // otherwise a thread that finished early frees the key and the next thread
    // legitimately wins it too. This barrier is what makes the contention real
    // rather than accidental.
    let all_claimed = Arc::new(Barrier::new(threads));
    let outcomes = Arc::new(Mutex::new(Vec::new()));
    let mut handles = Vec::new();

    for index in 0..threads {
        let store = Arc::clone(&store);
        let start = Arc::clone(&start);
        let all_claimed = Arc::clone(&all_claimed);
        let outcomes = Arc::clone(&outcomes);
        handles.push(std::thread::spawn(move || {
            let transaction = store.begin_transaction().expect("a transaction starts");
            start.wait();
            let result = store.put(
                &transaction,
                &key("openai"),
                &SecretString::new(format!("sk-thread-{index}")),
            );
            let won = result.is_ok();
            if !won {
                assert_eq!(
                    result,
                    Err(SecretStoreError::TransactionConflict),
                    "a loser must fail with a conflict, not some other error"
                );
            }
            outcomes
                .lock()
                .expect("the mutex is usable")
                .push((index, won));

            all_claimed.wait();
            if won {
                store.commit(&transaction).expect("the winner commits");
            } else {
                store.rollback(&transaction).expect("a loser rolls back");
            }
        }));
    }
    for handle in handles {
        handle.join().expect("the thread finishes");
    }

    let outcomes = outcomes.lock().expect("the mutex is usable");
    let winners: Vec<usize> = outcomes
        .iter()
        .filter(|(_, won)| *won)
        .map(|(index, _)| *index)
        .collect();
    assert_eq!(
        winners.len(),
        1,
        "exactly one transaction may hold the key, saw {winners:?}"
    );
    assert_eq!(
        store
            .get(&key("openai"))
            .expect("the credential is readable"),
        Some(SecretString::new(format!("sk-thread-{}", winners[0]))),
        "the stored value must be the winner's, not a blend of the racers"
    );
    assert_eq!(
        store
            .accounts(TRANSACTION_SERVICE)
            .expect("the backend enumerates"),
        Vec::<String>::new(),
        "every transaction should have finished cleanly"
    );
    assert_eq!(store.len(), 1);
}

#[test]
fn a_key_released_by_a_finished_transaction_can_be_claimed_again() {
    let store = MemorySecretStore::new();
    store
        .set(&key("openai"), &SecretString::new(OLD_VALUE))
        .expect("the pre-existing credential is stored");

    let first = store.begin_transaction().expect("a transaction starts");
    store
        .put(&first, &key("openai"), &SecretString::new(NEW_VALUE))
        .expect("the first transactional write lands");
    store.commit(&first).expect("the first transaction commits");

    // The conflict rule covers unresolved transactions only. Once the first one
    // is resolved the key is free again, and a store that kept rejecting here
    // would be permanently wedged after a single write.
    let second = store
        .begin_transaction()
        .expect("a second transaction starts");
    store
        .put(
            &second,
            &key("openai"),
            &SecretString::new("sk-third-value"),
        )
        .expect("the key is claimable once the first transaction resolved");
    store
        .commit(&second)
        .expect("the second transaction commits");

    assert_eq!(
        store
            .get(&key("openai"))
            .expect("the credential is readable"),
        Some(SecretString::new("sk-third-value"))
    );
}

// ---------------------------------------------------------------------------
// Backends that cannot be transactional
// ---------------------------------------------------------------------------

/// A store whose bookkeeping deletes fail on demand, used to stop `commit`
/// part-way through its cleanup without touching the engine's internals.
#[derive(Debug)]
struct FailsToCleanUp {
    inner: MemorySecretStore,
    armed: AtomicBool,
}

impl SecretStore for FailsToCleanUp {
    fn backend(&self) -> &'static str {
        "fails-to-clean-up"
    }

    fn get(&self, key: &CredentialKey) -> Result<Option<SecretString>, SecretStoreError> {
        self.inner.get(key)
    }

    fn set(&self, key: &CredentialKey, secret: &SecretString) -> Result<(), SecretStoreError> {
        self.inner.set(key, secret)
    }

    fn insert_if_absent(
        &self,
        key: &CredentialKey,
        secret: &SecretString,
    ) -> Result<bool, SecretStoreError> {
        self.inner.insert_if_absent(key, secret)
    }

    fn delete(&self, key: &CredentialKey) -> Result<bool, SecretStoreError> {
        let bookkeeping =
            key.account().starts_with("manifest.") || key.account().starts_with("shadow.");
        if key.service() == TRANSACTION_SERVICE && bookkeeping && self.armed.load(Ordering::SeqCst)
        {
            return Err(SecretStoreError::AccessDenied {
                backend: "fails-to-clean-up",
            });
        }
        self.inner.delete(key)
    }

    fn accounts(&self, service: &str) -> Result<Vec<String>, SecretStoreError> {
        self.inner.accounts(service)
    }
}

#[test]
fn a_commit_interrupted_during_cleanup_is_rolled_forward_by_recovery() {
    let flaky = FailsToCleanUp {
        inner: MemorySecretStore::new(),
        armed: AtomicBool::new(false),
    };
    flaky
        .set(&key("openai"), &SecretString::new(OLD_VALUE))
        .expect("the pre-existing credential is stored");

    let transaction = flaky.begin_transaction().expect("a transaction starts");
    flaky
        .put(&transaction, &key("openai"), &SecretString::new(NEW_VALUE))
        .expect("the transactional write lands");

    // The manifest flips to committed, then cleanup fails: exactly the state a
    // crash mid-cleanup would leave behind.
    flaky.armed.store(true, Ordering::SeqCst);
    assert_eq!(
        flaky.commit(&transaction),
        Err(SecretStoreError::AccessDenied {
            backend: "fails-to-clean-up"
        })
    );

    // Hand the same underlying data to a healthy store.
    let store = flaky.inner;
    assert!(
        read_manifest(&store).contains("\"state\":\"committed\""),
        "the manifest should be past the commit point"
    );

    let resolved = store.recover_pending().expect("recovery completes");
    assert_eq!(resolved.len(), 1);
    assert_eq!(
        resolved[0].outcome,
        RecoveryOutcome::CommitCompleted,
        "a transaction past its commit point must be completed, never undone"
    );
    assert_eq!(
        store
            .get(&key("openai"))
            .expect("the credential is readable"),
        Some(SecretString::new(NEW_VALUE)),
        "roll-forward must keep the committed value"
    );
    assert_eq!(
        store
            .accounts(TRANSACTION_SERVICE)
            .expect("the backend enumerates"),
        Vec::<String>::new()
    );
}

/// A store that can read and write but cannot enumerate.
#[derive(Debug, Default)]
struct CannotEnumerate(MemorySecretStore);

impl SecretStore for CannotEnumerate {
    fn backend(&self) -> &'static str {
        "cannot-enumerate"
    }

    fn get(&self, key: &CredentialKey) -> Result<Option<SecretString>, SecretStoreError> {
        self.0.get(key)
    }

    fn set(&self, key: &CredentialKey, secret: &SecretString) -> Result<(), SecretStoreError> {
        self.0.set(key, secret)
    }

    fn delete(&self, key: &CredentialKey) -> Result<bool, SecretStoreError> {
        self.0.delete(key)
    }
}

#[test]
fn a_backend_without_enumeration_reports_unsupported_instead_of_pretending() {
    let store = CannotEnumerate::default();

    assert_eq!(
        store.begin_transaction().unwrap_err(),
        SecretStoreError::TransactionUnsupported {
            backend: "cannot-enumerate"
        },
        "callers must be told transactions are unavailable"
    );
    assert_eq!(
        store.recover_pending().unwrap_err(),
        SecretStoreError::TransactionUnsupported {
            backend: "cannot-enumerate"
        }
    );
    assert_eq!(
        store.accounts("gta-claw").unwrap_err(),
        SecretStoreError::EnumerationUnsupported {
            backend: "cannot-enumerate"
        }
    );

    // The non-transactional API is unaffected.
    store
        .set(&key("openai"), &SecretString::new(OLD_VALUE))
        .expect("plain writes still work");
    assert_eq!(
        store.get(&key("openai")).expect("plain reads still work"),
        Some(SecretString::new(OLD_VALUE))
    );
}

#[test]
fn transaction_errors_render_without_revealing_secret_material() {
    let rendered: Vec<String> = [
        SecretStoreError::TransactionUnsupported { backend: "file" },
        SecretStoreError::EnumerationUnsupported { backend: "file" },
        SecretStoreError::UnknownTransaction,
        SecretStoreError::TransactionConflict,
        SecretStoreError::TransactionCommitted,
        SecretStoreError::TransactionAborted,
        SecretStoreError::TransactionCorrupt { backend: "file" },
    ]
    .iter()
    .map(|error| format!("{error} | {error:?}"))
    .collect();

    for text in &rendered {
        assert!(
            !text.contains(OLD_VALUE) && !text.contains(NEW_VALUE) && !text.contains("sk-"),
            "an error rendered secret-looking material: {text}"
        );
    }
    assert_eq!(
        rendered[2],
        "no such transaction is in flight | UnknownTransaction"
    );
    assert_eq!(
        rendered[0],
        "file does not support transactions | TransactionUnsupported { backend: \"file\" }"
    );
}

// ---------------------------------------------------------------------------
// Enumeration
// ---------------------------------------------------------------------------

#[test]
fn the_file_backend_enumerates_only_real_credentials_of_the_requested_service() {
    let root = unique_dir("enumerate");
    let store = FileSecretStore::new(&root).expect("the credential directory opens");
    store
        .set(&key("openai"), &SecretString::new("a"))
        .expect("a credential is stored");
    store
        .set(&key("anthropic"), &SecretString::new("b"))
        .expect("a credential is stored");
    store
        .set(
            &CredentialKey::new("other-service", "openai").expect("a valid key"),
            &SecretString::new("c"),
        )
        .expect("a credential is stored");

    // Debris that must never be mistaken for a credential.
    fs::write(root.join("not-a-credential.txt"), "junk").expect("the debris file is written");
    fs::write(root.join("gta-claw~leftover.cred.tmp"), "junk").expect("the debris file is written");

    let mut accounts = store.accounts("gta-claw").expect("the backend enumerates");
    accounts.sort();
    assert_eq!(accounts, vec!["anthropic".to_owned(), "openai".to_owned()]);

    assert_eq!(
        store
            .accounts("other-service")
            .expect("the backend enumerates"),
        vec!["openai".to_owned()]
    );
    assert_eq!(
        store.accounts("absent").expect("the backend enumerates"),
        Vec::<String>::new()
    );

    fs::remove_dir_all(&root).expect("the temporary directory is removed");
}

#[test]
fn file_names_round_trip_through_encoding_for_awkward_key_components() {
    for (service, account) in [
        ("gta-claw", "openai"),
        ("gta-claw.secret-transaction", "manifest.0123456789abcdef"),
        ("service with spaces", "account/with~separators"),
        ("unicode-服务", "账户"),
        ("dots.and_dashes-", "..."),
    ] {
        let credential = CredentialKey::new(service, account).expect("a valid key");
        let encoded = claw_provider_sdk::secret::encode_key(&credential);
        let decoded =
            claw_provider_sdk::secret::decode_key(&encoded).expect("the name decodes again");
        assert_eq!(
            decoded,
            (service.to_owned(), account.to_owned()),
            "round trip failed for {service}/{account} encoded as {encoded}"
        );
    }
}

#[test]
fn decoding_rejects_names_the_encoder_could_never_produce() {
    for candidate in [
        "no-suffix",
        "missing-separator.cred",
        "a~b~c.cred",
        "bad%zz~account.cred",
        "truncated%a~account.cred",
        "spaces here~account.cred",
    ] {
        assert_eq!(
            claw_provider_sdk::secret::decode_key(candidate),
            None,
            "{candidate:?} should not decode"
        );
    }
}

#[test]
fn the_memory_backend_enumerates_by_service() {
    let store = MemorySecretStore::new();
    store
        .set(&key("openai"), &SecretString::new("a"))
        .expect("a credential is stored");
    store
        .set(
            &CredentialKey::new("elsewhere", "openai").expect("a valid key"),
            &SecretString::new("b"),
        )
        .expect("a credential is stored");

    assert_eq!(
        store.accounts("gta-claw").expect("the backend enumerates"),
        vec!["openai".to_owned()]
    );
    assert_eq!(
        store.accounts("elsewhere").expect("the backend enumerates"),
        vec!["openai".to_owned()]
    );
    assert_eq!(
        store
            .accounts("nothing-here")
            .expect("the backend enumerates"),
        Vec::<String>::new()
    );
}

#[test]
fn recovery_collects_a_shadow_left_without_a_manifest() {
    let store = MemorySecretStore::new();
    // A crash between writing a shadow and recording it in the manifest leaves
    // an entry that no transaction references.
    let orphan = CredentialKey::new(
        TRANSACTION_SERVICE,
        "shadow.0123456789abcdef0123456789abcdef.0",
    )
    .expect("a valid shadow key");
    store
        .set(&orphan, &SecretString::new(OLD_VALUE))
        .expect("the orphan is stored");

    let resolved = store.recover_pending().expect("recovery completes");
    assert_eq!(
        resolved,
        Vec::new(),
        "an orphan is not a transaction, so nothing should be reported"
    );
    assert_eq!(
        store.get(&orphan).expect("the store is readable"),
        None,
        "the orphaned shadow must be collected"
    );
    assert!(store.is_empty());
}

#[test]
fn recovery_resolves_several_transactions_and_stays_idempotent() {
    let store = MemorySecretStore::new();
    store
        .set(&key("openai"), &SecretString::new(OLD_VALUE))
        .expect("a credential is stored");
    store
        .set(&key("groq"), &SecretString::new("gsk-old"))
        .expect("a credential is stored");

    let first = store.begin_transaction().expect("a transaction starts");
    store
        .put(&first, &key("openai"), &SecretString::new(NEW_VALUE))
        .expect("the write lands");
    let second = store.begin_transaction().expect("a transaction starts");
    store
        .remove(&second, &key("groq"))
        .expect("the removal lands");

    let mut resolved = store.recover_pending().expect("recovery completes");
    resolved.sort_by(|left, right| left.id.cmp(&right.id));
    assert_eq!(resolved.len(), 2);
    assert!(
        resolved
            .iter()
            .all(|entry| entry.outcome == RecoveryOutcome::RolledBack)
    );
    let ids: Vec<&TransactionId> = resolved.iter().map(|entry| &entry.id).collect();
    assert!(ids.contains(&&first) && ids.contains(&&second));

    assert_eq!(
        store.get(&key("openai")).expect("the store is readable"),
        Some(SecretString::new(OLD_VALUE))
    );
    assert_eq!(
        store.get(&key("groq")).expect("the store is readable"),
        Some(SecretString::new("gsk-old"))
    );
    assert_eq!(
        store
            .recover_pending()
            .expect("a second recovery completes"),
        Vec::new()
    );
    assert_eq!(store.len(), 2);
}

#[test]
fn a_recovered_transaction_can_no_longer_be_committed() {
    let store = MemorySecretStore::new();
    let transaction = store.begin_transaction().expect("a transaction starts");
    store
        .put(&transaction, &key("openai"), &SecretString::new(NEW_VALUE))
        .expect("the write lands");
    store.recover_pending().expect("recovery completes");

    assert_eq!(
        store.commit(&transaction),
        Err(SecretStoreError::UnknownTransaction),
        "recovery already resolved this transaction"
    );
    assert_eq!(
        store.get(&key("openai")).expect("the store is readable"),
        None
    );
}

#[test]
fn a_corrupt_manifest_is_reported_rather_than_guessed_at() {
    let store = MemorySecretStore::new();
    let transaction = store.begin_transaction().expect("a transaction starts");
    let accounts = manifest_accounts(&store);
    let manifest_key =
        CredentialKey::new(TRANSACTION_SERVICE, accounts[0].clone()).expect("a valid manifest key");
    store
        .set(&manifest_key, &SecretString::new("{not json"))
        .expect("the manifest is overwritten");

    assert_eq!(
        store.commit(&transaction),
        Err(SecretStoreError::TransactionCorrupt { backend: "memory" })
    );
    assert_eq!(
        store.rollback(&transaction),
        Err(SecretStoreError::TransactionCorrupt { backend: "memory" })
    );
}

#[test]
fn a_manifest_from_a_future_version_is_refused() {
    let store = MemorySecretStore::new();
    let transaction = store.begin_transaction().expect("a transaction starts");
    let accounts = manifest_accounts(&store);
    let manifest_key =
        CredentialKey::new(TRANSACTION_SERVICE, accounts[0].clone()).expect("a valid manifest key");
    store
        .set(
            &manifest_key,
            &SecretString::new(r#"{"version":99,"state":"pending","entries":[]}"#),
        )
        .expect("the manifest is overwritten");

    assert_eq!(
        store.rollback(&transaction),
        Err(SecretStoreError::TransactionCorrupt { backend: "memory" }),
        "an unknown manifest version must not be interpreted"
    );
}

#[test]
fn the_reserved_namespace_layout_is_stable() {
    let store = MemorySecretStore::new();
    store
        .set(&key("openai"), &SecretString::new(OLD_VALUE))
        .expect("a credential is stored");
    let transaction = store.begin_transaction().expect("a transaction starts");
    store
        .put(&transaction, &key("openai"), &SecretString::new(NEW_VALUE))
        .expect("the write lands");

    let mut accounts = store
        .accounts(TRANSACTION_SERVICE)
        .expect("the backend enumerates");
    accounts.sort();
    assert_eq!(
        accounts,
        vec![
            format!("manifest.{transaction}"),
            format!("shadow.{transaction}.0"),
        ],
        "the on-store layout is part of the recovery contract"
    );

    let manifest = read_manifest(&store);
    let expected = format!(
        "{{\"version\":1,\"state\":\"pending\",\"entries\":[{}]}}",
        "{\"service\":\"gta-claw\",\"account\":\"openai\",\"slot\":0,\"existed\":true}"
    );
    assert_eq!(manifest, expected);
}

#[test]
fn a_transaction_over_many_keys_rolls_all_of_them_back() {
    let store = MemorySecretStore::new();
    let mut expected = HashMap::new();
    for index in 0..64 {
        let account = format!("provider-{index}");
        let value = format!("sk-original-{index}");
        store
            .set(&key(&account), &SecretString::new(value.clone()))
            .expect("a credential is stored");
        expected.insert(account, value);
    }

    let transaction = store.begin_transaction().expect("a transaction starts");
    for index in 0..64 {
        let account = format!("provider-{index}");
        if index % 2 == 0 {
            store
                .put(
                    &transaction,
                    &key(&account),
                    &SecretString::new(format!("sk-changed-{index}")),
                )
                .expect("the write lands");
        } else {
            store
                .remove(&transaction, &key(&account))
                .expect("the removal lands");
        }
    }
    store
        .rollback(&transaction)
        .expect("the rollback completes");

    for (account, value) in &expected {
        assert_eq!(
            store.get(&key(account)).expect("the store is readable"),
            Some(SecretString::new(value.clone())),
            "{account} was not restored"
        );
    }
    assert_eq!(store.len(), 64);
}

#[test]
fn the_store_directory_is_left_untouched_when_a_transaction_never_starts() {
    let root = unique_dir("untouched");
    let store = FileSecretStore::new(&root).expect("the credential directory opens");
    store
        .set(&key("openai"), &SecretString::new(OLD_VALUE))
        .expect("a credential is stored");
    let before = listing(&root);

    assert_eq!(
        store.recover_pending().expect("recovery completes"),
        Vec::new()
    );
    assert_eq!(
        listing(&root),
        before,
        "recovery must not disturb a clean store"
    );

    fs::remove_dir_all(&root).expect("the temporary directory is removed");
}

fn listing(root: &Path) -> Vec<String> {
    let mut names: Vec<String> = fs::read_dir(root)
        .expect("the directory lists")
        .map(|entry| {
            entry
                .expect("a directory entry")
                .file_name()
                .to_string_lossy()
                .into_owned()
        })
        .collect();
    names.sort();
    names
}

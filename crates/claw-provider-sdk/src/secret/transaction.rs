//! Crash-durable transactions for the [`SecretStore`] port.
//!
//! # Why this exists
//!
//! Callers that migrate credentials need to undo a half-applied change after a
//! crash. Files can be journalled and replayed, but a secret cannot: writing the
//! previous value into a rollback journal would copy plaintext out of the store
//! that is supposed to own it.
//!
//! # How durability is achieved without leaking
//!
//! Every previous value stays **inside the secret store**. Before a key is
//! overwritten it is copied to a *shadow* entry held by the same backend --
//! Windows Credential Manager, the macOS Keychain, or the permission-strict file
//! backend -- so it keeps exactly the protection the platform gives every other
//! credential. The bookkeeping that says which shadow belongs to which key (the
//! *manifest*) is itself stored as an ordinary entry in that backend.
//!
//! Consequently the only thing a caller ever needs to persist in its own journal
//! or receipt is the opaque [`TransactionId`]. No plaintext, and no ciphertext
//! secret material, is written anywhere outside the backend. The manifest holds
//! key *names* and a shadow slot index; it never holds a value.
//!
//! # Crash model
//!
//! Each step is a single-entry write, and the manifest write is the commit point
//! of that step:
//!
//! 1. the shadow copy is written, then
//! 2. the manifest records it, and only then
//! 3. the live key is modified.
//!
//! A crash before step 2 leaves an orphaned shadow that
//! [`recover_pending`](SecretStore::recover_pending) garbage-collects. A crash
//! between steps 2 and 3 makes rollback restore a value that is already current,
//! which is harmless. A crash after step 3 is the case rollback exists for.
//!
//! [`commit`](SecretStore::commit) flips the manifest to `committed` before
//! deleting anything, so a crash mid-cleanup rolls *forward*; recovery never has
//! to guess which side of the commit point it died on.
//!
//! # Backends that cannot do this
//!
//! Transactions need to enumerate the reserved namespace. A backend that cannot
//! enumerate reports [`SecretStoreError::TransactionUnsupported`] from
//! [`begin_transaction`](SecretStore::begin_transaction) rather than silently
//! behaving non-transactionally.

use std::collections::BTreeSet;
use std::collections::hash_map::RandomState;
use std::fmt::{self, Display, Formatter};
use std::hash::{BuildHasher, Hasher};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};

use super::{CredentialKey, SecretStore, SecretStoreError, SecretString};

/// Service namespace reserved for transaction bookkeeping.
///
/// Transactional operations refuse to act on a key in this namespace, so a
/// caller cannot corrupt the journal through the public API.
pub const TRANSACTION_SERVICE: &str = "gta-claw.secret-transaction";

const MANIFEST_PREFIX: &str = "manifest.";
const SHADOW_PREFIX: &str = "shadow.";
const LOCK_ACCOUNT: &str = "lock.claim";
const MANIFEST_VERSION: u32 = 1;
const ID_HEX_LEN: usize = 32;

/// How long [`ClaimLock::acquire`] waits before giving up.
///
/// The critical section is a handful of store operations, so a wait anywhere
/// near this long means the holder died mid-snapshot; the caller is told to run
/// recovery rather than blocking forever.
const LOCK_TIMEOUT: Duration = Duration::from_secs(10);
const LOCK_POLL: Duration = Duration::from_millis(2);

/// Opaque identifier of an in-flight transaction.
///
/// This is the only value a caller may write to its own journal or receipt. It
/// reveals nothing about the keys or the values a transaction touches.
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct TransactionId(String);

impl TransactionId {
    /// Returns the identifier as a 32-character lowercase hexadecimal string.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// Parses an identifier previously produced by this module.
    ///
    /// Returns `None` unless the input is exactly 32 lowercase hexadecimal
    /// digits, which keeps a hostile or corrupted account name from being turned
    /// back into a usable identifier.
    #[must_use]
    pub fn parse(value: &str) -> Option<Self> {
        let usable = value.len() == ID_HEX_LEN
            && value
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte));
        usable.then(|| Self(value.to_owned()))
    }

    fn generate() -> Self {
        static COUNTER: AtomicU64 = AtomicU64::new(0);

        let high = RandomState::new().build_hasher().finish();
        // The nanosecond count only feeds the entropy mix, so the low 64 bits
        // are as good as the full `u128` and the mask keeps the conversion total.
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_or(0, |elapsed| {
                u64::try_from(elapsed.as_nanos() & u128::from(u64::MAX)).unwrap_or(u64::MAX)
            });
        let low = RandomState::new().build_hasher().finish()
            ^ nanos.rotate_left(17)
            ^ COUNTER.fetch_add(1, Ordering::Relaxed);
        Self(format!("{high:016x}{low:016x}"))
    }
}

impl Display for TransactionId {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.0)
    }
}

/// State a transaction manifest can be in.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum TransactionState {
    /// Started; changes may still be added and rollback is possible.
    Pending,
    /// Past the commit point; recovery completes it rather than undoing it.
    Committed,
    /// Rolling back; recovery finishes the rollback.
    Aborting,
}

/// How [`recover_pending`](SecretStore::recover_pending) resolved a transaction.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RecoveryOutcome {
    /// The transaction had not reached its commit point, so it was undone.
    RolledBack,
    /// The transaction was past its commit point, so cleanup was finished.
    CommitCompleted,
}

/// One transaction resolved during recovery.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RecoveredTransaction {
    /// Identifier of the resolved transaction.
    pub id: TransactionId,
    /// What recovery did with it.
    pub outcome: RecoveryOutcome,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
struct Manifest {
    version: u32,
    state: TransactionState,
    entries: Vec<ManifestEntry>,
}

/// A key enrolled in a transaction.
///
/// Deliberately holds no value: only the key names, the shadow slot and whether
/// the key existed beforehand.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
struct ManifestEntry {
    service: String,
    account: String,
    slot: u32,
    existed: bool,
}

impl ManifestEntry {
    fn matches(&self, key: &CredentialKey) -> bool {
        self.service == key.service() && self.account == key.account()
    }

    fn live_key(&self) -> Result<CredentialKey, SecretStoreError> {
        CredentialKey::new(self.service.clone(), self.account.clone())
    }
}

fn reserved_key(account: String) -> Result<CredentialKey, SecretStoreError> {
    CredentialKey::new(TRANSACTION_SERVICE, account)
}

fn manifest_key(id: &TransactionId) -> Result<CredentialKey, SecretStoreError> {
    reserved_key(format!("{MANIFEST_PREFIX}{id}"))
}

fn shadow_key(id: &TransactionId, slot: u32) -> Result<CredentialKey, SecretStoreError> {
    reserved_key(format!("{SHADOW_PREFIX}{id}.{slot}"))
}

fn corrupt<S: SecretStore + ?Sized>(store: &S) -> SecretStoreError {
    SecretStoreError::TransactionCorrupt {
        backend: store.backend(),
    }
}

/// Confirms the backend can enumerate its reserved namespace, and returns the
/// accounts currently in it.
fn reserved_accounts<S: SecretStore + ?Sized>(store: &S) -> Result<Vec<String>, SecretStoreError> {
    match store.accounts(TRANSACTION_SERVICE) {
        Ok(accounts) => Ok(accounts),
        Err(SecretStoreError::EnumerationUnsupported { backend }) => {
            Err(SecretStoreError::TransactionUnsupported { backend })
        }
        Err(error) => Err(error),
    }
}

fn load_manifest<S: SecretStore + ?Sized>(
    store: &S,
    id: &TransactionId,
) -> Result<Option<Manifest>, SecretStoreError> {
    let Some(raw) = store.get(&manifest_key(id)?)? else {
        return Ok(None);
    };
    let manifest: Manifest = serde_json::from_str(raw.expose()).map_err(|_| corrupt(store))?;
    if manifest.version != MANIFEST_VERSION {
        return Err(corrupt(store));
    }
    Ok(Some(manifest))
}

fn save_manifest<S: SecretStore + ?Sized>(
    store: &S,
    id: &TransactionId,
    manifest: &Manifest,
) -> Result<(), SecretStoreError> {
    let encoded = serde_json::to_string(manifest).map_err(|_| corrupt(store))?;
    store.set(&manifest_key(id)?, &SecretString::new(encoded))
}

/// Starts a transaction. See [`SecretStore::begin_transaction`].
pub(super) fn begin<S: SecretStore + ?Sized>(store: &S) -> Result<TransactionId, SecretStoreError> {
    reserved_accounts(store)?;
    let id = TransactionId::generate();
    if store.get(&manifest_key(&id)?)?.is_some() {
        return Err(SecretStoreError::Backend {
            backend: store.backend(),
            detail: "a transaction identifier was reused",
        });
    }
    save_manifest(
        store,
        &id,
        &Manifest {
            version: MANIFEST_VERSION,
            state: TransactionState::Pending,
            entries: Vec::new(),
        },
    )?;
    Ok(id)
}

fn require_pending<S: SecretStore + ?Sized>(
    store: &S,
    id: &TransactionId,
) -> Result<Manifest, SecretStoreError> {
    let manifest = load_manifest(store, id)?.ok_or(SecretStoreError::UnknownTransaction)?;
    match manifest.state {
        TransactionState::Pending => Ok(manifest),
        TransactionState::Committed => Err(SecretStoreError::TransactionCommitted),
        TransactionState::Aborting => Err(SecretStoreError::TransactionAborted),
    }
}

/// Guards the critical section that reads every manifest and then writes one.
///
/// Conflict detection is a scan followed by a write. Without mutual exclusion,
/// two transactions can both scan before either writes and both conclude the key
/// is free, which is exactly what
/// `concurrent_threads_contending_for_one_key_produce_exactly_one_winner`
/// caught. The lock is an entry in the reserved namespace claimed through
/// [`SecretStore::insert_if_absent`], so on the file backend it is an `O_EXCL`
/// create and the exclusion holds across processes, not just across threads.
///
/// A holder that dies leaves the entry behind. Waiters give up after
/// [`LOCK_TIMEOUT`] with [`SecretStoreError::TransactionConflict`], and
/// [`recover_pending`] breaks a lock that outlived its holder.
struct ClaimLock<'store, S: SecretStore + ?Sized> {
    store: &'store S,
}

impl<'store, S: SecretStore + ?Sized> ClaimLock<'store, S> {
    fn key() -> Result<CredentialKey, SecretStoreError> {
        reserved_key(LOCK_ACCOUNT.to_owned())
    }

    /// Claims the lock, waiting for a live holder to finish.
    fn acquire(store: &'store S, holder: &TransactionId) -> Result<Self, SecretStoreError> {
        Self::claim(store, holder.to_string(), false)
    }

    /// Claims the lock, breaking it if it outlived [`LOCK_TIMEOUT`].
    ///
    /// Only recovery may do this: its whole purpose is to resolve state a dead
    /// process left behind, and a lock held for longer than the timeout is part
    /// of that state.
    fn acquire_breaking_stale(store: &'store S) -> Result<Self, SecretStoreError> {
        Self::claim(store, String::from("recovery"), true)
    }

    fn claim(
        store: &'store S,
        holder: String,
        break_stale: bool,
    ) -> Result<Self, SecretStoreError> {
        let key = Self::key()?;
        let holder = SecretString::new(holder);
        let deadline = Instant::now() + LOCK_TIMEOUT;
        loop {
            if store.insert_if_absent(&key, &holder)? {
                return Ok(Self { store });
            }
            if Instant::now() >= deadline {
                if !break_stale {
                    return Err(SecretStoreError::TransactionConflict);
                }
                store.delete(&key)?;
                if store.insert_if_absent(&key, &holder)? {
                    return Ok(Self { store });
                }
                return Err(SecretStoreError::TransactionConflict);
            }
            std::thread::sleep(LOCK_POLL);
        }
    }
}

impl<S: SecretStore + ?Sized> Drop for ClaimLock<'_, S> {
    fn drop(&mut self) {
        // Releasing is best effort: a failure here leaves a stale lock, which
        // recovery breaks. Propagating it would mask the caller's real result.
        if let Ok(key) = Self::key() {
            let _ = self.store.delete(&key);
        }
    }
}

/// Rejects a second transaction touching a key another pending transaction owns.
///
/// The check reads the manifests out of the store rather than any in-process
/// table, so it also serialises transactions started by different processes.
fn detect_conflict<S: SecretStore + ?Sized>(
    store: &S,
    id: &TransactionId,
    key: &CredentialKey,
) -> Result<(), SecretStoreError> {
    for account in reserved_accounts(store)? {
        let Some(raw) = account.strip_prefix(MANIFEST_PREFIX) else {
            continue;
        };
        let Some(other) = TransactionId::parse(raw) else {
            continue;
        };
        if &other == id {
            continue;
        }
        let Some(manifest) = load_manifest(store, &other)? else {
            continue;
        };
        if manifest.state == TransactionState::Committed {
            continue;
        }
        if manifest.entries.iter().any(|entry| entry.matches(key)) {
            return Err(SecretStoreError::TransactionConflict);
        }
    }
    Ok(())
}

/// Copies a key's current value into the transaction. See
/// [`SecretStore::snapshot`].
pub(super) fn snapshot<S: SecretStore + ?Sized>(
    store: &S,
    id: &TransactionId,
    key: &CredentialKey,
) -> Result<(), SecretStoreError> {
    if key.service() == TRANSACTION_SERVICE {
        return Err(SecretStoreError::InvalidKey);
    }
    if require_pending(store, id)?
        .entries
        .iter()
        .any(|entry| entry.matches(key))
    {
        return Ok(());
    }

    // Everything from here to the manifest write must be atomic against other
    // transactions, or two of them can both find the key unclaimed.
    let _claim = ClaimLock::acquire(store, id)?;

    // Re-read under the lock: a transaction that won the race may have added
    // this very key while this call was waiting.
    let mut manifest = require_pending(store, id)?;
    if manifest.entries.iter().any(|entry| entry.matches(key)) {
        return Ok(());
    }
    detect_conflict(store, id, key)?;

    let slot = u32::try_from(manifest.entries.len()).map_err(|_| SecretStoreError::Backend {
        backend: store.backend(),
        detail: "the transaction holds too many keys",
    })?;
    let current = store.get(key)?;
    if let Some(value) = &current {
        store.set(&shadow_key(id, slot)?, value)?;
    }
    manifest.entries.push(ManifestEntry {
        service: key.service().to_owned(),
        account: key.account().to_owned(),
        slot,
        existed: current.is_some(),
    });
    save_manifest(store, id, &manifest)
}

/// Writes a value inside a transaction. See [`SecretStore::put`].
pub(super) fn put<S: SecretStore + ?Sized>(
    store: &S,
    id: &TransactionId,
    key: &CredentialKey,
    secret: &SecretString,
) -> Result<(), SecretStoreError> {
    snapshot(store, id, key)?;
    store.set(key, secret)
}

/// Removes a value inside a transaction. See [`SecretStore::remove`].
pub(super) fn remove<S: SecretStore + ?Sized>(
    store: &S,
    id: &TransactionId,
    key: &CredentialKey,
) -> Result<bool, SecretStoreError> {
    snapshot(store, id, key)?;
    store.delete(key)
}

fn discard_bookkeeping<S: SecretStore + ?Sized>(
    store: &S,
    id: &TransactionId,
    manifest: &Manifest,
) -> Result<(), SecretStoreError> {
    for entry in &manifest.entries {
        store.delete(&shadow_key(id, entry.slot)?)?;
    }
    store.delete(&manifest_key(id)?)?;
    Ok(())
}

/// Commits a transaction. See [`SecretStore::commit`].
pub(super) fn commit<S: SecretStore + ?Sized>(
    store: &S,
    id: &TransactionId,
) -> Result<(), SecretStoreError> {
    let mut manifest = load_manifest(store, id)?.ok_or(SecretStoreError::UnknownTransaction)?;
    match manifest.state {
        TransactionState::Aborting => return Err(SecretStoreError::TransactionAborted),
        TransactionState::Pending => {
            manifest.state = TransactionState::Committed;
            save_manifest(store, id, &manifest)?;
        }
        TransactionState::Committed => {}
    }
    discard_bookkeeping(store, id, &manifest)
}

fn finish_rollback<S: SecretStore + ?Sized>(
    store: &S,
    id: &TransactionId,
    manifest: &Manifest,
) -> Result<(), SecretStoreError> {
    for entry in manifest.entries.iter().rev() {
        let live = entry.live_key()?;
        if entry.existed {
            let shadow = store
                .get(&shadow_key(id, entry.slot)?)?
                .ok_or_else(|| corrupt(store))?;
            store.set(&live, &shadow)?;
        } else {
            store.delete(&live)?;
        }
    }
    discard_bookkeeping(store, id, manifest)
}

/// Rolls a transaction back. See [`SecretStore::rollback`].
pub(super) fn rollback<S: SecretStore + ?Sized>(
    store: &S,
    id: &TransactionId,
) -> Result<(), SecretStoreError> {
    let mut manifest = load_manifest(store, id)?.ok_or(SecretStoreError::UnknownTransaction)?;
    if manifest.state == TransactionState::Committed {
        return Err(SecretStoreError::TransactionCommitted);
    }
    if manifest.state == TransactionState::Pending {
        manifest.state = TransactionState::Aborting;
        save_manifest(store, id, &manifest)?;
    }
    finish_rollback(store, id, &manifest)
}

/// Resolves every transaction left in flight. See
/// [`SecretStore::recover_pending`].
pub(super) fn recover_pending<S: SecretStore + ?Sized>(
    store: &S,
) -> Result<Vec<RecoveredTransaction>, SecretStoreError> {
    // Held for the whole sweep so a transaction cannot add a shadow that the
    // orphan pass below would then mistake for debris. Breaking a stale lock is
    // recovery's job: a lock outliving its holder is exactly the kind of
    // leftover state this call exists to clear.
    let _claim = ClaimLock::acquire_breaking_stale(store)?;

    let accounts = reserved_accounts(store)?;
    let mut known = BTreeSet::new();
    for account in &accounts {
        if let Some(raw) = account.strip_prefix(MANIFEST_PREFIX)
            && let Some(id) = TransactionId::parse(raw)
        {
            known.insert(id);
        }
    }

    let mut recovered = Vec::new();
    for id in &known {
        let Some(mut manifest) = load_manifest(store, id)? else {
            continue;
        };
        let outcome = match manifest.state {
            TransactionState::Committed => {
                discard_bookkeeping(store, id, &manifest)?;
                RecoveryOutcome::CommitCompleted
            }
            TransactionState::Pending | TransactionState::Aborting => {
                if manifest.state == TransactionState::Pending {
                    manifest.state = TransactionState::Aborting;
                    save_manifest(store, id, &manifest)?;
                }
                finish_rollback(store, id, &manifest)?;
                RecoveryOutcome::RolledBack
            }
        };
        recovered.push(RecoveredTransaction {
            id: id.clone(),
            outcome,
        });
    }

    // A crash between writing a shadow and recording it leaves a shadow that no
    // manifest references. Those are the only entries left in the namespace now.
    for account in accounts {
        let Some(raw) = account.strip_prefix(SHADOW_PREFIX) else {
            continue;
        };
        let orphaned = raw
            .rsplit_once('.')
            .and_then(|(raw_id, _)| TransactionId::parse(raw_id))
            .is_some_and(|id| !known.contains(&id));
        if orphaned {
            store.delete(&reserved_key(account)?)?;
        }
    }
    Ok(recovered)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn identifiers_are_unique_and_parse_round_trips() {
        let mut seen = BTreeSet::new();
        for _ in 0..1_000 {
            let id = TransactionId::generate();
            assert_eq!(
                id.as_str().len(),
                ID_HEX_LEN,
                "identifier {id} is malformed"
            );
            assert_eq!(
                TransactionId::parse(id.as_str()).as_ref(),
                Some(&id),
                "identifier {id} did not survive a parse round trip"
            );
            assert!(
                seen.insert(id.clone()),
                "identifier {id} was generated twice"
            );
        }
        assert_eq!(seen.len(), 1_000);
    }

    #[test]
    fn parse_rejects_anything_that_is_not_a_generated_identifier() {
        for candidate in [
            "",
            "0123456789abcdef0123456789abcde",   // 31 digits
            "0123456789abcdef0123456789abcdef0", // 33 digits
            "0123456789ABCDEF0123456789abcdef",  // uppercase
            "0123456789abcdef0123456789abcdeg",  // out-of-range digit
            "../../etc/passwd0123456789abcdef",
        ] {
            assert_eq!(
                TransactionId::parse(candidate),
                None,
                "{candidate:?} was accepted as an identifier"
            );
        }
    }

    #[test]
    fn the_manifest_serialization_carries_key_names_but_no_values() {
        let manifest = Manifest {
            version: MANIFEST_VERSION,
            state: TransactionState::Pending,
            entries: vec![ManifestEntry {
                service: "gta-claw".to_owned(),
                account: "openai".to_owned(),
                slot: 0,
                existed: true,
            }],
        };
        let encoded = serde_json::to_string(&manifest).expect("the manifest serializes");
        assert_eq!(
            encoded,
            r#"{"version":1,"state":"pending","entries":[{"service":"gta-claw","account":"openai","slot":0,"existed":true}]}"#
        );
        let decoded: Manifest = serde_json::from_str(&encoded).expect("the manifest parses");
        assert_eq!(decoded, manifest);
    }

    #[test]
    fn reserved_account_names_are_built_from_the_identifier_alone() {
        let id = TransactionId::parse("0123456789abcdef0123456789abcdef").expect("a valid id");
        let manifest = manifest_key(&id).expect("a valid manifest key");
        assert_eq!(manifest.service(), TRANSACTION_SERVICE);
        assert_eq!(
            manifest.account(),
            "manifest.0123456789abcdef0123456789abcdef"
        );
        let shadow = shadow_key(&id, 7).expect("a valid shadow key");
        assert_eq!(shadow.service(), TRANSACTION_SERVICE);
        assert_eq!(
            shadow.account(),
            "shadow.0123456789abcdef0123456789abcdef.7"
        );
    }
}

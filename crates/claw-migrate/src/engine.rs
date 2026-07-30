use std::collections::{BTreeMap, BTreeSet};
use std::error::Error;
use std::fmt::{self, Debug, Display, Formatter};
use std::fs::{self, File, OpenOptions};
use std::io::{self, Read, Write};
use std::ops::Range;
use std::path::{Component, Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

use claw_config::{
    WriteOutcome, atomic_exchange_supported,
    copy_file_atomically as copy_config_file_atomically, exchange_paths_atomically,
    rename_path_no_replace, write_bytes_atomically,
};
use ed25519_dalek::{Signer, SigningKey};
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};
use sha2::{Digest, Sha256};

use crate::contract::{
    Artifact, ArtifactKind, ArtifactSignature, ContractViolation, Diagnostic, DiagnosticSeverity,
    InputKind, MIGRATION_CONTRACT_VERSION, MigrationInput, MigrationResult, MigrationStatus,
};
use crate::platform::PlatformPaths;

static BACKUP_SEQUENCE: AtomicU64 = AtomicU64::new(0);
const HASH_BUFFER_BYTES: usize = 64 * 1024;
const RECOVERY_SCHEMA_VERSION: u32 = 1;

/// Confidence assigned to a detected migration source.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DetectionConfidence {
    /// A directory exists but no strong marker was found.
    Low,
    /// Customizations or secondary state were found.
    Medium,
    /// Primary provider configuration was found.
    High,
}

/// Provider source detection result.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Detection {
    /// Whether usable source state was found.
    pub found: bool,
    /// Selected source root.
    pub source: PathBuf,
    /// Detection confidence.
    pub confidence: DetectionConfidence,
    /// Secret-free explanation.
    pub message: String,
}

/// Side-effect-free planning context.
pub struct PlanContext<'a> {
    /// Injectable host paths.
    pub paths: &'a dyn PlatformPaths,
    /// Authoritative explicit source; defaults are ignored when this is present.
    pub source: Option<&'a Path>,
    /// GTA Claw migration target root.
    pub target_root: &'a Path,
    /// Whether existing targets may be replaced.
    pub overwrite: bool,
    /// Artifact signer.
    pub signer: &'a dyn ArtifactSigner,
}

/// Mutable apply and rollback context.
pub struct ApplyContext<'a> {
    /// GTA Claw migration target root.
    pub target_root: &'a Path,
    /// Directory in which verified backups are created.
    pub backup_root: &'a Path,
    /// Whether existing targets may be replaced.
    pub overwrite: bool,
    /// Secret persistence adapter.
    pub secret_store: &'a mut dyn SecretStore,
}

/// Side-effect-free migration plan.
///
/// Serialization intentionally emits only the flattened frozen
/// [`MigrationResult`] shape. Filesystem operations remain internal.
#[derive(Serialize)]
pub struct MigrationPlan {
    /// Exact frozen result.
    #[serde(flatten)]
    pub result: MigrationResult,
    #[serde(skip)]
    pub(crate) provider_id: &'static str,
    #[serde(skip)]
    pub(crate) source_root: PathBuf,
    #[serde(skip)]
    pub(crate) target_root: PathBuf,
    #[serde(skip)]
    pub(crate) operations: Vec<MigrationOperation>,
    #[serde(skip)]
    source_digests: Vec<(PathBuf, String)>,
}

/// The plan's `Debug` output is deliberately a redacted summary: the operation
/// list and the recorded source digests are reported as counts so that neither a
/// migrated secret nor the full inventory of a user's profile can reach a log
/// line through a plan.
impl Debug for MigrationPlan {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("MigrationPlan")
            .field("result", &self.result)
            .field("provider_id", &self.provider_id)
            .field("source_root", &self.source_root)
            .field("target_root", &self.target_root)
            .field("operation_count", &self.operations.len())
            .field("source_digest_count", &self.source_digests.len())
            .finish_non_exhaustive()
    }
}

impl MigrationPlan {
    /// Number of planned mutations.
    #[must_use]
    pub const fn operation_count(&self) -> usize {
        self.operations.len()
    }

    /// Builds a non-frozen summary for guided dry-run output.
    #[must_use]
    pub fn report(&self) -> MigrationReport<'_> {
        let mut operation_kinds = BTreeMap::new();
        for operation in &self.operations {
            *operation_kinds.entry(operation.kind()).or_insert(0) += 1;
        }
        MigrationReport {
            provider_id: self.provider_id,
            operation_count: self.operations.len(),
            operation_kinds,
            result: &self.result,
        }
    }
}

/// Diagnostics-oriented migration plan summary.
///
/// This report is additive and intentionally separate from the frozen
/// [`MigrationResult`] serialization emitted by [`MigrationPlan`].
#[derive(Debug, Serialize)]
pub struct MigrationReport<'a> {
    /// Provider that produced the plan.
    pub provider_id: &'static str,
    /// Total planned mutations.
    pub operation_count: usize,
    /// Planned mutation counts grouped by stable kind label.
    pub operation_kinds: BTreeMap<&'static str, usize>,
    /// Frozen migration result and its diagnostics.
    #[serde(flatten)]
    pub result: &'a MigrationResult,
}

/// Secret bytes whose formatters are always redacted.
#[derive(Clone, Eq, PartialEq)]
pub struct SecretValue(Vec<u8>);

impl SecretValue {
    /// Copies sensitive bytes into an owned redacting wrapper.
    #[must_use]
    pub fn new(value: &[u8]) -> Self {
        Self(value.to_vec())
    }

    /// Exposes bytes only to secret-store adapters.
    #[must_use]
    pub fn expose(&self) -> &[u8] {
        &self.0
    }
}

impl Debug for SecretValue {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter.write_str("SecretValue([REDACTED])")
    }
}

impl Drop for SecretValue {
    fn drop(&mut self) {
        self.0.fill(0);
    }
}

/// Secret-store adapter failure that must not contain secret values.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SecretStoreError {
    message: String,
}

impl SecretStoreError {
    /// Creates a failure from a secret-free message.
    #[must_use]
    pub fn new(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
        }
    }
}

impl Display for SecretStoreError {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.message)
    }
}

impl Error for SecretStoreError {}

/// Durable transactional secret persistence used by apply and recovery.
pub trait SecretStore {
    /// Begins or resumes an idempotent durable transaction.
    ///
    /// # Errors
    ///
    /// Returns a [`SecretStoreError`] when the transaction's undo record cannot
    /// be created or reopened durably.
    fn begin_transaction(&mut self, transaction_id: &str) -> Result<(), SecretStoreError>;
    /// Durably stages a value without making it visible to normal reads.
    ///
    /// # Errors
    ///
    /// Returns a [`SecretStoreError`] when either the value or its exact
    /// pre-transaction undo state cannot be made durable. Repeated staging of the
    /// same transaction and key must be idempotent.
    fn stage(
        &mut self,
        transaction_id: &str,
        id: &str,
        value: SecretValue,
    ) -> Result<String, SecretStoreError>;
    /// Atomically publishes every value staged by a durable transaction.
    ///
    /// # Errors
    ///
    /// Returns a [`SecretStoreError`] when commit cannot be confirmed. This
    /// operation must be idempotent for restart recovery.
    fn commit_transaction(&mut self, transaction_id: &str) -> Result<(), SecretStoreError>;
    /// Restores the exact pre-transaction values, even after commit.
    ///
    /// # Errors
    ///
    /// Returns a [`SecretStoreError`] when durable rollback cannot complete.
    /// This operation must be idempotent.
    fn rollback_transaction(&mut self, transaction_id: &str) -> Result<(), SecretStoreError>;
}

/// Artifact signature port.
pub trait ArtifactSigner {
    /// Signs a lowercase artifact digest.
    ///
    /// # Errors
    ///
    /// Returns [`MigrationError::Signing`] when `sha256` is not 64 lowercase
    /// hexadecimal characters, or when the signing key is unavailable or refuses
    /// the operation. A plan is only ever emitted with a valid signature, so a
    /// failure here aborts planning instead of producing an unsigned manifest.
    fn sign(&self, sha256: &str) -> Result<ArtifactSignature, MigrationError>;
}

/// Ed25519 artifact signer backed by an in-memory signing key.
pub struct Ed25519ArtifactSigner {
    key_id: String,
    key: SigningKey,
}

impl Ed25519ArtifactSigner {
    /// Constructs a signer from a 32-byte Ed25519 secret key.
    #[must_use]
    pub fn from_bytes(key_id: impl Into<String>, secret_key: &[u8; 32]) -> Self {
        Self {
            key_id: key_id.into(),
            key: SigningKey::from_bytes(secret_key),
        }
    }
}

impl Debug for Ed25519ArtifactSigner {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("Ed25519ArtifactSigner")
            .field("key_id", &self.key_id)
            .field("key", &"[REDACTED]")
            .finish()
    }
}

impl ArtifactSigner for Ed25519ArtifactSigner {
    fn sign(&self, sha256: &str) -> Result<ArtifactSignature, MigrationError> {
        if !valid_digest(sha256) {
            return Err(MigrationError::Signing(
                "artifact digest is not lowercase SHA-256".to_owned(),
            ));
        }
        let signature = self.key.sign(sha256.as_bytes()).to_bytes();
        Ok(ArtifactSignature {
            algorithm: "ed25519".to_owned(),
            key_id: self.key_id.clone(),
            value: encode_hex(&signature),
        })
    }
}

/// Common migration provider lifecycle.
pub trait MigrationProvider {
    /// Stable provider identifier.
    fn id(&self) -> &'static str;
    /// Detects source state without mutation.
    ///
    /// # Errors
    ///
    /// Returns [`MigrationError::Io`] when a candidate directory exists but
    /// cannot be listed, typically because the profile is owned by another user
    /// or is on an unmounted volume. A profile that is simply absent is not an
    /// error: it is reported as [`Detection::found`] being `false`.
    fn detect(
        &self,
        paths: &dyn PlatformPaths,
        source: Option<&Path>,
    ) -> Result<Detection, MigrationError>;
    /// Produces a side-effect-free plan.
    ///
    /// # Errors
    ///
    /// Returns [`MigrationError::SourceNotFound`] when no state for this
    /// provider exists at the searched root — pass an explicit source if the
    /// tool keeps its configuration somewhere non-standard.
    /// [`MigrationError::InvalidInput`] names the one source file that is
    /// malformed (unparseable JSON, or an environment line that is not
    /// `KEY=VALUE`); repair or remove that file and plan again.
    /// [`MigrationError::Symlink`] and [`MigrationError::Io`] report a source
    /// tree that cannot be read safely, and [`MigrationError::Contract`] or
    /// [`MigrationError::Signing`] mean the plan itself could not be signed and
    /// validated.
    ///
    /// A refusal that is expected — an existing target without `overwrite`, or
    /// an executable legacy artifact — is *not* an error. It is returned as an
    /// `Ok` plan whose status is [`MigrationStatus::Failed`] carrying the
    /// `TARGET_EXISTS`, `NO_MIGRATABLE_STATE`, or
    /// `EXECUTABLE_ARTIFACT_REQUIRES_PORT` diagnostic, so the reason survives
    /// serialization into the frozen result contract.
    fn plan(&self, context: &PlanContext<'_>) -> Result<MigrationPlan, MigrationError>;
    /// Applies a previously reviewed plan transactionally.
    ///
    /// # Errors
    ///
    /// Returns [`MigrationError::ProviderMismatch`] when `plan` came from a
    /// different provider, and [`MigrationError::PlanNotApplicable`] when it is
    /// not a successful plan with at least one operation — only a reviewed,
    /// validated plan may be applied.
    /// [`MigrationError::Conflict`] means a target already exists and
    /// `overwrite` was not requested; review the file and re-run with overwrite
    /// if replacing it is intended. [`MigrationError::InvalidInput`] means the
    /// source changed between the dry run and apply, so the reviewed plan no
    /// longer describes what would be written; re-plan.
    /// [`MigrationError::UnsafeTarget`] and [`MigrationError::Symlink`] mean the
    /// target path escapes the migration root or passes through a symbolic link,
    /// and [`MigrationError::BackupVerification`] means a verified backup of an
    /// existing target could not be taken — in all three cases nothing has been
    /// written.
    ///
    /// [`MigrationError::ApplyFailed`] is the only variant that can be raised
    /// after writing began. It carries the original reason and every automatic
    /// filesystem or secret-transaction rollback failure. An empty rollback list
    /// means the target was restored to its pre-apply state.
    fn apply(
        &self,
        context: &mut ApplyContext<'_>,
        plan: &MigrationPlan,
    ) -> Result<ApplyReceipt, MigrationError> {
        if plan.provider_id != self.id() {
            return Err(MigrationError::ProviderMismatch);
        }
        apply_plan(context, plan)
    }
    /// Restores the pre-apply filesystem and secret-store state.
    ///
    /// # Errors
    ///
    /// Returns [`MigrationError::ProviderMismatch`] when `receipt` came from a
    /// different provider. [`MigrationError::Conflict`] means a target changed
    /// after apply — a concurrent edit, or a file whose post-apply state could
    /// not be read — and rollback refuses to overwrite work it did not make;
    /// restore that path from the receipt's backup directory yourself.
    /// [`MigrationError::BackupVerification`] means a backup no longer matches
    /// the digest recorded when it was taken, so it is not trustworthy enough to
    /// restore. [`MigrationError::SecretStore`] means the durable secret
    /// transaction could not be rolled back.
    fn rollback(
        &self,
        context: &mut ApplyContext<'_>,
        receipt: &ApplyReceipt,
    ) -> Result<(), MigrationError> {
        if receipt.provider_id != self.id() {
            return Err(MigrationError::ProviderMismatch);
        }
        let target_root = normalize_target_root(context.target_root)?;
        if receipt.target_root != target_root {
            return Err(MigrationError::UnsafeTarget(receipt.target_root.clone()));
        }
        rollback_receipt(context, receipt, &target_root)
    }
}

/// Persistent backup receipt required for rollback.
#[derive(Clone)]
pub struct ApplyReceipt {
    /// Provider that created the receipt.
    pub provider_id: String,
    /// Verified backup directory.
    pub backup_dir: PathBuf,
    target_root: PathBuf,
    secret_transaction_id: String,
    backups: Vec<BackupEntry>,
    created_directories: Vec<PathBuf>,
}

impl Debug for ApplyReceipt {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ApplyReceipt")
            .field("provider_id", &self.provider_id)
            .field("backup_dir", &self.backup_dir)
            .field("target_root", &self.target_root)
            .field("secret_transaction_id", &self.secret_transaction_id)
            .field("backup_count", &self.backups.len())
            .field("created_directory_count", &self.created_directories.len())
            .finish()
    }
}

/// Restores filesystem targets from an interrupted migration's durable manifest.
///
/// The manifest is validated in full before any path is changed. Targets that
/// match neither their recorded original nor intended digest are treated as
/// concurrent edits and left untouched.
///
/// # Errors
///
/// Returns [`MigrationError::InvalidInput`] for an unsupported or malformed
/// recovery schema, [`MigrationError::Conflict`] for a target changed outside
/// the interrupted apply, and the same backup, symlink, and I/O errors as normal
/// rollback.
pub fn recover_interrupted_migration(
    backup_dir: impl AsRef<Path>,
    secret_store: &mut dyn SecretStore,
) -> Result<(), MigrationError> {
    recover_interrupted_migration_with_hook(backup_dir.as_ref(), secret_store, |_| Ok(()))
}

fn recover_interrupted_migration_with_hook(
    backup_dir: &Path,
    secret_store: &mut dyn SecretStore,
    before_lock: impl FnOnce(&Path) -> Result<(), MigrationError>,
) -> Result<(), MigrationError> {
    let manifest_path = backup_dir.join("manifest.json");
    reject_symlink(&manifest_path)?;
    let hint = read_recovery_manifest(&manifest_path)?;
    before_lock(&manifest_path)?;
    let backup_root = backup_dir
        .parent()
        .ok_or_else(|| MigrationError::UnsafeTarget(backup_dir.to_owned()))?;
    let _lock = MigrationLock::acquire(&hint.target_root)?;
    let mut manifest = read_recovery_manifest(&manifest_path)?;
    if manifest.target_root != hint.target_root {
        return Err(MigrationError::InvalidInput {
            path: manifest_path,
            reason: "migration recovery target changed while acquiring its lock".to_owned(),
        });
    }
    match manifest.phase {
        RecoveryPhase::Committed | RecoveryPhase::RolledBack => Ok(()),
        RecoveryPhase::FilesystemCommitted => {
            let receipt = receipt_from_manifest(backup_dir, &manifest)?;
            verify_committed_state(&receipt)?;
            secret_store.commit_transaction(&manifest.secret_transaction_id)?;
            manifest.phase = RecoveryPhase::Committed;
            write_recovery_manifest(&backup_dir.join("manifest.json"), &manifest)
        }
        RecoveryPhase::Prepared | RecoveryPhase::Applying => {
            let mut receipt = receipt_from_manifest(backup_dir, &manifest)?;
            let mut displaced_conflict = None;
            let published_targets = receipt
                .backups
                .iter()
                .filter(|entry| {
                    entry
                        .transition
                        .as_ref()
                        .is_some_and(|transition| transition.phase == TransitionPhase::Published)
                })
                .map(|entry| entry.target.clone())
                .collect::<Vec<_>>();
            for target in published_targets {
                let entry = receipt
                    .backups
                    .iter()
                    .find(|entry| entry.target == target)
                    .expect("published target has receipt entry");
                if transition_rollback_completed(entry)? {
                    continue;
                }
                match validate_displaced_publication(&mut receipt, &target) {
                    Ok(()) => {}
                    Err(MigrationError::Conflict(path)) => displaced_conflict = Some(path),
                    Err(error) => return Err(error),
                }
            }
            let preserved_conflict =
                finalize_preserved_transition_conflicts(&mut receipt)?;
            let mut context = ApplyContext {
                target_root: &manifest.target_root,
                backup_root,
                overwrite: true,
                secret_store,
            };
            match rollback_receipt_locked(&mut context, &mut receipt) {
                Ok(()) => displaced_conflict
                    .or(preserved_conflict)
                    .map_or(Ok(()), |path| Err(MigrationError::Conflict(path))),
                Err(error) => Err(error),
            }
        }
    }
}

fn transition_rollback_completed(entry: &BackupEntry) -> Result<bool, MigrationError> {
    let Some(transition) = &entry.transition else {
        return Ok(false);
    };
    if transition.phase != TransitionPhase::Published {
        return Ok(false);
    }
    let target_matches_original = match &entry.digest {
        Some(expected) => {
            path_is_occupied(&entry.target) && digest_path(&entry.target)? == *expected
        }
        None => !path_is_occupied(&entry.target),
    };
    if !target_matches_original {
        return Ok(false);
    }
    let staging_matches_pending = match &entry.pending {
        Some(expected) if path_is_occupied(&transition.staging) => {
            digest_path(&transition.staging)? == *expected
        }
        Some(_) => true,
        None => !path_is_occupied(&transition.staging),
    };
    let old_absent = transition
        .old
        .as_ref()
        .is_none_or(|old| !path_is_occupied(old) || old == &transition.staging);
    Ok(staging_matches_pending
        && (transition.strategy != TransitionStrategy::DisplaceFile || old_absent))
}

fn finalize_preserved_transition_conflicts(
    receipt: &mut ApplyReceipt,
) -> Result<Option<PathBuf>, MigrationError> {
    let mut conflict = None;
    for index in 0..receipt.backups.len() {
        let phase = receipt.backups[index]
            .transition
            .as_ref()
            .map(|transition| transition.phase);
        if !matches!(
            phase,
            Some(TransitionPhase::ConflictRestoring | TransitionPhase::ConflictRestored)
        ) {
            continue;
        }
        conflict.get_or_insert_with(|| receipt.backups[index].target.clone());
        if phase == Some(TransitionPhase::ConflictRestoring) {
            let target_digest = digest_path(&receipt.backups[index].target)?;
            let conflict_digest = receipt.backups[index]
                .transition
                .as_ref()
                .and_then(|transition| transition.conflict_sha256.as_ref())
                .ok_or_else(|| MigrationError::Conflict(receipt.backups[index].target.clone()))?;
            if target_digest != *conflict_digest {
                restore_transition_conflict(receipt, index)?;
            }
        }
        let transition = receipt.backups[index]
            .transition
            .as_ref()
            .expect("conflict transition remains present")
            .clone();
        receipt.backups[index]
            .transition
            .as_mut()
            .expect("conflict transition remains present")
            .phase = TransitionPhase::RollbackCleaning;
        write_backup_manifest(receipt, RecoveryPhase::Applying)?;
        cleanup_path_transition(&transition)?;
        receipt.backups[index].pending = None;
        receipt.backups[index].applied = None;
        receipt.backups[index].transition = None;
        write_backup_manifest(receipt, RecoveryPhase::Applying)?;
    }
    Ok(conflict)
}

fn read_recovery_manifest(path: &Path) -> Result<RecoveryManifest, MigrationError> {
    reject_symlink(path)?;
    let bytes = read_bytes(path)?;
    let manifest: RecoveryManifest =
        serde_json::from_slice(&bytes).map_err(|error| MigrationError::InvalidInput {
            path: path.to_owned(),
            reason: format!("migration recovery manifest is malformed: {error}"),
        })?;
    if manifest.schema_version != RECOVERY_SCHEMA_VERSION {
        return Err(MigrationError::InvalidInput {
            path: path.to_owned(),
            reason: format!(
                "unsupported migration recovery schema {}; supported schema is {}",
                manifest.schema_version, RECOVERY_SCHEMA_VERSION
            ),
        });
    }
    Ok(manifest)
}

fn receipt_from_manifest(
    backup_dir: &Path,
    manifest: &RecoveryManifest,
) -> Result<ApplyReceipt, MigrationError> {
    if !manifest.target_root.is_absolute() {
        return Err(MigrationError::UnsafeTarget(manifest.target_root.clone()));
    }
    let created_directories =
        validate_created_directories(&manifest.created_directories, &manifest.target_root)?;
    let mut backups = Vec::with_capacity(manifest.entries.len());
    for entry in &manifest.entries {
        ensure_target_within(&manifest.target_root, &entry.target)?;
        ensure_no_symlink_ancestors(&manifest.target_root, &entry.target)?;
        match (&entry.backup, &entry.original_sha256) {
            (Some(backup), Some(expected))
                if backup.starts_with(backup_dir) && digest_path(backup)? == *expected => {}
            (None, None) => {}
            (Some(backup), _) => {
                return Err(MigrationError::BackupVerification(backup.clone()));
            }
            (None, Some(_)) => {
                return Err(MigrationError::BackupVerification(backup_dir.to_owned()));
            }
        }
        let transition = entry
            .transition
            .as_ref()
            .map(|transition| validate_recovery_transition(entry, transition))
            .transpose()?;
        let removal = entry
            .removal
            .as_ref()
            .map(|removal| validate_recovery_removal(entry, removal))
            .transpose()?;
        backups.push(BackupEntry {
            target: entry.target.clone(),
            backup: entry.backup.clone(),
            digest: entry.original_sha256.clone(),
            pending: entry.pending_sha256.clone(),
            applied: entry.applied.as_ref().map(|state| match state {
                RecoveryAppliedState::Absent => AppliedState::Absent,
                RecoveryAppliedState::Digest(digest) => AppliedState::Digest(digest.clone()),
                RecoveryAppliedState::Unknown => AppliedState::Unknown,
            }),
            transition,
            removal,
        });
    }
    Ok(ApplyReceipt {
        provider_id: manifest.provider_id.clone(),
        backup_dir: backup_dir.to_owned(),
        target_root: manifest.target_root.clone(),
        secret_transaction_id: manifest.secret_transaction_id.clone(),
        backups,
        created_directories,
    })
}

fn validate_created_directories(
    directories: &[PathBuf],
    target_root: &Path,
) -> Result<Vec<PathBuf>, MigrationError> {
    let mut unique = BTreeSet::new();
    for directory in directories {
        if !directory.is_absolute()
            || directory
                .components()
                .any(|component| matches!(component, Component::CurDir | Component::ParentDir))
        {
            return Err(MigrationError::UnsafeTarget(directory.clone()));
        }
        ensure_target_within(target_root, directory)?;
        ensure_no_symlink_ancestors(target_root, directory)?;
        if !unique.insert(directory.clone()) {
            return Err(MigrationError::InvalidInput {
                path: directory.clone(),
                reason: "duplicate created-directory recovery entry".to_owned(),
            });
        }
    }
    let mut validated = unique.into_iter().collect::<Vec<_>>();
    validated.sort_by_key(|directory| std::cmp::Reverse(directory.components().count()));
    Ok(validated)
}

fn validate_recovery_transition(
    entry: &RecoveryManifestEntry,
    transition: &RecoveryPathTransition,
) -> Result<PathTransition, MigrationError> {
    let parent = entry
        .target
        .parent()
        .ok_or_else(|| MigrationError::UnsafeTarget(entry.target.clone()))?;
    if transition.staging.parent() != Some(parent)
        || transition.old.as_deref().is_some_and(|old| old.parent() != Some(parent))
    {
        return Err(MigrationError::UnsafeTarget(entry.target.clone()));
    }
    reject_symlink_if_present(&transition.staging)?;
    if let Some(old) = &transition.old {
        reject_symlink_if_present(old)?;
    }
    match (transition.strategy, transition.phase) {
        (TransitionStrategy::Exchange, TransitionPhase::Prepared) => {
            let target_digest = digest_path(&entry.target)?;
            let staging_digest = digest_path(&transition.staging)?;
            let original = entry
                .original_sha256
                .as_ref()
                .ok_or_else(|| MigrationError::Conflict(entry.target.clone()))?;
            let pending = entry
                .pending_sha256
                .as_ref()
                .ok_or_else(|| MigrationError::Conflict(entry.target.clone()))?;
            let before_exchange = target_digest == *original && staging_digest == *pending;
            let after_exchange = target_digest == *pending && staging_digest == *original;
            if !before_exchange && !after_exchange {
                return Err(MigrationError::Conflict(entry.target.clone()));
            }
        }
        (TransitionStrategy::Rename, TransitionPhase::Prepared)
        | (TransitionStrategy::Rename, TransitionPhase::OldMoved) => {
            if path_is_occupied(&transition.staging)
                && entry.pending_sha256.as_ref().is_some_and(|expected| {
                    digest_path(&transition.staging).ok().as_ref() != Some(expected)
                })
            {
                return Err(MigrationError::Conflict(transition.staging.clone()));
            }
            if transition.phase == TransitionPhase::OldMoved
                && let Some(old) = &transition.old
                && entry
                    .original_sha256
                    .as_ref()
                    .is_none_or(|expected| digest_path(old).ok().as_ref() != Some(expected))
            {
                return Err(MigrationError::BackupVerification(old.clone()));
            }
        }
        (TransitionStrategy::Exchange, TransitionPhase::Published) => {
            let target_digest = digest_path(&entry.target)?;
            let original = entry
                .original_sha256
                .as_ref()
                .ok_or_else(|| MigrationError::Conflict(entry.target.clone()))?;
            let pending = entry
                .pending_sha256
                .as_ref()
                .ok_or_else(|| MigrationError::Conflict(entry.target.clone()))?;
            if target_digest == *original && !path_is_occupied(&transition.staging) {
                return Ok(PathTransition {
                    staging: transition.staging.clone(),
                    old: transition.old.clone(),
                    phase: transition.phase,
                    strategy: transition.strategy,
                    expected_displaced_sha256: transition.expected_displaced_sha256.clone(),
                    conflict_sha256: transition.conflict_sha256.clone(),
                });
            }
            let staging_digest = digest_path(&transition.staging)?;
            let forward_exchange = target_digest == *pending;
            let rollback_exchange = target_digest == *original && staging_digest == *pending;
            if !forward_exchange && !rollback_exchange {
                return Err(MigrationError::Conflict(entry.target.clone()));
            }
        }
        (
            TransitionStrategy::DisplaceFile,
            TransitionPhase::Prepared | TransitionPhase::Published,
        ) => {
            let target_digest = optional_digest_path(&entry.target)?;
            let staging_digest = optional_digest_path(&transition.staging)?;
            let old_digest = transition
                .old
                .as_ref()
                .map(|old| optional_digest_path(old))
                .transpose()?
                .flatten();
            let original = entry
                .original_sha256
                .as_ref()
                .ok_or_else(|| MigrationError::Conflict(entry.target.clone()))?;
            let pending = entry
                .pending_sha256
                .as_ref()
                .ok_or_else(|| MigrationError::Conflict(entry.target.clone()))?;
            let before = target_digest.as_ref() == Some(original)
                && staging_digest.as_ref() == Some(pending)
                && old_digest.is_none();
            let forward = target_digest.as_ref() == Some(pending)
                && staging_digest.is_none()
                && old_digest.is_some();
            let rolled_back = target_digest.as_ref() == Some(original)
                && staging_digest.as_ref() == Some(pending)
                && old_digest.is_none();
            if !before && !forward && !rolled_back {
                return Err(MigrationError::Conflict(entry.target.clone()));
            }
        }
        (TransitionStrategy::Rename, TransitionPhase::Published) => {
            if let Some(old) = &transition.old
                && path_is_occupied(old)
                && entry
                    .original_sha256
                    .as_ref()
                    .is_none_or(|expected| digest_path(old).ok().as_ref() != Some(expected))
            {
                return Err(MigrationError::BackupVerification(old.clone()));
            }
        }
        (
            TransitionStrategy::Exchange | TransitionStrategy::DisplaceFile,
            TransitionPhase::ConflictRestoring | TransitionPhase::ConflictRestored,
        ) => {
            let conflict = transition
                .conflict_sha256
                .as_ref()
                .ok_or_else(|| MigrationError::Conflict(entry.target.clone()))?;
            let pending = entry
                .pending_sha256
                .as_ref()
                .ok_or_else(|| MigrationError::Conflict(entry.target.clone()))?;
            let target_digest = optional_digest_path(&entry.target)?;
            let old_digest = transition
                .old
                .as_ref()
                .map(|old| optional_digest_path(old))
                .transpose()?
                .flatten();
            let staging_digest = optional_digest_path(&transition.staging)?;
            let before_restore = target_digest.as_ref() == Some(pending)
                && old_digest.as_ref() == Some(conflict);
            let after_restore = target_digest.as_ref() == Some(conflict)
                && staging_digest.as_ref() == Some(pending);
            if !before_restore && !after_restore {
                return Err(MigrationError::Conflict(entry.target.clone()));
            }
        }
        (
            TransitionStrategy::Rename,
            TransitionPhase::ConflictRestoring | TransitionPhase::ConflictRestored,
        ) => {
            return Err(MigrationError::InvalidInput {
                path: entry.target.clone(),
                reason: "rename transition cannot carry displaced conflict state".to_owned(),
            });
        }
        (_, TransitionPhase::Cleaning) => {}
        (_, TransitionPhase::RollbackCleaning) => {
            if entry
                .original_sha256
                .as_ref()
                .is_some_and(|expected| digest_path(&entry.target).ok().as_ref() != Some(expected))
                || entry.original_sha256.is_none() && path_is_occupied(&entry.target)
            {
                return Err(MigrationError::Conflict(entry.target.clone()));
            }
        }
        (
            TransitionStrategy::Exchange | TransitionStrategy::DisplaceFile,
            TransitionPhase::OldMoved,
        ) => {
            return Err(MigrationError::InvalidInput {
                path: entry.target.clone(),
                reason: "exchange transition cannot use old_moved phase".to_owned(),
            });
        }
    }
    Ok(PathTransition {
        staging: transition.staging.clone(),
        old: transition.old.clone(),
        phase: transition.phase,
        strategy: transition.strategy,
        expected_displaced_sha256: transition.expected_displaced_sha256.clone(),
        conflict_sha256: transition.conflict_sha256.clone(),
    })
}

fn validate_recovery_removal(
    entry: &RecoveryManifestEntry,
    removal: &RecoveryRemovalTransition,
) -> Result<RemovalTransition, MigrationError> {
    let parent = entry
        .target
        .parent()
        .ok_or_else(|| MigrationError::UnsafeTarget(entry.target.clone()))?;
    if removal.trash.parent() != Some(parent) || entry.original_sha256.is_some() {
        return Err(MigrationError::UnsafeTarget(entry.target.clone()));
    }
    reject_symlink_if_present(&removal.trash)?;
    Ok(RemovalTransition {
        trash: removal.trash.clone(),
        phase: removal.phase,
    })
}

fn rollback_path_transition(
    entry: &BackupEntry,
    transition: &PathTransition,
) -> Result<(), MigrationError> {
    if verify_restored_entry(entry).is_ok() {
        return Ok(());
    }
    if let Some(old) = &transition.old
        && path_is_occupied(old)
    {
        if transition.strategy == TransitionStrategy::Exchange
            && path_is_occupied(&entry.target)
        {
            exchange_paths_atomically(old, &entry.target).map_err(|source| MigrationError::Io {
                action: "exchange interrupted target with original",
                path: entry.target.clone(),
                source,
            })?;
            sync_parent_directory(&entry.target)?;
            return verify_restored_entry(entry);
        }
        if transition.strategy == TransitionStrategy::DisplaceFile
            && path_is_occupied(&entry.target)
        {
            claw_config::displace_file_atomically(old, &entry.target, &transition.staging)
                .map_err(|source| MigrationError::Io {
                    action: "restore displaced migration file",
                    path: entry.target.clone(),
                    source,
                })?;
            sync_parent_directory(&entry.target)?;
            return verify_restored_entry(entry);
        }
        let discard = path_is_occupied(&entry.target)
            .then(|| allocate_transition_path(&entry.target, "discard"))
            .transpose()?;
        if let Some(discard) = &discard {
            fs::rename(&entry.target, discard).map_err(|source| MigrationError::Io {
                action: "move interrupted target aside",
                path: entry.target.clone(),
                source,
            })?;
        }
        fs::rename(old, &entry.target).map_err(|source| MigrationError::Io {
            action: "restore old migration target name",
            path: entry.target.clone(),
            source,
        })?;
        sync_parent_directory(&entry.target)?;
        if let Some(discard) = &discard {
            remove_path_if_exists(discard)?;
        }
        return verify_restored_entry(entry);
    }
    if transition.strategy == TransitionStrategy::Rename
        && transition.old.is_none()
        && path_is_occupied(&entry.target)
    {
        fs::rename(&entry.target, &transition.staging).map_err(|source| MigrationError::Io {
            action: "move created target to rollback staging",
            path: entry.target.clone(),
            source,
        })?;
        sync_parent_directory(&entry.target)?;
        return verify_restored_entry(entry);
    }
    Err(MigrationError::BackupVerification(entry.target.clone()))
}

fn cleanup_path_transition(transition: &PathTransition) -> Result<(), MigrationError> {
    if path_is_occupied(&transition.staging) {
        remove_path_if_exists(&transition.staging)?;
    }
    if let Some(old) = &transition.old
        && path_is_occupied(old)
    {
        remove_path_if_exists(old)?;
    }
    Ok(())
}

fn verify_restored_entry(entry: &BackupEntry) -> Result<(), MigrationError> {
    match &entry.digest {
        Some(expected)
            if path_is_occupied(&entry.target) && digest_path(&entry.target)? == *expected =>
        {
            Ok(())
        }
        None if !path_is_occupied(&entry.target) => Ok(()),
        _ => Err(MigrationError::BackupVerification(entry.target.clone())),
    }
}

#[derive(Clone)]
struct BackupEntry {
    target: PathBuf,
    backup: Option<PathBuf>,
    digest: Option<String>,
    pending: Option<String>,
    applied: Option<AppliedState>,
    transition: Option<PathTransition>,
    removal: Option<RemovalTransition>,
}

#[derive(Clone)]
enum AppliedState {
    Absent,
    Digest(String),
    Unknown,
}

#[derive(Clone)]
struct PathTransition {
    staging: PathBuf,
    old: Option<PathBuf>,
    phase: TransitionPhase,
    strategy: TransitionStrategy,
    expected_displaced_sha256: Option<String>,
    conflict_sha256: Option<String>,
}

#[derive(Clone, Copy, Debug, Deserialize, Serialize, Eq, PartialEq)]
#[serde(rename_all = "snake_case")]
enum TransitionStrategy {
    Exchange,
    DisplaceFile,
    Rename,
}

#[derive(Clone)]
struct RemovalTransition {
    trash: PathBuf,
    phase: RemovalPhase,
}

#[derive(Clone, Copy, Debug, Deserialize, Serialize, Eq, PartialEq)]
#[serde(rename_all = "snake_case")]
enum RemovalPhase {
    Planned,
    Moved,
}

#[derive(Clone, Copy, Debug, Deserialize, Serialize, Eq, PartialEq)]
#[serde(rename_all = "snake_case")]
enum TransitionPhase {
    Prepared,
    OldMoved,
    Published,
    Cleaning,
    ConflictRestoring,
    ConflictRestored,
    RollbackCleaning,
}

#[derive(Clone, Copy, Debug, Deserialize, Serialize, Eq, PartialEq)]
#[serde(rename_all = "snake_case")]
enum RecoveryPhase {
    Prepared,
    Applying,
    FilesystemCommitted,
    Committed,
    RolledBack,
}

#[derive(Debug, Deserialize, Serialize)]
struct RecoveryManifest {
    schema_version: u32,
    provider_id: String,
    target_root: PathBuf,
    secret_transaction_id: String,
    phase: RecoveryPhase,
    entries: Vec<RecoveryManifestEntry>,
    created_directories: Vec<PathBuf>,
}

#[derive(Debug, Deserialize, Serialize)]
struct RecoveryManifestEntry {
    target: PathBuf,
    backup: Option<PathBuf>,
    original_sha256: Option<String>,
    pending_sha256: Option<String>,
    applied: Option<RecoveryAppliedState>,
    transition: Option<RecoveryPathTransition>,
    removal: Option<RecoveryRemovalTransition>,
}

#[derive(Debug, Deserialize, Serialize)]
struct RecoveryPathTransition {
    staging: PathBuf,
    old: Option<PathBuf>,
    phase: TransitionPhase,
    strategy: TransitionStrategy,
    expected_displaced_sha256: Option<String>,
    conflict_sha256: Option<String>,
}

#[derive(Debug, Deserialize, Serialize)]
struct RecoveryRemovalTransition {
    trash: PathBuf,
    phase: RemovalPhase,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(tag = "kind", content = "sha256", rename_all = "snake_case")]
enum RecoveryAppliedState {
    Absent,
    Digest(String),
    Unknown,
}

struct MigrationLock {
    _file: File,
}

impl MigrationLock {
    fn acquire(target_root: &Path) -> Result<Self, MigrationError> {
        let normalized_target = normalize_target_root(target_root)?;
        let lock_path = migration_lock_path_for_normalized(&normalized_target);
        let root = lock_path
            .parent()
            .expect("migration lock path always has a parent");
        create_dir_all(root)?;
        reject_symlink(root)?;
        let existed = path_is_occupied(&lock_path);
        reject_symlink_if_present(&lock_path)?;
        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .open(&lock_path)
            .map_err(|source| MigrationError::Io {
                action: "open migration lock",
                path: lock_path.clone(),
                source,
            })?;
        if !existed {
            sync_directory(root)?;
        }
        file.lock().map_err(|source| MigrationError::Io {
            action: "lock migration target",
            path: lock_path,
            source,
        })?;
        Ok(Self { _file: file })
    }
}

fn migration_lock_path(target_root: &Path) -> Result<PathBuf, MigrationError> {
    Ok(migration_lock_path_for_normalized(&normalize_target_root(
        target_root,
    )?))
}

fn normalize_target_root(target_root: &Path) -> Result<PathBuf, MigrationError> {
    let name = target_root
        .file_name()
        .ok_or_else(|| MigrationError::UnsafeTarget(target_root.to_owned()))?;
    let parent = target_root
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    let absolute_parent = if parent.is_absolute() {
        parent.to_owned()
    } else {
        std::env::current_dir()
            .map_err(|source| MigrationError::Io {
                action: "resolve current directory",
                path: parent.to_owned(),
                source,
            })?
            .join(parent)
    };
    create_dir_all(&absolute_parent)?;
    let canonical_parent =
        fs::canonicalize(&absolute_parent).map_err(|source| MigrationError::Io {
            action: "canonicalize migration target parent",
            path: absolute_parent,
            source,
        })?;
    let normalized = canonical_parent.join(name);
    reject_symlink_if_present(&normalized)?;
    if path_is_occupied(&normalized) {
        fs::canonicalize(&normalized).map_err(|source| MigrationError::Io {
            action: "canonicalize migration target",
            path: normalized,
            source,
        })
    } else {
        Ok(normalized)
    }
}

fn normalize_plan_target_root(target_root: &Path) -> Result<PathBuf, MigrationError> {
        let name = target_root
            .file_name()
            .ok_or_else(|| MigrationError::UnsafeTarget(target_root.to_owned()))?;
        let parent = target_root
            .parent()
            .filter(|parent| !parent.as_os_str().is_empty())
            .unwrap_or_else(|| Path::new("."));
        let absolute_parent = if parent.is_absolute() {
            parent.to_owned()
        } else {
            std::env::current_dir()
                .map_err(|source| MigrationError::Io {
                    action: "resolve current directory",
                    path: parent.to_owned(),
                    source,
                })?
                .join(parent)
        };
        let canonical_parent =
            fs::canonicalize(&absolute_parent).map_err(|source| MigrationError::Io {
                action: "canonicalize migration plan target parent",
                path: absolute_parent,
                source,
            })?;
        let normalized = canonical_parent.join(name);
        reject_symlink_if_present(&normalized)?;
        if path_is_occupied(&normalized) {
            fs::canonicalize(&normalized).map_err(|source| MigrationError::Io {
                action: "canonicalize migration plan target",
                path: normalized,
                source,
            })
        } else {
            Ok(normalized)
        }

}

fn normalize_directory_root(path: &Path) -> Result<PathBuf, MigrationError> {
    let absolute = if path.is_absolute() {
        path.to_owned()
    } else {
        std::env::current_dir()
            .map_err(|source| MigrationError::Io {
                action: "resolve current directory",
                path: path.to_owned(),
                source,
            })?
            .join(path)
    };
    create_dir_all(&absolute)?;
    fs::canonicalize(&absolute).map_err(|source| MigrationError::Io {
        action: "canonicalize migration directory",
        path: absolute,
        source,
    })
}

fn migration_lock_path_for_normalized(target_root: &Path) -> PathBuf {
    let parent = target_root
        .parent()
        .expect("normalized migration target always has a parent");
    #[cfg(any(windows, target_os = "macos"))]
    let identity = target_root.to_string_lossy().to_lowercase();
    #[cfg(not(any(windows, target_os = "macos")))]
    let identity = target_root.to_string_lossy();
    parent.join(format!(
        ".gta-claw.migration-{}.lock",
        &digest_bytes(identity.as_bytes())[..16]
    ))
}

pub(crate) enum MigrationOperation {
    CopyPath {
        source: PathBuf,
        target: PathBuf,
    },
    AppendFile {
        source: PathBuf,
        target: PathBuf,
        heading: String,
    },
    GeneratedCommandSkill {
        source: PathBuf,
        target: PathBuf,
        name: String,
    },
    TransformJson {
        source: PathBuf,
        target: PathBuf,
        namespace: String,
    },
    TransformText {
        source: PathBuf,
        target: PathBuf,
        namespace: String,
    },
    ImportEnvironment {
        source: PathBuf,
        target: PathBuf,
        namespace: String,
    },
    StoreDocument {
        source: PathBuf,
        target: PathBuf,
        secret_id: String,
    },
    WriteBytes {
        target: PathBuf,
        bytes: Vec<u8>,
    },
}

impl MigrationOperation {
    pub(crate) fn target(&self) -> &Path {
        match self {
            Self::CopyPath { target, .. }
            | Self::AppendFile { target, .. }
            | Self::GeneratedCommandSkill { target, .. }
            | Self::TransformJson { target, .. }
            | Self::TransformText { target, .. }
            | Self::ImportEnvironment { target, .. }
            | Self::StoreDocument { target, .. }
            | Self::WriteBytes { target, .. } => target,
        }
    }

    fn target_mut(&mut self) -> &mut PathBuf {
        match self {
            Self::CopyPath { target, .. }
            | Self::AppendFile { target, .. }
            | Self::GeneratedCommandSkill { target, .. }
            | Self::TransformJson { target, .. }
            | Self::TransformText { target, .. }
            | Self::ImportEnvironment { target, .. }
            | Self::StoreDocument { target, .. }
            | Self::WriteBytes { target, .. } => target,
        }
    }

    const fn kind(&self) -> &'static str {
        match self {
            Self::CopyPath { .. } => "copy",
            Self::AppendFile { .. } => "append",
            Self::GeneratedCommandSkill { .. } => "command-skill",
            Self::TransformJson { .. } => "json-config",
            Self::TransformText { .. } => "text-config",
            Self::ImportEnvironment { .. } => "environment",
            Self::StoreDocument { .. } => "secret-document",
            Self::WriteBytes { .. } => "manifest",
        }
    }

    fn source(&self) -> Option<&Path> {
        match self {
            Self::CopyPath { source, .. }
            | Self::AppendFile { source, .. }
            | Self::GeneratedCommandSkill { source, .. }
            | Self::TransformJson { source, .. }
            | Self::TransformText { source, .. }
            | Self::ImportEnvironment { source, .. }
            | Self::StoreDocument { source, .. } => Some(source),
            Self::WriteBytes { .. } => None,
        }
    }
}

/// Migration lifecycle failure.
#[derive(Debug)]
pub enum MigrationError {
    /// Source state was not found.
    SourceNotFound {
        /// Provider identifier.
        provider: &'static str,
        /// Searched root.
        path: PathBuf,
    },
    /// Filesystem operation failed.
    Io {
        /// Secret-free operation description.
        action: &'static str,
        /// Affected path.
        path: PathBuf,
        /// Operating-system error.
        source: io::Error,
    },
    /// A source data file was malformed.
    InvalidInput {
        /// Affected path.
        path: PathBuf,
        /// Secret-free reason.
        reason: String,
    },
    /// Existing target requires explicit overwrite.
    Conflict(PathBuf),
    /// Target escaped the configured migration root.
    UnsafeTarget(PathBuf),
    /// Symlinks are rejected to prevent source or target escapes.
    Symlink(PathBuf),
    /// Executable legacy artifact cannot be copied silently.
    ExecutableArtifact(PathBuf),
    /// Plan result violated the frozen contract.
    Contract(ContractViolation),
    /// Secret-store adapter failed.
    SecretStore(SecretStoreError),
    /// Artifact signing failed.
    Signing(String),
    /// Apply failed and attempted rollback.
    ApplyFailed {
        /// Original typed apply failure.
        cause: Box<Self>,
        /// Every rollback failure encountered while restoring independent entries.
        rollback_errors: Vec<String>,
    },
    /// Rollback attempted every independent entry but some restorations failed.
    RollbackFailed {
        /// Secret-free failures in rollback order.
        errors: Vec<String>,
    },
    /// Receipt or plan belongs to a different provider.
    ProviderMismatch,
    /// Only successful, validated plans may be applied.
    PlanNotApplicable,
    /// Backup verification failed.
    BackupVerification(PathBuf),
}

impl Display for MigrationError {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        match self {
            Self::SourceNotFound { provider, path } => {
                write!(
                    formatter,
                    "{provider} state was not found at {}",
                    path.display()
                )
            }
            Self::Io {
                action,
                path,
                source,
            } => write!(formatter, "{action} {}: {source}", path.display()),
            Self::InvalidInput { path, reason } => {
                write!(
                    formatter,
                    "invalid migration input {}: {reason}",
                    path.display()
                )
            }
            Self::Conflict(path) => {
                write!(formatter, "migration target exists: {}", path.display())
            }
            Self::UnsafeTarget(path) => {
                write!(
                    formatter,
                    "migration target escapes target root: {}",
                    path.display()
                )
            }
            Self::Symlink(path) => {
                write!(
                    formatter,
                    "migration refuses symbolic link: {}",
                    path.display()
                )
            }
            Self::ExecutableArtifact(path) => write!(
                formatter,
                "migration refuses executable legacy artifact: {}",
                path.display()
            ),
            Self::Contract(error) => write!(formatter, "migration contract violation: {error}"),
            Self::SecretStore(error) => write!(formatter, "secret store failed: {error}"),
            Self::Signing(reason) => write!(formatter, "artifact signing failed: {reason}"),
            Self::ApplyFailed {
                cause,
                rollback_errors,
            } => {
                write!(formatter, "migration apply failed: {cause}")?;
                if !rollback_errors.is_empty() {
                    write!(
                        formatter,
                        "; rollback failed: {}",
                        rollback_errors.join("; ")
                    )?;
                }
                Ok(())
            }
            Self::RollbackFailed { errors } => write!(
                formatter,
                "rollback completed with {} failure(s): {}",
                errors.len(),
                errors.join("; ")
            ),
            Self::ProviderMismatch => formatter.write_str("migration provider mismatch"),
            Self::PlanNotApplicable => {
                formatter.write_str("only a validated migrated plan may be applied")
            }
            Self::BackupVerification(path) => {
                write!(
                    formatter,
                    "backup verification failed for {}",
                    path.display()
                )
            }
        }
    }
}

impl Error for MigrationError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Io { source, .. } => Some(source),
            Self::Contract(error) => Some(error),
            Self::SecretStore(error) => Some(error),
            Self::ApplyFailed { cause, .. } => Some(cause.as_ref()),
            _ => None,
        }
    }
}

impl From<ContractViolation> for MigrationError {
    fn from(value: ContractViolation) -> Self {
        Self::Contract(value)
    }
}

impl From<SecretStoreError> for MigrationError {
    fn from(value: SecretStoreError) -> Self {
        Self::SecretStore(value)
    }
}

pub(crate) fn successful_plan(
    provider_id: &'static str,
    source_root: PathBuf,
    target_root: PathBuf,
    mut operations: Vec<MigrationOperation>,
    mut diagnostics: Vec<Diagnostic>,
    signer: &dyn ArtifactSigner,
) -> Result<MigrationPlan, MigrationError> {
    let original_target_root = target_root;
    let target_root = normalize_plan_target_root(&original_target_root)?;
    for operation in &mut operations {
        let relative = operation
            .target()
            .strip_prefix(&original_target_root)
            .map_err(|_| MigrationError::UnsafeTarget(operation.target().to_owned()))?
            .to_owned();
        *operation.target_mut() = target_root.join(relative);
    }
    for operation in &operations {
        ensure_target_within(&target_root, operation.target())?;
    }
    let input_digest = digest_path(&source_root)?;
    let source_digests = collect_source_digests(&operations)?;
    let manifest_relative = PathBuf::from("config")
        .join("migrations")
        .join(format!("{provider_id}.json5"));
    let manifest_target = target_root.join(&manifest_relative);
    let manifest = build_manifest(provider_id, &target_root, &operations)?;
    let artifact_digest = digest_bytes(&manifest);
    let signature = signer.sign(&artifact_digest)?;
    operations.push(MigrationOperation::WriteBytes {
        target: manifest_target,
        bytes: manifest,
    });
    diagnostics.push(Diagnostic {
        code: "BACKUP_REQUIRED".to_owned(),
        severity: DiagnosticSeverity::Info,
        message: "Apply verifies a backup of every existing target before writing.".to_owned(),
    });
    let result = MigrationResult {
        contract_version: MIGRATION_CONTRACT_VERSION.to_owned(),
        input: MigrationInput {
            kind: InputKind::Environment,
            source: source_root.display().to_string(),
            sha256: input_digest,
        },
        status: MigrationStatus::Migrated,
        exit_code: MigrationStatus::Migrated.exit_code(),
        recognized_bridges: Vec::new(),
        remaining_javascript: Vec::new(),
        artifacts: vec![Artifact {
            kind: ArtifactKind::Json5Config,
            path: path_to_slashes(&manifest_relative),
            sha256: artifact_digest,
            signature,
        }],
        diagnostics,
    };
    result.validate()?;
    Ok(MigrationPlan {
        result,
        provider_id,
        source_root,
        target_root,
        operations,
        source_digests,
    })
}

pub(crate) fn rejected_plan(
    provider_id: &'static str,
    source_root: PathBuf,
    target_root: PathBuf,
    code: &str,
    message: &str,
) -> Result<MigrationPlan, MigrationError> {
    let target_root = normalize_plan_target_root(&target_root)?;
    let result = MigrationResult {
        contract_version: MIGRATION_CONTRACT_VERSION.to_owned(),
        input: MigrationInput {
            kind: InputKind::Environment,
            source: source_root.display().to_string(),
            sha256: digest_path(&source_root)?,
        },
        status: MigrationStatus::Failed,
        exit_code: MigrationStatus::Failed.exit_code(),
        recognized_bridges: Vec::new(),
        remaining_javascript: Vec::new(),
        artifacts: Vec::new(),
        diagnostics: vec![Diagnostic {
            code: code.to_owned(),
            severity: DiagnosticSeverity::Error,
            message: message.to_owned(),
        }],
    };
    result.validate()?;
    Ok(MigrationPlan {
        result,
        provider_id,
        source_root,
        target_root,
        operations: Vec::new(),
        source_digests: Vec::new(),
    })
}

fn build_manifest(
    provider_id: &str,
    target_root: &Path,
    operations: &[MigrationOperation],
) -> Result<Vec<u8>, MigrationError> {
    #[derive(Serialize)]
    struct ManifestOperation<'a> {
        kind: &'a str,
        target: String,
    }
    #[derive(Serialize)]
    struct Manifest<'a> {
        contract_version: &'static str,
        provider: &'a str,
        operations: Vec<ManifestOperation<'a>>,
    }
    let listed = operations
        .iter()
        .map(|operation| {
            let relative = operation
                .target()
                .strip_prefix(target_root)
                .map_err(|_| MigrationError::UnsafeTarget(operation.target().to_path_buf()))?;
            Ok(ManifestOperation {
                kind: operation.kind(),
                target: path_to_slashes(relative),
            })
        })
        .collect::<Result<Vec<_>, MigrationError>>()?;
    serde_json::to_vec_pretty(&Manifest {
        contract_version: MIGRATION_CONTRACT_VERSION,
        provider: provider_id,
        operations: listed,
    })
    .map_err(|error| MigrationError::Signing(error.to_string()))
}

fn apply_plan(
    context: &mut ApplyContext<'_>,
    plan: &MigrationPlan,
) -> Result<ApplyReceipt, MigrationError> {
    plan.result.validate()?;
    if plan.result.status != MigrationStatus::Migrated || plan.operations.is_empty() {
        return Err(MigrationError::PlanNotApplicable);
    }
    let target_root = normalize_target_root(context.target_root)?;
    if plan.target_root != target_root {
        return Err(MigrationError::UnsafeTarget(plan.target_root.clone()));
    }
    verify_source_digests(plan)?;
    for operation in &plan.operations {
        ensure_target_within(&target_root, operation.target())?;
        ensure_no_symlink_ancestors(&target_root, operation.target())?;
        if path_is_occupied(operation.target())
            && !context.overwrite
            && !matches!(operation, MigrationOperation::AppendFile { .. })
        {
            return Err(MigrationError::Conflict(operation.target().to_path_buf()));
        }
    }
    let _lock = MigrationLock::acquire(&target_root)?;
    verify_source_digests(plan)?;
    for operation in &plan.operations {
        ensure_no_symlink_ancestors(&target_root, operation.target())?;
        if path_is_occupied(operation.target())
            && !context.overwrite
            && !matches!(operation, MigrationOperation::AppendFile { .. })
        {
            return Err(MigrationError::Conflict(operation.target().to_owned()));
        }
    }
    let backup_root = normalize_directory_root(context.backup_root)?;
    let backup_dir = create_backup_dir(&backup_root, plan.provider_id)?;
    let backups = backup_targets(&backup_dir, &plan.operations)?;
    verify_targets_unchanged(&backups)?;
    let created_directories =
        collect_missing_target_directories(&plan.operations, &target_root)?;
    let secret_transaction_id = new_secret_transaction_id(plan.provider_id, &target_root)?;
    let mut receipt = ApplyReceipt {
        provider_id: plan.provider_id.to_owned(),
        backup_dir,
        target_root,
        secret_transaction_id,
        backups,
        created_directories,
    };
    write_backup_manifest(&receipt, RecoveryPhase::Prepared)?;
    let apply_result = context
        .secret_store
        .begin_transaction(&receipt.secret_transaction_id)
        .map_err(MigrationError::from)
        .and_then(|()| apply_operations(context, &plan.operations, &mut receipt))
        .and_then(|()| verify_source_digests(plan))
        .and_then(|()| write_backup_manifest(&receipt, RecoveryPhase::FilesystemCommitted))
        .and_then(|()| {
            context
                .secret_store
                .commit_transaction(&receipt.secret_transaction_id)
                .map_err(MigrationError::from)
        })
        .and_then(|()| write_backup_manifest(&receipt, RecoveryPhase::Committed));
    if let Err(error) = apply_result {
        let rollback_errors = rollback_receipt_locked(context, &mut receipt)
            .err()
            .map_or_else(Vec::new, rollback_failure_messages);
        return Err(MigrationError::ApplyFailed {
            cause: Box::new(error),
            rollback_errors,
        });
    }
    Ok(receipt)
}

fn new_secret_transaction_id(
    provider_id: &str,
    target_root: &Path,
) -> Result<String, MigrationError> {
    let mut nonce = [0_u8; 16];
    getrandom::fill(&mut nonce)
        .map_err(|error| MigrationError::Signing(format!("generate transaction UUID: {error}")))?;
    nonce[6] = (nonce[6] & 0x0f) | 0x40;
    nonce[8] = (nonce[8] & 0x3f) | 0x80;
    let normalized = normalize_target_root(target_root)?;
    let target_identity = digest_bytes(&raw_os_path_bytes(&normalized));
    Ok(format_secret_transaction_id(
        provider_id,
        &target_identity[..16],
        std::process::id(),
        &nonce,
    ))
}

fn format_secret_transaction_id(
    provider_id: &str,
    target_identity: &str,
    process_id: u32,
    nonce: &[u8; 16],
) -> String {
    let uuid = encode_hex(nonce);
    format!(
        "{provider_id}-{target_identity}-p{process_id}-{}-{}-{}-{}-{}",
        &uuid[0..8],
        &uuid[8..12],
        &uuid[12..16],
        &uuid[16..20],
        &uuid[20..32]
    )
}

fn verify_source_digests(plan: &MigrationPlan) -> Result<(), MigrationError> {
    for (source, expected) in &plan.source_digests {
        if digest_path(source)? != *expected {
            return Err(MigrationError::InvalidInput {
                path: source.clone(),
                reason: "source changed after the reviewed dry-run plan".to_owned(),
            });
        }
    }
    Ok(())
}

fn collect_source_digests(
    operations: &[MigrationOperation],
) -> Result<Vec<(PathBuf, String)>, MigrationError> {
    let mut seen = BTreeSet::new();
    operations
        .iter()
        .filter_map(MigrationOperation::source)
        .filter(|source| seen.insert((*source).to_path_buf()))
        .map(|source| Ok((source.to_path_buf(), digest_path(source)?)))
        .collect()
}

enum PreparedOperation<'a> {
    Copy {
        source: &'a Path,
        target: &'a Path,
    },
    Bytes {
        target: &'a Path,
        bytes: Vec<u8>,
    },
    GeneratedSkill {
        target: &'a Path,
        bytes: Vec<u8>,
    },
}

impl PreparedOperation<'_> {
    const fn target(&self) -> &Path {
        match self {
            Self::Copy { target, .. }
            | Self::Bytes { target, .. }
            | Self::GeneratedSkill { target, .. } => target,
        }
    }

    fn stage(self) -> Result<StagedOperation<'_>, MigrationError> {
        match self {
            Self::Copy { source, target, .. } => {
                reject_symlink(source)?;
                create_parent(target)?;
                let staging = if source.is_dir() {
                    let staging = create_staging_directory(target)?;
                    copy_directory_contents(source, &staging)?;
                    set_path_permissions_from(source, &staging)?;
                    sync_directory(&staging)?;
                    staging
                } else if source.is_file() {
                    let staging = create_staging_file(target)?;
                    populate_staging_file_from_source(source, &staging)?;
                    staging
                } else {
                    return Err(MigrationError::SourceNotFound {
                        provider: "migration",
                        path: source.to_owned(),
                    });
                };
                let digest = digest_path(&staging)?;
                Ok(StagedOperation {
                    target,
                    staging,
                    digest,
                })
            }
            Self::Bytes { target, bytes } => {
                create_parent(target)?;
                let staging = create_staging_file(target)?;
                populate_staging_file(&staging, &bytes, 0o600)?;
                let digest = digest_path(&staging)?;
                Ok(StagedOperation {
                    target,
                    staging,
                    digest,
                })
            }
            Self::GeneratedSkill { target, bytes } => {
                create_parent(target)?;
                let staging = create_staging_directory(target)?;
                write_new_file_durably(&staging.join("SKILL.md"), &bytes, 0o600)?;
                sync_directory(&staging)?;
                let digest = digest_path(&staging)?;
                Ok(StagedOperation {
                    target,
                    staging,
                    digest,
                })
            }
        }
    }
}

struct StagedOperation<'a> {
    target: &'a Path,
    staging: PathBuf,
    digest: String,
}

impl StagedOperation<'_> {
    fn publish(self, receipt: &mut ApplyReceipt) -> Result<(), MigrationError> {
        publish_staged_path_transactionally(
            &self.staging,
            self.target,
            receipt,
            None,
        )
    }
}

fn prepare_operation<'a>(
    operation: &'a MigrationOperation,
    store: &mut dyn SecretStore,
    transaction_id: &str,
) -> Result<PreparedOperation<'a>, MigrationError> {
    match operation {
        MigrationOperation::CopyPath { source, target } => Ok(PreparedOperation::Copy {
            source,
            target,
        }),
        MigrationOperation::AppendFile {
            source,
            target,
            heading,
        } => Ok(PreparedOperation::Bytes {
            target,
            bytes: append_file_bytes(source, target, heading)?,
        }),
        MigrationOperation::GeneratedCommandSkill {
            source,
            target,
            name,
        } => Ok(PreparedOperation::GeneratedSkill {
            target,
            bytes: generated_command_skill_bytes(source, name)?,
        }),
        MigrationOperation::TransformJson {
            source,
            target,
            namespace,
        } => Ok(PreparedOperation::Bytes {
            target,
            bytes: transform_json_bytes(source, namespace, store, transaction_id)?,
        }),
        MigrationOperation::TransformText {
            source,
            target,
            namespace,
        } => Ok(PreparedOperation::Bytes {
            target,
            bytes: transform_text_bytes(source, namespace, store, transaction_id)?,
        }),
        MigrationOperation::ImportEnvironment {
            source,
            target,
            namespace,
        } => Ok(PreparedOperation::Bytes {
            target,
            bytes: import_environment_bytes(source, namespace, store, transaction_id)?,
        }),
        MigrationOperation::StoreDocument {
            source,
            target,
            secret_id,
        } => Ok(PreparedOperation::Bytes {
            target,
            bytes: stored_document_bytes(source, secret_id, store, transaction_id)?,
        }),
        MigrationOperation::WriteBytes { target, bytes } => Ok(PreparedOperation::Bytes {
            target,
            bytes: bytes.clone(),
        }),
    }
}

fn apply_operations(
    context: &mut ApplyContext<'_>,
    operations: &[MigrationOperation],
    receipt: &mut ApplyReceipt,
) -> Result<(), MigrationError> {
    for operation in operations {
        let _ = verify_operation_target(receipt, operation.target())?;
        preflight_operation_publication(operation)?;
        let prepared = prepare_operation(
            operation,
            context.secret_store,
            &receipt.secret_transaction_id,
        )?;
        let staged = prepared.stage()?;
        record_pending_state(receipt, staged.target, &staged.digest);
        write_backup_manifest(receipt, RecoveryPhase::Applying)?;
        let target = staged.target.to_path_buf();
        staged.publish(receipt)?;
        record_applied_state(receipt, &target)?;
        write_backup_manifest(receipt, RecoveryPhase::Applying)?;
    }
    Ok(())
}

fn preflight_operation_publication(
    operation: &MigrationOperation,
) -> Result<(), MigrationError> {
    preflight_operation_publication_with_exchange(operation, atomic_exchange_supported())
}

fn preflight_operation_publication_with_exchange(
    operation: &MigrationOperation,
    exchange_supported: bool,
) -> Result<(), MigrationError> {
    let target = operation.target();
    if !path_is_occupied(target) || exchange_supported {
        return Ok(());
    }
    let target_metadata = fs::symlink_metadata(target).map_err(|source| MigrationError::Io {
        action: "inspect publication target",
        path: target.to_owned(),
        source,
    })?;
    let result_is_directory = match operation {
        MigrationOperation::CopyPath { source, .. } => {
            let metadata =
                fs::symlink_metadata(source).map_err(|source_error| MigrationError::Io {
                    action: "inspect publication source",
                    path: source.to_owned(),
                    source: source_error,
                })?;
            metadata.is_dir()
        }
        MigrationOperation::GeneratedCommandSkill { .. } => true,
        MigrationOperation::AppendFile { .. }
        | MigrationOperation::TransformJson { .. }
        | MigrationOperation::TransformText { .. }
        | MigrationOperation::ImportEnvironment { .. }
        | MigrationOperation::StoreDocument { .. }
        | MigrationOperation::WriteBytes { .. } => false,
    };
    if result_is_directory || target_metadata.is_dir() {
        return Err(MigrationError::InvalidInput {
            path: target.to_owned(),
            reason: "cross-type or directory overwrite requires native atomic exchange".to_owned(),
        });
    }
    Ok(())
}

fn verify_operation_target(
    receipt: &ApplyReceipt,
    target: &Path,
) -> Result<Option<String>, MigrationError> {
    let mut observed = None;
    for backup in receipt
        .backups
        .iter()
        .filter(|entry| entry.target == target)
    {
        let current = if path_is_occupied(target) {
            Some(digest_path(target)?)
        } else {
            None
        };
        let original = match &backup.digest {
            Some(digest) => current.as_ref() == Some(digest),
            None => current.is_none(),
        };
        let pending = backup
            .pending
            .as_ref()
            .is_some_and(|digest| current.as_ref() == Some(digest));
        let applied = match &backup.applied {
            Some(AppliedState::Digest(digest)) => current.as_ref() == Some(digest),
            Some(AppliedState::Absent) => current.is_none(),
            Some(AppliedState::Unknown) | None => false,
        };
        if !original && !pending && !applied {
            return Err(MigrationError::Conflict(target.to_owned()));
        }
        observed = current;
    }
    Ok(observed)
}

fn record_pending_state(receipt: &mut ApplyReceipt, target: &Path, sha256: &str) {
    for backup in receipt
        .backups
        .iter_mut()
        .filter(|entry| entry.target == target)
    {
        backup.pending = Some(sha256.to_owned());
    }
}

fn record_applied_state(
    receipt: &mut ApplyReceipt,
    target: &Path,
) -> Result<(), MigrationError> {
    for backup in receipt
        .backups
        .iter_mut()
        .filter(|entry| entry.target == target)
    {
        let expected = backup
            .pending
            .as_ref()
            .ok_or_else(|| MigrationError::Conflict(backup.target.clone()))?;
        if !path_is_occupied(&backup.target) || digest_path(&backup.target)? != *expected {
            return Err(MigrationError::Conflict(backup.target.clone()));
        }
        backup.applied = Some(AppliedState::Digest(expected.clone()));
        backup.pending = None;
    }
    Ok(())
}

fn rollback_receipt(
    context: &mut ApplyContext<'_>,
    receipt: &ApplyReceipt,
    target_root: &Path,
) -> Result<(), MigrationError> {
    let _lock = MigrationLock::acquire(target_root)?;
    let mut receipt = receipt.clone();
    rollback_receipt_locked(context, &mut receipt)
}

fn rollback_receipt_locked(
    context: &mut ApplyContext<'_>,
    receipt: &mut ApplyReceipt,
) -> Result<(), MigrationError> {
    let preserved_conflict = finalize_preserved_transition_conflicts(receipt)?;
    verify_rollback_state(receipt)?;
    write_backup_manifest(receipt, RecoveryPhase::Applying)?;
    let mut errors = Vec::new();
    if let Err(error) = context
        .secret_store
        .rollback_transaction(&receipt.secret_transaction_id)
    {
        errors.push(format!(
            "secret transaction {}: {error}",
            receipt.secret_transaction_id
        ));
    }
    for index in (0..receipt.backups.len()).rev() {
        let entry = &receipt.backups[index];
        if entry.applied.is_none()
            && entry.pending.is_none()
            && entry.transition.is_none()
            && entry.removal.is_none()
        {
            continue;
        }
        let target = entry.target.clone();
        let backup = entry.backup.clone();
        let digest = entry.digest.clone();
        let transition = entry.transition.clone();
        let snapshot = entry.clone();
        let transition_can_restore = transition.as_ref().is_some_and(|transition| {
            verify_restored_entry(&snapshot).is_ok()
                || transition.phase != TransitionPhase::Cleaning
                    && transition
                    .old
                    .as_ref()
                    .is_some_and(|old| path_is_occupied(old))
        });
        let result = if transition_can_restore {
            let transition = transition.expect("transition was checked as present");
            rollback_path_transition(&snapshot, &transition).and_then(|()| {
                receipt.backups[index]
                    .transition
                    .as_mut()
                    .expect("transition remains present through rollback cleanup")
                    .phase = TransitionPhase::RollbackCleaning;
                write_backup_manifest(receipt, RecoveryPhase::Applying)?;
                cleanup_path_transition(&transition)?;
                receipt.backups[index].pending = None;
                receipt.backups[index].applied = Some(match digest.clone() {
                    Some(digest) => AppliedState::Digest(digest),
                    None => AppliedState::Absent,
                });
                receipt.backups[index].transition = None;
                write_backup_manifest(receipt, RecoveryPhase::Applying)
            })
        } else if let Some(backup) = backup {
            if let Some(transition) = &transition {
                if let Err(error) = cleanup_path_transition(transition) {
                    errors.push(error.to_string());
                    continue;
                }
            }
            receipt.backups[index].transition = None;
            write_backup_manifest(receipt, RecoveryPhase::Applying)
                .and_then(|()| {
                    copy_path_for_apply(
                        &backup,
                        &target,
                        receipt,
                        digest.as_deref(),
                    )
                })
                .and_then(|()| record_applied_state(receipt, &target))
                .and_then(|()| write_backup_manifest(receipt, RecoveryPhase::Applying))
        } else {
            remove_created_target_transactionally(receipt, index)
        };
        if let Err(error) = result {
            errors.push(error.to_string());
        }

    }
    if let Err(error) = remove_created_directories_if_empty(receipt) {
        errors.push(error.to_string());
    }
    if errors.is_empty() {
        write_backup_manifest(receipt, RecoveryPhase::RolledBack)?;
        preserved_conflict.map_or(Ok(()), |path| Err(MigrationError::Conflict(path)))
    } else {
        Err(MigrationError::RollbackFailed { errors })
    }
}

fn rollback_failure_messages(error: MigrationError) -> Vec<String> {
    match error {
        MigrationError::RollbackFailed { errors } => errors,
        other => vec![other.to_string()],
    }
}

fn verify_rollback_state(receipt: &ApplyReceipt) -> Result<(), MigrationError> {
    for backup in &receipt.backups {
        if backup.applied.is_none() && backup.pending.is_none() && backup.removal.is_none() {
            continue;
        }
        let current = if path_is_occupied(&backup.target) {
            Some(digest_path(&backup.target)?)
        } else {
            None
        };
        let original = match &backup.digest {
            Some(digest) => current.as_ref() == Some(digest),
            None => current.is_none(),
        };
        let pending = backup
            .pending
            .as_ref()
            .is_some_and(|digest| current.as_ref() == Some(digest));
        let applied = match &backup.applied {
            Some(AppliedState::Digest(digest)) => current.as_ref() == Some(digest),
            Some(AppliedState::Absent) => current.is_none(),
            Some(AppliedState::Unknown) | None => false,
        };
        if let Some(removal) = &backup.removal {
            let trash_exists = path_is_occupied(&removal.trash);
            let removal_owned = match removal.phase {
                RemovalPhase::Planned => {
                    original || pending || applied || current.is_none() && trash_exists
                }
                RemovalPhase::Moved => current.is_none(),
            };
            if !removal_owned {
                return Err(MigrationError::Conflict(backup.target.clone()));
            }
            continue;
        }
        let transitioning = backup.transition.as_ref().is_some_and(|transition| {
            transition.old.as_ref().is_some_and(|old| {
                path_is_occupied(old)
                    && backup
                        .digest
                        .as_ref()
                        .is_some_and(|expected| digest_path(old).ok().as_ref() == Some(expected))
            }) || backup.digest.is_none()
        });
        if !original && !pending && !applied && !transitioning {
            return Err(MigrationError::Conflict(backup.target.clone()));
        }
        if let (Some(path), Some(expected)) = (&backup.backup, &backup.digest)
            && digest_path(path)? != *expected
        {
            return Err(MigrationError::BackupVerification(path.clone()));
        }
    }
    Ok(())
}

fn verify_committed_state(receipt: &ApplyReceipt) -> Result<(), MigrationError> {
    for backup in &receipt.backups {
        if backup.transition.is_some() || backup.removal.is_some() || backup.pending.is_some() {
            return Err(MigrationError::Conflict(backup.target.clone()));
        }
        match &backup.applied {
            Some(AppliedState::Absent) if !path_is_occupied(&backup.target) => {}
            Some(AppliedState::Digest(expected))
                if path_is_occupied(&backup.target)
                    && digest_path(&backup.target)? == *expected => {}
            _ => return Err(MigrationError::Conflict(backup.target.clone())),
        }
        if let (Some(path), Some(expected)) = (&backup.backup, &backup.digest)
            && digest_path(path)? != *expected
        {
            return Err(MigrationError::BackupVerification(path.clone()));
        }
    }
    Ok(())
}

fn create_backup_dir(root: &Path, provider_id: &str) -> Result<PathBuf, MigrationError> {
    create_dir_all(root)?;
    let millis = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis();
    let sequence = BACKUP_SEQUENCE.fetch_add(1, Ordering::Relaxed);
    let directory = root.join(format!("{provider_id}-{millis}-{sequence}"));
    fs::create_dir(&directory).map_err(|source| MigrationError::Io {
        action: "create backup directory",
        path: directory.clone(),
        source,
    })?;
    sync_directory(root)?;
    Ok(directory)
}

fn backup_targets(
    backup_dir: &Path,
    operations: &[MigrationOperation],
) -> Result<Vec<BackupEntry>, MigrationError> {
    let mut seen = BTreeSet::new();
    let mut entries = Vec::new();
    for operation in operations {
        let target = operation.target();
        if !seen.insert(target.to_path_buf()) {
            continue;
        }
        if path_is_occupied(target) {
            reject_symlink(target)?;
            let backup = backup_dir.join("items").join(entries.len().to_string());
            copy_path(target, &backup)?;
            let source_digest = digest_path(target)?;
            let backup_digest = digest_path(&backup)?;
            if source_digest != backup_digest {
                return Err(MigrationError::BackupVerification(target.to_path_buf()));
            }
            entries.push(BackupEntry {
                target: target.to_path_buf(),
                backup: Some(backup),
                digest: Some(backup_digest),
                pending: None,
                applied: None,
                transition: None,
                removal: None,
            });
        } else {
            entries.push(BackupEntry {
                target: target.to_path_buf(),
                backup: None,
                digest: None,
                pending: None,
                applied: None,
                transition: None,
                removal: None,
            });
        }
    }
    Ok(entries)
}

fn collect_missing_target_directories(
    operations: &[MigrationOperation],
    target_root: &Path,
) -> Result<Vec<PathBuf>, MigrationError> {
    let mut missing = BTreeSet::new();
    for operation in operations {
        let mut current = operation.target().parent();
        while let Some(directory) = current {
            if !directory.starts_with(target_root) {
                break;
            }
            reject_symlink_if_present(directory)?;
            if !path_is_occupied(directory) {
                missing.insert(directory.to_owned());
            }
            if directory == target_root {
                break;
            }
            current = directory.parent();
        }
    }
    let mut directories = missing.into_iter().collect::<Vec<_>>();
    directories.sort_by_key(|directory| std::cmp::Reverse(directory.components().count()));
    Ok(directories)
}

fn remove_created_directories_if_empty(
    receipt: &ApplyReceipt,
) -> Result<(), MigrationError> {
    for directory in &receipt.created_directories {
        let metadata = match fs::symlink_metadata(directory) {
            Ok(metadata) => metadata,
            Err(source) if source.kind() == io::ErrorKind::NotFound => continue,
            Err(source) => {
                return Err(MigrationError::Io {
                    action: "inspect created migration directory",
                    path: directory.clone(),
                    source,
                });
            }
        };
        if is_link_or_reparse(&metadata) || !metadata.is_dir() {
            return Err(MigrationError::Conflict(directory.clone()));
        }
        let mut entries = fs::read_dir(directory).map_err(|source| MigrationError::Io {
            action: "read created migration directory",
            path: directory.clone(),
            source,
        })?;
        if entries.next().is_none() {
            fs::remove_dir(directory).map_err(|source| MigrationError::Io {
                action: "remove empty created migration directory",
                path: directory.clone(),
                source,
            })?;
            sync_parent_directory(directory)?;
        }
    }
    Ok(())
}

fn verify_targets_unchanged(backups: &[BackupEntry]) -> Result<(), MigrationError> {
    for backup in backups {
        match &backup.digest {
            Some(expected) => {
                if !path_is_occupied(&backup.target) || digest_path(&backup.target)? != *expected {
                    return Err(MigrationError::Conflict(backup.target.clone()));
                }
            }
            None if path_is_occupied(&backup.target) => {
                return Err(MigrationError::Conflict(backup.target.clone()));
            }
            None => {}
        }
    }
    Ok(())
}

fn write_backup_manifest(
    receipt: &ApplyReceipt,
    phase: RecoveryPhase,
) -> Result<(), MigrationError> {
    let entries = receipt
        .backups
        .iter()
        .map(|entry| RecoveryManifestEntry {
            target: entry.target.clone(),
            backup: entry.backup.clone(),
            original_sha256: entry.digest.clone(),
            pending_sha256: entry.pending.clone(),
            applied: entry.applied.as_ref().map(|state| match state {
                AppliedState::Absent => RecoveryAppliedState::Absent,
                AppliedState::Digest(digest) => RecoveryAppliedState::Digest(digest.clone()),
                AppliedState::Unknown => RecoveryAppliedState::Unknown,
            }),
            transition: entry.transition.as_ref().map(|transition| RecoveryPathTransition {
                staging: transition.staging.clone(),
                old: transition.old.clone(),
                phase: transition.phase,
                strategy: transition.strategy,
                expected_displaced_sha256: transition.expected_displaced_sha256.clone(),
                conflict_sha256: transition.conflict_sha256.clone(),
            }),
            removal: entry.removal.as_ref().map(|removal| RecoveryRemovalTransition {
                trash: removal.trash.clone(),
                phase: removal.phase,
            }),
        })
        .collect::<Vec<_>>();
    let manifest = RecoveryManifest {
        schema_version: RECOVERY_SCHEMA_VERSION,
        provider_id: receipt.provider_id.to_owned(),
        target_root: receipt.target_root.clone(),
        secret_transaction_id: receipt.secret_transaction_id.clone(),
        phase,
        entries,
        created_directories: receipt.created_directories.clone(),
    };
    write_recovery_manifest(&receipt.backup_dir.join("manifest.json"), &manifest)
}

fn write_recovery_manifest(path: &Path, manifest: &RecoveryManifest) -> Result<(), MigrationError> {
    let bytes = serde_json::to_vec_pretty(manifest).map_err(|error| {
        MigrationError::Signing(format!("backup manifest serialization: {error}"))
    })?;
    write_bytes(path, &bytes)
}

/// Reports whether anything at all occupies `path`.
///
/// Unlike [`Path::exists`] this does not follow symbolic links, so a link whose
/// destination is missing still counts as occupied. Every safety decision in
/// this module — conflict detection, backup selection, and removal — uses this
/// definition, because a dangling link is a real object that a later write would
/// otherwise silently follow out of the migration root.
fn path_is_occupied(path: &Path) -> bool {
    fs::symlink_metadata(path).is_ok()
}

fn append_file_bytes(
    source: &Path,
    target: &Path,
    heading: &str,
) -> Result<Vec<u8>, MigrationError> {
    reject_symlink(source)?;
    let content = read_bytes(source)?;
    let mut existing = if path_is_occupied(target) {
        reject_symlink(target)?;
        read_bytes(target)?
    } else {
        Vec::new()
    };
    if !existing.is_empty() && !existing.ends_with(b"\n") {
        existing.push(b'\n');
    }
    existing.extend_from_slice(format!("\n<!-- {heading} -->\n\n").as_bytes());
    existing.extend_from_slice(&content);
    if !existing.ends_with(b"\n") {
        existing.push(b'\n');
    }
    Ok(existing)
}

fn generated_command_skill_bytes(source: &Path, name: &str) -> Result<Vec<u8>, MigrationError> {
    let content = read_text(source)?;
    let description = content
        .split("\n\n")
        .map(str::trim)
        .find(|part| !part.is_empty())
        .unwrap_or("Imported Claude command")
        .replace('\n', " ");
    let description = description.chars().take(180).collect::<String>();
    let generated = format!(
        "---\nname: {name}\ndescription: {}\ndisable-model-invocation: true\n---\n\n<!-- Imported inert Claude command -->\n\n{}\n",
        serde_json::to_string(&description)
            .map_err(|error| MigrationError::Signing(error.to_string()))?,
        content.trim_end()
    );
    Ok(generated.into_bytes())
}

fn transform_json_bytes(
    source: &Path,
    namespace: &str,
    store: &mut dyn SecretStore,
    transaction_id: &str,
) -> Result<Vec<u8>, MigrationError> {
    let text = read_text(source)?;
    let mut value: Value =
        serde_json::from_str(&text).map_err(|_| MigrationError::InvalidInput {
            path: source.to_path_buf(),
            reason: "JSON configuration is malformed".to_owned(),
        })?;
    redact_json_value(&mut value, namespace, "", false, store, transaction_id)?;
    serde_json::to_vec_pretty(&value).map_err(|_| MigrationError::InvalidInput {
        path: source.to_path_buf(),
        reason: "JSON configuration could not be serialized".to_owned(),
    })
}

fn redact_json_value(
    value: &mut Value,
    namespace: &str,
    pointer: &str,
    secret_container: bool,
    store: &mut dyn SecretStore,
    transaction_id: &str,
) -> Result<(), MigrationError> {
    match value {
        Value::Object(object) => {
            for (key, child) in object {
                if key.eq_ignore_ascii_case("env_http_headers") {
                    continue;
                }
                let next_pointer = format!("{pointer}/{key}");
                let child_container = secret_container_key(key);
                if let Value::String(secret) = child
                    && (secret_container || secret_key(key))
                {
                    let id = secret_identifier(namespace, &next_pointer);
                    let reference =
                        route_secret(store, transaction_id, &id, secret.as_bytes())?;
                    *child = Value::String(reference);
                } else {
                    redact_json_value(
                        child,
                        namespace,
                        &next_pointer,
                        secret_container || child_container,
                        store,
                        transaction_id,
                    )?;
                }
            }
        }
        Value::Array(array) => {
            for (index, child) in array.iter_mut().enumerate() {
                redact_json_value(
                    child,
                    namespace,
                    &format!("{pointer}/{index}"),
                    secret_container,
                    store,
                    transaction_id,
                )?;
            }
        }
        Value::String(secret) if secret_container => {
            let id = secret_identifier(namespace, pointer);
            let reference = route_secret(store, transaction_id, &id, secret.as_bytes())?;
            *value = Value::String(reference);
        }
        _ => {}
    }
    Ok(())
}

fn transform_text_bytes(
    source: &Path,
    namespace: &str,
    store: &mut dyn SecretStore,
    transaction_id: &str,
) -> Result<Vec<u8>, MigrationError> {
    let input = read_text(source)?;
    let mut output = String::new();
    let mut toml_secret_section = false;
    let mut yaml_secret_indent = None;
    for (index, line) in input.lines().enumerate() {
        let trimmed = line.trim_start();
        let indentation = line.len() - trimmed.len();
        if let Some(container_indent) = yaml_secret_indent
            && !trimmed.is_empty()
            && !trimmed.starts_with('#')
            && indentation <= container_indent
        {
            yaml_secret_indent = None;
        }
        if trimmed.starts_with('[') && trimmed.ends_with(']') {
            let section = trimmed.trim_matches(['[', ']']);
            toml_secret_section = section
                .split('.')
                .next_back()
                .is_some_and(secret_container_key);
        }
        let transformed = if trimmed.starts_with('#') || trimmed.is_empty() {
            line.to_owned()
        } else if let Some((key, separator, raw)) = split_assignment(line) {
            let normalized_key = key.trim().trim_matches(['"', '\'']);
            let trimmed_raw = raw.trim();
            let starts_yaml_container =
                separator == ':' && trimmed_raw.is_empty() && secret_container_key(normalized_key);
            if starts_yaml_container {
                yaml_secret_indent = Some(indentation);
                line.to_owned()
            } else if separator == '='
                && secret_container_key(normalized_key)
                && trimmed_raw.starts_with('{')
            {
                transform_toml_inline_secret_table(
                    key,
                    raw,
                    (source, index, normalized_key),
                    namespace,
                    store,
                    transaction_id,
                )?
            } else if secret_key(normalized_key)
                || secret_container_key(normalized_key)
                || toml_secret_section
                || yaml_secret_indent.is_some()
            {
                let value = unquote(trimmed_raw);
                if value.is_empty() {
                    line.to_owned()
                } else {
                    let id = secret_identifier(namespace, &format!("/{index}/{normalized_key}"));
                    let reference =
                        route_secret(store, transaction_id, &id, value.as_bytes())?;
                    format!("{key}{separator} \"{reference}\"")
                }
            } else {
                line.to_owned()
            }
        } else {
            line.to_owned()
        };
        output.push_str(&transformed);
        output.push('\n');
    }
    Ok(output.into_bytes())
}

fn transform_toml_inline_secret_table(
    key: &str,
    raw: &str,
    location: (&Path, usize, &str),
    namespace: &str,
    store: &mut dyn SecretStore,
    transaction_id: &str,
) -> Result<String, MigrationError> {
    let (source, line_index, container_key) = location;
    let open = raw
        .find('{')
        .ok_or_else(|| invalid_inline_table(source, line_index))?;
    let close =
        matching_outer_brace(raw, open).ok_or_else(|| invalid_inline_table(source, line_index))?;
    let suffix = &raw[close + 1..];
    if !suffix.trim().is_empty() && !suffix.trim_start().starts_with('#') {
        return Err(invalid_inline_table(source, line_index));
    }
    let content = &raw[open + 1..close];
    let mut replacements = Vec::new();
    for segment in top_level_segments(content, ',') {
        let text = &content[segment.clone()];
        if text.trim().is_empty() {
            continue;
        }
        let Some(equals) = top_level_delimiter(text, '=') else {
            return Err(invalid_inline_table(source, line_index));
        };
        let entry_key = text[..equals].trim().trim_matches(['"', '\'']);
        let value = &text[equals + 1..];
        let value_start = value.len() - value.trim_start().len();
        let value_end = value.trim_end().len();
        if value_start == value.len() || value_start > value_end {
            return Err(invalid_inline_table(source, line_index));
        }
        let value_range =
            segment.start + equals + 1 + value_start..segment.start + equals + 1 + value_end;
        let plaintext = unquote(&content[value_range.clone()]);
        if plaintext.is_empty() {
            continue;
        }
        let id = secret_identifier(
            namespace,
            &format!("/{line_index}/{container_key}/{entry_key}"),
        );
        let reference = route_secret(store, transaction_id, &id, plaintext.as_bytes())?;
        replacements.push((value_range, format!("\"{reference}\"")));
    }

    let mut transformed = content.to_owned();
    for (range, replacement) in replacements.into_iter().rev() {
        transformed.replace_range(range, &replacement);
    }
    Ok(format!(
        "{key}={prefix}{transformed}{suffix}",
        prefix = &raw[..=open],
        suffix = &raw[close..]
    ))
}

fn invalid_inline_table(source: &Path, line_index: usize) -> MigrationError {
    MigrationError::InvalidInput {
        path: source.to_owned(),
        reason: format!(
            "inline env/http_headers table on line {} is not safely transformable",
            line_index + 1
        ),
    }
}

fn matching_outer_brace(value: &str, open: usize) -> Option<usize> {
    let mut braces = 0_usize;
    let mut brackets = 0_usize;
    let mut quote = None;
    let mut escaped = false;
    for (offset, character) in value[open..].char_indices() {
        if let Some(delimiter) = quote {
            if delimiter == '"' && character == '\\' && !escaped {
                escaped = true;
                continue;
            }
            if character == delimiter && !escaped {
                quote = None;
            }
            escaped = false;
            continue;
        }
        match character {
            '"' | '\'' => quote = Some(character),
            '{' => braces += 1,
            '}' if braces == 1 && brackets == 0 => return Some(open + offset),
            '}' => braces = braces.checked_sub(1)?,
            '[' => brackets += 1,
            ']' => brackets = brackets.checked_sub(1)?,
            _ => {}
        }
    }
    None
}

fn top_level_segments(value: &str, delimiter: char) -> Vec<Range<usize>> {
    let mut segments = Vec::new();
    let mut start = 0;
    for index in top_level_delimiters(value, delimiter) {
        segments.push(start..index);
        start = index + delimiter.len_utf8();
    }
    segments.push(start..value.len());
    segments
}

fn top_level_delimiter(value: &str, delimiter: char) -> Option<usize> {
    top_level_delimiters(value, delimiter).into_iter().next()
}

fn top_level_delimiters(value: &str, delimiter: char) -> Vec<usize> {
    let mut found = Vec::new();
    let mut braces = 0_usize;
    let mut brackets = 0_usize;
    let mut quote = None;
    let mut escaped = false;
    for (index, character) in value.char_indices() {
        if let Some(quote_character) = quote {
            if quote_character == '"' && character == '\\' && !escaped {
                escaped = true;
                continue;
            }
            if character == quote_character && !escaped {
                quote = None;
            }
            escaped = false;
            continue;
        }
        match character {
            '"' | '\'' => quote = Some(character),
            '{' => braces += 1,
            '}' => braces = braces.saturating_sub(1),
            '[' => brackets += 1,
            ']' => brackets = brackets.saturating_sub(1),
            _ if character == delimiter && braces == 0 && brackets == 0 => found.push(index),
            _ => {}
        }
    }
    found
}

fn import_environment_bytes(
    source: &Path,
    namespace: &str,
    store: &mut dyn SecretStore,
    transaction_id: &str,
) -> Result<Vec<u8>, MigrationError> {
    let input = read_text(source)?;
    let mut references = BTreeMap::new();
    for (index, line) in input.lines().enumerate() {
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') {
            continue;
        }
        let Some((key, value)) = trimmed.split_once('=') else {
            return Err(MigrationError::InvalidInput {
                path: source.to_path_buf(),
                reason: format!("environment line {} is not KEY=VALUE", index + 1),
            });
        };
        let key = key.trim();
        if !valid_environment_key(key) {
            return Err(MigrationError::InvalidInput {
                path: source.to_path_buf(),
                reason: format!("environment key on line {} is unsafe", index + 1),
            });
        }
        let value = unquote(value.trim());
        if !value.is_empty() {
            let id = secret_identifier(namespace, &format!("/{key}"));
            let reference = route_secret(store, transaction_id, &id, value.as_bytes())?;
            references.insert(key.to_owned(), reference);
        }
    }
    serde_json::to_vec_pretty(&references).map_err(|error| {
        MigrationError::Signing(format!("environment reference serialization: {error}"))
    })
}

fn stored_document_bytes(
    source: &Path,
    secret_id: &str,
    store: &mut dyn SecretStore,
    transaction_id: &str,
) -> Result<Vec<u8>, MigrationError> {
    let content = read_bytes(source)?;
    let reference = route_secret(store, transaction_id, secret_id, &content)?;
    let mut object = Map::new();
    object.insert("secret_ref".to_owned(), Value::String(reference));
    serde_json::to_vec_pretty(&Value::Object(object))
        .map_err(|error| MigrationError::Signing(error.to_string()))
}

fn route_secret(
    store: &mut dyn SecretStore,
    transaction_id: &str,
    id: &str,
    value: &[u8],
) -> Result<String, MigrationError> {
    let reference = store.stage(transaction_id, id, SecretValue::new(value))?;
    if !valid_secret_reference(&reference) {
        return Err(MigrationError::SecretStore(SecretStoreError::new(
            "secret store returned an invalid reference",
        )));
    }
    Ok(reference)
}

/// Rejects anything an adapter returns that is not an opaque store handle, so a
/// store that echoes the plaintext back cannot get it written into a migrated
/// configuration file.
fn valid_secret_reference(reference: &str) -> bool {
    (reference.starts_with("keyring://") || reference.starts_with("service://"))
        && reference.bytes().all(|byte| {
            byte.is_ascii_alphanumeric() || matches!(byte, b':' | b'/' | b'.' | b'_' | b'-')
        })
}

fn secret_identifier(namespace: &str, pointer: &str) -> String {
    let digest = digest_bytes(pointer.as_bytes());
    format!("{namespace}-{}", &digest[..16])
}

fn secret_key(key: &str) -> bool {
    let normalized = key.to_ascii_lowercase().replace(['-', '.'], "_");
    normalized.contains("token")
        || normalized.contains("secret")
        || normalized.contains("password")
        || normalized.contains("api_key")
        || normalized.contains("apikey")
        || normalized.contains("credential")
        || normalized == "authorization"
}

fn secret_container_key(key: &str) -> bool {
    matches!(
        key.to_ascii_lowercase().as_str(),
        "env" | "headers" | "http_headers"
    )
}

fn split_assignment(line: &str) -> Option<(&str, char, &str)> {
    let equals = line.find('=');
    let colon = line.find(':');
    let index = match (equals, colon) {
        (Some(left), Some(right)) => left.min(right),
        (Some(index), None) | (None, Some(index)) => index,
        (None, None) => return None,
    };
    let separator = line.as_bytes()[index] as char;
    Some((&line[..index], separator, &line[index + 1..]))
}

fn unquote(value: &str) -> &str {
    if value.len() >= 2
        && ((value.starts_with('"') && value.ends_with('"'))
            || (value.starts_with('\'') && value.ends_with('\'')))
    {
        &value[1..value.len() - 1]
    } else {
        value
    }
}

fn valid_environment_key(key: &str) -> bool {
    let mut bytes = key.bytes();
    matches!(bytes.next(), Some(b'a'..=b'z' | b'A'..=b'Z' | b'_'))
        && bytes.all(|byte| byte.is_ascii_alphanumeric() || byte == b'_')
}

pub(crate) fn reject_executable_tree(path: &Path) -> Result<(), MigrationError> {
    reject_symlink(path)?;
    if path.is_file() {
        return reject_executable_file(path);
    }
    for entry in sorted_entries(path)? {
        let metadata = fs::symlink_metadata(entry.path()).map_err(|source| MigrationError::Io {
            action: "inspect source type",
            path: entry.path(),
            source,
        })?;
        if is_link_or_reparse(&metadata) {
            return Err(MigrationError::Symlink(entry.path()));
        }
        if metadata.is_dir() {
            reject_executable_tree(&entry.path())?;
        } else if metadata.is_file() {
            reject_executable_file(&entry.path())?;
        }
    }
    Ok(())
}

fn reject_executable_file(path: &Path) -> Result<(), MigrationError> {
    let extension = path
        .extension()
        .and_then(|value| value.to_str())
        .unwrap_or_default()
        .to_ascii_lowercase();
    if matches!(
        extension.as_str(),
        "js" | "cjs" | "mjs" | "jsx" | "ts" | "tsx" | "wasm"
    ) {
        Err(MigrationError::ExecutableArtifact(path.to_path_buf()))
    } else {
        Ok(())
    }
}

pub(crate) fn digest_path(path: &Path) -> Result<String, MigrationError> {
    reject_symlink(path)?;
    if path.is_file() {
        let content_digest = digest_file_content(path)?;
        return Ok(encode_hex(&domain_file_digest(&content_digest)));
    }

    if !path.is_dir() {
        return Err(MigrationError::SourceNotFound {
            provider: "migration",
            path: path.to_path_buf(),
        });
    }
    Ok(encode_hex(&digest_directory(path, path)?))
}

fn optional_digest_path(path: &Path) -> Result<Option<String>, MigrationError> {
    match fs::symlink_metadata(path) {
        Ok(_) => digest_path(path).map(Some),
        Err(source) if source.kind() == io::ErrorKind::NotFound => Ok(None),
        Err(source) => Err(MigrationError::Io {
            action: "inspect digest path",
            path: path.to_owned(),
            source,
        }),
    }
}

fn digest_directory(
    root: &Path,
    current: &Path,
) -> Result<[u8; 32], MigrationError> {
    const DIRECTORY_ENTRY: u8 = 1;
    const FILE_ENTRY: u8 = 2;
    let mut hasher = Sha256::new();
    hasher.update(b"directory\0");
    for entry in sorted_entries(current)? {
        let path = entry.path();
        if is_publication_lock_artifact(&path) {
            continue;
        }
        let metadata = fs::symlink_metadata(&path).map_err(|source| MigrationError::Io {
            action: "inspect source type",
            path: path.clone(),
            source,
        })?;
        if is_link_or_reparse(&metadata) {
            return Err(MigrationError::Symlink(path));
        }
        let relative = path
            .strip_prefix(root)
            .map_err(|_| MigrationError::UnsafeTarget(path.clone()))?;
        let raw_path = raw_os_path_bytes(relative);
        if metadata.is_dir() {
            hasher.update([DIRECTORY_ENTRY]);
            update_length_prefixed(&mut hasher, &raw_path);
            hasher.update(digest_directory(root, &path)?);
        } else if metadata.is_file() {
            hasher.update([FILE_ENTRY]);
            update_length_prefixed(&mut hasher, &raw_path);
            hasher.update(digest_file_content(&path)?);
        }
    }
    Ok(hasher.finalize().into())
}

fn digest_file_content(path: &Path) -> Result<[u8; 32], MigrationError> {
    let file = File::open(path).map_err(|source| MigrationError::Io {
        action: "open for hashing",
        path: path.to_owned(),
        source,
    })?;
    let mut reader = file;
    let mut buffer = vec![0_u8; HASH_BUFFER_BYTES];
    let mut hasher = Sha256::new();
    loop {
        let read = reader
            .read(&mut buffer)
            .map_err(|source| MigrationError::Io {
                action: "hash",
                path: path.to_owned(),
                source,
            })?;
        if read == 0 {
            return Ok(hasher.finalize().into());
        }
        hasher.update(&buffer[..read]);
    }
}

fn update_length_prefixed(hasher: &mut Sha256, bytes: &[u8]) {
    hasher.update(
        u64::try_from(bytes.len())
            .expect("filesystem path length fits in u64")
            .to_le_bytes(),
    );
    hasher.update(bytes);
}

#[cfg(unix)]
fn raw_os_path_bytes(path: &Path) -> Vec<u8> {
    use std::os::unix::ffi::OsStrExt;

    path.as_os_str().as_bytes().to_vec()
}

#[cfg(windows)]
fn raw_os_path_bytes(path: &Path) -> Vec<u8> {
    use std::os::windows::ffi::OsStrExt;

    path.as_os_str()
        .encode_wide()
        .flat_map(u16::to_le_bytes)
        .collect()
}

#[cfg(not(any(unix, windows)))]
fn raw_os_path_bytes(path: &Path) -> Vec<u8> {
    path.as_os_str().as_encoded_bytes().to_vec()
}

fn digest_bytes(bytes: &[u8]) -> String {
    encode_hex(&Sha256::digest(bytes))
}

fn digest_path_bytes(bytes: &[u8]) -> String {
    let content: [u8; 32] = Sha256::digest(bytes).into();
    encode_hex(&domain_file_digest(&content))
}

fn domain_file_digest(content_digest: &[u8; 32]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(b"file\0");
    hasher.update(content_digest);
    hasher.finalize().into()
}

fn valid_digest(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
}

fn encode_hex(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut encoded = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        encoded.push(HEX[usize::from(byte >> 4)] as char);
        encoded.push(HEX[usize::from(byte & 0x0f)] as char);
    }
    encoded
}

fn ensure_target_within(root: &Path, target: &Path) -> Result<(), MigrationError> {
    if target
        .components()
        .any(|component| matches!(component, Component::ParentDir | Component::CurDir))
        || !target.starts_with(root)
    {
        return Err(MigrationError::UnsafeTarget(target.to_path_buf()));
    }
    Ok(())
}

/// Rejects a target whose root, directories, or final component is a symbolic
/// link.
///
/// A *dangling* link matters as much as a live one: `Path::exists` follows links
/// and reports `false` for a link whose destination is missing, so checking
/// existence would wave one through and let `fs::write` follow it and create the
/// file wherever the link points — outside the migration root, and without a
/// backup. Presence is therefore tested with `symlink_metadata`, which describes
/// the link itself.
fn ensure_no_symlink_ancestors(root: &Path, target: &Path) -> Result<(), MigrationError> {
    let relative = target
        .strip_prefix(root)
        .map_err(|_| MigrationError::UnsafeTarget(target.to_path_buf()))?;
    let mut current = root.to_path_buf();
    reject_symlink_if_present(&current)?;
    for component in relative.components() {
        let Component::Normal(part) = component else {
            continue;
        };
        current.push(part);
        reject_symlink_if_present(&current)?;
    }
    Ok(())
}

/// Rejects `path` when it is a symbolic link, tolerating a path that is absent.
fn reject_symlink_if_present(path: &Path) -> Result<(), MigrationError> {
    match fs::symlink_metadata(path) {
        Ok(metadata) if is_link_or_reparse(&metadata) => {
            Err(MigrationError::Symlink(path.to_path_buf()))
        }
        Ok(_) => Ok(()),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(source) => Err(MigrationError::Io {
            action: "inspect",
            path: path.to_path_buf(),
            source,
        }),
    }
}

fn copy_path(source: &Path, target: &Path) -> Result<(), MigrationError> {
    reject_symlink(source)?;
    if source.is_dir() {
        copy_directory_atomically(source, target)
    } else if source.is_file() {
        copy_file(source, target)
    } else {
        Err(MigrationError::SourceNotFound {
            provider: "migration",
            path: source.to_path_buf(),
        })
    }
}

fn copy_path_for_apply(
    source: &Path,
    target: &Path,
    receipt: &mut ApplyReceipt,
    replacement_pending: Option<&str>,
) -> Result<(), MigrationError> {
    reject_symlink(source)?;
    create_parent(target)?;
    let staging = if source.is_dir() {
        let staging = create_staging_directory(target)?;
        copy_directory_contents(source, &staging)?;
        set_path_permissions_from(source, &staging)?;
        sync_directory(&staging)?;
        staging
    } else if source.is_file() {
        let staging = create_staging_file(target)?;
        populate_staging_file_from_source(source, &staging)?;
        staging
    } else {
        return Err(MigrationError::SourceNotFound {
            provider: "migration",
            path: source.to_owned(),
        });
    };
    let staged_digest = digest_path(&staging)?;
    if replacement_pending.is_some_and(|expected| expected != staged_digest) {
        return Err(MigrationError::BackupVerification(source.to_owned()));
    }
    publish_staged_path_transactionally(
        &staging,
        target,
        receipt,
        replacement_pending,
    )
}

fn copy_directory_atomically(source: &Path, target: &Path) -> Result<(), MigrationError> {
    create_parent(target)?;
    let staging = create_staging_directory(target)?;
    let result = copy_directory_contents(source, &staging)
        .and_then(|()| set_path_permissions_from(source, &staging))
        .and_then(|()| sync_directory(&staging))
        .and_then(|()| publish_staged_path(&staging, target));
    if result.is_err() && path_is_occupied(&staging) {
        let _ = remove_path_if_exists(&staging);
    }
    result
}

fn copy_directory_contents(source: &Path, target: &Path) -> Result<(), MigrationError> {
    for entry in sorted_entries(source)? {
        let entry_source = entry.path();
        if is_publication_lock_artifact(&entry_source) {
            continue;
        }
        let entry_target = target.join(entry.file_name());
        let metadata =
            fs::symlink_metadata(&entry_source).map_err(|source| MigrationError::Io {
                action: "inspect source type",
                path: entry_source.clone(),
                source,
            })?;
        if is_link_or_reparse(&metadata) {
            return Err(MigrationError::Symlink(entry_source));
        }
        if metadata.is_dir() {
            fs::create_dir(&entry_target).map_err(|source| MigrationError::Io {
                action: "create staging directory",
                path: entry_target.clone(),
                source,
            })?;
            sync_directory(target)?;
            copy_directory_contents(&entry_source, &entry_target)?;
            set_path_permissions(&entry_target, metadata.permissions())?;
            sync_directory(&entry_target)?;
        } else if metadata.is_file() {
            copy_new_file_durably(&entry_source, &entry_target)?;
        }
    }
    Ok(())
}

fn set_path_permissions_from(source: &Path, target: &Path) -> Result<(), MigrationError> {
    let permissions =
        fs::symlink_metadata(source).map_err(|source_error| MigrationError::Io {
            action: "inspect source permissions",
            path: source.to_owned(),
            source: source_error,
        })?
        .permissions();
    set_path_permissions(target, permissions)
}

fn set_path_permissions(
    target: &Path,
    permissions: fs::Permissions,
) -> Result<(), MigrationError> {
    fs::set_permissions(target, permissions).map_err(|source| MigrationError::Io {
        action: "set staged path permissions",
        path: target.to_owned(),
        source,
    })
}

#[cfg(unix)]
fn set_unix_mode(file: &File, mode: u32) -> io::Result<()> {
    use std::os::unix::fs::PermissionsExt;

    file.set_permissions(fs::Permissions::from_mode(mode))
}

#[cfg(not(unix))]
fn set_unix_mode(_file: &File, _mode: u32) -> io::Result<()> {
    Ok(())
}

fn copy_new_file_durably(source: &Path, target: &Path) -> Result<(), MigrationError> {
    let metadata = fs::symlink_metadata(source).map_err(|source| MigrationError::Io {
        action: "inspect copy source",
        path: source.to_owned(),
        source,
    })?;
    if is_link_or_reparse(&metadata) || !metadata.is_file() {
        return Err(MigrationError::Symlink(source.to_owned()));
    }

    let mut input = File::open(source).map_err(|source| MigrationError::Io {
        action: "open copy source",
        path: source.to_owned(),
        source,
    })?;
    let mut output = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(target)
        .map_err(|source| MigrationError::Io {
            action: "create copied file",
            path: target.to_owned(),
            source,
        })?;
    io::copy(&mut input, &mut output).map_err(|source| MigrationError::Io {
        action: "copy file contents",
        path: target.to_owned(),
        source,
    })?;
    output
        .set_permissions(metadata.permissions())
        .and_then(|()| output.sync_all())
        .map_err(|source| MigrationError::Io {
            action: "synchronize copied file",
            path: target.to_owned(),
            source,
        })
}

fn write_new_file_durably(
    path: &Path,
    bytes: &[u8],
    unix_mode: u32,
) -> Result<(), MigrationError> {
    let mut output = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path)
        .map_err(|source| MigrationError::Io {
            action: "create staged file",
            path: path.to_owned(),
            source,
        })?;
    set_unix_mode(&output, unix_mode).map_err(|source| MigrationError::Io {
        action: "set staged file permissions",
        path: path.to_owned(),
        source,
    })?;
    output
        .write_all(bytes)
        .and_then(|()| output.sync_all())
        .map_err(|source| MigrationError::Io {
            action: "synchronize staged file",
            path: path.to_owned(),
            source,
        })
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum TransitionPoint {
    Prepared,
    BeforePublish,
    Exchanged,
    OldMoved,
    Published,
    Cleaning,
    Cleaned,
}

fn publish_staged_path_transactionally(
    staging: &Path,
    target: &Path,
    receipt: &mut ApplyReceipt,
    replacement_pending: Option<&str>,
) -> Result<(), MigrationError> {
    publish_staged_path_transactionally_with_hook(
        staging,
        target,
        receipt,
        replacement_pending,
        |_| Ok(()),
    )
}

fn publish_staged_path_transactionally_with_hook(
    staging: &Path,
    target: &Path,
    receipt: &mut ApplyReceipt,
    replacement_pending: Option<&str>,
    mut hook: impl FnMut(TransitionPoint) -> Result<(), MigrationError>,
) -> Result<(), MigrationError> {
    let expected_displaced = verify_operation_target(receipt, target)?;
    if let Some(expected) = replacement_pending {
        record_pending_state(receipt, target, expected);
    }
    let occupied = path_is_occupied(target);
    let staging_is_file = fs::symlink_metadata(staging)
        .map(|metadata| metadata.is_file())
        .map_err(|source| MigrationError::Io {
            action: "inspect staged publication",
            path: staging.to_owned(),
            source,
        })?;
    let target_is_file = if occupied {
        fs::symlink_metadata(target)
            .map(|metadata| metadata.is_file())
            .map_err(|source| MigrationError::Io {
                action: "inspect publication target",
                path: target.to_owned(),
                source,
            })?
    } else {
        false
    };
    let strategy = select_transition_strategy(
        occupied,
        atomic_exchange_supported(),
        cfg!(windows),
        staging_is_file && target_is_file,
        target,
    )?;
    let old = match strategy {
        TransitionStrategy::Exchange => Some(staging.to_owned()),
        TransitionStrategy::DisplaceFile => Some(allocate_transition_path(target, "displaced")?),
        TransitionStrategy::Rename => occupied
            .then(|| allocate_transition_path(target, "old"))
            .transpose()?,
    };
    set_path_transition(
        receipt,
        target,
        Some(PathTransition {
            staging: staging.to_owned(),
            old: old.clone(),
            phase: TransitionPhase::Prepared,
            strategy,
            expected_displaced_sha256: expected_displaced.clone(),
            conflict_sha256: None,
        }),
    )?;
    write_backup_manifest(receipt, RecoveryPhase::Applying)?;
    hook(TransitionPoint::Prepared)?;
    hook(TransitionPoint::BeforePublish)?;

    match strategy {
        TransitionStrategy::Exchange => {
            exchange_paths_atomically(staging, target).map_err(|source| MigrationError::Io {
                action: "exchange staged migration target",
                path: target.to_owned(),
                source,
            })?;
            hook(TransitionPoint::Exchanged)?;
        }
        TransitionStrategy::DisplaceFile => {
            let old = old.as_ref().expect("file displacement reserves old path");
            claw_config::displace_file_atomically(staging, target, old).map_err(|source| {
                MigrationError::Io {
                    action: "displace staged migration file",
                    path: target.to_owned(),
                    source,
                }
            })?;
            hook(TransitionPoint::Exchanged)?;
        }
        TransitionStrategy::Rename => {
            if let Some(old) = &old {
                reject_symlink(target)?;
                fs::rename(target, old).map_err(|source| MigrationError::Io {
                    action: "move old migration target aside",
                    path: target.to_owned(),
                    source,
                })?;
                set_transition_phase(receipt, target, TransitionPhase::OldMoved)?;
                write_backup_manifest(receipt, RecoveryPhase::Applying)?;
                hook(TransitionPoint::OldMoved)?;
                fs::rename(staging, target).map_err(|source| MigrationError::Io {
                    action: "publish staged migration target",
                    path: target.to_owned(),
                    source,
                })?;
            } else {
                match rename_path_no_replace(staging, target) {
                    Ok(()) => {}
                    Err(source) if path_is_occupied(target) => {
                        let target_metadata =
                            fs::symlink_metadata(target).map_err(|inspect| MigrationError::Io {
                                action: "inspect raced publication target",
                                path: target.to_owned(),
                                source: inspect,
                            })?;
                        let staging_metadata =
                            fs::symlink_metadata(staging).map_err(|inspect| MigrationError::Io {
                                action: "inspect raced staging target",
                                path: staging.to_owned(),
                                source: inspect,
                            })?;
                        let upgraded = select_transition_strategy(
                            true,
                            atomic_exchange_supported(),
                            cfg!(windows),
                            target_metadata.is_file() && staging_metadata.is_file(),
                            target,
                        )?;
                        let upgraded_old = match upgraded {
                            TransitionStrategy::Exchange => staging.to_owned(),
                            TransitionStrategy::DisplaceFile => {
                                allocate_transition_path(target, "displaced")?
                            }
                            TransitionStrategy::Rename => unreachable!("occupied target upgraded"),
                        };
                        {
                            let transition = receipt.backups
                                .iter_mut()
                                .find(|entry| entry.target == target)
                                .and_then(|entry| entry.transition.as_mut())
                                .ok_or_else(|| MigrationError::Conflict(target.to_owned()))?;
                            transition.strategy = upgraded;
                            transition.old = Some(upgraded_old.clone());
                        }
                        write_backup_manifest(receipt, RecoveryPhase::Applying)?;
                        match upgraded {
                            TransitionStrategy::Exchange => {
                                exchange_paths_atomically(staging, target).map_err(|source| {
                                    MigrationError::Io {
                                        action: "exchange raced migration target",
                                        path: target.to_owned(),
                                        source,
                                    }
                                })?;
                            }
                            TransitionStrategy::DisplaceFile => {
                                claw_config::displace_file_atomically(
                                    staging,
                                    target,
                                    &upgraded_old,
                                )
                                .map_err(|source| MigrationError::Io {
                                    action: "displace raced migration file",
                                    path: target.to_owned(),
                                    source,
                                })?;
                            }
                            TransitionStrategy::Rename => unreachable!("occupied target upgraded"),
                        }
                    }
                    Err(source) => {
                        return Err(MigrationError::Io {
                            action: "publish new migration target",
                            path: target.to_owned(),
                            source,
                        });
                    }
                }
            }
        }
    }
    set_transition_phase(receipt, target, TransitionPhase::Published)?;
    write_backup_manifest(receipt, RecoveryPhase::Applying)?;
    sync_parent_directory(target)?;
    hook(TransitionPoint::Published)?;
    validate_displaced_publication(receipt, target)?;

    if let Some(old) = &old {
        set_transition_phase(receipt, target, TransitionPhase::Cleaning)?;
        write_backup_manifest(receipt, RecoveryPhase::Applying)?;
        hook(TransitionPoint::Cleaning)?;
        remove_path_if_exists(old)?;
    }
    set_path_transition(receipt, target, None)?;
    write_backup_manifest(receipt, RecoveryPhase::Applying)?;
    hook(TransitionPoint::Cleaned)
}

fn validate_displaced_publication(
        receipt: &mut ApplyReceipt,
        target: &Path,
    ) -> Result<(), MigrationError> {
        let index = receipt
            .backups
            .iter()
            .position(|entry| entry.target == target)
            .ok_or_else(|| MigrationError::Conflict(target.to_owned()))?;
        let expected = receipt.backups[index]
            .transition
            .as_ref()
            .and_then(|transition| transition.expected_displaced_sha256.clone());
        let transition = receipt.backups[index]
            .transition
            .as_ref()
            .expect("expected digest requires transition")
            .clone();
        if expected.is_none() && transition.old.is_none() {
            return Ok(());
        }
        let old = transition
            .old
            .as_ref()
            .ok_or_else(|| MigrationError::Conflict(target.to_owned()))?;
        if !path_is_occupied(old) {
            return expected.map_or(Ok(()), |_| {
                Err(MigrationError::Conflict(target.to_owned()))
            });
        }
        let displaced = digest_path(old)?;
        if expected.as_ref() == Some(&displaced) {
            return Ok(());
        }
        backup_migration_conflict(receipt, old)?;
        receipt.backups[index]
            .transition
            .as_mut()
            .expect("transition remains present")
            .conflict_sha256 = Some(displaced.clone());
        receipt.backups[index]
            .transition
            .as_mut()
            .expect("transition remains present")
            .phase = TransitionPhase::ConflictRestoring;
        write_backup_manifest(receipt, RecoveryPhase::Applying)?;
        restore_transition_conflict(receipt, index)?;
        Err(MigrationError::Conflict(target.to_owned()))
    }

fn restore_transition_conflict(
        receipt: &mut ApplyReceipt,
        index: usize,
    ) -> Result<(), MigrationError> {
        let transition = receipt.backups[index]
            .transition
            .as_ref()
            .expect("conflict restoration requires transition")
            .clone();
        let old = transition
            .old
            .as_ref()
            .expect("occupied transition retains displaced object");
        match transition.strategy {
            TransitionStrategy::Exchange => {
                exchange_paths_atomically(old, &receipt.backups[index].target).map_err(|source| {
                    MigrationError::Io {
                        action: "restore concurrent migration target",
                        path: receipt.backups[index].target.clone(),
                        source,
                    }
                })?;
            }
            TransitionStrategy::DisplaceFile => {
                claw_config::displace_file_atomically(
                    old,
                    &receipt.backups[index].target,
                    &transition.staging,
                )
                .map_err(|source| MigrationError::Io {
                    action: "restore concurrent migration file",
                    path: receipt.backups[index].target.clone(),
                    source,
                })?;
            }
            TransitionStrategy::Rename => {
                return Err(MigrationError::InvalidInput {
                    path: receipt.backups[index].target.clone(),
                    reason: "rename transition cannot restore displaced conflict".to_owned(),
                });
            }
        }
        sync_parent_directory(&receipt.backups[index].target)?;
        let pending = receipt.backups[index]
            .pending
            .as_ref()
            .ok_or_else(|| MigrationError::Conflict(receipt.backups[index].target.clone()))?;
        if digest_path(&transition.staging)? != *pending {
            backup_migration_conflict(receipt, &transition.staging)?;
            return Err(MigrationError::Conflict(
                receipt.backups[index].target.clone(),
            ));
        }
        receipt.backups[index]
            .transition
            .as_mut()
            .expect("transition remains present")
            .phase = TransitionPhase::ConflictRestored;
        write_backup_manifest(receipt, RecoveryPhase::Applying)
    }

fn backup_migration_conflict(
        receipt: &ApplyReceipt,
        source: &Path,
    ) -> Result<PathBuf, MigrationError> {
        let directory = receipt.backup_dir.join("conflicts");
        create_dir_all(&directory)?;
        let sequence = BACKUP_SEQUENCE.fetch_add(1, Ordering::Relaxed);
        let backup = directory.join(sequence.to_string());
        copy_path(source, &backup)?;
        sync_directory(&directory)?;
        Ok(backup)
    }
fn select_transition_strategy(
    occupied: bool,
    exchange_supported: bool,
    file_displacement_supported: bool,
    file_to_file: bool,
    target: &Path,
) -> Result<TransitionStrategy, MigrationError> {
    match (
        occupied,
        exchange_supported,
        file_displacement_supported && file_to_file,
    ) {
        (true, true, _) => Ok(TransitionStrategy::Exchange),
        (true, false, true) => Ok(TransitionStrategy::DisplaceFile),
        (true, false, false) => Err(MigrationError::InvalidInput {
            path: target.to_owned(),
            reason: "cross-type or directory overwrite requires native atomic exchange".to_owned(),
        }),
        (false, _, _) => Ok(TransitionStrategy::Rename),
    }
}

fn allocate_transition_path(target: &Path, label: &str) -> Result<PathBuf, MigrationError> {
    let parent = target
        .parent()
        .ok_or_else(|| MigrationError::UnsafeTarget(target.to_owned()))?;
    let name = target
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or("target");
    for _ in 0..128 {
        let sequence = BACKUP_SEQUENCE.fetch_add(1, Ordering::Relaxed);
        let candidate = parent.join(format!(
            ".{name}.gta-claw.{label}.{}.{sequence}",
            std::process::id()
        ));
        match fs::symlink_metadata(&candidate) {
            Err(source) if source.kind() == io::ErrorKind::NotFound => return Ok(candidate),
            Ok(_) => {}
            Err(source) => {
                return Err(MigrationError::Io {
                    action: "inspect transition path",
                    path: candidate,
                    source,
                });
            }
        }
    }
    Err(MigrationError::Io {
        action: "allocate transition path",
        path: target.to_owned(),
        source: io::Error::new(
            io::ErrorKind::AlreadyExists,
            "could not allocate a unique transition path",
        ),
    })
}

fn set_path_transition(
    receipt: &mut ApplyReceipt,
    target: &Path,
    transition: Option<PathTransition>,
) -> Result<(), MigrationError> {
    let entry = receipt
        .backups
        .iter_mut()
        .find(|entry| entry.target == target)
        .ok_or_else(|| MigrationError::Conflict(target.to_owned()))?;
    entry.transition = transition;
    Ok(())
}

fn set_transition_phase(
    receipt: &mut ApplyReceipt,
    target: &Path,
    phase: TransitionPhase,
) -> Result<(), MigrationError> {
    let transition = receipt
        .backups
        .iter_mut()
        .find(|entry| entry.target == target)
        .and_then(|entry| entry.transition.as_mut())
        .ok_or_else(|| MigrationError::Conflict(target.to_owned()))?;
    transition.phase = phase;
    Ok(())
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum RemovalPoint {
    Planned,
    Renamed,
    Moved,
    Cleaned,
}

fn remove_created_target_transactionally(
    receipt: &mut ApplyReceipt,
    index: usize,
) -> Result<(), MigrationError> {
    remove_created_target_transactionally_with_hook(receipt, index, |_| Ok(()))
}

fn remove_created_target_transactionally_with_hook(
    receipt: &mut ApplyReceipt,
    index: usize,
    mut hook: impl FnMut(RemovalPoint) -> Result<(), MigrationError>,
) -> Result<(), MigrationError> {
    if receipt.backups[index].removal.is_none() {
        let expected_owned = receipt.backups[index]
            .pending
            .as_ref()
            .or_else(|| match &receipt.backups[index].applied {
                Some(AppliedState::Digest(digest)) => Some(digest),
                _ => None,
            })
            .cloned();
        if path_is_occupied(&receipt.backups[index].target) {
            let current = digest_path(&receipt.backups[index].target)?;
            if expected_owned.as_ref() != Some(&current) {
                return Err(MigrationError::Conflict(
                    receipt.backups[index].target.clone(),
                ));
            }
        } else if !matches!(
            receipt.backups[index].applied,
            Some(AppliedState::Absent)
        ) {
            return Err(MigrationError::Conflict(
                receipt.backups[index].target.clone(),
            ));
        }
    }
    if receipt.backups[index].removal.is_none() {
        let target = receipt.backups[index].target.clone();
        let trash = allocate_transition_path(&target, "rollback-trash")?;
        receipt.backups[index].removal = Some(RemovalTransition {
            trash,
            phase: RemovalPhase::Planned,
        });
        write_backup_manifest(receipt, RecoveryPhase::Applying)?;
        hook(RemovalPoint::Planned)?;
    }

    let target = receipt.backups[index].target.clone();
    let trash = receipt.backups[index]
        .removal
        .as_ref()
        .expect("removal was initialized")
        .trash
        .clone();
    let target_exists = path_is_occupied(&target);
    let trash_exists = path_is_occupied(&trash);
    if target_exists && trash_exists {
        return Err(MigrationError::Conflict(target));
    }
    if target_exists {
        fs::rename(&target, &trash).map_err(|source| MigrationError::Io {
            action: "move created target to rollback trash",
            path: target.clone(),
            source,
        })?;
        sync_parent_directory(&target)?;
        hook(RemovalPoint::Renamed)?;
    }

    receipt.backups[index].pending = None;
    receipt.backups[index].applied = Some(AppliedState::Absent);
    receipt.backups[index]
        .removal
        .as_mut()
        .expect("removal remains initialized")
        .phase = RemovalPhase::Moved;
    write_backup_manifest(receipt, RecoveryPhase::Applying)?;
    hook(RemovalPoint::Moved)?;

    if path_is_occupied(&trash) {
        remove_path_if_exists(&trash)?;
    }
    receipt.backups[index].removal = None;
    write_backup_manifest(receipt, RecoveryPhase::Applying)?;
    hook(RemovalPoint::Cleaned)
}

fn create_staging_directory(target: &Path) -> Result<PathBuf, MigrationError> {
    let parent = target
        .parent()
        .ok_or_else(|| MigrationError::UnsafeTarget(target.to_owned()))?;
    let file_name = target
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or("target");
    for _ in 0..128 {
        let sequence = BACKUP_SEQUENCE.fetch_add(1, Ordering::Relaxed);
        let staging = parent.join(format!(
            ".{file_name}.gta-claw.migrate-stage.{}.{sequence}",
            std::process::id()
        ));
        match fs::create_dir(&staging) {
            Ok(()) => {
                sync_directory(parent)?;
                return Ok(staging);
            }
            Err(source) if source.kind() == io::ErrorKind::AlreadyExists => {}
            Err(source) => {
                return Err(MigrationError::Io {
                    action: "create staging directory",
                    path: staging,
                    source,
                });
            }
        }
    }
    Err(MigrationError::Io {
        action: "create staging directory",
        path: target.to_owned(),
        source: io::Error::new(
            io::ErrorKind::AlreadyExists,
            "could not allocate a unique staging directory",
        ),
    })
}

fn publish_staged_path(staging: &Path, target: &Path) -> Result<(), MigrationError> {
    publish_staged_path_with_hook(staging, target, || Ok(()))
}

fn publish_staged_path_with_hook(
    staging: &Path,
    target: &Path,
    before_replace: impl FnOnce() -> Result<(), MigrationError>,
) -> Result<(), MigrationError> {
    before_replace()?;
    if path_is_occupied(target) {
        reject_symlink(target)?;
        remove_path_if_exists(target)?;
    }
    fs::rename(staging, target).map_err(|source| MigrationError::Io {
        action: "publish staged migration target",
        path: target.to_owned(),
        source,
    })?;
    sync_parent_directory(target)
}

fn copy_file(source: &Path, target: &Path) -> Result<(), MigrationError> {
    create_parent(target)?;
    if path_is_occupied(target) {
        let metadata = fs::symlink_metadata(target).map_err(|source| MigrationError::Io {
            action: "inspect copy target",
            path: target.to_owned(),
            source,
        })?;
        if is_link_or_reparse(&metadata) {
            return Err(MigrationError::Symlink(target.to_owned()));
        }
        if !metadata.is_file() {
            let staging = create_staging_file(target)?;
            let result = copy_config_file_atomically(source, &staging)
                .map_err(|error| MigrationError::Io {
                    action: "copy staged file",
                    path: staging.clone(),
                    source: io::Error::other(error.to_string()),
                })
                .and_then(|outcome| require_durable_write(&staging, &outcome))
                .and_then(|()| publish_staged_path(&staging, target));
            if result.is_err() && path_is_occupied(&staging) {
                let _ = remove_path_if_exists(&staging);
            }
            return result;
        }
    }
    let outcome =
        copy_config_file_atomically(source, target).map_err(|error| MigrationError::Io {
            action: "copy atomically",
            path: target.to_owned(),
            source: io::Error::other(error.to_string()),
        })?;
    require_durable_write(target, &outcome)
}

fn create_staging_file(target: &Path) -> Result<PathBuf, MigrationError> {
    let parent = target
        .parent()
        .ok_or_else(|| MigrationError::UnsafeTarget(target.to_owned()))?;
    let file_name = target
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or("target");
    for _ in 0..128 {
        let sequence = BACKUP_SEQUENCE.fetch_add(1, Ordering::Relaxed);
        let staging = parent.join(format!(
            ".{file_name}.gta-claw.migrate-stage.{}.{sequence}",
            std::process::id()
        ));
        match OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&staging)
        {
            Ok(file) => {
                file.sync_all().map_err(|source| MigrationError::Io {
                    action: "synchronize staging file",
                    path: staging.clone(),
                    source,
                })?;
                sync_directory(parent)?;
                return Ok(staging);
            }
            Err(source) if source.kind() == io::ErrorKind::AlreadyExists => {}
            Err(source) => {
                return Err(MigrationError::Io {
                    action: "create staging file",
                    path: staging,
                    source,
                });
            }
        }
    }
    Err(MigrationError::Io {
        action: "create staging file",
        path: target.to_owned(),
        source: io::Error::new(
            io::ErrorKind::AlreadyExists,
            "could not allocate a unique staging file",
        ),
    })
}

fn populate_staging_file_from_source(
    source: &Path,
    staging: &Path,
) -> Result<(), MigrationError> {
    let permissions =
        fs::symlink_metadata(source).map_err(|source_error| MigrationError::Io {
            action: "inspect staged copy source",
            path: source.to_owned(),
            source: source_error,
        })?
        .permissions();
    let mut input = File::open(source).map_err(|source| MigrationError::Io {
        action: "open staged copy source",
        path: source.to_owned(),
        source,
    })?;
    let mut output = OpenOptions::new()
        .write(true)
        .truncate(true)
        .open(staging)
        .map_err(|source| MigrationError::Io {
            action: "open staging file",
            path: staging.to_owned(),
            source,
        })?;
    output
        .set_permissions(permissions)
        .map_err(|source| MigrationError::Io {
            action: "set staging file permissions",
            path: staging.to_owned(),
            source,
        })?;
    io::copy(&mut input, &mut output).map_err(|source| MigrationError::Io {
        action: "copy into staging file",
        path: staging.to_owned(),
        source,
    })?;
    output.sync_all().map_err(|source| MigrationError::Io {
        action: "synchronize staging file",
        path: staging.to_owned(),
        source,
    })
}

fn populate_staging_file(
    staging: &Path,
    bytes: &[u8],
    unix_mode: u32,
) -> Result<(), MigrationError> {
    let mut output = OpenOptions::new()
        .write(true)
        .truncate(true)
        .open(staging)
        .map_err(|source| MigrationError::Io {
            action: "open staging file",
            path: staging.to_owned(),
            source,
        })?;
    set_unix_mode(&output, unix_mode).map_err(|source| MigrationError::Io {
        action: "set staging file permissions",
        path: staging.to_owned(),
        source,
    })?;
    output
        .write_all(bytes)
        .and_then(|()| output.sync_all())
        .map_err(|source| MigrationError::Io {
            action: "write staging file",
            path: staging.to_owned(),
            source,
        })
}

fn sorted_entries(path: &Path) -> Result<Vec<fs::DirEntry>, MigrationError> {
    let mut entries = fs::read_dir(path)
        .map_err(|source| MigrationError::Io {
            action: "read directory",
            path: path.to_path_buf(),
            source,
        })?
        .collect::<Result<Vec<_>, _>>()
        .map_err(|source| MigrationError::Io {
            action: "read directory entry",
            path: path.to_path_buf(),
            source,
        })?;
    entries.sort_by_key(fs::DirEntry::file_name);
    Ok(entries)
}

pub(crate) fn reject_symlink(path: &Path) -> Result<(), MigrationError> {
    let metadata = fs::symlink_metadata(path).map_err(|source| MigrationError::Io {
        action: "inspect",
        path: path.to_path_buf(),
        source,
    })?;
    if is_link_or_reparse(&metadata) {
        Err(MigrationError::Symlink(path.to_path_buf()))
    } else {
        Ok(())
    }
}

fn remove_path_if_exists(path: &Path) -> Result<(), MigrationError> {
    let Ok(metadata) = fs::symlink_metadata(path) else {
        return Ok(());
    };
    if is_link_or_reparse(&metadata) {
        return Err(MigrationError::Symlink(path.to_path_buf()));
    }
    let result = if metadata.is_dir() {
        fs::remove_dir_all(path)
    } else {
        fs::remove_file(path)
    };
    result.map_err(|source| MigrationError::Io {
        action: "remove",
        path: path.to_path_buf(),
        source,
    })?;
    sync_parent_directory(path)
}

fn read_bytes(path: &Path) -> Result<Vec<u8>, MigrationError> {
    reject_symlink(path)?;
    fs::read(path).map_err(|source| MigrationError::Io {
        action: "read",
        path: path.to_path_buf(),
        source,
    })
}

fn read_text(path: &Path) -> Result<String, MigrationError> {
    reject_symlink(path)?;
    fs::read_to_string(path).map_err(|source| MigrationError::Io {
        action: "read UTF-8 text",
        path: path.to_path_buf(),
        source,
    })
}

fn write_bytes(path: &Path, bytes: &[u8]) -> Result<(), MigrationError> {
    create_parent(path)?;
    if path_is_occupied(path) {
        let metadata = fs::symlink_metadata(path).map_err(|source| MigrationError::Io {
            action: "inspect write target",
            path: path.to_owned(),
            source,
        })?;
        if is_link_or_reparse(&metadata) {
            return Err(MigrationError::Symlink(path.to_owned()));
        }
        if !metadata.is_file() {
            let staging = create_staging_file(path)?;
            let result = write_bytes_atomically(&staging, bytes)
                .map_err(|error| MigrationError::Io {
                    action: "write staged file",
                    path: staging.clone(),
                    source: io::Error::other(error.to_string()),
                })
                .and_then(|outcome| require_durable_write(&staging, &outcome))
                .and_then(|()| publish_staged_path(&staging, path));
            if result.is_err() && path_is_occupied(&staging) {
                let _ = remove_path_if_exists(&staging);
            }
            return result;
        }
    }
    let outcome = write_bytes_atomically(path, bytes).map_err(|error| MigrationError::Io {
        action: "write atomically",
        path: path.to_owned(),
        source: io::Error::other(error.to_string()),
    })?;
    require_durable_write(path, &outcome)
}

fn create_parent(path: &Path) -> Result<(), MigrationError> {
    if let Some(parent) = path.parent() {
        create_dir_all(parent)?;
    }
    Ok(())
}

fn create_dir_all(path: &Path) -> Result<(), MigrationError> {
    create_dir_all_with_hook(path, |_| Ok(()))
}

fn create_dir_all_with_hook(
    path: &Path,
    mut after_parent_sync: impl FnMut(&Path) -> Result<(), MigrationError>,
) -> Result<(), MigrationError> {
    let mut missing = Vec::new();
    let mut current = path;
    loop {
        match fs::symlink_metadata(current) {
            Ok(metadata) => {
                if is_link_or_reparse(&metadata) {
                    return Err(MigrationError::Symlink(current.to_owned()));
                }
                if !metadata.is_dir() {
                    return Err(MigrationError::Io {
                        action: "create directory",
                        path: current.to_owned(),
                        source: io::Error::new(
                            io::ErrorKind::AlreadyExists,
                            "path component is not a directory",
                        ),
                    });
                }
                break;
            }
            Err(source) if source.kind() == io::ErrorKind::NotFound => {
                missing.push(current.to_owned());
                let Some(parent) = current.parent() else {
                    break;
                };
                if parent.as_os_str().is_empty() {
                    break;
                }
                current = parent;
            }
            Err(source) => {
                return Err(MigrationError::Io {
                    action: "inspect directory",
                    path: current.to_owned(),
                    source,
                });
            }
        }
    }
    for directory in missing.into_iter().rev() {
        fs::create_dir(&directory).map_err(|source| MigrationError::Io {
            action: "create directory",
            path: directory.clone(),
            source,
        })?;
        let parent = directory
            .parent()
            .filter(|parent| !parent.as_os_str().is_empty())
            .unwrap_or_else(|| Path::new("."));
        sync_directory(parent)?;
        after_parent_sync(&directory)?;
    }
    Ok(())
}

fn require_durable_write(path: &Path, outcome: &WriteOutcome) -> Result<(), MigrationError> {
    if outcome.warnings.is_empty() {
        Ok(())
    } else {
        Err(MigrationError::Io {
            action: "synchronize atomic publication",
            path: path.to_owned(),
            source: io::Error::other(format!("{:?}", outcome.warnings)),
        })
    }
}

#[cfg(unix)]
fn sync_directory(path: &Path) -> Result<(), MigrationError> {
    File::open(path)
        .and_then(|directory| directory.sync_all())
        .map_err(|source| MigrationError::Io {
            action: "synchronize directory",
            path: path.to_owned(),
            source,
        })
}

#[cfg(not(unix))]
fn sync_directory(_path: &Path) -> Result<(), MigrationError> {
    Ok(())
}

fn sync_parent_directory(path: &Path) -> Result<(), MigrationError> {
    let parent = path
        .parent()
        .ok_or_else(|| MigrationError::UnsafeTarget(path.to_owned()))?;
    sync_directory(parent)
}

#[cfg(unix)]
fn is_link_or_reparse(metadata: &fs::Metadata) -> bool {
    metadata.file_type().is_symlink()
}

#[cfg(windows)]
fn is_link_or_reparse(metadata: &fs::Metadata) -> bool {
    use std::os::windows::fs::MetadataExt;

    const FILE_ATTRIBUTE_REPARSE_POINT: u32 = 0x400;
    metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0
}

#[cfg(not(any(unix, windows)))]
fn is_link_or_reparse(metadata: &fs::Metadata) -> bool {
    metadata.file_type().is_symlink()
}

fn path_to_slashes(path: &Path) -> String {
    path.components()
        .filter_map(|component| match component {
            Component::Normal(value) => Some(value.to_string_lossy().into_owned()),
            _ => None,
        })
        .collect::<Vec<_>>()
        .join("/")
}

fn is_publication_lock_artifact(path: &Path) -> bool {
    path.file_name()
        .and_then(|name| name.to_str())
        .is_some_and(|name| name.ends_with(".gta-claw.lock"))
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::path::{Path, PathBuf};
    use std::sync::atomic::{AtomicU64, Ordering};

    use super::{
        AppliedState, ApplyContext, ApplyReceipt, BackupEntry, MigrationError, MigrationOperation,
        PathTransition, PreparedOperation, RecoveryPhase, RemovalPoint, SecretStore,
        SecretStoreError, SecretValue, TransitionPoint, TransitionStrategy,
        atomic_exchange_supported, copy_directory_atomically, create_dir_all_with_hook,
        digest_path, digest_path_bytes, exchange_paths_atomically, migration_lock_path,
        normalize_plan_target_root, preflight_operation_publication_with_exchange,
        publish_staged_path_transactionally_with_hook,
        remove_created_target_transactionally_with_hook, select_transition_strategy,
        format_secret_transaction_id, new_secret_transaction_id,
        record_applied_state, recover_interrupted_migration_with_hook, rollback_receipt,
        rollback_receipt_locked, write_backup_manifest,
        validate_created_directories,
    };

    static NEXT_DIRECTORY: AtomicU64 = AtomicU64::new(0);

    #[test]
    fn every_cross_type_transition_failpoint_recovers_the_old_directory() {
        let mut failpoints = vec![
            TransitionPoint::Prepared,
            TransitionPoint::Published,
            TransitionPoint::Cleaning,
            TransitionPoint::Cleaned,
        ];
        if atomic_exchange_supported() {
            failpoints.insert(1, TransitionPoint::Exchanged);
        } else {
            failpoints.insert(1, TransitionPoint::OldMoved);
        }
        for failpoint in failpoints {
            let directory = temporary_directory();
            let cleanup = Cleanup(directory.clone());
            let target_root = directory.join("target-root");
            let target = target_root.join("item");
            fs::create_dir_all(&target).expect("create old directory target");
            fs::write(target.join("value"), b"old").expect("write old target");
            let backup_dir = directory.join("backup").join("transaction");
            let backup = backup_dir.join("items").join("0");
            fs::create_dir_all(&backup).expect("create backup directory");
            fs::write(backup.join("value"), b"old").expect("write backup");
            let staging = target_root.join("staged-file");
            fs::write(&staging, b"new").expect("write staged file");
            let mut receipt = ApplyReceipt {
                provider_id: "test".to_owned(),
                backup_dir: backup_dir.clone(),
                target_root: target_root.clone(),
                secret_transaction_id: "test-transaction".to_owned(),
                backups: vec![BackupEntry {
                    target: target.clone(),
                    backup: Some(backup),
                    digest: Some(digest_path(&target).expect("digest old target")),
                    pending: Some(digest_path(&staging).expect("digest staged target")),
                    applied: None,
                    transition: None,
                    removal: None,
                }],
                created_directories: Vec::new(),
            };

            publish_staged_path_transactionally_with_hook(
                &staging,
                &target,
                &mut receipt,
                None,
                |reached| {
                    if reached == failpoint {
                        Err(MigrationError::Signing(format!(
                            "injected {failpoint:?} crash"
                        )))
                    } else {
                        Ok(())
                    }
                },
            )
            .expect_err("selected transition failpoint must stop publication");
            if failpoint == TransitionPoint::Published && atomic_exchange_supported() {
                let old = receipt.backups[0]
                    .transition
                    .as_ref()
                    .and_then(|transition| transition.old.as_ref())
                    .expect("published exchange retains displaced old path");
                exchange_paths_atomically(old, &target)
                    .expect("simulate rollback exchange before recovery process crashes");
                if old.is_dir() {
                    fs::remove_dir_all(old).expect("remove exchanged pending directory");
                } else {
                    fs::remove_file(old).expect("remove exchanged pending file");
                }
            }
            if failpoint == TransitionPoint::Cleaning {
                let old = receipt.backups[0]
                    .transition
                    .as_ref()
                    .and_then(|transition| transition.old.as_ref())
                    .expect("cleaning phase retains old path");
                fs::remove_file(old.join("value"))
                    .expect("simulate crash during recursive old-path cleanup");
            }

            let mut secrets = NoopSecretStore;
            recover_interrupted_migration_with_hook(
                &backup_dir,
                &mut secrets,
                |_| Ok(()),
            )
            .expect("durable transition state restores the old directory");
            assert_eq!(
                fs::read(target.join("value")).expect("read restored target"),
                b"old",
                "failed to recover after {failpoint:?}"
            );
            drop(cleanup);
        }
    }

    #[test]
    fn rollback_cleaning_resumes_partial_pending_directory_deletion() {
        if !atomic_exchange_supported() {
            return;
        }
        let directory = temporary_directory();
        let cleanup = Cleanup(directory.clone());
        let target_root = directory.join("target-root");
        fs::create_dir(&target_root).expect("create target root");
        let target = target_root.join("item");
        fs::write(&target, b"old file").expect("write original file");
        let backup_dir = directory.join("backup").join("transaction");
        let backup = backup_dir.join("items").join("0");
        fs::create_dir_all(backup.parent().expect("backup parent")).expect("create backup parent");
        fs::write(&backup, b"old file").expect("write exact backup");
        let staging = target_root.join("staged-directory");
        fs::create_dir(&staging).expect("create staged directory");
        fs::write(staging.join("one"), b"one").expect("write first staged file");
        fs::write(staging.join("two"), b"two").expect("write second staged file");
        let mut receipt = ApplyReceipt {
            provider_id: "test".to_owned(),
            backup_dir: backup_dir.clone(),
            target_root,
            secret_transaction_id: "test-transaction".to_owned(),
            backups: vec![BackupEntry {
                target: target.clone(),
                backup: Some(backup),
                digest: Some(digest_path(&target).expect("digest original")),
                pending: Some(digest_path(&staging).expect("digest pending directory")),
                applied: None,
                transition: None,
                removal: None,
            }],
            created_directories: Vec::new(),
        };
        publish_staged_path_transactionally_with_hook(
            &staging,
            &target,
            &mut receipt,
            None,
            |point| {
                if point == TransitionPoint::Published {
                    Err(MigrationError::Signing(
                        "crash after forward exchange".to_owned(),
                    ))
                } else {
                    Ok(())
                }
            },
        )
        .expect_err("leave published exchange journal");
        let displaced = receipt.backups[0]
            .transition
            .as_ref()
            .and_then(|transition| transition.old.as_ref())
            .expect("exchange retains original path")
            .clone();
        exchange_paths_atomically(&displaced, &target).expect("restore original file");
        receipt.backups[0]
            .transition
            .as_mut()
            .expect("transition remains")
            .phase = TransitionPhase::RollbackCleaning;
        write_backup_manifest(&receipt, RecoveryPhase::Applying)
            .expect("persist rollback cleaning");
        fs::remove_file(displaced.join("one")).expect("partially delete pending directory");
        let mut secrets = NoopSecretStore;

        recover_interrupted_migration_with_hook(&backup_dir, &mut secrets, |_| Ok(()))
            .expect("restart finishes pending directory cleanup");

        assert_eq!(fs::read(&target).expect("read restored original"), b"old file");
        assert!(!displaced.exists());
        drop(cleanup);
    }

    #[test]
    fn recovery_rereads_manifest_after_acquiring_the_target_lock() {
        let directory = temporary_directory();
        let cleanup = Cleanup(directory.clone());
        let target_root = directory.join("target");
        fs::create_dir(&target_root).expect("create target root");
        let backup_root = directory.join("backup");
        let backup_dir = backup_root.join("transaction");
        fs::create_dir_all(&backup_dir).expect("create backup directory");
        let receipt = ApplyReceipt {
            provider_id: "test".to_owned(),
            backup_dir: backup_dir.clone(),
            target_root,
            secret_transaction_id: "test-transaction".to_owned(),
            backups: Vec::new(),
            created_directories: Vec::new(),
        };
        write_backup_manifest(&receipt, RecoveryPhase::Applying).expect("write applying manifest");
        let mut secrets = CountingSecretStore::default();

        recover_interrupted_migration_with_hook(&backup_dir, &mut secrets, |manifest_path| {
            write_backup_manifest(&receipt, RecoveryPhase::Committed)?;
            assert_eq!(manifest_path, receipt.backup_dir.join("manifest.json"));
            Ok(())
        })
        .expect("locked reread observes committed phase");

        assert_eq!(secrets.rollback_calls, 0);
        drop(cleanup);
    }

    #[test]
    fn public_rollback_holds_the_target_lock_during_secret_rollback() {
        let directory = temporary_directory();
        let cleanup = Cleanup(directory.clone());
        let target_root = directory.join("target");
        fs::create_dir(&target_root).expect("create target root");
        let backup_root = directory.join("backup");
        fs::create_dir(&backup_root).expect("create backup root");
        let receipt = ApplyReceipt {
            provider_id: "test".to_owned(),
            backup_dir: backup_root.join("transaction"),
            target_root: target_root.clone(),
            secret_transaction_id: "test-transaction".to_owned(),
            backups: Vec::new(),
            created_directories: Vec::new(),
        };
        fs::create_dir(&receipt.backup_dir).expect("create receipt directory");
        write_backup_manifest(&receipt, RecoveryPhase::Committed).expect("write manifest");
        let mut secrets = LockCheckingSecretStore {
            lock_path: migration_lock_path(&target_root).expect("derive target lock path"),
            observed_lock: false,
        };
        let mut context = ApplyContext {
            target_root: &target_root,
            backup_root: &backup_root,
            overwrite: true,
            secret_store: &mut secrets,
        };

        rollback_receipt(&mut context, &receipt, &target_root)
            .expect("public rollback succeeds");

        assert!(secrets.observed_lock);
        drop(cleanup);
    }

    #[test]
    fn applied_state_refuses_to_adopt_bytes_that_do_not_match_pending_digest() {
        let directory = temporary_directory();
        let cleanup = Cleanup(directory.clone());
        let target_root = directory.join("target");
        fs::create_dir(&target_root).expect("create target root");
        let target = target_root.join("value");
        fs::write(&target, b"foreign bytes").expect("write foreign target");
        let expected_path = directory.join("expected");
        fs::write(&expected_path, b"expected bytes").expect("write expected bytes");
        let expected = digest_path(&expected_path).expect("digest expected bytes");
        let mut receipt = ApplyReceipt {
            provider_id: "test".to_owned(),
            backup_dir: directory.join("backup"),
            target_root,
            secret_transaction_id: "test-transaction".to_owned(),
            backups: vec![BackupEntry {
                target: target.clone(),
                backup: None,
                digest: None,
                pending: Some(expected.clone()),
                applied: None,
                transition: None,
                removal: None,
            }],
            created_directories: Vec::new(),
        };

        let error = record_applied_state(&mut receipt, &target)
            .expect_err("foreign target digest must not become transaction-owned");

        assert!(matches!(error, MigrationError::Conflict(path) if path == target));
        assert!(receipt.backups[0].applied.is_none());
        assert_eq!(receipt.backups[0].pending.as_deref(), Some(expected.as_str()));
        drop(cleanup);
    }

    #[test]
    fn source_mutation_after_staging_cannot_change_published_bytes() {
        let directory = temporary_directory();
        let cleanup = Cleanup(directory.clone());
        let source = directory.join("source");
        let target_root = directory.join("target");
        fs::create_dir(&target_root).expect("create target root");
        let target = target_root.join("copied");
        fs::write(&source, b"reviewed source").expect("write source");
        let staged = PreparedOperation::Copy {
            source: &source,
            target: &target,
        }
        .stage()
        .expect("stage reviewed source");
        fs::write(&source, b"mutated after staging").expect("mutate source");
        let backup_dir = directory.join("backup").join("transaction");
        fs::create_dir_all(&backup_dir).expect("create backup directory");
        let mut receipt = ApplyReceipt {
            provider_id: "test".to_owned(),
            backup_dir,
            target_root,
            secret_transaction_id: "test-transaction".to_owned(),
            backups: vec![BackupEntry {
                target: target.clone(),
                backup: None,
                digest: None,
                pending: Some(staged.digest.clone()),
                applied: None,
                transition: None,
                removal: None,
            }],
            created_directories: Vec::new(),
        };
        write_backup_manifest(&receipt, RecoveryPhase::Applying).expect("write pending manifest");

        staged.publish(&mut receipt).expect("publish exact staged output");
        record_applied_state(&mut receipt, &target).expect("record staged digest");

        assert_eq!(
            fs::read(target).expect("read published target"),
            b"reviewed source"
        );
        drop(cleanup);
    }

    #[cfg(unix)]
    #[test]
    fn staged_copy_and_generated_sensitive_files_preserve_reviewed_modes() {
        use std::os::unix::fs::PermissionsExt;

        let directory = temporary_directory();
        let cleanup = Cleanup(directory.clone());
        let source = directory.join("source");
        fs::write(&source, b"source").expect("write source");
        fs::set_permissions(&source, fs::Permissions::from_mode(0o640))
            .expect("set source mode");
        let copied_target = directory.join("copied");
        let copied = PreparedOperation::Copy {
            source: &source,
            target: &copied_target,
        }
        .stage()
        .expect("stage copy");
        assert_eq!(
            fs::symlink_metadata(&copied.staging)
                .expect("inspect copied staging")
                .permissions()
                .mode()
                & 0o777,
            0o640
        );
        let source_directory = directory.join("source-directory");
        fs::create_dir(&source_directory).expect("create source directory");
        let nested_directory = source_directory.join("read-only-nested");
        fs::create_dir(&nested_directory).expect("create nested directory");
        fs::write(nested_directory.join("child"), b"child").expect("write nested child");
        fs::set_permissions(&nested_directory, fs::Permissions::from_mode(0o555))
            .expect("set nested read-only mode");
        fs::set_permissions(&source_directory, fs::Permissions::from_mode(0o555))
            .expect("set source directory mode");
        let directory_target = directory.join("copied-directory");
        let copied_directory = PreparedOperation::Copy {
            source: &source_directory,
            target: &directory_target,
        }
        .stage()
        .expect("stage directory copy");
        assert_eq!(
            fs::symlink_metadata(&copied_directory.staging)
                .expect("inspect copied directory staging")
                .permissions()
                .mode()
                & 0o777,
            0o555
        );
        assert_eq!(
            fs::symlink_metadata(copied_directory.staging.join("read-only-nested"))
                .expect("inspect copied nested directory")
                .permissions()
                .mode()
                & 0o777,
            0o555
        );
        let backup_target = directory.join("backup-directory");
        copy_directory_atomically(&source_directory, &backup_target)
            .expect("backup read-only source directory");
        assert_eq!(
            fs::symlink_metadata(&backup_target)
                .expect("inspect backup directory")
                .permissions()
                .mode()
                & 0o777,
            0o555
        );
        let sensitive_target = directory.join("sensitive");
        let sensitive = PreparedOperation::Bytes {
            target: &sensitive_target,
            bytes: b"secret reference".to_vec(),
        }
        .stage()
        .expect("stage sensitive config");
        assert_eq!(
            fs::symlink_metadata(&sensitive.staging)
                .expect("inspect sensitive staging")
                .permissions()
                .mode()
                & 0o777,
            0o600
        );
        drop(cleanup);
    }

    #[test]
    fn atomic_displacement_preserves_noncooperating_writer_bytes() {
        let directory = temporary_directory();
        let cleanup = Cleanup(directory.clone());
        let target_root = directory.join("target");
        fs::create_dir(&target_root).expect("create target root");
        let target = target_root.join("value");
        fs::write(&target, b"original").expect("write original");
        let staging = target_root.join("staging");
        fs::write(&staging, b"migration").expect("write staged migration");
        let backup_dir = directory.join("backup").join("transaction");
        let backup = backup_dir.join("items").join("0");
        fs::create_dir_all(backup.parent().expect("backup parent")).expect("create backup parent");
        fs::write(&backup, b"original").expect("write exact backup");
        let mut receipt = ApplyReceipt {
            provider_id: "test".to_owned(),
            backup_dir: backup_dir.clone(),
            target_root,
            secret_transaction_id: "test-transaction".to_owned(),
            backups: vec![BackupEntry {
                target: target.clone(),
                backup: Some(backup),
                digest: Some(digest_path(&target).expect("digest original")),
                pending: Some(digest_path(&staging).expect("digest migration")),
                applied: None,
                transition: None,
                removal: None,
            }],
            created_directories: Vec::new(),
        };

        let error = publish_staged_path_transactionally_with_hook(
            &staging,
            &target,
            &mut receipt,
            None,
            |point| {
                if point == TransitionPoint::BeforePublish {
                    fs::write(&target, b"concurrent B").map_err(|source| MigrationError::Io {
                        action: "inject concurrent writer",
                        path: target.clone(),
                        source,
                    })?;
                }
                Ok(())
            },
        )
        .expect_err("displaced B must fail migration publication");

        assert!(matches!(error, MigrationError::Conflict(path) if path == target));
        assert_eq!(fs::read(&target).expect("read live B"), b"concurrent B");
        let conflict_backup = fs::read_dir(backup_dir.join("conflicts"))
            .expect("read conflict backups")
            .map(|entry| entry.expect("conflict entry").path())
            .find(|path| {
                path.is_file()
                    && !path
                        .file_name()
                        .and_then(|name| name.to_str())
                        .is_some_and(|name| name.ends_with(".gta-claw.lock"))
            })
            .expect("durable B conflict backup");
        assert_eq!(
            fs::read(conflict_backup).expect("read B backup"),
            b"concurrent B"
        );
        let mut secrets = NoopSecretStore;
        recover_interrupted_migration_with_hook(&backup_dir, &mut secrets, |_| Ok(()))
            .expect_err("recovery reports preserved concurrent B");
        assert_eq!(fs::read(target).expect("B remains live"), b"concurrent B");
        drop(cleanup);
    }

    #[test]
    fn absent_target_race_is_displaced_and_preserved() {
        let directory = temporary_directory();
        let cleanup = Cleanup(directory.clone());
        let target_root = directory.join("target");
        fs::create_dir(&target_root).expect("create target root");
        let target = target_root.join("value");
        let staging = target_root.join("staging");
        fs::write(&staging, b"migration").expect("write staged migration");
        let backup_dir = directory.join("backup").join("transaction");
        fs::create_dir_all(&backup_dir).expect("create backup directory");
        let mut receipt = ApplyReceipt {
            provider_id: "test".to_owned(),
            backup_dir: backup_dir.clone(),
            target_root,
            secret_transaction_id: "test-transaction".to_owned(),
            backups: vec![BackupEntry {
                target: target.clone(),
                backup: None,
                digest: None,
                pending: Some(digest_path(&staging).expect("digest migration")),
                applied: None,
                transition: None,
                removal: None,
            }],
            created_directories: Vec::new(),
        };

        publish_staged_path_transactionally_with_hook(
            &staging,
            &target,
            &mut receipt,
            None,
            |point| {
                if point == TransitionPoint::BeforePublish {
                    fs::write(&target, b"concurrent B").map_err(|source| MigrationError::Io {
                        action: "inject concurrent writer",
                        path: target.clone(),
                        source,
                    })?;
                }
                Ok(())
            },
        )
        .expect_err("absent-target race must become a conflict");

        assert_eq!(fs::read(&target).expect("read live B"), b"concurrent B");
        assert!(backup_dir.join("conflicts").is_dir());
        drop(cleanup);
    }

    #[test]
    fn preserved_conflict_does_not_short_circuit_other_entry_or_secret_rollback() {
        let directory = temporary_directory();
        let cleanup = Cleanup(directory.clone());
        let target_root = directory.join("target");
        fs::create_dir(&target_root).expect("create target root");
        let target_a = target_root.join("a");
        let target_b = target_root.join("b");
        fs::write(&target_a, b"applied A").expect("write applied A");
        fs::write(&target_b, b"concurrent B").expect("write concurrent B");
        let backup_dir = directory.join("backup").join("transaction");
        let backup_a = backup_dir.join("items").join("0");
        let backup_b = backup_dir.join("items").join("1");
        fs::create_dir_all(backup_a.parent().expect("backup parent"))
            .expect("create backup parent");
        fs::write(&backup_a, b"original A").expect("write A backup");
        fs::write(&backup_b, b"original B").expect("write B backup");
        let pending_b = target_root.join("pending-b");
        fs::write(&pending_b, b"migration B").expect("write pending B");
        let mut receipt = ApplyReceipt {
            provider_id: "test".to_owned(),
            backup_dir,
            target_root: target_root.clone(),
            secret_transaction_id: "test-transaction".to_owned(),
            backups: vec![
                BackupEntry {
                    target: target_a.clone(),
                    backup: Some(backup_a),
                    digest: Some(digest_path_bytes(b"original A")),
                    pending: None,
                    applied: Some(AppliedState::Digest(digest_path(&target_a).expect("digest A"))),
                    transition: None,
                    removal: None,
                },
                BackupEntry {
                    target: target_b.clone(),
                    backup: Some(backup_b),
                    digest: Some(digest_path_bytes(b"original B")),
                    pending: Some(digest_path(&pending_b).expect("digest pending B")),
                    applied: None,
                    transition: Some(PathTransition {
                        staging: pending_b,
                        old: None,
                        phase: TransitionPhase::ConflictRestored,
                        strategy: TransitionStrategy::Exchange,
                        expected_displaced_sha256: Some(digest_path_bytes(b"original B")),
                        conflict_sha256: Some(digest_path(&target_b).expect("digest conflict B")),
                    }),
                    removal: None,
                },
            ],
            created_directories: Vec::new(),
        };
        fs::create_dir_all(&receipt.backup_dir).expect("create receipt directory");
        write_backup_manifest(&receipt, RecoveryPhase::Applying).expect("write applying manifest");
        let mut secrets = CountingSecretStore::default();
        let mut context = ApplyContext {
            target_root: &target_root,
            backup_root: &directory.join("backup"),
            overwrite: true,
            secret_store: &mut secrets,
        };

        rollback_receipt_locked(&mut context, &mut receipt)
            .expect_err("preserved B conflict is returned after full rollback");

        assert_eq!(fs::read(target_a).expect("read restored A"), b"original A");
        assert_eq!(fs::read(target_b).expect("read preserved B"), b"concurrent B");
        assert_eq!(secrets.rollback_calls, 1);
        let manifest: serde_json::Value = serde_json::from_slice(
            &fs::read(receipt.backup_dir.join("manifest.json")).expect("read final manifest"),
        )
        .expect("decode final manifest");
        assert_eq!(manifest["phase"], "rolled_back");
        drop(cleanup);
    }

    #[test]
    fn every_new_directory_component_reports_after_its_parent_is_synced() {
        let directory = temporary_directory();
        let cleanup = Cleanup(directory.clone());
        let nested = directory.join("one").join("two").join("three");
        let mut synchronized = Vec::new();

        create_dir_all_with_hook(&nested, |created| {
            synchronized.push(created.to_owned());
            Ok(())
        })
        .expect("create and synchronize every directory component");

        assert_eq!(
            synchronized,
            vec![
                directory.join("one"),
                directory.join("one").join("two"),
                nested,
            ]
        );
        drop(cleanup);
    }

    #[test]
    fn lexical_aliases_derive_the_same_target_lock() {
        let relative = Path::new(".claw-migrate-lock-alias");
        let absolute = std::env::current_dir()
            .expect("current directory")
            .join(relative);

        assert_eq!(
            migration_lock_path(relative).expect("relative lock path"),
            migration_lock_path(&absolute).expect("absolute lock path")
        );
    }

    #[test]
    fn persisted_target_identity_is_absolute_and_cwd_independent() {
        let normalized = normalize_plan_target_root(Path::new(".claw-migrate-relative-target"))
            .expect("normalize relative target");
        let current = fs::canonicalize(std::env::current_dir().expect("current directory"))
            .expect("canonical current directory");

        assert!(normalized.is_absolute());
        assert_eq!(normalized.parent(), Some(current.as_path()));
    }

    #[test]
    fn recovery_rejects_created_directories_outside_target_root() {
        let directory = temporary_directory();
        let cleanup = Cleanup(directory.clone());
        let target_root = directory.join("target");
        let outside = directory.join("outside");
        let escaped = target_root.join("nested").join("..").join("..").join("outside");

        let error = validate_created_directories(&[outside.clone()], &target_root)
            .expect_err("manifest must not authorize removing an outside directory");

        assert!(matches!(error, MigrationError::UnsafeTarget(path) if path == outside));
        assert!(
            validate_created_directories(&[escaped], &target_root).is_err(),
            "parent components must not bypass target containment"
        );
        drop(cleanup);
    }

    #[test]
    fn file_and_directory_digests_are_domain_separated() {
        let directory = temporary_directory();
        let cleanup = Cleanup(directory.clone());
        let file = directory.join("empty-file");
        let folder = directory.join("empty-directory");
        fs::write(&file, b"").expect("write empty file");
        fs::create_dir(&folder).expect("create empty directory");

        assert_ne!(
            digest_path(&file).expect("digest file"),
            digest_path(&folder).expect("digest directory")
        );
        drop(cleanup);
    }

    #[test]
    fn directory_digest_length_prefixes_path_and_content_boundaries() {
        let directory = temporary_directory();
        let cleanup = Cleanup(directory.clone());
        let first = directory.join("first");
        let second = directory.join("second");
        fs::create_dir(&first).expect("create first directory");
        fs::create_dir(&second).expect("create second directory");
        fs::write(first.join("ab"), b"c").expect("write first layout");
        fs::write(second.join("a"), b"bc").expect("write second layout");

        assert_ne!(
            digest_path(&first).expect("digest first layout"),
            digest_path(&second).expect("digest second layout")
        );
        drop(cleanup);
    }

    #[cfg(unix)]
    #[test]
    fn directory_digest_preserves_non_utf8_path_bytes() {
        use std::ffi::OsString;
        use std::os::unix::ffi::OsStringExt;

        let directory = temporary_directory();
        let cleanup = Cleanup(directory.clone());
        let first = directory.join("first");
        let second = directory.join("second");
        fs::create_dir(&first).expect("create first directory");
        fs::create_dir(&second).expect("create second directory");
        fs::write(first.join(OsString::from_vec(vec![b'n', 0x80])), b"same")
            .expect("write first non-UTF8 name");
        fs::write(second.join(OsString::from_vec(vec![b'n', 0x81])), b"same")
            .expect("write second non-UTF8 name");

        assert_ne!(
            digest_path(&first).expect("digest first non-UTF8 layout"),
            digest_path(&second).expect("digest second non-UTF8 layout")
        );
        drop(cleanup);
    }

    #[test]
    fn occupied_cross_type_target_is_refused_without_native_exchange() {
        let target = Path::new("occupied-target");

        let error = select_transition_strategy(true, false, false, false, target)
            .expect_err("unsupported platform must not use remove-before-rename fallback");

        assert!(matches!(error, MigrationError::InvalidInput { path, .. } if path == target));
    }

    #[test]
    fn unsupported_cross_type_is_rejected_before_staging_or_pending_state() {
        let directory = temporary_directory();
        let cleanup = Cleanup(directory.clone());
        let target = directory.join("occupied-directory");
        fs::create_dir(&target).expect("create occupied directory");
        fs::write(target.join("old"), b"old").expect("write old tree");
        let operation = MigrationOperation::WriteBytes {
            target: target.clone(),
            bytes: b"new file".to_vec(),
        };
        let backup_dir = directory.join("backup").join("transaction");
        let backup = backup_dir.join("items").join("0");
        fs::create_dir_all(&backup).expect("create exact backup");
        fs::write(backup.join("old"), b"old").expect("write exact backup");
        let mut receipt = ApplyReceipt {
            provider_id: "test".to_owned(),
            backup_dir: backup_dir.clone(),
            target_root: directory.clone(),
            secret_transaction_id: "test-transaction".to_owned(),
            backups: vec![BackupEntry {
                target: target.clone(),
                backup: Some(backup),
                digest: Some(digest_path(&target).expect("digest original tree")),
                pending: None,
                applied: None,
                transition: None,
                removal: None,
            }],
            created_directories: Vec::new(),
        };
        write_backup_manifest(&receipt, RecoveryPhase::Prepared).expect("write prepared manifest");

        preflight_operation_publication_with_exchange(&operation, false)
            .expect_err("unsupported cross-type transition must fail in preflight");
        assert!(receipt.backups[0].pending.is_none());
        let mut secrets = NoopSecretStore;
        let mut context = ApplyContext {
            target_root: &directory,
            backup_root: &directory.join("backup"),
            overwrite: true,
            secret_store: &mut secrets,
        };
        rollback_receipt_locked(&mut context, &mut receipt)
            .expect("untouched original finalizes rollback cleanly");

        assert_eq!(fs::read(target.join("old")).expect("read old tree"), b"old");
        assert!(
            fs::read_dir(&directory)
                .expect("read parent")
                .all(|entry| {
                    !entry
                        .expect("directory entry")
                        .file_name()
                        .to_string_lossy()
                        .contains("migrate-stage")
                })
        );
        drop(cleanup);
    }

    #[test]
    fn transaction_id_process_component_prevents_cross_process_reuse() {
        let nonce = [7_u8; 16];

        assert_ne!(
            format_secret_transaction_id("codex", "target", 100, &nonce),
            format_secret_transaction_id("codex", "target", 101, &nonce)
        );
    }

    #[test]
    fn independent_processes_generate_distinct_transaction_ids() {
        let directory = temporary_directory();
        let cleanup = Cleanup(directory.clone());
        let target = directory.join("target");
        let executable = std::env::current_exe().expect("current test executable");
        let mut identifiers = Vec::new();
        for index in 0..2 {
            let output = directory.join(format!("transaction-{index}"));
            let status = std::process::Command::new(&executable)
                .arg("engine::tests::transaction_id_child_probe")
                .arg("--exact")
                .env("CLAW_MIGRATE_TRANSACTION_PROBE_OUTPUT", &output)
                .env("CLAW_MIGRATE_TRANSACTION_PROBE_TARGET", &target)
                .status()
                .expect("run transaction ID child process");
            assert!(status.success());
            identifiers.push(fs::read_to_string(output).expect("read child transaction ID"));
        }

        assert_ne!(identifiers[0], identifiers[1]);
        drop(cleanup);
    }

    #[test]
    fn transaction_id_child_probe() {
        let Ok(output) = std::env::var("CLAW_MIGRATE_TRANSACTION_PROBE_OUTPUT") else {
            return;
        };
        let target =
            PathBuf::from(std::env::var("CLAW_MIGRATE_TRANSACTION_PROBE_TARGET").expect("target"));
        let identifier =
            new_secret_transaction_id("test", &target).expect("generate transaction ID");
        fs::write(output, identifier).expect("write transaction ID probe");
    }

    #[test]
    fn every_created_tree_removal_failpoint_finishes_from_the_journal() {
        for failpoint in [
            RemovalPoint::Planned,
            RemovalPoint::Renamed,
            RemovalPoint::Moved,
            RemovalPoint::Cleaned,
        ] {
            let directory = temporary_directory();
            let cleanup = Cleanup(directory.clone());
            let target_root = directory.join("target-root");
            let target = target_root.join("created-tree");
            fs::create_dir_all(&target).expect("create target tree");
            fs::write(target.join("child"), b"created").expect("write target child");
            let backup_dir = directory.join("backup").join("transaction");
            fs::create_dir_all(&backup_dir).expect("create backup directory");
            let mut receipt = ApplyReceipt {
                provider_id: "test".to_owned(),
                backup_dir: backup_dir.clone(),
                target_root,
                secret_transaction_id: "test-transaction".to_owned(),
                backups: vec![BackupEntry {
                    target: target.clone(),
                    backup: None,
                    digest: None,
                    pending: None,
                    applied: Some(AppliedState::Digest(
                        digest_path(&target).expect("digest created tree"),
                    )),
                    transition: None,
                    removal: None,
                }],
                created_directories: Vec::new(),
            };
            write_backup_manifest(&receipt, RecoveryPhase::Applying)
                .expect("write initial applying manifest");

            remove_created_target_transactionally_with_hook(
                &mut receipt,
                0,
                |reached| {
                    if reached == failpoint {
                        Err(MigrationError::Signing(format!(
                            "injected {failpoint:?} removal crash"
                        )))
                    } else {
                        Ok(())
                    }
                },
            )
            .expect_err("selected removal failpoint must stop rollback");
            if failpoint == RemovalPoint::Moved {
                let trash = receipt.backups[0]
                    .removal
                    .as_ref()
                    .expect("moved phase retains trash")
                    .trash
                    .clone();
                fs::remove_file(trash.join("child"))
                    .expect("simulate crash during recursive trash deletion");
            }
            let mut secrets = NoopSecretStore;

            recover_interrupted_migration_with_hook(
                &backup_dir,
                &mut secrets,
                |_| Ok(()),
            )
            .expect("restart finishes journaled created-tree deletion");

            assert!(!target.exists(), "target survived {failpoint:?}");
            assert!(
                fs::read_dir(target.parent().expect("target parent"))
                    .expect("read target parent")
                    .all(|entry| {
                        !entry
                            .expect("directory entry")
                            .file_name()
                            .to_string_lossy()
                            .contains("rollback-trash")
                    })
            );
            drop(cleanup);
        }
    }

    #[test]
    fn absent_target_rollback_preserves_foreign_post_crash_file() {
        let directory = temporary_directory();
        let cleanup = Cleanup(directory.clone());
        let target_root = directory.join("target");
        fs::create_dir(&target_root).expect("create target root");
        let target = target_root.join("created");
        fs::write(&target, b"foreign post-crash bytes").expect("write foreign file");
        let backup_dir = directory.join("backup").join("transaction");
        fs::create_dir_all(&backup_dir).expect("create backup directory");
        let mut receipt = ApplyReceipt {
            provider_id: "test".to_owned(),
            backup_dir,
            target_root,
            secret_transaction_id: "test-transaction".to_owned(),
            backups: vec![BackupEntry {
                target: target.clone(),
                backup: None,
                digest: None,
                pending: Some(encode_hex(&domain_file_digest(
                    &Sha256::digest(b"transaction bytes").into(),
                ))),
                applied: None,
                transition: None,
                removal: None,
            }],
            created_directories: Vec::new(),
        };

        let error = remove_created_target_transactionally(&mut receipt, 0)
            .expect_err("foreign file must block absent-target rollback");

        assert!(matches!(error, MigrationError::Conflict(path) if path == target));
        assert_eq!(
            fs::read(target).expect("read preserved foreign bytes"),
            b"foreign post-crash bytes"
        );
        drop(cleanup);
    }

    struct NoopSecretStore;

    impl SecretStore for NoopSecretStore {
        fn begin_transaction(&mut self, _transaction_id: &str) -> Result<(), SecretStoreError> {
            Ok(())
        }

        fn stage(
            &mut self,
            _transaction_id: &str,
            id: &str,
            _value: SecretValue,
        ) -> Result<String, SecretStoreError> {
            Ok(format!("keyring://gta-claw/{id}"))
        }

        fn commit_transaction(&mut self, _transaction_id: &str) -> Result<(), SecretStoreError> {
            Ok(())
        }

        fn rollback_transaction(&mut self, _transaction_id: &str) -> Result<(), SecretStoreError> {
            Ok(())
        }
    }

    #[derive(Default)]
    struct CountingSecretStore {
        rollback_calls: usize,
    }

    impl SecretStore for CountingSecretStore {
        fn begin_transaction(&mut self, _transaction_id: &str) -> Result<(), SecretStoreError> {
            Ok(())
        }

        fn stage(
            &mut self,
            _transaction_id: &str,
            id: &str,
            _value: SecretValue,
        ) -> Result<String, SecretStoreError> {
            Ok(format!("keyring://gta-claw/{id}"))
        }

        fn commit_transaction(&mut self, _transaction_id: &str) -> Result<(), SecretStoreError> {
            Ok(())
        }

        fn rollback_transaction(&mut self, _transaction_id: &str) -> Result<(), SecretStoreError> {
            self.rollback_calls += 1;
            Ok(())
        }
    }

    struct LockCheckingSecretStore {
        lock_path: PathBuf,
        observed_lock: bool,
    }

    impl SecretStore for LockCheckingSecretStore {
        fn begin_transaction(&mut self, _transaction_id: &str) -> Result<(), SecretStoreError> {
            Ok(())
        }

        fn stage(
            &mut self,
            _transaction_id: &str,
            id: &str,
            _value: SecretValue,
        ) -> Result<String, SecretStoreError> {
            Ok(format!("keyring://gta-claw/{id}"))
        }

        fn commit_transaction(&mut self, _transaction_id: &str) -> Result<(), SecretStoreError> {
            Ok(())
        }

        fn rollback_transaction(&mut self, _transaction_id: &str) -> Result<(), SecretStoreError> {
            let external = fs::OpenOptions::new()
                .read(true)
                .write(true)
                .open(&self.lock_path)
                .expect("open migration lock");
            self.observed_lock = matches!(
                external.try_lock(),
                Err(fs::TryLockError::WouldBlock)
            );
            Ok(())
        }
    }

    fn temporary_directory() -> PathBuf {
        let sequence = NEXT_DIRECTORY.fetch_add(1, Ordering::Relaxed);
        let directory = std::env::temp_dir().join(format!(
            "claw-migrate-engine-{}-{sequence}",
            std::process::id()
        ));
        fs::create_dir(&directory).expect("create temporary directory");
        fs::canonicalize(directory).expect("canonicalize temporary directory")
    }

    struct Cleanup(PathBuf);

    impl Drop for Cleanup {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }
}

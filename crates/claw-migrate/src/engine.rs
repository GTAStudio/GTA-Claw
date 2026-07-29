use std::collections::{BTreeMap, BTreeSet};
use std::error::Error;
use std::fmt::{self, Debug, Display, Formatter};
use std::fs::{self, File, OpenOptions};
use std::io::{self, Read};
use std::ops::Range;
use std::path::{Component, Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

use claw_config::{
    WriteOutcome, copy_file_atomically as copy_config_file_atomically, write_bytes_atomically,
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

/// Reversible secret persistence port used by apply and rollback.
pub trait SecretStore {
    /// Returns an existing value so rollback can restore it.
    ///
    /// # Errors
    ///
    /// Returns a [`SecretStoreError`] when the platform keyring cannot be
    /// reached or unlocked — for example a locked login keychain, a headless
    /// session with no secret service running, or a denied access prompt. Apply
    /// refuses to continue in that case, because without a readable prior value
    /// rollback could not restore the credential it is about to replace.
    fn get(&mut self, id: &str) -> Result<Option<SecretValue>, SecretStoreError>;
    /// Persists a value and returns a safe reference suitable for configuration.
    ///
    /// # Errors
    ///
    /// Returns a [`SecretStoreError`] when the secret could not be written to
    /// the platform keyring — the store is locked, unavailable, out of space, or
    /// rejected the entry. Apply treats this as fatal and rolls back, so the
    /// plaintext is never written to a configuration file that the keyring does
    /// not actually back. Unlock the keyring and re-run the migration.
    fn put(&mut self, id: &str, value: SecretValue) -> Result<String, SecretStoreError>;
    /// Removes an entry that did not exist before apply.
    ///
    /// # Errors
    ///
    /// Returns a [`SecretStoreError`] when the keyring entry could not be
    /// deleted during rollback. Rollback reports it rather than hiding it: the
    /// filesystem is still restored, but the migrated credential remains in the
    /// keyring and has to be removed by hand.
    fn remove(&mut self, id: &str) -> Result<(), SecretStoreError>;
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
    /// after writing began. It carries the original reason and, in
    /// `rollback_error`, the reason automatic restoration did not finish. If
    /// `rollback_error` is `None` the target was restored to its pre-apply state;
    /// if it is `Some`, the verified backup directory named by the receipt must
    /// be restored by hand.
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
    /// restore. [`MigrationError::SecretStore`] means the platform keyring
    /// entries could not be restored or removed even though the filesystem was;
    /// unlock the keyring and remove the migrated entries by hand.
    fn rollback(
        &self,
        context: &mut ApplyContext<'_>,
        receipt: &ApplyReceipt,
    ) -> Result<(), MigrationError> {
        if receipt.provider_id != self.id() {
            return Err(MigrationError::ProviderMismatch);
        }
        rollback_receipt(context, receipt)
    }
}

/// Persistent backup receipt required for rollback.
pub struct ApplyReceipt {
    /// Provider that created the receipt.
    pub provider_id: &'static str,
    /// Verified backup directory.
    pub backup_dir: PathBuf,
    target_root: PathBuf,
    backups: Vec<BackupEntry>,
    secrets: Vec<SecretUndo>,
}

impl Debug for ApplyReceipt {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ApplyReceipt")
            .field("provider_id", &self.provider_id)
            .field("backup_dir", &self.backup_dir)
            .field("target_root", &self.target_root)
            .field("backup_count", &self.backups.len())
            .field("secret_count", &self.secrets.len())
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
pub fn recover_interrupted_migration(backup_dir: impl AsRef<Path>) -> Result<(), MigrationError> {
    let backup_dir = backup_dir.as_ref();
    let manifest_path = backup_dir.join("manifest.json");
    reject_symlink(&manifest_path)?;
    let bytes = read_bytes(&manifest_path)?;
    let mut manifest: RecoveryManifest =
        serde_json::from_slice(&bytes).map_err(|error| MigrationError::InvalidInput {
            path: manifest_path.clone(),
            reason: format!("migration recovery manifest is malformed: {error}"),
        })?;
    if manifest.schema_version != RECOVERY_SCHEMA_VERSION {
        return Err(MigrationError::InvalidInput {
            path: manifest_path,
            reason: format!(
                "unsupported migration recovery schema {}; supported schema is {}",
                manifest.schema_version, RECOVERY_SCHEMA_VERSION
            ),
        });
    }
    if matches!(
        manifest.phase,
        RecoveryPhase::Committed | RecoveryPhase::RolledBack
    ) {
        return Ok(());
    }

    let backup_root = backup_dir
        .parent()
        .ok_or_else(|| MigrationError::UnsafeTarget(backup_dir.to_owned()))?;
    let _lock = MigrationLock::acquire(backup_root, &manifest.target_root)?;
    let actions = recovery_actions(backup_dir, &manifest)?;
    for action in actions.into_iter().rev() {
        match action {
            RecoveryAction::None => {}
            RecoveryAction::Restore(entry) => restore_backup(&entry)?,
            RecoveryAction::Remove(path) => remove_path_if_exists(&path)?,
        }
    }
    manifest.phase = RecoveryPhase::RolledBack;
    write_recovery_manifest(&backup_dir.join("manifest.json"), &manifest)
}

enum RecoveryAction {
    None,
    Restore(BackupEntry),
    Remove(PathBuf),
}

fn recovery_actions(
    backup_dir: &Path,
    manifest: &RecoveryManifest,
) -> Result<Vec<RecoveryAction>, MigrationError> {
    let mut actions = Vec::with_capacity(manifest.entries.len());
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
        let current = if path_is_occupied(&entry.target) {
            Some(digest_path(&entry.target)?)
        } else {
            None
        };
        if current == entry.original_sha256 {
            actions.push(RecoveryAction::None);
            continue;
        }

        let intended = entry.pending_sha256.as_ref().or(match &entry.applied {
            Some(RecoveryAppliedState::Digest(digest)) => Some(digest),
            _ => None,
        });
        let touched_absent = matches!(&entry.applied, Some(RecoveryAppliedState::Absent));
        let recognized = intended.is_some_and(|expected| current.as_ref() == Some(expected))
            || current.is_none() && (entry.original_sha256.is_some() || touched_absent);
        if !recognized || matches!(&entry.applied, Some(RecoveryAppliedState::Unknown)) {
            return Err(MigrationError::Conflict(entry.target.clone()));
        }
        if entry.original_sha256.is_some() {
            actions.push(RecoveryAction::Restore(BackupEntry {
                target: entry.target.clone(),
                backup: entry.backup.clone(),
                digest: entry.original_sha256.clone(),
                pending: None,
                applied: None,
            }));
        } else if current.is_some() {
            actions.push(RecoveryAction::Remove(entry.target.clone()));
        } else {
            actions.push(RecoveryAction::None);
        }
    }
    Ok(actions)
}

struct BackupEntry {
    target: PathBuf,
    backup: Option<PathBuf>,
    digest: Option<String>,
    pending: Option<String>,
    applied: Option<AppliedState>,
}

#[derive(Clone)]
enum AppliedState {
    Absent,
    Digest(String),
    Unknown,
}

#[derive(Clone, Copy, Debug, Deserialize, Serialize, Eq, PartialEq)]
#[serde(rename_all = "snake_case")]
enum RecoveryPhase {
    Prepared,
    Applying,
    Committed,
    RolledBack,
}

#[derive(Debug, Deserialize, Serialize)]
struct RecoveryManifest {
    schema_version: u32,
    provider_id: String,
    target_root: PathBuf,
    phase: RecoveryPhase,
    entries: Vec<RecoveryManifestEntry>,
}

#[derive(Debug, Deserialize, Serialize)]
struct RecoveryManifestEntry {
    target: PathBuf,
    backup: Option<PathBuf>,
    original_sha256: Option<String>,
    pending_sha256: Option<String>,
    applied: Option<RecoveryAppliedState>,
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
    fn acquire(root: &Path, target_root: &Path) -> Result<Self, MigrationError> {
        create_dir_all(root)?;
        reject_symlink(root)?;
        let lock_path = root.join(format!(
            ".migration-{}.lock",
            &digest_bytes(target_root.to_string_lossy().as_bytes())[..16]
        ));
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

struct SecretUndo {
    id: String,
    previous: Option<SecretValue>,
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
    if plan.target_root != context.target_root {
        return Err(MigrationError::UnsafeTarget(plan.target_root.clone()));
    }
    verify_source_digests(plan)?;
    for operation in &plan.operations {
        ensure_target_within(context.target_root, operation.target())?;
        ensure_no_symlink_ancestors(context.target_root, operation.target())?;
        if path_is_occupied(operation.target())
            && !context.overwrite
            && !matches!(operation, MigrationOperation::AppendFile { .. })
        {
            return Err(MigrationError::Conflict(operation.target().to_path_buf()));
        }
    }
    let _lock = MigrationLock::acquire(context.backup_root, context.target_root)?;
    verify_source_digests(plan)?;
    for operation in &plan.operations {
        ensure_no_symlink_ancestors(context.target_root, operation.target())?;
        if path_is_occupied(operation.target())
            && !context.overwrite
            && !matches!(operation, MigrationOperation::AppendFile { .. })
        {
            return Err(MigrationError::Conflict(operation.target().to_owned()));
        }
    }
    let backup_dir = create_backup_dir(context.backup_root, plan.provider_id)?;
    let backups = backup_targets(&backup_dir, &plan.operations)?;
    verify_targets_unchanged(&backups)?;
    let mut receipt = ApplyReceipt {
        provider_id: plan.provider_id,
        backup_dir,
        target_root: context.target_root.to_path_buf(),
        backups,
        secrets: Vec::new(),
    };
    write_backup_manifest(&receipt, RecoveryPhase::Prepared)?;
    let apply_result = apply_operations(context, &plan.operations, &mut receipt)
        .and_then(|()| verify_source_digests(plan))
        .and_then(|()| write_backup_manifest(&receipt, RecoveryPhase::Committed));
    if let Err(error) = apply_result {
        let rollback_errors = rollback_receipt(context, &receipt)
            .err()
            .map_or_else(Vec::new, rollback_failure_messages);
        return Err(MigrationError::ApplyFailed {
            cause: Box::new(error),
            rollback_errors,
        });
    }
    Ok(receipt)
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
        sha256: String,
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

    fn sha256(&self) -> String {
        match self {
            Self::Copy { sha256, .. } => sha256.clone(),
            Self::Bytes { bytes, .. } => digest_bytes(bytes),
            Self::GeneratedSkill { bytes, .. } => {
                let mut hasher = Sha256::new();
                hasher.update(b"SKILL.md");
                hasher.update([0]);
                hasher.update(bytes);
                hasher.update([0xff]);
                encode_hex(&hasher.finalize())
            }
        }
    }

    fn publish(self) -> Result<(), MigrationError> {
        match self {
            Self::Copy { source, target, .. } => copy_path(source, target),
            Self::Bytes { target, bytes } => write_bytes(target, &bytes),
            Self::GeneratedSkill { target, bytes } => {
                publish_single_file_directory(target, "SKILL.md", &bytes)
            }
        }
    }
}

fn prepare_operation<'a>(
    operation: &'a MigrationOperation,
    store: &mut dyn SecretStore,
    undo: &mut Vec<SecretUndo>,
) -> Result<PreparedOperation<'a>, MigrationError> {
    match operation {
        MigrationOperation::CopyPath { source, target } => Ok(PreparedOperation::Copy {
            source,
            target,
            sha256: digest_path(source)?,
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
            bytes: transform_json_bytes(source, namespace, store, undo)?,
        }),
        MigrationOperation::TransformText {
            source,
            target,
            namespace,
        } => Ok(PreparedOperation::Bytes {
            target,
            bytes: transform_text_bytes(source, namespace, store, undo)?,
        }),
        MigrationOperation::ImportEnvironment {
            source,
            target,
            namespace,
        } => Ok(PreparedOperation::Bytes {
            target,
            bytes: import_environment_bytes(source, namespace, store, undo)?,
        }),
        MigrationOperation::StoreDocument {
            source,
            target,
            secret_id,
        } => Ok(PreparedOperation::Bytes {
            target,
            bytes: stored_document_bytes(source, secret_id, store, undo)?,
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
        let prepared = prepare_operation(operation, context.secret_store, &mut receipt.secrets)?;
        verify_operation_target(receipt, prepared.target())?;
        let sha256 = prepared.sha256();
        record_pending_state(receipt, prepared.target(), &sha256);
        write_backup_manifest(receipt, RecoveryPhase::Applying)?;
        let target = prepared.target().to_path_buf();
        let result = prepared.publish();
        record_applied_state(receipt, &target);
        let recorded = write_backup_manifest(receipt, RecoveryPhase::Applying);
        result?;
        recorded?;
    }
    Ok(())
}

fn verify_operation_target(receipt: &ApplyReceipt, target: &Path) -> Result<(), MigrationError> {
    for backup in receipt
        .backups
        .iter()
        .filter(|entry| entry.target == target)
    {
        match &backup.applied {
            Some(AppliedState::Absent) if path_is_occupied(target) => {
                return Err(MigrationError::Conflict(target.to_owned()));
            }
            Some(AppliedState::Absent) => {}
            Some(AppliedState::Digest(expected)) => {
                if !path_is_occupied(target) || digest_path(target)? != *expected {
                    return Err(MigrationError::Conflict(target.to_owned()));
                }
            }
            Some(AppliedState::Unknown) => {
                return Err(MigrationError::Conflict(target.to_owned()));
            }
            None => match &backup.digest {
                Some(expected)
                    if !path_is_occupied(target) || digest_path(target)? != *expected =>
                {
                    return Err(MigrationError::Conflict(target.to_owned()));
                }
                None if path_is_occupied(target) => {
                    return Err(MigrationError::Conflict(target.to_owned()));
                }
                _ => {}
            },
        }
    }
    Ok(())
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

fn record_applied_state(receipt: &mut ApplyReceipt, target: &Path) {
    for backup in receipt.backups.iter_mut().filter(|entry| {
        entry.target == target
            || entry.target.starts_with(target)
            || target.starts_with(&entry.target)
    }) {
        backup.applied = Some(if path_is_occupied(&backup.target) {
            digest_path(&backup.target).map_or(AppliedState::Unknown, AppliedState::Digest)
        } else {
            AppliedState::Absent
        });
        backup.pending = None;
    }
}

fn rollback_receipt(
    context: &mut ApplyContext<'_>,
    receipt: &ApplyReceipt,
) -> Result<(), MigrationError> {
    verify_rollback_state(receipt)?;
    write_backup_manifest(receipt, RecoveryPhase::Applying)?;
    let mut errors = Vec::new();
    for undo in receipt.secrets.iter().rev() {
        let result = if let Some(previous) = &undo.previous {
            context
                .secret_store
                .put(&undo.id, previous.clone())
                .map(|_| ())
        } else {
            context.secret_store.remove(&undo.id)
        };
        if let Err(error) = result {
            errors.push(format!("secret {}: {error}", undo.id));
        }
    }
    for backup in receipt.backups.iter().rev() {
        if backup.applied.is_none() {
            continue;
        }
        let result = restore_backup(backup);
        if let Err(error) = result {
            errors.push(error.to_string());
        }

        if backup.backup.is_none() {
            cleanup_empty_parents(&backup.target, context.target_root);
        }
    }
    if errors.is_empty() {
        write_backup_manifest(receipt, RecoveryPhase::RolledBack)
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
        let Some(applied) = &backup.applied else {
            continue;
        };
        match applied {
            AppliedState::Absent if path_is_occupied(&backup.target) => {
                return Err(MigrationError::Conflict(backup.target.clone()));
            }
            AppliedState::Absent => {}
            AppliedState::Digest(expected) => {
                if !path_is_occupied(&backup.target) || digest_path(&backup.target)? != *expected {
                    return Err(MigrationError::Conflict(backup.target.clone()));
                }
            }
            AppliedState::Unknown => {
                return Err(MigrationError::Conflict(backup.target.clone()));
            }
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
            });
        } else {
            entries.push(BackupEntry {
                target: target.to_path_buf(),
                backup: None,
                digest: None,
                pending: None,
                applied: None,
            });
        }
    }
    Ok(entries)
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
        })
        .collect::<Vec<_>>();
    let manifest = RecoveryManifest {
        schema_version: RECOVERY_SCHEMA_VERSION,
        provider_id: receipt.provider_id.to_owned(),
        target_root: receipt.target_root.clone(),
        phase,
        entries,
    };
    write_recovery_manifest(&receipt.backup_dir.join("manifest.json"), &manifest)
}

fn write_recovery_manifest(path: &Path, manifest: &RecoveryManifest) -> Result<(), MigrationError> {
    let bytes = serde_json::to_vec_pretty(manifest).map_err(|error| {
        MigrationError::Signing(format!("backup manifest serialization: {error}"))
    })?;
    write_bytes(path, &bytes)
}

fn restore_backup(entry: &BackupEntry) -> Result<(), MigrationError> {
    if let Some(backup) = &entry.backup {
        let expected = entry.digest.as_deref().unwrap_or_default();
        if digest_path(backup)? != expected {
            return Err(MigrationError::BackupVerification(backup.clone()));
        }
        create_parent(&entry.target)?;
        copy_path(backup, &entry.target)?;
        if digest_path(&entry.target)? != expected {
            return Err(MigrationError::BackupVerification(entry.target.clone()));
        }
    } else {
        remove_path_if_exists(&entry.target)?;
    }
    Ok(())
}

fn cleanup_empty_parents(target: &Path, root: &Path) {
    let mut current = target.parent();
    while let Some(directory) = current {
        if directory == root || !directory.starts_with(root) {
            break;
        }
        match fs::remove_dir(directory) {
            Ok(()) => current = directory.parent(),
            Err(_) => break,
        }
    }
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
    undo: &mut Vec<SecretUndo>,
) -> Result<Vec<u8>, MigrationError> {
    let text = read_text(source)?;
    let mut value: Value =
        serde_json::from_str(&text).map_err(|_| MigrationError::InvalidInput {
            path: source.to_path_buf(),
            reason: "JSON configuration is malformed".to_owned(),
        })?;
    redact_json_value(&mut value, namespace, "", false, store, undo)?;
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
    undo: &mut Vec<SecretUndo>,
) -> Result<(), MigrationError> {
    match value {
        Value::Object(object) => {
            for (key, child) in object {
                let next_pointer = format!("{pointer}/{key}");
                let child_container =
                    matches!(key.to_ascii_lowercase().as_str(), "env" | "headers");
                if let Value::String(secret) = child
                    && (secret_container || secret_key(key))
                {
                    let id = secret_identifier(namespace, &next_pointer);
                    let reference = route_secret(store, undo, &id, secret.as_bytes())?;
                    *child = Value::String(reference);
                } else {
                    redact_json_value(
                        child,
                        namespace,
                        &next_pointer,
                        secret_container || child_container,
                        store,
                        undo,
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
                    undo,
                )?;
            }
        }
        Value::String(secret) if secret_container => {
            let id = secret_identifier(namespace, pointer);
            let reference = route_secret(store, undo, &id, secret.as_bytes())?;
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
    undo: &mut Vec<SecretUndo>,
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
                    undo,
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
                    let reference = route_secret(store, undo, &id, value.as_bytes())?;
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
    undo: &mut Vec<SecretUndo>,
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
        let reference = route_secret(store, undo, &id, plaintext.as_bytes())?;
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
            "inline env/headers table on line {} is not safely transformable",
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
    undo: &mut Vec<SecretUndo>,
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
            let reference = route_secret(store, undo, &id, value.as_bytes())?;
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
    undo: &mut Vec<SecretUndo>,
) -> Result<Vec<u8>, MigrationError> {
    let content = read_bytes(source)?;
    let reference = route_secret(store, undo, secret_id, &content)?;
    let mut object = Map::new();
    object.insert("secret_ref".to_owned(), Value::String(reference));
    serde_json::to_vec_pretty(&Value::Object(object))
        .map_err(|error| MigrationError::Signing(error.to_string()))
}

fn route_secret(
    store: &mut dyn SecretStore,
    undo: &mut Vec<SecretUndo>,
    id: &str,
    value: &[u8],
) -> Result<String, MigrationError> {
    if !undo.iter().any(|entry| entry.id == id) {
        let previous = store.get(id)?;
        undo.push(SecretUndo {
            id: id.to_owned(),
            previous,
        });
    }
    let reference = store.put(id, SecretValue::new(value))?;
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
    matches!(key.to_ascii_lowercase().as_str(), "env" | "headers")
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
        let mut hasher = Sha256::new();
        update_digest_from_file(path, &mut hasher)?;
        return Ok(encode_hex(&hasher.finalize()));
    }
    if !path.is_dir() {
        return Err(MigrationError::SourceNotFound {
            provider: "migration",
            path: path.to_path_buf(),
        });
    }
    let mut hasher = Sha256::new();
    digest_directory(path, path, &mut hasher)?;
    Ok(encode_hex(&hasher.finalize()))
}

fn digest_directory(
    root: &Path,
    current: &Path,
    hasher: &mut Sha256,
) -> Result<(), MigrationError> {
    for entry in sorted_entries(current)? {
        let path = entry.path();
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
        hasher.update(path_to_slashes(relative).as_bytes());
        hasher.update([0]);
        if metadata.is_dir() {
            digest_directory(root, &path, hasher)?;
        } else if metadata.is_file() {
            update_digest_from_file(&path, hasher)?;
        }
        hasher.update([0xff]);
    }
    Ok(())
}

fn update_digest_from_file(path: &Path, hasher: &mut Sha256) -> Result<(), MigrationError> {
    let file = File::open(path).map_err(|source| MigrationError::Io {
        action: "open for hashing",
        path: path.to_owned(),
        source,
    })?;
    let mut reader = file;
    let mut buffer = vec![0_u8; HASH_BUFFER_BYTES];
    loop {
        let read = reader
            .read(&mut buffer)
            .map_err(|source| MigrationError::Io {
                action: "hash",
                path: path.to_owned(),
                source,
            })?;
        if read == 0 {
            return Ok(());
        }
        hasher.update(&buffer[..read]);
    }
}

fn digest_bytes(bytes: &[u8]) -> String {
    encode_hex(&Sha256::digest(bytes))
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

fn copy_directory_atomically(source: &Path, target: &Path) -> Result<(), MigrationError> {
    create_parent(target)?;
    let staging = create_staging_directory(target)?;
    let result = copy_directory_contents(source, &staging)
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
            copy_directory_contents(&entry_source, &entry_target)?;
            sync_directory(&entry_target)?;
        } else if metadata.is_file() {
            copy_file(&entry_source, &entry_target)?;
        }
    }
    Ok(())
}

fn publish_single_file_directory(
    target: &Path,
    file_name: &str,
    bytes: &[u8],
) -> Result<(), MigrationError> {
    create_parent(target)?;
    let staging = create_staging_directory(target)?;
    let result = write_bytes(&staging.join(file_name), bytes)
        .and_then(|()| sync_directory(&staging))
        .and_then(|()| publish_staged_path(&staging, target));
    if result.is_err() && path_is_occupied(&staging) {
        let _ = remove_path_if_exists(&staging);
    }
    result
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
    fs::create_dir_all(path).map_err(|source| MigrationError::Io {
        action: "create directory",
        path: path.to_path_buf(),
        source,
    })
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

#[cfg(test)]
mod tests {
    use std::fs;
    use std::path::PathBuf;
    use std::sync::atomic::{AtomicU64, Ordering};

    use super::{MigrationError, publish_staged_path_with_hook};

    static NEXT_DIRECTORY: AtomicU64 = AtomicU64::new(0);

    #[test]
    fn staged_overwrite_failpoint_leaves_the_old_target_visible() {
        let directory = temporary_directory();
        let cleanup = Cleanup(directory.clone());
        let target = directory.join("target");
        let staging = directory.join("staging");
        fs::create_dir(&target).expect("create old target");
        fs::write(target.join("value"), b"old").expect("write old target");
        fs::create_dir(&staging).expect("create staged target");
        fs::write(staging.join("value"), b"new").expect("write staged target");

        let error = publish_staged_path_with_hook(&staging, &target, || {
            Err(MigrationError::Signing(
                "injected crash barrier before replacement".to_owned(),
            ))
        })
        .expect_err("failpoint must stop publication");

        assert!(error.to_string().contains("injected crash barrier"));
        assert_eq!(
            fs::read(target.join("value")).expect("read old target"),
            b"old"
        );
        assert_eq!(
            fs::read(staging.join("value")).expect("read staged target"),
            b"new"
        );
        drop(cleanup);
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

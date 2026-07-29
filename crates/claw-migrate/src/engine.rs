use std::collections::{BTreeMap, BTreeSet};
use std::error::Error;
use std::fmt::{self, Debug, Display, Formatter};
use std::fs::{self, File};
use std::io::{self, Read, Seek, SeekFrom, Write};
use std::path::{Component, Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

use ed25519_dalek::{Signer, SigningKey};
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};
use sha2::{Digest, Sha256};
use toml_edit::{DocumentMut, Item, TableLike, Value as TomlValue};

use crate::atomicfs::{self, ObjectIdentity};
use crate::contract::{
    Artifact, ArtifactKind, ArtifactSignature, ContractViolation, Diagnostic, DiagnosticSeverity,
    InputKind, MIGRATION_CONTRACT_VERSION, MigrationInput, MigrationResult, MigrationStatus,
};
use crate::platform::PlatformPaths;

static BACKUP_SEQUENCE: AtomicU64 = AtomicU64::new(0);
const DURABLE_RECEIPT_VERSION: u32 = 1;

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
    /// Optional explicit source override.
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
    /// Begins a reversible transaction whose staged changes are immediately
    /// readable through the returned references until commit or rollback.
    ///
    /// Stores that cannot durably recover pending mutations may leave the
    /// default implementation in place; apply then refuses to migrate secrets
    /// rather than publishing configuration that cannot be paired with a
    /// recoverable secret-store state.
    ///
    /// # Errors
    ///
    /// Returns [`SecretStoreError`] when the adapter cannot begin a crash-safe
    /// secret transaction.
    fn begin_transaction(&mut self) -> Result<String, SecretStoreError> {
        Err(SecretStoreError::new(
            "secret store does not support crash-safe transactions",
        ))
    }
    /// Persists one transactional mutation and returns the opaque reference.
    ///
    /// # Errors
    ///
    /// Returns [`SecretStoreError`] when the secret transaction is missing or
    /// the adapter cannot stage the new secret value.
    fn put_transactional(
        &mut self,
        transaction_id: &str,
        id: &str,
        value: SecretValue,
    ) -> Result<String, SecretStoreError> {
        let _ = transaction_id;
        self.put(id, value)
    }
    /// Removes one transactional entry.
    ///
    /// # Errors
    ///
    /// Returns [`SecretStoreError`] when the secret transaction is missing or
    /// the adapter cannot stage the removal.
    fn remove_transactional(
        &mut self,
        transaction_id: &str,
        id: &str,
    ) -> Result<(), SecretStoreError> {
        let _ = transaction_id;
        self.remove(id)
    }
    /// Permanently keeps every staged mutation in `transaction_id`.
    ///
    /// # Errors
    ///
    /// Returns [`SecretStoreError`] when the adapter cannot finalize the
    /// transaction durably.
    fn commit_transaction(&mut self, transaction_id: &str) -> Result<(), SecretStoreError> {
        let _ = transaction_id;
        Err(SecretStoreError::new(
            "secret store does not support crash-safe transactions",
        ))
    }
    /// Restores every staged mutation in `transaction_id`.
    ///
    /// # Errors
    ///
    /// Returns [`SecretStoreError`] when the adapter cannot restore the
    /// transaction's original secret-store state.
    fn rollback_transaction(&mut self, transaction_id: &str) -> Result<(), SecretStoreError> {
        let _ = transaction_id;
        Err(SecretStoreError::new(
            "secret store does not support crash-safe transactions",
        ))
    }
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
    backups: Vec<BackupEntry>,
    secrets: Vec<SecretUndo>,
    secret_transaction: Option<String>,
}

impl Debug for ApplyReceipt {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ApplyReceipt")
            .field("provider_id", &self.provider_id)
            .field("backup_dir", &self.backup_dir)
            .field("backup_count", &self.backups.len())
            .field("secret_count", &self.secrets.len())
            .field("has_secret_transaction", &self.secret_transaction.is_some())
            .finish()
    }
}

struct BackupEntry {
    target: PathBuf,
    backup: Option<PathBuf>,
    original_digest: Option<String>,
    original_absent: bool,
    expected_new_digest: Option<String>,
    stage: Option<PathBuf>,
    applied: bool,
}

impl BackupEntry {
    /// Digest the target must still carry for this entry's next publication.
    ///
    /// Before the entry is published that is the pre-apply digest; afterwards it
    /// is whatever this apply itself wrote, so a second operation aimed at the
    /// same target (an append, for instance) compares against the bytes the
    /// first one published rather than against bytes that no longer exist.
    fn expected_current_digest(&self) -> Option<String> {
        if self.applied {
            self.expected_new_digest.clone()
        } else {
            self.original_digest.clone()
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
enum DurableReceiptState {
    Pending,
    FilesPublished,
    Committed,
    Aborted,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
struct DurableBackupEntry {
    target: PathBuf,
    backup: Option<PathBuf>,
    original_sha256: Option<String>,
    expected_new_sha256: Option<String>,
    original_absent: bool,
    /// Reserved staging path whose publication was in flight when the record was
    /// written, so recovery can remove the leftover after restoring the target.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    stage: Option<PathBuf>,
    /// Whether publication of this entry had already been attempted.
    ///
    /// Recorded *before* the atomic displacement so a crash between the rename
    /// and the parent-directory sync still leaves a receipt that names the entry
    /// as one recovery must inspect and restore.
    #[serde(default)]
    published: bool,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
struct DurableReceipt {
    version: u32,
    provider_id: String,
    state: DurableReceiptState,
    backups: Vec<DurableBackupEntry>,
    secret_transaction: Option<String>,
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
    recover_pending_backups(
        context.backup_root,
        context.target_root,
        context.secret_store,
    )?;
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
    let backup_dir = create_backup_dir(context.backup_root, plan.provider_id)?;
    let backups = backup_targets(&backup_dir, &plan.operations)?;
    verify_targets_unchanged(&backups)?;
    let mut receipt = ApplyReceipt {
        provider_id: plan.provider_id,
        backup_dir,
        backups,
        secrets: Vec::new(),
        secret_transaction: None,
    };
    if plan_uses_secrets(&plan.operations) {
        receipt.secret_transaction = Some(context.secret_store.begin_transaction()?);
    }
    write_backup_manifest(&receipt)?;
    write_durable_receipt(&receipt, DurableReceiptState::Pending)?;
    let apply_result = apply_operations(context, &plan.operations, &mut receipt)
        .and_then(|()| verify_source_digests(plan))
        .and_then(|()| write_durable_receipt(&receipt, DurableReceiptState::FilesPublished))
        .and_then(|()| {
            test_publish_failpoint::trigger("after_files_published", context.target_root);
            commit_secret_transaction(context.secret_store, &receipt)
        })
        .and_then(|()| write_durable_receipt(&receipt, DurableReceiptState::Committed));
    if let Err(error) = apply_result {
        let rollback_errors = match rollback_receipt(context, &receipt) {
            // `Aborted` is a durable claim that nothing of this apply survives.
            // It is only written once every entry has been re-read from disk and
            // proven to match its pre-apply state, so a rollback that restored
            // the bytes but could not sync the directory entry never gets
            // recorded as a clean abort.
            Ok(()) => match verify_restored_to_original(&receipt) {
                Ok(()) => write_durable_receipt(&receipt, DurableReceiptState::Aborted)
                    .err()
                    .map_or_else(Vec::new, |error| vec![error.to_string()]),
                Err(error) => vec![error.to_string()],
            },
            Err(error) => rollback_failure_messages(error),
        };
        return Err(MigrationError::ApplyFailed {
            cause: Box::new(error),
            rollback_errors,
        });
    }
    Ok(receipt)
}

/// Re-reads every target and proves it carries exactly its pre-apply state.
fn verify_restored_to_original(receipt: &ApplyReceipt) -> Result<(), MigrationError> {
    for backup in &receipt.backups {
        let occupied = path_is_occupied(&backup.target);
        let restored = match (&backup.original_digest, occupied) {
            (Some(expected), true) => digest_path(&backup.target)? == *expected,
            (None, false) => true,
            _ => false,
        };
        if !restored {
            return Err(MigrationError::Conflict(backup.target.clone()));
        }
        sync_nearest_existing_ancestor(&backup.target)?;
    }
    Ok(())
}

/// Flushes the closest directory that still exists above `path`.
///
/// Rollback removes the directories it created, so the immediate parent of a
/// restored-to-absent target is often gone by the time the abort is verified.
/// The entry that must reach stable storage is the one in the directory that
/// still holds the (now missing) name.
fn sync_nearest_existing_ancestor(path: &Path) -> Result<(), MigrationError> {
    let mut current = path.parent();
    while let Some(directory) = current {
        if directory.as_os_str().is_empty() {
            return Ok(());
        }
        match fs::symlink_metadata(directory) {
            Ok(metadata) if metadata.is_dir() => return sync_directory(directory),
            Ok(_) => return Ok(()),
            Err(error) if error.kind() == io::ErrorKind::NotFound => current = directory.parent(),
            Err(source) => {
                return Err(MigrationError::Io {
                    action: "inspect",
                    path: directory.to_path_buf(),
                    source,
                });
            }
        }
    }
    Ok(())
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

fn apply_operations(
    context: &mut ApplyContext<'_>,
    operations: &[MigrationOperation],
    receipt: &mut ApplyReceipt,
) -> Result<(), MigrationError> {
    for operation in operations {
        let target = operation.target();
        let mut staged = StagedArtifact::reserve(target, "stage")?;
        record_stage_reservation(receipt, target, staged.path());
        write_durable_receipt(receipt, DurableReceiptState::Pending)?;
        let secret_transaction = receipt.secret_transaction.clone();
        materialize_operation(
            context,
            operation,
            &mut staged,
            secret_transaction.as_deref(),
            &mut receipt.secrets,
        )?;
        staged.sync()?;
        let expected_new = digest_path(staged.path())?;
        let expected_current = current_expectation(receipt, target);

        // The digest of what is about to be published is recorded *before* the
        // displacement, so a crash between the rename and the parent sync still
        // leaves a receipt that describes the bytes now sitting at the target.
        // Without it, recovery would read its own output as a foreign edit.
        record_publication_intent(receipt, target, &expected_new);
        write_durable_receipt(receipt, DurableReceiptState::Pending)?;
        test_publish_failpoint::trigger("after_staging_write", target);
        publish_staged_artifact(
            context.target_root,
            target,
            &mut staged,
            expected_current.as_deref(),
            &receipt.backup_dir,
        )?;
        staged.into_published();
        record_applied_state(receipt, target)?;
        write_durable_receipt(receipt, DurableReceiptState::Pending)?;
    }
    Ok(())
}

/// Digest the next publication of `target` must find in place.
fn current_expectation(receipt: &ApplyReceipt, target: &Path) -> Option<String> {
    receipt
        .backups
        .iter()
        .find(|entry| entry.target == target)
        .and_then(BackupEntry::expected_current_digest)
}

fn record_stage_reservation(receipt: &mut ApplyReceipt, target: &Path, stage: &Path) {
    for backup in receipt
        .backups
        .iter_mut()
        .filter(|entry| entry.target == target)
    {
        backup.stage = Some(stage.to_path_buf());
    }
}

fn record_publication_intent(receipt: &mut ApplyReceipt, target: &Path, expected_new: &str) {
    for backup in receipt
        .backups
        .iter_mut()
        .filter(|entry| entry.target == target)
    {
        backup.expected_new_digest = Some(expected_new.to_owned());
        backup.applied = true;
    }
}

fn materialize_operation(
    context: &mut ApplyContext<'_>,
    operation: &MigrationOperation,
    staged: &mut StagedArtifact,
    secret_transaction: Option<&str>,
    secret_undo: &mut Vec<SecretUndo>,
) -> Result<(), MigrationError> {
    match operation {
        MigrationOperation::AppendFile {
            source,
            target,
            heading,
        } => {
            let bytes = appended_bytes(source, target, heading)?;
            staged.write_bytes(&bytes)
        }
        MigrationOperation::CopyPath { source, .. } => copy_into_stage(source, staged),
        MigrationOperation::GeneratedCommandSkill { source, name, .. } => {
            let generated = command_skill_bytes(source, name)?;
            staged.make_directory()?;
            let skill = staged.path().join("SKILL.md");
            write_bytes(&skill, generated.as_bytes())
        }
        MigrationOperation::TransformJson {
            source, namespace, ..
        } => {
            let bytes = transform_json(
                source,
                namespace,
                context.secret_store,
                secret_transaction,
                secret_undo,
            )?;
            staged.write_bytes(&bytes)
        }
        MigrationOperation::TransformText {
            source, namespace, ..
        } => {
            let bytes = transform_text(
                source,
                namespace,
                context.secret_store,
                secret_transaction,
                secret_undo,
            )?;
            staged.write_bytes(&bytes)
        }
        MigrationOperation::ImportEnvironment {
            source, namespace, ..
        } => {
            let bytes = import_environment(
                source,
                namespace,
                context.secret_store,
                secret_transaction,
                secret_undo,
            )?;
            staged.write_bytes(&bytes)
        }
        MigrationOperation::StoreDocument {
            source, secret_id, ..
        } => {
            let bytes = store_document(
                source,
                secret_id,
                context.secret_store,
                secret_transaction,
                secret_undo,
            )?;
            staged.write_bytes(&bytes)
        }
        MigrationOperation::WriteBytes { bytes, .. } => staged.write_bytes(bytes),
    }
}

/// A reserved publication path and the handle that proves what it names.
///
/// The handle stays open from reservation until publication. Dropping it and
/// re-opening by path would give up exactly the guarantee the `O_NOFOLLOW`
/// creation bought: between the two opens another process could delete the
/// reservation and leave a symbolic link in its place, and the migration would
/// then write through that link. Every byte therefore goes through the retained
/// handle, and [`StagedArtifact::verify_identity`] re-checks that the path still
/// names the same object immediately before the displacement.
struct StagedArtifact {
    path: PathBuf,
    handle: Option<File>,
    identity: ObjectIdentity,
    directory: bool,
    published: bool,
}

impl StagedArtifact {
    fn reserve(target: &Path, label: &str) -> Result<Self, MigrationError> {
        create_parent(target)?;
        for _ in 0..128 {
            let sequence = BACKUP_SEQUENCE.fetch_add(1, Ordering::Relaxed);
            let file_name = target
                .file_name()
                .and_then(|value| value.to_str())
                .unwrap_or("target");
            let candidate = target.with_file_name(format!(
                ".{file_name}.migration-{label}-{}.{}",
                std::process::id(),
                sequence
            ));
            match atomicfs::create_new_no_follow(&candidate) {
                Ok(handle) => {
                    let identity = atomicfs::identity_of_handle(&handle).map_err(|source| {
                        MigrationError::Io {
                            action: "inspect reserved publication path",
                            path: candidate.clone(),
                            source,
                        }
                    })?;
                    let staged = Self {
                        path: candidate,
                        handle: Some(handle),
                        identity,
                        directory: false,
                        published: false,
                    };
                    staged.verify_identity()?;
                    return Ok(staged);
                }
                Err(source) if source.kind() == io::ErrorKind::AlreadyExists => {}
                Err(source) => {
                    return Err(MigrationError::Io {
                        action: "reserve temporary publication path",
                        path: candidate,
                        source,
                    });
                }
            }
        }
        Err(MigrationError::Io {
            action: "reserve temporary publication path",
            path: target.to_path_buf(),
            source: io::Error::new(
                io::ErrorKind::AlreadyExists,
                "could not allocate a unique migration publication path",
            ),
        })
    }

    fn path(&self) -> &Path {
        &self.path
    }

    /// Confirms the reservation path still names the object opened at creation.
    fn verify_identity(&self) -> Result<(), MigrationError> {
        let observed =
            atomicfs::identity_of_path(&self.path).map_err(|source| MigrationError::Io {
                action: "inspect reserved publication path",
                path: self.path.clone(),
                source,
            })?;
        if observed == self.identity {
            return Ok(());
        }
        Err(MigrationError::Io {
            action: "inspect reserved publication path",
            path: self.path.clone(),
            source: io::Error::new(
                io::ErrorKind::InvalidData,
                "temporary publication path identity changed before publication",
            ),
        })
    }

    /// Replaces the reserved regular file with a freshly created directory.
    ///
    /// The reservation is removed through its own verified path and the
    /// directory is created with `create_dir`, which fails rather than adopting
    /// an object another process slipped in, and the new object's identity is
    /// recorded so publication still verifies what it is about to move.
    fn make_directory(&mut self) -> Result<(), MigrationError> {
        self.verify_identity()?;
        self.handle = None;
        remove_path_if_exists(&self.path)?;
        fs::create_dir(&self.path).map_err(|source| MigrationError::Io {
            action: "create staged directory",
            path: self.path.clone(),
            source,
        })?;
        self.identity =
            atomicfs::identity_of_path(&self.path).map_err(|source| MigrationError::Io {
                action: "inspect staged directory",
                path: self.path.clone(),
                source,
            })?;
        self.directory = true;
        Ok(())
    }

    fn write_bytes(&mut self, bytes: &[u8]) -> Result<(), MigrationError> {
        self.with_handle("write staged migration bytes", |handle| {
            handle.set_len(0)?;
            handle.seek(SeekFrom::Start(0))?;
            handle.write_all(bytes)?;
            handle.flush()
        })
    }

    /// Streams a regular file through the reservation's own handle.
    fn copy_from_file(&mut self, source: &Path) -> Result<(), MigrationError> {
        let mut reader = atomicfs::open_no_follow(source).map_err(|error| MigrationError::Io {
            action: "read",
            path: source.to_path_buf(),
            source: error,
        })?;
        self.with_handle("write staged migration bytes", |handle| {
            handle.set_len(0)?;
            handle.seek(SeekFrom::Start(0))?;
            io::copy(&mut reader, handle)?;
            handle.flush()
        })
    }

    fn with_handle<T>(
        &mut self,
        action: &'static str,
        operation: impl FnOnce(&mut File) -> io::Result<T>,
    ) -> Result<T, MigrationError> {
        let path = self.path.clone();
        let handle = self.handle.as_mut().ok_or_else(|| MigrationError::Io {
            action,
            path: path.clone(),
            source: io::Error::new(
                io::ErrorKind::InvalidInput,
                "staged directory has no regular-file handle",
            ),
        })?;
        operation(handle).map_err(|source| MigrationError::Io {
            action,
            path,
            source,
        })
    }

    fn sync(&mut self) -> Result<(), MigrationError> {
        if self.directory {
            sync_path_tree(&self.path)?;
        } else {
            self.with_handle("sync staged migration bytes", |handle| handle.sync_all())?;
        }
        self.verify_identity()
    }

    /// Releases the handle so the platform can move the staged object.
    fn release_handle(&mut self) {
        self.handle = None;
    }

    /// Marks the reservation as consumed so `Drop` leaves the filesystem alone.
    fn into_published(mut self) {
        self.published = true;
    }
}

impl Drop for StagedArtifact {
    fn drop(&mut self) {
        if self.published {
            return;
        }
        self.handle = None;
        let _ = remove_path_if_exists(&self.path);
    }
}

/// Publishes a staged object over `target` under a compare-and-swap.
///
/// The comparison is bound to the displacement rather than performed before it.
/// A digest read a moment earlier proves nothing: two applies can both observe
/// the same prior bytes, both stage a replacement, and the second rename then
/// destroys whatever the first one published. Exchanging the staged object with
/// the target moves the previous occupant to the staging path in the same atomic
/// step, so the object that is inspected is exactly the object that was
/// replaced. A mismatch is undone by swapping back and the displaced bytes are
/// preserved verbatim in the durable backup directory.
///
/// The target is occupied by either the old object or the new one at every
/// instant, including for a non-empty directory, which a plain rename cannot
/// replace at all.
fn publish_staged_artifact(
    target_root: &Path,
    target: &Path,
    staged: &mut StagedArtifact,
    expected_current: Option<&str>,
    conflict_root: &Path,
) -> Result<(), MigrationError> {
    ensure_no_symlink_ancestors(target_root, target)?;
    staged.verify_identity()?;
    test_publish_failpoint::run_barrier("before_publish", target);
    staged.verify_identity()?;
    staged.release_handle();
    swap_into_place(staged.path(), target, expected_current, conflict_root)
}

/// Compare-and-swap `replacement` onto `target`.
///
/// `expected` is the digest the target must still carry, or `None` when the
/// target must still be absent. On success `replacement` no longer exists.
fn swap_into_place(
    replacement: &Path,
    target: &Path,
    expected: Option<&str>,
    conflict_root: &Path,
) -> Result<(), MigrationError> {
    let Some(expected) = expected else {
        return match atomicfs::rename_no_replace(replacement, target) {
            Ok(()) => {
                test_publish_failpoint::trigger("after_target_moved", target);
                sync_parent_path(target)?;
                test_publish_failpoint::trigger("after_target_published", target);
                Ok(())
            }
            Err(source) if source.kind() == io::ErrorKind::AlreadyExists => {
                Err(preserve_conflicting_target(target, conflict_root)?)
            }
            Err(source) => Err(MigrationError::Io {
                action: "publish staged migration target",
                path: target.to_path_buf(),
                source,
            }),
        };
    };
    if !path_is_occupied(target) {
        return Err(MigrationError::Conflict(target.to_path_buf()));
    }
    atomicfs::exchange_paths(replacement, target).map_err(|source| MigrationError::Io {
        action: "publish staged migration target",
        path: target.to_path_buf(),
        source,
    })?;
    test_publish_failpoint::trigger("after_target_moved", target);
    match digest_path(replacement) {
        Ok(displaced) if displaced == expected => {
            remove_path_if_exists(replacement)?;
            sync_parent_path(target)?;
            test_publish_failpoint::trigger("after_target_published", target);
            Ok(())
        }
        outcome => {
            atomicfs::exchange_paths(replacement, target).map_err(|source| MigrationError::Io {
                action: "restore concurrently changed migration target",
                path: target.to_path_buf(),
                source,
            })?;
            sync_parent_path(target)?;
            match outcome {
                // A link planted at the target is named by the target it was
                // planted at, not by the staging path it was momentarily swapped
                // to while the comparison ran.
                Err(MigrationError::Symlink(_)) => {
                    Err(MigrationError::Symlink(target.to_path_buf()))
                }
                Err(error) => Err(error),
                Ok(_) => Err(preserve_conflicting_target(target, conflict_root)?),
            }
        }
    }
}

/// Copies the exact object occupying `target` into the durable conflict store.
///
/// The copy is what makes a refusal actionable: the bytes another writer
/// published are kept verbatim next to the receipt, and the target itself is
/// left exactly as that writer left it.
fn preserve_conflicting_target(
    target: &Path,
    conflict_root: &Path,
) -> Result<MigrationError, MigrationError> {
    if !path_is_occupied(target) {
        return Ok(MigrationError::Conflict(target.to_path_buf()));
    }
    let conflicts = conflict_root.join("conflicts");
    create_dir_all(&conflicts)?;
    let sequence = BACKUP_SEQUENCE.fetch_add(1, Ordering::Relaxed);
    let preserved = conflicts.join(sequence.to_string());
    remove_path_if_exists(&preserved)?;
    copy_path(target, &preserved)?;
    sync_path_tree(&preserved)?;
    sync_parent_path(&preserved)?;
    Ok(MigrationError::Conflict(preserved))
}

fn recover_pending_backups(
    backup_root: &Path,
    target_root: &Path,
    secret_store: &mut dyn SecretStore,
) -> Result<(), MigrationError> {
    if !backup_root.exists() {
        return Ok(());
    }
    for entry in sorted_entries(backup_root)? {
        let Ok(file_type) = entry.file_type() else {
            continue;
        };
        if !file_type.is_dir() {
            continue;
        }
        let backup_dir = entry.path();
        let receipt_path = backup_dir.join("receipt.json");
        if !receipt_path.exists() {
            continue;
        }
        let mut receipt = read_durable_receipt(&receipt_path)?;
        if receipt.version != DURABLE_RECEIPT_VERSION {
            return Err(MigrationError::Io {
                action: "parse durable migration receipt",
                path: receipt_path,
                source: io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!("unsupported durable receipt version {}", receipt.version),
                ),
            });
        }
        match receipt.state {
            DurableReceiptState::Pending => {
                restore_pending_receipt(target_root, &backup_dir, &receipt.backups)?;
                rollback_secret_transaction(secret_store, receipt.secret_transaction.as_deref())?;
                receipt.state = DurableReceiptState::Aborted;
                write_durable_receipt_at(&backup_dir, &receipt)?;
            }
            DurableReceiptState::FilesPublished => {
                // Secrets are only finalized once every published file is proven
                // to still carry the exact bytes this transaction wrote. A target
                // that was edited or deleted after publication means the
                // configuration a committed credential belongs to no longer
                // exists, so the transaction stays open and the receipt keeps its
                // pre-commit state.
                verify_published_files(target_root, &backup_dir, &receipt.backups)?;
                commit_secret_transaction_by_id(
                    secret_store,
                    receipt.secret_transaction.as_deref(),
                )?;
                receipt.state = DurableReceiptState::Committed;
                write_durable_receipt_at(&backup_dir, &receipt)?;
            }
            DurableReceiptState::Committed | DurableReceiptState::Aborted => {}
        }
    }
    Ok(())
}

/// Confirms every entry still carries the digest this transaction published.
fn verify_published_files(
    target_root: &Path,
    backup_dir: &Path,
    backups: &[DurableBackupEntry],
) -> Result<(), MigrationError> {
    for entry in backups {
        ensure_target_within(target_root, &entry.target)?;
        ensure_no_symlink_ancestors(target_root, &entry.target)?;
        let occupied = path_is_occupied(&entry.target);
        match (&entry.expected_new_sha256, occupied) {
            (Some(expected), true) if digest_path(&entry.target)? == *expected => {}
            (None, false) => {}
            (_, true) => return Err(preserve_conflicting_target(&entry.target, backup_dir)?),
            (Some(_), false) => return Err(MigrationError::Conflict(entry.target.clone())),
        }
    }
    Ok(())
}

fn restore_pending_receipt(
    target_root: &Path,
    backup_dir: &Path,
    backups: &[DurableBackupEntry],
) -> Result<(), MigrationError> {
    let targets = backups
        .iter()
        .map(|entry| entry.target.as_path())
        .collect::<Vec<_>>();
    for index in restoration_order(&targets) {
        let entry = &backups[index];
        ensure_target_within(target_root, &entry.target)?;
        ensure_no_symlink_ancestors(target_root, &entry.target)?;
        let backup = BackupEntry {
            target: entry.target.clone(),
            backup: entry.backup.clone(),
            original_digest: entry.original_sha256.clone(),
            original_absent: entry.original_absent,
            expected_new_digest: entry.expected_new_sha256.clone(),
            stage: entry.stage.clone(),
            applied: true,
        };
        restore_backup(&backup, backup_dir)?;
        if let Some(stage) = &entry.stage
            && stage != &entry.target
        {
            remove_path_if_exists(stage)?;
            sync_parent_path(stage)?;
        }
        if backup.backup.is_none() {
            cleanup_empty_parents(&backup.target, target_root);
        }
    }
    Ok(())
}

fn record_applied_state(receipt: &mut ApplyReceipt, target: &Path) -> Result<(), MigrationError> {
    for backup in receipt.backups.iter_mut().filter(|entry| {
        entry.target == target
            || entry.target.starts_with(target)
            || target.starts_with(&entry.target)
    }) {
        backup.applied = true;
        backup.expected_new_digest = if path_is_occupied(&backup.target) {
            Some(digest_path(&backup.target)?)
        } else {
            None
        };
        if backup.target == target {
            backup.stage = None;
        }
    }
    Ok(())
}

fn rollback_receipt(
    context: &mut ApplyContext<'_>,
    receipt: &ApplyReceipt,
) -> Result<(), MigrationError> {
    verify_rollback_state(receipt)?;
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
    if errors.is_empty()
        && let Err(error) =
            rollback_secret_transaction(context.secret_store, receipt.secret_transaction.as_deref())
    {
        errors.push(format!("secret transaction: {error}"));
    }
    let targets = receipt
        .backups
        .iter()
        .map(|entry| entry.target.as_path())
        .collect::<Vec<_>>();
    for index in restoration_order(&targets) {
        let backup = &receipt.backups[index];
        if !backup.applied {
            continue;
        }
        let result = restore_backup(backup, &receipt.backup_dir);
        if let Err(error) = result {
            errors.push(error.to_string());
        }

        if backup.backup.is_none() {
            cleanup_empty_parents(&backup.target, context.target_root);
        }
    }
    if errors.is_empty() {
        Ok(())
    } else {
        Err(MigrationError::RollbackFailed { errors })
    }
}

/// Order in which recorded targets must be put back.
///
/// Undo is reverse-of-apply, except that an ancestor is always restored before
/// anything nested inside it. Restoring a nested target first would rewrite the
/// ancestor directory's contents, and the ancestor's recorded post-apply digest
/// would then no longer describe what is on disk — indistinguishable from a
/// foreign edit, which rollback is required to refuse. Putting the ancestor back
/// restores the whole subtree in one atomic exchange and leaves every nested
/// entry already matching its own pre-apply state.
fn restoration_order(targets: &[&Path]) -> Vec<usize> {
    let mut order = (0..targets.len()).rev().collect::<Vec<_>>();
    order.sort_by_key(|&index| targets[index].components().count());
    order
}

fn rollback_failure_messages(error: MigrationError) -> Vec<String> {
    match error {
        MigrationError::RollbackFailed { errors } => errors,
        other => vec![other.to_string()],
    }
}

fn verify_rollback_state(receipt: &ApplyReceipt) -> Result<(), MigrationError> {
    for backup in &receipt.backups {
        if !backup.applied {
            continue;
        }
        let occupied = path_is_occupied(&backup.target);
        let matches_original = match (&backup.original_digest, occupied) {
            (Some(expected), true) => digest_path(&backup.target)? == *expected,
            (None, false) => true,
            _ => false,
        };
        if matches_original {
            continue;
        }
        match (&backup.expected_new_digest, occupied) {
            (Some(expected), true) if digest_path(&backup.target)? == *expected => {}
            (None, false) => {}
            _ => return Err(MigrationError::Conflict(backup.target.clone())),
        }
        if let (Some(path), Some(expected)) = (&backup.backup, &backup.original_digest)
            && digest_path(path)? != *expected
        {
            return Err(MigrationError::BackupVerification(path.clone()));
        }
    }
    Ok(())
}

fn create_backup_dir(root: &Path, provider_id: &str) -> Result<PathBuf, MigrationError> {
    create_dir_all(root)?;
    sync_parent_path(root)?;
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
    sync_parent_path(&directory)?;
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
            sync_path_tree(&backup)?;
            sync_parent_path(&backup)?;
            let source_digest = digest_path(target)?;
            let backup_digest = digest_path(&backup)?;
            if source_digest != backup_digest {
                return Err(MigrationError::BackupVerification(target.to_path_buf()));
            }
            entries.push(BackupEntry {
                target: target.to_path_buf(),
                backup: Some(backup),
                original_digest: Some(backup_digest),
                original_absent: false,
                expected_new_digest: None,
                stage: None,
                applied: false,
            });
        } else {
            entries.push(BackupEntry {
                target: target.to_path_buf(),
                backup: None,
                original_digest: None,
                original_absent: true,
                expected_new_digest: None,
                stage: None,
                applied: false,
            });
        }
    }
    Ok(entries)
}

fn verify_targets_unchanged(backups: &[BackupEntry]) -> Result<(), MigrationError> {
    for backup in backups {
        match &backup.original_digest {
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

fn write_backup_manifest(receipt: &ApplyReceipt) -> Result<(), MigrationError> {
    #[derive(Serialize)]
    struct ManifestEntry {
        target: String,
        backup: Option<String>,
        sha256: Option<String>,
    }
    let entries = receipt
        .backups
        .iter()
        .map(|entry| ManifestEntry {
            target: entry.target.display().to_string(),
            backup: entry.backup.as_ref().map(|path| path.display().to_string()),
            sha256: entry.original_digest.clone(),
        })
        .collect::<Vec<_>>();
    let bytes = serde_json::to_vec_pretty(&entries).map_err(|error| {
        MigrationError::Signing(format!("backup manifest serialization: {error}"))
    })?;
    write_durable_bytes(&receipt.backup_dir.join("manifest.json"), &bytes)
}

fn write_durable_receipt(
    receipt: &ApplyReceipt,
    state: DurableReceiptState,
) -> Result<(), MigrationError> {
    let durable = DurableReceipt {
        version: DURABLE_RECEIPT_VERSION,
        provider_id: receipt.provider_id.to_owned(),
        state,
        backups: receipt
            .backups
            .iter()
            .map(|entry| DurableBackupEntry {
                target: entry.target.clone(),
                backup: entry.backup.clone(),
                original_sha256: entry.original_digest.clone(),
                expected_new_sha256: entry.expected_new_digest.clone(),
                original_absent: entry.original_absent,
                stage: entry.stage.clone(),
                published: entry.applied,
            })
            .collect(),
        secret_transaction: receipt.secret_transaction.clone(),
    };
    write_durable_receipt_at(&receipt.backup_dir, &durable)
}

fn write_durable_receipt_at(
    backup_dir: &Path,
    receipt: &DurableReceipt,
) -> Result<(), MigrationError> {
    let bytes = serde_json::to_vec_pretty(receipt).map_err(|error| {
        MigrationError::Signing(format!("durable receipt serialization: {error}"))
    })?;
    write_durable_bytes(&backup_dir.join("receipt.json"), &bytes)
}

fn read_durable_receipt(path: &Path) -> Result<DurableReceipt, MigrationError> {
    let bytes = read_bytes(path)?;
    serde_json::from_slice(&bytes).map_err(|source| MigrationError::Io {
        action: "parse durable migration receipt",
        path: path.to_path_buf(),
        source: io::Error::new(io::ErrorKind::InvalidData, source.to_string()),
    })
}

/// Puts one entry back exactly as apply found it.
///
/// Restoration is published the same way apply publishes: the replacement is
/// materialized beside the target and exchanged into place, so a non-empty
/// directory can be restored at all and the target is never momentarily missing.
/// The exchange is compared against the digest the entry is expected to carry,
/// so a target another writer changed after apply is preserved instead of
/// silently overwritten.
fn restore_backup(entry: &BackupEntry, conflict_root: &Path) -> Result<(), MigrationError> {
    let occupied = path_is_occupied(&entry.target);
    let matches_original = match (&entry.original_digest, occupied) {
        (Some(expected), true) => digest_path(&entry.target)? == *expected,
        (None, false) => true,
        _ => false,
    };
    if matches_original {
        return Ok(());
    }
    let expected_current = match (&entry.expected_new_digest, occupied) {
        (Some(expected), true) if digest_path(&entry.target)? == *expected => {
            Some(expected.clone())
        }
        (None, false) => None,
        _ => return Err(preserve_conflicting_target(&entry.target, conflict_root)?),
    };
    let Some(backup) = &entry.backup else {
        remove_verified_target(&entry.target, expected_current.as_deref())?;
        sync_parent_path(&entry.target)?;
        return Ok(());
    };
    let expected = entry.original_digest.as_deref().unwrap_or_default();
    if digest_path(backup)? != expected {
        return Err(MigrationError::BackupVerification(backup.clone()));
    }
    let mut staged = StagedArtifact::reserve(&entry.target, "rollback")?;
    copy_into_stage(backup, &mut staged)?;
    staged.sync()?;
    if digest_path(staged.path())? != expected {
        return Err(MigrationError::BackupVerification(
            staged.path().to_path_buf(),
        ));
    }
    staged.release_handle();
    swap_into_place(
        staged.path(),
        &entry.target,
        expected_current.as_deref(),
        conflict_root,
    )?;
    staged.into_published();
    Ok(())
}

/// Removes a target this apply created, refusing to delete foreign bytes.
fn remove_verified_target(target: &Path, expected: Option<&str>) -> Result<(), MigrationError> {
    if let Some(expected) = expected
        && digest_path(target)? != *expected
    {
        return Err(MigrationError::Conflict(target.to_path_buf()));
    }
    remove_path_if_exists(target)
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

/// Materializes `source` into a reserved staging artifact.
///
/// A regular file is streamed through the reservation's own handle so the bytes
/// never travel through a path that could be re-pointed underneath them; a
/// directory tree is written into a directory created in place of the
/// reservation, whose identity is recorded and re-verified before publication.
fn copy_into_stage(source: &Path, staged: &mut StagedArtifact) -> Result<(), MigrationError> {
    reject_symlink(source)?;
    if source.is_dir() {
        staged.make_directory()?;
        let destination = staged.path().to_path_buf();
        return copy_path(source, &destination);
    }
    if source.is_file() {
        return staged.copy_from_file(source);
    }
    Err(MigrationError::SourceNotFound {
        provider: "migration",
        path: source.to_path_buf(),
    })
}

fn appended_bytes(source: &Path, target: &Path, heading: &str) -> Result<Vec<u8>, MigrationError> {
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

fn command_skill_bytes(source: &Path, name: &str) -> Result<String, MigrationError> {
    let content = read_text(source)?;
    let description = content
        .split("\n\n")
        .map(str::trim)
        .find(|part| !part.is_empty())
        .unwrap_or("Imported Claude command")
        .replace('\n', " ");
    let description = description.chars().take(180).collect::<String>();
    Ok(format!(
        "---\nname: {name}\ndescription: {}\ndisable-model-invocation: true\n---\n\n<!-- Imported inert Claude command -->\n\n{}\n",
        serde_json::to_string(&description)
            .map_err(|error| MigrationError::Signing(error.to_string()))?,
        content.trim_end()
    ))
}

fn transform_json(
    source: &Path,
    namespace: &str,
    store: &mut dyn SecretStore,
    transaction_id: Option<&str>,
    undo: &mut Vec<SecretUndo>,
) -> Result<Vec<u8>, MigrationError> {
    let text = read_text(source)?;
    let mut value: Value =
        serde_json::from_str(&text).map_err(|_| MigrationError::InvalidInput {
            path: source.to_path_buf(),
            reason: "JSON configuration is malformed".to_owned(),
        })?;
    redact_json_value(
        &mut value,
        namespace,
        "",
        false,
        store,
        transaction_id,
        undo,
    )?;
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
    transaction_id: Option<&str>,
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
                    let reference =
                        route_secret(store, transaction_id, undo, &id, secret.as_bytes())?;
                    *child = Value::String(reference);
                } else {
                    redact_json_value(
                        child,
                        namespace,
                        &next_pointer,
                        secret_container || child_container,
                        store,
                        transaction_id,
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
                    transaction_id,
                    undo,
                )?;
            }
        }
        Value::String(secret) if secret_container => {
            let id = secret_identifier(namespace, pointer);
            let reference = route_secret(store, transaction_id, undo, &id, secret.as_bytes())?;
            *value = Value::String(reference);
        }
        _ => {}
    }
    Ok(())
}

fn transform_text(
    source: &Path,
    namespace: &str,
    store: &mut dyn SecretStore,
    transaction_id: Option<&str>,
    undo: &mut Vec<SecretUndo>,
) -> Result<Vec<u8>, MigrationError> {
    let input = read_text(source)?;
    if source
        .extension()
        .and_then(|value| value.to_str())
        .is_some_and(|value| value.eq_ignore_ascii_case("toml"))
    {
        return transform_toml(source, &input, namespace, store, transaction_id, undo);
    }
    let mut output = String::new();
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
        let transformed = if trimmed.starts_with('#') || trimmed.is_empty() {
            line.to_owned()
        } else if let Some((key, separator, raw)) = split_assignment(line) {
            let normalized_key = key.trim().trim_matches(['"', '\'']);
            let raw = raw.trim();
            let starts_yaml_container =
                separator == ':' && raw.is_empty() && secret_container_key(normalized_key);
            if starts_yaml_container {
                yaml_secret_indent = Some(indentation);
                line.to_owned()
            } else if secret_key(normalized_key)
                || secret_container_key(normalized_key)
                || yaml_secret_indent.is_some()
            {
                let value = unquote(raw);
                if value.is_empty() {
                    line.to_owned()
                } else {
                    let id = secret_identifier(namespace, &format!("/{index}/{normalized_key}"));
                    let reference =
                        route_secret(store, transaction_id, undo, &id, value.as_bytes())?;
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

/// Rewrites a TOML document structurally, routing every secret it finds.
///
/// Identifiers come from the same traversal that rewrites the values, so a
/// document's secret identities are a function of its structure alone. The
/// earlier design planned identifiers from a separate line scan and consumed
/// them in document order, which broke on anything the scan could not see: a
/// trailing comment after an inline table hid every entry in it, the two
/// sequences fell out of step, and later values were routed under identifiers
/// belonging to earlier keys or under one shared fallback that overwrote each
/// credential with the next.
fn transform_toml(
    source: &Path,
    input: &str,
    namespace: &str,
    store: &mut dyn SecretStore,
    transaction_id: Option<&str>,
    undo: &mut Vec<SecretUndo>,
) -> Result<Vec<u8>, MigrationError> {
    let mut document =
        input
            .parse::<DocumentMut>()
            .map_err(|error| MigrationError::InvalidInput {
                path: source.to_path_buf(),
                reason: format!("TOML configuration is malformed: {error}"),
            })?;
    let mut context = TomlRedaction {
        namespace,
        store,
        transaction_id,
        undo,
    };
    context.item(document.as_item_mut(), "", false)?;
    let output = document.to_string();
    output
        .parse::<DocumentMut>()
        .map_err(|error| MigrationError::InvalidInput {
            path: source.to_path_buf(),
            reason: format!("TOML configuration could not be serialized: {error}"),
        })?;
    Ok(output.into_bytes())
}

/// One structural TOML redaction pass.
struct TomlRedaction<'a> {
    namespace: &'a str,
    store: &'a mut dyn SecretStore,
    transaction_id: Option<&'a str>,
    undo: &'a mut Vec<SecretUndo>,
}

impl TomlRedaction<'_> {
    fn item(
        &mut self,
        item: &mut Item,
        path: &str,
        secret_container: bool,
    ) -> Result<(), MigrationError> {
        match item {
            Item::Table(table) => self.table_like(table, path, secret_container),
            Item::Value(TomlValue::InlineTable(table)) => {
                self.inline_table(table, path, secret_container)
            }
            Item::Value(TomlValue::Array(array)) => {
                for (index, value) in array.iter_mut().enumerate() {
                    self.value(value, &format!("{path}/{index}"), secret_container)?;
                }
                Ok(())
            }
            Item::Value(value) => self.value(value, path, secret_container),
            Item::ArrayOfTables(array) => {
                for (index, table) in array.iter_mut().enumerate() {
                    self.table_like(table, &format!("{path}/{index}"), secret_container)?;
                }
                Ok(())
            }
            Item::None => Ok(()),
        }
    }

    fn table_like(
        &mut self,
        table: &mut dyn TableLike,
        path: &str,
        secret_container: bool,
    ) -> Result<(), MigrationError> {
        let keys = table
            .iter()
            .map(|(key, _)| key.to_owned())
            .collect::<Vec<_>>();
        for key in keys {
            let child_path = format!("{path}/{key}");
            let child_container = secret_container_key(&key);
            let Some(child) = table.get_mut(&key) else {
                continue;
            };
            if let Item::Value(TomlValue::String(secret)) = child
                && (secret_container || secret_key(&key))
            {
                let reference = self.route(&child_path, secret.value())?;
                *child = Item::Value(TomlValue::from(reference));
                continue;
            }
            self.item(child, &child_path, secret_container || child_container)?;
        }
        Ok(())
    }

    /// Redacts an inline table, including keys that are themselves secret names.
    ///
    /// A direct secret key nested inside an inline table — `provider = { api_key
    /// = "..." }` — is exactly as sensitive as the same key spelled out in a
    /// standard table. Checking only whether the *parent* key was `env` or
    /// `headers` left those credentials in plaintext in the migrated file.
    fn inline_table(
        &mut self,
        table: &mut toml_edit::InlineTable,
        path: &str,
        secret_container: bool,
    ) -> Result<(), MigrationError> {
        let keys = table
            .iter()
            .map(|(key, _)| key.to_owned())
            .collect::<Vec<_>>();
        for key in keys {
            let child_path = format!("{path}/{key}");
            let child_container = secret_container_key(&key);
            let Some(value) = table.get_mut(&key) else {
                continue;
            };
            if let TomlValue::String(secret) = value
                && (secret_container || secret_key(&key))
            {
                let reference = self.route(&child_path, secret.value())?;
                *value = TomlValue::from(reference);
                continue;
            }
            self.value(value, &child_path, secret_container || child_container)?;
        }
        Ok(())
    }

    fn value(
        &mut self,
        value: &mut TomlValue,
        path: &str,
        secret_container: bool,
    ) -> Result<(), MigrationError> {
        match value {
            TomlValue::String(secret) if secret_container => {
                let reference = self.route(path, secret.value())?;
                *value = TomlValue::from(reference);
                Ok(())
            }
            TomlValue::InlineTable(table) => self.inline_table(table, path, secret_container),
            TomlValue::Array(array) => {
                for (index, child) in array.iter_mut().enumerate() {
                    self.value(child, &format!("{path}/{index}"), secret_container)?;
                }
                Ok(())
            }
            _ => Ok(()),
        }
    }

    fn route(&mut self, path: &str, secret: &str) -> Result<String, MigrationError> {
        let id = secret_identifier(self.namespace, path);
        route_secret(
            self.store,
            self.transaction_id,
            self.undo,
            &id,
            secret.as_bytes(),
        )
    }
}

fn import_environment(
    source: &Path,
    namespace: &str,
    store: &mut dyn SecretStore,
    transaction_id: Option<&str>,
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
            let reference = route_secret(store, transaction_id, undo, &id, value.as_bytes())?;
            references.insert(key.to_owned(), reference);
        }
    }
    serde_json::to_vec_pretty(&references).map_err(|error| {
        MigrationError::Signing(format!("environment reference serialization: {error}"))
    })
}

fn store_document(
    source: &Path,
    secret_id: &str,
    store: &mut dyn SecretStore,
    transaction_id: Option<&str>,
    undo: &mut Vec<SecretUndo>,
) -> Result<Vec<u8>, MigrationError> {
    let content = read_bytes(source)?;
    let reference = route_secret(store, transaction_id, undo, secret_id, &content)?;
    let mut object = Map::new();
    object.insert("secret_ref".to_owned(), Value::String(reference));
    serde_json::to_vec_pretty(&Value::Object(object))
        .map_err(|error| MigrationError::Signing(error.to_string()))
}

fn route_secret(
    store: &mut dyn SecretStore,
    transaction_id: Option<&str>,
    undo: &mut Vec<SecretUndo>,
    id: &str,
    value: &[u8],
) -> Result<String, MigrationError> {
    let Some(transaction_id) = transaction_id else {
        return Err(MigrationError::SecretStore(SecretStoreError::new(
            "secret migration requires a crash-safe transactional secret store",
        )));
    };
    if !undo.iter().any(|entry| entry.id == id) {
        let previous = store.get(id)?;
        undo.push(SecretUndo {
            id: id.to_owned(),
            previous,
        });
    }
    let reference = store.put_transactional(transaction_id, id, SecretValue::new(value))?;
    if !valid_secret_reference(&reference) {
        return Err(MigrationError::SecretStore(SecretStoreError::new(
            "secret store returned an invalid reference",
        )));
    }
    Ok(reference)
}

fn plan_uses_secrets(operations: &[MigrationOperation]) -> bool {
    operations.iter().any(|operation| {
        matches!(
            operation,
            MigrationOperation::TransformJson { .. }
                | MigrationOperation::TransformText { .. }
                | MigrationOperation::ImportEnvironment { .. }
                | MigrationOperation::StoreDocument { .. }
        )
    })
}

fn commit_secret_transaction(
    store: &mut dyn SecretStore,
    receipt: &ApplyReceipt,
) -> Result<(), MigrationError> {
    commit_secret_transaction_by_id(store, receipt.secret_transaction.as_deref())
}

fn commit_secret_transaction_by_id(
    store: &mut dyn SecretStore,
    transaction_id: Option<&str>,
) -> Result<(), MigrationError> {
    if let Some(transaction_id) = transaction_id {
        store.commit_transaction(transaction_id)?;
    }
    Ok(())
}

fn rollback_secret_transaction(
    store: &mut dyn SecretStore,
    transaction_id: Option<&str>,
) -> Result<(), MigrationError> {
    if let Some(transaction_id) = transaction_id {
        store.rollback_transaction(transaction_id)?;
    }
    Ok(())
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
    if path.is_file() {
        return reject_executable_file(path);
    }
    for entry in sorted_entries(path)? {
        let file_type = entry.file_type().map_err(|source| MigrationError::Io {
            action: "inspect source type",
            path: entry.path(),
            source,
        })?;
        if file_type.is_symlink() {
            return Err(MigrationError::Symlink(entry.path()));
        }
        if file_type.is_dir() {
            reject_executable_tree(&entry.path())?;
        } else if file_type.is_file() {
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
        hash_file(path, &mut hasher)?;
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
        let file_type = entry.file_type().map_err(|source| MigrationError::Io {
            action: "inspect source type",
            path: path.clone(),
            source,
        })?;
        if file_type.is_symlink() {
            return Err(MigrationError::Symlink(path));
        }
        let relative = path
            .strip_prefix(root)
            .map_err(|_| MigrationError::UnsafeTarget(path.clone()))?;
        hasher.update(path_to_slashes(relative).as_bytes());
        hasher.update([0]);
        if file_type.is_dir() {
            digest_directory(root, &path, hasher)?;
        } else if file_type.is_file() {
            hash_file(&path, hasher)?;
        }
        hasher.update([0xff]);
    }
    Ok(())
}

fn hash_file(path: &Path, hasher: &mut Sha256) -> Result<(), MigrationError> {
    let mut file = fs::File::open(path).map_err(|source| MigrationError::Io {
        action: "read",
        path: path.to_path_buf(),
        source,
    })?;
    let mut buffer = [0_u8; 16 * 1024];
    loop {
        let count = file
            .read(&mut buffer)
            .map_err(|source| MigrationError::Io {
                action: "read",
                path: path.to_path_buf(),
                source,
            })?;
        if count == 0 {
            break;
        }
        hasher.update(&buffer[..count]);
    }
    Ok(())
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
        Ok(metadata) if metadata.file_type().is_symlink() => {
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
        create_dir_all(target)?;
        for entry in sorted_entries(source)? {
            let entry_source = entry.path();
            let entry_target = target.join(entry.file_name());
            let file_type = entry.file_type().map_err(|source| MigrationError::Io {
                action: "inspect source type",
                path: entry_source.clone(),
                source,
            })?;
            if file_type.is_symlink() {
                return Err(MigrationError::Symlink(entry_source));
            }
            if file_type.is_dir() {
                copy_path(&entry_source, &entry_target)?;
            } else if file_type.is_file() {
                copy_file(&entry_source, &entry_target)?;
            }
        }
        Ok(())
    } else if source.is_file() {
        copy_file(source, target)
    } else {
        Err(MigrationError::SourceNotFound {
            provider: "migration",
            path: source.to_path_buf(),
        })
    }
}

fn copy_file(source: &Path, target: &Path) -> Result<(), MigrationError> {
    create_parent(target)?;
    fs::copy(source, target)
        .map(|_| ())
        .map_err(|source_error| MigrationError::Io {
            action: "copy",
            path: source.to_path_buf(),
            source: source_error,
        })?;
    sync_file(target)?;
    sync_parent_path(target)?;
    Ok(())
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

fn reject_symlink(path: &Path) -> Result<(), MigrationError> {
    let metadata = fs::symlink_metadata(path).map_err(|source| MigrationError::Io {
        action: "inspect",
        path: path.to_path_buf(),
        source,
    })?;
    if metadata.file_type().is_symlink() {
        Err(MigrationError::Symlink(path.to_path_buf()))
    } else {
        Ok(())
    }
}

fn remove_path_if_exists(path: &Path) -> Result<(), MigrationError> {
    let Ok(metadata) = fs::symlink_metadata(path) else {
        return Ok(());
    };
    if metadata.file_type().is_symlink() {
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
    })
}

fn read_bytes(path: &Path) -> Result<Vec<u8>, MigrationError> {
    fs::read(path).map_err(|source| MigrationError::Io {
        action: "read",
        path: path.to_path_buf(),
        source,
    })
}

fn read_text(path: &Path) -> Result<String, MigrationError> {
    fs::read_to_string(path).map_err(|source| MigrationError::Io {
        action: "read UTF-8 text",
        path: path.to_path_buf(),
        source,
    })
}

fn write_bytes(path: &Path, bytes: &[u8]) -> Result<(), MigrationError> {
    create_parent(path)?;
    fs::write(path, bytes).map_err(|source| MigrationError::Io {
        action: "write",
        path: path.to_path_buf(),
        source,
    })
}

fn write_durable_bytes(path: &Path, bytes: &[u8]) -> Result<(), MigrationError> {
    create_parent(path)?;
    let mut staged = StagedArtifact::reserve(path, "receipt")?;
    staged.write_bytes(bytes)?;
    staged.sync()?;
    staged.release_handle();
    // Receipts are internal bookkeeping under the backup root, not a migration
    // target another writer competes for, so publication is an unconditional
    // rename rather than a compare-and-swap.
    fs::rename(staged.path(), path).map_err(|source| MigrationError::Io {
        action: "publish durable file",
        path: path.to_path_buf(),
        source,
    })?;
    staged.into_published();
    sync_parent_path(path)
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

fn sync_path_tree(path: &Path) -> Result<(), MigrationError> {
    if path.is_dir() {
        for entry in sorted_entries(path)? {
            sync_path_tree(&entry.path())?;
        }
        sync_directory(path)?;
    } else if path.is_file() {
        sync_file(path)?;
    }
    Ok(())
}

fn sync_file(path: &Path) -> Result<(), MigrationError> {
    File::open(path)
        .and_then(|file| file.sync_all())
        .map_err(|source| MigrationError::Io {
            action: "sync file",
            path: path.to_path_buf(),
            source,
        })
}

/// Flushes a directory entry to stable storage.
///
/// The failure is reported rather than swallowed. A platform that cannot honour
/// the request has not made the rename durable, and returning success there
/// would let apply record a publication that a power loss could still undo.
fn sync_directory(path: &Path) -> Result<(), MigrationError> {
    atomicfs::sync_directory(path).map_err(|source| MigrationError::Io {
        action: "sync directory",
        path: path.to_path_buf(),
        source,
    })
}

fn sync_parent_path(path: &Path) -> Result<(), MigrationError> {
    let parent = path.parent().ok_or_else(|| MigrationError::Io {
        action: "sync parent directory",
        path: path.to_path_buf(),
        source: io::Error::new(io::ErrorKind::InvalidInput, "path has no parent"),
    })?;
    sync_directory(parent)
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

/// Test-only utilities for simulating process crashes deterministically.
/// Exposed without `cfg(test)` so integration tests in `tests/` can reach them.
#[doc(hidden)]
#[allow(unreachable_pub)]
pub mod test_publish_failpoint {
    use std::path::{Path, PathBuf};
    use std::sync::Mutex;

    // Registrations are keyed by `(checkpoint, target path)` and held in a list
    // rather than a single slot, so tests that run in parallel inside one binary
    // arm independent failpoints instead of overwriting each other's.
    static ACTIVE: Mutex<Vec<(&'static str, PathBuf)>> = Mutex::new(Vec::new());

    type BarrierAction = Box<dyn Fn(&Path) + Send + Sync>;

    static BARRIERS: Mutex<Vec<(&'static str, PathBuf, BarrierAction)>> = Mutex::new(Vec::new());

    /// Held during the test; clears its own failpoint on drop.
    pub struct Guard {
        checkpoint: &'static str,
        target_path: PathBuf,
    }

    /// Held during the test; clears its own barrier on drop.
    pub struct BarrierGuard {
        checkpoint: &'static str,
        target_path: PathBuf,
    }

    /// Arms a failpoint at `checkpoint` scoped to `target_path`.
    ///
    /// Only a `trigger` call for the same `(checkpoint, target_path)` pair will
    /// panic; concurrent tests operating on different paths are unaffected.
    pub fn set_for(checkpoint: &'static str, target_path: impl AsRef<Path>) -> Guard {
        let target_path = target_path.as_ref().to_path_buf();
        ACTIVE
            .lock()
            .expect("lock failpoint")
            .push((checkpoint, target_path.clone()));
        Guard {
            checkpoint,
            target_path,
        }
    }

    /// Arms a one-shot action that runs at `checkpoint` for `target_path`.
    ///
    /// `before_publish` runs after every pre-publication check and immediately
    /// before the atomic displacement, which is the window a compare-and-swap
    /// exists to close.
    pub fn set_barrier(
        checkpoint: &'static str,
        target_path: impl AsRef<Path>,
        action: impl Fn(&Path) + Send + Sync + 'static,
    ) -> BarrierGuard {
        let target_path = target_path.as_ref().to_path_buf();
        BARRIERS.lock().expect("lock failpoint barrier").push((
            checkpoint,
            target_path.clone(),
            Box::new(action),
        ));
        BarrierGuard {
            checkpoint,
            target_path,
        }
    }

    fn take(
        registrations: &mut Vec<(&'static str, PathBuf)>,
        checkpoint: &str,
        target: &Path,
    ) -> bool {
        registrations
            .iter()
            .position(|(armed, path)| *armed == checkpoint && path == target)
            .map(|index| registrations.swap_remove(index))
            .is_some()
    }

    pub(super) fn trigger(checkpoint: &str, target: &Path) {
        let armed = {
            let mut registrations = ACTIVE.lock().expect("lock failpoint");
            take(&mut registrations, checkpoint, target)
        };
        assert!(!armed, "injected crash at {checkpoint}");
    }

    pub(super) fn run_barrier(checkpoint: &str, target: &Path) {
        let action = {
            let mut registrations = BARRIERS.lock().expect("lock failpoint barrier");
            registrations
                .iter()
                .position(|(armed, path, _)| *armed == checkpoint && path == target)
                .map(|index| registrations.swap_remove(index))
        };
        if let Some((_, _, action)) = action {
            action(target);
        }
    }

    impl Drop for Guard {
        fn drop(&mut self) {
            let mut registrations = ACTIVE.lock().expect("lock failpoint");
            take(&mut registrations, self.checkpoint, &self.target_path);
        }
    }

    impl Drop for BarrierGuard {
        fn drop(&mut self) {
            let mut registrations = BARRIERS.lock().expect("lock failpoint barrier");
            if let Some(index) = registrations
                .iter()
                .position(|(armed, path, _)| *armed == self.checkpoint && *path == self.target_path)
            {
                drop(registrations.swap_remove(index));
            }
        }
    }
}

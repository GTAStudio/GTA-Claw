use std::collections::{BTreeMap, BTreeSet};
use std::error::Error;
use std::fmt::{self, Debug, Display, Formatter};
use std::fs;
use std::io;
use std::path::{Component, Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

use ed25519_dalek::{Signer, SigningKey};
use serde::Serialize;
use serde_json::{Map, Value};
use sha2::{Digest, Sha256};

use crate::contract::{
    Artifact, ArtifactKind, ArtifactSignature, ContractViolation, Diagnostic, DiagnosticSeverity,
    InputKind, MIGRATION_CONTRACT_VERSION, MigrationInput, MigrationResult, MigrationStatus,
};
use crate::platform::PlatformPaths;

static BACKUP_SEQUENCE: AtomicU64 = AtomicU64::new(0);

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
}

impl Debug for ApplyReceipt {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ApplyReceipt")
            .field("provider_id", &self.provider_id)
            .field("backup_dir", &self.backup_dir)
            .field("backup_count", &self.backups.len())
            .field("secret_count", &self.secrets.len())
            .finish()
    }
}

struct BackupEntry {
    target: PathBuf,
    backup: Option<PathBuf>,
    digest: Option<String>,
    applied: Option<AppliedState>,
}

enum AppliedState {
    Absent,
    Digest(String),
    Unknown,
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
    let backup_dir = create_backup_dir(context.backup_root, plan.provider_id)?;
    let backups = backup_targets(&backup_dir, &plan.operations)?;
    verify_targets_unchanged(&backups)?;
    let mut receipt = ApplyReceipt {
        provider_id: plan.provider_id,
        backup_dir,
        backups,
        secrets: Vec::new(),
    };
    write_backup_manifest(&receipt)?;
    let apply_result = apply_operations(context, &plan.operations, &mut receipt)
        .and_then(|()| verify_source_digests(plan));
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

fn apply_operations(
    context: &mut ApplyContext<'_>,
    operations: &[MigrationOperation],
    receipt: &mut ApplyReceipt,
) -> Result<(), MigrationError> {
    for operation in operations {
        let result = match operation {
            MigrationOperation::CopyPath { source, target } => {
                replace_target_if_needed(target, context.overwrite)?;
                copy_path(source, target)
            }
            MigrationOperation::AppendFile {
                source,
                target,
                heading,
            } => append_file(source, target, heading),
            MigrationOperation::GeneratedCommandSkill {
                source,
                target,
                name,
            } => {
                replace_target_if_needed(target, context.overwrite)?;
                generate_command_skill(source, target, name)
            }
            MigrationOperation::TransformJson {
                source,
                target,
                namespace,
            } => {
                replace_target_if_needed(target, context.overwrite)?;
                transform_json(
                    source,
                    target,
                    namespace,
                    context.secret_store,
                    &mut receipt.secrets,
                )
            }
            MigrationOperation::TransformText {
                source,
                target,
                namespace,
            } => {
                replace_target_if_needed(target, context.overwrite)?;
                transform_text(
                    source,
                    target,
                    namespace,
                    context.secret_store,
                    &mut receipt.secrets,
                )
            }
            MigrationOperation::ImportEnvironment {
                source,
                target,
                namespace,
            } => {
                replace_target_if_needed(target, context.overwrite)?;
                import_environment(
                    source,
                    target,
                    namespace,
                    context.secret_store,
                    &mut receipt.secrets,
                )
            }
            MigrationOperation::StoreDocument {
                source,
                target,
                secret_id,
            } => {
                replace_target_if_needed(target, context.overwrite)?;
                store_document(
                    source,
                    target,
                    secret_id,
                    context.secret_store,
                    &mut receipt.secrets,
                )
            }
            MigrationOperation::WriteBytes { target, bytes } => {
                replace_target_if_needed(target, context.overwrite)?;
                write_bytes(target, bytes)
            }
        };
        record_applied_state(receipt, operation.target());
        result?;
    }
    Ok(())
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
    }
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
        Ok(())
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
                applied: None,
            });
        } else {
            entries.push(BackupEntry {
                target: target.to_path_buf(),
                backup: None,
                digest: None,
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
            sha256: entry.digest.clone(),
        })
        .collect::<Vec<_>>();
    let bytes = serde_json::to_vec_pretty(&entries).map_err(|error| {
        MigrationError::Signing(format!("backup manifest serialization: {error}"))
    })?;
    write_bytes(&receipt.backup_dir.join("manifest.json"), &bytes)
}

fn restore_backup(entry: &BackupEntry) -> Result<(), MigrationError> {
    if let Some(backup) = &entry.backup {
        let expected = entry.digest.as_deref().unwrap_or_default();
        if digest_path(backup)? != expected {
            return Err(MigrationError::BackupVerification(backup.clone()));
        }
        create_parent(&entry.target)?;
        let sequence = BACKUP_SEQUENCE.fetch_add(1, Ordering::Relaxed);
        let file_name = entry
            .target
            .file_name()
            .and_then(|value| value.to_str())
            .unwrap_or("target");
        let temporary = entry
            .target
            .with_file_name(format!(".{file_name}.rollback-{sequence}"));
        remove_path_if_exists(&temporary)?;
        copy_path(backup, &temporary)?;
        if digest_path(&temporary)? != expected {
            return Err(MigrationError::BackupVerification(temporary));
        }
        remove_path_if_exists(&entry.target)?;
        fs::rename(&temporary, &entry.target).map_err(|source| MigrationError::Io {
            action: "restore backup",
            path: entry.target.clone(),
            source,
        })?;
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

fn replace_target_if_needed(target: &Path, overwrite: bool) -> Result<(), MigrationError> {
    if path_is_occupied(target) {
        if !overwrite {
            return Err(MigrationError::Conflict(target.to_path_buf()));
        }
        remove_path_if_exists(target)?;
    }
    Ok(())
}

fn append_file(source: &Path, target: &Path, heading: &str) -> Result<(), MigrationError> {
    reject_symlink(source)?;
    let content = read_bytes(source)?;
    create_parent(target)?;
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
    write_bytes(target, &existing)
}

fn generate_command_skill(source: &Path, target: &Path, name: &str) -> Result<(), MigrationError> {
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
    create_dir_all(target)?;
    write_bytes(&target.join("SKILL.md"), generated.as_bytes())
}

fn transform_json(
    source: &Path,
    target: &Path,
    namespace: &str,
    store: &mut dyn SecretStore,
    undo: &mut Vec<SecretUndo>,
) -> Result<(), MigrationError> {
    let text = read_text(source)?;
    let mut value: Value =
        serde_json::from_str(&text).map_err(|_| MigrationError::InvalidInput {
            path: source.to_path_buf(),
            reason: "JSON configuration is malformed".to_owned(),
        })?;
    redact_json_value(&mut value, namespace, "", false, store, undo)?;
    let bytes = serde_json::to_vec_pretty(&value).map_err(|_| MigrationError::InvalidInput {
        path: source.to_path_buf(),
        reason: "JSON configuration could not be serialized".to_owned(),
    })?;
    write_bytes(target, &bytes)
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

fn transform_text(
    source: &Path,
    target: &Path,
    namespace: &str,
    store: &mut dyn SecretStore,
    undo: &mut Vec<SecretUndo>,
) -> Result<(), MigrationError> {
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
            let raw = raw.trim();
            let starts_yaml_container =
                separator == ':' && raw.is_empty() && secret_container_key(normalized_key);
            if starts_yaml_container {
                yaml_secret_indent = Some(indentation);
                line.to_owned()
            } else if secret_key(normalized_key)
                || secret_container_key(normalized_key)
                || toml_secret_section
                || yaml_secret_indent.is_some()
            {
                let value = unquote(raw);
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
    write_bytes(target, output.as_bytes())
}

fn import_environment(
    source: &Path,
    target: &Path,
    namespace: &str,
    store: &mut dyn SecretStore,
    undo: &mut Vec<SecretUndo>,
) -> Result<(), MigrationError> {
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
    let bytes = serde_json::to_vec_pretty(&references).map_err(|error| {
        MigrationError::Signing(format!("environment reference serialization: {error}"))
    })?;
    write_bytes(target, &bytes)
}

fn store_document(
    source: &Path,
    target: &Path,
    secret_id: &str,
    store: &mut dyn SecretStore,
    undo: &mut Vec<SecretUndo>,
) -> Result<(), MigrationError> {
    let content = read_bytes(source)?;
    let reference = route_secret(store, undo, secret_id, &content)?;
    let mut object = Map::new();
    object.insert("secret_ref".to_owned(), Value::String(reference));
    let bytes = serde_json::to_vec_pretty(&Value::Object(object))
        .map_err(|error| MigrationError::Signing(error.to_string()))?;
    write_bytes(target, &bytes)
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
        return Ok(digest_bytes(&read_bytes(path)?));
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
            hasher.update(read_bytes(&path)?);
        }
        hasher.update([0xff]);
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

fn path_to_slashes(path: &Path) -> String {
    path.components()
        .filter_map(|component| match component {
            Component::Normal(value) => Some(value.to_string_lossy().into_owned()),
            _ => None,
        })
        .collect::<Vec<_>>()
        .join("/")
}

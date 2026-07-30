use std::error::Error;
use std::ffi::{OsStr, OsString};
use std::fmt::{self, Display, Formatter};
use std::fs;
use std::io::{self, Read, Write};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};

use crate::atomicfs::{self, ObjectIdentity};
use crate::io::{
    PublicationLock, WriteOutcome, atomic_write_bytes, prepare_destination,
};
use crate::{CONFIG_SCHEMA_VERSION, ConfigError, parse_json5, to_json5};

static ARTIFACT_SEQUENCE: AtomicU64 = AtomicU64::new(0);
const RECOVERY_SCHEMA_VERSION: u32 = 2;
const MAX_RECOVERY_STEPS: usize = 32;

/// One completed destructive migration and its exact pre-migration bytes.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ConfigMigrationRecord {
    /// Migrated configuration path.
    pub config_path: PathBuf,
    /// File-synchronized backup containing the original bytes.
    pub backup_path: PathBuf,
    /// Original schema version.
    pub from_version: u32,
    /// Resulting schema version.
    pub to_version: u32,
}

/// Outcome of checking and migrating a configuration file.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ConfigMigrationOutcome {
    /// The file already used the current schema.
    Current,
    /// The file was migrated after an exact file-synchronized backup was created.
    Migrated(ConfigMigrationRecord),
}

/// Failure during backup-first schema migration or rollback.
#[derive(Debug)]
pub enum ConfigMigrationError {
    /// Typed configuration failure.
    Config(ConfigError),
    /// The source document did not contain an integer schema version.
    MissingVersion,
    /// No ordered migration path exists.
    UnsupportedPath {
        /// Version found in the document.
        found: u32,
        /// Current implementation version.
        current: u32,
    },
    /// The source changed at publication and the foreign bytes were preserved.
    ConcurrentEdit {
        /// Canonical configuration path left at the newest observed bytes.
        path: PathBuf,
        /// File-synchronized exact copy of the conflicting bytes.
        conflict_backup_path: PathBuf,
        /// SHA-256 digest reviewed before migration.
        expected_sha256: String,
        /// SHA-256 digest of `conflict_backup_path`.
        actual_sha256: String,
    },
    /// Backup or synchronized staging failed before publication.
    Backup {
        /// Artifact path involved.
        path: PathBuf,
        /// Operating-system failure.
        source: io::Error,
    },
    /// Migration publication failed and restoring the backup also failed.
    Restore {
        /// Publication failure.
        migration: ConfigError,
        /// Backup restoration failure.
        restore: io::Error,
        /// Exact original bytes retained for manual recovery.
        backup_path: PathBuf,
    },
    /// A synchronized recovery journal could not be decoded, replayed, or retired.
    Recovery {
        /// Recovery journal or artifact involved.
        path: PathBuf,
        /// Secret-free recovery diagnostic.
        message: String,
    },
}

impl Display for ConfigMigrationError {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        match self {
            Self::Config(error) => write!(formatter, "{error}"),
            Self::MissingVersion => formatter.write_str("schema_version: missing integer version"),
            Self::UnsupportedPath { found, current } => write!(
                formatter,
                "schema_version: no migration path from {found} to {current}"
            ),
            Self::ConcurrentEdit {
                path,
                conflict_backup_path,
                expected_sha256,
                actual_sha256,
            } => write!(
                formatter,
                "{} changed during schema migration (expected {expected_sha256}, found \
                 {actual_sha256}); exact conflicting bytes were preserved at {}",
                path.display(),
                conflict_backup_path.display()
            ),
            Self::Backup { path, source } => write!(
                formatter,
                "{}: could not create synchronized migration artifact: {source}",
                path.display()
            ),
            Self::Restore {
                migration,
                restore,
                backup_path,
            } => write!(
                formatter,
                "migration failed: {migration}; restoring the exact backup also failed: \
                 {restore}; backup remains at {}",
                backup_path.display()
            ),
            Self::Recovery { path, message } => {
                write!(
                    formatter,
                    "{}: migration recovery failed: {message}",
                    path.display()
                )
            }
        }
    }
}

impl Error for ConfigMigrationError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Config(error) => Some(error),
            Self::Backup { source, .. } => Some(source),
            Self::Restore { migration, .. } => Some(migration),
            Self::MissingVersion
            | Self::UnsupportedPath { .. }
            | Self::ConcurrentEdit { .. }
            | Self::Recovery { .. } => None,
        }
    }
}

impl From<ConfigError> for ConfigMigrationError {
    fn from(error: ConfigError) -> Self {
        Self::Config(error)
    }
}

/// Reads only the integer `schema_version` from a JSON5 configuration document.
///
/// Unknown fields and future domain shapes are ignored. This is a read-only
/// compatibility probe, not typed configuration validation, and it never
/// creates the publication lock or another sidecar.
///
/// # Errors
///
/// Returns [`ConfigMigrationError::Config`] for file I/O or JSON5 syntax
/// failures and [`ConfigMigrationError::MissingVersion`] when the top level has
/// no non-negative `u32` `schema_version`.
pub fn read_config_schema_version(
    path: impl AsRef<Path>,
) -> Result<u32, ConfigMigrationError> {
    read_version_probe(path.as_ref()).map(|probe| probe.version)
}

/// Migrates a version-zero envelope to the current schema after exact backup.
///
/// Current and unsupported versions are read-only fast paths when no recovery
/// journal exists. The fast path rechecks the handle-pinned generation and
/// canonical journal path after its probe before returning. A destructive
/// migration re-reads the document while holding the same stable sidecar lock
/// used by [`crate::write_file`] and [`crate::write_bytes_atomically`].
///
/// The candidate, original backup, and recovery journal are file-synchronized
/// before an atomic displacement closes the check/replace window. Unix also
/// synchronizes their parent entries; Windows retains its documented lack of a
/// supported directory flush. The exact object
/// displaced at publication is validated by digest and stable filesystem
/// identity, so a same-byte replacement object is still a concurrent edit.
/// Foreign bytes are backed up and restored unless an even newer live edit has
/// arrived; recovery never replaces that newer edit.
///
/// # Errors
///
/// Returns [`ConfigMigrationError::MissingVersion`] for a non-integer or absent
/// `schema_version`, [`ConfigMigrationError::UnsupportedPath`] for versions
/// other than zero and [`CONFIG_SCHEMA_VERSION`],
/// [`ConfigMigrationError::ConcurrentEdit`] when a non-cooperating writer wins
/// the publication race, and [`ConfigMigrationError::Recovery`] when recovery
/// cannot prove a safe filesystem topology.
pub fn migrate_config_file(
    path: impl AsRef<Path>,
) -> Result<ConfigMigrationOutcome, ConfigMigrationError> {
    migrate_config_file_with_hooks(path.as_ref(), |_| Ok(()), |_| Ok(()))
}

fn migrate_config_file_with_hooks(
    path: &Path,
    before_displacement: impl FnMut(&Path) -> io::Result<()>,
    after_displacement: impl FnMut(&Path) -> io::Result<()>,
) -> Result<ConfigMigrationOutcome, ConfigMigrationError> {
    migrate_config_file_with_probe_hook(
        path,
        |_| Ok(()),
        before_displacement,
        after_displacement,
    )
}

fn migrate_config_file_with_probe_hook(
    path: &Path,
    mut after_initial_probe: impl FnMut(&Path) -> io::Result<()>,
    mut before_displacement: impl FnMut(&Path) -> io::Result<()>,
    mut after_displacement: impl FnMut(&Path) -> io::Result<()>,
) -> Result<ConfigMigrationOutcome, ConfigMigrationError> {
    let canonical_path =
        prepare_destination(path).map_err(|source| ConfigError::io(path, source))?;
    let recovery_pending = recovery_exists(&canonical_path)?;
    if !recovery_pending {
        let probe = read_version_probe_no_follow(&canonical_path)?;
        after_initial_probe(&canonical_path)
            .map_err(|source| ConfigError::io(&canonical_path, source))?;
        let journal_absent_before_generation = !recovery_exists(&canonical_path)?;
        let generation_unchanged = probe.matches_generation(&canonical_path)?;
        let journal_absent_after_generation = !recovery_exists(&canonical_path)?;
        let stable = journal_absent_before_generation
            && generation_unchanged
            && journal_absent_after_generation;
        if stable {
            if probe.version == CONFIG_SCHEMA_VERSION {
                probe.validate_current(&canonical_path)?;
                return Ok(ConfigMigrationOutcome::Current);
            }
            reject_unsupported(probe.version)?;
        }
    }

    let lock = PublicationLock::acquire(&canonical_path)?;
    let canonical_path = lock.destination().to_owned();
    if let Some(journal) = read_recovery_journal(&canonical_path)? {
        let mut no_hooks = MigrationHooks::none();
        return recover_journal(&lock, journal, &mut no_hooks);
    }

    let mut probe = read_version_probe_no_follow(&canonical_path)?;
    if probe.version == CONFIG_SCHEMA_VERSION {
        probe.validate_current(&canonical_path)?;
        return Ok(ConfigMigrationOutcome::Current);
    }
    reject_unsupported(probe.version)?;

    let VersionProbe {
        source,
        mut document,
        version,
        identity,
        mode: source_mode,
        source_file: source_handle,
    } = probe;
    let source_sha256 = digest_bytes(&source);
    let source_identity = identity.ok_or_else(|| {
        recovery(
            &canonical_path,
            "locked source read did not capture a filesystem identity",
        )
    })?;
    let source_file = source_handle.as_ref().ok_or_else(|| {
        recovery(
            &canonical_path,
            "locked source read did not retain its filesystem handle",
        )
    })?;
    let object = document
        .as_object_mut()
        .ok_or(ConfigMigrationError::MissingVersion)?;
    object.insert(
        "schema_version".to_owned(),
        Value::from(CONFIG_SCHEMA_VERSION),
    );
    let candidate_source = json5::to_string(&document)
        .map_err(|error| ConfigError::Serialize(error.to_string()))?;
    let candidate = parse_json5(&candidate_source, &canonical_path.display().to_string())?;
    let candidate_bytes = to_json5(&candidate)?.into_bytes();
    let target_sha256 = digest_bytes(&candidate_bytes);
    let backup_path = create_artifact(
        &canonical_path,
        "schema-v0",
        &source,
        ArtifactSecurity::PrivateLike(source_file),
    )?
    .path;
    let candidate = create_artifact(
        &canonical_path,
        "schema-candidate",
        &candidate_bytes,
        ArtifactSecurity::PublishedLike(source_file),
    )?;
    let candidate_path = candidate.path;
    let displaced_path = displacement_path(&canonical_path, &candidate_path)?;
    let candidate_identity = candidate.identity;
    drop(source_handle);
    let journal = MigrationRecoveryJournal {
        schema_version: RECOVERY_SCHEMA_VERSION,
        config_path: canonical_path,
        backup_path,
        candidate_path,
        displaced_path,
        from_version: version,
        to_version: CONFIG_SCHEMA_VERSION,
        source_sha256,
        target_sha256,
        source_identity,
        candidate_identity,
        source_mode,
        state: RecoveryState::Prepared,
    };
    persist_recovery_journal(&journal)?;

    let mut hooks = MigrationHooks {
        before_displacement: Some(&mut before_displacement),
        after_displacement: Some(&mut after_displacement),
    };
    recover_journal(&lock, journal, &mut hooks)
}

/// Restores exact pre-migration bytes from a migration record.
///
/// Rollback uses the same stable destination lock as every other cooperating
/// configuration publication API.
///
/// # Errors
///
/// Returns [`ConfigMigrationError::Config`] when the backup cannot be read or
/// atomic publication fails, and [`ConfigMigrationError::Recovery`] when the
/// publication completed with a durability warning.
pub fn rollback_config_migration(
    record: &ConfigMigrationRecord,
) -> Result<(), ConfigMigrationError> {
    let lock = PublicationLock::acquire(&record.config_path)?;
    let bytes = read_file_no_follow(&record.backup_path)
        .map_err(|source| ConfigError::io(&record.backup_path, source))?;
    let outcome = lock.write_bytes(&bytes)?;
    require_durable(&outcome, lock.destination())?;
    Ok(())
}

struct VersionProbe {
    source: Vec<u8>,
    document: Value,
    version: u32,
    identity: Option<ObjectIdentity>,
    mode: Option<u32>,
    source_file: Option<fs::File>,
}

impl VersionProbe {
    fn validate_current(&self, path: &Path) -> Result<(), ConfigMigrationError> {
        let text = std::str::from_utf8(&self.source).map_err(|error| ConfigError::Syntax {
            source_name: path.display().to_string(),
            message: error.to_string(),
        })?;
        parse_json5(text, &path.display().to_string())?;
        Ok(())
    }

    fn matches_generation(&self, path: &Path) -> Result<bool, ConfigMigrationError> {
        let Some(identity) = self.identity else {
            return Ok(false);
        };
        let current =
            read_file_state(path).map_err(|source| ConfigError::io(path, source))?;
        Ok(current.matches(&digest_bytes(&self.source), identity, self.mode))
    }
}

fn read_version_probe(path: &Path) -> Result<VersionProbe, ConfigMigrationError> {
    let source = fs::read(path).map_err(|error| ConfigError::io(path, error))?;
    parse_version_probe(path, source, None, None, None)
}

fn read_version_probe_no_follow(path: &Path) -> Result<VersionProbe, ConfigMigrationError> {
    let snapshot = read_file_snapshot(path).map_err(|error| ConfigError::io(path, error))?;
    let FileSnapshot { bytes, state, file } = snapshot;
    parse_version_probe(
        path,
        bytes,
        Some(state.identity),
        state.mode,
        Some(file),
    )
}

fn parse_version_probe(
    path: &Path,
    source: Vec<u8>,
    identity: Option<ObjectIdentity>,
    mode: Option<u32>,
    source_file: Option<fs::File>,
) -> Result<VersionProbe, ConfigMigrationError> {
    let text = std::str::from_utf8(&source).map_err(|error| ConfigError::Syntax {
        source_name: path.display().to_string(),
        message: error.to_string(),
    })?;
    let document = json5::from_str::<Value>(text).map_err(|error| ConfigError::Syntax {
        source_name: path.display().to_string(),
        message: error.to_string(),
    })?;
    let version = document
        .get("schema_version")
        .and_then(Value::as_u64)
        .and_then(|version| u32::try_from(version).ok())
        .ok_or(ConfigMigrationError::MissingVersion)?;
    Ok(VersionProbe {
        source,
        document,
        version,
        identity,
        mode,
        source_file,
    })
}

fn reject_unsupported(version: u32) -> Result<(), ConfigMigrationError> {
    if version == 0 && CONFIG_SCHEMA_VERSION == 1 {
        Ok(())
    } else {
        Err(ConfigMigrationError::UnsupportedPath {
            found: version,
            current: CONFIG_SCHEMA_VERSION,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
struct MigrationRecoveryJournal {
    schema_version: u32,
    config_path: PathBuf,
    backup_path: PathBuf,
    candidate_path: PathBuf,
    displaced_path: PathBuf,
    from_version: u32,
    to_version: u32,
    source_sha256: String,
    target_sha256: String,
    source_identity: ObjectIdentity,
    candidate_identity: ObjectIdentity,
    source_mode: Option<u32>,
    state: RecoveryState,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(tag = "phase", rename_all = "snake_case")]
enum RecoveryState {
    Prepared,
    Restoring {
        state: Box<ConflictRestorationState>,
    },
}

#[derive(Clone, Debug, Deserialize, Serialize)]
struct ConflictRestorationState {
    original_conflict_sha256: String,
    original_conflict_identity: ObjectIdentity,
    original_conflict_mode: Option<u32>,
    original_conflict_backup_path: PathBuf,
    desired_sha256: String,
    desired_identity: ObjectIdentity,
    desired_mode: Option<u32>,
    desired_backup_path: PathBuf,
    expected_live_sha256: String,
    expected_live_identity: ObjectIdentity,
    expected_live_mode: Option<u32>,
    restore_path: PathBuf,
    output_path: PathBuf,
}

struct MigrationHooks<'a> {
    before_displacement: Option<&'a mut dyn FnMut(&Path) -> io::Result<()>>,
    after_displacement: Option<&'a mut dyn FnMut(&Path) -> io::Result<()>>,
}

impl MigrationHooks<'_> {
    const fn none() -> Self {
        Self {
            before_displacement: None,
            after_displacement: None,
        }
    }

    fn run_before(&mut self, path: &Path) -> io::Result<()> {
        self.before_displacement
            .take()
            .map_or(Ok(()), |hook| hook(path))
    }

    fn run_after(&mut self, path: &Path) -> io::Result<()> {
        self.after_displacement
            .take()
            .map_or(Ok(()), |hook| hook(path))
    }
}

fn recover_journal(
    lock: &PublicationLock,
    mut journal: MigrationRecoveryJournal,
    hooks: &mut MigrationHooks<'_>,
) -> Result<ConfigMigrationOutcome, ConfigMigrationError> {
    validate_recovery_journal(lock.destination(), &journal)?;
    require_digest(
        &journal.backup_path,
        &journal.source_sha256,
        "original backup",
    )?;
    match journal.state.clone() {
        RecoveryState::Prepared => drive_prepared(lock, &mut journal, hooks),
        RecoveryState::Restoring { .. } => drive_restoring(lock, &mut journal),
    }
}

#[allow(
    clippy::cognitive_complexity,
    reason = "prepared-journal replay explicitly classifies every safe crash topology"
)]
fn drive_prepared(
    lock: &PublicationLock,
    journal: &mut MigrationRecoveryJournal,
    hooks: &mut MigrationHooks<'_>,
) -> Result<ConfigMigrationOutcome, ConfigMigrationError> {
    for _ in 0..MAX_RECOVERY_STEPS {
        lock.validate()
            .map_err(|source| recovery_io(lock.destination(), &source))?;
        let live = optional_file_state(lock.destination())?;
        let candidate = optional_file_state(&journal.candidate_path)?;
        let displaced = if journal.displaced_path == journal.candidate_path {
            candidate.clone()
        } else {
            optional_file_state(&journal.displaced_path)?
        };
        let Some(live) = live else {
            return recover_absent_prepared(lock, journal, candidate, displaced);
        };

        let ready_to_displace = live.matches(
            &journal.source_sha256,
            journal.source_identity,
            journal.source_mode,
        ) && candidate.as_ref().is_some_and(|candidate| {
            candidate.matches(
                &journal.target_sha256,
                journal.candidate_identity,
                journal.source_mode,
            )
        }) && (journal.displaced_path == journal.candidate_path || displaced.is_none());
        if ready_to_displace {
            hooks
                .run_before(lock.destination())
                .map_err(|source| recovery_io(lock.destination(), &source))?;
            lock.validate()
                .map_err(|source| recovery_io(lock.destination(), &source))?;
            atomicfs::displace_file(
                &journal.candidate_path,
                lock.destination(),
                &journal.displaced_path,
            )
            .map_err(|source| {
                recovery(
                    lock.destination(),
                    format!(
                        "atomic displacement failed with the recovery journal retained: {source}"
                    ),
                )
            })?;
            hooks
                .run_after(lock.destination())
                .map_err(|source| recovery_io(lock.destination(), &source))?;
            sync_parent(lock.destination())
                .map_err(|source| recovery_io(lock.destination(), &source))?;
            continue;
        }

        if live.matches(
            &journal.target_sha256,
            journal.candidate_identity,
            journal.source_mode,
        ) {
            if displaced.as_ref().is_some_and(|displaced| {
                displaced.matches(
                    &journal.source_sha256,
                    journal.source_identity,
                    journal.source_mode,
                )
            }) {
                return complete_migration(journal);
            }
            if let Some(displaced) = displaced {
                return begin_conflict_restoration(lock, journal, displaced);
            }
            return preserve_live_conflict(lock.destination(), journal);
        }

        if !live.matches(
            &journal.source_sha256,
            journal.source_identity,
            journal.source_mode,
        ) {
            return preserve_live_conflict(lock.destination(), journal);
        }

        return Err(recovery(
            recovery_path(lock.destination()),
            "prepared journal artifacts do not match a safe pre- or post-displacement topology",
        ));
    }
    Err(recovery(
        recovery_path(lock.destination()),
        "migration recovery exceeded its bounded displacement attempts",
    ))
}

fn recover_absent_prepared(
    lock: &PublicationLock,
    journal: &MigrationRecoveryJournal,
    candidate: Option<FileState>,
    displaced: Option<FileState>,
) -> Result<ConfigMigrationOutcome, ConfigMigrationError> {
    let candidate_is_target = candidate.as_ref().is_some_and(|state| {
        state.matches(
            &journal.target_sha256,
            journal.candidate_identity,
            journal.source_mode,
        )
    });
    let displaced_is_source = displaced.as_ref().is_some_and(|state| {
        state.matches(
            &journal.source_sha256,
            journal.source_identity,
            journal.source_mode,
        )
    });
    let candidate_is_source = candidate.as_ref().is_some_and(|state| {
        state.matches(
            &journal.source_sha256,
            journal.source_identity,
            journal.source_mode,
        )
    });
    let source_path = if displaced_is_source {
        &journal.displaced_path
    } else if candidate_is_source {
        &journal.candidate_path
    } else {
        return Err(recovery(
            recovery_path(lock.destination()),
            "live destination is absent and no journal artifact is the original generation",
        ));
    };
    if journal.displaced_path != journal.candidate_path && !candidate_is_target {
        return Err(recovery(
            recovery_path(lock.destination()),
            "live destination is absent but the candidate generation cannot be proven",
        ));
    }

    match atomicfs::rename_no_replace(source_path, lock.destination()) {
        Ok(()) => {
            sync_parent(lock.destination())
                .map_err(|source| recovery_io(lock.destination(), &source))?;
            let retired = retire_recovery_journal(lock.destination())?;
            Err(recovery(
                retired,
                "an interrupted displacement left no live destination; the exact original \
                 generation was restored with no-replace and the active journal was retired; \
                 retry migration",
            ))
        }
        Err(source) if is_already_exists(&source) => {
            preserve_live_conflict(lock.destination(), journal)
        }
        Err(source) => Err(recovery(
            source_path,
            format!(
                "could not restore the absent destination with an atomic no-replace move: {source}"
            ),
        )),
    }
}

fn begin_conflict_restoration(
    lock: &PublicationLock,
    journal: &mut MigrationRecoveryJournal,
    observed: FileState,
) -> Result<ConfigMigrationOutcome, ConfigMigrationError> {
    let restore_path = journal.displaced_path.clone();
    let (desired_backup_path, desired) =
        backup_path_bytes(lock.destination(), "schema-conflict", &restore_path)?;
    if desired != observed {
        return Err(recovery(
            &restore_path,
            "displaced generation changed while its conflict backup was created",
        ));
    }
    let output_path = if journal.displaced_path == journal.candidate_path {
        restore_path.clone()
    } else {
        journal.candidate_path.clone()
    };
    journal.state = RecoveryState::Restoring {
        state: Box::new(ConflictRestorationState {
            original_conflict_sha256: desired.sha256.clone(),
            original_conflict_identity: desired.identity,
            original_conflict_mode: desired.mode,
            original_conflict_backup_path: desired_backup_path.clone(),
            desired_sha256: desired.sha256,
            desired_identity: desired.identity,
            desired_mode: desired.mode,
            desired_backup_path,
            expected_live_sha256: journal.target_sha256.clone(),
            expected_live_identity: journal.candidate_identity,
            expected_live_mode: journal.source_mode,
            restore_path,
            output_path,
        }),
    };
    persist_recovery_journal(journal)?;
    drive_restoring(lock, journal)
}

#[cfg(windows)]
fn restore_generation_preserving_security(
    replacement: &Path,
    destination: &Path,
    output: &Path,
) -> io::Result<()> {
    atomicfs::rename_no_replace(destination, output)?;
    atomicfs::rename_no_replace(replacement, destination).map_err(|error| {
        io::Error::new(
            error.kind(),
            format!(
                "{error}; destination security was quarantined at {} and replacement security \
                 remains at {}",
                output.display(),
                replacement.display()
            ),
        )
    })
}

#[cfg(not(windows))]
fn restore_generation_preserving_security(
    replacement: &Path,
    destination: &Path,
    output: &Path,
) -> io::Result<()> {
    atomicfs::displace_file(replacement, destination, output)
}

#[allow(
    clippy::cognitive_complexity,
    reason = "restoration replay must distinguish every live/restore/output generation topology"
)]
fn drive_restoring(
    lock: &PublicationLock,
    journal: &mut MigrationRecoveryJournal,
) -> Result<ConfigMigrationOutcome, ConfigMigrationError> {
    for _ in 0..MAX_RECOVERY_STEPS {
        let RecoveryState::Restoring { state } = journal.state.clone() else {
            return Err(recovery(
                recovery_path(lock.destination()),
                "conflict restoration lost its journal state",
            ));
        };
        let ConflictRestorationState {
            original_conflict_sha256,
            original_conflict_identity,
            original_conflict_mode,
            original_conflict_backup_path,
            desired_sha256,
            desired_identity,
            desired_mode,
            desired_backup_path,
            expected_live_sha256,
            expected_live_identity,
            expected_live_mode,
            restore_path,
            output_path,
        } = *state;
        require_digest(
            &original_conflict_backup_path,
            &original_conflict_sha256,
            "original conflict backup",
        )?;
        require_digest(
            &desired_backup_path,
            &desired_sha256,
            "current restoration backup",
        )?;

        let live = optional_file_state(lock.destination())?;
        let restore = optional_file_state(&restore_path)?;
        let same_artifact = restore_path == output_path;
        let output = if same_artifact {
            restore.clone()
        } else {
            optional_file_state(&output_path)?
        };
        let Some(live) = live else {
            let can_restore_absent = !same_artifact
                && restore.as_ref().is_some_and(|restore| {
                    restore.matches(&desired_sha256, desired_identity, desired_mode)
                })
                && output.as_ref().is_some_and(|output| {
                    output.matches(
                        &expected_live_sha256,
                        expected_live_identity,
                        expected_live_mode,
                    )
                });
            if !can_restore_absent {
                return Err(recovery(
                    recovery_path(lock.destination()),
                    "conflict restoration found an absent live path without a provable \
                     replacement/output topology",
                ));
            }
            atomicfs::rename_no_replace(&restore_path, lock.destination()).map_err(|source| {
                recovery(
                    &restore_path,
                    format!(
                        "could not restore the absent live path with an atomic no-replace move: \
                         {source}"
                    ),
                )
            })?;
            sync_parent(lock.destination())
                .map_err(|source| recovery_io(lock.destination(), &source))?;
            continue;
        };

        let before_exchange = live.matches(
            &expected_live_sha256,
            expected_live_identity,
            expected_live_mode,
        ) && restore.as_ref().is_some_and(|restore| {
            restore.matches(&desired_sha256, desired_identity, desired_mode)
        }) && (same_artifact || output.is_none());
        if before_exchange {
            lock.validate()
                .map_err(|source| recovery_io(lock.destination(), &source))?;
            restore_generation_preserving_security(
                &restore_path,
                lock.destination(),
                &output_path,
            )
            .map_err(|source| {
                recovery(
                    lock.destination(),
                    format!(
                        "conflict restoration failed with all evidence retained: {source}"
                    ),
                )
            })?;
            sync_parent(lock.destination())
                .map_err(|source| recovery_io(lock.destination(), &source))?;
            continue;
        }

        let restoration_complete =
            live.matches(&desired_sha256, desired_identity, desired_mode)
                && output.as_ref().is_some_and(|output| {
                    output.matches(
                        &expected_live_sha256,
                        expected_live_identity,
                        expected_live_mode,
                    )
                })
                && (same_artifact || restore.is_none());
        if restoration_complete {
            retire_recovery_journal(lock.destination())?;
            return Err(conflict_error(
                lock.destination(),
                journal,
                &original_conflict_backup_path,
                &original_conflict_sha256,
            ));
        }

        if live.matches(&desired_sha256, desired_identity, desired_mode)
            && let Some(next) = output
            && !next.matches(
                &expected_live_sha256,
                expected_live_identity,
                expected_live_mode,
            )
            && !next.matches(&desired_sha256, desired_identity, desired_mode)
        {
            let (next_backup_path, backed_up_next) =
                backup_path_bytes(lock.destination(), "schema-conflict-newer", &output_path)?;
            if backed_up_next != next {
                return Err(recovery(
                    &output_path,
                    "newer displaced generation changed while its backup was created",
                ));
            }
            let next_restore_path = output_path;
            let next_output_path = restore_path;
            journal.state = RecoveryState::Restoring {
                state: Box::new(ConflictRestorationState {
                    original_conflict_sha256,
                    original_conflict_identity,
                    original_conflict_mode,
                    original_conflict_backup_path,
                    desired_sha256: next.sha256,
                    desired_identity: next.identity,
                    desired_mode: next.mode,
                    desired_backup_path: next_backup_path,
                    expected_live_sha256: desired_sha256,
                    expected_live_identity: desired_identity,
                    expected_live_mode: desired_mode,
                    restore_path: next_restore_path,
                    output_path: next_output_path,
                }),
            };
            persist_recovery_journal(journal)?;
            continue;
        }

        if !live.matches(
            &expected_live_sha256,
            expected_live_identity,
            expected_live_mode,
        ) && !live.matches(&desired_sha256, desired_identity, desired_mode)
        {
            let (newest_backup, newest) = backup_path_bytes(
                lock.destination(),
                "schema-conflict-newest",
                lock.destination(),
            )?;
            if newest != live {
                return Err(recovery(
                    lock.destination(),
                    "newest live generation changed while its backup was created",
                ));
            }
            retire_recovery_journal(lock.destination())?;
            return Err(ConfigMigrationError::ConcurrentEdit {
                path: lock.destination().to_owned(),
                conflict_backup_path: newest_backup,
                expected_sha256: journal.source_sha256.clone(),
                actual_sha256: newest.sha256,
            });
        }

        return Err(recovery(
            recovery_path(lock.destination()),
            "conflict restoration artifacts do not match a safe atomic topology",
        ));
    }
    Err(recovery(
        recovery_path(lock.destination()),
        "conflict restoration exceeded its bounded displacement attempts",
    ))
}

fn preserve_live_conflict(
    path: &Path,
    journal: &MigrationRecoveryJournal,
) -> Result<ConfigMigrationOutcome, ConfigMigrationError> {
    let snapshot = read_file_snapshot(path).map_err(|source| recovery_io(path, &source))?;
    let conflict_backup_path = create_artifact(
        path,
        "schema-conflict",
        &snapshot.bytes,
        ArtifactSecurity::PrivateLike(&snapshot.file),
    )?
    .path;
    retire_recovery_journal(path)?;
    Err(ConfigMigrationError::ConcurrentEdit {
        path: path.to_owned(),
        conflict_backup_path,
        expected_sha256: journal.source_sha256.clone(),
        actual_sha256: snapshot.state.sha256,
    })
}

fn conflict_error(
    path: &Path,
    journal: &MigrationRecoveryJournal,
    conflict_backup_path: &Path,
    actual_sha256: &str,
) -> ConfigMigrationError {
    ConfigMigrationError::ConcurrentEdit {
        path: path.to_owned(),
        conflict_backup_path: conflict_backup_path.to_owned(),
        expected_sha256: journal.source_sha256.clone(),
        actual_sha256: actual_sha256.to_owned(),
    }
}

fn complete_migration(
    journal: &MigrationRecoveryJournal,
) -> Result<ConfigMigrationOutcome, ConfigMigrationError> {
    let live = read_file_state(&journal.config_path)
        .map_err(|source| recovery_io(&journal.config_path, &source))?;
    if !live.matches(
        &journal.target_sha256,
        journal.candidate_identity,
        journal.source_mode,
    ) {
        return preserve_live_conflict(&journal.config_path, journal);
    }
    cleanup_known_artifact(
        &journal.candidate_path,
        &journal.source_sha256,
        journal.source_identity,
    )?;
    if journal.displaced_path != journal.candidate_path {
        cleanup_known_artifact(
            &journal.displaced_path,
            &journal.source_sha256,
            journal.source_identity,
        )?;
    }
    remove_recovery_journal(&journal.config_path)?;
    Ok(ConfigMigrationOutcome::Migrated(journal.record()))
}

impl MigrationRecoveryJournal {
    fn record(&self) -> ConfigMigrationRecord {
        ConfigMigrationRecord {
            config_path: self.config_path.clone(),
            backup_path: self.backup_path.clone(),
            from_version: self.from_version,
            to_version: self.to_version,
        }
    }
}

fn recovery_exists(path: &Path) -> Result<bool, ConfigMigrationError> {
    let journal_path = recovery_path(path);
    match fs::symlink_metadata(&journal_path) {
        Ok(_) => Ok(true),
        Err(source) if source.kind() == io::ErrorKind::NotFound => Ok(false),
        Err(source) => Err(recovery_io(&journal_path, &source)),
    }
}

fn read_recovery_journal(
    path: &Path,
) -> Result<Option<MigrationRecoveryJournal>, ConfigMigrationError> {
    let journal_path = recovery_path(path);
    let bytes = match read_file_no_follow(&journal_path) {
        Ok(bytes) => bytes,
        Err(source) if source.kind() == io::ErrorKind::NotFound => return Ok(None),
        Err(source) => return Err(recovery_io(&journal_path, &source)),
    };
    let journal = serde_json::from_slice(&bytes)
        .map_err(|error| recovery(&journal_path, error.to_string()))?;
    validate_recovery_journal(path, &journal)?;
    Ok(Some(journal))
}

fn validate_recovery_journal(
    path: &Path,
    journal: &MigrationRecoveryJournal,
) -> Result<(), ConfigMigrationError> {
    let journal_path = recovery_path(path);
    if journal.schema_version != RECOVERY_SCHEMA_VERSION {
        return Err(recovery(
            journal_path,
            format!(
                "unsupported recovery schema {}; supported schema is {}",
                journal.schema_version, RECOVERY_SCHEMA_VERSION
            ),
        ));
    }
    if journal.config_path != path {
        return Err(recovery(
            journal_path,
            "journal config path does not match the locked destination",
        ));
    }
    for artifact in [
        &journal.backup_path,
        &journal.candidate_path,
        &journal.displaced_path,
    ] {
        validate_artifact_path(path, artifact)?;
    }
    for digest in [&journal.source_sha256, &journal.target_sha256] {
        validate_digest(&journal_path, digest)?;
    }
    validate_mode(&journal_path, journal.source_mode)?;
    if let RecoveryState::Restoring { state } = &journal.state {
        let ConflictRestorationState {
            original_conflict_sha256,
            original_conflict_identity: _,
            original_conflict_mode,
            original_conflict_backup_path,
            desired_sha256,
            desired_identity: _,
            desired_mode,
            desired_backup_path,
            expected_live_sha256,
            expected_live_identity: _,
            expected_live_mode,
            restore_path,
            output_path,
        } = state.as_ref();
        for artifact in [
            original_conflict_backup_path,
            desired_backup_path,
            restore_path,
            output_path,
        ] {
            validate_artifact_path(path, artifact)?;
        }
        for digest in [
            original_conflict_sha256,
            desired_sha256,
            expected_live_sha256,
        ] {
            validate_digest(&journal_path, digest)?;
        }
        for mode in [
            original_conflict_mode,
            desired_mode,
            expected_live_mode,
        ] {
            validate_mode(&journal_path, *mode)?;
        }
    }
    Ok(())
}

fn validate_artifact_path(path: &Path, artifact: &Path) -> Result<(), ConfigMigrationError> {
    if artifact == path
        || artifact == recovery_path(path)
        || artifact.parent() != path.parent()
        || !artifact_name_belongs_to(path, artifact)
    {
        return Err(recovery(
            recovery_path(path),
            "journal artifact path does not belong to the locked configuration",
        ));
    }
    Ok(())
}

fn artifact_name_belongs_to(path: &Path, artifact: &Path) -> bool {
    let Some(config_name) = path.file_name() else {
        return false;
    };
    artifact.file_name().is_some_and(|name| {
        name.to_string_lossy()
            .starts_with(config_name.to_string_lossy().as_ref())
    })
}

fn validate_digest(path: &Path, digest: &str) -> Result<(), ConfigMigrationError> {
    if digest.len() == 64
        && digest
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        Ok(())
    } else {
        Err(recovery(path, "journal contains an invalid SHA-256 digest"))
    }
}

fn validate_mode(path: &Path, mode: Option<u32>) -> Result<(), ConfigMigrationError> {
    if mode.is_none_or(|mode| mode <= 0o777) {
        Ok(())
    } else {
        Err(recovery(path, "journal contains an invalid Unix permission mode"))
    }
}

fn persist_recovery_journal(
    journal: &MigrationRecoveryJournal,
) -> Result<(), ConfigMigrationError> {
    let journal_path = recovery_path(&journal.config_path);
    let bytes = serde_json::to_vec_pretty(journal)
        .map_err(|error| recovery(&journal_path, error.to_string()))?;
    let outcome = atomic_write_bytes(&journal_path, &bytes, || Ok(()))
        .map_err(|source| recovery_io(&journal_path, &source))?;
    require_durable(&outcome, &journal_path)
}

fn retire_recovery_journal(path: &Path) -> Result<PathBuf, ConfigMigrationError> {
    let journal_path = recovery_path(path);
    for _ in 0..128 {
        let sequence = ARTIFACT_SEQUENCE.fetch_add(1, Ordering::Relaxed);
        let retired = path.with_file_name(sibling_name(
            "",
            path.file_name().unwrap_or_else(|| OsStr::new("config")),
            &format!(
                ".schema-migration.conflict.{}.{sequence}.json",
                std::process::id()
            ),
        ));
        match atomicfs::rename_no_replace(&journal_path, &retired) {
            Ok(()) => {
                sync_parent(&retired).map_err(|source| recovery_io(&retired, &source))?;
                return Ok(retired);
            }
            Err(source) if is_already_exists(&source) => {}
            Err(source) => return Err(recovery_io(&journal_path, &source)),
        }
    }
    Err(recovery(
        journal_path,
        "could not allocate a unique retired recovery journal",
    ))
}

fn remove_recovery_journal(path: &Path) -> Result<(), ConfigMigrationError> {
    let journal_path = recovery_path(path);
    match fs::remove_file(&journal_path) {
        Ok(()) => {}
        Err(source) if source.kind() == io::ErrorKind::NotFound => {}
        Err(source) => return Err(recovery_io(&journal_path, &source)),
    }
    sync_parent(&journal_path).map_err(|source| recovery_io(&journal_path, &source))
}

fn cleanup_known_artifact(
    path: &Path,
    expected_sha256: &str,
    expected_identity: ObjectIdentity,
) -> Result<(), ConfigMigrationError> {
    let Some(actual) = optional_file_state(path)? else {
        return Ok(());
    };
    if actual.sha256 != expected_sha256 || actual.identity != expected_identity {
        return Err(recovery(
            path,
            "refusing to remove a recovery artifact from another generation",
        ));
    }
    match fs::remove_file(path) {
        Ok(()) => Ok(()),
        Err(source) => {
            protect_retained_artifact(path).map_err(|dacl_error| {
                recovery(
                    path,
                    format!(
                        "{source}; additionally failed to protect the retained recovery artifact: \
                         {dacl_error}"
                    ),
                )
            })?;
            Err(recovery_io(path, &source))
        }
    }
}

#[cfg(windows)]
fn protect_retained_artifact(path: &Path) -> io::Result<()> {
    atomicfs::protect_restrictive_dacl(path)
}

#[cfg(not(windows))]
#[expect(
    clippy::unnecessary_wraps,
    reason = "the signature mirrors the fallible Windows ACL protection"
)]
const fn protect_retained_artifact(_path: &Path) -> io::Result<()> {
    Ok(())
}

fn backup_path_bytes(
    config_path: &Path,
    label: &str,
    source_path: &Path,
) -> Result<(PathBuf, FileState), ConfigMigrationError> {
    let snapshot =
        read_file_snapshot(source_path).map_err(|source| recovery_io(source_path, &source))?;
    let backup = create_artifact(
        config_path,
        label,
        &snapshot.bytes,
        ArtifactSecurity::PrivateLike(&snapshot.file),
    )?
    .path;
    Ok((backup, snapshot.state))
}

fn create_artifact(
    path: &Path,
    label: &str,
    bytes: &[u8],
    security: ArtifactSecurity<'_>,
) -> Result<CreatedArtifact, ConfigMigrationError> {
    for _ in 0..128 {
        let artifact = unique_artifact_path(path, label);
        match atomicfs::create_new_no_follow(&artifact) {
            Ok(mut file) => {
                let identity = atomicfs::identity_of_handle(&file).map_err(|source| {
                    ConfigMigrationError::Backup {
                        path: artifact.clone(),
                        source,
                    }
                })?;
                set_artifact_permissions(&file, security).map_err(|source| {
                    ConfigMigrationError::Backup {
                        path: artifact.clone(),
                        source,
                    }
                })?;
                file.write_all(bytes)
                    .and_then(|()| file.flush())
                    .and_then(|()| file.sync_all())
                    .map_err(|source| ConfigMigrationError::Backup {
                        path: artifact.clone(),
                        source,
                    })?;
                drop(file);
                if atomicfs::identity_of_path(&artifact)
                    .map_err(|source| ConfigMigrationError::Backup {
                        path: artifact.clone(),
                        source,
                    })?
                    != identity
                {
                    return Err(ConfigMigrationError::Backup {
                        path: artifact,
                        source: io::Error::new(
                            io::ErrorKind::Interrupted,
                            "migration artifact identity changed while it was written",
                        ),
                    });
                }
                sync_parent(&artifact).map_err(|source| ConfigMigrationError::Backup {
                    path: artifact.clone(),
                    source,
                })?;
                return Ok(CreatedArtifact {
                    path: artifact,
                    identity,
                });
            }
            Err(source) if source.kind() == io::ErrorKind::AlreadyExists => {}
            Err(source) => {
                return Err(ConfigMigrationError::Backup {
                    path: artifact,
                    source,
                });
            }
        }
    }
    Err(ConfigMigrationError::Backup {
        path: path.to_owned(),
        source: io::Error::new(
            io::ErrorKind::AlreadyExists,
            "could not allocate a unique migration artifact",
        ),
    })
}

struct CreatedArtifact {
    path: PathBuf,
    identity: ObjectIdentity,
}

#[derive(Clone, Copy)]
enum ArtifactSecurity<'a> {
    PrivateLike(&'a fs::File),
    PublishedLike(&'a fs::File),
}

fn unique_artifact_path(path: &Path, label: &str) -> PathBuf {
    let sequence = ARTIFACT_SEQUENCE.fetch_add(1, Ordering::Relaxed);
    path.with_file_name(sibling_name(
        "",
        path.file_name().unwrap_or_else(|| OsStr::new("config")),
        &format!(".{label}.{}.{sequence}.bak", std::process::id()),
    ))
}

#[cfg(windows)]
fn displacement_path(path: &Path, _candidate_path: &Path) -> Result<PathBuf, ConfigMigrationError> {
    for _ in 0..128 {
        let artifact = unique_artifact_path(path, "schema-displaced");
        match fs::symlink_metadata(&artifact) {
            Err(source) if source.kind() == io::ErrorKind::NotFound => return Ok(artifact),
            Ok(_) => {}
            Err(source) => return Err(recovery_io(&artifact, &source)),
        }
    }
    Err(recovery(
        path,
        "could not allocate an absent Windows displacement path",
    ))
}

#[cfg(not(windows))]
#[expect(
    clippy::unnecessary_wraps,
    reason = "the signature mirrors the fallible Windows path allocation"
)]
fn displacement_path(
    _path: &Path,
    candidate_path: &Path,
) -> Result<PathBuf, ConfigMigrationError> {
    Ok(candidate_path.to_owned())
}

#[cfg(unix)]
fn set_artifact_permissions(
    file: &fs::File,
    security: ArtifactSecurity<'_>,
) -> io::Result<()> {
    use std::os::unix::fs::PermissionsExt;

    let mode = match security {
        ArtifactSecurity::PrivateLike(source) => {
            let _ = source;
            0o600
        }
        ArtifactSecurity::PublishedLike(source) => {
            source.metadata()?.permissions().mode() & 0o777
        }
    };
    file.set_permissions(fs::Permissions::from_mode(mode))
}

#[cfg(windows)]
fn set_artifact_permissions(
    file: &fs::File,
    security: ArtifactSecurity<'_>,
) -> io::Result<()> {
    let source = match security {
        ArtifactSecurity::PrivateLike(source) | ArtifactSecurity::PublishedLike(source) => source,
    };
    atomicfs::copy_restrictive_dacl(source, file)
}

#[cfg(not(any(unix, windows)))]
#[expect(
    clippy::missing_const_for_fn,
    clippy::unnecessary_wraps,
    reason = "the signature mirrors the fallible Unix permission propagation"
)]
fn set_artifact_permissions(
    _file: &fs::File,
    _security: ArtifactSecurity<'_>,
) -> io::Result<()> {
    Ok(())
}

fn require_digest(
    path: &Path,
    expected_sha256: &str,
    label: &str,
) -> Result<(), ConfigMigrationError> {
    let actual = read_file_state(path).map_err(|source| recovery_io(path, &source))?;
    if actual.sha256 == expected_sha256 {
        Ok(())
    } else {
        Err(recovery(
            path,
            format!("{label} digest does not match the recovery journal"),
        ))
    }
}

fn require_durable(
    outcome: &WriteOutcome,
    path: &Path,
) -> Result<(), ConfigMigrationError> {
    if outcome.warnings.is_empty() {
        Ok(())
    } else {
        Err(recovery(
            path,
            format!(
                "atomic publication reported durability warning(s): {:?}",
                outcome.warnings
            ),
        ))
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct FileState {
    sha256: String,
    identity: ObjectIdentity,
    mode: Option<u32>,
}

impl FileState {
    fn matches(
        &self,
        sha256: &str,
        identity: ObjectIdentity,
        mode: Option<u32>,
    ) -> bool {
        self.sha256 == sha256 && self.identity == identity && self.mode == mode
    }
}

struct FileSnapshot {
    bytes: Vec<u8>,
    state: FileState,
    file: fs::File,
}

fn read_file_snapshot(path: &Path) -> io::Result<FileSnapshot> {
    let mut file = atomicfs::open_no_follow(path)?;
    let metadata = file.metadata()?;
    if !metadata.is_file() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "recovery artifact is not a regular file",
        ));
    }
    let identity = atomicfs::identity_of_handle(&file)?;
    let mut bytes = Vec::new();
    file.read_to_end(&mut bytes)?;
    if atomicfs::identity_of_path(path)? != identity {
        return Err(io::Error::new(
            io::ErrorKind::Interrupted,
            "filesystem object changed while it was being read",
        ));
    }
    Ok(FileSnapshot {
        state: FileState {
            sha256: digest_bytes(&bytes),
            identity,
            mode: permission_mode(&metadata),
        },
        bytes,
        file,
    })
}

fn read_file_no_follow(path: &Path) -> io::Result<Vec<u8>> {
    read_file_snapshot(path).map(|snapshot| snapshot.bytes)
}

fn read_file_state(path: &Path) -> io::Result<FileState> {
    read_file_snapshot(path).map(|snapshot| snapshot.state)
}

fn optional_file_state(path: &Path) -> Result<Option<FileState>, ConfigMigrationError> {
    match read_file_state(path) {
        Ok(state) => Ok(Some(state)),
        Err(source) if source.kind() == io::ErrorKind::NotFound => Ok(None),
        Err(source) => Err(recovery_io(path, &source)),
    }
}

fn is_already_exists(error: &io::Error) -> bool {
    error.kind() == io::ErrorKind::AlreadyExists
        || matches!(error.raw_os_error(), Some(80 | 183))
}

#[cfg(unix)]
#[expect(
    clippy::unnecessary_wraps,
    reason = "the optional representation is serialized uniformly across Unix and Windows"
)]
fn permission_mode(metadata: &fs::Metadata) -> Option<u32> {
    use std::os::unix::fs::PermissionsExt;

    Some(metadata.permissions().mode() & 0o777)
}

#[cfg(not(unix))]
const fn permission_mode(_metadata: &fs::Metadata) -> Option<u32> {
    None
}

fn digest_bytes(bytes: &[u8]) -> String {
    encode_hex(&Sha256::digest(bytes))
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

fn recovery_path(path: &Path) -> PathBuf {
    path.with_file_name(sibling_name(
        ".",
        path.file_name().unwrap_or_else(|| OsStr::new("config")),
        ".schema-migration.recovery.json",
    ))
}

fn sibling_name(prefix: &str, file_name: &OsStr, suffix: &str) -> OsString {
    let mut name = OsString::from(prefix);
    name.push(file_name);
    name.push(suffix);
    name
}

#[cfg(unix)]
fn sync_parent(path: &Path) -> io::Result<()> {
    atomicfs::sync_directory(
        path.parent()
            .expect("prepared configuration paths always have a parent"),
    )
}

#[cfg(not(unix))]
#[expect(
    clippy::missing_const_for_fn,
    clippy::unnecessary_wraps,
    reason = "Windows deliberately has no supported directory flush"
)]
fn sync_parent(_path: &Path) -> io::Result<()> {
    // Windows offers no supported directory flush. Recovery files themselves
    // are write-through and synchronized; directory-entry power-loss durability
    // remains the documented platform limitation.
    Ok(())
}

fn recovery_io(path: &Path, source: &io::Error) -> ConfigMigrationError {
    recovery(path, source.to_string())
}

fn recovery(path: impl Into<PathBuf>, message: impl Into<String>) -> ConfigMigrationError {
    ConfigMigrationError::Recovery {
        path: path.into(),
        message: message.into(),
    }
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::io;
    use std::path::{Path, PathBuf};
    use std::sync::atomic::{AtomicU64, Ordering};

    use serde_json::Value;

    use super::{
        ConfigMigrationError, ConfigMigrationOutcome, migrate_config_file,
        migrate_config_file_with_hooks, migrate_config_file_with_probe_hook,
        persist_recovery_journal, read_config_schema_version, read_recovery_journal, recovery_path,
    };
    use crate::{atomicfs, io::publication_lock_path};

    static NEXT_DIRECTORY: AtomicU64 = AtomicU64::new(0);

    const VERSION_ZERO: &str = r#"
{
  schema_version: 0,
  core: {
    auth: { github: { pat: "env:GITHUB_TOKEN", device: { enabled: false } } },
    role: { source_url: "https://roles.example.test/default.json" },
    channels: { teams: { enabled: false } },
    server: {},
    logging: {},
    sessions: {},
    copilot: {},
    legacy: {},
    updates: {},
    admin: {},
    network: {},
  },
}
"#;

    #[test]
    fn tolerant_version_probe_ignores_future_document_shape_without_sidecars() {
        let directory = TestDirectory::create("version-probe");
        let path = directory.path().join("config.json5");
        fs::write(
            &path,
            "{ schema_version: 99, future_domain: { arbitrary: [1, 2, 3] } }",
        )
        .expect("write future document");

        assert_eq!(
            read_config_schema_version(&path).expect("read only schema version"),
            99
        );
        assert!(!publication_lock_path(&path).exists());
        assert!(!recovery_path(&path).exists());
    }

    #[test]
    fn current_fast_path_rechecks_a_journal_created_after_probe() {
        let directory = TestDirectory::create("current-journal-barrier");
        let path = directory.path().join("config.json5");
        let current = VERSION_ZERO.replace("schema_version: 0", "schema_version: 1");
        fs::write(&path, current).expect("write current config");

        let error = migrate_config_file_with_probe_hook(
            &path,
            |destination| fs::write(recovery_path(destination), b"{}"),
            |_| Ok(()),
            |_| Ok(()),
        )
        .expect_err("mid-read journal must prevent a fast-path Current result");

        assert!(matches!(error, ConfigMigrationError::Recovery { .. }));
        assert!(recovery_path(&path).exists());
    }

    #[test]
    fn current_fast_path_rechecks_generation_after_probe() {
        let directory = TestDirectory::create("current-generation-barrier");
        let path = directory.path().join("config.json5");
        let current = VERSION_ZERO.replace("schema_version: 0", "schema_version: 1");
        fs::write(&path, current).expect("write current config");

        let outcome = migrate_config_file_with_probe_hook(
            &path,
            |destination| fs::write(destination, VERSION_ZERO),
            |_| Ok(()),
            |_| Ok(()),
        )
        .expect("changed generation must be re-read under lock");

        assert!(matches!(outcome, ConfigMigrationOutcome::Migrated(_)));
    }

    #[test]
    fn writer_immediately_before_cas_is_restored_and_retry_is_clean() {
        let directory = TestDirectory::create("before-cas");
        let path = directory.path().join("config.json5");
        fs::write(&path, VERSION_ZERO).expect("write original");
        let concurrent = version_zero_with_role("before-cas");

        let error = migrate_config_file_with_hooks(
            &path,
            |destination| publish_external(destination, concurrent.as_bytes()),
            |_| Ok(()),
        )
        .expect_err("the displaced writer must win");

        let backup = concurrent_backup(error);
        assert_eq!(fs::read(&path).expect("read live bytes"), concurrent.as_bytes());
        assert_eq!(
            fs::read(&backup).expect("read conflict backup"),
            concurrent.as_bytes()
        );
        assert!(
            !recovery_path(&path).exists(),
            "a retired conflict must not poison the next migration"
        );

        let retry = migrate_config_file(&path).expect("retry the concurrent source");
        let ConfigMigrationOutcome::Migrated(record) = retry else {
            panic!("version-zero concurrent bytes must migrate on retry");
        };
        assert_eq!(
            fs::read(record.backup_path).expect("read retry backup"),
            concurrent.as_bytes()
        );
    }

    #[test]
    fn same_bytes_new_object_before_cas_is_not_mistaken_for_the_source_generation() {
        let directory = TestDirectory::create("same-bytes-before-cas");
        let path = directory.path().join("config.json5");
        fs::write(&path, VERSION_ZERO).expect("write original");
        let source_identity = atomicfs::identity_of_path(&path).expect("source identity");
        let mut raced_identity = None;

        let error = migrate_config_file_with_hooks(
            &path,
            |destination| {
                publish_external(destination, VERSION_ZERO.as_bytes())?;
                raced_identity =
                    Some(atomicfs::identity_of_path(destination)?);
                Ok(())
            },
            |_| Ok(()),
        )
        .expect_err("same bytes from a new object must conflict");

        let backup = concurrent_backup(error);
        let raced_identity = raced_identity.expect("record raced identity");
        assert_ne!(source_identity, raced_identity);
        assert_eq!(
            atomicfs::identity_of_path(&path).expect("live identity"),
            raced_identity,
            "the exact racing generation must be restored live"
        );
        assert_eq!(
            fs::read(backup).expect("read conflict backup"),
            VERSION_ZERO.as_bytes()
        );
    }

    #[test]
    fn writer_immediately_after_cas_stays_live_and_is_backed_up() {
        let directory = TestDirectory::create("after-cas");
        let path = directory.path().join("config.json5");
        fs::write(&path, VERSION_ZERO).expect("write original");
        let concurrent = version_zero_with_role("after-cas");

        let error = migrate_config_file_with_hooks(
            &path,
            |_| Ok(()),
            |destination| publish_external(destination, concurrent.as_bytes()),
        )
        .expect_err("the post-CAS writer must be reported");

        let backup = concurrent_backup(error);
        assert_eq!(fs::read(&path).expect("read live bytes"), concurrent.as_bytes());
        assert_eq!(
            fs::read(backup).expect("read conflict backup"),
            concurrent.as_bytes()
        );
        assert!(!recovery_path(&path).exists());
    }

    #[test]
    fn same_bytes_new_object_after_cas_is_preserved_as_the_newer_live_generation() {
        let directory = TestDirectory::create("same-bytes-after-cas");
        let path = directory.path().join("config.json5");
        fs::write(&path, VERSION_ZERO).expect("write original");
        let mut raced_identity = None;

        let error = migrate_config_file_with_hooks(
            &path,
            |_| Ok(()),
            |destination| {
                let exact_target = fs::read(destination)?;
                let published_identity = atomicfs::identity_of_path(destination)?;
                publish_external(destination, &exact_target)?;
                let replacement_identity = atomicfs::identity_of_path(destination)?;
                assert_ne!(published_identity, replacement_identity);
                raced_identity = Some(replacement_identity);
                Ok(())
            },
        )
        .expect_err("same target bytes from a new object must conflict");

        let backup = concurrent_backup(error);
        assert_eq!(
            atomicfs::identity_of_path(&path).expect("live identity"),
            raced_identity.expect("record raced identity")
        );
        assert_eq!(
            fs::read(&backup).expect("read conflict backup"),
            fs::read(&path).expect("read live target")
        );
    }

    #[test]
    fn migration_re_reads_the_source_after_acquiring_the_lock() {
        let directory = TestDirectory::create("reread-under-lock");
        let path = directory.path().join("config.json5");
        fs::write(&path, VERSION_ZERO).expect("write original");
        let replacement = version_zero_with_role("arrived-before-lock");

        let outcome = migrate_config_file_with_probe_hook(
            &path,
            |_| {
                fs::write(&path, replacement.as_bytes())
            },
            |_| Ok(()),
            |_| Ok(()),
        )
        .expect("migrate the bytes re-read under lock");

        let ConfigMigrationOutcome::Migrated(record) = outcome else {
            panic!("the replacement remains version zero and must migrate");
        };
        assert_eq!(
            fs::read(record.backup_path).expect("read exact backup"),
            replacement.as_bytes()
        );
    }

    #[test]
    fn restart_completes_a_crash_immediately_after_atomic_displacement() {
        let directory = TestDirectory::create("restart-after-cas");
        let path = directory.path().join("config.json5");
        fs::write(&path, VERSION_ZERO).expect("write original");

        migrate_config_file_with_hooks(
            &path,
            |_| Ok(()),
            |_| Err(io::Error::other("injected crash after displacement")),
        )
        .expect_err("failpoint must retain the prepared journal");
        assert!(recovery_path(&path).is_file());
        let migrated: Value =
            json5::from_str(&fs::read_to_string(&path).expect("read displaced target"))
                .expect("parse target");
        assert_eq!(migrated["schema_version"], 1);

        let outcome = migrate_config_file(&path).expect("restart completes migration");
        assert!(matches!(outcome, ConfigMigrationOutcome::Migrated(_)));
        assert!(!recovery_path(&path).exists());
    }

    #[test]
    fn absent_live_path_restores_original_and_retires_prepared_journal() {
        let directory = TestDirectory::create("absent-prepared");
        let path = directory.path().join("config.json5");
        fs::write(&path, VERSION_ZERO).expect("write original");
        migrate_config_file_with_hooks(
            &path,
            |_| Err(io::Error::other("injected crash before displacement")),
            |_| Ok(()),
        )
        .expect_err("leave prepared journal");
        let mut journal = read_recovery_journal(&path)
            .expect("read journal")
            .expect("active journal");
        let displaced = path.with_file_name("config.json5.schema-displaced-test.bak");
        atomicfs::rename_no_replace(&path, &displaced).expect("move original out of live path");
        journal.displaced_path = displaced;
        persist_recovery_journal(&journal).expect("persist absent-live topology");

        let error = migrate_config_file(&path)
            .expect_err("recovery reports the restored interrupted publication");

        assert!(matches!(error, ConfigMigrationError::Recovery { .. }));
        assert_eq!(
            fs::read(&path).expect("read restored live bytes"),
            VERSION_ZERO.as_bytes()
        );
        assert!(
            !recovery_path(&path).exists(),
            "active journal must be retired"
        );
        assert!(matches!(
            migrate_config_file(&path).expect("retry after retirement"),
            ConfigMigrationOutcome::Migrated(_)
        ));
    }

    #[test]
    fn restart_restores_bytes_displaced_from_a_racing_writer() {
        let directory = TestDirectory::create("restart-displaced-writer");
        let path = directory.path().join("config.json5");
        fs::write(&path, VERSION_ZERO).expect("write original");
        let concurrent = version_zero_with_role("displaced-before-crash");

        migrate_config_file_with_hooks(
            &path,
            |destination| publish_external(destination, concurrent.as_bytes()),
            |_| Err(io::Error::other("injected crash before displaced validation")),
        )
        .expect_err("leave the concurrent object in the displacement artifact");

        let error =
            migrate_config_file(&path).expect_err("restart must restore and report the writer");
        let backup = concurrent_backup(error);
        assert_eq!(fs::read(&path).expect("read live bytes"), concurrent.as_bytes());
        assert_eq!(
            fs::read(backup).expect("read exact conflict backup"),
            concurrent.as_bytes()
        );
        assert!(!recovery_path(&path).exists());
    }

    #[test]
    fn restart_never_replaces_a_newer_live_edit() {
        let directory = TestDirectory::create("restart-newer-live");
        let path = directory.path().join("config.json5");
        fs::write(&path, VERSION_ZERO).expect("write original");
        migrate_config_file_with_hooks(
            &path,
            |_| Ok(()),
            |_| Err(io::Error::other("injected crash after displacement")),
        )
        .expect_err("leave a post-displacement journal");
        let newer = version_zero_with_role("newer-after-crash");
        publish_external(&path, newer.as_bytes()).expect("publish newer edit");

        let error = migrate_config_file(&path)
            .expect_err("restart must refuse to replace the newer live edit");

        let backup = concurrent_backup(error);
        assert_eq!(fs::read(&path).expect("read live bytes"), newer.as_bytes());
        assert_eq!(
            fs::read(backup).expect("read newer backup"),
            newer.as_bytes()
        );
        assert!(!recovery_path(&path).exists());
    }

    #[test]
    fn missing_displacement_evidence_fails_closed() {
        let directory = TestDirectory::create("missing-displacement");
        let path = directory.path().join("config.json5");
        fs::write(&path, VERSION_ZERO).expect("write original");
        migrate_config_file_with_hooks(
            &path,
            |_| Ok(()),
            |_| Err(io::Error::other("injected uncertain exchange outcome")),
        )
        .expect_err("leave a post-displacement journal");
        let journal = read_recovery_journal(&path)
            .expect("read journal")
            .expect("active journal");
        fs::remove_file(&journal.displaced_path).expect("remove displacement evidence");

        let error =
            migrate_config_file(&path).expect_err("missing evidence must never look successful");

        assert!(matches!(error, ConfigMigrationError::ConcurrentEdit { .. }));
        let live: Value = json5::from_str(&fs::read_to_string(&path).expect("read live target"))
            .expect("parse live target");
        assert_eq!(live["schema_version"], 1);
        assert!(!recovery_path(&path).exists());
    }

    #[test]
    fn migration_holds_the_same_stable_lock_as_regular_publication() {
        let directory = TestDirectory::create("shared-lock");
        let path = directory.path().join("config.json5");
        fs::write(&path, VERSION_ZERO).expect("write original");

        let outcome = migrate_config_file_with_hooks(
            &path,
            |destination| {
                let lock_path = publication_lock_path(destination);
                let second_handle = fs::OpenOptions::new()
                    .read(true)
                    .write(true)
                    .open(lock_path)?;
                assert!(
                    matches!(
                        second_handle.try_lock(),
                        Err(fs::TryLockError::WouldBlock)
                    ),
                    "the target sidecar must remain locked through CAS"
                );
                Ok(())
            },
            |_| Ok(()),
        )
        .expect("migrate with observed lock");

        assert!(matches!(outcome, ConfigMigrationOutcome::Migrated(_)));
    }

    #[cfg(unix)]
    #[test]
    fn current_and_unsupported_fast_paths_do_not_write_the_directory() {
        use std::os::unix::fs::PermissionsExt;

        let directory = TestDirectory::create("read-only-fast-path");
        let current_path = directory.path().join("current.json5");
        let unsupported_path = directory.path().join("unsupported.json5");
        fs::write(
            &current_path,
            VERSION_ZERO.replace("schema_version: 0", "schema_version: 1"),
        )
        .expect("write current");
        fs::write(
            &unsupported_path,
            VERSION_ZERO.replace("schema_version: 0", "schema_version: 99"),
        )
        .expect("write unsupported");
        fs::set_permissions(directory.path(), fs::Permissions::from_mode(0o555))
            .expect("make directory read-only");

        assert_eq!(
            migrate_config_file(&current_path).expect("read current config"),
            ConfigMigrationOutcome::Current
        );
        assert!(matches!(
            migrate_config_file(&unsupported_path),
            Err(ConfigMigrationError::UnsupportedPath { found: 99, .. })
        ));
        assert!(!publication_lock_path(&current_path).exists());
        assert!(!publication_lock_path(&unsupported_path).exists());

        fs::set_permissions(directory.path(), fs::Permissions::from_mode(0o700))
            .expect("restore directory permissions");
    }

    #[cfg(unix)]
    #[test]
    fn migration_preserves_restrictive_mode_and_private_backup_mode() {
        use std::os::unix::fs::PermissionsExt;

        let directory = TestDirectory::create("permissions");
        let path = directory.path().join("config.json5");
        fs::write(&path, VERSION_ZERO).expect("write original");
        fs::set_permissions(&path, fs::Permissions::from_mode(0o640))
            .expect("set source mode");

        let ConfigMigrationOutcome::Migrated(record) =
            migrate_config_file(&path).expect("migrate")
        else {
            panic!("version zero must migrate");
        };

        assert_eq!(
            fs::metadata(&path)
                .expect("stat migrated config")
                .permissions()
                .mode()
                & 0o777,
            0o640
        );
        assert_eq!(
            fs::metadata(record.backup_path)
                .expect("stat exact backup")
                .permissions()
                .mode()
                & 0o777,
            0o600
        );
    }

    #[cfg(windows)]
    #[test]
    fn migration_backup_copies_and_protects_the_source_dacl() {
        let directory = TestDirectory::create("windows-backup-dacl");
        let path = directory.path().join("config.json5");
        fs::write(&path, VERSION_ZERO).expect("write original");
        let source = atomicfs::open_no_follow(&path).expect("open source");
        let source_dacl = atomicfs::dacl_bytes(&source).expect("read source DACL");

        let ConfigMigrationOutcome::Migrated(record) =
            migrate_config_file(&path).expect("migrate")
        else {
            panic!("version zero must migrate");
        };
        let backup = atomicfs::open_no_follow(&record.backup_path).expect("open backup");

        assert_eq!(
            atomicfs::dacl_bytes(&backup).expect("read backup DACL"),
            source_dacl
        );
        assert!(
            atomicfs::dacl_is_protected(&backup).expect("read backup DACL control"),
            "backup DACL must not gain broader inherited ACEs"
        );
    }

    #[cfg(windows)]
    #[test]
    fn conflict_backup_copies_and_protects_the_conflicting_dacl() {
        let directory = TestDirectory::create("windows-conflict-dacl");
        let path = directory.path().join("config.json5");
        fs::write(&path, VERSION_ZERO).expect("write original");
        let concurrent = version_zero_with_role("windows-conflict-dacl");

        let error = migrate_config_file_with_hooks(
            &path,
            |destination| {
                publish_external(destination, concurrent.as_bytes())?;
                atomicfs::protect_restrictive_dacl(destination)
            },
            |_| Ok(()),
        )
        .expect_err("concurrent object must be restored");
        let backup_path = concurrent_backup(error);
        let live = atomicfs::open_no_follow(&path).expect("open live conflict");
        let backup = atomicfs::open_no_follow(&backup_path).expect("open conflict backup");

        assert_eq!(
            atomicfs::dacl_bytes(&backup).expect("read conflict backup DACL"),
            atomicfs::dacl_bytes(&live).expect("read live conflict DACL")
        );
        assert!(
            atomicfs::dacl_is_protected(&live).expect("read live conflict DACL control"),
            "restored winner must keep its protected DACL rather than candidate security"
        );
        assert!(
            atomicfs::dacl_is_protected(&backup).expect("read conflict DACL control"),
            "conflict backup DACL must not gain broader inherited ACEs"
        );
    }

    #[cfg(windows)]
    #[test]
    fn restart_conflict_restoration_keeps_the_winner_dacl() {
        let directory = TestDirectory::create("windows-winner-dacl");
        let path = directory.path().join("config.json5");
        fs::write(&path, VERSION_ZERO).expect("write original");
        let winner = version_zero_with_role("windows-winner-dacl");
        migrate_config_file_with_hooks(
            &path,
            |destination| {
                publish_external(destination, winner.as_bytes())?;
                atomicfs::set_dacl_protection(destination, true)
            },
            |_| Err(io::Error::other("injected crash after displacement")),
        )
        .expect_err("leave candidate live and winner displaced");
        atomicfs::set_dacl_protection(&path, false)
            .expect("give candidate a different DACL control state");

        let error =
            migrate_config_file(&path).expect_err("restart reports and restores the winner");

        assert!(matches!(error, ConfigMigrationError::ConcurrentEdit { .. }));
        assert_eq!(
            fs::read(&path).expect("read restored winner"),
            winner.as_bytes()
        );
        let live = atomicfs::open_no_follow(&path).expect("open restored winner");
        assert!(
            atomicfs::dacl_is_protected(&live).expect("read winner DACL control"),
            "no-replace restoration must preserve winner security instead of candidate security"
        );
    }

    #[cfg(unix)]
    #[test]
    fn relative_paths_use_the_canonical_target_and_sidecar() {
        let directory = TestDirectory::create("relative");
        let path = directory.path().join("config.json5");
        fs::write(&path, VERSION_ZERO).expect("write original");
        let relative = relative_from_current_directory(&path);

        let ConfigMigrationOutcome::Migrated(record) =
            migrate_config_file(&relative).expect("migrate through relative path")
        else {
            panic!("version zero must migrate");
        };

        let canonical = fs::canonicalize(&path).expect("canonical config");
        assert_eq!(record.config_path, canonical);
        assert!(publication_lock_path(&canonical).is_file());
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn normal_macos_canonical_aliases_are_supported() {
        let sequence = NEXT_DIRECTORY.fetch_add(1, Ordering::Relaxed);
        let alias_directory = std::env::temp_dir().join(format!(
            "claw-config-macos-alias-{}-{sequence}",
            std::process::id()
        ));
        fs::create_dir(&alias_directory).expect("create aliased temp directory");
        let cleanup = Cleanup(alias_directory.clone());
        let path = alias_directory.join("config.json5");
        fs::write(&path, VERSION_ZERO).expect("write original");

        let ConfigMigrationOutcome::Migrated(record) =
            migrate_config_file(&path).expect("migrate through macOS alias")
        else {
            panic!("version zero must migrate");
        };

        assert_eq!(
            record.config_path,
            fs::canonicalize(&path).expect("canonical path")
        );
        drop(cleanup);
    }

    #[cfg(windows)]
    #[test]
    fn windows_aliases_use_the_handle_resolved_journal_path() {
        let directory = TestDirectory::create("windows-short-journal");
        let path = directory
            .path()
            .join("Configuration Migration Long Name.json5");
        fs::write(&path, VERSION_ZERO).expect("write original");
        let extended = fs::canonicalize(&path).expect("canonical extended path");
        let short = atomicfs::short_path(&path)
            .ok()
            .filter(|short| short != &path && short != &extended);
        let alias = short.as_deref().unwrap_or(path.as_path());

        migrate_config_file_with_hooks(
            alias,
            |_| Err(io::Error::other("injected crash before displacement")),
            |_| Ok(()),
        )
        .expect_err("leave journal through Windows alias");

        let canonical = crate::io::prepare_destination(&extended)
            .expect("handle-resolved destination");
        assert!(recovery_path(&canonical).is_file());
        if let Some(short) = short {
            assert!(
                !recovery_path(&short).exists(),
                "short spelling must not derive a second journal"
            );
        }
    }

    fn concurrent_backup(error: ConfigMigrationError) -> PathBuf {
        let ConfigMigrationError::ConcurrentEdit {
            conflict_backup_path,
            ..
        } = error
        else {
            panic!("expected a concurrent edit, got {error}");
        };
        conflict_backup_path
    }

    fn version_zero_with_role(label: &str) -> String {
        VERSION_ZERO.replace(
            "https://roles.example.test/default.json",
            &format!("https://roles.example.test/{label}.json"),
        )
    }

    fn publish_external(destination: &Path, bytes: &[u8]) -> io::Result<()> {
        let sequence = NEXT_DIRECTORY.fetch_add(1, Ordering::Relaxed);
        let staging = destination.with_file_name(format!(
            ".external-writer-{}-{sequence}",
            std::process::id()
        ));
        fs::write(&staging, bytes)?;
        #[cfg(windows)]
        {
            fs::remove_file(destination)?;
            fs::rename(staging, destination)
        }
        #[cfg(not(windows))]
        {
            fs::rename(staging, destination)
        }
    }

    #[cfg(unix)]
    fn relative_from_current_directory(target: &Path) -> PathBuf {
        let current = fs::canonicalize(std::env::current_dir().expect("current directory"))
            .expect("canonical current directory");
        let target = fs::canonicalize(target).expect("canonical target");
        let current_components: Vec<_> = current.components().collect();
        let target_components: Vec<_> = target.components().collect();
        let common = current_components
            .iter()
            .zip(&target_components)
            .take_while(|(left, right)| left == right)
            .count();
        assert!(
            common > 0 && current.is_absolute() && target.is_absolute(),
            "current and target paths must share a filesystem root"
        );
        let mut relative = PathBuf::new();
        for _ in common..current_components.len() {
            relative.push("..");
        }
        for component in &target_components[common..] {
            relative.push(component.as_os_str());
        }
        relative
    }

    struct TestDirectory {
        path: PathBuf,
        _cleanup: Cleanup,
    }

    impl TestDirectory {
        fn create(label: &str) -> Self {
            let sequence = NEXT_DIRECTORY.fetch_add(1, Ordering::Relaxed);
            let path = std::env::temp_dir().join(format!(
                "claw-config-versioning-{label}-{}-{sequence}",
                std::process::id()
            ));
            fs::create_dir(&path).expect("create temporary directory");
            let path = fs::canonicalize(path).expect("canonicalize temporary directory");
            Self {
                _cleanup: Cleanup(path.clone()),
                path,
            }
        }

        fn path(&self) -> &Path {
            &self.path
        }
    }

    struct Cleanup(PathBuf);

    impl Drop for Cleanup {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }
}

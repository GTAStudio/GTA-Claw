use std::error::Error;
use std::fmt::{self, Display, Formatter};
use std::fs::{self, File, OpenOptions};
use std::io::{self, Read, Write};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};

use crate::io::{PublicationLock, atomic_write_bytes};
use crate::{
    CONFIG_SCHEMA_VERSION, ConfigError, WriteOutcome, displace_file_atomically, parse_json5,
    to_json5,
};

static BACKUP_SEQUENCE: AtomicU64 = AtomicU64::new(0);
const RECOVERY_SCHEMA_VERSION: u32 = 1;
const HASH_BUFFER_BYTES: usize = 64 * 1024;

/// One completed destructive migration and its exact pre-migration bytes.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ConfigMigrationRecord {
    /// Migrated configuration path.
    pub config_path: PathBuf,
    /// Durable backup containing the original bytes.
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
    /// The file was migrated after a durable backup was created.
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
    /// The source changed after it was read and the concurrent bytes were preserved.
    ConcurrentEdit {
        /// Configuration path left untouched.
        path: PathBuf,
        /// Durable backup containing the concurrently written bytes.
        conflict_backup_path: PathBuf,
        /// Digest of the bytes originally reviewed for migration.
        expected_sha256: String,
        /// Digest of the exact concurrent bytes in `conflict_backup_path`.
        actual_sha256: String,
    },
    /// Backup creation failed before any destructive operation.
    Backup {
        /// Intended backup path.
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
    /// A durable recovery journal could not be decoded, replayed, or removed.
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
                 {actual_sha256}); concurrent bytes were preserved at {}",
                path.display(),
                conflict_backup_path.display()
            ),
            Self::Backup { path, source } => {
                write!(
                    formatter,
                    "{}: could not create migration backup: {source}",
                    path.display()
                )
            }
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

/// Migrates a version-zero envelope to the current schema after exact backup.
///
/// Version zero is the pre-versioned form of the existing strict envelope; its
/// only destructive migration is writing `schema_version: 1`. Newer unknown
/// versions fail closed.
///
/// # Errors
///
/// Returns [`ConfigMigrationError::Config`] wrapping [`ConfigError::Io`] when
/// `path` cannot be read and [`ConfigError::Syntax`] when its bytes are not
/// UTF-8 or not well-formed JSON5. Returns
/// [`ConfigMigrationError::MissingVersion`] when the document has no integer
/// `schema_version`, or when the top level is not an object, and
/// [`ConfigMigrationError::UnsupportedPath`] for any version other than `0` or
/// the current one, so a file written by a newer build is never rewritten.
///
/// A file already at the current version is still fully validated, so
/// [`ConfigError::Decode`] or [`ConfigError::Validation`] can be returned
/// without anything being written.
///
/// The already-current path reads the document twice, once as a
/// `serde_json::Value` to find `schema_version` and once through
/// [`crate::parse_json5`] to validate it. That was measured and left alone: the
/// `Value` read costs 6.5-10.4us against 4.2us for the typed read, and every
/// cheaper way to reach `schema_version` either loses the exact JSON5 syntax
/// diagnostic or turns a non-object document from
/// [`ConfigMigrationError::MissingVersion`] into a decode failure. Both are
/// observable, and neither is worth 7us on a path that has already paid for a
/// file read.
///
/// The migration holds an advisory lock from the first read through publication.
/// A SHA-256 compare-and-swap immediately before rename detects non-cooperating
/// writers; [`ConfigMigrationError::ConcurrentEdit`] leaves their bytes in place
/// and names an exact durable backup of them.
///
/// Before publication, the original backup, candidate, and versioned recovery
/// journal are all synchronized. A later invocation replays an interrupted
/// journal, so a crash leaves either the original or migrated file and enough
/// durable evidence to finish safely.
pub fn migrate_config_file(
    path: impl AsRef<Path>,
) -> Result<ConfigMigrationOutcome, ConfigMigrationError> {
    migrate_config_file_with_hook(path.as_ref(), |_| Ok(()))
}

fn migrate_config_file_with_hook(
    path: &Path,
    before_publish: impl FnOnce(&Path) -> io::Result<()>,
) -> Result<ConfigMigrationOutcome, ConfigMigrationError> {
    migrate_config_file_with_hooks(path, before_publish, |_| Ok(()))
}

fn migrate_config_file_with_hooks(
    path: &Path,
    before_publish: impl FnOnce(&Path) -> io::Result<()>,
    after_displacement: impl FnOnce(&Path) -> io::Result<()>,
) -> Result<ConfigMigrationOutcome, ConfigMigrationError> {
    let initial_source = fs::read(path).map_err(|source| ConfigError::io(path, source))?;
    let initial_text =
        std::str::from_utf8(&initial_source).map_err(|error| ConfigError::Syntax {
            source_name: path.display().to_string(),
            message: error.to_string(),
        })?;
    let initial_document =
        json5::from_str::<Value>(initial_text).map_err(|error| ConfigError::Syntax {
            source_name: path.display().to_string(),
            message: error.to_string(),
        })?;
    let initial_version = initial_document
        .get("schema_version")
        .and_then(Value::as_u64)
        .and_then(|version| u32::try_from(version).ok())
        .ok_or(ConfigMigrationError::MissingVersion)?;
    let recovery_exists = match fs::symlink_metadata(recovery_path(path)) {
        Ok(_) => true,
        Err(source) if source.kind() == io::ErrorKind::NotFound => false,
        Err(source) => return Err(recovery_io(&recovery_path(path), &source)),
    };
    if !recovery_exists {
        if initial_version == CONFIG_SCHEMA_VERSION {
            parse_json5(initial_text, &path.display().to_string())?;
            return Ok(ConfigMigrationOutcome::Current);
        }
        if initial_version != 0 || CONFIG_SCHEMA_VERSION != 1 {
            return Err(ConfigMigrationError::UnsupportedPath {
                found: initial_version,
                current: CONFIG_SCHEMA_VERSION,
            });
        }
    }

    let lock = PublicationLock::acquire(path)?;
    let path = lock.destination().to_owned();
    if let Some(record) = recover_interrupted_migration(&lock)? {
        return Ok(ConfigMigrationOutcome::Migrated(record));
    }

    let source = fs::read(&path).map_err(|source| ConfigError::io(&path, source))?;
    let text = std::str::from_utf8(&source).map_err(|error| ConfigError::Syntax {
        source_name: path.display().to_string(),
        message: error.to_string(),
    })?;
    let mut document = json5::from_str::<Value>(text).map_err(|error| ConfigError::Syntax {
        source_name: path.display().to_string(),
        message: error.to_string(),
    })?;
    let version = document
        .get("schema_version")
        .and_then(Value::as_u64)
        .and_then(|version| u32::try_from(version).ok())
        .ok_or(ConfigMigrationError::MissingVersion)?;
    if version == CONFIG_SCHEMA_VERSION {
        parse_json5(text, &path.display().to_string())?;
        return Ok(ConfigMigrationOutcome::Current);
    }
    if version != 0 || CONFIG_SCHEMA_VERSION != 1 {
        return Err(ConfigMigrationError::UnsupportedPath {
            found: version,
            current: CONFIG_SCHEMA_VERSION,
        });
    }
    let source_sha256 = digest_bytes(&source);

    let object = document
        .as_object_mut()
        .ok_or(ConfigMigrationError::MissingVersion)?;
    object.insert(
        "schema_version".to_owned(),
        Value::from(CONFIG_SCHEMA_VERSION),
    );
    let candidate_source =
        json5::to_string(&document).map_err(|error| ConfigError::Serialize(error.to_string()))?;
    let candidate = parse_json5(&candidate_source, &path.display().to_string())?;
    let candidate_source = to_json5(&candidate)?;
    let candidate_bytes = candidate_source.as_bytes();
    let target_sha256 = digest_bytes(candidate_bytes);

    let backup_path = create_artifact(&path, "schema-v0", &source)?;
    let candidate_path = create_artifact(&path, "schema-candidate", candidate_bytes)?;
    let displaced_path = displacement_path(&path, &candidate_path)?;
    let journal = MigrationRecoveryJournal {
        schema_version: RECOVERY_SCHEMA_VERSION,
        config_path: path.clone(),
        backup_path: backup_path.clone(),
        candidate_path,
        displaced_path,
        from_version: version,
        to_version: CONFIG_SCHEMA_VERSION,
        source_sha256: source_sha256.clone(),
        target_sha256,
        conflict_restoration: None,
    };
    persist_recovery_journal(&path, &journal)?;
    before_publish(&recovery_path(&path))
        .map_err(|source| ConfigMigrationError::Config(ConfigError::io(&path, source)))?;
    match publish_candidate_with_hook(&lock, &journal, after_displacement) {
        Ok(()) => {}
        Err(error @ ConfigMigrationError::ConcurrentEdit { .. }) => {
            retire_recovery_journal(&path, &journal)?;
            return Err(error);
        }
        Err(error) => return Err(error),
    }
    cleanup_recovery_journal(&path, &journal)?;

    Ok(ConfigMigrationOutcome::Migrated(ConfigMigrationRecord {
        config_path: path,
        backup_path,
        from_version: version,
        to_version: CONFIG_SCHEMA_VERSION,
    }))
}

/// Restores exact pre-migration bytes from a migration record.
///
/// # Errors
///
/// Returns [`ConfigMigrationError::Config`] wrapping [`ConfigError::Io`] when
/// `record.backup_path` cannot be read, for example because the backup was
/// deleted after the migration, and when restoring those bytes over
/// `record.config_path` fails any step of the atomic write. The configuration
/// file keeps its migrated contents whenever this returns an error.
pub fn rollback_config_migration(
    record: &ConfigMigrationRecord,
) -> Result<(), ConfigMigrationError> {
    let lock = PublicationLock::acquire(&record.config_path)?;
    let path = lock.destination().to_owned();
    let bytes = fs::read(&record.backup_path)
        .map_err(|source| ConfigError::io(&record.backup_path, source))?;
    let outcome = lock.write_bytes(&bytes)?;
    require_durable(&outcome, &path)?;
    Ok(())
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
    conflict_restoration: Option<ConflictRestoration>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
struct ConflictRestoration {
    restored_sha256: String,
    newer_sha256: String,
    phase: ConflictRestorationPhase,
}

#[derive(Clone, Copy, Debug, Deserialize, Serialize, Eq, PartialEq)]
#[serde(rename_all = "snake_case")]
enum ConflictRestorationPhase {
    Prepared,
    NewerRestored,
}

fn recover_interrupted_migration(
    lock: &PublicationLock,
) -> Result<Option<ConfigMigrationRecord>, ConfigMigrationError> {
    let path = lock.destination();
    let journal_path = recovery_path(path);
    let bytes = match fs::read(&journal_path) {
        Ok(bytes) => bytes,
        Err(source) if source.kind() == io::ErrorKind::NotFound => return Ok(None),
        Err(source) => return Err(recovery_io(&journal_path, &source)),
    };
    let mut journal: MigrationRecoveryJournal =
        serde_json::from_slice(&bytes).map_err(|error| ConfigMigrationError::Recovery {
            path: journal_path.clone(),
            message: error.to_string(),
        })?;
    validate_recovery_journal(path, &journal_path, &journal)?;
    if hash_file(&journal.backup_path)
        .map_err(|source| recovery_io(&journal.backup_path, &source))?
        != journal.source_sha256
    {
        return Err(ConfigMigrationError::Recovery {
            path: journal.backup_path,
            message: "original backup digest does not match the recovery journal".to_owned(),
        });
    }
    let current_sha256 = hash_file(path).map_err(|source| recovery_io(path, &source))?;
    let candidate_sha256 = optional_hash_file(&journal.candidate_path)?;
    let displaced_sha256 = if journal.displaced_path == journal.candidate_path {
        candidate_sha256.clone()
    } else {
        optional_hash_file(&journal.displaced_path)?
    };
    if journal.conflict_restoration.is_some() {
        return recover_conflict_restoration(path, &mut journal);
    }
    if current_sha256 == journal.target_sha256 {
        match displaced_sha256 {
            Some(displaced) if displaced == journal.source_sha256 => {
                cleanup_recovery_journal(path, &journal)?;
                return Ok(Some(journal.record()));
            }
            Some(displaced) => {
                let error = concurrent_edit_from_path(
                    path,
                    &journal.source_sha256,
                    &journal.displaced_path,
                )?;
                restore_displaced(path, &journal, &displaced)?;
                retire_recovery_journal(path, &journal)?;
                return Err(error);
            }
            None => {
                cleanup_recovery_journal(path, &journal)?;
                return Ok(Some(journal.record()));
            }
        }
    }
    let candidate_is_target =
        candidate_sha256.as_deref() == Some(journal.target_sha256.as_str());
    let no_separate_displacement = journal.displaced_path == journal.candidate_path
        || displaced_sha256.is_none();
    let candidate_is_original =
        candidate_sha256.as_deref() == Some(journal.source_sha256.as_str());
    if candidate_is_original && current_sha256 != journal.source_sha256 {
        let error = concurrent_edit(path, &journal.source_sha256)?;
        retire_recovery_journal(path, &journal)?;
        return Err(error);
    }
    let conflict_restoration_interrupted = current_sha256 != journal.source_sha256
        && candidate_sha256.is_some()
        && !candidate_is_target
        && !candidate_is_original
        && no_separate_displacement;
    if conflict_restoration_interrupted {
        let error = concurrent_edit(path, &journal.source_sha256)?;
        restore_candidate_over_current(path, &journal, &current_sha256)?;
        retire_recovery_journal(path, &journal)?;
        return Err(error);
    }
    if candidate_is_target && no_separate_displacement {
        if current_sha256 != journal.source_sha256 {
            let error = concurrent_edit(path, &journal.source_sha256)?;
            retire_recovery_journal(path, &journal)?;
            return Err(error);
        }
    } else {
        return Err(ConfigMigrationError::Recovery {
            path: journal_path,
            message: "recovery journal artifacts do not match a safe displacement topology"
                .to_owned(),
        });
    }
    if let Err(error @ ConfigMigrationError::ConcurrentEdit { .. }) =
        publish_candidate(lock, &journal)
    {
        retire_recovery_journal(path, &journal)?;
        return Err(error);
    }
    cleanup_recovery_journal(path, &journal)?;
    Ok(Some(journal.record()))
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

fn validate_recovery_journal(
    path: &Path,
    journal_path: &Path,
    journal: &MigrationRecoveryJournal,
) -> Result<(), ConfigMigrationError> {
    if journal.schema_version != RECOVERY_SCHEMA_VERSION {
        return Err(ConfigMigrationError::Recovery {
            path: journal_path.to_owned(),
            message: format!(
                "unsupported recovery schema {}; supported schema is {}",
                journal.schema_version, RECOVERY_SCHEMA_VERSION
            ),
        });
    }
    if journal.config_path != path
        || journal.backup_path.parent() != path.parent()
        || journal.candidate_path.parent() != path.parent()
        || journal.displaced_path.parent() != path.parent()
    {
        return Err(ConfigMigrationError::Recovery {
            path: journal_path.to_owned(),
            message: "recovery journal paths do not match the locked configuration".to_owned(),
        });
    }
    if journal.source_sha256.len() != 64 || journal.target_sha256.len() != 64 {
        return Err(ConfigMigrationError::Recovery {
            path: journal_path.to_owned(),
            message: "recovery journal contains an invalid SHA-256 digest".to_owned(),
        });
    }
    Ok(())
}

fn persist_recovery_journal(
    path: &Path,
    journal: &MigrationRecoveryJournal,
) -> Result<(), ConfigMigrationError> {
    let journal_path = recovery_path(path);
    let bytes =
        serde_json::to_vec_pretty(journal).map_err(|error| ConfigMigrationError::Recovery {
            path: journal_path.clone(),
            message: error.to_string(),
        })?;
    let outcome = atomic_write_bytes(&journal_path, &bytes, || Ok(()))
        .map_err(|source| recovery_io(&journal_path, &source))?;
    require_durable(&outcome, &journal_path)
}

fn publish_candidate(
    lock: &PublicationLock,
    journal: &MigrationRecoveryJournal,
) -> Result<(), ConfigMigrationError> {
    publish_candidate_with_hook(lock, journal, |_| Ok(()))
}

fn publish_candidate_with_hook(
    lock: &PublicationLock,
    journal: &MigrationRecoveryJournal,
    after_displacement: impl FnOnce(&Path) -> io::Result<()>,
) -> Result<(), ConfigMigrationError> {
    let path = lock.destination();
    if hash_file(&journal.candidate_path)
        .map_err(|source| recovery_io(&journal.candidate_path, &source))?
        != journal.target_sha256
    {
        return Err(ConfigMigrationError::Recovery {
            path: journal.candidate_path.clone(),
            message: "candidate digest does not match recovery journal".to_owned(),
        });
    }
    displace_file_atomically(
        &journal.candidate_path,
        path,
        &journal.displaced_path,
    )
    .map_err(|source| recovery_io(path, &source))?;
    sync_parent(path).map_err(|source| recovery_io(path, &source))?;
    after_displacement(&journal.displaced_path)
        .map_err(|source| recovery_io(&journal.displaced_path, &source))?;
    let displaced_sha256 = hash_file(&journal.displaced_path)
        .map_err(|source| recovery_io(&journal.displaced_path, &source))?;
    if displaced_sha256 == journal.source_sha256 {
        return Ok(());
    }
    let error =
        concurrent_edit_from_path(path, &journal.source_sha256, &journal.displaced_path)?;
    restore_displaced(path, journal, &displaced_sha256)?;
    Err(error)
}

fn retire_recovery_journal(
    path: &Path,
    journal: &MigrationRecoveryJournal,
) -> Result<PathBuf, ConfigMigrationError> {
    let journal_path = recovery_path(path);
    let retired = (0..128)
        .find_map(|_| {
            let sequence = BACKUP_SEQUENCE.fetch_add(1, Ordering::Relaxed);
            let retired = path.with_file_name(format!(
                ".{}.schema-migration.conflict.{}.{}.json",
                path.file_name()
                    .and_then(|name| name.to_str())
                    .unwrap_or("config"),
                std::process::id(),
                sequence
            ));
            match fs::symlink_metadata(&retired) {
                Err(source) if source.kind() == io::ErrorKind::NotFound => Some(Ok(retired)),
                Ok(_) => None,
                Err(source) => Some(Err(recovery_io(&retired, &source))),
            }
        })
        .transpose()?
        .ok_or_else(|| ConfigMigrationError::Recovery {
            path: journal_path.clone(),
            message: "could not allocate a unique retired recovery journal".to_owned(),
        })?;
    fs::rename(&journal_path, &retired)
        .map_err(|source| recovery_io(&journal_path, &source))?;
    sync_parent(&retired).map_err(|source| recovery_io(&retired, &source))?;
    cleanup_displacement_artifacts(journal)?;
    Ok(retired)
}

fn concurrent_edit(
    path: &Path,
    expected_sha256: &str,
) -> Result<ConfigMigrationError, ConfigMigrationError> {
    let concurrent = fs::read(path).map_err(|source| ConfigError::io(path, source))?;
    let actual_sha256 = digest_bytes(&concurrent);
    let conflict_backup_path = create_artifact(path, "schema-conflict", &concurrent)?;
    Ok(ConfigMigrationError::ConcurrentEdit {
        path: path.to_owned(),
        conflict_backup_path,
        expected_sha256: expected_sha256.to_owned(),
        actual_sha256,
    })
}

fn concurrent_edit_from_path(
    config_path: &Path,
    expected_sha256: &str,
    concurrent_path: &Path,
) -> Result<ConfigMigrationError, ConfigMigrationError> {
    let concurrent =
        fs::read(concurrent_path).map_err(|source| ConfigError::io(concurrent_path, source))?;
    let actual_sha256 = digest_bytes(&concurrent);
    let conflict_backup_path =
        create_artifact(config_path, "schema-conflict", &concurrent)?;
    Ok(ConfigMigrationError::ConcurrentEdit {
        path: config_path.to_owned(),
        conflict_backup_path,
        expected_sha256: expected_sha256.to_owned(),
        actual_sha256,
    })
}

fn restore_displaced(
    path: &Path,
    journal: &MigrationRecoveryJournal,
    expected_restored_sha256: &str,
) -> Result<(), ConfigMigrationError> {
    displace_file_atomically(
        &journal.displaced_path,
        path,
        &journal.candidate_path,
    )
    .map_err(|source| recovery_io(path, &source))?;
    sync_parent(path).map_err(|source| recovery_io(path, &source))?;
    let newly_displaced_sha256 = hash_file(&journal.candidate_path)
        .map_err(|source| recovery_io(&journal.candidate_path, &source))?;
    if newly_displaced_sha256 == journal.target_sha256 {
        return Ok(());
    }

    restore_candidate_over_current(path, journal, expected_restored_sha256)
}

fn restore_candidate_over_current(
    path: &Path,
    journal: &MigrationRecoveryJournal,
    expected_current_sha256: &str,
) -> Result<(), ConfigMigrationError> {
    backup_concurrent_path(path, &journal.candidate_path)?;
    let newer_sha256 = hash_file(&journal.candidate_path)
        .map_err(|source| recovery_io(&journal.candidate_path, &source))?;
    let mut updated = journal.clone();
    updated.conflict_restoration = Some(ConflictRestoration {
        restored_sha256: expected_current_sha256.to_owned(),
        newer_sha256,
        phase: ConflictRestorationPhase::Prepared,
    });
    persist_recovery_journal(path, &updated)?;
    complete_newer_restoration(path, &mut updated)
}

fn complete_newer_restoration(
    path: &Path,
    journal: &mut MigrationRecoveryJournal,
) -> Result<(), ConfigMigrationError> {
    let state = journal
        .conflict_restoration
        .as_ref()
        .expect("conflict restoration state was persisted")
        .clone();
    displace_file_atomically(
        &journal.candidate_path,
        path,
        &journal.displaced_path,
    )
    .map_err(|source| recovery_io(path, &source))?;
    sync_parent(path).map_err(|source| recovery_io(path, &source))?;
    let twice_displaced_sha256 = hash_file(&journal.displaced_path)
        .map_err(|source| recovery_io(&journal.displaced_path, &source))?;
    if twice_displaced_sha256 != state.restored_sha256 {
        let preserved = backup_concurrent_path(path, &journal.displaced_path)?;
        return Err(ConfigMigrationError::Recovery {
            path: journal.displaced_path.clone(),
            message: format!(
                "multiple concurrent edits raced conflict restoration; newest displaced bytes \
                 were preserved at {}",
                preserved.display()
            ),
        });
    }
    journal
        .conflict_restoration
        .as_mut()
        .expect("conflict restoration state remains present")
        .phase = ConflictRestorationPhase::NewerRestored;
    persist_recovery_journal(path, journal)
}

fn recover_conflict_restoration(
    path: &Path,
    journal: &mut MigrationRecoveryJournal,
) -> Result<Option<ConfigMigrationRecord>, ConfigMigrationError> {
    let state = journal
        .conflict_restoration
        .as_ref()
        .expect("caller checked conflict restoration state")
        .clone();
    let current_sha256 = hash_file(path).map_err(|source| recovery_io(path, &source))?;
    let candidate_sha256 = optional_hash_file(&journal.candidate_path)?;
    let displaced_sha256 = if journal.displaced_path == journal.candidate_path {
        candidate_sha256.clone()
    } else {
        optional_hash_file(&journal.displaced_path)?
    };
    let before_newer_restore = current_sha256 == state.restored_sha256
        && candidate_sha256.as_deref() == Some(state.newer_sha256.as_str());
    let displaced_holds_restored =
        displaced_sha256.as_deref() == Some(state.restored_sha256.as_str());
    let after_newer_restore =
        current_sha256 == state.newer_sha256 && displaced_holds_restored;
    if before_newer_restore {
        complete_newer_restoration(path, journal)?;
    } else if after_newer_restore {
        if state.phase != ConflictRestorationPhase::NewerRestored {
            journal
                .conflict_restoration
                .as_mut()
                .expect("state remains present")
                .phase = ConflictRestorationPhase::NewerRestored;
            persist_recovery_journal(path, journal)?;
        }
    } else {
        return Err(ConfigMigrationError::Recovery {
            path: recovery_path(path),
            message: "conflict restoration journal does not match a safe B/C topology".to_owned(),
        });
    }
    let restored_path = if optional_hash_file(&journal.displaced_path)?.as_deref()
        == Some(state.restored_sha256.as_str())
    {
        &journal.displaced_path
    } else {
        &journal.candidate_path
    };
    let error = concurrent_edit_from_path(path, &journal.source_sha256, restored_path)?;
    retire_recovery_journal(path, journal)?;
    Err(error)
}

fn backup_concurrent_path(
    config_path: &Path,
    concurrent_path: &Path,
) -> Result<PathBuf, ConfigMigrationError> {
    let bytes =
        fs::read(concurrent_path).map_err(|source| ConfigError::io(concurrent_path, source))?;
    create_artifact(config_path, "schema-conflict", &bytes)
}

fn cleanup_recovery_journal(
    path: &Path,
    journal: &MigrationRecoveryJournal,
) -> Result<(), ConfigMigrationError> {
    let journal_path = recovery_path(path);
    cleanup_displacement_artifacts(journal)?;
    remove_if_present(&journal_path)?;
    sync_parent(&journal_path).map_err(|source| recovery_io(&journal_path, &source))
}

fn cleanup_displacement_artifacts(
    journal: &MigrationRecoveryJournal,
) -> Result<(), ConfigMigrationError> {
    remove_if_present(&journal.candidate_path)?;
    if journal.displaced_path != journal.candidate_path {
        remove_if_present(&journal.displaced_path)?;
    }
    sync_parent(&journal.candidate_path)
        .map_err(|source| recovery_io(&journal.candidate_path, &source))
}

fn optional_hash_file(path: &Path) -> Result<Option<String>, ConfigMigrationError> {
    match hash_file(path) {
        Ok(digest) => Ok(Some(digest)),
        Err(source) if source.kind() == io::ErrorKind::NotFound => Ok(None),
        Err(source) => Err(recovery_io(path, &source)),
    }
}

fn remove_if_present(path: &Path) -> Result<(), ConfigMigrationError> {
    match fs::remove_file(path) {
        Ok(()) => Ok(()),
        Err(source) if source.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(source) => Err(recovery_io(path, &source)),
    }
}

fn recovery_path(path: &Path) -> PathBuf {
    path.with_file_name(format!(
        ".{}.schema-migration.recovery.json",
        path.file_name()
            .and_then(|name| name.to_str())
            .unwrap_or("config")
    ))
}

#[cfg(windows)]
fn displacement_path(
    path: &Path,
    _candidate_path: &Path,
) -> Result<PathBuf, ConfigMigrationError> {
    allocate_artifact_path(path, "schema-displaced")
}

#[cfg(not(windows))]
fn displacement_path(
    _path: &Path,
    candidate_path: &Path,
) -> Result<PathBuf, ConfigMigrationError> {
    Ok(candidate_path.to_owned())
}

#[cfg(windows)]
fn allocate_artifact_path(
    path: &Path,
    label: &str,
) -> Result<PathBuf, ConfigMigrationError> {
    for _ in 0..128 {
        let sequence = BACKUP_SEQUENCE.fetch_add(1, Ordering::Relaxed);
        let artifact = path.with_file_name(format!(
            "{}.{label}.{}.{}.bak",
            path.file_name()
                .and_then(|name| name.to_str())
                .unwrap_or("config"),
            std::process::id(),
            sequence
        ));
        match fs::symlink_metadata(&artifact) {
            Err(source) if source.kind() == io::ErrorKind::NotFound => return Ok(artifact),
            Ok(_) => {}
            Err(source) => return Err(recovery_io(&artifact, &source)),
        }
    }
    Err(ConfigMigrationError::Recovery {
        path: path.to_owned(),
        message: "could not allocate a unique migration artifact path".to_owned(),
    })
}

fn create_artifact(
    path: &Path,
    label: &str,
    bytes: &[u8],
) -> Result<PathBuf, ConfigMigrationError> {
    create_artifact_io(path, label, bytes).map_err(|source| ConfigMigrationError::Backup {
        path: path.to_owned(),
        source,
    })
}

fn create_artifact_io(path: &Path, label: &str, bytes: &[u8]) -> io::Result<PathBuf> {
    for _ in 0..128 {
        let sequence = BACKUP_SEQUENCE.fetch_add(1, Ordering::Relaxed);
        let backup_path = path.with_file_name(format!(
            "{}.{label}.{}.{}.bak",
            path.file_name()
                .and_then(|name| name.to_str())
                .unwrap_or("config"),
            std::process::id(),
            sequence
        ));
        match OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&backup_path)
        {
            Ok(mut file) => {
                if let Err(source) = file
                    .write_all(bytes)
                    .and_then(|()| file.flush())
                    .and_then(|()| file.sync_all())
                {
                    drop(file);
                    let _ = fs::remove_file(&backup_path);
                    return Err(source);
                }
                sync_parent(&backup_path)?;
                return Ok(backup_path);
            }
            Err(source) if source.kind() == io::ErrorKind::AlreadyExists => {}
            Err(source) => return Err(source),
        }
    }
    Err(io::Error::new(
        io::ErrorKind::AlreadyExists,
        "could not allocate a unique migration artifact",
    ))
}

fn require_durable(outcome: &WriteOutcome, path: &Path) -> Result<(), ConfigMigrationError> {
    if outcome.warnings.is_empty() {
        Ok(())
    } else {
        Err(ConfigMigrationError::Recovery {
            path: path.to_owned(),
            message: format!(
                "atomic publication reported durability warning(s): {:?}",
                outcome.warnings
            ),
        })
    }
}

fn hash_file(path: &Path) -> io::Result<String> {
    let file = File::open(path)?;
    let mut reader = file;
    let mut hasher = Sha256::new();
    let mut buffer = vec![0_u8; HASH_BUFFER_BYTES];
    loop {
        let read = reader.read(&mut buffer)?;
        if read == 0 {
            break;
        }
        hasher.update(&buffer[..read]);
    }
    Ok(encode_hex(&hasher.finalize()))
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

fn recovery_io(path: &Path, source: &io::Error) -> ConfigMigrationError {
    ConfigMigrationError::Recovery {
        path: path.to_owned(),
        message: source.to_string(),
    }
}

#[cfg(unix)]
fn sync_parent(path: &Path) -> io::Result<()> {
    fs::File::open(
        path.parent()
            .expect("allocated backup paths always have a parent"),
    )?
    .sync_all()
}

#[cfg(not(unix))]
fn sync_parent(_path: &Path) -> io::Result<()> {
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::fs::{self, OpenOptions};
    use std::io;
    use std::path::PathBuf;
    use std::sync::atomic::{AtomicU64, Ordering};

    use super::{
        ConfigMigrationError, ConfigMigrationOutcome, ConflictRestoration,
        ConflictRestorationPhase, MigrationRecoveryJournal, digest_bytes,
        displace_file_atomically, migrate_config_file, migrate_config_file_with_hook,
        migrate_config_file_with_hooks, persist_recovery_journal, recovery_path,
    };
    use crate::io::publication_lock_path;

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
    fn locked_digest_cas_preserves_and_backs_up_concurrent_bytes() {
        let directory = temporary_directory("concurrent");
        let cleanup = Cleanup(directory.clone());
        let path = directory.join("config.json5");
        fs::write(&path, VERSION_ZERO).expect("write original");
        let concurrent = VERSION_ZERO.replace(
            "https://roles.example.test/default.json",
            "https://roles.example.test/concurrent.json",
        );

        let error = migrate_config_file_with_hook(&path, |_| {
            let external = OpenOptions::new()
                .read(true)
                .write(true)
                .open(publication_lock_path(&path))
                .expect("open second lock handle");
            assert!(
                matches!(external.try_lock(), Err(fs::TryLockError::WouldBlock)),
                "migration must hold the stable sidecar lock through CAS"
            );
            fs::write(&path, concurrent.as_bytes())
        })
        .expect_err("concurrent edit must fail");

        let conflict_backup_path = match error {
            ConfigMigrationError::ConcurrentEdit {
                conflict_backup_path,
                ..
            } => conflict_backup_path,
            other => panic!("expected concurrent edit, got {other}"),
        };
        assert_eq!(
            fs::read(&path).expect("read live bytes"),
            concurrent.as_bytes()
        );
        assert_eq!(
            fs::read(conflict_backup_path).expect("read conflict backup"),
            concurrent.as_bytes()
        );
        assert!(
            !recovery_path(&path).exists(),
            "conflicting journal must be retired so retry is not poisoned"
        );

        let retry = migrate_config_file(&path).expect("retry migrates concurrent bytes");
        let ConfigMigrationOutcome::Migrated(record) = retry else {
            panic!("concurrent version-zero bytes must migrate on retry");
        };
        assert_eq!(
            fs::read(record.backup_path).expect("read retry backup"),
            concurrent.as_bytes()
        );
        drop(cleanup);
    }

    #[test]
    fn second_concurrent_edit_is_restored_live_and_never_cleaned_as_candidate() {
        let directory = temporary_directory("second-concurrent");
        let cleanup = Cleanup(directory.clone());
        let path = directory.join("config.json5");
        fs::write(&path, VERSION_ZERO).expect("write original");
        let concurrent_b = VERSION_ZERO.replace(
            "https://roles.example.test/default.json",
            "https://roles.example.test/concurrent-b.json",
        );
        let concurrent_c = VERSION_ZERO.replace(
            "https://roles.example.test/default.json",
            "https://roles.example.test/concurrent-c.json",
        );

        let error = migrate_config_file_with_hooks(
            &path,
            |_| fs::write(&path, concurrent_b.as_bytes()),
            |_| fs::write(&path, concurrent_c.as_bytes()),
        )
        .expect_err("both concurrent edits must defeat migration CAS");

        let ConfigMigrationError::ConcurrentEdit {
            conflict_backup_path,
            ..
        } = error
        else {
            panic!("expected concurrent edit, got {error}");
        };
        assert_eq!(
            fs::read(&path).expect("read newest live edit"),
            concurrent_c.as_bytes()
        );
        assert_eq!(
            fs::read(conflict_backup_path).expect("read first conflict backup"),
            concurrent_b.as_bytes()
        );
        assert!(!recovery_path(&path).exists());
        drop(cleanup);
    }

    #[cfg(any(unix, windows))]
    #[test]
    fn restart_recognizes_conflict_restoration_interrupted_before_newer_edit_restore() {
        let directory = temporary_directory("conflict-restore-restart");
        let cleanup = Cleanup(directory.clone());
        let path = directory.join("config.json5");
        fs::write(&path, VERSION_ZERO).expect("write original");
        let concurrent_b = VERSION_ZERO.replace(
            "https://roles.example.test/default.json",
            "https://roles.example.test/concurrent-b.json",
        );
        let concurrent_c = VERSION_ZERO.replace(
            "https://roles.example.test/default.json",
            "https://roles.example.test/concurrent-c.json",
        );
        migrate_config_file_with_hooks(
            &path,
            |_| fs::write(&path, concurrent_b.as_bytes()),
            |_| Err(io::Error::other("crash after first displacement")),
        )
        .expect_err("leave first displacement journal active");
        fs::write(&path, concurrent_c.as_bytes()).expect("publish newer concurrent edit");
        let mut journal: MigrationRecoveryJournal = serde_json::from_slice(
            &fs::read(recovery_path(&path)).expect("read active journal"),
        )
        .expect("decode active journal");
        displace_file_atomically(
            &journal.displaced_path,
            &path,
            &journal.candidate_path,
        )
        .expect("simulate restoring B before process crashes");
        journal.conflict_restoration = Some(ConflictRestoration {
            restored_sha256: digest_bytes(concurrent_b.as_bytes()),
            newer_sha256: digest_bytes(concurrent_c.as_bytes()),
            phase: ConflictRestorationPhase::Prepared,
        });
        persist_recovery_journal(&path, &journal).expect("persist B/C restoration phase");
        displace_file_atomically(
            &journal.candidate_path,
            &path,
            &journal.displaced_path,
        )
        .expect("simulate restoring C before phase update crashes");

        let error = migrate_config_file(&path)
            .expect_err("restart reports concurrent edit after restoring C live");

        let ConfigMigrationError::ConcurrentEdit {
            conflict_backup_path,
            ..
        } = error
        else {
            panic!("expected concurrent edit, got {error}");
        };
        assert_eq!(
            fs::read(&path).expect("read newest live edit"),
            concurrent_c.as_bytes()
        );
        assert_eq!(
            fs::read(conflict_backup_path).expect("read B conflict backup"),
            concurrent_b.as_bytes()
        );
        assert!(!recovery_path(&path).exists());
        drop(cleanup);
    }

    #[cfg(any(unix, windows))]
    #[test]
    fn original_bytes_in_candidate_never_overwrite_new_live_edit_on_restart() {
        let directory = temporary_directory("candidate-original");
        let cleanup = Cleanup(directory.clone());
        let path = directory.join("config.json5");
        fs::write(&path, VERSION_ZERO).expect("write original");
        migrate_config_file_with_hooks(
            &path,
            |_| Ok(()),
            |_| Err(io::Error::other("crash after migration displacement")),
        )
        .expect_err("leave displacement journal active");
        let journal: MigrationRecoveryJournal = serde_json::from_slice(
            &fs::read(recovery_path(&path)).expect("read active journal"),
        )
        .expect("decode active journal");
        displace_file_atomically(
            &journal.displaced_path,
            &path,
            &journal.candidate_path,
        )
        .expect("simulate original restoration before crash");
        let newer = VERSION_ZERO.replace(
            "https://roles.example.test/default.json",
            "https://roles.example.test/newer-live.json",
        );
        fs::write(&path, newer.as_bytes()).expect("write newer live edit");

        migrate_config_file(&path).expect_err("newer live edit must be reported");

        assert_eq!(fs::read(&path).expect("read live bytes"), newer.as_bytes());
        assert!(!recovery_path(&path).exists());
        assert!(!journal.candidate_path.exists());
        drop(cleanup);
    }

    #[test]
    fn restart_replays_a_durable_prepared_migration() {
        let directory = temporary_directory("restart");
        let cleanup = Cleanup(directory);
        let path = cleanup.0.join("config.json5");
        fs::write(&path, VERSION_ZERO).expect("write original");

        migrate_config_file_with_hook(&path, |_| {
            Err(io::Error::other("injected crash before publication"))
        })
        .expect_err("failpoint must interrupt migration");
        assert_eq!(
            fs::read(&path).expect("old bytes remain"),
            VERSION_ZERO.as_bytes()
        );
        assert!(recovery_path(&path).is_file(), "journal must survive");

        let outcome = migrate_config_file(&path).expect("restart completes migration");
        assert!(matches!(outcome, ConfigMigrationOutcome::Migrated(_)));
        let migrated: serde_json::Value =
            json5::from_str(&fs::read_to_string(&path).expect("read migrated"))
                .expect("parse migrated");
        assert_eq!(migrated["schema_version"], 1);
        assert!(
            !recovery_path(&path).exists(),
            "completed journal is removed"
        );
    }

    #[cfg(any(unix, windows))]
    #[test]
    fn restart_recognizes_crash_immediately_after_atomic_displacement() {
        let directory = temporary_directory("exchanged-restart");
        let cleanup = Cleanup(directory);
        let path = cleanup.0.join("config.json5");
        fs::write(&path, VERSION_ZERO).expect("write original");

        migrate_config_file_with_hooks(
            &path,
            |_| Ok(()),
            |_| Err(io::Error::other("injected crash after displacement")),
        )
        .expect_err("displacement failpoint interrupts migration");
        let displaced_target: serde_json::Value =
            json5::from_str(&fs::read_to_string(&path).expect("read displaced target"))
                .expect("parse displaced target");
        assert_eq!(displaced_target["schema_version"], 1);
        assert!(recovery_path(&path).is_file());

        let outcome = migrate_config_file(&path).expect("restart completes exchanged migration");

        assert!(matches!(outcome, ConfigMigrationOutcome::Migrated(_)));
        assert!(!recovery_path(&path).exists());
    }

    fn temporary_directory(label: &str) -> PathBuf {
        let sequence = NEXT_DIRECTORY.fetch_add(1, Ordering::Relaxed);
        let directory = std::env::temp_dir().join(format!(
            "claw-config-versioning-{label}-{}-{sequence}",
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

use std::cell::RefCell;
use std::error::Error;
use std::fmt::{self, Display, Formatter};
use std::fs::{self, File, OpenOptions};
use std::io::{self, Read, Write};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};

use crate::io::{atomic_write_bytes, prepare_destination};
use crate::{CONFIG_SCHEMA_VERSION, ConfigError, WriteOutcome, parse_json5, to_json5};

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
    let path = prepare_destination(path).map_err(|source| ConfigError::io(path, source))?;
    let _lock = MigrationLock::acquire(&path)?;
    if let Some(record) = recover_interrupted_migration(&path)? {
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
    let journal = MigrationRecoveryJournal {
        schema_version: RECOVERY_SCHEMA_VERSION,
        config_path: path.clone(),
        backup_path: backup_path.clone(),
        candidate_path,
        from_version: version,
        to_version: CONFIG_SCHEMA_VERSION,
        source_sha256: source_sha256.clone(),
        target_sha256,
    };
    persist_recovery_journal(&path, &journal)?;
    before_publish(&recovery_path(&path))
        .map_err(|source| ConfigMigrationError::Config(ConfigError::io(&path, source)))?;
    publish_candidate(&path, candidate_bytes, &source_sha256)?;
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
    let path = prepare_destination(&record.config_path)
        .map_err(|source| ConfigError::io(&record.config_path, source))?;
    let _lock = MigrationLock::acquire(&path)?;
    let bytes = fs::read(&record.backup_path)
        .map_err(|source| ConfigError::io(&record.backup_path, source))?;
    let outcome = atomic_write_bytes(&path, &bytes, || Ok(()))
        .map_err(|source| ConfigError::io(&path, source))?;
    require_durable(&outcome, &path)?;
    Ok(())
}

#[derive(Debug, Deserialize, Serialize)]
struct MigrationRecoveryJournal {
    schema_version: u32,
    config_path: PathBuf,
    backup_path: PathBuf,
    candidate_path: PathBuf,
    from_version: u32,
    to_version: u32,
    source_sha256: String,
    target_sha256: String,
}

struct MigrationLock {
    _file: File,
}

impl MigrationLock {
    fn acquire(path: &Path) -> Result<Self, ConfigMigrationError> {
        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .open(path)
            .map_err(|source| ConfigError::io(path, source))?;
        file.lock()
            .map_err(|source| ConfigError::io(path, source))?;
        Ok(Self { _file: file })
    }
}

fn recover_interrupted_migration(
    path: &Path,
) -> Result<Option<ConfigMigrationRecord>, ConfigMigrationError> {
    let journal_path = recovery_path(path);
    let bytes = match fs::read(&journal_path) {
        Ok(bytes) => bytes,
        Err(source) if source.kind() == io::ErrorKind::NotFound => return Ok(None),
        Err(source) => return Err(recovery_io(&journal_path, &source)),
    };
    let journal: MigrationRecoveryJournal =
        serde_json::from_slice(&bytes).map_err(|error| ConfigMigrationError::Recovery {
            path: journal_path.clone(),
            message: error.to_string(),
        })?;
    validate_recovery_journal(path, &journal_path, &journal)?;

    let current_sha256 = hash_file(path).map_err(|source| recovery_io(path, &source))?;
    if current_sha256 == journal.target_sha256 {
        cleanup_recovery_journal(path, &journal)?;
        return Ok(Some(journal.record()));
    }
    if current_sha256 != journal.source_sha256 {
        return Err(concurrent_edit(path, &journal.source_sha256)?);
    }
    if hash_file(&journal.backup_path)
        .map_err(|source| recovery_io(&journal.backup_path, &source))?
        != journal.source_sha256
    {
        return Err(ConfigMigrationError::Recovery {
            path: journal.backup_path,
            message: "original backup digest does not match the recovery journal".to_owned(),
        });
    }
    if hash_file(&journal.candidate_path)
        .map_err(|source| recovery_io(&journal.candidate_path, &source))?
        != journal.target_sha256
    {
        return Err(ConfigMigrationError::Recovery {
            path: journal.candidate_path,
            message: "candidate digest does not match the recovery journal".to_owned(),
        });
    }
    let candidate = fs::read(&journal.candidate_path)
        .map_err(|source| recovery_io(&journal.candidate_path, &source))?;
    publish_candidate(path, &candidate, &journal.source_sha256)?;
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
    path: &Path,
    candidate: &[u8],
    expected_sha256: &str,
) -> Result<(), ConfigMigrationError> {
    let conflict = RefCell::new(None);
    let outcome = atomic_write_bytes(path, candidate, || {
        let actual_sha256 = hash_file(path)?;
        if actual_sha256 == expected_sha256 {
            return Ok(());
        }
        let concurrent = fs::read(path)?;
        let actual_sha256 = digest_bytes(&concurrent);
        let conflict_backup_path = create_artifact_io(path, "schema-conflict", &concurrent)?;
        *conflict.borrow_mut() = Some((conflict_backup_path, actual_sha256));
        Err(io::Error::other(
            "configuration changed during schema migration",
        ))
    });
    match outcome {
        Ok(outcome) => require_durable(&outcome, path),
        Err(_) if conflict.borrow().is_some() => {
            let (conflict_backup_path, actual_sha256) = conflict
                .into_inner()
                .expect("conflict was checked before extraction");
            Err(ConfigMigrationError::ConcurrentEdit {
                path: path.to_owned(),
                conflict_backup_path,
                expected_sha256: expected_sha256.to_owned(),
                actual_sha256,
            })
        }
        Err(source) => Err(ConfigMigrationError::Config(ConfigError::io(path, source))),
    }
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

fn cleanup_recovery_journal(
    path: &Path,
    journal: &MigrationRecoveryJournal,
) -> Result<(), ConfigMigrationError> {
    let journal_path = recovery_path(path);
    remove_if_present(&journal_path)?;
    sync_parent(&journal_path).map_err(|source| recovery_io(&journal_path, &source))?;
    remove_if_present(&journal.candidate_path)?;
    sync_parent(&journal.candidate_path)
        .map_err(|source| recovery_io(&journal.candidate_path, &source))
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
        ConfigMigrationError, ConfigMigrationOutcome, migrate_config_file,
        migrate_config_file_with_hook, recovery_path,
    };

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
                .open(&path)
                .expect("open second lock handle");
            assert!(
                matches!(external.try_lock(), Err(fs::TryLockError::WouldBlock)),
                "migration must hold the advisory file lock through CAS"
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

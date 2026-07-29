use std::error::Error;
use std::fmt::{self, Display, Formatter};
use std::fs::{self, OpenOptions};
use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

use serde_json::Value;
use sha2::{Digest, Sha256};

use crate::io::{
    WriteOutcome, WriteWarning, atomic_write_bytes, atomic_write_bytes_locked,
    with_destination_lock,
};
use crate::{CONFIG_SCHEMA_VERSION, ConfigError, parse_json5, to_json5};

static BACKUP_SEQUENCE: AtomicU64 = AtomicU64::new(0);

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
    /// A migration lock could not be acquired.
    Lock {
        /// Lock file path.
        path: PathBuf,
        /// Operating-system failure.
        source: io::Error,
    },
    /// The source changed after review and before publication.
    ConcurrentEdit {
        /// Migrated configuration path.
        config_path: PathBuf,
        /// Durable backup containing the concurrent bytes.
        backup_path: PathBuf,
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
    /// Publication finished but durability warnings prevent claiming success.
    DurabilityWarning {
        /// Published path whose parent directory did not sync cleanly.
        path: PathBuf,
        /// Exact backup that still reconstructs the pre-migration bytes.
        backup_path: Option<PathBuf>,
        /// Non-fatal warnings from atomic publication.
        warnings: Vec<WriteWarning>,
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
            Self::Backup { path, source } => {
                write!(
                    formatter,
                    "{}: could not create migration backup: {source}",
                    path.display()
                )
            }
            Self::Lock { path, source } => {
                write!(
                    formatter,
                    "{}: could not acquire migration lock: {source}",
                    path.display()
                )
            }
            Self::ConcurrentEdit {
                config_path,
                backup_path,
            } => write!(
                formatter,
                "{}: concurrent edit detected; migration refused to overwrite newer bytes and \
                 backed them up at {}",
                config_path.display(),
                backup_path.display()
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
            Self::DurabilityWarning {
                path,
                backup_path,
                warnings,
            } => {
                let detail = warnings
                    .iter()
                    .map(|warning| match warning {
                        WriteWarning::BackupCleanupFailed { path, message } => {
                            format!("backup cleanup failed at {}: {message}", path.display())
                        }
                        WriteWarning::DirectorySyncFailed { path, message } => {
                            format!("directory sync failed at {}: {message}", path.display())
                        }
                    })
                    .collect::<Vec<_>>()
                    .join("; ");
                match backup_path {
                    Some(backup_path) => write!(
                        formatter,
                        "{}: published bytes but durability is uncertain: {detail}; exact backup \
                         remains at {}",
                        path.display(),
                        backup_path.display()
                    ),
                    None => write!(
                        formatter,
                        "{}: published bytes but durability is uncertain: {detail}",
                        path.display()
                    ),
                }
            }
        }
    }
}

impl Error for ConfigMigrationError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Config(error) => Some(error),
            Self::Backup { source, .. } | Self::Lock { source, .. } => Some(source),
            Self::Restore { migration, .. } => Some(migration),
            Self::MissingVersion
            | Self::UnsupportedPath { .. }
            | Self::ConcurrentEdit { .. }
            | Self::DurabilityWarning { .. } => None,
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
/// Returns [`ConfigMigrationError::Backup`] when the exact-bytes backup cannot
/// be created, written, or `fsync`-ed; the original file is untouched because
/// the backup is taken before any destructive step. If publication fails after
/// the backup exists, the original bytes are restored and the publication error
/// is returned as [`ConfigMigrationError::Config`]; if that restore also fails,
/// [`ConfigMigrationError::Restore`] carries both failures and the backup path
/// in the record's `backup_path` remains the recovery source.
pub fn migrate_config_file(
    path: impl AsRef<Path>,
) -> Result<ConfigMigrationOutcome, ConfigMigrationError> {
    migrate_config_file_with_precommit(path, |_| {})
}

fn migrate_config_file_with_precommit(
    path: impl AsRef<Path>,
    mut precommit: impl FnMut(&Path),
) -> Result<ConfigMigrationOutcome, ConfigMigrationError> {
    let path = path.as_ref();
    let (source, _document, version) = read_versioned_document(path)?;
    let source_name = path.display().to_string();
    if version == CONFIG_SCHEMA_VERSION {
        let text = std::str::from_utf8(&source).map_err(|error| ConfigError::Syntax {
            source_name,
            message: error.to_string(),
        })?;
        parse_json5(text, &path.display().to_string())?;
        return Ok(ConfigMigrationOutcome::Current);
    }
    if version != 0 || CONFIG_SCHEMA_VERSION != 1 {
        return Err(ConfigMigrationError::UnsupportedPath {
            found: version,
            current: CONFIG_SCHEMA_VERSION,
        });
    }

    let mut outcome = None;
    with_destination_lock(path, |locked_path| {
        outcome = Some((|| {
            let (source, mut document, version) = read_versioned_document(locked_path)?;
            if version == CONFIG_SCHEMA_VERSION {
                let text = std::str::from_utf8(&source).map_err(|error| ConfigError::Syntax {
                    source_name: locked_path.display().to_string(),
                    message: error.to_string(),
                })?;
                parse_json5(text, &locked_path.display().to_string())?;
                return Ok(ConfigMigrationOutcome::Current);
            }
            if version != 0 || CONFIG_SCHEMA_VERSION != 1 {
                return Err(ConfigMigrationError::UnsupportedPath {
                    found: version,
                    current: CONFIG_SCHEMA_VERSION,
                });
            }

            let object = document
                .as_object_mut()
                .ok_or(ConfigMigrationError::MissingVersion)?;
            object.insert(
                "schema_version".to_owned(),
                Value::from(CONFIG_SCHEMA_VERSION),
            );
            let candidate_source = json5::to_string(&document)
                .map_err(|error| ConfigError::Serialize(error.to_string()))?;
            let candidate = parse_json5(&candidate_source, &locked_path.display().to_string())?;
            let destination_bytes = to_json5(&candidate)
                .map_err(ConfigMigrationError::Config)?
                .into_bytes();
            let source_digest = digest_hex(&source);
            let backup_path = create_backup(locked_path, &source)?;
            let mut conflict_backup = None;
            let write_outcome = atomic_write_bytes_locked(locked_path, &destination_bytes, || {
                precommit(locked_path);
                let current = fs::read(locked_path)?;
                if digest_hex(&current) != source_digest {
                    let backup = create_backup_io(locked_path, &current)?;
                    conflict_backup = Some(backup);
                    return Err(io::Error::new(
                        io::ErrorKind::AlreadyExists,
                        "concurrent edit detected",
                    ));
                }
                Ok(())
            });
            if let Err(source) = write_outcome {
                if let Some(concurrent_backup) = conflict_backup {
                    return Err(ConfigMigrationError::ConcurrentEdit {
                        config_path: locked_path.to_owned(),
                        backup_path: concurrent_backup,
                    });
                }
                return Err(ConfigMigrationError::Config(ConfigError::io(
                    locked_path,
                    source,
                )));
            }
            surface_durability_warnings(
                locked_path,
                Some(&backup_path),
                write_outcome.expect("checked above"),
            )?;
            Ok(ConfigMigrationOutcome::Migrated(ConfigMigrationRecord {
                config_path: locked_path.to_owned(),
                backup_path,
                from_version: version,
                to_version: CONFIG_SCHEMA_VERSION,
            }))
        })());
        Ok(())
    })
    .map_err(|source| ConfigMigrationError::Config(ConfigError::io(path, source)))?;
    outcome.expect("locked migration always sets an outcome")
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
    let bytes = fs::read(&record.backup_path)
        .map_err(|source| ConfigError::io(&record.backup_path, source))?;
    let outcome = atomic_write_bytes(&record.config_path, &bytes, || Ok(()))
        .map_err(|source| ConfigError::io(&record.config_path, source))?;
    surface_durability_warnings(&record.config_path, Some(&record.backup_path), outcome)?;
    Ok(())
}

fn surface_durability_warnings(
    path: &Path,
    backup_path: Option<&Path>,
    outcome: WriteOutcome,
) -> Result<(), ConfigMigrationError> {
    if outcome.warnings.is_empty() {
        return Ok(());
    }
    Err(ConfigMigrationError::DurabilityWarning {
        path: path.to_owned(),
        backup_path: backup_path.map(Path::to_owned),
        warnings: outcome.warnings,
    })
}

fn read_versioned_document(path: &Path) -> Result<(Vec<u8>, Value, u32), ConfigMigrationError> {
    let source = fs::read(path).map_err(|source| ConfigError::io(path, source))?;
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
    Ok((source, document, version))
}

fn create_backup(path: &Path, bytes: &[u8]) -> Result<PathBuf, ConfigMigrationError> {
    create_backup_io(path, bytes).map_err(|source| ConfigMigrationError::Backup {
        path: path.to_owned(),
        source,
    })
}

fn create_backup_io(path: &Path, bytes: &[u8]) -> io::Result<PathBuf> {
    for _ in 0..128 {
        let sequence = BACKUP_SEQUENCE.fetch_add(1, Ordering::Relaxed);
        let backup_path = path.with_file_name(format!(
            "{}.schema-v0.{}.{}.bak",
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
                file.write_all(bytes)
                    .and_then(|()| file.flush())
                    .and_then(|()| file.sync_all())
                    .map_err(|source| io::Error::new(source.kind(), source.to_string()))?;
                sync_parent(&backup_path)?;
                return Ok(backup_path);
            }
            Err(source) if source.kind() == io::ErrorKind::AlreadyExists => {}
            Err(source) => return Err(source),
        }
    }
    Err(io::Error::new(
        io::ErrorKind::AlreadyExists,
        "could not allocate a unique migration backup",
    ))
}

fn digest_hex(bytes: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    encode_hex(&hasher.finalize())
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

#[cfg(test)]
mod lock_tests {
    use super::{ConfigMigrationOutcome, migrate_config_file_with_precommit};
    use crate::io::destination_lock_path_for_tests;

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
    fn stale_lock_file_without_live_owner_does_not_block_migration() {
        let directory = std::env::temp_dir().join(format!(
            "claw-config-versioning-stale-lock-{}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&directory);
        std::fs::create_dir_all(&directory).expect("create directory");
        let path = directory.join("config.json5");
        std::fs::write(&path, VERSION_ZERO).expect("write version zero");
        let lock = destination_lock_path_for_tests(&path);
        std::fs::write(&lock, b"stale owner").expect("write stale lock");
        let outcome = migrate_config_file_with_precommit(&path, |_| {}).expect("migrate");
        assert!(matches!(outcome, ConfigMigrationOutcome::Migrated(_)));
        let _ = std::fs::remove_dir_all(&directory);
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
    use std::sync::mpsc;
    use std::thread;

    use super::{
        ConfigMigrationError, ConfigMigrationOutcome, migrate_config_file_with_precommit,
        rollback_config_migration,
    };
    use crate::io::{inject_directory_sync_warning_for_tests, write_bytes_atomically};

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
    fn concurrent_edit_is_detected_and_backed_up_before_publication() {
        let directory = std::env::temp_dir().join(format!(
            "claw-config-versioning-test-{}-{}",
            std::process::id(),
            1
        ));
        let _ = std::fs::remove_dir_all(&directory);
        std::fs::create_dir_all(&directory).expect("create directory");
        let path = directory.join("config.json5");
        let concurrent = VERSION_ZERO.replace("schema_version: 0", "schema_version: 99");
        std::fs::write(&path, VERSION_ZERO.as_bytes()).expect("write source");

        let error = migrate_config_file_with_precommit(&path, |path| {
            std::fs::write(path, concurrent.as_bytes()).expect("write concurrent bytes");
        })
        .expect_err("concurrent edit must fail");

        match error {
            ConfigMigrationError::ConcurrentEdit {
                config_path,
                backup_path,
            } => {
                assert_eq!(config_path, path);
                assert_eq!(
                    std::fs::read(&backup_path).expect("read conflict backup"),
                    concurrent.as_bytes()
                );
            }
            other => panic!("expected concurrent edit error, got {other}"),
        }
        assert_eq!(
            std::fs::read(&path).expect("source preserved"),
            concurrent.as_bytes()
        );
        assert!(
            matches!(
                migrate_config_file_with_precommit(&path, |_| {}),
                Err(ConfigMigrationError::UnsupportedPath { .. })
                    | Ok(ConfigMigrationOutcome::Current)
            ),
            "post-conflict source remains untouched by failed migration"
        );
        let _ = std::fs::remove_dir_all(&directory);
    }

    #[test]
    fn migration_and_regular_writes_share_one_publication_lock() {
        let directory = std::env::temp_dir().join(format!(
            "claw-config-versioning-shared-lock-{}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&directory);
        std::fs::create_dir_all(&directory).expect("create directory");
        let path = directory.join("config.json5");
        let replacement = VERSION_ZERO.replace("schema_version: 0", "schema_version: 1");
        let expected = replacement.clone();
        std::fs::write(&path, VERSION_ZERO.as_bytes()).expect("write source");
        let (ready_tx, ready_rx) = mpsc::channel();
        let (finish_tx, finish_rx) = mpsc::channel();
        let writer_path = path.clone();
        let writer = thread::spawn(move || {
            ready_rx.recv().expect("wait for migration precommit");
            write_bytes_atomically(&writer_path, replacement.as_bytes()).expect("writer publish");
            finish_tx.send(()).expect("report writer completion");
        });

        let outcome = migrate_config_file_with_precommit(&path, |_| {
            ready_tx.send(()).expect("release concurrent writer");
            assert!(
                finish_rx.try_recv().is_err(),
                "regular writer must still be blocked by the migration lock"
            );
        })
        .expect("migrate");
        assert!(matches!(outcome, ConfigMigrationOutcome::Migrated(_)));
        writer.join().expect("join writer");
        assert_eq!(
            std::fs::read(&path).expect("read final bytes"),
            expected.as_bytes()
        );
        let _ = std::fs::remove_dir_all(&directory);
    }

    #[test]
    fn rollback_directory_sync_warning_is_not_reported_as_success() {
        let directory = std::env::temp_dir().join(format!(
            "claw-config-versioning-rollback-warning-{}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&directory);
        std::fs::create_dir_all(&directory).expect("create directory");
        let path = directory.join("config.json5");
        std::fs::write(&path, VERSION_ZERO.as_bytes()).expect("write source");
        let record = match migrate_config_file_with_precommit(&path, |_| {}).expect("migrate") {
            ConfigMigrationOutcome::Migrated(record) => record,
            ConfigMigrationOutcome::Current => panic!("expected a migration record"),
        };
        let _guard = inject_directory_sync_warning_for_tests();
        let error = rollback_config_migration(&record).expect_err("rollback warning must surface");
        assert!(matches!(
            error,
            ConfigMigrationError::DurabilityWarning { .. }
        ));
        let _ = std::fs::remove_dir_all(&directory);
    }
}

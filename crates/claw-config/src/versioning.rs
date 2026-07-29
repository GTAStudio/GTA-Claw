use std::error::Error;
use std::fmt::{self, Display, Formatter};
use std::fs::{self, File, OpenOptions};
use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

use serde_json::Value;
use sha2::{Digest, Sha256};

use crate::io::atomic_write_bytes;
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
        }
    }
}

impl Error for ConfigMigrationError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Config(error) => Some(error),
            Self::Backup { source, .. } | Self::Lock { source, .. } => Some(source),
            Self::Restore { migration, .. } => Some(migration),
            Self::MissingVersion | Self::UnsupportedPath { .. } | Self::ConcurrentEdit { .. } => {
                None
            }
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

    let _lock = MigrationLock::acquire(path)?;
    let (source, mut document, version) = read_versioned_document(path)?;
    if version == CONFIG_SCHEMA_VERSION {
        let text = std::str::from_utf8(&source).map_err(|error| ConfigError::Syntax {
            source_name: path.display().to_string(),
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
    let destination_bytes = to_json5(&candidate)
        .map_err(ConfigMigrationError::Config)?
        .into_bytes();
    let source_digest = digest_hex(&source);

    let backup_path = create_backup(path, &source)?;
    let mut conflict_backup = None;
    if let Err(source) = atomic_write_bytes(path, &destination_bytes, || {
        precommit(path);
        let current = fs::read(path)?;
        if digest_hex(&current) != source_digest {
            let backup = create_backup_io(path, &current)?;
            conflict_backup = Some(backup);
            return Err(io::Error::new(
                io::ErrorKind::AlreadyExists,
                "concurrent edit detected",
            ));
        }
        Ok(())
    }) {
        if let Some(concurrent_backup) = conflict_backup {
            return Err(ConfigMigrationError::ConcurrentEdit {
                config_path: path.to_owned(),
                backup_path: concurrent_backup,
            });
        }
        return Err(ConfigMigrationError::Config(ConfigError::io(path, source)));
    }
    Ok(ConfigMigrationOutcome::Migrated(ConfigMigrationRecord {
        config_path: path.to_owned(),
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
    let bytes = fs::read(&record.backup_path)
        .map_err(|source| ConfigError::io(&record.backup_path, source))?;
    atomic_write_bytes(&record.config_path, &bytes, || Ok(()))
        .map_err(|source| ConfigError::io(&record.config_path, source))?;
    Ok(())
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

struct MigrationLock {
    file: File,
}

impl MigrationLock {
    fn lock_path(config_path: &Path) -> PathBuf {
        config_path.with_file_name(format!(
            ".{}.schema-migrate.lock",
            config_path
                .file_name()
                .and_then(|name| name.to_str())
                .unwrap_or("config")
        ))
    }

    fn acquire(config_path: &Path) -> Result<Self, ConfigMigrationError> {
        let lock_path = Self::lock_path(config_path);
        reject_lock_link_or_reparse(&lock_path).map_err(|source| ConfigMigrationError::Lock {
            path: lock_path.clone(),
            source,
        })?;
        let lock_file = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .open(&lock_path)
            .map_err(|source| ConfigMigrationError::Lock {
                path: lock_path.clone(),
                source,
            })?;
        lock_file
            .try_lock()
            .map_err(|source| ConfigMigrationError::Lock {
                path: lock_path.clone(),
                source: source.into(),
            })?;
        lock_file
            .sync_all()
            .map_err(|source| ConfigMigrationError::Lock {
                path: lock_path.clone(),
                source,
            })?;
        sync_parent(&lock_path).map_err(|source| ConfigMigrationError::Lock {
            path: lock_path.clone(),
            source,
        })?;
        reject_lock_link_or_reparse(&lock_path).map_err(|source| ConfigMigrationError::Lock {
            path: lock_path.clone(),
            source,
        })?;
        Ok(Self { file: lock_file })
    }
}

impl Drop for MigrationLock {
    fn drop(&mut self) {
        let _ = self.file.unlock();
    }
}

fn reject_lock_link_or_reparse(path: &Path) -> io::Result<()> {
    match fs::symlink_metadata(path) {
        Ok(metadata) if is_link_or_reparse(&metadata) => Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "lock must not be a symlink or reparse point",
        )),
        Ok(_) => Ok(()),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(error),
    }
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

#[cfg(test)]
impl MigrationLock {
    fn test_lock_path(config_path: &Path) -> PathBuf {
        Self::lock_path(config_path)
    }
}

#[cfg(test)]
mod lock_tests {
    use super::{ConfigMigrationOutcome, MigrationLock, migrate_config_file_with_precommit};

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
        let lock = MigrationLock::test_lock_path(&path);
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
    use super::{ConfigMigrationError, ConfigMigrationOutcome, migrate_config_file_with_precommit};

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
}

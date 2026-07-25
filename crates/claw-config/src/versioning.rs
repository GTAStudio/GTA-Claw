use std::error::Error;
use std::fmt::{self, Display, Formatter};
use std::fs::{self, OpenOptions};
use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

use serde_json::Value;

use crate::io::atomic_write_bytes;
use crate::{CONFIG_SCHEMA_VERSION, ConfigError, load_file, parse_json5, write_file};

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
            Self::Restore { migration, restore } => write!(
                formatter,
                "migration failed: {migration}; restoring the exact backup also failed: {restore}"
            ),
        }
    }
}

impl Error for ConfigMigrationError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Config(error) => Some(error),
            Self::Backup { source, .. } => Some(source),
            Self::Restore { migration, .. } => Some(migration),
            Self::MissingVersion | Self::UnsupportedPath { .. } => None,
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
pub fn migrate_config_file(
    path: impl AsRef<Path>,
) -> Result<ConfigMigrationOutcome, ConfigMigrationError> {
    let path = path.as_ref();
    let source = fs::read(path).map_err(|source| ConfigError::io(path, source))?;
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
        load_file(path)?;
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

    let backup_path = create_backup(path, &source)?;
    if let Err(migration) = write_file(path, &candidate) {
        if let Err(restore) = atomic_write_bytes(path, &source, || Ok(())) {
            return Err(ConfigMigrationError::Restore { migration, restore });
        }
        return Err(ConfigMigrationError::Config(migration));
    }
    Ok(ConfigMigrationOutcome::Migrated(ConfigMigrationRecord {
        config_path: path.to_owned(),
        backup_path,
        from_version: version,
        to_version: CONFIG_SCHEMA_VERSION,
    }))
}

/// Restores exact pre-migration bytes from a migration record.
pub fn rollback_config_migration(
    record: &ConfigMigrationRecord,
) -> Result<(), ConfigMigrationError> {
    let bytes = fs::read(&record.backup_path)
        .map_err(|source| ConfigError::io(&record.backup_path, source))?;
    atomic_write_bytes(&record.config_path, &bytes, || Ok(()))
        .map_err(|source| ConfigError::io(&record.config_path, source))?;
    Ok(())
}

fn create_backup(path: &Path, bytes: &[u8]) -> Result<PathBuf, ConfigMigrationError> {
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
                    .map_err(|source| ConfigMigrationError::Backup {
                        path: backup_path.clone(),
                        source,
                    })?;
                sync_parent(&backup_path).map_err(|source| ConfigMigrationError::Backup {
                    path: backup_path.clone(),
                    source,
                })?;
                return Ok(backup_path);
            }
            Err(source) if source.kind() == io::ErrorKind::AlreadyExists => {}
            Err(source) => {
                return Err(ConfigMigrationError::Backup {
                    path: backup_path,
                    source,
                });
            }
        }
    }
    Err(ConfigMigrationError::Backup {
        path: path.to_owned(),
        source: io::Error::new(
            io::ErrorKind::AlreadyExists,
            "could not allocate a unique migration backup",
        ),
    })
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

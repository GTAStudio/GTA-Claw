use std::fs::{self, OpenOptions};
use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

use claw_config::{ConfigError, ConfigSnapshot, load_file, write_file};

use crate::setup::{read_optional_file, restore_paths};
use crate::state::{CrestodianState, ensure_parent_directory, read_state, write_state};
use crate::{CRESTODIAN_STATE_SCHEMA_VERSION, CrestodianError};

static RECOVERY_SEQUENCE: AtomicU64 = AtomicU64::new(0);

/// Health of the strict configuration file.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ConfigCondition {
    /// No file exists.
    Missing,
    /// The file parses and validates.
    Healthy,
    /// Bytes are malformed, truncated, unreadable, or semantically invalid.
    Corrupt {
        /// Actionable parser, path, or I/O diagnostic.
        diagnostic: String,
    },
    /// The envelope schema is newer or otherwise unsupported.
    Incompatible {
        /// Version found in the file.
        found: u32,
        /// Version supported by this build.
        supported: u32,
    },
}

/// Health of Crestodian auxiliary state.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum StateCondition {
    /// No state file exists.
    Missing,
    /// State is structurally valid and current.
    Healthy,
    /// State bytes are malformed, truncated, unreadable, or invalid.
    Corrupt {
        /// Actionable parser, path, or I/O diagnostic.
        diagnostic: String,
    },
    /// State uses a different schema version.
    Incompatible {
        /// Version found in the state.
        found: u32,
        /// Version supported by this build.
        supported: u32,
    },
}

/// Pre-recovery health assessment.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RecoveryAssessment {
    /// Configuration condition.
    pub config: ConfigCondition,
    /// Auxiliary-state condition.
    pub state: StateCondition,
}

/// One recovery mutation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum RecoveryAction {
    /// Existing healthy bytes were not touched.
    Unchanged,
    /// A missing file was created from the known-good baseline.
    Created,
    /// Invalid bytes were replaced after exact backup.
    Replaced {
        /// Backup containing the invalid original bytes.
        backup_path: PathBuf,
    },
}

/// Successful backup-first recovery.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RecoveryReport {
    /// Health observed before any mutation.
    pub before: RecoveryAssessment,
    /// Configuration mutation.
    pub config_action: RecoveryAction,
    /// State mutation.
    pub state_action: RecoveryAction,
    /// Durable directory retaining all recovery evidence.
    pub backup_directory: Option<PathBuf>,
    /// Backups of orphaned atomic-write temporary files.
    pub interrupted_artifact_backups: Vec<PathBuf>,
}

/// Setup and recovery owner for caller-selected paths.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Crestodian {
    config_path: PathBuf,
    state_path: PathBuf,
}

impl Crestodian {
    /// Creates a Crestodian instance without consulting real user directories.
    #[must_use]
    pub fn new(config_path: impl Into<PathBuf>, state_path: impl Into<PathBuf>) -> Self {
        Self {
            config_path: config_path.into(),
            state_path: state_path.into(),
        }
    }

    /// Diagnoses missing, corrupt, interrupted, and incompatible files.
    #[must_use]
    pub fn inspect(&self) -> RecoveryAssessment {
        RecoveryAssessment {
            config: inspect_config(&self.config_path),
            state: inspect_state(&self.state_path),
        }
    }

    /// Repairs invalid or missing files from a caller-provided known-good config.
    ///
    /// Original bytes and orphaned atomic-write artifacts are copied and flushed
    /// before any replacement. If a later write fails, every earlier mutation is
    /// restored to its exact original bytes.
    pub fn recover(
        &self,
        baseline: &ConfigSnapshot,
        unix_millis: u64,
    ) -> Result<RecoveryReport, CrestodianError> {
        let before = self.inspect();
        let repair_config = !matches!(before.config, ConfigCondition::Healthy);
        let repair_state = !matches!(before.state, StateCondition::Healthy);
        if !repair_config && !repair_state {
            return Ok(RecoveryReport {
                before,
                config_action: RecoveryAction::Unchanged,
                state_action: RecoveryAction::Unchanged,
                backup_directory: None,
                interrupted_artifact_backups: Vec::new(),
            });
        }

        let original_config = if repair_config {
            read_recoverable_file(&self.config_path)?
        } else {
            None
        };
        let original_state = if repair_state {
            read_recoverable_file(&self.state_path)?
        } else {
            None
        };
        let backup_directory = create_backup_directory(&self.config_path)?;
        let config_backup = original_config
            .as_deref()
            .map(|bytes| backup_bytes(&backup_directory, "config.original", bytes))
            .transpose()?;
        let state_backup = original_state
            .as_deref()
            .map(|bytes| backup_bytes(&backup_directory, "state.original", bytes))
            .transpose()?;
        let interrupted_artifact_backups =
            backup_interrupted_artifacts(&self.config_path, &backup_directory)?;

        let config_action = action(original_config.as_ref(), config_backup);
        let state_action = action(original_state.as_ref(), state_backup);
        let mut config_mutated = false;
        if repair_config {
            ensure_parent_directory(&self.config_path)?;
            write_file(&self.config_path, baseline)?;
            config_mutated = true;
        }
        if repair_state {
            let state = CrestodianState {
                last_recovery_unix_ms: Some(unix_millis),
                ..CrestodianState::default()
            };
            if let Err(operation) = write_state(&self.state_path, &state) {
                let mut restore_failures = Vec::new();
                if config_mutated {
                    restore_failures.extend(restore_paths([(
                        self.config_path.as_path(),
                        original_config.as_deref(),
                    )]));
                }
                restore_failures.extend(restore_paths([(
                    self.state_path.as_path(),
                    original_state.as_deref(),
                )]));
                if restore_failures.is_empty() {
                    return Err(operation);
                }
                return Err(CrestodianError::Rollback {
                    operation: Box::new(operation),
                    restore_failures,
                });
            }
        }
        Ok(RecoveryReport {
            before,
            config_action: if repair_config {
                config_action
            } else {
                RecoveryAction::Unchanged
            },
            state_action: if repair_state {
                state_action
            } else {
                RecoveryAction::Unchanged
            },
            backup_directory: Some(backup_directory),
            interrupted_artifact_backups,
        })
    }
}

fn inspect_config(path: &Path) -> ConfigCondition {
    match load_file(path) {
        Ok(_) => ConfigCondition::Healthy,
        Err(ConfigError::Io { source, .. }) if source.kind() == io::ErrorKind::NotFound => {
            ConfigCondition::Missing
        }
        Err(ConfigError::UnsupportedVersion { found, supported }) => {
            ConfigCondition::Incompatible { found, supported }
        }
        Err(error) => ConfigCondition::Corrupt {
            diagnostic: error.to_string(),
        },
    }
}

fn inspect_state(path: &Path) -> StateCondition {
    match read_state(path) {
        Ok(state) if state.schema_version == CRESTODIAN_STATE_SCHEMA_VERSION => {
            StateCondition::Healthy
        }
        Ok(state) => StateCondition::Incompatible {
            found: state.schema_version,
            supported: CRESTODIAN_STATE_SCHEMA_VERSION,
        },
        Err(CrestodianError::Io { source, .. })
            if source.kind() == io::ErrorKind::NotFound
                || source.kind() == io::ErrorKind::NotADirectory =>
        {
            StateCondition::Missing
        }
        Err(error) => StateCondition::Corrupt {
            diagnostic: error.to_string(),
        },
    }
}

fn read_recoverable_file(path: &Path) -> Result<Option<Vec<u8>>, CrestodianError> {
    match fs::metadata(path) {
        Ok(metadata) if metadata.is_file() => read_optional_file(path),
        Ok(_) => Err(CrestodianError::UnsafePath {
            path: path.to_owned(),
            message: "recovery target must be a regular file",
        }),
        Err(source)
            if source.kind() == io::ErrorKind::NotFound
                || source.kind() == io::ErrorKind::NotADirectory =>
        {
            Ok(None)
        }
        Err(source) => Err(CrestodianError::io(path, source)),
    }
}

fn create_backup_directory(config_path: &Path) -> Result<PathBuf, CrestodianError> {
    ensure_parent_directory(config_path)?;
    let parent = config_path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    for _ in 0..128 {
        let sequence = RECOVERY_SEQUENCE.fetch_add(1, Ordering::Relaxed);
        let path = parent.join(format!(
            ".crestodian-recovery-{}-{sequence}",
            std::process::id()
        ));
        match fs::create_dir(&path) {
            Ok(()) => {
                sync_directory(parent)?;
                return Ok(path);
            }
            Err(source) if source.kind() == io::ErrorKind::AlreadyExists => {}
            Err(source) => return Err(CrestodianError::io(path, source)),
        }
    }
    Err(CrestodianError::io(
        parent,
        io::Error::new(
            io::ErrorKind::AlreadyExists,
            "could not allocate a unique recovery directory",
        ),
    ))
}

fn backup_bytes(directory: &Path, name: &str, bytes: &[u8]) -> Result<PathBuf, CrestodianError> {
    let path = directory.join(name);
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&path)
        .map_err(|source| CrestodianError::io(&path, source))?;
    file.write_all(bytes)
        .and_then(|()| file.flush())
        .and_then(|()| file.sync_all())
        .map_err(|source| CrestodianError::io(&path, source))?;
    sync_directory(directory)?;
    Ok(path)
}

fn backup_interrupted_artifacts(
    config_path: &Path,
    backup_directory: &Path,
) -> Result<Vec<PathBuf>, CrestodianError> {
    let parent = config_path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    let file_name = config_path
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or("config");
    let prefix = format!(".{file_name}.gta-claw.tmp.");
    let mut sources = fs::read_dir(parent)
        .map_err(|source| CrestodianError::io(parent, source))?
        .collect::<Result<Vec<_>, _>>()
        .map_err(|source| CrestodianError::io(parent, source))?;
    sources.sort_by_key(|entry| entry.file_name());
    let mut backups = Vec::new();
    for (index, entry) in sources.into_iter().enumerate() {
        let name = entry.file_name();
        let Some(name_text) = name.to_str() else {
            continue;
        };
        if !name_text.starts_with(&prefix)
            || !entry
                .file_type()
                .map_err(|source| CrestodianError::io(entry.path(), source))?
                .is_file()
        {
            continue;
        }
        let bytes =
            fs::read(entry.path()).map_err(|source| CrestodianError::io(entry.path(), source))?;
        backups.push(backup_bytes(
            backup_directory,
            &format!("interrupted-{index}-{name_text}"),
            &bytes,
        )?);
    }
    Ok(backups)
}

fn action(original: Option<&Vec<u8>>, backup: Option<PathBuf>) -> RecoveryAction {
    match (original, backup) {
        (None, None) => RecoveryAction::Created,
        (Some(_), Some(backup_path)) => RecoveryAction::Replaced { backup_path },
        _ => unreachable!("backup state follows original file presence"),
    }
}

#[cfg(unix)]
fn sync_directory(path: &Path) -> Result<(), CrestodianError> {
    fs::File::open(path)
        .and_then(|directory| directory.sync_all())
        .map_err(|source| CrestodianError::io(path, source))
}

#[cfg(not(unix))]
fn sync_directory(_path: &Path) -> Result<(), CrestodianError> {
    Ok(())
}

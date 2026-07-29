use std::fs::{self, OpenOptions};
use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

use claw_config::{ConfigError, ConfigSnapshot, WriteWarning, parse_json5, write_file};

use crate::setup::{read_optional_file, restore_paths};
use crate::state::{
    CrestodianState, decode_state, ensure_parent_directory, inspect_state_schema_version,
    write_state,
};
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

/// Operator-facing next step derived from a recovery assessment.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RecoveryGuidance {
    /// Both files are healthy.
    NoAction,
    /// Neither file exists, so guided first-run setup is the clearest path.
    RunGuidedSetup,
    /// Corrupt or partially missing state can be rebuilt from a known-good config.
    RecoverFromBaseline,
    /// A newer schema must be handled by a compatible build rather than overwritten.
    UseCompatibleBuild,
}

impl RecoveryAssessment {
    /// Returns the safest operator action for this assessment.
    #[must_use]
    pub const fn guidance(&self) -> RecoveryGuidance {
        if matches!(self.config, ConfigCondition::Incompatible { .. })
            || matches!(self.state, StateCondition::Incompatible { .. })
        {
            RecoveryGuidance::UseCompatibleBuild
        } else if matches!(self.config, ConfigCondition::Healthy)
            && matches!(self.state, StateCondition::Healthy)
        {
            RecoveryGuidance::NoAction
        } else if matches!(self.config, ConfigCondition::Missing)
            && matches!(self.state, StateCondition::Missing)
        {
            RecoveryGuidance::RunGuidedSetup
        } else {
            RecoveryGuidance::RecoverFromBaseline
        }
    }
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
    /// Non-fatal atomic-write warnings raised while republishing.
    ///
    /// A [`WriteWarning::DirectorySyncFailed`] here means a replacement was
    /// published by rename but its directory entry could not be synchronized,
    /// so recovery completed without being able to promise the result survives
    /// a power cut. It is reported rather than swallowed because the caller is
    /// the only one that can decide whether that is acceptable.
    pub warnings: Vec<WriteWarning>,
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
    ///
    /// A successful recovery still reports every non-fatal atomic-write warning
    /// in [`RecoveryReport::warnings`], so a directory that could not be synced
    /// is visible to the caller instead of being swallowed by the success.
    ///
    /// # Errors
    ///
    /// Returns [`CrestodianError::UnsafePath`] when the configuration or state
    /// path exists but is not a regular file, and [`CrestodianError::Io`] when
    /// no unique recovery directory can be allocated, an original file or an
    /// orphaned atomic-write artifact cannot be read, or a backup cannot be
    /// written, `fsync`-ed, and published into a synced directory. Returns
    /// [`CrestodianError::Config`] when the baseline itself cannot be written
    /// atomically. If the state write fails after the configuration was already
    /// replaced, both files are restored to their exact original bytes and the
    /// original failure is returned as-is, or wrapped in
    /// [`CrestodianError::Rollback`] listing every restoration that also failed.
    /// Nothing is ever replaced before its backup is durable.
    pub fn recover(
        &self,
        baseline: &ConfigSnapshot,
        unix_millis: u64,
    ) -> Result<RecoveryReport, CrestodianError> {
        let original_config = read_recoverable_file(&self.config_path)?;
        let original_state = read_recoverable_file(&self.state_path)?;
        let before = RecoveryAssessment {
            config: inspect_config_bytes(&self.config_path, original_config.as_deref()),
            state: inspect_state_bytes(&self.state_path, original_state.as_deref()),
        };
        if let ConfigCondition::Incompatible { found, supported } = before.config {
            return Err(CrestodianError::IncompatibleRecoverySchema {
                path: self.config_path.clone(),
                found,
                supported,
            });
        }
        if let StateCondition::Incompatible { found, supported } = before.state {
            return Err(CrestodianError::IncompatibleRecoverySchema {
                path: self.state_path.clone(),
                found,
                supported,
            });
        }
        let repair_config = !matches!(before.config, ConfigCondition::Healthy);
        let repair_state = !matches!(before.state, StateCondition::Healthy);
        if !repair_config && !repair_state {
            return Ok(RecoveryReport {
                before,
                config_action: RecoveryAction::Unchanged,
                state_action: RecoveryAction::Unchanged,
                backup_directory: None,
                interrupted_artifact_backups: Vec::new(),
                warnings: Vec::new(),
            });
        }

        let interrupted_artifacts = read_interrupted_artifacts(&self.config_path)?;
        let needs_backup = repair_config && original_config.is_some()
            || repair_state && original_state.is_some()
            || !interrupted_artifacts.is_empty();
        let backup_directory = needs_backup
            .then(|| create_backup_directory(&self.config_path))
            .transpose()?;
        let config_backup = match (&backup_directory, repair_config) {
            (Some(directory), true) => original_config
                .as_deref()
                .map(|bytes| backup_bytes(directory, "config.original", bytes))
                .transpose()?,
            _ => None,
        };
        let state_backup = match (&backup_directory, repair_state) {
            (Some(directory), true) => original_state
                .as_deref()
                .map(|bytes| backup_bytes(directory, "state.original", bytes))
                .transpose()?,
            _ => None,
        };
        let interrupted_artifact_backups = match &backup_directory {
            Some(directory) => backup_interrupted_artifacts(&interrupted_artifacts, directory)?,
            None => Vec::new(),
        };

        let config_action = action(config_backup);
        let state_action = action(state_backup);
        let mut warnings = Vec::new();
        let config_mutated = if repair_config {
            ensure_parent_directory(&self.config_path)?;
            warnings.extend(write_file(&self.config_path, baseline)?.warnings);
            true
        } else {
            false
        };
        if repair_state {
            let state = CrestodianState {
                last_recovery_unix_ms: Some(unix_millis),
                ..CrestodianState::default()
            };
            match write_state(&self.state_path, &state) {
                Ok(outcome) => warnings.extend(outcome.warnings),
                Err(operation) => {
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
            backup_directory,
            interrupted_artifact_backups,
            warnings,
        })
    }
}

fn inspect_config(path: &Path) -> ConfigCondition {
    match read_recoverable_file(path) {
        Ok(bytes) => inspect_config_bytes(path, bytes.as_deref()),
        Err(error) => ConfigCondition::Corrupt {
            diagnostic: error.to_string(),
        },
    }
}

fn inspect_config_bytes(path: &Path, bytes: Option<&[u8]>) -> ConfigCondition {
    let Some(bytes) = bytes else {
        return ConfigCondition::Missing;
    };
    let source = match std::str::from_utf8(bytes) {
        Ok(source) => source,
        Err(error) => {
            return ConfigCondition::Corrupt {
                diagnostic: format!("{}: invalid UTF-8: {error}", path.display()),
            };
        }
    };
    if let Ok(document) = json5::from_str::<serde_json::Value>(source)
        && let Some(found) = document
            .get("schema_version")
            .and_then(serde_json::Value::as_u64)
            .and_then(|value| u32::try_from(value).ok())
        && found != claw_config::CONFIG_SCHEMA_VERSION
    {
        return ConfigCondition::Incompatible {
            found,
            supported: claw_config::CONFIG_SCHEMA_VERSION,
        };
    }
    match parse_json5(source, &path.display().to_string()) {
        Ok(_) => ConfigCondition::Healthy,
        Err(ConfigError::UnsupportedVersion { found, supported }) => {
            ConfigCondition::Incompatible { found, supported }
        }
        Err(error) => ConfigCondition::Corrupt {
            diagnostic: error.to_string(),
        },
    }
}

fn inspect_state(path: &Path) -> StateCondition {
    match read_recoverable_file(path) {
        Ok(bytes) => inspect_state_bytes(path, bytes.as_deref()),
        Err(error) => StateCondition::Corrupt {
            diagnostic: error.to_string(),
        },
    }
}

fn inspect_state_bytes(path: &Path, bytes: Option<&[u8]>) -> StateCondition {
    let Some(bytes) = bytes else {
        return StateCondition::Missing;
    };
    match inspect_state_schema_version(path, bytes) {
        Ok(found) if found != CRESTODIAN_STATE_SCHEMA_VERSION => {
            return StateCondition::Incompatible {
                found,
                supported: CRESTODIAN_STATE_SCHEMA_VERSION,
            };
        }
        Ok(_) => {}
        Err(error) => {
            return StateCondition::Corrupt {
                diagnostic: error.to_string(),
            };
        }
    }
    match decode_state(path, bytes) {
        Ok(state) if state.schema_version == CRESTODIAN_STATE_SCHEMA_VERSION => {
            StateCondition::Healthy
        }
        Ok(state) => StateCondition::Incompatible {
            found: state.schema_version,
            supported: CRESTODIAN_STATE_SCHEMA_VERSION,
        },
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

fn read_interrupted_artifacts(
    config_path: &Path,
) -> Result<Vec<(String, Vec<u8>)>, CrestodianError> {
    let parent = config_path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    let file_name = config_path
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or("config");
    let prefix = format!(".{file_name}.gta-claw.tmp.");
    let mut sources = match fs::read_dir(parent) {
        Ok(sources) => sources
            .collect::<Result<Vec<_>, _>>()
            .map_err(|source| CrestodianError::io(parent, source))?,
        Err(source) if source.kind() == io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(source) => return Err(CrestodianError::io(parent, source)),
    };
    sources.sort_by_key(fs::DirEntry::file_name);
    let mut artifacts = Vec::new();
    for entry in sources {
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
        artifacts.push((name_text.to_owned(), bytes));
    }
    Ok(artifacts)
}

fn backup_interrupted_artifacts(
    artifacts: &[(String, Vec<u8>)],
    backup_directory: &Path,
) -> Result<Vec<PathBuf>, CrestodianError> {
    let mut backups = Vec::new();
    for (index, (name, bytes)) in artifacts.iter().enumerate() {
        backups.push(backup_bytes(
            backup_directory,
            &format!("interrupted-{index}-{name}"),
            bytes,
        )?);
    }
    Ok(backups)
}

/// Classifies one recovered path from the backup its original bytes produced.
///
/// A backup exists exactly when the path held bytes worth preserving, so the
/// backup alone decides between a creation and a replacement. Deriving the
/// action from one value keeps the two from ever disagreeing.
fn action(backup: Option<PathBuf>) -> RecoveryAction {
    backup.map_or(RecoveryAction::Created, |backup_path| {
        RecoveryAction::Replaced { backup_path }
    })
}

/// Flushes a directory entry through the same primitive the atomic writer uses.
///
/// The operating-system failure is reported rather than swallowed, on every
/// platform. A rescue that could not make its directory entry durable has not
/// finished, and saying otherwise would be a claim the filesystem never made.
fn sync_directory(path: &Path) -> Result<(), CrestodianError> {
    claw_config::sync_directory(path).map_err(CrestodianError::Config)
}

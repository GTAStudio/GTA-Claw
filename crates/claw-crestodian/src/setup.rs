use std::fs;
use std::path::{Path, PathBuf};

use claw_config::{
    ConfigSnapshot, SecretRef, WriteWarning, migrate_legacy_environment, write_bytes_atomically,
    write_file,
};

use crate::CrestodianError;
use crate::error::RestoreFailure;
use crate::state::{CrestodianState, ensure_parent_directory, write_state};

/// Stable guided setup field.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SetupField {
    /// Environment variable containing a GitHub token.
    GithubTokenEnvironment,
    /// Absolute role source URL.
    RoleSourceUrl,
    /// Optional workspace path.
    Workspace,
    /// Whether Microsoft Teams should be enabled.
    EnableTeams,
    /// Teams application identifier.
    TeamsAppId,
    /// Environment variable containing the Teams application password.
    TeamsPasswordEnvironment,
}

/// Machine-readable validation guidance for one setup answer.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SetupConstraint {
    /// The answer must exactly match this frozen value.
    Exact(&'static str),
    /// The answer must be an absolute HTTP(S) URL.
    AbsoluteHttpUrl,
    /// The answer is an optional filesystem path.
    OptionalPath,
    /// The answer is a boolean choice.
    Boolean,
    /// The answer is required when another boolean field is enabled.
    RequiredWhen(SetupField),
    /// The answer must match a frozen value when another field is enabled.
    ExactWhen {
        /// Required value.
        value: &'static str,
        /// Enabling field.
        field: SetupField,
    },
}

/// One deterministic guided setup prompt.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SetupQuestion {
    /// Stable field receiving the answer.
    pub field: SetupField,
    /// Operator-facing prompt.
    pub prompt: &'static str,
    /// Whether setup requires an answer.
    pub required: bool,
    /// Whether the answer itself contains secret bytes.
    pub secret: bool,
    /// Constraint a UI can enforce before submitting the complete answer set.
    pub constraint: SetupConstraint,
}

/// Typed answers accepted by first-run setup.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SetupAnswers {
    /// Name of the environment variable holding the GitHub token.
    pub github_token_environment: String,
    /// Absolute HTTP(S) role source.
    pub role_source_url: String,
    /// Optional initial workspace.
    pub workspace: Option<PathBuf>,
    /// Whether Microsoft Teams is enabled.
    pub enable_teams: bool,
    /// Teams application identifier when Teams is enabled.
    pub teams_app_id: Option<String>,
    /// Canonical Teams password environment variable when Teams is enabled.
    pub teams_password_environment: Option<String>,
}

/// Successful first-run setup publication.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SetupReport {
    /// Newly validated configuration.
    pub config: ConfigSnapshot,
    /// Persisted auxiliary state.
    pub state: CrestodianState,
    /// Non-fatal atomic-write warnings.
    pub warnings: Vec<WriteWarning>,
}

/// Backup-safe guided first-run setup flow.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GuidedSetup {
    config_path: PathBuf,
    state_path: PathBuf,
}

impl GuidedSetup {
    /// Creates a setup flow using only caller-selected paths.
    #[must_use]
    pub fn new(config_path: impl Into<PathBuf>, state_path: impl Into<PathBuf>) -> Self {
        Self {
            config_path: config_path.into(),
            state_path: state_path.into(),
        }
    }

    /// Returns the closed prompt sequence.
    #[must_use]
    pub const fn questions() -> [SetupQuestion; 6] {
        [
            SetupQuestion {
                field: SetupField::GithubTokenEnvironment,
                prompt: "GitHub token environment variable",
                required: true,
                secret: false,
                constraint: SetupConstraint::Exact("GITHUB_TOKEN"),
            },
            SetupQuestion {
                field: SetupField::RoleSourceUrl,
                prompt: "Role source URL",
                required: true,
                secret: false,
                constraint: SetupConstraint::AbsoluteHttpUrl,
            },
            SetupQuestion {
                field: SetupField::Workspace,
                prompt: "Initial workspace",
                required: false,
                secret: false,
                constraint: SetupConstraint::OptionalPath,
            },
            SetupQuestion {
                field: SetupField::EnableTeams,
                prompt: "Enable Microsoft Teams",
                required: true,
                secret: false,
                constraint: SetupConstraint::Boolean,
            },
            SetupQuestion {
                field: SetupField::TeamsAppId,
                prompt: "Microsoft Teams application ID",
                required: false,
                secret: false,
                constraint: SetupConstraint::RequiredWhen(SetupField::EnableTeams),
            },
            SetupQuestion {
                field: SetupField::TeamsPasswordEnvironment,
                prompt: "Microsoft Teams password environment variable",
                required: false,
                secret: false,
                constraint: SetupConstraint::ExactWhen {
                    value: "MicrosoftAppPassword",
                    field: SetupField::EnableTeams,
                },
            },
        ]
    }

    /// Validates answers and transactionally publishes config then state.
    ///
    /// An empty existing config is considered interrupted first-run state and is
    /// restored exactly if publishing auxiliary state fails.
    ///
    /// # Errors
    ///
    /// Returns [`CrestodianError::AlreadyConfigured`] when the configuration
    /// path already holds non-empty bytes, so setup never overwrites an
    /// authored configuration. Returns [`CrestodianError::InvalidAnswer`],
    /// naming the field, for a GitHub token variable that is not a valid
    /// environment name or is not the frozen `GITHUB_TOKEN`, an empty role
    /// source URL, an empty workspace, a missing Teams application ID while
    /// Teams is enabled, a Teams password variable other than
    /// `MicrosoftAppPassword`, or answers the legacy environment migration
    /// itself refuses. Returns [`CrestodianError::Io`] when an existing file
    /// cannot be read or a parent directory cannot be created, and
    /// [`CrestodianError::Config`] when the configuration cannot be written
    /// atomically. If the state write fails after the configuration was already
    /// published, both paths are restored to their exact previous bytes and the
    /// original failure is returned as-is, or wrapped in
    /// [`CrestodianError::Rollback`] listing every restoration that also failed.
    pub fn apply(&self, answers: &SetupAnswers) -> Result<SetupReport, CrestodianError> {
        let previous_config = read_optional_file(&self.config_path)?;
        if previous_config
            .as_ref()
            .is_some_and(|bytes| !bytes.is_empty())
        {
            return Err(CrestodianError::AlreadyConfigured(self.config_path.clone()));
        }
        let previous_state = read_optional_file(&self.state_path)?;
        SecretRef::environment(&answers.github_token_environment).map_err(|message| {
            CrestodianError::InvalidAnswer {
                field: "github_token_environment",
                message: message.to_owned(),
            }
        })?;
        if answers.github_token_environment != "GITHUB_TOKEN" {
            return Err(CrestodianError::InvalidAnswer {
                field: "github_token_environment",
                message: "the frozen legacy contract requires GITHUB_TOKEN".to_owned(),
            });
        }
        if answers.role_source_url.trim().is_empty() {
            return Err(CrestodianError::InvalidAnswer {
                field: "role_source_url",
                message: "must not be empty".to_owned(),
            });
        }
        if answers
            .workspace
            .as_ref()
            .is_some_and(|path| path.as_os_str().is_empty())
        {
            return Err(CrestodianError::InvalidAnswer {
                field: "workspace",
                message: "must not be empty".to_owned(),
            });
        }
        let teams = if answers.enable_teams {
            "true"
        } else {
            "false"
        };
        if answers.enable_teams
            && answers
                .teams_app_id
                .as_ref()
                .is_none_or(|value| value.trim().is_empty())
        {
            return Err(CrestodianError::InvalidAnswer {
                field: "teams_app_id",
                message: "is required when Microsoft Teams is enabled".to_owned(),
            });
        }
        if answers.enable_teams
            && answers.teams_password_environment.as_deref() != Some("MicrosoftAppPassword")
        {
            return Err(CrestodianError::InvalidAnswer {
                field: "teams_password_environment",
                message: "the frozen legacy contract requires MicrosoftAppPassword".to_owned(),
            });
        }
        let mut environment = vec![
            ("GITHUB_TOKEN", "__present_in_platform_environment__"),
            ("AGENT_ROLE_URL", answers.role_source_url.as_str()),
            ("ENABLE_TEAMS", teams),
        ];
        if answers.enable_teams {
            if let Some(app_id) = answers.teams_app_id.as_deref() {
                environment.push(("MicrosoftAppId", app_id));
            }
            environment.push((
                "MicrosoftAppPassword",
                "__present_in_platform_environment__",
            ));
        }
        let migrated = migrate_legacy_environment(environment).map_err(|error| {
            CrestodianError::InvalidAnswer {
                field: "configuration",
                message: error.to_string(),
            }
        })?;

        ensure_parent_directory(&self.config_path)?;
        let mut warnings = write_file(&self.config_path, &migrated.config)?.warnings;
        let state = CrestodianState {
            schema_version: crate::CRESTODIAN_STATE_SCHEMA_VERSION,
            setup_completed: true,
            workspace: answers.workspace.clone(),
            last_recovery_unix_ms: None,
        };
        match write_state(&self.state_path, &state) {
            Ok(outcome) => warnings.extend(outcome.warnings),
            Err(operation) => {
                let restore_failures = restore_paths([
                    (&self.config_path, previous_config.as_deref()),
                    (&self.state_path, previous_state.as_deref()),
                ]);
                if restore_failures.is_empty() {
                    return Err(operation);
                }
                return Err(CrestodianError::Rollback {
                    operation: Box::new(operation),
                    restore_failures,
                });
            }
        }
        Ok(SetupReport {
            config: migrated.config,
            state,
            warnings,
        })
    }
}

pub(crate) fn read_optional_file(path: &Path) -> Result<Option<Vec<u8>>, CrestodianError> {
    match fs::read(path) {
        Ok(bytes) => Ok(Some(bytes)),
        Err(source)
            if matches!(
                source.kind(),
                std::io::ErrorKind::NotFound | std::io::ErrorKind::NotADirectory
            ) =>
        {
            Ok(None)
        }
        Err(source) => Err(CrestodianError::io(path, source)),
    }
}

pub(crate) fn restore_paths<const N: usize>(
    paths: [(&Path, Option<&[u8]>); N],
) -> Vec<RestoreFailure> {
    let mut failures = Vec::new();
    for (path, original) in paths {
        if let Err(message) = restore_path(path, original) {
            failures.push(RestoreFailure {
                path: path.to_owned(),
                message,
            });
        }
    }
    failures
}

/// Puts one path back exactly as it was, byte for byte or absent.
///
fn restore_path(path: &Path, original: Option<&[u8]>) -> Result<(), String> {
    let Some(bytes) = original else {
        let metadata = match fs::symlink_metadata(path) {
            Ok(metadata) => metadata,
            Err(error)
                if matches!(
                    error.kind(),
                    std::io::ErrorKind::NotFound | std::io::ErrorKind::NotADirectory
                ) =>
            {
                return Ok(());
            }
            Err(error) => return Err(error.to_string()),
        };
        if is_link_or_reparse(&metadata) || !metadata.is_file() {
            return Err(
                "rollback target must be a regular file, not a link or reparse point".to_owned(),
            );
        }
        fs::remove_file(path).map_err(|error| error.to_string())?;
        return sync_parent_directory(path).map_err(|error| error.to_string());
    };
    ensure_parent_directory(path).map_err(|error| error.to_string())?;
    let restored = write_bytes_atomically(path, bytes).map_err(|error| error.to_string())?;
    warnings_as_restore_result(&restored.warnings)
}

fn warnings_as_restore_result(warnings: &[claw_config::WriteWarning]) -> Result<(), String> {
    if warnings.is_empty() {
        Ok(())
    } else {
        Err(format!(
            "original bytes were restored with durability warning(s): {warnings:?}"
        ))
    }
}

#[cfg(unix)]
fn sync_parent_directory(path: &Path) -> std::io::Result<()> {
    let parent = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    fs::File::open(parent)?.sync_all()
}

#[cfg(not(unix))]
fn sync_parent_directory(_path: &Path) -> std::io::Result<()> {
    Ok(())
}

#[cfg(unix)]
fn is_link_or_reparse(metadata: &fs::Metadata) -> bool {
    metadata.file_type().is_symlink()
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::path::PathBuf;
    use std::sync::atomic::{AtomicU64, Ordering};

    use claw_config::WriteWarning;

    use super::{restore_path, warnings_as_restore_result};

    static NEXT_RELATIVE_PATH: AtomicU64 = AtomicU64::new(0);

    #[test]
    fn rollback_directory_sync_warning_is_a_restore_failure() {
        let error = warnings_as_restore_result(&[WriteWarning::DirectorySyncFailed {
            path: PathBuf::from("/config"),
            message: "injected directory sync failure".to_owned(),
        }])
        .expect_err("durability warning must be surfaced");

        assert!(error.contains("injected directory sync failure"));
    }

    #[test]
    fn rollback_removes_a_relative_file_and_syncs_the_current_directory() {
        let sequence = NEXT_RELATIVE_PATH.fetch_add(1, Ordering::Relaxed);
        let path = PathBuf::from(format!(
            ".claw-crestodian-relative-rollback-{}-{sequence}",
            std::process::id()
        ));
        fs::write(&path, b"created during failed setup").expect("write relative rollback target");

        restore_path(&path, None).expect("remove and synchronize relative rollback target");

        assert!(!path.exists());
    }
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

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
            },
            SetupQuestion {
                field: SetupField::RoleSourceUrl,
                prompt: "Role source URL",
                required: true,
                secret: false,
            },
            SetupQuestion {
                field: SetupField::Workspace,
                prompt: "Initial workspace",
                required: false,
                secret: false,
            },
            SetupQuestion {
                field: SetupField::EnableTeams,
                prompt: "Enable Microsoft Teams",
                required: true,
                secret: false,
            },
            SetupQuestion {
                field: SetupField::TeamsAppId,
                prompt: "Microsoft Teams application ID",
                required: false,
                secret: false,
            },
            SetupQuestion {
                field: SetupField::TeamsPasswordEnvironment,
                prompt: "Microsoft Teams password environment variable",
                required: false,
                secret: false,
            },
        ]
    }

    /// Validates answers and transactionally publishes config then state.
    ///
    /// An empty existing config is considered interrupted first-run state and is
    /// restored exactly if publishing auxiliary state fails.
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
        if let Some(app_id) = &answers.teams_app_id {
            environment.push(("MicrosoftAppId", app_id.as_str()));
        }
        if answers.teams_password_environment.is_some() {
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
        Err(source) if source.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(source) => Err(CrestodianError::io(path, source)),
    }
}

pub(crate) fn restore_paths<const N: usize>(
    paths: [(&Path, Option<&[u8]>); N],
) -> Vec<RestoreFailure> {
    let mut failures = Vec::new();
    for (path, original) in paths {
        let result = match original {
            Some(bytes) => {
                if let Err(error) = ensure_parent_directory(path) {
                    Err(error.to_string())
                } else {
                    write_bytes_atomically(path, bytes)
                        .map(|_| ())
                        .map_err(|error| error.to_string())
                }
            }
            None => match fs::remove_file(path) {
                Ok(()) => Ok(()),
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
                Err(error) => Err(error.to_string()),
            },
        };
        if let Err(message) = result {
            failures.push(RestoreFailure {
                path: path.to_owned(),
                message,
            });
        }
    }
    failures
}

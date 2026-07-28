use std::error::Error;
use std::fmt::{self, Display, Formatter};
use std::io;
use std::path::PathBuf;

use claw_config::ConfigError;

/// One failed attempt to restore exact pre-operation bytes.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RestoreFailure {
    /// Path that could not be restored.
    pub path: PathBuf,
    /// Operating-system diagnostic.
    pub message: String,
}

/// Setup, state, rescue, or recovery failure.
#[derive(Debug)]
pub enum CrestodianError {
    /// Strict configuration operation failed.
    Config(ConfigError),
    /// Auxiliary state I/O failed.
    Io {
        /// Path involved in the operation.
        path: PathBuf,
        /// Underlying operating-system failure.
        source: io::Error,
    },
    /// Auxiliary state was malformed at an exact Serde path.
    StateDecode {
        /// State file path.
        path: PathBuf,
        /// Exact JSON path, or `<root>`.
        json_path: String,
        /// Decoder diagnostic.
        message: String,
    },
    /// Durable ring-zero settings were malformed at an exact Serde path.
    SettingsDecode {
        /// Settings file path.
        path: PathBuf,
        /// Exact JSON path, or `<root>`.
        json_path: String,
        /// Decoder diagnostic.
        message: String,
    },
    /// Durable ring-zero settings failed re-validation.
    InvalidSettings {
        /// Settings file path.
        path: PathBuf,
        /// Validation diagnostic.
        message: String,
    },
    /// A persisted audit line could not be decoded.
    AuditDecode {
        /// Audit trail path.
        path: PathBuf,
        /// One-based line number, or `0` for a whole-file failure.
        line: usize,
        /// Decoder diagnostic.
        message: String,
    },
    /// First-run setup refused to overwrite an authored configuration.
    AlreadyConfigured(PathBuf),
    /// A path that must be a regular file had a different kind.
    UnsafePath {
        /// Rejected path.
        path: PathBuf,
        /// Safety diagnostic.
        message: &'static str,
    },
    /// A write failed and restoring exact original bytes also encountered errors.
    Rollback {
        /// Original operation failure.
        operation: Box<Self>,
        /// Every restoration failure.
        restore_failures: Vec<RestoreFailure>,
    },
    /// A guided answer failed validation before any write.
    InvalidAnswer {
        /// Stable answer field.
        field: &'static str,
        /// Actionable validation diagnostic.
        message: String,
    },
}

impl CrestodianError {
    pub(crate) fn io(path: impl Into<PathBuf>, source: io::Error) -> Self {
        Self::Io {
            path: path.into(),
            source,
        }
    }
}

impl Display for CrestodianError {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        match self {
            Self::Config(error) => write!(formatter, "{error}"),
            Self::Io { path, source } => write!(formatter, "{}: {source}", path.display()),
            Self::StateDecode {
                path,
                json_path,
                message,
            } => write!(
                formatter,
                "{}: state field {json_path}: {message}",
                path.display()
            ),
            Self::SettingsDecode {
                path,
                json_path,
                message,
            } => write!(
                formatter,
                "{}: settings field {json_path}: {message}",
                path.display()
            ),
            Self::InvalidSettings { path, message } => {
                write!(formatter, "{}: {message}", path.display())
            }
            Self::AuditDecode {
                path,
                line,
                message,
            } => write!(
                formatter,
                "{}: audit line {line}: {message}",
                path.display()
            ),
            Self::AlreadyConfigured(path) => write!(
                formatter,
                "{}: first-run setup refuses to overwrite authored configuration",
                path.display()
            ),
            Self::UnsafePath { path, message } => {
                write!(formatter, "{}: {message}", path.display())
            }
            Self::Rollback {
                operation,
                restore_failures,
            } => write!(
                formatter,
                "{operation}; rollback had {} additional failure(s)",
                restore_failures.len()
            ),
            Self::InvalidAnswer { field, message } => {
                write!(formatter, "setup answer {field}: {message}")
            }
        }
    }
}

impl Error for CrestodianError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Config(error) => Some(error),
            Self::Io { source, .. } => Some(source),
            Self::Rollback { operation, .. } => Some(operation),
            Self::StateDecode { .. }
            | Self::SettingsDecode { .. }
            | Self::InvalidSettings { .. }
            | Self::AuditDecode { .. }
            | Self::AlreadyConfigured(_)
            | Self::UnsafePath { .. }
            | Self::InvalidAnswer { .. } => None,
        }
    }
}

impl From<ConfigError> for CrestodianError {
    fn from(error: ConfigError) -> Self {
        Self::Config(error)
    }
}

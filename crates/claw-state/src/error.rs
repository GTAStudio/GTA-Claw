use std::error::Error;
use std::fmt::{self, Display, Formatter};
use std::path::PathBuf;

/// A deterministic database failure with no SQLx type in the public API.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DatabaseFailure {
    operation: &'static str,
    code: Option<String>,
    message: String,
}

impl DatabaseFailure {
    pub(crate) fn from_sqlx(operation: &'static str, error: sqlx::Error) -> Self {
        let (code, message) = match error {
            sqlx::Error::Database(database) => (
                database.code().map(|code| code.into_owned()),
                database.message().to_owned(),
            ),
            other => (None, other.to_string()),
        };
        Self {
            operation,
            code,
            message,
        }
    }

    /// Returns the operation that failed.
    #[must_use]
    pub const fn operation(&self) -> &'static str {
        self.operation
    }

    /// Returns SQLite's stable result code when one was available.
    #[must_use]
    pub fn code(&self) -> Option<&str> {
        self.code.as_deref()
    }

    /// Returns the database-provided diagnostic.
    #[must_use]
    pub fn message(&self) -> &str {
        &self.message
    }
}

impl Display for DatabaseFailure {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        if let Some(code) = &self.code {
            write!(
                formatter,
                "{} failed (SQLite code {code}): {}",
                self.operation, self.message
            )
        } else {
            write!(formatter, "{} failed: {}", self.operation, self.message)
        }
    }
}

impl Error for DatabaseFailure {}

/// Failures surfaced by the durable state boundary.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum StateError {
    /// A configured path cannot represent an on-disk SQLite store.
    InvalidPath {
        /// Rejected path.
        path: PathBuf,
        /// Stable rejection reason.
        reason: &'static str,
    },
    /// A filesystem operation failed.
    FileSystem {
        /// Operation that failed.
        operation: &'static str,
        /// Relevant path.
        path: PathBuf,
        /// Platform diagnostic.
        message: String,
    },
    /// Another writer currently owns this store.
    StoreLocked {
        /// Advisory lock path.
        path: PathBuf,
    },
    /// SQLite rejected an operation.
    Database(DatabaseFailure),
    /// An already-applied migration no longer matches the embedded SQL.
    MigrationChecksumDrift {
        /// Migration version.
        version: i64,
        /// Stored checksum.
        applied: String,
        /// Current embedded checksum.
        embedded: String,
    },
    /// The database schema was produced by a newer binary.
    NewerSchema {
        /// Highest applied schema version.
        found: i64,
        /// Highest version this binary supports.
        supported: i64,
    },
    /// Applied migration history is incomplete or otherwise invalid.
    InvalidMigrationHistory {
        /// Stable diagnostic.
        reason: String,
    },
    /// A backup destination must not be overwritten.
    BackupDestinationExists {
        /// Existing destination.
        path: PathBuf,
    },
    /// Snapshot publication completed but rollback could not restore a clean destination.
    PublicationUncertain {
        /// Destination that may contain a published snapshot.
        path: PathBuf,
        /// Publication and rollback diagnostic.
        reason: String,
    },
    /// Store shutdown completed with one or more durability or cleanup degradations.
    CloseDegraded {
        /// Whether the final WAL checkpoint completed.
        checkpoint_completed: bool,
        /// Whether the persisted application writer row was released.
        application_lock_released: bool,
        /// Whether the OS identity lock was explicitly released.
        os_lock_released: bool,
        /// Combined deterministic diagnostic.
        reason: String,
    },
    /// A stored backup failed validation.
    InvalidBackup {
        /// Backup path.
        path: PathBuf,
        /// Stable diagnostic.
        reason: String,
    },
    /// A durable record already exists.
    AlreadyExists {
        /// Record kind.
        entity: &'static str,
        /// Record identifier.
        id: String,
    },
    /// A durable record was not found.
    NotFound {
        /// Record kind.
        entity: &'static str,
        /// Record identifier.
        id: String,
    },
    /// A referenced parent record does not exist.
    ForeignKeyViolation {
        /// Referenced record kind.
        entity: &'static str,
        /// Referenced identifier.
        id: String,
    },
    /// A parent record exists but cannot accept the requested child.
    InactiveParent {
        /// Parent record kind.
        entity: &'static str,
        /// Parent identifier.
        id: String,
        /// Current parent state.
        state: &'static str,
    },
    /// A caller attempted a forbidden state-machine transition.
    InvalidTransition {
        /// Record kind.
        entity: &'static str,
        /// Source state.
        from: &'static str,
        /// Requested state.
        to: &'static str,
    },
    /// An optimistic version changed before the update committed.
    OptimisticConflict {
        /// Record kind.
        entity: &'static str,
        /// Record identifier.
        id: String,
        /// Version supplied by the caller.
        expected_version: i64,
    },
    /// A caller or persisted row violated a state invariant.
    InvalidValue {
        /// Value category.
        field: &'static str,
        /// Stable rejection reason.
        reason: &'static str,
    },
}

impl Display for StateError {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidPath { path, reason } => {
                write!(formatter, "invalid state path {}: {reason}", path.display())
            }
            Self::FileSystem {
                operation,
                path,
                message,
            } => write!(
                formatter,
                "{operation} {} failed: {message}",
                path.display()
            ),
            Self::StoreLocked { path } => {
                write!(
                    formatter,
                    "state store is locked by another writer: {}",
                    path.display()
                )
            }
            Self::Database(error) => Display::fmt(error, formatter),
            Self::MigrationChecksumDrift {
                version,
                applied,
                embedded,
            } => write!(
                formatter,
                "migration {version} checksum drift: applied {applied}, embedded {embedded}"
            ),
            Self::NewerSchema { found, supported } => write!(
                formatter,
                "database schema version {found} is newer than supported version {supported}"
            ),
            Self::InvalidMigrationHistory { reason } => {
                write!(formatter, "invalid migration history: {reason}")
            }
            Self::BackupDestinationExists { path } => {
                write!(
                    formatter,
                    "backup destination already exists: {}",
                    path.display()
                )
            }
            Self::PublicationUncertain { path, reason } => {
                write!(
                    formatter,
                    "snapshot publication state is uncertain at {}: {reason}",
                    path.display()
                )
            }
            Self::CloseDegraded {
                checkpoint_completed,
                application_lock_released,
                os_lock_released,
                reason,
            } => write!(
                formatter,
                "state store closed with degradation (checkpoint={checkpoint_completed}, application_lock={application_lock_released}, os_lock={os_lock_released}): {reason}"
            ),
            Self::InvalidBackup { path, reason } => {
                write!(formatter, "invalid backup {}: {reason}", path.display())
            }
            Self::AlreadyExists { entity, id } => write!(formatter, "{entity} {id} already exists"),
            Self::NotFound { entity, id } => write!(formatter, "{entity} {id} was not found"),
            Self::ForeignKeyViolation { entity, id } => {
                write!(formatter, "referenced {entity} {id} was not found")
            }
            Self::InactiveParent { entity, id, state } => {
                write!(
                    formatter,
                    "{entity} {id} is {state} and cannot accept children"
                )
            }
            Self::InvalidTransition { entity, from, to } => {
                write!(formatter, "invalid {entity} transition from {from} to {to}")
            }
            Self::OptimisticConflict {
                entity,
                id,
                expected_version,
            } => write!(
                formatter,
                "{entity} {id} changed from expected version {expected_version}"
            ),
            Self::InvalidValue { field, reason } => {
                write!(formatter, "invalid {field}: {reason}")
            }
        }
    }
}

impl Error for StateError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Database(error) => Some(error),
            _ => None,
        }
    }
}

pub(crate) fn database(operation: &'static str, error: sqlx::Error) -> StateError {
    StateError::Database(DatabaseFailure::from_sqlx(operation, error))
}

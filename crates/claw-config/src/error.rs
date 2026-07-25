use std::error::Error;
use std::fmt::{self, Display, Formatter};
use std::io;
use std::path::PathBuf;

/// A deterministic configuration failure with source and field context.
#[derive(Debug)]
pub enum ConfigError {
    /// Reading or writing a configuration file failed.
    Io {
        /// File involved in the failed operation.
        path: PathBuf,
        /// Underlying operating-system error.
        source: io::Error,
    },
    /// JSON5 syntax was malformed.
    Syntax {
        /// Logical source name or file path.
        source_name: String,
        /// Parser diagnostic including line and column.
        message: String,
    },
    /// A typed field could not be decoded.
    Decode {
        /// Logical source name or file path.
        source_name: String,
        /// Serde field path.
        path: String,
        /// Decoder diagnostic.
        message: String,
    },
    /// The schema envelope version is unsupported.
    UnsupportedVersion {
        /// Version found in the document.
        found: u32,
        /// Only version accepted by this crate.
        supported: u32,
    },
    /// A typed value violated a domain invariant.
    Validation {
        /// Stable dotted field path.
        path: String,
        /// Invariant violation.
        message: String,
    },
    /// Serializing a validated snapshot or schema failed.
    Serialize(String),
}

impl ConfigError {
    pub(crate) fn io(path: impl Into<PathBuf>, source: io::Error) -> Self {
        Self::Io {
            path: path.into(),
            source,
        }
    }

    pub(crate) fn from_serialize(error: impl Display) -> Self {
        Self::Serialize(error.to_string())
    }
}

impl Display for ConfigError {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io { path, source } => write!(formatter, "{}: {source}", path.display()),
            Self::Syntax {
                source_name,
                message,
            } => write!(formatter, "{source_name}: invalid JSON5: {message}"),
            Self::Decode {
                source_name,
                path,
                message,
            } => write!(formatter, "{source_name}: field {path}: {message}"),
            Self::UnsupportedVersion { found, supported } => write!(
                formatter,
                "schema_version: unsupported version {found}; supported version is {supported}"
            ),
            Self::Validation { path, message } => write!(formatter, "{path}: {message}"),
            Self::Serialize(message) => write!(formatter, "configuration serialization: {message}"),
        }
    }
}

impl Error for ConfigError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Io { source, .. } => Some(source),
            _ => None,
        }
    }
}

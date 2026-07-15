//! Base-owned validation for the desktop supply-chain policy.

use std::error::Error;
use std::fmt;

pub mod changes;
pub mod input;
pub mod metadata;
pub mod ownership;
pub mod policy;
pub mod process;
pub mod validation;
pub mod workflows;

/// Result type used by the trusted validator.
pub type PolicyResult<T> = Result<T, PolicyError>;

/// A fail-closed validation or execution error.
#[derive(Debug, Clone, Eq, PartialEq)]
pub struct PolicyError {
    message: String,
}

impl PolicyError {
    /// Creates a validation error.
    #[must_use]
    pub fn new(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
        }
    }
}

impl fmt::Display for PolicyError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.message)
    }
}

impl Error for PolicyError {}

impl From<std::io::Error> for PolicyError {
    fn from(error: std::io::Error) -> Self {
        Self::new(error.to_string())
    }
}

impl From<serde_json::Error> for PolicyError {
    fn from(error: serde_json::Error) -> Self {
        Self::new(error.to_string())
    }
}

/// Builds a contextual fail-closed error.
#[must_use]
pub fn error(context: &str, detail: impl fmt::Display) -> PolicyError {
    PolicyError::new(format!("{context}: {detail}"))
}

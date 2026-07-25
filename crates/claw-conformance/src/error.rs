//! Structured conformance violations.

use std::fmt;

/// Stable violation category suitable for CI assertions.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ViolationCode {
    /// An artifact could not be read.
    Io,
    /// JSON did not satisfy its strongly typed schema.
    JsonSchema,
    /// The manifest or fixed topology drifted.
    ManifestDrift,
    /// An inventory artifact drifted from the frozen identity contract.
    InventoryDrift,
    /// A ledger artifact drifted from the frozen feature contract.
    LedgerDrift,
    /// A ledger status was raised without its required acceptance evidence.
    LedgerEvidence,
    /// A claim referred to an unknown frozen ID.
    UnknownClaim,
    /// A claim was registered more than once.
    DuplicateClaim,
    /// A claim had missing or unverifiable evidence.
    ClaimEvidence,
}

/// One precise conformance failure.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ConformanceError {
    code: ViolationCode,
    subject: Option<String>,
    json_path: Option<String>,
    message: String,
}

impl ConformanceError {
    pub(crate) fn new(
        code: ViolationCode,
        subject: impl Into<Option<String>>,
        message: impl Into<String>,
    ) -> Self {
        Self {
            code,
            subject: subject.into(),
            json_path: None,
            message: message.into(),
        }
    }

    pub(crate) fn at_json_path(
        subject: impl Into<String>,
        path: impl Into<String>,
        message: impl Into<String>,
    ) -> Self {
        Self {
            code: ViolationCode::JsonSchema,
            subject: Some(subject.into()),
            json_path: Some(path.into()),
            message: message.into(),
        }
    }

    /// Returns the stable violation category.
    #[must_use]
    pub const fn code(&self) -> ViolationCode {
        self.code
    }

    /// Returns the affected feature, inventory, claim, or artifact.
    #[must_use]
    pub fn subject(&self) -> Option<&str> {
        self.subject.as_deref()
    }

    /// Returns the serde-style JSON path for schema failures.
    #[must_use]
    pub fn json_path(&self) -> Option<&str> {
        self.json_path.as_deref()
    }

    /// Returns the detailed rejection reason.
    #[must_use]
    pub fn message(&self) -> &str {
        &self.message
    }
}

impl fmt::Display for ConformanceError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match (&self.subject, &self.json_path) {
            (Some(subject), Some(path)) => {
                write!(formatter, "{subject} at {path}: {}", self.message)
            }
            (Some(subject), None) => write!(formatter, "{subject}: {}", self.message),
            (None, _) => formatter.write_str(&self.message),
        }
    }
}

impl std::error::Error for ConformanceError {}

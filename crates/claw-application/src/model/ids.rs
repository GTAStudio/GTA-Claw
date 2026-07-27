//! Validated identifiers used across application ports.

use std::error::Error;
use std::fmt::{self, Display, Formatter};

/// The largest identifier accepted by any application port.
pub const MAX_IDENTIFIER_BYTES: usize = 128;

/// A rejected identifier value.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct IdentifierError {
    kind: &'static str,
    reason: &'static str,
}

impl IdentifierError {
    /// Returns the identifier family that rejected the value.
    #[must_use]
    pub const fn kind(&self) -> &'static str {
        self.kind
    }

    /// Returns why the value was rejected.
    #[must_use]
    pub const fn reason(&self) -> &'static str {
        self.reason
    }
}

impl Display for IdentifierError {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        write!(formatter, "invalid {}: {}", self.kind, self.reason)
    }
}

impl Error for IdentifierError {}

fn parse_identifier(kind: &'static str, value: &str) -> Result<String, IdentifierError> {
    let trimmed = value.trim();

    if trimmed.is_empty() {
        return Err(IdentifierError {
            kind,
            reason: "must not be empty",
        });
    }
    if trimmed.len() > MAX_IDENTIFIER_BYTES {
        return Err(IdentifierError {
            kind,
            reason: "is too long",
        });
    }
    if trimmed.chars().any(char::is_control) {
        return Err(IdentifierError {
            kind,
            reason: "must not contain control characters",
        });
    }

    Ok(trimmed.to_owned())
}

macro_rules! identifier {
    ($name:ident, $kind:literal, $doc:literal) => {
        #[doc = $doc]
        #[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
        pub struct $name(String);

        impl $name {
            /// Creates the identifier after enforcing the shared invariant.
            ///
            /// # Errors
            ///
            /// Returns [`IdentifierError`] naming this identifier family when
            /// the trimmed value is empty, is longer than
            /// [`MAX_IDENTIFIER_BYTES`] bytes, or contains a control
            /// character. All three mean the caller supplied a value that no
            /// port will accept, so the request that carried it should be
            /// rejected rather than retried.
            pub fn new(value: impl AsRef<str>) -> Result<Self, IdentifierError> {
                parse_identifier($kind, value.as_ref()).map(Self)
            }

            /// Returns the identifier as text.
            #[must_use]
            pub fn as_str(&self) -> &str {
                &self.0
            }
        }

        impl Display for $name {
            fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
                formatter.write_str(&self.0)
            }
        }

        impl TryFrom<String> for $name {
            type Error = IdentifierError;

            fn try_from(value: String) -> Result<Self, IdentifierError> {
                Self::new(value)
            }
        }

        impl From<$name> for String {
            fn from(value: $name) -> Self {
                value.0
            }
        }
    };
}

identifier!(
    ToolCallId,
    "tool call id",
    "Identifies one provider-requested tool call within a turn."
);
identifier!(
    ApprovalId,
    "approval id",
    "Identifies one pending approval request."
);
identifier!(GoalId, "goal id", "Identifies one durable session goal.");
identifier!(
    WorkerId,
    "worker id",
    "Identifies one closed-protocol worker."
);
identifier!(
    LeaseId,
    "lease id",
    "Identifies one cooperative host suspension lease."
);

/// Identifies one turn inside a session.
#[derive(Clone, Copy, Debug, Default, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct TurnId(u64);

impl TurnId {
    /// The first turn of a session.
    pub const FIRST: Self = Self(0);

    /// Creates a turn identifier from its ordinal.
    #[must_use]
    pub const fn new(ordinal: u64) -> Self {
        Self(ordinal)
    }

    /// Returns the ordinal of this turn.
    #[must_use]
    pub const fn ordinal(self) -> u64 {
        self.0
    }

    /// Returns the next turn, saturating at the representable maximum.
    #[must_use]
    pub const fn next(self) -> Self {
        Self(self.0.saturating_add(1))
    }
}

impl Display for TurnId {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        write!(formatter, "turn-{}", self.0)
    }
}

#[cfg(test)]
mod tests {
    use std::error::Error;

    use super::{GoalId, IdentifierError, MAX_IDENTIFIER_BYTES, ToolCallId, TurnId};

    #[test]
    fn identifiers_trim_boundary_whitespace() {
        let id = ToolCallId::new("  call-1\t").expect("valid tool call id");

        assert_eq!(id.as_str(), "call-1");
    }

    #[test]
    fn identifiers_reject_control_characters() {
        let error = GoalId::new("goal\u{7}1").expect_err("control characters are rejected");

        assert_eq!(error.kind(), "goal id");
        assert_eq!(error.reason(), "must not contain control characters");
    }

    #[test]
    fn identifiers_reject_oversized_values() {
        let oversized = "g".repeat(MAX_IDENTIFIER_BYTES + 1);
        let error = GoalId::new(oversized).expect_err("oversized ids are rejected");

        assert_eq!(error.kind(), "goal id");
        assert_eq!(error.reason(), "is too long");
        assert!(GoalId::new("g".repeat(MAX_IDENTIFIER_BYTES)).is_ok());
    }

    #[test]
    fn identifier_error_renders_kind_and_reason() {
        let error = ToolCallId::new(" ").expect_err("blank ids are rejected");

        assert_eq!(error.to_string(), "invalid tool call id: must not be empty");
    }

    #[test]
    fn turn_ids_advance_and_saturate() {
        assert_eq!(TurnId::FIRST.ordinal(), 0);
        assert_eq!(TurnId::FIRST.next(), TurnId::new(1));
        assert_eq!(TurnId::new(u64::MAX).next(), TurnId::new(u64::MAX));
        assert_eq!(TurnId::new(3).to_string(), "turn-3");
    }

    #[test]
    fn identifier_error_is_a_std_error() {
        fn assert_error<T: Error>(_: &T) {}

        let error: IdentifierError = ToolCallId::new("").expect_err("blank ids are rejected");
        assert_error(&error);
    }
}

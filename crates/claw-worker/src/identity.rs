//! Bounded, validated identifiers.
//!
//! Every identifier that crosses the closed worker boundary is length-capped
//! and restricted to one explicit alphabet before it is ever used as a map key.
//! Validation happens during deserialization, so an oversized or exotic
//! identifier is rejected by the parser rather than by a later lookup.

use std::error::Error;
use std::fmt::{self, Display, Formatter};

use serde::{Deserialize, Serialize};

/// Maximum UTF-8 byte length of any closed worker protocol identifier.
pub const MAX_IDENTIFIER_BYTES: usize = 128;

/// A rejected identifier.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum IdentifierError {
    /// The identifier was empty.
    Empty,
    /// The identifier exceeded the pinned byte cap.
    TooLong {
        /// Pinned maximum byte length.
        limit: usize,
        /// Byte length of the rejected identifier.
        actual: usize,
    },
    /// The identifier contained a byte outside the accepted alphabet.
    ForbiddenByte {
        /// Zero-based byte offset of the offending byte.
        index: usize,
        /// The offending byte.
        byte: u8,
    },
}

impl Display for IdentifierError {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        match self {
            Self::Empty => formatter.write_str("identifier must not be empty"),
            Self::TooLong { limit, actual } => write!(
                formatter,
                "identifier is {actual} bytes; the maximum is {limit}"
            ),
            Self::ForbiddenByte { index, byte } => write!(
                formatter,
                "identifier byte {byte:#04x} at offset {index} is outside the accepted alphabet"
            ),
        }
    }
}

impl Error for IdentifierError {}

/// Accepts ASCII alphanumerics plus `-`, `_`, `.` and `:`.
///
/// The alphabet is deliberately narrow: whitespace, control bytes, quotes,
/// wildcards and every non-ASCII byte are refused, so an identifier can never
/// be confused with a glob, a path traversal or a second identifier.
fn validate(value: &str) -> Result<(), IdentifierError> {
    if value.is_empty() {
        return Err(IdentifierError::Empty);
    }
    if value.len() > MAX_IDENTIFIER_BYTES {
        return Err(IdentifierError::TooLong {
            limit: MAX_IDENTIFIER_BYTES,
            actual: value.len(),
        });
    }
    for (index, byte) in value.bytes().enumerate() {
        let accepted = byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.' | b':');
        if !accepted {
            return Err(IdentifierError::ForbiddenByte { index, byte });
        }
    }
    Ok(())
}

macro_rules! identifier {
    ($name:ident, $what:literal) => {
        #[doc = concat!("A validated ", $what, ".")]
        #[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd, Deserialize)]
        #[serde(try_from = "String")]
        pub struct $name(String);

        impl $name {
            #[doc = concat!("Validates and wraps a ", $what, ".")]
            ///
            /// # Errors
            ///
            /// Returns [`IdentifierError`] when the value is empty, longer than
            /// [`MAX_IDENTIFIER_BYTES`], or contains a byte outside the accepted
            /// alphabet.
            pub fn new(value: impl Into<String>) -> Result<Self, IdentifierError> {
                let value = value.into();
                validate(&value)?;
                Ok(Self(value))
            }

            /// Borrows the validated identifier.
            #[must_use]
            pub fn as_str(&self) -> &str {
                &self.0
            }
        }

        impl TryFrom<String> for $name {
            type Error = IdentifierError;

            fn try_from(value: String) -> Result<Self, Self::Error> {
                Self::new(value)
            }
        }

        impl From<$name> for String {
            fn from(value: $name) -> Self {
                value.0
            }
        }

        // `#[serde(into = "String")]` would clone the identifier on every
        // serialization, because `into` is defined as `self.clone().into()`.
        // Writing the borrowed string produces the same bytes with no
        // allocation, which matters on the per-call frame encode path.
        impl Serialize for $name {
            fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
            where
                S: serde::Serializer,
            {
                serializer.serialize_str(&self.0)
            }
        }

        impl Display for $name {
            fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
                formatter.write_str(&self.0)
            }
        }
    };
}

identifier!(WorkerId, "worker identity");
identifier!(TicketId, "admission ticket identity");
identifier!(CallId, "worker RPC call identity");

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ordinary_identifiers_are_accepted_verbatim() {
        let worker = WorkerId::new("worker-01.eu:west").expect("accept ordinary worker identity");
        assert_eq!(worker.as_str(), "worker-01.eu:west");
        assert_eq!(worker.to_string(), "worker-01.eu:west");
    }

    #[test]
    fn empty_identifier_is_rejected() {
        assert_eq!(WorkerId::new(""), Err(IdentifierError::Empty));
    }

    #[test]
    fn oversized_identifier_is_rejected_with_both_bounds() {
        let oversized = "w".repeat(MAX_IDENTIFIER_BYTES + 1);
        assert_eq!(
            TicketId::new(oversized),
            Err(IdentifierError::TooLong {
                limit: MAX_IDENTIFIER_BYTES,
                actual: MAX_IDENTIFIER_BYTES + 1,
            })
        );
    }

    #[test]
    fn identifier_at_the_cap_is_accepted() {
        let exact = "w".repeat(MAX_IDENTIFIER_BYTES);
        assert!(TicketId::new(exact).is_ok());
    }

    #[test]
    fn wildcards_and_whitespace_are_refused_at_their_exact_offset() {
        assert_eq!(
            CallId::new("call *"),
            Err(IdentifierError::ForbiddenByte {
                index: 4,
                byte: b' ',
            })
        );
        assert_eq!(
            WorkerId::new("worker/../root"),
            Err(IdentifierError::ForbiddenByte {
                index: 6,
                byte: b'/',
            })
        );
    }

    #[test]
    fn deserialization_rejects_an_invalid_identifier() {
        let error = serde_json::from_str::<WorkerId>("\"worker one\"")
            .expect_err("deserialization must reject a forbidden byte");
        assert!(
            error.to_string().contains("outside the accepted alphabet"),
            "unexpected deserialization error: {error}"
        );
    }
}

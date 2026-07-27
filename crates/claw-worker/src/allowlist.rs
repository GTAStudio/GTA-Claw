//! The closed RPC method allowlist.
//!
//! The allowlist is a set of exact names. There is no wildcard, no prefix rule
//! and no "everything under `worker.`" shorthand, because every one of those
//! turns a closed set into an open one the moment a new method is registered.
//! A method name is refused by [`MethodName::new`] unless it is a dotted,
//! lowercase, non-empty-segment ASCII identifier, so `*` cannot even be spelled
//! as a member.

use std::collections::BTreeSet;
use std::error::Error;
use std::fmt::{self, Display, Formatter};

use serde::{Deserialize, Serialize};

/// Maximum UTF-8 byte length of a method name.
pub const MAX_METHOD_NAME_BYTES: usize = 128;

/// The closed method set this crate defines for worker sessions.
///
/// The upstream inventory freezes the `worker` role and its `closed_worker`
/// protocol class but not the method identities, so this list is this crate's
/// own design. It is exported so a Gateway can grant a subset explicitly; it is
/// never applied implicitly, and a session that was granted a subset cannot
/// reach the rest.
pub const WORKER_PROTOCOL_METHODS: [&str; 6] = [
    "worker.heartbeat",
    "worker.lease.renew",
    "worker.task.claim",
    "worker.task.complete",
    "worker.task.fail",
    "worker.task.progress",
];

/// A rejected method name.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MethodNameError {
    /// The name was empty.
    Empty,
    /// The name exceeded the pinned byte cap.
    TooLong {
        /// Pinned maximum byte length.
        limit: usize,
        /// Byte length of the rejected name.
        actual: usize,
    },
    /// A dot-separated segment was empty, as in `worker..claim` or `.claim`.
    EmptySegment {
        /// Zero-based index of the empty segment.
        segment: usize,
    },
    /// The name contained a byte outside the accepted alphabet.
    ForbiddenByte {
        /// Zero-based byte offset of the offending byte.
        index: usize,
        /// The offending byte.
        byte: u8,
    },
}

impl Display for MethodNameError {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        match self {
            Self::Empty => formatter.write_str("method name must not be empty"),
            Self::TooLong { limit, actual } => write!(
                formatter,
                "method name is {actual} bytes; the maximum is {limit}"
            ),
            Self::EmptySegment { segment } => {
                write!(formatter, "method name segment {segment} is empty")
            }
            Self::ForbiddenByte { index, byte } => write!(
                formatter,
                "method name byte {byte:#04x} at offset {index} is outside the accepted alphabet"
            ),
        }
    }
}

impl Error for MethodNameError {}

/// A validated closed-protocol method name.
///
/// Names are case-sensitive and are only ever compared for exact equality, so
/// `Worker.Heartbeat` is a different — and, given the lowercase alphabet,
/// unspellable — name from `worker.heartbeat`.
#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd, Deserialize)]
#[serde(try_from = "String")]
pub struct MethodName(String);

impl MethodName {
    /// Validates and wraps a method name.
    ///
    /// # Errors
    ///
    /// Returns [`MethodNameError`] when the name is empty, longer than
    /// [`MAX_METHOD_NAME_BYTES`], has an empty dot-separated segment, or
    /// contains a byte outside `[a-z0-9._]`.
    pub fn new(value: impl Into<String>) -> Result<Self, MethodNameError> {
        let value = value.into();
        if value.is_empty() {
            return Err(MethodNameError::Empty);
        }
        if value.len() > MAX_METHOD_NAME_BYTES {
            return Err(MethodNameError::TooLong {
                limit: MAX_METHOD_NAME_BYTES,
                actual: value.len(),
            });
        }
        for (index, byte) in value.bytes().enumerate() {
            let accepted =
                byte.is_ascii_lowercase() || byte.is_ascii_digit() || matches!(byte, b'.' | b'_');
            if !accepted {
                return Err(MethodNameError::ForbiddenByte { index, byte });
            }
        }
        for (segment, part) in value.split('.').enumerate() {
            if part.is_empty() {
                return Err(MethodNameError::EmptySegment { segment });
            }
        }
        Ok(Self(value))
    }

    /// Borrows the validated name.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl TryFrom<String> for MethodName {
    type Error = MethodNameError;

    fn try_from(value: String) -> Result<Self, Self::Error> {
        Self::new(value)
    }
}

impl From<MethodName> for String {
    fn from(value: MethodName) -> Self {
        value.0
    }
}

// `#[serde(into = "String")]` clones the name on every serialization; writing
// the borrowed string is the same bytes without the allocation.
impl Serialize for MethodName {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_str(&self.0)
    }
}

impl Display for MethodName {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.0)
    }
}

/// An exact, closed set of callable method names.
///
/// [`MethodAllowlist::default`] is the empty set, which admits nothing. That is
/// deliberate: a default-constructed allowlist must never be a working one.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct MethodAllowlist {
    methods: BTreeSet<MethodName>,
}

impl MethodAllowlist {
    /// Creates the empty allowlist, which admits nothing.
    #[must_use]
    pub fn empty() -> Self {
        Self::default()
    }

    /// Creates a closed set from already-validated names.
    #[must_use]
    pub fn closed(methods: impl IntoIterator<Item = MethodName>) -> Self {
        Self {
            methods: methods.into_iter().collect(),
        }
    }

    /// Validates each name and creates a closed set.
    ///
    /// # Errors
    ///
    /// Returns the first [`MethodNameError`] encountered, so a set containing
    /// an unusable entry is never built. In particular `"*"` is rejected as a
    /// forbidden byte rather than being stored as a wildcard.
    pub fn parse_closed<'a>(
        names: impl IntoIterator<Item = &'a str>,
    ) -> Result<Self, MethodNameError> {
        let mut methods = BTreeSet::new();
        for name in names {
            methods.insert(MethodName::new(name)?);
        }
        Ok(Self { methods })
    }

    /// Creates the full method set defined by [`WORKER_PROTOCOL_METHODS`].
    ///
    /// # Panics
    ///
    /// Panics if the pinned constant ever stops being a set of valid names,
    /// which is a defect in this crate rather than a caller error.
    #[must_use]
    pub fn worker_protocol() -> Self {
        Self::parse_closed(WORKER_PROTOCOL_METHODS)
            .expect("every pinned worker protocol method name is valid")
    }

    /// Reports whether the exact name is a member.
    #[must_use]
    pub fn admits(&self, method: &MethodName) -> bool {
        self.methods.contains(method)
    }

    /// Returns the members in canonical order.
    pub fn iter(&self) -> impl Iterator<Item = &MethodName> {
        self.methods.iter()
    }

    /// Returns the number of members.
    #[must_use]
    pub fn len(&self) -> usize {
        self.methods.len()
    }

    /// Reports whether the set admits nothing.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.methods.is_empty()
    }
}

impl<'a> IntoIterator for &'a MethodAllowlist {
    type Item = &'a MethodName;
    type IntoIter = std::collections::btree_set::Iter<'a, MethodName>;

    fn into_iter(self) -> Self::IntoIter {
        self.methods.iter()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pinned_worker_methods_are_sorted_and_unique() {
        let mut sorted = WORKER_PROTOCOL_METHODS.to_vec();
        sorted.sort_unstable();
        sorted.dedup();
        assert_eq!(sorted, WORKER_PROTOCOL_METHODS.to_vec());
        assert_eq!(
            MethodAllowlist::worker_protocol().len(),
            WORKER_PROTOCOL_METHODS.len()
        );
    }

    #[test]
    fn a_wildcard_cannot_be_spelled_as_a_member() {
        assert_eq!(
            MethodName::new("*"),
            Err(MethodNameError::ForbiddenByte {
                index: 0,
                byte: b'*',
            })
        );
        assert_eq!(
            MethodAllowlist::parse_closed(["worker.*"]),
            Err(MethodNameError::ForbiddenByte {
                index: 7,
                byte: b'*',
            })
        );
    }

    #[test]
    fn uppercase_spelling_of_a_member_is_not_a_name_at_all() {
        assert_eq!(
            MethodName::new("Worker.heartbeat"),
            Err(MethodNameError::ForbiddenByte {
                index: 0,
                byte: b'W',
            })
        );
    }

    #[test]
    fn empty_segments_are_rejected() {
        assert_eq!(
            MethodName::new("worker..claim"),
            Err(MethodNameError::EmptySegment { segment: 1 })
        );
        assert_eq!(
            MethodName::new(".worker"),
            Err(MethodNameError::EmptySegment { segment: 0 })
        );
        assert_eq!(
            MethodName::new("worker."),
            Err(MethodNameError::EmptySegment { segment: 1 })
        );
    }

    #[test]
    fn oversized_method_name_is_rejected_with_both_bounds() {
        let oversized = "m".repeat(MAX_METHOD_NAME_BYTES + 1);
        assert_eq!(
            MethodName::new(oversized),
            Err(MethodNameError::TooLong {
                limit: MAX_METHOD_NAME_BYTES,
                actual: MAX_METHOD_NAME_BYTES + 1,
            })
        );
    }

    #[test]
    fn the_default_allowlist_admits_nothing() {
        let allowlist = MethodAllowlist::default();
        assert!(allowlist.is_empty());
        for name in WORKER_PROTOCOL_METHODS {
            let method = MethodName::new(name).expect("pinned method name is valid");
            assert!(
                !allowlist.admits(&method),
                "default allowlist admitted `{name}`"
            );
        }
    }

    #[test]
    fn a_granted_subset_does_not_reach_the_rest_of_the_protocol() {
        let allowlist =
            MethodAllowlist::parse_closed(["worker.heartbeat"]).expect("parse granted subset");
        let granted = MethodName::new("worker.heartbeat").expect("valid name");
        let withheld = MethodName::new("worker.task.claim").expect("valid name");
        assert!(allowlist.admits(&granted));
        assert!(!allowlist.admits(&withheld));
    }
}

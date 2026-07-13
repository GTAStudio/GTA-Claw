use std::error::Error;
use std::fmt::{self, Display, Formatter};

/// Proven maximum initial/pre-authentication frame size (64 KiB).
pub const PREAUTH_MAX_FRAME_BYTES: usize = 64 * 1024;
/// Proven maximum authenticated frame size (25 MiB).
pub const AUTHENTICATED_MAX_FRAME_BYTES: usize = 25 * 1024 * 1024;
/// `serde_json`'s enabled-by-default recursion guard depth.
pub const DEFAULT_JSON_NESTING_DEPTH: usize = 128;

/// Connection phase selecting the proven transport frame cap.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TransportPhase {
    /// The challenge/connect phase.
    PreAuthentication,
    /// A connection whose authentication has completed.
    Authenticated,
}

impl TransportPhase {
    /// Returns the pinned byte cap for this phase.
    #[must_use]
    pub const fn max_frame_bytes(self) -> usize {
        match self {
            Self::PreAuthentication => PREAUTH_MAX_FRAME_BYTES,
            Self::Authenticated => AUTHENTICATED_MAX_FRAME_BYTES,
        }
    }
}

/// Explicit limits for protocol dimensions that have no upstream compatibility maximum.
///
/// [`ValidationPolicy::for_phase`] derives conservative defaults mechanically:
/// byte-oriented limits and collection counts use the proven transport cap,
/// while nesting uses `serde_json`'s default recursion guard.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ValidationPolicy {
    /// Maximum UTF-8 byte length of a request identifier.
    pub max_request_id_bytes: usize,
    /// Maximum UTF-8 byte length of any protocol name.
    pub max_name_bytes: usize,
    /// Maximum UTF-8 byte length of an error message.
    pub max_error_message_bytes: usize,
    /// Maximum encoded byte length of opaque error details.
    pub max_error_details_bytes: usize,
    /// Maximum number of entries in any JSON object or array.
    pub max_collection_items: usize,
    /// Maximum JSON object/array nesting depth.
    pub max_nesting_depth: usize,
}

impl ValidationPolicy {
    /// Creates defaults mechanically derived from the phase's transport cap.
    #[must_use]
    pub const fn for_phase(phase: TransportPhase) -> Self {
        Self::for_transport_cap(phase.max_frame_bytes())
    }

    /// Creates defaults mechanically derived from an explicit transport cap.
    #[must_use]
    pub const fn for_transport_cap(max_frame_bytes: usize) -> Self {
        Self {
            max_request_id_bytes: max_frame_bytes,
            max_name_bytes: max_frame_bytes,
            max_error_message_bytes: max_frame_bytes,
            max_error_details_bytes: max_frame_bytes,
            max_collection_items: max_frame_bytes,
            max_nesting_depth: DEFAULT_JSON_NESTING_DEPTH,
        }
    }

    pub(crate) fn validate(&self) -> Result<(), LimitError> {
        for (name, value) in [
            ("max_request_id_bytes", self.max_request_id_bytes),
            ("max_name_bytes", self.max_name_bytes),
            ("max_error_message_bytes", self.max_error_message_bytes),
            ("max_error_details_bytes", self.max_error_details_bytes),
            ("max_collection_items", self.max_collection_items),
            ("max_nesting_depth", self.max_nesting_depth),
        ] {
            if value == 0 {
                return Err(LimitError::ZeroLimit(name));
            }
        }
        Ok(())
    }
}

/// An invalid caller-supplied validation policy.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum LimitError {
    /// A limit must not be zero.
    ZeroLimit(&'static str),
}

impl Display for LimitError {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        match self {
            Self::ZeroLimit(name) => {
                write!(formatter, "validation limit `{name}` must be positive")
            }
        }
    }
}

impl Error for LimitError {}

//! Frame size caps applied before anything is parsed.
//!
//! A payload limit that is enforced by the deserializer is not a payload limit:
//! by the time serde reports an error it has already walked the frame and
//! allocated for it. The controller therefore compares
//! [`slice::len`][slice-len] against these caps first and returns
//! [`AdmissionRejection::PayloadTooLarge`] or
//! [`CallRejection::PayloadTooLarge`] without touching the bytes.
//!
//! [slice-len]: https://doc.rust-lang.org/std/primitive.slice.html#method.len
//! [`AdmissionRejection::PayloadTooLarge`]: crate::error::AdmissionRejection::PayloadTooLarge
//! [`CallRejection::PayloadTooLarge`]: crate::error::CallRejection::PayloadTooLarge

use std::error::Error;
use std::fmt::{self, Display, Formatter};

/// Default cap on an encoded admission frame (8 KiB).
///
/// An admission request carries three short identifiers and one 64-character
/// secret, so the honest frame is well under a kilobyte. The cap is set far
/// below the Gateway's own pre-authentication frame cap because an unadmitted
/// worker has proven nothing yet.
pub const DEFAULT_MAX_ADMISSION_BYTES: usize = 8 * 1024;

/// Default cap on an encoded worker RPC frame (256 KiB).
pub const DEFAULT_MAX_CALL_BYTES: usize = 256 * 1024;

/// Byte caps enforced ahead of parsing.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PayloadLimits {
    /// Maximum encoded length of an admission frame.
    pub max_admission_bytes: usize,
    /// Maximum encoded length of a worker RPC frame.
    pub max_call_bytes: usize,
}

impl PayloadLimits {
    /// Creates explicit caps.
    #[must_use]
    pub const fn new(max_admission_bytes: usize, max_call_bytes: usize) -> Self {
        Self {
            max_admission_bytes,
            max_call_bytes,
        }
    }

    /// Rejects a cap of zero, which would deny every frame including honest ones.
    ///
    /// # Errors
    ///
    /// Returns [`LimitError::ZeroLimit`] naming the offending field.
    pub const fn validate(&self) -> Result<(), LimitError> {
        if self.max_admission_bytes == 0 {
            return Err(LimitError::ZeroLimit("max_admission_bytes"));
        }
        if self.max_call_bytes == 0 {
            return Err(LimitError::ZeroLimit("max_call_bytes"));
        }
        Ok(())
    }
}

impl Default for PayloadLimits {
    fn default() -> Self {
        Self::new(DEFAULT_MAX_ADMISSION_BYTES, DEFAULT_MAX_CALL_BYTES)
    }
}

/// An unusable caller-supplied cap.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum LimitError {
    /// A cap must be positive.
    ZeroLimit(&'static str),
}

impl Display for LimitError {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        match self {
            Self::ZeroLimit(name) => write!(formatter, "payload limit `{name}` must be positive"),
        }
    }
}

impl Error for LimitError {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_limits_validate() {
        assert_eq!(PayloadLimits::default().validate(), Ok(()));
    }

    #[test]
    fn zero_admission_cap_is_named_in_the_rejection() {
        assert_eq!(
            PayloadLimits::new(0, DEFAULT_MAX_CALL_BYTES).validate(),
            Err(LimitError::ZeroLimit("max_admission_bytes"))
        );
    }

    #[test]
    fn zero_call_cap_is_named_in_the_rejection() {
        assert_eq!(
            PayloadLimits::new(DEFAULT_MAX_ADMISSION_BYTES, 0).validate(),
            Err(LimitError::ZeroLimit("max_call_bytes"))
        );
    }
}

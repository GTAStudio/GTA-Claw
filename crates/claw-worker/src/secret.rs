//! The admission secret and the randomness port that mints it.
//!
//! A ticket identifier is a lookup key, not a credential. The credential is a
//! 256-bit secret that the Gateway generates once, hands to exactly one worker
//! out of band, and never logs: [`AdmissionSecret`] redacts itself in [`Debug`]
//! and compares in constant time, so neither a log line nor a timing side
//! channel reveals it.

use std::error::Error;
use std::fmt::{self, Debug, Display, Formatter};

use ring::rand::{SecureRandom, SystemRandom};
use serde::{Deserialize, Serialize};
use subtle::ConstantTimeEq;

/// Length of an admission secret in bytes.
pub const ADMISSION_SECRET_BYTES: usize = 32;

/// Length of an admission ticket identifier in bytes before hex encoding.
pub const TICKET_ID_BYTES: usize = 16;

/// A 256-bit single-use admission credential.
///
/// The wire form is lowercase hex. [`Serialize`] emits the secret verbatim
/// because the worker has to receive it; [`Debug`] never does.
#[derive(Clone, Deserialize, Serialize)]
#[serde(try_from = "String", into = "String")]
pub struct AdmissionSecret([u8; ADMISSION_SECRET_BYTES]);

impl AdmissionSecret {
    /// Wraps raw secret bytes.
    #[must_use]
    pub const fn from_bytes(bytes: [u8; ADMISSION_SECRET_BYTES]) -> Self {
        Self(bytes)
    }

    /// Parses the lowercase hex wire form.
    ///
    /// # Errors
    ///
    /// Returns [`SecretParseError`] when the input is not exactly
    /// `2 * ADMISSION_SECRET_BYTES` lowercase hex digits.
    pub fn parse(value: &str) -> Result<Self, SecretParseError> {
        let expected = ADMISSION_SECRET_BYTES * 2;
        if value.len() != expected {
            return Err(SecretParseError::BadLength {
                expected,
                actual: value.len(),
            });
        }
        let mut bytes = [0_u8; ADMISSION_SECRET_BYTES];
        for (index, pair) in value.as_bytes().chunks_exact(2).enumerate() {
            let high = hex_value(pair[0]).ok_or(SecretParseError::NonHexByte {
                index: index * 2,
                byte: pair[0],
            })?;
            let low = hex_value(pair[1]).ok_or(SecretParseError::NonHexByte {
                index: index * 2 + 1,
                byte: pair[1],
            })?;
            bytes[index] = (high << 4) | low;
        }
        Ok(Self(bytes))
    }

    /// Renders the lowercase hex wire form.
    ///
    /// This is the one place the secret leaves the type; it exists because the
    /// worker must be told its own credential.
    #[must_use]
    pub fn to_wire_string(&self) -> String {
        encode_hex(&self.0)
    }
}

impl Debug for AdmissionSecret {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter.write_str("AdmissionSecret([REDACTED])")
    }
}

impl PartialEq for AdmissionSecret {
    fn eq(&self, other: &Self) -> bool {
        self.0.ct_eq(&other.0).into()
    }
}

impl Eq for AdmissionSecret {}

impl TryFrom<String> for AdmissionSecret {
    type Error = SecretParseError;

    fn try_from(value: String) -> Result<Self, Self::Error> {
        Self::parse(&value)
    }
}

impl From<AdmissionSecret> for String {
    fn from(value: AdmissionSecret) -> Self {
        value.to_wire_string()
    }
}

const fn hex_value(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        _ => None,
    }
}

/// Encodes bytes as lowercase hex.
#[must_use]
pub fn encode_hex(bytes: &[u8]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut encoded = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        encoded.push(char::from(DIGITS[usize::from(byte >> 4)]));
        encoded.push(char::from(DIGITS[usize::from(byte & 0x0f)]));
    }
    encoded
}

/// A malformed admission secret on the wire.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SecretParseError {
    /// The hex string was not the exact expected length.
    BadLength {
        /// Required number of hex digits.
        expected: usize,
        /// Number of digits supplied.
        actual: usize,
    },
    /// A byte was not a lowercase hex digit.
    NonHexByte {
        /// Zero-based offset of the offending byte.
        index: usize,
        /// The offending byte.
        byte: u8,
    },
}

impl Display for SecretParseError {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        match self {
            Self::BadLength { expected, actual } => write!(
                formatter,
                "admission secret must be {expected} hex digits; {actual} were supplied"
            ),
            Self::NonHexByte { index, byte } => write!(
                formatter,
                "admission secret byte {byte:#04x} at offset {index} is not a lowercase hex digit"
            ),
        }
    }
}

impl Error for SecretParseError {}

/// The randomness this crate needs, as a port.
///
/// No deterministic implementation ships with this crate. A test that wants
/// reproducible secrets implements this trait itself, which keeps a predictable
/// source from being one `use` away in production code.
pub trait SecretSource: Debug + Send + Sync {
    /// Fills `out` with unpredictable bytes.
    ///
    /// # Errors
    ///
    /// Returns [`SecretSourceError`] if the source cannot produce bytes. The
    /// caller must treat this as a failure to issue, never as a reason to
    /// proceed with a weak secret.
    fn fill(&self, out: &mut [u8]) -> Result<(), SecretSourceError>;
}

/// The operating system randomness source.
#[derive(Debug)]
pub struct OsSecretSource {
    random: SystemRandom,
}

impl OsSecretSource {
    /// Creates the source.
    #[must_use]
    pub fn new() -> Self {
        Self {
            random: SystemRandom::new(),
        }
    }
}

impl Default for OsSecretSource {
    fn default() -> Self {
        Self::new()
    }
}

impl SecretSource for OsSecretSource {
    fn fill(&self, out: &mut [u8]) -> Result<(), SecretSourceError> {
        self.random.fill(out).map_err(|_| SecretSourceError)
    }
}

/// The randomness source could not produce bytes.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SecretSourceError;

impl Display for SecretSourceError {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter.write_str("the secret source could not produce random bytes")
    }
}

impl Error for SecretSourceError {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn debug_never_renders_the_secret() {
        let secret = AdmissionSecret::from_bytes([0xab; ADMISSION_SECRET_BYTES]);
        let rendered = format!("{secret:?}");
        assert_eq!(rendered, "AdmissionSecret([REDACTED])");
        assert!(!rendered.contains("ab"));
    }

    #[test]
    fn wire_form_round_trips() {
        let secret = AdmissionSecret::from_bytes([0x0f; ADMISSION_SECRET_BYTES]);
        let wire = secret.to_wire_string();
        assert_eq!(wire.len(), ADMISSION_SECRET_BYTES * 2);
        assert_eq!(AdmissionSecret::parse(&wire), Ok(secret));
    }

    #[test]
    fn a_secret_differing_in_one_bit_is_not_equal() {
        let mut bytes = [0x00; ADMISSION_SECRET_BYTES];
        let first = AdmissionSecret::from_bytes(bytes);
        bytes[ADMISSION_SECRET_BYTES - 1] = 0x01;
        assert_ne!(first, AdmissionSecret::from_bytes(bytes));
    }

    #[test]
    fn a_truncated_secret_is_rejected_by_length() {
        assert_eq!(
            AdmissionSecret::parse("00"),
            Err(SecretParseError::BadLength {
                expected: ADMISSION_SECRET_BYTES * 2,
                actual: 2,
            })
        );
    }

    #[test]
    fn uppercase_hex_is_rejected_at_its_offset() {
        let mut wire = "0".repeat(ADMISSION_SECRET_BYTES * 2);
        wire.replace_range(3..4, "A");
        assert_eq!(
            AdmissionSecret::parse(&wire),
            Err(SecretParseError::NonHexByte {
                index: 3,
                byte: b'A',
            })
        );
    }

    #[test]
    fn the_operating_system_source_produces_distinct_secrets() {
        let source = OsSecretSource::new();
        let mut first = [0_u8; ADMISSION_SECRET_BYTES];
        let mut second = [0_u8; ADMISSION_SECRET_BYTES];
        source.fill(&mut first).expect("fill first secret");
        source.fill(&mut second).expect("fill second secret");
        assert_ne!(first, second);
        assert_ne!(first, [0_u8; ADMISSION_SECRET_BYTES]);
    }
}

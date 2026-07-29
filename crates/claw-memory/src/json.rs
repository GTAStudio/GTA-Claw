//! Size-bounded JSON input for persisted and transported memory values.

use std::error::Error;
use std::fmt::{self, Display, Formatter};
use std::io::{self, Read};

use serde::de::DeserializeOwned;

/// A failure while reading a size-bounded JSON document.
#[derive(Debug)]
pub enum JsonDecodeError {
    /// The input stream could not be read.
    Io(io::Error),
    /// The raw document exceeded the caller's byte limit.
    InputTooLong {
        /// Inclusive raw byte limit.
        limit: usize,
    },
    /// The bounded document was not valid JSON for the requested type.
    Json(serde_json::Error),
}

impl Display for JsonDecodeError {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io(error) => write!(formatter, "could not read memory JSON: {error}"),
            Self::InputTooLong { limit } => {
                write!(
                    formatter,
                    "memory JSON exceeds the {limit}-byte input limit"
                )
            }
            Self::Json(error) => write!(formatter, "invalid memory JSON: {error}"),
        }
    }
}

impl Error for JsonDecodeError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Io(error) => Some(error),
            Self::Json(error) => Some(error),
            Self::InputTooLong { .. } => None,
        }
    }
}

/// Reads and decodes one JSON value without allowing serde to consume more
/// than `max_input_bytes` of attacker-controlled input.
///
/// The raw document is bounded before serde parses its first field. This is
/// required for reader-backed JSON because `serde_json` may otherwise grow an
/// internal scratch buffer while decoding an escaped string, including an
/// unknown or reordered field that no nested value visitor has seen yet.
///
/// # Errors
///
/// Returns [`JsonDecodeError::InputTooLong`] before deserialization when the
/// raw document is over the limit, plus explicit I/O and JSON errors.
pub fn from_json_reader<T, R>(reader: R, max_input_bytes: usize) -> Result<T, JsonDecodeError>
where
    T: DeserializeOwned,
    R: Read,
{
    let probe_limit = max_input_bytes.saturating_add(1);
    let initial_capacity = probe_limit.min(8 * 1024);
    let mut bytes = Vec::with_capacity(initial_capacity);
    reader
        .take(u64::try_from(probe_limit).unwrap_or(u64::MAX))
        .read_to_end(&mut bytes)
        .map_err(JsonDecodeError::Io)?;
    if bytes.len() > max_input_bytes {
        return Err(JsonDecodeError::InputTooLong {
            limit: max_input_bytes,
        });
    }
    serde_json::from_slice(&bytes).map_err(JsonDecodeError::Json)
}

#[cfg(test)]
mod tests {
    use super::{JsonDecodeError, from_json_reader};
    use crate::{MemoryRecord, Session};

    #[test]
    fn a_document_within_the_outer_limit_decodes_normally() {
        let document = br#"{"id":"s","messages":[],"summaries":[],"next_ordinal":0}"#;

        let session =
            from_json_reader::<Session, _>(document.as_slice(), document.len()).expect("valid");

        assert_eq!(session.id().as_str(), "s");
    }

    #[test]
    fn direct_reader_decode_is_fenced_before_any_session_field_is_parsed() {
        let document = br#"{"id":"s","messages":[],"summaries":[],"next_ordinal":0}"#;
        let mut input = std::io::Cursor::new(document);

        assert!(serde_json::from_reader::<_, Session>(&mut input).is_err());
        assert_eq!(input.position(), 0);
    }

    #[test]
    fn outer_limit_rejects_a_reordered_escaped_role_before_serde_parses_it() {
        let document = format!(
            r#"{{"id":"s","messages":[{{"role":"{}","id":0,"content":"x","unix_millis":1,"pinned":false}}],"summaries":[],"next_ordinal":1}}"#,
            "\\u0061".repeat(64)
        );

        assert!(matches!(
            from_json_reader::<Session, _>(document.as_bytes(), 128),
            Err(JsonDecodeError::InputTooLong { limit: 128 })
        ));
    }

    #[test]
    fn outer_limit_rejects_a_huge_escaped_field_name_before_nested_decode() {
        let document = format!(
            r#"{{"{}":"ignored","id":"r","session":"s","kind":"note","text":"x","unix_millis":1,"tags":[]}}"#,
            "\\u0061".repeat(64)
        );

        assert!(matches!(
            from_json_reader::<MemoryRecord, _>(document.as_bytes(), 128),
            Err(JsonDecodeError::InputTooLong { limit: 128 })
        ));
    }
}

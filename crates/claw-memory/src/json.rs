//! Size-bounded JSON input for persisted and transported memory values.

use std::error::Error;
use std::fmt::{self, Display, Formatter};
use std::io::{self, Read};

use serde::de::DeserializeOwned;
use serde::de::{DeserializeSeed, Error as _, MapAccess, SeqAccess, Visitor};
use serde_json::{Map, Number, Value};

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

/// Reads one unambiguous JSON value with bounded allocation and nesting.
///
/// In addition to the caller's raw byte limit, this rejects duplicate object
/// keys, nesting beyond 64 containers, and more than 16,384 values. Existing
/// typed readers keep their own deserialization semantics.
///
/// # Errors
///
/// Returns the errors of [`from_json_reader`], with structural violations
/// reported as [`JsonDecodeError::Json`] before the offending value is built.
pub fn from_json_value_reader<R: Read>(
    reader: R,
    max_input_bytes: usize,
) -> Result<Value, JsonDecodeError> {
    from_json_reader::<StrictValue, _>(reader, max_input_bytes).map(|value| value.0)
}

struct StrictValue(Value);

impl<'de> serde::Deserialize<'de> for StrictValue {
    fn deserialize<Deserializer>(deserializer: Deserializer) -> Result<Self, Deserializer::Error>
    where
        Deserializer: serde::Deserializer<'de>,
    {
        ValueSeed {
            depth: 0,
            remaining: &mut 16_384,
        }
        .deserialize(deserializer)
        .map(Self)
    }
}

struct ValueSeed<'budget> {
    depth: usize,
    remaining: &'budget mut usize,
}

impl<'de> DeserializeSeed<'de> for ValueSeed<'_> {
    type Value = Value;

    fn deserialize<Deserializer>(
        self,
        deserializer: Deserializer,
    ) -> Result<Value, Deserializer::Error>
    where
        Deserializer: serde::Deserializer<'de>,
    {
        if self.depth > 64 || *self.remaining == 0 {
            return Err(Deserializer::Error::custom(
                "JSON structural budget exceeded",
            ));
        }
        *self.remaining -= 1;
        deserializer.deserialize_any(self)
    }
}

impl<'de> Visitor<'de> for ValueSeed<'_> {
    type Value = Value;

    fn expecting(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter.write_str("a bounded JSON value without duplicate keys")
    }

    fn visit_bool<DecodeError: serde::de::Error>(self, value: bool) -> Result<Value, DecodeError> {
        Ok(Value::Bool(value))
    }

    fn visit_i64<DecodeError: serde::de::Error>(self, value: i64) -> Result<Value, DecodeError> {
        Ok(Value::Number(Number::from(value)))
    }

    fn visit_u64<DecodeError: serde::de::Error>(self, value: u64) -> Result<Value, DecodeError> {
        Ok(Value::Number(Number::from(value)))
    }

    fn visit_f64<DecodeError: serde::de::Error>(self, value: f64) -> Result<Value, DecodeError> {
        Number::from_f64(value)
            .map(Value::Number)
            .ok_or_else(|| DecodeError::custom("JSON numbers must be finite"))
    }

    fn visit_str<DecodeError: serde::de::Error>(self, value: &str) -> Result<Value, DecodeError> {
        Ok(Value::String(value.to_owned()))
    }

    fn visit_string<DecodeError: serde::de::Error>(
        self,
        value: String,
    ) -> Result<Value, DecodeError> {
        Ok(Value::String(value))
    }

    fn visit_unit<DecodeError: serde::de::Error>(self) -> Result<Value, DecodeError> {
        Ok(Value::Null)
    }

    fn visit_seq<Access>(self, mut access: Access) -> Result<Value, Access::Error>
    where
        Access: SeqAccess<'de>,
    {
        if self.depth >= 64 {
            return Err(Access::Error::custom("JSON nesting budget exceeded"));
        }
        let mut values = Vec::new();
        while let Some(value) = access.next_element_seed(ValueSeed {
            depth: self.depth + 1,
            remaining: self.remaining,
        })? {
            values.push(value);
        }
        Ok(Value::Array(values))
    }

    fn visit_map<Access>(self, mut access: Access) -> Result<Value, Access::Error>
    where
        Access: MapAccess<'de>,
    {
        if self.depth >= 64 {
            return Err(Access::Error::custom("JSON nesting budget exceeded"));
        }
        let mut values = Map::new();
        while let Some(key) = access.next_key::<String>()? {
            if values.contains_key(&key) {
                return Err(Access::Error::custom("duplicate JSON object key"));
            }
            let value = access.next_value_seed(ValueSeed {
                depth: self.depth + 1,
                remaining: self.remaining,
            })?;
            values.insert(key, value);
        }
        Ok(Value::Object(values))
    }
}

#[cfg(test)]
mod tests {
    use super::{JsonDecodeError, from_json_reader, from_json_value_reader};
    use crate::{MemoryRecord, Session};

    #[test]
    fn strict_value_reader_preserves_json_types_and_exact_integer_values() {
        let document = br#"{"integer":18446744073709551615,"minimum":-9223372036854775808,"number":1.25,"text":"line\nvalue","array":[null,true,false]}"#;
        let expected: serde_json::Value =
            serde_json::from_slice(document).expect("valid reference");
        let actual =
            from_json_value_reader(document.as_slice(), document.len()).expect("strict JSON");
        assert_eq!(actual, expected);
        assert_eq!(actual["integer"].as_u64(), Some(u64::MAX));
        assert_eq!(actual["minimum"].as_i64(), Some(i64::MIN));
    }

    #[test]
    fn strict_value_reader_rejects_ambiguous_deep_wide_and_trailing_input() {
        for document in [
            r#"{"path":"reviewed","path":"changed"}"#,
            r#"{"outer":{"value":1,"\u0076alue":2}}"#,
            "{} {}",
            "1e9999",
        ] {
            assert!(from_json_value_reader(document.as_bytes(), document.len()).is_err());
        }
        let accepted = format!("{}0{}", "[".repeat(64), "]".repeat(64));
        assert!(from_json_value_reader(accepted.as_bytes(), accepted.len()).is_ok());
        let rejected = format!("{}0{}", "[".repeat(10_000), "]".repeat(10_000));
        assert!(from_json_value_reader(rejected.as_bytes(), rejected.len()).is_err());
        let accepted = serde_json::to_vec(&vec![0; 16_383]).expect("bounded array");
        assert!(from_json_value_reader(accepted.as_slice(), accepted.len()).is_ok());
        let rejected = serde_json::to_vec(&vec![0; 16_384]).expect("oversized array");
        assert!(from_json_value_reader(rejected.as_slice(), rejected.len()).is_err());
        assert!(matches!(
            from_json_value_reader(b"{}".as_slice(), 1),
            Err(JsonDecodeError::InputTooLong { .. })
        ));
    }

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

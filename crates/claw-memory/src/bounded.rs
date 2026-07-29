use std::fmt;
use std::marker::PhantomData;

use serde::de::{self, Deserialize, Deserializer, IgnoredAny, SeqAccess, Visitor};
use serde_json::value::RawValue;

pub(crate) struct BoundedString<const MAX: usize>(String);

pub(crate) fn reject_unbounded_json_reader<'de, D>() -> Result<(), D::Error>
where
    D: Deserializer<'de>,
{
    if std::any::type_name::<D>().contains("serde_json::read::IoRead") {
        return Err(de::Error::custom(
            "reader-backed memory JSON must use claw_memory::from_json_reader",
        ));
    }
    Ok(())
}

impl<const MAX: usize> BoundedString<MAX> {
    pub(crate) fn into_inner(self) -> String {
        self.0
    }
}

const fn max_encoded_string_bytes(max_decoded_bytes: usize) -> usize {
    max_decoded_bytes.saturating_mul(6).saturating_add(2)
}

struct StringVisitor<const MAX: usize>;

impl<const MAX: usize> Visitor<'_> for StringVisitor<MAX> {
    type Value = BoundedString<MAX>;

    fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "a string no longer than {MAX} bytes")
    }

    fn visit_str<E>(self, value: &str) -> Result<Self::Value, E>
    where
        E: de::Error,
    {
        if value.len() > MAX {
            return Err(E::invalid_length(value.len(), &self));
        }
        Ok(BoundedString(value.to_owned()))
    }

    fn visit_string<E>(self, value: String) -> Result<Self::Value, E>
    where
        E: de::Error,
    {
        if value.len() > MAX {
            return Err(E::invalid_length(value.len(), &self));
        }
        Ok(BoundedString(value))
    }
}

impl<'de, const MAX: usize> Deserialize<'de> for BoundedString<MAX> {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        reject_unbounded_json_reader::<D>()?;
        let deserializer_name = std::any::type_name::<D>();
        if deserializer_name.contains("serde_json::read::StrRead")
            || deserializer_name.contains("serde_json::read::SliceRead")
        {
            // Borrow the complete token from in-memory JSON so escaped strings
            // are rejected by encoded size before serde_json allocates a
            // decoded scratch String.
            let raw: &'de RawValue = Deserialize::deserialize(deserializer)?;
            let encoded = raw.get();
            if encoded.len() > max_encoded_string_bytes(MAX) {
                return Err(de::Error::custom(format_args!(
                    "encoded string exceeds the {MAX}-byte decoded bound"
                )));
            }
            let value: String = serde_json::from_str(encoded).map_err(de::Error::custom)?;
            if value.len() > MAX {
                return Err(de::Error::custom(format_args!(
                    "string is {} bytes, maximum is {MAX}",
                    value.len()
                )));
            }
            return Ok(Self(value));
        }

        // Owned values and non-JSON serde formats cannot expose the original
        // token. They remain compatible and are checked before the value is
        // retained by this type. Reader-backed JSON should use
        // `from_json_reader`, which bounds the entire raw document first.
        deserializer.deserialize_string(StringVisitor::<MAX>)
    }
}

pub(crate) struct BoundedVec<T, const MAX: usize>(Vec<T>);

impl<T, const MAX: usize> BoundedVec<T, MAX> {
    pub(crate) fn into_inner(self) -> Vec<T> {
        self.0
    }
}

struct VecVisitor<T, const MAX: usize>(PhantomData<T>);

impl<'de, T, const MAX: usize> Visitor<'de> for VecVisitor<T, MAX>
where
    T: Deserialize<'de>,
{
    type Value = BoundedVec<T, MAX>;

    fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "a sequence with at most {MAX} elements")
    }

    fn visit_seq<A>(self, mut sequence: A) -> Result<Self::Value, A::Error>
    where
        A: SeqAccess<'de>,
    {
        let capacity = sequence.size_hint().unwrap_or(0).min(MAX);
        let mut values = Vec::with_capacity(capacity);
        while values.len() < MAX {
            let Some(value) = sequence.next_element()? else {
                return Ok(BoundedVec(values));
            };
            values.push(value);
        }
        if sequence.next_element::<IgnoredAny>()?.is_some() {
            return Err(de::Error::invalid_length(MAX.saturating_add(1), &self));
        }
        Ok(BoundedVec(values))
    }
}

impl<'de, T, const MAX: usize> Deserialize<'de> for BoundedVec<T, MAX>
where
    T: Deserialize<'de>,
{
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        deserializer.deserialize_seq(VecVisitor::<T, MAX>(PhantomData))
    }
}

#[cfg(test)]
mod tests {
    use super::{BoundedString, BoundedVec};

    #[test]
    fn max_plus_one_string_is_rejected() {
        assert!(serde_json::from_str::<BoundedString<4>>(r#""1234""#).is_ok());
        assert!(serde_json::from_str::<BoundedString<4>>(r#""12345""#).is_err());
    }

    #[test]
    fn escaped_max_plus_one_string_is_rejected_from_borrowed_input() {
        assert!(serde_json::from_str::<BoundedString<4>>(r#""\u0031\u0032\u0033\u0034""#).is_ok());
        assert!(
            serde_json::from_str::<BoundedString<4>>(r#""\u0031\u0032\u0033\u0034\u0035""#)
                .is_err()
        );
    }

    #[test]
    fn owned_strings_remain_compatible_and_bounded() {
        assert!(serde_json::from_value::<BoundedString<4>>(serde_json::json!("1234")).is_ok());
        assert!(serde_json::from_value::<BoundedString<4>>(serde_json::json!("12345")).is_err());
    }

    #[test]
    fn direct_reader_decode_is_rejected_before_consuming_unbounded_input() {
        use serde::Deserialize as _;

        let mut input = std::io::Cursor::new(br#""1234""#);
        let mut deserializer = serde_json::Deserializer::from_reader(&mut input);

        assert!(BoundedString::<4>::deserialize(&mut deserializer).is_err());
        assert_eq!(input.position(), 0);
    }

    #[test]
    fn max_plus_one_vector_is_rejected() {
        assert!(serde_json::from_str::<BoundedVec<u8, 2>>("[1,2]").is_ok());
        assert!(serde_json::from_str::<BoundedVec<u8, 2>>("[1,2,3]").is_err());
    }
}

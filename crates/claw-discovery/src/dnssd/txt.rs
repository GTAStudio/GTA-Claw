//! The DNS-SD TXT record key/value contract from RFC 6763 section 6.
//!
//! A TXT record is a sequence of length-prefixed character strings, each at most
//! 255 bytes. Every string carries one key, optionally followed by `=` and a
//! value. The distinction between an absent key, a key with no `=` at all, a key
//! with an empty value and a key with a value is load-bearing, so this module
//! models all four rather than flattening them into `Option<String>`.

use std::collections::BTreeSet;

use super::DnsSdError;

/// Maximum length in bytes of one TXT character string.
pub const MAX_CHARACTER_STRING_BYTES: usize = 255;

/// The four states a TXT key can be in, per RFC 6763 section 6.4.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum TxtValue {
    /// The key is present with no `=`, which RFC 6763 defines as a boolean true.
    Boolean,
    /// The key is present as `key=` with a zero-length value.
    Empty,
    /// The key is present with a non-empty, otherwise opaque binary value.
    Present(Vec<u8>),
}

impl TxtValue {
    /// Returns the value bytes, treating boolean and empty keys as no bytes.
    #[must_use]
    pub fn bytes(&self) -> &[u8] {
        match self {
            Self::Boolean | Self::Empty => &[],
            Self::Present(value) => value,
        }
    }

    /// Returns the value as UTF-8 text when it is valid UTF-8.
    #[must_use]
    pub fn as_text(&self) -> Option<&str> {
        core::str::from_utf8(self.bytes()).ok()
    }
}

/// An ordered list of TXT character strings.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct TxtRecord {
    strings: Vec<Vec<u8>>,
}

impl TxtRecord {
    /// Builds an empty TXT record.
    ///
    /// An empty record still encodes as a single zero-length string, because
    /// RFC 6763 section 6.1 forbids a TXT record with zero rdata bytes.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Appends one raw character string.
    ///
    /// # Errors
    ///
    /// Returns [`DnsSdError::CharacterStringTooLong`] above 255 bytes.
    pub fn push_raw(&mut self, string: impl Into<Vec<u8>>) -> Result<(), DnsSdError> {
        let string = string.into();
        if string.len() > MAX_CHARACTER_STRING_BYTES {
            return Err(DnsSdError::CharacterStringTooLong(string.len()));
        }
        self.strings.push(string);
        Ok(())
    }

    /// Appends `key=value`.
    ///
    /// # Errors
    ///
    /// Returns [`DnsSdError::InvalidTxtKey`] when the key is empty or contains a
    /// byte outside printable US-ASCII other than `=`, and
    /// [`DnsSdError::CharacterStringTooLong`] when the joined string exceeds 255
    /// bytes.
    pub fn push_pair(&mut self, key: &str, value: impl AsRef<[u8]>) -> Result<(), DnsSdError> {
        validate_key(key)?;
        let value = value.as_ref();
        let mut string = Vec::with_capacity(key.len() + 1 + value.len());
        string.extend_from_slice(key.as_bytes());
        string.push(b'=');
        string.extend_from_slice(value);
        self.push_raw(string)
    }

    /// Appends a bare key, which RFC 6763 reads as a boolean true.
    ///
    /// # Errors
    ///
    /// Returns [`DnsSdError::InvalidTxtKey`] for an invalid key.
    pub fn push_flag(&mut self, key: &str) -> Result<(), DnsSdError> {
        validate_key(key)?;
        self.push_raw(key.as_bytes().to_vec())
    }

    /// Returns the raw character strings in wire order.
    #[must_use]
    pub fn strings(&self) -> &[Vec<u8>] {
        &self.strings
    }

    /// Looks a key up case-insensitively, honouring first-occurrence-wins.
    ///
    /// RFC 6763 section 6.4 requires a receiver to silently ignore every
    /// occurrence of a key after the first, so a later duplicate can never
    /// override an earlier one.
    #[must_use]
    pub fn get(&self, key: &str) -> Option<TxtValue> {
        let key = key.as_bytes();
        for string in &self.strings {
            let (candidate, value) = split_string(string);
            if candidate.len() != key.len() {
                continue;
            }
            if !candidate
                .iter()
                .zip(key.iter())
                .all(|(a, b)| a.eq_ignore_ascii_case(b))
            {
                continue;
            }
            return Some(match value {
                None => TxtValue::Boolean,
                Some([]) => TxtValue::Empty,
                Some(bytes) => TxtValue::Present(bytes.to_vec()),
            });
        }
        None
    }

    /// Returns the distinct keys in wire order, lowercased, ignoring duplicates.
    #[must_use]
    pub fn keys(&self) -> Vec<String> {
        let mut seen: BTreeSet<String> = BTreeSet::new();
        let mut keys = Vec::new();
        for string in &self.strings {
            let (key, _) = split_string(string);
            let key = String::from_utf8_lossy(key).to_lowercase();
            if key.is_empty() {
                continue;
            }
            if seen.insert(key.clone()) {
                keys.push(key);
            }
        }
        keys
    }

    /// Encodes the record body, without the enclosing resource record header.
    #[must_use]
    pub fn encode(&self) -> Vec<u8> {
        if self.strings.is_empty() {
            return vec![0];
        }
        let mut out = Vec::new();
        for string in &self.strings {
            // push_raw is the only way to add a string and it bounds the length.
            let length = u8::try_from(string.len()).unwrap_or(u8::MAX);
            out.push(length);
            out.extend_from_slice(&string[..usize::from(length)]);
        }
        out
    }

    /// Decodes a TXT record body.
    ///
    /// # Errors
    ///
    /// Returns [`DnsSdError::EmptyTxtRdata`] for zero rdata bytes and
    /// [`DnsSdError::Truncated`] when a length prefix runs past the end.
    pub fn decode(bytes: &[u8]) -> Result<Self, DnsSdError> {
        if bytes.is_empty() {
            return Err(DnsSdError::EmptyTxtRdata);
        }
        let mut strings = Vec::new();
        let mut index = 0usize;
        while index < bytes.len() {
            let length = usize::from(bytes[index]);
            index += 1;
            let end = index.checked_add(length).ok_or(DnsSdError::Truncated)?;
            if end > bytes.len() {
                return Err(DnsSdError::Truncated);
            }
            strings.push(bytes[index..end].to_vec());
            index = end;
        }
        if strings.len() == 1 && strings[0].is_empty() {
            strings.clear();
        }
        Ok(Self { strings })
    }
}

fn split_string(string: &[u8]) -> (&[u8], Option<&[u8]>) {
    let Some(index) = string.iter().position(|&byte| byte == b'=') else {
        return (string, None);
    };
    (&string[..index], Some(&string[index + 1..]))
}

fn validate_key(key: &str) -> Result<(), DnsSdError> {
    if key.is_empty() {
        return Err(DnsSdError::InvalidTxtKey(key.to_owned()));
    }
    let printable_and_not_equals = |byte: &u8| (0x20..=0x7e).contains(byte) && *byte != b'=';
    if !key.as_bytes().iter().all(printable_and_not_equals) {
        return Err(DnsSdError::InvalidTxtKey(key.to_owned()));
    }
    Ok(())
}

//! Domain names in presentation and wire form.
//!
//! The presentation grammar is RFC 1035 section 5.1: `\.` and `\\` escape a
//! literal dot and backslash, `\DDD` is an exact decimal byte, and every other
//! byte stands for itself. RFC 6763 section 4.3 relies on exactly that escaping
//! to carry a service instance name — which is UTF-8 and may legitimately
//! contain a dot — inside a single DNS label.

use core::fmt::{self, Write as _};

use super::DnsSdError;

/// Maximum length in bytes of a single DNS label.
pub const MAX_LABEL_BYTES: usize = 63;
/// Maximum length in bytes of an encoded domain name, including the root byte.
pub const MAX_NAME_BYTES: usize = 255;

/// A domain name held as its decoded labels, root exclusive.
#[derive(Clone, Debug, Default, Eq)]
pub struct Name {
    labels: Vec<Vec<u8>>,
}

impl Name {
    /// Builds a name from already decoded labels.
    ///
    /// # Errors
    ///
    /// Returns [`DnsSdError::EmptyLabel`] for a zero-length label,
    /// [`DnsSdError::LabelTooLong`] above 63 bytes and
    /// [`DnsSdError::NameTooLong`] when the encoded name would exceed 255
    /// bytes.
    pub fn from_labels<I, L>(labels: I) -> Result<Self, DnsSdError>
    where
        I: IntoIterator<Item = L>,
        L: Into<Vec<u8>>,
    {
        let labels: Vec<Vec<u8>> = labels.into_iter().map(Into::into).collect();
        let name = Self { labels };
        name.validate()?;
        Ok(name)
    }

    /// Parses a name from its presentation form.
    ///
    /// A single trailing dot denotes the root and is optional; the empty string
    /// and `"."` both parse to the root name.
    ///
    /// # Errors
    ///
    /// Returns [`DnsSdError::BadEscape`] for a truncated or non-decimal escape
    /// sequence and for a `\DDD` value above 255, plus the length errors listed
    /// on [`Name::from_labels`].
    pub fn parse(text: &str) -> Result<Self, DnsSdError> {
        let bytes = text.as_bytes();
        if bytes.is_empty() || bytes == b"." {
            return Ok(Self::default());
        }
        let mut labels: Vec<Vec<u8>> = Vec::new();
        let mut current: Vec<u8> = Vec::new();
        let mut index = 0usize;
        let mut ended_with_dot = false;
        while index < bytes.len() {
            let byte = bytes[index];
            ended_with_dot = false;
            match byte {
                b'.' => {
                    labels.push(core::mem::take(&mut current));
                    ended_with_dot = true;
                    index += 1;
                }
                b'\\' => {
                    let (value, consumed) = decode_escape(bytes, index)?;
                    current.push(value);
                    index += consumed;
                }
                other => {
                    current.push(other);
                    index += 1;
                }
            }
        }
        if !ended_with_dot {
            labels.push(current);
        }
        let name = Self { labels };
        name.validate()?;
        Ok(name)
    }

    /// Returns the decoded labels, root exclusive.
    #[must_use]
    pub fn labels(&self) -> &[Vec<u8>] {
        &self.labels
    }

    /// Returns the number of labels, root exclusive.
    #[must_use]
    pub const fn label_count(&self) -> usize {
        self.labels.len()
    }

    /// Returns `true` when this is the root name.
    #[must_use]
    pub const fn is_root(&self) -> bool {
        self.labels.is_empty()
    }

    /// Returns the number of bytes this name occupies when encoded uncompressed.
    #[must_use]
    pub fn encoded_len(&self) -> usize {
        self.labels
            .iter()
            .map(|label| label.len() + 1)
            .sum::<usize>()
            + 1
    }

    /// Returns the name with the leading `count` labels removed.
    ///
    /// Removing more labels than the name has yields the root name.
    #[must_use]
    pub fn parent(&self, count: usize) -> Self {
        let start = count.min(self.labels.len());
        Self {
            labels: self.labels[start..].to_vec(),
        }
    }

    /// Returns the name with `label` prepended.
    ///
    /// # Errors
    ///
    /// Returns the same length errors as [`Name::from_labels`].
    pub fn prepend(&self, label: impl Into<Vec<u8>>) -> Result<Self, DnsSdError> {
        let mut labels = Vec::with_capacity(self.labels.len() + 1);
        labels.push(label.into());
        labels.extend(self.labels.iter().cloned());
        let name = Self { labels };
        name.validate()?;
        Ok(name)
    }

    /// Returns `true` when `self` is equal to `ancestor` or lies beneath it.
    ///
    /// Comparison is ASCII case-insensitive, matching DNS name equality.
    #[must_use]
    pub fn is_within(&self, ancestor: &Self) -> bool {
        if ancestor.labels.len() > self.labels.len() {
            return false;
        }
        let offset = self.labels.len() - ancestor.labels.len();
        self.labels[offset..]
            .iter()
            .zip(ancestor.labels.iter())
            .all(|(left, right)| labels_equal(left, right))
    }

    fn validate(&self) -> Result<(), DnsSdError> {
        for label in &self.labels {
            if label.is_empty() {
                return Err(DnsSdError::EmptyLabel);
            }
            if label.len() > MAX_LABEL_BYTES {
                return Err(DnsSdError::LabelTooLong(label.len()));
            }
        }
        let encoded = self.encoded_len();
        if encoded > MAX_NAME_BYTES {
            return Err(DnsSdError::NameTooLong(encoded));
        }
        Ok(())
    }
}

impl PartialEq for Name {
    fn eq(&self, other: &Self) -> bool {
        self.labels.len() == other.labels.len()
            && self
                .labels
                .iter()
                .zip(other.labels.iter())
                .all(|(left, right)| labels_equal(left, right))
    }
}

impl fmt::Display for Name {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.labels.is_empty() {
            return formatter.write_str(".");
        }
        for label in &self.labels {
            formatter.write_str(&escape_label(label))?;
            formatter.write_str(".")?;
        }
        Ok(())
    }
}

fn decode_escape(bytes: &[u8], index: usize) -> Result<(u8, usize), DnsSdError> {
    let first = *bytes.get(index + 1).ok_or(DnsSdError::BadEscape)?;
    if !first.is_ascii_digit() {
        return Ok((first, 2));
    }
    let second = *bytes.get(index + 2).ok_or(DnsSdError::BadEscape)?;
    let third = *bytes.get(index + 3).ok_or(DnsSdError::BadEscape)?;
    if !second.is_ascii_digit() || !third.is_ascii_digit() {
        return Err(DnsSdError::BadEscape);
    }
    let value =
        u32::from(first - b'0') * 100 + u32::from(second - b'0') * 10 + u32::from(third - b'0');
    let value = u8::try_from(value).map_err(|_| DnsSdError::BadEscape)?;
    Ok((value, 4))
}

/// Escapes one already decoded label into presentation form.
#[must_use]
pub fn escape_label(label: &[u8]) -> String {
    let mut text = String::with_capacity(label.len());
    for &byte in label {
        match byte {
            b'.' => text.push_str("\\."),
            b'\\' => text.push_str("\\\\"),
            0x20..=0x7e => text.push(char::from(byte)),
            // Writing into a `String` is infallible, so there is no error to
            // propagate out of an escape.
            other => {
                let _ = write!(text, "\\{other:03}");
            }
        }
    }
    text
}

fn labels_equal(left: &[u8], right: &[u8]) -> bool {
    left.len() == right.len()
        && left
            .iter()
            .zip(right.iter())
            .all(|(a, b)| a.eq_ignore_ascii_case(b))
}

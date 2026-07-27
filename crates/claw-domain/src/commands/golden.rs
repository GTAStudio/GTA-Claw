//! A dependency-free reader for the golden fixture tables under
//! `crates/claw-domain/tests/fixtures/commands/`.
//!
//! The fixtures are the pinned input/output tables that the parity tests compare
//! against, so they must be readable without pulling a serialization crate into
//! this crate. The format is deliberately tiny:
//!
//! ```text
//! # comments start with '#'
//! name: inline-think-directive
//! input: "please /think high answer me"
//! cleaned: "please answer me"
//! level: high
//!
//! name: next-record
//! ...
//! ```
//!
//! * A record is a run of consecutive content lines; one or more blank lines end it.
//! * A comment line never ends a record.
//! * Every content line is `key: value`.
//! * A value that starts with `"` is a quoted string supporting `\\`, `\"`, `\n`,
//!   `\r`, `\t`, `\0` and `\u{..}`; anything else is a bare token taken verbatim
//!   after trimming. Quoting is what makes leading, trailing and repeated
//!   whitespace expressible, which every interesting directive case needs.
//! * A key may repeat; the values accumulate in source order.
//! * An absent key is `None`, which is distinct from a key set to `""`.

use std::error::Error;
use std::fmt::{self, Display, Formatter};

/// A malformed golden fixture.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GoldenError {
    line: usize,
    reason: String,
}

impl GoldenError {
    /// Returns the 1-based line number the failure was found on.
    #[must_use]
    pub const fn line(&self) -> usize {
        self.line
    }

    /// Returns the human-readable reason.
    #[must_use]
    pub fn reason(&self) -> &str {
        &self.reason
    }
}

impl Display for GoldenError {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        write!(formatter, "line {}: {}", self.line, self.reason)
    }
}

impl Error for GoldenError {}

/// One `key: value` record of a golden fixture table.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct GoldenRecord {
    line: usize,
    fields: Vec<(String, String)>,
}

impl GoldenRecord {
    /// Returns the 1-based line the record starts on.
    #[must_use]
    pub const fn line(&self) -> usize {
        self.line
    }

    /// Returns the first value recorded for `key`, if any.
    #[must_use]
    pub fn get(&self, key: &str) -> Option<&str> {
        self.fields
            .iter()
            .find(|(name, _)| name == key)
            .map(|(_, value)| value.as_str())
    }

    /// Returns every value recorded for `key`, in source order.
    #[must_use]
    pub fn values(&self, key: &str) -> Vec<&str> {
        self.fields
            .iter()
            .filter(|(name, _)| name == key)
            .map(|(_, value)| value.as_str())
            .collect()
    }

    /// Returns the value recorded for `key`.
    ///
    /// # Panics
    ///
    /// Panics when the key is absent. A missing key in a pinned table is a
    /// fixture defect rather than a runtime condition, and failing loudly at the
    /// exact record is what makes the table maintainable.
    #[must_use]
    pub fn require(&self, key: &str) -> &str {
        self.get(key).unwrap_or_else(|| {
            panic!(
                "golden record starting at line {} is missing required key `{key}`",
                self.line
            )
        })
    }

    /// Returns a boolean field, defaulting to `default` when the key is absent.
    ///
    /// # Panics
    ///
    /// Panics when the value is neither `true` nor `false`.
    #[must_use]
    pub fn flag(&self, key: &str, default: bool) -> bool {
        match self.get(key) {
            None => default,
            Some("true") => true,
            Some("false") => false,
            Some(other) => panic!(
                "golden record starting at line {} has non-boolean `{key}`: {other}",
                self.line
            ),
        }
    }

    /// Returns the field names in source order, including repeats.
    #[must_use]
    pub fn keys(&self) -> Vec<&str> {
        self.fields.iter().map(|(name, _)| name.as_str()).collect()
    }
}

/// Parses a golden fixture file into its records.
///
/// # Errors
///
/// Returns [`GoldenError`] when a line is neither blank, a comment, nor a
/// well-formed `key: value` pair, or when a quoted value is unterminated or
/// carries an unknown escape.
pub fn parse_golden(source: &str) -> Result<Vec<GoldenRecord>, GoldenError> {
    let mut records: Vec<GoldenRecord> = Vec::new();
    let mut current: Option<GoldenRecord> = None;

    for (index, raw_line) in source.lines().enumerate() {
        let line_number = index + 1;
        let line = raw_line.trim_end_matches(['\r', '\n']);
        let trimmed = line.trim();

        if trimmed.is_empty() {
            if let Some(record) = current.take() {
                records.push(record);
            }
            continue;
        }
        if trimmed.starts_with('#') {
            continue;
        }

        let (key, value) = parse_field(trimmed, line_number)?;
        current
            .get_or_insert_with(|| GoldenRecord {
                line: line_number,
                fields: Vec::new(),
            })
            .fields
            .push((key, value));
    }

    if let Some(record) = current.take() {
        records.push(record);
    }
    Ok(records)
}

fn parse_field(line: &str, line_number: usize) -> Result<(String, String), GoldenError> {
    let separator = line.find(':').ok_or_else(|| GoldenError {
        line: line_number,
        reason: format!("expected `key: value`, found `{line}`"),
    })?;
    let key = line[..separator].trim();
    if key.is_empty()
        || !key
            .chars()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '_')
        || key.starts_with(|c: char| c.is_ascii_digit())
    {
        return Err(GoldenError {
            line: line_number,
            reason: format!("`{key}` is not a lowercase snake_case key"),
        });
    }
    let raw_value = line[separator + 1..].trim();
    let value = if raw_value.starts_with('"') {
        decode_quoted(raw_value, line_number)?
    } else {
        raw_value.to_owned()
    };
    Ok((key.to_owned(), value))
}

fn decode_quoted(raw: &str, line_number: usize) -> Result<String, GoldenError> {
    let mut characters = raw.chars();
    let opening = characters.next();
    debug_assert_eq!(opening, Some('"'));

    let mut decoded = String::new();
    loop {
        let Some(character) = characters.next() else {
            return Err(GoldenError {
                line: line_number,
                reason: "unterminated quoted value".to_owned(),
            });
        };
        match character {
            '"' => break,
            '\\' => {
                let escape = characters.next().ok_or_else(|| GoldenError {
                    line: line_number,
                    reason: "value ends with a dangling escape".to_owned(),
                })?;
                decoded.push(decode_escape(escape, &mut characters, line_number)?);
            }
            other => decoded.push(other),
        }
    }

    let trailing: String = characters.collect();
    if !trailing.trim().is_empty() {
        return Err(GoldenError {
            line: line_number,
            reason: format!(
                "trailing text after the quoted value: `{}`",
                trailing.trim()
            ),
        });
    }
    Ok(decoded)
}

fn decode_escape(
    escape: char,
    characters: &mut std::str::Chars<'_>,
    line_number: usize,
) -> Result<char, GoldenError> {
    match escape {
        '\\' => Ok('\\'),
        '"' => Ok('"'),
        'n' => Ok('\n'),
        'r' => Ok('\r'),
        't' => Ok('\t'),
        '0' => Ok('\0'),
        'u' => decode_unicode_escape(characters, line_number),
        other => Err(GoldenError {
            line: line_number,
            reason: format!("unknown escape `\\{other}`"),
        }),
    }
}

fn decode_unicode_escape(
    characters: &mut std::str::Chars<'_>,
    line_number: usize,
) -> Result<char, GoldenError> {
    let malformed = || GoldenError {
        line: line_number,
        reason: "expected `\\u{...}` with hexadecimal digits".to_owned(),
    };
    if characters.next() != Some('{') {
        return Err(malformed());
    }
    let mut digits = String::new();
    loop {
        let character = characters.next().ok_or_else(malformed)?;
        if character == '}' {
            break;
        }
        if !character.is_ascii_hexdigit() {
            return Err(malformed());
        }
        digits.push(character);
    }
    let code_point = u32::from_str_radix(&digits, 16).map_err(|_| malformed())?;
    char::from_u32(code_point).ok_or_else(|| GoldenError {
        line: line_number,
        reason: format!("`\\u{{{digits}}}` is not a Unicode scalar value"),
    })
}

#[cfg(test)]
mod tests {
    use super::{GoldenRecord, parse_golden};

    #[test]
    fn records_are_separated_by_blank_lines_and_ignore_comments() {
        let records = parse_golden(
            "# leading comment\nname: first\ninput: \"a\"\n\n\n# between\nname: second\ninput: \"b\"\n",
        )
        .expect("well formed fixture");

        assert_eq!(records.len(), 2);
        assert_eq!(records[0].require("name"), "first");
        assert_eq!(records[0].require("input"), "a");
        assert_eq!(records[1].require("name"), "second");
        assert_eq!(records[1].line(), 7);
    }

    #[test]
    fn quoted_values_preserve_whitespace_and_escapes() {
        let records =
            parse_golden("input: \"  a\\tb\\n \\\"q\\\" \\\\ \\u{feff}  \"\n").expect("valid");

        assert_eq!(records[0].require("input"), "  a\tb\n \"q\" \\ \u{feff}  ");
    }

    #[test]
    fn bare_values_are_taken_verbatim_after_trimming() {
        let records = parse_golden("level:   high  \nflag: true\n").expect("valid");

        assert_eq!(records[0].require("level"), "high");
        assert!(records[0].flag("flag", false));
        assert!(records[0].flag("absent", true));
    }

    #[test]
    fn repeated_keys_accumulate_in_order() {
        let records = parse_golden("alias: /a\nalias: /b\n").expect("valid");

        assert_eq!(records[0].values("alias"), vec!["/a", "/b"]);
        assert_eq!(records[0].get("alias"), Some("/a"));
        assert_eq!(records[0].keys(), vec!["alias", "alias"]);
    }

    #[test]
    fn an_absent_key_is_distinct_from_an_empty_value() {
        let records = parse_golden("cleaned: \"\"\n").expect("valid");

        assert_eq!(records[0].get("cleaned"), Some(""));
        assert_eq!(records[0].get("raw"), None);
    }

    #[test]
    fn malformed_lines_are_rejected_with_their_line_number() {
        let missing_colon = parse_golden("name: ok\nnot a field\n").expect_err("must reject");
        assert_eq!(missing_colon.line(), 2);
        assert!(missing_colon.reason().contains("expected `key: value`"));

        let bad_key = parse_golden("Name: ok\n").expect_err("must reject");
        assert_eq!(bad_key.line(), 1);
        assert!(bad_key.reason().contains("snake_case"));

        let unterminated = parse_golden("input: \"oops\n").expect_err("must reject");
        assert_eq!(unterminated.reason(), "unterminated quoted value");

        let unknown_escape = parse_golden("input: \"a\\qb\"\n").expect_err("must reject");
        assert!(unknown_escape.reason().contains("unknown escape"));

        let trailing = parse_golden("input: \"a\" junk\n").expect_err("must reject");
        assert!(trailing.reason().contains("trailing text"));

        let dangling = parse_golden("input: \"a\\").expect_err("must reject");
        assert!(dangling.reason().contains("dangling escape"));

        let bad_unicode = parse_golden("input: \"\\u{d800}\"\n").expect_err("must reject");
        assert!(bad_unicode.reason().contains("not a Unicode scalar value"));

        let bad_unicode_shape = parse_golden("input: \"\\uFEFF\"\n").expect_err("must reject");
        assert!(bad_unicode_shape.reason().contains("hexadecimal"));
    }

    #[test]
    fn missing_required_keys_panic_with_the_record_line() {
        let record = GoldenRecord::default();

        let failure = std::panic::catch_unwind(|| record.require("name"))
            .expect_err("a missing key must panic");
        let message = failure
            .downcast_ref::<String>()
            .expect("panic payload is a String");
        assert!(message.contains("missing required key `name`"), "{message}");
    }
}

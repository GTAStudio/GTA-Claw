//! JavaScript-compatible string helpers used by the command and directive ports.
//!
//! The upstream implementation is JavaScript, so its whitespace class, `trim()`
//! and `String.prototype.replace` semantics decide observable behaviour. Rust's
//! own `char::is_whitespace` is *almost* the same set: it implements the Unicode
//! `White_Space` property, while ECMA-262 `\s` is `White_Space` plus `U+FEFF`.
//! Getting that one code point wrong would silently change where a directive
//! boundary is found, so the difference is encoded here once and reused.

/// Returns whether `value` is whitespace for ECMA-262 `\s`, `trim()` and friends.
pub(crate) const fn is_js_space(value: char) -> bool {
    value.is_whitespace() || value == '\u{feff}'
}

/// Trims leading and trailing ECMA-262 whitespace, like JavaScript `trim()`.
pub(crate) fn js_trim(value: &str) -> &str {
    value.trim_matches(is_js_space)
}

/// Trims leading ECMA-262 whitespace, like JavaScript `trimStart()`.
pub(crate) fn js_trim_start(value: &str) -> &str {
    value.trim_start_matches(is_js_space)
}

/// Collapses every run of ECMA-262 whitespace to one space, like `replace(/\s+/g, " ")`.
pub(crate) fn collapse_js_whitespace(value: &str) -> String {
    let mut collapsed = String::with_capacity(value.len());
    let mut in_space = false;
    for character in value.chars() {
        if is_js_space(character) {
            if !in_space {
                collapsed.push(' ');
                in_space = true;
            }
            continue;
        }
        in_space = false;
        collapsed.push(character);
    }
    collapsed
}

/// Ports `normalizeOptionalLowercaseString`: trim, drop empties, lowercase.
pub(crate) fn normalize_optional_lowercase(value: &str) -> Option<String> {
    let trimmed = js_trim(value);
    if trimmed.is_empty() {
        return None;
    }
    Some(trimmed.to_lowercase())
}

/// Ports `normalizeLowercaseStringOrEmpty`: like the above but empty instead of `None`.
pub(crate) fn normalize_lowercase_or_empty(value: &str) -> String {
    normalize_optional_lowercase(value).unwrap_or_default()
}

/// Ports `normalizeOptionalString`: trim and drop empties without lowercasing.
pub(crate) fn normalize_optional(value: &str) -> Option<&str> {
    let trimmed = js_trim(value);
    if trimmed.is_empty() {
        None
    } else {
        Some(trimmed)
    }
}

/// Returns the byte length of the leading ECMA-262 whitespace run in `value`.
pub(crate) fn leading_space_len(value: &str) -> usize {
    value.len() - js_trim_start(value).len()
}

#[cfg(test)]
mod tests {
    use super::{
        collapse_js_whitespace, is_js_space, js_trim, leading_space_len,
        normalize_lowercase_or_empty, normalize_optional, normalize_optional_lowercase,
    };

    #[test]
    fn js_whitespace_includes_the_byte_order_mark() {
        assert!(is_js_space('\u{feff}'));
        assert!(!'\u{feff}'.is_whitespace());
        assert!(is_js_space('\u{00a0}'));
        assert!(is_js_space('\u{3000}'));
        assert!(!is_js_space('\u{200b}'));
    }

    #[test]
    fn js_trim_removes_the_byte_order_mark_rust_trim_keeps() {
        assert_eq!(js_trim("\u{feff} hi \u{feff}"), "hi");
        assert_eq!("\u{feff} hi \u{feff}".trim(), "\u{feff} hi \u{feff}");
    }

    #[test]
    fn whitespace_runs_collapse_to_a_single_space() {
        assert_eq!(collapse_js_whitespace(" a \t\n b  "), " a b ");
        assert_eq!(collapse_js_whitespace(""), "");
        assert_eq!(collapse_js_whitespace("\u{feff}a"), " a");
    }

    #[test]
    fn optional_normalizers_drop_blank_input() {
        assert_eq!(
            normalize_optional_lowercase("  HiGH "),
            Some("high".to_owned())
        );
        assert_eq!(normalize_optional_lowercase("   "), None);
        assert_eq!(normalize_lowercase_or_empty("   "), "");
        assert_eq!(normalize_optional("  Keep Me  "), Some("Keep Me"));
        assert_eq!(normalize_optional(" \u{feff} "), None);
    }

    #[test]
    fn leading_space_len_counts_bytes_not_chars() {
        assert_eq!(leading_space_len("\u{3000}x"), 3);
        assert_eq!(leading_space_len("x"), 0);
    }
}

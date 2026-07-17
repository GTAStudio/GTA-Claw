//! Canonical portable identities for filesystem and rendered workflow names.

use caseless::Caseless as _;
use unicode_normalization::UnicodeNormalization as _;

/// Returns Unicode canonical caseless identity: NFD(case-fold(NFD(value))).
#[must_use]
pub fn canonical_caseless(value: &str) -> String {
    value.chars().nfd().default_case_fold().nfd().collect()
}

/// Returns the punctuation-insensitive portable identity used for workflow spoof checks.
#[must_use]
pub fn spoof_identity(value: &str) -> String {
    canonical_caseless(value)
        .bytes()
        .filter(u8::is_ascii_alphanumeric)
        .map(char::from)
        .collect()
}

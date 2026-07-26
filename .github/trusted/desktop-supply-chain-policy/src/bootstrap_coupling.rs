//! Per-path change coupling between the live Bootstrap-managed files and the historical
//! GTABOOT1 archive.
//!
//! The historical archive is a fingerprint-bound composite snapshot of the 28 exact paths in
//! `BOOTSTRAP_FILES`. It is canonical the moment it is written, but it can silently go stale
//! when a live path changes afterward: nothing forces a reviewer to decide whether the
//! historical record should follow the live change or intentionally stay as it was. This
//! module closes that gap. For every trusted Git changed path that is exactly one of the 28
//! Bootstrap-managed paths, the candidate must make one explicit, mechanically checked
//! decision:
//!
//! - **Synchronize**: the candidate regenerated the archive so its entry for that path equals
//!   the candidate's own normalized live bytes, and the candidate's own declared
//!   `BOOTSTRAP_FINGERPRINT` source constant agrees with the semantic fingerprint of that
//!   regenerated archive. The pull request must directly touch both the archive and the
//!   fingerprint-bearing source file. Every one of the 28 canonical archive entries — not
//!   just the touched path — must independently be either carried over byte-for-byte from the
//!   trusted archive or freshly synchronized to the candidate's own live bytes for that path;
//!   this is what stops a candidate from fabricating arbitrary bytes for an untouched path and
//!   then simply hashing whatever it wrote.
//! - **Preserve**: the candidate appended a new, strictly bounded, append-only preservation
//!   record to the ledger, binding the exact normalized base-live and candidate-live SHA-256
//!   digests, the still-archived payload digest, the archive's semantic fingerprint, and a
//!   bounded rationale.
//!
//! Silence fails closed. This check is purely a function of the trusted changed-path
//! manifest; it never compares live and archive bytes globally, so an unrelated historical
//! mismatch outside the current pull request's changed paths is out of scope.

use std::collections::BTreeSet;

use toml::Value as TomlValue;

use crate::changes::{ChangeManifest, ChangedPath};
use crate::input::{SafeRoot, sha256};
use crate::policy::{
    BOOTSTRAP_FILES, BootstrapSnapshotArchive, MAX_LOCK_BYTES, MAX_REPOSITORY_BYTES,
    archive_semantic_fingerprint, is_bootstrap_managed_path, normalize_text,
};
use crate::{PolicyError, PolicyResult, error};

/// Canonical path of the append-only Bootstrap preservation ledger.
pub const LEDGER_PATH: &str =
    ".github/trusted/desktop-supply-chain-policy/policy/bootstrap-preservation-records.toml";
/// Canonical path of the fingerprint-bearing validator source file.
pub const POLICY_SOURCE_PATH: &str = ".github/trusted/desktop-supply-chain-policy/src/policy.rs";
/// Canonical path of the historical Bootstrap archive.
pub const BOOTSTRAP_SNAPSHOT_PATH: &str =
    ".github/trusted/desktop-supply-chain-policy/policy/bootstrap.snapshot";

const MAX_LEDGER_BYTES: u64 = 1024 * 1024;
const MAX_RECORDS: usize = 512;
const MIN_RATIONALE_BYTES: usize = 8;
const MAX_RATIONALE_BYTES: usize = 500;
const DECLARATION_PREFIX: &str = "const BOOTSTRAP_FINGERPRINT";

/// One immutable, strictly ordered decision to preserve a stale historical archive entry.
#[derive(Debug, Clone, Eq, PartialEq)]
pub struct PreservationRecord {
    sequence: u64,
    path: String,
    base_sha256: String,
    candidate_sha256: String,
    archive_payload_sha256: String,
    archive_fingerprint: String,
    rationale: String,
}

impl PreservationRecord {
    /// Returns the exact Bootstrap-managed path this record preserves.
    #[must_use]
    pub fn path(&self) -> &str {
        &self.path
    }

    /// Returns the append-only ledger position, starting at one.
    #[must_use]
    pub const fn sequence(&self) -> u64 {
        self.sequence
    }
}

fn hash_field(
    table: &toml::map::Map<String, TomlValue>,
    key: &str,
    index: usize,
) -> PolicyResult<String> {
    let value = table.get(key).and_then(TomlValue::as_str).ok_or_else(|| {
        PolicyError::new(format!(
            "Bootstrap preservation ledger record {index} is missing {key}"
        ))
    })?;
    if value.len() != 64
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(PolicyError::new(format!(
            "Bootstrap preservation ledger record {index} {key} must be a lowercase 64-character hex digest"
        )));
    }
    Ok(value.to_owned())
}

fn parse_record(value: &TomlValue, index: usize) -> PolicyResult<PreservationRecord> {
    let table = value.as_table().ok_or_else(|| {
        PolicyError::new(format!(
            "Bootstrap preservation ledger record {index} must be a table"
        ))
    })?;
    let expected: BTreeSet<&str> = [
        "sequence",
        "path",
        "base_sha256",
        "candidate_sha256",
        "archive_payload_sha256",
        "archive_fingerprint",
        "rationale",
    ]
    .into_iter()
    .collect();
    let actual: BTreeSet<&str> = table.keys().map(String::as_str).collect();
    if actual != expected {
        return Err(PolicyError::new(format!(
            "Bootstrap preservation ledger record {index} schema changed"
        )));
    }
    let sequence = table
        .get("sequence")
        .and_then(TomlValue::as_integer)
        .filter(|value| *value >= 1)
        .ok_or_else(|| {
            PolicyError::new(format!(
                "Bootstrap preservation ledger record {index} has an invalid sequence"
            ))
        })?;
    let expected_sequence = i64::try_from(index + 1)
        .map_err(|_| PolicyError::new("Bootstrap preservation ledger sequence overflow"))?;
    if sequence != expected_sequence {
        return Err(PolicyError::new(format!(
            "Bootstrap preservation ledger records are not strictly ordered by sequence at record {index}"
        )));
    }
    let path = table
        .get("path")
        .and_then(TomlValue::as_str)
        .ok_or_else(|| {
            PolicyError::new(format!(
                "Bootstrap preservation ledger record {index} path is missing"
            ))
        })?;
    if !is_bootstrap_managed_path(path) {
        return Err(PolicyError::new(format!(
            "Bootstrap preservation ledger record {index} path is not an exact Bootstrap-managed path: {path}"
        )));
    }
    let base_sha256 = hash_field(table, "base_sha256", index)?;
    let candidate_sha256 = hash_field(table, "candidate_sha256", index)?;
    let archive_payload_sha256 = hash_field(table, "archive_payload_sha256", index)?;
    let archive_fingerprint = hash_field(table, "archive_fingerprint", index)?;
    let rationale = table
        .get("rationale")
        .and_then(TomlValue::as_str)
        .ok_or_else(|| {
            PolicyError::new(format!(
                "Bootstrap preservation ledger record {index} rationale is missing"
            ))
        })?;
    if rationale.len() < MIN_RATIONALE_BYTES
        || rationale.len() > MAX_RATIONALE_BYTES
        || rationale.trim() != rationale
        || !rationale.bytes().all(|byte| (0x20..=0x7e).contains(&byte))
    {
        return Err(PolicyError::new(format!(
            "Bootstrap preservation ledger record {index} rationale is out of bounds or contains unprintable bytes"
        )));
    }
    Ok(PreservationRecord {
        sequence: u64::try_from(sequence)
            .map_err(|_| PolicyError::new("Bootstrap preservation ledger sequence overflow"))?,
        path: path.to_owned(),
        base_sha256,
        candidate_sha256,
        archive_payload_sha256,
        archive_fingerprint,
        rationale: rationale.to_owned(),
    })
}

/// Strictly parses the canonical Bootstrap preservation ledger.
pub fn parse_ledger(bytes: &[u8]) -> PolicyResult<Vec<PreservationRecord>> {
    if u64::try_from(bytes.len()).unwrap_or(u64::MAX) > MAX_LEDGER_BYTES {
        return Err(PolicyError::new(format!(
            "Bootstrap preservation ledger exceeds {MAX_LEDGER_BYTES} bytes"
        )));
    }
    let text = std::str::from_utf8(bytes)
        .map_err(|cause| error("Bootstrap preservation ledger is not UTF-8", cause))?;
    let value: TomlValue = toml::from_str(text)
        .map_err(|cause| error("parse Bootstrap preservation ledger", cause))?;
    let table = value.as_table().ok_or_else(|| {
        PolicyError::new("Bootstrap preservation ledger root must be a TOML table")
    })?;
    if table.len() != 2 || table.get("version").and_then(TomlValue::as_integer) != Some(1) {
        return Err(PolicyError::new(
            "Bootstrap preservation ledger version or schema changed",
        ));
    }
    let records_value = table
        .get("record")
        .and_then(TomlValue::as_array)
        .ok_or_else(|| PolicyError::new("Bootstrap preservation ledger record array is missing"))?;
    if records_value.len() > MAX_RECORDS {
        return Err(PolicyError::new(format!(
            "Bootstrap preservation ledger exceeds {MAX_RECORDS} records"
        )));
    }
    let mut records = Vec::with_capacity(records_value.len());
    for (index, entry) in records_value.iter().enumerate() {
        records.push(parse_record(entry, index)?);
    }
    for outer in 0..records.len() {
        for inner in (outer + 1)..records.len() {
            if records[outer].path == records[inner].path
                && records[outer].base_sha256 == records[inner].base_sha256
                && records[outer].candidate_sha256 == records[inner].candidate_sha256
                && records[outer].archive_payload_sha256 == records[inner].archive_payload_sha256
                && records[outer].archive_fingerprint == records[inner].archive_fingerprint
            {
                return Err(PolicyError::new(format!(
                    "Bootstrap preservation ledger contains a duplicate record for {}",
                    records[outer].path
                )));
            }
        }
    }
    Ok(records)
}

/// Reads the ledger beneath a safe root, treating an absent file as an empty ledger.
pub fn read_ledger(root: &SafeRoot) -> PolicyResult<Vec<PreservationRecord>> {
    if !root.exists(LEDGER_PATH)? {
        return Ok(Vec::new());
    }
    parse_ledger(&root.read_bytes(LEDGER_PATH, MAX_LEDGER_BYTES)?)
}

fn source_code_mask(bytes: &[u8]) -> Vec<bool> {
    let mut mask = vec![false; bytes.len()];
    let mut index = 0usize;
    while index < bytes.len() {
        if bytes[index] == b'/' && bytes.get(index + 1) == Some(&b'/') {
            while index < bytes.len() && bytes[index] != b'\n' {
                index += 1;
            }
        } else if bytes[index] == b'/' && bytes.get(index + 1) == Some(&b'*') {
            index += 2;
            while index < bytes.len()
                && !(bytes[index] == b'*' && bytes.get(index + 1) == Some(&b'/'))
            {
                index += 1;
            }
            index = bytes.len().min(index + 2);
        } else if bytes[index] == b'"' {
            index += 1;
            while index < bytes.len() && bytes[index] != b'"' {
                if bytes[index] == b'\\' && index + 1 < bytes.len() {
                    index += 2;
                } else {
                    index += 1;
                }
            }
            index = bytes.len().min(index + 1);
        } else {
            mask[index] = true;
            index += 1;
        }
    }
    mask
}

fn is_identifier_byte(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || byte == b'_'
}

fn find_declaration(bytes: &[u8], mask: &[bool]) -> Vec<usize> {
    let pattern = DECLARATION_PREFIX.as_bytes();
    let mut matches = Vec::new();
    if bytes.len() < pattern.len() {
        return matches;
    }
    for start in 0..=(bytes.len() - pattern.len()) {
        let end = start + pattern.len();
        if &bytes[start..end] != pattern {
            continue;
        }
        if !mask[start..end].iter().all(|&code| code) {
            continue;
        }
        if start > 0 && is_identifier_byte(bytes[start - 1]) {
            continue;
        }
        if bytes.get(end).is_some_and(|&byte| is_identifier_byte(byte)) {
            continue;
        }
        matches.push(start);
    }
    matches
}

fn skip_whitespace(bytes: &[u8], mut index: usize) -> usize {
    while matches!(bytes.get(index), Some(b' ' | b'\t' | b'\r' | b'\n')) {
        index += 1;
    }
    index
}

/// Strictly parses the candidate's own reviewed `BOOTSTRAP_FINGERPRINT` source declaration.
///
/// Exactly one `const BOOTSTRAP_FINGERPRINT: &str = "<64-hex>";` declaration must appear
/// outside comments and string literals. Any other count, comment/string decoys, or a
/// malformed literal fail closed.
pub fn extract_declared_bootstrap_fingerprint(source: &str) -> PolicyResult<String> {
    let bytes = source.as_bytes();
    let mask = source_code_mask(bytes);
    let matches = find_declaration(bytes, &mask);
    if matches.len() != 1 {
        return Err(PolicyError::new(format!(
            "candidate BOOTSTRAP_FINGERPRINT declaration is missing or ambiguous: found {} exact declarations",
            matches.len()
        )));
    }
    let mut index = matches[0] + DECLARATION_PREFIX.len();
    index = skip_whitespace(bytes, index);
    if bytes.get(index) != Some(&b':') {
        return Err(PolicyError::new(
            "candidate BOOTSTRAP_FINGERPRINT declaration is not a strict const binding",
        ));
    }
    index = skip_whitespace(bytes, index + 1);
    if !bytes[index..].starts_with(b"&str") {
        return Err(PolicyError::new(
            "candidate BOOTSTRAP_FINGERPRINT declaration is not typed as &str",
        ));
    }
    index = skip_whitespace(bytes, index + 4);
    if bytes.get(index) != Some(&b'=') {
        return Err(PolicyError::new(
            "candidate BOOTSTRAP_FINGERPRINT declaration is missing its initializer",
        ));
    }
    index = skip_whitespace(bytes, index + 1);
    if bytes.get(index) != Some(&b'"') {
        return Err(PolicyError::new(
            "candidate BOOTSTRAP_FINGERPRINT declaration value is not a plain string literal",
        ));
    }
    let start = index + 1;
    let mut end = start;
    while bytes.get(end).is_some_and(|&byte| byte != b'"') {
        end += 1;
    }
    if end >= bytes.len() {
        return Err(PolicyError::new(
            "candidate BOOTSTRAP_FINGERPRINT declaration string literal is unterminated",
        ));
    }
    let hex = &source[start..end];
    index = skip_whitespace(bytes, end + 1);
    if bytes.get(index) != Some(&b';') {
        return Err(PolicyError::new(
            "candidate BOOTSTRAP_FINGERPRINT declaration is missing its terminating semicolon",
        ));
    }
    if hex.len() != 64
        || !hex
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(PolicyError::new(
            "candidate BOOTSTRAP_FINGERPRINT declaration is not a lowercase 64-character hex digest",
        ));
    }
    Ok(hex.to_owned())
}

fn read_archive(root: &SafeRoot) -> PolicyResult<BootstrapSnapshotArchive> {
    let bytes = root.read_bytes(BOOTSTRAP_SNAPSHOT_PATH, MAX_REPOSITORY_BYTES)?;
    BootstrapSnapshotArchive::parse(&bytes)
}

fn live_bytes(root: &SafeRoot, path: &str, treat_missing_as_empty: bool) -> PolicyResult<Vec<u8>> {
    if treat_missing_as_empty && !root.exists(path)? {
        return Ok(Vec::new());
    }
    Ok(normalize_text(&root.read_bytes(path, MAX_LOCK_BYTES)?))
}

fn coupling_error(path: &str) -> PolicyError {
    PolicyError::new(format!(
        "historical Bootstrap-managed path changed without an explicit archive/preservation companion decision: {path}"
    ))
}

/// Requires every one of the 28 canonical archive entries to be either carried over unchanged
/// from the trusted archive, or freshly synchronized to the candidate's own live bytes for
/// that exact path.
///
/// This is what actually stops a candidate from fabricating arbitrary bytes for an untouched
/// Bootstrap-managed path while genuinely synchronizing a different, touched one: fabricated
/// bytes match neither the immutable trusted archive nor the candidate's real live checkout,
/// so they are rejected here before any per-path Synchronize/Preserve decision is evaluated.
fn validate_archive_entries_are_trustworthy(
    candidate: &SafeRoot,
    trusted_archive: &BootstrapSnapshotArchive,
    candidate_archive: &BootstrapSnapshotArchive,
) -> PolicyResult<()> {
    for path in BOOTSTRAP_FILES {
        let candidate_payload = candidate_archive.payload(path).ok_or_else(|| {
            PolicyError::new(format!(
                "Bootstrap snapshot archive is missing the canonical entry: {path}"
            ))
        })?;
        let trusted_payload = trusted_archive.payload(path);
        let candidate_live = live_bytes(candidate, path, true)?;
        if Some(candidate_payload) != trusted_payload && candidate_payload != candidate_live {
            return Err(PolicyError::new(format!(
                "Bootstrap snapshot archive entry matches neither the trusted archive nor the candidate's own live bytes: {path}"
            )));
        }
    }
    Ok(())
}

/// Validates the per-path Synchronize/Preserve coupling for every changed Bootstrap-managed
/// path in the trusted changed-path manifest.
///
/// This is a residual, additive check: it only inspects paths that are exactly one of the 28
/// `BOOTSTRAP_FILES` entries in the manifest's changed paths, and it never falls back to a
/// global live/archive comparison. It must run after every other existing static/workflow/
/// repository/metadata check so that their exact diagnostics keep firing first.
pub fn validate_bootstrap_change_coupling(
    trusted: &SafeRoot,
    candidate: &SafeRoot,
    manifest: &ChangeManifest,
) -> PolicyResult<()> {
    let touched: Vec<&ChangedPath> = manifest
        .paths
        .iter()
        .filter(|entry| is_bootstrap_managed_path(&entry.path))
        .collect();
    if touched.is_empty() {
        return Ok(());
    }
    for entry in &touched {
        if entry.status == 'T' {
            return Err(PolicyError::new(format!(
                "historical Bootstrap-managed path type change is never permitted: {}",
                entry.path
            )));
        }
    }

    let changed_paths: BTreeSet<&str> = manifest
        .paths
        .iter()
        .map(|entry| entry.path.as_str())
        .collect();

    let trusted_records = read_ledger(trusted)?;
    let candidate_records = read_ledger(candidate)?;
    if candidate_records.len() < trusted_records.len()
        || candidate_records[..trusted_records.len()] != trusted_records[..]
    {
        return Err(PolicyError::new(
            "Bootstrap preservation ledger removed or edited an existing protected record",
        ));
    }
    let new_records = &candidate_records[trusted_records.len()..];
    let mut consumed = vec![false; new_records.len()];

    let trusted_archive = read_archive(trusted)?;
    let candidate_archive = read_archive(candidate)?;
    validate_archive_entries_are_trustworthy(candidate, &trusted_archive, &candidate_archive)?;
    let candidate_fingerprint_source =
        candidate.read_text(POLICY_SOURCE_PATH, crate::input::DEFAULT_FILE_LIMIT)?;
    let archive_fingerprint = archive_semantic_fingerprint(&candidate_archive)?;
    let declared_fingerprint =
        extract_declared_bootstrap_fingerprint(&candidate_fingerprint_source);

    for entry in &touched {
        let path = entry.path.as_str();
        let base_bytes = live_bytes(trusted, path, entry.status == 'A')?;
        let candidate_bytes = live_bytes(candidate, path, entry.status == 'D')?;
        let base_sha = sha256(&base_bytes);
        let candidate_sha = sha256(&candidate_bytes);

        let synchronized = candidate_archive.payload(path) == Some(candidate_bytes.as_slice())
            && changed_paths.contains(BOOTSTRAP_SNAPSHOT_PATH)
            && changed_paths.contains(POLICY_SOURCE_PATH)
            && declared_fingerprint
                .as_ref()
                .is_ok_and(|value| value == &archive_fingerprint);
        if synchronized {
            continue;
        }

        let archive_payload_sha = candidate_archive
            .payload(path)
            .map(sha256)
            .unwrap_or_default();
        let preserved_index = new_records.iter().position(|record| {
            record.path == path
                && record.base_sha256 == base_sha
                && record.candidate_sha256 == candidate_sha
                && record.archive_payload_sha256 == archive_payload_sha
                && record.archive_fingerprint == archive_fingerprint
        });
        match preserved_index {
            Some(index) => consumed[index] = true,
            None => return Err(coupling_error(path)),
        }
    }

    for (record, used) in new_records.iter().zip(consumed.iter()) {
        if !*used {
            return Err(PolicyError::new(format!(
                "Bootstrap preservation ledger contains an extraneous, stale, or unconsumed record: {}",
                record.path()
            )));
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::{extract_declared_bootstrap_fingerprint, parse_ledger};

    const VALID_HEX: &str = "96e8c3dabd6d341133ddae8732e90fe088c62f5dc78d1f579eeeac5f9e8497d3";

    #[test]
    fn extracts_the_exact_reviewed_declaration() {
        let source = format!(
            "const OTHER: &str = \"z\";\nconst BOOTSTRAP_FINGERPRINT: &str =\n    \"{VALID_HEX}\";\n"
        );
        assert_eq!(
            extract_declared_bootstrap_fingerprint(&source).expect("extract fingerprint"),
            VALID_HEX
        );
    }

    #[test]
    fn rejects_a_decoy_hidden_in_a_line_comment() {
        let source =
            format!("// const BOOTSTRAP_FINGERPRINT: &str = \"{VALID_HEX}\";\nconst X: u8 = 0;\n");
        assert!(extract_declared_bootstrap_fingerprint(&source).is_err());
    }

    #[test]
    fn rejects_a_decoy_hidden_in_a_block_comment() {
        let source = format!(
            "/* const BOOTSTRAP_FINGERPRINT: &str = \"{VALID_HEX}\"; */\nconst X: u8 = 0;\n"
        );
        assert!(extract_declared_bootstrap_fingerprint(&source).is_err());
    }

    #[test]
    fn rejects_a_decoy_hidden_in_a_string_literal() {
        let source = format!(
            "const NOTE: &str = \"const BOOTSTRAP_FINGERPRINT: &str = \\\"{VALID_HEX}\\\";\";\n"
        );
        assert!(extract_declared_bootstrap_fingerprint(&source).is_err());
    }

    #[test]
    fn rejects_ambiguous_multiple_declarations() {
        let source = format!(
            "const BOOTSTRAP_FINGERPRINT: &str = \"{VALID_HEX}\";\nconst BOOTSTRAP_FINGERPRINT: &str = \"{VALID_HEX}\";\n"
        );
        assert!(extract_declared_bootstrap_fingerprint(&source).is_err());
    }

    #[test]
    fn rejects_a_similarly_named_constant() {
        let source = format!("const BOOTSTRAP_FINGERPRINT_OLD: &str = \"{VALID_HEX}\";\n");
        assert!(extract_declared_bootstrap_fingerprint(&source).is_err());
    }

    #[test]
    fn rejects_uppercase_or_short_hex() {
        let source = "const BOOTSTRAP_FINGERPRINT: &str = \"ABCDEF\";\n";
        assert!(extract_declared_bootstrap_fingerprint(source).is_err());
    }

    #[test]
    fn empty_ledger_parses_to_no_records() {
        let ledger = parse_ledger(b"version = 1\nrecord = []\n").expect("parse empty ledger");
        assert!(ledger.is_empty());
    }

    #[test]
    fn ledger_rejects_out_of_order_sequence() {
        let text = format!(
            "version = 1\n[[record]]\nsequence = 2\npath = \".gitattributes\"\nbase_sha256 = \"{VALID_HEX}\"\ncandidate_sha256 = \"{VALID_HEX}\"\narchive_payload_sha256 = \"{VALID_HEX}\"\narchive_fingerprint = \"{VALID_HEX}\"\nrationale = \"reviewed intentionally\"\n"
        );
        assert!(parse_ledger(text.as_bytes()).is_err());
    }
}

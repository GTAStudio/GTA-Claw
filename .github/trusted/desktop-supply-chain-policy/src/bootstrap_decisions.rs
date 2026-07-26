//! Residual coupling between live Bootstrap sources and the historical snapshot.

use std::collections::{BTreeMap, BTreeSet};

use toml::Value as TomlValue;

use crate::changes::{ChangeManifest, validate_oid};
use crate::input::{DEFAULT_FILE_LIMIT, SafeRoot, sha256};
use crate::policy::{BOOTSTRAP_FILES, BootstrapSnapshotArchive, MAX_LOCK_BYTES, normalize_text};
use crate::{PolicyError, PolicyResult, error};

/// Canonical append-only preservation decision ledger.
pub const BOOTSTRAP_SOURCE_DECISIONS_PATH: &str =
    ".github/trusted/desktop-supply-chain-policy/policy/bootstrap-source-decisions.toml";
/// Historical Bootstrap archive reviewed alongside synchronized updates.
pub const BOOTSTRAP_SNAPSHOT_PATH: &str =
    ".github/trusted/desktop-supply-chain-policy/policy/bootstrap.snapshot";
/// Source containing the single reviewed Bootstrap fingerprint declaration.
pub const BOOTSTRAP_FINGERPRINT_SOURCE_PATH: &str =
    ".github/trusted/desktop-supply-chain-policy/src/policy.rs";

const MAX_DECISION_LEDGER_BYTES: u64 = 1024 * 1024;
const MAX_DECISIONS: usize = 4096;
const MAX_RATIONALE_BYTES: usize = 512;
const FINGERPRINT_DECLARATION_PREFIX: &[u8] = b"const BOOTSTRAP_FINGERPRINT: &str =\n    \"";

/// Successful residual coupling evidence.
#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub struct BootstrapSourceDecisionEvidence {
    /// Exact changed Bootstrap source count from trusted Git.
    pub changed_paths: usize,
    /// Sources synchronized into the candidate archive.
    pub synchronized_paths: usize,
    /// Sources covered by newly appended preservation decisions.
    pub preserved_paths: usize,
}

#[derive(Debug, Clone, Eq, PartialEq)]
struct PreservationDecision {
    id: usize,
    path: String,
    base_oid: String,
    base_live_sha256: String,
    candidate_live_sha256: String,
    snapshot_payload_sha256: String,
    snapshot_fingerprint: String,
    rationale: String,
}

/// A reviewed, archive-bound permission for one live source to diverge from its
/// frozen historical payload.
///
/// Unlike a [`PreservationDecision`], a standing preservation records no per-change
/// transition and is deliberately not bound to `manifest.base`, so it stays valid
/// while the protected base advances. It binds only archive-side facts, which makes
/// it void the moment the historical payload it names is rewritten.
#[derive(Debug, Clone, Eq, PartialEq)]
struct StandingPreservation {
    id: usize,
    path: String,
    base_oid: String,
    snapshot_payload_sha256: String,
    snapshot_fingerprint: String,
    rationale: String,
}

#[derive(Debug, Clone, Eq, PartialEq)]
struct DecisionLedger {
    decisions: Vec<PreservationDecision>,
    standing: Vec<StandingPreservation>,
}

fn exact_keys(
    table: &toml::map::Map<String, TomlValue>,
    expected: &[&str],
    label: &str,
) -> PolicyResult<()> {
    let actual = table.keys().map(String::as_str).collect::<BTreeSet<_>>();
    let expected = expected.iter().copied().collect::<BTreeSet<_>>();
    if actual != expected {
        return Err(PolicyError::new(format!(
            "Bootstrap source decision {label} schema changed"
        )));
    }
    Ok(())
}

/// Accepts exactly the schema-1 ledger root, with or without the optional
/// `standing` array, and reports whether that array is present.
fn ledger_root_shape(table: &toml::map::Map<String, TomlValue>) -> PolicyResult<bool> {
    let actual = table.keys().map(String::as_str).collect::<BTreeSet<_>>();
    for (expected, has_standing) in [
        (["schema_version", "decisions"].as_slice(), false),
        (["schema_version", "decisions", "standing"].as_slice(), true),
    ] {
        if actual == expected.iter().copied().collect::<BTreeSet<_>>() {
            return Ok(has_standing);
        }
    }
    Err(PolicyError::new(
        "Bootstrap source decision ledger schema changed",
    ))
}

fn decision_string<'a>(
    table: &'a toml::map::Map<String, TomlValue>,
    key: &str,
) -> PolicyResult<&'a str> {
    table.get(key).and_then(TomlValue::as_str).ok_or_else(|| {
        PolicyError::new(format!(
            "Bootstrap source decision field {key} must be a string"
        ))
    })
}

fn validate_hash(value: &str, field: &str) -> PolicyResult<()> {
    if value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Ok(());
    }
    Err(PolicyError::new(format!(
        "Bootstrap source decision field {field} must be a lowercase full SHA-256"
    )))
}

fn validate_rationale(value: &str) -> PolicyResult<()> {
    if value.is_empty()
        || value.len() > MAX_RATIONALE_BYTES
        || value.trim() != value
        || !value.bytes().all(|byte| (b' '..=b'~').contains(&byte))
    {
        return Err(PolicyError::new(format!(
            "Bootstrap source decision rationale must be 1..={MAX_RATIONALE_BYTES} bytes of trimmed printable ASCII"
        )));
    }
    Ok(())
}

fn toml_string(value: &str) -> String {
    let mut quoted = String::with_capacity(value.len() + 2);
    quoted.push('"');
    for character in value.chars() {
        if matches!(character, '"' | '\\') {
            quoted.push('\\');
        }
        quoted.push(character);
    }
    quoted.push('"');
    quoted
}

impl DecisionLedger {
    fn parse(bytes: &[u8], label: &str) -> PolicyResult<Self> {
        if u64::try_from(bytes.len()).unwrap_or(u64::MAX) > MAX_DECISION_LEDGER_BYTES {
            return Err(PolicyError::new(format!(
                "{label} Bootstrap source decision ledger exceeds {MAX_DECISION_LEDGER_BYTES} bytes"
            )));
        }
        let normalized = normalize_text(bytes);
        let text = std::str::from_utf8(&normalized)
            .map_err(|cause| error(&format!("parse {label} decision ledger as UTF-8"), cause))?;
        let value: TomlValue = toml::from_str(text)
            .map_err(|cause| error(&format!("parse {label} decision ledger TOML"), cause))?;
        let root = value.as_table().ok_or_else(|| {
            PolicyError::new(format!(
                "{label} Bootstrap source decision ledger root must be a table"
            ))
        })?;
        let has_standing = ledger_root_shape(root)?;
        if root.get("schema_version").and_then(TomlValue::as_integer) != Some(1) {
            return Err(PolicyError::new(
                "Bootstrap source decision ledger schema_version must be 1",
            ));
        }
        let values = root
            .get("decisions")
            .and_then(TomlValue::as_array)
            .ok_or_else(|| {
                PolicyError::new("Bootstrap source decision ledger decisions must be an array")
            })?;
        if values.len() > MAX_DECISIONS {
            return Err(PolicyError::new(format!(
                "Bootstrap source decision ledger exceeds {MAX_DECISIONS} decisions"
            )));
        }

        let mut decisions = Vec::with_capacity(values.len());
        let mut stable_keys = BTreeSet::new();
        for (index, value) in values.iter().enumerate() {
            let table = value.as_table().ok_or_else(|| {
                PolicyError::new("Bootstrap source decision entry must be a table")
            })?;
            exact_keys(
                table,
                &[
                    "id",
                    "path",
                    "base_oid",
                    "base_live_sha256",
                    "candidate_live_sha256",
                    "snapshot_payload_sha256",
                    "snapshot_fingerprint",
                    "rationale",
                ],
                "entry",
            )?;
            let id = table
                .get("id")
                .and_then(TomlValue::as_integer)
                .and_then(|value| usize::try_from(value).ok())
                .ok_or_else(|| {
                    PolicyError::new("Bootstrap source decision id must be a positive integer")
                })?;
            let expected_id = index + 1;
            if id != expected_id {
                return Err(PolicyError::new(format!(
                    "Bootstrap source decisions are not strictly sorted with consecutive ids: expected {expected_id}, found {id}"
                )));
            }
            let path = decision_string(table, "path")?;
            if !BOOTSTRAP_FILES.contains(&path) {
                return Err(PolicyError::new(format!(
                    "Bootstrap source decision path is not in BOOTSTRAP_FILES: {path}"
                )));
            }
            let base_oid = decision_string(table, "base_oid")?;
            validate_oid(base_oid, "Bootstrap source decision base_oid")?;
            if !stable_keys.insert((base_oid.to_owned(), path.to_owned())) {
                return Err(PolicyError::new(format!(
                    "Bootstrap source decision stable key is duplicated: base_oid={base_oid} path={path}"
                )));
            }
            let base_live_sha256 = decision_string(table, "base_live_sha256")?;
            let candidate_live_sha256 = decision_string(table, "candidate_live_sha256")?;
            let snapshot_payload_sha256 = decision_string(table, "snapshot_payload_sha256")?;
            let snapshot_fingerprint = decision_string(table, "snapshot_fingerprint")?;
            for (field, hash) in [
                ("base_live_sha256", base_live_sha256),
                ("candidate_live_sha256", candidate_live_sha256),
                ("snapshot_payload_sha256", snapshot_payload_sha256),
                ("snapshot_fingerprint", snapshot_fingerprint),
            ] {
                validate_hash(hash, field)?;
            }
            let rationale = decision_string(table, "rationale")?;
            validate_rationale(rationale)?;
            decisions.push(PreservationDecision {
                id,
                path: path.to_owned(),
                base_oid: base_oid.to_owned(),
                base_live_sha256: base_live_sha256.to_owned(),
                candidate_live_sha256: candidate_live_sha256.to_owned(),
                snapshot_payload_sha256: snapshot_payload_sha256.to_owned(),
                snapshot_fingerprint: snapshot_fingerprint.to_owned(),
                rationale: rationale.to_owned(),
            });
        }

        let standing = if has_standing {
            Self::parse_standing(root)?
        } else {
            Vec::new()
        };

        let ledger = Self {
            decisions,
            standing,
        };
        if ledger.canonical_text().as_bytes() != normalized {
            return Err(PolicyError::new(format!(
                "{label} Bootstrap source decision ledger is not canonical"
            )));
        }
        Ok(ledger)
    }

    fn parse_standing(
        root: &toml::map::Map<String, TomlValue>,
    ) -> PolicyResult<Vec<StandingPreservation>> {
        let values = root
            .get("standing")
            .and_then(TomlValue::as_array)
            .ok_or_else(|| {
                PolicyError::new("Bootstrap source decision ledger standing must be an array")
            })?;
        if values.is_empty() {
            return Err(PolicyError::new(
                "Bootstrap source decision ledger standing must be omitted when empty",
            ));
        }
        if values.len() > MAX_DECISIONS {
            return Err(PolicyError::new(format!(
                "Bootstrap source decision ledger exceeds {MAX_DECISIONS} standing preservations"
            )));
        }
        let mut standing = Vec::with_capacity(values.len());
        let mut previous_path: Option<&str> = None;
        for (index, value) in values.iter().enumerate() {
            let table = value.as_table().ok_or_else(|| {
                PolicyError::new("Bootstrap standing preservation entry must be a table")
            })?;
            exact_keys(
                table,
                &[
                    "id",
                    "path",
                    "base_oid",
                    "snapshot_payload_sha256",
                    "snapshot_fingerprint",
                    "rationale",
                ],
                "standing entry",
            )?;
            let id = table
                .get("id")
                .and_then(TomlValue::as_integer)
                .and_then(|value| usize::try_from(value).ok())
                .ok_or_else(|| {
                    PolicyError::new(
                        "Bootstrap standing preservation id must be a positive integer",
                    )
                })?;
            let expected_id = index + 1;
            if id != expected_id {
                return Err(PolicyError::new(format!(
                    "Bootstrap standing preservations are not strictly sorted with consecutive ids: expected {expected_id}, found {id}"
                )));
            }
            let path = decision_string(table, "path")?;
            if !BOOTSTRAP_FILES.contains(&path) {
                return Err(PolicyError::new(format!(
                    "Bootstrap standing preservation path is not in BOOTSTRAP_FILES: {path}"
                )));
            }
            if previous_path.is_some_and(|previous| previous >= path) {
                return Err(PolicyError::new(format!(
                    "Bootstrap standing preservations are not strictly sorted by path: {path}"
                )));
            }
            previous_path = Some(path);
            let base_oid = decision_string(table, "base_oid")?;
            validate_oid(base_oid, "Bootstrap standing preservation base_oid")?;
            let snapshot_payload_sha256 = decision_string(table, "snapshot_payload_sha256")?;
            let snapshot_fingerprint = decision_string(table, "snapshot_fingerprint")?;
            for (field, hash) in [
                ("snapshot_payload_sha256", snapshot_payload_sha256),
                ("snapshot_fingerprint", snapshot_fingerprint),
            ] {
                validate_hash(hash, field)?;
            }
            let rationale = decision_string(table, "rationale")?;
            validate_rationale(rationale)?;
            standing.push(StandingPreservation {
                id,
                path: path.to_owned(),
                base_oid: base_oid.to_owned(),
                snapshot_payload_sha256: snapshot_payload_sha256.to_owned(),
                snapshot_fingerprint: snapshot_fingerprint.to_owned(),
                rationale: rationale.to_owned(),
            });
        }
        Ok(standing)
    }

    fn canonical_text(&self) -> String {
        let mut output = String::from("schema_version = 1\n");
        if self.decisions.is_empty() {
            output.push_str("decisions = []\n");
        }
        for decision in &self.decisions {
            output.push_str("\n[[decisions]]\n");
            output.push_str(&format!("id = {}\n", decision.id));
            for (field, value) in [
                ("path", decision.path.as_str()),
                ("base_oid", decision.base_oid.as_str()),
                ("base_live_sha256", decision.base_live_sha256.as_str()),
                (
                    "candidate_live_sha256",
                    decision.candidate_live_sha256.as_str(),
                ),
                (
                    "snapshot_payload_sha256",
                    decision.snapshot_payload_sha256.as_str(),
                ),
                (
                    "snapshot_fingerprint",
                    decision.snapshot_fingerprint.as_str(),
                ),
                ("rationale", decision.rationale.as_str()),
            ] {
                output.push_str(field);
                output.push_str(" = ");
                output.push_str(&toml_string(value));
                output.push('\n');
            }
        }
        for entry in &self.standing {
            output.push_str("\n[[standing]]\n");
            output.push_str(&format!("id = {}\n", entry.id));
            for (field, value) in [
                ("path", entry.path.as_str()),
                ("base_oid", entry.base_oid.as_str()),
                (
                    "snapshot_payload_sha256",
                    entry.snapshot_payload_sha256.as_str(),
                ),
                ("snapshot_fingerprint", entry.snapshot_fingerprint.as_str()),
                ("rationale", entry.rationale.as_str()),
            ] {
                output.push_str(field);
                output.push_str(" = ");
                output.push_str(&toml_string(value));
                output.push('\n');
            }
        }
        output
    }
}

fn read_ledger(root: &SafeRoot, label: &str) -> PolicyResult<DecisionLedger> {
    let bytes = root.read_bytes(BOOTSTRAP_SOURCE_DECISIONS_PATH, MAX_DECISION_LEDGER_BYTES)?;
    DecisionLedger::parse(&bytes, label)
}

fn appended_decisions<'a>(
    trusted: &DecisionLedger,
    candidate: &'a DecisionLedger,
) -> PolicyResult<&'a [PreservationDecision]> {
    if candidate.decisions.len() < trusted.decisions.len() {
        return Err(PolicyError::new(format!(
            "Bootstrap source decision ledger deleted existing record id {}",
            candidate.decisions.len() + 1
        )));
    }
    for (trusted, candidate) in trusted.decisions.iter().zip(&candidate.decisions) {
        if trusted != candidate {
            return Err(PolicyError::new(format!(
                "Bootstrap source decision ledger edited existing record id {}",
                trusted.id
            )));
        }
    }
    Ok(&candidate.decisions[trusted.decisions.len()..])
}

fn skip_block_comment(bytes: &[u8], start: usize) -> PolicyResult<usize> {
    let mut depth = 1_usize;
    let mut offset = start + 2;
    while offset + 1 < bytes.len() {
        if bytes[offset..].starts_with(b"/*") {
            depth = depth
                .checked_add(1)
                .ok_or_else(|| PolicyError::new("Rust block-comment nesting overflowed"))?;
            offset += 2;
        } else if bytes[offset..].starts_with(b"*/") {
            depth -= 1;
            offset += 2;
            if depth == 0 {
                return Ok(offset);
            }
        } else {
            offset += 1;
        }
    }
    Err(PolicyError::new(
        "Bootstrap fingerprint source has an unterminated block comment",
    ))
}

fn skip_quoted_string(bytes: &[u8], quote: usize) -> PolicyResult<usize> {
    let mut offset = quote + 1;
    while offset < bytes.len() {
        match bytes[offset] {
            b'\\' => {
                offset = offset.checked_add(2).ok_or_else(|| {
                    PolicyError::new("Bootstrap fingerprint source string offset overflowed")
                })?;
            }
            b'"' => return Ok(offset + 1),
            _ => offset += 1,
        }
    }
    Err(PolicyError::new(
        "Bootstrap fingerprint source has an unterminated string",
    ))
}

fn raw_string_open(bytes: &[u8], start: usize) -> Option<(usize, usize)> {
    let mut offset = if bytes.get(start) == Some(&b'r') {
        start + 1
    } else if matches!(bytes.get(start), Some(b'b' | b'c')) && bytes.get(start + 1) == Some(&b'r') {
        start + 2
    } else {
        return None;
    };
    let hashes_start = offset;
    while bytes.get(offset) == Some(&b'#') {
        offset += 1;
    }
    (bytes.get(offset) == Some(&b'"')).then_some((offset, offset - hashes_start))
}

fn skip_raw_string(bytes: &[u8], quote: usize, hashes: usize) -> PolicyResult<usize> {
    let mut offset = quote + 1;
    while offset < bytes.len() {
        if bytes[offset] == b'"'
            && bytes
                .get(offset + 1..offset + 1 + hashes)
                .is_some_and(|suffix| suffix.iter().all(|byte| *byte == b'#'))
        {
            return Ok(offset + 1 + hashes);
        }
        offset += 1;
    }
    Err(PolicyError::new(
        "Bootstrap fingerprint source has an unterminated raw string",
    ))
}

fn exact_fingerprint_declaration(source: &[u8], start: usize) -> PolicyResult<String> {
    let declaration = source
        .get(start..)
        .ok_or_else(|| PolicyError::new("Bootstrap fingerprint declaration offset changed"))?;
    if !declaration.starts_with(FINGERPRINT_DECLARATION_PREFIX) {
        return Err(PolicyError::new(
            "Bootstrap fingerprint declaration syntax changed",
        ));
    }
    let hash_start = FINGERPRINT_DECLARATION_PREFIX.len();
    let hash_end = hash_start + 64;
    let hash = declaration
        .get(hash_start..hash_end)
        .ok_or_else(|| PolicyError::new("Bootstrap fingerprint declaration is truncated"))?;
    if declaration.get(hash_end..hash_end + 2) != Some(b"\";") {
        return Err(PolicyError::new(
            "Bootstrap fingerprint declaration syntax changed",
        ));
    }
    let hash = std::str::from_utf8(hash)
        .map_err(|cause| error("parse Bootstrap fingerprint declaration", cause))?;
    validate_hash(hash, "BOOTSTRAP_FINGERPRINT")?;
    Ok(hash.to_owned())
}

fn parse_bootstrap_fingerprint_source(bytes: &[u8]) -> PolicyResult<String> {
    let source = std::str::from_utf8(bytes)
        .map_err(|cause| error("parse Bootstrap fingerprint source as UTF-8", cause))?;
    let bytes = source.as_bytes();
    let mut offset = 0_usize;
    let mut brace_depth = 0_usize;
    let mut previous_identifier: Option<(&str, usize, bool)> = None;
    let mut penultimate_identifier: Option<&str> = None;
    let mut last_token_was_semicolon = false;
    let mut declarations = Vec::new();

    while offset < bytes.len() {
        if bytes[offset].is_ascii_whitespace() {
            offset += 1;
            continue;
        }
        if bytes[offset..].starts_with(b"//") {
            offset = bytes[offset..]
                .iter()
                .position(|byte| *byte == b'\n')
                .map_or(bytes.len(), |length| offset + length + 1);
            continue;
        }
        if bytes[offset..].starts_with(b"/*") {
            offset = skip_block_comment(bytes, offset)?;
            continue;
        }
        if let Some((quote, hashes)) = raw_string_open(bytes, offset) {
            offset = skip_raw_string(bytes, quote, hashes)?;
            previous_identifier = None;
            penultimate_identifier = None;
            last_token_was_semicolon = false;
            continue;
        }
        let quote = if bytes[offset] == b'"' {
            Some(offset)
        } else if matches!(bytes[offset], b'b' | b'c') && bytes.get(offset + 1) == Some(&b'"') {
            Some(offset + 1)
        } else {
            None
        };
        if let Some(quote) = quote {
            offset = skip_quoted_string(bytes, quote)?;
            previous_identifier = None;
            penultimate_identifier = None;
            last_token_was_semicolon = false;
            continue;
        }
        if bytes[offset].is_ascii_alphabetic() || bytes[offset] == b'_' {
            let start = offset;
            offset += 1;
            while bytes
                .get(offset)
                .is_some_and(|byte| byte.is_ascii_alphanumeric() || *byte == b'_')
            {
                offset += 1;
            }
            let identifier = &source[start..offset];
            if identifier == "BOOTSTRAP_FINGERPRINT" {
                match previous_identifier {
                    Some(("const", declaration_start, true)) => {
                        declarations.push((
                            brace_depth,
                            exact_fingerprint_declaration(bytes, declaration_start)?,
                        ));
                    }
                    Some(("const", _, false)) => {
                        return Err(PolicyError::new(
                            "Bootstrap fingerprint declaration must not be attribute-gated or prefixed",
                        ));
                    }
                    Some(("static", _, _)) => {
                        return Err(PolicyError::new(
                            "Bootstrap fingerprint must use the exact const declaration",
                        ));
                    }
                    Some(("mut", _, _)) if penultimate_identifier == Some("static") => {
                        return Err(PolicyError::new(
                            "Bootstrap fingerprint must use the exact const declaration",
                        ));
                    }
                    _ => {}
                }
            }
            penultimate_identifier = previous_identifier.map(|(identifier, _, _)| identifier);
            previous_identifier = Some((identifier, start, last_token_was_semicolon));
            last_token_was_semicolon = false;
            continue;
        }
        match bytes[offset] {
            b'{' => brace_depth = brace_depth.saturating_add(1),
            b'}' => {
                brace_depth = brace_depth.checked_sub(1).ok_or_else(|| {
                    PolicyError::new("Bootstrap fingerprint source brace nesting changed")
                })?;
            }
            _ => {}
        }
        previous_identifier = None;
        penultimate_identifier = None;
        last_token_was_semicolon = bytes[offset] == b';';
        offset += 1;
    }
    if brace_depth != 0 {
        return Err(PolicyError::new(
            "Bootstrap fingerprint source brace nesting changed",
        ));
    }
    if declarations.len() != 1 || declarations[0].0 != 0 {
        return Err(PolicyError::new(
            "Bootstrap fingerprint source must contain exactly one top-level exact declaration",
        ));
    }
    Ok(declarations.remove(0).1)
}

struct SnapshotState {
    bytes: Vec<u8>,
    source_bytes: Vec<u8>,
    archive: BootstrapSnapshotArchive,
    fingerprint: String,
    configured_fingerprint: String,
}

fn read_snapshot_state(root: &SafeRoot, label: &str) -> PolicyResult<SnapshotState> {
    let bytes = root.read_bytes(BOOTSTRAP_SNAPSHOT_PATH, 512 * 1024 * 1024)?;
    let archive = BootstrapSnapshotArchive::parse(&bytes)
        .map_err(|cause| error(&format!("parse {label} Bootstrap snapshot"), cause))?;
    archive
        .validate_bootstrap_contents()
        .map_err(|cause| error(&format!("validate {label} Bootstrap snapshot"), cause))?;
    if archive.canonical_bytes()? != bytes {
        return Err(PolicyError::new(format!(
            "{label} Bootstrap snapshot is not canonical"
        )));
    }
    let source_bytes = root.read_bytes(BOOTSTRAP_FINGERPRINT_SOURCE_PATH, DEFAULT_FILE_LIMIT)?;
    let configured_fingerprint =
        parse_bootstrap_fingerprint_source(&source_bytes).map_err(|cause| {
            error(
                &format!("parse {label} Bootstrap fingerprint source"),
                cause,
            )
        })?;
    let fingerprint = archive.semantic_fingerprint();
    Ok(SnapshotState {
        bytes,
        source_bytes,
        archive,
        fingerprint,
        configured_fingerprint,
    })
}

fn manifest_statuses(manifest: &ChangeManifest) -> PolicyResult<BTreeMap<&str, char>> {
    let mut statuses = BTreeMap::new();
    for changed in &manifest.paths {
        if statuses
            .insert(changed.path.as_str(), changed.status)
            .is_some()
        {
            return Err(PolicyError::new(format!(
                "trusted changed-path manifest repeats path: {}",
                changed.path
            )));
        }
    }
    Ok(statuses)
}

fn residual_error(path: &str) -> PolicyError {
    PolicyError::new(format!(
        "Bootstrap source change requires synchronized snapshot/fingerprint or a new bound preservation decision: {path}"
    ))
}

/// Returns the standing preservation that still covers `path`, if any.
///
/// The entry must be present *and identical* in both the protected base ledger and the
/// candidate ledger. Reading it from the protected base is what makes it unforgeable: a
/// candidate cannot mint its own coverage, because an entry the base does not already
/// carry is ignored, and an entry the candidate edits or drops stops matching.
fn standing_preservation<'a>(
    trusted: &'a DecisionLedger,
    candidate: &DecisionLedger,
    path: &str,
) -> Option<&'a StandingPreservation> {
    let entry = trusted.standing.iter().find(|entry| entry.path == path)?;
    candidate
        .standing
        .iter()
        .any(|candidate_entry| candidate_entry == entry)
        .then_some(entry)
}

/// Forces an explicit snapshot synchronization, a newly appended preservation decision, or an
/// already-reviewed standing preservation for every changed Bootstrap source.
pub fn validate_bootstrap_source_decisions(
    trusted: &SafeRoot,
    candidate: &SafeRoot,
    manifest: &ChangeManifest,
) -> PolicyResult<BootstrapSourceDecisionEvidence> {
    let statuses = manifest_statuses(manifest)?;
    let changed = BOOTSTRAP_FILES
        .into_iter()
        .filter_map(|path| statuses.get(path).copied().map(|status| (path, status)))
        .collect::<Vec<_>>();

    let trusted_ledger = read_ledger(trusted, "protected-base")?;
    let candidate_ledger = read_ledger(candidate, "candidate")?;
    let additions = appended_decisions(&trusted_ledger, &candidate_ledger)?;
    let trusted_snapshot = read_snapshot_state(trusted, "protected-base")?;
    let candidate_snapshot = read_snapshot_state(candidate, "candidate")?;
    if trusted_snapshot.fingerprint != trusted_snapshot.configured_fingerprint {
        return Err(PolicyError::new(
            "protected-base Bootstrap snapshot fingerprint does not match BOOTSTRAP_FINGERPRINT",
        ));
    }

    let snapshot_manifest_status = statuses.get(BOOTSTRAP_SNAPSHOT_PATH).copied();
    let fingerprint_manifest_status = statuses.get(BOOTSTRAP_FINGERPRINT_SOURCE_PATH).copied();
    let ledger_manifest_status = statuses.get(BOOTSTRAP_SOURCE_DECISIONS_PATH).copied();
    let snapshot_bytes_changed = trusted_snapshot.bytes != candidate_snapshot.bytes;
    let fingerprint_source_changed =
        trusted_snapshot.source_bytes != candidate_snapshot.source_bytes;
    let mut synchronized = BTreeSet::new();
    let mut preserved = BTreeSet::new();
    let mut used_additions = vec![false; additions.len()];

    for (path, status) in &changed {
        if *status != 'M' {
            return Err(PolicyError::new(format!(
                "Bootstrap source change cannot be coupled because live bytes are unavailable: {path} status={status}"
            )));
        }
        let trusted_live = normalize_text(&trusted.read_bytes(path, MAX_LOCK_BYTES)?);
        let candidate_live = normalize_text(&candidate.read_bytes(path, MAX_LOCK_BYTES)?);
        let trusted_payload = trusted_snapshot
            .archive
            .payload(path)
            .ok_or_else(|| PolicyError::new(format!("protected-base snapshot lacks {path}")))?;
        let candidate_payload = candidate_snapshot
            .archive
            .payload(path)
            .ok_or_else(|| PolicyError::new(format!("candidate snapshot lacks {path}")))?;
        let archive_payload_changed = trusted_payload != candidate_payload;
        let update_is_complete = archive_payload_changed
            && candidate_payload == candidate_live
            && snapshot_bytes_changed
            && fingerprint_source_changed
            && snapshot_manifest_status == Some('M')
            && fingerprint_manifest_status == Some('M')
            && candidate_snapshot.fingerprint == candidate_snapshot.configured_fingerprint;
        if update_is_complete {
            synchronized.insert(*path);
            continue;
        }

        let matches = additions
            .iter()
            .enumerate()
            .filter(|(_, decision)| decision.path == *path)
            .collect::<Vec<_>>();
        if matches.is_empty() {
            if archive_payload_changed {
                return Err(residual_error(path));
            }
            let Some(entry) = standing_preservation(&trusted_ledger, &candidate_ledger, path)
            else {
                return Err(residual_error(path));
            };
            if entry.snapshot_payload_sha256 != sha256(candidate_payload) {
                return Err(PolicyError::new(format!(
                    "Bootstrap standing preservation no longer binds the frozen historical payload: {path}"
                )));
            }
            if entry.snapshot_fingerprint != candidate_snapshot.fingerprint {
                return Err(PolicyError::new(format!(
                    "Bootstrap standing preservation no longer binds the candidate Bootstrap archive fingerprint: {path}"
                )));
            }
            preserved.insert(*path);
            continue;
        }
        if matches.len() != 1 {
            return Err(PolicyError::new(format!(
                "candidate appended duplicate Bootstrap preservation decisions for {path}"
            )));
        }
        let (addition_index, decision) = matches[0];
        if archive_payload_changed {
            return Err(PolicyError::new(format!(
                "Bootstrap preservation decision moved the embedded historical payload: {path}"
            )));
        }
        if ledger_manifest_status != Some('M') {
            return Err(PolicyError::new(format!(
                "new Bootstrap preservation decision is missing the trusted ledger changed-path entry: {path}"
            )));
        }
        if decision.base_oid != manifest.base {
            return Err(PolicyError::new(format!(
                "Bootstrap preservation decision base_oid does not bind {path}"
            )));
        }
        for (field, actual, expected) in [
            (
                "base_live_sha256",
                decision.base_live_sha256.as_str(),
                sha256(&trusted_live),
            ),
            (
                "candidate_live_sha256",
                decision.candidate_live_sha256.as_str(),
                sha256(&candidate_live),
            ),
            (
                "snapshot_payload_sha256",
                decision.snapshot_payload_sha256.as_str(),
                sha256(candidate_payload),
            ),
            (
                "snapshot_fingerprint",
                decision.snapshot_fingerprint.as_str(),
                candidate_snapshot.fingerprint.clone(),
            ),
        ] {
            if actual != expected {
                return Err(PolicyError::new(format!(
                    "Bootstrap preservation decision {field} does not bind {path}"
                )));
            }
        }
        used_additions[addition_index] = true;
        preserved.insert(*path);
    }

    for path in BOOTSTRAP_FILES {
        if trusted_snapshot.archive.payload(path) != candidate_snapshot.archive.payload(path)
            && !synchronized.contains(path)
        {
            return Err(PolicyError::new(format!(
                "candidate Bootstrap snapshot changed without a synchronized live source decision: {path}"
            )));
        }
    }
    if let Some((_, decision)) = additions
        .iter()
        .enumerate()
        .find(|(index, _)| !used_additions[*index])
    {
        return Err(PolicyError::new(format!(
            "candidate contains extraneous Bootstrap preservation decision id {} for {}",
            decision.id, decision.path
        )));
    }
    if candidate_snapshot.fingerprint != candidate_snapshot.configured_fingerprint {
        return Err(PolicyError::new(
            "candidate Bootstrap snapshot fingerprint does not match BOOTSTRAP_FINGERPRINT",
        ));
    }

    Ok(BootstrapSourceDecisionEvidence {
        changed_paths: changed.len(),
        synchronized_paths: synchronized.len(),
        preserved_paths: preserved.len(),
    })
}

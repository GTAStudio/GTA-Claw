//! Bounded read-only `OpenClaw` state inspection, never an activation or import operation.

use std::collections::BTreeMap;
use std::fmt::{self, Display, Formatter};
use std::path::Path;

use claw_tools::sandbox::{EntryKind, RelativePath, Sandbox, SandboxLimits};
use serde::de::{DeserializeSeed, MapAccess, SeqAccess, Visitor};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};

/// Upstream source used to verify configuration and per-agent session layout.
pub const SOURCE_COMMIT: &str = "3a9d69db306cd7f081e06254cb89c4bcc14a7107";
const MAX_ENTRIES: usize = 4096;
const MAX_TOTAL_BYTES: u64 = 64 * 1024 * 1024;
const MAX_FILE_BYTES: u64 = 8 * 1024 * 1024;
const MAX_JSONL_LINES: usize = 100_000;
const MAX_VALUE_NODES: usize = 16_384;
const MAX_VALUE_DEPTH: usize = 64;

struct BoundedDocument(Value);

struct ValueSeed<'a> {
    remaining: &'a mut usize,
    depth: usize,
}

impl<'de> DeserializeSeed<'de> for ValueSeed<'_> {
    type Value = Value;

    fn deserialize<Deserializer: serde::Deserializer<'de>>(
        self,
        deserializer: Deserializer,
    ) -> Result<Value, Deserializer::Error> {
        if self.depth > MAX_VALUE_DEPTH || *self.remaining == 0 {
            return Err(serde::de::Error::custom(
                "source document exceeded its structural budget",
            ));
        }
        *self.remaining -= 1;
        deserializer.deserialize_any(self)
    }
}

impl<'de> Visitor<'de> for ValueSeed<'_> {
    type Value = Value;

    fn expecting(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter.write_str("a bounded JSON value with unambiguous fields")
    }

    fn visit_bool<Error: serde::de::Error>(self, value: bool) -> Result<Value, Error> {
        Ok(Value::Bool(value))
    }
    fn visit_i64<Error: serde::de::Error>(self, value: i64) -> Result<Value, Error> {
        Ok(Value::Number(value.into()))
    }
    fn visit_u64<Error: serde::de::Error>(self, value: u64) -> Result<Value, Error> {
        Ok(Value::Number(value.into()))
    }
    fn visit_f64<Error: serde::de::Error>(self, value: f64) -> Result<Value, Error> {
        serde_json::Number::from_f64(value)
            .map(Value::Number)
            .ok_or_else(|| Error::custom("non-finite numbers require manual mapping"))
    }
    fn visit_unit<Error: serde::de::Error>(self) -> Result<Value, Error> {
        Ok(Value::Null)
    }
    fn visit_str<Error: serde::de::Error>(self, value: &str) -> Result<Value, Error> {
        Ok(Value::String(value.to_owned()))
    }
    fn visit_string<Error: serde::de::Error>(self, value: String) -> Result<Value, Error> {
        Ok(Value::String(value))
    }

    fn visit_seq<Sequence: SeqAccess<'de>>(
        self,
        mut sequence: Sequence,
    ) -> Result<Value, Sequence::Error> {
        let mut values = Vec::new();
        while let Some(value) = sequence.next_element_seed(ValueSeed {
            remaining: self.remaining,
            depth: self.depth + 1,
        })? {
            values.push(value);
        }
        Ok(Value::Array(values))
    }

    fn visit_map<Mapping: MapAccess<'de>>(
        self,
        mut mapping: Mapping,
    ) -> Result<Value, Mapping::Error> {
        let mut fields = serde_json::Map::new();
        while let Some(key) = mapping.next_key::<String>()? {
            if fields.contains_key(&key) {
                return Err(serde::de::Error::custom(
                    "duplicate source fields require manual mapping",
                ));
            }
            let value = mapping.next_value_seed(ValueSeed {
                remaining: self.remaining,
                depth: self.depth + 1,
            })?;
            fields.insert(key, value);
        }
        Ok(Value::Object(fields))
    }
}

impl<'de> Deserialize<'de> for BoundedDocument {
    fn deserialize<Deserializer: serde::Deserializer<'de>>(
        deserializer: Deserializer,
    ) -> Result<Self, Deserializer::Error> {
        let mut remaining = MAX_VALUE_NODES;
        ValueSeed {
            remaining: &mut remaining,
            depth: 0,
        }
        .deserialize(deserializer)
        .map(Self)
    }
}

/// Classification of source material; none of these authorizes copying or executing it.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SourceKind {
    /// JSON/JSON5 configuration, projected without its values.
    Configuration,
    /// Agent session index JSON.
    SessionIndex,
    /// JSONL transcript, inspected without returning message contents.
    Transcript,
    /// SQLite or WAL/SHM requires a verified consistent snapshot and reader.
    SqliteSnapshotRequired,
    /// Credential, identity or pairing material, not read.
    CredentialsExcluded,
    /// Scripts, plugins and executable assets require explicit porting review.
    ExecutionReviewRequired,
    /// Logs and transient runtime data, not read.
    TransientExcluded,
    /// A link or non-regular object, never followed.
    LinkExcluded,
    /// Other source material needing an explicit mapping.
    Unmapped,
}

/// Secret-free metadata for one source entry.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SourceEntry {
    /// Relative path inside the explicitly selected state root.
    pub path: String,
    /// Required handling category.
    pub kind: SourceKind,
    /// Observed file size; absent for directories and links.
    pub bytes: Option<u64>,
    /// Number of records parsed, not their contents.
    pub records: Option<usize>,
    /// Whether this preview actually read the file contents.
    pub content_read: bool,
}

/// Stable diagnostic which cannot contain source configuration values or message text.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct PreviewDiagnostic {
    /// Machine-readable reason for manual review.
    pub code: &'static str,
    /// Affected relative entry, if one can be safely identified.
    pub path: Option<String>,
}

/// A read-only inventory, explicitly not a verified snapshot or executable migration plan.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
#[allow(
    clippy::struct_excessive_bools,
    reason = "The wire envelope reports independent explicit safety guarantees"
)]
pub struct OpenClawPreview {
    /// Version of this native preview envelope.
    pub schema_version: u32,
    /// Fixed upstream layout reference, not a detected installed binary version.
    pub reference_commit: &'static str,
    /// Root-name profile hint only; never consulted as a permission.
    pub profile_hint: Option<String>,
    /// Config's recorded last-touched version, not a verified installed version.
    pub recorded_version: Option<String>,
    /// A recognized configuration or session layout was found.
    pub recognized: bool,
    /// Always false until an independent consistent snapshot procedure succeeds.
    pub snapshot_verified: bool,
    /// Always false: this API has no copy, credential activation or execution path.
    pub migration_ready: bool,
    /// Always false: historical work cannot resume from an inspection.
    pub resume_execution: bool,
    /// Number of actual file bytes read within the inspection budget.
    pub bytes_read: u64,
    /// Stable digest of the inventory and private source content digests, not a snapshot proof.
    pub fingerprint: String,
    /// Sorted bounded source entry metadata.
    pub entries: Vec<SourceEntry>,
    /// Counts by known configuration surface; values and secret material are omitted.
    pub configured_surfaces: BTreeMap<String, usize>,
    /// Explicitly unresolved or excluded content.
    pub diagnostics: Vec<PreviewDiagnostic>,
}

/// A safe inspection refusal, without OS paths or source payloads in its message.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PreviewError {
    /// The explicit root is absent, a link, not a directory or unsafe to pin.
    UnsafeRoot,
    /// A source object cannot be read without violating the sandbox boundary.
    SourceUnavailable,
    /// The bounded file, entry, depth or byte budget was exceeded.
    LimitExceeded,
    /// A JSON/JSON5/JSONL source does not match its advertised container shape.
    InvalidSource,
}

impl Display for PreviewError {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::UnsafeRoot => "OpenClaw preview requires an explicit existing non-link directory",
            Self::SourceUnavailable => "OpenClaw source cannot be read safely; preserve it and inspect its permissions or links",
            Self::LimitExceeded => "OpenClaw inspection exceeded its fixed resource budget; select a bounded verified snapshot",
            Self::InvalidSource => "OpenClaw source contains an invalid configuration, session index or transcript; no import was attempted",
        })
    }
}

impl std::error::Error for PreviewError {}

fn diagnostic(preview: &mut OpenClawPreview, code: &'static str, path: Option<&str>) {
    preview.diagnostics.push(PreviewDiagnostic {
        code,
        path: path.map(str::to_owned),
    });
}

fn excluded_directory(name: &str) -> Option<SourceKind> {
    match name.to_ascii_lowercase().as_str() {
        "credentials" | "identity" | "devices" | "pairing" => Some(SourceKind::CredentialsExcluded),
        "extensions" | "plugins" | "node_modules" | ".git" => {
            Some(SourceKind::ExecutionReviewRequired)
        }
        "logs" | "tmp" | "cache" => Some(SourceKind::TransientExcluded),
        _ => None,
    }
}

fn classify(path: &str) -> SourceKind {
    let lower = path.to_ascii_lowercase();
    let name = lower.rsplit('/').next().unwrap_or(&lower);
    let extension = Path::new(name).extension().and_then(|value| value.to_str());
    if matches!(
        name,
        ".env" | "auth-profiles.json" | "auth.json" | "device.json" | "device-auth.json"
    ) || matches!(extension, Some("key" | "pem"))
    {
        SourceKind::CredentialsExcluded
    } else if matches!(name, "openclaw.json" | "clawdbot.json") {
        SourceKind::Configuration
    } else if matches!(extension, Some("sqlite" | "sqlite3" | "db"))
        || name.ends_with("-wal")
        || name.ends_with("-shm")
    {
        SourceKind::SqliteSnapshotRequired
    } else if name == "sessions.json"
        && lower.starts_with("agents/")
        && lower.contains("/sessions/")
    {
        SourceKind::SessionIndex
    } else if extension == Some("jsonl")
        && lower.starts_with("agents/")
        && lower.contains("/sessions/")
    {
        SourceKind::Transcript
    } else if matches!(
        extension,
        Some("js" | "mjs" | "cjs" | "ts" | "wasm" | "exe" | "dll" | "so" | "sh" | "ps1")
    ) {
        SourceKind::ExecutionReviewRequired
    } else {
        SourceKind::Unmapped
    }
}

fn inspect_configuration(
    value: &Value,
    path: &str,
    preview: &mut OpenClawPreview,
) -> Result<(), PreviewError> {
    let object = value.as_object().ok_or(PreviewError::InvalidSource)?;
    preview.recognized = true;
    if let Some(version) = value
        .pointer("/meta/lastTouchedVersion")
        .and_then(Value::as_str)
        && !version.is_empty()
        && version.len() <= 64
        && version
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'-' | b'+'))
    {
        preview.recorded_version = Some(version.to_owned());
    }
    for surface in [
        "channels", "models", "plugins", "skills", "cron", "hooks", "session", "memory", "agents",
        "gateway",
    ] {
        if let Some(value) = object.get(surface) {
            preview.configured_surfaces.insert(
                surface.to_owned(),
                value.as_object().map_or(1, serde_json::Map::len),
            );
        }
    }
    if value.pointer("/agents/defaults/workspace").is_some()
        || value.pointer("/agents/list").is_some()
    {
        diagnostic(
            preview,
            "WORKSPACE_REFERENCES_REQUIRE_EXPLICIT_SNAPSHOT_ROOTS",
            Some(path),
        );
    }
    let mut pending = vec![value];
    let mut visited = 0;
    while let Some(value) = pending.pop() {
        visited += 1;
        if visited > 16_384 {
            return Err(PreviewError::LimitExceeded);
        }
        match value {
            Value::Object(fields) => {
                if fields.contains_key("$include") {
                    diagnostic(preview, "CONFIG_INCLUDES_NOT_RESOLVED", Some(path));
                }
                pending.extend(fields.values());
            }
            Value::Array(values) => pending.extend(values),
            _ => {}
        }
    }
    diagnostic(preview, "CONFIG_VALUES_AND_SECRETS_WITHHELD", Some(path));
    Ok(())
}

fn inspect_content(
    kind: SourceKind,
    bytes: &[u8],
    path: &str,
    preview: &mut OpenClawPreview,
) -> Result<Option<usize>, PreviewError> {
    let text = std::str::from_utf8(bytes).map_err(|_| PreviewError::InvalidSource)?;
    match kind {
        SourceKind::Configuration => {
            let BoundedDocument(value) =
                json5::from_str(text).map_err(|_| PreviewError::InvalidSource)?;
            inspect_configuration(&value, path, preview)?;
            Ok(None)
        }
        SourceKind::SessionIndex => {
            let BoundedDocument(value) =
                serde_json::from_str(text).map_err(|_| PreviewError::InvalidSource)?;
            let entries = value.as_object().ok_or(PreviewError::InvalidSource)?;
            if entries.len() > MAX_JSONL_LINES {
                return Err(PreviewError::LimitExceeded);
            }
            for entry in entries.values() {
                if !entry.is_object() {
                    return Err(PreviewError::InvalidSource);
                }
                if let Some(target) = entry["sessionFile"].as_str() {
                    if target.starts_with("sqlite:") {
                        diagnostic(
                            preview,
                            "SQLITE_TRANSCRIPT_TARGET_REQUIRES_VERIFIED_READER",
                            Some(path),
                        );
                    } else if Path::new(target).is_absolute()
                        || target.contains("..")
                        || target.contains(':')
                    {
                        diagnostic(
                            preview,
                            "SESSION_FILE_REFERENCE_REQUIRES_MANUAL_MAPPING",
                            Some(path),
                        );
                    }
                }
            }
            preview.recognized = true;
            Ok(Some(entries.len()))
        }
        SourceKind::Transcript => {
            let mut records = 0;
            for line in text.lines().filter(|line| !line.trim().is_empty()) {
                records += 1;
                if records > MAX_JSONL_LINES || line.len() > 1024 * 1024 {
                    return Err(PreviewError::LimitExceeded);
                }
                let BoundedDocument(value) =
                    serde_json::from_str(line).map_err(|_| PreviewError::InvalidSource)?;
                if !value.is_object() || !value["type"].is_string() {
                    return Err(PreviewError::InvalidSource);
                }
            }
            preview.recognized = true;
            diagnostic(
                preview,
                "TRANSCRIPT_SCHEMA_AND_REFERENCES_REQUIRE_MAPPING",
                Some(path),
            );
            Ok(Some(records))
        }
        _ => Ok(None),
    }
}

/// Inspects only the explicitly selected `OpenClaw` state tree, with no writes or external I/O.
///
/// # Errors
/// Refuses unsafe roots, links used as input files, malformed recognized data and exceeded budgets.
/// Existing state, credentials, plugins, tasks and source configuration are never modified.
pub fn inspect(root: &Path) -> Result<OpenClawPreview, PreviewError> {
    #[cfg(windows)]
    if !matches!(root.components().next(), Some(std::path::Component::Prefix(prefix)) if matches!(prefix.kind(), std::path::Prefix::Disk(_) | std::path::Prefix::VerbatimDisk(_)))
    {
        return Err(PreviewError::UnsafeRoot);
    }
    let metadata = std::fs::symlink_metadata(root).map_err(|_| PreviewError::UnsafeRoot)?;
    if !root.is_absolute() || !metadata.is_dir() || metadata.file_type().is_symlink() {
        return Err(PreviewError::UnsafeRoot);
    }
    #[cfg(windows)]
    {
        use std::os::windows::fs::MetadataExt;
        if metadata.file_attributes() & 0x400 != 0 {
            return Err(PreviewError::UnsafeRoot);
        }
    }
    let sandbox = Sandbox::new_pinned(
        root,
        SandboxLimits {
            max_file_bytes: MAX_FILE_BYTES,
            max_directory_entries: MAX_ENTRIES,
            max_walked_files: MAX_ENTRIES,
            ..SandboxLimits::default()
        },
    )
    .map_err(|_| PreviewError::UnsafeRoot)?;
    let mut preview = OpenClawPreview {
        schema_version: 1,
        reference_commit: SOURCE_COMMIT,
        profile_hint: root
            .file_name()
            .and_then(|name| name.to_str())
            .and_then(|name| name.strip_prefix(".openclaw-"))
            .filter(|name| {
                name.len() <= 64
                    && name
                        .bytes()
                        .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
            })
            .map(str::to_owned),
        recorded_version: None,
        recognized: false,
        snapshot_verified: false,
        migration_ready: false,
        resume_execution: false,
        bytes_read: 0,
        fingerprint: String::new(),
        entries: Vec::new(),
        configured_surfaces: BTreeMap::new(),
        diagnostics: Vec::new(),
    };
    let mut pending: Vec<RelativePath> = vec![sandbox.resolve_root().relative().clone()];
    let mut visited = 0;
    let mut witnesses = BTreeMap::new();
    while let Some(directory) = pending.pop() {
        if directory.components().len() > 12 {
            return Err(PreviewError::LimitExceeded);
        }
        let entries = sandbox
            .read_directory(&directory)
            .map_err(|_| PreviewError::SourceUnavailable)?;
        for entry in entries {
            visited += 1;
            if visited > MAX_ENTRIES {
                return Err(PreviewError::LimitExceeded);
            }
            let path = entry.path.as_str().to_owned();
            let kind = match entry.kind {
                EntryKind::Directory => {
                    if let Some(kind) = excluded_directory(entry.path.file_name()) {
                        kind
                    } else {
                        pending.push(entry.path);
                        continue;
                    }
                }
                EntryKind::File => classify(&path),
                EntryKind::Link | EntryKind::Other => SourceKind::LinkExcluded,
            };
            let should_read = matches!(
                kind,
                SourceKind::Configuration | SourceKind::SessionIndex | SourceKind::Transcript
            );
            let records = if should_read {
                let size = entry.size_bytes.ok_or(PreviewError::SourceUnavailable)?;
                if size > MAX_FILE_BYTES
                    || preview.bytes_read.saturating_add(size) > MAX_TOTAL_BYTES
                {
                    return Err(PreviewError::LimitExceeded);
                }
                let bytes = sandbox
                    .read_file(&entry.path)
                    .map_err(|_| PreviewError::SourceUnavailable)?;
                preview.bytes_read = preview
                    .bytes_read
                    .checked_add(
                        u64::try_from(bytes.len()).map_err(|_| PreviewError::LimitExceeded)?,
                    )
                    .ok_or(PreviewError::LimitExceeded)?;
                if preview.bytes_read > MAX_TOTAL_BYTES {
                    return Err(PreviewError::LimitExceeded);
                }
                witnesses.insert(path.clone(), hex(&Sha256::digest(&bytes)));
                inspect_content(kind, &bytes, &path, &mut preview)?
            } else {
                None
            };
            preview.entries.push(SourceEntry {
                path,
                kind,
                bytes: entry.size_bytes,
                records,
                content_read: should_read,
            });
        }
    }
    preview
        .entries
        .sort_by(|left, right| left.path.cmp(&right.path));
    diagnostic(
        &mut preview,
        "LIVE_TREE_IS_NOT_A_VERIFIED_CONSISTENT_SNAPSHOT",
        None,
    );
    diagnostic(
        &mut preview,
        "HISTORICAL_TASKS_REMAIN_PAUSED_NO_AUTOMATIC_EXECUTION",
        None,
    );
    diagnostic(
        &mut preview,
        "SQLITE_WAL_CREDENTIALS_AND_EXTERNAL_ROOTS_REQUIRE_SEPARATE_REVIEW",
        None,
    );
    let witness = serde_json::to_vec(&(&preview.entries, witnesses))
        .map_err(|_| PreviewError::InvalidSource)?;
    preview.fingerprint = hex(&Sha256::digest(witness));
    Ok(preview)
}

fn hex(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    bytes
        .iter()
        .flat_map(|byte| [HEX[usize::from(byte >> 4)], HEX[usize::from(byte & 15)]])
        .map(char::from)
        .collect()
}

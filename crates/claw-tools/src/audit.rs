//! Structured audit records for every tool invocation, with secret redaction.

use std::error::Error;
use std::fmt::{self, Display, Formatter};

use serde::Serialize;
use serde_json::{Map, Value, json};

use crate::permission::{Capability, DenialReason, GrantId, Resource};

/// Replacement emitted in place of any value classified as sensitive.
pub const REDACTION: &str = "[REDACTED]";

/// Maximum characters preserved from any single audited string.
const MAX_AUDITED_STRING_CHARS: usize = 256;
/// Maximum array elements preserved in an audited value.
const MAX_AUDITED_ITEMS: usize = 32;
/// Maximum nesting depth walked while redacting.
const MAX_AUDITED_DEPTH: u8 = 8;
/// Shortest run of token-shaped characters treated as an opaque credential.
const MIN_OPAQUE_TOKEN_CHARS: usize = 32;

/// Argument names whose values are never recorded.
const SENSITIVE_KEY_FRAGMENTS: [&str; 14] = [
    "apikey",
    "api_key",
    "authorization",
    "auth",
    "cookie",
    "credential",
    "passphrase",
    "password",
    "passwd",
    "private",
    "pwd",
    "secret",
    "session",
    "token",
];

/// Literal prefixes that mark a string as credential material.
const SENSITIVE_VALUE_PREFIXES: [&str; 8] = [
    "-----begin",
    "aws_",
    "basic ",
    "bearer ",
    "ghp_",
    "github_pat_",
    "sk-",
    "xoxb-",
];

/// Outcome recorded for one tool invocation.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AuditOutcome {
    /// The invocation was authorized and completed.
    Allowed,
    /// A policy gate refused the invocation.
    Denied,
    /// The invocation was authorized but failed during execution.
    Failed,
}

/// Stable reason attached to an audit record.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AuditReason {
    /// Every gate passed and the tool completed.
    PolicySatisfied,
    /// The permission broker refused the request.
    PolicyRejected,
    /// Argument validation refused the payload.
    ValidationRejected,
    /// The requested tool is not registered.
    UnknownTool,
    /// The sandbox refused the requested path.
    SandboxRejected,
    /// A declared resource limit was exceeded.
    LimitExceeded,
    /// The tool ran but reported a failure.
    ExecutionFailed,
}

/// Stage of an invocation that a record describes.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AuditPhase {
    /// Written after authorization and before the tool runs.
    Authorized,
    /// Written after the invocation reached a terminal state.
    Completed,
}

/// One durable record describing a single tool invocation attempt.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct ToolAuditRecord {
    /// Invoked tool identity.
    pub tool: String,
    /// Stage of the invocation.
    pub phase: AuditPhase,
    /// Capability the tool declared.
    pub capability: Option<Capability>,
    /// Concrete resource the capability was exercised against.
    pub resource: Option<Resource>,
    /// Grant that authorized the invocation, when one did.
    pub grant: Option<GrantId>,
    /// Allowed, denied, or failed.
    pub outcome: AuditOutcome,
    /// Stable reason code.
    pub reason: AuditReason,
    /// Refusal detail when the broker denied the request.
    pub denial: Option<DenialReason>,
    /// Redacted argument payload.
    pub arguments: Value,
    /// Caller-supplied wall-clock instant.
    pub unix_millis: u64,
}

/// Durable audit persistence port.
///
/// Implementations must return only after the record is committed. A tool
/// invocation whose audit write fails is aborted rather than silently allowed.
pub trait ToolAuditSink {
    /// Persists exactly one record or fails the protected invocation.
    fn persist(&mut self, record: &ToolAuditRecord) -> Result<(), AuditError>;
}

/// A mandatory audit write failed.
#[derive(Debug)]
pub struct AuditError {
    context: &'static str,
    source: Option<Box<dyn Error + Send + Sync>>,
}

impl AuditError {
    /// Creates an audit failure with a static context string.
    #[must_use]
    pub const fn new(context: &'static str) -> Self {
        Self {
            context,
            source: None,
        }
    }

    /// Attaches a concrete adapter error.
    #[must_use]
    pub fn with_source(context: &'static str, source: impl Error + Send + Sync + 'static) -> Self {
        Self {
            context,
            source: Some(Box::new(source)),
        }
    }
}

impl Display for AuditError {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        write!(formatter, "mandatory tool audit failed: {}", self.context)
    }
}

impl Error for AuditError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        self.source
            .as_ref()
            .map(|error| error.as_ref() as &(dyn Error + 'static))
    }
}

/// An audit sink that keeps records in memory for tests and local inspection.
#[derive(Clone, Debug, Default)]
pub struct InMemoryAuditSink {
    records: Vec<ToolAuditRecord>,
}

impl InMemoryAuditSink {
    /// Creates an empty sink.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Returns every persisted record in invocation order.
    #[must_use]
    pub fn records(&self) -> &[ToolAuditRecord] {
        &self.records
    }
}

impl ToolAuditSink for InMemoryAuditSink {
    fn persist(&mut self, record: &ToolAuditRecord) -> Result<(), AuditError> {
        self.records.push(record.clone());
        Ok(())
    }
}

/// Produces an audit-safe description of a payload with no schema behind it.
///
/// Used only for an unregistered tool name, where nothing about the payload is
/// trustworthy: key names are sanitized and every value is withheld.
#[must_use]
pub fn opaque_arguments(value: &Value) -> Value {
    let Some(object) = value.as_object() else {
        return json!({ "[shape]": shape_name(value) });
    };
    let keys: Vec<Value> = object
        .keys()
        .take(MAX_AUDITED_ITEMS)
        .map(|key| Value::String(sanitize_key(key)))
        .collect();
    json!({
        "withheld": true,
        "field_count": u64::try_from(object.len()).unwrap_or(u64::MAX),
        "fields": Value::Array(keys),
    })
}

/// Names the JSON shape of a value without revealing any of its content.
fn shape_name(value: &Value) -> &'static str {
    match value {
        Value::Null => "null",
        Value::Bool(_) => "boolean",
        Value::Number(_) => "number",
        Value::String(_) => "string",
        Value::Array(_) => "array",
        Value::Object(_) => "object",
    }
}

/// Keeps an attacker-chosen key name out of the audit log verbatim.
fn sanitize_key(key: &str) -> String {
    let sanitized: String = key
        .chars()
        .filter(|character| character.is_ascii_alphanumeric() || matches!(character, '_' | '-'))
        .take(48)
        .collect();
    if sanitized.is_empty() {
        "<unprintable>".to_owned()
    } else {
        sanitized
    }
}

/// Produces an audit-safe copy of a caller-supplied argument payload.
///
/// Values are redacted when their key names or their own shape indicate
/// credential material, long strings are truncated, and both breadth and depth
/// are bounded so a hostile payload cannot inflate the audit log.
#[must_use]
pub fn redact(value: &Value) -> Value {
    redact_at(value, 0)
}

fn redact_at(value: &Value, depth: u8) -> Value {
    if depth >= MAX_AUDITED_DEPTH {
        return Value::String("[TRUNCATED]".to_owned());
    }
    match value {
        Value::String(text) => redact_string(text),
        Value::Array(items) => {
            let mut output: Vec<Value> = items
                .iter()
                .take(MAX_AUDITED_ITEMS)
                .map(|item| redact_at(item, depth + 1))
                .collect();
            if items.len() > MAX_AUDITED_ITEMS {
                output.push(Value::String("[TRUNCATED]".to_owned()));
            }
            Value::Array(output)
        }
        Value::Object(entries) => {
            let mut output = Map::new();
            for (key, item) in entries.iter().take(MAX_AUDITED_ITEMS) {
                let redacted = if is_sensitive_key(key) {
                    Value::String(REDACTION.to_owned())
                } else {
                    redact_at(item, depth + 1)
                };
                output.insert(key.clone(), redacted);
            }
            if entries.len() > MAX_AUDITED_ITEMS {
                output.insert(
                    "[TRUNCATED]".to_owned(),
                    Value::from(entries.len() - MAX_AUDITED_ITEMS),
                );
            }
            Value::Object(output)
        }
        other => other.clone(),
    }
}

fn redact_string(text: &str) -> Value {
    if looks_like_credential(text) {
        return Value::String(REDACTION.to_owned());
    }
    if text.chars().count() > MAX_AUDITED_STRING_CHARS {
        let head: String = text.chars().take(MAX_AUDITED_STRING_CHARS).collect();
        return Value::String(format!("{head}[TRUNCATED]"));
    }
    Value::String(text.to_owned())
}

fn is_sensitive_key(key: &str) -> bool {
    let normalized: String = key
        .chars()
        .filter(|character| character.is_ascii_alphanumeric() || *character == '_')
        .flat_map(char::to_lowercase)
        .collect();
    SENSITIVE_KEY_FRAGMENTS
        .iter()
        .any(|fragment| normalized.contains(fragment))
}

fn looks_like_credential(text: &str) -> bool {
    let lowered = text.trim().to_ascii_lowercase();
    if SENSITIVE_VALUE_PREFIXES
        .iter()
        .any(|prefix| lowered.starts_with(prefix))
    {
        return true;
    }
    text.split(|character: char| {
        !(character.is_ascii_alphanumeric() || matches!(character, '-' | '_' | '+' | '/' | '='))
    })
    .any(is_opaque_token)
}

/// Classifies a run as an opaque credential when it is long and mixes classes.
fn is_opaque_token(candidate: &str) -> bool {
    if candidate.len() < MIN_OPAQUE_TOKEN_CHARS {
        return false;
    }
    let digits = candidate.bytes().filter(u8::is_ascii_digit).count();
    let lower = candidate.bytes().filter(u8::is_ascii_lowercase).count();
    let upper = candidate.bytes().filter(u8::is_ascii_uppercase).count();
    let classes = usize::from(digits > 0) + usize::from(lower > 0) + usize::from(upper > 0);
    classes >= 2 && digits + lower + upper >= candidate.len() * 3 / 4
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    #[test]
    fn sensitive_keys_are_replaced_regardless_of_spelling() {
        let redacted = redact(&json!({
            "Authorization": "Bearer abc",
            "api-key": "value",
            "SESSION_ID": "value",
            "userPassword": "value",
            "path": "src/main.rs",
        }));
        assert_eq!(redacted["Authorization"], Value::String(REDACTION.into()));
        assert_eq!(redacted["api-key"], Value::String(REDACTION.into()));
        assert_eq!(redacted["SESSION_ID"], Value::String(REDACTION.into()));
        assert_eq!(redacted["userPassword"], Value::String(REDACTION.into()));
        assert_eq!(redacted["path"], Value::String("src/main.rs".into()));
    }

    #[test]
    fn credential_shaped_values_are_replaced_even_under_benign_keys() {
        let redacted = redact(&json!({
            "note": "ghp_0123456789abcdefghijklmnopqrstuvwxyz",
            "header": "Bearer short",
            "pem": "-----BEGIN PRIVATE KEY-----",
            "opaque": "AKIA5RANDOMLOOKING0123456789abcdefXYZ",
            "prose": "the quick brown fox jumps over the lazy dog again and again",
            "digits": "01234567890123456789012345678901234567890",
        }));
        assert_eq!(redacted["note"], Value::String(REDACTION.into()));
        assert_eq!(redacted["header"], Value::String(REDACTION.into()));
        assert_eq!(redacted["pem"], Value::String(REDACTION.into()));
        assert_eq!(redacted["opaque"], Value::String(REDACTION.into()));
        assert_eq!(
            redacted["prose"],
            Value::String("the quick brown fox jumps over the lazy dog again and again".to_owned())
        );
        assert_eq!(
            redacted["digits"],
            Value::String("01234567890123456789012345678901234567890".to_owned()),
            "single-class runs are not treated as opaque credentials"
        );
    }

    #[test]
    fn long_strings_deep_nesting_and_wide_arrays_are_bounded() {
        let long = "a".repeat(MAX_AUDITED_STRING_CHARS + 50);
        let redacted = redact(&json!({ "content": long }));
        let rendered = redacted["content"].as_str().expect("string");
        assert_eq!(
            rendered.chars().count(),
            MAX_AUDITED_STRING_CHARS + "[TRUNCATED]".len()
        );
        assert!(rendered.ends_with("[TRUNCATED]"));

        let wide: Vec<Value> = (0..MAX_AUDITED_ITEMS + 5).map(Value::from).collect();
        let redacted = redact(&Value::Array(wide));
        let items = redacted.as_array().expect("array");
        assert_eq!(items.len(), MAX_AUDITED_ITEMS + 1);
        assert_eq!(
            items[MAX_AUDITED_ITEMS],
            Value::String("[TRUNCATED]".to_owned())
        );

        let mut deep = Value::String("leaf".to_owned());
        for _ in 0..(MAX_AUDITED_DEPTH + 2) {
            deep = Value::Array(vec![deep]);
        }
        let redacted = redact(&deep);
        let mut cursor = &redacted;
        let mut levels = 0_u8;
        while let Some(items) = cursor.as_array() {
            cursor = &items[0];
            levels += 1;
        }
        assert_eq!(levels, MAX_AUDITED_DEPTH);
        assert_eq!(cursor, &Value::String("[TRUNCATED]".to_owned()));
    }

    #[test]
    fn a_serialized_record_never_contains_the_original_secret() {
        let record = ToolAuditRecord {
            tool: "fs_write".to_owned(),
            phase: AuditPhase::Completed,
            capability: Some(Capability::FilesystemWrite),
            resource: Some(Resource::Path("config/app.json".to_owned())),
            grant: None,
            outcome: AuditOutcome::Allowed,
            reason: AuditReason::PolicySatisfied,
            denial: None,
            arguments: redact(&json!({
                "path": "config/app.json",
                "token": "hunter2-super-secret",
            })),
            unix_millis: 1_700_000_000_000,
        };
        let rendered = serde_json::to_string(&record).expect("serialize record");
        assert!(!rendered.contains("hunter2-super-secret"));
        assert!(rendered.contains(REDACTION));
        assert!(rendered.contains("config/app.json"));
    }
}

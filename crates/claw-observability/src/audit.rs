//! Durable security audit channel, deliberately separate from tracing.

use std::collections::BTreeMap;
use std::fs::{File, OpenOptions};
use std::io::{self, Write};
use std::path::Path;
use std::sync::Mutex;
use std::time::{SystemTime, UNIX_EPOCH};

use serde::Serialize;

use crate::redaction::{REDACTED, is_sensitive_field};

static AUDIT_WRITE_LOCK: Mutex<()> = Mutex::new(());

/// Outcome of a security-relevant operation.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AuditOutcome {
    /// The operation was allowed and completed.
    Success,
    /// The operation was explicitly denied.
    Denied,
    /// The operation failed after authorization.
    Failure,
}

/// A structured security audit record.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct AuditEvent {
    timestamp_ms: u128,
    category: String,
    action: String,
    outcome: AuditOutcome,
    actor: String,
    target: String,
    fields: BTreeMap<String, String>,
}

impl AuditEvent {
    /// Creates an audit event timestamped with the current system clock.
    #[must_use]
    pub fn new(
        category: impl Into<String>,
        action: impl Into<String>,
        outcome: AuditOutcome,
        actor: impl Into<String>,
        target: impl Into<String>,
    ) -> Self {
        let timestamp_ms = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_or(0, |duration| duration.as_millis());
        Self {
            timestamp_ms,
            category: category.into(),
            action: action.into(),
            outcome,
            actor: actor.into(),
            target: target.into(),
            fields: BTreeMap::new(),
        }
    }

    /// Adds a field, automatically redacting values with sensitive keys.
    #[must_use]
    pub fn field(mut self, key: impl Into<String>, value: impl Into<String>) -> Self {
        let key = key.into();
        let value = if is_sensitive_field(&key) {
            REDACTED.to_owned()
        } else {
            value.into()
        };
        self.fields.insert(key, value);
        self
    }

    /// Milliseconds since the Unix epoch.
    #[must_use]
    pub const fn timestamp_ms(&self) -> u128 {
        self.timestamp_ms
    }
}

/// Separate synchronous port for security audit events.
pub trait AuditSink: Send + Sync {
    /// Persists an event before returning success.
    fn record(&self, event: &AuditEvent) -> io::Result<()>;
}

/// Append-only JSON-lines audit sink that flushes and synchronizes each event.
#[derive(Debug)]
pub struct DurableFileAuditSink {
    file: Mutex<File>,
}

impl DurableFileAuditSink {
    /// Opens or creates an append-only audit file.
    pub fn open(path: impl AsRef<Path>) -> io::Result<Self> {
        let file = OpenOptions::new().create(true).append(true).open(path)?;
        Ok(Self {
            file: Mutex::new(file),
        })
    }
}

impl AuditSink for DurableFileAuditSink {
    fn record(&self, event: &AuditEvent) -> io::Result<()> {
        let mut encoded = serde_json::to_vec(event).map_err(io::Error::other)?;
        encoded.push(b'\n');
        let _write_guard = AUDIT_WRITE_LOCK
            .lock()
            .map_err(|_| io::Error::other("global audit writer lock poisoned"))?;
        let mut file = self
            .file
            .lock()
            .map_err(|_| io::Error::other("audit file lock poisoned"))?;
        file.write_all(&encoded)?;
        file.flush()?;
        file.sync_data()
    }
}

/// Thread-safe in-memory audit sink for tests.
#[derive(Debug, Default)]
pub struct InMemoryAuditSink {
    events: Mutex<Vec<AuditEvent>>,
}

impl InMemoryAuditSink {
    /// Returns all events in recording order.
    pub fn events(&self) -> io::Result<Vec<AuditEvent>> {
        self.events
            .lock()
            .map(|events| events.clone())
            .map_err(|_| io::Error::other("audit memory lock poisoned"))
    }
}

impl AuditSink for InMemoryAuditSink {
    fn record(&self, event: &AuditEvent) -> io::Result<()> {
        self.events
            .lock()
            .map_err(|_| io::Error::other("audit memory lock poisoned"))?
            .push(event.clone());
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::thread;

    use serde_json::Value;

    use super::{AuditEvent, AuditOutcome, AuditSink, DurableFileAuditSink, InMemoryAuditSink};
    use crate::redaction::REDACTED;

    static NEXT_FILE: AtomicU64 = AtomicU64::new(0);

    fn temporary_file() -> std::path::PathBuf {
        std::env::temp_dir().join(format!(
            "claw-audit-{}-{}.jsonl",
            std::process::id(),
            NEXT_FILE.fetch_add(1, Ordering::Relaxed)
        ))
    }

    #[test]
    fn audit_fields_apply_mandatory_redaction() {
        let sink = InMemoryAuditSink::default();
        let event = AuditEvent::new(
            "authorization",
            "gateway.connect",
            AuditOutcome::Denied,
            "device-1",
            "gateway",
        )
        .field("reason", "scope missing")
        .field("access_token", "must-not-appear");
        sink.record(&event).expect("record event");

        let recorded = sink.events().expect("read events");
        assert_eq!(recorded, vec![event]);
        let json = serde_json::to_value(&recorded[0]).expect("serialize event");
        assert_eq!(json["fields"]["reason"], "scope missing");
        assert_eq!(json["fields"]["access_token"], REDACTED);
        assert_eq!(
            json["fields"]
                .as_object()
                .expect("audit fields object")
                .values()
                .filter(|value| value.as_str() == Some("must-not-appear"))
                .count(),
            0
        );
    }

    #[test]
    fn durable_sink_appends_complete_json_lines() {
        let path = temporary_file();
        let first = AuditEvent::new(
            "pairing",
            "approve",
            AuditOutcome::Success,
            "operator",
            "device-a",
        );
        let second = AuditEvent::new(
            "authorization",
            "tool.invoke",
            AuditOutcome::Denied,
            "session-a",
            "shell",
        );
        {
            let sink = DurableFileAuditSink::open(&path).expect("open audit sink");
            sink.record(&first).expect("record first");
            sink.record(&second).expect("record second");
        }

        let content = fs::read_to_string(&path).expect("read audit file");
        let values = content
            .lines()
            .map(|line| serde_json::from_str::<Value>(line).expect("JSON line"))
            .collect::<Vec<_>>();
        assert_eq!(values.len(), 2);
        assert_eq!(values[0]["category"], "pairing");
        assert_eq!(values[0]["outcome"], "success");
        assert_eq!(values[0]["target"], "device-a");
        assert_eq!(values[1]["category"], "authorization");
        assert_eq!(values[1]["outcome"], "denied");
        assert_eq!(values[1]["target"], "shell");
        fs::remove_file(path).expect("remove audit file");
    }

    #[test]
    fn separate_sink_instances_preserve_json_line_framing() {
        let path = temporary_file();
        let first = Arc::new(DurableFileAuditSink::open(&path).expect("open first sink"));
        let second = Arc::new(DurableFileAuditSink::open(&path).expect("open second sink"));
        let handles = [first, second].map(|sink| {
            thread::spawn(move || {
                for index in 0..10 {
                    sink.record(&AuditEvent::new(
                        "authorization",
                        format!("attempt-{index}"),
                        AuditOutcome::Success,
                        "operator",
                        "gateway",
                    ))
                    .expect("record concurrent event");
                }
            })
        });
        for handle in handles {
            handle.join().expect("join audit writer");
        }

        let content = fs::read_to_string(&path).expect("read audit file");
        let records = content
            .lines()
            .map(|line| serde_json::from_str::<Value>(line).expect("complete JSON line"))
            .collect::<Vec<_>>();
        assert_eq!(records.len(), 20);
        assert_eq!(
            records
                .iter()
                .filter(|record| record["category"] == "authorization")
                .count(),
            20
        );
        fs::remove_file(path).expect("remove audit file");
    }
}

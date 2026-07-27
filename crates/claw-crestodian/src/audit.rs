//! Durable, metadata-only rescue audit trail.
//!
//! Audit persistence is mandatory: an approved ring-zero mutation is abandoned
//! when its pre-action record cannot be written, so the trail is opened for
//! append, flushed, and synced on every event rather than buffered.

use std::fs::OpenOptions;
use std::io::Write;
use std::path::{Path, PathBuf};

use crate::CrestodianError;
use crate::rescue::{RescueAuditEvent, RescueAuditSink};
use crate::state::ensure_parent_directory;

/// Append-only JSON Lines rescue audit trail at a caller-selected path.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct JsonlRescueAudit {
    path: PathBuf,
}

impl JsonlRescueAudit {
    /// Creates a trail writer without touching the filesystem.
    #[must_use]
    pub fn new(path: impl Into<PathBuf>) -> Self {
        Self { path: path.into() }
    }

    /// Returns the trail path.
    #[must_use]
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Reads every persisted event in write order.
    ///
    /// A missing trail is an empty trail; a malformed line is an error rather
    /// than a silently skipped record.
    pub fn read(path: &Path) -> Result<Vec<RescueAuditEvent>, CrestodianError> {
        let bytes = match std::fs::read(path) {
            Ok(bytes) => bytes,
            Err(source)
                if matches!(
                    source.kind(),
                    std::io::ErrorKind::NotFound | std::io::ErrorKind::NotADirectory
                ) =>
            {
                return Ok(Vec::new());
            }
            Err(source) => return Err(CrestodianError::io(path, source)),
        };
        let text = String::from_utf8(bytes).map_err(|error| CrestodianError::AuditDecode {
            path: path.to_owned(),
            line: 0,
            message: error.to_string(),
        })?;
        let mut events = Vec::new();
        for (index, line) in text.lines().enumerate() {
            if line.trim().is_empty() {
                continue;
            }
            let event =
                serde_json::from_str(line).map_err(|error| CrestodianError::AuditDecode {
                    path: path.to_owned(),
                    line: index + 1,
                    message: error.to_string(),
                })?;
            events.push(event);
        }
        Ok(events)
    }
}

impl RescueAuditSink for JsonlRescueAudit {
    type Error = CrestodianError;

    fn persist(&mut self, event: &RescueAuditEvent) -> Result<(), Self::Error> {
        ensure_parent_directory(&self.path)?;
        let mut line = serde_json::to_vec(event).map_err(|error| {
            CrestodianError::Config(claw_config::ConfigError::Serialize(error.to_string()))
        })?;
        line.push(b'\n');
        let mut file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(&self.path)
            .map_err(|source| CrestodianError::io(&self.path, source))?;
        file.write_all(&line)
            .and_then(|()| file.flush())
            .and_then(|()| file.sync_all())
            .map_err(|source| CrestodianError::io(&self.path, source))
    }
}

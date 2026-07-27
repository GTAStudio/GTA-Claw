use std::fs;
use std::path::{Path, PathBuf};

use claw_config::{WriteOutcome, write_bytes_atomically};
use serde::{Deserialize, Serialize};

use crate::CrestodianError;

/// Current Crestodian auxiliary-state schema.
pub const CRESTODIAN_STATE_SCHEMA_VERSION: u32 = 1;

/// Small, non-secret setup and recovery state.
#[derive(Clone, Debug, Eq, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CrestodianState {
    /// State schema version.
    pub schema_version: u32,
    /// Whether guided first-run setup completed.
    pub setup_completed: bool,
    /// Optional configured workspace.
    pub workspace: Option<PathBuf>,
    /// Caller-supplied time of the last successful recovery.
    pub last_recovery_unix_ms: Option<u64>,
}

impl Default for CrestodianState {
    fn default() -> Self {
        Self {
            schema_version: CRESTODIAN_STATE_SCHEMA_VERSION,
            setup_completed: false,
            workspace: None,
            last_recovery_unix_ms: None,
        }
    }
}

pub(crate) fn decode_state(path: &Path, bytes: &[u8]) -> Result<CrestodianState, CrestodianError> {
    let refuse = |json_path: String, message: String| CrestodianError::StateDecode {
        path: path.to_owned(),
        json_path,
        message,
    };
    let mut deserializer = serde_json::Deserializer::from_slice(bytes);
    let state = serde_path_to_error::deserialize(&mut deserializer).map_err(|error| {
        let json_path = error.path().to_string();
        refuse(
            if json_path.is_empty() {
                "<root>".to_owned()
            } else {
                json_path
            },
            error.inner().to_string(),
        )
    })?;
    // Bytes trailing a complete state object mean the file is not one this
    // build wrote; reporting it corrupt keeps a torn tail from passing as
    // healthy state just because its first object happened to parse.
    deserializer
        .end()
        .map_err(|error| refuse("<root>".to_owned(), error.to_string()))?;
    Ok(state)
}

pub(crate) fn write_state(
    path: &Path,
    state: &CrestodianState,
) -> Result<WriteOutcome, CrestodianError> {
    ensure_parent_directory(path)?;
    let mut bytes = serde_json::to_vec_pretty(state).map_err(|error| {
        CrestodianError::Config(claw_config::ConfigError::Serialize(error.to_string()))
    })?;
    bytes.push(b'\n');
    write_bytes_atomically(path, &bytes).map_err(CrestodianError::Config)
}

pub(crate) fn ensure_parent_directory(path: &Path) -> Result<(), CrestodianError> {
    let parent = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    fs::create_dir_all(parent).map_err(|source| CrestodianError::io(parent, source))
}

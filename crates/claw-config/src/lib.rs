//! Strict GTA Claw JSON5 configuration, atomic persistence, transactional
//! reload classification, and deterministic GTA legacy environment migration.
//!
//! This crate implements only the typed GTA legacy runtime domains represented
//! by [`ConfigDomain`]. It does not claim the full upstream OpenClaw
//! configuration surface and rejects unknown domains rather than retaining
//! untyped values.

mod error;
mod io;
mod migration;
mod model;
mod reload;
mod wire;

use serde::de::IgnoredAny;

pub use error::ConfigError;
pub use io::{WriteOutcome, WriteWarning, load_file, write_file};
pub use migration::{
    ManualMapping, MigrationDiagnostic, MigrationError, MigrationResult, migrate_legacy_environment,
};
pub use model::{
    AdminConfig, AuthConfig, CONFIG_SCHEMA_VERSION, ChannelsConfig, ConfigDomain, ConfigSnapshot,
    CopilotConfig, CoreConfig, DiscordConfig, LegacySkillsConfig, LogLevel, LoggingConfig,
    NetworkConfig, RoleConfig, SecretRef, ServerConfig, SessionsConfig, TeamsConfig,
    TelegramConfig, UpdatesConfig, WhatsappConfig,
};
pub use reload::{ReloadManager, ReloadOutcome};
use wire::EnvelopeWire;

/// Parses UTF-8 JSON5 into a completely validated typed snapshot.
pub fn parse_json5(source: &str, source_name: &str) -> Result<ConfigSnapshot, ConfigError> {
    json5::from_str::<IgnoredAny>(source).map_err(|error| ConfigError::Syntax {
        source_name: source_name.to_owned(),
        message: error.to_string(),
    })?;

    let mut deserializer = json5::Deserializer::from_str(source);
    let wire: EnvelopeWire =
        serde_path_to_error::deserialize(&mut deserializer).map_err(|error| {
            let path = error.path().to_string();
            ConfigError::Decode {
                source_name: source_name.to_owned(),
                path: if path.is_empty() {
                    "<root>".to_owned()
                } else {
                    path
                },
                message: error.inner().to_string(),
            }
        })?;
    wire.validate()
}

/// Serializes a validated snapshot to deterministic JSON5.
///
/// Secret material cannot be serialized because snapshots contain only
/// [`SecretRef`] values.
pub fn to_json5(snapshot: &ConfigSnapshot) -> Result<String, ConfigError> {
    let mut output = json5::to_string(&EnvelopeWire::from(snapshot))
        .map_err(|error| ConfigError::Serialize(error.to_string()))?;
    output.push('\n');
    Ok(output)
}

/// Returns the generated JSON Schema for the strict JSON5 document shape.
pub fn schema_json() -> Result<String, ConfigError> {
    let schema = schemars::schema_for!(EnvelopeWire);
    serde_json::to_string_pretty(&schema).map_err(|error| ConfigError::Serialize(error.to_string()))
}

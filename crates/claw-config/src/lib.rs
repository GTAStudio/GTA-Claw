//! Strict GTA Claw JSON5 configuration, atomic persistence, transactional
//! reload classification, and deterministic GTA legacy environment migration.
//!
//! The additive [`OpenClawConfig`] model covers the frozen 47-domain upstream
//! source surface. The original [`ConfigSnapshot`] API remains the strict,
//! validated GTA legacy runtime envelope used by existing callers.
//!
//! [`parse_role_document`] owns the interpretation half of the frozen remote
//! role contract: the size bound, the JSON and plain-text encodings, the
//! `content`/`prompt` precedence, the optional model, and the diagnostics.
//! The transport half stays behind the [`RoleSourceFetcher`] port, because this
//! crate has no HTTP client and does not gain one.

mod atomicfs;
/// Strongly typed source configuration for the frozen 47-domain contract.
pub mod domains;
mod error;
mod io;
mod layer;
mod migration;
mod model;
mod reload;
mod role;
mod versioning;
mod wire;

use serde::de::IgnoredAny;

pub use domains::{
    AcpDomain, AgentBinding, AgentsDomain, ApprovalsDomain, AssistantUiConfig, AudioDomain,
    AuditDomain, AuthDomain, AutomaticUpdateConfig, BroadcastDomain, BrowserDomain,
    CONFIG_DOMAIN_NAMES, ChannelsDomain, CliDomain, CloudWorkersDomain, CommandsDomain,
    CommitmentsDomain, CrestodianConfig, CrestodianRescueConfig, CronDomain, DiagnosticsDomain,
    DiscoveryDomain, EnvironmentConfig, GatewayDomain, HooksDomain, InstallPolicyConfig,
    InstallPolicyExec, InstallPolicyExecSource, InstallTarget, LoggingDomain, MarketplacesDomain,
    McpDomain, MediaConfig, MemoryDomain, MessagesDomain, MetaConfig, ModelsDomain, NodeHostDomain,
    OpenClawConfig, OpenClawConfigChange, OpenClawConfigFileWatcher, OpenClawConfigHub,
    OpenClawConfigLayers, OpenClawConfigSubscription, OpenClawDomain, PluginsDomain, ProxyDomain,
    RescueAuto, RescueEnabled, ResolvedOpenClawConfig, SecretsDomain, SecurityAuditConfig,
    SecurityAuditSuppression, SecurityConfig, SessionDomain, ShellEnvironmentConfig, SkillsDomain,
    SurfaceConfigEntry, TalkDomain, ToolsDomain, TranscriptsDomain, TuiConfig, TuiFooterConfig,
    UiConfig, UpdateChannel, UpdateConfig, WebDomain, WizardConfig, WizardMode,
    openclaw_schema_json, openclaw_to_json5, parse_openclaw_json5,
};
pub use error::ConfigError;
pub use io::{
    WriteOutcome, WriteWarning, load_file, sync_directory, write_bytes_atomically, write_file,
};
pub use layer::{ConfigLayerKind, ConfigLayers, LayeredConfigError, ResolvedConfig};
pub use migration::{
    ManualMapping, MigrationDiagnostic, MigrationError, MigrationResult, migrate_legacy_environment,
};
pub use model::{
    AdminConfig, AuthConfig, CONFIG_SCHEMA_VERSION, ChannelsConfig, ConfigDomain, ConfigSnapshot,
    CopilotConfig, CoreConfig, DiscordConfig, LegacySkillsConfig, LogLevel, LoggingConfig,
    NetworkConfig, PlatformSecretStore, RoleConfig, SecretMaterial, SecretRef, SecretStoreError,
    ServerConfig, SessionsConfig, TeamsConfig, TelegramConfig, UpdatesConfig, WhatsappConfig,
    store_secret,
};
pub use reload::{
    ConfigChange, ConfigFileWatcher, ConfigHub, ConfigHubError, ConfigSubscription, ReloadManager,
    ReloadOutcome,
};
pub use role::{
    ROLE_DOCUMENT_MAX_BYTES, ROLE_FETCH_ACCEPT, ROLE_FETCH_TIMEOUT_MS, RoleDiagnostic,
    RoleDocument, RoleDocumentOutcome, RoleFetchRequest, RoleJsonRejection, RoleLoadError,
    RoleParseError, RoleResponse, RoleSourceFetcher, load_role, parse_role_document,
};
pub use versioning::{
    ConfigMigrationError, ConfigMigrationOutcome, ConfigMigrationRecord, migrate_config_file,
    rollback_config_migration,
};
use wire::EnvelopeWire;

/// Parses UTF-8 JSON5 into a completely validated typed snapshot.
///
/// # Errors
///
/// Returns [`ConfigError::Syntax`] when `source` is not well-formed JSON5,
/// [`ConfigError::Decode`] naming the exact dotted field path when a value has
/// the wrong JSON type or an unknown key is present,
/// [`ConfigError::UnsupportedVersion`] when `schema_version` is not
/// [`CONFIG_SCHEMA_VERSION`], and [`ConfigError::Validation`] when a decoded
/// value violates a domain invariant, such as a non-HTTP(S) `core.role.source_url`,
/// a port outside 1..=65535, or a secret field holding plaintext instead of an
/// `env:<NAME>` reference. `source_name` is echoed back in every diagnostic so
/// the caller can point at the file that was rejected.
pub fn parse_json5(source: &str, source_name: &str) -> Result<ConfigSnapshot, ConfigError> {
    // One JSON5 scan on the success path. The `IgnoredAny` pre-scan exists to
    // classify malformed input as `Syntax` rather than `Decode`, and the
    // `serde_path_to_error` wrapper exists to name the offending field; neither
    // produces anything a document that decodes cleanly can use. A rejected
    // document is re-read by `envelope_rejection`, which reproduces both.
    // Measured on the legacy envelope (best-of-7 x 5000, interleaved release
    // binaries): 9.20us -> 4.18us.
    json5::from_str::<EnvelopeWire>(source)
        .map_err(|_| envelope_rejection(source, source_name))?
        .validate()
}

/// Re-reads a rejected envelope in the original diagnostic order: JSON5 syntax
/// first, then the exact dotted field path.
#[cold]
fn envelope_rejection(source: &str, source_name: &str) -> ConfigError {
    if let Err(error) = json5::from_str::<IgnoredAny>(source) {
        return ConfigError::Syntax {
            source_name: source_name.to_owned(),
            message: error.to_string(),
        };
    }
    let mut deserializer = json5::Deserializer::from_str(source);
    match serde_path_to_error::deserialize::<_, EnvelopeWire>(&mut deserializer) {
        Err(error) => {
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
        }
        // Unreachable: the only failure `json5::from_str` reports that a bare
        // `Deserializer` does not is trailing content, which the `IgnoredAny`
        // scan above already rejected. Classified as syntax rather than
        // panicking so a future json5 divergence degrades into a diagnostic.
        Ok(_) => ConfigError::Syntax {
            source_name: source_name.to_owned(),
            message: "document is not well-formed JSON5".to_owned(),
        },
    }
}

/// Serializes a validated snapshot to deterministic JSON5.
///
/// Secret material cannot be serialized because snapshots contain only
/// [`SecretRef`] values.
///
/// Encoding into a pre-reserved buffer with `json5::to_writer` was measured on
/// the larger 47-domain document and rejected there; see
/// [`openclaw_to_json5`] for the numbers. The same reasoning applies to this
/// much smaller envelope.
///
/// # Errors
///
/// Returns [`ConfigError::Serialize`] when the JSON5 encoder rejects the wire
/// envelope. A snapshot obtained from [`parse_json5`] is always encodable, so
/// this only fires if the encoder itself fails, for example on allocation
/// failure.
pub fn to_json5(snapshot: &ConfigSnapshot) -> Result<String, ConfigError> {
    let mut output = json5::to_string(&EnvelopeWire::from(snapshot))
        .map_err(|error| ConfigError::Serialize(error.to_string()))?;
    output.push('\n');
    Ok(output)
}

/// Returns the generated JSON Schema for the strict JSON5 document shape.
///
/// Like [`openclaw_schema_json`], this is a tool entry point rather than
/// startup work: `schemars` rebuilds the schema on every call, measured at
/// 41.0-42.7us, and no binary in the workspace calls it while starting.
///
/// # Errors
///
/// Returns [`ConfigError::Serialize`] when the generated schema cannot be
/// rendered as pretty JSON. The schema is derived at compile time, so this only
/// fires if the JSON writer itself fails.
pub fn schema_json() -> Result<String, ConfigError> {
    let schema = schemars::schema_for!(EnvelopeWire);
    serde_json::to_string_pretty(&schema).map_err(|error| ConfigError::Serialize(error.to_string()))
}

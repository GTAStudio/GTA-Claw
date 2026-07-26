//! Strict GTA Claw JSON5 configuration, atomic persistence, transactional
//! reload classification, and deterministic GTA legacy environment migration.
//!
//! The additive [`OpenClawConfig`] model covers the frozen 47-domain upstream
//! source surface. The original [`ConfigSnapshot`] API remains the strict,
//! validated GTA legacy runtime envelope used by existing callers.

/// Strongly typed source configuration for the frozen 47-domain contract.
pub mod domains;
mod error;
mod io;
mod layer;
pub mod legacy;
mod migration;
mod model;
mod reload;
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
pub use io::{WriteOutcome, WriteWarning, load_file, write_bytes_atomically, write_file};
pub use layer::{ConfigLayerKind, ConfigLayers, LayeredConfigError, ResolvedConfig};
pub use legacy::{
    AcceptedOnlyReason, ConsumerEnforcement, LEGACY_RUNTIME_CONFIGS, LegacyRuntimeConfig,
    LegacyRuntimeDisposition, LegacyRuntimeKey, LegacyRuntimeOwner, legacy_runtime_config,
};
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
pub use versioning::{
    ConfigMigrationError, ConfigMigrationOutcome, ConfigMigrationRecord, migrate_config_file,
    rollback_config_migration,
};
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

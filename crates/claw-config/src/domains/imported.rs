#![allow(missing_docs)]

use std::fmt::{self, Debug, Formatter};
use std::{borrow::Cow, collections::BTreeMap};

use schemars::{JsonSchema, Schema, SchemaGenerator, json_schema};
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use serde_json::Value;

macro_rules! optional_config {
    ($name:ident { $($field:ident: $type:ty),* $(,)? }) => {
        #[derive(Clone, Debug, Default, PartialEq, Deserialize, JsonSchema, Serialize)]
        #[serde(default, deny_unknown_fields, rename_all = "camelCase")]
        pub struct $name {
            $(
                #[serde(skip_serializing_if = "Option::is_none")]
                pub $field: Option<$type>,
            )*
        }
    };
}

macro_rules! string_enum {
    ($name:ident, $rename:literal, $($variant:ident),+ $(,)?) => {
        #[derive(Clone, Copy, Debug, Eq, PartialEq, Deserialize, JsonSchema, Serialize)]
        #[serde(rename_all = $rename)]
        pub enum $name {
            $($variant),+
        }
    };
}

#[derive(Clone, Debug, PartialEq, Deserialize, JsonSchema, Serialize)]
#[serde(untagged)]
pub enum StringOrNumber {
    String(String),
    Number(i64),
}

#[derive(Clone, Debug, PartialEq, Deserialize, JsonSchema, Serialize)]
#[serde(untagged)]
pub enum StringOrFalse {
    String(String),
    False(LiteralFalse),
}

#[derive(Clone, Debug, PartialEq, Deserialize, JsonSchema, Serialize)]
#[serde(untagged)]
pub enum StringNumberOrFalse {
    String(String),
    Number(i64),
    False(LiteralFalse),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct LiteralFalse(bool);

impl JsonSchema for LiteralFalse {
    fn schema_name() -> Cow<'static, str> {
        "LiteralFalse".into()
    }

    fn schema_id() -> Cow<'static, str> {
        concat!(module_path!(), "::LiteralFalse").into()
    }

    fn json_schema(_generator: &mut SchemaGenerator) -> Schema {
        json_schema!({ "const": false })
    }
}

impl<'de> Deserialize<'de> for LiteralFalse {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        if bool::deserialize(deserializer)? {
            Err(serde::de::Error::custom("expected false"))
        } else {
            Ok(Self(false))
        }
    }
}

impl Serialize for LiteralFalse {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_bool(false)
    }
}

#[derive(Clone, Debug, PartialEq, Deserialize, JsonSchema, Serialize)]
#[serde(untagged)]
pub enum BoolOrAuto {
    Bool(bool),
    Auto(AutoValue),
}

string_enum!(AutoValue, "lowercase", Auto);

#[derive(Clone, PartialEq, Serialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct DomainSecretRef {
    source: SecretSource,
    provider: String,
    id: String,
}

impl DomainSecretRef {
    pub fn new(
        source: SecretSource,
        provider: impl Into<String>,
        id: impl Into<String>,
    ) -> Result<Self, &'static str> {
        let reference = Self {
            source,
            provider: provider.into(),
            id: id.into(),
        };
        reference.validate()?;
        Ok(reference)
    }

    #[must_use]
    pub const fn source(&self) -> SecretSource {
        self.source
    }

    #[must_use]
    pub fn provider(&self) -> &str {
        &self.provider
    }

    #[must_use]
    pub fn id(&self) -> &str {
        &self.id
    }

    fn validate(&self) -> Result<(), &'static str> {
        if !valid_secret_provider_alias(&self.provider) {
            return Err("secret provider must match [a-z][a-z0-9_-]{0,63}");
        }
        let valid_id = match self.source {
            SecretSource::Env => valid_env_secret_id(&self.id),
            SecretSource::File => valid_file_secret_id(&self.id),
            SecretSource::Exec => valid_exec_secret_id(&self.id),
        };
        if valid_id {
            Ok(())
        } else {
            Err("secret reference id is invalid for its source")
        }
    }
}

impl JsonSchema for DomainSecretRef {
    fn schema_name() -> Cow<'static, str> {
        "DomainSecretRef".into()
    }

    fn schema_id() -> Cow<'static, str> {
        concat!(module_path!(), "::DomainSecretRef").into()
    }

    fn json_schema(_generator: &mut SchemaGenerator) -> Schema {
        json_schema!({
            "oneOf": [
                {
                    "type": "object",
                    "properties": {
                        "source": { "const": "env" },
                        "provider": {
                            "type": "string",
                            "pattern": "^[a-z][a-z0-9_-]{0,63}$"
                        },
                        "id": {
                            "type": "string",
                            "pattern": "^[A-Z][A-Z0-9_]{0,127}$"
                        }
                    },
                    "required": ["source", "provider", "id"],
                    "additionalProperties": false
                },
                {
                    "type": "object",
                    "properties": {
                        "source": { "const": "file" },
                        "provider": {
                            "type": "string",
                            "pattern": "^[a-z][a-z0-9_-]{0,63}$"
                        },
                        "id": {
                            "anyOf": [
                                { "const": "value" },
                                {
                                    "type": "string",
                                    "pattern": "^(/([^~]|~[01])*)+$"
                                }
                            ]
                        }
                    },
                    "required": ["source", "provider", "id"],
                    "additionalProperties": false
                },
                {
                    "type": "object",
                    "properties": {
                        "source": { "const": "exec" },
                        "provider": {
                            "type": "string",
                            "pattern": "^[a-z][a-z0-9_-]{0,63}$"
                        },
                        "id": {
                            "type": "string",
                            "pattern": "^[A-Za-z0-9][A-Za-z0-9._:/#-]{0,255}$",
                            "not": { "pattern": "(^|/)\\.\\.?(/|$)" }
                        }
                    },
                    "required": ["source", "provider", "id"],
                    "additionalProperties": false
                }
            ]
        })
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct DomainSecretRefWire {
    source: SecretSource,
    provider: String,
    id: String,
}

impl<'de> Deserialize<'de> for DomainSecretRef {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let wire = DomainSecretRefWire::deserialize(deserializer)?;
        Self::new(wire.source, wire.provider, wire.id).map_err(serde::de::Error::custom)
    }
}

impl Debug for DomainSecretRef {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter.write_str("DomainSecretRef([REDACTED])")
    }
}

impl fmt::Display for DomainSecretRef {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter.write_str("secret-ref:[REDACTED]")
    }
}

string_enum!(SecretSource, "lowercase", Env, File, Exec);

#[derive(Clone, PartialEq, Deserialize, JsonSchema)]
#[serde(untagged)]
pub enum SecretInput {
    Literal(String),
    Reference(DomainSecretRef),
}

impl Debug for SecretInput {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter.write_str("SecretInput([REDACTED])")
    }
}

impl Serialize for SecretInput {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        match self {
            Self::Literal(_) => serializer.serialize_str("[REDACTED]"),
            Self::Reference(reference) => reference.serialize(serializer),
        }
    }
}

string_enum!(AuthMode, "kebab-case", ApiKey, AwsSdk, Oauth, Token);

#[derive(Clone, Debug, PartialEq, Deserialize, JsonSchema, Serialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct AuthProfileConfig {
    pub provider: String,
    pub mode: AuthMode,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub email: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub display_name: Option<String>,
}

optional_config!(AuthCooldownConfig {
    billing_backoff_hours: f64,
    billing_backoff_hours_by_provider: BTreeMap<String, f64>,
    billing_max_hours: f64,
    auth_permanent_backoff_minutes: f64,
    auth_permanent_max_minutes: f64,
    failure_window_hours: f64,
    overloaded_profile_rotations: u32,
    overloaded_backoff_ms: u64,
    rate_limited_profile_rotations: u32,
});

string_enum!(DiscordMembershipType, "camelCase", CanViewChannel);

#[derive(Clone, Debug, PartialEq, Deserialize, JsonSchema, Serialize)]
#[serde(tag = "type", deny_unknown_fields)]
pub enum AccessGroupConfig {
    #[serde(rename = "discord.channelAudience")]
    DiscordChannelAudience {
        #[serde(rename = "guildId")]
        guild_id: String,
        #[serde(rename = "channelId")]
        channel_id: String,
        #[serde(skip_serializing_if = "Option::is_none")]
        membership: Option<DiscordMembershipType>,
    },
    #[serde(rename = "message.senders")]
    MessageSenders {
        members: BTreeMap<String, Vec<String>>,
    },
}

optional_config!(AcpDispatchConfig { enabled: bool });
optional_config!(AcpStreamConfig {
    coalesce_idle_ms: u64,
    max_chunk_chars: u32,
    repeat_suppression: bool,
    delivery_mode: AcpDeliveryMode,
    hidden_boundary_separator: AcpHiddenBoundarySeparator,
    max_output_chars: u32,
    max_session_update_chars: u32,
    tag_visibility: BTreeMap<String, bool>,
});
optional_config!(AcpRuntimeConfig {
    ttl_minutes: u32,
    install_command: String,
});
string_enum!(AcpDeliveryMode, "snake_case", Live, FinalOnly);
string_enum!(
    AcpHiddenBoundarySeparator,
    "lowercase",
    None,
    Space,
    Newline,
    Paragraph
);

optional_config!(DiagnosticsOtelConfig {
    enabled: bool,
    endpoint: String,
    traces_endpoint: String,
    metrics_endpoint: String,
    logs_endpoint: String,
    protocol: OtelProtocol,
    headers: BTreeMap<String, String>,
    service_name: String,
    traces: bool,
    metrics: bool,
    logs: bool,
    logs_exporter: OtelLogsExporter,
    sample_rate: f64,
    flush_interval_ms: u64,
    capture_content: OtelCaptureContent,
});
string_enum!(OtelLogsExporter, "lowercase", Otlp, Stdout, Both);

#[derive(Clone, Copy, Debug, Eq, PartialEq, Deserialize, JsonSchema, Serialize)]
pub enum OtelProtocol {
    #[serde(rename = "http/protobuf")]
    HttpProtobuf,
    #[serde(rename = "grpc")]
    Grpc,
}

#[derive(Clone, Debug, PartialEq, Deserialize, JsonSchema, Serialize)]
#[serde(untagged)]
pub enum OtelCaptureContent {
    Enabled(bool),
    Options(OtelCaptureContentConfig),
}

optional_config!(OtelCaptureContentConfig {
    enabled: bool,
    input_messages: bool,
    output_messages: bool,
    tool_inputs: bool,
    tool_outputs: bool,
    system_prompt: bool,
    tool_definitions: bool,
});

optional_config!(DiagnosticsCacheTraceConfig {
    enabled: bool,
    file_path: String,
    include_messages: bool,
    include_prompt: bool,
    include_system: bool,
});

string_enum!(
    LogLevel,
    "lowercase",
    Silent,
    Fatal,
    Error,
    Warn,
    Info,
    Debug,
    Trace
);
string_enum!(ConsoleStyle, "lowercase", Pretty, Compact, Json);
string_enum!(RedactSensitive, "lowercase", Off, Tools);
string_enum!(AuditMessagesMode, "lowercase", Off, Direct, All);

optional_config!(CliBannerConfig {
    tagline_mode: CliBannerTaglineMode,
});
string_enum!(CliBannerTaglineMode, "lowercase", Random, Default, Off);

string_enum!(
    BrowserDriver,
    "kebab-case",
    Openclaw,
    Clawd,
    ExistingSession,
    Extension
);
string_enum!(BrowserSnapshotMode, "lowercase", Efficient);

#[derive(Clone, Debug, PartialEq, Deserialize, JsonSchema, Serialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct BrowserProfileConfig {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cdp_port: Option<u16>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cdp_url: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub user_data_dir: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub mcp_command: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub mcp_args: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub driver: Option<BrowserDriver>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub headless: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub executable_path: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub attach_only: Option<bool>,
    pub color: String,
}

optional_config!(BrowserSnapshotDefaults {
    mode: BrowserSnapshotMode,
});
optional_config!(BrowserTabCleanupConfig {
    enabled: bool,
    idle_minutes: f64,
    max_tabs_per_session: u32,
    sweep_minutes: f64,
});
optional_config!(BrowserSsrfPolicyConfig {
    dangerously_allow_private_network: bool,
    allowed_hostnames: Vec<String>,
    hostname_allowlist: Vec<String>,
});

string_enum!(SessionScope, "kebab-case", PerSender, Global);
string_enum!(
    DmScope,
    "kebab-case",
    Main,
    PerPeer,
    PerChannelPeer,
    PerAccountChannelPeer
);
string_enum!(TypingMode, "lowercase", Never, Instant, Thinking, Message);
string_enum!(SessionResetMode, "lowercase", Daily, Idle);
string_enum!(SessionSendPolicyAction, "lowercase", Allow, Deny);
string_enum!(SpawnContextMode, "lowercase", Isolated, Fork);
string_enum!(SessionMaintenanceMode, "lowercase", Enforce, Warn);

optional_config!(SessionResetConfig {
    mode: SessionResetMode,
    at_hour: u8,
    idle_minutes: f64,
});
optional_config!(SessionResetByTypeConfig {
    direct: SessionResetConfig,
    dm: SessionResetConfig,
    group: SessionResetConfig,
    thread: SessionResetConfig,
});
optional_config!(SessionSendPolicyMatch {
    channel: String,
    chat_type: String,
    key_prefix: String,
    raw_key_prefix: String,
});

#[derive(Clone, Debug, PartialEq, Deserialize, JsonSchema, Serialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct SessionSendPolicyRule {
    pub action: SessionSendPolicyAction,
    #[serde(rename = "match", skip_serializing_if = "Option::is_none")]
    pub match_filter: Option<SessionSendPolicyMatch>,
}

optional_config!(SessionSendPolicyConfig {
    default: SessionSendPolicyAction,
    rules: Vec<SessionSendPolicyRule>,
});
optional_config!(SessionWriteLockConfig {
    acquire_timeout_ms: u64,
    stale_ms: u64,
    max_hold_ms: u64,
});
optional_config!(SessionAgentToAgentConfig {
    max_ping_pong_turns: u8,
});
optional_config!(SessionThreadBindingsConfig {
    enabled: bool,
    idle_hours: f64,
    max_age_hours: f64,
    spawn_sessions: bool,
    default_spawn_context: SpawnContextMode,
});
optional_config!(SessionMaintenanceConfig {
    mode: SessionMaintenanceMode,
    prune_after: StringOrNumber,
    prune_days: u32,
    max_entries: u32,
    rotate_bytes: StringOrNumber,
    reset_archive_retention: StringNumberOrFalse,
    max_disk_bytes: StringNumberOrFalse,
    high_water_bytes: StringOrNumber,
});

optional_config!(WebReconnectConfig {
    initial_ms: u64,
    max_ms: u64,
    factor: f64,
    jitter: f64,
    max_attempts: u32,
});
optional_config!(WebWhatsAppConfig {
    keep_alive_interval_ms: u64,
    connect_timeout_ms: u64,
    default_query_timeout_ms: u64,
});

pub type ExtensionObject = BTreeMap<String, Value>;

#[derive(Clone, Debug, PartialEq, Deserialize, JsonSchema, Serialize)]
#[serde(tag = "source", rename_all = "lowercase", deny_unknown_fields)]
pub enum SecretProviderConfig {
    Env {
        #[serde(skip_serializing_if = "Option::is_none")]
        allowlist: Option<Vec<String>>,
    },
    File {
        path: String,
        #[serde(skip_serializing_if = "Option::is_none")]
        mode: Option<FileSecretProviderMode>,
        #[serde(rename = "timeoutMs", skip_serializing_if = "Option::is_none")]
        timeout_ms: Option<u64>,
        #[serde(rename = "maxBytes", skip_serializing_if = "Option::is_none")]
        max_bytes: Option<u64>,
        #[serde(rename = "allowInsecurePath", skip_serializing_if = "Option::is_none")]
        allow_insecure_path: Option<bool>,
    },
    Exec(ExecSecretProviderConfig),
}

#[derive(Clone, Debug, PartialEq, Deserialize, JsonSchema, Serialize)]
#[serde(untagged, deny_unknown_fields)]
pub enum ExecSecretProviderConfig {
    Manual {
        command: String,
        #[serde(skip_serializing_if = "Option::is_none")]
        args: Option<Vec<String>>,
        #[serde(rename = "timeoutMs", skip_serializing_if = "Option::is_none")]
        timeout_ms: Option<u64>,
        #[serde(rename = "noOutputTimeoutMs", skip_serializing_if = "Option::is_none")]
        no_output_timeout_ms: Option<u64>,
        #[serde(rename = "maxOutputBytes", skip_serializing_if = "Option::is_none")]
        max_output_bytes: Option<u64>,
        #[serde(rename = "jsonOnly", skip_serializing_if = "Option::is_none")]
        json_only: Option<bool>,
        #[serde(skip_serializing_if = "Option::is_none")]
        env: Option<BTreeMap<String, String>>,
        #[serde(rename = "passEnv", skip_serializing_if = "Option::is_none")]
        pass_env: Option<Vec<String>>,
        #[serde(rename = "trustedDirs", skip_serializing_if = "Option::is_none")]
        trusted_dirs: Option<Vec<String>>,
        #[serde(rename = "allowInsecurePath", skip_serializing_if = "Option::is_none")]
        allow_insecure_path: Option<bool>,
        #[serde(
            rename = "allowSymlinkCommand",
            skip_serializing_if = "Option::is_none"
        )]
        allow_symlink_command: Option<bool>,
    },
    Plugin {
        #[serde(rename = "pluginIntegration")]
        plugin_integration: PluginIntegrationRef,
    },
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Deserialize, JsonSchema, Serialize)]
pub enum FileSecretProviderMode {
    #[serde(rename = "singleValue")]
    SingleValue,
    #[serde(rename = "json")]
    Json,
}

#[derive(Clone, Debug, Eq, PartialEq, Deserialize, JsonSchema, Serialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct PluginIntegrationRef {
    pub plugin_id: String,
    pub integration_id: String,
}

optional_config!(SecretDefaultsConfig {
    env: String,
    file: String,
    exec: String,
});
optional_config!(SecretResolutionConfig {
    max_provider_concurrency: u32,
    max_refs_per_provider: u32,
    max_batch_bytes: u64,
});

#[derive(Clone, Debug, Eq, PartialEq, Deserialize, JsonSchema, Serialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct MarketplaceFeedTrustedPublicKey {
    pub key_id: String,
    pub public_key: String,
}

#[derive(Clone, Debug, Eq, PartialEq, Deserialize, JsonSchema, Serialize)]
#[serde(tag = "mode", rename_all = "lowercase", deny_unknown_fields)]
pub enum MarketplaceFeedVerificationConfig {
    Unsigned,
    Signed {
        keys: Vec<MarketplaceFeedTrustedPublicKey>,
        #[serde(skip_serializing_if = "Option::is_none")]
        threshold: Option<u32>,
    },
}

#[derive(Clone, Debug, Eq, PartialEq, Deserialize, JsonSchema, Serialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct MarketplaceFeedProfileConfig {
    pub url: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub verification: Option<MarketplaceFeedVerificationConfig>,
}

#[derive(Clone, Debug, Eq, PartialEq, Deserialize, JsonSchema, Serialize)]
#[serde(tag = "type", rename_all = "lowercase", deny_unknown_fields)]
pub enum MarketplaceSourceProfileConfig {
    Npm,
    Clawhub,
    Git,
}

optional_config!(SkillConfig {
    enabled: bool,
    api_key: SecretInput,
    env: BTreeMap<String, String>,
    config: ExtensionObject,
});
optional_config!(SkillsLoadConfig {
    extra_dirs: Vec<String>,
    allow_symlink_targets: Vec<String>,
    watch: bool,
    watch_debounce_ms: u64,
});
string_enum!(SkillNodeManager, "lowercase", Npm, Pnpm, Yarn, Bun);
optional_config!(SkillsInstallConfig {
    prefer_brew: bool,
    node_manager: SkillNodeManager,
    allow_uploaded_archives: bool,
});
optional_config!(SkillsLimitsConfig {
    max_candidates_per_root: u32,
    max_skills_loaded_per_source: u32,
    max_skills_in_prompt: u32,
    max_skills_prompt_chars: u32,
    max_skill_file_bytes: u64,
});
string_enum!(SkillApprovalPolicy, "lowercase", Pending, Auto);
optional_config!(SkillsWorkshopAutonomousConfig { enabled: bool });
optional_config!(SkillsWorkshopConfig {
    autonomous: SkillsWorkshopAutonomousConfig,
    approval_policy: SkillApprovalPolicy,
    allow_symlink_target_writes: bool,
    max_pending: u32,
    max_skill_bytes: u64,
});

optional_config!(PluginHooksConfig {
    allow_prompt_injection: bool,
    allow_conversation_access: bool,
    timeout_ms: u64,
    timeouts: BTreeMap<String, u64>,
});
optional_config!(PluginSubagentConfig {
    allow_model_override: bool,
    allowed_models: Vec<String>,
});
optional_config!(PluginLlmConfig {
    allow_model_override: bool,
    allowed_models: Vec<String>,
    allow_agent_id_override: bool,
});
optional_config!(PluginEntryConfig {
    enabled: bool,
    hooks: PluginHooksConfig,
    subagent: PluginSubagentConfig,
    llm: PluginLlmConfig,
    config: ExtensionObject,
});
optional_config!(PluginSlotsConfig {
    memory: String,
    context_engine: String,
});
optional_config!(PluginsLoadConfig { paths: Vec<String> });
string_enum!(BundledDiscoveryMode, "lowercase", Compat, Allowlist);

string_enum!(SilentReplyPolicy, "lowercase", Allow, Disallow);
optional_config!(SilentReplyPolicyShape {
    group: SilentReplyPolicy,
    internal: SilentReplyPolicy,
});

optional_config!(NodeHostBrowserProxyConfig {
    enabled: bool,
    allow_profiles: Vec<String>,
});
optional_config!(NodeHostSkillsConfig { enabled: bool });

string_enum!(McpTransport, "kebab-case", Stdio, Sse, StreamableHttp);

#[derive(Clone, Debug, PartialEq, Deserialize, JsonSchema, Serialize)]
#[serde(untagged)]
pub enum SensitivePrimitive {
    String(String),
    Number(f64),
    Boolean(bool),
}

#[derive(Clone, Debug, Default, PartialEq, Deserialize, JsonSchema, Serialize)]
#[serde(default, rename_all = "camelCase")]
pub struct McpServerConfig {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub enabled: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub command: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub args: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub env: Option<BTreeMap<String, SensitivePrimitive>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cwd: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub working_directory: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub url: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub transport: Option<McpTransport>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub headers: Option<BTreeMap<String, SensitivePrimitive>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub connect_timeout: Option<f64>,
    #[serde(
        rename = "connectionTimeoutMs",
        skip_serializing_if = "Option::is_none"
    )]
    pub connection_timeout_ms: Option<f64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub request_timeout_ms: Option<f64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub timeout: Option<f64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub supports_parallel_tool_calls: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub auth: Option<McpAuthMode>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub oauth: Option<McpOAuthConfig>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ssl_verify: Option<bool>,
    #[serde(rename = "ssl_verify", skip_serializing_if = "Option::is_none")]
    pub ssl_verify_legacy: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub client_cert: Option<String>,
    #[serde(rename = "client_cert", skip_serializing_if = "Option::is_none")]
    pub client_cert_legacy: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub client_key: Option<String>,
    #[serde(rename = "client_key", skip_serializing_if = "Option::is_none")]
    pub client_key_legacy: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tool_filter: Option<McpServerToolFilterConfig>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub codex: Option<McpServerCodexConfig>,
    #[serde(flatten)]
    pub extra: ExtensionObject,
}

string_enum!(McpAuthMode, "lowercase", Oauth);
string_enum!(McpCodexToolApprovalMode, "lowercase", Auto, Prompt, Approve);
optional_config!(McpOAuthConfig {
    auth_profile_id: String,
    scope: String,
    redirect_url: String,
    client_metadata_url: String,
});
optional_config!(McpServerToolFilterConfig {
    include: Vec<String>,
    exclude: Vec<String>,
});
#[derive(Clone, Debug, Default, PartialEq, Deserialize, JsonSchema, Serialize)]
#[serde(default, deny_unknown_fields)]
pub struct McpServerCodexConfig {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub agents: Option<Vec<String>>,
    #[serde(
        rename = "defaultToolsApprovalMode",
        skip_serializing_if = "Option::is_none"
    )]
    pub default_tools_approval_mode: Option<McpCodexToolApprovalMode>,
    #[serde(
        rename = "default_tools_approval_mode",
        skip_serializing_if = "Option::is_none"
    )]
    pub default_tools_approval_mode_legacy: Option<McpCodexToolApprovalMode>,
}
optional_config!(NodeHostMcpConfig {
    servers: BTreeMap<String, McpServerConfig>,
});

string_enum!(BroadcastStrategy, "lowercase", Parallel, Sequential);

#[derive(Clone, Debug, Default, PartialEq, Deserialize, JsonSchema, Serialize)]
#[serde(default, rename_all = "camelCase")]
pub struct BroadcastConfig {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub strategy: Option<BroadcastStrategy>,
    #[serde(flatten)]
    pub peers: BTreeMap<String, Vec<String>>,
}

#[derive(Clone, Debug, PartialEq, Deserialize, JsonSchema, Serialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct AudioTranscriptionConfig {
    pub command: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub timeout_seconds: Option<u32>,
}

string_enum!(VisibleRepliesMode, "snake_case", Automatic, MessageTool);
string_enum!(ResponseUsageMode, "lowercase", On, Off, Tokens, Full);

#[derive(Clone, Debug, PartialEq, Deserialize, JsonSchema, Serialize)]
#[serde(untagged)]
pub enum ResponseUsageConfig {
    Mode(ResponseUsageMode),
    PerChannel(BTreeMap<String, ResponseUsageMode>),
}

#[derive(Clone, Debug, PartialEq, Deserialize, JsonSchema, Serialize)]
#[serde(untagged)]
pub enum UsageTemplateConfig {
    Text(String),
    Structured(ExtensionObject),
}

string_enum!(QueueMode, "lowercase", Steer, Followup, Collect, Interrupt);
string_enum!(QueueDropPolicy, "lowercase", Old, New, Summarize);
optional_config!(QueueConfig {
    mode: QueueMode,
    by_channel: BTreeMap<String, QueueMode>,
    debounce_ms: u64,
    debounce_ms_by_channel: BTreeMap<String, u64>,
    cap: u32,
    drop: QueueDropPolicy,
});
optional_config!(InboundDebounceConfig {
    debounce_ms: u64,
    by_channel: BTreeMap<String, u64>,
});
string_enum!(UnmentionedInboundMode, "snake_case", UserRequest, RoomEvent);
optional_config!(GroupChatConfig {
    mention_patterns: Vec<String>,
    history_limit: u32,
    unmentioned_inbound: UnmentionedInboundMode,
    visible_replies: VisibleRepliesMode,
});

optional_config!(StatusReactionsEmojiConfig {
    queued: String,
    thinking: String,
    tool: String,
    coding: String,
    web: String,
    deploy: String,
    build: String,
    concierge: String,
    done: String,
    error: String,
    stall_soft: String,
    stall_hard: String,
    compacting: String,
});
optional_config!(StatusReactionsTimingConfig {
    debounce_ms: u64,
    stall_soft_ms: u64,
    stall_hard_ms: u64,
    done_hold_ms: u64,
    error_hold_ms: u64,
});
optional_config!(StatusReactionsConfig {
    enabled: bool,
    emojis: StatusReactionsEmojiConfig,
    timing: StatusReactionsTimingConfig,
});

string_enum!(TtsAutoMode, "lowercase", Off, Always, Inbound, Tagged);
string_enum!(TtsMode, "lowercase", Final, All);
string_enum!(
    TtsFallbackPolicy,
    "kebab-case",
    PreservePersona,
    ProviderDefaults,
    Fail
);
optional_config!(TtsPersonaPromptConfig {
    profile: String,
    scene: String,
    sample_context: String,
    style: String,
    accent: String,
    pacing: String,
    constraints: Vec<String>,
});
optional_config!(TtsPersonaConfig {
    label: String,
    description: String,
    provider: String,
    fallback_policy: TtsFallbackPolicy,
    prompt: TtsPersonaPromptConfig,
    providers: BTreeMap<String, ExtensionObject>,
});
optional_config!(TtsModelOverridesConfig {
    enabled: bool,
    allow_text: bool,
    allow_provider: bool,
    allow_voice: bool,
    allow_model_id: bool,
    allow_voice_settings: bool,
    allow_normalization: bool,
    allow_seed: bool,
});
optional_config!(TtsConfig {
    auto: TtsAutoMode,
    enabled: bool,
    mode: TtsMode,
    provider: String,
    persona: String,
    personas: BTreeMap<String, TtsPersonaConfig>,
    summary_model: String,
    model_overrides: TtsModelOverridesConfig,
    providers: BTreeMap<String, ExtensionObject>,
    prefs_path: String,
    max_text_length: u32,
    timeout_ms: u64,
});

string_enum!(
    AckReactionScope,
    "kebab-case",
    GroupMentions,
    GroupAll,
    Direct,
    All,
    Off,
    None
);

#[derive(Clone, Debug, PartialEq, Deserialize, JsonSchema, Serialize)]
#[serde(untagged)]
pub enum NativeCommandMode {
    Enabled(bool),
    Auto(AutoValue),
}

string_enum!(CommandOwnerDisplay, "lowercase", Raw, Hash);

string_enum!(ChannelGroupPolicy, "lowercase", Open, Disabled, Allowlist);
string_enum!(
    ChannelContextVisibility,
    "snake_case",
    All,
    Allowlist,
    AllowlistQuote
);
string_enum!(MarkdownTableMode, "lowercase", Off, Bullets, Code, Block);
string_enum!(
    ChannelDmPolicy,
    "lowercase",
    Pairing,
    Allowlist,
    Open,
    Disabled
);

optional_config!(ChannelHeartbeatConfig {
    show_ok: bool,
    show_alerts: bool,
    use_indicator: bool,
});
optional_config!(BotLoopProtectionConfig {
    enabled: bool,
    max_events_per_window: u32,
    window_seconds: u32,
    cooldown_seconds: u32,
});
optional_config!(ChannelDefaultsConfig {
    group_policy: ChannelGroupPolicy,
    context_visibility: ChannelContextVisibility,
    heartbeat: ChannelHeartbeatConfig,
    bot_loop_protection: BotLoopProtectionConfig,
});
optional_config!(ChannelMarkdownConfig {
    tables: MarkdownTableMode,
});
optional_config!(ChannelDmConfig { history_limit: u32 });
optional_config!(ChannelBlockStreamingConfig {
    enabled: bool,
    coalesce: BlockStreamingCoalesceConfig,
});
string_enum!(ChannelChunkMode, "lowercase", Length, Newline);
optional_config!(ChannelStreamingConfig {
    chunk_mode: ChannelChunkMode,
    block: ChannelBlockStreamingConfig,
});
optional_config!(ChannelHealthMonitorConfig { enabled: bool });
optional_config!(BlockStreamingCoalesceConfig {
    min_chars: u32,
    max_chars: u32,
    idle_ms: u64,
});

#[derive(Clone, Debug, Default, PartialEq, Deserialize, JsonSchema, Serialize)]
#[serde(default, rename_all = "camelCase")]
pub struct BuiltinChannelConfig {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub capabilities: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub markdown: Option<ChannelMarkdownConfig>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub config_writes: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub enabled: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub bot_token: Option<SecretInput>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub app_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub app_password: Option<SecretInput>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub verify_token: Option<SecretInput>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub access_token: Option<SecretInput>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub phone_number_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub webhook_path: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub poll_interval_ms: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub gateway_url: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub gateway_intents: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub dm_policy: Option<ChannelDmPolicy>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub allow_from: Option<Vec<StringOrNumber>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub default_to: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub group_allow_from: Option<Vec<StringOrNumber>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub group_policy: Option<ChannelGroupPolicy>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub context_visibility: Option<ChannelContextVisibility>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub history_limit: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub dm_history_limit: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub dms: Option<BTreeMap<String, ChannelDmConfig>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub text_chunk_limit: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub streaming: Option<ChannelStreamingConfig>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub heartbeat: Option<ChannelHeartbeatConfig>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub health_monitor: Option<ChannelHealthMonitorConfig>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub response_prefix: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub media_max_mb: Option<f64>,
    #[serde(flatten)]
    pub channel_specific: ExtensionObject,
}

#[derive(Clone, Debug, Default, PartialEq, Deserialize, JsonSchema, Serialize)]
#[serde(default, rename_all = "camelCase")]
pub struct ChannelsDomain {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub defaults: Option<ChannelDefaultsConfig>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub model_by_channel: Option<BTreeMap<String, BTreeMap<String, String>>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub discord: Option<BuiltinChannelConfig>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub googlechat: Option<BuiltinChannelConfig>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub imessage: Option<BuiltinChannelConfig>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub irc: Option<BuiltinChannelConfig>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub msteams: Option<BuiltinChannelConfig>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub signal: Option<BuiltinChannelConfig>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub slack: Option<BuiltinChannelConfig>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub telegram: Option<BuiltinChannelConfig>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub whatsapp: Option<BuiltinChannelConfig>,
    #[serde(flatten)]
    pub plugin_channels: BTreeMap<String, BuiltinChannelConfig>,
}

#[derive(Clone, Debug, PartialEq, Deserialize, JsonSchema, Serialize)]
#[serde(untagged)]
pub enum AgentModelConfig {
    Model(String),
    Selection(AgentModelSelectionConfig),
}

optional_config!(AgentModelSelectionConfig {
    primary: String,
    fallbacks: Vec<String>,
});

#[derive(Clone, Debug, PartialEq, Deserialize, JsonSchema, Serialize)]
#[serde(untagged)]
pub enum AgentToolModelConfig {
    Model(String),
    Selection(AgentToolModelSelectionConfig),
}

optional_config!(AgentToolModelSelectionConfig {
    primary: String,
    fallbacks: Vec<String>,
    timeout_ms: u64,
});
optional_config!(AgentModelEntryConfig { alias: String });

string_enum!(
    ThinkingLevel,
    "lowercase",
    Off,
    Minimal,
    Low,
    Medium,
    High,
    Xhigh,
    Adaptive,
    Max,
    Ultra
);
string_enum!(VerboseLevel, "lowercase", Off, On, Full);
string_enum!(ToolProgressDetailMode, "lowercase", Explain, Raw);
string_enum!(ReasoningDefaultMode, "lowercase", Off, On, Stream);
string_enum!(ElevatedDefaultMode, "lowercase", Off, On, Ask, Full);
string_enum!(OnOff, "lowercase", On, Off);
string_enum!(
    AgentContextInjection,
    "kebab-case",
    Always,
    ContinuationSkip,
    Never
);
#[derive(Clone, Copy, Debug, Eq, PartialEq, Deserialize, JsonSchema, Serialize)]
pub enum OptionalBootstrapFileName {
    #[serde(rename = "SOUL.md")]
    Soul,
    #[serde(rename = "USER.md")]
    User,
    #[serde(rename = "HEARTBEAT.md")]
    Heartbeat,
    #[serde(rename = "IDENTITY.md")]
    Identity,
}
string_enum!(
    BootstrapPromptTruncationWarningMode,
    "lowercase",
    Off,
    Once,
    Always
);
#[derive(Clone, Copy, Debug, Eq, PartialEq, Deserialize, JsonSchema, Serialize)]
pub enum TimeFormat {
    #[serde(rename = "auto")]
    Auto,
    #[serde(rename = "12")]
    Twelve,
    #[serde(rename = "24")]
    TwentyFour,
}
string_enum!(
    AgentImageQualityPreference,
    "lowercase",
    Auto,
    Efficient,
    Balanced,
    High
);
string_enum!(BlockStreamingBreakMode, "snake_case", TextEnd, MessageEnd);
string_enum!(
    BlockBreakPreference,
    "lowercase",
    Paragraph,
    Newline,
    Sentence
);
string_enum!(HumanDelayMode, "lowercase", Off, Natural, Custom);
string_enum!(CompactionMode, "lowercase", Default, Safeguard);

optional_config!(AgentDefaultsExperimentalConfig {
    local_model_lean: bool,
});
optional_config!(AgentStartupContextConfig {
    daily_memory_days: u32,
    max_file_bytes: u64,
    max_file_chars: u32,
    max_total_chars: u32,
});
optional_config!(AgentContextLimitsConfig {
    memory_get_max_chars: u32,
    memory_get_default_lines: u32,
    tool_result_max_chars: u32,
    post_compaction_max_chars: u32,
});
optional_config!(AgentContextPruningConfig {
    soft_trim_ratio: f64,
    hard_clear_ratio: f64,
    keep_last_assistants: u32,
});
optional_config!(AgentCompactionConfig {
    mode: CompactionMode,
    max_history_share: f64,
    recent_turns_preserve: u32,
});
optional_config!(AgentRunRetriesConfig {
    base: u32,
    per_profile: u32,
    min: u32,
    max: u32,
});
optional_config!(EmbeddedAgentConfig {
    project_settings_policy: ProjectSettingsPolicy,
    execution_contract: ExecutionContract,
});
string_enum!(
    ProjectSettingsPolicy,
    "lowercase",
    Trusted,
    Sanitize,
    Ignore
);
string_enum!(ExecutionContract, "kebab-case", Default, StrictAgentic);
optional_config!(BlockStreamingChunkConfig {
    min_chars: u32,
    max_chars: u32,
    break_preference: BlockBreakPreference,
});
optional_config!(HumanDelayConfig {
    mode: HumanDelayMode,
    min_ms: u64,
    max_ms: u64,
});
optional_config!(HeartbeatActiveHoursConfig {
    start: String,
    end: String,
    timezone: String,
});
optional_config!(HeartbeatConfig {
    every: String,
    active_hours: HeartbeatActiveHoursConfig,
});
optional_config!(SubagentsDefaultsConfig {
    max_spawn_depth: u8,
    max_children_per_agent: u8,
    max_concurrent: u32,
    archive_after_minutes: u32,
});

#[derive(Clone, Debug, Default, PartialEq, Deserialize, JsonSchema, Serialize)]
#[serde(default, rename_all = "camelCase")]
pub struct CliBackendConfig {
    #[serde(flatten)]
    pub fields: ExtensionObject,
}

#[derive(Clone, Debug, Default, PartialEq, Deserialize, JsonSchema, Serialize)]
#[serde(default, rename_all = "camelCase")]
pub struct MemorySearchConfig {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub enabled: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub provider: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub model: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sources: Option<Vec<String>>,
    #[serde(flatten)]
    pub provider_options: ExtensionObject,
}

#[derive(Clone, Debug, Default, PartialEq, Deserialize, JsonSchema, Serialize)]
#[serde(default, rename_all = "camelCase")]
pub struct AgentSandboxConfig {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub mode: Option<SandboxMode>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub backend: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub workspace_access: Option<WorkspaceAccessMode>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub session_tools_visibility: Option<SessionToolsVisibility>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub scope: Option<SandboxScope>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub workspace_root: Option<String>,
    #[serde(flatten)]
    pub backend_options: ExtensionObject,
}
string_enum!(SandboxMode, "kebab-case", Off, NonMain, All);
string_enum!(WorkspaceAccessMode, "lowercase", None, Ro, Rw);
string_enum!(SessionToolsVisibility, "lowercase", Spawned, All);
string_enum!(SandboxScope, "lowercase", Session, Agent, Shared);

optional_config!(IdentityConfig {
    name: String,
    theme: String,
    emoji: String,
    avatar: String,
});
optional_config!(AgentSkillsLimitsConfig {
    max_skills: u32,
    max_prompt_chars: u32,
});
optional_config!(AgentSubagentsConfig {
    allow_agents: Vec<String>,
    model: AgentModelConfig,
    thinking: ThinkingLevel,
});
optional_config!(AgentToolsConfig {
    profile: ToolProfileId,
    allow: Vec<String>,
    also_allow: Vec<String>,
    deny: Vec<String>,
});

#[derive(Clone, Debug, PartialEq, Deserialize, JsonSchema, Serialize)]
#[serde(tag = "type", rename_all = "lowercase", deny_unknown_fields)]
pub enum AgentRuntimeConfig {
    Embedded,
    Acp {
        #[serde(skip_serializing_if = "Option::is_none")]
        acp: Option<AgentRuntimeAcpConfig>,
    },
}
optional_config!(AgentRuntimeAcpConfig {
    agent: String,
    backend: String,
    mode: AcpSessionMode,
    cwd: String,
});
string_enum!(AcpSessionMode, "lowercase", Persistent, Oneshot);

#[derive(Clone, Debug, Default, PartialEq, Deserialize, JsonSchema, Serialize)]
#[serde(default, deny_unknown_fields, rename_all = "camelCase")]
pub struct AgentDefaultsConfig {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub params: Option<ExtensionObject>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub model: Option<AgentModelConfig>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub utility_model: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub image_model: Option<AgentToolModelConfig>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub image_generation_model: Option<AgentToolModelConfig>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub video_generation_model: Option<AgentToolModelConfig>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub music_generation_model: Option<AgentToolModelConfig>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub voice_model: Option<AgentToolModelConfig>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub media_generation_auto_provider_fallback: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub pdf_model: Option<AgentToolModelConfig>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub pdf_max_bytes_mb: Option<f64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub pdf_max_pages: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub models: Option<BTreeMap<String, AgentModelEntryConfig>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub workspace: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub skills: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub silent_reply: Option<SilentReplyPolicyShape>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub repo_root: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub prompt_overlays: Option<ExtensionObject>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub skip_bootstrap: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub skip_optional_bootstrap_files: Option<Vec<OptionalBootstrapFileName>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub context_injection: Option<AgentContextInjection>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub bootstrap_max_chars: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub bootstrap_total_max_chars: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub experimental: Option<AgentDefaultsExperimentalConfig>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub bootstrap_prompt_truncation_warning: Option<BootstrapPromptTruncationWarningMode>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub user_timezone: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub startup_context: Option<AgentStartupContextConfig>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub context_limits: Option<AgentContextLimitsConfig>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub time_format: Option<TimeFormat>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub envelope_timezone: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub envelope_timestamp: Option<OnOff>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub envelope_elapsed: Option<OnOff>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub context_tokens: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cli_backends: Option<BTreeMap<String, CliBackendConfig>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub memory_search: Option<MemorySearchConfig>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub context_pruning: Option<AgentContextPruningConfig>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub compaction: Option<AgentCompactionConfig>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub run_retries: Option<AgentRunRetriesConfig>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub embedded_agent: Option<EmbeddedAgentConfig>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub thinking_default: Option<ThinkingLevel>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub verbose_default: Option<VerboseLevel>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tool_progress_detail: Option<ToolProgressDetailMode>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reasoning_default: Option<ReasoningDefaultMode>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub elevated_default: Option<ElevatedDefaultMode>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub block_streaming_default: Option<OnOff>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub block_streaming_break: Option<BlockStreamingBreakMode>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub block_streaming_chunk: Option<BlockStreamingChunkConfig>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub block_streaming_coalesce: Option<BlockStreamingCoalesceConfig>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub human_delay: Option<HumanDelayConfig>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub timeout_seconds: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub media_max_mb: Option<f64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub image_max_dimension_px: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub image_quality: Option<AgentImageQualityPreference>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub typing_interval_seconds: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub typing_mode: Option<TypingMode>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub heartbeat: Option<HeartbeatConfig>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub max_concurrent: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub subagents: Option<SubagentsDefaultsConfig>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sandbox: Option<AgentSandboxConfig>,
}

#[derive(Clone, Debug, PartialEq, Deserialize, JsonSchema, Serialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct AgentConfig {
    pub id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub default: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub workspace: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub agent_dir: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub model: Option<AgentModelConfig>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub utility_model: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub models: Option<BTreeMap<String, AgentModelEntryConfig>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub thinking_default: Option<ThinkingLevel>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub verbose_default: Option<VerboseLevel>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tool_progress_detail: Option<ToolProgressDetailMode>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reasoning_default: Option<ReasoningDefaultMode>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub fast_mode_default: Option<BoolOrAuto>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub context_injection: Option<AgentContextInjection>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub bootstrap_max_chars: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub bootstrap_total_max_chars: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub experimental: Option<AgentDefaultsExperimentalConfig>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub skills: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub memory_search: Option<MemorySearchConfig>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub human_delay: Option<HumanDelayConfig>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tts: Option<TtsConfig>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub skills_limits: Option<AgentSkillsLimitsConfig>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub context_limits: Option<AgentContextLimitsConfig>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub context_tokens: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub heartbeat: Option<HeartbeatConfig>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub identity: Option<IdentityConfig>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub group_chat: Option<GroupChatConfig>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub subagents: Option<AgentSubagentsConfig>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub run_retries: Option<AgentRunRetriesConfig>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub embedded_agent: Option<EmbeddedAgentConfig>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sandbox: Option<AgentSandboxConfig>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub params: Option<ExtensionObject>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tools: Option<AgentToolsConfig>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub runtime: Option<AgentRuntimeConfig>,
}

string_enum!(ToolProfileId, "lowercase", Minimal, Coding, Messaging, Full);
string_enum!(ExecHost, "lowercase", Auto, Sandbox, Gateway, Node);
string_enum!(ExecMode, "lowercase", Deny, Allowlist, Ask, Auto, Full);
string_enum!(ExecSecurity, "lowercase", Deny, Allowlist, Full);
string_enum!(ExecAskMode, "kebab-case", Off, OnMiss, Always);
string_enum!(ToolSearchMode, "lowercase", Code, Tools, Directory);
string_enum!(CodeModeRuntime, "kebab-case", QuickjsWasi);
string_enum!(CodeModeOnly, "lowercase", Only);
string_enum!(CodeModeLanguage, "lowercase", Javascript, Typescript);

optional_config!(ToolPolicyConfig {
    profile: ToolProfileId,
    allow: Vec<String>,
    also_allow: Vec<String>,
    deny: Vec<String>,
});
optional_config!(GroupToolPolicyConfig {
    allow: Vec<String>,
    deny: Vec<String>,
});
optional_config!(OpenAiCodexSearchConfig {
    model: String,
    reasoning_effort: String,
});

#[derive(Clone, Debug, Default, PartialEq, Deserialize, JsonSchema, Serialize)]
#[serde(default, rename_all = "camelCase")]
pub struct ToolsWebSearchConfig {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub enabled: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub provider: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub max_results: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub timeout_seconds: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cache_ttl_minutes: Option<f64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub api_key: Option<SecretInput>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub openai_codex: Option<OpenAiCodexSearchConfig>,
    #[serde(flatten)]
    pub provider_options: ExtensionObject,
}

optional_config!(ToolsWebFetchConfig {
    enabled: bool,
    max_chars: u32,
    timeout_seconds: u32,
    cache_ttl_minutes: f64,
});
optional_config!(ToolsWebConfig {
    search: ToolsWebSearchConfig,
    fetch: ToolsWebFetchConfig,
});
optional_config!(MediaToolsConfig {
    image: ExtensionObject,
    audio: ExtensionObject,
    video: ExtensionObject,
});
optional_config!(LinkToolsConfig {
    enabled: bool,
    max_links: u32,
    timeout_seconds: u32,
});
optional_config!(ToolsSessionsConfig { visibility: String });
optional_config!(ToolLoopDetectionConfig {
    enabled: bool,
    history_size: u32,
    warning_threshold: u32,
    critical_threshold: u32,
});

#[derive(Clone, Debug, PartialEq, Deserialize, JsonSchema, Serialize)]
#[serde(untagged)]
pub enum ToolSearchConfig {
    Enabled(bool),
    Options(ToolSearchOptions),
}
optional_config!(ToolSearchOptions {
    enabled: bool,
    mode: ToolSearchMode,
    code_timeout_ms: u64,
    search_default_limit: u32,
    max_search_limit: u32,
});

#[derive(Clone, Debug, PartialEq, Deserialize, JsonSchema, Serialize)]
#[serde(untagged)]
pub enum CodeModeConfig {
    Enabled(bool),
    Options(CodeModeOptions),
}
optional_config!(CodeModeOptions {
    enabled: bool,
    runtime: CodeModeRuntime,
    mode: CodeModeOnly,
    languages: Vec<CodeModeLanguage>,
    timeout_ms: u64,
    memory_limit_bytes: u64,
    max_output_bytes: u64,
    max_snapshot_bytes: u64,
    max_pending_tool_calls: u32,
    snapshot_ttl_seconds: u32,
    search_default_limit: u32,
    max_search_limit: u32,
});
optional_config!(MessageToolsConfig {
    allow_cross_context: bool,
});
optional_config!(AgentToAgentToolsConfig {
    enabled: bool,
    allow: Vec<String>,
});
optional_config!(ToolsElevatedConfig {
    enabled: bool,
    allow_from: BTreeMap<String, Vec<StringOrNumber>>,
});
optional_config!(SafeBinProfileFixture {
    allow_args: Vec<String>,
    deny_args: Vec<String>,
});
optional_config!(ExecReviewerConfig {
    enabled: bool,
    model: String,
});
optional_config!(ExecApplyPatchConfig {
    enabled: bool,
    workspace_only: bool,
});
optional_config!(ExecToolConfig {
    host: ExecHost,
    mode: ExecMode,
    security: ExecSecurity,
    ask: ExecAskMode,
    node: String,
    path_prepend: Vec<String>,
    safe_bins: Vec<String>,
    strict_inline_eval: bool,
    command_highlighting: bool,
    safe_bin_trusted_dirs: Vec<String>,
    safe_bin_profiles: BTreeMap<String, SafeBinProfileFixture>,
    reviewer: ExecReviewerConfig,
    background_ms: u64,
    timeout_sec: u32,
    approval_running_notice_ms: u64,
    cleanup_ms: u64,
    notify_on_exit: bool,
    notify_on_exit_empty_success: bool,
    apply_patch: ExecApplyPatchConfig,
});
optional_config!(FsToolsConfig {
    workspace_only: bool,
});
optional_config!(SubagentToolsPolicyConfig {
    allow: Vec<String>,
    deny: Vec<String>,
});
optional_config!(SandboxToolsPolicyConfig {
    allow: Vec<String>,
    deny: Vec<String>,
});
optional_config!(SessionsSpawnToolsConfig {
    allow_agents: Vec<String>,
});
optional_config!(ToolsExperimentalConfig {
    group_tool_results: bool,
});

string_enum!(RouteBindingType, "lowercase", Route);
string_enum!(AcpBindingType, "lowercase", Acp);
string_enum!(ChatTypeKind, "lowercase", Direct, Group, Channel, Dm);

#[derive(Clone, Debug, PartialEq, Deserialize, JsonSchema, Serialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct AgentBindingPeerMatch {
    pub kind: ChatTypeKind,
    pub id: String,
}

#[derive(Clone, Debug, PartialEq, Deserialize, JsonSchema, Serialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct AgentBindingMatch {
    pub channel: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub account_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub peer: Option<AgentBindingPeerMatch>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub guild_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub team_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub roles: Option<Vec<String>>,
}
optional_config!(AgentBindingSessionConfig { dm_scope: DmScope });
optional_config!(AgentBindingAcpOptions {
    mode: AcpSessionMode,
    label: String,
    cwd: String,
    backend: String,
});

#[derive(Clone, Debug, PartialEq, Deserialize, JsonSchema, Serialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct AgentRouteBinding {
    #[serde(rename = "type", skip_serializing_if = "Option::is_none")]
    pub binding_type: Option<RouteBindingType>,
    pub agent_id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub comment: Option<String>,
    #[serde(rename = "match")]
    pub binding_match: AgentBindingMatch,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub session: Option<AgentBindingSessionConfig>,
}

#[derive(Clone, Debug, PartialEq, Deserialize, JsonSchema, Serialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct AgentAcpBinding {
    #[serde(rename = "type")]
    pub binding_type: AcpBindingType,
    pub agent_id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub comment: Option<String>,
    #[serde(rename = "match")]
    pub binding_match: AgentBindingMatch,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub acp: Option<AgentBindingAcpOptions>,
}

#[derive(Clone, Debug, PartialEq, Deserialize, JsonSchema, Serialize)]
#[serde(untagged)]
pub enum AgentBinding {
    Route(AgentRouteBinding),
    Acp(AgentAcpBinding),
}

string_enum!(
    ExecApprovalForwardingMode,
    "lowercase",
    Session,
    Targets,
    Both
);
optional_config!(ExecApprovalForwardingConfig {
    enabled: bool,
    mode: ExecApprovalForwardingMode,
    agent_filter: Vec<String>,
    session_filter: Vec<String>,
    targets: Vec<ExecApprovalForwardTarget>,
});

#[derive(Clone, Debug, PartialEq, Deserialize, JsonSchema, Serialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct ExecApprovalForwardTarget {
    pub channel: String,
    pub to: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub account_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub thread_id: Option<StringOrNumber>,
}

string_enum!(ModelsMode, "lowercase", Merge, Replace);
string_enum!(
    ModelProviderAuthMode,
    "kebab-case",
    ApiKey,
    AwsSdk,
    Oauth,
    Token
);

#[derive(Clone, Copy, Debug, Eq, PartialEq, Deserialize, JsonSchema, Serialize)]
pub enum ModelApi {
    #[serde(rename = "openai-completions")]
    OpenAiCompletions,
    #[serde(rename = "openai-responses")]
    OpenAiResponses,
    #[serde(rename = "openai-chatgpt-responses")]
    OpenAiChatGptResponses,
    #[serde(rename = "anthropic-messages")]
    AnthropicMessages,
    #[serde(rename = "google-generative-ai")]
    GoogleGenerativeAi,
    #[serde(rename = "google-vertex")]
    GoogleVertex,
    #[serde(rename = "github-copilot")]
    GitHubCopilot,
    #[serde(rename = "bedrock-converse-stream")]
    BedrockConverseStream,
    #[serde(rename = "ollama")]
    Ollama,
    #[serde(rename = "azure-openai-responses")]
    AzureOpenAiResponses,
}

string_enum!(ModelInputModality, "lowercase", Text, Image, Video, Audio);
string_enum!(MetadataSourceMarker, "kebab-case", ModelsAdd);

optional_config!(ModelPricingConfig { enabled: bool });
#[derive(Clone, Debug, PartialEq, Deserialize, JsonSchema, Serialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct ModelCostConfig {
    pub input: f64,
    pub output: f64,
    pub cache_read: f64,
    pub cache_write: f64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tiered_pricing: Option<Vec<ModelTieredPriceConfig>>,
}

#[derive(Clone, Debug, PartialEq, Deserialize, JsonSchema, Serialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct ModelTieredPriceConfig {
    pub input: f64,
    pub output: f64,
    pub cache_read: f64,
    pub cache_write: f64,
    pub range: ModelTierRange,
}

#[derive(Clone, Debug, PartialEq, Deserialize, JsonSchema, Serialize)]
#[serde(untagged)]
pub enum ModelTierRange {
    Bounded([u64; 2]),
    Open([u64; 1]),
}

optional_config!(ThinkingLevelMapConfig {
    off: NullableString,
    minimal: NullableString,
    low: NullableString,
    medium: NullableString,
    high: NullableString,
    xhigh: NullableString,
    max: NullableString,
});
#[derive(Clone, Debug, PartialEq, Deserialize, JsonSchema, Serialize)]
#[serde(untagged)]
pub enum NullableString {
    String(String),
    Null(()),
}
optional_config!(ModelAgentRuntimePolicyConfig { id: String });
optional_config!(ModelImageInputConfig {
    max_bytes: u64,
    max_pixels: u64,
    max_side_px: u32,
    preferred_side_px: u32,
    token_mode: ModelImageTokenMode,
});
string_enum!(ModelImageTokenMode, "lowercase", Tile, Detail, Provider);
optional_config!(ModelMediaInputConfig {
    image: ModelImageInputConfig,
});

#[derive(Clone, Debug, PartialEq, Deserialize, JsonSchema, Serialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct ModelProviderLocalServiceConfig {
    pub command: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub args: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cwd: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub env: Option<BTreeMap<String, SecretInput>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub health_url: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ready_timeout_ms: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub idle_stop_ms: Option<u64>,
}

#[derive(Clone, Debug, PartialEq, Deserialize, JsonSchema, Serialize)]
#[serde(tag = "mode", rename_all = "kebab-case", deny_unknown_fields)]
pub enum ConfiguredProviderRequestAuth {
    ProviderDefault,
    AuthorizationBearer {
        token: SecretInput,
    },
    Header {
        #[serde(rename = "headerName")]
        header_name: String,
        value: SecretInput,
        #[serde(skip_serializing_if = "Option::is_none")]
        prefix: Option<String>,
    },
}

optional_config!(ConfiguredProviderRequestTls {
    ca: SecretInput,
    cert: SecretInput,
    key: SecretInput,
    passphrase: SecretInput,
    server_name: String,
    insecure_skip_verify: bool,
});

#[derive(Clone, Debug, PartialEq, Deserialize, JsonSchema, Serialize)]
#[serde(tag = "mode", rename_all = "kebab-case", deny_unknown_fields)]
pub enum ConfiguredProviderRequestProxy {
    EnvProxy {
        #[serde(skip_serializing_if = "Option::is_none")]
        tls: Option<ConfiguredProviderRequestTls>,
    },
    ExplicitProxy {
        url: String,
        #[serde(skip_serializing_if = "Option::is_none")]
        tls: Option<ConfiguredProviderRequestTls>,
    },
}

optional_config!(ConfiguredModelProviderRequestConfig {
    headers: BTreeMap<String, SecretInput>,
    auth: ConfiguredProviderRequestAuth,
    proxy: ConfiguredProviderRequestProxy,
    tls: ConfiguredProviderRequestTls,
    allow_private_network: bool,
});

string_enum!(
    ModelMaxTokensField,
    "snake_case",
    MaxCompletionTokens,
    MaxTokens
);
string_enum!(
    ModelThinkingFormat,
    "kebab-case",
    Openai,
    Openrouter,
    Deepseek,
    Together,
    Qwen,
    QwenChatTemplate,
    Zai
);
optional_config!(ModelCompatConfig {
    supports_store: bool,
    supports_prompt_cache_key: bool,
    supports_developer_role: bool,
    supports_reasoning_effort: bool,
    supports_temperature: bool,
    supports_usage_in_streaming: bool,
    supports_tools: bool,
    supports_strict_mode: bool,
    requires_string_content: bool,
    strict_message_keys: bool,
    visible_reasoning_detail_types: Vec<String>,
    supported_reasoning_efforts: Vec<String>,
    reasoning_effort_map: BTreeMap<String, String>,
    max_tokens_field: ModelMaxTokensField,
    thinking_format: ModelThinkingFormat,
    requires_tool_result_name: bool,
    requires_assistant_after_tool_result: bool,
    requires_thinking_as_text: bool,
    requires_reasoning_content_on_assistant_messages: bool,
    tool_schema_profile: String,
    unsupported_tool_schema_keywords: Vec<String>,
    native_web_search_tool: bool,
    tool_call_arguments_encoding: String,
    requires_mistral_tool_ids: bool,
    requires_open_ai_anthropic_tool_payload: bool,
});

#[derive(Clone, Debug, PartialEq, Deserialize, JsonSchema, Serialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct ModelDefinitionConfig {
    pub id: String,
    pub name: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub api: Option<ModelApi>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub base_url: Option<String>,
    pub reasoning: bool,
    pub input: Vec<ModelInputModality>,
    pub cost: ModelCostConfig,
    pub context_window: u32,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub context_tokens: Option<u32>,
    pub max_tokens: u32,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub thinking_level_map: Option<ThinkingLevelMapConfig>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub params: Option<ExtensionObject>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub agent_runtime: Option<ModelAgentRuntimePolicyConfig>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub headers: Option<BTreeMap<String, String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub compat: Option<ModelCompatConfig>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub media_input: Option<ModelMediaInputConfig>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub metadata_source: Option<MetadataSourceMarker>,
}

#[derive(Clone, Debug, Default, PartialEq, Deserialize, JsonSchema, Serialize)]
#[serde(default, deny_unknown_fields, rename_all = "camelCase")]
pub struct ModelProviderConfig {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub base_url: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub api_key: Option<SecretInput>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub auth: Option<ModelProviderAuthMode>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub api: Option<ModelApi>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub context_window: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub context_tokens: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub max_tokens: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub timeout_seconds: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub region: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(rename = "injectNumCtxForOpenAICompat")]
    pub inject_num_ctx_for_open_ai_compat: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub params: Option<ExtensionObject>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub agent_runtime: Option<ModelAgentRuntimePolicyConfig>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub local_service: Option<ModelProviderLocalServiceConfig>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub headers: Option<BTreeMap<String, SecretInput>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub auth_header: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub request: Option<ConfiguredModelProviderRequestConfig>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub models: Option<Vec<ModelDefinitionConfig>>,
}

string_enum!(
    CronRetryOn,
    "snake_case",
    RateLimit,
    Overloaded,
    Network,
    Timeout,
    ServerError
);
string_enum!(CronAlertMode, "lowercase", Announce, Webhook);
optional_config!(CronTriggersConfig {
    enabled: bool,
    min_interval_ms: u64,
});
optional_config!(CronRetryConfig {
    max_attempts: u32,
    backoff_ms: Vec<u64>,
    retry_on: Vec<CronRetryOn>,
});
optional_config!(CronRunLogConfig {
    max_bytes: StringOrNumber,
    keep_lines: u32,
});
optional_config!(CronFailureAlertConfig {
    enabled: bool,
    after: u32,
    cooldown_ms: u64,
    include_skipped: bool,
    mode: CronAlertMode,
    account_id: String,
});
optional_config!(CronFailureDestinationConfig {
    channel: String,
    to: String,
    account_id: String,
    mode: CronAlertMode,
});

#[derive(Clone, Debug, PartialEq, Deserialize, JsonSchema, Serialize)]
#[serde(untagged)]
pub enum SessionRetention {
    Duration(String),
    Disabled(LiteralFalse),
}

#[derive(Clone, Debug, PartialEq, Deserialize, JsonSchema, Serialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct TranscriptsAutoStartConfig {
    pub provider_id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub session_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub title: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub account_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub guild_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub channel_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub meeting_url: Option<String>,
}

string_enum!(HookAction, "lowercase", Wake, Agent);
string_enum!(HookWakeMode, "kebab-case", Now, NextHeartbeat);
string_enum!(HooksGmailTailscaleMode, "lowercase", Off, Serve, Funnel);
string_enum!(
    HooksGmailThinking,
    "lowercase",
    Off,
    Minimal,
    Low,
    Medium,
    High
);
optional_config!(HookMappingMatch {
    path: String,
    source: String,
});
optional_config!(HookMappingTransform {
    module: String,
    export: String,
});

#[derive(Clone, Debug, Default, PartialEq, Deserialize, JsonSchema, Serialize)]
#[serde(default, deny_unknown_fields, rename_all = "camelCase")]
pub struct HookMappingConfig {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub id: Option<String>,
    #[serde(rename = "match", skip_serializing_if = "Option::is_none")]
    pub match_rule: Option<HookMappingMatch>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub action: Option<HookAction>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub wake_mode: Option<HookWakeMode>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub agent_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub session_key: Option<SecretInput>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub message_template: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub text_template: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub deliver: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub allow_unsafe_external_content: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub channel: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub to: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub model: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub thinking: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub timeout_seconds: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub transform: Option<HookMappingTransform>,
}
optional_config!(HooksGmailServeConfig {
    bind: String,
    port: u16,
    path: String,
});
optional_config!(HooksGmailTailscaleConfig {
    mode: HooksGmailTailscaleMode,
    path: String,
    target: String,
});
optional_config!(HooksGmailConfig {
    account: String,
    label: String,
    topic: String,
    subscription: String,
    push_token: SecretInput,
    hook_url: String,
    include_body: bool,
    max_bytes: u32,
    renew_every_minutes: u32,
    allow_unsafe_external_content: bool,
    serve: HooksGmailServeConfig,
    tailscale: HooksGmailTailscaleConfig,
    model: String,
    thinking: HooksGmailThinking,
});

#[derive(Clone, Debug, PartialEq, Deserialize, JsonSchema, Serialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct InternalHookHandler {
    pub event: String,
    pub module: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub export: Option<String>,
}

#[derive(Clone, Debug, Default, PartialEq, Deserialize, JsonSchema, Serialize)]
#[serde(default, rename_all = "camelCase")]
pub struct HookConfig {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub enabled: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub env: Option<BTreeMap<String, String>>,
    #[serde(flatten)]
    pub options: ExtensionObject,
}

optional_config!(InternalHooksLoadConfig {
    extra_dirs: Vec<String>,
});
optional_config!(InternalHooksConfig {
    enabled: bool,
    handlers: Vec<InternalHookHandler>,
    entries: BTreeMap<String, HookConfig>,
    load: InternalHooksLoadConfig,
    installs: BTreeMap<String, ExtensionObject>,
});

optional_config!(DiscoveryWideAreaConfig {
    enabled: bool,
    domain: String,
});
string_enum!(DiscoveryMdnsMode, "lowercase", Off, Minimal, Full);
optional_config!(DiscoveryMdnsConfig {
    mode: DiscoveryMdnsMode,
});

string_enum!(
    TalkRealtimeMode,
    "kebab-case",
    Realtime,
    SttTts,
    Transcription
);
string_enum!(
    TalkRealtimeTransport,
    "kebab-case",
    Webrtc,
    ProviderWebsocket,
    GatewayRelay,
    ManagedRoom
);
string_enum!(
    TalkRealtimeBrain,
    "kebab-case",
    AgentConsult,
    DirectTools,
    None
);
string_enum!(
    TalkConsultRouting,
    "kebab-case",
    ProviderDirect,
    ForceAgentConsult
);

#[derive(Clone, Debug, Default, PartialEq, Deserialize, JsonSchema, Serialize)]
#[serde(default, rename_all = "camelCase")]
pub struct TalkProviderEntry {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub api_key: Option<SecretInput>,
    #[serde(flatten)]
    pub options: ExtensionObject,
}

optional_config!(TalkRealtimeConfig {
    provider: String,
    providers: BTreeMap<String, TalkProviderEntry>,
    model: String,
    speaker_voice: String,
    speaker_voice_id: String,
    voice: String,
    instructions: String,
    mode: TalkRealtimeMode,
    transport: TalkRealtimeTransport,
    vad_threshold: f64,
    silence_duration_ms: u32,
    prefix_padding_ms: u32,
    reasoning_effort: String,
    brain: TalkRealtimeBrain,
    consult_routing: TalkConsultRouting,
});

string_enum!(
    GatewayBindMode,
    "lowercase",
    Auto,
    Lan,
    Loopback,
    Custom,
    Tailnet
);
string_enum!(GatewayMode, "lowercase", Local, Remote);
string_enum!(
    GatewayAuthMode,
    "kebab-case",
    None,
    Token,
    Password,
    TrustedProxy
);
string_enum!(TailscaleMode, "lowercase", Off, Serve, Funnel);
string_enum!(SshHostKeyPolicy, "lowercase", Strict, Openssh);
string_enum!(GatewayReloadMode, "lowercase", Off, Restart, Hot, Hybrid);
string_enum!(EmbedSandboxMode, "lowercase", Strict, Scripts, Trusted);
string_enum!(BrowserNodeMode, "lowercase", Auto, Manual, Off);
string_enum!(GatewayRemoteTransport, "lowercase", Ssh, Direct);

optional_config!(GatewayControlUiConfig {
    enabled: bool,
    base_path: String,
    root: String,
    tool_titles: bool,
    embed_sandbox: EmbedSandboxMode,
    allow_external_embed_urls: bool,
    chat_message_max_width: String,
    allowed_origins: Vec<String>,
    dangerously_allow_host_header_origin_fallback: bool,
    allow_insecure_auth: bool,
    dangerously_disable_device_auth: bool,
});
optional_config!(GatewayTerminalConfig {
    enabled: bool,
    shell: String,
    detached_session_timeout_seconds: u32,
});
optional_config!(GatewayRateLimitConfig {
    max_attempts: u32,
    window_ms: u64,
    lockout_ms: u64,
    exempt_loopback: bool,
});

#[derive(Clone, Debug, PartialEq, Deserialize, JsonSchema, Serialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct GatewayTrustedProxyConfig {
    pub user_header: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub required_headers: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub allow_users: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub allow_loopback: Option<bool>,
}

optional_config!(GatewayAuthConfig {
    mode: GatewayAuthMode,
    token: SecretInput,
    password: SecretInput,
    allow_tailscale: bool,
    rate_limit: GatewayRateLimitConfig,
    trusted_proxy: GatewayTrustedProxyConfig,
});
optional_config!(GatewayToolsConfig {
    deny: Vec<String>,
    allow: Vec<String>,
});
optional_config!(GatewayTailscaleConfig {
    mode: TailscaleMode,
    reset_on_exit: bool,
    service_name: String,
    preserve_funnel: bool,
});
optional_config!(GatewayRemoteConfig {
    enabled: bool,
    url: String,
    transport: GatewayRemoteTransport,
    remote_port: u16,
    token: SecretInput,
    password: SecretInput,
    tls_fingerprint: String,
    ssh_target: String,
    ssh_identity: String,
    ssh_host_key_policy: SshHostKeyPolicy,
});
optional_config!(GatewayReloadConfig {
    mode: GatewayReloadMode,
    debounce_ms: u32,
    deferral_timeout_ms: u32,
});
optional_config!(GatewayTlsConfig {
    enabled: bool,
    auto_generate: bool,
    cert_path: String,
    key_path: String,
    ca_path: String,
});
optional_config!(UrlFetchShapeConfig {
    allow_url: bool,
    url_allowlist: Vec<String>,
    allowed_mimes: Vec<String>,
    max_bytes: u32,
    max_redirects: u32,
    timeout_ms: u32,
});
optional_config!(PdfConfig {
    max_pages: u32,
    max_pixels: u32,
    min_text_chars: u32,
});

#[derive(Clone, Debug, Default, PartialEq, Deserialize, JsonSchema, Serialize)]
#[serde(default, deny_unknown_fields, rename_all = "camelCase")]
pub struct GatewayHttpResponsesFilesConfig {
    #[serde(flatten)]
    pub fetch: UrlFetchShapeConfig,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub max_chars: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub pdf: Option<PdfConfig>,
}

optional_config!(GatewayHttpChatCompletionsConfig {
    enabled: bool,
    max_body_bytes: u32,
    max_image_parts: u32,
    max_total_image_bytes: u32,
    images: UrlFetchShapeConfig,
});
optional_config!(GatewayHttpResponsesConfig {
    enabled: bool,
    max_body_bytes: u32,
    max_url_parts: u32,
    files: GatewayHttpResponsesFilesConfig,
    images: UrlFetchShapeConfig,
});
optional_config!(GatewayHttpEndpointsConfig {
    chat_completions: GatewayHttpChatCompletionsConfig,
    responses: GatewayHttpResponsesConfig,
});
optional_config!(GatewayHttpSecurityHeadersConfig {
    strict_transport_security: StringOrFalse,
});
optional_config!(GatewayHttpConfig {
    endpoints: GatewayHttpEndpointsConfig,
    security_headers: GatewayHttpSecurityHeadersConfig,
});
optional_config!(GatewayNodesBrowserConfig {
    mode: BrowserNodeMode,
    node: String,
});
optional_config!(SshVerifyObject {
    user: String,
    identity: String,
    timeout_ms: u32,
    cidrs: Vec<String>,
});

#[derive(Clone, Debug, PartialEq, Deserialize, JsonSchema, Serialize)]
#[serde(untagged)]
pub enum SshVerifyConfig {
    Enabled(bool),
    Options(SshVerifyObject),
}
optional_config!(GatewayNodesPairingConfig {
    auto_approve_cidrs: Vec<String>,
    ssh_verify: SshVerifyConfig,
});
optional_config!(EnabledConfig { enabled: bool });
optional_config!(GatewayNodesConfig {
    browser: GatewayNodesBrowserConfig,
    pairing: GatewayNodesPairingConfig,
    plugin_tools: EnabledConfig,
    skills: EnabledConfig,
    allow_commands: Vec<String>,
    deny_commands: Vec<String>,
});
optional_config!(GatewayPushApnsRelayConfig {
    base_url: String,
    timeout_ms: u64,
});
optional_config!(GatewayPushApnsConfig {
    relay: GatewayPushApnsRelayConfig,
});
optional_config!(GatewayPushConfig {
    apns: GatewayPushApnsConfig,
});

string_enum!(CloudWorkerInstallMethod, "lowercase", Bundle, Npm);
optional_config!(CloudWorkerLifetimePolicyConfig {
    idle_timeout_minutes: u32,
    max_lifetime_minutes: u32,
});

#[derive(Clone, Debug, PartialEq, Deserialize, JsonSchema, Serialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct CloudWorkerProfileConfig {
    pub provider: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub install: Option<CloudWorkerInstallMethod>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub settings: Option<ExtensionObject>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub lifetime: Option<CloudWorkerLifetimePolicyConfig>,
}

string_enum!(MemoryBackend, "lowercase", Builtin, Qmd);
string_enum!(MemoryCitationsMode, "lowercase", Auto, On, Off);
string_enum!(MemoryQmdSearchMode, "lowercase", Query, Search, Vsearch);
string_enum!(MemoryQmdStartupMode, "lowercase", Off, Idle, Immediate);
optional_config!(MemoryQmdMcporterConfig {
    enabled: bool,
    server_name: String,
    start_daemon: bool,
});

#[derive(Clone, Debug, PartialEq, Deserialize, JsonSchema, Serialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct MemoryQmdIndexPath {
    pub path: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub pattern: Option<String>,
}

optional_config!(MemoryQmdSessionConfig {
    enabled: bool,
    export_dir: String,
    retention_days: u32,
});
optional_config!(MemoryQmdUpdateConfig {
    interval: String,
    debounce_ms: u32,
    on_boot: bool,
    startup: MemoryQmdStartupMode,
    startup_delay_ms: u32,
    wait_for_boot_sync: bool,
    embed_interval: String,
    command_timeout_ms: u32,
    update_timeout_ms: u32,
    embed_timeout_ms: u32,
});
optional_config!(MemoryQmdLimitsConfig {
    max_results: u32,
    max_snippet_chars: u32,
    max_injected_chars: u32,
    timeout_ms: u32,
});
optional_config!(MemoryQmdConfig {
    command: String,
    mcporter: MemoryQmdMcporterConfig,
    search_mode: MemoryQmdSearchMode,
    rerank: bool,
    search_tool: String,
    include_default_memory: bool,
    paths: Vec<MemoryQmdIndexPath>,
    sessions: MemoryQmdSessionConfig,
    update: MemoryQmdUpdateConfig,
    limits: MemoryQmdLimitsConfig,
    scope: Vec<String>,
});

optional_config!(McpAppsConfig {
    enabled: bool,
    sandbox_origin: String,
    sandbox_port: u16,
});

string_enum!(ProxyLoopbackMode, "kebab-case", GatewayOnly, Proxy, Block);
optional_config!(ProxyTlsConfig { ca_file: String });
optional_config!(ProxyDomain {
    enabled: bool,
    proxy_url: SecretInput,
    tls: ProxyTlsConfig,
    loopback_mode: ProxyLoopbackMode,
});

fn valid_secret_provider_alias(value: &str) -> bool {
    (1..=64).contains(&value.len())
        && value
            .bytes()
            .next()
            .is_some_and(|byte| byte.is_ascii_lowercase())
        && value.bytes().all(|byte| {
            byte.is_ascii_lowercase() || byte.is_ascii_digit() || matches!(byte, b'_' | b'-')
        })
}

fn valid_env_secret_id(value: &str) -> bool {
    (1..=128).contains(&value.len())
        && value
            .bytes()
            .next()
            .is_some_and(|byte| byte.is_ascii_uppercase())
        && value
            .bytes()
            .all(|byte| byte.is_ascii_uppercase() || byte.is_ascii_digit() || byte == b'_')
}

fn valid_file_secret_id(value: &str) -> bool {
    if value == "value" {
        return true;
    }
    let Some(pointer) = value.strip_prefix('/') else {
        return false;
    };
    pointer.split('/').all(|segment| {
        let bytes = segment.as_bytes();
        let mut index = 0;
        while index < bytes.len() {
            if bytes[index] == b'~' {
                if !matches!(bytes.get(index + 1), Some(b'0' | b'1')) {
                    return false;
                }
                index += 2;
            } else {
                index += 1;
            }
        }
        true
    })
}

fn valid_exec_secret_id(value: &str) -> bool {
    (1..=256).contains(&value.len())
        && value
            .bytes()
            .next()
            .is_some_and(|byte| byte.is_ascii_alphanumeric())
        && value.bytes().all(|byte| {
            byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b':' | b'/' | b'#' | b'-')
        })
        && value
            .split('/')
            .all(|segment| !matches!(segment, "." | ".."))
}

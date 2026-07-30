use std::collections::BTreeMap;

use crate::ConfigError;
use crate::layer::{merge_layer, merge_value};
use crate::migration::parse_legacy_integer;
use crate::{ConfigLayerKind, LayeredConfigError};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use serde_json::Value;

mod imported;
mod reload;
pub use imported::*;
pub use reload::*;

/// Frozen top-level domain order from `compat/upstream/inventories/config-domains.json`.
pub const CONFIG_DOMAIN_NAMES: [&str; 47] = [
    "$schema",
    "meta",
    "auth",
    "accessGroups",
    "acp",
    "env",
    "wizard",
    "diagnostics",
    "logging",
    "audit",
    "security",
    "cli",
    "crestodian",
    "update",
    "browser",
    "ui",
    "tui",
    "secrets",
    "marketplaces",
    "skills",
    "plugins",
    "surfaces",
    "models",
    "nodeHost",
    "agents",
    "tools",
    "bindings",
    "broadcast",
    "audio",
    "media",
    "messages",
    "commands",
    "approvals",
    "session",
    "web",
    "channels",
    "cron",
    "transcripts",
    "commitments",
    "hooks",
    "discovery",
    "talk",
    "gateway",
    "cloudWorkers",
    "memory",
    "mcp",
    "proxy",
];

macro_rules! object_domain {
    ($(#[$meta:meta])* $name:ident, $value:ty) => {
        $(#[$meta])*
        #[derive(Clone, Debug, Default, Eq, PartialEq, Deserialize, JsonSchema, Serialize)]
        #[serde(transparent)]
        pub struct $name(pub BTreeMap<String, $value>);
    };
}

macro_rules! typed_domain {
    (@define [$($equality:ident),*] $(#[$meta:meta])* $name:ident { $($field:ident: $type:ty => $wire:literal),* $(,)? }) => {
        $(#[$meta])*
        #[expect(
            missing_docs,
            reason = "these fields are the frozen upstream JSON keys; the authoritative \
                      description of each one lives in compat/upstream, not in a per-field \
                      comment that could silently drift from it"
        )]
        #[derive(Clone, Debug, Default, PartialEq, $($equality,)* Deserialize, JsonSchema, Serialize)]
        #[serde(default, deny_unknown_fields)]
        pub struct $name {
            $(
                #[serde(rename = $wire, skip_serializing_if = "Option::is_none")]
                pub $field: Option<$type>,
            )*
        }
    };
    // Domains that carry an IEEE-754 value, directly or through a nested type.
    // `Eq` promises reflexivity, which floating point does not provide, so these
    // deliberately stop at `PartialEq`.
    ($(#[$meta:meta])* partial_eq_only $name:ident { $($field:ident: $type:ty => $wire:literal),* $(,)? }) => {
        typed_domain!(@define [] $(#[$meta])* $name { $($field: $type => $wire),* });
    };
    ($(#[$meta:meta])* $name:ident { $($field:ident: $type:ty => $wire:literal),* $(,)? }) => {
        typed_domain!(@define [Eq] $(#[$meta])* $name { $($field: $type => $wire),* });
    };
}

typed_domain!(
    /// Authentication provider and profile configuration.
    partial_eq_only AuthDomain {
        profiles: BTreeMap<String, AuthProfileConfig> => "profiles",
        order: BTreeMap<String, Vec<String>> => "order",
        cooldowns: AuthCooldownConfig => "cooldowns",
    }
);
object_domain!(
    /// Named access-group configuration.
    AccessGroupsDomain,
    AccessGroupConfig
);
typed_domain!(
    /// Agent Client Protocol integration configuration.
    AcpDomain {
        enabled: bool => "enabled",
        dispatch: AcpDispatchConfig => "dispatch",
        backend: String => "backend",
        fallbacks: Vec<String> => "fallbacks",
        default_agent: String => "defaultAgent",
        allowed_agents: Vec<String> => "allowedAgents",
        max_concurrent_sessions: u32 => "maxConcurrentSessions",
        stream: AcpStreamConfig => "stream",
        runtime: AcpRuntimeConfig => "runtime",
    }
);
typed_domain!(
    /// Diagnostics and tracing configuration.
    partial_eq_only DiagnosticsDomain {
        enabled: bool => "enabled",
        flags: Vec<String> => "flags",
        stuck_session_warn_ms: u64 => "stuckSessionWarnMs",
        stuck_session_abort_ms: u64 => "stuckSessionAbortMs",
        memory_pressure_snapshot: bool => "memoryPressureSnapshot",
        otel: DiagnosticsOtelConfig => "otel",
        cache_trace: DiagnosticsCacheTraceConfig => "cacheTrace",
    }
);
typed_domain!(
    /// Log sink, level, rotation, and redaction configuration.
    LoggingDomain {
        level: LogLevel => "level",
        file: String => "file",
        max_file_bytes: u64 => "maxFileBytes",
        console_level: LogLevel => "consoleLevel",
        console_style: ConsoleStyle => "consoleStyle",
        redact_sensitive: RedactSensitive => "redactSensitive",
        redact_patterns: Vec<String> => "redactPatterns",
    }
);
typed_domain!(
    /// Metadata-only activity audit configuration.
    AuditDomain {
        enabled: bool => "enabled",
        messages: AuditMessagesMode => "messages",
    }
);
typed_domain!(
    /// CLI defaults and command-specific configuration.
    CliDomain {
        banner: CliBannerConfig => "banner",
    }
);
typed_domain!(
    /// Browser automation configuration.
    partial_eq_only BrowserDomain {
        enabled: bool => "enabled",
        allow_system_profile_import: bool => "allowSystemProfileImport",
        evaluate_enabled: bool => "evaluateEnabled",
        cdp_url: String => "cdpUrl",
        remote_cdp_timeout_ms: u64 => "remoteCdpTimeoutMs",
        remote_cdp_handshake_timeout_ms: u64 => "remoteCdpHandshakeTimeoutMs",
        local_launch_timeout_ms: u64 => "localLaunchTimeoutMs",
        local_cdp_ready_timeout_ms: u64 => "localCdpReadyTimeoutMs",
        action_timeout_ms: u64 => "actionTimeoutMs",
        color: String => "color",
        executable_path: String => "executablePath",
        headless: bool => "headless",
        no_sandbox: bool => "noSandbox",
        attach_only: bool => "attachOnly",
        cdp_port_range_start: u16 => "cdpPortRangeStart",
        default_profile: String => "defaultProfile",
        profiles: BTreeMap<String, BrowserProfileConfig> => "profiles",
        snapshot_defaults: BrowserSnapshotDefaults => "snapshotDefaults",
        tab_cleanup: BrowserTabCleanupConfig => "tabCleanup",
        ssrf_policy: BrowserSsrfPolicyConfig => "ssrfPolicy",
        extra_args: Vec<String> => "extraArgs",
    }
);
typed_domain!(
    /// Secret provider and resolution configuration.
    SecretsDomain {
        providers: BTreeMap<String, SecretProviderConfig> => "providers",
        defaults: SecretDefaultsConfig => "defaults",
        resolution: SecretResolutionConfig => "resolution",
    }
);
typed_domain!(
    /// Marketplace feed and package-source configuration.
    MarketplacesDomain {
        feeds: BTreeMap<String, MarketplaceFeedProfileConfig> => "feeds",
        sources: BTreeMap<String, MarketplaceSourceProfileConfig> => "sources",
    }
);
typed_domain!(
    /// Skill loading configuration.
    SkillsDomain {
        allow_bundled: Vec<String> => "allowBundled",
        load: SkillsLoadConfig => "load",
        install: SkillsInstallConfig => "install",
        limits: SkillsLimitsConfig => "limits",
        workshop: SkillsWorkshopConfig => "workshop",
        entries: BTreeMap<String, SkillConfig> => "entries",
    }
);
typed_domain!(
    /// Plugin registry and runtime configuration.
    PluginsDomain {
        enabled: bool => "enabled",
        allow: Vec<String> => "allow",
        deny: Vec<String> => "deny",
        load: PluginsLoadConfig => "load",
        slots: PluginSlotsConfig => "slots",
        entries: BTreeMap<String, PluginEntryConfig> => "entries",
        bundled_discovery: BundledDiscoveryMode => "bundledDiscovery",
        installs: BTreeMap<String, ExtensionObject> => "installs",
    }
);
typed_domain!(
    /// Model provider and catalog configuration.
    partial_eq_only ModelsDomain {
        mode: ModelsMode => "mode",
        providers: BTreeMap<String, ModelProviderConfig> => "providers",
        pricing: ModelPricingConfig => "pricing",
    }
);
typed_domain!(
    /// Node-host pairing and remote command configuration.
    partial_eq_only NodeHostDomain {
        browser_proxy: NodeHostBrowserProxyConfig => "browserProxy",
        mcp: NodeHostMcpConfig => "mcp",
        skills: NodeHostSkillsConfig => "skills",
    }
);
typed_domain!(
    /// Agent defaults, entries, and runtime policy.
    partial_eq_only AgentsDomain {
        defaults: AgentDefaultsConfig => "defaults",
        list: Vec<AgentConfig> => "list",
    }
);
typed_domain!(
    /// Tool exposure and execution policy.
    partial_eq_only ToolsDomain {
        profile: ToolProfileId => "profile",
        allow: Vec<String> => "allow",
        also_allow: Vec<String> => "alsoAllow",
        deny: Vec<String> => "deny",
        by_provider: BTreeMap<String, ToolPolicyConfig> => "byProvider",
        tools_by_sender: BTreeMap<String, GroupToolPolicyConfig> => "toolsBySender",
        web: ToolsWebConfig => "web",
        media: MediaToolsConfig => "media",
        links: LinkToolsConfig => "links",
        message: MessageToolsConfig => "message",
        agent_to_agent: AgentToAgentToolsConfig => "agentToAgent",
        sessions: ToolsSessionsConfig => "sessions",
        elevated: ToolsElevatedConfig => "elevated",
        exec: ExecToolConfig => "exec",
        fs: FsToolsConfig => "fs",
        loop_detection: ToolLoopDetectionConfig => "loopDetection",
        tool_search: ToolSearchConfig => "toolSearch",
        code_mode: CodeModeConfig => "codeMode",
        sessions_spawn: SessionsSpawnToolsConfig => "sessions_spawn",
        subagents: SubagentToolsPolicyConfig => "subagents",
        sandbox: SandboxToolsPolicyConfig => "sandbox",
        experimental: ToolsExperimentalConfig => "experimental",
    }
);
/// Broadcast command and delivery configuration.
pub type BroadcastDomain = BroadcastConfig;
typed_domain!(
    /// Audio command and media handling configuration.
    AudioDomain {
        transcription: AudioTranscriptionConfig => "transcription",
    }
);
typed_domain!(
    /// Message formatting and delivery configuration.
    MessagesDomain {
        message_prefix: String => "messagePrefix",
        visible_replies: VisibleRepliesMode => "visibleReplies",
        response_prefix: String => "responsePrefix",
        usage_template: UsageTemplateConfig => "usageTemplate",
        response_usage: ResponseUsageConfig => "responseUsage",
        group_chat: GroupChatConfig => "groupChat",
        queue: QueueConfig => "queue",
        inbound: InboundDebounceConfig => "inbound",
        ack_reaction: String => "ackReaction",
        ack_reaction_scope: AckReactionScope => "ackReactionScope",
        remove_ack_after_reply: bool => "removeAckAfterReply",
        status_reactions: StatusReactionsConfig => "statusReactions",
        suppress_tool_errors: bool => "suppressToolErrors",
        tts: TtsConfig => "tts",
    }
);
typed_domain!(
    /// Chat command configuration.
    CommandsDomain {
        native: NativeCommandMode => "native",
        native_skills: NativeCommandMode => "nativeSkills",
        text: bool => "text",
        bash: bool => "bash",
        bash_foreground_ms: u32 => "bashForegroundMs",
        config: bool => "config",
        mcp: bool => "mcp",
        plugins: bool => "plugins",
        debug: bool => "debug",
        restart: bool => "restart",
        use_access_groups: bool => "useAccessGroups",
        owner_allow_from: Vec<StringOrNumber> => "ownerAllowFrom",
        owner_display: CommandOwnerDisplay => "ownerDisplay",
        owner_display_secret: SecretInput => "ownerDisplaySecret",
        allow_from: BTreeMap<String, Vec<StringOrNumber>> => "allowFrom",
    }
);
typed_domain!(
    /// Human approval workflow configuration.
    ApprovalsDomain {
        exec: ExecApprovalForwardingConfig => "exec",
        plugin: ExecApprovalForwardingConfig => "plugin",
    }
);
typed_domain!(
    /// Session keying, reset, and maintenance configuration.
    partial_eq_only SessionDomain {
        scope: SessionScope => "scope",
        dm_scope: DmScope => "dmScope",
        identity_links: BTreeMap<String, Vec<String>> => "identityLinks",
        reset_triggers: Vec<String> => "resetTriggers",
        idle_minutes: f64 => "idleMinutes",
        reset: SessionResetConfig => "reset",
        reset_by_type: SessionResetByTypeConfig => "resetByType",
        reset_by_channel: BTreeMap<String, SessionResetConfig> => "resetByChannel",
        store: String => "store",
        typing_interval_seconds: f64 => "typingIntervalSeconds",
        typing_mode: TypingMode => "typingMode",
        main_key: String => "mainKey",
        send_policy: SessionSendPolicyConfig => "sendPolicy",
        write_lock: SessionWriteLockConfig => "writeLock",
        agent_to_agent: SessionAgentToAgentConfig => "agentToAgent",
        thread_bindings: SessionThreadBindingsConfig => "threadBindings",
        maintenance: SessionMaintenanceConfig => "maintenance",
    }
);
typed_domain!(
    /// Web runtime configuration.
    partial_eq_only WebDomain {
        enabled: bool => "enabled",
        heartbeat_seconds: f64 => "heartbeatSeconds",
        reconnect: WebReconnectConfig => "reconnect",
        whatsapp: WebWhatsAppConfig => "whatsapp",
    }
);
typed_domain!(
    /// Cron scheduling and retention configuration.
    CronDomain {
        enabled: bool => "enabled",
        store: String => "store",
        max_concurrent_runs: u32 => "maxConcurrentRuns",
        triggers: CronTriggersConfig => "triggers",
        retry: CronRetryConfig => "retry",
        webhook: String => "webhook",
        webhook_token: SecretInput => "webhookToken",
        session_retention: SessionRetention => "sessionRetention",
        run_log: CronRunLogConfig => "runLog",
        failure_alert: CronFailureAlertConfig => "failureAlert",
        failure_destination: CronFailureDestinationConfig => "failureDestination",
    }
);
typed_domain!(
    /// Transcript persistence and export configuration.
    TranscriptsDomain {
        enabled: bool => "enabled",
        max_utterances: u32 => "maxUtterances",
        auto_start: Vec<TranscriptsAutoStartConfig> => "autoStart",
    }
);
typed_domain!(
    /// Commitment and reminder extraction configuration.
    CommitmentsDomain {
        enabled: bool => "enabled",
        max_per_day: u32 => "maxPerDay",
    }
);
typed_domain!(
    /// Runtime hook and queue configuration.
    HooksDomain {
        enabled: bool => "enabled",
        path: String => "path",
        token: SecretInput => "token",
        default_session_key: SecretInput => "defaultSessionKey",
        allow_request_session_key: bool => "allowRequestSessionKey",
        allowed_session_key_prefixes: Vec<String> => "allowedSessionKeyPrefixes",
        allowed_agent_ids: Vec<String> => "allowedAgentIds",
        max_body_bytes: usize => "maxBodyBytes",
        presets: Vec<String> => "presets",
        transforms_dir: String => "transformsDir",
        mappings: Vec<HookMappingConfig> => "mappings",
        gmail: HooksGmailConfig => "gmail",
        internal: InternalHooksConfig => "internal",
    }
);
typed_domain!(
    /// Network discovery and advertisement configuration.
    DiscoveryDomain {
        wide_area: DiscoveryWideAreaConfig => "wideArea",
        mdns: DiscoveryMdnsConfig => "mdns",
    }
);
typed_domain!(
    /// Voice and talk-mode configuration.
    partial_eq_only TalkDomain {
        provider: String => "provider",
        providers: BTreeMap<String, TalkProviderEntry> => "providers",
        realtime: TalkRealtimeConfig => "realtime",
        consult_thinking_level: ThinkingLevel => "consultThinkingLevel",
        consult_fast_mode: bool => "consultFastMode",
        speech_locale: String => "speechLocale",
        interrupt_on_speech: bool => "interruptOnSpeech",
        silence_timeout_ms: u32 => "silenceTimeoutMs",
    }
);
typed_domain!(
    /// Gateway server, authentication, UI, and dispatch configuration.
    GatewayDomain {
        port: u16 => "port",
        mode: GatewayMode => "mode",
        bind: GatewayBindMode => "bind",
        custom_bind_host: String => "customBindHost",
        control_ui: GatewayControlUiConfig => "controlUi",
        terminal: GatewayTerminalConfig => "terminal",
        auth: GatewayAuthConfig => "auth",
        tailscale: GatewayTailscaleConfig => "tailscale",
        remote: GatewayRemoteConfig => "remote",
        reload: GatewayReloadConfig => "reload",
        tls: GatewayTlsConfig => "tls",
        http: GatewayHttpConfig => "http",
        push: GatewayPushConfig => "push",
        nodes: GatewayNodesConfig => "nodes",
        trusted_proxies: Vec<String> => "trustedProxies",
        allow_real_ip_fallback: bool => "allowRealIpFallback",
        tools: GatewayToolsConfig => "tools",
        handshake_timeout_ms: u32 => "handshakeTimeoutMs",
        channel_health_check_minutes: u32 => "channelHealthCheckMinutes",
        channel_stale_event_threshold_minutes: u32 => "channelStaleEventThresholdMinutes",
        channel_max_restarts_per_hour: u32 => "channelMaxRestartsPerHour",
    }
);
typed_domain!(
    /// Cloud-worker provider configuration.
    CloudWorkersDomain {
        profiles: BTreeMap<String, CloudWorkerProfileConfig> => "profiles",
    }
);
typed_domain!(
    /// Memory indexing and search configuration.
    MemoryDomain {
        backend: MemoryBackend => "backend",
        citations: MemoryCitationsMode => "citations",
        qmd: MemoryQmdConfig => "qmd",
    }
);
typed_domain!(
    /// Model Context Protocol client and server configuration.
    partial_eq_only McpDomain {
        servers: BTreeMap<String, McpServerConfig> => "servers",
        apps: McpAppsConfig => "apps",
        session_idle_ttl_ms: f64 => "sessionIdleTtlMs",
    }
);

/// Metadata written with an authored `OpenClaw` configuration.
#[derive(Clone, Debug, Default, Eq, PartialEq, Deserialize, JsonSchema, Serialize)]
#[serde(default, deny_unknown_fields, rename_all = "camelCase")]
pub struct MetaConfig {
    /// Last `OpenClaw` version that wrote the file.
    pub last_touched_version: Option<String>,
    /// ISO timestamp at which the file was last written.
    pub last_touched_at: Option<String>,
}

/// Login-shell environment import settings.
#[derive(Clone, Debug, Default, Eq, PartialEq, Deserialize, JsonSchema, Serialize)]
#[serde(default, deny_unknown_fields, rename_all = "camelCase")]
pub struct ShellEnvironmentConfig {
    /// Whether login-shell import is enabled.
    pub enabled: bool,
    /// Login-shell execution timeout in milliseconds.
    pub timeout_ms: Option<u64>,
}

/// Environment variables applied when the process environment does not define them.
#[derive(Clone, Debug, Default, Eq, PartialEq, Deserialize, JsonSchema, Serialize)]
#[serde(default, rename_all = "camelCase")]
pub struct EnvironmentConfig {
    /// Optional login-shell import.
    pub shell_env: Option<ShellEnvironmentConfig>,
    /// Explicit environment variable values.
    pub vars: BTreeMap<String, String>,
    /// Upstream sugar allowing variables directly below `env`.
    #[serde(flatten)]
    pub direct: BTreeMap<String, String>,
}

/// Installation mode recorded by the setup wizard.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Deserialize, JsonSchema, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum WizardMode {
    /// Local installation.
    Local,
    /// Remote installation.
    Remote,
}

/// Last completed setup-wizard information.
#[derive(Clone, Debug, Default, Eq, PartialEq, Deserialize, JsonSchema, Serialize)]
#[serde(default, deny_unknown_fields, rename_all = "camelCase")]
pub struct WizardConfig {
    /// Last completion timestamp.
    pub last_run_at: Option<String>,
    /// `OpenClaw` version used for the run.
    pub last_run_version: Option<String>,
    /// Source commit used for the run.
    pub last_run_commit: Option<String>,
    /// Command that invoked the run.
    pub last_run_command: Option<String>,
    /// Whether the run configured a local or remote installation.
    pub last_run_mode: Option<WizardMode>,
    /// Timestamp at which the security acknowledgement was accepted.
    pub security_acknowledged_at: Option<String>,
}

/// One persisted suppression for a known security finding.
#[derive(Clone, Debug, Eq, PartialEq, Deserialize, JsonSchema, Serialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct SecurityAuditSuppression {
    /// Exact security check identifier.
    pub check_id: String,
    /// Optional title substring.
    pub title_includes: Option<String>,
    /// Optional detail substring.
    pub detail_includes: Option<String>,
    /// Operator rationale.
    pub reason: Option<String>,
}

/// Security-audit policy.
#[derive(Clone, Debug, Default, Eq, PartialEq, Deserialize, JsonSchema, Serialize)]
#[serde(default, deny_unknown_fields)]
pub struct SecurityAuditConfig {
    /// Accepted findings omitted from active results.
    pub suppressions: Vec<SecurityAuditSuppression>,
}

/// Targets controlled by install policy.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Deserialize, JsonSchema, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum InstallTarget {
    /// Skill installation.
    Skill,
    /// Plugin installation.
    Plugin,
}

/// Trusted install-policy command.
#[derive(Clone, Debug, Eq, PartialEq, Deserialize, JsonSchema, Serialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct InstallPolicyExec {
    /// Closed command source discriminator.
    pub source: InstallPolicyExecSource,
    /// Absolute executable path.
    pub command: String,
    /// Command arguments.
    #[serde(default)]
    pub args: Vec<String>,
    /// Overall timeout.
    pub timeout_ms: Option<u64>,
    /// No-output timeout.
    pub no_output_timeout_ms: Option<u64>,
    /// Maximum captured output bytes.
    pub max_output_bytes: Option<u64>,
    /// Explicit child environment.
    #[serde(default)]
    pub env: BTreeMap<String, String>,
    /// Parent environment allowlist.
    #[serde(default)]
    pub pass_env: Vec<String>,
    /// Trusted executable directories.
    #[serde(default)]
    pub trusted_dirs: Vec<String>,
    /// Whether insecure executable paths are allowed.
    #[serde(default)]
    pub allow_insecure_path: bool,
    /// Whether the command itself may be a symlink.
    #[serde(default)]
    pub allow_symlink_command: bool,
}

/// Closed install-policy command source.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Deserialize, JsonSchema, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum InstallPolicyExecSource {
    /// Direct process execution without a shell.
    Exec,
}

/// Operator-owned install policy.
#[derive(Clone, Debug, Default, Eq, PartialEq, Deserialize, JsonSchema, Serialize)]
#[serde(default, deny_unknown_fields, rename_all = "camelCase")]
pub struct InstallPolicyConfig {
    /// Whether policy is active.
    pub enabled: bool,
    /// Covered targets, or all targets when empty.
    pub targets: Vec<InstallTarget>,
    /// Trusted policy command.
    pub exec: Option<InstallPolicyExec>,
}

/// Security policy and accepted audit findings.
#[derive(Clone, Debug, Default, Eq, PartialEq, Deserialize, JsonSchema, Serialize)]
#[serde(default, deny_unknown_fields, rename_all = "camelCase")]
pub struct SecurityConfig {
    /// Security-audit configuration.
    pub audit: Option<SecurityAuditConfig>,
    /// Install policy.
    pub install_policy: Option<InstallPolicyConfig>,
}

/// Remote Crestodian rescue state.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Deserialize, JsonSchema, Serialize)]
#[serde(untagged)]
pub enum RescueEnabled {
    /// Runtime posture decides whether rescue is enabled.
    Auto(RescueAuto),
    /// Explicit enablement.
    Explicit(bool),
}

impl Default for RescueEnabled {
    fn default() -> Self {
        Self::Auto(RescueAuto::Auto)
    }
}

/// Closed automatic rescue mode.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Deserialize, JsonSchema, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum RescueAuto {
    /// Enable only for unsandboxed YOLO posture.
    Auto,
}

/// Message-channel rescue policy.
#[derive(Clone, Debug, Eq, PartialEq, Deserialize, JsonSchema, Serialize)]
#[serde(default, deny_unknown_fields, rename_all = "camelCase")]
pub struct CrestodianRescueConfig {
    /// Rescue enablement gate.
    pub enabled: RescueEnabled,
    /// Whether only owner direct messages may invoke rescue.
    pub owner_dm_only: bool,
    /// Pending write approval lifetime in minutes.
    #[schemars(range(min = 1, max = 1_440))]
    pub pending_ttl_minutes: u16,
}

impl Default for CrestodianRescueConfig {
    fn default() -> Self {
        Self {
            enabled: RescueEnabled::default(),
            owner_dm_only: true,
            pending_ttl_minutes: 15,
        }
    }
}

/// Crestodian setup and rescue configuration.
#[derive(Clone, Debug, Default, Eq, PartialEq, Deserialize, JsonSchema, Serialize)]
#[serde(default, deny_unknown_fields)]
pub struct CrestodianConfig {
    /// Remote rescue policy.
    pub rescue: Option<CrestodianRescueConfig>,
}

/// Frozen update channel.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Deserialize, JsonSchema, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum UpdateChannel {
    /// Stable releases.
    Stable,
    /// Extended stable releases.
    ExtendedStable,
    /// Beta releases.
    Beta,
    /// Development releases.
    Dev,
}

/// Background update policy.
#[derive(Clone, Debug, Default, PartialEq, Deserialize, JsonSchema, Serialize)]
#[serde(default, deny_unknown_fields, rename_all = "camelCase")]
pub struct AutomaticUpdateConfig {
    /// Whether background update checks and application are enabled.
    pub enabled: bool,
    /// Stable-channel minimum delay.
    pub stable_delay_hours: Option<f64>,
    /// Stable-channel jitter window.
    pub stable_jitter_hours: Option<f64>,
    /// Beta-channel check interval.
    pub beta_check_interval_hours: Option<f64>,
}

/// Signed update settings.
#[derive(Clone, Debug, Default, PartialEq, Deserialize, JsonSchema, Serialize)]
#[serde(default, deny_unknown_fields, rename_all = "camelCase")]
pub struct UpdateConfig {
    /// Selected update channel.
    pub channel: Option<UpdateChannel>,
    /// Whether to check on gateway startup.
    pub check_on_start: Option<bool>,
    /// Background update policy.
    pub auto: Option<AutomaticUpdateConfig>,
}

/// Assistant presentation settings.
#[derive(Clone, Debug, Default, Eq, PartialEq, Deserialize, JsonSchema, Serialize)]
#[serde(default, deny_unknown_fields)]
pub struct AssistantUiConfig {
    /// Display name.
    pub name: Option<String>,
    /// Emoji, short text, image URL, or data URI.
    pub avatar: Option<String>,
}

/// Graphical user-interface settings.
#[derive(Clone, Debug, Default, Eq, PartialEq, Deserialize, JsonSchema, Serialize)]
#[serde(default, deny_unknown_fields, rename_all = "camelCase")]
pub struct UiConfig {
    /// Accent color in hexadecimal notation.
    pub seam_color: Option<String>,
    /// Assistant presentation.
    pub assistant: Option<AssistantUiConfig>,
}

/// Terminal footer settings.
#[derive(Clone, Debug, Default, Eq, PartialEq, Deserialize, JsonSchema, Serialize)]
#[serde(default, deny_unknown_fields, rename_all = "camelCase")]
pub struct TuiFooterConfig {
    /// Whether remote gateway hostnames appear in the footer.
    pub show_remote_host: bool,
}

/// Terminal user-interface settings.
#[derive(Clone, Debug, Default, Eq, PartialEq, Deserialize, JsonSchema, Serialize)]
#[serde(default, deny_unknown_fields)]
pub struct TuiConfig {
    /// Footer settings.
    pub footer: Option<TuiFooterConfig>,
}

/// Per-surface behavior.
#[derive(Clone, Debug, Default, Eq, PartialEq, Deserialize, JsonSchema, Serialize)]
#[serde(default, deny_unknown_fields, rename_all = "camelCase")]
pub struct SurfaceConfigEntry {
    /// Surface-specific silent reply policy.
    pub silent_reply: Option<SilentReplyPolicyShape>,
}

/// Inbound-media persistence settings.
#[derive(Clone, Debug, Default, Eq, PartialEq, Deserialize, JsonSchema, Serialize)]
#[serde(default, deny_unknown_fields, rename_all = "camelCase")]
pub struct MediaConfig {
    /// Whether original uploaded filenames are preserved.
    pub preserve_filenames: bool,
    /// Optional persisted-media retention window.
    pub ttl_hours: Option<u64>,
}

/// Complete pinned `OpenClaw` source configuration.
///
/// Every inventory domain has a distinct Rust type. Plugin-extensible upstream
/// domains retain their nested object entries while fixed core domains reject
/// unknown fields.
#[derive(Clone, Debug, Default, PartialEq, Deserialize, JsonSchema, Serialize)]
#[serde(default, deny_unknown_fields, rename_all = "camelCase")]
pub struct OpenClawConfig {
    /// JSON Schema URL used by editors.
    #[serde(rename = "$schema")]
    pub schema: Option<String>,
    /// Writer metadata.
    pub meta: Option<MetaConfig>,
    /// Authentication providers and profiles.
    pub auth: Option<AuthDomain>,
    /// Named access groups.
    pub access_groups: Option<AccessGroupsDomain>,
    /// ACP integration.
    pub acp: Option<AcpDomain>,
    /// Environment import and defaults.
    pub env: Option<EnvironmentConfig>,
    /// Last setup-wizard run.
    pub wizard: Option<WizardConfig>,
    /// Diagnostics and tracing.
    pub diagnostics: Option<DiagnosticsDomain>,
    /// Logging.
    pub logging: Option<LoggingDomain>,
    /// Activity audit ledger.
    pub audit: Option<AuditDomain>,
    /// Security policy.
    pub security: Option<SecurityConfig>,
    /// CLI behavior.
    pub cli: Option<CliDomain>,
    /// Crestodian behavior.
    pub crestodian: Option<CrestodianConfig>,
    /// Update behavior.
    pub update: Option<UpdateConfig>,
    /// Browser automation.
    pub browser: Option<BrowserDomain>,
    /// Graphical UI.
    pub ui: Option<UiConfig>,
    /// Terminal UI.
    pub tui: Option<TuiConfig>,
    /// Secret providers.
    pub secrets: Option<SecretsDomain>,
    /// Marketplace feeds.
    pub marketplaces: Option<MarketplacesDomain>,
    /// Skills.
    pub skills: Option<SkillsDomain>,
    /// Plugins.
    pub plugins: Option<PluginsDomain>,
    /// Per-surface policy.
    pub surfaces: Option<BTreeMap<String, SurfaceConfigEntry>>,
    /// Model providers and catalog.
    pub models: Option<ModelsDomain>,
    /// Node host.
    pub node_host: Option<NodeHostDomain>,
    /// Agents.
    pub agents: Option<AgentsDomain>,
    /// Tool policy.
    pub tools: Option<ToolsDomain>,
    /// Legacy/direct bindings.
    pub bindings: Option<Vec<AgentBinding>>,
    /// Broadcast delivery.
    pub broadcast: Option<BroadcastDomain>,
    /// Audio.
    pub audio: Option<AudioDomain>,
    /// Inbound media.
    pub media: Option<MediaConfig>,
    /// Message formatting and delivery.
    pub messages: Option<MessagesDomain>,
    /// Chat commands.
    pub commands: Option<CommandsDomain>,
    /// Human approvals.
    pub approvals: Option<ApprovalsDomain>,
    /// Sessions.
    pub session: Option<SessionDomain>,
    /// Web runtime.
    pub web: Option<WebDomain>,
    /// Channels.
    pub channels: Option<ChannelsDomain>,
    /// Cron.
    pub cron: Option<CronDomain>,
    /// Transcripts.
    pub transcripts: Option<TranscriptsDomain>,
    /// Commitments.
    pub commitments: Option<CommitmentsDomain>,
    /// Runtime hooks.
    pub hooks: Option<HooksDomain>,
    /// Network discovery.
    pub discovery: Option<DiscoveryDomain>,
    /// Talk mode.
    pub talk: Option<TalkDomain>,
    /// Gateway.
    pub gateway: Option<GatewayDomain>,
    /// Cloud workers.
    pub cloud_workers: Option<CloudWorkersDomain>,
    /// Memory.
    pub memory: Option<MemoryDomain>,
    /// MCP.
    pub mcp: Option<McpDomain>,
    /// Forward proxy.
    pub proxy: Option<ProxyDomain>,
}

/// Result of resolving source-domain configuration layers.
#[derive(Clone, Debug, PartialEq)]
pub struct ResolvedOpenClawConfig {
    /// Fully merged and validated 47-domain configuration.
    pub config: OpenClawConfig,
    /// Layers that participated, in ascending precedence order.
    pub applied_layers: Vec<ConfigLayerKind>,
}

/// Deterministic resolver for the frozen source-domain configuration.
///
/// Objects merge recursively while arrays and scalars replace lower-precedence
/// values. Legacy runtime environment variables with a direct source-domain
/// equivalent are projected as references or typed values; the complete legacy
/// runtime mapping remains available through [`crate::ConfigLayers`].
#[derive(Clone, Default)]
pub struct OpenClawConfigLayers {
    system: Option<String>,
    user: Option<String>,
    workspace: Option<String>,
    environment: BTreeMap<String, String>,
    command_line: Option<String>,
}

impl std::fmt::Debug for OpenClawConfigLayers {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("OpenClawConfigLayers")
            .field("system_configured", &self.system.is_some())
            .field("user_configured", &self.user.is_some())
            .field("workspace_configured", &self.workspace.is_some())
            .field("environment_count", &self.environment.len())
            .field("command_line_configured", &self.command_line.is_some())
            .finish()
    }
}

impl OpenClawConfigLayers {
    /// Creates a resolver containing only source-model defaults.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Sets a partial machine-wide source configuration.
    #[must_use]
    pub fn with_system_json5(mut self, source: impl Into<String>) -> Self {
        self.system = Some(source.into());
        self
    }

    /// Sets a partial per-user source configuration.
    #[must_use]
    pub fn with_user_json5(mut self, source: impl Into<String>) -> Self {
        self.user = Some(source.into());
        self
    }

    /// Sets a partial workspace source configuration.
    #[must_use]
    pub fn with_workspace_json5(mut self, source: impl Into<String>) -> Self {
        self.workspace = Some(source.into());
        self
    }

    /// Replaces the legacy environment variables considered by this resolver.
    #[must_use]
    pub fn with_environment<K, V, I>(mut self, variables: I) -> Self
    where
        K: Into<String>,
        V: Into<String>,
        I: IntoIterator<Item = (K, V)>,
    {
        self.environment = variables
            .into_iter()
            .map(|(name, value)| (name.into(), value.into()))
            .collect();
        self
    }

    /// Sets a partial command-line source override.
    #[must_use]
    pub fn with_command_line_json5(mut self, source: impl Into<String>) -> Self {
        self.command_line = Some(source.into());
        self
    }

    /// Resolves defaults, system, user, workspace, environment, then CLI.
    ///
    /// Layers are merged in place: `merge_layer` moves each parsed overlay
    /// into the accumulator instead of cloning it, so resolution is one
    /// allocation pass over the layers rather than one per layer per domain.
    ///
    /// Caching the built-in tree in a `OnceLock` was measured and rejected:
    /// `serde_json::to_value(OpenClawConfig::default())` costs 1.43-1.58us and
    /// cloning a cached `Value` of the same shape costs 0.76us, so the whole
    /// saving is under 1% of a three-layer resolution that measured 97us.
    ///
    /// # Errors
    ///
    /// Returns [`LayeredConfigError::Layer`] tagged with the offending
    /// [`ConfigLayerKind`] when one of the partial layers is not JSON5 or does
    /// not parse to an object, and [`LayeredConfigError::Result`] when the merged
    /// document cannot be re-encoded or fails whole-document validation. The
    /// second case is the common one in practice: each layer is only checked for
    /// shape on its own, so an override that pushes a value out of range, for
    /// example `gateway.port` to `0`, is only reported once every layer has been
    /// merged.
    pub fn resolve(&self) -> Result<ResolvedOpenClawConfig, LayeredConfigError> {
        let mut merged = serde_json::to_value(OpenClawConfig::default())
            .map_err(ConfigError::from_serialize)
            .map_err(LayeredConfigError::Result)?;
        let mut applied_layers = vec![ConfigLayerKind::BuiltIn];
        for (kind, source) in [
            (ConfigLayerKind::System, self.system.as_deref()),
            (ConfigLayerKind::User, self.user.as_deref()),
            (ConfigLayerKind::Workspace, self.workspace.as_deref()),
        ] {
            if let Some(source) = source {
                merge_layer(&mut merged, source, kind)?;
                applied_layers.push(kind);
            }
        }
        if !self.environment.is_empty() {
            apply_source_environment(&mut merged, &self.environment)?;
            applied_layers.push(ConfigLayerKind::Environment);
        }
        if let Some(source) = &self.command_line {
            merge_layer(&mut merged, source, ConfigLayerKind::CommandLine)?;
            applied_layers.push(ConfigLayerKind::CommandLine);
        }
        validate_source_shape(&merged, "<layered-openclaw-config>")
            .map_err(LayeredConfigError::Result)?;
        let config = decode_openclaw_value(&merged, "<layered-openclaw-config>")
            .and_then(|config| {
                config.validate()?;
                Ok(config)
            })
            .map_err(LayeredConfigError::Result)?;
        Ok(ResolvedOpenClawConfig {
            config,
            applied_layers,
        })
    }
}

fn apply_source_environment(
    merged: &mut Value,
    variables: &BTreeMap<String, String>,
) -> Result<(), LayeredConfigError> {
    for (name, path) in [
        ("PORT", &["gateway", "port"][..]),
        ("LOG_LEVEL", &["logging", "level"][..]),
        ("AUTO_UPDATE", &["update", "auto", "enabled"][..]),
        ("ENABLE_TEAMS", &["channels", "msteams", "enabled"][..]),
        ("ENABLE_TELEGRAM", &["channels", "telegram", "enabled"][..]),
        ("ENABLE_DISCORD", &["channels", "discord", "enabled"][..]),
        ("ENABLE_WHATSAPP", &["channels", "whatsapp", "enabled"][..]),
        (
            "TELEGRAM_POLL_INTERVAL_MS",
            &["channels", "telegram", "pollIntervalMs"][..],
        ),
        (
            "DISCORD_GATEWAY_INTENTS",
            &["channels", "discord", "gatewayIntents"][..],
        ),
    ] {
        let Some(value) = variables.get(name) else {
            continue;
        };
        let converted = match name {
            "PORT" | "TELEGRAM_POLL_INTERVAL_MS" | "DISCORD_GATEWAY_INTENTS" => {
                let (minimum, maximum) = match name {
                    "PORT" => (1, Some(65_535)),
                    "TELEGRAM_POLL_INTERVAL_MS" => (500, Some(60_000)),
                    "DISCORD_GATEWAY_INTENTS" => (1, None),
                    _ => unreachable!("integer environment mapping is exhaustive"),
                };
                Value::from(parse_environment_u64(name, value, minimum, maximum)?)
            }
            "AUTO_UPDATE" | "ENABLE_TEAMS" | "ENABLE_TELEGRAM" | "ENABLE_DISCORD"
            | "ENABLE_WHATSAPP" => {
                let enabled = parse_environment_bool(name, value)?;
                if name == "AUTO_UPDATE" && enabled {
                    return Err(environment_layer_error(
                        name,
                        "true is unsupported because dependency updates are review-only",
                    ));
                }
                Value::Bool(enabled)
            }
            "LOG_LEVEL" => Value::String(parse_environment_log_level(name, value)?),
            _ => Value::String(value.clone()),
        };
        set_source_path(merged, path, converted);
    }
    for (name, path) in [
        ("MicrosoftAppId", &["channels", "msteams", "appId"][..]),
        (
            "WHATSAPP_PHONE_NUMBER_ID",
            &["channels", "whatsapp", "phoneNumberId"][..],
        ),
    ] {
        if let Some(value) = variables.get(name).map(|value| value.trim())
            && !value.is_empty()
        {
            set_source_path(merged, path, Value::String(value.to_owned()));
        }
    }
    for (name, path, default) in [
        (
            "DISCORD_GATEWAY_URL",
            &["channels", "discord", "gatewayUrl"][..],
            "wss://gateway.discord.gg/?v=10&encoding=json",
        ),
        (
            "WHATSAPP_WEBHOOK_PATH",
            &["channels", "whatsapp", "webhookPath"][..],
            "/whatsapp/webhook",
        ),
    ] {
        if let Some(value) = variables.get(name) {
            let value = value.trim();
            set_source_path(
                merged,
                path,
                Value::String(if value.is_empty() { default } else { value }.to_owned()),
            );
        }
    }
    for (name, path) in [
        (
            "MicrosoftAppPassword",
            &["channels", "msteams", "appPassword"][..],
        ),
        (
            "TELEGRAM_BOT_TOKEN",
            &["channels", "telegram", "botToken"][..],
        ),
        (
            "DISCORD_BOT_TOKEN",
            &["channels", "discord", "botToken"][..],
        ),
        (
            "WHATSAPP_VERIFY_TOKEN",
            &["channels", "whatsapp", "verifyToken"][..],
        ),
        (
            "WHATSAPP_ACCESS_TOKEN",
            &["channels", "whatsapp", "accessToken"][..],
        ),
    ] {
        if let Some(value) = variables.get(name).map(|value| value.trim())
            && !value.is_empty()
        {
            let projected = if valid_canonical_env_secret_id(name) {
                environment_secret_reference(name)
            } else {
                Value::String(value.to_owned())
            };
            set_source_path(merged, path, projected);
        }
    }
    if let Some((name, value)) = [
        "HTTPS_PROXY",
        "https_proxy",
        "HTTP_PROXY",
        "http_proxy",
        "ALL_PROXY",
        "all_proxy",
    ]
    .into_iter()
    .find_map(|name| {
        variables
            .get(name)
            .filter(|value| !value.trim().is_empty())
            .map(|value| (name, value))
    }) {
        let projected = if valid_canonical_env_secret_id(name) {
            environment_secret_reference(name)
        } else {
            Value::String(value.trim().to_owned())
        };
        set_source_path(merged, &["proxy", "proxyUrl"], projected);
    }
    Ok(())
}

fn parse_environment_u64(
    name: &str,
    value: &str,
    minimum: u64,
    maximum: Option<u64>,
) -> Result<u64, LayeredConfigError> {
    parse_legacy_integer(value, minimum, maximum)
        .map_err(|message| environment_layer_error(name, &message))
}

fn parse_environment_bool(name: &str, value: &str) -> Result<bool, LayeredConfigError> {
    match value {
        "true" => Ok(true),
        "false" => Ok(false),
        _ => Err(environment_layer_error(
            name,
            "must be exactly `true` or `false`",
        )),
    }
}

fn parse_environment_log_level(name: &str, value: &str) -> Result<String, LayeredConfigError> {
    if matches!(
        value,
        "trace" | "debug" | "info" | "warn" | "error" | "fatal"
    ) {
        Ok(value.to_owned())
    } else {
        Err(environment_layer_error(
            name,
            "must be one of trace, debug, info, warn, error, fatal",
        ))
    }
}

fn environment_layer_error(name: &str, message: &str) -> LayeredConfigError {
    LayeredConfigError::Layer {
        layer: ConfigLayerKind::Environment,
        error: ConfigError::Validation {
            path: name.to_owned(),
            message: message.to_owned(),
        },
    }
}

fn environment_secret_reference(name: &str) -> Value {
    serde_json::json!({
        "source": "env",
        "provider": "default",
        "id": name,
    })
}

fn valid_canonical_env_secret_id(value: &str) -> bool {
    (1..=128).contains(&value.len())
        && value
            .bytes()
            .next()
            .is_some_and(|byte| byte.is_ascii_uppercase())
        && value
            .bytes()
            .all(|byte| byte.is_ascii_uppercase() || byte.is_ascii_digit() || byte == b'_')
}

fn set_source_path(root: &mut Value, path: &[&str], value: Value) {
    let mut overlay = value;
    for segment in path.iter().rev() {
        let mut object = serde_json::Map::new();
        object.insert((*segment).to_owned(), overlay);
        overlay = Value::Object(object);
    }
    merge_value(root, overlay);
}

impl OpenClawConfig {
    /// Validates invariants not expressible through Serde's shape checks.
    ///
    /// # Errors
    ///
    /// Returns [`ConfigError::Validation`] carrying the exact dotted path of the
    /// first violated invariant. The checked rules are: `env.shellEnv.timeoutMs`
    /// and every other timeout or TTL must be greater than zero;
    /// `env.<NAME>` keys must match `[A-Za-z_][A-Za-z0-9_]*`;
    /// `security.audit.suppressions[_].checkId` and
    /// `security.installPolicy.exec.command` must not be blank;
    /// `crestodian.rescue.pendingTtlMinutes` must be from 1 through 1440;
    /// the `update.auto` hour values must be finite and non-negative;
    /// `ui.seamColor` must be a six-digit hexadecimal color;
    /// `gateway.port` must be from 1 through 65535; and every
    /// `bindings[_]` ACP entry must carry a non-empty `match.peer.id`.
    pub fn validate(&self) -> Result<(), ConfigError> {
        if let Some(env) = &self.env {
            if let Some(shell) = &env.shell_env
                && shell.timeout_ms == Some(0)
            {
                return validation("env.shellEnv.timeoutMs", "must be greater than zero");
            }
            for name in env.vars.keys().chain(env.direct.keys()) {
                if !valid_environment_name(name) {
                    return validation(
                        &format!("env.{name}"),
                        "environment name must match [A-Za-z_][A-Za-z0-9_]*",
                    );
                }
            }
        }
        if let Some(security) = &self.security {
            if let Some(audit) = &security.audit {
                for (index, suppression) in audit.suppressions.iter().enumerate() {
                    if suppression.check_id.trim().is_empty() {
                        return validation(
                            &format!("security.audit.suppressions[{index}].checkId"),
                            "must not be empty",
                        );
                    }
                }
            }
            if let Some(policy) = &security.install_policy
                && let Some(exec) = &policy.exec
            {
                if exec.command.trim().is_empty() {
                    return validation("security.installPolicy.exec.command", "must not be empty");
                }
                if exec.timeout_ms == Some(0) {
                    return validation(
                        "security.installPolicy.exec.timeoutMs",
                        "must be greater than zero",
                    );
                }
            }
        }
        if let Some(crestodian) = &self.crestodian
            && let Some(rescue) = &crestodian.rescue
            && !(1..=1_440).contains(&rescue.pending_ttl_minutes)
        {
            return validation(
                "crestodian.rescue.pendingTtlMinutes",
                "must be from 1 through 1440",
            );
        }
        if let Some(update) = &self.update
            && let Some(auto) = &update.auto
        {
            for (path, value) in [
                ("update.auto.stableDelayHours", auto.stable_delay_hours),
                ("update.auto.stableJitterHours", auto.stable_jitter_hours),
                (
                    "update.auto.betaCheckIntervalHours",
                    auto.beta_check_interval_hours,
                ),
            ] {
                if value.is_some_and(|value| !value.is_finite() || value < 0.0) {
                    return validation(path, "must be a finite non-negative number");
                }
            }
        }
        if let Some(ui) = &self.ui
            && let Some(color) = &ui.seam_color
            && !valid_hex_color(color)
        {
            return validation("ui.seamColor", "must be a six-digit hexadecimal color");
        }
        if self
            .media
            .as_ref()
            .is_some_and(|media| media.ttl_hours == Some(0))
        {
            return validation("media.ttlHours", "must be greater than zero");
        }
        if self
            .gateway
            .as_ref()
            .is_some_and(|gateway| gateway.port == Some(0))
        {
            return validation("gateway.port", "must be from 1 through 65535");
        }
        if let Some(acp) = &self.acp {
            if acp.max_concurrent_sessions == Some(0) {
                return validation("acp.maxConcurrentSessions", "must be greater than zero");
            }
            if acp
                .runtime
                .as_ref()
                .is_some_and(|runtime| runtime.ttl_minutes == Some(0))
            {
                return validation("acp.runtime.ttlMinutes", "must be greater than zero");
            }
        }
        if let Some(bindings) = &self.bindings {
            for (index, binding) in bindings.iter().enumerate() {
                if let AgentBinding::Acp(binding) = binding
                    && binding
                        .binding_match
                        .peer
                        .as_ref()
                        .is_none_or(|peer| peer.id.trim().is_empty())
                {
                    return validation(
                        &format!("bindings[{index}].match.peer"),
                        "ACP bindings require a non-empty match.peer.id",
                    );
                }
            }
        }
        Ok(())
    }
}

/// Parses and validates the pinned 47-domain source configuration.
///
/// # Errors
///
/// Returns [`ConfigError::Syntax`] when `source` is not well-formed JSON5 and
/// [`ConfigError::Decode`] naming the exact dotted path when a value has the
/// wrong JSON type, when a fixed core domain carries an unknown key, when a
/// top-level key is outside the frozen 47-domain set, when a direct `env` entry
/// is not a string, or when `bindings[_].agentId` is not a string. Returns
/// [`ConfigError::Validation`] for every cross-field invariant listed on
/// [`OpenClawConfig::validate`]. `source_name` is echoed in each diagnostic so
/// the caller can name the rejected file.
pub fn parse_openclaw_json5(
    source: &str,
    source_name: &str,
) -> Result<OpenClawConfig, ConfigError> {
    // One JSON5 scan on the success path. The `serde_json::Value` tree and the
    // `serde_path_to_error` wrapper both exist only to describe a rejection, so
    // a document that decodes cleanly no longer pays for either; a document that
    // does not is re-read by `openclaw_rejection`, which reproduces the original
    // diagnostic exactly. Measured over the 47-domain fixture corpus
    // (9.8 KiB, best-of-7 x 2000, interleaved release binaries): building the
    // `Value` cost 72-79us and tracking paths cost a further 14-16us on top of
    // the 59-61us decode, so startup fell 155.8us -> 59.1us.
    let config = json5::from_str::<OpenClawConfig>(source)
        .map_err(|_| openclaw_rejection(source, source_name))?;
    config.validate()?;
    Ok(config)
}

/// Re-reads a document that already failed, in the original diagnostic order:
/// JSON5 syntax, then the `env`/`bindings` shape pre-check, then the exact
/// dotted field path.
#[cold]
fn openclaw_rejection(source: &str, source_name: &str) -> ConfigError {
    let raw = match json5::from_str::<Value>(source) {
        Ok(raw) => raw,
        Err(error) => {
            return ConfigError::Syntax {
                source_name: source_name.to_owned(),
                message: error.to_string(),
            };
        }
    };
    if let Err(error) = validate_source_shape(&raw, source_name) {
        return error;
    }
    let mut deserializer = json5::Deserializer::from_str(source);
    match serde_path_to_error::deserialize::<_, OpenClawConfig>(&mut deserializer) {
        Err(error) => ConfigError::Decode {
            source_name: source_name.to_owned(),
            path: nonempty_path(error.path().to_string()),
            message: error.inner().to_string(),
        },
        // Unreachable: the only failure `json5::from_str` reports that a bare
        // `Deserializer` does not is trailing content, and that already returned
        // above as a syntax error. Classified as syntax rather than panicking so
        // a future json5 divergence degrades into a diagnostic, not a crash.
        Ok(_) => ConfigError::Syntax {
            source_name: source_name.to_owned(),
            message: "document is not well-formed JSON5".to_owned(),
        },
    }
}

fn decode_openclaw_value(raw: &Value, source_name: &str) -> Result<OpenClawConfig, ConfigError> {
    // Decoding straight from the merged tree skips a whole
    // `Value -> UTF-8 -> Value` round trip. The round trip is only worth its
    // cost when it has a diagnostic to produce, because `serde_json::Error`
    // carries a line and column that a borrowed `Value` cannot, so it is kept
    // for the rejection path. Measured on the layered resolver: 122.6-142.2us
    // for the round trip against 22.7us borrowed.
    OpenClawConfig::deserialize(raw).or_else(|_| decode_openclaw_value_located(raw, source_name))
}

#[cold]
fn decode_openclaw_value_located(
    raw: &Value,
    source_name: &str,
) -> Result<OpenClawConfig, ConfigError> {
    let bytes = serde_json::to_vec(raw).map_err(ConfigError::from_serialize)?;
    let mut deserializer = serde_json::Deserializer::from_slice(&bytes);
    serde_path_to_error::deserialize(&mut deserializer).map_err(|error| ConfigError::Decode {
        source_name: source_name.to_owned(),
        path: nonempty_path(error.path().to_string()),
        message: error.inner().to_string(),
    })
}

fn validate_source_shape(raw: &Value, source_name: &str) -> Result<(), ConfigError> {
    if let Some(environment) = raw.get("env").and_then(Value::as_object) {
        for (name, value) in environment {
            if !matches!(name.as_str(), "shellEnv" | "vars") && !value.is_string() {
                return decode_shape(
                    source_name,
                    &format!("env.{name}"),
                    "direct environment values must be strings",
                );
            }
        }
    }
    if let Some(bindings) = raw.get("bindings").and_then(Value::as_array) {
        for (index, binding) in bindings.iter().enumerate() {
            if let Some(agent_id) = binding.get("agentId")
                && !agent_id.is_string()
            {
                return decode_shape(
                    source_name,
                    &format!("bindings[{index}].agentId"),
                    "agentId must be a string",
                );
            }
        }
    }
    Ok(())
}

fn decode_shape<T>(source_name: &str, path: &str, message: &str) -> Result<T, ConfigError> {
    Err(ConfigError::Decode {
        source_name: source_name.to_owned(),
        path: path.to_owned(),
        message: message.to_owned(),
    })
}

/// Serializes the pinned 47-domain source configuration to deterministic JSON5.
///
/// Encoding through a pre-reserved buffer was measured and rejected:
/// `json5::to_writer` into a `Vec::with_capacity(16_384)` plus
/// `String::from_utf8` ran 41.6-41.8us against 41.1-43.7us for
/// `json5::to_string` followed by `String::push`, which is inside the noise of
/// a loaded machine and costs a magic constant plus a second UTF-8 validation.
///
/// # Errors
///
/// Returns [`ConfigError::Validation`] when `config` was assembled in memory and
/// violates one of the invariants listed on [`OpenClawConfig::validate`]; the
/// value is re-checked here so an invalid document can never be written out.
/// Returns [`ConfigError::Serialize`] when the JSON5 encoder rejects the
/// validated value.
pub fn openclaw_to_json5(config: &OpenClawConfig) -> Result<String, ConfigError> {
    config.validate()?;
    let mut output =
        json5::to_string(config).map_err(|error| ConfigError::Serialize(error.to_string()))?;
    output.push('\n');
    Ok(output)
}

/// Returns JSON Schema for the complete pinned 47-domain source configuration.
///
/// This is not startup work: `schemars` builds the whole 47-domain schema on
/// every call, which measured 1.79-1.85ms, but no binary in the workspace calls
/// it while starting. It is a tool entry point, so the cost is left where it is
/// visible rather than moved into a build script that would have to be kept in
/// step with the model.
///
/// # Errors
///
/// Returns [`ConfigError::Serialize`] when the generated schema cannot be
/// rendered as pretty JSON. The schema itself is derived at compile time, so
/// this only fires if the JSON writer fails.
pub fn openclaw_schema_json() -> Result<String, ConfigError> {
    let schema = schemars::schema_for!(OpenClawConfig);
    serde_json::to_string_pretty(&schema).map_err(|error| ConfigError::Serialize(error.to_string()))
}

fn nonempty_path(path: String) -> String {
    if path.is_empty() {
        "<root>".to_owned()
    } else {
        path
    }
}

fn valid_environment_name(value: &str) -> bool {
    let mut chars = value.chars();
    matches!(chars.next(), Some('_' | 'A'..='Z' | 'a'..='z'))
        && chars.all(|character| matches!(character, '_' | 'A'..='Z' | 'a'..='z' | '0'..='9'))
}

fn valid_hex_color(value: &str) -> bool {
    value.len() == 7
        && value.starts_with('#')
        && value[1..].bytes().all(|byte| byte.is_ascii_hexdigit())
}

fn validation<T>(path: &str, message: &str) -> Result<T, ConfigError> {
    Err(ConfigError::Validation {
        path: path.to_owned(),
        message: message.to_owned(),
    })
}

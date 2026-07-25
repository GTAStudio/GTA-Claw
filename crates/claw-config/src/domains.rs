use std::collections::BTreeMap;

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::ConfigError;

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
    ($(#[$meta:meta])* $name:ident) => {
        $(#[$meta])*
        #[derive(Clone, Debug, Default, PartialEq, Deserialize, JsonSchema, Serialize)]
        #[serde(transparent)]
        pub struct $name(pub BTreeMap<String, Value>);
    };
}

macro_rules! typed_domain {
    ($(#[$meta:meta])* $name:ident { $($field:ident => $wire:literal),* $(,)? }) => {
        $(#[$meta])*
        #[allow(missing_docs)]
        #[derive(Clone, Debug, Default, PartialEq, Deserialize, JsonSchema, Serialize)]
        #[serde(default, deny_unknown_fields)]
        pub struct $name {
            $(
                #[serde(rename = $wire)]
                pub $field: Option<Value>,
            )*
        }
    };
}

typed_domain!(
    /// Authentication provider and profile configuration.
    AuthDomain {
        profiles => "profiles",
        order => "order",
        cooldowns => "cooldowns",
    }
);
object_domain!(
    /// Named access-group configuration.
    AccessGroupsDomain
);
typed_domain!(
    /// Agent Client Protocol integration configuration.
    AcpDomain {
        enabled => "enabled",
        dispatch => "dispatch",
        backend => "backend",
        fallbacks => "fallbacks",
        default_agent => "defaultAgent",
        allowed_agents => "allowedAgents",
        max_concurrent_sessions => "maxConcurrentSessions",
        stream => "stream",
        runtime => "runtime",
    }
);
typed_domain!(
    /// Diagnostics and tracing configuration.
    DiagnosticsDomain {
        enabled => "enabled",
        flags => "flags",
        stuck_session_warn_ms => "stuckSessionWarnMs",
        stuck_session_abort_ms => "stuckSessionAbortMs",
        memory_pressure_snapshot => "memoryPressureSnapshot",
        otel => "otel",
        cache_trace => "cacheTrace",
    }
);
typed_domain!(
    /// Log sink, level, rotation, and redaction configuration.
    LoggingDomain {
        level => "level",
        file => "file",
        max_file_bytes => "maxFileBytes",
        console_level => "consoleLevel",
        console_style => "consoleStyle",
        redact_sensitive => "redactSensitive",
        redact_patterns => "redactPatterns",
    }
);
typed_domain!(
    /// Metadata-only activity audit configuration.
    AuditDomain {
        enabled => "enabled",
        messages => "messages",
    }
);
typed_domain!(
    /// CLI defaults and command-specific configuration.
    CliDomain {
        banner => "banner",
    }
);
typed_domain!(
    /// Browser automation configuration.
    BrowserDomain {
        enabled => "enabled",
        allow_system_profile_import => "allowSystemProfileImport",
        evaluate_enabled => "evaluateEnabled",
        cdp_url => "cdpUrl",
        remote_cdp_timeout_ms => "remoteCdpTimeoutMs",
        remote_cdp_handshake_timeout_ms => "remoteCdpHandshakeTimeoutMs",
        local_launch_timeout_ms => "localLaunchTimeoutMs",
        local_cdp_ready_timeout_ms => "localCdpReadyTimeoutMs",
        action_timeout_ms => "actionTimeoutMs",
        color => "color",
        executable_path => "executablePath",
        headless => "headless",
        no_sandbox => "noSandbox",
        attach_only => "attachOnly",
        cdp_port_range_start => "cdpPortRangeStart",
        default_profile => "defaultProfile",
        profiles => "profiles",
        snapshot_defaults => "snapshotDefaults",
        tab_cleanup => "tabCleanup",
        ssrf_policy => "ssrfPolicy",
        extra_args => "extraArgs",
    }
);
typed_domain!(
    /// Secret provider and resolution configuration.
    SecretsDomain {
        providers => "providers",
        defaults => "defaults",
        resolution => "resolution",
    }
);
typed_domain!(
    /// Marketplace feed and package-source configuration.
    MarketplacesDomain {
        feeds => "feeds",
        sources => "sources",
    }
);
typed_domain!(
    /// Skill loading configuration.
    SkillsDomain {
        allow_bundled => "allowBundled",
        load => "load",
        install => "install",
        limits => "limits",
        workshop => "workshop",
        entries => "entries",
    }
);
typed_domain!(
    /// Plugin registry and runtime configuration.
    PluginsDomain {
        enabled => "enabled",
        allow => "allow",
        deny => "deny",
        load => "load",
        slots => "slots",
        entries => "entries",
        bundled_discovery => "bundledDiscovery",
        installs => "installs",
    }
);
typed_domain!(
    /// Model provider and catalog configuration.
    ModelsDomain {
        mode => "mode",
        providers => "providers",
        pricing => "pricing",
    }
);
typed_domain!(
    /// Node-host pairing and remote command configuration.
    NodeHostDomain {
        browser_proxy => "browserProxy",
        mcp => "mcp",
        skills => "skills",
    }
);
typed_domain!(
    /// Agent defaults, entries, and runtime policy.
    AgentsDomain {
        defaults => "defaults",
        list => "list",
    }
);
typed_domain!(
    /// Tool exposure and execution policy.
    ToolsDomain {
        profile => "profile",
        allow => "allow",
        also_allow => "alsoAllow",
        deny => "deny",
        by_provider => "byProvider",
        tools_by_sender => "toolsBySender",
        web => "web",
        media => "media",
        links => "links",
        message => "message",
        agent_to_agent => "agentToAgent",
        sessions => "sessions",
        elevated => "elevated",
        exec => "exec",
        fs => "fs",
        loop_detection => "loopDetection",
        tool_search => "toolSearch",
        code_mode => "codeMode",
        sessions_spawn => "sessions_spawn",
        subagents => "subagents",
        sandbox => "sandbox",
        experimental => "experimental",
    }
);
typed_domain!(
    /// One legacy/direct agent binding.
    AgentBinding {
        binding_type => "type",
        agent_id => "agentId",
        comment => "comment",
        binding_match => "match",
        session => "session",
        acp => "acp",
    }
);
typed_domain!(
    /// Broadcast command and delivery configuration.
    BroadcastDomain {
        strategy => "strategy",
    }
);
typed_domain!(
    /// Audio command and media handling configuration.
    AudioDomain {
        transcription => "transcription",
    }
);
typed_domain!(
    /// Message formatting and delivery configuration.
    MessagesDomain {
        message_prefix => "messagePrefix",
        visible_replies => "visibleReplies",
        response_prefix => "responsePrefix",
        usage_template => "usageTemplate",
        response_usage => "responseUsage",
        group_chat => "groupChat",
        queue => "queue",
        inbound => "inbound",
        ack_reaction => "ackReaction",
        ack_reaction_scope => "ackReactionScope",
        remove_ack_after_reply => "removeAckAfterReply",
        status_reactions => "statusReactions",
        suppress_tool_errors => "suppressToolErrors",
        tts => "tts",
    }
);
typed_domain!(
    /// Chat command configuration.
    CommandsDomain {
        native => "native",
        native_skills => "nativeSkills",
        text => "text",
        bash => "bash",
        bash_foreground_ms => "bashForegroundMs",
        config => "config",
        mcp => "mcp",
        plugins => "plugins",
        debug => "debug",
        restart => "restart",
        use_access_groups => "useAccessGroups",
        owner_allow_from => "ownerAllowFrom",
        owner_display => "ownerDisplay",
        owner_display_secret => "ownerDisplaySecret",
        allow_from => "allowFrom",
    }
);
typed_domain!(
    /// Human approval workflow configuration.
    ApprovalsDomain {
        exec => "exec",
        plugin => "plugin",
    }
);
typed_domain!(
    /// Session keying, reset, and maintenance configuration.
    SessionDomain {
        scope => "scope",
        dm_scope => "dmScope",
        identity_links => "identityLinks",
        reset_triggers => "resetTriggers",
        idle_minutes => "idleMinutes",
        reset => "reset",
        reset_by_type => "resetByType",
        reset_by_channel => "resetByChannel",
        store => "store",
        typing_interval_seconds => "typingIntervalSeconds",
        typing_mode => "typingMode",
        main_key => "mainKey",
        send_policy => "sendPolicy",
        write_lock => "writeLock",
        agent_to_agent => "agentToAgent",
        thread_bindings => "threadBindings",
        maintenance => "maintenance",
    }
);
typed_domain!(
    /// Web runtime configuration.
    WebDomain {
        enabled => "enabled",
        heartbeat_seconds => "heartbeatSeconds",
        reconnect => "reconnect",
        whatsapp => "whatsapp",
    }
);
object_domain!(
    /// Built-in and plugin-owned channel configuration.
    ChannelsDomain
);
typed_domain!(
    /// Cron scheduling and retention configuration.
    CronDomain {
        enabled => "enabled",
        store => "store",
        max_concurrent_runs => "maxConcurrentRuns",
        triggers => "triggers",
        retry => "retry",
        webhook => "webhook",
        webhook_token => "webhookToken",
        session_retention => "sessionRetention",
        run_log => "runLog",
        failure_alert => "failureAlert",
        failure_destination => "failureDestination",
    }
);
typed_domain!(
    /// Transcript persistence and export configuration.
    TranscriptsDomain {
        enabled => "enabled",
        max_utterances => "maxUtterances",
        auto_start => "autoStart",
    }
);
typed_domain!(
    /// Commitment and reminder extraction configuration.
    CommitmentsDomain {
        enabled => "enabled",
        max_per_day => "maxPerDay",
    }
);
typed_domain!(
    /// Runtime hook and queue configuration.
    HooksDomain {
        enabled => "enabled",
        path => "path",
        token => "token",
        default_session_key => "defaultSessionKey",
        allow_request_session_key => "allowRequestSessionKey",
        allowed_session_key_prefixes => "allowedSessionKeyPrefixes",
        allowed_agent_ids => "allowedAgentIds",
        max_body_bytes => "maxBodyBytes",
        presets => "presets",
        transforms_dir => "transformsDir",
        mappings => "mappings",
        gmail => "gmail",
        internal => "internal",
    }
);
typed_domain!(
    /// Network discovery and advertisement configuration.
    DiscoveryDomain {
        wide_area => "wideArea",
        mdns => "mdns",
    }
);
typed_domain!(
    /// Voice and talk-mode configuration.
    TalkDomain {
        provider => "provider",
        providers => "providers",
        realtime => "realtime",
        consult_thinking_level => "consultThinkingLevel",
        consult_fast_mode => "consultFastMode",
        speech_locale => "speechLocale",
        interrupt_on_speech => "interruptOnSpeech",
        silence_timeout_ms => "silenceTimeoutMs",
    }
);
typed_domain!(
    /// Gateway server, authentication, UI, and dispatch configuration.
    GatewayDomain {
        port => "port",
        mode => "mode",
        bind => "bind",
        custom_bind_host => "customBindHost",
        control_ui => "controlUi",
        terminal => "terminal",
        auth => "auth",
        tailscale => "tailscale",
        remote => "remote",
        reload => "reload",
        tls => "tls",
        http => "http",
        push => "push",
        nodes => "nodes",
        trusted_proxies => "trustedProxies",
        allow_real_ip_fallback => "allowRealIpFallback",
        tools => "tools",
        handshake_timeout_ms => "handshakeTimeoutMs",
        channel_health_check_minutes => "channelHealthCheckMinutes",
        channel_stale_event_threshold_minutes => "channelStaleEventThresholdMinutes",
        channel_max_restarts_per_hour => "channelMaxRestartsPerHour",
    }
);
typed_domain!(
    /// Cloud-worker provider configuration.
    CloudWorkersDomain {
        profiles => "profiles",
    }
);
typed_domain!(
    /// Memory indexing and search configuration.
    MemoryDomain {
        backend => "backend",
        citations => "citations",
        qmd => "qmd",
    }
);
typed_domain!(
    /// Model Context Protocol client and server configuration.
    McpDomain {
        servers => "servers",
        apps => "apps",
        session_idle_ttl_ms => "sessionIdleTtlMs",
    }
);
object_domain!(
    /// Operator-managed forward-proxy configuration.
    ProxyDomain
);

/// Metadata written with an authored OpenClaw configuration.
#[derive(Clone, Debug, Default, Eq, PartialEq, Deserialize, JsonSchema, Serialize)]
#[serde(default, deny_unknown_fields, rename_all = "camelCase")]
pub struct MetaConfig {
    /// Last OpenClaw version that wrote the file.
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
#[derive(Clone, Debug, Default, PartialEq, Deserialize, JsonSchema, Serialize)]
#[serde(default, rename_all = "camelCase")]
pub struct EnvironmentConfig {
    /// Optional login-shell import.
    pub shell_env: Option<ShellEnvironmentConfig>,
    /// Explicit environment variable values.
    pub vars: BTreeMap<String, String>,
    /// Upstream sugar allowing variables directly below `env`.
    #[serde(flatten)]
    pub direct: BTreeMap<String, Value>,
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
    /// OpenClaw version used for the run.
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
#[derive(Clone, Debug, Default, PartialEq, Deserialize, JsonSchema, Serialize)]
#[serde(default, deny_unknown_fields, rename_all = "camelCase")]
pub struct SurfaceConfigEntry {
    /// Surface-specific silent reply policy.
    pub silent_reply: Option<Value>,
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

/// Complete pinned OpenClaw source configuration.
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

impl OpenClawConfig {
    /// Validates invariants not expressible through Serde's shape checks.
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
        Ok(())
    }
}

/// Parses and validates the pinned 47-domain source configuration.
pub fn parse_openclaw_json5(
    source: &str,
    source_name: &str,
) -> Result<OpenClawConfig, ConfigError> {
    json5::from_str::<serde::de::IgnoredAny>(source).map_err(|error| ConfigError::Syntax {
        source_name: source_name.to_owned(),
        message: error.to_string(),
    })?;
    let mut deserializer = json5::Deserializer::from_str(source);
    let config = serde_path_to_error::deserialize::<_, OpenClawConfig>(&mut deserializer).map_err(
        |error| ConfigError::Decode {
            source_name: source_name.to_owned(),
            path: nonempty_path(error.path().to_string()),
            message: error.inner().to_string(),
        },
    )?;
    config.validate()?;
    Ok(config)
}

/// Serializes the pinned 47-domain source configuration to deterministic JSON5.
pub fn openclaw_to_json5(config: &OpenClawConfig) -> Result<String, ConfigError> {
    config.validate()?;
    let mut output =
        json5::to_string(config).map_err(|error| ConfigError::Serialize(error.to_string()))?;
    output.push('\n');
    Ok(output)
}

/// Returns JSON Schema for the complete pinned 47-domain source configuration.
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

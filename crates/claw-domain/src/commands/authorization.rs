//! Command-level authorization.
//!
//! Ports `src/auto-reply/command-auth.ts` and the command gates documented in
//! `docs/tools/slash-commands.md` from the frozen upstream baseline.
//!
//! Upstream resolves the channel plugin through a plugin registry and lets
//! plugins override allowlist formatting (`formatAllowFrom`), allowlist
//! resolution (`resolveAllowFrom`) and sender-candidate ordering
//! (`preferSenderE164ForCommands`). Plugin loading is not part of this crate, so
//! the resolved provider id, the channel allowlist and the
//! `enforceOwnerForCommands` switch are inputs instead. Because the fallback
//! resolver never throws, the `hadResolutionError` branch cannot occur and is
//! not modelled.

use std::collections::BTreeMap;
use std::error::Error;
use std::fmt::{self, Display, Formatter};

use super::registry::{
    CommandDefinition, CommandFeature, CommandRegistry, CommandSource, should_handle_text_commands,
};
use super::text::{js_trim, normalize_lowercase_or_empty, normalize_optional};

/// The frozen channel ids from `compat/upstream/inventories/channels.json`.
///
/// `resolveOwnerAllowFromList` treats a `prefix:remainder` owner entry as
/// channel-scoped only when `prefix` normalizes to a known channel id, so the
/// pinned set decides whether `slack:U1` is scoped or literal.
pub const KNOWN_CHANNEL_IDS: [&str; 29] = [
    "clickclack",
    "discord",
    "feishu",
    "googlechat",
    "imessage",
    "irc",
    "line",
    "matrix",
    "mattermost",
    "msteams",
    "nextcloud-talk",
    "nostr",
    "openclaw-weixin",
    "openclaw-zaloclawbot",
    "qa-channel",
    "qqbot",
    "raft",
    "signal",
    "slack",
    "sms",
    "synology-chat",
    "telegram",
    "tlon",
    "twitch",
    "wecom",
    "whatsapp",
    "yuanbao",
    "zalo",
    "zalouser",
];

/// Ports `normalizeAnyChannelId`.
#[must_use]
pub fn normalize_any_channel_id(raw: &str) -> Option<&'static str> {
    let key = normalize_lowercase_or_empty(raw);
    KNOWN_CHANNEL_IDS
        .into_iter()
        .find(|channel| *channel == key)
}

/// The `commands` configuration block.
///
/// `Default` reproduces the documented defaults: `text` and `restart` are on,
/// `useAccessGroups` is on, and every other feature flag is off.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CommandsConfig {
    text: bool,
    bash: bool,
    config: bool,
    mcp: bool,
    plugins: bool,
    debug: bool,
    restart: bool,
    use_access_groups: bool,
    allow_from: Option<BTreeMap<String, Vec<String>>>,
    owner_allow_from: Vec<String>,
}

impl Default for CommandsConfig {
    fn default() -> Self {
        Self {
            text: true,
            bash: false,
            config: false,
            mcp: false,
            plugins: false,
            debug: false,
            restart: true,
            use_access_groups: true,
            allow_from: None,
            owner_allow_from: Vec::new(),
        }
    }
}

impl CommandsConfig {
    /// Returns whether `/...` text commands are handled.
    #[must_use]
    pub const fn text(&self) -> bool {
        self.text
    }

    /// Returns whether access groups gate command visibility.
    #[must_use]
    pub const fn use_access_groups(&self) -> bool {
        self.use_access_groups
    }

    /// Returns whether a feature flag is enabled.
    #[must_use]
    pub const fn feature_enabled(&self, feature: CommandFeature) -> bool {
        match feature {
            CommandFeature::Bash => self.bash,
            CommandFeature::Config => self.config,
            CommandFeature::Mcp => self.mcp,
            CommandFeature::Plugins => self.plugins,
            CommandFeature::Debug => self.debug,
            CommandFeature::Restart => self.restart,
        }
    }

    /// Returns the configured `commands.ownerAllowFrom` list.
    #[must_use]
    pub fn owner_allow_from(&self) -> &[String] {
        &self.owner_allow_from
    }

    /// Returns whether `commands.allowFrom` is configured at all.
    #[must_use]
    pub const fn allow_from_configured(&self) -> bool {
        self.allow_from.is_some()
    }

    /// Sets `commands.text`.
    #[must_use]
    pub const fn with_text(mut self, enabled: bool) -> Self {
        self.text = enabled;
        self
    }

    /// Sets `commands.useAccessGroups`.
    #[must_use]
    pub const fn with_use_access_groups(mut self, enabled: bool) -> Self {
        self.use_access_groups = enabled;
        self
    }

    /// Sets one feature flag.
    #[must_use]
    pub const fn with_feature(mut self, feature: CommandFeature, enabled: bool) -> Self {
        match feature {
            CommandFeature::Bash => self.bash = enabled,
            CommandFeature::Config => self.config = enabled,
            CommandFeature::Mcp => self.mcp = enabled,
            CommandFeature::Plugins => self.plugins = enabled,
            CommandFeature::Debug => self.debug = enabled,
            CommandFeature::Restart => self.restart = enabled,
        }
        self
    }

    /// Sets `commands.ownerAllowFrom`.
    #[must_use]
    pub fn with_owner_allow_from<I, S>(mut self, entries: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        self.owner_allow_from = entries.into_iter().map(Into::into).collect();
        self
    }

    /// Adds one `commands.allowFrom` list, keyed by provider id or `*`.
    #[must_use]
    pub fn with_allow_from<I, S>(mut self, provider: &str, entries: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        self.allow_from.get_or_insert_with(BTreeMap::new).insert(
            provider.to_owned(),
            entries.into_iter().map(Into::into).collect(),
        );
        self
    }

    /// Marks `commands.allowFrom` as present but empty.
    #[must_use]
    pub fn with_empty_allow_from(mut self) -> Self {
        self.allow_from.get_or_insert_with(BTreeMap::new);
        self
    }

    /// Ports `resolveCommandsAllowFromList`.
    ///
    /// A provider-specific key wins over `"*"`; `None` means "not configured, fall
    /// back to the channel allowlist".
    #[must_use]
    pub fn resolve_commands_allow_from(&self, provider_id: Option<&str>) -> Option<Vec<String>> {
        let allow_from = self.allow_from.as_ref()?;
        let provider_key = provider_id.unwrap_or("");
        let list = allow_from
            .get(provider_key)
            .or_else(|| allow_from.get("*"))?;
        Some(format_allow_from_list(list))
    }
}

/// The per-channel inputs upstream reads from the resolved channel plugin.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct ChannelSettings {
    allow_from: Vec<String>,
    enforce_owner_for_commands: bool,
    native_command_surface: bool,
}

impl ChannelSettings {
    /// Sets the channel-level `allowFrom` list.
    #[must_use]
    pub fn with_allow_from<I, S>(mut self, entries: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        self.allow_from = entries.into_iter().map(Into::into).collect();
        self
    }

    /// Sets `plugin.commands.enforceOwnerForCommands`.
    #[must_use]
    pub const fn with_enforce_owner_for_commands(mut self, enforce: bool) -> Self {
        self.enforce_owner_for_commands = enforce;
        self
    }

    /// Sets whether the surface exposes native slash commands.
    #[must_use]
    pub const fn with_native_command_surface(mut self, native: bool) -> Self {
        self.native_command_surface = native;
        self
    }

    /// Returns the channel-level `allowFrom` list.
    #[must_use]
    pub fn allow_from(&self) -> &[String] {
        &self.allow_from
    }

    /// Returns whether owner enforcement is forced for this channel.
    #[must_use]
    pub const fn enforce_owner_for_commands(&self) -> bool {
        self.enforce_owner_for_commands
    }

    /// Returns whether the surface exposes native slash commands.
    #[must_use]
    pub const fn native_command_surface(&self) -> bool {
        self.native_command_surface
    }
}

/// The message context fields `resolveCommandAuthorization` reads.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct MessageContext {
    provider: Option<String>,
    from: String,
    to: String,
    sender_id: Option<String>,
    sender_e164: Option<String>,
    chat_type: Option<String>,
    gateway_client_scopes: Vec<String>,
    owner_allow_from: Vec<String>,
    internal_channel: bool,
    native_command_turn: bool,
    command_authorized: bool,
    source: CommandSource,
}

impl MessageContext {
    /// Starts from a context whose sender is allowed by the channel allowlist.
    #[must_use]
    pub fn authorized() -> Self {
        Self {
            command_authorized: true,
            ..Self::default()
        }
    }

    /// Sets `ctx.Provider`.
    #[must_use]
    pub fn with_provider(mut self, provider: &str) -> Self {
        self.provider = normalize_optional(provider).map(str::to_owned);
        self
    }

    /// Sets `ctx.From`.
    #[must_use]
    pub fn with_from(mut self, from: &str) -> Self {
        self.from = js_trim(from).to_owned();
        self
    }

    /// Sets `ctx.To`.
    #[must_use]
    pub fn with_to(mut self, to: &str) -> Self {
        self.to = js_trim(to).to_owned();
        self
    }

    /// Sets `ctx.SenderId`.
    #[must_use]
    pub fn with_sender_id(mut self, sender_id: &str) -> Self {
        self.sender_id = normalize_optional(sender_id).map(str::to_owned);
        self
    }

    /// Sets `ctx.SenderE164`.
    #[must_use]
    pub fn with_sender_e164(mut self, sender_e164: &str) -> Self {
        self.sender_e164 = normalize_optional(sender_e164).map(str::to_owned);
        self
    }

    /// Sets `ctx.ChatType`.
    #[must_use]
    pub fn with_chat_type(mut self, chat_type: &str) -> Self {
        self.chat_type = normalize_optional(chat_type).map(str::to_owned);
        self
    }

    /// Sets `ctx.GatewayClientScopes`.
    #[must_use]
    pub fn with_gateway_client_scopes<I, S>(mut self, scopes: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        self.gateway_client_scopes = scopes.into_iter().map(Into::into).collect();
        self
    }

    /// Sets `ctx.OwnerAllowFrom`.
    #[must_use]
    pub fn with_owner_allow_from<I, S>(mut self, entries: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        self.owner_allow_from = entries.into_iter().map(Into::into).collect();
        self
    }

    /// Sets whether the provider is an internal message channel.
    #[must_use]
    pub const fn with_internal_channel(mut self, internal: bool) -> Self {
        self.internal_channel = internal;
        self
    }

    /// Sets whether this turn is a native command turn.
    #[must_use]
    pub const fn with_native_command_turn(mut self, native: bool) -> Self {
        self.native_command_turn = native;
        self
    }

    /// Sets `commandAuthorized`, the channel-level allowlist verdict.
    #[must_use]
    pub const fn with_command_authorized(mut self, authorized: bool) -> Self {
        self.command_authorized = authorized;
        self
    }

    /// Sets where the invocation arrived from.
    #[must_use]
    pub const fn with_source(mut self, source: CommandSource) -> Self {
        self.source = source;
        self
    }

    /// Returns where the invocation arrived from.
    #[must_use]
    pub const fn source(&self) -> CommandSource {
        self.source
    }

    /// Ports `resolveSenderCandidates`.
    #[must_use]
    pub fn sender_candidates(&self) -> Vec<String> {
        let mut candidates = Vec::new();
        if let Some(sender_id) = self.sender_id.as_ref() {
            candidates.push(sender_id.clone());
        }
        if let Some(sender_e164) = self.sender_e164.as_ref() {
            candidates.push(sender_e164.clone());
        }
        if candidates.is_empty() && self.should_use_from_as_sender_fallback() {
            candidates.push(self.from.clone());
        }
        let mut normalized: Vec<String> = Vec::new();
        for candidate in candidates {
            if !normalized.contains(&candidate) {
                normalized.push(candidate);
            }
        }
        normalized
    }

    /// Ports `shouldUseFromAsSenderFallback`.
    fn should_use_from_as_sender_fallback(&self) -> bool {
        if self.from.is_empty() {
            return false;
        }
        let chat_type = self
            .chat_type
            .as_deref()
            .map_or_else(String::new, normalize_lowercase_or_empty);
        if !chat_type.is_empty() && chat_type != "direct" {
            return false;
        }
        !is_conversation_like_identity(&self.from)
    }
}

/// Ports `isConversationLikeIdentity`.
fn is_conversation_like_identity(value: &str) -> bool {
    let normalized = normalize_lowercase_or_empty(value);
    if normalized.is_empty() {
        return false;
    }
    if normalized.starts_with("chat_id:") {
        return true;
    }
    // `/(^|:)(channel|group|thread|topic|room|space|spaces):/`
    const KINDS: [&str; 7] = [
        "channel", "group", "thread", "topic", "room", "space", "spaces",
    ];
    KINDS.into_iter().any(|kind| {
        let needle = format!("{kind}:");
        if normalized.starts_with(&needle) {
            return true;
        }
        normalized.contains(&format!(":{needle}"))
    })
}

fn format_allow_from_list(list: &[String]) -> Vec<String> {
    list.iter()
        .filter_map(|entry| normalize_optional(entry).map(str::to_owned))
        .collect()
}

fn is_wildcard_allow_from_entry(entry: &str) -> bool {
    js_trim(entry) == "*"
}

fn has_wildcard_allow_from(list: &[String]) -> bool {
    list.iter().any(|entry| is_wildcard_allow_from_entry(entry))
}

fn strip_wildcard_allow_from(list: &[String]) -> Vec<String> {
    list.iter()
        .filter(|entry| !is_wildcard_allow_from_entry(entry))
        .cloned()
        .collect()
}

/// Ports `resolveOwnerAllowFromList`.
fn resolve_owner_allow_from_list(raw: &[String], provider_id: Option<&str>) -> Vec<String> {
    let mut filtered: Vec<String> = Vec::new();
    for entry in raw {
        let Some(trimmed) = normalize_optional(entry) else {
            continue;
        };
        if let Some(separator) = trimmed.find(':').filter(|index| *index > 0)
            && let Some(channel) = normalize_any_channel_id(&trimmed[..separator])
        {
            // Channel-prefixed entries require a matching provider.
            if provider_id != Some(channel) {
                continue;
            }
            let remainder = js_trim(&trimmed[separator + 1..]);
            if !remainder.is_empty() {
                filtered.push(remainder.to_owned());
            }
            continue;
        }
        filtered.push(trimmed.to_owned());
    }
    format_allow_from_list(&filtered)
}

/// The result of `resolveCommandAuthorization`.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SenderAuthorization {
    provider_id: Option<String>,
    owner_list: Vec<String>,
    sender_id: Option<String>,
    sender_is_owner: bool,
    is_owner_for_commands: bool,
    is_authorized_sender: bool,
}

impl SenderAuthorization {
    /// Returns the resolved provider id.
    #[must_use]
    pub fn provider_id(&self) -> Option<&str> {
        self.provider_id.as_deref()
    }

    /// Returns the deduplicated owner list.
    #[must_use]
    pub fn owner_list(&self) -> &[String] {
        &self.owner_list
    }

    /// Returns the sender identity commands are attributed to.
    #[must_use]
    pub fn sender_id(&self) -> Option<&str> {
        self.sender_id.as_deref()
    }

    /// Returns whether the sender is an owner.
    #[must_use]
    pub const fn sender_is_owner(&self) -> bool {
        self.sender_is_owner
    }

    /// Returns whether the sender satisfies owner-gated commands.
    #[must_use]
    pub const fn is_owner_for_commands(&self) -> bool {
        self.is_owner_for_commands
    }

    /// Returns whether the sender may run commands at all.
    #[must_use]
    pub const fn is_authorized_sender(&self) -> bool {
        self.is_authorized_sender
    }
}

/// Ports `resolveCommandAuthorization`.
#[must_use]
pub fn resolve_command_authorization(
    config: &CommandsConfig,
    channel: &ChannelSettings,
    context: &MessageContext,
) -> SenderAuthorization {
    let provider_id = context
        .provider
        .as_deref()
        .and_then(normalize_any_channel_id);

    let commands_allow_from_list = config.resolve_commands_allow_from(provider_id);
    let allow_from_list = format_allow_from_list(channel.allow_from());

    let config_owner_list = resolve_owner_allow_from_list(config.owner_allow_from(), provider_id);
    let context_owner_list = resolve_owner_allow_from_list(&context.owner_allow_from, provider_id);

    let allow_all = allow_from_list.is_empty() || has_wildcard_allow_from(&allow_from_list);
    let owner_candidates_for_commands = if allow_all {
        Vec::new()
    } else {
        let stripped = strip_wildcard_allow_from(&allow_from_list);
        if !stripped.is_empty() {
            stripped
        } else if let Some(to) = normalize_optional(&context.to) {
            vec![to.to_owned()]
        } else {
            Vec::new()
        }
    };

    let owner_allow_all = has_wildcard_allow_from(&config_owner_list);
    let explicit_owners = strip_wildcard_allow_from(&config_owner_list);
    let explicit_overrides = strip_wildcard_allow_from(&context_owner_list);
    let owner_list_source = if !explicit_owners.is_empty() {
        explicit_owners.clone()
    } else if owner_allow_all {
        Vec::new()
    } else if !explicit_overrides.is_empty() {
        explicit_overrides
    } else {
        owner_candidates_for_commands.clone()
    };
    let mut owner_list: Vec<String> = Vec::new();
    for entry in owner_list_source {
        if !owner_list.contains(&entry) {
            owner_list.push(entry);
        }
    }

    let sender_candidates = context.sender_candidates();
    let matched_sender = sender_candidates
        .iter()
        .find(|candidate| owner_list.contains(candidate))
        .cloned();
    let matched_command_owner = sender_candidates
        .iter()
        .any(|candidate| owner_candidates_for_commands.contains(candidate));

    let enforce_owner = channel.enforce_owner_for_commands();
    let sender_is_owner_by_scope = context.internal_channel
        && context
            .gateway_client_scopes
            .iter()
            .any(|scope| scope == "operator.admin");
    let owner_allowlist_configured = owner_allow_all || !explicit_owners.is_empty();
    let sender_is_owner = matched_sender.is_some() || sender_is_owner_by_scope || owner_allow_all;
    let require_owner = enforce_owner || owner_allowlist_configured;
    // Upstream spells the first two arms separately; they collapse to one here.
    let is_owner_for_commands = if !require_owner || owner_allow_all {
        true
    } else if owner_allowlist_configured {
        sender_is_owner
    } else {
        sender_is_owner_by_scope || matched_command_owner
    };
    let native_command_authorized =
        context.command_authorized && context.native_command_turn && !require_owner;

    let is_authorized_sender = if enforce_owner && !is_owner_for_commands {
        false
    } else if let Some(list) = commands_allow_from_list.as_ref() {
        // `commands.allowFrom` is the sole source once configured.
        has_wildcard_allow_from(list)
            || sender_candidates
                .iter()
                .any(|candidate| list.contains(candidate))
    } else {
        context.command_authorized && (is_owner_for_commands || native_command_authorized)
    };

    let sender_id = matched_sender.or_else(|| sender_candidates.first().cloned());

    SenderAuthorization {
        provider_id: provider_id.map(str::to_owned),
        owner_list,
        sender_id,
        sender_is_owner,
        is_owner_for_commands,
        is_authorized_sender,
    }
}

/// A command invocation that passed every authorization check.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CommandInvocation {
    key: String,
    alias: String,
    args: Option<String>,
}

impl CommandInvocation {
    /// Returns the registry key of the invoked command.
    #[must_use]
    pub fn key(&self) -> &str {
        &self.key
    }

    /// Returns the alias the sender used.
    #[must_use]
    pub fn alias(&self) -> &str {
        &self.alias
    }

    /// Returns the trailing argument string.
    #[must_use]
    pub fn args(&self) -> Option<&str> {
        self.args.as_deref()
    }
}

/// Why a command invocation was rejected.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum CommandDenial {
    /// `commands.text` is off on a surface that has native commands.
    TextCommandsDisabled,
    /// The body did not resolve to a registered command.
    UnknownCommand {
        /// The body as normalized before lookup.
        body: String,
    },
    /// The sender is not allowed to run commands.
    SenderNotAuthorized,
    /// A `commands.<flag>` feature gate is off.
    FeatureDisabled {
        /// The gate that rejected the invocation.
        feature: CommandFeature,
    },
    /// The command is owner-only and the sender is not an owner.
    OwnerRequired {
        /// The registry key of the command.
        key: String,
    },
}

impl CommandDenial {
    /// Returns a stable machine-readable reason code.
    #[must_use]
    pub const fn code(&self) -> &'static str {
        match self {
            Self::TextCommandsDisabled => "text_commands_disabled",
            Self::UnknownCommand { .. } => "unknown_command",
            Self::SenderNotAuthorized => "sender_not_authorized",
            Self::FeatureDisabled { .. } => "feature_disabled",
            Self::OwnerRequired { .. } => "owner_required",
        }
    }
}

impl Display for CommandDenial {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        match self {
            Self::TextCommandsDisabled => {
                formatter.write_str("Text commands are disabled on this surface")
            }
            Self::UnknownCommand { body } => write!(formatter, "Unknown command: {body}"),
            Self::SenderNotAuthorized => {
                formatter.write_str("Sender is not authorized to run commands")
            }
            Self::FeatureDisabled { feature } => {
                write!(formatter, "Command requires {}", feature.config_path())
            }
            Self::OwnerRequired { key } => {
                write!(formatter, "Command requires an owner: /{key}")
            }
        }
    }
}

impl Error for CommandDenial {}

/// Resolves and authorizes one command body.
///
/// The checks run in the documented order: surface routing, registry lookup,
/// sender authorization, feature gates, then owner gates. Every rejection
/// carries the reason so callers (and the golden tables) can pin it.
///
/// # Errors
///
/// Returns the first [`CommandDenial`] that applies.
pub fn authorize_command(
    registry: &CommandRegistry,
    config: &CommandsConfig,
    channel: &ChannelSettings,
    context: &MessageContext,
    body: &str,
) -> Result<CommandInvocation, CommandDenial> {
    if !should_handle_text_commands(
        config.text(),
        context.source(),
        channel.native_command_surface(),
    ) {
        return Err(CommandDenial::TextCommandsDisabled);
    }

    let resolved =
        registry
            .resolve_text_command(body, None)
            .ok_or_else(|| CommandDenial::UnknownCommand {
                body: js_trim(body).to_owned(),
            })?;
    let command: &CommandDefinition = resolved.command();

    let authorization = resolve_command_authorization(config, channel, context);
    if !authorization.is_authorized_sender() {
        return Err(CommandDenial::SenderNotAuthorized);
    }

    let args = resolved.args();
    if let Some(feature) = command.gate().required_feature(args)
        && !config.feature_enabled(feature)
    {
        return Err(CommandDenial::FeatureDisabled { feature });
    }
    if command.gate().requires_owner(args) && !authorization.is_owner_for_commands() {
        return Err(CommandDenial::OwnerRequired {
            key: command.key().to_owned(),
        });
    }

    Ok(CommandInvocation {
        key: command.key().to_owned(),
        alias: resolved.alias().to_owned(),
        args: args.map(str::to_owned),
    })
}

#[cfg(test)]
mod tests {
    use super::{
        ChannelSettings, CommandDenial, CommandsConfig, MessageContext, authorize_command,
        normalize_any_channel_id, resolve_command_authorization,
    };
    use crate::commands::registry::{CommandFeature, CommandRegistry};

    #[test]
    fn an_unconfigured_deployment_authorizes_every_sender() {
        let authorization = resolve_command_authorization(
            &CommandsConfig::default(),
            &ChannelSettings::default(),
            &MessageContext::authorized().with_sender_id("U1"),
        );

        assert!(authorization.is_authorized_sender());
        assert!(authorization.is_owner_for_commands());
    }

    #[test]
    fn commands_allow_from_is_the_sole_source_once_configured() {
        let config = CommandsConfig::default().with_allow_from("slack", ["U-ALLOWED"]);
        let channel = ChannelSettings::default();

        let allowed = resolve_command_authorization(
            &config,
            &channel,
            &MessageContext::authorized()
                .with_provider("slack")
                .with_sender_id("U-ALLOWED"),
        );
        // `commandAuthorized` is false, but the commands list still decides.
        let denied = resolve_command_authorization(
            &config,
            &channel,
            &MessageContext::authorized()
                .with_provider("slack")
                .with_command_authorized(false)
                .with_sender_id("U-OTHER"),
        );

        assert!(allowed.is_authorized_sender());
        assert!(!denied.is_authorized_sender());
    }

    #[test]
    fn a_channel_scoped_owner_entry_is_ignored_on_other_channels() {
        let config = CommandsConfig::default().with_owner_allow_from(["slack:U-OWNER"]);

        let on_slack = resolve_command_authorization(
            &config,
            &ChannelSettings::default(),
            &MessageContext::authorized()
                .with_provider("slack")
                .with_sender_id("U-OWNER"),
        );
        let on_discord = resolve_command_authorization(
            &config,
            &ChannelSettings::default(),
            &MessageContext::authorized()
                .with_provider("discord")
                .with_sender_id("U-OWNER"),
        );

        assert_eq!(on_slack.owner_list(), ["U-OWNER"]);
        assert!(on_slack.sender_is_owner());
        assert!(on_discord.owner_list().is_empty());
        assert!(!on_discord.sender_is_owner());
    }

    #[test]
    fn a_feature_gate_denies_before_the_owner_gate() {
        let registry = CommandRegistry::builtin();
        let error = authorize_command(
            &registry,
            &CommandsConfig::default(),
            &ChannelSettings::default(),
            &MessageContext::authorized().with_sender_id("U1"),
            "/mcp list",
        )
        .expect_err("mcp is gated");

        assert_eq!(
            error,
            CommandDenial::FeatureDisabled {
                feature: CommandFeature::Mcp
            }
        );
        assert_eq!(error.to_string(), "Command requires commands.mcp");
    }

    #[test]
    fn owner_only_commands_are_denied_with_a_reason() {
        let registry = CommandRegistry::builtin();
        let config = CommandsConfig::default().with_owner_allow_from(["U-OWNER"]);
        let error = authorize_command(
            &registry,
            &config,
            &ChannelSettings::default(),
            &MessageContext::authorized().with_sender_id("U-INTRUDER"),
            "/send hello",
        )
        .expect_err("send is owner-only");

        assert_eq!(error.code(), "sender_not_authorized");
        assert_eq!(error, CommandDenial::SenderNotAuthorized);
    }

    #[test]
    fn only_frozen_channel_ids_normalize() {
        assert_eq!(normalize_any_channel_id(" Slack "), Some("slack"));
        assert_eq!(
            normalize_any_channel_id("nextcloud-talk"),
            Some("nextcloud-talk")
        );
        assert_eq!(normalize_any_channel_id("myspace"), None);
    }
}

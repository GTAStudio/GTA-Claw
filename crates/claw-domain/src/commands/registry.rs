//! The pinned chat command registry and its text-command resolution rules.
//!
//! Ports `src/auto-reply/commands-registry.shared.ts`,
//! `src/auto-reply/commands-registry-normalize.ts` and
//! `src/auto-reply/commands-text-routing.ts` from the frozen upstream baseline,
//! together with the command availability rules stated in
//! `docs/tools/slash-commands.md`.
//!
//! The registry is the only place aliases are declared. Upstream's
//! `assertCommandRegistry` rejects a registry whose aliases collide, and so does
//! [`CommandRegistry::new`], with the same rejection text.

use std::collections::BTreeMap;
use std::error::Error;
use std::fmt::{self, Display, Formatter};

use super::text::{
    collapse_js_whitespace, is_js_space, js_trim, js_trim_start, leading_space_len,
    normalize_lowercase_or_empty, normalize_optional, normalize_optional_lowercase,
};

/// Where a command may be invoked.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CommandScope {
    /// Text `/...` messages only.
    Text,
    /// Provider-native slash commands only.
    Native,
    /// Both text and native surfaces.
    Both,
}

impl CommandScope {
    /// Returns the upstream spelling of the scope.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Text => "text",
            Self::Native => "native",
            Self::Both => "both",
        }
    }
}

impl Display for CommandScope {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

/// A `commands.*` configuration flag that gates a command.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CommandFeature {
    /// `commands.bash`, default off.
    Bash,
    /// `commands.config`, default off.
    Config,
    /// `commands.mcp`, default off.
    Mcp,
    /// `commands.plugins`, default off.
    Plugins,
    /// `commands.debug`, default off.
    Debug,
    /// `commands.restart`, default on.
    Restart,
}

impl CommandFeature {
    /// Every gate flag.
    pub const ALL: [Self; 6] = [
        Self::Bash,
        Self::Config,
        Self::Mcp,
        Self::Plugins,
        Self::Debug,
        Self::Restart,
    ];

    /// Returns the short configuration key, without the `commands.` prefix.
    #[must_use]
    pub const fn key(self) -> &'static str {
        match self {
            Self::Bash => "bash",
            Self::Config => "config",
            Self::Mcp => "mcp",
            Self::Plugins => "plugins",
            Self::Debug => "debug",
            Self::Restart => "restart",
        }
    }

    /// Parses a short configuration key.
    #[must_use]
    pub fn from_key(key: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|feature| feature.key() == key)
    }

    /// Returns the dotted configuration path that enables the feature.
    #[must_use]
    pub const fn config_path(self) -> &'static str {
        match self {
            Self::Bash => "commands.bash",
            Self::Config => "commands.config",
            Self::Mcp => "commands.mcp",
            Self::Plugins => "commands.plugins",
            Self::Debug => "commands.debug",
            Self::Restart => "commands.restart",
        }
    }
}

impl Display for CommandFeature {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.config_path())
    }
}

/// The command-level gate applied on top of sender authorization.
///
/// Both halves may be scoped to a subcommand, because upstream gates some
/// commands entirely (`/config` needs `commands.config`) and others only for
/// specific first arguments (`/allowlist add` needs `commands.config`, plain
/// `/allowlist` does not; `/plugins install` needs owner identity, `/plugins
/// list` does not).
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct CommandGate {
    feature: Option<CommandFeature>,
    feature_subcommands: Vec<String>,
    owner_required: bool,
    owner_subcommands: Vec<String>,
}

impl CommandGate {
    /// A command reachable by any authorized sender.
    #[must_use]
    pub const fn none() -> Self {
        Self {
            feature: None,
            feature_subcommands: Vec::new(),
            owner_required: false,
            owner_subcommands: Vec::new(),
        }
    }

    /// A command gated on a configuration flag for every invocation.
    #[must_use]
    pub const fn feature(feature: CommandFeature) -> Self {
        Self {
            feature: Some(feature),
            feature_subcommands: Vec::new(),
            owner_required: false,
            owner_subcommands: Vec::new(),
        }
    }

    /// A command gated on owner identity for every invocation.
    #[must_use]
    pub const fn owner() -> Self {
        Self {
            feature: None,
            feature_subcommands: Vec::new(),
            owner_required: true,
            owner_subcommands: Vec::new(),
        }
    }

    /// A command gated on both a configuration flag and owner identity.
    #[must_use]
    pub const fn feature_and_owner(feature: CommandFeature) -> Self {
        Self {
            feature: Some(feature),
            feature_subcommands: Vec::new(),
            owner_required: true,
            owner_subcommands: Vec::new(),
        }
    }

    /// A command gated on a configuration flag only for the named subcommands.
    #[must_use]
    pub fn feature_for(feature: CommandFeature, subcommands: &[&str]) -> Self {
        Self {
            feature: Some(feature),
            feature_subcommands: subcommands
                .iter()
                .map(|entry| (*entry).to_owned())
                .collect(),
            owner_required: false,
            owner_subcommands: Vec::new(),
        }
    }

    /// A command gated on a flag always, and on owner identity for the named writes.
    #[must_use]
    pub fn feature_with_owner_for(feature: CommandFeature, owner_subcommands: &[&str]) -> Self {
        Self {
            feature: Some(feature),
            feature_subcommands: Vec::new(),
            owner_required: true,
            owner_subcommands: owner_subcommands
                .iter()
                .map(|entry| (*entry).to_owned())
                .collect(),
        }
    }

    /// Returns the configuration flag this invocation needs, if any.
    #[must_use]
    pub fn required_feature(&self, args: Option<&str>) -> Option<CommandFeature> {
        let feature = self.feature?;
        if self.feature_subcommands.is_empty() {
            return Some(feature);
        }
        subcommand_matches(&self.feature_subcommands, args).then_some(feature)
    }

    /// Returns whether this invocation needs owner identity.
    #[must_use]
    pub fn requires_owner(&self, args: Option<&str>) -> bool {
        if !self.owner_required {
            return false;
        }
        if self.owner_subcommands.is_empty() {
            return true;
        }
        subcommand_matches(&self.owner_subcommands, args)
    }

    /// Returns the flag this command can require, ignoring subcommand scoping.
    #[must_use]
    pub const fn declared_feature(&self) -> Option<CommandFeature> {
        self.feature
    }

    /// Returns whether owner identity is ever required.
    #[must_use]
    pub const fn declares_owner(&self) -> bool {
        self.owner_required
    }

    /// Returns the subcommands the flag is scoped to, empty when unscoped.
    #[must_use]
    pub fn feature_subcommands(&self) -> &[String] {
        &self.feature_subcommands
    }

    /// Returns the subcommands owner identity is scoped to, empty when unscoped.
    #[must_use]
    pub fn owner_subcommands(&self) -> &[String] {
        &self.owner_subcommands
    }
}

fn subcommand_matches(subcommands: &[String], args: Option<&str>) -> bool {
    let Some(args) = args else {
        return false;
    };
    let Some(first) = args.split(is_js_space).find(|token| !token.is_empty()) else {
        return false;
    };
    let lowered = first.to_lowercase();
    subcommands.iter().any(|entry| entry == &lowered)
}

/// One command in the registry.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CommandDefinition {
    key: String,
    native_name: Option<String>,
    native_aliases: Vec<String>,
    text_aliases: Vec<String>,
    accepts_args: bool,
    scope: CommandScope,
    gate: CommandGate,
}

impl CommandDefinition {
    /// Defines a command, deriving the scope exactly as `defineChatCommand` does.
    ///
    /// A command with a native name and at least one text alias is `both`; with a
    /// native name and no text alias it is `native`; without a native name it is
    /// `text`.
    #[must_use]
    pub fn define(key: &str, native_name: Option<&str>, text_aliases: &[&str]) -> Self {
        let aliases: Vec<String> = text_aliases
            .iter()
            .map(|alias| js_trim(alias).to_owned())
            .filter(|alias| !alias.is_empty())
            .collect();
        let scope = match native_name {
            Some(_) if aliases.is_empty() => CommandScope::Native,
            Some(_) => CommandScope::Both,
            None => CommandScope::Text,
        };
        Self {
            key: key.to_owned(),
            native_name: native_name.map(ToOwned::to_owned),
            native_aliases: Vec::new(),
            text_aliases: aliases,
            accepts_args: false,
            scope,
            gate: CommandGate::none(),
        }
    }

    /// Marks the command as accepting a trailing argument string.
    #[must_use]
    pub fn accepting_args(mut self) -> Self {
        self.accepts_args = true;
        self
    }

    /// Overrides the derived scope.
    #[must_use]
    pub fn with_scope(mut self, scope: CommandScope) -> Self {
        self.scope = scope;
        self
    }

    /// Adds native-surface aliases.
    #[must_use]
    pub fn with_native_aliases(mut self, aliases: &[&str]) -> Self {
        self.native_aliases = aliases.iter().map(|alias| (*alias).to_owned()).collect();
        self
    }

    /// Sets the authorization gate.
    #[must_use]
    pub fn with_gate(mut self, gate: CommandGate) -> Self {
        self.gate = gate;
        self
    }

    /// Returns the stable command key.
    #[must_use]
    pub fn key(&self) -> &str {
        &self.key
    }

    /// Returns the provider-native command name, if the command has one.
    #[must_use]
    pub fn native_name(&self) -> Option<&str> {
        self.native_name.as_deref()
    }

    /// Returns the provider-native aliases.
    #[must_use]
    pub fn native_aliases(&self) -> &[String] {
        &self.native_aliases
    }

    /// Returns every text alias, canonical alias first.
    #[must_use]
    pub fn text_aliases(&self) -> &[String] {
        &self.text_aliases
    }

    /// Returns the canonical text alias, falling back to `/<key>`.
    #[must_use]
    pub fn canonical(&self) -> String {
        self.text_aliases
            .first()
            .and_then(|alias| normalize_optional(alias))
            .map_or_else(|| format!("/{}", self.key), ToOwned::to_owned)
    }

    /// Returns whether a trailing argument string is accepted.
    #[must_use]
    pub const fn accepts_args(&self) -> bool {
        self.accepts_args
    }

    /// Returns the invocation scope.
    #[must_use]
    pub const fn scope(&self) -> CommandScope {
        self.scope
    }

    /// Returns the authorization gate.
    #[must_use]
    pub const fn gate(&self) -> &CommandGate {
        &self.gate
    }
}

/// A registry that violates a structural invariant.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum RegistryError {
    /// Two commands share a key.
    DuplicateKey(String),
    /// Two commands share a text alias.
    DuplicateAlias(String),
    /// Two commands share a native name or native alias.
    DuplicateNativeCommand(String),
    /// A text alias does not start with `/`.
    AliasMissingLeadingSlash(String),
    /// A text-only command declares a native name.
    TextOnlyHasNativeName(String),
    /// A text-only command declares native aliases.
    TextOnlyHasNativeAliases(String),
    /// A text-only command declares no text alias.
    TextOnlyMissingTextAlias(String),
    /// A native-capable command declares no native name.
    NativeMissingNativeName(String),
    /// A native-only command declares text aliases.
    NativeOnlyHasTextAliases(String),
}

impl Display for RegistryError {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        match self {
            Self::DuplicateKey(key) => write!(formatter, "Duplicate command key: {key}"),
            Self::DuplicateAlias(alias) => write!(formatter, "Duplicate command alias: {alias}"),
            Self::DuplicateNativeCommand(alias) => {
                write!(formatter, "Duplicate native command: {alias}")
            }
            Self::AliasMissingLeadingSlash(alias) => {
                write!(formatter, "Command alias missing leading '/': {alias}")
            }
            Self::TextOnlyHasNativeName(key) => {
                write!(formatter, "Text-only command has native name: {key}")
            }
            Self::TextOnlyHasNativeAliases(key) => {
                write!(formatter, "Text-only command has native aliases: {key}")
            }
            Self::TextOnlyMissingTextAlias(key) => {
                write!(formatter, "Text-only command missing text alias: {key}")
            }
            Self::NativeMissingNativeName(key) => {
                write!(formatter, "Native command missing native name: {key}")
            }
            Self::NativeOnlyHasTextAliases(key) => {
                write!(formatter, "Native-only command has text aliases: {key}")
            }
        }
    }
}

impl Error for RegistryError {}

/// A text command resolved against the registry.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ResolvedCommand<'registry> {
    command: &'registry CommandDefinition,
    alias: String,
    args: Option<String>,
}

impl<'registry> ResolvedCommand<'registry> {
    /// Returns the matched command.
    #[must_use]
    pub const fn command(&self) -> &'registry CommandDefinition {
        self.command
    }

    /// Returns the alias the sender actually used, lowercased.
    #[must_use]
    pub fn alias(&self) -> &str {
        &self.alias
    }

    /// Returns the trailing argument string, if the command accepts one.
    #[must_use]
    pub fn args(&self) -> Option<&str> {
        self.args.as_deref()
    }
}

/// Where a command invocation arrived from.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub enum CommandSource {
    /// A `/...` chat message.
    #[default]
    Text,
    /// A provider-native slash command.
    Native,
}

/// Ports `shouldHandleTextCommands`.
///
/// Upstream derives `native_command_surface` from the loaded channel plugins;
/// here it is an input, because plugin loading is not part of this crate.
#[must_use]
pub fn should_handle_text_commands(
    commands_text_enabled: bool,
    source: CommandSource,
    native_command_surface: bool,
) -> bool {
    if source == CommandSource::Native {
        return true;
    }
    if commands_text_enabled {
        return true;
    }
    !native_command_surface
}

/// A validated set of commands with an alias index.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CommandRegistry {
    commands: Vec<CommandDefinition>,
    alias_index: BTreeMap<String, usize>,
}

impl CommandRegistry {
    /// Validates and indexes a command list.
    ///
    /// # Errors
    ///
    /// Returns the first [`RegistryError`] found, in upstream's check order:
    /// duplicate keys, then surface invariants and native-name collisions, then
    /// text alias shape and text alias collisions.
    pub fn new(commands: Vec<CommandDefinition>) -> Result<Self, RegistryError> {
        let mut keys: Vec<&str> = Vec::new();
        let mut native_names: Vec<String> = Vec::new();
        let mut alias_index: BTreeMap<String, usize> = BTreeMap::new();

        for (index, command) in commands.iter().enumerate() {
            if keys.contains(&command.key.as_str()) {
                return Err(RegistryError::DuplicateKey(command.key.clone()));
            }
            keys.push(command.key.as_str());

            let native_name = command.native_name.as_deref().map_or("", js_trim);
            if command.scope == CommandScope::Text {
                if !native_name.is_empty() {
                    return Err(RegistryError::TextOnlyHasNativeName(command.key.clone()));
                }
                if !command.native_aliases.is_empty() {
                    return Err(RegistryError::TextOnlyHasNativeAliases(command.key.clone()));
                }
                if command.text_aliases.is_empty() {
                    return Err(RegistryError::TextOnlyMissingTextAlias(command.key.clone()));
                }
            } else if native_name.is_empty() {
                return Err(RegistryError::NativeMissingNativeName(command.key.clone()));
            } else {
                for alias in std::iter::once(native_name.to_owned())
                    .chain(command.native_aliases.iter().cloned())
                {
                    let native_key = normalize_lowercase_or_empty(&alias);
                    if native_names.contains(&native_key) {
                        return Err(RegistryError::DuplicateNativeCommand(alias));
                    }
                    native_names.push(native_key);
                }
            }

            if command.scope == CommandScope::Native && !command.text_aliases.is_empty() {
                return Err(RegistryError::NativeOnlyHasTextAliases(command.key.clone()));
            }

            for alias in &command.text_aliases {
                if !alias.starts_with('/') {
                    return Err(RegistryError::AliasMissingLeadingSlash(alias.clone()));
                }
                let alias_key = normalize_lowercase_or_empty(alias);
                if alias_index.contains_key(&alias_key) {
                    return Err(RegistryError::DuplicateAlias(alias.clone()));
                }
                alias_index.insert(alias_key, index);
            }
        }

        Ok(Self {
            commands,
            alias_index,
        })
    }

    /// Returns the pinned built-in registry.
    ///
    /// # Panics
    ///
    /// Never in practice: `builtin_commands_are_a_valid_registry` proves the
    /// pinned table satisfies every invariant, and the table is a constant.
    #[must_use]
    pub fn builtin() -> Self {
        Self::new(builtin_commands()).expect("the pinned builtin command table is valid")
    }

    /// Returns every command in declaration order.
    #[must_use]
    pub fn commands(&self) -> &[CommandDefinition] {
        &self.commands
    }

    /// Returns the command with the given key.
    #[must_use]
    pub fn command(&self, key: &str) -> Option<&CommandDefinition> {
        self.commands.iter().find(|command| command.key == key)
    }

    /// Returns the command owning a text alias, matched case-insensitively.
    #[must_use]
    pub fn resolve_alias(&self, alias: &str) -> Option<&CommandDefinition> {
        let key = normalize_optional_lowercase(alias)?;
        self.alias_index
            .get(&key)
            .and_then(|index| self.commands.get(*index))
    }

    /// Returns every `(alias, command key)` pair, ordered by alias.
    #[must_use]
    pub fn aliases(&self) -> Vec<(&str, &str)> {
        self.alias_index
            .iter()
            .filter_map(|(alias, index)| {
                self.commands
                    .get(*index)
                    .map(|command| (alias.as_str(), command.key.as_str()))
            })
            .collect()
    }

    /// Ports `normalizeCommandBody`.
    ///
    /// Rewrites `/cmd: value` to `/cmd value`, strips a trailing `@botname`
    /// mention, and canonicalizes a known alias to its primary spelling.
    #[must_use]
    pub fn normalize_command_body(&self, raw: &str, bot_username: Option<&str>) -> String {
        let trimmed = js_trim(raw);
        if !trimmed.starts_with('/') {
            return trimmed.to_owned();
        }

        let (single_line, multiline_tail) = match trimmed.find('\n') {
            None => (trimmed, None),
            Some(index) => (
                js_trim(&trimmed[..index]),
                Some(js_trim_start(&trimmed[index + 1..])),
            ),
        };

        let normalized = apply_colon_syntax(single_line);
        let command_body = apply_bot_mention(&normalized, bot_username);

        let lowered = normalize_lowercase_or_empty(&command_body);
        if let Some(command) = self
            .alias_index
            .get(&lowered)
            .and_then(|index| self.commands.get(*index))
        {
            return append_multiline_tail(&command.canonical(), multiline_tail, Some(command));
        }

        let Some((token, rest)) = split_command_token(&command_body) else {
            return append_multiline_tail(&command_body, multiline_tail, None);
        };
        let token_key = format!("/{}", normalize_lowercase_or_empty(token));
        let Some(command) = self
            .alias_index
            .get(&token_key)
            .and_then(|index| self.commands.get(*index))
        else {
            return append_multiline_tail(&command_body, multiline_tail, None);
        };
        if rest.is_some() && !command.accepts_args {
            return command_body;
        }
        let normalized_rest = rest.map_or("", js_trim_start);
        let head = if normalized_rest.is_empty() {
            command.canonical()
        } else {
            format!("{} {normalized_rest}", command.canonical())
        };
        append_multiline_tail(&head, multiline_tail, Some(command))
    }

    /// Ports `resolveTextCommand`: resolves raw chat text to a command and args.
    #[must_use]
    pub fn resolve_text_command(
        &self,
        raw: &str,
        bot_username: Option<&str>,
    ) -> Option<ResolvedCommand<'_>> {
        let normalized = self.normalize_command_body(raw, bot_username);
        let trimmed = js_trim(&normalized).to_owned();
        let alias = self.maybe_resolve_text_alias(&trimmed, bot_username)?;
        let command = self
            .alias_index
            .get(&alias)
            .and_then(|index| self.commands.get(*index))?;
        if !command.accepts_args {
            return Some(ResolvedCommand {
                command,
                alias,
                args: None,
            });
        }
        let args = js_trim(trimmed.get(alias.len()..).unwrap_or("")).to_owned();
        Some(ResolvedCommand {
            command,
            alias,
            args: (!args.is_empty()).then_some(args),
        })
    }

    /// Ports `maybeResolveTextAlias`: returns the canonical lowercase alias.
    #[must_use]
    pub fn maybe_resolve_text_alias(
        &self,
        raw: &str,
        bot_username: Option<&str>,
    ) -> Option<String> {
        let normalized_body = self.normalize_command_body(raw, bot_username);
        let trimmed = js_trim(&normalized_body);
        if !trimmed.starts_with('/') {
            return None;
        }
        let normalized = normalize_lowercase_or_empty(trimmed);
        if self.alias_index.contains_key(&normalized) {
            return Some(normalized);
        }
        if !self.detection_matches(&normalized) {
            return None;
        }
        let after = normalized.strip_prefix('/')?;
        let token_end = after
            .find(|character: char| is_js_space(character) || character == ':')
            .unwrap_or(after.len());
        if token_end == 0 {
            return None;
        }
        if token_end != after.len() && !after[token_end..].starts_with(is_js_space) {
            return None;
        }
        let token_key = format!("/{}", &after[..token_end]);
        self.alias_index
            .contains_key(&token_key)
            .then_some(token_key)
    }

    /// Ports `getCommandDetection`'s regex as a direct predicate.
    fn detection_matches(&self, normalized: &str) -> bool {
        self.commands.iter().any(|command| {
            command.text_aliases.iter().any(|alias| {
                let Some(alias_key) = normalize_optional_lowercase(alias) else {
                    return false;
                };
                let Some(remainder) = normalized.strip_prefix(alias_key.as_str()) else {
                    return false;
                };
                if remainder.is_empty() {
                    return true;
                }
                if command.accepts_args {
                    // `\s+[\s\S]+`
                    let spaces = leading_space_len(remainder);
                    if spaces > 0 && remainder.chars().count() >= 2 {
                        return true;
                    }
                    // `\s*:\s*[\s\S]*`
                    return js_trim_start(remainder).starts_with(':');
                }
                // `(?:\s*:\s*)?`
                let Some(after_colon) = js_trim_start(remainder).strip_prefix(':') else {
                    return false;
                };
                js_trim_start(after_colon).is_empty()
            })
        })
    }
}

/// Ports the `^\/([^\s:]+)\s*:(.*)$` rewrite of `/cmd: value` to `/cmd value`.
fn apply_colon_syntax(single_line: &str) -> String {
    let Some(after) = single_line.strip_prefix('/') else {
        return single_line.to_owned();
    };
    let name_end = after
        .find(|character: char| is_js_space(character) || character == ':')
        .unwrap_or(after.len());
    if name_end == 0 {
        return single_line.to_owned();
    }
    let command = &after[..name_end];
    let remainder = &after[name_end..];
    let spaces = leading_space_len(remainder);
    let Some(rest) = remainder[spaces..].strip_prefix(':') else {
        return single_line.to_owned();
    };
    let normalized_rest = js_trim_start(rest);
    if normalized_rest.is_empty() {
        format!("/{command}")
    } else {
        format!("/{command} {normalized_rest}")
    }
}

/// Ports the `^\/([^\s@]+)@([^\s]+)(.*)$` bot-mention strip.
fn apply_bot_mention(normalized: &str, bot_username: Option<&str>) -> String {
    let Some(bot) = bot_username.and_then(normalize_optional_lowercase) else {
        return normalized.to_owned();
    };
    let Some(after) = normalized.strip_prefix('/') else {
        return normalized.to_owned();
    };
    let name_end = after
        .find(|character: char| is_js_space(character) || character == '@')
        .unwrap_or(after.len());
    if name_end == 0 {
        return normalized.to_owned();
    }
    let Some(rest) = after[name_end..].strip_prefix('@') else {
        return normalized.to_owned();
    };
    let mention_end = rest.find(is_js_space).unwrap_or(rest.len());
    if mention_end == 0 {
        return normalized.to_owned();
    }
    if normalize_lowercase_or_empty(&rest[..mention_end]) != bot {
        return normalized.to_owned();
    }
    format!("/{}{}", &after[..name_end], &rest[mention_end..])
}

/// Ports the `^\/([^\s]+)(?:\s+([\s\S]+))?$` token split, backtracking included.
fn split_command_token(command_body: &str) -> Option<(&str, Option<&str>)> {
    let after = command_body.strip_prefix('/')?;
    let name_end = after.find(is_js_space).unwrap_or(after.len());
    if name_end == 0 {
        return None;
    }
    let token = &after[..name_end];
    let remainder = &after[name_end..];
    if remainder.is_empty() {
        return Some((token, None));
    }
    let spaces = leading_space_len(remainder);
    if spaces < remainder.len() {
        return Some((token, Some(&remainder[spaces..])));
    }
    // Every remaining character is whitespace, so the greedy `\s+` gives one
    // character back to let `[\s\S]+` match. With a single character left there
    // is nothing to give back and the whole pattern fails.
    let last = remainder.chars().next_back()?;
    let start = remainder.len() - last.len_utf8();
    if start == 0 {
        return None;
    }
    Some((token, Some(&remainder[start..])))
}

/// Ports `appendMultilineTail`.
fn append_multiline_tail(
    head: &str,
    tail: Option<&str>,
    command: Option<&CommandDefinition>,
) -> String {
    let Some(tail) = tail.filter(|tail| !tail.is_empty()) else {
        return head.to_owned();
    };
    match command.map(CommandDefinition::key) {
        None | Some("skill" | "learn") => format!("{head}\n{tail}"),
        Some("reset") => {
            let flattened = js_trim(&collapse_js_whitespace(tail)).to_owned();
            if flattened.is_empty() {
                head.to_owned()
            } else {
                format!("{head} {flattened}")
            }
        }
        Some(_) => head.to_owned(),
    }
}

/// The pinned built-in command table.
///
/// Mirrors `buildBuiltinChatCommands` at the frozen upstream baseline, with the
/// six `registerAlias` calls already folded into the alias lists. The gates come
/// from `docs/tools/slash-commands.md`.
#[must_use]
pub fn builtin_commands() -> Vec<CommandDefinition> {
    vec![
        CommandDefinition::define("help", Some("help"), &["/help"]),
        CommandDefinition::define("commands", Some("commands"), &["/commands"]),
        CommandDefinition::define("tools", Some("tools"), &["/tools"]).accepting_args(),
        CommandDefinition::define("skill", Some("skill"), &["/skill"]).accepting_args(),
        CommandDefinition::define("learn", Some("learn"), &["/learn"]).accepting_args(),
        CommandDefinition::define("status", Some("status"), &["/status"])
            .accepting_args()
            .with_gate(CommandGate::feature_for(
                CommandFeature::Plugins,
                &["plugins"],
            )),
        CommandDefinition::define("goal", Some("goal"), &["/goal"]).accepting_args(),
        CommandDefinition::define("diagnostics", Some("diagnostics"), &["/diagnostics"])
            .accepting_args()
            .with_gate(CommandGate::owner()),
        CommandDefinition::define("login", Some("login"), &["/login"])
            .accepting_args()
            .with_gate(CommandGate::owner()),
        CommandDefinition::define("crestodian", None, &["/crestodian"])
            .accepting_args()
            .with_gate(CommandGate::owner()),
        CommandDefinition::define("tasks", Some("tasks"), &["/tasks"]),
        CommandDefinition::define("allowlist", None, &["/allowlist"])
            .accepting_args()
            .with_gate(CommandGate::feature_for(
                CommandFeature::Config,
                &["add", "remove"],
            )),
        CommandDefinition::define("approve", Some("approve"), &["/approve"]).accepting_args(),
        CommandDefinition::define("context", Some("context"), &["/context"]).accepting_args(),
        CommandDefinition::define("btw", Some("btw"), &["/btw", "/side"])
            .accepting_args()
            .with_native_aliases(&["side"]),
        CommandDefinition::define(
            "export-session",
            Some("export-session"),
            &["/export-session", "/export"],
        )
        .accepting_args(),
        CommandDefinition::define(
            "export-trajectory",
            Some("export-trajectory"),
            &["/export-trajectory", "/trajectory"],
        )
        .accepting_args(),
        CommandDefinition::define("tts", Some("tts"), &["/tts"]).accepting_args(),
        CommandDefinition::define("whoami", Some("whoami"), &["/whoami", "/id"]),
        CommandDefinition::define("session", Some("session"), &["/session"]).accepting_args(),
        CommandDefinition::define("subagents", Some("subagents"), &["/subagents"]).accepting_args(),
        CommandDefinition::define("acp", Some("acp"), &["/acp"]).accepting_args(),
        CommandDefinition::define("focus", Some("focus"), &["/focus"]).accepting_args(),
        CommandDefinition::define("unfocus", Some("unfocus"), &["/unfocus"]),
        CommandDefinition::define("agents", Some("agents"), &["/agents"]),
        CommandDefinition::define("steer", Some("steer"), &["/steer", "/tell"]).accepting_args(),
        CommandDefinition::define("config", Some("config"), &["/config"])
            .accepting_args()
            .with_gate(CommandGate::feature_and_owner(CommandFeature::Config)),
        CommandDefinition::define("mcp", Some("mcp"), &["/mcp"])
            .accepting_args()
            .with_gate(CommandGate::feature_and_owner(CommandFeature::Mcp)),
        CommandDefinition::define("plugins", Some("plugins"), &["/plugins", "/plugin"])
            .accepting_args()
            .with_gate(CommandGate::feature_with_owner_for(
                CommandFeature::Plugins,
                &["install", "enable", "disable"],
            )),
        CommandDefinition::define("debug", Some("debug"), &["/debug"])
            .accepting_args()
            .with_gate(CommandGate::feature_and_owner(CommandFeature::Debug)),
        CommandDefinition::define("usage", Some("usage"), &["/usage"]).accepting_args(),
        CommandDefinition::define("stop", Some("stop"), &["/stop"]),
        CommandDefinition::define("restart", Some("restart"), &["/restart"])
            .with_gate(CommandGate::feature(CommandFeature::Restart)),
        CommandDefinition::define("activation", Some("activation"), &["/activation"])
            .accepting_args(),
        CommandDefinition::define("send", Some("send"), &["/send"])
            .accepting_args()
            .with_gate(CommandGate::owner()),
        CommandDefinition::define("reset", Some("reset"), &["/reset"]).accepting_args(),
        CommandDefinition::define("new", Some("new"), &["/new"]).accepting_args(),
        CommandDefinition::define("name", Some("name"), &["/name"]).accepting_args(),
        CommandDefinition::define("compact", Some("compact"), &["/compact"]).accepting_args(),
        CommandDefinition::define("think", Some("think"), &["/think", "/thinking", "/t"])
            .accepting_args(),
        CommandDefinition::define("verbose", Some("verbose"), &["/verbose", "/v"]).accepting_args(),
        CommandDefinition::define("trace", Some("trace"), &["/trace"]).accepting_args(),
        CommandDefinition::define("fast", Some("fast"), &["/fast"]).accepting_args(),
        CommandDefinition::define("reasoning", Some("reasoning"), &["/reasoning", "/reason"])
            .accepting_args(),
        CommandDefinition::define("elevated", Some("elevated"), &["/elevated", "/elev"])
            .accepting_args(),
        CommandDefinition::define("exec", Some("exec"), &["/exec"]).accepting_args(),
        CommandDefinition::define("model", Some("model"), &["/model"]).accepting_args(),
        CommandDefinition::define("models", Some("models"), &["/models"]).accepting_args(),
        CommandDefinition::define("queue", Some("queue"), &["/queue"]).accepting_args(),
        CommandDefinition::define("bash", None, &["/bash"])
            .accepting_args()
            .with_gate(CommandGate::feature(CommandFeature::Bash)),
    ]
}

#[cfg(test)]
mod tests {
    use super::{
        CommandDefinition, CommandFeature, CommandGate, CommandRegistry, CommandScope,
        CommandSource, RegistryError, builtin_commands, should_handle_text_commands,
    };

    #[test]
    fn builtin_commands_are_a_valid_registry() {
        let registry = CommandRegistry::new(builtin_commands()).expect("pinned table is valid");

        assert_eq!(registry.commands().len(), 50);
        assert_eq!(registry.aliases().len(), 61);
    }

    #[test]
    fn scope_is_derived_from_the_native_name_and_aliases() {
        assert_eq!(
            CommandDefinition::define("a", Some("a"), &["/a"]).scope(),
            CommandScope::Both
        );
        assert_eq!(
            CommandDefinition::define("b", Some("b"), &[]).scope(),
            CommandScope::Native
        );
        assert_eq!(
            CommandDefinition::define("c", None, &["/c"]).scope(),
            CommandScope::Text
        );
    }

    #[test]
    fn structural_violations_are_rejected_with_upstream_text() {
        let duplicate_key = CommandRegistry::new(vec![
            CommandDefinition::define("dup", Some("one"), &["/one"]),
            CommandDefinition::define("dup", Some("two"), &["/two"]),
        ])
        .expect_err("duplicate keys must be rejected");
        assert_eq!(duplicate_key, RegistryError::DuplicateKey("dup".to_owned()));
        assert_eq!(duplicate_key.to_string(), "Duplicate command key: dup");

        let duplicate_native = CommandRegistry::new(vec![
            CommandDefinition::define("one", Some("same"), &["/one"]),
            CommandDefinition::define("two", Some("Same"), &["/two"]),
        ])
        .expect_err("duplicate native names must be rejected");
        assert_eq!(
            duplicate_native.to_string(),
            "Duplicate native command: Same"
        );

        let native_only_with_text = CommandRegistry::new(vec![
            CommandDefinition::define("one", Some("one"), &["/one"])
                .with_scope(CommandScope::Native),
        ])
        .expect_err("native-only commands may not carry text aliases");
        assert_eq!(
            native_only_with_text.to_string(),
            "Native-only command has text aliases: one"
        );

        let text_only_with_native = CommandRegistry::new(vec![
            CommandDefinition::define("one", Some("one"), &["/one"]).with_scope(CommandScope::Text),
        ])
        .expect_err("text-only commands may not carry a native name");
        assert_eq!(
            text_only_with_native.to_string(),
            "Text-only command has native name: one"
        );

        let missing_native = CommandRegistry::new(vec![
            CommandDefinition::define("one", None, &["/one"]).with_scope(CommandScope::Both),
        ])
        .expect_err("native commands need a native name");
        assert_eq!(
            missing_native.to_string(),
            "Native command missing native name: one"
        );
    }

    #[test]
    fn gates_scope_to_subcommands() {
        let plugins = CommandGate::feature_with_owner_for(
            CommandFeature::Plugins,
            &["install", "enable", "disable"],
        );
        assert_eq!(
            plugins.required_feature(Some("list")),
            Some(CommandFeature::Plugins)
        );
        assert!(!plugins.requires_owner(Some("list")));
        assert!(plugins.requires_owner(Some("  ENABLE  context7")));
        assert!(!plugins.requires_owner(None));

        let allowlist = CommandGate::feature_for(CommandFeature::Config, &["add", "remove"]);
        assert_eq!(allowlist.required_feature(Some("list")), None);
        assert_eq!(
            allowlist.required_feature(Some("add user")),
            Some(CommandFeature::Config)
        );
        assert!(!allowlist.requires_owner(Some("add user")));
    }

    #[test]
    fn text_commands_stay_available_on_surfaces_without_native_commands() {
        assert!(should_handle_text_commands(true, CommandSource::Text, true));
        assert!(!should_handle_text_commands(
            false,
            CommandSource::Text,
            true
        ));
        assert!(should_handle_text_commands(
            false,
            CommandSource::Text,
            false
        ));
        assert!(should_handle_text_commands(
            false,
            CommandSource::Native,
            true
        ));
    }
}

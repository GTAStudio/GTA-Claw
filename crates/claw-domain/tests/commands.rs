//! Golden tests for the command registry, authorization and inline directives.
//!
//! Every table lives in `tests/fixtures/commands/` and pins fixed input/output
//! pairs taken from `openclaw/openclaw@b43e832fcc8000ed7287c7accc54e381db607f85`.
//! The tables are checked in both directions where that is meaningful: the alias
//! table must not omit a registered alias and must not name one that does not
//! exist.

use std::collections::BTreeSet;

use claw_domain::commands::authorization::{
    ChannelSettings, CommandDenial, CommandInvocation, CommandsConfig, MessageContext,
    authorize_command,
};
use claw_domain::commands::directives::{
    Directive, extract_directive_for_sender, extract_exec_directive,
};
use claw_domain::commands::golden::{GoldenRecord, parse_golden};
use claw_domain::commands::registry::{
    CommandDefinition, CommandFeature, CommandGate, CommandRegistry, CommandScope, CommandSource,
    RegistryError,
};

const ALIASES: &str = include_str!("fixtures/commands/aliases.golden");
const TEXT_COMMANDS: &str = include_str!("fixtures/commands/text_commands.golden");
const DIRECTIVES: &str = include_str!("fixtures/commands/directives.golden");
const EXEC: &str = include_str!("fixtures/commands/exec.golden");
const AUTHORIZATION: &str = include_str!("fixtures/commands/authorization.golden");
const REGISTRY_ERRORS: &str = include_str!("fixtures/commands/registry_errors.golden");

fn records(source: &str, name: &str) -> Vec<GoldenRecord> {
    match parse_golden(source) {
        Ok(records) => {
            assert!(!records.is_empty(), "{name} golden table is empty");
            records
        }
        Err(error) => panic!("{name} golden table is malformed: {error}"),
    }
}

/// Names the record for assertion messages.
fn label(record: &GoldenRecord, key: &str) -> String {
    format!(
        "{} (golden record at line {})",
        record.get(key).unwrap_or("<unnamed>"),
        record.line()
    )
}

// ---------------------------------------------------------------------------
// aliases
// ---------------------------------------------------------------------------

/// The pinned registry must match the alias table exactly, in both directions.
#[test]
fn command_registry_matches_the_pinned_alias_table() {
    let registry = CommandRegistry::builtin();
    let table = records(ALIASES, "aliases");

    assert_eq!(
        table.len(),
        registry.commands().len(),
        "the alias table and the registry disagree on how many commands exist"
    );

    let mut seen_aliases: BTreeSet<String> = BTreeSet::new();
    for record in &table {
        let key = record.require("key");
        let command = registry
            .command(key)
            .unwrap_or_else(|| panic!("the registry is missing the pinned command `{key}`"));

        assert_eq!(
            command.scope().as_str(),
            record.require("scope"),
            "scope mismatch for `{key}`"
        );
        assert_eq!(
            command.native_name(),
            record.get("native_name"),
            "native name mismatch for `{key}`"
        );
        assert_eq!(
            command.native_aliases(),
            record.values("native_alias"),
            "native alias mismatch for `{key}`"
        );
        assert_eq!(
            command.text_aliases(),
            record.values("alias"),
            "text alias mismatch for `{key}`"
        );
        assert_eq!(
            command.accepts_args(),
            record.flag("accepts_args", false),
            "acceptsArgs mismatch for `{key}`"
        );

        let expected_feature = record.get("feature").map(|name| {
            CommandFeature::from_key(name)
                .unwrap_or_else(|| panic!("unknown feature `{name}` for `{key}`"))
        });
        assert_eq!(
            command.gate().declared_feature(),
            expected_feature,
            "feature gate mismatch for `{key}`"
        );
        assert_eq!(
            command.gate().feature_subcommands(),
            subcommands(record.get("feature_subcommands")),
            "feature subcommand scope mismatch for `{key}`"
        );
        assert_eq!(
            command.gate().declares_owner(),
            record.flag("owner_required", false),
            "owner gate mismatch for `{key}`"
        );
        assert_eq!(
            command.gate().owner_subcommands(),
            subcommands(record.get("owner_subcommands")),
            "owner subcommand scope mismatch for `{key}`"
        );

        for alias in record.values("alias") {
            assert!(
                seen_aliases.insert(alias.to_lowercase()),
                "the alias table lists `{alias}` twice"
            );
            let owner = registry
                .resolve_alias(alias)
                .unwrap_or_else(|| panic!("the registry does not resolve alias `{alias}`"));
            assert_eq!(
                owner.key(),
                key,
                "alias `{alias}` resolves to the wrong command"
            );
        }
    }

    let registered: BTreeSet<String> = registry
        .aliases()
        .into_iter()
        .map(|(alias, _)| alias.to_owned())
        .collect();
    assert_eq!(
        registered, seen_aliases,
        "the registry and the alias table do not agree on the alias set"
    );
}

fn subcommands(raw: Option<&str>) -> Vec<String> {
    raw.map(|value| value.split('|').map(str::to_owned).collect())
        .unwrap_or_default()
}

/// Every directive name must also be a registered alias of its command, so the
/// two surfaces cannot drift apart.
#[test]
fn every_directive_name_is_a_registered_alias() {
    let registry = CommandRegistry::builtin();

    for directive in Directive::ALL {
        let command = registry
            .command(directive.command_key())
            .unwrap_or_else(|| {
                panic!(
                    "directive `{directive}` has no command `{}`",
                    directive.command_key()
                )
            });
        for name in directive.names() {
            let alias = format!("/{name}");
            let owner = registry
                .resolve_alias(&alias)
                .unwrap_or_else(|| panic!("directive name `{alias}` is not a registered alias"));
            assert_eq!(
                owner.key(),
                command.key(),
                "directive name `{alias}` belongs to a different command"
            );
        }
    }
}

// ---------------------------------------------------------------------------
// text command resolution
// ---------------------------------------------------------------------------

/// Text bodies must resolve exactly as the pinned table says, including the
/// bodies that must not resolve at all.
#[test]
fn text_command_resolution_matches_the_golden_table() {
    let registry = CommandRegistry::builtin();

    for record in records(TEXT_COMMANDS, "text_commands") {
        let case = label(&record, "name");
        let input = record.require("input");
        let resolved = registry.resolve_text_command(input, record.get("bot"));

        if !record.flag("resolved", true) {
            assert!(
                resolved.is_none(),
                "{case}: expected `{input}` not to resolve, got {resolved:?}"
            );
            continue;
        }

        let resolved = resolved
            .unwrap_or_else(|| panic!("{case}: expected `{input}` to resolve to a command"));
        assert_eq!(
            resolved.command().key(),
            record.require("key"),
            "{case}: key"
        );
        assert_eq!(resolved.alias(), record.require("alias"), "{case}: alias");
        assert_eq!(resolved.args(), record.get("args"), "{case}: args");
    }
}

// ---------------------------------------------------------------------------
// inline directives
// ---------------------------------------------------------------------------

/// Inline directive parsing must match the pinned table, including the bodies
/// where a `/name` is deliberately *not* a directive.
#[test]
fn inline_directive_parsing_matches_the_golden_table() {
    for record in records(DIRECTIVES, "directives") {
        let case = label(&record, "name");
        let name = record.require("directive");
        let directive = Directive::from_key(name)
            .unwrap_or_else(|| panic!("{case}: unknown directive `{name}`"));
        let input = record.require("input");
        let authorized = record.flag("authorized", true);

        let parsed = extract_directive_for_sender(directive, input, authorized);

        assert_eq!(
            parsed.present(),
            record.flag("present", false),
            "{case}: presence"
        );
        assert_eq!(
            parsed.cleaned(),
            record.require("cleaned"),
            "{case}: cleaned"
        );
        assert_eq!(
            parsed.raw_level(),
            record.get("raw_level"),
            "{case}: raw level"
        );
        assert_eq!(
            parsed.level().map(|level| level.as_str()),
            record.get("level"),
            "{case}: normalized level"
        );
    }
}

/// `/exec` consumes only the options it recognizes; everything else survives.
#[test]
fn exec_directive_parsing_matches_the_golden_table() {
    for record in records(EXEC, "exec") {
        let case = label(&record, "name");
        let parsed = extract_exec_directive(record.require("input"));

        assert_eq!(
            parsed.present(),
            record.flag("present", false),
            "{case}: presence"
        );
        assert_eq!(
            parsed.has_options(),
            record.flag("has_options", false),
            "{case}: has options"
        );
        assert_eq!(
            parsed.cleaned(),
            record.require("cleaned"),
            "{case}: cleaned"
        );
        assert_eq!(parsed.host(), record.get("host"), "{case}: host");
        assert_eq!(
            parsed.security(),
            record.get("security"),
            "{case}: security"
        );
        assert_eq!(parsed.ask(), record.get("ask"), "{case}: ask");
        assert_eq!(parsed.node(), record.get("node"), "{case}: node");
        assert_eq!(
            parsed.invalid_host(),
            record.flag("invalid_host", false),
            "{case}: invalid host"
        );
        assert_eq!(
            parsed.invalid_security(),
            record.flag("invalid_security", false),
            "{case}: invalid security"
        );
        assert_eq!(
            parsed.invalid_ask(),
            record.flag("invalid_ask", false),
            "{case}: invalid ask"
        );
        assert_eq!(
            parsed.invalid_node(),
            record.flag("invalid_node", false),
            "{case}: invalid node"
        );
        if let Some(expected) = record.get("raw_host") {
            assert_eq!(parsed.raw_host(), Some(expected), "{case}: raw host");
        }
        if let Some(expected) = record.get("raw_security") {
            assert_eq!(
                parsed.raw_security(),
                Some(expected),
                "{case}: raw security"
            );
        }
        if let Some(expected) = record.get("raw_ask") {
            assert_eq!(parsed.raw_ask(), Some(expected), "{case}: raw ask");
        }
        if let Some(expected) = record.get("raw_node") {
            assert_eq!(parsed.raw_node(), Some(expected), "{case}: raw node");
        }
    }
}

// ---------------------------------------------------------------------------
// authorization
// ---------------------------------------------------------------------------

/// Authorization outcomes must match the pinned table, and every denial must
/// carry the pinned reason.
#[test]
fn command_authorization_matches_the_golden_table() {
    let registry = CommandRegistry::builtin();

    for record in records(AUTHORIZATION, "authorization") {
        let case = label(&record, "name");
        let config = build_config(&record);
        let channel = build_channel(&record);
        let context = build_context(&record);
        let body = record.require("body");

        let outcome = authorize_command(&registry, &config, &channel, &context, body);

        match record.get("denied") {
            None => {
                let invocation: CommandInvocation = outcome
                    .unwrap_or_else(|error| panic!("{case}: expected success, denied by {error}"));
                assert_eq!(invocation.key(), record.require("key"), "{case}: key");
                assert_eq!(invocation.args(), record.get("args"), "{case}: args");
            }
            Some(expected_code) => {
                let denial: CommandDenial = outcome
                    .map(|invocation| invocation.key().to_owned())
                    .expect_err(&format!("{case}: expected a denial"));
                assert_eq!(denial.code(), expected_code, "{case}: denial code");
                assert_eq!(
                    denial.to_string(),
                    record.require("reason"),
                    "{case}: denial reason"
                );
            }
        }
    }
}

fn build_config(record: &GoldenRecord) -> CommandsConfig {
    let mut config = CommandsConfig::default().with_text(record.flag("commands_text", true));
    for name in record.values("feature_on") {
        let feature =
            CommandFeature::from_key(name).unwrap_or_else(|| panic!("unknown feature_on `{name}`"));
        config = config.with_feature(feature, true);
    }
    for name in record.values("feature_off") {
        let feature = CommandFeature::from_key(name)
            .unwrap_or_else(|| panic!("unknown feature_off `{name}`"));
        config = config.with_feature(feature, false);
    }
    let owner_allow_from = record.values("owner_allow_from");
    if !owner_allow_from.is_empty() {
        config = config.with_owner_allow_from(owner_allow_from);
    }
    if let Some(provider_key) = record.get("commands_allow_from_key") {
        config = config.with_allow_from(provider_key, record.values("commands_allow_from"));
    }
    config
}

fn build_channel(record: &GoldenRecord) -> ChannelSettings {
    ChannelSettings::default()
        .with_allow_from(record.values("channel_allow_from"))
        .with_enforce_owner_for_commands(record.flag("enforce_owner", false))
        .with_native_command_surface(record.flag("native_surface", false))
}

fn build_context(record: &GoldenRecord) -> MessageContext {
    let mut context = MessageContext::authorized()
        .with_command_authorized(record.flag("command_authorized", true))
        .with_internal_channel(record.flag("internal_channel", false))
        .with_native_command_turn(record.flag("native_turn", false))
        .with_gateway_client_scopes(record.values("scope"))
        .with_owner_allow_from(record.values("ctx_owner_allow_from"));
    if let Some(provider) = record.get("provider") {
        context = context.with_provider(provider);
    }
    if let Some(from) = record.get("from") {
        context = context.with_from(from);
    }
    if let Some(to) = record.get("to") {
        context = context.with_to(to);
    }
    if let Some(sender_id) = record.get("sender_id") {
        context = context.with_sender_id(sender_id);
    }
    if let Some(sender_e164) = record.get("sender_e164") {
        context = context.with_sender_e164(sender_e164);
    }
    if let Some(chat_type) = record.get("chat_type") {
        context = context.with_chat_type(chat_type);
    }
    match record.get("source") {
        Some("native") => context.with_source(CommandSource::Native),
        Some("text") | None => context.with_source(CommandSource::Text),
        Some(other) => panic!("unknown source `{other}`"),
    }
}

// ---------------------------------------------------------------------------
// registry validation
// ---------------------------------------------------------------------------

/// A malformed registry must be rejected with upstream's exact message. Alias
/// collisions are what make the pinned alias table trustworthy.
#[test]
fn registry_validation_errors_match_the_golden_table() {
    for record in records(REGISTRY_ERRORS, "registry_errors") {
        let scenario = record.require("scenario");
        let commands = malformed_registry(scenario);
        let error: RegistryError = CommandRegistry::new(commands)
            .map(|registry| registry.commands().len())
            .expect_err(&format!("{scenario}: expected a rejection"));
        assert_eq!(error.to_string(), record.require("error"), "{scenario}");
    }
}

fn malformed_registry(scenario: &str) -> Vec<CommandDefinition> {
    match scenario {
        "duplicate_key" => vec![
            CommandDefinition::define("dup", None, &["/one"]),
            CommandDefinition::define("dup", None, &["/two"]),
        ],
        "text_only_has_native_name" => vec![
            CommandDefinition::define("texty", Some("texty"), &["/texty"])
                .with_scope(CommandScope::Text),
        ],
        "text_only_has_native_aliases" => vec![
            CommandDefinition::define("texty", None, &["/texty"]).with_native_aliases(&["texty"]),
        ],
        "text_only_missing_text_alias" => {
            vec![CommandDefinition::define("texty", None, &[]).with_scope(CommandScope::Text)]
        }
        "native_missing_native_name" => {
            vec![CommandDefinition::define("nat", None, &["/nat"]).with_scope(CommandScope::Both)]
        }
        "duplicate_native_command" => vec![
            CommandDefinition::define("first", Some("shared"), &["/first"]),
            CommandDefinition::define("second", Some("shared"), &["/second"]),
        ],
        "duplicate_native_alias" => vec![
            CommandDefinition::define("first", Some("first"), &["/first"]),
            CommandDefinition::define("second", Some("second"), &["/second"])
                .with_native_aliases(&["shared"]),
            CommandDefinition::define("third", Some("third"), &["/third"])
                .with_native_aliases(&["shared"]),
        ],
        "native_only_has_text_aliases" => vec![
            CommandDefinition::define("nat", Some("nat"), &["/nat"])
                .with_scope(CommandScope::Native),
        ],
        "alias_missing_leading_slash" => vec![CommandDefinition::define("help", None, &["help"])],
        "duplicate_alias" => vec![
            CommandDefinition::define("first", None, &["/dupe"]),
            CommandDefinition::define("second", None, &["/dupe"]),
        ],
        "duplicate_alias_differing_case" => vec![
            CommandDefinition::define("first", None, &["/dupe"]),
            CommandDefinition::define("second", None, &["/DUPE"]),
        ],
        other => panic!("unknown registry error scenario `{other}`"),
    }
}

/// The gate helpers must scope to the first argument only.
#[test]
fn subcommand_scoped_gates_only_fire_on_their_subcommand() {
    let gate = CommandGate::feature_for(CommandFeature::Config, &["add", "remove"]);

    assert_eq!(gate.required_feature(None), None);
    assert_eq!(gate.required_feature(Some("show")), None);
    assert_eq!(
        gate.required_feature(Some("ADD +1555")),
        Some(CommandFeature::Config)
    );
    assert_eq!(gate.required_feature(Some("readd")), None);

    let gate = CommandGate::feature_with_owner_for(CommandFeature::Plugins, &["install"]);

    assert_eq!(gate.required_feature(None), Some(CommandFeature::Plugins));
    assert!(!gate.requires_owner(Some("list")));
    assert!(gate.requires_owner(Some("install demo")));
}

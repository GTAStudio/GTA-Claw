use std::collections::{BTreeMap, BTreeSet};
use std::error::Error;
use std::fmt::{self, Display, Formatter};

use crate::ConfigSnapshot;
use crate::error::ConfigError;
use crate::model::SecretRef;
use crate::wire::{EnvelopeWire, LogLevelWire};

#[derive(Clone, Copy, Debug)]
pub(crate) struct LegacyMappingContract {
    id: MappingId,
    legacy_env: &'static str,
    aliases: &'static [&'static str],
    scope: &'static str,
    target: &'static str,
    secret: bool,
    _default_json: &'static str,
    _conversion: &'static str,
    _validation: &'static str,
    _required_when: &'static str,
    _known_legacy_quirk: Option<&'static str>,
}

include!(concat!(env!("OUT_DIR"), "/legacy_mappings.rs"));

/// A migration row that cannot be represented by this runtime configuration.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ManualMapping {
    /// Canonical audited legacy environment name.
    pub legacy_env: &'static str,
    /// Frozen target key that requires a later subsystem or manual action.
    pub target: &'static str,
    /// Why automatic runtime migration is intentionally unavailable.
    pub reason: &'static str,
}

/// A non-fatal migration diagnostic.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum MigrationDiagnostic {
    /// A present value belongs to deploy, build, CI, or an intentionally absent runtime.
    ManualRequired(ManualMapping),
}

/// Result of converting supplied audited environment entries.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MigrationResult {
    /// Fully validated typed runtime configuration.
    pub config: ConfigSnapshot,
    /// Deterministically ordered manual actions.
    pub diagnostics: Vec<MigrationDiagnostic>,
}

/// A deterministic failure to convert GTA legacy environment entries.
#[derive(Debug)]
pub enum MigrationError {
    /// The same environment name was supplied with different values.
    DuplicateVariable {
        /// Conflicting variable name.
        name: String,
    },
    /// Canonical and alias names supplied different nonempty values.
    AliasConflict {
        /// Frozen destination key.
        target: &'static str,
        /// Conflicting names in contract priority order.
        names: Vec<String>,
    },
    /// A supported legacy value failed its frozen conversion or validation rule.
    InvalidValue {
        /// Environment variable whose value failed.
        legacy_env: &'static str,
        /// Frozen destination key.
        target: &'static str,
        /// Specific conversion failure.
        message: String,
    },
    /// The converted candidate failed complete typed validation.
    Config(ConfigError),
}

impl Display for MigrationError {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        match self {
            Self::DuplicateVariable { name } => {
                write!(
                    formatter,
                    "legacy environment variable {name} has conflicting values"
                )
            }
            Self::AliasConflict { target, names } => write!(
                formatter,
                "legacy aliases for {target} conflict: {}",
                names.join(", ")
            ),
            Self::InvalidValue {
                legacy_env,
                target,
                message,
            } => write!(formatter, "{legacy_env} -> {target}: {message}"),
            Self::Config(error) => write!(formatter, "migrated configuration: {error}"),
        }
    }
}

impl Error for MigrationError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Config(error) => Some(error),
            _ => None,
        }
    }
}

/// Converts only caller-supplied entries using the frozen audited mapping.
///
/// This pure function never reads process environment state. Alias conflicts
/// are detected before equal values are deduplicated. Secret values are used
/// only to determine presence; the output stores an [`SecretRef`] to the
/// selected environment name.
pub fn migrate_legacy_environment<'a>(
    variables: impl IntoIterator<Item = (&'a str, &'a str)>,
) -> Result<MigrationResult, MigrationError> {
    let variables = collect_variables(variables)?;
    migrate_collected(&variables)
}

fn migrate_collected(
    variables: &BTreeMap<String, String>,
) -> Result<MigrationResult, MigrationError> {
    let (wire, diagnostics) = apply_mappings(variables, default_envelope(), true)?;
    let config = wire.validate().map_err(MigrationError::Config)?;
    Ok(MigrationResult {
        config,
        diagnostics,
    })
}

fn apply_mappings(
    variables: &BTreeMap<String, String>,
    mut wire: EnvelopeWire,
    infer_device_from_existing_client: bool,
) -> Result<(EnvelopeWire, Vec<MigrationDiagnostic>), MigrationError> {
    let mut diagnostics = Vec::new();
    let mut explicit_device_flow = false;
    let mut explicit_device_client_id = false;

    for mapping in LEGACY_MAPPINGS {
        let selected = select_value(mapping, variables)?;
        let Some((name, value)) = selected else {
            continue;
        };
        if mapping.scope != "runtime" || mapping.id == MappingId::CopilotCliPath {
            if !value.is_empty() {
                diagnostics.push(MigrationDiagnostic::ManualRequired(ManualMapping {
                    legacy_env: mapping.legacy_env,
                    target: mapping.target,
                    reason: manual_reason(mapping),
                }));
            }

            continue;
        }

        match mapping.id {
            MappingId::GithubToken => {
                wire.core.auth.github.pat = secret_reference(mapping, name, value, true)?;
            }
            MappingId::DeviceFlowEnabled => {
                explicit_device_flow = true;
                wire.core.auth.github.device.enabled = parse_bool(mapping, value)?;
            }
            MappingId::GithubClientId => {
                explicit_device_client_id = true;
                wire.core.auth.github.device.client_id = trimmed_optional(value);
            }
            MappingId::Microsoftappid => {
                wire.core.channels.teams.app_id = trimmed_optional(value);
            }
            MappingId::Microsoftapppassword => {
                wire.core.channels.teams.app_password =
                    secret_reference(mapping, name, value, true)?;
            }
            MappingId::AgentRoleUrl => {
                if value.is_empty() {
                    return Err(invalid(mapping, "must not be empty"));
                }
                wire.core.role.source_url = value.to_owned();
            }
            MappingId::EnabledSkills => {
                wire.core.legacy.skills.source_urls = split_trimmed(value);
            }
            MappingId::EnableTeams => {
                wire.core.channels.teams.enabled = parse_bool(mapping, value)?;
            }
            MappingId::EnableTelegram => {
                wire.core.channels.telegram.enabled = parse_bool(mapping, value)?;
            }
            MappingId::TelegramBotToken => {
                wire.core.channels.telegram.bot_token =
                    secret_reference(mapping, name, value, true)?;
            }
            MappingId::TelegramPollIntervalMs => {
                wire.core.channels.telegram.poll_interval_ms =
                    parse_u64(mapping, value, 500, Some(60_000))?;
            }
            MappingId::EnableDiscord => {
                wire.core.channels.discord.enabled = parse_bool(mapping, value)?;
            }
            MappingId::DiscordBotToken => {
                wire.core.channels.discord.bot_token =
                    secret_reference(mapping, name, value, true)?;
            }
            MappingId::DiscordGatewayUrl => {
                wire.core.channels.discord.gateway_url = default_when_trimmed_empty(
                    value,
                    "wss://gateway.discord.gg/?v=10&encoding=json",
                );
            }
            MappingId::DiscordGatewayIntents => {
                wire.core.channels.discord.gateway_intents = parse_u64(mapping, value, 1, None)?;
            }
            MappingId::EnableWhatsapp => {
                wire.core.channels.whatsapp.enabled = parse_bool(mapping, value)?;
            }
            MappingId::WhatsappVerifyToken => {
                wire.core.channels.whatsapp.verify_token =
                    secret_reference(mapping, name, value, true)?;
            }
            MappingId::WhatsappAccessToken => {
                wire.core.channels.whatsapp.access_token =
                    secret_reference(mapping, name, value, true)?;
            }
            MappingId::WhatsappPhoneNumberId => {
                wire.core.channels.whatsapp.phone_number_id = trimmed_optional(value);
            }
            MappingId::WhatsappWebhookPath => {
                wire.core.channels.whatsapp.webhook_path =
                    default_when_trimmed_empty(value, "/whatsapp/webhook");
            }
            MappingId::Port => {
                wire.core.server.port = u16::try_from(parse_u64(mapping, value, 1, Some(65_535))?)
                    .map_err(|error| invalid(mapping, error.to_string()))?;
            }
            MappingId::LogLevel => {
                wire.core.logging.level = parse_log_level(mapping, value)?;
            }
            MappingId::NodeEnv => {
                wire.core.logging.development_transport = value == "development";
            }
            MappingId::SessionTtlMs => {
                wire.core.sessions.ttl_ms = parse_u64(mapping, value, 1_000, None)?;
            }
            MappingId::MaxSessions => {
                wire.core.sessions.max_entries =
                    usize::try_from(parse_u64(mapping, value, 1, None)?)
                        .map_err(|error| invalid(mapping, error.to_string()))?;
            }
            MappingId::CopilotModel => {
                wire.core.copilot.default_model = default_when_empty(value, "gpt-4o");
            }
            MappingId::SkillExecTimeoutMs => {
                wire.core.legacy.skills.execution_timeout_ms =
                    parse_u64(mapping, value, 100, None)?;
            }
            MappingId::SdkRequestTimeoutMs => {
                wire.core.copilot.request_timeout_ms = parse_u64(mapping, value, 1_000, None)?;
            }
            MappingId::RateLimitPerMin => {
                wire.core.server.teams_rate_limit_per_minute =
                    u32::try_from(parse_u64(mapping, value, 1, None)?)
                        .map_err(|error| invalid(mapping, error.to_string()))?;
            }
            MappingId::AllowedSkillDomains => {
                wire.core.legacy.skills.allowed_domains = split_lowercase_deduplicated(value);
            }
            MappingId::Domain => {
                wire.core.server.public_domain = default_when_empty(value, "localhost");
            }
            MappingId::AutoUpdate => {
                wire.core.updates.enabled = parse_bool(mapping, value)?;
            }
            MappingId::AdminToken => {
                wire.core.admin.bearer_token = secret_reference(mapping, name, value, false)?;
            }
            MappingId::TrustProxy => {
                wire.core.server.trust_proxy = parse_bool(mapping, value)?;
            }
            MappingId::HttpsProxy => {
                wire.core.network.proxy_url = secret_reference(mapping, name, value, true)?;
            }
            MappingId::CopilotCliPath
            | MappingId::DockerImage
            | MappingId::AppLang
            | MappingId::CopilotCliVersion
            | MappingId::DockerhubUsername
            | MappingId::DockerhubToken
            | MappingId::DockerhubImage => unreachable!("handled as manual mapping"),
        }
    }

    if !explicit_device_flow && (infer_device_from_existing_client || explicit_device_client_id) {
        wire.core.auth.github.device.enabled = wire.core.auth.github.device.client_id.is_some();
    }

    Ok((wire, diagnostics))
}

pub(crate) fn apply_legacy_environment_layer<'a>(
    base: EnvelopeWire,
    variables: impl IntoIterator<Item = (&'a str, &'a str)>,
) -> Result<EnvelopeWire, MigrationError> {
    let variables = collect_variables(variables)?;
    apply_mappings(&variables, base, false).map(|(wire, _)| wire)
}

fn collect_variables<'a>(
    variables: impl IntoIterator<Item = (&'a str, &'a str)>,
) -> Result<BTreeMap<String, String>, MigrationError> {
    let mut collected = BTreeMap::new();
    for (name, value) in variables {
        if let Some(previous) = collected.insert(name.to_owned(), value.to_owned())
            && previous != value
        {
            return Err(MigrationError::DuplicateVariable {
                name: name.to_owned(),
            });
        }
    }
    Ok(collected)
}

fn select_value<'a>(
    mapping: &LegacyMappingContract,
    variables: &'a BTreeMap<String, String>,
) -> Result<Option<(&'static str, &'a str)>, MigrationError> {
    let names = std::iter::once(mapping.legacy_env).chain(mapping.aliases.iter().copied());
    let present: Vec<_> = names
        .filter_map(|name| {
            variables
                .get(name)
                .filter(|value| !value.is_empty())
                .map(|value| (name, value.as_str()))
        })
        .collect();
    let distinct: BTreeSet<_> = present.iter().map(|(_, value)| *value).collect();
    if distinct.len() > 1 {
        return Err(MigrationError::AliasConflict {
            target: mapping.target,
            names: present
                .into_iter()
                .map(|(name, _)| name.to_owned())
                .collect(),
        });
    }
    if let Some(selected) = present.first() {
        return Ok(Some(*selected));
    }
    Ok(variables
        .get(mapping.legacy_env)
        .map(|value| (mapping.legacy_env, value.as_str())))
}

fn secret_reference(
    mapping: &LegacyMappingContract,
    selected_name: &'static str,
    value: &str,
    trim: bool,
) -> Result<Option<String>, MigrationError> {
    debug_assert!(mapping.secret);
    let present = if trim {
        !value.trim().is_empty()
    } else {
        !value.is_empty()
    };
    if !present {
        return Ok(None);
    }
    SecretRef::environment(selected_name)
        .map(|reference| Some(reference.as_str().to_owned()))
        .map_err(|message| invalid(mapping, message))
}

fn parse_bool(mapping: &LegacyMappingContract, value: &str) -> Result<bool, MigrationError> {
    match value {
        "true" => Ok(true),
        "false" => Ok(false),
        _ => Err(invalid(mapping, "must be exactly 'true' or 'false'")),
    }
}

fn parse_u64(
    mapping: &LegacyMappingContract,
    value: &str,
    minimum: u64,
    maximum: Option<u64>,
) -> Result<u64, MigrationError> {
    let parsed = match parse_integer_prefix(value) {
        IntegerPrefix::Parsed(value) => value,
        IntegerPrefix::Missing => {
            return Err(invalid(mapping, "must start with a base-10 integer"));
        }
        IntegerPrefix::Overflow => {
            return Err(invalid(mapping, "integer prefix is too large to represent"));
        }
    };
    let parsed = u64::try_from(parsed).map_err(|_| invalid(mapping, "must not be negative"))?;
    if parsed < minimum || maximum.is_some_and(|maximum| parsed > maximum) {
        let requirement = maximum.map_or_else(
            || format!("must be at least {minimum}"),
            |maximum| format!("must be from {minimum} through {maximum}"),
        );
        return Err(invalid(mapping, requirement));
    }
    Ok(parsed)
}

enum IntegerPrefix {
    Parsed(i128),
    Missing,
    Overflow,
}

fn parse_integer_prefix(value: &str) -> IntegerPrefix {
    let value = value.trim_start_matches(char::is_whitespace);
    let bytes = value.as_bytes();
    let mut end = usize::from(matches!(bytes.first(), Some(b'+' | b'-')));
    let start_digits = end;
    while bytes.get(end).is_some_and(u8::is_ascii_digit) {
        end += 1;
    }
    if end == start_digits {
        return IntegerPrefix::Missing;
    }
    match value[..end].parse() {
        Ok(value) => IntegerPrefix::Parsed(value),
        Err(_) => IntegerPrefix::Overflow,
    }
}

fn parse_log_level(
    mapping: &LegacyMappingContract,
    value: &str,
) -> Result<LogLevelWire, MigrationError> {
    match value {
        "trace" => Ok(LogLevelWire::Trace),
        "debug" => Ok(LogLevelWire::Debug),
        "info" => Ok(LogLevelWire::Info),
        "warn" => Ok(LogLevelWire::Warn),
        "error" => Ok(LogLevelWire::Error),
        "fatal" => Ok(LogLevelWire::Fatal),
        _ => Err(invalid(
            mapping,
            "must be one of trace, debug, info, warn, error, fatal",
        )),
    }
}

fn trimmed_optional(value: &str) -> Option<String> {
    let value = value.trim();
    (!value.is_empty()).then(|| value.to_owned())
}

fn split_trimmed(value: &str) -> Vec<String> {
    value
        .split(',')
        .map(str::trim)
        .filter(|entry| !entry.is_empty())
        .map(str::to_owned)
        .collect()
}

fn split_lowercase_deduplicated(value: &str) -> Vec<String> {
    let mut seen = BTreeSet::new();
    split_trimmed(value)
        .into_iter()
        .map(|entry| entry.to_lowercase())
        .filter(|entry| seen.insert(entry.clone()))
        .collect()
}

fn default_when_trimmed_empty(value: &str, default: &str) -> String {
    let value = value.trim();
    if value.is_empty() {
        default.to_owned()
    } else {
        value.to_owned()
    }
}

fn default_when_empty(value: &str, default: &str) -> String {
    if value.is_empty() {
        default.to_owned()
    } else {
        value.to_owned()
    }
}

fn manual_reason(mapping: &LegacyMappingContract) -> &'static str {
    if mapping.id == MappingId::CopilotCliPath {
        "Copilot CLI execution is intentionally absent from the production Rust runtime"
    } else {
        match mapping.scope {
            "deployer" => "deployer configuration is outside the runtime configuration envelope",
            "build" => "build-time configuration requires explicit build tooling",
            "ci" => "publishing credentials and settings remain owned by CI",
            _ => "mapping is not supported by this configuration foundation",
        }
    }
}

fn invalid(mapping: &LegacyMappingContract, message: impl Into<String>) -> MigrationError {
    MigrationError::InvalidValue {
        legacy_env: mapping.legacy_env,
        target: mapping.target,
        message: message.into(),
    }
}

fn default_envelope() -> EnvelopeWire {
    EnvelopeWire::default()
}

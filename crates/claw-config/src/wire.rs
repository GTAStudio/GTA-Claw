use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use url::Url;

use crate::error::ConfigError;
use crate::model::{
    AdminConfig, AuthConfig, CONFIG_SCHEMA_VERSION, ChannelsConfig, ConfigSnapshot, CopilotConfig,
    CoreConfig, DiscordConfig, LegacySkillsConfig, LogLevel, LoggingConfig, ModelAliasConfig,
    NetworkConfig, ProviderCompletionApi, ProviderConfig, ProviderKind, RoleConfig, SecretRef,
    ServerConfig, SessionsConfig, TeamsConfig, TelegramConfig, UpdatesConfig, WhatsappConfig,
};

#[derive(Clone, Debug, Deserialize, JsonSchema, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct EnvelopeWire {
    pub(crate) schema_version: u32,
    pub(crate) core: CoreWire,
}

impl Default for EnvelopeWire {
    fn default() -> Self {
        Self {
            schema_version: CONFIG_SCHEMA_VERSION,
            core: CoreWire::default(),
        }
    }
}

#[derive(Clone, Debug, Default, Deserialize, JsonSchema, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct CoreWire {
    pub(crate) auth: AuthWire,
    pub(crate) role: RoleWire,
    pub(crate) channels: ChannelsWire,
    pub(crate) server: ServerWire,
    pub(crate) logging: LoggingWire,
    pub(crate) sessions: SessionsWire,
    pub(crate) copilot: CopilotWire,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) provider: Option<ProviderWire>,
    pub(crate) legacy: LegacyWire,
    pub(crate) updates: UpdatesWire,
    pub(crate) admin: AdminWire,
    pub(crate) network: NetworkWire,
}

#[derive(Clone, Debug, Default, Deserialize, JsonSchema, Serialize)]
#[serde(default, deny_unknown_fields)]
pub(crate) struct AuthWire {
    pub(crate) github: GithubAuthWire,
}

#[derive(Clone, Debug, Default, Deserialize, JsonSchema, Serialize)]
#[serde(default, deny_unknown_fields)]
pub(crate) struct GithubAuthWire {
    pub(crate) pat: Option<String>,
    pub(crate) device: DeviceAuthWire,
}

#[derive(Clone, Debug, Default, Deserialize, JsonSchema, Serialize)]
#[serde(default, deny_unknown_fields)]
pub(crate) struct DeviceAuthWire {
    pub(crate) enabled: bool,
    pub(crate) client_id: Option<String>,
}

#[derive(Clone, Debug, Default, Deserialize, JsonSchema, Serialize)]
#[serde(default, deny_unknown_fields)]
pub(crate) struct RoleWire {
    pub(crate) source_url: String,
}

#[derive(Clone, Debug, Default, Deserialize, JsonSchema, Serialize)]
#[serde(default, deny_unknown_fields)]
pub(crate) struct ChannelsWire {
    pub(crate) teams: TeamsWire,
    pub(crate) telegram: TelegramWire,
    pub(crate) discord: DiscordWire,
    pub(crate) whatsapp: WhatsappWire,
}

#[derive(Clone, Debug, Deserialize, JsonSchema, Serialize)]
#[serde(default, deny_unknown_fields)]
pub(crate) struct TeamsWire {
    pub(crate) enabled: bool,
    pub(crate) app_id: Option<String>,
    pub(crate) app_password: Option<String>,
}

impl Default for TeamsWire {
    fn default() -> Self {
        Self {
            enabled: true,
            app_id: None,
            app_password: None,
        }
    }
}

#[derive(Clone, Debug, Deserialize, JsonSchema, Serialize)]
#[serde(default, deny_unknown_fields)]
pub(crate) struct TelegramWire {
    pub(crate) enabled: bool,
    pub(crate) bot_token: Option<String>,
    pub(crate) poll_interval_ms: u64,
}

impl Default for TelegramWire {
    fn default() -> Self {
        Self {
            enabled: false,
            bot_token: None,
            poll_interval_ms: 2_000,
        }
    }
}

#[derive(Clone, Debug, Deserialize, JsonSchema, Serialize)]
#[serde(default, deny_unknown_fields)]
pub(crate) struct DiscordWire {
    pub(crate) enabled: bool,
    pub(crate) bot_token: Option<String>,
    pub(crate) gateway_url: String,
    pub(crate) gateway_intents: u64,
}

impl Default for DiscordWire {
    fn default() -> Self {
        Self {
            enabled: false,
            bot_token: None,
            gateway_url: "wss://gateway.discord.gg/?v=10&encoding=json".to_owned(),
            gateway_intents: 33_281,
        }
    }
}

#[derive(Clone, Debug, Deserialize, JsonSchema, Serialize)]
#[serde(default, deny_unknown_fields)]
pub(crate) struct WhatsappWire {
    pub(crate) enabled: bool,
    pub(crate) verify_token: Option<String>,
    pub(crate) access_token: Option<String>,
    pub(crate) app_secret: Option<String>,
    pub(crate) phone_number_id: Option<String>,
    pub(crate) webhook_path: String,
}

impl Default for WhatsappWire {
    fn default() -> Self {
        Self {
            enabled: false,
            verify_token: None,
            access_token: None,
            app_secret: None,
            phone_number_id: None,
            webhook_path: "/whatsapp/webhook".to_owned(),
        }
    }
}

#[derive(Clone, Debug, Deserialize, JsonSchema, Serialize)]
#[serde(default, deny_unknown_fields)]
pub(crate) struct ServerWire {
    pub(crate) port: u16,
    pub(crate) teams_rate_limit_per_minute: u32,
    pub(crate) public_domain: String,
    pub(crate) trust_proxy: bool,
}

impl Default for ServerWire {
    fn default() -> Self {
        Self {
            port: 3_978,
            teams_rate_limit_per_minute: 30,
            public_domain: "localhost".to_owned(),
            trust_proxy: false,
        }
    }
}

#[derive(Clone, Copy, Debug, Default, Deserialize, JsonSchema, Serialize)]
#[serde(rename_all = "lowercase")]
pub(crate) enum LogLevelWire {
    Trace,
    Debug,
    #[default]
    Info,
    Warn,
    Error,
    Fatal,
}

#[derive(Clone, Debug, Default, Deserialize, JsonSchema, Serialize)]
#[serde(default, deny_unknown_fields)]
pub(crate) struct LoggingWire {
    pub(crate) level: LogLevelWire,
    pub(crate) development_transport: bool,
}

#[derive(Clone, Debug, Deserialize, JsonSchema, Serialize)]
#[serde(default, deny_unknown_fields)]
pub(crate) struct SessionsWire {
    pub(crate) ttl_ms: u64,
    pub(crate) max_entries: usize,
}

impl Default for SessionsWire {
    fn default() -> Self {
        Self {
            ttl_ms: 3_600_000,
            max_entries: 100,
        }
    }
}

#[derive(Clone, Debug, Deserialize, JsonSchema, Serialize)]
#[serde(default, deny_unknown_fields)]
pub(crate) struct CopilotWire {
    pub(crate) default_model: String,
    pub(crate) request_timeout_ms: u64,
}

impl Default for CopilotWire {
    fn default() -> Self {
        Self {
            default_model: "gpt-4o".to_owned(),
            request_timeout_ms: 120_000,
        }
    }
}

#[derive(Clone, Debug, Deserialize, JsonSchema, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct ProviderWire {
    kind: ProviderKind,
    #[serde(skip_serializing_if = "Option::is_none")]
    model: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    model_aliases: Option<Vec<ModelAliasWire>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    api_key: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    base_url: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    credential_origin: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    request_timeout_ms: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    completion_api: Option<ProviderCompletionApi>,
    #[serde(skip_serializing_if = "Option::is_none")]
    max_observed_turn_tokens: Option<u64>,
}

#[derive(Clone, Debug, Deserialize, JsonSchema, Serialize)]
#[serde(deny_unknown_fields)]
struct ModelAliasWire {
    alias: String,
    model: String,
}

impl ProviderWire {
    fn validate(self) -> Result<ProviderConfig, ConfigError> {
        if self.kind == ProviderKind::Disabled {
            if self.model.is_some()
                || self.model_aliases.is_some()
                || self.api_key.is_some()
                || self.base_url.is_some()
                || self.credential_origin.is_some()
                || self.request_timeout_ms.is_some()
                || self.completion_api.is_some()
                || self.max_observed_turn_tokens.is_some()
            {
                return validation(
                    "core.provider",
                    "disabled selection must not include active provider settings",
                );
            }
            return Ok(ProviderConfig {
                kind: self.kind,
                model: None,
                model_aliases: Vec::new(),
                api_key: None,
                base_url: None,
                credential_origin: None,
                request_timeout_ms: None,
                completion_api: None,
                max_observed_turn_tokens: None,
            });
        }
        let Some(model) = self.model.filter(|model| valid_model_identifier(model)) else {
            return validation(
                "core.provider.model",
                "requires an exact nonblank model identifier of at most 256 bytes",
            );
        };
        let model_aliases = self.model_aliases.unwrap_or_default();
        if model_aliases.len() > 128 {
            return validation(
                "core.provider.model_aliases",
                "exceeds 128 explicit aliases",
            );
        }
        if model_aliases
            .iter()
            .map(|entry| entry.alias.len().saturating_add(entry.model.len()))
            .fold(0_usize, usize::saturating_add)
            > 4096
        {
            return validation(
                "core.provider.model_aliases",
                "alias names and targets exceed 4096 UTF-8 bytes",
            );
        }
        let mut names = std::collections::BTreeSet::new();
        for entry in &model_aliases {
            if !valid_model_identifier(&entry.alias)
                || !valid_model_identifier(&entry.model)
                || entry.alias == model
                || entry.alias == "openclaw"
                || entry.alias.starts_with("openclaw/")
                || !names.insert(entry.alias.as_str())
            {
                return validation(
                    "core.provider.model_aliases",
                    "requires unique valid aliases distinct from the exact selected model",
                );
            }
        }
        if model_aliases
            .iter()
            .any(|entry| names.contains(entry.model.as_str()))
        {
            return validation(
                "core.provider.model_aliases",
                "must point directly to exact model identifiers, not aliases",
            );
        }
        let model_aliases = model_aliases
            .into_iter()
            .map(|entry| ModelAliasConfig {
                alias: entry.alias,
                model: entry.model,
            })
            .collect();
        let timeout = self.request_timeout_ms.unwrap_or(120_000);
        validate_range(timeout, 1_000, 120_000, "core.provider.request_timeout_ms")?;
        if self.kind == ProviderKind::Copilot {
            if self.api_key.is_some()
                || self.base_url.is_some()
                || self.credential_origin.is_some()
                || self.completion_api.is_some()
            {
                return validation(
                    "core.provider",
                    "Copilot uses core.auth.github and does not accept native endpoint or API key fields",
                );
            }
            return Ok(ProviderConfig {
                kind: self.kind,
                model: Some(model),
                model_aliases,
                api_key: None,
                base_url: None,
                credential_origin: None,
                request_timeout_ms: Some(timeout),
                completion_api: None,
                max_observed_turn_tokens: self.max_observed_turn_tokens,
            });
        }
        if self.kind == ProviderKind::Anthropic && self.completion_api.is_some() {
            return validation(
                "core.provider.completion_api",
                "is supported only for OpenAI-compatible selection",
            );
        }
        if self
            .api_key
            .as_ref()
            .is_some_and(|reference| reference.len() > 1024)
        {
            return validation(
                "core.provider.api_key",
                "credential reference exceeds 1024 bytes",
            );
        }
        let api_key = secret(self.api_key, "core.provider.api_key")?;
        if api_key.is_none() {
            return validation(
                "core.provider.api_key",
                "is required for the selected native provider",
            );
        }
        let endpoint = self.base_url.unwrap_or_else(|| {
            if self.kind == ProviderKind::Openai {
                "https://api.openai.com/v1/".to_owned()
            } else {
                "https://api.anthropic.com/".to_owned()
            }
        });
        let endpoint = provider_url(&endpoint, "core.provider.base_url")?;
        let origin = endpoint.origin().ascii_serialization();
        if let Some(expected) = self.credential_origin {
            let expected = provider_url(&expected, "core.provider.credential_origin")?;
            if expected.path() != "/" || expected.origin() != endpoint.origin() {
                return validation(
                    "core.provider.credential_origin",
                    "must name exactly the endpoint origin, without a path",
                );
            }
        }
        Ok(ProviderConfig {
            kind: self.kind,
            model: Some(model),
            model_aliases,
            api_key,
            base_url: Some(endpoint.to_string()),
            credential_origin: Some(origin),
            request_timeout_ms: Some(timeout),
            completion_api: if self.kind == ProviderKind::Openai {
                Some(
                    self.completion_api
                        .unwrap_or(ProviderCompletionApi::ChatCompletions),
                )
            } else {
                None
            },
            max_observed_turn_tokens: self.max_observed_turn_tokens,
        })
    }
}

fn valid_model_identifier(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 256
        && !value
            .chars()
            .any(|character| character.is_control() || character.is_whitespace())
}

fn provider_url(value: &str, path: &str) -> Result<Url, ConfigError> {
    if value.len() > 2048 {
        return validation(path, "provider URL exceeds 2048 bytes");
    }
    require_url(value, path, &["https", "http"])?;
    let endpoint = Url::parse(value).map_err(|_| ConfigError::Validation {
        path: path.to_owned(),
        message: "invalid provider URL".to_owned(),
    })?;
    if endpoint.query().is_some()
        || value.contains('\\')
        || value
            .chars()
            .any(|character| character.is_control() || character.is_whitespace())
        || value.split('/').any(|part| matches!(part, "." | ".."))
        || (endpoint.scheme() == "http"
            && !match endpoint.host() {
                Some(url::Host::Ipv4(address)) => address.is_loopback(),
                Some(url::Host::Ipv6(address)) => address.is_loopback(),
                _ => false,
            })
    {
        return validation(
            path,
            "requires HTTPS or literal loopback HTTP without query, whitespace or ambiguous paths",
        );
    }
    Ok(endpoint)
}

impl From<&ProviderConfig> for ProviderWire {
    fn from(config: &ProviderConfig) -> Self {
        Self {
            kind: config.kind,
            model: config.model.clone(),
            model_aliases: (!config.model_aliases.is_empty()).then(|| {
                config
                    .model_aliases
                    .iter()
                    .map(|entry| ModelAliasWire {
                        alias: entry.alias.clone(),
                        model: entry.model.clone(),
                    })
                    .collect()
            }),
            api_key: config.api_key.as_ref().map(secret_string),
            base_url: config.base_url.clone(),
            credential_origin: config.credential_origin.clone(),
            request_timeout_ms: config.request_timeout_ms,
            completion_api: config.completion_api,
            max_observed_turn_tokens: config.max_observed_turn_tokens,
        }
    }
}

#[derive(Clone, Debug, Default, Deserialize, JsonSchema, Serialize)]
#[serde(default, deny_unknown_fields)]
pub(crate) struct LegacyWire {
    pub(crate) skills: LegacySkillsWire,
}

#[derive(Clone, Debug, Deserialize, JsonSchema, Serialize)]
#[serde(default, deny_unknown_fields)]
pub(crate) struct LegacySkillsWire {
    pub(crate) source_urls: Vec<String>,
    pub(crate) execution_timeout_ms: u64,
    pub(crate) allowed_domains: Vec<String>,
}

impl Default for LegacySkillsWire {
    fn default() -> Self {
        Self {
            source_urls: Vec::new(),
            execution_timeout_ms: 30_000,
            allowed_domains: Vec::new(),
        }
    }
}

#[derive(Clone, Debug, Default, Deserialize, JsonSchema, Serialize)]
#[serde(default, deny_unknown_fields)]
pub(crate) struct UpdatesWire {
    pub(crate) enabled: bool,
}

#[derive(Clone, Debug, Default, Deserialize, JsonSchema, Serialize)]
#[serde(default, deny_unknown_fields)]
pub(crate) struct AdminWire {
    pub(crate) bearer_token: Option<String>,
}

#[derive(Clone, Debug, Default, Deserialize, JsonSchema, Serialize)]
#[serde(default, deny_unknown_fields)]
pub(crate) struct NetworkWire {
    pub(crate) proxy_url: Option<String>,
}

impl EnvelopeWire {
    pub(crate) fn validate(self) -> Result<ConfigSnapshot, ConfigError> {
        if self.schema_version != CONFIG_SCHEMA_VERSION {
            return Err(ConfigError::UnsupportedVersion {
                found: self.schema_version,
                supported: CONFIG_SCHEMA_VERSION,
            });
        }

        let provider = self.core.provider.map(ProviderWire::validate).transpose()?;
        let auth = AuthConfig {
            github_pat: secret(self.core.auth.github.pat, "core.auth.github.pat")?,
            device_enabled: self.core.auth.github.device.enabled,
            device_client_id: nonempty_optional(
                self.core.auth.github.device.client_id,
                "core.auth.github.device.client_id",
            )?,
        };
        if auth.device_enabled && auth.device_client_id.is_none() {
            return validation(
                "core.auth.github.device.client_id",
                "is required when device flow is enabled",
            );
        }
        if !auth.device_enabled
            && auth.github_pat.is_none()
            && provider
                .as_ref()
                .is_none_or(|provider| provider.kind == ProviderKind::Copilot)
        {
            return validation(
                "core.auth.github.pat",
                "is required when device flow is disabled",
            );
        }

        require_url(
            &self.core.role.source_url,
            "core.role.source_url",
            &["http", "https"],
        )?;
        validate_range(
            self.core.channels.telegram.poll_interval_ms,
            500,
            60_000,
            "core.channels.telegram.poll_interval_ms",
        )?;
        if self.core.channels.discord.gateway_url.is_empty() {
            return validation("core.channels.discord.gateway_url", "must not be empty");
        }
        if self.core.channels.discord.gateway_intents == 0 {
            return validation(
                "core.channels.discord.gateway_intents",
                "must be at least 1",
            );
        }
        if !self.core.channels.whatsapp.webhook_path.starts_with('/') {
            return validation("core.channels.whatsapp.webhook_path", "must start with '/'");
        }
        if self.core.server.teams_rate_limit_per_minute == 0 {
            return validation(
                "core.server.teams_rate_limit_per_minute",
                "must be at least 1",
            );
        }
        if self.core.server.port == 0 {
            return validation("core.server.port", "must be from 1 through 65535");
        }
        if self.core.server.public_domain.is_empty() {
            return validation("core.server.public_domain", "must not be empty");
        }
        if self.core.sessions.ttl_ms < 1_000 {
            return validation("core.sessions.ttl_ms", "must be at least 1000");
        }
        if self.core.sessions.max_entries == 0 {
            return validation("core.sessions.max_entries", "must be at least 1");
        }
        if self.core.copilot.default_model.is_empty() {
            return validation("core.copilot.default_model", "must not be empty");
        }
        if self.core.copilot.request_timeout_ms < 1_000 {
            return validation("core.copilot.request_timeout_ms", "must be at least 1000");
        }
        if self.core.legacy.skills.execution_timeout_ms < 100 {
            return validation(
                "core.legacy.skills.execution_timeout_ms",
                "must be at least 100",
            );
        }
        for (index, source_url) in self.core.legacy.skills.source_urls.iter().enumerate() {
            require_url(
                source_url,
                &format!("core.legacy.skills.source_urls[{index}]"),
                &["http", "https"],
            )?;
        }

        let teams = TeamsConfig {
            enabled: self.core.channels.teams.enabled,
            app_id: nonempty_optional(
                self.core.channels.teams.app_id,
                "core.channels.teams.app_id",
            )?,
            app_password: secret(
                self.core.channels.teams.app_password,
                "core.channels.teams.app_password",
            )?,
        };
        require_channel_fields(
            teams.enabled,
            [
                ("core.channels.teams.app_id", teams.app_id.is_some()),
                (
                    "core.channels.teams.app_password",
                    teams.app_password.is_some(),
                ),
            ],
        )?;

        let telegram = TelegramConfig {
            enabled: self.core.channels.telegram.enabled,
            bot_token: secret(
                self.core.channels.telegram.bot_token,
                "core.channels.telegram.bot_token",
            )?,
            poll_interval_ms: self.core.channels.telegram.poll_interval_ms,
        };
        require_channel_fields(
            telegram.enabled,
            [(
                "core.channels.telegram.bot_token",
                telegram.bot_token.is_some(),
            )],
        )?;

        let discord = DiscordConfig {
            enabled: self.core.channels.discord.enabled,
            bot_token: secret(
                self.core.channels.discord.bot_token,
                "core.channels.discord.bot_token",
            )?,
            gateway_url: self.core.channels.discord.gateway_url,
            gateway_intents: self.core.channels.discord.gateway_intents,
        };
        require_channel_fields(
            discord.enabled,
            [(
                "core.channels.discord.bot_token",
                discord.bot_token.is_some(),
            )],
        )?;

        let whatsapp = WhatsappConfig {
            enabled: self.core.channels.whatsapp.enabled,
            verify_token: secret(
                self.core.channels.whatsapp.verify_token,
                "core.channels.whatsapp.verify_token",
            )?,
            access_token: secret(
                self.core.channels.whatsapp.access_token,
                "core.channels.whatsapp.access_token",
            )?,
            app_secret: secret(
                self.core.channels.whatsapp.app_secret,
                "core.channels.whatsapp.app_secret",
            )?,
            phone_number_id: nonempty_optional(
                self.core.channels.whatsapp.phone_number_id,
                "core.channels.whatsapp.phone_number_id",
            )?,
            webhook_path: self.core.channels.whatsapp.webhook_path,
        };
        require_channel_fields(
            whatsapp.enabled,
            [
                (
                    "core.channels.whatsapp.verify_token",
                    whatsapp.verify_token.is_some(),
                ),
                (
                    "core.channels.whatsapp.access_token",
                    whatsapp.access_token.is_some(),
                ),
                (
                    "core.channels.whatsapp.phone_number_id",
                    whatsapp.phone_number_id.is_some(),
                ),
            ],
        )?;

        Ok(ConfigSnapshot {
            core: CoreConfig {
                auth,
                role: RoleConfig {
                    source_url: self.core.role.source_url,
                },
                channels: ChannelsConfig {
                    teams,
                    telegram,
                    discord,
                    whatsapp,
                },
                server: ServerConfig {
                    port: self.core.server.port,
                    teams_rate_limit_per_minute: self.core.server.teams_rate_limit_per_minute,
                    public_domain: self.core.server.public_domain,
                    trust_proxy: self.core.server.trust_proxy,
                },
                logging: LoggingConfig {
                    level: self.core.logging.level.into(),
                    development_transport: self.core.logging.development_transport,
                },
                sessions: SessionsConfig {
                    ttl_ms: self.core.sessions.ttl_ms,
                    max_entries: self.core.sessions.max_entries,
                },
                copilot: CopilotConfig {
                    default_model: self.core.copilot.default_model,
                    request_timeout_ms: self.core.copilot.request_timeout_ms,
                },
                provider,
                legacy_skills: LegacySkillsConfig {
                    source_urls: self.core.legacy.skills.source_urls,
                    execution_timeout_ms: self.core.legacy.skills.execution_timeout_ms,
                    allowed_domains: self.core.legacy.skills.allowed_domains,
                },
                updates: UpdatesConfig {
                    enabled: self.core.updates.enabled,
                },
                admin: AdminConfig {
                    bearer_token: secret(self.core.admin.bearer_token, "core.admin.bearer_token")?,
                },
                network: NetworkConfig {
                    proxy_url: secret(self.core.network.proxy_url, "core.network.proxy_url")?,
                },
            },
        })
    }
}

impl From<&ConfigSnapshot> for EnvelopeWire {
    fn from(snapshot: &ConfigSnapshot) -> Self {
        let core = &snapshot.core;
        Self {
            schema_version: CONFIG_SCHEMA_VERSION,
            core: CoreWire {
                auth: AuthWire {
                    github: GithubAuthWire {
                        pat: core.auth.github_pat.as_ref().map(secret_string),
                        device: DeviceAuthWire {
                            enabled: core.auth.device_enabled,
                            client_id: core.auth.device_client_id.clone(),
                        },
                    },
                },
                role: RoleWire {
                    source_url: core.role.source_url.clone(),
                },
                channels: ChannelsWire {
                    teams: TeamsWire {
                        enabled: core.channels.teams.enabled,
                        app_id: core.channels.teams.app_id.clone(),
                        app_password: core.channels.teams.app_password.as_ref().map(secret_string),
                    },
                    telegram: TelegramWire {
                        enabled: core.channels.telegram.enabled,
                        bot_token: core.channels.telegram.bot_token.as_ref().map(secret_string),
                        poll_interval_ms: core.channels.telegram.poll_interval_ms,
                    },
                    discord: DiscordWire {
                        enabled: core.channels.discord.enabled,
                        bot_token: core.channels.discord.bot_token.as_ref().map(secret_string),
                        gateway_url: core.channels.discord.gateway_url.clone(),
                        gateway_intents: core.channels.discord.gateway_intents,
                    },
                    whatsapp: WhatsappWire {
                        enabled: core.channels.whatsapp.enabled,
                        verify_token: core
                            .channels
                            .whatsapp
                            .verify_token
                            .as_ref()
                            .map(secret_string),
                        access_token: core
                            .channels
                            .whatsapp
                            .access_token
                            .as_ref()
                            .map(secret_string),
                        app_secret: core
                            .channels
                            .whatsapp
                            .app_secret
                            .as_ref()
                            .map(secret_string),
                        phone_number_id: core.channels.whatsapp.phone_number_id.clone(),
                        webhook_path: core.channels.whatsapp.webhook_path.clone(),
                    },
                },
                server: ServerWire {
                    port: core.server.port,
                    teams_rate_limit_per_minute: core.server.teams_rate_limit_per_minute,
                    public_domain: core.server.public_domain.clone(),
                    trust_proxy: core.server.trust_proxy,
                },
                logging: LoggingWire {
                    level: core.logging.level.into(),
                    development_transport: core.logging.development_transport,
                },
                sessions: SessionsWire {
                    ttl_ms: core.sessions.ttl_ms,
                    max_entries: core.sessions.max_entries,
                },
                copilot: CopilotWire {
                    default_model: core.copilot.default_model.clone(),
                    request_timeout_ms: core.copilot.request_timeout_ms,
                },
                provider: core.provider.as_ref().map(ProviderWire::from),
                legacy: LegacyWire {
                    skills: LegacySkillsWire {
                        source_urls: core.legacy_skills.source_urls.clone(),
                        execution_timeout_ms: core.legacy_skills.execution_timeout_ms,
                        allowed_domains: core.legacy_skills.allowed_domains.clone(),
                    },
                },
                updates: UpdatesWire {
                    enabled: core.updates.enabled,
                },
                admin: AdminWire {
                    bearer_token: core.admin.bearer_token.as_ref().map(secret_string),
                },
                network: NetworkWire {
                    proxy_url: core.network.proxy_url.as_ref().map(secret_string),
                },
            },
        }
    }
}

impl From<LogLevelWire> for LogLevel {
    fn from(value: LogLevelWire) -> Self {
        match value {
            LogLevelWire::Trace => Self::Trace,
            LogLevelWire::Debug => Self::Debug,
            LogLevelWire::Info => Self::Info,
            LogLevelWire::Warn => Self::Warn,
            LogLevelWire::Error => Self::Error,
            LogLevelWire::Fatal => Self::Fatal,
        }
    }
}

impl From<LogLevel> for LogLevelWire {
    fn from(value: LogLevel) -> Self {
        match value {
            LogLevel::Trace => Self::Trace,
            LogLevel::Debug => Self::Debug,
            LogLevel::Info => Self::Info,
            LogLevel::Warn => Self::Warn,
            LogLevel::Error => Self::Error,
            LogLevel::Fatal => Self::Fatal,
        }
    }
}

fn secret(value: Option<String>, path: &str) -> Result<Option<SecretRef>, ConfigError> {
    value
        .map(|value| {
            SecretRef::parse(value).map_err(|message| ConfigError::Validation {
                path: path.to_owned(),
                message: message.to_owned(),
            })
        })
        .transpose()
}

fn secret_string(reference: &SecretRef) -> String {
    reference.as_str().to_owned()
}

fn nonempty_optional(value: Option<String>, path: &str) -> Result<Option<String>, ConfigError> {
    match value {
        Some(value) if value.trim().is_empty() => validation(path, "must not be empty"),
        value => Ok(value),
    }
}

fn require_url(value: &str, path: &str, schemes: &[&str]) -> Result<(), ConfigError> {
    let url = Url::parse(value).map_err(|error| ConfigError::Validation {
        path: path.to_owned(),
        message: format!("must be a valid absolute URL: {error}"),
    })?;
    if !schemes.contains(&url.scheme()) {
        return validation(
            path,
            &format!("scheme must be one of {}", schemes.join(", ")),
        );
    }
    if url.host_str().is_none_or(str::is_empty) {
        return validation(path, "host must not be empty");
    }
    if !url.username().is_empty() || url.password().is_some() {
        return validation(path, "userinfo is not allowed");
    }
    if url.fragment().is_some() {
        return validation(path, "fragment is not allowed");
    }
    if url.port() == Some(0) {
        return validation(path, "port must be from 1 through 65535");
    }
    Ok(())
}

fn validate_range(value: u64, minimum: u64, maximum: u64, path: &str) -> Result<(), ConfigError> {
    if (minimum..=maximum).contains(&value) {
        Ok(())
    } else {
        validation(path, &format!("must be from {minimum} through {maximum}"))
    }
}

fn require_channel_fields<const N: usize>(
    enabled: bool,
    fields: [(&str, bool); N],
) -> Result<(), ConfigError> {
    if !enabled {
        return Ok(());
    }
    for (path, present) in fields {
        if !present {
            return validation(path, "is required when the channel is enabled");
        }
    }
    Ok(())
}

fn validation<T>(path: &str, message: &str) -> Result<T, ConfigError> {
    Err(ConfigError::Validation {
        path: path.to_owned(),
        message: message.to_owned(),
    })
}

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::error::ConfigError;
use crate::model::{
    AdminConfig, AuthConfig, CONFIG_SCHEMA_VERSION, ChannelsConfig, ConfigSnapshot, CopilotConfig,
    CoreConfig, DiscordConfig, LegacySkillsConfig, LogLevel, LoggingConfig, NetworkConfig,
    RoleConfig, SecretRef, ServerConfig, SessionsConfig, TeamsConfig, TelegramConfig,
    UpdatesConfig, WhatsappConfig,
};

#[derive(Clone, Debug, Deserialize, JsonSchema, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct EnvelopeWire {
    pub(crate) schema_version: u32,
    pub(crate) core: CoreWire,
}

#[derive(Clone, Debug, Deserialize, JsonSchema, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct CoreWire {
    pub(crate) auth: AuthWire,
    pub(crate) role: RoleWire,
    pub(crate) channels: ChannelsWire,
    pub(crate) server: ServerWire,
    pub(crate) logging: LoggingWire,
    pub(crate) sessions: SessionsWire,
    pub(crate) copilot: CopilotWire,
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
    pub(crate) phone_number_id: Option<String>,
    pub(crate) webhook_path: String,
}

impl Default for WhatsappWire {
    fn default() -> Self {
        Self {
            enabled: false,
            verify_token: None,
            access_token: None,
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
        if !auth.device_enabled && auth.github_pat.is_none() {
            return validation(
                "core.auth.github.pat",
                "is required when device flow is disabled",
            );
        }

        require_http_url(&self.core.role.source_url, "core.role.source_url")?;
        validate_range(
            self.core.channels.telegram.poll_interval_ms,
            500,
            60_000,
            "core.channels.telegram.poll_interval_ms",
        )?;
        if self.core.channels.discord.gateway_url.trim().is_empty() {
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
            require_http_url(
                source_url,
                &format!("core.legacy.skills.source_urls[{index}]"),
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
                        pat: secret_string(core.auth.github_pat.as_ref()),
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
                        app_password: secret_string(core.channels.teams.app_password.as_ref()),
                    },
                    telegram: TelegramWire {
                        enabled: core.channels.telegram.enabled,
                        bot_token: secret_string(core.channels.telegram.bot_token.as_ref()),
                        poll_interval_ms: core.channels.telegram.poll_interval_ms,
                    },
                    discord: DiscordWire {
                        enabled: core.channels.discord.enabled,
                        bot_token: secret_string(core.channels.discord.bot_token.as_ref()),
                        gateway_url: core.channels.discord.gateway_url.clone(),
                        gateway_intents: core.channels.discord.gateway_intents,
                    },
                    whatsapp: WhatsappWire {
                        enabled: core.channels.whatsapp.enabled,
                        verify_token: secret_string(core.channels.whatsapp.verify_token.as_ref()),
                        access_token: secret_string(core.channels.whatsapp.access_token.as_ref()),
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
                    bearer_token: secret_string(core.admin.bearer_token.as_ref()),
                },
                network: NetworkWire {
                    proxy_url: secret_string(core.network.proxy_url.as_ref()),
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

fn secret_string(value: Option<&SecretRef>) -> Option<String> {
    value.map(|reference| reference.as_str().to_owned())
}

fn nonempty_optional(value: Option<String>, path: &str) -> Result<Option<String>, ConfigError> {
    match value {
        Some(value) if value.trim().is_empty() => validation(path, "must not be empty"),
        value => Ok(value),
    }
}

fn require_http_url(value: &str, path: &str) -> Result<(), ConfigError> {
    if value
        .chars()
        .any(|character| character.is_whitespace() || character.is_control())
    {
        return validation(path, "must be an absolute HTTP(S) URL");
    }
    let authority_and_path = value
        .strip_prefix("http://")
        .or_else(|| value.strip_prefix("https://"));
    let Some(authority_and_path) = authority_and_path else {
        return validation(path, "must be an absolute HTTP(S) URL");
    };
    let authority = authority_and_path
        .split(['/', '?', '#'])
        .next()
        .unwrap_or_default();
    if authority.is_empty() || authority.starts_with(':') || authority.ends_with(':') {
        return validation(path, "must be an absolute HTTP(S) URL");
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

use std::error::Error;
use std::fmt::{self, Debug, Display, Formatter};

use serde::{Serialize, Serializer};

/// The only configuration schema version currently implemented.
pub const CONFIG_SCHEMA_VERSION: u32 = 1;

/// A configuration domain whose behavior is implemented by this foundation.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum ConfigDomain {
    /// GitHub authentication references and device-flow settings.
    Auth,
    /// Remote GTA legacy role source.
    Role,
    /// GTA legacy messaging-channel settings.
    Channels,
    /// Headless server settings.
    Server,
    /// Logging settings.
    Logging,
    /// In-memory legacy session limits.
    Sessions,
    /// Copilot provider settings.
    Copilot,
    /// GTA legacy skill migration settings.
    LegacySkills,
    /// Signed-update policy switch.
    Updates,
    /// Administrator route authorization.
    Admin,
    /// Outbound network settings.
    Network,
}

/// A non-secret reference to secret material.
#[derive(Clone, Eq, PartialEq)]
pub struct SecretRef(String);

impl SecretRef {
    /// Creates a reference to an environment variable without retaining its value.
    ///
    /// # Errors
    ///
    /// Returns the message `"environment name must match [A-Za-z_][A-Za-z0-9_]*"`
    /// when `name` is empty, starts with a digit, or contains any character
    /// outside that set. The rejected name is deliberately not echoed back,
    /// because callers commonly pass the secret itself here by mistake.
    pub fn environment(name: impl Into<String>) -> Result<Self, &'static str> {
        let name = name.into();
        if !is_environment_name(&name) {
            return Err("environment name must match [A-Za-z_][A-Za-z0-9_]*");
        }
        Ok(Self(format!("env:{name}")))
    }

    /// Parses a persisted reference. Plaintext values are rejected.
    ///
    /// # Errors
    ///
    /// An `env:` value is forwarded to [`Self::environment`] and fails with its
    /// message when the name is malformed. Any other value must be a
    /// `keyring://`, `service://`, or `fd://` platform reference; anything else,
    /// including bare plaintext, fails with
    /// `"only env:<NAME> secret references are supported"`. Platform references
    /// are additionally rejected when they contain `?`, `#`, `@`, `%`, control
    /// characters, or surrounding whitespace, when a `keyring`/`service`
    /// reference is not exactly `<service>/<account>` with each part 1..=128
    /// alphanumeric-leading characters, or when an `fd` reference is not a
    /// canonical non-negative decimal descriptor. The value is never included in
    /// the message, because it may be the secret.
    pub fn parse(value: impl Into<String>) -> Result<Self, &'static str> {
        let value = value.into();
        if let Some(name) = value.strip_prefix("env:") {
            return Self::environment(name);
        }
        if valid_platform_secret_reference(&value) {
            return Ok(Self(value));
        }
        Err("only env:<NAME> secret references are supported")
    }

    /// Returns the reference string, never the referenced secret.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl Display for SecretRef {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter.write_str("secret-ref:[REDACTED]")
    }
}

impl Debug for SecretRef {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter.write_str("SecretRef([REDACTED])")
    }
}

impl Serialize for SecretRef {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str("secret-ref:[REDACTED]")
    }
}

fn is_environment_name(value: &str) -> bool {
    let mut chars = value.chars();
    matches!(chars.next(), Some('_' | 'A'..='Z' | 'a'..='z'))
        && chars.all(|character| matches!(character, '_' | 'A'..='Z' | 'a'..='z' | '0'..='9'))
}

fn valid_platform_secret_reference(value: &str) -> bool {
    let Some((scheme, identifier)) = value.split_once("://") else {
        return false;
    };
    if !matches!(scheme, "keyring" | "service" | "fd")
        || identifier.is_empty()
        || value.contains(['?', '#', '@', '%'])
        || value.trim() != value
        || value.chars().any(char::is_control)
    {
        return false;
    }
    if scheme == "fd" {
        return identifier.bytes().all(|byte| byte.is_ascii_digit())
            && (identifier == "0" || !identifier.starts_with('0'));
    }
    let mut parts = identifier.split('/');
    let first = parts.next();
    let second = parts.next();
    first.is_some_and(valid_secret_identifier)
        && second.is_some_and(valid_secret_identifier)
        && parts.next().is_none()
}

fn valid_secret_identifier(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 128
        && value.bytes().enumerate().all(|(index, byte)| {
            byte.is_ascii_alphanumeric() || (index > 0 && matches!(byte, b'.' | b'_' | b'-'))
        })
}

/// Borrowed secret bytes passed directly to a platform secret store.
///
/// Formatting and serialization are always redacted. Only secret-store
/// implementations can request the plaintext through [`Self::expose`].
pub struct SecretMaterial<'a>(&'a str);

impl<'a> SecretMaterial<'a> {
    /// Wraps plaintext for immediate transfer to a secret store.
    #[must_use]
    pub const fn new(value: &'a str) -> Self {
        Self(value)
    }

    /// Exposes plaintext to the platform store implementation.
    #[must_use]
    pub const fn expose(&self) -> &'a str {
        self.0
    }
}

impl Debug for SecretMaterial<'_> {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter.write_str("SecretMaterial([REDACTED])")
    }
}

impl Display for SecretMaterial<'_> {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter.write_str("[REDACTED]")
    }
}

impl Serialize for SecretMaterial<'_> {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str("[REDACTED]")
    }
}

/// Platform adapter that persists plaintext and returns only a reference.
pub trait PlatformSecretStore {
    /// Backend error that must not include the secret bytes.
    type Error: Error + Send + Sync + 'static;

    /// Stores one value under a non-secret logical label.
    ///
    /// # Errors
    ///
    /// Returns the implementation's [`Self::Error`] when the platform backend
    /// refuses the write, for example because the keychain is locked, the
    /// caller is not authorized, or `label` collides with an existing entry.
    /// Implementations must not include the plaintext in that error.
    fn store(&mut self, label: &str, secret: SecretMaterial<'_>) -> Result<SecretRef, Self::Error>;
}

/// Stores secret material without retaining it in configuration.
///
/// # Errors
///
/// Returns [`SecretStoreError::InvalidLabel`] when `label` is empty, longer than
/// 128 bytes, or contains anything other than ASCII alphanumerics, `.`, `_`, and
/// `-`; the backend is not called in that case. Returns
/// [`SecretStoreError::Backend`] wrapping the platform failure when the store
/// itself rejects the write. Neither variant carries `plaintext`.
pub fn store_secret<S: PlatformSecretStore>(
    store: &mut S,
    label: &str,
    plaintext: &str,
) -> Result<SecretRef, SecretStoreError<S::Error>> {
    if label.is_empty()
        || label.len() > 128
        || !label
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-'))
    {
        return Err(SecretStoreError::InvalidLabel);
    }
    store
        .store(label, SecretMaterial::new(plaintext))
        .map_err(SecretStoreError::Backend)
}

/// Failure to route secret material to a platform store.
#[derive(Debug)]
pub enum SecretStoreError<E> {
    /// The logical label was empty, too long, or malformed.
    InvalidLabel,
    /// The platform backend rejected the write.
    Backend(E),
}

impl<E: Display> Display for SecretStoreError<E> {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidLabel => formatter.write_str("invalid platform secret label"),
            Self::Backend(error) => write!(formatter, "platform secret store failed: {error}"),
        }
    }
}

impl<E: Error + 'static> Error for SecretStoreError<E> {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::InvalidLabel => None,
            Self::Backend(error) => Some(error),
        }
    }
}

/// A fully parsed and validated immutable configuration.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ConfigSnapshot {
    pub(crate) core: CoreConfig,
}

impl ConfigSnapshot {
    /// Returns the validated core settings.
    #[must_use]
    pub const fn core(&self) -> &CoreConfig {
        &self.core
    }
}

/// Implemented core configuration domains.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CoreConfig {
    pub(crate) auth: AuthConfig,
    pub(crate) role: RoleConfig,
    pub(crate) channels: ChannelsConfig,
    pub(crate) server: ServerConfig,
    pub(crate) logging: LoggingConfig,
    pub(crate) sessions: SessionsConfig,
    pub(crate) copilot: CopilotConfig,
    pub(crate) legacy_skills: LegacySkillsConfig,
    pub(crate) updates: UpdatesConfig,
    pub(crate) admin: AdminConfig,
    pub(crate) network: NetworkConfig,
}

impl CoreConfig {
    /// Returns GitHub authentication configuration.
    #[must_use]
    pub const fn auth(&self) -> &AuthConfig {
        &self.auth
    }

    /// Returns role-source configuration.
    #[must_use]
    pub const fn role(&self) -> &RoleConfig {
        &self.role
    }

    /// Returns channel configuration.
    #[must_use]
    pub const fn channels(&self) -> &ChannelsConfig {
        &self.channels
    }

    /// Returns server configuration.
    #[must_use]
    pub const fn server(&self) -> &ServerConfig {
        &self.server
    }

    /// Returns logging configuration.
    #[must_use]
    pub const fn logging(&self) -> &LoggingConfig {
        &self.logging
    }

    /// Returns session configuration.
    #[must_use]
    pub const fn sessions(&self) -> &SessionsConfig {
        &self.sessions
    }

    /// Returns provider configuration.
    #[must_use]
    pub const fn copilot(&self) -> &CopilotConfig {
        &self.copilot
    }

    /// Returns GTA legacy skill migration configuration.
    #[must_use]
    pub const fn legacy_skills(&self) -> &LegacySkillsConfig {
        &self.legacy_skills
    }

    /// Returns update-policy configuration.
    #[must_use]
    pub const fn updates(&self) -> &UpdatesConfig {
        &self.updates
    }

    /// Returns administrator configuration.
    #[must_use]
    pub const fn admin(&self) -> &AdminConfig {
        &self.admin
    }

    /// Returns outbound-network configuration.
    #[must_use]
    pub const fn network(&self) -> &NetworkConfig {
        &self.network
    }
}

/// GitHub authentication settings.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AuthConfig {
    pub(crate) github_pat: Option<SecretRef>,
    pub(crate) device_enabled: bool,
    pub(crate) device_client_id: Option<String>,
}

impl AuthConfig {
    /// Returns the personal-access-token reference.
    #[must_use]
    pub const fn github_pat(&self) -> Option<&SecretRef> {
        self.github_pat.as_ref()
    }

    /// Reports whether GitHub device flow is enabled.
    #[must_use]
    pub const fn device_enabled(&self) -> bool {
        self.device_enabled
    }

    /// Returns the device-flow client identifier.
    #[must_use]
    pub fn device_client_id(&self) -> Option<&str> {
        self.device_client_id.as_deref()
    }
}

/// Remote role source settings.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RoleConfig {
    pub(crate) source_url: String,
}

impl RoleConfig {
    /// Returns the absolute HTTP(S) role URL.
    #[must_use]
    pub fn source_url(&self) -> &str {
        &self.source_url
    }
}

/// Supported GTA legacy messaging channels.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ChannelsConfig {
    pub(crate) teams: TeamsConfig,
    pub(crate) telegram: TelegramConfig,
    pub(crate) discord: DiscordConfig,
    pub(crate) whatsapp: WhatsappConfig,
}

impl ChannelsConfig {
    /// Returns Microsoft Teams settings.
    #[must_use]
    pub const fn teams(&self) -> &TeamsConfig {
        &self.teams
    }

    /// Returns Telegram settings.
    #[must_use]
    pub const fn telegram(&self) -> &TelegramConfig {
        &self.telegram
    }

    /// Returns Discord settings.
    #[must_use]
    pub const fn discord(&self) -> &DiscordConfig {
        &self.discord
    }

    /// Returns `WhatsApp` settings.
    #[must_use]
    pub const fn whatsapp(&self) -> &WhatsappConfig {
        &self.whatsapp
    }
}

/// Microsoft Teams channel settings.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TeamsConfig {
    pub(crate) enabled: bool,
    pub(crate) app_id: Option<String>,
    pub(crate) app_password: Option<SecretRef>,
}

impl TeamsConfig {
    /// Reports whether the channel is enabled.
    #[must_use]
    pub const fn enabled(&self) -> bool {
        self.enabled
    }
}

/// Telegram channel settings.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TelegramConfig {
    pub(crate) enabled: bool,
    pub(crate) bot_token: Option<SecretRef>,
    pub(crate) poll_interval_ms: u64,
}

impl TelegramConfig {
    /// Reports whether the channel is enabled.
    #[must_use]
    pub const fn enabled(&self) -> bool {
        self.enabled
    }

    /// Returns the polling interval in milliseconds.
    #[must_use]
    pub const fn poll_interval_ms(&self) -> u64 {
        self.poll_interval_ms
    }
}

/// Discord channel settings.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DiscordConfig {
    pub(crate) enabled: bool,
    pub(crate) bot_token: Option<SecretRef>,
    pub(crate) gateway_url: String,
    pub(crate) gateway_intents: u64,
}

impl DiscordConfig {
    /// Reports whether the channel is enabled.
    #[must_use]
    pub const fn enabled(&self) -> bool {
        self.enabled
    }
}

/// `WhatsApp` channel settings.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct WhatsappConfig {
    pub(crate) enabled: bool,
    pub(crate) verify_token: Option<SecretRef>,
    pub(crate) access_token: Option<SecretRef>,
    pub(crate) phone_number_id: Option<String>,
    pub(crate) webhook_path: String,
}

impl WhatsappConfig {
    /// Reports whether the channel is enabled.
    #[must_use]
    pub const fn enabled(&self) -> bool {
        self.enabled
    }
}

/// Headless HTTP server settings.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ServerConfig {
    pub(crate) port: u16,
    pub(crate) teams_rate_limit_per_minute: u32,
    pub(crate) public_domain: String,
    pub(crate) trust_proxy: bool,
}

impl ServerConfig {
    /// Returns the listening port.
    #[must_use]
    pub const fn port(&self) -> u16 {
        self.port
    }

    /// Returns the externally advertised domain.
    #[must_use]
    pub fn public_domain(&self) -> &str {
        &self.public_domain
    }
}

/// Supported logging levels.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum LogLevel {
    /// Trace diagnostics.
    Trace,
    /// Debug diagnostics.
    Debug,
    /// Informational messages.
    Info,
    /// Warnings.
    Warn,
    /// Errors.
    Error,
    /// Fatal errors.
    Fatal,
}

/// Logging settings.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LoggingConfig {
    pub(crate) level: LogLevel,
    pub(crate) development_transport: bool,
}

impl LoggingConfig {
    /// Returns the configured level.
    #[must_use]
    pub const fn level(&self) -> LogLevel {
        self.level
    }
}

/// Legacy in-memory session limits.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SessionsConfig {
    pub(crate) ttl_ms: u64,
    pub(crate) max_entries: usize,
}

/// Copilot provider settings implemented by the Rust provider boundary.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CopilotConfig {
    pub(crate) default_model: String,
    pub(crate) request_timeout_ms: u64,
}

impl CopilotConfig {
    /// Returns the default provider model identifier.
    #[must_use]
    pub fn default_model(&self) -> &str {
        &self.default_model
    }
}

/// Legacy skill migration settings, not a JavaScript execution host.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LegacySkillsConfig {
    pub(crate) source_urls: Vec<String>,
    pub(crate) execution_timeout_ms: u64,
    pub(crate) allowed_domains: Vec<String>,
}

/// Signed-update policy settings.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct UpdatesConfig {
    pub(crate) enabled: bool,
}

/// Administrator route settings.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AdminConfig {
    pub(crate) bearer_token: Option<SecretRef>,
}

/// Outbound network settings.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NetworkConfig {
    pub(crate) proxy_url: Option<SecretRef>,
}

impl NetworkConfig {
    /// Returns the outbound proxy secret reference.
    #[must_use]
    pub const fn proxy_url(&self) -> Option<&SecretRef> {
        self.proxy_url.as_ref()
    }
}

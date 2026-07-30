//! Configuration for the legacy Node-compatible HTTP facade.

use std::fmt::{self, Debug, Formatter};
use std::time::Duration;

use ring::hmac;
use serde::ser::SerializeStruct;
use serde::{Serialize, Serializer};
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;

/// Enabled legacy channel routes and health metadata.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct LegacyChannelStatus {
    enabled: u8,
}

impl LegacyChannelStatus {
    const TEAMS: u8 = 1;
    const TELEGRAM: u8 = 1 << 1;
    const DISCORD: u8 = 1 << 2;
    const WHATSAPP: u8 = 1 << 3;

    /// Returns whether the Bot Framework/Teams route is enabled.
    #[must_use]
    pub const fn teams(self) -> bool {
        self.enabled & Self::TEAMS != 0
    }

    /// Returns whether Telegram is enabled in the composed service.
    #[must_use]
    pub const fn telegram(self) -> bool {
        self.enabled & Self::TELEGRAM != 0
    }

    /// Returns whether Discord is enabled in the composed service.
    #[must_use]
    pub const fn discord(self) -> bool {
        self.enabled & Self::DISCORD != 0
    }

    /// Returns whether the `WhatsApp` webhook route is enabled.
    #[must_use]
    pub const fn whatsapp(self) -> bool {
        self.enabled & Self::WHATSAPP != 0
    }

    /// Enables or disables the Bot Framework/Teams route.
    pub const fn set_teams(&mut self, enabled: bool) {
        self.set(Self::TEAMS, enabled);
    }

    /// Enables or disables Telegram health metadata.
    pub const fn set_telegram(&mut self, enabled: bool) {
        self.set(Self::TELEGRAM, enabled);
    }

    /// Enables or disables Discord health metadata.
    pub const fn set_discord(&mut self, enabled: bool) {
        self.set(Self::DISCORD, enabled);
    }

    /// Enables or disables the `WhatsApp` webhook route.
    pub const fn set_whatsapp(&mut self, enabled: bool) {
        self.set(Self::WHATSAPP, enabled);
    }

    const fn set(&mut self, channel: u8, enabled: bool) {
        if enabled {
            self.enabled |= channel;
        } else {
            self.enabled &= !channel;
        }
    }

    pub(crate) const fn any_enabled(self) -> bool {
        self.enabled != 0
    }
}

impl Serialize for LegacyChannelStatus {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let mut status = serializer.serialize_struct("LegacyChannelStatus", 4)?;
        status.serialize_field("teams", &self.teams())?;
        status.serialize_field("telegram", &self.telegram())?;
        status.serialize_field("discord", &self.discord())?;
        status.serialize_field("whatsapp", &self.whatsapp())?;
        status.end()
    }
}

/// Pre-hashed credential protecting the legacy admin routes.
#[derive(Clone)]
pub struct LegacyAdminCredential {
    digest: [u8; 32],
}

impl LegacyAdminCredential {
    /// Hashes an admin token without retaining its plaintext.
    #[must_use]
    pub fn new(token: &str) -> Self {
        Self {
            digest: Sha256::digest(token.as_bytes()).into(),
        }
    }

    pub(crate) fn verifies(&self, token: &str) -> bool {
        let presented: [u8; 32] = Sha256::digest(token.as_bytes()).into();
        bool::from(self.digest.ct_eq(&presented))
    }
}

impl Debug for LegacyAdminCredential {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("LegacyAdminCredential")
            .field("digest", &"[REDACTED]")
            .finish()
    }
}

/// Configured legacy `WhatsApp` verification route.
#[derive(Clone)]
pub struct LegacyWhatsAppConfig {
    webhook_path: String,
    verify_digest: [u8; 32],
    signature_key: hmac::Key,
    phone_number_id: String,
}

impl LegacyWhatsAppConfig {
    /// Creates a verified webhook route.
    ///
    /// # Errors
    ///
    /// Returns [`LegacyConfigError::InvalidWebhookPath`] unless `webhook_path`
    /// is one absolute, query-free path with no Axum capture syntax.
    pub fn new(
        webhook_path: impl Into<String>,
        verify_token: &str,
        app_secret: &str,
        phone_number_id: impl Into<String>,
    ) -> Result<Self, LegacyConfigError> {
        let webhook_path = webhook_path.into();
        if !valid_webhook_path(&webhook_path) {
            return Err(LegacyConfigError::InvalidWebhookPath);
        }
        let phone_number_id = phone_number_id.into();
        if verify_token.is_empty()
            || app_secret.is_empty()
            || phone_number_id.is_empty()
            || !phone_number_id
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-'))
        {
            return Err(LegacyConfigError::InvalidWhatsAppConfiguration);
        }
        Ok(Self {
            webhook_path,
            verify_digest: Sha256::digest(verify_token.as_bytes()).into(),
            signature_key: hmac::Key::new(hmac::HMAC_SHA256, app_secret.as_bytes()),
            phone_number_id,
        })
    }

    /// Returns the exact path registered for both webhook methods.
    #[must_use]
    pub fn webhook_path(&self) -> &str {
        &self.webhook_path
    }

    pub(crate) fn verifies(&self, token: &str) -> bool {
        let presented: [u8; 32] = Sha256::digest(token.as_bytes()).into();
        bool::from(self.verify_digest.ct_eq(&presented))
    }

    pub(crate) fn verifies_signature(&self, payload: &[u8], signature: Option<&str>) -> bool {
        let Some(signature) = signature.and_then(|value| value.strip_prefix("sha256=")) else {
            return false;
        };
        let Some(digest) = decode_sha256(signature) else {
            return false;
        };
        hmac::verify(&self.signature_key, payload, &digest).is_ok()
    }

    pub(crate) fn phone_number_id(&self) -> &str {
        &self.phone_number_id
    }
}

impl Debug for LegacyWhatsAppConfig {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("LegacyWhatsAppConfig")
            .field("webhook_path", &self.webhook_path)
            .field("verify_digest", &"[REDACTED]")
            .field("signature_key", &"[REDACTED]")
            .field("phone_number_id", &self.phone_number_id)
            .finish()
    }
}

fn decode_sha256(value: &str) -> Option<[u8; 32]> {
    if value.len() != 64 {
        return None;
    }
    let mut digest = [0_u8; 32];
    for (index, pair) in value.as_bytes().chunks_exact(2).enumerate() {
        digest[index] = (hex_nibble(pair[0])? << 4) | hex_nibble(pair[1])?;
    }
    Some(digest)
}

const fn hex_nibble(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        b'A'..=b'F' => Some(byte - b'A' + 10),
        _ => None,
    }
}

fn valid_webhook_path(path: &str) -> bool {
    path.starts_with('/')
        && path.len() > 1
        && !path.contains(['?', '#', '{', '}'])
        && !path.chars().any(char::is_whitespace)
        && path
            .split('/')
            .skip(1)
            .all(|segment| !segment.is_empty() && !segment.starts_with([':', '*']))
        && !LEGACY_RESERVED_PATHS.contains(&path)
}

const LEGACY_RESERVED_PATHS: &[&str] = &[
    "/health",
    "/healthz",
    "/ready",
    "/readyz",
    "/auth/device",
    "/chat",
    "/api/messages",
    "/admin/reload",
    "/admin/system",
    "/admin/exec",
];

/// Resource limits for the legacy compatibility facade.
#[derive(Clone, Debug)]
pub struct LegacyHttpLimits {
    /// Maximum JSON body size for chat and channel requests.
    pub body_bytes: usize,
    /// Deadline for receiving a complete request body.
    pub body_timeout: Duration,
    /// Deadline for one runtime, channel, reload, or admin operation.
    pub operation_timeout: Duration,
    /// Maximum number of source IP token buckets retained.
    pub rate_limit_clients: usize,
    /// Inactive token-bucket retention.
    pub rate_limit_idle_timeout: Duration,
    /// Maximum `WhatsApp` messages traversed in one webhook request.
    pub whatsapp_messages: usize,
}

impl Default for LegacyHttpLimits {
    fn default() -> Self {
        Self {
            body_bytes: 256 * 1024,
            body_timeout: Duration::from_secs(30),
            operation_timeout: Duration::from_mins(2),
            rate_limit_clients: 4_096,
            rate_limit_idle_timeout: Duration::from_mins(5),
            whatsapp_messages: 128,
        }
    }
}

/// Complete configuration for the legacy Node-compatible HTTP facade.
#[derive(Clone, Debug)]
pub struct LegacyApiConfig {
    /// Whether GitHub Device Flow is available to unauthenticated callers.
    pub device_flow_enabled: bool,
    /// Enabled channel metadata and conditional route switches.
    pub channels: LegacyChannelStatus,
    /// Default model used when a successful reload does not select one.
    pub default_model: String,
    /// Per-IP Teams request capacity and per-minute refill rate.
    pub teams_rate_limit_per_minute: u32,
    /// Whether the first `x-forwarded-for` entry identifies the Teams caller.
    pub trust_proxy: bool,
    /// Optional credential that enables legacy admin routes.
    pub admin_credential: Option<LegacyAdminCredential>,
    /// Optional `WhatsApp` path and verification credential.
    pub whatsapp: Option<LegacyWhatsAppConfig>,
    /// Request, operation, rate-bucket, and webhook limits.
    pub limits: LegacyHttpLimits,
}

impl Default for LegacyApiConfig {
    fn default() -> Self {
        Self {
            device_flow_enabled: false,
            channels: LegacyChannelStatus::default(),
            default_model: "openclaw".to_owned(),
            teams_rate_limit_per_minute: 60,
            trust_proxy: false,
            admin_credential: None,
            whatsapp: None,
            limits: LegacyHttpLimits::default(),
        }
    }
}

/// Invalid legacy-facade composition.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum LegacyConfigError {
    /// The default model is empty.
    EmptyDefaultModel,
    /// A byte, client, message, or rate capacity is zero.
    ZeroLimit,
    /// The configured `WhatsApp` path is not a safe absolute static path.
    InvalidWebhookPath,
    /// The `WhatsApp` verification, signing, or phone identity is empty or malformed.
    InvalidWhatsAppConfiguration,
    /// Teams is enabled but no Teams adapter was supplied.
    MissingTeamsAdapter,
    /// `WhatsApp` is enabled without both route configuration and an adapter.
    MissingWhatsAppAdapter,
}

impl fmt::Display for LegacyConfigError {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::EmptyDefaultModel => "legacy default model must not be empty",
            Self::ZeroLimit => "legacy HTTP limits and rate capacity must be nonzero",
            Self::InvalidWebhookPath => "legacy WhatsApp webhook path is invalid",
            Self::InvalidWhatsAppConfiguration => {
                "legacy WhatsApp authentication configuration is invalid"
            }
            Self::MissingTeamsAdapter => "Teams is enabled without a Teams adapter",
            Self::MissingWhatsAppAdapter => {
                "WhatsApp is enabled without route configuration and an adapter"
            }
        })
    }
}

impl std::error::Error for LegacyConfigError {}

//! Official channel metadata and Rust-native adapters.
//!
//! Every frozen official channel is registered. [`ImplementationStatus`] keeps
//! registry coverage separate from executable behavior so metadata-only entries
//! cannot be mistaken for working integrations.

use std::collections::VecDeque;
use std::fmt::{self, Debug, Formatter};
use std::io::{Read, Write};
use std::net::TcpStream;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use claw_channel_sdk::{
    Channel, ChannelCredential, ChannelError, ConfigurationError, CredentialBindingError,
    DeliveryAcknowledgement, DeliveryState, InboundMessage, InvalidMessageReason, OutboundMessage,
    ProtocolErrorKind, SecretStoreError, TransportErrorKind, UnsupportedOperation,
};

const CATALOG_PATH: &str = "scripts/lib/official-external-channel-catalog.json";
const TEXT_OUT: &[ChannelCapability] = &[ChannelCapability::OutboundText];
const QA_CAPABILITIES: &[ChannelCapability] = &[
    ChannelCapability::InboundText,
    ChannelCapability::OutboundText,
];
const NO_CAPABILITIES: &[ChannelCapability] = &[];
const ACCESS_TOKEN: &[AuthMode] = &[AuthMode::AccessToken];
const APP_CREDENTIALS: &[AuthMode] = &[AuthMode::AppCredentials];
const BOT_TOKEN: &[AuthMode] = &[AuthMode::BotToken];
const BOT_TOKEN_AND_PASSWORD: &[AuthMode] = &[AuthMode::BotToken, AuthMode::Password];
const BOT_TOKEN_AND_WEBHOOK: &[AuthMode] = &[AuthMode::BotToken, AuthMode::WebhookSecret];
const EXTERNAL_PLUGIN: &[AuthMode] = &[AuthMode::ExternalPlugin];
const LOCAL_SERVICE: &[AuthMode] = &[AuthMode::LocalService];
const NO_AUTH: &[AuthMode] = &[AuthMode::None];
const OAUTH2: &[AuthMode] = &[AuthMode::OAuth2];
const OPTIONAL_PASSWORD: &[AuthMode] = &[AuthMode::OptionalPassword];
const PASSWORD: &[AuthMode] = &[AuthMode::Password];
const PLATFORM_SESSION: &[AuthMode] = &[AuthMode::PlatformSession];
const PRIVATE_KEY: &[AuthMode] = &[AuthMode::PrivateKey];
const PROFILE: &[AuthMode] = &[AuthMode::Profile];
const TOKEN_AND_WEBHOOK: &[AuthMode] = &[AuthMode::AccessToken, AuthMode::WebhookSecret];
const WEBHOOK_URL: &[AuthMode] = &[AuthMode::WebhookUrl];

/// One channel capability implemented by this Rust crate.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum ChannelCapability {
    /// Normalized text can be received.
    InboundText,
    /// Normalized text can be sent.
    OutboundText,
}

/// Credential mode declared by this crate for configuration routing.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AuthMode {
    /// Bot token.
    BotToken,
    /// OAuth 2 authorization.
    OAuth2,
    /// Application identifier and secret.
    AppCredentials,
    /// Service account identity.
    ServiceAccount,
    /// Bearer or personal access token.
    AccessToken,
    /// Webhook signing secret used by a provider-native integration.
    WebhookSecret,
    /// Incoming webhook URL that embeds its destination and secret.
    WebhookUrl,
    /// Platform-owned authenticated session.
    PlatformSession,
    /// Locally managed companion service.
    LocalService,
    /// Password or application password.
    Password,
    /// Optional server password.
    OptionalPassword,
    /// Authenticated local CLI profile.
    Profile,
    /// Private identity/signing key.
    PrivateKey,
    /// Authentication is owned by an external package.
    ExternalPlugin,
    /// No authentication.
    None,
}

/// Honest executable coverage for one registry entry.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ImplementationStatus {
    /// Complete local implementation of the frozen QA contract.
    Full,
    /// Outbound text works through the generic webhook adapter; inbound and
    /// richer provider behavior remain unimplemented.
    OutboundWebhook,
    /// Identity, provenance, and auth metadata only.
    RegistrationOnly,
}

/// Exact frozen identity metadata plus explicitly scoped Rust behavior.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ChannelDescriptor {
    /// Frozen inventory record identifier.
    pub record_id: &'static str,
    /// Exact channel identifier.
    pub id: &'static str,
    /// Frozen classification.
    pub classification: &'static str,
    /// Frozen upstream source path.
    pub source_path: &'static str,
    /// Upstream plugin identifier when source-backed.
    pub plugin_id: Option<&'static str>,
    /// Official package name for catalog-only entries.
    pub package_name: Option<&'static str>,
    /// Frozen provenance.
    pub provenance: &'static str,
    /// Official catalog package for source-backed entries.
    pub catalog_package: Option<&'static str>,
    /// Official catalog path when one exists.
    pub catalog_source_path: Option<&'static str>,
    /// Capabilities actually implemented by this crate.
    pub capabilities: &'static [ChannelCapability],
    /// Credential policy declared by this crate for configuration routing.
    ///
    /// The frozen channel inventory does not specify authentication modes.
    pub auth_modes: &'static [AuthMode],
    /// Executable coverage, kept distinct from registry presence.
    pub implementation: ImplementationStatus,
}

macro_rules! source_channel {
    ($id:literal, $auth:expr, $capabilities:expr, $implementation:expr) => {
        ChannelDescriptor {
            record_id: concat!("channel:", $id),
            id: $id,
            classification: "official_integration",
            source_path: concat!("extensions/", $id, "/openclaw.plugin.json"),
            plugin_id: Some($id),
            package_name: None,
            provenance: "source_manifest",
            catalog_package: Some(concat!("@openclaw/", $id)),
            catalog_source_path: Some(CATALOG_PATH),
            capabilities: $capabilities,
            auth_modes: $auth,
            implementation: $implementation,
        }
    };
}

macro_rules! source_only_channel {
    ($id:literal, $auth:expr, $capabilities:expr, $implementation:expr) => {
        ChannelDescriptor {
            record_id: concat!("channel:", $id),
            id: $id,
            classification: "official_integration",
            source_path: concat!("extensions/", $id, "/openclaw.plugin.json"),
            plugin_id: Some($id),
            package_name: None,
            provenance: "source_manifest",
            catalog_package: None,
            catalog_source_path: None,
            capabilities: $capabilities,
            auth_modes: $auth,
            implementation: $implementation,
        }
    };
}

macro_rules! catalog_channel {
    ($id:literal, $package:literal, $auth:expr) => {
        ChannelDescriptor {
            record_id: concat!("channel:", $id),
            id: $id,
            classification: "official_integration",
            source_path: CATALOG_PATH,
            plugin_id: None,
            package_name: Some($package),
            provenance: "official_catalog_only",
            catalog_package: None,
            catalog_source_path: None,
            capabilities: NO_CAPABILITIES,
            auth_modes: $auth,
            implementation: ImplementationStatus::RegistrationOnly,
        }
    };
}

static REGISTRY: [ChannelDescriptor; 29] = [
    source_channel!(
        "mattermost",
        WEBHOOK_URL,
        TEXT_OUT,
        ImplementationStatus::OutboundWebhook
    ),
    source_channel!(
        "msteams",
        APP_CREDENTIALS,
        NO_CAPABILITIES,
        ImplementationStatus::RegistrationOnly
    ),
    source_channel!(
        "feishu",
        APP_CREDENTIALS,
        NO_CAPABILITIES,
        ImplementationStatus::RegistrationOnly
    ),
    source_channel!(
        "sms",
        APP_CREDENTIALS,
        NO_CAPABILITIES,
        ImplementationStatus::RegistrationOnly
    ),
    catalog_channel!(
        "openclaw-weixin",
        "@tencent-weixin/openclaw-weixin",
        EXTERNAL_PLUGIN
    ),
    source_channel!(
        "googlechat",
        WEBHOOK_URL,
        TEXT_OUT,
        ImplementationStatus::OutboundWebhook
    ),
    source_channel!(
        "clickclack",
        BOT_TOKEN,
        NO_CAPABILITIES,
        ImplementationStatus::RegistrationOnly
    ),
    source_channel!(
        "line",
        TOKEN_AND_WEBHOOK,
        NO_CAPABILITIES,
        ImplementationStatus::RegistrationOnly
    ),
    source_channel!(
        "zalouser",
        PLATFORM_SESSION,
        NO_CAPABILITIES,
        ImplementationStatus::RegistrationOnly
    ),
    source_channel!(
        "zalo",
        BOT_TOKEN_AND_WEBHOOK,
        NO_CAPABILITIES,
        ImplementationStatus::RegistrationOnly
    ),
    source_only_channel!(
        "imessage",
        PLATFORM_SESSION,
        NO_CAPABILITIES,
        ImplementationStatus::RegistrationOnly
    ),
    source_channel!(
        "matrix",
        ACCESS_TOKEN,
        NO_CAPABILITIES,
        ImplementationStatus::RegistrationOnly
    ),
    catalog_channel!("yuanbao", "openclaw-plugin-yuanbao", EXTERNAL_PLUGIN),
    source_channel!(
        "signal",
        LOCAL_SERVICE,
        NO_CAPABILITIES,
        ImplementationStatus::RegistrationOnly
    ),
    source_only_channel!(
        "qa-channel",
        NO_AUTH,
        QA_CAPABILITIES,
        ImplementationStatus::Full
    ),
    catalog_channel!("wecom", "@wecom/wecom-openclaw-plugin", APP_CREDENTIALS),
    source_channel!(
        "nextcloud-talk",
        BOT_TOKEN_AND_PASSWORD,
        NO_CAPABILITIES,
        ImplementationStatus::RegistrationOnly
    ),
    source_channel!(
        "slack",
        WEBHOOK_URL,
        TEXT_OUT,
        ImplementationStatus::OutboundWebhook
    ),
    source_channel!(
        "discord",
        WEBHOOK_URL,
        TEXT_OUT,
        ImplementationStatus::OutboundWebhook
    ),
    source_channel!(
        "twitch",
        OAUTH2,
        NO_CAPABILITIES,
        ImplementationStatus::RegistrationOnly
    ),
    catalog_channel!(
        "openclaw-zaloclawbot",
        "@zalo-platforms/openclaw-zaloclawbot",
        EXTERNAL_PLUGIN
    ),
    source_channel!(
        "synology-chat",
        TOKEN_AND_WEBHOOK,
        NO_CAPABILITIES,
        ImplementationStatus::RegistrationOnly
    ),
    source_channel!(
        "raft",
        PROFILE,
        NO_CAPABILITIES,
        ImplementationStatus::RegistrationOnly
    ),
    source_channel!(
        "tlon",
        PASSWORD,
        NO_CAPABILITIES,
        ImplementationStatus::RegistrationOnly
    ),
    source_channel!(
        "nostr",
        PRIVATE_KEY,
        NO_CAPABILITIES,
        ImplementationStatus::RegistrationOnly
    ),
    source_channel!(
        "whatsapp",
        PLATFORM_SESSION,
        NO_CAPABILITIES,
        ImplementationStatus::RegistrationOnly
    ),
    source_only_channel!(
        "telegram",
        BOT_TOKEN,
        NO_CAPABILITIES,
        ImplementationStatus::RegistrationOnly
    ),
    source_channel!(
        "qqbot",
        APP_CREDENTIALS,
        NO_CAPABILITIES,
        ImplementationStatus::RegistrationOnly
    ),
    source_channel!(
        "irc",
        OPTIONAL_PASSWORD,
        NO_CAPABILITIES,
        ImplementationStatus::RegistrationOnly
    ),
];

/// Returns the immutable 29-entry official channel registry.
#[must_use]
pub const fn registry() -> &'static [ChannelDescriptor] {
    &REGISTRY
}

/// Looks up one channel by exact identifier.
#[must_use]
pub fn descriptor(id: &str) -> Option<&'static ChannelDescriptor> {
    REGISTRY.iter().find(|entry| entry.id == id)
}

/// Clock port used to make delivery acknowledgements deterministic.
pub trait UnixClock {
    /// Returns Unix time in milliseconds.
    fn now_unix_ms(&self) -> u64;
}

/// System-backed clock.
#[derive(Clone, Copy, Debug, Default)]
pub struct SystemClock;

impl UnixClock for SystemClock {
    fn now_unix_ms(&self) -> u64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis()
            .try_into()
            .unwrap_or(u64::MAX)
    }
}

/// Captured webhook response metadata without response bodies.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct WebhookResponse {
    /// HTTP status code.
    pub status: u16,
}

/// Redirect policy carried by every outbound webhook request.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RedirectPolicy {
    /// Do not follow redirects.
    ///
    /// A future transport that supports redirects must introduce a distinct
    /// policy requiring origin validation on every hop. It must never forward
    /// credentials across origins.
    Reject,
}

/// Credential-bearing webhook request with redacted formatting.
pub struct WebhookRequest<'a> {
    endpoint: &'a str,
    body: &'a [u8],
    redirect_policy: RedirectPolicy,
}

impl WebhookRequest<'_> {
    /// Returns the complete secret endpoint for immediate transport use.
    ///
    /// Implementations must not log, persist, or include this value in errors.
    #[must_use]
    pub const fn endpoint(&self) -> &str {
        self.endpoint
    }

    /// Returns the JSON body.
    #[must_use]
    pub const fn body(&self) -> &[u8] {
        self.body
    }

    /// Returns the mandatory redirect behavior.
    #[must_use]
    pub const fn redirect_policy(&self) -> RedirectPolicy {
        self.redirect_policy
    }
}

impl Debug for WebhookRequest<'_> {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("WebhookRequest")
            .field("endpoint", &"[REDACTED]")
            .field(
                "body",
                &format_args!("[REDACTED; {} bytes]", self.body.len()),
            )
            .field("redirect_policy", &self.redirect_policy)
            .finish()
    }
}

/// HTTP transport port for outgoing webhook adapters.
pub trait WebhookTransport {
    /// Posts one request without logging credentials or following redirects.
    ///
    /// Implementations must return a 3xx response to the caller rather than
    /// following it. This prevents a trusted webhook origin from forwarding
    /// credential-bearing request state to another origin.
    fn post_json(&self, request: &WebhookRequest<'_>) -> Result<WebhookResponse, ChannelError>;
}

/// Plain HTTP transport restricted to loopback fixture servers.
///
/// Production HTTPS is intentionally delegated to a platform transport with
/// certificate validation. This adapter exists for deterministic local
/// end-to-end tests and cannot send credentials to remote hosts.
#[derive(Clone, Copy, Debug, Default)]
pub struct LoopbackHttpTransport;

impl WebhookTransport for LoopbackHttpTransport {
    fn post_json(&self, request: &WebhookRequest<'_>) -> Result<WebhookResponse, ChannelError> {
        if request.redirect_policy() != RedirectPolicy::Reject {
            return Err(ChannelError::Configuration(
                ConfigurationError::InvalidAdapterConfiguration,
            ));
        }
        let parsed = ParsedLoopbackEndpoint::parse(request.endpoint())?;
        let mut stream = TcpStream::connect((&*parsed.host, parsed.port))
            .map_err(|_| ChannelError::Transport(TransportErrorKind::Connection))?;
        stream
            .set_read_timeout(Some(Duration::from_secs(5)))
            .map_err(|_| ChannelError::Transport(TransportErrorKind::Io))?;
        stream
            .set_write_timeout(Some(Duration::from_secs(5)))
            .map_err(|_| ChannelError::Transport(TransportErrorKind::Io))?;
        let wire_request = format!(
            "POST {} HTTP/1.1\r\nHost: {}:{}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
            parsed.target,
            parsed.host,
            parsed.port,
            request.body().len()
        );
        stream
            .write_all(wire_request.as_bytes())
            .and_then(|()| stream.write_all(request.body()))
            .map_err(|_| ChannelError::Transport(TransportErrorKind::Io))?;
        let mut response = Vec::new();
        stream
            .read_to_end(&mut response)
            .map_err(|_| ChannelError::Transport(TransportErrorKind::Io))?;
        parse_status(&response).map(|status| WebhookResponse { status })
    }
}

struct ParsedLoopbackEndpoint {
    host: String,
    port: u16,
    target: String,
}

impl ParsedLoopbackEndpoint {
    fn parse(endpoint: &str) -> Result<Self, ChannelError> {
        let remainder = endpoint
            .strip_prefix("http://")
            .ok_or(ChannelError::Configuration(
                ConfigurationError::InvalidAdapterConfiguration,
            ))?;
        let (authority, target) = remainder
            .split_once('/')
            .map_or((remainder, "/".to_owned()), |(authority, target)| {
                (authority, format!("/{target}"))
            });
        let (host, port) = authority
            .rsplit_once(':')
            .ok_or(ChannelError::Configuration(
                ConfigurationError::InvalidAdapterConfiguration,
            ))?;
        if !matches!(host, "127.0.0.1" | "localhost") {
            return Err(ChannelError::Configuration(
                ConfigurationError::InvalidAdapterConfiguration,
            ));
        }
        let port = port.parse().map_err(|_| {
            ChannelError::Configuration(ConfigurationError::InvalidAdapterConfiguration)
        })?;
        Ok(Self {
            host: host.to_owned(),
            port,
            target,
        })
    }
}

fn parse_status(response: &[u8]) -> Result<u16, ChannelError> {
    let first_line = response
        .split(|byte| *byte == b'\n')
        .next()
        .ok_or(ChannelError::Protocol(ProtocolErrorKind::MalformedResponse))?;
    let first_line = std::str::from_utf8(first_line)
        .map_err(|_| ChannelError::Protocol(ProtocolErrorKind::MalformedResponse))?;
    let mut parts = first_line.trim_end_matches('\r').split_ascii_whitespace();
    let version = parts.next();
    let status = parts.next();
    if version != Some("HTTP/1.1") {
        return Err(ChannelError::Protocol(ProtocolErrorKind::MalformedResponse));
    }
    status
        .ok_or(ChannelError::Protocol(ProtocolErrorKind::MissingField))?
        .parse()
        .map_err(|_| ChannelError::Protocol(ProtocolErrorKind::InvalidField))
}

/// Outbound text adapter for webhook-compatible official channels.
pub struct WebhookChannel<T, C> {
    channel_id: &'static str,
    account_id: String,
    payload_field: &'static str,
    transport: T,
    clock: C,
}

impl<T, C> WebhookChannel<T, C> {
    /// Builds an adapter only for registry entries explicitly marked as webhook-capable.
    pub fn new(
        channel_id: &'static str,
        account_id: impl Into<String>,
        transport: T,
        clock: C,
    ) -> Result<Self, ChannelError> {
        let payload_field = match channel_id {
            "discord" => "content",
            "googlechat" | "mattermost" | "slack" => "text",
            _ => {
                return Err(ChannelError::Configuration(
                    ConfigurationError::InvalidAdapterConfiguration,
                ));
            }
        };
        let account_id = account_id.into();
        if account_id.is_empty() {
            return Err(ChannelError::Configuration(
                ConfigurationError::InvalidAdapterConfiguration,
            ));
        }
        Ok(Self {
            channel_id,
            account_id,
            payload_field,
            transport,
            clock,
        })
    }
}

impl<T: Debug, C: Debug> Debug for WebhookChannel<T, C> {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("WebhookChannel")
            .field("channel_id", &self.channel_id)
            .field("account_id", &self.account_id)
            .field("payload_field", &self.payload_field)
            .field("transport", &self.transport)
            .field("clock", &self.clock)
            .finish()
    }
}

impl<T, C> Channel for WebhookChannel<T, C>
where
    T: WebhookTransport,
    C: UnixClock,
{
    fn id(&self) -> &str {
        self.channel_id
    }

    fn poll_inbound(&mut self) -> Result<Option<InboundMessage>, ChannelError> {
        Err(ChannelError::Unsupported(UnsupportedOperation::Inbound))
    }

    fn send_outbound(
        &mut self,
        message: &OutboundMessage,
        credential: Option<&ChannelCredential>,
    ) -> Result<DeliveryAcknowledgement, ChannelError> {
        message.validate().map_err(ChannelError::InvalidMessage)?;
        if message.account_id != self.account_id {
            return Err(ChannelError::Configuration(
                ConfigurationError::CredentialScopeMismatch,
            ));
        }
        if !message.attachments.is_empty() {
            return Err(ChannelError::Unsupported(UnsupportedOperation::Attachments));
        }
        if message.reply_to.is_some() {
            return Err(ChannelError::Unsupported(UnsupportedOperation::Replies));
        }
        let text = message.text.as_deref().ok_or(ChannelError::InvalidMessage(
            InvalidMessageReason::EmptyContent,
        ))?;
        let credential = credential.ok_or(ChannelError::Credential(SecretStoreError::NotFound))?;
        let body = serde_json::to_vec(&serde_json::json!({ self.payload_field: text }))
            .map_err(|_| ChannelError::Protocol(ProtocolErrorKind::InvalidField))?;
        let response = credential
            .expose_embedded_endpoint(self.channel_id, &self.account_id, |endpoint| {
                self.transport.post_json(&WebhookRequest {
                    endpoint,
                    body: &body,
                    redirect_policy: RedirectPolicy::Reject,
                })
            })
            .map_err(map_credential_binding)??;
        match response.status {
            200..=299 => Ok(DeliveryAcknowledgement {
                idempotency_key: message.idempotency_key.clone(),
                remote_message_id: None,
                state: DeliveryState::Accepted,
                accepted_at_unix_ms: self.clock.now_unix_ms(),
            }),
            401 | 403 => Err(ChannelError::Authentication),
            429 => Err(ChannelError::RateLimited {
                retry_after: Duration::from_secs(1),
            }),
            status => Err(ChannelError::RemoteRejected { status }),
        }
    }
}

fn map_credential_binding(error: CredentialBindingError) -> ChannelError {
    ChannelError::CredentialBinding(error)
}

/// Fully local QA channel used by acceptance and lifecycle tests.
#[derive(Debug)]
pub struct QaChannel<C> {
    account_id: String,
    inbound: VecDeque<InboundMessage>,
    outbound: Vec<OutboundMessage>,
    clock: C,
}

impl<C> QaChannel<C> {
    /// Creates an empty QA channel.
    pub fn new(account_id: impl Into<String>, clock: C) -> Result<Self, ChannelError> {
        let account_id = account_id.into();
        if account_id.is_empty() {
            return Err(ChannelError::Configuration(
                ConfigurationError::InvalidAdapterConfiguration,
            ));
        }
        Ok(Self {
            account_id,
            inbound: VecDeque::new(),
            outbound: Vec::new(),
            clock,
        })
    }

    /// Adds one validated fixture message to the inbound queue.
    pub fn push_inbound(&mut self, message: InboundMessage) -> Result<(), ChannelError> {
        message.validate().map_err(ChannelError::InvalidMessage)?;
        if message.channel_id != "qa-channel" || message.account_id != self.account_id {
            return Err(ChannelError::Configuration(
                ConfigurationError::CredentialScopeMismatch,
            ));
        }
        self.inbound.push_back(message);
        Ok(())
    }

    /// Returns outbound messages accepted by this local adapter.
    #[must_use]
    pub fn outbound(&self) -> &[OutboundMessage] {
        &self.outbound
    }
}

impl<C: UnixClock> Channel for QaChannel<C> {
    fn id(&self) -> &str {
        "qa-channel"
    }

    fn poll_inbound(&mut self) -> Result<Option<InboundMessage>, ChannelError> {
        Ok(self.inbound.pop_front())
    }

    fn send_outbound(
        &mut self,
        message: &OutboundMessage,
        _credential: Option<&ChannelCredential>,
    ) -> Result<DeliveryAcknowledgement, ChannelError> {
        message.validate().map_err(ChannelError::InvalidMessage)?;
        if message.account_id != self.account_id {
            return Err(ChannelError::Configuration(
                ConfigurationError::CredentialScopeMismatch,
            ));
        }
        self.outbound.push(message.clone());
        Ok(DeliveryAcknowledgement {
            idempotency_key: message.idempotency_key.clone(),
            remote_message_id: Some(format!("qa-{}", self.outbound.len())),
            state: DeliveryState::Delivered,
            accepted_at_unix_ms: self.clock.now_unix_ms(),
        })
    }
}

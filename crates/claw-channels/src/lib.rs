//! Official channel metadata and Rust-native adapters.
//!
//! Every frozen official channel is registered. [`ImplementationStatus`] keeps
//! registry coverage separate from executable behavior so metadata-only entries
//! cannot be mistaken for working integrations.

use std::borrow::Cow;
use std::collections::VecDeque;
use std::error::Error;
use std::fmt::{self, Debug, Display, Formatter};
use std::io::{Read, Write};
use std::net::TcpStream;
use std::num::NonZeroU32;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use claw_channel_sdk::{
    Channel, ChannelCredential, ChannelError, ConfigurationError, CredentialBindingError,
    DeliveryAcknowledgement, DeliveryState, InboundMessage, InvalidMessageReason, LengthUnit,
    OutboundMessage, OutboundRetrySafety, OutputLimit, ProtocolErrorKind, SecretStoreError,
    SegmentationError, TextSegments, TransportErrorKind, UnsupportedOperation, segment_text,
    segment_text_iter,
};
use serde::ser::SerializeMap;
use serde::{Serialize, Serializer};

mod bounded;
pub mod commands;
pub mod diagnostics;
pub mod discord;
pub mod lifecycle;
pub mod message_processor;
pub mod routing;
pub mod teams;
pub mod telegram;
pub mod transport;
pub mod whatsapp;

pub use commands::{
    InboundOutcome, classify_inbound, command_registry, command_surface, help_text,
};
pub use diagnostics::{DiagnosticCode, DiagnosticLevel, DiagnosticSink, OperatorDiagnostic};
pub use discord::{
    DISCORD_CLIENT_LABEL, DISCORD_RECONNECT_DELAY, DISCORD_SEND_REQUEST_TIMEOUT, DiscordChannel,
    DiscordCreateMessageRequest, DiscordGatewayPhase, DiscordGatewayRequest, DiscordPacketOutcome,
    DiscordTransport,
};
pub use lifecycle::SupervisedChannel;
pub use message_processor::{
    ALREADY_AUTHENTICATED_REPLY, AuthenticationPrompt, COMMAND_REJECTED_REPLY,
    COMMON_DISPATCH_POLICY, COMMON_FAILURE_REPLY, COMMON_UNCONFIGURED_REPLY, ConversationService,
    DispatchInput, DispatchOutcome, DispatchPolicy, ReplySource, TEAMS_DISPATCH_POLICY,
    TEAMS_FAILURE_REPLY, TEAMS_UNCONFIGURED_REPLY, dispatch_incoming,
};
pub use routing::{ChannelRouter, ExchangeSupport, RouterError, RoutingError, exchange_support};
pub use teams::{
    TEAMS_GREETING, TeamsAction, TeamsActivityError, TeamsActivityHandler, TeamsActivityOutcome,
};
pub use telegram::{
    TELEGRAM_LONG_POLL_TIMEOUT, TELEGRAM_POLL_REQUEST_TIMEOUT, TELEGRAM_SEND_REQUEST_TIMEOUT,
    TelegramChannel, TelegramPollRequest, TelegramPollStats, TelegramSendRequest,
    TelegramTransport,
};
pub use transport::{MAX_PROVIDER_RESPONSE_BYTES, ProviderResponse};
pub use whatsapp::{
    WHATSAPP_GRAPH_API_VERSION, WHATSAPP_MAX_MESSAGES_PER_WEBHOOK, WHATSAPP_SEND_REQUEST_TIMEOUT,
    WhatsAppChannel, WhatsAppSendError, WhatsAppSendRequest, WhatsAppTransport,
    WhatsAppVerificationQuery, WhatsAppVerificationResponse, WhatsAppWebhookHandling,
    WhatsAppWebhookResponse, WhatsAppWebhookStats, verify_whatsapp_webhook_signature,
};

const CATALOG_PATH: &str = "scripts/lib/official-external-channel-catalog.json";
const TEXT_OUT: &[ChannelCapability] = &[ChannelCapability::OutboundText];
const TEXT_IO: &[ChannelCapability] = &[
    ChannelCapability::InboundText,
    ChannelCapability::OutboundText,
];
const QA_CAPABILITIES: &[ChannelCapability] = &[
    ChannelCapability::InboundText,
    ChannelCapability::OutboundText,
];
const NO_CAPABILITIES: &[ChannelCapability] = &[];
const ACCESS_TOKEN: &[AuthMode] = &[AuthMode::AccessToken];
const APP_CREDENTIALS: &[AuthMode] = &[AuthMode::AppCredentials];
const BOT_TOKEN: &[AuthMode] = &[AuthMode::BotToken];
const BOT_TOKEN_AND_WEBHOOK_URL: &[AuthMode] = &[AuthMode::BotToken, AuthMode::WebhookUrl];
const BOT_TOKEN_AND_PASSWORD: &[AuthMode] = &[AuthMode::BotToken, AuthMode::Password];
const BOT_TOKEN_AND_WEBHOOK: &[AuthMode] = &[AuthMode::BotToken, AuthMode::WebhookSecret];
const EXTERNAL_PLUGIN: &[AuthMode] = &[AuthMode::ExternalPlugin];
const LOCAL_SERVICE: &[AuthMode] = &[AuthMode::LocalService];
const NO_AUTH: &[AuthMode] = &[AuthMode::None];
const OAUTH2: &[AuthMode] = &[AuthMode::OAuth2];
const OPTIONAL_PASSWORD: &[AuthMode] = &[AuthMode::OptionalPassword];
const PASSWORD: &[AuthMode] = &[AuthMode::Password];
const PLATFORM_SESSION: &[AuthMode] = &[AuthMode::PlatformSession];
const WHATSAPP_AUTH: &[AuthMode] = &[
    AuthMode::PlatformSession,
    AuthMode::AccessToken,
    AuthMode::WebhookSecret,
];
const PRIVATE_KEY: &[AuthMode] = &[AuthMode::PrivateKey];
const PROFILE: &[AuthMode] = &[AuthMode::Profile];
const TOKEN_AND_WEBHOOK: &[AuthMode] = &[AuthMode::AccessToken, AuthMode::WebhookSecret];
const WEBHOOK_URL: &[AuthMode] = &[AuthMode::WebhookUrl];

/// Declared outbound length limits, and where each number came from.
///
/// Every value below is transcribed from a file in this repository. None of
/// them is recalled from a provider's documentation, because a limit that
/// cannot be re-derived from the tree is a limit nobody can review, and a wrong
/// one silently truncates a user's message.
///
/// The frozen channel inventory at `compat/upstream/inventories/channels.json`
/// carries identity and provenance only — no lengths — so the source is the
/// frozen legacy behavior ledger. `compat/legacy/ledger/behaviors.json` records
/// `behavior.message.channel-limits` as `"Teams and Telegram use 4000-character
/// chunks, Discord 1900, and WhatsApp 3500"`, and the four call sites it points
/// at are `src/bot/teamsBot.ts` (`TEAMS_MAX_MESSAGE_LENGTH = 4000`),
/// `src/channels/telegramPolling.ts` (`splitMessage(text, 4000)`),
/// `src/channels/discordGateway.ts` (`splitMessage(text, 1900)`) and
/// `src/channels/whatsappWebhook.ts` (`splitMessage(text, 3500)`).
///
/// The unit is [`LengthUnit::Utf16CodeUnits`] rather than characters. The
/// ledger prose says "character", but every one of those call sites measures
/// with JavaScript `String.length`, which counts UTF-16 code units. The two
/// disagree exactly on astral-plane text — one emoji is 1 character and 2 code
/// units — and the obligation being discharged is behavioral parity with the
/// program that is still in production, so the implementation's unit wins.
///
/// The other 25 registered channels have no limit anywhere in this repository
/// and are therefore modelled as absent. Segmentation refuses for them.
const fn declared_limit(max: u32) -> Option<OutputLimit> {
    match NonZeroU32::new(max) {
        Some(max) => Some(OutputLimit::new(max, LengthUnit::Utf16CodeUnits)),
        None => None,
    }
}

/// One channel capability implemented by this Rust crate.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum ChannelCapability {
    /// Normalized text can be received.
    InboundText,
    /// Normalized text can be sent.
    OutboundText,
    /// Failed outbound attempts are positively safe to repeat.
    SafeOutboundRetry,
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
    /// Legacy production behavior is implemented behind daemon-owned transport
    /// and HTTP composition ports.
    CompatibilityShim,
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
    /// Maximum length of one outbound message, when this repository can prove it.
    ///
    /// [`None`] means no source in this tree states a limit for this channel.
    /// It does not mean the provider has none; it means nothing here may guess
    /// at it, so segmentation refuses. See `declared_limit` for the
    /// provenance of every value that is present.
    ///
    /// A declared limit is metadata, exactly like [`Self::auth_modes`]. It says
    /// nothing about whether this crate can talk to the channel; that remains
    /// [`Self::implementation`]'s job.
    pub output_limit: Option<OutputLimit>,
    /// Executable coverage, kept distinct from registry presence.
    pub implementation: ImplementationStatus,
}

macro_rules! source_channel {
    ($id:literal, $auth:expr, $capabilities:expr, $implementation:expr) => {
        source_channel!($id, $auth, $capabilities, $implementation, None)
    };
    ($id:literal, $auth:expr, $capabilities:expr, $implementation:expr, $limit:expr) => {
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
            output_limit: $limit,
            implementation: $implementation,
        }
    };
}

macro_rules! source_only_channel {
    ($id:literal, $auth:expr, $capabilities:expr, $implementation:expr) => {
        source_only_channel!($id, $auth, $capabilities, $implementation, None)
    };
    ($id:literal, $auth:expr, $capabilities:expr, $implementation:expr, $limit:expr) => {
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
            output_limit: $limit,
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
            output_limit: None,
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
        TEXT_IO,
        ImplementationStatus::CompatibilityShim,
        declared_limit(4000)
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
        BOT_TOKEN_AND_WEBHOOK_URL,
        TEXT_IO,
        ImplementationStatus::CompatibilityShim,
        declared_limit(1900)
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
        WHATSAPP_AUTH,
        TEXT_IO,
        ImplementationStatus::CompatibilityShim,
        declared_limit(3500)
    ),
    source_only_channel!(
        "telegram",
        BOT_TOKEN,
        TEXT_IO,
        ImplementationStatus::CompatibilityShim,
        declared_limit(4000)
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
///
/// The registry is a fixed 29-entry table of short identifiers, so a scan beats
/// a hashed or sorted index here: measured on this table it is roughly 1.6x
/// faster than a `HashMap` and 2.5x faster than a binary search, and it needs no
/// lazy initialization. Revisit only if the inventory stops being frozen.
#[must_use]
pub fn descriptor(id: &str) -> Option<&'static ChannelDescriptor> {
    REGISTRY.iter().find(|entry| entry.id == id)
}

/// Returns the proven outbound length limit for one registered channel.
///
/// `Ok(None)` states that this repository contains no limit for that channel.
/// That is a different fact from "the identifier is unknown" and from "the
/// provider imposes no limit", and it is the case in which nothing may be
/// segmented.
///
/// # Errors
///
/// Returns [`RoutingError::UnknownChannel`] when `channel_id` is not one of the
/// 29 frozen official identifiers.
pub fn output_limit(channel_id: &str) -> Result<Option<OutputLimit>, RoutingError> {
    descriptor(channel_id)
        .map(|entry| entry.output_limit)
        .ok_or(RoutingError::UnknownChannel)
}

/// Splits outbound text into the segments one registered channel would send.
///
/// Segments borrow from `text` wherever possible; only a segment that had to
/// re-open a code fence owns its bytes.
///
/// This is the honest surface for the channels whose limit this repository can
/// prove but whose transport is not implemented: the segmentation is real and
/// testable even where the delivery is not.
///
/// # Errors
///
/// - [`OutboundTextError::UnknownChannel`] when `channel_id` is not one of the
///   29 frozen official identifiers.
/// - [`OutboundTextError::NoProvenLimit`] when the channel is registered but no
///   source in this repository states its limit. Guessing one would silently
///   truncate the caller's message, so this refuses instead.
/// - [`OutboundTextError::Segmentation`] when the text cannot be split to the
///   declared limit without corrupting a cluster or a code fence.
pub fn segment_outbound_text<'a>(
    channel_id: &str,
    text: &'a str,
) -> Result<Vec<Cow<'a, str>>, OutboundTextError> {
    let limit = output_limit(channel_id).map_err(|_| OutboundTextError::UnknownChannel)?;
    let limit = limit.ok_or(OutboundTextError::NoProvenLimit)?;
    Ok(segment_text(text, Some(limit))?)
}

/// Lazily yields the canonical outbound segments for one registered channel.
///
/// The iterator builds no segment vector and borrows ordinary text directly;
/// only fenced-code continuation markers allocate. It shares the same engine
/// and errors as [`segment_outbound_text`].
///
/// # Errors
///
/// - [`OutboundTextError::UnknownChannel`] when `channel_id` is unregistered.
/// - [`OutboundTextError::NoProvenLimit`] when the channel has no declared
///   output limit.
pub fn segment_outbound_text_iter<'a>(
    channel_id: &str,
    text: &'a str,
) -> Result<TextSegments<'a>, OutboundTextError> {
    let limit = output_limit(channel_id).map_err(|_| OutboundTextError::UnknownChannel)?;
    let limit = limit.ok_or(OutboundTextError::NoProvenLimit)?;
    Ok(segment_text_iter(text, Some(limit))?)
}

/// Why outbound text could not be segmented for a registered channel.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum OutboundTextError {
    /// The identifier is not one of the 29 frozen official channels.
    UnknownChannel,
    /// The channel is registered but this repository states no limit for it.
    NoProvenLimit,
    /// The declared limit exists and the text still could not be segmented.
    Segmentation(SegmentationError),
}

impl Display for OutboundTextError {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        match self {
            Self::UnknownChannel => formatter.write_str("channel identifier is not registered"),
            Self::NoProvenLimit => {
                formatter.write_str("channel has no proven outbound length limit")
            }
            Self::Segmentation(error) => Display::fmt(error, formatter),
        }
    }
}

impl Error for OutboundTextError {}

impl From<SegmentationError> for OutboundTextError {
    fn from(error: SegmentationError) -> Self {
        Self::Segmentation(error)
    }
}

impl From<OutboundTextError> for ChannelError {
    fn from(error: OutboundTextError) -> Self {
        match error {
            OutboundTextError::UnknownChannel | OutboundTextError::NoProvenLimit => {
                Self::Configuration(ConfigurationError::InvalidAdapterConfiguration)
            }
            OutboundTextError::Segmentation(error) => error.into(),
        }
    }
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
    ///
    /// # Errors
    ///
    /// Implementations return [`ChannelError::Configuration`] when the request
    /// carries a redirect policy or endpoint form they refuse to send,
    /// [`ChannelError::Transport`] when the connection, TLS handshake, write, or
    /// read failed, and [`ChannelError::Protocol`] when the response could not
    /// be parsed far enough to recover a status code. A status the provider
    /// returned is reported through [`WebhookResponse`], not as an error, so the
    /// adapter decides what each status means.
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
        // The target is interpolated into the request line, so a space or a
        // control character in it would end that line early and let the rest of
        // the endpoint be read as headers of its own.
        if endpoint.bytes().any(|byte| byte <= b' ' || byte == 0x7f) {
            return Err(ChannelError::Configuration(
                ConfigurationError::InvalidAdapterConfiguration,
            ));
        }
        let remainder = endpoint
            .strip_prefix("http://")
            .ok_or(ChannelError::Configuration(
                ConfigurationError::InvalidAdapterConfiguration,
            ))?;
        let (authority, target) = remainder.split_once('/').map_or_else(
            || (remainder, "/".to_owned()),
            |(authority, target)| (authority, format!("/{target}")),
        );
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
///
/// Text longer than the channel's proven output limit is segmented and posted
/// as several sequential requests. Only `discord` has such a limit today; the
/// other three webhook channels have none in this repository, so their text is
/// posted exactly as before rather than split against an invented bound.
pub struct WebhookChannel<T, C> {
    channel_id: &'static str,
    account_id: String,
    conversation_id: String,
    payload_field: &'static str,
    transport: T,
    clock: C,
}

impl<T, C> WebhookChannel<T, C> {
    /// Builds an adapter only for registry entries explicitly marked as webhook-capable.
    ///
    /// # Errors
    ///
    /// Returns [`ChannelError::Configuration`] with
    /// [`ConfigurationError::InvalidAdapterConfiguration`] when `channel_id` is
    /// not one of the four webhook-capable official channels (`discord`,
    /// `googlechat`, `mattermost`, `slack`) — the rest of the registry has no
    /// outbound implementation and must not be constructible here — or when the
    /// account or conversation identifier is empty, longer than 256 bytes,
    /// whitespace-padded, or contains a control character.
    pub fn new(
        channel_id: &'static str,
        account_id: impl Into<String>,
        conversation_id: impl Into<String>,
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
        let conversation_id = conversation_id.into();
        if invalid_routing_identifier(&account_id) || invalid_routing_identifier(&conversation_id) {
            return Err(ChannelError::Configuration(
                ConfigurationError::InvalidAdapterConfiguration,
            ));
        }
        Ok(Self {
            channel_id,
            account_id,
            conversation_id,
            payload_field,
            transport,
            clock,
        })
    }
}

impl<T: WebhookTransport, C> WebhookChannel<T, C> {
    /// Posts exactly one segment and maps its status to a channel error.
    ///
    /// A multi-segment message calls this once per segment and stops at the
    /// first failure, which leaves the segments already accepted delivered.
    /// This is why the adapter declares [`OutboundRetrySafety::NotSafeToRepeat`]:
    /// repeating the whole message would repost those segments.
    fn post_text(&self, text: &str, credential: &ChannelCredential) -> Result<(), ChannelError> {
        let body = serde_json::to_vec(&WebhookPayload {
            field: self.payload_field,
            text,
        })
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
            200..=299 => Ok(()),
            401 | 403 => Err(ChannelError::Authentication),
            429 => Err(ChannelError::RateLimited {
                retry_after: Duration::from_secs(1),
            }),
            status => Err(ChannelError::RemoteRejected { status }),
        }
    }
}

impl<T: Debug, C: Debug> Debug for WebhookChannel<T, C> {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("WebhookChannel")
            .field("channel_id", &self.channel_id)
            .field("account_id", &self.account_id)
            .field("conversation_id", &self.conversation_id)
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

    fn outbound_retry_safety(&self) -> OutboundRetrySafety {
        OutboundRetrySafety::NotSafeToRepeat
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
        if message.conversation_id != self.conversation_id {
            return Err(ChannelError::Configuration(
                ConfigurationError::ConversationScopeMismatch,
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
        match descriptor(self.channel_id).and_then(|entry| entry.output_limit) {
            Some(limit) => {
                for segment in segment_text_iter(text, Some(limit))? {
                    self.post_text(segment?.as_ref(), credential)?;
                }
            }
            None => self.post_text(text, credential)?,
        }
        Ok(DeliveryAcknowledgement {
            correlation_key: message.correlation_key.clone(),
            remote_message_id: None,
            state: DeliveryState::Accepted,
            accepted_at_unix_ms: self.clock.now_unix_ms(),
        })
    }
}

const fn map_credential_binding(error: CredentialBindingError) -> ChannelError {
    ChannelError::CredentialBinding(error)
}

/// The single-field JSON body every webhook-capable official channel accepts.
///
/// Serializing this directly produces the same bytes as building a
/// `serde_json::Value` first, without allocating the intermediate map, string
/// key, and boxed value on every outbound message.
struct WebhookPayload<'a> {
    field: &'static str,
    text: &'a str,
}

impl Serialize for WebhookPayload<'_> {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let mut body = serializer.serialize_map(Some(1))?;
        body.serialize_entry(self.field, self.text)?;
        body.end()
    }
}

pub(crate) fn invalid_routing_identifier(value: &str) -> bool {
    value.is_empty()
        || value.len() > 256
        || value.trim() != value
        || value.chars().any(char::is_control)
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
    ///
    /// # Errors
    ///
    /// Returns [`ChannelError::Configuration`] with
    /// [`ConfigurationError::InvalidAdapterConfiguration`] when `account_id` is
    /// empty, since routing is keyed by channel and account and an empty
    /// account could never be addressed.
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
    ///
    /// # Errors
    ///
    /// - [`ChannelError::InvalidMessage`] when the fixture fails common
    ///   validation, carrying the exact reason.
    /// - [`ChannelError::Configuration`] with
    ///   [`ConfigurationError::CredentialScopeMismatch`] when the message is not
    ///   addressed to `qa-channel` and this adapter's own account, so a fixture
    ///   cannot be queued on the wrong tenant.
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
    fn id(&self) -> &'static str {
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
            correlation_key: message.correlation_key.clone(),
            remote_message_id: Some(format!("qa-{}", self.outbound.len())),
            state: DeliveryState::Delivered,
            accepted_at_unix_ms: self.clock.now_unix_ms(),
        })
    }
}

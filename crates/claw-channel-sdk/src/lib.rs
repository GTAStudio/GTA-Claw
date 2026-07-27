//! Transport-neutral messaging contracts shared by GTA Claw channels.
//!
//! The SDK deliberately owns no network client and no credential persistence.
//! Channel adapters receive secrets through [`SecretStore`] and transports
//! through their own explicit ports.

use std::error::Error;
use std::fmt::{self, Debug, Display, Formatter};
use std::num::NonZeroU32;
use std::str::FromStr;
use std::time::Duration;

use secrecy::{ExposeSecret, SecretString};
use serde::{Deserialize, Serialize};

pub mod commands;
pub mod lifecycle;

pub use commands::{
    COMMAND_PREFIX, CommandDispatchError, CommandInvocation, CommandParseError, CommandRegistry,
    CommandRegistryError, CommandSpec, MAX_COMMAND_ARGUMENT_CHARS, MAX_COMMAND_ARGUMENTS,
    MAX_COMMAND_MENTION_CHARS, MAX_COMMAND_NAME_CHARS, parse_command,
};
pub use lifecycle::{
    ChannelSession, ConnectionState, ConnectionSupervisor, IllegalTransition, LifecycleEvent,
    LifecycleObserver,
};

/// Maximum number of attachment bytes accepted by the common message model.
pub const MAX_ATTACHMENT_BYTES: u64 = 25 * 1024 * 1024;

/// A typed attachment carried by an inbound or outbound message.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct Attachment {
    /// Optional human-readable file name.
    pub file_name: Option<String>,
    /// IANA media type, such as `image/png`.
    pub media_type: String,
    /// Declared size in bytes.
    pub byte_len: u64,
    /// Content location or inline bytes.
    pub source: AttachmentSource,
}

impl Attachment {
    /// Validates common attachment invariants before transport-specific work.
    ///
    /// # Errors
    ///
    /// - [`InvalidMessageReason::InvalidMediaType`] when the media type is
    ///   empty, padded with whitespace, missing the `/` separator, or contains
    ///   a control character.
    /// - [`InvalidMessageReason::AttachmentTooLarge`] when `byte_len` exceeds
    ///   [`MAX_ATTACHMENT_BYTES`].
    /// - [`InvalidMessageReason::AttachmentLengthMismatch`] when inline bytes
    ///   are present and their length is not exactly `byte_len`, so a truncated
    ///   upload cannot be presented as a complete one.
    /// - [`InvalidMessageReason::InvalidAttachmentUrl`] when a remote source is
    ///   not an `http://` or `https://` URL.
    pub fn validate(&self) -> Result<(), InvalidMessageReason> {
        if self.media_type.is_empty()
            || self.media_type.trim() != self.media_type
            || !self.media_type.contains('/')
            || self.media_type.chars().any(char::is_control)
        {
            return Err(InvalidMessageReason::InvalidMediaType);
        }
        if self.byte_len > MAX_ATTACHMENT_BYTES {
            return Err(InvalidMessageReason::AttachmentTooLarge);
        }
        match &self.source {
            AttachmentSource::Inline(bytes)
                if u64::try_from(bytes.len()).ok() != Some(self.byte_len) =>
            {
                Err(InvalidMessageReason::AttachmentLengthMismatch)
            }
            AttachmentSource::Remote(url)
                if !url.starts_with("https://") && !url.starts_with("http://") =>
            {
                Err(InvalidMessageReason::InvalidAttachmentUrl)
            }
            _ => Ok(()),
        }
    }
}

/// Storage form for attachment content.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AttachmentSource {
    /// Bytes supplied directly by the caller.
    Inline(Vec<u8>),
    /// HTTP(S) URL to content resolved by an adapter.
    Remote(String),
}

/// A normalized message received from a channel.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct InboundMessage {
    /// Provider-assigned message identifier.
    pub id: String,
    /// Registered channel identifier.
    pub channel_id: String,
    /// Configured account identifier.
    pub account_id: String,
    /// Provider conversation, room, or peer identifier.
    pub conversation_id: String,
    /// Provider sender identifier.
    pub sender_id: String,
    /// Optional textual body.
    pub text: Option<String>,
    /// Typed attachments.
    pub attachments: Vec<Attachment>,
    /// Receive timestamp in Unix milliseconds.
    pub received_at_unix_ms: u64,
}

impl InboundMessage {
    /// Validates common identifiers and content invariants.
    ///
    /// # Errors
    ///
    /// - [`InvalidMessageReason::InvalidIdentifier`] when the message id,
    ///   channel id, account id, conversation id, or sender id is empty, longer
    ///   than 256 bytes, padded with whitespace, or contains a control
    ///   character.
    /// - [`InvalidMessageReason::EmptyContent`] when the message carries
    ///   neither text nor attachments and so has nothing to deliver.
    /// - [`InvalidMessageReason::InvalidText`] when the text contains a null
    ///   character.
    /// - Any reason from [`Attachment::validate`] for the first attachment that
    ///   fails.
    pub fn validate(&self) -> Result<(), InvalidMessageReason> {
        validate_message_fields(
            [
                self.id.as_str(),
                self.channel_id.as_str(),
                self.account_id.as_str(),
                self.conversation_id.as_str(),
                self.sender_id.as_str(),
            ],
            self.text.as_deref(),
            &self.attachments,
        )
    }
}

/// A normalized message to be sent through a channel.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct OutboundMessage {
    /// Caller-assigned correlation identifier.
    ///
    /// This value supports tracing only. It does not imply provider-side
    /// deduplication or make delivery safe to retry.
    pub correlation_key: String,
    /// Configured account identifier.
    pub account_id: String,
    /// Provider conversation, room, or peer identifier.
    pub conversation_id: String,
    /// Optional textual body.
    pub text: Option<String>,
    /// Typed attachments.
    pub attachments: Vec<Attachment>,
    /// Optional provider message identifier being replied to.
    pub reply_to: Option<String>,
}

impl OutboundMessage {
    /// Validates common identifiers and content invariants.
    ///
    /// # Errors
    ///
    /// - [`InvalidMessageReason::InvalidIdentifier`] when the correlation key,
    ///   account id, conversation id, or `reply_to` id is empty, longer than
    ///   256 bytes, padded with whitespace, or contains a control character.
    /// - [`InvalidMessageReason::EmptyContent`] when the message carries
    ///   neither text nor attachments and so has nothing to deliver.
    /// - [`InvalidMessageReason::InvalidText`] when the text contains a null
    ///   character.
    /// - Any reason from [`Attachment::validate`] for the first attachment that
    ///   fails.
    pub fn validate(&self) -> Result<(), InvalidMessageReason> {
        validate_message_fields(
            [
                self.correlation_key.as_str(),
                self.account_id.as_str(),
                self.conversation_id.as_str(),
            ],
            self.text.as_deref(),
            &self.attachments,
        )?;
        if self.reply_to.as_deref().is_some_and(invalid_identifier) {
            return Err(InvalidMessageReason::InvalidIdentifier);
        }
        Ok(())
    }
}

fn validate_message_fields<const N: usize>(
    identifiers: [&str; N],
    text: Option<&str>,
    attachments: &[Attachment],
) -> Result<(), InvalidMessageReason> {
    if identifiers.into_iter().any(invalid_identifier) {
        return Err(InvalidMessageReason::InvalidIdentifier);
    }
    if text.is_none_or(str::is_empty) && attachments.is_empty() {
        return Err(InvalidMessageReason::EmptyContent);
    }
    if text.is_some_and(|value| value.chars().any(|character| character == '\0')) {
        return Err(InvalidMessageReason::InvalidText);
    }
    for attachment in attachments {
        attachment.validate()?;
    }
    Ok(())
}

fn invalid_identifier(value: &str) -> bool {
    value.is_empty()
        || value.len() > 256
        || value.trim() != value
        || value.chars().any(char::is_control)
}

/// Confirmation returned after an outbound delivery attempt is accepted.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct DeliveryAcknowledgement {
    /// Correlation key copied verbatim from the outbound message.
    ///
    /// Its presence confirms request/response correlation only, not that the
    /// channel or provider deduplicated this delivery.
    pub correlation_key: String,
    /// Provider-assigned message identifier when one is available.
    pub remote_message_id: Option<String>,
    /// Provider delivery state.
    pub state: DeliveryState,
    /// Acceptance timestamp in Unix milliseconds.
    pub accepted_at_unix_ms: u64,
}

/// Provider delivery state represented without overclaiming final delivery.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum DeliveryState {
    /// The provider accepted the operation.
    Accepted,
    /// The provider queued the operation.
    Queued,
    /// The provider explicitly confirmed final delivery.
    Delivered,
}

/// Whether an outbound delivery operation is safe to repeat after failure.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub enum OutboundRetrySafety {
    /// Retrying may duplicate delivery.
    ///
    /// This is the default because an omitted declaration must cost a delivery
    /// rather than silently duplicate one.
    #[default]
    NotSafeToRepeat,
    /// The channel positively guarantees repeated attempts are deduplicated.
    SafeToRepeat,
}

/// Core inbound and outbound behavior implemented by a channel adapter.
pub trait Channel {
    /// Returns the exact registered channel identifier.
    fn id(&self) -> &str;

    /// Polls one normalized inbound message.
    ///
    /// # Errors
    ///
    /// Implementations return [`ChannelError::Unsupported`] with
    /// [`UnsupportedOperation::Inbound`] when the adapter is outbound-only,
    /// [`ChannelError::NotConnected`] when no session is open,
    /// [`ChannelError::Transport`] when the poll itself failed, and
    /// [`ChannelError::Protocol`] when the provider answered with a payload
    /// that could not be normalized into an [`InboundMessage`].
    fn poll_inbound(&mut self) -> Result<Option<InboundMessage>, ChannelError>;

    /// Declares whether failed outbound attempts are safe to repeat.
    ///
    /// Implementations must override this only when they positively enforce
    /// deduplication across repeated attempts. The default fails closed.
    fn outbound_retry_safety(&self) -> OutboundRetrySafety {
        OutboundRetrySafety::NotSafeToRepeat
    }

    /// Sends one normalized outbound message with an optional scoped credential.
    ///
    /// # Errors
    ///
    /// Implementations return [`ChannelError::InvalidMessage`] when
    /// [`OutboundMessage::validate`] rejects the message,
    /// [`ChannelError::Configuration`] when the message is addressed to an
    /// account or conversation this adapter is not bound to,
    /// [`ChannelError::Credential`] when a credential this channel requires was
    /// not supplied, [`ChannelError::CredentialBinding`] when the supplied
    /// credential is enrolled for another scope or destination,
    /// [`ChannelError::Unsupported`] for attachments or replies the adapter does
    /// not implement, [`ChannelError::NotConnected`] when no session is open,
    /// and [`ChannelError::Authentication`], [`ChannelError::RateLimited`],
    /// [`ChannelError::RemoteRejected`], [`ChannelError::Transport`] or
    /// [`ChannelError::Protocol`] for what the provider did with the request.
    fn send_outbound(
        &mut self,
        message: &OutboundMessage,
        credential: Option<&ChannelCredential>,
    ) -> Result<DeliveryAcknowledgement, ChannelError>;
}

/// Scope used to retrieve one channel credential.
#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub struct CredentialRequest {
    /// Exact registered channel identifier.
    pub channel_id: String,
    /// Configured account identifier.
    pub account_id: String,
    /// Credential purpose.
    pub kind: CredentialKind,
    /// Destination capability this credential is authorized for.
    ///
    /// Secret stores must include this binding in their lookup key. Changing a
    /// network origin therefore selects a different credential rather than
    /// silently reusing the old one.
    pub binding: CredentialBinding,
}

/// Closed set of channel credential purposes.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum CredentialKind {
    /// Long-lived bearer or bot token.
    Token,
    /// Incoming webhook URL, treated as a credential because it embeds a secret.
    WebhookUrl,
    /// OAuth client secret.
    ClientSecret,
    /// Password or application password.
    Password,
    /// Private signing or identity key.
    PrivateKey,
}

/// Approved destination bound to a stored credential.
#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub enum CredentialBinding {
    /// Credential may be attached only to this exact HTTPS origin.
    Origin(ApprovedOrigin),
    /// Credential is itself a complete endpoint, such as a webhook URL.
    ///
    /// Because destination and secret are one value, no independent base URL
    /// can be swapped while retaining the credential.
    EmbeddedEndpoint,
    /// Credential may be consumed only by a local, non-network operation.
    LocalOnly,
}

/// Canonical HTTPS origin parsed from configuration but not yet trusted.
///
/// The origin contains only scheme, host, and optional port. Paths, queries,
/// fragments, user information, and plaintext HTTP are not representable.
#[derive(Clone, Eq, Hash, PartialEq)]
pub struct NetworkOrigin {
    host: String,
    port: Option<u16>,
}

impl NetworkOrigin {
    /// Parses an HTTPS host and optional non-zero port.
    ///
    /// # Errors
    ///
    /// - [`NetworkOriginError::InvalidPort`] when the port is explicitly `0`.
    /// - [`NetworkOriginError::InvalidHost`] when the host is empty, longer
    ///   than 253 bytes, padded with whitespace, contains a control character,
    ///   contains any of `/ \ @ ? # [ ]`, ends with a dot, or has a DNS label
    ///   that is empty, longer than 63 bytes, hyphen-anchored, or not
    ///   alphanumeric-or-hyphen. Every one of these would let a path, query,
    ///   user-info, or trailing-dot spelling smuggle a second destination past
    ///   an origin comparison.
    /// - [`NetworkOriginError::AmbiguousIpLiteral`] when the host is a decimal,
    ///   octal, or hexadecimal spelling of an IP address such as `2130706433`
    ///   or `0x7f000001`. These resolve like an address but compare like a
    ///   name, so they are refused rather than canonicalized.
    pub fn https(host: &str, port: Option<u16>) -> Result<Self, NetworkOriginError> {
        if port == Some(0) {
            return Err(NetworkOriginError::InvalidPort);
        }
        let canonical_host = canonical_host(host)?;
        Ok(Self {
            host: canonical_host,
            port,
        })
    }

    /// Returns the canonical HTTPS origin.
    #[must_use]
    pub fn as_str(&self) -> String {
        self.to_string()
    }

    /// Returns the canonical host without brackets.
    ///
    /// Trust policy implementations should use this value for DNS and address
    /// classification rather than reparsing [`Self::as_str`].
    #[must_use]
    pub fn host(&self) -> &str {
        &self.host
    }

    /// Returns the explicitly enrolled port.
    #[must_use]
    pub const fn port(&self) -> Option<u16> {
        self.port
    }
}

impl Debug for NetworkOrigin {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter
            .debug_tuple("NetworkOrigin")
            .field(&self.as_str())
            .finish()
    }
}

impl Display for NetworkOrigin {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter.write_str("https://")?;
        if self.host.contains(':') {
            write!(formatter, "[{}]", self.host)?;
        } else {
            formatter.write_str(&self.host)?;
        }
        if let Some(port) = self.port {
            write!(formatter, ":{port}")?;
        }
        Ok(())
    }
}

fn canonical_host(host: &str) -> Result<String, NetworkOriginError> {
    if host.is_empty()
        || host.len() > 253
        || host.trim() != host
        || host.chars().any(char::is_control)
        || host.contains(['/', '\\', '@', '?', '#', '[', ']'])
    {
        return Err(NetworkOriginError::InvalidHost);
    }
    if let Ok(address) = std::net::IpAddr::from_str(host) {
        return Ok(match address {
            std::net::IpAddr::V6(address) => address
                .to_ipv4_mapped()
                .map_or_else(|| address.to_string(), |mapped| mapped.to_string()),
            std::net::IpAddr::V4(address) => address.to_string(),
        });
    }
    let labels = host.split('.').collect::<Vec<_>>();
    let ambiguous_ipv4 = labels
        .iter()
        .all(|label| !label.is_empty() && label.bytes().all(|byte| byte.is_ascii_digit()))
        || labels.iter().any(|label| {
            label
                .strip_prefix("0x")
                .or_else(|| label.strip_prefix("0X"))
                .is_some_and(|hex| {
                    !hex.is_empty() && hex.bytes().all(|byte| byte.is_ascii_hexdigit())
                })
        });
    if ambiguous_ipv4 {
        return Err(NetworkOriginError::AmbiguousIpLiteral);
    }
    if host.ends_with('.')
        || host.split('.').any(|label| {
            label.is_empty()
                || label.len() > 63
                || label.starts_with('-')
                || label.ends_with('-')
                || !label
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
        })
    {
        return Err(NetworkOriginError::InvalidHost);
    }
    Ok(host.to_ascii_lowercase())
}

/// Invalid network-origin syntax.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum NetworkOriginError {
    /// Host syntax is malformed or includes URL components.
    InvalidHost,
    /// Host uses a non-canonical decimal, octal, or hexadecimal IP spelling.
    AmbiguousIpLiteral,
    /// Explicit port is zero.
    InvalidPort,
}

impl Display for NetworkOriginError {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::InvalidHost => "network origin host is invalid",
            Self::AmbiguousIpLiteral => "network origin uses an ambiguous IP literal",
            Self::InvalidPort => "network origin port is invalid",
        })
    }
}

impl Error for NetworkOriginError {}

/// Policy port for explicit channel-origin trust enrollment.
///
/// Implementations own durable enrollment and SSRF policy, including decisions
/// about private, loopback, link-local, and DNS-resolved addresses. A parsed
/// [`NetworkOrigin`] cannot bind a credential until this port authorizes the
/// exact channel and account.
pub trait OriginTrustStore {
    /// Returns whether the exact scope and origin were explicitly enrolled.
    ///
    /// # Errors
    ///
    /// Implementations return [`OriginTrustError::Unavailable`] when the
    /// enrollment record could not be read at all, and
    /// [`OriginTrustError::PolicyDenied`] when the origin is refused on policy
    /// grounds regardless of enrollment, such as a loopback, link-local, or
    /// otherwise private destination an operator is not allowed to enroll. An
    /// origin that is simply not enrolled is `Ok(false)`, not an error, so a
    /// missing enrollment cannot be confused with a broken policy store.
    fn is_enrolled(
        &self,
        channel_id: &str,
        account_id: &str,
        origin: &NetworkOrigin,
    ) -> Result<bool, OriginTrustError>;
}

/// Origin trust lookup failure.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum OriginTrustError {
    /// Exact channel, account, and origin were not enrolled.
    NotEnrolled,
    /// Trust policy denied this origin.
    PolicyDenied,
    /// Trust enrollment backend is unavailable.
    Unavailable,
}

impl Display for OriginTrustError {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::NotEnrolled => "channel origin is not enrolled",
            Self::PolicyDenied => "channel origin is denied by policy",
            Self::Unavailable => "channel origin trust store is unavailable",
        })
    }
}

impl Error for OriginTrustError {}

/// Unforgeable proof that one exact channel/account origin was enrolled.
#[derive(Clone, Eq, Hash, PartialEq)]
pub struct ApprovedOrigin {
    channel_id: String,
    account_id: String,
    origin: NetworkOrigin,
}

impl ApprovedOrigin {
    /// Returns the canonical HTTPS origin.
    #[must_use]
    pub fn as_str(&self) -> String {
        self.origin.as_str()
    }
}

impl Debug for ApprovedOrigin {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ApprovedOrigin")
            .field("channel_id", &self.channel_id)
            .field("account_id", &self.account_id)
            .field("origin", &self.origin)
            .finish()
    }
}

impl Display for ApprovedOrigin {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        Display::fmt(&self.origin, formatter)
    }
}

/// Authorizes a parsed origin through explicit durable enrollment.
///
/// # Errors
///
/// - [`OriginTrustError::PolicyDenied`] when `channel_id` or `account_id` is
///   empty, because an unscoped enrollment would authorize every channel.
/// - [`OriginTrustError::NotEnrolled`] when the trust store has no enrollment
///   for this exact channel, account, and origin. This is what an operator sees
///   after pointing a channel at a self-hosted endpoint without enrolling it.
/// - Whatever [`OriginTrustStore::is_enrolled`] returned, unchanged, when the
///   policy store itself refused or could not answer.
pub fn authorize_origin<T: OriginTrustStore>(
    trust: &T,
    channel_id: &str,
    account_id: &str,
    origin: &NetworkOrigin,
) -> Result<ApprovedOrigin, OriginTrustError> {
    if channel_id.is_empty() || account_id.is_empty() {
        return Err(OriginTrustError::PolicyDenied);
    }
    if !trust.is_enrolled(channel_id, account_id, origin)? {
        return Err(OriginTrustError::NotEnrolled);
    }
    Ok(ApprovedOrigin {
        channel_id: channel_id.to_owned(),
        account_id: account_id.to_owned(),
        origin: origin.clone(),
    })
}

/// Secret channel credential with redacted formatting.
///
/// The value is not serializable. Its enrollment scope is inseparable from the
/// secret, and each exposure method verifies channel, account, purpose, and
/// destination before lending the bytes to an adapter operation.
#[derive(Clone)]
pub struct ChannelCredential {
    secret: SecretString,
    scope: CredentialRequest,
}

impl ChannelCredential {
    /// Binds owned secret material to the exact request used as its store key.
    ///
    /// # Errors
    ///
    /// - [`CredentialBindingError::ScopeMismatch`] when the scope's channel or
    ///   account id is empty, over 256 bytes, whitespace-padded, or contains a
    ///   control character, and when the scope carries an [`ApprovedOrigin`]
    ///   that was enrolled for a different channel or account. The second case
    ///   is the one that matters: it stops one channel's enrollment from
    ///   authorizing another channel's secret.
    /// - [`CredentialBindingError::InvalidBinding`] when
    ///   [`CredentialKind::WebhookUrl`] is paired with anything other than
    ///   [`CredentialBinding::EmbeddedEndpoint`], or that binding is used for
    ///   any other kind. A webhook URL is its own destination, so the two must
    ///   travel together.
    pub fn bind(
        secret: impl Into<String>,
        scope: CredentialRequest,
    ) -> Result<Self, CredentialBindingError> {
        if invalid_identifier(&scope.channel_id) || invalid_identifier(&scope.account_id) {
            return Err(CredentialBindingError::ScopeMismatch);
        }
        match (&scope.kind, &scope.binding) {
            (CredentialKind::WebhookUrl, CredentialBinding::EmbeddedEndpoint) => {}
            (CredentialKind::WebhookUrl, _) | (_, CredentialBinding::EmbeddedEndpoint) => {
                return Err(CredentialBindingError::InvalidBinding);
            }
            (_, CredentialBinding::Origin(origin))
                if origin.channel_id != scope.channel_id
                    || origin.account_id != scope.account_id =>
            {
                return Err(CredentialBindingError::ScopeMismatch);
            }
            _ => {}
        }
        Ok(Self {
            secret: SecretString::from(secret.into()),
            scope,
        })
    }

    /// Returns whether this credential came from the exact requested store key.
    #[must_use]
    pub fn matches_request(&self, request: &CredentialRequest) -> bool {
        &self.scope == request
    }

    /// Exposes an origin-bound credential only to its approved HTTPS origin.
    ///
    /// # Errors
    ///
    /// - [`CredentialBindingError::ScopeMismatch`] when `channel_id`,
    ///   `account_id`, or `kind` differs from the enrollment this credential
    ///   was bound to.
    /// - [`CredentialBindingError::DestinationMismatch`] when the credential is
    ///   not origin-bound at all, or is bound to a different approved origin
    ///   than `origin`. This is the check that stops a redirected or
    ///   reconfigured endpoint from receiving the old secret.
    ///
    /// The secret is lent to `operation` only after both checks pass.
    pub fn expose_for_origin<T>(
        &self,
        channel_id: &str,
        account_id: &str,
        kind: CredentialKind,
        origin: &ApprovedOrigin,
        operation: impl FnOnce(&str) -> T,
    ) -> Result<T, CredentialBindingError> {
        self.require_scope(
            channel_id,
            account_id,
            kind,
            &CredentialBinding::Origin(origin.clone()),
        )?;
        Ok(operation(self.secret.expose_secret()))
    }

    /// Exposes a credential that embeds its own endpoint.
    ///
    /// # Errors
    ///
    /// - [`CredentialBindingError::ScopeMismatch`] when `channel_id` or
    ///   `account_id` differs from the enrollment, or the credential is not a
    ///   [`CredentialKind::WebhookUrl`]. A bot token can never be posted as a
    ///   webhook URL.
    /// - [`CredentialBindingError::DestinationMismatch`] when the credential is
    ///   a webhook URL bound to an origin or to local use instead of being its
    ///   own endpoint.
    pub fn expose_embedded_endpoint<T>(
        &self,
        channel_id: &str,
        account_id: &str,
        operation: impl FnOnce(&str) -> T,
    ) -> Result<T, CredentialBindingError> {
        self.require_scope(
            channel_id,
            account_id,
            CredentialKind::WebhookUrl,
            &CredentialBinding::EmbeddedEndpoint,
        )?;
        Ok(operation(self.secret.expose_secret()))
    }

    /// Exposes a local-only credential to a matching local operation.
    ///
    /// # Errors
    ///
    /// - [`CredentialBindingError::ScopeMismatch`] when `channel_id`,
    ///   `account_id`, or `kind` differs from the enrollment.
    /// - [`CredentialBindingError::DestinationMismatch`] when the credential is
    ///   bound to a network origin or is an embedded endpoint, so a secret
    ///   enrolled for a remote provider cannot be handed to a local companion
    ///   service.
    pub fn expose_local<T>(
        &self,
        channel_id: &str,
        account_id: &str,
        kind: CredentialKind,
        operation: impl FnOnce(&str) -> T,
    ) -> Result<T, CredentialBindingError> {
        self.require_scope(channel_id, account_id, kind, &CredentialBinding::LocalOnly)?;
        Ok(operation(self.secret.expose_secret()))
    }

    fn require_scope(
        &self,
        channel_id: &str,
        account_id: &str,
        kind: CredentialKind,
        binding: &CredentialBinding,
    ) -> Result<(), CredentialBindingError> {
        if self.scope.channel_id != channel_id
            || self.scope.account_id != account_id
            || self.scope.kind != kind
        {
            return Err(CredentialBindingError::ScopeMismatch);
        }
        if &self.scope.binding != binding {
            return Err(CredentialBindingError::DestinationMismatch);
        }
        Ok(())
    }
}

impl Debug for ChannelCredential {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter.write_str("ChannelCredential([REDACTED])")
    }
}

impl Display for ChannelCredential {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter.write_str("channel-credential:[REDACTED]")
    }
}

/// Credential exposure denied before secret bytes reach a transport.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CredentialBindingError {
    /// Channel, account, or credential purpose does not match enrollment.
    ScopeMismatch,
    /// Destination does not match the enrolled origin or endpoint form.
    DestinationMismatch,
    /// Credential purpose and binding form are incompatible.
    InvalidBinding,
}

impl Display for CredentialBindingError {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::ScopeMismatch => "channel credential scope does not match",
            Self::DestinationMismatch => "channel credential destination does not match",
            Self::InvalidBinding => "channel credential binding form is invalid",
        })
    }
}

impl Error for CredentialBindingError {}

/// Port for retrieving credentials from platform-owned secure storage.
pub trait SecretStore {
    /// Retrieves exactly one scoped credential.
    ///
    /// # Errors
    ///
    /// Implementations return [`SecretStoreError::NotFound`] when nothing is
    /// stored for this exact channel, account, purpose, and destination — the
    /// error an operator sees when a channel is enabled before its credential
    /// is provisioned; [`SecretStoreError::AccessDenied`] when the platform
    /// keychain refused the process; [`SecretStoreError::Unavailable`] when the
    /// backend could not be reached or is locked; and
    /// [`SecretStoreError::InvalidCredential`] when the stored material exists
    /// but cannot be bound to the requested scope.
    fn get(&self, request: &CredentialRequest) -> Result<ChannelCredential, SecretStoreError>;
}

/// Failures returned by a secret store without carrying backend strings.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SecretStoreError {
    /// No credential exists for the requested scope.
    NotFound,
    /// Access to the secure backend was denied.
    AccessDenied,
    /// The secure backend is unavailable.
    Unavailable,
    /// Stored credential material is malformed.
    InvalidCredential,
}

impl Display for SecretStoreError {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::NotFound => "channel credential was not found",
            Self::AccessDenied => "channel credential access was denied",
            Self::Unavailable => "channel credential store is unavailable",
            Self::InvalidCredential => "stored channel credential is invalid",
        })
    }
}

impl Error for SecretStoreError {}

/// Sends with a credential loaded from a scope-checked [`SecretStore`].
///
/// # Errors
///
/// - [`ChannelError::Configuration`] with
///   [`ConfigurationError::CredentialScopeMismatch`] when the request names a
///   different channel than the adapter reports, or a different account than
///   the message is addressed to. The store is not consulted in that case.
/// - [`ChannelError::Credential`] with whatever the store reported, typically
///   [`SecretStoreError::NotFound`] for a channel whose credential was never
///   provisioned.
/// - [`ChannelError::CredentialBinding`] with
///   [`CredentialBindingError::ScopeMismatch`] when the store answered with a
///   credential enrolled for some other scope than the one requested.
/// - Whatever [`Channel::send_outbound`] returned once the credential was
///   loaded and scope-checked.
pub fn send_using_store<C, S>(
    channel: &mut C,
    store: &S,
    request: &CredentialRequest,
    message: &OutboundMessage,
) -> Result<DeliveryAcknowledgement, ChannelError>
where
    C: Channel,
    S: SecretStore,
{
    if request.channel_id != channel.id() || request.account_id != message.account_id {
        return Err(ChannelError::Configuration(
            ConfigurationError::CredentialScopeMismatch,
        ));
    }
    let credential = store.get(request).map_err(ChannelError::Credential)?;
    if !credential.matches_request(request) {
        return Err(ChannelError::CredentialBinding(
            CredentialBindingError::ScopeMismatch,
        ));
    }
    channel.send_outbound(message, Some(&credential))
}

/// Validated exponential retry configuration.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RetryPolicy {
    max_attempts: NonZeroU32,
    initial_delay: Duration,
    max_delay: Duration,
    multiplier: NonZeroU32,
}

impl RetryPolicy {
    /// Creates a retry policy.
    ///
    /// # Errors
    ///
    /// Returns [`ConfigurationError::InvalidRetryPolicy`] when `initial_delay`
    /// is zero, which would make the backoff spin, or when `max_delay` is
    /// shorter than `initial_delay`, which would clamp the very first wait to
    /// less than the operator asked for.
    pub fn new(
        max_attempts: NonZeroU32,
        initial_delay: Duration,
        max_delay: Duration,
        multiplier: NonZeroU32,
    ) -> Result<Self, ConfigurationError> {
        if initial_delay.is_zero() || max_delay < initial_delay {
            return Err(ConfigurationError::InvalidRetryPolicy);
        }
        Ok(Self {
            max_attempts,
            initial_delay,
            max_delay,
            multiplier,
        })
    }

    /// Returns the maximum number of attempts, including the first.
    #[must_use]
    pub const fn max_attempts(self) -> NonZeroU32 {
        self.max_attempts
    }
}

/// Port for retry delays, enabling deterministic tests and runtime cancellation.
pub trait BackoffSleeper {
    /// Blocks or asynchronously delegates one retry delay.
    fn sleep(&mut self, delay: Duration);
}

/// Sends an outbound message and retries only when the channel declares it safe.
///
/// A retryable error alone is insufficient: it may have happened after a
/// provider accepted the message. The channel must positively guarantee that
/// repeating the operation cannot duplicate delivery.
///
/// # Errors
///
/// Returns the error [`Channel::send_outbound`] last produced. That happens on
/// the first attempt when the error is not retryable, when the channel declares
/// [`OutboundRetrySafety::NotSafeToRepeat`] — the default, so an undeclared
/// channel never retries — and otherwise once the policy's attempt budget is
/// spent. Typical values an operator sees are [`ChannelError::Credential`] for
/// a channel with no provisioned secret, [`ChannelError::Authentication`] for a
/// rejected token, and [`ChannelError::RateLimited`] or
/// [`ChannelError::Transport`] when every permitted attempt failed.
pub fn send_with_retry<C, S>(
    channel: &mut C,
    message: &OutboundMessage,
    credential: Option<&ChannelCredential>,
    policy: RetryPolicy,
    sleeper: &mut S,
) -> Result<DeliveryAcknowledgement, ChannelError>
where
    C: Channel,
    S: BackoffSleeper,
{
    let mut delay = policy.initial_delay;
    let retry_safety = channel.outbound_retry_safety();
    for attempt in 1..=policy.max_attempts.get() {
        match channel.send_outbound(message, credential) {
            Ok(acknowledgement) => return Ok(acknowledgement),
            Err(error)
                if error.is_retryable()
                    && attempt < policy.max_attempts.get()
                    && retry_safety == OutboundRetrySafety::SafeToRepeat =>
            {
                let requested_delay = error.retry_after().unwrap_or(delay);
                sleeper.sleep(requested_delay.min(policy.max_delay));
                delay = delay
                    .saturating_mul(policy.multiplier.get())
                    .min(policy.max_delay);
            }
            Err(error) => return Err(error),
        }
    }
    unreachable!("a non-zero retry policy always performs at least one attempt")
}

/// Fixed-window outbound rate limiter with explicit caller-supplied time.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RateLimiter {
    limit: NonZeroU32,
    window: Duration,
    window_started_at: Duration,
    used: u32,
}

impl RateLimiter {
    /// Creates a limiter beginning at `started_at`.
    ///
    /// # Errors
    ///
    /// Returns [`ConfigurationError::InvalidRateLimit`] when `window` is zero,
    /// which would restart the window on every call and let the limit through
    /// unenforced.
    pub const fn new(
        limit: NonZeroU32,
        window: Duration,
        started_at: Duration,
    ) -> Result<Self, ConfigurationError> {
        if window.is_zero() {
            return Err(ConfigurationError::InvalidRateLimit);
        }
        Ok(Self {
            limit,
            window,
            window_started_at: started_at,
            used: 0,
        })
    }

    /// Consumes one permit or returns an exact retry duration.
    ///
    /// # Errors
    ///
    /// Returns [`ChannelError::RateLimited`] when this window's permits are
    /// already spent. `retry_after` is the exact remainder of the current
    /// window, so a caller can wait that long instead of guessing. A `now`
    /// earlier than the window start is treated as a clock step and opens a
    /// fresh window rather than locking the channel out.
    pub fn acquire(&mut self, now: Duration) -> Result<(), ChannelError> {
        let elapsed = now.saturating_sub(self.window_started_at);
        if elapsed >= self.window || now < self.window_started_at {
            self.window_started_at = now;
            self.used = 0;
        }
        if self.used >= self.limit.get() {
            return Err(ChannelError::RateLimited {
                retry_after: self.window.saturating_sub(elapsed),
            });
        }
        self.used += 1;
        Ok(())
    }
}

/// Common message validation failures.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum InvalidMessageReason {
    /// A required identifier is empty, malformed, or too long.
    InvalidIdentifier,
    /// Neither text nor attachments were supplied.
    EmptyContent,
    /// Text contains a forbidden null character.
    InvalidText,
    /// Media type syntax is invalid.
    InvalidMediaType,
    /// Attachment exceeds the common size bound.
    AttachmentTooLarge,
    /// Inline byte length differs from the declared length.
    AttachmentLengthMismatch,
    /// Remote attachment URL is not HTTP(S).
    InvalidAttachmentUrl,
}

/// Channel setup errors.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ConfigurationError {
    /// Credential scope does not match channel or account routing.
    CredentialScopeMismatch,
    /// Message conversation does not match the adapter's bound destination.
    ConversationScopeMismatch,
    /// Retry parameters are inconsistent.
    InvalidRetryPolicy,
    /// Rate limit window is zero.
    InvalidRateLimit,
    /// Adapter-specific configuration is absent or malformed.
    InvalidAdapterConfiguration,
}

/// Network failure category without unsafe backend-provided strings.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TransportErrorKind {
    /// Connection could not be established.
    Connection,
    /// Operation timed out.
    Timeout,
    /// Name resolution failed.
    NameResolution,
    /// TLS negotiation or certificate validation failed.
    Tls,
    /// Local input/output operation failed.
    Io,
}

/// Protocol failure category without response body leakage.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ProtocolErrorKind {
    /// Response framing is malformed.
    MalformedResponse,
    /// Required response field is absent.
    MissingField,
    /// Response field has an invalid value.
    InvalidField,
}

/// Operation not supported by an adapter.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum UnsupportedOperation {
    /// Adapter does not implement inbound polling.
    Inbound,
    /// Adapter does not implement outbound delivery.
    Outbound,
    /// Adapter does not implement attachments.
    Attachments,
    /// Adapter does not implement replies.
    Replies,
}

/// Closed, credential-safe channel failure taxonomy.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ChannelError {
    /// Common message validation failed.
    InvalidMessage(InvalidMessageReason),
    /// Adapter setup is invalid.
    Configuration(ConfigurationError),
    /// Credential retrieval failed.
    Credential(SecretStoreError),
    /// Credential is not enrolled for the requested scope or destination.
    CredentialBinding(CredentialBindingError),
    /// Remote authentication failed.
    Authentication,
    /// Local or remote rate limit was reached.
    RateLimited {
        /// Duration before another attempt is allowed.
        retry_after: Duration,
    },
    /// Transport failed.
    Transport(TransportErrorKind),
    /// Remote response violated the expected protocol.
    Protocol(ProtocolErrorKind),
    /// Remote endpoint rejected the operation.
    RemoteRejected {
        /// HTTP-like status code without a response body.
        status: u16,
    },
    /// Adapter does not implement the requested operation.
    Unsupported(UnsupportedOperation),
    /// A lifecycle event was requested in a state that forbids it.
    Lifecycle(IllegalTransition),
    /// Messages were exchanged while no session was open.
    NotConnected {
        /// State the channel was actually in.
        state: ConnectionState,
    },
}

impl ChannelError {
    /// Returns whether retrying can succeed without changing input or credentials.
    #[must_use]
    pub const fn is_retryable(&self) -> bool {
        match self {
            Self::RateLimited { .. }
            | Self::Transport(
                TransportErrorKind::Connection
                | TransportErrorKind::Timeout
                | TransportErrorKind::NameResolution
                | TransportErrorKind::Io,
            ) => true,
            Self::RemoteRejected { status } => *status == 429 || *status >= 500,
            Self::InvalidMessage(_)
            | Self::Configuration(_)
            | Self::Credential(_)
            | Self::CredentialBinding(_)
            | Self::Authentication
            | Self::Transport(TransportErrorKind::Tls)
            | Self::Protocol(_)
            | Self::Unsupported(_)
            | Self::Lifecycle(_)
            | Self::NotConnected { .. } => false,
        }
    }

    /// Returns a provider-requested delay when one was supplied.
    #[must_use]
    pub const fn retry_after(&self) -> Option<Duration> {
        match self {
            Self::RateLimited { retry_after } => Some(*retry_after),
            _ => None,
        }
    }
}

impl Display for ChannelError {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidMessage(reason) => {
                write!(formatter, "invalid channel message: {reason:?}")
            }
            Self::Configuration(reason) => {
                write!(formatter, "invalid channel configuration: {reason:?}")
            }
            Self::Credential(error) => write!(formatter, "channel credential failed: {error}"),
            Self::CredentialBinding(error) => {
                write!(formatter, "channel credential binding failed: {error}")
            }
            Self::Authentication => formatter.write_str("channel authentication failed"),
            Self::RateLimited { retry_after } => {
                write!(formatter, "channel rate limited for {retry_after:?}")
            }
            Self::Transport(kind) => write!(formatter, "channel transport failed: {kind:?}"),
            Self::Protocol(kind) => write!(formatter, "channel protocol failed: {kind:?}"),
            Self::RemoteRejected { status } => {
                write!(formatter, "channel delivery rejected with status {status}")
            }
            Self::Unsupported(operation) => {
                write!(formatter, "channel operation is unsupported: {operation:?}")
            }
            Self::Lifecycle(transition) => Display::fmt(transition, formatter),
            Self::NotConnected { state } => {
                write!(formatter, "channel is not connected: {state:?}")
            }
        }
    }
}

impl Error for ChannelError {}

#[cfg(test)]
mod tests {
    use std::collections::VecDeque;

    use super::*;

    fn message() -> OutboundMessage {
        OutboundMessage {
            correlation_key: "request-1".to_owned(),
            account_id: "primary".to_owned(),
            conversation_id: "room-7".to_owned(),
            text: Some("hello".to_owned()),
            attachments: Vec::new(),
            reply_to: None,
        }
    }

    fn approved_origin() -> ApprovedOrigin {
        let origin = NetworkOrigin::https("API.Example.test", None).expect("valid origin");
        authorize_origin(&AllowTrust, "test", "primary", &origin).expect("enrolled origin")
    }

    fn token_request() -> CredentialRequest {
        CredentialRequest {
            channel_id: "test".to_owned(),
            account_id: "primary".to_owned(),
            kind: CredentialKind::Token,
            binding: CredentialBinding::Origin(approved_origin()),
        }
    }

    struct TestChannel {
        results: VecDeque<Result<DeliveryAcknowledgement, ChannelError>>,
        credentials: Vec<String>,
    }

    impl Channel for TestChannel {
        fn id(&self) -> &'static str {
            "test"
        }

        fn poll_inbound(&mut self) -> Result<Option<InboundMessage>, ChannelError> {
            Ok(None)
        }

        fn send_outbound(
            &mut self,
            _message: &OutboundMessage,
            credential: Option<&ChannelCredential>,
        ) -> Result<DeliveryAcknowledgement, ChannelError> {
            if let Some(credential) = credential {
                let value = credential
                    .expose_for_origin(
                        "test",
                        "primary",
                        CredentialKind::Token,
                        &approved_origin(),
                        str::to_owned,
                    )
                    .map_err(ChannelError::CredentialBinding)?;
                self.credentials.push(value);
            }
            self.results.pop_front().expect("configured result")
        }
    }

    struct SafeRetryChannel(TestChannel);

    impl Channel for SafeRetryChannel {
        fn id(&self) -> &str {
            self.0.id()
        }

        fn poll_inbound(&mut self) -> Result<Option<InboundMessage>, ChannelError> {
            self.0.poll_inbound()
        }

        fn outbound_retry_safety(&self) -> OutboundRetrySafety {
            OutboundRetrySafety::SafeToRepeat
        }

        fn send_outbound(
            &mut self,
            message: &OutboundMessage,
            credential: Option<&ChannelCredential>,
        ) -> Result<DeliveryAcknowledgement, ChannelError> {
            self.0.send_outbound(message, credential)
        }
    }

    #[derive(Default)]
    struct Sleeper(Vec<Duration>);

    impl BackoffSleeper for Sleeper {
        fn sleep(&mut self, delay: Duration) {
            self.0.push(delay);
        }
    }

    struct Store;

    struct AllowTrust;

    impl OriginTrustStore for AllowTrust {
        fn is_enrolled(
            &self,
            _channel_id: &str,
            _account_id: &str,
            _origin: &NetworkOrigin,
        ) -> Result<bool, OriginTrustError> {
            Ok(true)
        }
    }

    struct DenyTrust;

    impl OriginTrustStore for DenyTrust {
        fn is_enrolled(
            &self,
            _channel_id: &str,
            _account_id: &str,
            _origin: &NetworkOrigin,
        ) -> Result<bool, OriginTrustError> {
            Ok(false)
        }
    }

    impl SecretStore for Store {
        fn get(&self, request: &CredentialRequest) -> Result<ChannelCredential, SecretStoreError> {
            ChannelCredential::bind("super-secret-token", request.clone())
                .map_err(|_| SecretStoreError::InvalidCredential)
        }
    }

    #[test]
    fn credential_formatting_is_fully_redacted() {
        let credential =
            ChannelCredential::bind("super-secret-token", token_request()).expect("valid binding");
        assert_eq!(format!("{credential:?}"), "ChannelCredential([REDACTED])");
        assert_eq!(credential.to_string(), "channel-credential:[REDACTED]");
        assert!(!format!("{credential:?}").contains("super-secret-token"));
        assert!(!credential.to_string().contains("super-secret-token"));
    }

    #[test]
    fn store_delivery_scope_checks_and_does_not_leak_secret() {
        let request = token_request();
        let acknowledgement = DeliveryAcknowledgement {
            correlation_key: "request-1".to_owned(),
            remote_message_id: Some("remote-4".to_owned()),
            state: DeliveryState::Accepted,
            accepted_at_unix_ms: 42,
        };
        let mut channel = TestChannel {
            results: VecDeque::from([Ok(acknowledgement.clone())]),
            credentials: Vec::new(),
        };
        assert_eq!(
            send_using_store(&mut channel, &Store, &request, &message()),
            Ok(acknowledgement)
        );
        assert_eq!(channel.credentials, vec!["super-secret-token".to_owned()]);
        assert!(!format!("{request:?}").contains("super-secret-token"));
    }

    #[test]
    fn origin_bound_credential_cannot_be_reused_after_endpoint_change() {
        let credential =
            ChannelCredential::bind("super-secret-token", token_request()).expect("valid binding");
        let attacker = NetworkOrigin::https("attacker.example", None).expect("valid origin");
        let attacker = authorize_origin(&AllowTrust, "test", "primary", &attacker)
            .expect("separately enrolled origin");
        assert_eq!(
            credential.expose_for_origin(
                "test",
                "primary",
                CredentialKind::Token,
                &attacker,
                str::to_owned,
            ),
            Err(CredentialBindingError::DestinationMismatch)
        );
        let rendered = ChannelError::CredentialBinding(CredentialBindingError::DestinationMismatch)
            .to_string();
        assert_eq!(
            rendered,
            "channel credential binding failed: channel credential destination does not match"
        );
        assert!(!rendered.contains("super-secret-token"));
        assert!(!rendered.contains("attacker.example"));
    }

    #[test]
    fn embedded_endpoint_credential_cannot_be_exposed_as_a_token() {
        let scope = CredentialRequest {
            channel_id: "discord".to_owned(),
            account_id: "primary".to_owned(),
            kind: CredentialKind::WebhookUrl,
            binding: CredentialBinding::EmbeddedEndpoint,
        };
        let credential = ChannelCredential::bind("https://discord.example/secret-hook", scope)
            .expect("valid binding");
        assert_eq!(
            credential.expose_for_origin(
                "discord",
                "primary",
                CredentialKind::Token,
                &approved_origin(),
                str::to_owned,
            ),
            Err(CredentialBindingError::ScopeMismatch)
        );
        assert_eq!(
            credential.expose_embedded_endpoint("discord", "other-account", str::to_owned,),
            Err(CredentialBindingError::ScopeMismatch)
        );
    }

    #[test]
    fn approved_origin_rejects_url_components_and_canonicalizes_host() {
        let origin = approved_origin();
        assert_eq!(origin.as_str(), "https://api.example.test");
        assert_eq!(
            NetworkOrigin::https("api.example.test/path", None),
            Err(NetworkOriginError::InvalidHost)
        );
        assert_eq!(
            NetworkOrigin::https("user@api.example.test", None),
            Err(NetworkOriginError::InvalidHost)
        );
        assert_eq!(
            NetworkOrigin::https("api.example.test", Some(0)),
            Err(NetworkOriginError::InvalidPort)
        );
    }

    #[test]
    fn parsed_origin_cannot_bind_credentials_without_explicit_enrollment() {
        let private_origin =
            NetworkOrigin::https("192.168.1.7", Some(8443)).expect("valid private origin syntax");
        assert_eq!(
            authorize_origin(&DenyTrust, "test", "primary", &private_origin),
            Err(OriginTrustError::NotEnrolled)
        );
        assert_eq!(
            authorize_origin(&AllowTrust, "test", "primary", &private_origin)
                .expect("explicit enterprise enrollment")
                .as_str(),
            "https://192.168.1.7:8443"
        );
    }

    #[test]
    fn ipv4_mapped_ipv6_and_ipv4_share_one_origin_identity() {
        assert_eq!(
            NetworkOrigin::https("::ffff:192.168.1.7", Some(8443)),
            NetworkOrigin::https("192.168.1.7", Some(8443))
        );
    }

    #[test]
    fn ambiguous_ipv4_spellings_are_never_treated_as_dns_hosts() {
        for host in [
            "2130706433",
            "127.1",
            "0177.0.0.1",
            "0x7f.0.0.1",
            "0x7f000001",
        ] {
            assert_eq!(
                NetworkOrigin::https(host, None),
                Err(NetworkOriginError::AmbiguousIpLiteral),
                "{host}"
            );
        }
    }

    #[test]
    fn inconsistent_origin_scope_and_binding_form_are_rejected_at_construction() {
        let network = NetworkOrigin::https("api.example.test", None).expect("valid origin");
        let approved =
            authorize_origin(&AllowTrust, "slack", "primary", &network).expect("enrolled origin");
        assert_eq!(
            ChannelCredential::bind(
                "discord-token",
                CredentialRequest {
                    channel_id: "discord".to_owned(),
                    account_id: "primary".to_owned(),
                    kind: CredentialKind::Token,
                    binding: CredentialBinding::Origin(approved),
                },
            )
            .expect_err("inconsistent scope"),
            CredentialBindingError::ScopeMismatch
        );
        assert_eq!(
            ChannelCredential::bind(
                "not-a-webhook",
                CredentialRequest {
                    channel_id: "discord".to_owned(),
                    account_id: "primary".to_owned(),
                    kind: CredentialKind::Token,
                    binding: CredentialBinding::EmbeddedEndpoint,
                },
            )
            .expect_err("incompatible binding"),
            CredentialBindingError::InvalidBinding
        );
    }

    #[test]
    fn retry_uses_provider_delay_then_stops_on_success() {
        let acknowledgement = DeliveryAcknowledgement {
            correlation_key: "request-1".to_owned(),
            remote_message_id: None,
            state: DeliveryState::Queued,
            accepted_at_unix_ms: 9,
        };
        let mut channel = SafeRetryChannel(TestChannel {
            results: VecDeque::from([
                Err(ChannelError::RateLimited {
                    retry_after: Duration::from_secs(3),
                }),
                Err(ChannelError::Transport(TransportErrorKind::Connection)),
                Ok(acknowledgement.clone()),
            ]),
            credentials: Vec::new(),
        });
        let policy = RetryPolicy::new(
            NonZeroU32::new(3).expect("non-zero"),
            Duration::from_secs(1),
            Duration::from_secs(4),
            NonZeroU32::new(2).expect("non-zero"),
        )
        .expect("valid");
        let mut sleeper = Sleeper::default();
        assert_eq!(
            send_with_retry(&mut channel, &message(), None, policy, &mut sleeper),
            Ok(acknowledgement)
        );
        assert_eq!(
            sleeper.0,
            vec![Duration::from_secs(3), Duration::from_secs(2)]
        );
    }

    #[test]
    fn retry_defaults_closed_when_delivery_is_not_declared_safe_to_repeat() {
        let failure = ChannelError::Transport(TransportErrorKind::Timeout);
        let mut channel = TestChannel {
            results: VecDeque::from([
                Err(failure.clone()),
                Ok(DeliveryAcknowledgement {
                    correlation_key: "request-1".to_owned(),
                    remote_message_id: None,
                    state: DeliveryState::Accepted,
                    accepted_at_unix_ms: 9,
                }),
            ]),
            credentials: Vec::new(),
        };
        let policy = RetryPolicy::new(
            NonZeroU32::new(2).expect("non-zero"),
            Duration::from_secs(1),
            Duration::from_secs(4),
            NonZeroU32::new(2).expect("non-zero"),
        )
        .expect("valid");
        let mut sleeper = Sleeper::default();

        assert_eq!(
            send_with_retry(&mut channel, &message(), None, policy, &mut sleeper),
            Err(failure)
        );
        assert!(sleeper.0.is_empty());
        assert_eq!(channel.results.len(), 1);
    }

    #[test]
    fn fixed_window_limit_returns_exact_retry_after() {
        let mut limiter = RateLimiter::new(
            NonZeroU32::new(2).expect("non-zero"),
            Duration::from_secs(10),
            Duration::from_secs(100),
        )
        .expect("valid");
        assert_eq!(limiter.acquire(Duration::from_secs(100)), Ok(()));
        assert_eq!(limiter.acquire(Duration::from_secs(102)), Ok(()));
        assert_eq!(
            limiter.acquire(Duration::from_secs(104)),
            Err(ChannelError::RateLimited {
                retry_after: Duration::from_secs(6)
            })
        );
        assert_eq!(limiter.acquire(Duration::from_secs(110)), Ok(()));
    }

    #[test]
    fn attachment_length_and_message_content_are_validated() {
        let attachment = Attachment {
            file_name: Some("report.txt".to_owned()),
            media_type: "text/plain".to_owned(),
            byte_len: 4,
            source: AttachmentSource::Inline(vec![1, 2, 3]),
        };
        assert_eq!(
            attachment.validate(),
            Err(InvalidMessageReason::AttachmentLengthMismatch)
        );

        let empty = OutboundMessage {
            text: None,
            ..message()
        };
        assert_eq!(empty.validate(), Err(InvalidMessageReason::EmptyContent));
    }
}

//! Transport-neutral messaging contracts shared by GTA Claw channels.
//!
//! The SDK deliberately owns no network client and no credential persistence.
//! Channel adapters receive secrets through [`SecretStore`] and transports
//! through their own explicit ports.

use std::error::Error;
use std::fmt::{self, Debug, Display, Formatter};
use std::num::NonZeroU32;
use std::time::Duration;

use secrecy::{ExposeSecret, SecretString};
use serde::{Deserialize, Serialize};

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
    /// Caller-assigned idempotency identifier.
    pub idempotency_key: String,
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
    pub fn validate(&self) -> Result<(), InvalidMessageReason> {
        validate_message_fields(
            [
                self.idempotency_key.as_str(),
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
    /// Idempotency key supplied by the caller.
    pub idempotency_key: String,
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

/// Core inbound and outbound behavior implemented by a channel adapter.
pub trait Channel {
    /// Returns the exact registered channel identifier.
    fn id(&self) -> &str;

    /// Polls one normalized inbound message.
    fn poll_inbound(&mut self) -> Result<Option<InboundMessage>, ChannelError>;

    /// Sends one normalized outbound message with an optional scoped credential.
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

/// Secret channel credential with redacted formatting.
///
/// The value is not serializable. Adapters can inspect it only inside
/// [`ChannelCredential::expose_to`], which discourages retaining borrowed bytes.
#[derive(Clone)]
pub struct ChannelCredential(SecretString);

impl ChannelCredential {
    /// Wraps owned secret material returned by a secret store.
    #[must_use]
    pub fn new(secret: impl Into<String>) -> Self {
        Self(SecretString::from(secret.into()))
    }

    /// Exposes the value only for the duration of one adapter operation.
    pub fn expose_to<T>(&self, operation: impl FnOnce(&str) -> T) -> T {
        operation(self.0.expose_secret())
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

/// Port for retrieving credentials from platform-owned secure storage.
pub trait SecretStore {
    /// Retrieves exactly one scoped credential.
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

/// Sends an outbound message and retries only errors classified as retryable.
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
    for attempt in 1..=policy.max_attempts.get() {
        match channel.send_outbound(message, credential) {
            Ok(acknowledgement) => return Ok(acknowledgement),
            Err(error) if error.is_retryable() && attempt < policy.max_attempts.get() => {
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
    pub fn new(
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
}

impl ChannelError {
    /// Returns whether retrying can succeed without changing input or credentials.
    #[must_use]
    pub const fn is_retryable(&self) -> bool {
        match self {
            Self::RateLimited { .. } => true,
            Self::Transport(
                TransportErrorKind::Connection
                | TransportErrorKind::Timeout
                | TransportErrorKind::NameResolution
                | TransportErrorKind::Io,
            ) => true,
            Self::RemoteRejected { status } => *status == 429 || *status >= 500,
            Self::InvalidMessage(_)
            | Self::Configuration(_)
            | Self::Credential(_)
            | Self::Authentication
            | Self::Transport(TransportErrorKind::Tls)
            | Self::Protocol(_)
            | Self::Unsupported(_) => false,
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
            idempotency_key: "request-1".to_owned(),
            account_id: "primary".to_owned(),
            conversation_id: "room-7".to_owned(),
            text: Some("hello".to_owned()),
            attachments: Vec::new(),
            reply_to: None,
        }
    }

    struct TestChannel {
        results: VecDeque<Result<DeliveryAcknowledgement, ChannelError>>,
        credentials: Vec<String>,
    }

    impl Channel for TestChannel {
        fn id(&self) -> &str {
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
                self.credentials.push(credential.expose_to(str::to_owned));
            }
            self.results.pop_front().expect("configured result")
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

    impl SecretStore for Store {
        fn get(&self, _request: &CredentialRequest) -> Result<ChannelCredential, SecretStoreError> {
            Ok(ChannelCredential::new("super-secret-token"))
        }
    }

    #[test]
    fn credential_formatting_is_fully_redacted() {
        let credential = ChannelCredential::new("super-secret-token");
        assert_eq!(format!("{credential:?}"), "ChannelCredential([REDACTED])");
        assert_eq!(credential.to_string(), "channel-credential:[REDACTED]");
        assert!(!format!("{credential:?}").contains("super-secret-token"));
        assert!(!credential.to_string().contains("super-secret-token"));
    }

    #[test]
    fn store_delivery_scope_checks_and_does_not_leak_secret() {
        let request = CredentialRequest {
            channel_id: "test".to_owned(),
            account_id: "primary".to_owned(),
            kind: CredentialKind::Token,
        };
        let acknowledgement = DeliveryAcknowledgement {
            idempotency_key: "request-1".to_owned(),
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
    fn retry_uses_provider_delay_then_stops_on_success() {
        let acknowledgement = DeliveryAcknowledgement {
            idempotency_key: "request-1".to_owned(),
            remote_message_id: None,
            state: DeliveryState::Queued,
            accepted_at_unix_ms: 9,
        };
        let mut channel = TestChannel {
            results: VecDeque::from([
                Err(ChannelError::RateLimited {
                    retry_after: Duration::from_secs(3),
                }),
                Err(ChannelError::Transport(TransportErrorKind::Connection)),
                Ok(acknowledgement.clone()),
            ]),
            credentials: Vec::new(),
        };
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

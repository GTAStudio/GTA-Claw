//! Telegram long-polling and segmented reply compatibility adapter.

use std::fmt::{self, Debug, Formatter};
use std::num::NonZeroUsize;
use std::time::Duration;

use claw_channel_sdk::{
    ApprovedOrigin, Channel, ChannelCredential, ChannelError, ConfigurationError, ConnectionState,
    ConnectionStateMachine, CredentialBindingError, CredentialKind, DeliveryAcknowledgement,
    DeliveryState, InboundMessage, InvalidMessageReason, LifecycleEvent, OutboundMessage,
    OutboundRetrySafety, ProtocolErrorKind, SecretStoreError, UnsupportedOperation,
};
use serde::Deserialize;

use crate::bounded::BoundedQueue;
use crate::diagnostics::{DiagnosticCode, DiagnosticLevel, DiagnosticSink, OperatorDiagnostic};
use crate::transport::{ProviderResponse, require_official_origin};
use crate::{UnixClock, invalid_routing_identifier, segment_outbound_text_iter};

/// Telegram long-poll timeout sent to `getUpdates`.
pub const TELEGRAM_LONG_POLL_TIMEOUT: Duration = Duration::from_secs(25);

/// Client-side timeout for one Telegram `getUpdates` request.
pub const TELEGRAM_POLL_REQUEST_TIMEOUT: Duration = Duration::from_secs(35);

/// Client-side timeout for one Telegram `sendMessage` request.
pub const TELEGRAM_SEND_REQUEST_TIMEOUT: Duration = Duration::from_secs(10);

/// Borrowed, credential-bearing Telegram polling request.
pub struct TelegramPollRequest<'a> {
    bot_token: &'a str,
    offset: Option<i64>,
}

impl TelegramPollRequest<'_> {
    /// Returns the bot token for immediate transport use.
    ///
    /// Implementations must not log, persist, or include it in errors.
    #[must_use]
    pub const fn bot_token(&self) -> &str {
        self.bot_token
    }

    /// Returns the first update identifier the provider should return.
    #[must_use]
    pub const fn offset(&self) -> Option<i64> {
        self.offset
    }

    /// Returns the provider-side long-poll timeout.
    #[must_use]
    pub const fn long_poll_timeout(&self) -> Duration {
        TELEGRAM_LONG_POLL_TIMEOUT
    }

    /// Returns the client-side request timeout.
    #[must_use]
    pub const fn request_timeout(&self) -> Duration {
        TELEGRAM_POLL_REQUEST_TIMEOUT
    }
}

impl Debug for TelegramPollRequest<'_> {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("TelegramPollRequest")
            .field("bot_token", &"[REDACTED]")
            .field("offset", &self.offset)
            .field("long_poll_timeout", &TELEGRAM_LONG_POLL_TIMEOUT)
            .field("request_timeout", &TELEGRAM_POLL_REQUEST_TIMEOUT)
            .finish()
    }
}

/// Borrowed, credential-bearing Telegram send request.
pub struct TelegramSendRequest<'a> {
    bot_token: &'a str,
    chat_id: i64,
    text: &'a str,
}

impl TelegramSendRequest<'_> {
    /// Returns the bot token for immediate transport use.
    ///
    /// Implementations must not log, persist, or include it in errors.
    #[must_use]
    pub const fn bot_token(&self) -> &str {
        self.bot_token
    }

    /// Returns the Telegram chat identifier.
    #[must_use]
    pub const fn chat_id(&self) -> i64 {
        self.chat_id
    }

    /// Returns one already-bounded text chunk.
    #[must_use]
    pub const fn text(&self) -> &str {
        self.text
    }

    /// Returns whether link previews must be disabled.
    #[must_use]
    pub const fn disable_web_page_preview(&self) -> bool {
        true
    }

    /// Returns the client-side request timeout.
    #[must_use]
    pub const fn request_timeout(&self) -> Duration {
        TELEGRAM_SEND_REQUEST_TIMEOUT
    }
}

impl Debug for TelegramSendRequest<'_> {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("TelegramSendRequest")
            .field("bot_token", &"[REDACTED]")
            .field("chat_id", &self.chat_id)
            .field(
                "text",
                &format_args!("[REDACTED; {} bytes]", self.text.len()),
            )
            .field("disable_web_page_preview", &true)
            .field("request_timeout", &TELEGRAM_SEND_REQUEST_TIMEOUT)
            .finish()
    }
}

/// Daemon-owned Telegram HTTP transport.
pub trait TelegramTransport {
    /// Executes one `getUpdates` request.
    ///
    /// # Errors
    ///
    /// Returns a typed [`ChannelError`] for transport or response framing
    /// failures. Provider statuses remain in [`ProviderResponse`].
    fn get_updates(
        &mut self,
        request: &TelegramPollRequest<'_>,
    ) -> Result<ProviderResponse, ChannelError>;

    /// Executes one `sendMessage` request.
    ///
    /// # Errors
    ///
    /// Returns a typed [`ChannelError`] for transport or response framing
    /// failures. Provider statuses remain in [`ProviderResponse`].
    fn send_message(
        &mut self,
        request: &TelegramSendRequest<'_>,
    ) -> Result<ProviderResponse, ChannelError>;
}

/// Counters from one completed Telegram polling request.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct TelegramPollStats {
    /// Updates returned by the provider.
    pub updates: usize,
    /// Text messages accepted into the bounded inbound queue.
    pub queued: usize,
    /// Non-message, blank, or bot-authored updates ignored.
    pub ignored: usize,
    /// Messages dropped after the bounded queue filled.
    ///
    /// The offset still advances first, matching the legacy polling contract.
    pub dropped: usize,
    /// Offset that will be sent on the next poll.
    pub next_offset: i64,
}

/// Telegram polling plus outbound text adapter.
pub struct TelegramChannel<T, C> {
    account_id: String,
    origin: ApprovedOrigin,
    transport: T,
    clock: C,
    lifecycle: ConnectionStateMachine,
    inbound: BoundedQueue<InboundMessage>,
    offset: i64,
    poll_interval: Duration,
}

impl<T, C> TelegramChannel<T, C> {
    /// Creates a stopped Telegram adapter.
    ///
    /// # Errors
    ///
    /// Returns [`ChannelError::Configuration`] when account routing is invalid,
    /// the poll interval is zero, or `origin` is not the exact enrolled
    /// `https://api.telegram.org` origin for this Telegram account.
    pub fn new(
        account_id: impl Into<String>,
        origin: ApprovedOrigin,
        transport: T,
        clock: C,
        inbound_capacity: NonZeroUsize,
        poll_interval: Duration,
    ) -> Result<Self, ChannelError> {
        let account_id = account_id.into();
        if invalid_routing_identifier(&account_id) || poll_interval.is_zero() {
            return Err(ChannelError::Configuration(
                ConfigurationError::InvalidAdapterConfiguration,
            ));
        }
        require_official_origin(&origin, "telegram", &account_id, "api.telegram.org")?;
        Ok(Self {
            account_id,
            origin,
            transport,
            clock,
            lifecycle: ConnectionStateMachine::new(),
            inbound: BoundedQueue::new(inbound_capacity),
            offset: 0,
            poll_interval,
        })
    }

    /// Returns the current lifecycle state.
    #[must_use]
    pub const fn state(&self) -> ConnectionState {
        self.lifecycle.state()
    }

    /// Returns the next Telegram update offset.
    #[must_use]
    pub const fn offset(&self) -> i64 {
        self.offset
    }

    /// Returns the configured delay between poll attempts.
    #[must_use]
    pub const fn poll_interval(&self) -> Duration {
        self.poll_interval
    }

    /// Returns the number of queued inbound messages.
    #[must_use]
    pub fn queued_inbound(&self) -> usize {
        self.inbound.len()
    }

    /// Returns the transport for inspection.
    #[must_use]
    pub const fn transport(&self) -> &T {
        &self.transport
    }

    /// Starts polling. Repeated starts while running are harmless.
    ///
    /// # Errors
    ///
    /// Returns [`ChannelError::Lifecycle`] after terminal stop.
    pub fn start(&mut self, diagnostics: &mut impl DiagnosticSink) -> Result<bool, ChannelError> {
        if self.lifecycle.state() == ConnectionState::Connected {
            return Ok(false);
        }
        self.lifecycle
            .apply(LifecycleEvent::ConnectRequested, &mut ())?;
        self.lifecycle.apply(LifecycleEvent::Established, &mut ())?;
        diagnostics.record(self.diagnostic(
            DiagnosticLevel::Info,
            DiagnosticCode::ChannelStarted,
            None,
            None,
            None,
        ));
        Ok(true)
    }

    /// Stops polling permanently and discards queued inbound work.
    ///
    /// Repeated calls are idempotent. Because this adapter performs no hidden
    /// background work, return means no later poll can begin.
    ///
    /// # Errors
    ///
    /// Returns [`ChannelError::Lifecycle`] only if the shared transition table
    /// refuses the current nonterminal state.
    pub fn stop(&mut self, diagnostics: &mut impl DiagnosticSink) -> Result<bool, ChannelError> {
        if self.lifecycle.state() == ConnectionState::Closed {
            return Ok(false);
        }
        self.lifecycle
            .apply(LifecycleEvent::ShutdownRequested, &mut ())?;
        self.inbound.clear();
        diagnostics.record(self.diagnostic(
            DiagnosticLevel::Info,
            DiagnosticCode::ChannelStopped,
            None,
            None,
            None,
        ));
        Ok(true)
    }

    fn diagnostic<'a>(
        &'a self,
        level: DiagnosticLevel,
        code: DiagnosticCode,
        conversation_id: Option<&'a str>,
        remote_status: Option<u16>,
        retry_after: Option<Duration>,
    ) -> OperatorDiagnostic<'a> {
        OperatorDiagnostic {
            level,
            code,
            channel_id: "telegram",
            account_id: &self.account_id,
            conversation_id,
            remote_status,
            retry_after,
        }
    }
}

impl<T: TelegramTransport, C: UnixClock> TelegramChannel<T, C> {
    /// Performs one offset-based long-poll request and normalizes its updates.
    ///
    /// The caller owns the outer loop and waits [`Self::poll_interval`] after
    /// success or failure. This method never sleeps and therefore stops
    /// deterministically between requests.
    ///
    /// # Errors
    ///
    /// Returns [`ChannelError::NotConnected`] unless started, credential
    /// binding failures before token exposure, typed transport/provider errors,
    /// or protocol errors for malformed and over-large responses.
    pub fn poll_once(
        &mut self,
        credential: &ChannelCredential,
        diagnostics: &mut impl DiagnosticSink,
    ) -> Result<TelegramPollStats, ChannelError> {
        self.require_running()?;
        let offset = (self.offset > 0).then_some(self.offset);
        let response = credential
            .expose_for_origin(
                "telegram",
                &self.account_id,
                CredentialKind::Token,
                &self.origin,
                |bot_token| {
                    self.transport
                        .get_updates(&TelegramPollRequest { bot_token, offset })
                },
            )
            .map_err(map_credential_binding)?;
        let response = match response {
            Ok(response) => response,
            Err(error) => {
                self.record_poll_failure(diagnostics, &error, None);
                return Err(error);
            }
        };
        if let Err(error) = response.require_bounded() {
            self.record_poll_failure(diagnostics, &error, Some(response.status()));
            return Err(error);
        }
        if let Err(error) = classify_response(&response, self.poll_interval) {
            self.record_poll_failure(diagnostics, &error, Some(response.status()));
            return Err(error);
        }

        let Ok(envelope) = serde_json::from_slice::<TelegramUpdates<'_>>(response.body()) else {
            let error = ChannelError::Protocol(ProtocolErrorKind::MalformedResponse);
            self.record_poll_failure(diagnostics, &error, Some(response.status()));
            return Err(error);
        };
        if !envelope.ok {
            let error = ChannelError::Protocol(ProtocolErrorKind::InvalidField);
            self.record_poll_failure(diagnostics, &error, Some(response.status()));
            return Err(error);
        }

        let mut stats = TelegramPollStats {
            updates: envelope.result.len(),
            ..TelegramPollStats::default()
        };
        for update in envelope.result {
            let next_offset = update
                .update_id
                .checked_add(1)
                .ok_or(ChannelError::Protocol(ProtocolErrorKind::InvalidField))?;
            self.offset = self.offset.max(next_offset);

            let Some(message) = update.message else {
                stats.ignored += 1;
                continue;
            };
            if message.from.as_ref().is_some_and(|sender| sender.is_bot) {
                stats.ignored += 1;
                diagnostics.record(self.diagnostic(
                    DiagnosticLevel::Info,
                    DiagnosticCode::BotMessageIgnored,
                    None,
                    None,
                    None,
                ));
                continue;
            }
            let Some(text) = message.text.map(str::trim).filter(|text| !text.is_empty()) else {
                stats.ignored += 1;
                diagnostics.record(self.diagnostic(
                    DiagnosticLevel::Info,
                    DiagnosticCode::EmptyMessageIgnored,
                    None,
                    None,
                    None,
                ));
                continue;
            };
            if message.message_id < 0 {
                stats.ignored += 1;
                diagnostics.record(self.diagnostic(
                    DiagnosticLevel::Warning,
                    DiagnosticCode::MalformedPayload,
                    None,
                    None,
                    None,
                ));
                continue;
            }
            let conversation_id = format!("telegram:{}", message.chat.id);
            let sender_id = message.from.as_ref().map_or_else(
                || "telegram-user".to_owned(),
                |sender| sender.id.to_string(),
            );
            let received_at_unix_ms = message
                .date
                .and_then(|seconds| seconds.checked_mul(1_000))
                .unwrap_or_else(|| self.clock.now_unix_ms());
            let normalized = InboundMessage {
                id: message.message_id.to_string(),
                channel_id: "telegram".to_owned(),
                account_id: self.account_id.clone(),
                conversation_id,
                sender_id,
                text: Some(text.to_owned()),
                attachments: Vec::new(),
                received_at_unix_ms,
            };
            if let Err(dropped) = self.inbound.push(normalized) {
                stats.dropped += 1;
                diagnostics.record(self.diagnostic(
                    DiagnosticLevel::Warning,
                    DiagnosticCode::InboundQueueFull,
                    Some(&dropped.conversation_id),
                    None,
                    None,
                ));
            } else {
                stats.queued += 1;
            }
        }
        stats.next_offset = self.offset;
        Ok(stats)
    }

    const fn require_running(&self) -> Result<(), ChannelError> {
        if self.lifecycle.state().can_exchange() {
            Ok(())
        } else {
            Err(ChannelError::NotConnected {
                state: self.lifecycle.state(),
            })
        }
    }

    fn record_poll_failure(
        &self,
        diagnostics: &mut impl DiagnosticSink,
        error: &ChannelError,
        status: Option<u16>,
    ) {
        diagnostics.record(self.diagnostic(
            DiagnosticLevel::Error,
            DiagnosticCode::PollFailed,
            None,
            status,
            error.retry_after().or(Some(self.poll_interval)),
        ));
    }
}

impl<T: TelegramTransport, C: UnixClock> Channel for TelegramChannel<T, C> {
    fn id(&self) -> &'static str {
        "telegram"
    }

    fn poll_inbound(&mut self) -> Result<Option<InboundMessage>, ChannelError> {
        self.require_running()?;
        Ok(self.inbound.pop())
    }

    fn outbound_retry_safety(&self) -> OutboundRetrySafety {
        OutboundRetrySafety::NotSafeToRepeat
    }

    fn send_outbound(
        &mut self,
        message: &OutboundMessage,
        credential: Option<&ChannelCredential>,
    ) -> Result<DeliveryAcknowledgement, ChannelError> {
        self.require_running()?;
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
        let chat_id = message
            .conversation_id
            .strip_prefix("telegram:")
            .filter(|value| !value.is_empty())
            .and_then(|value| value.parse::<i64>().ok())
            .ok_or(ChannelError::Configuration(
                ConfigurationError::ConversationScopeMismatch,
            ))?;
        let text = message.text.as_deref().ok_or(ChannelError::InvalidMessage(
            InvalidMessageReason::EmptyContent,
        ))?;
        let credential = credential.ok_or(ChannelError::Credential(SecretStoreError::NotFound))?;
        let segments = segment_outbound_text_iter("telegram", text)?;
        let mut remote_message_id = None;
        credential
            .expose_for_origin(
                "telegram",
                &self.account_id,
                CredentialKind::Token,
                &self.origin,
                |bot_token| -> Result<(), ChannelError> {
                    for chunk in segments {
                        let chunk = chunk?;
                        let response = self.transport.send_message(&TelegramSendRequest {
                            bot_token,
                            chat_id,
                            text: chunk.as_ref(),
                        })?;
                        response.require_bounded()?;
                        classify_response(&response, Duration::from_secs(1))?;
                        let envelope: TelegramSendEnvelope =
                            serde_json::from_slice(response.body()).map_err(|_| {
                                ChannelError::Protocol(ProtocolErrorKind::MalformedResponse)
                            })?;
                        if !envelope.ok {
                            return Err(ChannelError::Protocol(ProtocolErrorKind::InvalidField));
                        }
                        remote_message_id =
                            envelope.result.map(|result| result.message_id.to_string());
                    }
                    Ok(())
                },
            )
            .map_err(map_credential_binding)??;
        Ok(DeliveryAcknowledgement {
            correlation_key: message.correlation_key.clone(),
            remote_message_id,
            state: DeliveryState::Accepted,
            accepted_at_unix_ms: self.clock.now_unix_ms(),
        })
    }
}

#[derive(Deserialize)]
struct TelegramUpdates<'a> {
    ok: bool,
    #[serde(default, borrow)]
    result: Vec<TelegramUpdate<'a>>,
}

#[derive(Deserialize)]
struct TelegramUpdate<'a> {
    update_id: i64,
    #[serde(borrow)]
    message: Option<TelegramMessage<'a>>,
}

#[derive(Deserialize)]
struct TelegramMessage<'a> {
    message_id: i64,
    chat: TelegramChat,
    from: Option<TelegramUser>,
    #[serde(borrow)]
    text: Option<&'a str>,
    date: Option<u64>,
}

#[derive(Deserialize)]
struct TelegramChat {
    id: i64,
}

#[derive(Deserialize)]
struct TelegramUser {
    id: i64,
    #[serde(default)]
    is_bot: bool,
}

#[derive(Deserialize)]
struct TelegramSendEnvelope {
    ok: bool,
    result: Option<TelegramSendResult>,
}

#[derive(Deserialize)]
struct TelegramSendResult {
    message_id: i64,
}

#[derive(Deserialize)]
struct TelegramErrorEnvelope {
    parameters: Option<TelegramErrorParameters>,
}

#[derive(Deserialize)]
struct TelegramErrorParameters {
    retry_after: Option<u64>,
}

fn classify_response(
    response: &ProviderResponse,
    default_retry_after: Duration,
) -> Result<(), ChannelError> {
    match response.status() {
        200..=299 => Ok(()),
        401 | 403 => Err(ChannelError::Authentication),
        429 => Err(ChannelError::RateLimited {
            retry_after: serde_json::from_slice::<TelegramErrorEnvelope>(response.body())
                .ok()
                .and_then(|envelope| envelope.parameters)
                .and_then(|parameters| parameters.retry_after)
                .map(Duration::from_secs)
                .or_else(|| response.retry_after())
                .unwrap_or(default_retry_after),
        }),
        status => Err(ChannelError::RemoteRejected { status }),
    }
}

const fn map_credential_binding(error: CredentialBindingError) -> ChannelError {
    ChannelError::CredentialBinding(error)
}

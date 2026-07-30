//! `WhatsApp` webhook verification, normalization, and Graph reply adapter.

use std::collections::VecDeque;
use std::fmt::{self, Debug, Formatter};
use std::num::NonZeroUsize;
use std::time::Duration;

use claw_channel_sdk::{
    ApprovedOrigin, Channel, ChannelCredential, ChannelError, ConfigurationError, ConnectionState,
    ConnectionStateMachine, CredentialBindingError, CredentialKind, DeliveryAcknowledgement,
    DeliveryState, InboundMessage, InvalidMessageReason, LifecycleEvent, OutboundMessage,
    OutboundRetrySafety, ProtocolErrorKind, SecretStoreError, UnsupportedOperation,
};
use ring::hmac;
use serde::Deserialize;

use crate::bounded::BoundedQueue;
use crate::diagnostics::{DiagnosticCode, DiagnosticLevel, DiagnosticSink, OperatorDiagnostic};
use crate::transport::{MAX_PROVIDER_RESPONSE_BYTES, ProviderResponse, require_official_origin};
use crate::{UnixClock, invalid_routing_identifier, segment_outbound_text_iter};

/// Client-side timeout for one `WhatsApp` Graph API send.
pub const WHATSAPP_SEND_REQUEST_TIMEOUT: Duration = Duration::from_secs(10);

/// `WhatsApp` Graph API version used by the legacy adapter.
pub const WHATSAPP_GRAPH_API_VERSION: u8 = 20;

/// Largest number of message objects accepted in one webhook payload.
///
/// The same bound sizes completion retention so a fully acknowledged batch
/// remains deduplicated even when the inbound queue is much smaller.
pub const WHATSAPP_MAX_MESSAGES_PER_WEBHOOK: usize = 1_024;

const WHATSAPP_COMPLETED_ID_TTL_MS: u64 = 7 * 24 * 60 * 60 * 1_000;

/// Borrowed webhook verification query.
pub struct WhatsAppVerificationQuery<'a> {
    /// `hub.mode`.
    pub mode: Option<&'a str>,
    /// `hub.verify_token`.
    pub verify_token: Option<&'a str>,
    /// `hub.challenge`.
    pub challenge: Option<&'a str>,
}

impl Debug for WhatsAppVerificationQuery<'_> {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("WhatsAppVerificationQuery")
            .field("mode", &self.mode)
            .field("verify_token", &self.verify_token.map(|_| "[REDACTED]"))
            .field("challenge", &self.challenge)
            .finish()
    }
}

/// Exact HTTP-compatible webhook verification decision.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum WhatsAppVerificationResponse<'a> {
    /// Return the raw challenge as `text/plain`.
    Accepted(&'a str),
    /// Return `{"error":"Forbidden"}` as JSON.
    Forbidden,
}

impl<'a> WhatsAppVerificationResponse<'a> {
    /// Returns the HTTP status.
    #[must_use]
    pub const fn status(self) -> u16 {
        match self {
            Self::Accepted(_) => 200,
            Self::Forbidden => 403,
        }
    }

    /// Returns the exact response content type.
    #[must_use]
    pub const fn content_type(self) -> &'static str {
        match self {
            Self::Accepted(_) => "text/plain",
            Self::Forbidden => "application/json",
        }
    }

    /// Returns the exact response body.
    #[must_use]
    pub const fn body(self) -> &'a str {
        match self {
            Self::Accepted(challenge) => challenge,
            Self::Forbidden => r#"{"error":"Forbidden"}"#,
        }
    }
}

/// HTTP-compatible result body for an incoming `WhatsApp` webhook.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum WhatsAppWebhookResponse {
    /// Processing and every outbound send completed.
    Accepted,
    /// Parsing, processing, or an outbound send failed.
    Failed,
}

impl WhatsAppWebhookResponse {
    /// Returns the HTTP status.
    #[must_use]
    pub const fn status(self) -> u16 {
        match self {
            Self::Accepted => 200,
            Self::Failed => 500,
        }
    }

    /// Returns the exact JSON response body.
    #[must_use]
    pub const fn body(self) -> &'static str {
        match self {
            Self::Accepted => r#"{"ok":true}"#,
            Self::Failed => r#"{"error":"Webhook handling failed"}"#,
        }
    }

    /// Maps completion of the full webhook pipeline to its HTTP response.
    #[must_use]
    pub const fn for_result<T, E>(result: &Result<T, E>) -> Self {
        if result.is_ok() {
            Self::Accepted
        } else {
            Self::Failed
        }
    }
}

/// Borrowed, credential-bearing `WhatsApp` Graph send request.
pub struct WhatsAppSendRequest<'a> {
    access_token: &'a str,
    phone_number_id: &'a str,
    to: &'a str,
    text: &'a str,
}

impl WhatsAppSendRequest<'_> {
    /// Returns the access token for the Authorization header.
    ///
    /// Implementations must prefix it with `Bearer ` and must not log it.
    #[must_use]
    pub const fn access_token(&self) -> &str {
        self.access_token
    }

    /// Returns the configured sender phone-number identifier.
    #[must_use]
    pub const fn phone_number_id(&self) -> &str {
        self.phone_number_id
    }

    /// Returns the recipient identifier.
    #[must_use]
    pub const fn to(&self) -> &str {
        self.to
    }

    /// Returns one already-bounded text chunk.
    #[must_use]
    pub const fn text(&self) -> &str {
        self.text
    }

    /// Returns the required messaging product.
    #[must_use]
    pub const fn messaging_product(&self) -> &'static str {
        "whatsapp"
    }

    /// Returns the Graph API version.
    #[must_use]
    pub const fn api_version(&self) -> u8 {
        WHATSAPP_GRAPH_API_VERSION
    }

    /// Returns the client-side timeout.
    #[must_use]
    pub const fn request_timeout(&self) -> Duration {
        WHATSAPP_SEND_REQUEST_TIMEOUT
    }
}

impl Debug for WhatsAppSendRequest<'_> {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("WhatsAppSendRequest")
            .field("access_token", &"[REDACTED]")
            .field("phone_number_id", &self.phone_number_id)
            .field("to", &self.to)
            .field(
                "text",
                &format_args!("[REDACTED; {} bytes]", self.text.len()),
            )
            .field("api_version", &WHATSAPP_GRAPH_API_VERSION)
            .field("request_timeout", &WHATSAPP_SEND_REQUEST_TIMEOUT)
            .finish()
    }
}

/// Daemon-owned `WhatsApp` Graph API transport.
pub trait WhatsAppTransport {
    /// Sends one Graph API text request.
    ///
    /// # Errors
    ///
    /// Returns a stage-aware failure so resumable webhook delivery advances only
    /// after transport invocation. Provider statuses remain in
    /// [`ProviderResponse`].
    fn send_text(
        &mut self,
        request: &WhatsAppSendRequest<'_>,
    ) -> Result<ProviderResponse, WhatsAppSendError>;
}

/// Delivery-stage failure from one `WhatsApp` Graph API send.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum WhatsAppSendError {
    /// Cancellation was observed before the transport was invoked.
    CancelledBeforeSend,
    /// Request construction failed before transport invocation.
    FailedBeforeSend(ChannelError),
    /// The transport was invoked, but delivery cannot be proven either way.
    AmbiguousAfterSend(ChannelError),
}

impl WhatsAppSendError {
    const fn into_channel_error(self) -> ChannelError {
        match self {
            Self::CancelledBeforeSend => {
                ChannelError::Transport(claw_channel_sdk::TransportErrorKind::CancelledBeforeSend)
            }
            Self::FailedBeforeSend(error) | Self::AmbiguousAfterSend(error) => error,
        }
    }
}

/// Counters from one parsed `WhatsApp` webhook.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct WhatsAppWebhookStats {
    /// Message objects present in the payload.
    pub messages: usize,
    /// Text messages accepted into the bounded inbound queue.
    pub queued: usize,
    /// Non-text, blank, malformed, self-authored, completed, or pending duplicates ignored.
    pub ignored: usize,
    /// Messages dropped after the bounded queue filled.
    pub dropped: usize,
}

/// Successful completion of the synchronous webhook pipeline.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct WhatsAppWebhookHandling {
    /// Parsing and bounded-queue counters.
    pub ingestion: WhatsAppWebhookStats,
    /// Messages whose processor and optional reply completed.
    pub processed: usize,
}

/// Verifies Meta's `X-Hub-Signature-256` over the exact webhook bytes.
///
/// # Errors
///
/// Returns a credential binding error unless `app_secret` is a local-only
/// [`CredentialKind::WebhookSecret`] for this `WhatsApp` account.
pub fn verify_whatsapp_webhook_signature(
    account_id: &str,
    payload: &[u8],
    signature: &str,
    app_secret: &ChannelCredential,
) -> Result<bool, ChannelError> {
    let Some(tag) = decode_sha256_signature(signature) else {
        return Ok(false);
    };
    app_secret
        .expose_local(
            "whatsapp",
            account_id,
            CredentialKind::WebhookSecret,
            |secret| {
                let key = hmac::Key::new(hmac::HMAC_SHA256, secret.as_bytes());
                hmac::verify(&key, payload, &tag).is_ok()
            },
        )
        .map_err(map_credential_binding)
}

/// `WhatsApp` webhook plus Graph API text adapter.
pub struct WhatsAppChannel<T, C> {
    account_id: String,
    phone_number_id: String,
    graph_origin: ApprovedOrigin,
    transport: T,
    clock: C,
    lifecycle: ConnectionStateMachine,
    inbound: BoundedQueue<InboundMessage>,
    completed_message_capacity: usize,
    pending_reply_capacity: usize,
    completed_messages: VecDeque<CompletedWhatsAppMessage>,
    pending_replies: VecDeque<PendingWhatsAppReply>,
}

impl<T, C> WhatsAppChannel<T, C> {
    /// Creates a stopped `WhatsApp` adapter.
    ///
    /// # Errors
    ///
    /// Returns [`ChannelError::Configuration`] for invalid account or phone
    /// routing, or when `graph_origin` is not the exact enrolled
    /// `https://graph.facebook.com` origin for this account. `inbound_capacity`
    /// bounds queued work. Partial reply checkpoints are capped at twice that
    /// size, and completion history covers the full inbound queue, those
    /// checkpoints, and one maximum webhook batch.
    pub fn new(
        account_id: impl Into<String>,
        phone_number_id: impl Into<String>,
        graph_origin: ApprovedOrigin,
        transport: T,
        clock: C,
        inbound_capacity: NonZeroUsize,
    ) -> Result<Self, ChannelError> {
        let account_id = account_id.into();
        let phone_number_id = phone_number_id.into();
        if invalid_routing_identifier(&account_id) || invalid_routing_identifier(&phone_number_id) {
            return Err(ChannelError::Configuration(
                ConfigurationError::InvalidAdapterConfiguration,
            ));
        }
        require_official_origin(&graph_origin, "whatsapp", &account_id, "graph.facebook.com")?;
        let inbound_message_capacity = inbound_capacity.get();
        let pending_reply_capacity = inbound_message_capacity.saturating_mul(2);
        let completed_message_capacity = WHATSAPP_MAX_MESSAGES_PER_WEBHOOK
            .saturating_add(pending_reply_capacity)
            .saturating_add(inbound_message_capacity);
        Ok(Self {
            account_id,
            phone_number_id,
            graph_origin,
            transport,
            clock,
            lifecycle: ConnectionStateMachine::new(),
            inbound: BoundedQueue::new(inbound_capacity),
            completed_message_capacity,
            pending_reply_capacity,
            completed_messages: VecDeque::new(),
            pending_replies: VecDeque::new(),
        })
    }

    /// Returns the current lifecycle state.
    #[must_use]
    pub const fn state(&self) -> ConnectionState {
        self.lifecycle.state()
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

    /// Starts accepting webhook and outbound work.
    ///
    /// Repeated starts while running are harmless.
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

    /// Stops accepting work and clears queued messages.
    ///
    /// Repeated stops are idempotent.
    ///
    /// # Errors
    ///
    /// Returns [`ChannelError::Lifecycle`] only when the shared transition table
    /// refuses the current nonterminal state.
    pub fn stop(&mut self, diagnostics: &mut impl DiagnosticSink) -> Result<bool, ChannelError> {
        if self.lifecycle.state() == ConnectionState::Closed {
            return Ok(false);
        }
        self.lifecycle
            .apply(LifecycleEvent::ShutdownRequested, &mut ())?;
        self.inbound.clear();
        self.completed_messages.clear();
        self.pending_replies.clear();
        diagnostics.record(self.diagnostic(
            DiagnosticLevel::Info,
            DiagnosticCode::ChannelStopped,
            None,
            None,
            None,
        ));
        Ok(true)
    }

    /// Verifies a `WhatsApp` webhook challenge with a local-only secret.
    ///
    /// # Errors
    ///
    /// Returns [`ChannelError::NotConnected`] unless started, or a credential
    /// binding error when the verification secret is not a local-only
    /// [`CredentialKind::WebhookSecret`] for this account.
    pub fn verify_webhook<'a>(
        &self,
        query: &WhatsAppVerificationQuery<'a>,
        verification_secret: &ChannelCredential,
        diagnostics: &mut impl DiagnosticSink,
    ) -> Result<WhatsAppVerificationResponse<'a>, ChannelError> {
        self.require_running()?;
        let token_matches = match query.verify_token {
            Some(candidate) => verification_secret
                .expose_local(
                    "whatsapp",
                    &self.account_id,
                    CredentialKind::WebhookSecret,
                    |expected| constant_time_eq(candidate.as_bytes(), expected.as_bytes()),
                )
                .map_err(map_credential_binding)?,
            None => false,
        };
        match query.challenge {
            Some(challenge)
                if query.mode == Some("subscribe") && !challenge.is_empty() && token_matches =>
            {
                Ok(WhatsAppVerificationResponse::Accepted(challenge))
            }
            Some(_) | None => {
                diagnostics.record(self.diagnostic(
                    DiagnosticLevel::Warning,
                    DiagnosticCode::VerificationRejected,
                    None,
                    Some(403),
                    None,
                ));
                Ok(WhatsAppVerificationResponse::Forbidden)
            }
        }
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
            channel_id: "whatsapp",
            account_id: &self.account_id,
            conversation_id,
            remote_status,
            retry_after,
        }
    }
}

impl<T: WhatsAppTransport, C: UnixClock> WhatsAppChannel<T, C> {
    /// Parses, processes, and replies to one webhook before returning.
    ///
    /// This is the compatibility path an HTTP adapter should call: an `Ok`
    /// result maps to [`WhatsAppWebhookResponse::Accepted`], while any error maps
    /// to [`WhatsAppWebhookResponse::Failed`]. Entries, changes, messages, and
    /// segmented replies are processed sequentially. Each queued item and prior
    /// checkpoint gets at most one attempt per call, so a failing item cannot
    /// keep a later redelivered item from making progress.
    ///
    /// # Errors
    ///
    /// Returns the first parsing, callback, credential, transport, provider, or
    /// protocol error after preserving failed work and attempting the remaining
    /// bounded items once.
    pub fn handle_webhook(
        &mut self,
        payload: &[u8],
        access_credential: &ChannelCredential,
        process: impl FnMut(&InboundMessage) -> Result<Option<String>, ChannelError>,
        diagnostics: &mut impl DiagnosticSink,
    ) -> Result<WhatsAppWebhookHandling, ChannelError> {
        let ingestion = self.ingest_webhook(payload, diagnostics)?;
        let processed = self.process_webhook_queue(access_credential, process)?;
        if ingestion.dropped > 0 {
            return Err(ChannelError::RateLimited {
                retry_after: Duration::from_secs(1),
            });
        }
        Ok(WhatsAppWebhookHandling {
            ingestion,
            processed,
        })
    }

    /// Parses a bounded webhook payload and queues normalized text messages.
    ///
    /// # Errors
    ///
    /// Returns [`ChannelError::NotConnected`] unless started and typed protocol
    /// errors for over-large byte or message counts and malformed JSON.
    pub fn ingest_webhook(
        &mut self,
        payload: &[u8],
        diagnostics: &mut impl DiagnosticSink,
    ) -> Result<WhatsAppWebhookStats, ChannelError> {
        self.require_running()?;
        if payload.len() > MAX_PROVIDER_RESPONSE_BYTES {
            diagnostics.record(self.diagnostic(
                DiagnosticLevel::Warning,
                DiagnosticCode::MalformedPayload,
                None,
                None,
                None,
            ));
            return Err(ChannelError::Protocol(ProtocolErrorKind::PayloadTooLarge));
        }
        let body: WhatsAppWebhookBody<'_> = serde_json::from_slice(payload).map_err(|_| {
            diagnostics.record(self.diagnostic(
                DiagnosticLevel::Warning,
                DiagnosticCode::MalformedPayload,
                None,
                None,
                None,
            ));
            ChannelError::Protocol(ProtocolErrorKind::MalformedResponse)
        })?;
        let message_count = body
            .entry
            .iter()
            .flat_map(|entry| &entry.changes)
            .filter_map(|change| change.value.as_ref())
            .map(|value| value.messages.len())
            .sum::<usize>();
        if message_count > WHATSAPP_MAX_MESSAGES_PER_WEBHOOK {
            diagnostics.record(self.diagnostic(
                DiagnosticLevel::Warning,
                DiagnosticCode::MalformedPayload,
                None,
                None,
                None,
            ));
            return Err(ChannelError::Protocol(ProtocolErrorKind::PayloadTooLarge));
        }
        if body
            .entry
            .iter()
            .flat_map(|entry| &entry.changes)
            .filter_map(|change| change.value.as_ref())
            .any(|value| {
                !value.messages.is_empty()
                    && value
                        .metadata
                        .is_none_or(|metadata| metadata.phone_number_id != self.phone_number_id)
            })
        {
            diagnostics.record(self.diagnostic(
                DiagnosticLevel::Warning,
                DiagnosticCode::MalformedPayload,
                None,
                None,
                None,
            ));
            return Err(ChannelError::Protocol(ProtocolErrorKind::InvalidField));
        }
        self.prune_completed_messages();
        let mut stats = WhatsAppWebhookStats::default();
        for entry in body.entry {
            for change in entry.changes {
                let Some(value) = change.value else {
                    continue;
                };
                for message in value.messages {
                    stats.messages += 1;
                    if self.refresh_completed_message(message.id)
                        || self.inbound.iter().any(|queued| queued.id == message.id)
                        || self
                            .pending_replies
                            .iter()
                            .any(|pending| pending.message_id == message.id)
                    {
                        stats.ignored += 1;
                        continue;
                    }
                    if message.kind != Some("text")
                        || message.from == self.phone_number_id
                        || invalid_routing_identifier(message.from)
                        || invalid_routing_identifier(message.id)
                    {
                        stats.ignored += 1;
                        if message.from == self.phone_number_id {
                            diagnostics.record(self.diagnostic(
                                DiagnosticLevel::Info,
                                DiagnosticCode::BotMessageIgnored,
                                None,
                                None,
                                None,
                            ));
                        }
                        continue;
                    }
                    let Some(text) = message
                        .text
                        .and_then(|text| text.body)
                        .map(str::trim)
                        .filter(|text| !text.is_empty())
                    else {
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
                    let received_at_unix_ms = message
                        .timestamp
                        .and_then(|timestamp| timestamp.parse::<u64>().ok())
                        .and_then(|seconds| seconds.checked_mul(1_000))
                        .unwrap_or_else(|| self.clock.now_unix_ms());
                    let normalized = InboundMessage {
                        id: message.id.to_owned(),
                        channel_id: "whatsapp".to_owned(),
                        account_id: self.account_id.clone(),
                        conversation_id: format!("whatsapp:{}", message.from),
                        sender_id: message.from.to_owned(),
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
            }
        }
        Ok(stats)
    }

    /// Processes queued webhook messages and sends replies sequentially.
    ///
    /// The callback owns engine and command composition. Returning `None` or
    /// blank text suppresses a reply. Failed callbacks are requeued and failed
    /// replies retain their next-segment checkpoint. Other bounded items still
    /// receive one attempt before the HTTP layer returns
    /// [`WhatsAppWebhookResponse::Failed`].
    ///
    /// # Errors
    ///
    /// Returns the first callback, credential, transport, provider, or protocol
    /// error after every item present at entry receives at most one attempt.
    pub fn process_webhook_queue(
        &mut self,
        access_credential: &ChannelCredential,
        mut process: impl FnMut(&InboundMessage) -> Result<Option<String>, ChannelError>,
    ) -> Result<usize, ChannelError> {
        self.require_running()?;
        let mut processed = 0;
        let pending_attempts = self.pending_replies.len();
        let inbound_attempts = self.inbound.len();
        let mut first_error = None;

        for _ in 0..inbound_attempts {
            let Some(message) = self.inbound.pop() else {
                break;
            };
            if self.pending_replies.len() >= self.pending_reply_capacity {
                self.inbound
                    .push(message)
                    .map_err(|_| ChannelError::Protocol(ProtocolErrorKind::InvalidField))?;
                first_error.get_or_insert(ChannelError::RateLimited {
                    retry_after: Duration::from_secs(1),
                });
                continue;
            }
            let reply = match process(&message) {
                Ok(reply) => reply,
                Err(error) => {
                    self.inbound
                        .push(message)
                        .map_err(|_| ChannelError::Protocol(ProtocolErrorKind::InvalidField))?;
                    first_error.get_or_insert(error);
                    continue;
                }
            };
            let Some(reply) = reply.filter(|reply| !reply.trim().is_empty()) else {
                self.remember_completed(message.id);
                processed += 1;
                continue;
            };
            let to = message.conversation_id.strip_prefix("whatsapp:").ok_or(
                ChannelError::Configuration(ConfigurationError::ConversationScopeMismatch),
            )?;
            let mut pending = PendingWhatsAppReply {
                message_id: message.id,
                to: to.to_owned(),
                text: reply,
                next_chunk: 0,
            };
            if let Err(error) = self.resume_pending_reply(&mut pending, access_credential) {
                self.pending_replies.push_back(pending);
                first_error.get_or_insert(error);
                continue;
            }
            self.remember_completed(pending.message_id);
            processed += 1;
        }

        for _ in 0..pending_attempts {
            let Some(mut pending) = self.pending_replies.pop_front() else {
                break;
            };
            if let Err(error) = self.resume_pending_reply(&mut pending, access_credential) {
                self.pending_replies.push_back(pending);
                first_error.get_or_insert(error);
                continue;
            }
            self.remember_completed(pending.message_id);
            processed += 1;
        }

        first_error.map_or(Ok(processed), Err)
    }

    fn resume_pending_reply(
        &mut self,
        pending: &mut PendingWhatsAppReply,
        credential: &ChannelCredential,
    ) -> Result<(), ChannelError> {
        let segments = segment_outbound_text_iter("whatsapp", &pending.text)?;
        credential
            .expose_for_origin(
                "whatsapp",
                &self.account_id,
                CredentialKind::Token,
                &self.graph_origin,
                |access_token| -> Result<(), ChannelError> {
                    for (index, chunk) in segments.into_iter().enumerate().skip(pending.next_chunk)
                    {
                        let chunk = chunk?;
                        let response = match self.transport.send_text(&WhatsAppSendRequest {
                            access_token,
                            phone_number_id: &self.phone_number_id,
                            to: &pending.to,
                            text: chunk.as_ref(),
                        }) {
                            Ok(response) => response,
                            Err(WhatsAppSendError::AmbiguousAfterSend(error)) => {
                                pending.next_chunk = index + 1;
                                return Err(error);
                            }
                            Err(error) => return Err(error.into_channel_error()),
                        };
                        classify_response(&response)?;
                        pending.next_chunk = index + 1;
                        response.require_bounded()?;
                    }
                    Ok(())
                },
            )
            .map_err(map_credential_binding)??;
        Ok(())
    }

    fn remember_completed(&mut self, message_id: String) {
        self.prune_completed_messages();
        while self.completed_messages.len() >= self.completed_message_capacity {
            self.completed_messages.pop_front();
        }
        self.completed_messages.push_back(CompletedWhatsAppMessage {
            message_id,
            completed_at_unix_ms: self.clock.now_unix_ms(),
        });
    }

    fn refresh_completed_message(&mut self, message_id: &str) -> bool {
        let Some(index) = self
            .completed_messages
            .iter()
            .position(|completed| completed.message_id == message_id)
        else {
            return false;
        };
        let Some(mut completed) = self.completed_messages.remove(index) else {
            return false;
        };
        // Keep IDs in this acknowledgment behind older history while the
        // bounded inbound queue and pending replies drain.
        completed.completed_at_unix_ms = self.clock.now_unix_ms();
        self.completed_messages.push_back(completed);
        true
    }

    fn prune_completed_messages(&mut self) {
        let now = self.clock.now_unix_ms();
        while self.completed_messages.front().is_some_and(|completed| {
            now.saturating_sub(completed.completed_at_unix_ms) >= WHATSAPP_COMPLETED_ID_TTL_MS
        }) {
            self.completed_messages.pop_front();
        }
    }

    fn send_text_to(
        &mut self,
        to: &str,
        text: &str,
        credential: &ChannelCredential,
    ) -> Result<Option<String>, ChannelError> {
        let segments = segment_outbound_text_iter("whatsapp", text)?;
        let mut remote_message_id = None;
        credential
            .expose_for_origin(
                "whatsapp",
                &self.account_id,
                CredentialKind::Token,
                &self.graph_origin,
                |access_token| -> Result<(), ChannelError> {
                    for chunk in segments {
                        let chunk = chunk?;
                        let response = self
                            .transport
                            .send_text(&WhatsAppSendRequest {
                                access_token,
                                phone_number_id: &self.phone_number_id,
                                to,
                                text: chunk.as_ref(),
                            })
                            .map_err(WhatsAppSendError::into_channel_error)?;
                        classify_response(&response)?;
                        response.require_bounded()?;
                        if !response.body().is_empty() {
                            let sent: WhatsAppSendEnvelope<'_> =
                                serde_json::from_slice(response.body()).map_err(|_| {
                                    ChannelError::Protocol(ProtocolErrorKind::MalformedResponse)
                                })?;
                            remote_message_id =
                                sent.messages.last().map(|message| message.id.to_owned());
                        }
                    }
                    Ok(())
                },
            )
            .map_err(map_credential_binding)??;
        Ok(remote_message_id)
    }
}

impl<T: WhatsAppTransport, C: UnixClock> Channel for WhatsAppChannel<T, C> {
    fn id(&self) -> &'static str {
        "whatsapp"
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
        let to = message
            .conversation_id
            .strip_prefix("whatsapp:")
            .filter(|value| !invalid_routing_identifier(value))
            .ok_or(ChannelError::Configuration(
                ConfigurationError::ConversationScopeMismatch,
            ))?;
        let text = message.text.as_deref().ok_or(ChannelError::InvalidMessage(
            InvalidMessageReason::EmptyContent,
        ))?;
        let credential = credential.ok_or(ChannelError::Credential(SecretStoreError::NotFound))?;
        let remote_message_id = self.send_text_to(to, text, credential)?;
        Ok(DeliveryAcknowledgement {
            correlation_key: message.correlation_key.clone(),
            remote_message_id,
            state: DeliveryState::Accepted,
            accepted_at_unix_ms: self.clock.now_unix_ms(),
        })
    }
}

#[derive(Deserialize)]
struct WhatsAppWebhookBody<'a> {
    #[serde(default, borrow)]
    entry: Vec<WhatsAppEntry<'a>>,
}

#[derive(Deserialize)]
struct WhatsAppEntry<'a> {
    #[serde(default, borrow)]
    changes: Vec<WhatsAppChange<'a>>,
}

#[derive(Deserialize)]
struct WhatsAppChange<'a> {
    #[serde(borrow)]
    value: Option<WhatsAppValue<'a>>,
}

#[derive(Deserialize)]
struct WhatsAppValue<'a> {
    #[serde(borrow)]
    metadata: Option<WhatsAppMetadata<'a>>,
    #[serde(default, borrow)]
    messages: Vec<WhatsAppMessage<'a>>,
}

#[derive(Clone, Copy, Deserialize)]
struct WhatsAppMetadata<'a> {
    phone_number_id: &'a str,
}

#[derive(Deserialize)]
struct WhatsAppMessage<'a> {
    from: &'a str,
    id: &'a str,
    timestamp: Option<&'a str>,
    #[serde(rename = "type")]
    kind: Option<&'a str>,
    #[serde(borrow)]
    text: Option<WhatsAppText<'a>>,
}

#[derive(Deserialize)]
struct WhatsAppText<'a> {
    body: Option<&'a str>,
}

#[derive(Deserialize)]
struct WhatsAppSendEnvelope<'a> {
    #[serde(default, borrow)]
    messages: Vec<WhatsAppSentMessage<'a>>,
}

#[derive(Deserialize)]
struct WhatsAppSentMessage<'a> {
    id: &'a str,
}

struct PendingWhatsAppReply {
    message_id: String,
    to: String,
    text: String,
    next_chunk: usize,
}

struct CompletedWhatsAppMessage {
    message_id: String,
    completed_at_unix_ms: u64,
}

fn classify_response(response: &ProviderResponse) -> Result<(), ChannelError> {
    match response.status() {
        200..=299 => Ok(()),
        401 | 403 => Err(ChannelError::Authentication),
        429 => Err(ChannelError::RateLimited {
            retry_after: response
                .retry_after()
                .unwrap_or_else(|| Duration::from_secs(1)),
        }),
        status => Err(ChannelError::RemoteRejected { status }),
    }
}

fn constant_time_eq(left: &[u8], right: &[u8]) -> bool {
    let mut difference = left.len() ^ right.len();
    let max_len = left.len().max(right.len());
    for index in 0..max_len {
        let left_byte = left.get(index).copied().unwrap_or_default();
        let right_byte = right.get(index).copied().unwrap_or_default();
        difference |= usize::from(left_byte ^ right_byte);
    }
    difference == 0
}

fn decode_sha256_signature(signature: &str) -> Option<[u8; 32]> {
    let encoded = signature.strip_prefix("sha256=")?;
    if encoded.len() != 64 {
        return None;
    }
    let mut decoded = [0_u8; 32];
    for (index, pair) in encoded.as_bytes().chunks_exact(2).enumerate() {
        let high = decode_hex(pair[0])?;
        let low = decode_hex(pair[1])?;
        decoded[index] = (high << 4) | low;
    }
    Some(decoded)
}

const fn decode_hex(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        b'A'..=b'F' => Some(byte - b'A' + 10),
        _ => None,
    }
}

const fn map_credential_binding(error: CredentialBindingError) -> ChannelError {
    ChannelError::CredentialBinding(error)
}

#[cfg(test)]
mod tests {
    use std::cell::{Cell, RefCell};
    use std::collections::VecDeque;
    use std::rc::Rc;

    use claw_channel_sdk::{
        CredentialBinding, CredentialRequest, NetworkOrigin, OriginTrustError, OriginTrustStore,
        authorize_origin,
    };

    use super::*;

    const ACCOUNT: &str = "account";

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

    #[derive(Clone, Copy)]
    struct FixedClock(u64);

    impl UnixClock for FixedClock {
        fn now_unix_ms(&self) -> u64 {
            self.0
        }
    }

    struct RecordingTransport {
        sent: Rc<RefCell<Vec<String>>>,
    }

    impl WhatsAppTransport for RecordingTransport {
        fn send_text(
            &mut self,
            request: &WhatsAppSendRequest<'_>,
        ) -> Result<ProviderResponse, WhatsAppSendError> {
            self.sent.borrow_mut().push(request.text().to_owned());
            Ok(ProviderResponse::new(200, Vec::new()))
        }
    }

    struct ScriptedStageTransport {
        results: Rc<RefCell<VecDeque<Result<ProviderResponse, WhatsAppSendError>>>>,
        attempts: Rc<Cell<usize>>,
    }

    impl WhatsAppTransport for ScriptedStageTransport {
        fn send_text(
            &mut self,
            _request: &WhatsAppSendRequest<'_>,
        ) -> Result<ProviderResponse, WhatsAppSendError> {
            self.attempts.set(self.attempts.get() + 1);
            self.results
                .borrow_mut()
                .pop_front()
                .expect("scripted send stage")
        }
    }

    fn approved_origin() -> ApprovedOrigin {
        let origin =
            NetworkOrigin::https("graph.facebook.com", None).expect("valid WhatsApp origin");
        authorize_origin(&AllowTrust, "whatsapp", ACCOUNT, &origin).expect("approved origin")
    }

    fn credential(origin: ApprovedOrigin) -> ChannelCredential {
        ChannelCredential::bind(
            "access-token",
            CredentialRequest {
                channel_id: "whatsapp".to_owned(),
                account_id: ACCOUNT.to_owned(),
                kind: CredentialKind::Token,
                binding: CredentialBinding::Origin(origin),
            },
        )
        .expect("bound credential")
    }

    fn inbound(id: String) -> InboundMessage {
        InboundMessage {
            id,
            channel_id: "whatsapp".to_owned(),
            account_id: ACCOUNT.to_owned(),
            conversation_id: "whatsapp:15550001".to_owned(),
            sender_id: "15550001".to_owned(),
            text: Some("queued".to_owned()),
            attachments: Vec::new(),
            received_at_unix_ms: 1,
        }
    }

    #[test]
    fn current_maximum_batch_survives_near_full_history_and_existing_work() {
        let sent = Rc::new(RefCell::new(Vec::new()));
        let origin = approved_origin();
        let access = credential(origin.clone());
        let mut channel = WhatsAppChannel::new(
            ACCOUNT,
            "phone-id",
            origin,
            RecordingTransport {
                sent: Rc::clone(&sent),
            },
            FixedClock(10_000),
            NonZeroUsize::new(3).expect("non-zero capacity"),
        )
        .expect("WhatsApp channel");
        channel.start(&mut ()).expect("started");

        for index in 0..WHATSAPP_MAX_MESSAGES_PER_WEBHOOK {
            channel
                .completed_messages
                .push_back(CompletedWhatsAppMessage {
                    message_id: format!("payload-{index}"),
                    completed_at_unix_ms: 10_000,
                });
        }
        for index in 0..channel.pending_reply_capacity {
            channel
                .completed_messages
                .push_back(CompletedWhatsAppMessage {
                    message_id: format!("old-{index}"),
                    completed_at_unix_ms: 10_000,
                });
        }
        assert_eq!(
            channel.completed_messages.len(),
            channel.completed_message_capacity - 3
        );
        assert_eq!(
            channel.completed_message_capacity,
            WHATSAPP_MAX_MESSAGES_PER_WEBHOOK + channel.pending_reply_capacity + 3
        );

        for index in 0..3 {
            channel
                .inbound
                .push(inbound(format!("queued-{index}")))
                .expect("existing inbound capacity");
        }
        for index in 0..3 {
            channel.pending_replies.push_back(PendingWhatsAppReply {
                message_id: format!("pending-{index}"),
                to: "15550001".to_owned(),
                text: format!("pending reply {index}"),
                next_chunk: 0,
            });
        }
        assert_eq!(channel.inbound.len(), 3);
        assert_eq!(channel.pending_replies.len(), 3);

        let messages = (0..WHATSAPP_MAX_MESSAGES_PER_WEBHOOK)
            .map(|index| {
                format!(
                    r#"{{"from":"15550001","id":"payload-{index}","type":"text","text":{{"body":"duplicate"}}}}"#
                )
            })
            .collect::<Vec<_>>()
            .join(",");
        let payload = format!(
            r#"{{"entry":[{{"changes":[{{"value":{{"metadata":{{"phone_number_id":"phone-id"}},"messages":[{messages}]}}}}]}}]}}"#
        );
        let processed = Cell::new(0);

        let handled = channel
            .handle_webhook(
                payload.as_bytes(),
                &access,
                |_| {
                    processed.set(processed.get() + 1);
                    Ok(None)
                },
                &mut (),
            )
            .expect("current payload acknowledged");
        assert_eq!(handled.ingestion.ignored, WHATSAPP_MAX_MESSAGES_PER_WEBHOOK);
        assert_eq!(handled.processed, 6);
        assert_eq!(processed.get(), 3);
        assert_eq!(sent.borrow().len(), 3);

        let sent_before_replay = sent.borrow().len();
        let processed_before_replay = processed.get();
        let replay = channel
            .handle_webhook(
                payload.as_bytes(),
                &access,
                |_| panic!("the acknowledged maximum batch must remain completed"),
                &mut (),
            )
            .expect("immediate replay acknowledged");
        assert_eq!(replay.ingestion.ignored, WHATSAPP_MAX_MESSAGES_PER_WEBHOOK);
        assert_eq!(replay.processed, 0);
        assert_eq!(processed.get(), processed_before_replay);
        assert_eq!(sent.borrow().len(), sent_before_replay);
    }

    #[test]
    fn checkpoint_advances_only_when_the_send_may_have_transmitted() {
        let results = Rc::new(RefCell::new(VecDeque::from([
            Err(WhatsAppSendError::CancelledBeforeSend),
            Err(WhatsAppSendError::AmbiguousAfterSend(
                ChannelError::Transport(claw_channel_sdk::TransportErrorKind::Timeout),
            )),
        ])));
        let attempts = Rc::new(Cell::new(0));
        let origin = approved_origin();
        let access = credential(origin.clone());
        let mut channel = WhatsAppChannel::new(
            ACCOUNT,
            "phone-id",
            origin,
            ScriptedStageTransport {
                results,
                attempts: Rc::clone(&attempts),
            },
            FixedClock(10_000),
            NonZeroUsize::new(1).expect("non-zero capacity"),
        )
        .expect("WhatsApp channel");
        channel.start(&mut ()).expect("started");
        channel.pending_replies.push_back(PendingWhatsAppReply {
            message_id: "message-1".to_owned(),
            to: "15550001".to_owned(),
            text: "reply".to_owned(),
            next_chunk: 0,
        });

        assert_eq!(
            channel.process_webhook_queue(&access, |_| panic!("pending reply skips processing")),
            Err(ChannelError::Transport(
                claw_channel_sdk::TransportErrorKind::CancelledBeforeSend
            ))
        );
        assert_eq!(channel.pending_replies[0].next_chunk, 0);
        assert!(channel.completed_messages.is_empty());
        assert_eq!(attempts.get(), 1);

        assert_eq!(
            channel.process_webhook_queue(&access, |_| panic!("pending reply skips processing")),
            Err(ChannelError::Transport(
                claw_channel_sdk::TransportErrorKind::Timeout
            ))
        );
        assert_eq!(channel.pending_replies[0].next_chunk, 1);
        assert!(channel.completed_messages.is_empty());
        assert_eq!(attempts.get(), 2);

        assert_eq!(
            channel.process_webhook_queue(&access, |_| panic!("pending reply skips processing")),
            Ok(1)
        );
        assert!(channel.pending_replies.is_empty());
        assert_eq!(channel.completed_messages.len(), 1);
        assert_eq!(channel.completed_messages[0].message_id, "message-1");
        assert_eq!(attempts.get(), 2);
    }
}

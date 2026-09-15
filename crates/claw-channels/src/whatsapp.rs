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
const WHATSAPP_REPLY_WINDOW_MS: u64 = 24 * 60 * 60 * 1_000;

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

/// Provider-reported message state, separate from the local API acceptance receipt.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum WhatsAppDeliveryState {
    /// The Cloud service reports dispatch to its delivery path.
    Sent,
    /// The provider reports delivery to the recipient.
    Delivered,
    /// The provider reports that the recipient read the message.
    Read,
    /// The provider reports a failed delivery attempt.
    Failed,
}

impl WhatsAppDeliveryState {
    /// Returns the provider status label without conflating it with local send confirmation.
    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            Self::Sent => "sent",
            Self::Delivered => "delivered",
            Self::Read => "read",
            Self::Failed => "failed",
        }
    }
}

/// Bounded status metadata from a webhook whose signature must be verified by the host.
#[derive(Clone, Eq, PartialEq)]
pub struct WhatsAppDeliveryUpdate {
    /// Configured receiving phone account, not a caller-selected override.
    pub account_id: String,
    /// Provider receipt identity of the original outbound message.
    pub remote_message_id: String,
    /// Recipient whose original receipt must match.
    pub recipient_id: String,
    /// Provider-reported status, separate from local transport state.
    pub state: WhatsAppDeliveryState,
    /// Provider timestamp in Unix milliseconds.
    pub unix_millis: i64,
    /// Bounded numeric failure code, excluding freeform error text.
    pub failure_code: Option<u32>,
}

impl std::fmt::Debug for WhatsAppDeliveryUpdate {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("WhatsAppDeliveryUpdate")
            .field("state", &self.state)
            .field("unix_millis", &self.unix_millis)
            .finish_non_exhaustive()
    }
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

    /// Parses status callbacks for this configured phone without executing or sending messages.
    ///
    /// The host must verify the signature over the exact bytes before consuming these updates.
    ///
    /// # Errors
    /// Refuses foreign phone identities, malformed IDs/timestamps and oversized status batches.
    pub fn delivery_updates(
        &self,
        payload: &[u8],
    ) -> Result<Vec<WhatsAppDeliveryUpdate>, ChannelError> {
        #[derive(Deserialize)]
        struct Envelope<'a> {
            #[serde(default, borrow)]
            entry: Vec<Entry<'a>>,
        }
        #[derive(Deserialize)]
        struct Entry<'a> {
            #[serde(default, borrow)]
            changes: Vec<Change<'a>>,
        }
        #[derive(Deserialize)]
        struct Change<'a> {
            #[serde(borrow)]
            value: Option<StatusValue<'a>>,
        }
        #[derive(Deserialize)]
        struct StatusValue<'a> {
            #[serde(borrow)]
            metadata: Option<WhatsAppMetadata<'a>>,
            #[serde(default, borrow)]
            statuses: Vec<DeliveryReport<'a>>,
        }
        #[derive(Deserialize)]
        struct DeliveryReport<'a> {
            id: &'a str,
            recipient_id: &'a str,
            timestamp: &'a str,
            status: WhatsAppDeliveryState,
            #[serde(default)]
            errors: Vec<StatusError>,
        }
        #[derive(Deserialize)]
        struct StatusError {
            code: u32,
        }

        self.require_running()?;
        if payload.len() > MAX_PROVIDER_RESPONSE_BYTES {
            return Err(ChannelError::Protocol(ProtocolErrorKind::PayloadTooLarge));
        }
        let body: Envelope<'_> = serde_json::from_slice(payload)
            .map_err(|_| ChannelError::Protocol(ProtocolErrorKind::MalformedResponse))?;
        let mut updates = Vec::new();
        for value in body
            .entry
            .into_iter()
            .flat_map(|entry| entry.changes)
            .filter_map(|change| change.value)
        {
            if !value.statuses.is_empty()
                && value
                    .metadata
                    .is_none_or(|metadata| metadata.phone_number_id != self.phone_number_id)
            {
                return Err(ChannelError::Protocol(ProtocolErrorKind::InvalidField));
            }
            for status in value.statuses {
                if updates.len() >= WHATSAPP_MAX_MESSAGES_PER_WEBHOOK {
                    return Err(ChannelError::Protocol(ProtocolErrorKind::PayloadTooLarge));
                }
                if !valid_cloud_receipt_id(status.id)
                    || invalid_routing_identifier(status.recipient_id)
                    || status.timestamp.is_empty()
                    || !status.timestamp.bytes().all(|byte| byte.is_ascii_digit())
                    || status.errors.len() > 16
                {
                    return Err(ChannelError::Protocol(ProtocolErrorKind::InvalidField));
                }
                let unix_millis = status
                    .timestamp
                    .parse::<i64>()
                    .ok()
                    .and_then(|seconds| seconds.checked_mul(1_000))
                    .ok_or(ChannelError::Protocol(ProtocolErrorKind::InvalidField))?;
                updates.push(WhatsAppDeliveryUpdate {
                    account_id: self.account_id.clone(),
                    remote_message_id: status.id.to_owned(),
                    recipient_id: status.recipient_id.to_owned(),
                    state: status.status,
                    unix_millis,
                    failure_code: if status.status == WhatsAppDeliveryState::Failed {
                        status.errors.first().map(|error| error.code)
                    } else {
                        None
                    },
                });
            }
        }
        Ok(updates)
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
        self.ingest_webhook_mode(payload, diagnostics, false)
    }

    /// Queues native text input only after every message has a valid provider reply timestamp.
    ///
    /// # Errors
    /// Refuses missing/malformed/expired timestamps before mutating the inbound queue.
    pub fn ingest_native_webhook(
        &mut self,
        payload: &[u8],
        diagnostics: &mut impl DiagnosticSink,
    ) -> Result<WhatsAppWebhookStats, ChannelError> {
        self.ingest_webhook_mode(payload, diagnostics, true)
    }

    fn ingest_webhook_mode(
        &mut self,
        payload: &[u8],
        diagnostics: &mut impl DiagnosticSink,
        native: bool,
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
        if native {
            let now = self.clock.now_unix_ms();
            for message in body
                .entry
                .iter()
                .flat_map(|entry| &entry.changes)
                .filter_map(|change| change.value.as_ref())
                .flat_map(|value| &value.messages)
                .filter(|message| {
                    message.kind == Some("text") && message.from != self.phone_number_id
                })
            {
                let received_at = native_message_timestamp(message.timestamp)
                    .ok_or(ChannelError::Protocol(ProtocolErrorKind::InvalidField))?;
                validate_reply_timestamp(received_at, now)?;
            }
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
                    let received_at_unix_ms = if native {
                        native_message_timestamp(message.timestamp)
                            .ok_or(ChannelError::Protocol(ProtocolErrorKind::InvalidField))?
                    } else {
                        message
                            .timestamp
                            .and_then(|timestamp| timestamp.parse::<u64>().ok())
                            .and_then(|seconds| seconds.checked_mul(1_000))
                            .unwrap_or_else(|| self.clock.now_unix_ms())
                    };
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

    /// Checks the native route and conservative text-reply window for this inbound message.
    ///
    /// # Errors
    /// Refuses foreign routes, missing/future timestamps and messages at least 24 hours old.
    pub fn validate_native_reply(&self, message: &InboundMessage) -> Result<(), ChannelError> {
        self.require_running()?;
        message.validate().map_err(ChannelError::InvalidMessage)?;
        if message.channel_id != "whatsapp"
            || message.account_id != self.account_id
            || message.conversation_id != format!("whatsapp:{}", message.sender_id)
        {
            return Err(ChannelError::Configuration(
                ConfigurationError::ConversationScopeMismatch,
            ));
        }
        validate_reply_timestamp(message.received_at_unix_ms, self.clock.now_unix_ms())
    }

    /// Sends exactly one normalized reply segment and requires a complete Cloud acknowledgement.
    ///
    /// The native host owns the durable claim and must not repeat an unconfirmed call.
    ///
    /// # Errors
    /// Refuses invalid/expired routes, multi-segment input and missing or malformed remote IDs.
    pub fn send_confirmed_reply_segment(
        &mut self,
        message: &InboundMessage,
        content: &str,
        credential: &ChannelCredential,
    ) -> Result<String, ChannelError> {
        self.validate_native_reply(message)?;
        let mut segments = segment_outbound_text_iter("whatsapp", content)?;
        let first = segments
            .next()
            .transpose()?
            .ok_or(ChannelError::InvalidMessage(
                InvalidMessageReason::EmptyContent,
            ))?;
        if first.as_ref() != content || segments.next().is_some() {
            return Err(ChannelError::Protocol(ProtocolErrorKind::PayloadTooLarge));
        }
        credential
            .expose_for_origin(
                "whatsapp",
                &self.account_id,
                CredentialKind::Token,
                &self.graph_origin,
                |access_token| {
                    validate_reply_timestamp(
                        message.received_at_unix_ms,
                        self.clock.now_unix_ms(),
                    )?;
                    let response = self
                        .transport
                        .send_text(&WhatsAppSendRequest {
                            access_token,
                            phone_number_id: &self.phone_number_id,
                            to: &message.sender_id,
                            text: content,
                        })
                        .map_err(WhatsAppSendError::into_channel_error)?;
                    classify_response(&response)?;
                    response.require_bounded()?;
                    let sent: WhatsAppSendEnvelope<'_> = serde_json::from_slice(response.body())
                        .map_err(|_| {
                            ChannelError::Protocol(ProtocolErrorKind::MalformedResponse)
                        })?;
                    let [receipt] = sent.messages.as_slice() else {
                        return Err(ChannelError::Protocol(ProtocolErrorKind::InvalidField));
                    };
                    if !valid_cloud_receipt_id(receipt.id) {
                        return Err(ChannelError::Protocol(ProtocolErrorKind::InvalidField));
                    }
                    Ok(receipt.id.to_owned())
                },
            )
            .map_err(map_credential_binding)?
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

fn native_message_timestamp(timestamp: Option<&str>) -> Option<u64> {
    let timestamp = timestamp
        .filter(|value| !value.is_empty() && value.bytes().all(|byte| byte.is_ascii_digit()))?;
    timestamp
        .parse::<u64>()
        .ok()?
        .checked_mul(1_000)
        .filter(|millis| *millis > 0)
}

fn validate_reply_timestamp(received_at: u64, now: u64) -> Result<(), ChannelError> {
    if received_at == 0
        || now
            .checked_sub(received_at)
            .is_none_or(|age| age >= WHATSAPP_REPLY_WINDOW_MS)
    {
        return Err(ChannelError::Protocol(ProtocolErrorKind::InvalidField));
    }
    Ok(())
}

fn valid_cloud_receipt_id(id: &str) -> bool {
    id.len() > 6
        && id.len() <= 256
        && id.starts_with("wamid.")
        && id.bytes().all(|byte| {
            byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'+' | b'/' | b'_' | b'-' | b'=')
        })
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
    for (index, pair) in encoded.as_bytes().as_chunks::<2>().0.iter().enumerate() {
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
    fn whatsapp_delivery_updates_bind_phone_recipient_and_keep_only_bounded_status_metadata() {
        let origin = approved_origin();
        let mut channel = WhatsAppChannel::new(
            ACCOUNT,
            "phone-id",
            origin,
            RecordingTransport {
                sent: Rc::new(RefCell::new(Vec::new())),
            },
            FixedClock(1),
            NonZeroUsize::new(2).expect("queue"),
        )
        .expect("channel");
        channel.start(&mut ()).expect("started");
        for state in ["sent", "delivered", "read", "failed"] {
            let body = serde_json::json!({"entry":[{"changes":[{"value":{"metadata":{"phone_number_id":"phone-id"},"statuses":[{"id":"wamid.confirmed","recipient_id":"15550001","status":state,"timestamp":"42","errors":[{"code":131_000,"message":"private-error-detail"}]}]}}]}]});
            let updates = channel
                .delivery_updates(body.to_string().as_bytes())
                .expect("verified status fields");
            assert_eq!(updates.len(), 1);
            assert_eq!(updates[0].state.label(), state);
            assert_eq!(updates[0].account_id, ACCOUNT);
            assert_eq!(updates[0].recipient_id, "15550001");
            assert_eq!(updates[0].unix_millis, 42_000);
            assert_eq!(
                updates[0].failure_code,
                (state == "failed").then_some(131_000)
            );
            assert!(!format!("{updates:?}").contains("private-error-detail"));
            for (pointer, invalid) in [
                (
                    "/entry/0/changes/0/value/metadata/phone_number_id",
                    serde_json::json!("other-phone"),
                ),
                (
                    "/entry/0/changes/0/value/statuses/0/id",
                    serde_json::json!("wrong-id"),
                ),
                (
                    "/entry/0/changes/0/value/statuses/0/recipient_id",
                    serde_json::json!(""),
                ),
                (
                    "/entry/0/changes/0/value/statuses/0/timestamp",
                    serde_json::json!("9223372036854775807"),
                ),
                (
                    "/entry/0/changes/0/value/statuses/0/status",
                    serde_json::json!("unknown"),
                ),
            ] {
                let mut changed = body.clone();
                *changed.pointer_mut(pointer).expect("field") = invalid;
                assert!(
                    channel
                        .delivery_updates(changed.to_string().as_bytes())
                        .is_err(),
                    "{pointer}"
                );
            }
        }
        assert!(
            channel
                .delivery_updates(br#"{"entry":[]}"#)
                .expect("empty status set")
                .is_empty()
        );
        assert!(
            channel
                .poll_inbound()
                .expect("status callbacks never enqueue model input")
                .is_none()
        );
    }

    #[test]
    fn native_whatsapp_segment_requires_one_cloud_receipt_without_hidden_splitting() {
        for response in [
            br#"{"messages":[{"id":"wamid.fixture-one"}]}"#.as_slice(),
            b"",
            b"{}",
            br#"{"messages":[]}"#,
            br#"{"messages":[{"id":"wamid.one"},{"id":"wamid.two"}]}"#,
            br#"{"messages":[{"id":"invalid-id"}]}"#,
            br#"{"messages":[{"id":"wamid. bad"}]}"#,
        ] {
            let origin = approved_origin();
            let access = credential(origin.clone());
            let attempts = Rc::new(Cell::new(0));
            let transport = ScriptedStageTransport {
                results: Rc::new(RefCell::new(VecDeque::from([Ok(ProviderResponse::new(
                    200, response,
                ))]))),
                attempts: Rc::clone(&attempts),
            };
            let mut channel = WhatsAppChannel::new(
                ACCOUNT,
                "phone-id",
                origin,
                transport,
                FixedClock(10),
                NonZeroUsize::new(2).expect("queue"),
            )
            .expect("channel");
            channel.start(&mut ()).expect("started");
            let mut message = inbound("message-one".to_owned());
            message.received_at_unix_ms = 1;
            let mut foreign = message.clone();
            foreign.account_id = "other-account".to_owned();
            assert!(
                channel
                    .send_confirmed_reply_segment(&foreign, "reply", &access)
                    .is_err()
            );
            foreign = message.clone();
            foreign.conversation_id = "whatsapp:someone-else".to_owned();
            assert!(
                channel
                    .send_confirmed_reply_segment(&foreign, "reply", &access)
                    .is_err()
            );
            assert!(
                channel
                    .send_confirmed_reply_segment(&message, &"x".repeat(8_000), &access)
                    .is_err()
            );
            assert_eq!(attempts.get(), 0);
            let result = channel.send_confirmed_reply_segment(&message, "reply", &access);
            assert_eq!(
                result.is_ok(),
                response == br#"{"messages":[{"id":"wamid.fixture-one"}]}"#
            );
            assert_eq!(
                attempts.get(),
                1,
                "the native entry never retries a remote request"
            );
        }
    }

    #[test]
    fn native_whatsapp_ingress_requires_timestamps_before_enqueuing_any_batch_member() {
        let sent = Rc::new(RefCell::new(Vec::new()));
        let mut channel = WhatsAppChannel::new(
            ACCOUNT,
            "phone-id",
            approved_origin(),
            RecordingTransport {
                sent: Rc::clone(&sent),
            },
            FixedClock(1_000 + WHATSAPP_REPLY_WINDOW_MS),
            NonZeroUsize::new(2).expect("queue"),
        )
        .expect("channel");
        channel.start(&mut ()).expect("started");
        let body = serde_json::json!({"entry":[{"changes":[{"value":{"metadata":{"phone_number_id":"phone-id"},"messages":[{"from":"15550001","id":"timestamp-one","type":"text","timestamp":"2","text":{"body":"valid input"}},{"from":"15550001","id":"timestamp-two","type":"text","timestamp":"3","text":{"body":"later input"}}]}}]}]});
        for invalid in [
            serde_json::Value::Null,
            serde_json::json!(""),
            serde_json::json!("0"),
            serde_json::json!("-1"),
            serde_json::json!("+2"),
            serde_json::json!("18446744073709551615"),
            serde_json::json!("86402"),
            serde_json::json!("1"),
        ] {
            let mut rejected = body.clone();
            rejected["entry"][0]["changes"][0]["value"]["messages"][1]["timestamp"] = invalid;
            assert!(
                channel
                    .ingest_native_webhook(rejected.to_string().as_bytes(), &mut ())
                    .is_err()
            );
            assert!(
                channel.poll_inbound().expect("queue").is_none(),
                "no partial admission before rejecting later timestamps"
            );
        }
        assert_eq!(
            channel
                .ingest_native_webhook(body.to_string().as_bytes(), &mut ())
                .expect("native batch")
                .queued,
            2
        );
        assert_eq!(
            channel
                .poll_inbound()
                .expect("queue")
                .expect("first")
                .received_at_unix_ms,
            2_000
        );
        assert_eq!(
            channel
                .poll_inbound()
                .expect("queue")
                .expect("second")
                .received_at_unix_ms,
            3_000
        );
        assert!(sent.borrow().is_empty());
        let mut legacy = body;
        legacy["entry"][0]["changes"][0]["value"]["messages"][0]["timestamp"] =
            serde_json::Value::Null;
        assert_eq!(
            channel
                .ingest_webhook(legacy.to_string().as_bytes(), &mut ())
                .expect("legacy compatibility")
                .queued,
            2
        );
        assert_eq!(
            channel
                .poll_inbound()
                .expect("queue")
                .expect("legacy first")
                .received_at_unix_ms,
            1_000 + WHATSAPP_REPLY_WINDOW_MS
        );
    }

    #[test]
    fn native_whatsapp_text_reply_window_is_rechecked_before_each_transport_call() {
        struct AdjustableClock(Rc<Cell<u64>>);
        impl UnixClock for AdjustableClock {
            fn now_unix_ms(&self) -> u64 {
                self.0.get()
            }
        }
        let now = Rc::new(Cell::new(1_000 + WHATSAPP_REPLY_WINDOW_MS - 1));
        let attempts = Rc::new(Cell::new(0));
        let origin = approved_origin();
        let access = credential(origin.clone());
        let transport = ScriptedStageTransport {
            results: Rc::new(RefCell::new(VecDeque::from([Ok(ProviderResponse::new(
                200,
                br#"{"messages":[{"id":"wamid.window-one"}]}"#.to_vec(),
            ))]))),
            attempts: Rc::clone(&attempts),
        };
        let mut channel = WhatsAppChannel::new(
            ACCOUNT,
            "phone-id",
            origin,
            transport,
            AdjustableClock(Rc::clone(&now)),
            NonZeroUsize::new(2).expect("queue"),
        )
        .expect("channel");
        channel.start(&mut ()).expect("started");
        let mut message = inbound("window-one".to_owned());
        message.received_at_unix_ms = 1_000;
        assert_eq!(
            channel
                .send_confirmed_reply_segment(&message, "reply", &access)
                .expect("inside window"),
            "wamid.window-one"
        );
        now.set(1_000 + WHATSAPP_REPLY_WINDOW_MS);
        assert!(
            channel
                .send_confirmed_reply_segment(&message, "later segment", &access)
                .is_err()
        );
        now.set(999);
        assert!(
            channel
                .send_confirmed_reply_segment(&message, "clock rollback", &access)
                .is_err()
        );
        now.set(1_000);
        message.received_at_unix_ms = 0;
        assert!(
            channel
                .send_confirmed_reply_segment(&message, "unknown time", &access)
                .is_err()
        );
        message.received_at_unix_ms = u64::MAX;
        assert!(
            channel
                .send_confirmed_reply_segment(&message, "invalid future", &access)
                .is_err()
        );
        assert_eq!(
            attempts.get(),
            1,
            "expired/untrusted timestamps never reach transport or trigger templates"
        );
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

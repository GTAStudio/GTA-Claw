//! Structured, credential-safe channel diagnostics.

use std::fmt::{self, Display, Formatter};
use std::time::Duration;

/// Operator-facing diagnostic severity.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DiagnosticLevel {
    /// Normal lifecycle information.
    Info,
    /// Recoverable degradation or ignored provider input.
    Warning,
    /// An operation failed or exhausted its recovery budget.
    Error,
}

/// Stable channel diagnostic category.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DiagnosticCode {
    /// A channel began accepting work.
    ChannelStarted,
    /// A channel stopped and will accept no new work.
    ChannelStopped,
    /// Empty inbound text was ignored.
    EmptyMessageIgnored,
    /// A message authored by a bot was ignored.
    BotMessageIgnored,
    /// A command addressed to another bot was ignored.
    ForeignCommandIgnored,
    /// Provider input could not be parsed.
    MalformedPayload,
    /// Required conversation routing was absent.
    MissingConversation,
    /// The configured engine is unavailable and authentication is required.
    AuthenticationRequired,
    /// Conversation processing failed and a stable apology was returned.
    ConversationFailed,
    /// A bounded inbound queue refused an additional message.
    InboundQueueFull,
    /// A bounded action queue refused additional work.
    ActionQueueFull,
    /// A provider polling operation failed and may be retried.
    PollFailed,
    /// A channel transport could not open or send gateway control traffic.
    ConnectionFailed,
    /// A disconnected channel scheduled another connection attempt.
    ReconnectScheduled,
    /// A channel exhausted its configured reconnect budget.
    ReconnectExhausted,
    /// A Discord gateway transport opened.
    GatewayConnected,
    /// A Discord gateway transport closed.
    GatewayDisconnected,
    /// A Discord heartbeat acknowledgement did not arrive in time.
    HeartbeatMissed,
    /// A provider rejected an outbound operation.
    ProviderRejected,
    /// A webhook challenge was rejected.
    VerificationRejected,
}

impl Display for DiagnosticCode {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::ChannelStarted => "channel started",
            Self::ChannelStopped => "channel stopped",
            Self::EmptyMessageIgnored => "empty inbound message ignored",
            Self::BotMessageIgnored => "bot-authored message ignored",
            Self::ForeignCommandIgnored => "command addressed to another bot ignored",
            Self::MalformedPayload => "provider payload was malformed",
            Self::MissingConversation => "provider message has no conversation route",
            Self::AuthenticationRequired => "conversation engine requires authentication",
            Self::ConversationFailed => "conversation processing failed",
            Self::InboundQueueFull => "inbound queue is full",
            Self::ActionQueueFull => "channel action queue is full",
            Self::PollFailed => "provider poll failed",
            Self::ConnectionFailed => "channel connection operation failed",
            Self::ReconnectScheduled => "channel reconnect scheduled",
            Self::ReconnectExhausted => "channel reconnect budget exhausted",
            Self::GatewayConnected => "gateway connected",
            Self::GatewayDisconnected => "gateway disconnected",
            Self::HeartbeatMissed => "gateway heartbeat acknowledgement missed",
            Self::ProviderRejected => "provider rejected channel operation",
            Self::VerificationRejected => "webhook verification rejected",
        })
    }
}

/// One diagnostic event with bounded, non-secret context.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct OperatorDiagnostic<'a> {
    /// Event severity.
    pub level: DiagnosticLevel,
    /// Stable event category.
    pub code: DiagnosticCode,
    /// Exact registered channel identifier.
    pub channel_id: &'static str,
    /// Configured account identifier.
    pub account_id: &'a str,
    /// Provider conversation identifier when available.
    pub conversation_id: Option<&'a str>,
    /// Provider status code when available. Response bodies are never included.
    pub remote_status: Option<u16>,
    /// Delay before the next scheduled attempt when available.
    pub retry_after: Option<Duration>,
}

impl Display for OperatorDiagnostic<'_> {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "{}: channel={} account={}",
            self.code, self.channel_id, self.account_id
        )?;
        if let Some(conversation_id) = self.conversation_id {
            write!(formatter, " conversation={conversation_id}")?;
        }
        if let Some(status) = self.remote_status {
            write!(formatter, " status={status}")?;
        }
        if let Some(retry_after) = self.retry_after {
            write!(formatter, " retry_after={retry_after:?}")?;
        }
        Ok(())
    }
}

/// Sink for structured channel diagnostics.
pub trait DiagnosticSink {
    /// Records one event. Implementations must not enrich it with credentials or
    /// unreviewed provider response bodies.
    fn record(&mut self, diagnostic: OperatorDiagnostic<'_>);
}

impl DiagnosticSink for () {
    fn record(&mut self, _diagnostic: OperatorDiagnostic<'_>) {}
}

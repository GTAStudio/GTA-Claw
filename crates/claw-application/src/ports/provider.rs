//! The model provider port and its incremental stream contract.

use claw_domain::SessionId;

use super::{PortError, PortFuture};
use crate::model::ids::{ToolCallId, TurnId};
use crate::model::message::ToolCall;

/// Coverage of the primary input/output token counters supplied by a provider.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub enum UsageReporting {
    /// No usage object was supplied; zero counters do not mean free inference.
    #[default]
    Unreported,
    /// Some usage was observed, but complete primary counters are unproven.
    Partial,
    /// Input and output counters were explicitly reported, including zero.
    /// This is not evidence of settled billing or complete pricing details.
    Complete,
}

impl UsageReporting {
    /// Stable label for persisted or operator-facing metadata.
    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            Self::Unreported => "unreported",
            Self::Partial => "partial",
            Self::Complete => "complete",
        }
    }
}

/// A confirmed terminal on a model response; transport failures have no such record.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ProviderResponseFinish {
    /// A complete text response.
    Stop,
    /// A complete set of function calls.
    ToolCalls,
    /// Output stopped at the token limit.
    Length,
    /// Output stopped at a provider filter.
    ContentFilter,
}

impl ProviderResponseFinish {
    /// Stable storage label for the confirmed response terminal.
    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            Self::Stop => "stop",
            Self::ToolCalls => "tool_calls",
            Self::Length => "length",
            Self::ContentFilter => "content_filter",
        }
    }
}

/// Bounded metadata reported for a response, not a proof of monetary settlement.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProviderResponseReport {
    /// Provider instance that actually returned the response.
    pub provider: String,
    /// Model named in the response, not a later model selection.
    pub model: String,
    /// Remote response identifier, when one was supplied.
    pub response_id: Option<String>,
    /// Which primary usage fields were explicitly reported.
    pub usage_reporting: UsageReporting,
    /// Total input tokens, including cached input.
    pub input_tokens: u64,
    /// Total output tokens, including reasoning when reported.
    pub output_tokens: u64,
    /// Reported subset of input served from cache.
    pub cached_input_tokens: u64,
    /// Reported subset of output used for reasoning.
    pub reasoning_tokens: u64,
    /// Confirmed response terminal, including partial output.
    pub finish_reason: ProviderResponseFinish,
}

impl ProviderResponseReport {
    /// Checks metadata and counters before runtime storage or operator display.
    ///
    /// # Errors
    /// Refuses unbounded identities, inconsistent counters and fabricated unreported usage.
    pub fn validate(&self) -> Result<(), PortError> {
        let valid = |value: &str| {
            !value.is_empty()
                && value.len() <= 512
                && !value
                    .chars()
                    .any(|character| character.is_control() || character.is_whitespace())
        };
        if !valid(&self.provider)
            || !valid(&self.model)
            || self.response_id.as_deref().is_some_and(|id| !valid(id))
            || self.input_tokens.checked_add(self.output_tokens).is_none()
            || self.cached_input_tokens > self.input_tokens
            || self.reasoning_tokens > self.output_tokens
            || (self.usage_reporting == UsageReporting::Unreported
                && (self.input_tokens != 0 || self.output_tokens != 0))
        {
            return Err(PortError::Invalid(
                "provider response accounting is inconsistent".to_owned(),
            ));
        }
        Ok(())
    }
}

/// One admitted provider round's response metadata. A missing report remains unknown.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProviderRoundRecord {
    /// Zero-based round index in its owning turn.
    pub round: u32,
    /// Response metadata, absent when no confirmed report was received.
    pub response: Option<ProviderResponseReport>,
}

impl ProviderRoundRecord {
    /// Validates a bounded, gap-free sequence of reports without aggregating unknown usage.
    ///
    /// # Errors
    /// Refuses duplicate, missing, reordered or excessive rounds and invalid response reports.
    pub fn validate_sequence(records: &[Self]) -> Result<(), PortError> {
        if records.len() > MAX_PROVIDER_ROUND_RECORDS {
            return Err(PortError::Invalid(
                "provider accounting round limit exceeded".to_owned(),
            ));
        }
        for (index, record) in records.iter().enumerate() {
            if u32::try_from(index).ok() != Some(record.round) {
                return Err(PortError::Invalid(
                    "provider accounting rounds are not contiguous".to_owned(),
                ));
            }
            if let Some(response) = &record.response {
                response.validate()?;
            }
        }
        Ok(())
    }
}

/// Bound on accounting entries stored in one turn, independent of context or output sizes.
pub const MAX_PROVIDER_ROUND_RECORDS: usize = 1024;

/// One prompt message handed to a provider.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum PromptMessage {
    /// Runtime or policy context.
    System {
        /// The instruction text.
        text: String,
    },
    /// Operator-authored input.
    User {
        /// The input text.
        text: String,
    },
    /// A previous assistant response.
    Assistant {
        /// The response text.
        text: String,
        /// The tool calls that response requested.
        tool_calls: Vec<ToolCall>,
    },
    /// The result of a tool the assistant requested.
    ToolResult {
        /// The call the result answers.
        call_id: ToolCallId,
        /// The serialised tool output.
        output: String,
        /// Whether the tool failed.
        failed: bool,
    },
}

/// One provider round for a single turn.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProviderRequest {
    /// The session that owns the turn.
    pub session_id: SessionId,
    /// The turn being executed.
    pub turn: TurnId,
    /// The zero-based provider round inside the turn.
    pub round: u32,
    /// The assembled prompt.
    pub messages: Vec<PromptMessage>,
    /// The tool names the provider may call.
    pub tool_names: Vec<String>,
    /// The model the round must run against, when the operator selected one.
    ///
    /// `None` means the adapter picks its own default. Adapters that cannot honour an explicit
    /// selection should fail the round rather than silently substitute another model.
    pub model: Option<String>,
}

/// One incremental unit of provider output.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ProviderChunk {
    /// Additional visible assistant text.
    TextDelta {
        /// The appended text.
        text: String,
    },
    /// Additional hidden reasoning text.
    ReasoningDelta {
        /// The appended text.
        text: String,
    },
    /// A tool call has started streaming.
    ToolCallBegin {
        /// The provider-assigned call identifier.
        call_id: ToolCallId,
        /// The tool being called.
        name: String,
    },
    /// Additional JSON argument text for an open tool call.
    ToolCallArgumentsDelta {
        /// The open call the fragment belongs to.
        call_id: ToolCallId,
        /// The appended JSON fragment.
        fragment: String,
    },
    /// A tool call has finished streaming.
    ToolCallEnd {
        /// The call being closed.
        call_id: ToolCallId,
    },
    /// The assistant message is complete.
    MessageEnd,
}

/// A pull-based stream of provider output.
///
/// The trait is pull-based rather than `Stream`-based so this crate stays free of async
/// ecosystem dependencies while remaining object-safe.
pub trait ProviderStream: Send {
    /// Returns the latest confirmed response metadata without I/O or inference.
    ///
    /// Older adapters return `None`; absence never means the operation was free.
    fn response_report(&self) -> Option<ProviderResponseReport> {
        None
    }

    /// Returns the next chunk, or `None` once the provider closed the stream cleanly.
    fn next_chunk(&mut self) -> PortFuture<'_, Result<Option<ProviderChunk>, PortError>>;
}

/// Opens provider streams for turns.
pub trait ProviderPort: Send + Sync + 'static {
    /// Starts one provider round and returns its stream.
    fn start_round(
        &self,
        request: ProviderRequest,
    ) -> PortFuture<'_, Result<Box<dyn ProviderStream>, PortError>>;
}

#[cfg(test)]
mod accounting_tests {
    use super::*;

    #[test]
    fn response_reporting_preserves_unknown_zero_and_refuses_inconsistent_counters() {
        let mut report = ProviderResponseReport {
            provider: "owned-provider".to_owned(),
            model: "owned-model".to_owned(),
            response_id: Some("owned-response".to_owned()),
            usage_reporting: UsageReporting::Unreported,
            input_tokens: 0,
            output_tokens: 0,
            cached_input_tokens: 0,
            reasoning_tokens: 0,
            finish_reason: ProviderResponseFinish::Length,
        };
        assert!(report.validate().is_ok());
        report.input_tokens = 1;
        assert!(report.validate().is_err());
        report.usage_reporting = UsageReporting::Partial;
        assert!(report.validate().is_ok());
        report.usage_reporting = UsageReporting::Complete;
        report.input_tokens = 0;
        assert!(report.validate().is_ok());
        report.reasoning_tokens = 1;
        assert!(report.validate().is_err());
        report.reasoning_tokens = 0;
        report.cached_input_tokens = 1;
        assert!(report.validate().is_err());
        report.cached_input_tokens = 0;
        report.input_tokens = u64::MAX;
        report.output_tokens = 1;
        assert!(report.validate().is_err());
        report.input_tokens = 0;
        report.response_id = Some("bad identity".to_owned());
        assert!(report.validate().is_err());
        assert_eq!(UsageReporting::Unreported.label(), "unreported");
        assert_eq!(ProviderResponseFinish::Length.label(), "length");
    }
}

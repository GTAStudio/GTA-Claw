//! The model provider port and its incremental stream contract.

use claw_domain::SessionId;

use super::{PortError, PortFuture};
use crate::model::ids::{ToolCallId, TurnId};
use crate::model::message::ToolCall;

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

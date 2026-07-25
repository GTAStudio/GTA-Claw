//! The model provider port and its incremental stream contract.

use claw_domain::SessionId;
use serde::{Deserialize, Serialize};

use super::{PortError, PortFuture};
use crate::model::ids::{ToolCallId, TurnId};
use crate::model::message::ToolCall;

/// One prompt message handed to a provider.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case", tag = "role")]
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
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ProviderRequest {
    /// The session that owns the turn.
    #[serde(with = "crate::model::session_id_serde")]
    pub session_id: SessionId,
    /// The turn being executed.
    pub turn: TurnId,
    /// The zero-based provider round inside the turn.
    pub round: u32,
    /// The assembled prompt.
    pub messages: Vec<PromptMessage>,
    /// The tool names the provider may call.
    pub tool_names: Vec<String>,
}

/// One incremental unit of provider output.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case", tag = "chunk")]
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

#[cfg(test)]
mod tests {
    use super::{PromptMessage, ProviderChunk};
    use crate::model::ids::ToolCallId;

    #[test]
    fn chunks_serialise_with_a_tagged_representation() {
        let encoded = serde_json::to_string(&ProviderChunk::ToolCallBegin {
            call_id: ToolCallId::new("call-1").expect("valid call id"),
            name: "read_file".to_owned(),
        })
        .expect("chunk serialises");

        assert_eq!(
            encoded,
            "{\"chunk\":\"tool_call_begin\",\"call_id\":\"call-1\",\"name\":\"read_file\"}"
        );
    }

    #[test]
    fn message_end_serialises_without_a_payload() {
        let encoded = serde_json::to_string(&ProviderChunk::MessageEnd).expect("chunk serialises");

        assert_eq!(encoded, "{\"chunk\":\"message_end\"}");
        assert_eq!(
            serde_json::from_str::<ProviderChunk>(&encoded).expect("chunk deserialises"),
            ProviderChunk::MessageEnd
        );
    }

    #[test]
    fn prompt_messages_round_trip_through_json() {
        let message = PromptMessage::ToolResult {
            call_id: ToolCallId::new("call-2").expect("valid call id"),
            output: "ok".to_owned(),
            failed: false,
        };
        let encoded = serde_json::to_string(&message).expect("prompt serialises");

        assert_eq!(
            encoded,
            "{\"role\":\"tool_result\",\"call_id\":\"call-2\",\"output\":\"ok\",\"failed\":false}"
        );
        assert_eq!(
            serde_json::from_str::<PromptMessage>(&encoded).expect("prompt deserialises"),
            message
        );
    }
}

//! Assistant message values produced by streaming assembly.

use serde::{Deserialize, Serialize};

use super::ids::ToolCallId;

/// A fully assembled tool call requested by the provider.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ToolCall {
    /// The provider-assigned call identifier.
    pub call_id: ToolCallId,
    /// The tool name to dispatch.
    pub name: String,
    /// The complete JSON argument document, as received.
    pub arguments: String,
}

/// A tool call whose arguments never finished streaming.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct PendingToolCall {
    /// The provider-assigned call identifier.
    pub call_id: ToolCallId,
    /// The tool name to dispatch, when it was announced.
    pub name: String,
    /// The argument fragments received before the stream ended.
    pub partial_arguments: String,
}

/// A complete assistant message.
#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
pub struct AssistantMessage {
    /// The visible assistant text.
    pub text: String,
    /// The hidden reasoning text, when the provider emits it.
    pub reasoning: String,
    /// Tool calls whose arguments completed.
    pub tool_calls: Vec<ToolCall>,
}

/// Everything recoverable from a stream that ended before the message completed.
#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
pub struct PartialAssistantMessage {
    /// The visible assistant text received so far.
    pub text: String,
    /// The hidden reasoning text received so far.
    pub reasoning: String,
    /// Tool calls whose arguments completed before the interruption.
    pub tool_calls: Vec<ToolCall>,
    /// Tool calls that were still streaming when the interruption happened.
    pub pending_tool_calls: Vec<PendingToolCall>,
    /// The next sequence number a resumed assembler must emit.
    pub next_sequence: u64,
}

impl PartialAssistantMessage {
    /// Returns whether any content at all was recovered.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.text.is_empty()
            && self.reasoning.is_empty()
            && self.tool_calls.is_empty()
            && self.pending_tool_calls.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::{AssistantMessage, PartialAssistantMessage, PendingToolCall, ToolCall};
    use crate::model::ids::ToolCallId;

    #[test]
    fn assistant_messages_round_trip_through_json() {
        let message = AssistantMessage {
            text: "done".to_owned(),
            reasoning: "because".to_owned(),
            tool_calls: vec![ToolCall {
                call_id: ToolCallId::new("call-1").expect("valid call id"),
                name: "read_file".to_owned(),
                arguments: "{\"path\":\"a.txt\"}".to_owned(),
            }],
        };

        let encoded = serde_json::to_string(&message).expect("message serialises");

        assert_eq!(
            encoded,
            "{\"text\":\"done\",\"reasoning\":\"because\",\"tool_calls\":[{\"call_id\":\"call-1\",\"name\":\"read_file\",\"arguments\":\"{\\\"path\\\":\\\"a.txt\\\"}\"}]}"
        );
        assert_eq!(
            serde_json::from_str::<AssistantMessage>(&encoded).expect("message deserialises"),
            message
        );
    }

    #[test]
    fn partial_emptiness_tracks_every_content_channel() {
        let mut partial = PartialAssistantMessage::default();
        assert!(partial.is_empty());

        partial.pending_tool_calls.push(PendingToolCall {
            call_id: ToolCallId::new("call-2").expect("valid call id"),
            name: "write_file".to_owned(),
            partial_arguments: "{\"pa".to_owned(),
        });
        assert!(!partial.is_empty());

        let mut reasoning_only = PartialAssistantMessage::default();
        reasoning_only.reasoning.push_str("thinking");
        assert!(!reasoning_only.is_empty());
    }
}

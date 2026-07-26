//! Assistant message values produced by streaming assembly.

use super::ids::ToolCallId;

/// A fully assembled tool call requested by the provider.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ToolCall {
    /// The provider-assigned call identifier.
    pub call_id: ToolCallId,
    /// The tool name to dispatch.
    pub name: String,
    /// The complete JSON argument document, as received.
    pub arguments: String,
}

/// A tool call whose arguments never finished streaming.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PendingToolCall {
    /// The provider-assigned call identifier.
    pub call_id: ToolCallId,
    /// The tool name to dispatch, when it was announced.
    pub name: String,
    /// The argument fragments received before the stream ended.
    pub partial_arguments: String,
}

/// A complete assistant message.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct AssistantMessage {
    /// The visible assistant text.
    pub text: String,
    /// The hidden reasoning text, when the provider emits it.
    pub reasoning: String,
    /// Tool calls whose arguments completed.
    pub tool_calls: Vec<ToolCall>,
}

/// Everything recoverable from a stream that ended before the message completed.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
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
    use super::{PartialAssistantMessage, PendingToolCall};
    use crate::model::ids::ToolCallId;

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

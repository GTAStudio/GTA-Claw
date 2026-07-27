//! Incremental assembly of provider streams into ordered, replayable events.
//!
//! The assembler is the only place that turns a provider's chunk soup into a coherent assistant
//! message. It guarantees three things:
//!
//! * every emitted event carries a gap-free sequence number,
//! * tool calls are assembled from interleaved fragments without cross-contamination, and
//! * an interrupted stream can be turned into a [`PartialAssistantMessage`] and resumed later
//!   without renumbering already-emitted events.

use std::error::Error;
use std::fmt::{self, Display, Formatter};

use claw_application::model::ids::ToolCallId;
use claw_application::model::message::{
    AssistantMessage, PartialAssistantMessage, PendingToolCall, ToolCall,
};
use claw_application::ports::provider::ProviderChunk;
use serde::{Deserialize, Serialize};

/// The largest assembled message the assembler will accept, in bytes.
pub const MAX_ASSEMBLED_BYTES: usize = 4 * 1024 * 1024;

/// A rejected provider stream.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum StreamError {
    /// A tool call was opened twice.
    DuplicateToolCall(ToolCallId),
    /// A fragment or close arrived for a call that was never opened.
    UnknownToolCall(ToolCallId),
    /// A tool call was announced without a name.
    EmptyToolName(ToolCallId),
    /// The stream produced content after the message was closed.
    ContentAfterEnd,
    /// The message closed while a tool call was still streaming.
    UnterminatedToolCall(ToolCallId),
    /// The assembled message exceeded [`MAX_ASSEMBLED_BYTES`].
    MessageTooLarge {
        /// The configured limit.
        limit: usize,
        /// The size the message would have reached.
        actual: usize,
    },
}

impl Display for StreamError {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        match self {
            Self::DuplicateToolCall(id) => write!(formatter, "tool call {id} was opened twice"),
            Self::UnknownToolCall(id) => write!(formatter, "tool call {id} was never opened"),
            Self::EmptyToolName(id) => write!(formatter, "tool call {id} has no tool name"),
            Self::ContentAfterEnd => {
                formatter.write_str("provider sent content after the message ended")
            }
            Self::UnterminatedToolCall(id) => {
                write!(formatter, "message ended while tool call {id} was open")
            }
            Self::MessageTooLarge { limit, actual } => {
                write!(
                    formatter,
                    "assembled message is {actual} bytes, limit {limit}"
                )
            }
        }
    }
}

impl Error for StreamError {}

/// What one assembled event carries.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case", tag = "payload")]
pub enum StreamPayload {
    /// Visible assistant text was appended.
    TextDelta {
        /// The appended text.
        delta: String,
    },
    /// Hidden reasoning text was appended.
    ReasoningDelta {
        /// The appended text.
        delta: String,
    },
    /// A tool call started streaming.
    ToolCallStarted {
        /// The call identifier.
        #[serde(with = "crate::wire::tool_call_id")]
        call_id: ToolCallId,
        /// The tool being called.
        name: String,
    },
    /// A tool call finished streaming and is ready to dispatch.
    ToolCallCompleted {
        /// The assembled call.
        #[serde(with = "crate::wire::tool_call")]
        call: ToolCall,
    },
    /// The assistant message is complete.
    MessageCompleted {
        /// The assembled message.
        #[serde(with = "crate::wire::assistant_message")]
        message: AssistantMessage,
    },
}

/// One assembled event with its position in the turn's event order.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct StreamEvent {
    /// The gap-free position of this event within the turn.
    pub sequence: u64,
    /// The event content.
    pub payload: StreamPayload,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct OpenToolCall {
    call_id: ToolCallId,
    name: String,
    arguments: String,
}

/// Assembles one assistant message from a provider stream.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct StreamAssembler {
    text: String,
    reasoning: String,
    tool_calls: Vec<ToolCall>,
    open: Vec<OpenToolCall>,
    next_sequence: u64,
    limit: usize,
    ended: bool,
}

impl StreamAssembler {
    /// Creates an assembler that starts numbering at sequence zero.
    #[must_use]
    pub const fn new() -> Self {
        Self::with_limit(MAX_ASSEMBLED_BYTES)
    }

    /// Creates an assembler with a custom size limit.
    #[must_use]
    pub const fn with_limit(limit: usize) -> Self {
        Self {
            text: String::new(),
            reasoning: String::new(),
            tool_calls: Vec::new(),
            open: Vec::new(),
            next_sequence: 0,
            limit,
            ended: false,
        }
    }

    /// Rebuilds an assembler from an interrupted stream, continuing its sequence numbering.
    ///
    /// Pending tool calls are reopened, so the fragments that arrive after the interruption
    /// append to the arguments already received.
    #[must_use]
    pub fn resume(partial: PartialAssistantMessage, limit: usize) -> Self {
        Self {
            text: partial.text,
            reasoning: partial.reasoning,
            tool_calls: partial.tool_calls,
            open: partial
                .pending_tool_calls
                .into_iter()
                .map(|pending| OpenToolCall {
                    call_id: pending.call_id,
                    name: pending.name,
                    arguments: pending.partial_arguments,
                })
                .collect(),
            next_sequence: partial.next_sequence,
            limit,
            ended: false,
        }
    }

    /// Returns the sequence number the next emitted event will carry.
    #[must_use]
    pub const fn next_sequence(&self) -> u64 {
        self.next_sequence
    }

    /// Returns whether the provider closed the message.
    #[must_use]
    pub const fn is_ended(&self) -> bool {
        self.ended
    }

    /// Returns the identifiers of every tool call still streaming.
    #[must_use]
    pub fn open_tool_calls(&self) -> Vec<ToolCallId> {
        self.open.iter().map(|open| open.call_id.clone()).collect()
    }

    /// Feeds one chunk and returns the events it produced.
    ///
    /// # Errors
    ///
    /// Returns a [`StreamError`] when the provider violates the stream contract.
    pub fn push(&mut self, chunk: ProviderChunk) -> Result<Vec<StreamEvent>, StreamError> {
        if self.ended {
            return Err(StreamError::ContentAfterEnd);
        }

        match chunk {
            ProviderChunk::TextDelta { text } => {
                if text.is_empty() {
                    return Ok(Vec::new());
                }
                self.reserve(text.len())?;
                self.text.push_str(&text);
                Ok(vec![self.emit(StreamPayload::TextDelta { delta: text })])
            }
            ProviderChunk::ReasoningDelta { text } => {
                if text.is_empty() {
                    return Ok(Vec::new());
                }
                self.reserve(text.len())?;
                self.reasoning.push_str(&text);
                Ok(vec![
                    self.emit(StreamPayload::ReasoningDelta { delta: text }),
                ])
            }
            ProviderChunk::ToolCallBegin { call_id, name } => {
                if name.trim().is_empty() {
                    return Err(StreamError::EmptyToolName(call_id));
                }
                if self.is_known(&call_id) {
                    return Err(StreamError::DuplicateToolCall(call_id));
                }
                self.reserve(name.len())?;
                self.open.push(OpenToolCall {
                    call_id: call_id.clone(),
                    name: name.clone(),
                    arguments: String::new(),
                });
                Ok(vec![
                    self.emit(StreamPayload::ToolCallStarted { call_id, name }),
                ])
            }
            ProviderChunk::ToolCallArgumentsDelta { call_id, fragment } => {
                self.reserve(fragment.len())?;
                let open = self
                    .open
                    .iter_mut()
                    .find(|open| open.call_id == call_id)
                    .ok_or_else(|| StreamError::UnknownToolCall(call_id.clone()))?;
                open.arguments.push_str(&fragment);
                Ok(Vec::new())
            }
            ProviderChunk::ToolCallEnd { call_id } => {
                let index = self
                    .open
                    .iter()
                    .position(|open| open.call_id == call_id)
                    .ok_or_else(|| StreamError::UnknownToolCall(call_id.clone()))?;
                let open = self.open.remove(index);
                let call = ToolCall {
                    call_id: open.call_id,
                    name: open.name,
                    arguments: open.arguments,
                };
                self.tool_calls.push(call.clone());
                Ok(vec![self.emit(StreamPayload::ToolCallCompleted { call })])
            }
            ProviderChunk::MessageEnd => {
                if let Some(open) = self.open.first() {
                    return Err(StreamError::UnterminatedToolCall(open.call_id.clone()));
                }
                self.ended = true;
                let message = AssistantMessage {
                    text: self.text.clone(),
                    reasoning: self.reasoning.clone(),
                    tool_calls: self.tool_calls.clone(),
                };
                Ok(vec![self.emit(StreamPayload::MessageCompleted { message })])
            }
        }
    }

    /// Returns the completed message, or `None` when the stream never ended.
    #[must_use]
    pub fn finish(self) -> Option<AssistantMessage> {
        self.ended.then_some(AssistantMessage {
            text: self.text,
            reasoning: self.reasoning,
            tool_calls: self.tool_calls,
        })
    }

    /// Converts an interrupted stream into everything a later turn can recover.
    #[must_use]
    pub fn into_partial(self) -> PartialAssistantMessage {
        PartialAssistantMessage {
            text: self.text,
            reasoning: self.reasoning,
            tool_calls: self.tool_calls,
            pending_tool_calls: self
                .open
                .into_iter()
                .map(|open| PendingToolCall {
                    call_id: open.call_id,
                    name: open.name,
                    partial_arguments: open.arguments,
                })
                .collect(),
            next_sequence: self.next_sequence,
        }
    }

    fn is_known(&self, call_id: &ToolCallId) -> bool {
        self.open.iter().any(|open| &open.call_id == call_id)
            || self.tool_calls.iter().any(|call| &call.call_id == call_id)
    }

    fn assembled_len(&self) -> usize {
        self.text.len()
            + self.reasoning.len()
            + self
                .tool_calls
                .iter()
                .map(|call| call.name.len() + call.arguments.len())
                .sum::<usize>()
            + self
                .open
                .iter()
                .map(|open| open.name.len() + open.arguments.len())
                .sum::<usize>()
    }

    fn reserve(&self, additional: usize) -> Result<(), StreamError> {
        let actual = self.assembled_len().saturating_add(additional);
        if actual > self.limit {
            return Err(StreamError::MessageTooLarge {
                limit: self.limit,
                actual,
            });
        }
        Ok(())
    }

    const fn emit(&mut self, payload: StreamPayload) -> StreamEvent {
        let sequence = self.next_sequence;
        self.next_sequence = self.next_sequence.saturating_add(1);
        StreamEvent { sequence, payload }
    }
}

impl Default for StreamAssembler {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use claw_application::model::ids::ToolCallId;
    use claw_application::model::message::{AssistantMessage, PendingToolCall, ToolCall};
    use claw_application::ports::provider::ProviderChunk;

    use super::{StreamAssembler, StreamError, StreamEvent, StreamPayload};

    fn call_id(value: &str) -> ToolCallId {
        ToolCallId::new(value).expect("valid tool call id")
    }

    fn push_all(assembler: &mut StreamAssembler, chunks: Vec<ProviderChunk>) -> Vec<StreamEvent> {
        let mut events = Vec::new();
        for chunk in chunks {
            events.extend(
                assembler
                    .push(chunk)
                    .unwrap_or_else(|error| panic!("chunk must be accepted: {error}")),
            );
        }
        events
    }

    #[test]
    fn text_deltas_are_emitted_in_order_with_gap_free_sequences() {
        let mut assembler = StreamAssembler::new();
        let events = push_all(
            &mut assembler,
            vec![
                ProviderChunk::TextDelta {
                    text: "Hel".to_owned(),
                },
                ProviderChunk::TextDelta {
                    text: "lo, ".to_owned(),
                },
                ProviderChunk::TextDelta {
                    text: "world".to_owned(),
                },
                ProviderChunk::MessageEnd,
            ],
        );

        assert_eq!(
            events,
            vec![
                StreamEvent {
                    sequence: 0,
                    payload: StreamPayload::TextDelta {
                        delta: "Hel".to_owned()
                    },
                },
                StreamEvent {
                    sequence: 1,
                    payload: StreamPayload::TextDelta {
                        delta: "lo, ".to_owned()
                    },
                },
                StreamEvent {
                    sequence: 2,
                    payload: StreamPayload::TextDelta {
                        delta: "world".to_owned()
                    },
                },
                StreamEvent {
                    sequence: 3,
                    payload: StreamPayload::MessageCompleted {
                        message: AssistantMessage {
                            text: "Hello, world".to_owned(),
                            reasoning: String::new(),
                            tool_calls: Vec::new(),
                        },
                    },
                },
            ]
        );
        assert_eq!(assembler.next_sequence(), 4);
    }

    #[test]
    fn empty_deltas_produce_no_events_and_do_not_consume_sequences() {
        let mut assembler = StreamAssembler::new();

        assert_eq!(
            assembler
                .push(ProviderChunk::TextDelta {
                    text: String::new()
                })
                .expect("empty deltas are accepted"),
            Vec::new()
        );
        assert_eq!(
            assembler
                .push(ProviderChunk::ReasoningDelta {
                    text: String::new()
                })
                .expect("empty deltas are accepted"),
            Vec::new()
        );
        assert_eq!(assembler.next_sequence(), 0);
    }

    #[test]
    fn interleaved_tool_call_fragments_never_cross_contaminate() {
        let mut assembler = StreamAssembler::new();
        let events = push_all(
            &mut assembler,
            vec![
                ProviderChunk::ToolCallBegin {
                    call_id: call_id("a"),
                    name: "read_file".to_owned(),
                },
                ProviderChunk::ToolCallBegin {
                    call_id: call_id("b"),
                    name: "write_file".to_owned(),
                },
                ProviderChunk::ToolCallArgumentsDelta {
                    call_id: call_id("a"),
                    fragment: "{\"path\":".to_owned(),
                },
                ProviderChunk::ToolCallArgumentsDelta {
                    call_id: call_id("b"),
                    fragment: "{\"body\":".to_owned(),
                },
                ProviderChunk::ToolCallArgumentsDelta {
                    call_id: call_id("a"),
                    fragment: "\"a.txt\"}".to_owned(),
                },
                ProviderChunk::ToolCallArgumentsDelta {
                    call_id: call_id("b"),
                    fragment: "\"hi\"}".to_owned(),
                },
                ProviderChunk::ToolCallEnd {
                    call_id: call_id("b"),
                },
                ProviderChunk::ToolCallEnd {
                    call_id: call_id("a"),
                },
                ProviderChunk::MessageEnd,
            ],
        );

        let call_b = ToolCall {
            call_id: call_id("b"),
            name: "write_file".to_owned(),
            arguments: "{\"body\":\"hi\"}".to_owned(),
        };
        let call_a = ToolCall {
            call_id: call_id("a"),
            name: "read_file".to_owned(),
            arguments: "{\"path\":\"a.txt\"}".to_owned(),
        };

        assert_eq!(
            events,
            vec![
                StreamEvent {
                    sequence: 0,
                    payload: StreamPayload::ToolCallStarted {
                        call_id: call_id("a"),
                        name: "read_file".to_owned(),
                    },
                },
                StreamEvent {
                    sequence: 1,
                    payload: StreamPayload::ToolCallStarted {
                        call_id: call_id("b"),
                        name: "write_file".to_owned(),
                    },
                },
                StreamEvent {
                    sequence: 2,
                    payload: StreamPayload::ToolCallCompleted {
                        call: call_b.clone()
                    },
                },
                StreamEvent {
                    sequence: 3,
                    payload: StreamPayload::ToolCallCompleted {
                        call: call_a.clone()
                    },
                },
                StreamEvent {
                    sequence: 4,
                    payload: StreamPayload::MessageCompleted {
                        message: AssistantMessage {
                            text: String::new(),
                            reasoning: String::new(),
                            tool_calls: vec![call_b, call_a],
                        },
                    },
                },
            ]
        );
    }

    #[test]
    fn reopening_a_completed_call_is_rejected() {
        let mut assembler = StreamAssembler::new();
        push_all(
            &mut assembler,
            vec![
                ProviderChunk::ToolCallBegin {
                    call_id: call_id("a"),
                    name: "read_file".to_owned(),
                },
                ProviderChunk::ToolCallEnd {
                    call_id: call_id("a"),
                },
            ],
        );

        assert_eq!(
            assembler.push(ProviderChunk::ToolCallBegin {
                call_id: call_id("a"),
                name: "read_file".to_owned(),
            }),
            Err(StreamError::DuplicateToolCall(call_id("a")))
        );
    }

    #[test]
    fn fragments_and_closes_for_unknown_calls_are_rejected() {
        let mut assembler = StreamAssembler::new();

        assert_eq!(
            assembler.push(ProviderChunk::ToolCallArgumentsDelta {
                call_id: call_id("ghost"),
                fragment: "{}".to_owned(),
            }),
            Err(StreamError::UnknownToolCall(call_id("ghost")))
        );
        assert_eq!(
            assembler.push(ProviderChunk::ToolCallEnd {
                call_id: call_id("ghost"),
            }),
            Err(StreamError::UnknownToolCall(call_id("ghost")))
        );
    }

    #[test]
    fn unnamed_tool_calls_are_rejected() {
        let mut assembler = StreamAssembler::new();

        assert_eq!(
            assembler.push(ProviderChunk::ToolCallBegin {
                call_id: call_id("a"),
                name: "   ".to_owned(),
            }),
            Err(StreamError::EmptyToolName(call_id("a")))
        );
    }

    #[test]
    fn ending_with_an_open_tool_call_is_rejected() {
        let mut assembler = StreamAssembler::new();
        push_all(
            &mut assembler,
            vec![ProviderChunk::ToolCallBegin {
                call_id: call_id("a"),
                name: "read_file".to_owned(),
            }],
        );

        assert_eq!(
            assembler.push(ProviderChunk::MessageEnd),
            Err(StreamError::UnterminatedToolCall(call_id("a")))
        );
        assert!(!assembler.is_ended());
    }

    #[test]
    fn content_after_the_message_ends_is_rejected() {
        let mut assembler = StreamAssembler::new();
        push_all(&mut assembler, vec![ProviderChunk::MessageEnd]);

        assert!(assembler.is_ended());
        assert_eq!(
            assembler.push(ProviderChunk::TextDelta {
                text: "late".to_owned()
            }),
            Err(StreamError::ContentAfterEnd)
        );
    }

    #[test]
    fn oversized_messages_are_rejected_before_they_are_stored() {
        let mut assembler = StreamAssembler::with_limit(8);
        push_all(
            &mut assembler,
            vec![ProviderChunk::TextDelta {
                text: "12345".to_owned(),
            }],
        );

        assert_eq!(
            assembler.push(ProviderChunk::TextDelta {
                text: "6789".to_owned()
            }),
            Err(StreamError::MessageTooLarge {
                limit: 8,
                actual: 9
            })
        );
        assert_eq!(
            assembler.into_partial().text,
            "12345",
            "a rejected chunk must not be stored"
        );
    }

    #[test]
    fn an_interrupted_stream_recovers_text_completed_calls_and_pending_calls() {
        let mut assembler = StreamAssembler::new();
        push_all(
            &mut assembler,
            vec![
                ProviderChunk::TextDelta {
                    text: "working".to_owned(),
                },
                ProviderChunk::ReasoningDelta {
                    text: "hmm".to_owned(),
                },
                ProviderChunk::ToolCallBegin {
                    call_id: call_id("done"),
                    name: "read_file".to_owned(),
                },
                ProviderChunk::ToolCallArgumentsDelta {
                    call_id: call_id("done"),
                    fragment: "{}".to_owned(),
                },
                ProviderChunk::ToolCallEnd {
                    call_id: call_id("done"),
                },
                ProviderChunk::ToolCallBegin {
                    call_id: call_id("open"),
                    name: "write_file".to_owned(),
                },
                ProviderChunk::ToolCallArgumentsDelta {
                    call_id: call_id("open"),
                    fragment: "{\"pa".to_owned(),
                },
            ],
        );

        assert_eq!(assembler.open_tool_calls(), vec![call_id("open")]);
        let partial = assembler.into_partial();

        assert_eq!(partial.text, "working");
        assert_eq!(partial.reasoning, "hmm");
        assert_eq!(
            partial.tool_calls,
            vec![ToolCall {
                call_id: call_id("done"),
                name: "read_file".to_owned(),
                arguments: "{}".to_owned(),
            }]
        );
        assert_eq!(
            partial.pending_tool_calls,
            vec![PendingToolCall {
                call_id: call_id("open"),
                name: "write_file".to_owned(),
                partial_arguments: "{\"pa".to_owned(),
            }]
        );
        assert_eq!(partial.next_sequence, 5);
    }

    #[test]
    fn a_resumed_assembler_continues_sequences_and_completes_pending_calls() {
        let mut first = StreamAssembler::new();
        push_all(
            &mut first,
            vec![
                ProviderChunk::TextDelta {
                    text: "part one ".to_owned(),
                },
                ProviderChunk::ToolCallBegin {
                    call_id: call_id("open"),
                    name: "write_file".to_owned(),
                },
                ProviderChunk::ToolCallArgumentsDelta {
                    call_id: call_id("open"),
                    fragment: "{\"path\":".to_owned(),
                },
            ],
        );
        let partial = first.into_partial();

        let mut second = StreamAssembler::resume(partial, super::MAX_ASSEMBLED_BYTES);
        let events = push_all(
            &mut second,
            vec![
                ProviderChunk::ToolCallArgumentsDelta {
                    call_id: call_id("open"),
                    fragment: "\"b.txt\"}".to_owned(),
                },
                ProviderChunk::ToolCallEnd {
                    call_id: call_id("open"),
                },
                ProviderChunk::TextDelta {
                    text: "part two".to_owned(),
                },
                ProviderChunk::MessageEnd,
            ],
        );

        let completed = ToolCall {
            call_id: call_id("open"),
            name: "write_file".to_owned(),
            arguments: "{\"path\":\"b.txt\"}".to_owned(),
        };

        assert_eq!(
            events,
            vec![
                StreamEvent {
                    sequence: 2,
                    payload: StreamPayload::ToolCallCompleted {
                        call: completed.clone()
                    },
                },
                StreamEvent {
                    sequence: 3,
                    payload: StreamPayload::TextDelta {
                        delta: "part two".to_owned()
                    },
                },
                StreamEvent {
                    sequence: 4,
                    payload: StreamPayload::MessageCompleted {
                        message: AssistantMessage {
                            text: "part one part two".to_owned(),
                            reasoning: String::new(),
                            tool_calls: vec![completed.clone()],
                        },
                    },
                },
            ]
        );
        assert_eq!(
            second.finish(),
            Some(AssistantMessage {
                text: "part one part two".to_owned(),
                reasoning: String::new(),
                tool_calls: vec![completed],
            })
        );
    }

    #[test]
    fn finish_returns_nothing_for_an_unfinished_stream() {
        let mut assembler = StreamAssembler::new();
        push_all(
            &mut assembler,
            vec![ProviderChunk::TextDelta {
                text: "hi".to_owned(),
            }],
        );

        assert_eq!(assembler.finish(), None);
    }

    #[test]
    fn stream_errors_render_their_cause() {
        assert_eq!(
            StreamError::DuplicateToolCall(call_id("a")).to_string(),
            "tool call a was opened twice"
        );
        assert_eq!(
            StreamError::UnknownToolCall(call_id("a")).to_string(),
            "tool call a was never opened"
        );
        assert_eq!(
            StreamError::EmptyToolName(call_id("a")).to_string(),
            "tool call a has no tool name"
        );
        assert_eq!(
            StreamError::ContentAfterEnd.to_string(),
            "provider sent content after the message ended"
        );
        assert_eq!(
            StreamError::UnterminatedToolCall(call_id("a")).to_string(),
            "message ended while tool call a was open"
        );
        assert_eq!(
            StreamError::MessageTooLarge {
                limit: 4,
                actual: 9
            }
            .to_string(),
            "assembled message is 9 bytes, limit 4"
        );
    }

    #[test]
    fn events_round_trip_through_json() {
        let event = StreamEvent {
            sequence: 7,
            payload: StreamPayload::ToolCallStarted {
                call_id: call_id("a"),
                name: "read_file".to_owned(),
            },
        };
        let encoded = serde_json::to_string(&event).expect("event serialises");

        assert_eq!(
            encoded,
            "{\"sequence\":7,\"payload\":{\"payload\":\"tool_call_started\",\"call_id\":\"a\",\"name\":\"read_file\"}}"
        );
        assert_eq!(
            serde_json::from_str::<StreamEvent>(&encoded).expect("event deserialises"),
            event
        );
    }
}

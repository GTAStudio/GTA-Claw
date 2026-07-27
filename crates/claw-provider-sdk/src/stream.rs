//! Streaming completion events, incremental tool-call assembly and usage accounting.

use std::fmt::{self, Debug};
use std::pin::Pin;
use std::task::{Context, Poll};

use futures_core::Stream;

use crate::cancel::CancelToken;
use crate::error::{ErrorKind, Operation, ProviderError};
use crate::model::{
    AssistantMessage, ContentPart, FinishReason, ModelError, ToolArguments, ToolCall, Usage,
};

/// One incremental event produced by a streaming completion.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum StreamEvent {
    /// The provider accepted the request and named the serving model.
    Started {
        /// Provider-assigned response identifier.
        id: String,
        /// Model that is actually serving the request.
        model: String,
    },
    /// A fragment of visible assistant text.
    TextDelta(String),
    /// A fragment of the model's reasoning summary.
    ReasoningDelta(String),
    /// A new tool call started at `index`.
    ToolCallStarted {
        /// Position of the call in the assistant turn.
        index: usize,
        /// Provider-assigned call identifier.
        id: String,
        /// Tool name.
        name: String,
    },
    /// A fragment of the argument document of the call at `index`.
    ToolCallArgumentsDelta {
        /// Position of the call in the assistant turn.
        index: usize,
        /// Raw argument fragment, which is not independently valid JSON.
        delta: String,
    },
    /// The call at `index` is complete and its arguments parsed.
    ToolCallCompleted {
        /// Position of the call in the assistant turn.
        index: usize,
        /// The assembled call.
        call: ToolCall,
    },
    /// Updated token accounting.
    UsageUpdate(Usage),
    /// The stream finished.
    Completed {
        /// Why generation stopped.
        finish_reason: FinishReason,
        /// Final token accounting.
        usage: Usage,
    },
}

/// Largest number of tool calls one assistant turn may accumulate.
///
/// The index of a streamed tool call comes straight off the wire, so without a
/// ceiling a single malformed or hostile chunk (`"index": 4000000000`) would
/// make the assembler reserve one slot per index. Real providers cap parallel
/// tool calls in the low hundreds.
pub const MAX_TOOL_CALLS: usize = 1_024;

/// Largest reassembled argument document for one tool call, in bytes.
///
/// Argument fragments accumulate across events, so the per-event limit of the
/// stream decoder does not bound them; this does.
pub const MAX_TOOL_ARGUMENT_BYTES: usize = 1_048_576;

/// Largest aggregate argument payload retained across one streamed assistant turn.
///
/// A per-call bound alone still allowed [`MAX_TOOL_CALLS`] calls to retain one
/// mebibyte each. This aggregate ceiling keeps the whole assembler within a
/// predictable memory budget.
pub const MAX_TOTAL_TOOL_ARGUMENT_BYTES: usize = 4 * MAX_TOOL_ARGUMENT_BYTES;

/// Largest reassembled identifier or name for one tool call, in bytes.
///
/// Both arrive as fragments and both are identifiers, not payloads.
pub const MAX_TOOL_NAME_BYTES: usize = 512;

/// Incrementally assembles tool calls that arrive as indexed fragments.
///
/// Providers emit an identifier and name once and then stream the argument
/// document in arbitrary fragments. The assembler keeps one buffer per index and
/// validates the JSON framing only when the call is completed.
///
/// # Bounded memory
///
/// Everything the assembler stores comes from the wire, so every buffer is
/// capped: at most [`MAX_TOOL_CALLS`] calls, [`MAX_TOOL_NAME_BYTES`] of
/// identifier and of name, [`MAX_TOOL_ARGUMENT_BYTES`] of arguments per call,
/// and [`MAX_TOTAL_TOOL_ARGUMENT_BYTES`] across the turn. Fragments past a cap
/// are rejected and make [`ToolCallAssembler::complete`] return a typed size
/// error instead of allowing a truncated document to look valid.
#[derive(Debug, Default)]
pub struct ToolCallAssembler {
    partials: Vec<PartialToolCall>,
    total_argument_bytes: usize,
}

#[derive(Clone, Debug, Default)]
struct PartialToolCall {
    id: String,
    name: String,
    arguments: String,
    announced: bool,
    completed: bool,
    overflowed: bool,
}

impl ToolCallAssembler {
    /// Creates an empty assembler.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Returns the number of tool calls seen so far.
    #[must_use]
    pub const fn len(&self) -> usize {
        self.partials.len()
    }

    /// Returns `true` when no tool call has been seen.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.partials.is_empty()
    }

    /// Applies one fragment and returns the events it produced.
    ///
    /// A [`StreamEvent::ToolCallStarted`] is emitted exactly once per index, as
    /// soon as both an identifier and a name are known.
    ///
    /// An `index` at or above [`MAX_TOOL_CALLS`] is ignored and yields no
    /// events, as is any fragment that would push a buffer past
    /// [`MAX_TOOL_NAME_BYTES`], [`MAX_TOOL_ARGUMENT_BYTES`], or
    /// [`MAX_TOTAL_TOOL_ARGUMENT_BYTES`].
    pub fn accept(
        &mut self,
        index: usize,
        id: Option<&str>,
        name: Option<&str>,
        arguments: Option<&str>,
    ) -> Vec<StreamEvent> {
        if index >= MAX_TOOL_CALLS {
            return Vec::new();
        }
        if self.partials.len() <= index {
            self.partials.resize(index + 1, PartialToolCall::default());
        }
        let mut events = Vec::new();
        {
            let partial = &mut self.partials[index];
            if let Some(id) = id
                && !id.is_empty()
                && id.len() <= MAX_TOOL_NAME_BYTES
            {
                partial.id.clear();
                partial.id.push_str(id);
            }
            if let Some(name) = name
                && !name.is_empty()
                && partial.name.len() + name.len() <= MAX_TOOL_NAME_BYTES
            {
                partial.name.push_str(name);
            }
            if !partial.announced && !partial.id.is_empty() && !partial.name.is_empty() {
                partial.announced = true;
                events.push(StreamEvent::ToolCallStarted {
                    index,
                    id: partial.id.clone(),
                    name: partial.name.clone(),
                });
            }
            if let Some(fragment) = arguments
                && !fragment.is_empty()
            {
                let call_size = partial.arguments.len().checked_add(fragment.len());
                let total_size = self.total_argument_bytes.checked_add(fragment.len());
                if call_size.is_some_and(|size| size <= MAX_TOOL_ARGUMENT_BYTES)
                    && total_size.is_some_and(|size| size <= MAX_TOTAL_TOOL_ARGUMENT_BYTES)
                {
                    partial.arguments.push_str(fragment);
                    self.total_argument_bytes += fragment.len();
                    events.push(StreamEvent::ToolCallArgumentsDelta {
                        index,
                        delta: fragment.to_owned(),
                    });
                } else {
                    partial.overflowed = true;
                }
            }
        }
        events
    }

    /// Finalizes the call at `index`.
    ///
    /// # Errors
    ///
    /// Returns [`ModelError::InvalidIdentifier`] when `index` was never seen
    /// (including an index the size caps rejected), when the call never
    /// received a name, or when it was already completed, and
    /// [`ModelError::ToolArgumentsTooLarge`] when a fragment crossed a size
    /// ceiling, and [`ModelError::ToolArgumentsNotAnObject`] when the accepted
    /// fragments do not parse as a single JSON object.
    pub fn complete(&mut self, index: usize) -> Result<StreamEvent, ModelError> {
        let partial = self
            .partials
            .get_mut(index)
            .ok_or(ModelError::InvalidIdentifier { field: "tool_call" })?;
        if partial.name.is_empty() || partial.completed {
            return Err(ModelError::InvalidIdentifier { field: "tool_call" });
        }
        if partial.overflowed {
            return Err(ModelError::ToolArgumentsTooLarge {
                limit: MAX_TOTAL_TOOL_ARGUMENT_BYTES,
            });
        }
        partial.completed = true;
        let call = ToolCall {
            id: partial.id.clone(),
            name: partial.name.clone(),
            arguments: ToolArguments::new(partial.arguments.clone())?,
        };
        Ok(StreamEvent::ToolCallCompleted { index, call })
    }

    /// Finalizes every call that has not been completed yet, in index order.
    ///
    /// # Errors
    ///
    /// Returns [`ModelError::InvalidIdentifier`] for the first call that never
    /// received a name, [`ModelError::ToolArgumentsTooLarge`] when a size limit
    /// was crossed, and [`ModelError::ToolArgumentsNotAnObject`] for the first
    /// call whose accepted fragments are not a single JSON object.
    pub fn complete_all(&mut self) -> Result<Vec<ToolCall>, ModelError> {
        let mut calls = Vec::with_capacity(self.partials.len());
        for partial in &mut self.partials {
            if partial.name.is_empty() {
                return Err(ModelError::InvalidIdentifier { field: "tool_call" });
            }
            if partial.overflowed {
                return Err(ModelError::ToolArgumentsTooLarge {
                    limit: MAX_TOTAL_TOOL_ARGUMENT_BYTES,
                });
            }
            partial.completed = true;
            calls.push(ToolCall {
                id: partial.id.clone(),
                name: partial.name.clone(),
                arguments: ToolArguments::new(partial.arguments.clone())?,
            });
        }
        Ok(calls)
    }
}

/// Accumulates the assistant turn and usage while a stream is consumed.
#[derive(Debug, Default)]
pub struct StreamAccumulator {
    text: String,
    reasoning: String,
    tool_calls: Vec<ToolCall>,
    usage: Usage,
    finish_reason: Option<FinishReason>,
}

impl StreamAccumulator {
    /// Creates an empty accumulator.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Folds one event into the accumulated state.
    pub fn accept(&mut self, event: &StreamEvent) {
        match event {
            StreamEvent::TextDelta(delta) => self.text.push_str(delta),
            StreamEvent::ReasoningDelta(delta) => self.reasoning.push_str(delta),
            StreamEvent::ToolCallCompleted { call, .. } => self.tool_calls.push(call.clone()),
            StreamEvent::UsageUpdate(usage) => self.usage = *usage,
            StreamEvent::Completed {
                finish_reason,
                usage,
            } => {
                self.finish_reason = Some(finish_reason.clone());
                if usage.total_tokens() > 0 {
                    self.usage = *usage;
                }
            }
            StreamEvent::Started { .. }
            | StreamEvent::ToolCallStarted { .. }
            | StreamEvent::ToolCallArgumentsDelta { .. } => {}
        }
    }

    /// Returns the token accounting seen so far.
    #[must_use]
    pub const fn usage(&self) -> Usage {
        self.usage
    }

    /// Returns the finish reason, when the stream reported one.
    ///
    /// Stays `None` when the stream ended before a
    /// [`StreamEvent::Completed`] arrived — a truncated turn is reported as an
    /// absent finish reason rather than an invented one.
    #[must_use]
    pub const fn finish_reason(&self) -> Option<&FinishReason> {
        self.finish_reason.as_ref()
    }

    /// Builds the assistant turn accumulated so far.
    #[must_use]
    pub fn message(&self) -> AssistantMessage {
        AssistantMessage {
            content: if self.text.is_empty() {
                Vec::new()
            } else {
                vec![ContentPart::Text(self.text.clone())]
            },
            reasoning: if self.reasoning.is_empty() {
                None
            } else {
                Some(self.reasoning.clone())
            },
            tool_calls: self.tool_calls.clone(),
        }
    }
}

/// A cancellable stream of [`StreamEvent`] values.
///
/// Dropping the stream drops `inner`, and `inner` owns the HTTP response body,
/// so the drop closes the connection. The drop also cancels the token, which
/// releases anything else still watching it (a retry sleep, a body reader that
/// outlives this handle). Calling [`CompletionStream::cancel`] signals the same
/// token without dropping the body: the next poll then returns
/// [`ErrorKind::Cancelled`] and ends the stream, and the body is released when
/// the handle itself is dropped.
pub struct CompletionStream {
    provider: String,
    inner: Pin<Box<dyn Stream<Item = Result<StreamEvent, ProviderError>> + Send>>,
    cancel: CancelToken,
    finished: bool,
}

impl CompletionStream {
    /// Wraps a provider-specific event stream.
    #[must_use]
    pub fn new(
        provider: impl Into<String>,
        cancel: CancelToken,
        inner: Pin<Box<dyn Stream<Item = Result<StreamEvent, ProviderError>> + Send>>,
    ) -> Self {
        Self {
            provider: provider.into(),
            inner,
            cancel,
            finished: false,
        }
    }

    /// Requests cancellation of the underlying HTTP exchange.
    pub fn cancel(&self) {
        self.cancel.cancel();
    }

    /// Returns the cancellation token driving this stream.
    #[must_use]
    pub fn cancel_token(&self) -> CancelToken {
        self.cancel.clone()
    }

    /// Returns the provider that produced this stream.
    #[must_use]
    pub fn provider(&self) -> &str {
        &self.provider
    }
}

impl Debug for CompletionStream {
    /// Renders the observable state.
    ///
    /// `inner` is a boxed provider-specific stream with no useful rendering, so
    /// it is reported as the non-exhaustive marker rather than named.
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("CompletionStream")
            .field("provider", &self.provider)
            .field("cancelled", &self.cancel.is_cancelled())
            .field("finished", &self.finished)
            .finish_non_exhaustive()
    }
}

impl Stream for CompletionStream {
    type Item = Result<StreamEvent, ProviderError>;

    fn poll_next(self: Pin<&mut Self>, context: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        let this = self.get_mut();
        if this.finished {
            return Poll::Ready(None);
        }
        if this.cancel.is_cancelled() {
            this.finished = true;
            return Poll::Ready(Some(Err(ProviderError::new(
                ErrorKind::Cancelled,
                &this.provider,
                Operation::StreamCompletion,
                "stream cancelled by caller",
            ))));
        }
        match this.inner.as_mut().poll_next(context) {
            Poll::Ready(None) => {
                this.finished = true;
                Poll::Ready(None)
            }
            Poll::Ready(Some(Err(error))) => {
                this.finished = true;
                Poll::Ready(Some(Err(error)))
            }
            other => other,
        }
    }
}

impl Drop for CompletionStream {
    fn drop(&mut self) {
        self.cancel.cancel();
    }
}

#[cfg(test)]
mod tests {
    use futures_util::StreamExt;

    use super::*;

    #[test]
    fn assembler_announces_a_call_once_both_identifier_and_name_are_known() {
        let mut assembler = ToolCallAssembler::new();
        assert!(assembler.is_empty());

        assert!(assembler.accept(0, Some("call_1"), None, None).is_empty());
        assert_eq!(
            assembler.accept(0, None, Some("read_file"), None),
            vec![StreamEvent::ToolCallStarted {
                index: 0,
                id: "call_1".to_owned(),
                name: "read_file".to_owned(),
            }]
        );
        assert!(assembler.accept(0, None, Some(""), None).is_empty());
        assert_eq!(assembler.len(), 1);
    }

    #[test]
    fn assembler_joins_argument_fragments_and_validates_only_at_completion() {
        let mut assembler = ToolCallAssembler::new();
        assembler.accept(0, Some("call_1"), Some("read_file"), None);
        let fragments = ["{\"pa", "th\":\"/e", "tc/hosts\",\"lines\":", "12}"];
        let mut deltas = Vec::new();
        for fragment in fragments {
            for event in assembler.accept(0, None, None, Some(fragment)) {
                if let StreamEvent::ToolCallArgumentsDelta { index, delta } = event {
                    assert_eq!(index, 0);
                    deltas.push(delta);
                }
            }
        }
        assert_eq!(deltas, fragments.map(str::to_owned).to_vec());

        let completed = assembler.complete(0).expect("valid json object");
        assert_eq!(
            completed,
            StreamEvent::ToolCallCompleted {
                index: 0,
                call: ToolCall {
                    id: "call_1".to_owned(),
                    name: "read_file".to_owned(),
                    arguments: ToolArguments::new("{\"path\":\"/etc/hosts\",\"lines\":12}")
                        .expect("valid"),
                },
            }
        );
    }

    #[test]
    fn assembler_supports_interleaved_parallel_calls() {
        let mut assembler = ToolCallAssembler::new();
        assembler.accept(0, Some("a"), Some("alpha"), Some("{\"x\":"));
        assembler.accept(1, Some("b"), Some("beta"), Some("{\"y\":"));
        assembler.accept(0, None, None, Some("1}"));
        assembler.accept(1, None, None, Some("2}"));

        let calls = assembler.complete_all().expect("both calls assemble");
        assert_eq!(calls.len(), 2);
        assert_eq!(calls[0].id, "a");
        assert_eq!(calls[0].name, "alpha");
        assert_eq!(calls[0].arguments.as_str(), "{\"x\":1}");
        assert_eq!(calls[1].id, "b");
        assert_eq!(calls[1].name, "beta");
        assert_eq!(calls[1].arguments.as_str(), "{\"y\":2}");
    }

    #[test]
    fn assembler_rejects_truncated_argument_documents() {
        let mut assembler = ToolCallAssembler::new();
        assembler.accept(0, Some("a"), Some("alpha"), Some("{\"x\":"));
        assert_eq!(
            assembler.complete(0),
            Err(ModelError::ToolArgumentsNotAnObject)
        );
    }

    #[test]
    fn assembler_rejects_unknown_indexes_and_nameless_calls() {
        let mut assembler = ToolCallAssembler::new();
        assert_eq!(
            assembler.complete(3),
            Err(ModelError::InvalidIdentifier { field: "tool_call" })
        );
        assembler.accept(0, Some("a"), None, Some("{}"));
        assert_eq!(
            assembler.complete(0),
            Err(ModelError::InvalidIdentifier { field: "tool_call" })
        );
    }

    #[test]
    fn a_wire_supplied_index_beyond_the_ceiling_allocates_nothing() {
        let mut assembler = ToolCallAssembler::new();
        // The index comes straight off the wire; `usize::MAX` used to overflow
        // `index + 1` and ask `Vec::resize` for one slot per index.
        assert!(
            assembler
                .accept(usize::MAX, Some("a"), Some("alpha"), Some("{}"))
                .is_empty()
        );
        assert!(
            assembler
                .accept(MAX_TOOL_CALLS, Some("a"), Some("alpha"), Some("{}"))
                .is_empty()
        );
        assert!(assembler.is_empty());
        assert_eq!(
            assembler.complete(MAX_TOOL_CALLS),
            Err(ModelError::InvalidIdentifier { field: "tool_call" })
        );

        assert_eq!(
            assembler
                .accept(MAX_TOOL_CALLS - 1, Some("a"), Some("alpha"), None)
                .len(),
            1
        );
        assert_eq!(assembler.len(), MAX_TOOL_CALLS);
    }

    #[test]
    fn argument_and_name_fragments_stop_at_their_ceilings() {
        let mut assembler = ToolCallAssembler::new();
        assembler.accept(0, Some("call_1"), Some("alpha"), Some("{\"a\":\""));

        let oversized = "b".repeat(MAX_TOOL_ARGUMENT_BYTES);
        assert!(
            assembler.accept(0, None, None, Some(&oversized)).is_empty(),
            "a fragment past the ceiling produces no delta event"
        );
        assert_eq!(
            assembler.complete(0),
            Err(ModelError::ToolArgumentsTooLarge {
                limit: MAX_TOTAL_TOOL_ARGUMENT_BYTES
            })
        );

        let mut assembler = ToolCallAssembler::new();
        let long_name = "n".repeat(MAX_TOOL_NAME_BYTES + 1);
        assembler.accept(0, Some("call_1"), Some(&long_name), None);
        assert!(
            assembler
                .complete(0)
                .is_err_and(|error| error == ModelError::InvalidIdentifier { field: "tool_call" }),
            "an over-long name is dropped, leaving the call nameless"
        );
    }

    #[test]
    fn aggregate_tool_arguments_are_bounded_across_calls() {
        let mut assembler = ToolCallAssembler::new();
        let full = format!(
            "{{\"value\":\"{}\"}}",
            "a".repeat(MAX_TOOL_ARGUMENT_BYTES - 12)
        );
        assert_eq!(full.len(), MAX_TOOL_ARGUMENT_BYTES);

        for index in 0..4 {
            assembler.accept(
                index,
                Some(&format!("call-{index}")),
                Some("tool"),
                Some(&full),
            );
        }
        assembler.accept(4, Some("call-4"), Some("tool"), Some("{}"));

        assert_eq!(
            assembler.complete(4),
            Err(ModelError::ToolArgumentsTooLarge {
                limit: MAX_TOTAL_TOOL_ARGUMENT_BYTES
            })
        );
        assert!(
            assembler.complete(0).is_ok(),
            "calls accepted before the aggregate ceiling remain usable"
        );
    }

    #[test]
    fn assembler_normalizes_zero_argument_calls() {
        let mut assembler = ToolCallAssembler::new();
        assembler.accept(0, Some("a"), Some("ping"), None);
        let calls = assembler.complete_all().expect("assembles");
        assert_eq!(calls[0].arguments.as_str(), "{}");
    }

    #[test]
    fn accumulator_folds_text_reasoning_tool_calls_and_usage() {
        let mut accumulator = StreamAccumulator::new();
        let usage = Usage {
            input_tokens: 10,
            output_tokens: 4,
            cached_input_tokens: 2,
            reasoning_tokens: 1,
        };
        let call = ToolCall {
            id: "call_1".to_owned(),
            name: "ping".to_owned(),
            arguments: ToolArguments::new("{}").expect("valid"),
        };
        for event in [
            StreamEvent::Started {
                id: "resp_1".to_owned(),
                model: "gpt-5.6".to_owned(),
            },
            StreamEvent::ReasoningDelta("think".to_owned()),
            StreamEvent::TextDelta("Hello, ".to_owned()),
            StreamEvent::TextDelta("world".to_owned()),
            StreamEvent::ToolCallStarted {
                index: 0,
                id: "call_1".to_owned(),
                name: "ping".to_owned(),
            },
            StreamEvent::ToolCallCompleted {
                index: 0,
                call: call.clone(),
            },
            StreamEvent::UsageUpdate(usage),
            StreamEvent::Completed {
                finish_reason: FinishReason::ToolCalls,
                usage,
            },
        ] {
            accumulator.accept(&event);
        }

        let message = accumulator.message();
        assert_eq!(message.text(), "Hello, world");
        assert_eq!(message.reasoning.as_deref(), Some("think"));
        assert_eq!(message.tool_calls, vec![call]);
        assert_eq!(accumulator.usage(), usage);
        assert_eq!(accumulator.finish_reason(), Some(&FinishReason::ToolCalls));
    }

    #[test]
    fn accumulator_keeps_the_last_usage_update_when_the_final_event_has_none() {
        let mut accumulator = StreamAccumulator::new();
        let usage = Usage {
            input_tokens: 7,
            output_tokens: 3,
            cached_input_tokens: 0,
            reasoning_tokens: 0,
        };
        accumulator.accept(&StreamEvent::UsageUpdate(usage));
        accumulator.accept(&StreamEvent::Completed {
            finish_reason: FinishReason::Stop,
            usage: Usage::default(),
        });
        assert_eq!(accumulator.usage(), usage);
        assert_eq!(accumulator.usage().total_tokens(), 10);
    }

    fn event_stream(
        events: Vec<Result<StreamEvent, ProviderError>>,
    ) -> Pin<Box<dyn Stream<Item = Result<StreamEvent, ProviderError>> + Send>> {
        Box::pin(futures_util::stream::iter(events))
    }

    #[tokio::test]
    async fn completion_stream_forwards_events_until_exhaustion() {
        let mut stream = CompletionStream::new(
            "openai",
            CancelToken::new(),
            event_stream(vec![
                Ok(StreamEvent::TextDelta("a".to_owned())),
                Ok(StreamEvent::Completed {
                    finish_reason: FinishReason::Stop,
                    usage: Usage::default(),
                }),
            ]),
        );
        assert_eq!(stream.provider(), "openai");
        assert_eq!(
            stream.next().await,
            Some(Ok(StreamEvent::TextDelta("a".to_owned())))
        );
        assert_eq!(
            stream.next().await,
            Some(Ok(StreamEvent::Completed {
                finish_reason: FinishReason::Stop,
                usage: Usage::default(),
            }))
        );
        assert_eq!(stream.next().await, None);
        assert_eq!(stream.next().await, None);
    }

    #[tokio::test]
    async fn cancelling_a_stream_ends_it_with_a_cancelled_error() {
        let mut stream = CompletionStream::new(
            "anthropic",
            CancelToken::new(),
            event_stream(vec![
                Ok(StreamEvent::TextDelta("a".to_owned())),
                Ok(StreamEvent::TextDelta("b".to_owned())),
            ]),
        );
        assert_eq!(
            stream.next().await,
            Some(Ok(StreamEvent::TextDelta("a".to_owned())))
        );
        stream.cancel();
        let error = stream
            .next()
            .await
            .expect("one more item")
            .expect_err("cancelled");
        assert_eq!(error.kind(), ErrorKind::Cancelled);
        assert_eq!(error.provider(), "anthropic");
        assert_eq!(error.operation(), Operation::StreamCompletion);
        assert_eq!(stream.next().await, None);
    }

    #[tokio::test]
    async fn dropping_a_stream_cancels_its_token() {
        let token = CancelToken::new();
        let stream = CompletionStream::new("groq", token.clone(), event_stream(Vec::new()));
        assert!(!token.is_cancelled());
        drop(stream);
        assert!(token.is_cancelled());
    }

    #[tokio::test]
    async fn an_error_terminates_the_stream() {
        let mut stream = CompletionStream::new(
            "openai",
            CancelToken::new(),
            event_stream(vec![
                Err(ProviderError::new(
                    ErrorKind::Protocol,
                    "openai",
                    Operation::StreamCompletion,
                    "bad frame",
                )),
                Ok(StreamEvent::TextDelta("never".to_owned())),
            ]),
        );
        let error = stream
            .next()
            .await
            .expect("first item")
            .expect_err("protocol failure");
        assert_eq!(error.kind(), ErrorKind::Protocol);
        assert_eq!(stream.next().await, None);
    }
}

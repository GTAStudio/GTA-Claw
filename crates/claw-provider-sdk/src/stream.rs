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

/// Incrementally assembles tool calls that arrive as indexed fragments.
///
/// Providers emit an identifier and name once and then stream the argument
/// document in arbitrary fragments. The assembler keeps one buffer per index and
/// validates the JSON framing only when the call is completed.
#[derive(Debug, Default)]
pub struct ToolCallAssembler {
    partials: Vec<PartialToolCall>,
}

#[derive(Clone, Debug, Default)]
struct PartialToolCall {
    id: String,
    name: String,
    arguments: String,
    announced: bool,
    completed: bool,
}

impl ToolCallAssembler {
    /// Creates an empty assembler.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Returns the number of tool calls seen so far.
    #[must_use]
    pub fn len(&self) -> usize {
        self.partials.len()
    }

    /// Returns `true` when no tool call has been seen.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.partials.is_empty()
    }

    /// Applies one fragment and returns the events it produced.
    ///
    /// A [`StreamEvent::ToolCallStarted`] is emitted exactly once per index, as
    /// soon as both an identifier and a name are known.
    pub fn accept(
        &mut self,
        index: usize,
        id: Option<&str>,
        name: Option<&str>,
        arguments: Option<&str>,
    ) -> Vec<StreamEvent> {
        if self.partials.len() <= index {
            self.partials.resize(index + 1, PartialToolCall::default());
        }
        let mut events = Vec::new();
        {
            let partial = &mut self.partials[index];
            if let Some(id) = id
                && !id.is_empty()
            {
                partial.id.clear();
                partial.id.push_str(id);
            }
            if let Some(name) = name
                && !name.is_empty()
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
                partial.arguments.push_str(fragment);
                events.push(StreamEvent::ToolCallArgumentsDelta {
                    index,
                    delta: fragment.to_owned(),
                });
            }
        }
        events
    }

    /// Finalizes the call at `index`.
    ///
    /// # Errors
    ///
    /// Returns [`ModelError`] when the index is unknown, the call never received
    /// a name, or the accumulated arguments are not a JSON object.
    pub fn complete(&mut self, index: usize) -> Result<StreamEvent, ModelError> {
        let partial = self
            .partials
            .get_mut(index)
            .ok_or(ModelError::InvalidIdentifier { field: "tool_call" })?;
        if partial.name.is_empty() || partial.completed {
            return Err(ModelError::InvalidIdentifier { field: "tool_call" });
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
    /// Returns [`ModelError`] for the first call that cannot be assembled.
    pub fn complete_all(&mut self) -> Result<Vec<ToolCall>, ModelError> {
        let mut calls = Vec::with_capacity(self.partials.len());
        for index in 0..self.partials.len() {
            if self.partials[index].completed {
                let partial = &self.partials[index];
                calls.push(ToolCall {
                    id: partial.id.clone(),
                    name: partial.name.clone(),
                    arguments: ToolArguments::new(partial.arguments.clone())?,
                });
                continue;
            }
            match self.complete(index)? {
                StreamEvent::ToolCallCompleted { call, .. } => calls.push(call),
                _ => unreachable!("complete always returns ToolCallCompleted"),
            }
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
    #[must_use]
    pub fn finish_reason(&self) -> Option<&FinishReason> {
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
/// Dropping the stream drops the underlying HTTP response, which closes the
/// connection. Calling [`CompletionStream::cancel`] does the same explicitly and
/// makes the next poll return [`ErrorKind::Cancelled`].
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
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("CompletionStream")
            .field("provider", &self.provider)
            .field("cancelled", &self.cancel.is_cancelled())
            .field("finished", &self.finished)
            .finish()
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

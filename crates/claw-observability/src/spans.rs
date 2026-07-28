//! Canonical span constructors for end-to-end correlation.

use std::time::Duration;

use tracing::{Level, Span, field, span};

/// Terminal lifecycle outcome recorded on a canonical span.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SpanOutcome {
    /// The operation completed successfully.
    Succeeded,
    /// The operation failed.
    Failed,
    /// The operation was cancelled before completion.
    Cancelled,
}

impl SpanOutcome {
    const fn as_str(self) -> &'static str {
        match self {
            Self::Succeeded => "succeeded",
            Self::Failed => "failed",
            Self::Cancelled => "cancelled",
        }
    }
}

/// Records terminal lifecycle fields previously reserved by this module.
///
/// Call this before emitting the terminal event inside `span`. The helper does
/// no clock reads or allocation and immediately returns for a disabled span.
/// `error_kind` should be a stable category such as `timeout` rather than an
/// unbounded or sensitive error message.
pub fn record_completion(
    span: &Span,
    outcome: SpanOutcome,
    duration: Duration,
    error_kind: Option<&str>,
) {
    if span.is_disabled() {
        return;
    }
    span.record("lifecycle.outcome", outcome.as_str());
    span.record(
        "duration_ms",
        u64::try_from(duration.as_millis()).unwrap_or(u64::MAX),
    );
    if let Some(error_kind) = error_kind {
        span.record("error.kind", error_kind);
    }
}

/// Creates a session-lifecycle span.
#[must_use]
pub fn session(session_id: &str) -> Span {
    span!(
        Level::INFO,
        "session",
        session.id = session_id,
        lifecycle.outcome = field::Empty,
        duration_ms = field::Empty,
        error.kind = field::Empty,
    )
}

/// Creates a turn span correlated to its session.
#[must_use]
pub fn turn(session_id: &str, turn_id: &str) -> Span {
    span!(
        Level::INFO,
        "turn",
        session.id = session_id,
        turn.id = turn_id,
        lifecycle.outcome = field::Empty,
        duration_ms = field::Empty,
        error.kind = field::Empty,
    )
}

/// Creates a tool-call span correlated to its session and turn.
#[must_use]
pub fn tool_call(session_id: &str, turn_id: &str, call_id: &str, tool_name: &str) -> Span {
    span!(
        Level::INFO,
        "tool.call",
        session.id = session_id,
        turn.id = turn_id,
        tool.call.id = call_id,
        tool.name = tool_name,
        lifecycle.outcome = field::Empty,
        duration_ms = field::Empty,
        error.kind = field::Empty,
    )
}

/// Creates a provider-request span correlated to its session and turn.
#[must_use]
pub fn provider_request(
    session_id: &str,
    turn_id: &str,
    request_id: &str,
    provider: &str,
    model: &str,
) -> Span {
    span!(
        Level::INFO,
        "provider.request",
        session.id = session_id,
        turn.id = turn_id,
        provider.request.id = request_id,
        provider.name = provider,
        provider.model = model,
        lifecycle.outcome = field::Empty,
        duration_ms = field::Empty,
        error.kind = field::Empty,
    )
}

/// Creates a gateway-method span with an optional request correlation ID.
#[must_use]
pub fn gateway_method(session_id: &str, request_id: &str, method: &str) -> Span {
    span!(
        Level::INFO,
        "gateway.method",
        session.id = session_id,
        gateway.request.id = request_id,
        gateway.method = method,
        lifecycle.outcome = field::Empty,
        duration_ms = field::Empty,
        error.kind = field::Empty,
    )
}

#[cfg(test)]
mod tests {
    use std::sync::{Arc, Mutex};
    use std::time::Duration;

    use serde_json::Value;
    use tracing_subscriber::layer::SubscriberExt;

    use super::{
        SpanOutcome, gateway_method, provider_request, record_completion, session, tool_call, turn,
    };
    use crate::redaction::{REDACTED, RedactingLayer};
    use crate::telemetry::LogFormat;

    #[derive(Clone, Debug, Default)]
    struct SharedWriter(Arc<Mutex<Vec<u8>>>);

    impl std::io::Write for SharedWriter {
        fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
            self.0
                .lock()
                .map_err(|_| std::io::Error::other("test writer lock poisoned"))?
                .extend_from_slice(bytes);
            Ok(bytes.len())
        }

        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    #[test]
    fn span_names_follow_the_convention() {
        tracing::subscriber::with_default(tracing_subscriber::registry(), || {
            assert_eq!(
                session("s").metadata().map(tracing::Metadata::name),
                Some("session")
            );
            assert_eq!(
                turn("s", "t").metadata().map(tracing::Metadata::name),
                Some("turn")
            );
            assert_eq!(
                tool_call("s", "t", "c", "shell")
                    .metadata()
                    .map(tracing::Metadata::name),
                Some("tool.call")
            );
            assert_eq!(
                provider_request("s", "t", "r", "openai", "gpt")
                    .metadata()
                    .map(tracing::Metadata::name),
                Some("provider.request")
            );
            assert_eq!(
                gateway_method("s", "r", "health")
                    .metadata()
                    .map(tracing::Metadata::name),
                Some("gateway.method")
            );
        });
    }

    #[test]
    fn completion_fields_are_visible_without_weakening_redaction() {
        let writer = SharedWriter::default();
        let captured = Arc::clone(&writer.0);
        let subscriber =
            tracing_subscriber::registry().with(RedactingLayer::new(LogFormat::Json, writer));

        tracing::subscriber::with_default(subscriber, || {
            let span = provider_request("s-1", "t-1", "r-1", "openai", "gpt");
            record_completion(
                &span,
                SpanOutcome::Failed,
                Duration::from_millis(125),
                Some("timeout"),
            );
            let _entered = span.enter();
            tracing::error!(api_token = "must-not-appear", "provider request failed");
        });

        let output = String::from_utf8(captured.lock().expect("capture lock").clone())
            .expect("UTF-8 output");
        let event: Value = serde_json::from_str(output.trim()).expect("JSON telemetry");
        let fields = &event["spans"][0]["fields"];
        assert_eq!(fields["lifecycle.outcome"], "failed");
        assert_eq!(fields["duration_ms"], 125);
        assert_eq!(fields["error.kind"], "timeout");
        assert_eq!(event["fields"]["api_token"], REDACTED);
        assert!(!event.to_string().contains("must-not-appear"));
    }

    #[test]
    fn every_terminal_outcome_has_a_stable_name() {
        assert_eq!(SpanOutcome::Succeeded.as_str(), "succeeded");
        assert_eq!(SpanOutcome::Failed.as_str(), "failed");
        assert_eq!(SpanOutcome::Cancelled.as_str(), "cancelled");
    }
}

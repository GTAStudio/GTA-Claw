//! Canonical span constructors for end-to-end correlation.

use tracing::{Level, Span, span};

/// Creates a session-lifecycle span.
#[must_use]
pub fn session(session_id: &str) -> Span {
    span!(Level::INFO, "session", session.id = session_id)
}

/// Creates a turn span correlated to its session.
#[must_use]
pub fn turn(session_id: &str, turn_id: &str) -> Span {
    span!(
        Level::INFO,
        "turn",
        session.id = session_id,
        turn.id = turn_id
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
        tool.name = tool_name
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
        provider.model = model
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
        gateway.method = method
    )
}

#[cfg(test)]
mod tests {
    use super::{gateway_method, provider_request, session, tool_call, turn};

    #[test]
    fn span_names_follow_the_convention() {
        tracing::subscriber::with_default(tracing_subscriber::registry(), || {
            assert_eq!(
                session("s").metadata().map(|meta| meta.name()),
                Some("session")
            );
            assert_eq!(
                turn("s", "t").metadata().map(|meta| meta.name()),
                Some("turn")
            );
            assert_eq!(
                tool_call("s", "t", "c", "shell")
                    .metadata()
                    .map(|meta| meta.name()),
                Some("tool.call")
            );
            assert_eq!(
                provider_request("s", "t", "r", "openai", "gpt")
                    .metadata()
                    .map(|meta| meta.name()),
                Some("provider.request")
            );
            assert_eq!(
                gateway_method("s", "r", "health")
                    .metadata()
                    .map(|meta| meta.name()),
                Some("gateway.method")
            );
        });
    }
}

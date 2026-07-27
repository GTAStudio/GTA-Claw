//! Golden coverage for `interop.openai.chat-completions`.
//!
//! The acceptance row requires JSON and SSE `/v1/chat/completions` golden tests
//! that match the pinned request, stream, usage and error contracts. Each test
//! below pins one of those four obligations against a fixture in
//! `tests/fixtures/openai/chat/`, and the runtime behind the HTTP surface is a
//! scripted double, so nothing here reaches a real provider.

mod openai_support;

use claw_http_api::ToolChoice;
use openai_support::{
    RequestSpec, assert_error_contracts_are_distinct, observe, run_fixture, script, spawn,
};
use serde_json::{Value, json};

/// Ledger row this file is evidence for.
const FEATURE: &str = "interop.openai.chat-completions";

/// A buffered completion matches the pinned OpenAI envelope and usage block.
#[tokio::test]
async fn chat_completion_json_matches_the_pinned_contract() {
    let run = run_fixture(FEATURE, "chat/json_completion.json").await;

    let body = run.observed["body"].clone();
    assert_eq!(body["object"], "chat.completion");
    assert_eq!(body["choices"][0]["message"]["role"], "assistant");
    assert_eq!(body["choices"][0]["message"]["content"], "Berlin is sunny.");
    assert_eq!(body["choices"][0]["finish_reason"], "stop");
    assert_eq!(
        body["usage"],
        json!({ "prompt_tokens": 11, "completion_tokens": 7, "total_tokens": 18 }),
        "usage must be reported from the provider accounting, not synthesised"
    );

    // The system message is lifted into instructions rather than being dropped,
    // and the user turn survives into the prompt the provider actually sees.
    let request = run.server.runtime.generation_request();
    assert_eq!(
        request.instructions.as_deref(),
        Some("Answer in one sentence.")
    );
    assert!(
        request.prompt.contains("What is the weather in Berlin?"),
        "prompt lost the user turn: {:?}",
        request.prompt
    );
    assert_eq!(
        request.model, "openclaw",
        "the routing identifier must reach the provider unchanged"
    );
}

/// Client tool calls surface as a `tool_calls` completion rather than as text.
#[tokio::test]
async fn chat_completion_reports_tool_calls_with_the_pinned_finish_reason() {
    let run = run_fixture(FEATURE, "chat/json_tool_calls.json").await;

    let choice = run.observed["body"]["choices"][0].clone();
    assert_eq!(choice["finish_reason"], "tool_calls");
    let call = choice["message"]["tool_calls"][0].clone();
    assert_eq!(call["type"], "function");
    assert_eq!(call["function"]["name"], "get_weather");
    assert_eq!(call["function"]["arguments"], "{\"city\":\"Berlin\"}");

    // `tool_choice: "required"` has to reach the provider, otherwise the
    // guarantee the caller asked for is only enforced after the fact.
    let request = run.server.runtime.generation_request();
    assert_eq!(request.tool_choice, ToolChoice::Required);
    assert_eq!(request.tools.len(), 1);
    assert_eq!(request.tools[0].name, "get_weather");
}

/// A pinned stop sequence truncates the provider text before it is rendered.
#[tokio::test]
async fn chat_completion_applies_the_requested_stop_sequence() {
    let run = run_fixture(FEATURE, "chat/json_stop_sequence_truncation.json").await;

    let content = run.observed["body"]["choices"][0]["message"]["content"]
        .as_str()
        .expect("assistant content")
        .to_owned();
    assert_eq!(content, "visible answer");
    assert!(
        !content.contains("hidden continuation"),
        "text past the stop sequence leaked to the client"
    );
}

/// Usage is passed through from the provider rather than being a constant.
///
/// A golden alone cannot prove this: a hard-coded usage block would match its
/// own golden forever. Two runs of the same request with different provider
/// accounting are what makes the pinned numbers meaningful.
#[tokio::test]
async fn chat_usage_tracks_the_provider_rather_than_a_constant() {
    let mut reported = Vec::new();
    for usage in [
        json!({ "input_tokens": 11, "output_tokens": 7, "total_tokens": 18 }),
        json!({ "input_tokens": 402, "output_tokens": 91, "total_tokens": 493 }),
    ] {
        let server = spawn(script(json!({
            "generate": { "kind": "output", "text": "ok", "usage": usage.clone() }
        })))
        .await;
        let response = server
            .send(&RequestSpec::post(
                "/v1/chat/completions",
                "operator-token",
                json!({
                    "model": "openclaw",
                    "messages": [{ "role": "user", "content": "hello" }]
                }),
            ))
            .await;
        assert_eq!(response.status, 200);
        reported.push(response.json()["usage"].clone());
    }

    assert_eq!(
        reported[0],
        json!({ "prompt_tokens": 11, "completion_tokens": 7, "total_tokens": 18 })
    );
    assert_eq!(
        reported[1],
        json!({ "prompt_tokens": 402, "completion_tokens": 91, "total_tokens": 493 })
    );
    assert_ne!(
        reported[0], reported[1],
        "usage did not follow the provider, so the pinned numbers prove nothing"
    );
}

/// The streamed completion pins the whole event sequence, including `[DONE]`.
#[tokio::test]
async fn chat_stream_emits_the_complete_pinned_event_sequence() {
    let run = run_fixture(FEATURE, "chat/sse_stream_with_usage.json").await;

    assert!(
        run.response
            .header("content-type")
            .is_some_and(|value| value.starts_with("text/event-stream")),
        "streamed completions must be served as an event stream, got {:?}",
        run.response.header("content-type")
    );
    let events = run.events();
    assert!(
        events.len() >= 6,
        "a role chunk, content deltas, a stop chunk, a usage chunk and [DONE] were expected, got {}",
        events.len()
    );
    assert_eq!(
        events.last().and_then(|event| event.data.as_str()),
        Some("[DONE]"),
        "the stream must terminate with the OpenAI sentinel"
    );

    let chunks = decoded_chunks(&run.observed);
    assert_eq!(chunks[0]["choices"][0]["delta"]["role"], "assistant");
    let text = chunks
        .iter()
        .filter_map(|chunk| chunk["choices"][0]["delta"]["content"].as_str())
        .collect::<String>();
    assert_eq!(text, "Berlin is sunny.");

    let finish = chunks
        .iter()
        .filter_map(|chunk| chunk["choices"][0]["finish_reason"].as_str())
        .collect::<Vec<_>>();
    assert_eq!(
        finish,
        vec!["stop"],
        "exactly one chunk may close the choice"
    );

    let usage = chunks
        .last()
        .expect("a usage chunk precedes [DONE]")
        .get("usage")
        .cloned()
        .expect("stream_options.include_usage requested a usage chunk");
    assert_eq!(
        usage,
        json!({ "prompt_tokens": 11, "completion_tokens": 7, "total_tokens": 18 })
    );

    // Every chunk of one completion carries the same identifier. Normalisation
    // keeps equal identifiers equal, so this relation is pinned by the golden
    // as well as asserted here.
    let ids = chunks
        .iter()
        .map(|chunk| chunk["id"].to_string())
        .collect::<std::collections::BTreeSet<_>>();
    assert_eq!(ids.len(), 1, "chunks of one completion disagreed on `id`");
}

/// Usage chunks are opt-in through `stream_options`.
#[tokio::test]
async fn chat_stream_omits_usage_unless_stream_options_requests_it() {
    let run = run_fixture(FEATURE, "chat/sse_stream_without_usage.json").await;

    let chunks = decoded_chunks(&run.observed);
    assert!(
        chunks.iter().all(|chunk| chunk.get("usage").is_none()),
        "a usage chunk was emitted without stream_options.include_usage"
    );
    assert_eq!(
        run.events().last().and_then(|event| event.data.as_str()),
        Some("[DONE]")
    );

    // The same script with the option set does emit one, so the absence above
    // is the option taking effect rather than usage being unimplemented.
    let with_usage = run_fixture(FEATURE, "chat/sse_stream_with_usage.json").await;
    assert!(
        decoded_chunks(&with_usage.observed)
            .iter()
            .any(|chunk| chunk.get("usage").is_some())
    );
}

/// Streamed tool calls are framed as an opening chunk plus argument deltas.
#[tokio::test]
async fn chat_stream_frames_tool_calls_as_indexed_argument_deltas() {
    let run = run_fixture(FEATURE, "chat/sse_tool_call.json").await;

    let chunks = decoded_chunks(&run.observed);
    let calls = chunks
        .iter()
        .filter_map(|chunk| chunk["choices"][0]["delta"]["tool_calls"][0].as_object())
        .cloned()
        .collect::<Vec<_>>();
    assert!(
        calls.len() >= 2,
        "a tool call must be announced before its arguments are streamed, got {} frames",
        calls.len()
    );

    let opening = &calls[0];
    assert_eq!(opening["index"], json!(0));
    assert_eq!(opening["type"], json!("function"));
    assert_eq!(opening["function"]["name"], json!("get_weather"));
    assert_eq!(opening["function"]["arguments"], json!(""));

    let arguments = calls
        .iter()
        .filter_map(|call| call["function"]["arguments"].as_str())
        .collect::<String>();
    assert_eq!(arguments, "{\"city\":\"Berlin\"}");

    let finish = chunks
        .iter()
        .filter_map(|chunk| chunk["choices"][0]["finish_reason"].as_str())
        .collect::<Vec<_>>();
    assert_eq!(finish, vec!["tool_calls"]);
    assert_eq!(
        run.events().last().and_then(|event| event.data.as_str()),
        Some("[DONE]")
    );
}

/// A provider failure mid-stream is reported inside the stream and terminated.
#[tokio::test]
async fn chat_stream_reports_provider_failure_as_a_terminal_error_frame() {
    let run = run_fixture(FEATURE, "chat/sse_provider_failure.json").await;

    assert_eq!(
        run.response.status, 200,
        "the status is already committed when the failure happens"
    );
    let events = run.events();
    assert_eq!(
        events.last().and_then(|event| event.data.as_str()),
        Some("[DONE]"),
        "a failed stream must still terminate with the sentinel"
    );

    let error = events
        .iter()
        .rev()
        .find(|event| event.data.get("error").is_some())
        .map(|event| event.data.clone())
        .expect("the failure must be delivered as a classified error frame");
    assert_eq!(error["error"]["type"], "api_error");
    assert_eq!(
        error["error"]["message"],
        "upstream provider dropped the connection"
    );
}

/// Every failure class keeps its own status, type and message.
#[tokio::test]
async fn chat_errors_stay_classified_per_failure_class() {
    let mut observed = Vec::new();
    for name in [
        "error_unauthenticated",
        "error_scope_not_granted",
        "error_unknown_model",
        "error_missing_messages",
        "error_unknown_field",
        "error_malformed_json",
        "error_invalid_temperature",
        "error_unsupported_tool_declaration",
        "error_provider_not_found",
        "error_provider_unavailable",
        "error_provider_timeout",
        "error_output_token_limit",
    ] {
        let run = run_fixture(FEATURE, &format!("chat/{name}.json")).await;
        observed.push((name.to_owned(), run.observed));
    }

    let status_of = |name: &str| {
        observed
            .iter()
            .find(|(fixture, _)| fixture == name)
            .map(|(_, value)| value["status"].as_u64().expect("status"))
            .expect("fixture ran")
    };
    assert_eq!(status_of("error_unauthenticated"), 401);
    assert_eq!(status_of("error_scope_not_granted"), 403);
    assert_eq!(status_of("error_unknown_model"), 400);
    assert_eq!(status_of("error_provider_not_found"), 404);
    assert_eq!(
        status_of("error_output_token_limit"),
        502,
        "a provider that breaks a requested constraint is an upstream fault, not a client fault"
    );
    assert_eq!(status_of("error_provider_unavailable"), 503);
    assert_eq!(status_of("error_provider_timeout"), 504);

    assert_error_contracts_are_distinct(&observed);
}

/// The wrong method is refused by the router, before any handler runs.
///
/// This one is deliberately outside the classified-error table above: the
/// router answers with an empty body and an `Allow` header rather than with an
/// OpenAI error envelope, and pinning that difference is the point.
#[tokio::test]
async fn chat_rejects_the_wrong_method_at_the_router() {
    let run = run_fixture(FEATURE, "chat/error_wrong_method.json").await;

    assert_eq!(run.observed["status"], 405);
    let allow = run.observed["headers"]["allow"]
        .as_str()
        .expect("a 405 must advertise the accepted methods")
        .split(',')
        .map(str::trim)
        .map(str::to_owned)
        .collect::<Vec<_>>();
    assert!(allow.contains(&"POST".to_owned()), "Allow was {allow:?}");
    assert!(
        run.server.runtime.generation_requests().is_empty(),
        "a rejected method still reached the provider"
    );
}

/// Authentication is refused before the provider is consulted.
#[tokio::test]
async fn chat_rejects_unauthenticated_callers_without_reaching_the_provider() {
    let server = spawn(script(json!({
        "generate": { "kind": "output", "text": "must not be produced" }
    })))
    .await;

    let mut request = RequestSpec::post(
        "/v1/chat/completions",
        "operator-token",
        json!({
            "model": "openclaw",
            "messages": [{ "role": "user", "content": "hello" }]
        }),
    );
    request.token = None;
    let response = server.send(&request).await;

    assert_eq!(response.status, 401);
    assert_eq!(observe(&response)["body"]["error"]["type"], "unauthorized");
    assert!(
        server.runtime.generation_requests().is_empty(),
        "an unauthenticated request reached the provider"
    );
}

/// Decodes the pinned SSE payloads of a golden run into JSON chunks.
///
/// `[DONE]` stays in the golden as an ordinary event so the terminator is
/// pinned, but it is not a chunk, so it is dropped here.
fn decoded_chunks(observed: &Value) -> Vec<Value> {
    observed["events"]
        .as_array()
        .expect("a streamed response records an event array")
        .iter()
        .map(|event| event["data"].clone())
        .filter(|data| data.as_str() != Some("[DONE]"))
        .map(|data| match data {
            Value::String(raw) => {
                serde_json::from_str(&raw).unwrap_or_else(|error| panic!("chunk is JSON: {error}"))
            }
            other => other,
        })
        .collect()
}

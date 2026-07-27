//! Golden coverage for `interop.openai.openresponses`.
//!
//! The acceptance row requires JSON and SSE `/v1/responses` golden tests that
//! match the pinned item, event, tool, usage and error contracts. Each of those
//! five obligations is pinned below against a fixture in
//! `tests/fixtures/openai/responses/`, driven by a scripted runtime rather than
//! by any real provider.

mod openai_support;

use openai_support::{
    RequestSpec, assert_error_contracts_are_distinct, run_fixture, script, spawn,
};
use serde_json::{Value, json};

/// Ledger row this file is evidence for.
const FEATURE: &str = "interop.openai.openresponses";

/// The event sequence a plain streamed response emits, terminator included.
const COMPLETED_STREAM_EVENTS: [&str; 12] = [
    "response.created",
    "response.in_progress",
    "response.output_item.added",
    "response.content_part.added",
    "response.output_text.delta",
    "response.output_text.delta",
    "response.output_text.delta",
    "response.output_text.done",
    "response.content_part.done",
    "response.output_item.done",
    "response.completed",
    "[DONE]",
];

/// A buffered response matches the pinned resource, item tree and usage.
#[tokio::test]
async fn response_json_matches_the_pinned_resource_contract() {
    let run = run_fixture(FEATURE, "responses/json_completed.json").await;

    let body = run.observed["body"].clone();
    assert_eq!(body["object"], "response");
    assert_eq!(body["status"], "completed");
    assert_eq!(body["model"], "openclaw");

    let item = body["output"][0].clone();
    assert_eq!(item["type"], "message");
    assert_eq!(item["role"], "assistant");
    assert_eq!(item["status"], "completed");
    assert_eq!(item["content"][0]["type"], "output_text");
    assert_eq!(item["content"][0]["text"], "Berlin is sunny.");

    assert_eq!(
        body["usage"],
        json!({ "input_tokens": 13, "output_tokens": 5, "total_tokens": 18 }),
        "the Responses surface reports usage under its own token names"
    );

    let request = run.server.runtime.generation_request();
    assert_eq!(
        request.instructions.as_deref(),
        Some("Answer in one sentence.")
    );
    assert_eq!(request.prompt, "What is the weather in Berlin?");
}

/// Structured input items are flattened into instructions and an active turn.
#[tokio::test]
async fn response_accepts_structured_input_items() {
    let run = run_fixture(FEATURE, "responses/json_input_items.json").await;

    assert_eq!(run.observed["body"]["status"], "completed");

    let request = run.server.runtime.generation_request();
    assert_eq!(request.model, "openclaw/main");
    assert_eq!(request.instructions.as_deref(), Some("Be terse."));
    assert!(
        request.prompt.contains("How many moons does Mars have?"),
        "the active user item was lost: {:?}",
        request.prompt
    );
}

/// Function calls surface as their own output item and an incomplete status.
#[tokio::test]
async fn response_reports_function_calls_as_pinned_output_items() {
    let run = run_fixture(FEATURE, "responses/json_function_call.json").await;

    let body = run.observed["body"].clone();
    assert_eq!(
        body["status"], "incomplete",
        "a turn waiting on a tool result is not complete"
    );

    let call = body["output"]
        .as_array()
        .expect("output items")
        .iter()
        .find(|item| item["type"] == "function_call")
        .cloned()
        .expect("a function_call item");
    assert_eq!(call["name"], "get_weather");
    assert_eq!(call["arguments"], "{\"city\":\"Berlin\"}");
    assert_eq!(call["status"], "completed");
    assert_eq!(
        body["usage"],
        json!({ "input_tokens": 27, "output_tokens": 11, "total_tokens": 38 })
    );
}

/// Usage follows the provider rather than being a constant.
///
/// A golden alone cannot show this, because a hard-coded usage block would
/// match its own golden forever.
#[tokio::test]
async fn response_usage_tracks_the_provider_rather_than_a_constant() {
    let mut reported = Vec::new();
    for usage in [
        json!({ "input_tokens": 13, "output_tokens": 5, "total_tokens": 18 }),
        json!({ "input_tokens": 640, "output_tokens": 77, "total_tokens": 717 }),
    ] {
        let server = spawn(script(json!({
            "generate": { "kind": "output", "text": "ok", "usage": usage }
        })))
        .await;
        let response = server
            .send(&RequestSpec::post(
                "/v1/responses",
                "operator-token",
                json!({ "model": "openclaw", "input": "hello" }),
            ))
            .await;
        assert_eq!(response.status, 200);
        reported.push(response.json()["usage"].clone());
    }

    assert_eq!(
        reported[0],
        json!({ "input_tokens": 13, "output_tokens": 5, "total_tokens": 18 })
    );
    assert_eq!(
        reported[1],
        json!({ "input_tokens": 640, "output_tokens": 77, "total_tokens": 717 })
    );
    assert_ne!(
        reported[0], reported[1],
        "usage did not follow the provider, so the pinned numbers prove nothing"
    );
}

/// The streamed response pins the whole named event sequence.
#[tokio::test]
async fn response_stream_emits_the_complete_pinned_event_sequence() {
    let run = run_fixture(FEATURE, "responses/sse_completed.json").await;

    assert!(
        run.response
            .header("content-type")
            .is_some_and(|value| value.starts_with("text/event-stream")),
        "streamed responses must be served as an event stream"
    );
    assert_eq!(event_names(&run.observed), COMPLETED_STREAM_EVENTS);

    // Every named event repeats its own name inside the payload, which is what
    // clients that ignore the SSE event line rely on.
    for event in run.observed["events"].as_array().expect("events") {
        if let Some(name) = event.get("event").and_then(Value::as_str) {
            assert_eq!(
                event["data"]["type"], name,
                "event {name} carried a payload typed differently"
            );
        }
    }

    let deltas = payloads(&run.observed, "response.output_text.delta")
        .iter()
        .filter_map(|payload| payload["delta"].as_str().map(str::to_owned))
        .collect::<Vec<_>>();
    assert_eq!(deltas, vec!["Berlin ", "is ", "sunny."]);

    let done = payloads(&run.observed, "response.output_text.done");
    assert_eq!(done[0]["text"], "Berlin is sunny.");

    let completed = payloads(&run.observed, "response.completed");
    assert_eq!(completed.len(), 1);
    assert_eq!(completed[0]["response"]["status"], "completed");
    assert_eq!(
        completed[0]["response"]["usage"],
        json!({ "input_tokens": 13, "output_tokens": 5, "total_tokens": 18 }),
        "the terminal event must carry the usage accounting"
    );

    // The resource identity is stable from the first event to the last.
    let created = payloads(&run.observed, "response.created");
    assert_eq!(
        created[0]["response"]["id"], completed[0]["response"]["id"],
        "the stream changed response identity part way through"
    );
}

/// Streamed function calls add their own output item events.
#[tokio::test]
async fn response_stream_frames_function_calls_as_their_own_items() {
    let run = run_fixture(FEATURE, "responses/sse_function_call.json").await;

    let names = event_names(&run.observed);
    assert_eq!(names.last(), Some(&"[DONE]"));
    assert_eq!(
        names
            .iter()
            .filter(|name| **name == "response.output_item.added")
            .count(),
        2,
        "the assistant item and the function call item are both announced"
    );

    let call_item = payloads(&run.observed, "response.output_item.done")
        .into_iter()
        .find(|payload| payload["item"]["type"] == "function_call")
        .expect("a completed function_call item");
    assert_eq!(call_item["output_index"], json!(1));
    assert_eq!(call_item["item"]["name"], "get_weather");
    assert_eq!(call_item["item"]["arguments"], "{\"city\":\"Berlin\"}");

    let completed = payloads(&run.observed, "response.completed");
    assert_eq!(
        completed[0]["response"]["status"], "incomplete",
        "a stream that ends on a tool call has not finished the turn"
    );
    assert_eq!(
        completed[0]["response"]["output"]
            .as_array()
            .expect("output items")
            .len(),
        2
    );
}

/// A failed stream emits `response.failed` and still terminates.
#[tokio::test]
async fn response_stream_reports_failure_as_a_pinned_failed_event() {
    let run = run_fixture(FEATURE, "responses/sse_failed.json").await;

    let names = event_names(&run.observed);
    assert!(
        names.contains(&"response.failed"),
        "a failed stream must say so: {names:?}"
    );
    assert!(
        !names.contains(&"response.completed"),
        "a failed stream must not also claim completion: {names:?}"
    );
    assert_eq!(names.last(), Some(&"[DONE]"));

    let failed = payloads(&run.observed, "response.failed");
    assert_eq!(failed[0]["response"]["status"], "failed");
    assert_eq!(failed[0]["response"]["error"]["code"], "api_error");
    assert_eq!(
        failed[0]["response"]["error"]["message"],
        "upstream provider dropped the connection"
    );
}

/// Constrained streams withhold deltas until the constraint has been checked.
#[tokio::test]
async fn response_stream_buffers_deltas_while_a_constraint_is_pending() {
    let run = run_fixture(FEATURE, "responses/sse_constrained_buffering.json").await;

    let deltas = payloads(&run.observed, "response.output_text.delta");
    assert_eq!(
        deltas.len(),
        1,
        "a constrained stream emits one delta once validation has passed"
    );
    assert_eq!(deltas[0]["delta"], "Berlin is sunny.");
    assert_eq!(event_names(&run.observed).last(), Some(&"[DONE]"));

    // The unconstrained fixture streams the same text as three deltas, so the
    // single delta above is the constraint taking effect rather than the
    // provider script differing.
    let unconstrained = run_fixture(FEATURE, "responses/sse_completed.json").await;
    assert_eq!(
        payloads(&unconstrained.observed, "response.output_text.delta").len(),
        3
    );
}

/// Every failure class keeps its own status and error code.
#[tokio::test]
async fn response_errors_stay_classified_per_failure_class() {
    let mut observed = Vec::new();
    for name in [
        "error_unauthenticated",
        "error_scope_not_granted",
        "error_unknown_model",
        "error_provider_not_found",
        "error_provider_unavailable",
        "error_provider_timeout",
        "error_output_token_limit",
        "error_required_tool_not_called",
    ] {
        let run = run_fixture(FEATURE, &format!("responses/{name}.json")).await;
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
    assert_eq!(status_of("error_output_token_limit"), 502);
    assert_eq!(status_of("error_required_tool_not_called"), 502);
    assert_eq!(status_of("error_provider_unavailable"), 503);
    assert_eq!(status_of("error_provider_timeout"), 504);

    // Provider failures are reported as failed response resources, not as bare
    // error envelopes, so the resource shape is pinned too.
    for name in [
        "error_provider_not_found",
        "error_provider_unavailable",
        "error_provider_timeout",
        "error_output_token_limit",
        "error_required_tool_not_called",
    ] {
        let body = &observed
            .iter()
            .find(|(fixture, _)| fixture == name)
            .expect("fixture ran")
            .1["body"];
        assert_eq!(body["object"], "response", "{name} lost the resource shape");
        assert_eq!(body["status"], "failed", "{name} did not report failure");
    }

    assert_error_contracts_are_distinct(&observed);
}

/// Request validation failures are pinned as one deliberately generic message.
///
/// This is a known difference rather than a contract worth celebrating: five
/// materially different malformed bodies all answer `400 invalid_request_error`
/// with the message `invalid request`, so a client cannot tell a missing input
/// from an unsupported tool type. It is pinned here so the collapse is visible
/// evidence instead of an unnoticed regression, and so that narrowing it later
/// is a deliberate, reviewed fixture change.
#[tokio::test]
async fn response_request_validation_errors_share_one_generic_message() {
    let mut observed = Vec::new();
    for name in [
        "error_missing_input",
        "error_unknown_field",
        "error_invalid_input_item",
        "error_invalid_temperature",
        "error_invalid_tool_declaration",
    ] {
        let run = run_fixture(FEATURE, &format!("responses/{name}.json")).await;
        observed.push((name, run.observed));
    }

    for (name, value) in &observed {
        assert_eq!(value["status"], 400, "{name} left the request-error class");
        assert_eq!(value["body"]["error"]["type"], "invalid_request_error");
        assert_eq!(
            value["body"]["error"]["message"], "invalid request",
            "{name} no longer shares the generic message; narrow this test rather than widening it"
        );
    }

    // The routing identifier is the one request error that does say what went
    // wrong, so the generic message above is not simply "every 400 is opaque".
    let specific = run_fixture(FEATURE, "responses/error_unknown_model.json").await;
    assert_eq!(specific.observed["status"], 400);
    assert_eq!(
        specific.observed["body"]["error"]["message"],
        "Invalid `model`. Use `openclaw` or `openclaw/<agentId>`."
    );
}

/// The wrong method is refused by the router, before any handler runs.
#[tokio::test]
async fn response_rejects_the_wrong_method_at_the_router() {
    let run = run_fixture(FEATURE, "responses/error_wrong_method.json").await;

    assert_eq!(run.observed["status"], 405);
    let allow = run.observed["headers"]["allow"]
        .as_str()
        .expect("a 405 must advertise the accepted methods")
        .split(',')
        .map(str::trim)
        .map(str::to_owned)
        .collect::<Vec<_>>();
    assert!(allow.contains(&"POST".to_owned()), "Allow was {allow:?}");
    assert!(run.server.runtime.generation_requests().is_empty());
}

/// Returns the ordered event names of a pinned stream.
///
/// The unnamed terminator is reported as `[DONE]` so a caller can assert the
/// whole sequence, terminator included, in one comparison.
fn event_names(observed: &Value) -> Vec<&str> {
    observed["events"]
        .as_array()
        .expect("a streamed response records an event array")
        .iter()
        .map(|event| {
            event
                .get("event")
                .and_then(Value::as_str)
                .or_else(|| event["data"].as_str())
                .expect("every event is either named or the terminator")
        })
        .collect()
}

/// Returns the payloads of every event with the given name, in order.
fn payloads(observed: &Value, name: &str) -> Vec<Value> {
    observed["events"]
        .as_array()
        .expect("a streamed response records an event array")
        .iter()
        .filter(|event| event.get("event").and_then(Value::as_str) == Some(name))
        .map(|event| event["data"].clone())
        .collect()
}

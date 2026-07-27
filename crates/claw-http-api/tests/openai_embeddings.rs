//! Golden coverage for `interop.openai.embeddings`.
//!
//! The acceptance row requires embedding request, provider policy, dimensions,
//! usage and error fixtures to pass. Each of those five obligations is pinned
//! below against a fixture in `tests/fixtures/openai/embeddings/`, with a
//! scripted embedding provider standing in for any real one.

mod openai_support;

use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use openai_support::{
    RequestSpec, assert_error_contracts_are_distinct, observe, run_fixture, script, spawn,
};
use serde_json::json;

/// Ledger row this file is evidence for.
const FEATURE: &str = "interop.openai.embeddings";

/// A single-input request matches the pinned list envelope and usage block.
#[tokio::test]
async fn embedding_request_matches_the_pinned_contract() {
    let run = run_fixture(FEATURE, "embeddings/float_single.json").await;

    let body = run.observed["body"].clone();
    assert_eq!(body["object"], "list");
    assert_eq!(body["model"], "openclaw");
    assert_eq!(body["data"][0]["object"], "embedding");
    assert_eq!(body["data"][0]["index"], 0);
    assert_eq!(body["data"][0]["embedding"], json!([0.25, -0.5, 0.75]));

    let request = run.server.runtime.embedding_request();
    assert_eq!(request.model, "openclaw");
    assert_eq!(request.input, vec!["Berlin".to_owned()]);
    assert_eq!(request.dimensions, None);
}

/// Batched inputs come back as one indexed embedding each, in request order.
#[tokio::test]
async fn embedding_batch_preserves_input_order_and_indices() {
    let run = run_fixture(FEATURE, "embeddings/float_batch.json").await;

    let data = run.observed["body"]["data"]
        .as_array()
        .expect("data list")
        .clone();
    assert_eq!(data.len(), 3);
    for (index, item) in data.iter().enumerate() {
        assert_eq!(
            item["index"],
            json!(index),
            "indices must follow input order"
        );
    }
    assert_eq!(data[0]["embedding"], json!([1.0, 0.0]));
    assert_eq!(data[1]["embedding"], json!([0.0, 1.0]));
    assert_eq!(data[2]["embedding"], json!([-1.0, -1.0]));

    let request = run.server.runtime.embedding_request();
    assert_eq!(request.model, "openclaw/main");
    assert_eq!(
        request.input,
        vec!["Berlin".to_owned(), "Paris".to_owned(), "Rome".to_owned()],
        "every input must reach the provider exactly once, in order"
    );
}

/// A requested dimension count reaches the provider and changes the result.
#[tokio::test]
async fn embedding_dimensions_reach_the_provider_and_shape_the_result() {
    let requested = run_fixture(FEATURE, "embeddings/dimensions_requested.json").await;

    assert_eq!(
        requested.server.runtime.embedding_request().dimensions,
        Some(5),
        "the requested width must be forwarded, not silently dropped"
    );
    for item in requested.observed["body"]["data"]
        .as_array()
        .expect("data list")
    {
        assert_eq!(
            item["embedding"].as_array().expect("vector").len(),
            5,
            "the returned vector width did not honour `dimensions`"
        );
    }

    // Without the field the provider picks its own width, so the assertion
    // above is the request taking effect rather than a fixed provider width.
    let defaulted = run_fixture(FEATURE, "embeddings/dimensions_defaulted.json").await;
    assert_eq!(
        defaulted.server.runtime.embedding_request().dimensions,
        None
    );
    assert_eq!(
        defaulted.observed["body"]["data"][0]["embedding"]
            .as_array()
            .expect("vector")
            .len(),
        3
    );
}

/// `encoding_format: "base64"` packs the same vector as little-endian f32.
#[tokio::test]
async fn embedding_base64_encoding_packs_little_endian_float32() {
    let run = run_fixture(FEATURE, "embeddings/encoding_format_base64.json").await;

    let encoded = run.observed["body"]["data"][0]["embedding"]
        .as_str()
        .expect("base64 encoding yields a string, not an array")
        .to_owned();
    let bytes = STANDARD.decode(&encoded).expect("payload is base64");
    assert_eq!(bytes.len(), 3 * 4, "three float32 values were expected");

    let decoded = bytes
        .chunks_exact(4)
        .map(|chunk| f32::from_le_bytes(chunk.try_into().expect("four bytes")))
        .collect::<Vec<_>>();
    assert_eq!(decoded, vec![0.25_f32, -0.5, 0.75]);

    // The float path returns the same vector, so the encoding is a rendering
    // choice rather than a different embedding.
    let float = run_fixture(FEATURE, "embeddings/float_single.json").await;
    assert_eq!(
        float.observed["body"]["data"][0]["embedding"],
        json!([0.25, -0.5, 0.75])
    );
}

/// Usage is reported as a pinned constant zero.
///
/// This is a known difference from upstream rather than a contract worth
/// celebrating: the endpoint reports no token accounting at all. It is pinned
/// so the gap is visible evidence, and so that reporting real counts later has
/// to be a deliberate, reviewed fixture change.
#[tokio::test]
async fn embedding_usage_is_pinned_as_a_known_constant_zero() {
    for fixture in [
        "embeddings/float_single.json",
        "embeddings/float_batch.json",
        "embeddings/encoding_format_base64.json",
    ] {
        let run = run_fixture(FEATURE, fixture).await;
        assert_eq!(
            run.observed["body"]["usage"],
            json!({ "prompt_tokens": 0, "total_tokens": 0 }),
            "{fixture} changed the pinned usage block"
        );
    }
}

/// Provider policy is pinned: only OpenClaw routing identifiers are accepted.
#[tokio::test]
async fn embedding_provider_policy_accepts_only_openclaw_identifiers() {
    let server = spawn(script(json!({
        "agents": ["main", "research"],
        "embed": { "kind": "dimensioned" }
    })))
    .await;

    for model in [
        "openclaw",
        "openclaw/default",
        "openclaw/main",
        "openclaw/research",
    ] {
        let response = server
            .send(&RequestSpec::post(
                "/v1/embeddings",
                "operator-token",
                json!({ "model": model, "input": "Berlin" }),
            ))
            .await;
        assert_eq!(response.status, 200, "{model} should be routable");
        assert_eq!(response.json()["model"], model, "the model must be echoed");
    }

    for model in [
        "text-embedding-3-small",
        "openclaw/unknown",
        "openclaw/",
        "openai/openclaw",
        "",
    ] {
        let response = server
            .send(&RequestSpec::post(
                "/v1/embeddings",
                "operator-token",
                json!({ "model": model, "input": "Berlin" }),
            ))
            .await;
        assert_eq!(response.status, 400, "{model} should not be routable");
    }
}

/// Input size limits are enforced before the provider is consulted.
///
/// These bounds are asserted programmatically rather than from fixtures: a
/// golden holding 129 inputs or an 8 KiB string would obscure the contract it
/// is meant to pin.
#[tokio::test]
async fn embedding_input_limits_are_enforced_before_the_provider() {
    let cases = [
        (
            "too many inputs",
            json!(vec!["x"; 129]),
            "Too many inputs (max 128).",
        ),
        (
            "one input too long",
            json!(["x".repeat(8_193)]),
            "Input too long (max 8192 chars).",
        ),
        (
            "total input too large",
            json!(vec!["x".repeat(8_192); 9]),
            "Total input too large (max 65536 chars).",
        ),
    ];

    for (name, input, message) in cases {
        let server = spawn(script(json!({ "embed": { "kind": "dimensioned" } }))).await;
        let response = server
            .send(&RequestSpec::post(
                "/v1/embeddings",
                "operator-token",
                json!({ "model": "openclaw", "input": input }),
            ))
            .await;

        assert_eq!(response.status, 400, "{name} was not refused");
        let observed = observe(&response);
        assert_eq!(observed["body"]["error"]["type"], "invalid_request_error");
        assert_eq!(observed["body"]["error"]["message"], message, "{name}");
        assert!(
            server.runtime.embedding_requests().is_empty(),
            "{name} still reached the embedding provider"
        );
    }

    // The bounds are inclusive on the accepting side, so the refusals above are
    // limits rather than a blanket rejection of large requests.
    let server = spawn(script(json!({ "embed": { "kind": "dimensioned" } }))).await;
    let response = server
        .send(&RequestSpec::post(
            "/v1/embeddings",
            "operator-token",
            json!({ "model": "openclaw", "input": vec!["x"; 128] }),
        ))
        .await;
    assert_eq!(response.status, 200);
    assert_eq!(server.runtime.embedding_request().input.len(), 128);
}

/// An empty input list is accepted, which is pinned as a known difference.
#[tokio::test]
async fn embedding_empty_input_is_accepted_as_a_known_difference() {
    let run = run_fixture(FEATURE, "embeddings/empty_input_is_accepted.json").await;

    assert_eq!(run.observed["status"], 200);
    assert_eq!(run.observed["body"]["data"], json!([]));
    assert!(run.server.runtime.embedding_request().input.is_empty());
}

/// Every failure class keeps its own status, type and message.
#[tokio::test]
async fn embedding_errors_stay_classified_per_failure_class() {
    let mut observed = Vec::new();
    for name in [
        "error_unauthenticated",
        "error_scope_not_granted",
        "error_missing_model",
        "error_unknown_model",
        "error_invalid_input_type",
        "error_provider_rejected_input",
        "error_provider_unavailable",
        "error_provider_timeout",
    ] {
        let run = run_fixture(FEATURE, &format!("embeddings/{name}.json")).await;
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
    assert_eq!(status_of("error_missing_model"), 400);
    assert_eq!(status_of("error_unknown_model"), 400);
    assert_eq!(status_of("error_invalid_input_type"), 400);
    assert_eq!(
        status_of("error_provider_rejected_input"),
        400,
        "a provider-side input rejection must stay a client error"
    );
    assert_eq!(status_of("error_provider_unavailable"), 503);
    assert_eq!(status_of("error_provider_timeout"), 504);

    assert_error_contracts_are_distinct(&observed);
}

/// The wrong method is refused by the router, before any handler runs.
#[tokio::test]
async fn embedding_rejects_the_wrong_method_at_the_router() {
    let run = run_fixture(FEATURE, "embeddings/error_wrong_method.json").await;

    assert_eq!(run.observed["status"], 405);
    let allow = run.observed["headers"]["allow"]
        .as_str()
        .expect("a 405 must advertise the accepted methods")
        .split(',')
        .map(str::trim)
        .map(str::to_owned)
        .collect::<Vec<_>>();
    assert!(allow.contains(&"POST".to_owned()), "Allow was {allow:?}");
    assert!(run.server.runtime.embedding_requests().is_empty());
}

//! Golden contract tests for the OpenAI-compatible models API.
//!
//! Evidence for ledger row `interop.openai.models`, whose acceptance text reads:
//! *List and retrieve model endpoint tests match pinned filtering, identifiers,
//! and errors.*

mod openai_support;

use openai_support::{
    RequestSpec, assert_error_contracts_are_distinct, observe, run_fixture, spawn,
};
use serde_json::{Value, json};

/// Ledger row every fixture in this file is evidence for.
const FEATURE: &str = "interop.openai.models";

#[tokio::test]
async fn model_list_publishes_only_configured_openclaw_identifiers() {
    let run = run_fixture(FEATURE, "models/list.json").await;
    let body = &run.observed["body"];

    let identifiers = body["data"]
        .as_array()
        .expect("model list data")
        .iter()
        .map(|model| model["id"].as_str().expect("model id").to_owned())
        .collect::<Vec<_>>();
    assert_eq!(
        identifiers,
        vec![
            "openclaw",
            "openclaw/default",
            "openclaw/main",
            "openclaw/research"
        ],
        "the model list is not the configured agent set"
    );
    assert!(
        !identifiers.iter().any(|id| id.contains("secret-internal")),
        "a provider-advertised identifier leaked past the OpenClaw naming filter"
    );
}

#[tokio::test]
async fn duplicate_agent_configuration_is_collapsed_into_one_identifier() {
    let server = spawn(openai_support::script(json!({
        "agents": ["default", "main", "main"]
    })))
    .await;
    let response = server
        .send(&RequestSpec::get("/v1/models", "operator-token"))
        .await;

    assert_eq!(response.status, 200);
    let identifiers = response.json()["data"]
        .as_array()
        .expect("model list data")
        .iter()
        .map(|model| model["id"].as_str().expect("model id").to_owned())
        .collect::<Vec<_>>();
    assert_eq!(
        identifiers,
        vec!["openclaw", "openclaw/default", "openclaw/main"],
        "repeated agent identifiers were not de-duplicated"
    );
}

#[tokio::test]
async fn model_retrieve_returns_the_pinned_model_resource() {
    let run = run_fixture(FEATURE, "models/retrieve.json").await;
    assert_eq!(run.observed["body"]["object"], "model");
    assert_eq!(run.observed["body"]["id"], "openclaw/main");
}

#[tokio::test]
async fn read_scope_alone_is_sufficient_for_both_model_endpoints() {
    let server = spawn(openai_support::script(json!({}))).await;

    let list = server
        .send(&RequestSpec::get("/v1/models", "read-token"))
        .await;
    let retrieve = server
        .send(&RequestSpec::get("/v1/models/openclaw", "read-token"))
        .await;

    assert_eq!(
        list.status, 200,
        "a read-scoped operator cannot list models"
    );
    assert_eq!(
        retrieve.status, 200,
        "a read-scoped operator cannot retrieve a model"
    );
}

#[tokio::test]
async fn model_endpoints_classify_every_failure_distinctly() {
    let fixtures = [
        "models/error_unauthenticated.json",
        "models/error_scope_not_granted.json",
        "models/error_role_not_authorized.json",
        "models/error_malformed_identifier.json",
        "models/error_unknown_identifier.json",
        "models/error_provider_unavailable.json",
    ];
    let mut observed = Vec::new();
    for fixture in fixtures {
        let run = run_fixture(FEATURE, fixture).await;
        observed.push((fixture.to_owned(), run.observed));
    }

    let statuses = observed
        .iter()
        .map(|(_, value)| value["status"].as_u64().expect("status"))
        .collect::<Vec<_>>();
    assert_eq!(statuses, vec![401, 403, 403, 400, 404, 503]);

    // The two 403s share a status but must not share a reason.
    let scope_denied = &observed[1].1["body"]["error"]["message"];
    let role_denied = &observed[2].1["body"]["error"]["message"];
    assert_eq!(scope_denied, "missing scope: operator.read");
    assert_eq!(role_denied, "missing scope: operator.read");

    let classified = observed
        .iter()
        .filter(|(name, _)| !name.contains("role_not_authorized"))
        .cloned()
        .collect::<Vec<(String, Value)>>();
    assert_error_contracts_are_distinct(&classified);
}

#[tokio::test]
async fn model_endpoints_reject_the_wrong_method_without_reaching_the_handler() {
    let server = spawn(openai_support::script(json!({}))).await;
    let mut request = RequestSpec::get("/v1/models", "operator-token");
    request.method = "POST".to_owned();

    let response = server.send(&request).await;
    let observed = observe(&response);

    assert_eq!(observed["status"], 405);
    let allowed = observed["headers"]["allow"]
        .as_str()
        .expect("405 responses carry Allow")
        .split(',')
        .map(str::trim)
        .collect::<Vec<_>>();
    assert!(allowed.contains(&"GET"), "Allow omitted the bound method");
    assert!(
        !allowed.contains(&"POST"),
        "Allow advertised the method that was just refused"
    );
}

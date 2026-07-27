//! Golden coverage for `interop.openai.tools-invoke`.
//!
//! The acceptance row requires authenticated `/tools/invoke` schema, policy,
//! result and error tests. Each of those four obligations is pinned below
//! against a fixture in `tests/fixtures/openai/tools_invoke/`, with a scripted
//! tool port standing in for any real tool runtime.

mod openai_support;

use openai_support::{
    RequestSpec, assert_error_contracts_are_distinct, observe, run_fixture, script, spawn,
};
use serde_json::json;

/// Ledger row this file is evidence for.
const FEATURE: &str = "interop.openai.tools-invoke";

/// A successful invocation matches the pinned success envelope.
#[tokio::test]
async fn tool_invocation_matches_the_pinned_success_contract() {
    let run = run_fixture(FEATURE, "tools_invoke/success_echo.json").await;

    assert_eq!(run.observed["status"], 200);
    assert_eq!(run.observed["body"]["ok"], true);
    assert_eq!(
        run.observed["body"]["result"],
        json!({ "message": "hello", "count": 2 })
    );

    let invocation = run.server.runtime.tool_invocation();
    assert_eq!(invocation.name, "echo");
    assert_eq!(
        invocation.arguments,
        json!({ "message": "hello", "count": 2 })
    );
    assert_eq!(invocation.action, None);
}

/// The full request schema reaches the tool port.
#[tokio::test]
async fn tool_invocation_schema_reaches_the_tool_port() {
    let run = run_fixture(FEATURE, "tools_invoke/schema_full_request.json").await;

    let invocation = run.server.runtime.tool_invocation();
    assert_eq!(invocation.name, "echo");
    assert_eq!(invocation.arguments, json!({ "message": "hello" }));
    assert_eq!(invocation.action.as_deref(), Some("run"));
    assert_eq!(
        invocation.context.session_key.as_deref(),
        Some("session-from-body")
    );
    assert_eq!(
        invocation.context.agent_id.as_deref(),
        Some("agent-from-body")
    );
    assert_eq!(
        invocation.context.idempotency_key.as_deref(),
        Some("idem-1")
    );
    assert!(
        invocation.context.dry_run,
        "dryRun must reach the tool, otherwise a rehearsal would execute for real"
    );
}

/// The legacy `tool` alias and an absent `args` object are both accepted.
#[tokio::test]
async fn tool_invocation_accepts_the_legacy_name_alias() {
    let run = run_fixture(FEATURE, "tools_invoke/schema_tool_alias.json").await;

    assert_eq!(run.observed["status"], 200);
    let invocation = run.server.runtime.tool_invocation();
    assert_eq!(invocation.name, "echo");
    assert_eq!(
        invocation.arguments,
        json!({}),
        "an absent args object must become an empty object, not null"
    );
    assert!(!invocation.context.dry_run);
    assert_eq!(invocation.context.idempotency_key, None);
}

/// Header-supplied context is honoured, and body fields win over headers.
#[tokio::test]
async fn tool_invocation_context_comes_from_headers_with_the_body_winning() {
    let run = run_fixture(FEATURE, "tools_invoke/schema_header_context.json").await;

    let context = run.server.runtime.tool_invocation().context;
    assert_eq!(
        context.session_key.as_deref(),
        Some("session-from-body"),
        "the body must win over the matching header"
    );
    assert_eq!(
        context.agent_id.as_deref(),
        Some("agent-from-header"),
        "a header must be honoured when the body omits the field"
    );
    assert_eq!(context.message_channel.as_deref(), Some("channel-1"));
    assert_eq!(context.account_id.as_deref(), Some("account-1"));
    assert_eq!(context.agent_to.as_deref(), Some("recipient-1"));
    assert_eq!(context.agent_thread_id.as_deref(), Some("thread-1"));
}

/// Ownership is asserted rather than derived, which is pinned as a difference.
///
/// The adapter reports every HTTP caller as the session owner. That is a real
/// difference worth naming: a future change that derives ownership from the
/// authenticated principal has to update this test deliberately.
#[tokio::test]
async fn tool_invocation_ownership_is_pinned_as_a_known_constant() {
    for token in ["operator-token", "write-token"] {
        let server = spawn(script(json!({ "tool": { "kind": "echo" } }))).await;
        let response = server
            .send(&RequestSpec::post(
                "/tools/invoke",
                token,
                json!({ "name": "echo", "args": {} }),
            ))
            .await;
        assert_eq!(response.status, 200);
        assert!(
            server.runtime.tool_invocation().context.sender_is_owner,
            "{token} was not reported as the session owner"
        );
    }
}

/// Policy outcomes are passed through with their status and flags.
#[tokio::test]
async fn tool_policy_outcomes_are_passed_through_verbatim() {
    let approval = run_fixture(FEATURE, "tools_invoke/policy_requires_approval.json").await;
    assert_eq!(approval.observed["status"], 403);
    assert_eq!(approval.observed["body"]["ok"], false);
    assert_eq!(
        approval.observed["body"]["error"],
        json!({
            "type": "approval_required",
            "message": "operator approval is required for this tool",
            "requiresApproval": true
        })
    );

    let denied = run_fixture(FEATURE, "tools_invoke/policy_denied.json").await;
    assert_eq!(denied.observed["status"], 403);
    assert_eq!(denied.observed["body"]["error"]["type"], "policy_denied");
    assert!(
        denied.observed["body"]["error"]
            .get("requiresApproval")
            .is_none(),
        "a denial that cannot be escalated must not advertise an approval path"
    );
}

/// Successful results carry the tool's own status and payload.
#[tokio::test]
async fn tool_results_carry_the_tool_status_and_payload() {
    let queued = run_fixture(FEATURE, "tools_invoke/result_status_passthrough.json").await;
    assert_eq!(
        queued.observed["status"], 202,
        "the tool's own success status must survive"
    );
    assert_eq!(queued.observed["body"]["ok"], true);
    assert_eq!(
        queued.observed["body"]["result"],
        json!({ "queued": true, "jobId": "job-7" })
    );

    let empty = run_fixture(FEATURE, "tools_invoke/result_absent.json").await;
    assert_eq!(empty.observed["status"], 200);
    assert_eq!(empty.observed["body"]["ok"], true);
    assert_eq!(
        empty.observed["body"]["result"],
        json!(null),
        "the result key must exist even when the tool produced nothing"
    );
}

/// Every failure class keeps its own status and message.
#[tokio::test]
async fn tool_errors_stay_classified_per_failure_class() {
    let mut observed = Vec::new();
    for name in [
        "error_unauthenticated",
        "error_scope_not_granted",
        "error_missing_name",
        "error_tool_not_found",
        "error_invalid_arguments",
        "error_tool_unavailable",
        "error_tool_timeout",
        "error_tool_internal",
    ] {
        let run = run_fixture(FEATURE, &format!("tools_invoke/{name}.json")).await;
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
    assert_eq!(status_of("error_missing_name"), 400);
    assert_eq!(status_of("error_invalid_arguments"), 400);
    assert_eq!(status_of("error_tool_not_found"), 404);
    assert_eq!(status_of("error_tool_internal"), 500);
    assert_eq!(status_of("error_tool_unavailable"), 503);
    assert_eq!(status_of("error_tool_timeout"), 504);

    assert_error_contracts_are_distinct(&observed);
}

/// A blank tool name is refused exactly like a missing one.
#[tokio::test]
async fn tool_invocation_refuses_a_blank_name() {
    let run = run_fixture(FEATURE, "tools_invoke/error_blank_name.json").await;

    assert_eq!(run.observed["status"], 400);
    assert_eq!(run.observed["body"]["error"]["type"], "invalid_request");
    assert!(
        run.server.runtime.tool_invocations().is_empty(),
        "a blank name still reached the tool port"
    );
}

/// A non-operator principal is refused without leaking why.
#[tokio::test]
async fn tool_invocation_refuses_non_operator_principals() {
    let role = run_fixture(FEATURE, "tools_invoke/error_role_not_authorized.json").await;
    let scope = run_fixture(FEATURE, "tools_invoke/error_scope_not_granted.json").await;

    assert_eq!(role.observed["status"], 403);
    assert_eq!(
        role.observed["body"], scope.observed["body"],
        "the wrong role and a missing scope must be indistinguishable to the caller"
    );
    assert!(
        role.server.runtime.tool_invocations().is_empty(),
        "an unauthorized role still reached the tool port"
    );
}

/// Authentication is refused before the tool port is reached.
#[tokio::test]
async fn tool_invocation_refuses_unauthenticated_callers_before_the_tool_port() {
    let server = spawn(script(json!({ "tool": { "kind": "echo" } }))).await;

    let mut request = RequestSpec::post(
        "/tools/invoke",
        "operator-token",
        json!({ "name": "echo", "args": {} }),
    );
    request.token = None;
    let response = server.send(&request).await;

    assert_eq!(response.status, 401);
    assert_eq!(observe(&response)["body"]["error"]["type"], "unauthorized");
    assert!(
        server.runtime.tool_invocations().is_empty(),
        "an unauthenticated request reached the tool port"
    );
}

/// The wrong method is refused by the router, before any handler runs.
#[tokio::test]
async fn tool_invocation_rejects_the_wrong_method_at_the_router() {
    let run = run_fixture(FEATURE, "tools_invoke/error_wrong_method.json").await;

    assert_eq!(run.observed["status"], 405);
    let allow = run.observed["headers"]["allow"]
        .as_str()
        .expect("a 405 must advertise the accepted methods")
        .split(',')
        .map(str::trim)
        .map(str::to_owned)
        .collect::<Vec<_>>();
    assert!(allow.contains(&"POST".to_owned()), "Allow was {allow:?}");
    assert!(run.server.runtime.tool_invocations().is_empty());
}

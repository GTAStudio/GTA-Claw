//! Secret-authenticated task-flow webhook surface.

use axum::extract::{Path, Request, State};
use axum::http::StatusCode;
use axum::response::Response;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;
use tokio::time::timeout;
use tokio_util::sync::CancellationToken;

use crate::auth::bearer_token;
use crate::error::ApiError;
use crate::http_support::{CancelOnDrop, json_response, read_json_value, rejected_response};
use crate::state::ApiState;

const ACTIONS: [&str; 13] = [
    "create_flow",
    "get_flow",
    "list_flows",
    "find_latest_flow",
    "resolve_flow",
    "get_task_summary",
    "set_waiting",
    "resume_flow",
    "finish_flow",
    "fail_flow",
    "request_cancel",
    "cancel_flow",
    "run_task",
];

pub(crate) async fn invoke(
    State(state): State<ApiState>,
    Path(route_id): Path<String>,
    request: Request,
) -> Result<Response, ApiError> {
    let Some(route) = state.inner.config.webhooks.get(&route_id) else {
        return Ok(rejected_response(
            request,
            state.inner.config.limits.webhook_body_bytes,
            state.inner.config.limits.body_timeout,
            (StatusCode::NOT_FOUND, "not found"),
        )
        .await);
    };
    let presented = bearer_token(request.headers())
        .or_else(|| {
            request
                .headers()
                .get("x-openclaw-webhook-secret")
                .and_then(|value| value.to_str().ok())
                .map(str::trim)
        })
        .unwrap_or("");
    let digest: [u8; 32] = Sha256::digest(presented.as_bytes()).into();
    if presented.is_empty() || !bool::from(route.secret_digest.ct_eq(&digest)) {
        return Ok(rejected_response(
            request,
            state.inner.config.limits.webhook_body_bytes,
            state.inner.config.limits.body_timeout,
            (StatusCode::UNAUTHORIZED, "unauthorized"),
        )
        .await);
    }
    let limits = &state.inner.config.limits;
    let value = read_json_value(request, limits.webhook_body_bytes, limits.body_timeout)
        .await
        .map_err(|error| webhook_error(error.status, "invalid_request", "invalid request body"))?;
    let action = value
        .as_object()
        .and_then(|object| object.get("action"))
        .and_then(Value::as_str)
        .filter(|action| ACTIONS.contains(action))
        .ok_or_else(|| {
            webhook_error(
                StatusCode::BAD_REQUEST,
                "invalid_request",
                "action: invalid request",
            )
        })?;
    validate_action(action, &value)?;
    let cancellation = CancellationToken::new();
    let _cancel_on_drop = CancelOnDrop::new(&cancellation);
    let outcome = timeout(
        limits.operation_timeout,
        state
            .inner
            .services
            .webhooks
            .invoke(route_id.clone(), value, cancellation),
    )
    .await
    .map_err(|_| {
        webhook_error(
            StatusCode::SERVICE_UNAVAILABLE,
            "unavailable",
            "request timed out",
        )
    })?
    .map_err(|_| {
        webhook_error(
            StatusCode::SERVICE_UNAVAILABLE,
            "unavailable",
            "request failed",
        )
    })?;
    let status = StatusCode::from_u16(outcome.status).unwrap_or(StatusCode::INTERNAL_SERVER_ERROR);
    let body = if status.is_success() || status == StatusCode::ACCEPTED {
        let mut body = json!({
            "ok":true,
            "routeId":route_id,
            "result":outcome.result
        });
        if let Some(code) = outcome.code {
            body["code"] = json!(code);
        }
        body
    } else {
        json!({
            "ok":false,
            "routeId":route_id,
            "code":outcome.code.unwrap_or_else(||"request_rejected".to_owned()),
            "error":outcome.error.unwrap_or_else(||"request rejected".to_owned()),
            "result":outcome.result
        })
    };
    Ok(json_response(status, &body))
}

fn validate_action(action: &str, value: &Value) -> Result<(), ApiError> {
    let object = value.as_object().expect("action was read from object");
    let require_string = |field: &str| {
        object
            .get(field)
            .and_then(Value::as_str)
            .is_some_and(|value| !value.trim().is_empty())
    };
    let optional_string = |field: &str, nullable: bool| {
        object.get(field).is_none_or(|value| {
            (nullable && value.is_null())
                || value.as_str().is_some_and(|value| !value.trim().is_empty())
        })
    };
    let optional_u64 = |field: &str| {
        object
            .get(field)
            .is_none_or(|value| value.as_u64().is_some())
    };
    let optional_bool = |field: &str| {
        object
            .get(field)
            .is_none_or(|value| value.as_bool().is_some())
    };
    let optional_enum = |field: &str, allowed: &[&str]| {
        object
            .get(field)
            .is_none_or(|value| value.as_str().is_some_and(|value| allowed.contains(&value)))
    };
    let only = |allowed: &[&str]| object.keys().all(|field| allowed.contains(&field.as_str()));
    let valid = match action {
        "create_flow" => {
            only(&[
                "action",
                "controllerId",
                "goal",
                "status",
                "notifyPolicy",
                "currentStep",
                "stateJson",
                "waitJson",
            ]) && require_string("goal")
                && optional_string("controllerId", false)
                && optional_enum("status", &["queued", "running", "waiting", "blocked"])
                && optional_enum("notifyPolicy", &["done_only", "state_changes", "silent"])
                && optional_string("currentStep", true)
        }
        "get_flow" | "get_task_summary" | "cancel_flow" => {
            only(&["action", "flowId"]) && require_string("flowId")
        }
        "list_flows" | "find_latest_flow" => only(&["action"]),
        "resolve_flow" => only(&["action", "token"]) && require_string("token"),
        "set_waiting" => {
            only(&[
                "action",
                "flowId",
                "expectedRevision",
                "currentStep",
                "stateJson",
                "waitJson",
                "blockedTaskId",
                "blockedSummary",
            ]) && require_string("flowId")
                && object
                    .get("expectedRevision")
                    .and_then(Value::as_u64)
                    .is_some()
                && optional_string("currentStep", true)
                && optional_string("blockedTaskId", true)
                && optional_string("blockedSummary", true)
        }
        "resume_flow" => {
            only(&[
                "action",
                "flowId",
                "expectedRevision",
                "status",
                "currentStep",
                "stateJson",
            ]) && require_string("flowId")
                && object
                    .get("expectedRevision")
                    .and_then(Value::as_u64)
                    .is_some()
                && optional_enum("status", &["queued", "running"])
                && optional_string("currentStep", true)
        }
        "finish_flow" => {
            only(&["action", "flowId", "expectedRevision", "stateJson"])
                && require_string("flowId")
                && object
                    .get("expectedRevision")
                    .and_then(Value::as_u64)
                    .is_some()
        }
        "fail_flow" => {
            only(&[
                "action",
                "flowId",
                "expectedRevision",
                "stateJson",
                "blockedTaskId",
                "blockedSummary",
            ]) && require_string("flowId")
                && object
                    .get("expectedRevision")
                    .and_then(Value::as_u64)
                    .is_some()
                && optional_string("blockedTaskId", true)
                && optional_string("blockedSummary", true)
        }
        "request_cancel" => {
            only(&["action", "flowId", "expectedRevision"])
                && require_string("flowId")
                && object
                    .get("expectedRevision")
                    .and_then(Value::as_u64)
                    .is_some()
        }
        "run_task" => {
            only(&[
                "action",
                "flowId",
                "runtime",
                "sourceId",
                "childSessionKey",
                "parentTaskId",
                "agentId",
                "runId",
                "label",
                "task",
                "preferMetadata",
                "notifyPolicy",
                "status",
                "startedAt",
                "lastEventAt",
                "progressSummary",
            ]) && require_string("flowId")
                && require_string("task")
                && matches!(
                    object.get("runtime").and_then(Value::as_str),
                    Some("subagent" | "acp")
                )
                && [
                    "sourceId",
                    "childSessionKey",
                    "parentTaskId",
                    "agentId",
                    "runId",
                    "label",
                ]
                .iter()
                .all(|field| optional_string(field, false))
                && optional_bool("preferMetadata")
                && optional_enum("notifyPolicy", &["done_only", "state_changes", "silent"])
                && optional_enum("status", &["queued", "running"])
                && optional_u64("startedAt")
                && optional_u64("lastEventAt")
                && optional_string("progressSummary", true)
                && (object.get("status").and_then(Value::as_str) == Some("running")
                    || (!object.contains_key("startedAt")
                        && !object.contains_key("lastEventAt")
                        && !object.contains_key("progressSummary")))
        }
        _ => false,
    };
    if valid {
        Ok(())
    } else {
        Err(webhook_error(
            StatusCode::BAD_REQUEST,
            "invalid_request",
            "invalid request",
        ))
    }
}

fn webhook_error(status: StatusCode, code: &str, message: &str) -> ApiError {
    ApiError {
        status,
        body: json!({"ok":false,"code":code,"error":message}),
        allow: None,
    }
}

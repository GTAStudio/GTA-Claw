//! `OpenClaw` `/tools/invoke` HTTP adapter.

use axum::extract::{Extension, Request, State};
use axum::http::StatusCode;
use axum::response::Response;
use claw_security::authorization::Role;
use serde_json::{Map, Value, json};
use tokio::time::timeout;
use tokio_util::sync::CancellationToken;

use crate::auth::{Principal, authorize_tool_access};
use crate::error::ApiError;
use crate::http_support::{CancelOnDrop, json_response, read_json_value};
use crate::ports::{PortErrorKind, ToolInvocation, ToolInvocationContext, ToolOutcome};
use crate::state::ApiState;

pub(crate) async fn invoke(
    State(state): State<ApiState>,
    Extension(principal): Extension<Principal>,
    request: Request,
) -> Result<Response, ApiError> {
    let limits = &state.inner.config.limits;
    let invocation_context = ToolInvocationContext {
        session_key: optional_body_string_from_request(&request, "x-openclaw-session-key"),
        agent_id: optional_body_string_from_request(&request, "x-openclaw-agent-id"),
        idempotency_key: None,
        message_channel: optional_body_string_from_request(&request, "x-openclaw-message-channel"),
        account_id: optional_body_string_from_request(&request, "x-openclaw-account-id"),
        agent_to: optional_body_string_from_request(&request, "x-openclaw-message-to"),
        agent_thread_id: optional_body_string_from_request(&request, "x-openclaw-thread-id"),
        sender_is_owner: principal.role == Role::Owner,
        authenticated_role: principal.role,
        authenticated_scopes: principal.scopes,
        dry_run: false,
    };
    let value = read_json_value(request, limits.tools_body_bytes, limits.body_timeout).await?;
    let body = value.as_object().cloned().unwrap_or_default();
    let name = body
        .get("name")
        .or_else(|| body.get("tool"))
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|name| !name.is_empty())
        .ok_or_else(|| {
            ApiError::openai(
                StatusCode::BAD_REQUEST,
                "tools.invoke requires name",
                "invalid_request",
            )
        })?
        .to_owned();
    authorize_tool_access(
        principal,
        principal.role == Role::Owner,
        state.inner.services.tools.access(&name),
        state.inner.services.audit.as_ref(),
    )?;
    let arguments = body
        .get("args")
        .and_then(Value::as_object)
        .cloned()
        .unwrap_or_default();
    let mut context = invocation_context;
    context.session_key = body_string(&body, "sessionKey").or(context.session_key);
    context.agent_id = body_string(&body, "agentId").or(context.agent_id);
    context.idempotency_key = body_string(&body, "idempotencyKey");
    context.dry_run = body.get("dryRun").and_then(Value::as_bool).unwrap_or(false);
    let invocation = ToolInvocation {
        name,
        arguments: Value::Object(arguments),
        action: body_string(&body, "action"),
        context,
    };
    let cancellation = CancellationToken::new();
    let _cancel_on_drop = CancelOnDrop::new(&cancellation);
    let outcome = timeout(
        limits.operation_timeout,
        state.inner.services.tools.invoke(invocation, cancellation),
    )
    .await
    .map_err(|_| {
        ApiError::openai(
            StatusCode::GATEWAY_TIMEOUT,
            "tool execution timed out",
            "tool_error",
        )
    })?
    .map_err(|error| {
        let (status, error_type) = match error.kind {
            PortErrorKind::InvalidRequest => (StatusCode::BAD_REQUEST, "tool_error"),
            PortErrorKind::NotFound => (StatusCode::NOT_FOUND, "tool_error"),
            PortErrorKind::Unavailable => (StatusCode::SERVICE_UNAVAILABLE, "tool_error"),
            PortErrorKind::Timeout => (StatusCode::GATEWAY_TIMEOUT, "tool_error"),
            PortErrorKind::CommittedButNotDurable => {
                (StatusCode::CONFLICT, "committed_but_not_durable")
            }
            PortErrorKind::Internal => (StatusCode::INTERNAL_SERVER_ERROR, "tool_error"),
        };
        ApiError::openai(status, error.message, error_type)
    })?;
    Ok(tool_response(outcome))
}

fn optional_body_string_from_request(request: &Request, name: &str) -> Option<String> {
    request
        .headers()
        .get(name)
        .and_then(|value| value.to_str().ok())
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(str::to_owned)
}

fn body_string(body: &Map<String, Value>, name: &str) -> Option<String> {
    body.get(name)
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(str::to_owned)
}

fn tool_response(outcome: ToolOutcome) -> Response {
    let status = StatusCode::from_u16(outcome.status).unwrap_or(StatusCode::INTERNAL_SERVER_ERROR);
    if outcome.ok {
        return json_response(
            status,
            &json!({"ok":true,"result":outcome.result.unwrap_or(Value::Null)}),
        );
    }
    let mut error = Map::new();
    error.insert(
        "type".to_owned(),
        Value::String(
            outcome
                .error_type
                .unwrap_or_else(|| "tool_error".to_owned()),
        ),
    );
    error.insert(
        "message".to_owned(),
        Value::String(
            outcome
                .error_message
                .unwrap_or_else(|| "tool execution failed".to_owned()),
        ),
    );
    if let Some(requires_approval) = outcome.requires_approval {
        error.insert(
            "requiresApproval".to_owned(),
            Value::Bool(requires_approval),
        );
    }
    json_response(status, &json!({"ok":false,"error":error}))
}

//! Authenticated, allowlisted Admin HTTP RPC.

use axum::extract::{Extension, Request, State};
use axum::http::{HeaderValue, StatusCode, header};
use axum::response::Response;
use claw_protocol::gateway::{MethodScope, PluginLookup, resolve_gateway_method};
use serde_json::{Value, json};
use tokio::time::timeout;
use tokio_util::sync::CancellationToken;

use crate::auth::{Principal, authorize_scope, protocol_scope_to_security};
use crate::error::ApiError;
use crate::http_support::{CancelOnDrop, json_response, read_json_value};
use crate::ports::{AdminFailure, AdminSuccess};
use crate::state::ApiState;

/// Exact frozen upstream Admin HTTP RPC allowlist.
pub const ADMIN_HTTP_RPC_METHODS: &[&str] = &[
    "health",
    "status",
    "logs.tail",
    "usage.status",
    "usage.cost",
    "gateway.restart.request",
    "gateway.suspend.prepare",
    "gateway.suspend.status",
    "gateway.suspend.resume",
    "commands.list",
    "config.get",
    "config.schema",
    "config.schema.lookup",
    "config.set",
    "config.patch",
    "config.apply",
    "channels.status",
    "channels.start",
    "channels.stop",
    "channels.logout",
    "web.login.start",
    "web.login.wait",
    "models.list",
    "models.authStatus",
    "agents.list",
    "agents.create",
    "agents.update",
    "agents.delete",
    "exec.approvals.get",
    "exec.approvals.set",
    "exec.approvals.node.get",
    "exec.approvals.node.set",
    "cron.status",
    "cron.list",
    "cron.get",
    "cron.runs",
    "cron.add",
    "cron.update",
    "cron.remove",
    "cron.run",
    "device.pair.list",
    "device.pair.approve",
    "device.pair.reject",
    "device.pair.remove",
    "node.list",
    "node.describe",
    "node.pair.list",
    "node.pair.approve",
    "node.pair.reject",
    "node.pair.remove",
    "node.rename",
    "tasks.list",
    "tasks.get",
    "tasks.cancel",
    "doctor.memory.status",
    "update.status",
];

pub(crate) async fn rpc(
    State(state): State<ApiState>,
    Extension(principal): Extension<Principal>,
    request: Request,
) -> Result<Response, ApiError> {
    let limits = &state.inner.config.limits;
    let value = read_json_value(request, limits.admin_body_bytes, limits.body_timeout)
        .await
        .map_err(|error| map_body_error(&error))?;
    let object = value.as_object().ok_or_else(|| {
        admin_error(
            StatusCode::BAD_REQUEST,
            "invalid_request",
            "request body must be an object",
        )
    })?;
    let method = object
        .get("method")
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|method| !method.is_empty())
        .ok_or_else(|| {
            admin_error(
                StatusCode::BAD_REQUEST,
                "invalid_request",
                "method must be a non-empty string",
            )
        })?
        .to_owned();
    let id = object
        .get("id")
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|id| !id.is_empty())
        .map_or_else(|| state.id("rpc"), str::to_owned);
    if !ADMIN_HTTP_RPC_METHODS.contains(&method.as_str()) {
        return Ok(admin_response(
            StatusCode::BAD_REQUEST,
            &json!({
                "id":id,
                "ok":false,
                "error":{
                    "code":"INVALID_REQUEST",
                    "message":format!("admin HTTP RPC method is not supported: {method}")
                }
            }),
        ));
    }
    let descriptor = resolve_gateway_method(&method, PluginLookup::Deny).map_err(|_| {
        admin_error(
            StatusCode::BAD_REQUEST,
            "invalid_request",
            "method is not in the frozen Gateway registry",
        )
    })?;
    let required = match descriptor.scope() {
        MethodScope::Operator(scope) => protocol_scope_to_security(scope),
        MethodScope::Dynamic | MethodScope::Node => {
            return Err(admin_error(
                StatusCode::FORBIDDEN,
                "forbidden",
                "method is not available to the trusted operator surface",
            ));
        }
    };
    authorize_scope(principal, required, state.inner.services.audit.as_ref())
        .map_err(|_| admin_error(StatusCode::FORBIDDEN, "forbidden", "Forbidden"))?;
    if method == "commands.list" {
        return Ok(admin_response(
            StatusCode::OK,
            &json!({"id":id,"ok":true,"payload":{"methods":ADMIN_HTTP_RPC_METHODS}}),
        ));
    }
    let params = object.get("params").cloned();
    let cancellation = CancellationToken::new();
    let _cancel_on_drop = CancelOnDrop::new(&cancellation);
    // `AdminFailure` is part of the frozen port surface, so the `Err` payload
    // cannot be boxed without changing the public API.
    #[expect(
        clippy::result_large_err,
        reason = "`AdminFailure` is a frozen public port type; boxing it here would change `AdminPort::dispatch`'s signature and the wire contract it feeds"
    )]
    let result = timeout(
        limits.operation_timeout,
        state
            .inner
            .services
            .admin
            .dispatch(method, params, cancellation),
    )
    .await
    .unwrap_or_else(|_| {
        Err(AdminFailure {
            code: "AGENT_TIMEOUT".to_owned(),
            message: "gateway method timed out".to_owned(),
            details: None,
            retryable: Some(true),
            retry_after_ms: None,
        })
    });
    match result {
        Ok(success) => Ok(admin_success_response(&id, success)),
        Err(failure) => Ok(admin_failure_response(&id, failure)),
    }
}

fn admin_success_response(id: &str, success: AdminSuccess) -> Response {
    let mut body = json!({"id":id,"ok":true,"payload":success.payload});
    if let Some(meta) = success.meta {
        body["meta"] = meta;
    }
    admin_response(StatusCode::OK, &body)
}

fn admin_failure_response(id: &str, failure: AdminFailure) -> Response {
    let status = match failure.code.as_str() {
        "INVALID_REQUEST" => StatusCode::BAD_REQUEST,
        "APPROVAL_NOT_FOUND" => StatusCode::NOT_FOUND,
        "UNAVAILABLE" => StatusCode::SERVICE_UNAVAILABLE,
        "AGENT_TIMEOUT" => StatusCode::GATEWAY_TIMEOUT,
        "NOT_LINKED" | "NOT_PAIRED" => StatusCode::CONFLICT,
        _ => StatusCode::INTERNAL_SERVER_ERROR,
    };
    let mut error = json!({"code":failure.code,"message":failure.message});
    if let Some(details) = failure.details {
        error["details"] = details;
    }
    if let Some(retryable) = failure.retryable {
        error["retryable"] = json!(retryable);
    }
    if let Some(retry_after_ms) = failure.retry_after_ms {
        error["retryAfterMs"] = json!(retry_after_ms);
    }
    admin_response(status, &json!({"id":id,"ok":false,"error":error}))
}

fn map_body_error(error: &ApiError) -> ApiError {
    let message = match error.status {
        StatusCode::PAYLOAD_TOO_LARGE => "Payload too large",
        StatusCode::REQUEST_TIMEOUT => "request body timed out",
        _ => "request body must be valid JSON",
    };
    admin_error(error.status, "invalid_request", message)
}

fn admin_error(status: StatusCode, kind: &str, message: &str) -> ApiError {
    ApiError {
        status,
        body: json!({"ok":false,"error":{"type":kind,"message":message}}),
        allow: None,
    }
}

fn admin_response(status: StatusCode, body: &Value) -> Response {
    let mut response = json_response(status, body);
    response
        .headers_mut()
        .insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    response
}

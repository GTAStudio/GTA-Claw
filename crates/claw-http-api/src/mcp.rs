//! Bearer-authenticated streamable HTTP MCP loopback endpoint.

use std::convert::Infallible;
use std::net::{IpAddr, SocketAddr};

use axum::extract::{ConnectInfo, Request, State};
use axum::http::{HeaderValue, Method, StatusCode, header};
use axum::response::sse::{Event, KeepAlive, Sse};
use axum::response::{IntoResponse, Response};
use serde_json::{Value, json};
use tokio::sync::mpsc;
use tokio::time::timeout;
use tokio_stream::wrappers::ReceiverStream;
use tokio_util::sync::CancellationToken;
use url::Url;

use crate::auth::bearer_token;
use crate::error::{ApiError, json_rpc_error};
use crate::http_support::{CancelOnDrop, json_response, read_json_value, rejected_response};
use crate::ports::{ToolInvocation, ToolInvocationContext, ToolOutcome};
use crate::state::ApiState;

const SUPPORTED_PROTOCOLS: [&str; 2] = ["2025-03-26", "2024-11-05"];

pub(crate) async fn handle(
    State(state): State<ApiState>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    request: Request,
) -> Result<Response, ApiError> {
    if !peer.ip().is_loopback() {
        return Ok(rejected_response(
            request,
            state.inner.config.limits.mcp_body_bytes,
            state.inner.config.limits.body_timeout,
            ApiError::simple(StatusCode::FORBIDDEN, "forbidden"),
        )
        .await);
    }
    if let Err(error) = validate_browser_origin(request.headers()) {
        return Ok(rejected_response(
            request,
            state.inner.config.limits.mcp_body_bytes,
            state.inner.config.limits.body_timeout,
            error,
        )
        .await);
    }
    let sender_is_owner = match authenticate(&state, request.headers()) {
        Ok(sender_is_owner) => sender_is_owner,
        Err(error) => {
            return Ok(rejected_response(
                request,
                state.inner.config.limits.mcp_body_bytes,
                state.inner.config.limits.body_timeout,
                error,
            )
            .await);
        }
    };
    match *request.method() {
        Method::GET => Ok(mcp_sse(&state)),
        Method::DELETE => Ok(json_response(StatusCode::OK, &json!({"ok":true}))),
        Method::POST => post(state, request, sender_is_owner).await,
        _ => Err(ApiError::method("GET, POST, DELETE")),
    }
}

fn validate_browser_origin(headers: &axum::http::HeaderMap) -> Result<(), ApiError> {
    let Some(origin) = headers
        .get(header::ORIGIN)
        .and_then(|value| value.to_str().ok())
    else {
        return Ok(());
    };
    let origin = Url::parse(origin)
        .map_err(|_| ApiError::simple(StatusCode::FORBIDDEN, "forbidden_origin"))?;
    let local = origin.host_str().is_some_and(|host| {
        host.eq_ignore_ascii_case("localhost")
            || host
                .parse::<IpAddr>()
                .is_ok_and(|address| address.is_loopback())
    });
    if local && matches!(origin.scheme(), "http" | "https") {
        Ok(())
    } else {
        Err(ApiError::simple(StatusCode::FORBIDDEN, "forbidden_origin"))
    }
}

fn authenticate(state: &ApiState, headers: &axum::http::HeaderMap) -> Result<bool, ApiError> {
    let token = bearer_token(headers).ok_or_else(unauthorized)?;
    if state
        .inner
        .config
        .mcp_owner_authenticator
        .authenticate_token(token)
        .is_some()
    {
        return Ok(true);
    }
    if state
        .inner
        .config
        .mcp_authenticator
        .authenticate_token(token)
        .is_some()
    {
        return Ok(false);
    }
    Err(unauthorized())
}

async fn post(
    state: ApiState,
    request: Request,
    sender_is_owner: bool,
) -> Result<Response, ApiError> {
    let content_type = request
        .headers()
        .get(header::CONTENT_TYPE)
        .and_then(|value| value.to_str().ok())
        .unwrap_or("");
    if !content_type.starts_with("application/json") {
        return Ok(rejected_response(
            request,
            state.inner.config.limits.mcp_body_bytes,
            state.inner.config.limits.body_timeout,
            json_response(
                StatusCode::UNSUPPORTED_MEDIA_TYPE,
                &json!({"error":"unsupported_media_type"}),
            ),
        )
        .await);
    }
    let limits = &state.inner.config.limits;
    let value = match read_json_value(request, limits.mcp_body_bytes, limits.body_timeout).await {
        Ok(value) => value,
        Err(error) if error.status == StatusCode::PAYLOAD_TOO_LARGE => {
            return Ok(json_response(
                StatusCode::PAYLOAD_TOO_LARGE,
                &json!({"error":"payload_too_large"}),
            ));
        }
        Err(error) if error.status == StatusCode::REQUEST_TIMEOUT => {
            return Ok(json_response(
                StatusCode::REQUEST_TIMEOUT,
                &json!({"error":"request_body_timeout"}),
            ));
        }
        Err(_) => {
            return Ok(json_response(
                StatusCode::BAD_REQUEST,
                &json_rpc_error(Value::Null, -32700, "Parse error"),
            ));
        }
    };
    let is_batch = value.is_array();
    let messages = match value {
        Value::Array(messages) if !messages.is_empty() => messages,
        Value::Array(_) => vec![Value::Null],
        message => vec![message],
    };
    let mut responses = Vec::new();
    for message in messages {
        if let Some(response) = handle_message(&state, message, sender_is_owner).await {
            responses.push(response);
        }
    }
    if responses.is_empty() {
        return Ok(json_response(StatusCode::ACCEPTED, &Value::Null));
    }
    let body = if is_batch {
        Value::Array(responses)
    } else {
        responses.into_iter().next().unwrap_or(Value::Null)
    };
    Ok(json_response(StatusCode::OK, &body))
}

async fn handle_message(state: &ApiState, message: Value, sender_is_owner: bool) -> Option<Value> {
    let Some(object) = message.as_object() else {
        return Some(json_rpc_error(Value::Null, -32600, "Invalid Request"));
    };
    let id = object
        .get("id")
        .filter(|id| id.is_null() || id.is_string() || id.is_number())
        .cloned()
        .unwrap_or(Value::Null);
    if object.get("jsonrpc").and_then(Value::as_str) != Some("2.0") {
        return Some(json_rpc_error(id, -32600, "Invalid Request"));
    }
    let Some(method) = object.get("method").and_then(Value::as_str) else {
        return Some(json_rpc_error(id, -32600, "Invalid Request"));
    };
    let params = object.get("params").and_then(Value::as_object);
    match method {
        "initialize" => {
            let requested = params
                .and_then(|params| params.get("protocolVersion"))
                .and_then(Value::as_str)
                .unwrap_or("");
            let protocol = SUPPORTED_PROTOCOLS
                .iter()
                .copied()
                .find(|protocol| *protocol == requested)
                .unwrap_or(SUPPORTED_PROTOCOLS[0]);
            Some(rpc_result(
                &id,
                &json!({
                    "protocolVersion":protocol,
                    "capabilities":{"tools":{}},
                    "serverInfo":{"name":"openclaw","version":"0.1.0"}
                }),
            ))
        }
        "notifications/initialized" | "notifications/cancelled" => None,
        "tools/list" => match timeout(
            state.inner.config.limits.operation_timeout,
            state.inner.services.tools.list(),
        )
        .await
        {
            Ok(Ok(tools)) => Some(rpc_result(&id, &json!({"tools":tools}))),
            _ => Some(json_rpc_error(id, -32603, "Internal error")),
        },
        "tools/call" => {
            let name = params
                .and_then(|params| params.get("name"))
                .and_then(Value::as_str)
                .map_or("", str::trim);
            let arguments = params
                .and_then(|params| params.get("arguments"))
                .cloned()
                .unwrap_or_else(|| json!({}));
            if !arguments.is_object() {
                return Some(json_rpc_error(
                    id,
                    -32602,
                    "Invalid params: tools/call arguments must be an object",
                ));
            }
            if name.is_empty() {
                return Some(rpc_result(
                    &id,
                    &tool_call_error("Tool not available: unknown"),
                ));
            }
            let cancellation = CancellationToken::new();
            let _cancel_on_drop = CancelOnDrop::new(&cancellation);
            match timeout(
                state.inner.config.limits.operation_timeout,
                state.inner.services.tools.invoke(
                    ToolInvocation {
                        name: name.to_owned(),
                        arguments,
                        action: None,
                        context: ToolInvocationContext {
                            session_key: None,
                            agent_id: None,
                            idempotency_key: None,
                            message_channel: None,
                            account_id: None,
                            agent_to: None,
                            agent_thread_id: None,
                            sender_is_owner,
                            dry_run: false,
                        },
                    },
                    cancellation,
                ),
            )
            .await
            {
                Ok(Ok(outcome)) => Some(rpc_result(&id, &mcp_tool_result(outcome))),
                Ok(Err(error)) => Some(rpc_result(&id, &tool_call_error(&error.message))),
                Err(_) => Some(rpc_result(
                    &id,
                    &tool_call_error("tool execution timed out"),
                )),
            }
        }
        _ => Some(json_rpc_error(
            id,
            -32601,
            format!("Method not found: {method}"),
        )),
    }
}

fn rpc_result(id: &Value, result: &Value) -> Value {
    json!({"jsonrpc":"2.0","id":id,"result":result})
}

fn mcp_tool_result(outcome: ToolOutcome) -> Value {
    if !outcome.ok {
        return tool_call_error(
            outcome
                .error_message
                .as_deref()
                .unwrap_or("tool execution failed"),
        );
    }
    let result = outcome.result.unwrap_or(Value::Null);
    let content = match result {
        Value::Object(ref object) if object.get("content").is_some_and(Value::is_array) => {
            object["content"].clone()
        }
        Value::String(text) => json!([{"type":"text","text":text}]),
        other => json!([{"type":"text","text":serde_json::to_string(&other).unwrap_or_default()}]),
    };
    json!({"content":content,"isError":false})
}

fn tool_call_error(message: &str) -> Value {
    json!({"content":[{"type":"text","text":message}],"isError":true})
}

fn mcp_sse(state: &ApiState) -> Response {
    let cancellation = CancellationToken::new();
    let producer_cancellation = cancellation.clone();
    let (sender, receiver) = mpsc::channel::<Result<Event, Infallible>>(1);
    tokio::spawn(async move {
        if sender.send(Ok(Event::default().comment(""))).await.is_ok() {
            producer_cancellation.cancelled().await;
        }
    });
    let stream = McpStream {
        inner: ReceiverStream::new(receiver),
        cancellation,
    };
    let mut response = Sse::new(stream)
        .keep_alive(
            KeepAlive::new()
                .interval(state.inner.config.limits.heartbeat_interval)
                .text(""),
        )
        .into_response();
    response.headers_mut().insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static("text/event-stream; charset=utf-8"),
    );
    response
}

struct McpStream {
    inner: ReceiverStream<Result<Event, Infallible>>,
    cancellation: CancellationToken,
}

impl futures_core::Stream for McpStream {
    type Item = Result<Event, Infallible>;

    fn poll_next(
        mut self: std::pin::Pin<&mut Self>,
        context: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Option<Self::Item>> {
        std::pin::Pin::new(&mut self.inner).poll_next(context)
    }
}

impl Drop for McpStream {
    fn drop(&mut self) {
        self.cancellation.cancel();
    }
}

fn unauthorized() -> ApiError {
    ApiError::simple(StatusCode::UNAUTHORIZED, "unauthorized")
}

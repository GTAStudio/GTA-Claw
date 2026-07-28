//! Typed HTTP errors and exact upstream response envelopes.

use axum::Json;
use axum::http::{HeaderValue, StatusCode, header};
use axum::response::{IntoResponse, Response};
use serde::Serialize;
use serde_json::{Value, json};

/// A safe client-facing HTTP failure.
#[derive(Clone, Debug)]
pub(crate) struct ApiError {
    pub(crate) status: StatusCode,
    pub(crate) body: Value,
    pub(crate) allow: Option<&'static str>,
}

impl ApiError {
    pub(crate) fn openai(status: StatusCode, message: impl Into<String>, kind: &str) -> Self {
        Self {
            status,
            body: json!({"error": {"message": message.into(), "type": kind}}),
            allow: None,
        }
    }

    pub(crate) fn simple(status: StatusCode, error: &str) -> Self {
        Self {
            status,
            body: json!({"error": error}),
            allow: None,
        }
    }

    pub(crate) fn method(allow: &'static str) -> Self {
        Self {
            status: StatusCode::METHOD_NOT_ALLOWED,
            body: json!({"error": {"message": "Method Not Allowed", "type": "method_not_allowed"}}),
            allow: Some(allow),
        }
    }

    pub(crate) fn forbidden(scope: &str) -> Self {
        Self {
            status: StatusCode::FORBIDDEN,
            body: json!({
                "ok": false,
                "error": {"type": "forbidden", "message": format!("missing scope: {scope}")}
            }),
            allow: None,
        }
    }
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        let mut response = (self.status, Json(self.body)).into_response();
        if matches!(
            self.status,
            StatusCode::PAYLOAD_TOO_LARGE | StatusCode::REQUEST_TIMEOUT
        ) {
            response
                .headers_mut()
                .insert(header::CONNECTION, HeaderValue::from_static("close"));
        }
        if let Some(allow) = self.allow {
            response
                .headers_mut()
                .insert(header::ALLOW, HeaderValue::from_static(allow));
        }
        response
    }
}

#[derive(Serialize)]
pub(crate) struct JsonRpcErrorBody {
    pub(crate) jsonrpc: &'static str,
    pub(crate) id: Value,
    pub(crate) error: JsonRpcErrorObject,
}

#[derive(Serialize)]
pub(crate) struct JsonRpcErrorObject {
    pub(crate) code: i32,
    pub(crate) message: String,
}

pub(crate) fn json_rpc_error(id: Value, code: i32, message: impl Into<String>) -> Value {
    serde_json::to_value(JsonRpcErrorBody {
        jsonrpc: "2.0",
        id,
        error: JsonRpcErrorObject {
            code,
            message: message.into(),
        },
    })
    .expect("JSON-RPC error is serializable")
}

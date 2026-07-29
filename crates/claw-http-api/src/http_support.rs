//! Shared bounded body and response helpers.

use std::time::Duration;

use axum::body::{Body, Bytes, to_bytes};
use axum::extract::Request;
use axum::http::StatusCode;
use axum::http::{HeaderValue, header};
use axum::response::{IntoResponse, Response};
use serde::de::DeserializeOwned;
use serde_json::Value;
use tokio::time::timeout;
use tokio_util::sync::CancellationToken;

use crate::error::ApiError;

const MAX_REJECTION_DRAIN_TIMEOUT: Duration = Duration::from_secs(1);

pub(crate) struct CancelOnDrop(CancellationToken);

impl CancelOnDrop {
    pub(crate) fn new(cancellation: &CancellationToken) -> Self {
        Self(cancellation.clone())
    }
}

impl Drop for CancelOnDrop {
    fn drop(&mut self) {
        self.0.cancel();
    }
}

pub(crate) async fn read_json_value(
    request: Request,
    max_bytes: usize,
    body_timeout: Duration,
) -> Result<Value, ApiError> {
    let bytes = read_body(request, max_bytes, body_timeout).await?;
    serde_json::from_slice(&bytes).map_err(|error| {
        ApiError::openai(
            StatusCode::BAD_REQUEST,
            format!("Invalid JSON: {error}"),
            "invalid_request_error",
        )
    })
}

pub(crate) async fn read_body(
    request: Request,
    max_bytes: usize,
    body_timeout: Duration,
) -> Result<Bytes, ApiError> {
    let bytes = timeout(body_timeout, to_bytes(request.into_body(), max_bytes))
        .await
        .map_err(|_| {
            ApiError::openai(
                StatusCode::REQUEST_TIMEOUT,
                "Request body timeout",
                "invalid_request_error",
            )
        })?
        .map_err(|_| {
            ApiError::openai(
                StatusCode::PAYLOAD_TOO_LARGE,
                "Payload too large",
                "invalid_request_error",
            )
        })?;
    if bytes.iter().all(u8::is_ascii_whitespace) {
        return Err(ApiError::openai(
            StatusCode::BAD_REQUEST,
            "request body must be JSON",
            "invalid_request_error",
        ));
    }
    Ok(bytes)
}

pub(crate) async fn drain_request_body(
    request: Request,
    max_bytes: usize,
    body_timeout: Duration,
) -> Result<(), ApiError> {
    timeout(body_timeout, to_bytes(request.into_body(), max_bytes))
        .await
        .map_err(|_| {
            ApiError::openai(
                StatusCode::REQUEST_TIMEOUT,
                "Request body timeout",
                "invalid_request_error",
            )
        })?
        .map_err(|_| {
            ApiError::openai(
                StatusCode::PAYLOAD_TOO_LARGE,
                "Payload too large",
                "invalid_request_error",
            )
        })?;
    Ok(())
}

pub(crate) async fn rejected_response(
    request: Request,
    max_bytes: usize,
    body_timeout: Duration,
    rejection: impl IntoResponse,
) -> Response {
    let drained = drain_request_body(
        request,
        max_bytes,
        body_timeout.min(MAX_REJECTION_DRAIN_TIMEOUT),
    )
    .await
    .is_ok();
    let response = rejection.into_response();
    if drained {
        response
    } else {
        close_connection_response(response)
    }
}

pub(crate) fn close_connection_response(response: impl IntoResponse) -> Response {
    let mut response = response.into_response();
    response
        .headers_mut()
        .insert(header::CONNECTION, HeaderValue::from_static("close"));
    response
}

pub(crate) async fn read_json<T: DeserializeOwned>(
    request: Request,
    max_bytes: usize,
    body_timeout: Duration,
) -> Result<T, ApiError> {
    let bytes = read_body(request, max_bytes, body_timeout).await?;
    serde_json::from_slice(&bytes).map_err(|error| {
        let message = match error.classify() {
            serde_json::error::Category::Data => without_json_location(&error),
            serde_json::error::Category::Syntax
            | serde_json::error::Category::Eof
            | serde_json::error::Category::Io => format!("Invalid JSON: {error}"),
        };
        ApiError::openai(StatusCode::BAD_REQUEST, message, "invalid_request_error")
    })
}

fn without_json_location(error: &serde_json::Error) -> String {
    let mut rendered = error.to_string();
    let suffix = format!(" at line {} column {}", error.line(), error.column());
    if rendered.ends_with(&suffix) {
        rendered.truncate(rendered.len() - suffix.len());
    }
    rendered
}

pub(crate) fn json_body(value: &Value) -> Body {
    Body::from(serde_json::to_vec(value).expect("JSON value is serializable"))
}

pub(crate) fn json_response(status: StatusCode, value: &Value) -> Response {
    let mut response = (status, json_body(value)).into_response();
    response.headers_mut().insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static("application/json; charset=utf-8"),
    );
    response
}

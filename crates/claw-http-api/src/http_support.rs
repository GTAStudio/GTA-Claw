//! Shared bounded body and response helpers.

use std::time::Duration;

use axum::body::{Body, to_bytes};
use axum::extract::Request;
use axum::http::StatusCode;
use axum::http::{HeaderValue, header};
use axum::response::{IntoResponse, Response};
use serde::de::DeserializeOwned;
use serde_json::Value;
use tokio::time::timeout;
use tokio_util::sync::CancellationToken;

use crate::error::ApiError;

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
    serde_json::from_slice(&bytes).map_err(|error| {
        ApiError::openai(
            StatusCode::BAD_REQUEST,
            format!("Invalid JSON: {error}"),
            "invalid_request_error",
        )
    })
}

pub(crate) async fn read_json<T: DeserializeOwned>(
    request: Request,
    max_bytes: usize,
    body_timeout: Duration,
) -> Result<T, ApiError> {
    let value = read_json_value(request, max_bytes, body_timeout).await?;
    serde_json::from_value(value).map_err(|error| {
        ApiError::openai(
            StatusCode::BAD_REQUEST,
            error.to_string(),
            "invalid_request_error",
        )
    })
}

pub(crate) fn json_body(value: &Value) -> Body {
    Body::from(serde_json::to_vec(value).expect("JSON value is serializable"))
}

pub(crate) fn json_response(status: StatusCode, value: Value) -> Response {
    let mut response = (status, json_body(&value)).into_response();
    response.headers_mut().insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static("application/json; charset=utf-8"),
    );
    response
}

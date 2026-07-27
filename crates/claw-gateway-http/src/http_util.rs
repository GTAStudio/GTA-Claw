//! Shared response helpers for the Gateway HTTP surface.

use std::sync::{Mutex, MutexGuard, PoisonError};

use axum::Json;
use axum::http::{HeaderValue, StatusCode, header};
use axum::response::{IntoResponse, Response};
use serde_json::Value;

/// Builds a JSON response that proxies and browsers must never cache.
pub(crate) fn json_response(status: StatusCode, body: Value) -> Response {
    let mut response = (status, Json(body)).into_response();
    response
        .headers_mut()
        .insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    response
}

/// Adds `Connection: close` so a load balancer sheds its keep-alive sockets.
pub(crate) fn close_connection(mut response: Response) -> Response {
    response
        .headers_mut()
        .insert(header::CONNECTION, HeaderValue::from_static("close"));
    response
}

/// Adds the `Retry-After` hint carried by a transient 503.
pub(crate) fn retry_after(mut response: Response, seconds: u32) -> Response {
    if let Ok(value) = HeaderValue::from_str(&seconds.to_string()) {
        response.headers_mut().insert(header::RETRY_AFTER, value);
    }
    response
}

/// Locks a mutex without ever panicking on a poisoned guard.
///
/// Every mutex in this crate guards plain bookkeeping, so a panic elsewhere
/// leaves the data structurally intact. Propagating the poison would turn one
/// unrelated panic into a permanently unavailable probe surface.
pub(crate) fn lock<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    mutex.lock().unwrap_or_else(PoisonError::into_inner)
}

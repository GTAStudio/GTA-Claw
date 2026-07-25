//! Liveness and dependency-backed readiness probes.

use axum::extract::{Request, State};
use axum::http::{HeaderValue, StatusCode, header};
use axum::response::Response;
use serde_json::json;

use crate::http_support::json_response;
use crate::state::ApiState;

pub(crate) async fn live() -> Response {
    no_store(json_response(
        StatusCode::OK,
        json!({"ok":true,"status":"live"}),
    ))
}

pub(crate) async fn ready(State(state): State<ApiState>, request: Request) -> Response {
    let include_details = state
        .inner
        .config
        .authenticator
        .authenticate_headers(request.headers())
        .is_some();
    let snapshot = state.inner.services.readiness.snapshot();
    let (status, body) = match snapshot {
        Ok(snapshot) => (
            if snapshot.ready {
                StatusCode::OK
            } else {
                StatusCode::SERVICE_UNAVAILABLE
            },
            if include_details {
                serde_json::to_value(snapshot).expect("readiness serializes")
            } else {
                json!({"ready":snapshot.ready})
            },
        ),
        Err(_) => (
            StatusCode::SERVICE_UNAVAILABLE,
            if include_details {
                json!({"ready":false,"failing":["internal"],"uptimeMs":0})
            } else {
                json!({"ready":false})
            },
        ),
    };
    no_store(json_response(status, body))
}

fn no_store(mut response: Response) -> Response {
    response
        .headers_mut()
        .insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    response
}

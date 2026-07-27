//! Liveness and dependency-backed readiness probes.
//!
//! The two probes answer different questions and must be allowed to disagree.
//! Liveness answers "should this process be restarted?", so a host that is
//! draining — deliberately refusing new work while it finishes what it has —
//! stays live. Readiness answers "should this process be routed to?", so the
//! same drain must fail it. Flipping both together would have an orchestrator
//! kill a process that is shutting down cleanly.

use axum::extract::{Request, State};
use axum::http::{HeaderValue, StatusCode, header};
use axum::response::Response;
use serde_json::json;

use crate::http_support::json_response;
use crate::state::ApiState;

pub(crate) async fn live(State(state): State<ApiState>) -> Response {
    let serving = state.inner.serving.serving_state();
    // A live process is live regardless of phase. The label is reported only
    // when the host is not accepting work, so a drain is visible here without
    // ever being mistaken for a restart signal.
    let body = if serving.accepts_work() {
        json!({"ok":true,"status":"live"})
    } else {
        json!({"ok":true,"status":"live","phase":serving.phase()})
    };
    no_store(json_response(StatusCode::OK, body))
}

pub(crate) async fn ready(State(state): State<ApiState>, request: Request) -> Response {
    let include_details = state
        .inner
        .config
        .authenticator
        .authenticate_headers(request.headers())
        .is_some();
    let serving = state.inner.serving.serving_state();
    let (dependencies_ready, mut failing, uptime_ms) =
        match state.inner.services.readiness.snapshot() {
            Ok(snapshot) => (snapshot.ready, snapshot.failing, snapshot.uptime_ms),
            Err(_) => (false, vec![String::from("internal")], 0),
        };
    if !serving.accepts_work() {
        // Reported first: the host's own refusal outranks any dependency, and a
        // reader looking for the cause should see it ahead of the noise a drain
        // can itself produce.
        failing.insert(0, serving.phase().to_string());
    }
    let ready = serving.accepts_work() && dependencies_ready;
    let status = if ready {
        StatusCode::OK
    } else {
        StatusCode::SERVICE_UNAVAILABLE
    };
    let body = if include_details {
        json!({"ready":ready,"failing":failing,"uptimeMs":uptime_ms})
    } else {
        json!({"ready":ready})
    };
    no_store(json_response(status, body))
}

fn no_store(mut response: Response) -> Response {
    response
        .headers_mut()
        .insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    response
}

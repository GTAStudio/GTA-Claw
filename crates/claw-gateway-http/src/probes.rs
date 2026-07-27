//! Liveness and readiness probe endpoints.
//!
//! Four paths, two semantics:
//!
//! | Path | Family | 200 when |
//! | --- | --- | --- |
//! | `/health`, `/healthz` | liveness | the process has not stopped, **including while it drains** |
//! | `/ready`, `/readyz` | readiness | the process is serving *and* every dependency is usable |
//!
//! The draining phase is the one that separates them. An orchestrator that
//! killed a draining pod because readiness went red would cut in-flight work
//! short, so liveness deliberately stays green through the whole drain while
//! readiness flips to `503` the instant the drain begins.

use std::sync::Arc;

use axum::Router;
use axum::extract::State;
use axum::http::StatusCode;
use axum::response::Response;
use axum::routing::get;
use serde_json::{Value, json};

use crate::http_util::{close_connection, json_response, retry_after};
use crate::lifecycle::{GatewayLifecycle, ReadinessCheck, ServingState};

/// Paths that answer the liveness question.
pub const LIVENESS_PATHS: [&str; 2] = ["/health", "/healthz"];
/// Paths that answer the readiness question.
pub const READINESS_PATHS: [&str; 2] = ["/ready", "/readyz"];
/// Seconds a readiness `503` asks the caller to wait before retrying.
pub const READINESS_RETRY_AFTER_SECONDS: u32 = 1;

/// Probe surface: one lifecycle plus the dependencies readiness consults.
#[derive(Clone)]
pub struct ProbeSurface {
    lifecycle: GatewayLifecycle,
    checks: Arc<Vec<Arc<dyn ReadinessCheck>>>,
}

impl ProbeSurface {
    /// Creates a probe surface with no dependencies beyond the lifecycle itself.
    #[must_use]
    pub fn new(lifecycle: GatewayLifecycle) -> Self {
        Self {
            lifecycle,
            checks: Arc::new(Vec::new()),
        }
    }

    /// Adds one readiness dependency.
    #[must_use]
    pub fn with_check(mut self, check: Arc<dyn ReadinessCheck>) -> Self {
        Arc::make_mut(&mut self.checks).push(check);
        self
    }

    /// Returns the lifecycle this surface reports on.
    #[must_use]
    pub fn lifecycle(&self) -> &GatewayLifecycle {
        &self.lifecycle
    }

    /// Returns the current readiness verdict.
    #[must_use]
    pub fn readiness(&self) -> Readiness {
        let state = self.lifecycle.state();
        let mut failing: Vec<String> = state
            .readiness_reason()
            .into_iter()
            .map(str::to_owned)
            .collect();
        failing.extend(
            self.checks
                .iter()
                .filter(|check| !check.is_ready())
                .map(|check| check.name().to_owned()),
        );
        Readiness { state, failing }
    }
}

/// Outcome of one readiness evaluation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Readiness {
    /// The serving phase observed during the evaluation.
    pub state: ServingState,
    /// Every reason the process is not ready, starting with the serving phase.
    pub failing: Vec<String>,
}

impl Readiness {
    /// Returns whether the process may be routed new work.
    #[must_use]
    pub fn is_ready(&self) -> bool {
        self.failing.is_empty()
    }
}

/// Builds the four probe routes.
pub fn probe_router(surface: ProbeSurface) -> Router {
    let mut router = Router::new();
    for path in LIVENESS_PATHS {
        router = router.route(path, get(liveness));
    }
    for path in READINESS_PATHS {
        router = router.route(path, get(readiness));
    }
    router.with_state(surface)
}

async fn liveness(State(surface): State<ProbeSurface>) -> Response {
    let state = surface.lifecycle.state();
    let live = state.is_live();
    let body = json!({
        "ok": live,
        "status": if live { "live" } else { "stopped" },
        "state": state.as_str(),
        "draining": state.is_draining(),
        "uptimeMs": uptime_ms(&surface),
    });
    let status = if live {
        StatusCode::OK
    } else {
        StatusCode::SERVICE_UNAVAILABLE
    };
    shed_when_leaving(json_response(status, body), state)
}

async fn readiness(State(surface): State<ProbeSurface>) -> Response {
    let readiness = surface.readiness();
    let ready = readiness.is_ready();
    let body = json!({
        "ok": ready,
        "ready": ready,
        "state": readiness.state.as_str(),
        "draining": readiness.state.is_draining(),
        "failing": Value::from(readiness.failing.clone()),
        "uptimeMs": uptime_ms(&surface),
    });
    let response = if ready {
        json_response(StatusCode::OK, body)
    } else {
        retry_after(
            json_response(StatusCode::SERVICE_UNAVAILABLE, body),
            READINESS_RETRY_AFTER_SECONDS,
        )
    };
    shed_when_leaving(response, readiness.state)
}

fn shed_when_leaving(response: Response, state: ServingState) -> Response {
    if state.accepts_new_work() || state == ServingState::Starting {
        response
    } else {
        close_connection(response)
    }
}

fn uptime_ms(surface: &ProbeSurface) -> u64 {
    u64::try_from(surface.lifecycle.uptime().as_millis()).unwrap_or(u64::MAX)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::lifecycle::ReadinessFlag;

    #[test]
    fn readiness_lists_the_drain_before_the_failing_dependencies() {
        let lifecycle = GatewayLifecycle::serving();
        let provider = ReadinessFlag::new("provider", false);
        let surface = ProbeSurface::new(lifecycle.clone()).with_check(provider.clone());
        assert_eq!(surface.readiness().failing, vec!["provider".to_owned()]);
        lifecycle.begin_draining();
        assert_eq!(
            surface.readiness().failing,
            vec!["draining".to_owned(), "provider".to_owned()]
        );
        provider.set_ready(true);
        let readiness = surface.readiness();
        assert_eq!(readiness.failing, vec!["draining".to_owned()]);
        assert!(
            !readiness.is_ready(),
            "healthy dependencies must not make a draining process ready"
        );
    }
}

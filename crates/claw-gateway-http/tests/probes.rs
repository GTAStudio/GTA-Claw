//! HTTP behaviour of the four Gateway probe endpoints.
//!
//! The probes exist to be read by an orchestrator, so what matters is not that
//! they answer but that liveness and readiness answer *differently* while the
//! process drains.

use std::sync::Arc;

use axum::Router;
use axum::body::Body;
use axum::http::{HeaderMap, Request, StatusCode};
use claw_gateway_http::{
    GatewayLifecycle, InMemoryResultSink, LIVENESS_PATHS, ProbeSurface, READINESS_PATHS,
    ReadinessFlag, WatchLimits, WatchNodeRegistry, WatchNodeTransport, gateway_http_router,
};
use http_body_util::BodyExt;
use hyper_util::client::legacy::Client;
use hyper_util::client::legacy::connect::HttpConnector;
use hyper_util::rt::TokioExecutor;
use serde_json::Value;
use tokio::net::TcpListener;
use tower::ServiceExt;

struct Reply {
    status: StatusCode,
    headers: HeaderMap,
    body: Value,
}

impl Reply {
    fn header(&self, name: &str) -> Option<&str> {
        self.headers.get(name).and_then(|value| value.to_str().ok())
    }
}

async fn probe(router: &Router, path: &str) -> Reply {
    let response = router
        .clone()
        .oneshot(
            Request::builder()
                .method("GET")
                .uri(path)
                .body(Body::empty())
                .expect("probe request"),
        )
        .await
        .expect("probe response");
    let status = response.status();
    let headers = response.headers().clone();
    let bytes = response
        .into_body()
        .collect()
        .await
        .expect("probe body")
        .to_bytes();
    Reply {
        status,
        headers,
        body: serde_json::from_slice(&bytes).expect("probe body is JSON"),
    }
}

fn surface() -> (GatewayLifecycle, Arc<ReadinessFlag>, ProbeSurface) {
    let lifecycle = GatewayLifecycle::starting();
    let store = ReadinessFlag::new("store", true);
    let surface = ProbeSurface::new(lifecycle.clone()).with_check(store.clone());
    (lifecycle, store, surface)
}

fn router_for(surface: ProbeSurface) -> Router {
    gateway_http_router(
        surface,
        WatchNodeTransport::new(
            WatchLimits::default(),
            WatchNodeRegistry::new(),
            InMemoryResultSink::new(),
        ),
    )
}

#[tokio::test]
async fn probe_endpoints_report_liveness_and_readiness_across_the_draining_lifecycle() {
    let (lifecycle, store, surface) = surface();
    let router = router_for(surface);

    // Starting: alive, but nothing may be routed here yet.
    for path in LIVENESS_PATHS {
        let reply = probe(&router, path).await;
        assert_eq!(
            reply.status,
            StatusCode::OK,
            "{path} liveness while starting"
        );
        assert_eq!(reply.body["ok"], true);
        assert_eq!(reply.body["status"], "live");
        assert_eq!(reply.body["state"], "starting");
        assert_eq!(reply.body["draining"], false);
        assert_eq!(reply.header("cache-control"), Some("no-store"), "{path}");
        assert!(reply.body["uptimeMs"].as_u64().is_some(), "{path}");
    }
    for path in READINESS_PATHS {
        let reply = probe(&router, path).await;
        assert_eq!(
            reply.status,
            StatusCode::SERVICE_UNAVAILABLE,
            "{path} readiness while starting"
        );
        assert_eq!(reply.body["ready"], false);
        assert_eq!(reply.body["failing"], serde_json::json!(["starting"]));
        assert_eq!(reply.header("retry-after"), Some("1"), "{path}");
    }

    // Serving with healthy dependencies: all four agree.
    assert!(lifecycle.mark_serving());
    for path in LIVENESS_PATHS.into_iter().chain(READINESS_PATHS) {
        let reply = probe(&router, path).await;
        assert_eq!(reply.status, StatusCode::OK, "{path} while serving");
        assert_eq!(reply.body["ok"], true, "{path} while serving");
        assert_eq!(reply.body["state"], "serving", "{path} while serving");
        assert_eq!(reply.body["draining"], false, "{path} while serving");
        assert_eq!(reply.header("cache-control"), Some("no-store"), "{path}");
        assert_eq!(
            reply.header("connection"),
            None,
            "{path} must not shed sockets while serving"
        );
        assert_eq!(reply.header("retry-after"), None, "{path} while serving");
    }

    // A failing dependency separates the two families without a drain.
    store.set_ready(false);
    for path in LIVENESS_PATHS {
        let reply = probe(&router, path).await;
        assert_eq!(
            reply.status,
            StatusCode::OK,
            "{path} liveness must ignore dependency health"
        );
    }
    for path in READINESS_PATHS {
        let reply = probe(&router, path).await;
        assert_eq!(reply.status, StatusCode::SERVICE_UNAVAILABLE, "{path}");
        assert_eq!(
            reply.body["failing"],
            serde_json::json!(["store"]),
            "{path}"
        );
    }
    store.set_ready(true);

    // Draining: this is the state the two families are built to disagree in.
    assert!(lifecycle.begin_draining());
    for path in LIVENESS_PATHS {
        let reply = probe(&router, path).await;
        assert_eq!(
            reply.status,
            StatusCode::OK,
            "{path} must stay live for the whole drain"
        );
        assert_eq!(reply.body["ok"], true, "{path} while draining");
        assert_eq!(reply.body["status"], "live", "{path} while draining");
        assert_eq!(reply.body["state"], "draining", "{path} while draining");
        assert_eq!(reply.body["draining"], true, "{path} while draining");
        assert_eq!(
            reply.header("connection"),
            Some("close"),
            "{path} must shed keep-alive sockets while draining"
        );
    }
    for path in READINESS_PATHS {
        let reply = probe(&router, path).await;
        assert_eq!(
            reply.status,
            StatusCode::SERVICE_UNAVAILABLE,
            "{path} must refuse new work the moment the drain begins"
        );
        assert_eq!(reply.body["ok"], false, "{path} while draining");
        assert_eq!(reply.body["ready"], false, "{path} while draining");
        assert_eq!(reply.body["state"], "draining", "{path} while draining");
        assert_eq!(
            reply.body["failing"],
            serde_json::json!(["draining"]),
            "{path} must name the drain, not a dependency"
        );
        assert_eq!(reply.header("retry-after"), Some("1"), "{path}");
        assert_eq!(reply.header("connection"), Some("close"), "{path}");
    }

    // Stopped: liveness finally goes red too.
    assert!(lifecycle.mark_stopped());
    for path in LIVENESS_PATHS {
        let reply = probe(&router, path).await;
        assert_eq!(reply.status, StatusCode::SERVICE_UNAVAILABLE, "{path}");
        assert_eq!(reply.body["ok"], false, "{path} once stopped");
        assert_eq!(reply.body["status"], "stopped", "{path} once stopped");
    }
    for path in READINESS_PATHS {
        let reply = probe(&router, path).await;
        assert_eq!(reply.status, StatusCode::SERVICE_UNAVAILABLE, "{path}");
        assert_eq!(
            reply.body["failing"],
            serde_json::json!(["stopped"]),
            "{path}"
        );
    }
}

#[tokio::test]
async fn probe_endpoints_answer_over_a_real_listener_and_flip_when_the_drain_begins() {
    let (lifecycle, _store, surface) = surface();
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind an ephemeral probe port");
    let address = listener.local_addr().expect("probe listener address");
    let server = tokio::spawn(claw_gateway_http::serve(router_for(surface), listener));
    let client: Client<HttpConnector, Body> = Client::builder(TokioExecutor::new()).build_http();

    assert!(lifecycle.mark_serving());
    for path in LIVENESS_PATHS.into_iter().chain(READINESS_PATHS) {
        let uri = format!("http://{address}{path}");
        let response = client
            .get(uri.parse().expect("probe uri"))
            .await
            .expect(path);
        assert_eq!(response.status(), StatusCode::OK, "{path} over TCP");
    }

    lifecycle.begin_draining();
    for path in LIVENESS_PATHS {
        let uri = format!("http://{address}{path}");
        let response = client
            .get(uri.parse().expect("probe uri"))
            .await
            .expect(path);
        assert_eq!(
            response.status(),
            StatusCode::OK,
            "{path} must stay live over TCP while draining"
        );
        assert_eq!(
            response
                .headers()
                .get("connection")
                .and_then(|value| value.to_str().ok()),
            Some("close"),
            "{path} over TCP while draining"
        );
    }
    for path in READINESS_PATHS {
        let uri = format!("http://{address}{path}");
        let response = client
            .get(uri.parse().expect("probe uri"))
            .await
            .expect(path);
        assert_eq!(
            response.status(),
            StatusCode::SERVICE_UNAVAILABLE,
            "{path} must refuse new work over TCP while draining"
        );
        let bytes = response
            .into_body()
            .collect()
            .await
            .expect("readiness body")
            .to_bytes();
        let body: Value = serde_json::from_slice(&bytes).expect("readiness body is JSON");
        assert_eq!(body["failing"], serde_json::json!(["draining"]), "{path}");
    }

    server.abort();
}

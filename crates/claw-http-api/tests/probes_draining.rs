//! Draining behavior of the four probe routes, over real TCP sockets.
//!
//! `/health` and `/healthz` are liveness; `/ready` and `/readyz` are readiness.
//! The property under test is that a drain drives those two apart: readiness
//! must fail so load balancers stop routing, while liveness must keep
//! succeeding so orchestrators do not kill a process that is shutting down
//! cleanly. A test that only asserted "probes return 200" would pass against an
//! implementation with no notion of draining at all, which is exactly the gap
//! this file exists to close.

use std::collections::BTreeMap;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use claw_http_api::{
    ApiConfig, BearerAuthenticator, BearerCredential, DeterministicRuntime, HttpApi, ServingState,
    ServingStateHandle, ServingStatePort,
};
use claw_security::authorization::{Role, Scope, ScopeSet};
use serde_json::{Value, json};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::task::JoinHandle;
use tokio::time::timeout;

const LIVENESS_PATHS: [&str; 2] = ["/health", "/healthz"];
const READINESS_PATHS: [&str; 2] = ["/ready", "/readyz"];
const OPERATOR_TOKEN: &str = "operator-token";

#[tokio::test]
async fn every_probe_path_answers_and_each_alias_pair_is_indistinguishable() {
    let runtime = DeterministicRuntime::new();
    let server = spawn(runtime.clone(), Arc::new(ServingStateHandle::serving())).await;

    let live = get(&server, "/health", None).await;
    let live_alias = get(&server, "/healthz", None).await;
    assert_eq!(live.status, 200, "/health answers while serving");
    assert_eq!(live_alias.status, 200, "/healthz answers while serving");
    assert_eq!(
        live.json(),
        live_alias.json(),
        "/health and /healthz are aliases and must not diverge"
    );

    let ready = get(&server, "/ready", Some(OPERATOR_TOKEN)).await;
    let ready_alias = get(&server, "/readyz", Some(OPERATOR_TOKEN)).await;
    assert_eq!(ready.status, 200, "/ready answers while serving");
    assert_eq!(ready_alias.status, 200, "/readyz answers while serving");
    // `uptimeMs` advances between the two calls, so the alias check covers the
    // verdict and its reasons rather than the whole body.
    assert_eq!(
        (
            ready.json()["ready"].clone(),
            ready.json()["failing"].clone()
        ),
        (
            ready_alias.json()["ready"].clone(),
            ready_alias.json()["failing"].clone()
        ),
        "/ready and /readyz are aliases and must not diverge"
    );

    for path in LIVENESS_PATHS.iter().chain(READINESS_PATHS.iter()) {
        let response = get(&server, path, Some(OPERATOR_TOKEN)).await;
        assert_eq!(
            response.headers.get("cache-control").map(String::as_str),
            Some("no-store"),
            "{path} must never be cached"
        );
    }
}

#[tokio::test]
async fn draining_fails_readiness_on_both_paths_while_liveness_stays_live() {
    let runtime = DeterministicRuntime::new();
    let serving = ServingStateHandle::serving();
    let server = spawn(runtime.clone(), Arc::new(serving.clone())).await;

    for path in READINESS_PATHS {
        let before = get(&server, path, Some(OPERATOR_TOKEN)).await;
        assert_eq!(before.status, 200, "{path} is ready before the drain");
        assert_eq!(before.json()["ready"], json!(true));
        assert_eq!(
            before.json()["failing"],
            json!([]),
            "{path} reports nothing failing before the drain"
        );
    }
    for path in LIVENESS_PATHS {
        let before = get(&server, path, Some(OPERATOR_TOKEN)).await;
        assert_eq!(before.status, 200, "{path} is live before the drain");
        assert_eq!(
            before.json(),
            json!({"ok":true,"status":"live"}),
            "{path} reports no phase while serving normally"
        );
    }

    serving.begin_draining();

    for path in READINESS_PATHS {
        let during = get(&server, path, Some(OPERATOR_TOKEN)).await;
        assert_eq!(
            during.status, 503,
            "{path} must stop being routed to during a drain"
        );
        assert_eq!(during.json()["ready"], json!(false));
        assert_eq!(
            during.json()["failing"],
            json!(["draining"]),
            "{path} must name the drain as the reason"
        );
        assert_eq!(
            during.json().as_object().expect("object").len(),
            3,
            "{path} keeps the frozen three-field readiness shape while draining"
        );
    }
    for path in LIVENESS_PATHS {
        let during = get(&server, path, Some(OPERATOR_TOKEN)).await;
        assert_eq!(
            during.status, 200,
            "{path} must stay live during a drain, or the process gets restarted mid-shutdown"
        );
        assert_eq!(
            during.json(),
            json!({"ok":true,"status":"live","phase":"draining"}),
            "{path} observes the drain without failing on it"
        );
    }
}

#[tokio::test]
async fn draining_is_reported_distinctly_from_a_failing_dependency() {
    let runtime = DeterministicRuntime::new();
    let serving = ServingStateHandle::serving();
    let server = spawn(runtime.clone(), Arc::new(serving.clone())).await;

    runtime.set_ready(false);
    let dependency_only = get(&server, "/ready", Some(OPERATOR_TOKEN)).await;
    assert_eq!(dependency_only.status, 503);
    assert_eq!(
        dependency_only.json()["failing"],
        json!(["provider"]),
        "a failing dependency must not be mislabelled as a drain"
    );

    runtime.set_ready(true);
    serving.begin_draining();
    let drain_only = get(&server, "/ready", Some(OPERATOR_TOKEN)).await;
    assert_eq!(
        drain_only.status, 503,
        "a drain fails readiness even with every dependency green"
    );
    assert_eq!(
        drain_only.json()["failing"],
        json!(["draining"]),
        "a drain must be its own reason, not a fabricated dependency failure"
    );

    runtime.set_ready(false);
    let both = get(&server, "/ready", Some(OPERATOR_TOKEN)).await;
    assert_eq!(both.status, 503);
    assert_eq!(
        both.json()["failing"],
        json!(["draining", "provider"]),
        "both reasons survive, with the host's own refusal reported first"
    );
}

#[tokio::test]
async fn the_drain_reason_is_not_disclosed_to_unauthenticated_callers() {
    let runtime = DeterministicRuntime::new();
    let serving = ServingStateHandle::serving();
    let server = spawn(runtime.clone(), Arc::new(serving.clone())).await;

    serving.begin_draining();

    for path in READINESS_PATHS {
        let anonymous = get(&server, path, None).await;
        assert_eq!(
            anonymous.status, 503,
            "{path} still tells an anonymous load balancer to stop routing"
        );
        assert_eq!(
            anonymous.json(),
            json!({"ready":false}),
            "{path} must not leak why it is unready"
        );
        assert!(
            !anonymous.text().contains("draining"),
            "{path} leaked the shutdown phase to an unauthenticated caller"
        );
    }
}

#[tokio::test]
async fn probe_bodies_are_byte_identical_to_the_frozen_shape_while_serving() {
    let runtime = DeterministicRuntime::new();
    let server = spawn(runtime.clone(), Arc::new(ServingStateHandle::serving())).await;

    for path in LIVENESS_PATHS {
        let live = get(&server, path, None).await;
        assert_eq!(
            live.json(),
            json!({"ok":true,"status":"live"}),
            "{path} gained a field that the frozen liveness contract does not allow"
        );
    }

    let detailed = get(&server, "/ready", Some(OPERATOR_TOKEN)).await;
    let body = detailed.json();
    assert_eq!(body["ready"], json!(true));
    assert_eq!(body["failing"], json!([]));
    assert!(body["uptimeMs"].as_u64().is_some());
    assert_eq!(
        body.as_object().expect("object").len(),
        3,
        "readiness details keep exactly three fields"
    );
}

#[tokio::test]
async fn a_drained_host_never_returns_to_service() {
    let runtime = DeterministicRuntime::new();
    let serving = ServingStateHandle::serving();
    let server = spawn(runtime.clone(), Arc::new(serving.clone())).await;

    serving.begin_draining();
    serving.begin_serving();

    let after = get(&server, "/ready", Some(OPERATOR_TOKEN)).await;
    assert_eq!(
        after.status, 503,
        "a host that has announced a drain must not flap back into rotation"
    );
    assert_eq!(after.json()["failing"], json!(["draining"]));
}

#[tokio::test]
async fn a_host_that_has_not_begun_serving_is_unready_without_claiming_to_drain() {
    let runtime = DeterministicRuntime::new();
    let serving = ServingStateHandle::starting();
    let server = spawn(runtime.clone(), Arc::new(serving.clone())).await;

    let before = get(&server, "/ready", Some(OPERATOR_TOKEN)).await;
    assert_eq!(before.status, 503, "a starting host is not ready");
    assert_eq!(
        before.json()["failing"],
        json!(["starting"]),
        "the reason must be the real phase, not a hard-coded drain label"
    );
    let live = get(&server, "/health", Some(OPERATOR_TOKEN)).await;
    assert_eq!(live.status, 200, "a starting host is still live");
    assert_eq!(live.json()["phase"], json!("starting"));

    serving.begin_serving();
    let after = get(&server, "/ready", Some(OPERATOR_TOKEN)).await;
    assert_eq!(after.status, 200, "readiness follows the host into service");
    assert_eq!(after.json()["failing"], json!([]));
}

#[tokio::test]
async fn readiness_follows_a_caller_supplied_serving_state_port() {
    struct Quiescing;

    impl ServingStatePort for Quiescing {
        fn serving_state(&self) -> ServingState {
            ServingState::new("quiescing", false)
        }
    }

    let runtime = DeterministicRuntime::new();
    let server = spawn(runtime.clone(), Arc::new(Quiescing)).await;

    let ready = get(&server, "/ready", Some(OPERATOR_TOKEN)).await;
    assert_eq!(
        ready.status, 503,
        "the host's own port decides readiness, not a default inside the adapter"
    );
    assert_eq!(
        ready.json()["failing"],
        json!(["quiescing"]),
        "the caller's phase label is surfaced verbatim"
    );
    let live = get(&server, "/health", Some(OPERATOR_TOKEN)).await;
    assert_eq!(live.status, 200);
    assert_eq!(live.json()["phase"], json!("quiescing"));
}

struct Server {
    address: SocketAddr,
    task: JoinHandle<()>,
}

impl Drop for Server {
    fn drop(&mut self) {
        self.task.abort();
    }
}

struct HttpResponse {
    status: u16,
    headers: BTreeMap<String, String>,
    body: Vec<u8>,
}

impl HttpResponse {
    fn json(&self) -> Value {
        serde_json::from_slice(&self.body).expect("response is JSON")
    }

    fn text(&self) -> &str {
        std::str::from_utf8(&self.body).expect("response is UTF-8")
    }
}

fn config() -> ApiConfig {
    ApiConfig::new(BearerAuthenticator::new(vec![BearerCredential::new(
        OPERATOR_TOKEN,
        Role::Operator,
        ScopeSet::from_scopes([Scope::OperatorAdmin]),
    )]))
}

async fn spawn(runtime: Arc<DeterministicRuntime>, serving: Arc<dyn ServingStatePort>) -> Server {
    let api = HttpApi::with_serving_state(config(), runtime.services(), serving);
    // Port zero: parallel test binaries must never contend for a fixed port.
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind test listener");
    let address = listener.local_addr().expect("listener address");
    let task = tokio::spawn(async move {
        api.serve(listener).await.expect("serve test API");
    });
    Server { address, task }
}

async fn get(server: &Server, path: &str, token: Option<&str>) -> HttpResponse {
    let mut stream = TcpStream::connect(server.address)
        .await
        .expect("connect test server");
    let mut head = format!(
        "GET {path} HTTP/1.1\r\nHost: {}\r\nConnection: close\r\nContent-Length: 0\r\n",
        server.address
    );
    if let Some(token) = token {
        head.push_str(&format!("Authorization: Bearer {token}\r\n"));
    }
    head.push_str("\r\n");
    stream
        .write_all(head.as_bytes())
        .await
        .expect("write request");
    let mut raw = Vec::new();
    timeout(Duration::from_secs(5), stream.read_to_end(&mut raw))
        .await
        .expect("response timeout")
        .expect("read response");
    parse_response(&raw)
}

fn parse_response(raw: &[u8]) -> HttpResponse {
    let split = raw
        .windows(4)
        .position(|window| window == b"\r\n\r\n")
        .expect("response has a header terminator");
    let head = std::str::from_utf8(&raw[..split]).expect("headers are UTF-8");
    let mut lines = head.split("\r\n");
    let status = lines
        .next()
        .and_then(|line| line.split_whitespace().nth(1))
        .and_then(|code| code.parse().ok())
        .expect("response has a status code");
    let headers = lines
        .filter_map(|line| line.split_once(':'))
        .map(|(name, value)| (name.trim().to_ascii_lowercase(), value.trim().to_owned()))
        .collect();
    HttpResponse {
        status,
        headers,
        body: raw[split + 4..].to_vec(),
    }
}

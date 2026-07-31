//! Acceptance tests for the guarded TaskFlow webhook surface.
//!
//! Each of the six properties the feature ledger requires — configurable route,
//! secret, replay, body limit, session binding and TaskFlow dispatch — is
//! covered here both at the pure admission-decision level, where the refusal
//! reason is asserted exactly, and over a real TCP socket, where the status,
//! the wire code and the absence of a dispatch are asserted together.

use std::collections::BTreeMap;
use std::fs;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicI64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use axum::response::IntoResponse;
use claw_http_api::{
    AdmittedWebhook, ApiConfig, BearerAuthenticator, BearerCredential, DeterministicRuntime,
    HttpApi, PathRejection, PortError, PortFuture, ReplayPolicy, WEBHOOK_DELIVERY_HEADER,
    WEBHOOK_SECRET_HEADER, WEBHOOK_SESSION_HEADER, WEBHOOK_TIMESTAMP_HEADER, WebhookClock,
    WebhookConfigError, WebhookGuard, WebhookGuardConfig, WebhookOutcome, WebhookPort,
    WebhookRejection, WebhookRoute, WebhookRouteBinding,
};
use claw_security::authorization::{Role, Scope, ScopeSet};
use http::{HeaderMap, HeaderName, HeaderValue, Method, StatusCode, header};
use serde_json::{Value, json};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::task::JoinHandle;
use tokio::time::timeout;
use tokio_util::sync::CancellationToken;

const NOW: i64 = 1_750_000_000;
const ROUTE_ID: &str = "zapier";
const ROUTE_SECRET: &str = "route-secret-value";
const ROUTE_SESSION: &str = "agent-session-alpha";
const ROUTE_PATH: &str = "/hooks/inbound/zapier";
const CANONICAL_PATH: &str = "/plugins/webhooks/zapier";
const OTHER_ROUTE_ID: &str = "github";
const OTHER_ROUTE_SECRET: &str = "other-secret-value";
const OTHER_ROUTE_SESSION: &str = "agent-session-beta";
const OTHER_CANONICAL_PATH: &str = "/plugins/webhooks/github";

// ---------------------------------------------------------------------------
// Test doubles
// ---------------------------------------------------------------------------

#[derive(Debug, Default)]
struct RecordingWebhooks {
    calls: Mutex<Vec<(String, Value)>>,
    outcome: Mutex<Option<WebhookOutcome>>,
}

impl RecordingWebhooks {
    fn calls(&self) -> Vec<(String, Value)> {
        self.calls.lock().expect("webhook call lock").clone()
    }

    fn set_outcome(&self, outcome: WebhookOutcome) {
        *self.outcome.lock().expect("webhook outcome lock") = Some(outcome);
    }
}

impl WebhookPort for RecordingWebhooks {
    fn invoke(
        &self,
        route_id: String,
        action: Value,
        _cancellation: CancellationToken,
    ) -> PortFuture<'_, Result<WebhookOutcome, PortError>> {
        Box::pin(async move {
            self.calls
                .lock()
                .expect("webhook call lock")
                .push((route_id.clone(), action.clone()));
            let configured = self.outcome.lock().expect("webhook outcome lock").clone();
            Ok(configured.unwrap_or_else(|| WebhookOutcome {
                status: 200,
                code: None,
                error: None,
                result: json!({"routeId": route_id, "action": action}),
            }))
        })
    }
}

#[derive(Debug)]
struct TestClock(AtomicI64);

impl TestClock {
    fn new(now: i64) -> Self {
        Self(AtomicI64::new(now))
    }

    fn set(&self, now: i64) {
        self.0.store(now, Ordering::Release);
    }
}

impl WebhookClock for TestClock {
    fn unix_seconds(&self) -> i64 {
        self.0.load(Ordering::Acquire)
    }
}

// ---------------------------------------------------------------------------
// Harness
// ---------------------------------------------------------------------------

fn binding(route_id: &str, session_key: &str, secret: &str) -> WebhookRouteBinding {
    WebhookRouteBinding::new(route_id, session_key, secret)
}

fn two_route_guard_config() -> WebhookGuardConfig {
    WebhookGuardConfig::resolve([
        binding(ROUTE_ID, ROUTE_SESSION, ROUTE_SECRET).with_path(ROUTE_PATH),
        binding(OTHER_ROUTE_ID, OTHER_ROUTE_SESSION, OTHER_ROUTE_SECRET),
    ])
    .expect("two distinct routes resolve")
}

fn api_config() -> ApiConfig {
    let mut config = ApiConfig::new(BearerAuthenticator::new(vec![BearerCredential::new(
        "operator-token",
        Role::Operator,
        ScopeSet::from_scopes([Scope::OperatorAdmin]),
    )]));
    config.webhooks.insert(
        ROUTE_ID.to_owned(),
        WebhookRoute::new(ROUTE_ID, ROUTE_SECRET),
    );
    config.webhooks.insert(
        OTHER_ROUTE_ID.to_owned(),
        WebhookRoute::new(OTHER_ROUTE_ID, OTHER_ROUTE_SECRET),
    );
    config
}

struct GuardedServer {
    address: SocketAddr,
    task: JoinHandle<()>,
    webhooks: Arc<RecordingWebhooks>,
    clock: Arc<TestClock>,
}

impl Drop for GuardedServer {
    fn drop(&mut self) {
        self.task.abort();
    }
}

async fn spawn(guard_config: WebhookGuardConfig) -> GuardedServer {
    spawn_api(Some(guard_config)).await
}

async fn spawn_unguarded() -> GuardedServer {
    spawn_api(None).await
}

async fn spawn_api(guard_config: Option<WebhookGuardConfig>) -> GuardedServer {
    let runtime = DeterministicRuntime::new();
    let webhooks = Arc::new(RecordingWebhooks::default());
    let mut services = runtime.services();
    services.webhooks = webhooks.clone();
    let clock = Arc::new(TestClock::new(NOW));
    let api = HttpApi::new(api_config(), services);
    let api = match guard_config {
        Some(guard_config) => {
            api.with_webhook_guard(WebhookGuard::with_clock(guard_config, clock.clone()))
        }
        None => api,
    };
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind webhook test listener");
    let address = listener
        .local_addr()
        .expect("webhook test listener address");
    let task = tokio::spawn(async move {
        api.serve(listener).await.expect("serve webhook test API");
    });
    GuardedServer {
        address,
        task,
        webhooks,
        clock,
    }
}

struct HttpResponse {
    status: u16,
    headers: BTreeMap<String, String>,
    body: Vec<u8>,
}

impl HttpResponse {
    fn json(&self) -> Value {
        serde_json::from_slice(&self.body).expect("response body is JSON")
    }

    fn code(&self) -> String {
        self.json()
            .get("code")
            .and_then(Value::as_str)
            .unwrap_or_default()
            .to_owned()
    }
}

async fn send(
    address: SocketAddr,
    method: &str,
    path: &str,
    headers: &[(&str, &str)],
    body: &[u8],
) -> HttpResponse {
    send_framed(address, method, path, headers, body, false).await
}

async fn send_chunked(
    address: SocketAddr,
    path: &str,
    headers: &[(&str, &str)],
    body: &[u8],
) -> HttpResponse {
    send_framed(address, "POST", path, headers, body, true).await
}

async fn send_framed(
    address: SocketAddr,
    method: &str,
    path: &str,
    headers: &[(&str, &str)],
    body: &[u8],
    chunked: bool,
) -> HttpResponse {
    let mut stream = TcpStream::connect(address)
        .await
        .expect("connect webhook test server");
    let framing = if chunked {
        "Transfer-Encoding: chunked\r\n".to_owned()
    } else {
        format!("Content-Length: {}\r\n", body.len())
    };
    let mut head =
        format!("{method} {path} HTTP/1.1\r\nHost: {address}\r\nConnection: close\r\n{framing}");
    for (name, value) in headers {
        head.push_str(&format!("{name}: {value}\r\n"));
    }
    head.push_str("\r\n");
    stream
        .write_all(head.as_bytes())
        .await
        .expect("write request head");
    if chunked {
        for chunk in body.chunks(16 * 1024) {
            if stream
                .write_all(format!("{:x}\r\n", chunk.len()).as_bytes())
                .await
                .is_err()
                || stream.write_all(chunk).await.is_err()
                || stream.write_all(b"\r\n").await.is_err()
            {
                break;
            }
        }
        let _ = stream.write_all(b"0\r\n\r\n").await;
    } else {
        // A refused oversized body is answered before it is fully read, so the
        // peer may close the connection mid-write. That is the behaviour under
        // test, not a harness failure.
        let _ = stream.write_all(body).await;
    }
    let raw = timeout(Duration::from_secs(5), read_to_end(&mut stream))
        .await
        .expect("webhook response timeout");
    parse_response(&raw)
}

async fn read_to_end(stream: &mut TcpStream) -> Vec<u8> {
    let mut raw = Vec::new();
    let mut buffer = [0_u8; 8 * 1024];
    loop {
        match stream.read(&mut buffer).await {
            Ok(0) | Err(_) => return raw,
            Ok(read) => raw.extend_from_slice(&buffer[..read]),
        }
    }
}

fn parse_response(raw: &[u8]) -> HttpResponse {
    let split = raw
        .windows(4)
        .position(|window| window == b"\r\n\r\n")
        .expect("response head terminator");
    let head = std::str::from_utf8(&raw[..split]).expect("response head is UTF-8");
    let mut lines = head.split("\r\n");
    let status = lines
        .next()
        .and_then(|line| line.split_whitespace().nth(1))
        .and_then(|code| code.parse::<u16>().ok())
        .expect("response status line");
    let headers = lines
        .filter_map(|line| line.split_once(':'))
        .map(|(name, value)| (name.trim().to_ascii_lowercase(), value.trim().to_owned()))
        .collect::<BTreeMap<_, _>>();
    let mut body = raw[split + 4..].to_vec();
    if let Some(length) = headers
        .get("content-length")
        .and_then(|value| value.parse::<usize>().ok())
    {
        body.truncate(length);
    }
    HttpResponse {
        status,
        headers,
        body,
    }
}

fn header_map(pairs: &[(&str, &str)]) -> HeaderMap {
    let mut map = HeaderMap::new();
    for (name, value) in pairs {
        map.insert(
            HeaderName::from_bytes(name.as_bytes()).expect("test header name"),
            HeaderValue::from_str(value).expect("test header value"),
        );
    }
    map
}

fn delivery_headers(secret: &str, delivery_id: &str, timestamp: i64) -> HeaderMap {
    header_map(&[
        (WEBHOOK_SECRET_HEADER, secret),
        (WEBHOOK_DELIVERY_HEADER, delivery_id),
        (WEBHOOK_TIMESTAMP_HEADER, &timestamp.to_string()),
    ])
}

fn wire_headers<'a>(
    secret: &'a str,
    delivery_id: &'a str,
    timestamp: &'a str,
) -> Vec<(&'a str, &'a str)> {
    vec![
        (WEBHOOK_SECRET_HEADER, secret),
        (WEBHOOK_DELIVERY_HEADER, delivery_id),
        (WEBHOOK_TIMESTAMP_HEADER, timestamp),
    ]
}

fn guard(config: WebhookGuardConfig, now: i64) -> (WebhookGuard, Arc<TestClock>) {
    let clock = Arc::new(TestClock::new(now));
    (WebhookGuard::with_clock(config, clock.clone()), clock)
}

fn list_flows() -> Vec<u8> {
    serde_json::to_vec(&json!({"action": "list_flows"})).expect("serialize action")
}

fn fixture_path(name: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests")
        .join("fixtures")
        .join("webhooks")
        .join(name)
}

fn guard_source_path() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("src")
        .join("webhooks")
        .join("guard.rs")
}

fn function_body<'source>(source: &'source str, signature: &str) -> &'source str {
    let start = source
        .find(signature)
        .unwrap_or_else(|| panic!("guard source declares `{signature}`"))
        + signature.len();
    let mut depth = 1_usize;
    for (offset, character) in source[start..].char_indices() {
        match character {
            '{' => depth += 1,
            '}' => {
                depth -= 1;
                if depth == 0 {
                    return &source[start..start + offset];
                }
            }
            _ => {}
        }
    }
    panic!("`{signature}` is not brace-balanced");
}

// ---------------------------------------------------------------------------
// Configurable route
// ---------------------------------------------------------------------------

#[test]
fn configurable_webhook_routes_resolve_only_when_every_declaration_is_valid() {
    let resolved = two_route_guard_config();
    assert_eq!(
        resolved.served_paths().collect::<Vec<_>>(),
        vec![ROUTE_PATH, OTHER_CANONICAL_PATH, CANONICAL_PATH],
        "a custom path never releases the canonical path it would otherwise be reached by"
    );
    let custom = resolved
        .route_at(ROUTE_PATH)
        .expect("custom path is served");
    assert_eq!(custom.route_id(), ROUTE_ID);
    assert_eq!(custom.session_key(), ROUTE_SESSION);
    assert_eq!(custom.path(), ROUTE_PATH);
    assert_eq!(
        resolved
            .route_at(CANONICAL_PATH)
            .expect("canonical path stays guarded")
            .route_id(),
        ROUTE_ID
    );
    assert_eq!(
        resolved
            .route_at("/hooks/inbound/zapier/")
            .expect("one trailing slash resolves to the same route")
            .route_id(),
        ROUTE_ID
    );
    assert!(resolved.route_at("/hooks/inbound").is_none());
    assert!(resolved.route_at("/hooks/inbound/zapier/extra").is_none());

    let default_only =
        WebhookGuardConfig::resolve([binding(ROUTE_ID, ROUTE_SESSION, ROUTE_SECRET)])
            .expect("a route without a declared path resolves");
    assert_eq!(
        default_only.served_paths().collect::<Vec<_>>(),
        vec![CANONICAL_PATH],
        "the default path is derived from the route id"
    );

    let disabled = WebhookGuardConfig::resolve([
        binding(ROUTE_ID, ROUTE_SESSION, ROUTE_SECRET).with_enabled(false)
    ])
    .expect("a disabled route resolves to nothing");
    assert_eq!(disabled.served_paths().count(), 0);

    let cases: Vec<(&str, WebhookConfigError, Vec<WebhookRouteBinding>)> = vec![
        (
            "an empty route id",
            WebhookConfigError::InvalidRouteId {
                route_id: "   ".to_owned(),
            },
            vec![binding("   ", ROUTE_SESSION, ROUTE_SECRET)],
        ),
        (
            "a route id carrying a path separator",
            WebhookConfigError::InvalidRouteId {
                route_id: "a/b".to_owned(),
            },
            vec![binding("a/b", ROUTE_SESSION, ROUTE_SECRET)],
        ),
        (
            "a repeated route id",
            WebhookConfigError::DuplicateRouteId {
                route_id: ROUTE_ID.to_owned(),
            },
            vec![
                binding(ROUTE_ID, ROUTE_SESSION, ROUTE_SECRET),
                binding(ROUTE_ID, OTHER_ROUTE_SESSION, OTHER_ROUTE_SECRET),
            ],
        ),
        (
            "an unbound session",
            WebhookConfigError::EmptySessionKey {
                route_id: ROUTE_ID.to_owned(),
            },
            vec![binding(ROUTE_ID, "  ", ROUTE_SECRET)],
        ),
        (
            "a session key carrying a header injection",
            WebhookConfigError::InvalidSessionKey {
                route_id: ROUTE_ID.to_owned(),
            },
            vec![binding(
                ROUTE_ID,
                "alpha\r\nx-openclaw-session-key: beta",
                ROUTE_SECRET,
            )],
        ),
        (
            "an empty secret",
            WebhookConfigError::EmptySecret {
                route_id: ROUTE_ID.to_owned(),
            },
            vec![binding(ROUTE_ID, ROUTE_SESSION, "")],
        ),
        (
            "a relative path",
            WebhookConfigError::InvalidPath {
                route_id: ROUTE_ID.to_owned(),
                path: "hooks/zapier".to_owned(),
                reason: PathRejection::NotAbsolute,
            },
            vec![binding(ROUTE_ID, ROUTE_SESSION, ROUTE_SECRET).with_path("hooks/zapier")],
        ),
        (
            "a traversal segment",
            WebhookConfigError::InvalidPath {
                route_id: ROUTE_ID.to_owned(),
                path: "/hooks/../admin".to_owned(),
                reason: PathRejection::RelativeSegment,
            },
            vec![binding(ROUTE_ID, ROUTE_SESSION, ROUTE_SECRET).with_path("/hooks/../admin")],
        ),
        (
            "an empty segment",
            WebhookConfigError::InvalidPath {
                route_id: ROUTE_ID.to_owned(),
                path: "/hooks//zapier".to_owned(),
                reason: PathRejection::EmptySegment,
            },
            vec![binding(ROUTE_ID, ROUTE_SESSION, ROUTE_SECRET).with_path("/hooks//zapier")],
        ),
        (
            "a query string",
            WebhookConfigError::InvalidPath {
                route_id: ROUTE_ID.to_owned(),
                path: "/hooks/zapier?token=1".to_owned(),
                reason: PathRejection::QueryOrFragment,
            },
            vec![binding(ROUTE_ID, ROUTE_SESSION, ROUTE_SECRET).with_path("/hooks/zapier?token=1")],
        ),
        (
            "a percent escape",
            WebhookConfigError::InvalidPath {
                route_id: ROUTE_ID.to_owned(),
                path: "/hooks/%2e%2e".to_owned(),
                reason: PathRejection::PercentEncoded,
            },
            vec![binding(ROUTE_ID, ROUTE_SESSION, ROUTE_SECRET).with_path("/hooks/%2e%2e")],
        ),
        (
            "the site root",
            WebhookConfigError::InvalidPath {
                route_id: ROUTE_ID.to_owned(),
                path: "/".to_owned(),
                reason: PathRejection::Root,
            },
            vec![binding(ROUTE_ID, ROUTE_SESSION, ROUTE_SECRET).with_path("/")],
        ),
        (
            "two routes on one path",
            WebhookConfigError::PathConflict {
                path: "/hooks/shared".to_owned(),
                route_id: OTHER_ROUTE_ID.to_owned(),
                existing_route_id: ROUTE_ID.to_owned(),
            },
            vec![
                binding(ROUTE_ID, ROUTE_SESSION, ROUTE_SECRET).with_path("/hooks/shared"),
                binding(OTHER_ROUTE_ID, OTHER_ROUTE_SESSION, OTHER_ROUTE_SECRET)
                    .with_path("/hooks/shared"),
            ],
        ),
        (
            "a custom path that shadows another route's canonical path",
            WebhookConfigError::PathConflict {
                path: CANONICAL_PATH.to_owned(),
                route_id: OTHER_ROUTE_ID.to_owned(),
                existing_route_id: ROUTE_ID.to_owned(),
            },
            vec![
                binding(ROUTE_ID, ROUTE_SESSION, ROUTE_SECRET),
                binding(OTHER_ROUTE_ID, OTHER_ROUTE_SESSION, OTHER_ROUTE_SECRET)
                    .with_path(CANONICAL_PATH),
            ],
        ),
    ];

    for (description, expected, bindings) in cases {
        let error = WebhookGuardConfig::resolve(bindings)
            .err()
            .unwrap_or_else(|| panic!("{description} must not resolve"));
        assert_eq!(
            error, expected,
            "{description} was refused for a wrong reason"
        );
    }
}

#[tokio::test]
async fn configurable_webhook_path_dispatches_and_never_frees_the_canonical_path() {
    let server = spawn(two_route_guard_config()).await;

    let custom = send(
        server.address,
        "POST",
        ROUTE_PATH,
        &wire_headers(ROUTE_SECRET, "delivery-1", &NOW.to_string()),
        &list_flows(),
    )
    .await;
    assert_eq!(custom.status, 200, "custom path did not dispatch");
    assert_eq!(custom.json()["routeId"], json!(ROUTE_ID));

    let canonical = send(
        server.address,
        "POST",
        CANONICAL_PATH,
        &wire_headers(ROUTE_SECRET, "delivery-2", &NOW.to_string()),
        &list_flows(),
    )
    .await;
    assert_eq!(canonical.status, 200, "canonical path did not dispatch");

    let unguarded_canonical_without_delivery_id = send(
        server.address,
        "POST",
        CANONICAL_PATH,
        &[(WEBHOOK_SECRET_HEADER, ROUTE_SECRET)],
        &list_flows(),
    )
    .await;
    assert_eq!(
        unguarded_canonical_without_delivery_id.status, 400,
        "the canonical path bypassed the guard"
    );
    assert_eq!(
        unguarded_canonical_without_delivery_id.code(),
        "missing_delivery_id"
    );

    let unknown = send(
        server.address,
        "POST",
        "/plugins/webhooks/unknown-route",
        &wire_headers(ROUTE_SECRET, "delivery-3", &NOW.to_string()),
        &list_flows(),
    )
    .await;
    assert_eq!(
        unknown.status, 404,
        "an unconfigured route id was served by the frozen dispatcher"
    );

    let wrong_method = send(
        server.address,
        "GET",
        ROUTE_PATH,
        &wire_headers(ROUTE_SECRET, "delivery-4", &NOW.to_string()),
        b"",
    )
    .await;
    assert_eq!(wrong_method.status, 405);
    assert_eq!(
        wrong_method.headers.get("allow").map(String::as_str),
        Some("POST")
    );

    assert_eq!(
        server
            .webhooks
            .calls()
            .iter()
            .map(|(route_id, _)| route_id.clone())
            .collect::<Vec<_>>(),
        vec![ROUTE_ID.to_owned(), ROUTE_ID.to_owned()],
        "only the two admitted deliveries reached TaskFlow"
    );
}

// ---------------------------------------------------------------------------
// Secret
// ---------------------------------------------------------------------------

#[tokio::test]
async fn webhook_secret_refuses_every_near_miss_without_revealing_which_check_failed() {
    let (guard, _clock) = guard(two_route_guard_config(), NOW);

    assert!(
        guard
            .admit(
                &Method::POST,
                ROUTE_PATH,
                &delivery_headers(ROUTE_SECRET, "delivery-ok", NOW),
                Some(32),
            )
            .is_ok(),
        "the configured secret must be accepted"
    );

    let mut prefix = ROUTE_SECRET.to_owned();
    prefix.pop();
    let mut first_byte_differs = ROUTE_SECRET.to_owned();
    first_byte_differs.replace_range(0..1, "R");
    let mut last_byte_differs = ROUTE_SECRET.to_owned();
    let last = last_byte_differs.len() - 1;
    last_byte_differs.replace_range(last.., "E");

    let near_misses = [
        ("a truncated secret", prefix),
        ("an extended secret", format!("{ROUTE_SECRET}x")),
        ("a secret differing in its first byte", first_byte_differs),
        ("a secret differing in its last byte", last_byte_differs),
        ("another route's secret", OTHER_ROUTE_SECRET.to_owned()),
        ("a very long secret", "x".repeat(4096)),
    ];
    for (description, presented) in near_misses {
        let rejection = guard
            .admit(
                &Method::POST,
                ROUTE_PATH,
                &delivery_headers(&presented, "delivery-near-miss", NOW),
                Some(32),
            )
            .expect_err(description);
        assert_eq!(
            rejection,
            WebhookRejection::SecretMismatch,
            "{description} was refused for a wrong reason"
        );
        assert_eq!(rejection.code(), "unauthorized");
        assert_eq!(rejection.wire_message(), "unauthorized");
    }

    let missing = guard
        .admit(
            &Method::POST,
            ROUTE_PATH,
            &header_map(&[
                (WEBHOOK_DELIVERY_HEADER, "delivery-none"),
                (WEBHOOK_TIMESTAMP_HEADER, &NOW.to_string()),
            ]),
            Some(32),
        )
        .expect_err("an unauthenticated delivery must be refused");
    assert_eq!(missing, WebhookRejection::MissingSecret);
    assert_eq!(
        (missing.status(), missing.code(), missing.wire_message()),
        (
            WebhookRejection::SecretMismatch.status(),
            WebhookRejection::SecretMismatch.code(),
            WebhookRejection::SecretMismatch.wire_message()
        ),
        "the wire response must not distinguish a missing secret from a wrong one"
    );

    let server = spawn(two_route_guard_config()).await;
    let refused = send(
        server.address,
        "POST",
        ROUTE_PATH,
        &wire_headers("not-the-secret", "delivery-1", &NOW.to_string()),
        &list_flows(),
    )
    .await;
    assert_eq!(refused.status, 401);
    assert_eq!(refused.code(), "unauthorized");
    assert_eq!(refused.json()["error"], json!("unauthorized"));
    assert_eq!(
        refused
            .headers
            .get("x-content-type-options")
            .map(String::as_str),
        Some("nosniff"),
        "guard refusals must keep the frozen response hardening headers"
    );

    let accepted_via_bearer = send(
        server.address,
        "POST",
        ROUTE_PATH,
        &[
            ("Authorization", &format!("Bearer {ROUTE_SECRET}")),
            (WEBHOOK_DELIVERY_HEADER, "delivery-2"),
            (WEBHOOK_TIMESTAMP_HEADER, &NOW.to_string()),
        ],
        &list_flows(),
    )
    .await;
    assert_eq!(accepted_via_bearer.status, 200);

    assert_eq!(
        server.webhooks.calls().len(),
        1,
        "only the authenticated delivery reached TaskFlow"
    );
}

#[test]
fn webhook_secret_comparison_is_constant_time_over_fixed_width_digests() {
    let source = fs::read_to_string(guard_source_path()).expect("read the guard source");
    for signature in [
        "fn secret_matches(expected: &[u8; 32], presented: &str) -> bool {",
        "fn session_matches(expected: &str, presented: &str) -> bool {",
    ] {
        let body = function_body(&source, signature);
        assert!(
            body.contains("ct_eq("),
            "`{signature}` must compare with subtle's constant-time equality"
        );
        assert!(
            body.contains("secret_digest("),
            "`{signature}` must compare fixed-width digests, not variable-length inputs"
        );
        for forbidden in ["==", "!=", "starts_with", "eq_ignore_ascii_case", "cmp("] {
            assert!(
                !body.contains(forbidden),
                "`{signature}` must not use `{forbidden}`, which short-circuits on the first differing byte"
            );
        }
    }
    assert!(
        source.contains("use subtle::ConstantTimeEq;"),
        "the guard must import the constant-time comparison it relies on"
    );
}

// ---------------------------------------------------------------------------
// Replay
// ---------------------------------------------------------------------------

#[test]
fn replayed_webhook_delivery_is_refused_and_cannot_be_reopened_by_expiry() {
    let policy = ReplayPolicy {
        window: Duration::from_secs(60),
        max_tracked: 8,
    };
    let (guard, clock) = guard(two_route_guard_config().with_replay_policy(policy), NOW);

    assert!(
        guard
            .admit(
                &Method::POST,
                ROUTE_PATH,
                &delivery_headers(ROUTE_SECRET, "delivery-1", NOW),
                None,
            )
            .is_ok()
    );
    assert_eq!(
        guard
            .admit(
                &Method::POST,
                ROUTE_PATH,
                &delivery_headers(ROUTE_SECRET, "delivery-1", NOW),
                None,
            )
            .expect_err("a repeated delivery id must be refused"),
        WebhookRejection::ReplayedDelivery {
            delivery_id: "delivery-1".to_owned()
        }
    );
    assert!(
        guard
            .admit(
                &Method::POST,
                ROUTE_PATH,
                &delivery_headers(ROUTE_SECRET, "delivery-2", NOW),
                None,
            )
            .is_ok(),
        "a fresh delivery id must still be accepted"
    );
    assert!(
        guard
            .admit(
                &Method::POST,
                OTHER_CANONICAL_PATH,
                &delivery_headers(OTHER_ROUTE_SECRET, "delivery-1", NOW),
                None,
            )
            .is_ok(),
        "the replay ledger is scoped per route"
    );

    // Once the ledger entry for `delivery-1` expires, replaying it is refused as
    // stale instead of being accepted: retention and skew tolerance are one
    // window, so expiry can never reopen the replay hole.
    clock.set(NOW + 61);
    assert_eq!(
        guard
            .admit(
                &Method::POST,
                ROUTE_PATH,
                &delivery_headers(ROUTE_SECRET, "delivery-1", NOW),
                None,
            )
            .expect_err("an expired ledger entry must not readmit its delivery"),
        WebhookRejection::TimestampOutsideWindow {
            skew_seconds: 61,
            tolerance_seconds: 60
        }
    );

    clock.set(NOW);
    assert_eq!(
        guard
            .admit(
                &Method::POST,
                ROUTE_PATH,
                &delivery_headers(ROUTE_SECRET, "delivery-future", NOW + 61),
                None,
            )
            .expect_err("a far-future delivery must be refused"),
        WebhookRejection::TimestampOutsideWindow {
            skew_seconds: -61,
            tolerance_seconds: 60
        }
    );

    let malformed = [
        (
            "no delivery id",
            header_map(&[
                (WEBHOOK_SECRET_HEADER, ROUTE_SECRET),
                (WEBHOOK_TIMESTAMP_HEADER, &NOW.to_string()),
            ]),
            WebhookRejection::MissingDeliveryId,
        ),
        (
            "a delivery id with a space",
            header_map(&[
                (WEBHOOK_SECRET_HEADER, ROUTE_SECRET),
                (WEBHOOK_DELIVERY_HEADER, "delivery id"),
                (WEBHOOK_TIMESTAMP_HEADER, &NOW.to_string()),
            ]),
            WebhookRejection::MalformedDeliveryId,
        ),
        (
            "an over-long delivery id",
            header_map(&[
                (WEBHOOK_SECRET_HEADER, ROUTE_SECRET),
                (WEBHOOK_DELIVERY_HEADER, &"d".repeat(129)),
                (WEBHOOK_TIMESTAMP_HEADER, &NOW.to_string()),
            ]),
            WebhookRejection::MalformedDeliveryId,
        ),
        (
            "no timestamp",
            header_map(&[
                (WEBHOOK_SECRET_HEADER, ROUTE_SECRET),
                (WEBHOOK_DELIVERY_HEADER, "delivery-x"),
            ]),
            WebhookRejection::MissingTimestamp,
        ),
        (
            "a non-numeric timestamp",
            header_map(&[
                (WEBHOOK_SECRET_HEADER, ROUTE_SECRET),
                (WEBHOOK_DELIVERY_HEADER, "delivery-x"),
                (WEBHOOK_TIMESTAMP_HEADER, "yesterday"),
            ]),
            WebhookRejection::MalformedTimestamp,
        ),
    ];
    for (description, headers, expected) in malformed {
        assert_eq!(
            guard
                .admit(&Method::POST, ROUTE_PATH, &headers, None)
                .expect_err(description),
            expected,
            "{description} was refused for a wrong reason"
        );
    }
}

/// A ledger entry lives for one window measured from the delivery's own
/// timestamp, never from the clock at admission time.
///
/// Retaining entries for `now + window` would drop a future-dated delivery
/// while it is still fresh enough to pass the skew check, reopening the replay
/// hole the ledger exists to close.
#[test]
fn replay_ledger_retention_follows_the_delivery_timestamp_not_the_clock() {
    let policy = ReplayPolicy {
        window: Duration::from_secs(60),
        max_tracked: 8,
    };
    let (guard, clock) = guard(two_route_guard_config().with_replay_policy(policy), NOW);

    assert!(
        guard
            .admit(
                &Method::POST,
                ROUTE_PATH,
                &delivery_headers(ROUTE_SECRET, "delivery-ahead", NOW + 40),
                None,
            )
            .is_ok(),
        "a delivery inside the future tolerance is accepted"
    );

    // At NOW + 70 the delivery is still only 30 s stale, so it would be admitted
    // again if the guard had already forgotten it.
    clock.set(NOW + 70);
    assert_eq!(
        guard
            .admit(
                &Method::POST,
                ROUTE_PATH,
                &delivery_headers(ROUTE_SECRET, "delivery-ahead", NOW + 40),
                None,
            )
            .expect_err("a delivery still inside its own window must stay in the ledger"),
        WebhookRejection::ReplayedDelivery {
            delivery_id: "delivery-ahead".to_owned()
        }
    );

    // Once the delivery's own timestamp leaves the window it is refused as
    // stale, so forgetting it can never readmit it.
    clock.set(NOW + 101);
    assert_eq!(
        guard
            .admit(
                &Method::POST,
                ROUTE_PATH,
                &delivery_headers(ROUTE_SECRET, "delivery-ahead", NOW + 40),
                None,
            )
            .expect_err("an aged-out delivery must be refused as stale"),
        WebhookRejection::TimestampOutsideWindow {
            skew_seconds: 61,
            tolerance_seconds: 60
        }
    );
}

/// Only `POST` reaches the TaskFlow dispatcher, and the refusal advertises it.
#[test]
fn guarded_webhook_routes_admit_no_method_other_than_post() {
    let (guard, _clock) = guard(two_route_guard_config(), NOW);

    for method in [
        Method::GET,
        Method::PUT,
        Method::PATCH,
        Method::DELETE,
        Method::HEAD,
        Method::OPTIONS,
    ] {
        let rejection = guard
            .admit(
                &method,
                ROUTE_PATH,
                &delivery_headers(ROUTE_SECRET, "delivery-method", NOW),
                None,
            )
            .expect_err("only POST may reach the dispatcher");
        assert_eq!(
            rejection,
            WebhookRejection::MethodNotAllowed,
            "{method} was refused for a wrong reason"
        );
        let response = rejection.into_response();
        assert_eq!(response.status(), StatusCode::METHOD_NOT_ALLOWED);
        assert_eq!(
            response
                .headers()
                .get(header::ALLOW)
                .expect("a 405 advertises the methods it allows"),
            "POST"
        );
    }

    assert!(
        guard
            .admit(
                &Method::POST,
                ROUTE_PATH,
                &delivery_headers(ROUTE_SECRET, "delivery-method", NOW),
                None,
            )
            .is_ok(),
        "POST is still admitted once every other method is refused"
    );
}

/// The dispatcher only ever sees the session key the guard bound the route to.
#[test]
fn admitted_delivery_seals_the_session_header_it_forwards() {
    let admitted = AdmittedWebhook {
        route_id: ROUTE_ID.to_owned(),
        session_key: ROUTE_SESSION.to_owned(),
        max_body_bytes: 1024,
    };
    let session_header = HeaderName::from_static(WEBHOOK_SESSION_HEADER);

    // A caller may pass the guard by presenting the bound key first and then
    // smuggle a second value that the guard never inspected.
    let mut smuggled = header_map(&[(WEBHOOK_SESSION_HEADER, ROUTE_SESSION)]);
    smuggled.append(
        session_header.clone(),
        HeaderValue::from_static(OTHER_ROUTE_SESSION),
    );
    assert_eq!(
        smuggled.get_all(&session_header).iter().count(),
        2,
        "the smuggling attempt must actually reach the guard"
    );
    admitted.seal_session_binding(&mut smuggled);
    assert_eq!(
        smuggled.get_all(&session_header).iter().collect::<Vec<_>>(),
        vec![ROUTE_SESSION],
        "a sealed delivery carries exactly one session key, and it is the bound one"
    );

    // A caller that presents no session key at all is bound just as firmly.
    let mut silent = header_map(&[(WEBHOOK_SECRET_HEADER, ROUTE_SECRET)]);
    admitted.seal_session_binding(&mut silent);
    assert_eq!(
        silent.get_all(&session_header).iter().collect::<Vec<_>>(),
        vec![ROUTE_SESSION],
        "an unbound delivery is stamped with the route's session key"
    );
    assert_eq!(
        silent.get(WEBHOOK_SECRET_HEADER).map(HeaderValue::as_bytes),
        Some(ROUTE_SECRET.as_bytes()),
        "sealing the session binding must not disturb the other headers"
    );
}

#[test]
fn replay_ledger_fails_closed_once_its_bound_is_reached() {
    let policy = ReplayPolicy {
        window: Duration::from_secs(60),
        max_tracked: 3,
    };
    let (guard, clock) = guard(two_route_guard_config().with_replay_policy(policy), NOW);

    for index in 0..3 {
        assert!(
            guard
                .admit(
                    &Method::POST,
                    ROUTE_PATH,
                    &delivery_headers(ROUTE_SECRET, &format!("delivery-{index}"), NOW),
                    None,
                )
                .is_ok(),
            "delivery {index} must fit inside the bound"
        );
    }
    assert_eq!(
        guard
            .admit(
                &Method::POST,
                ROUTE_PATH,
                &delivery_headers(ROUTE_SECRET, "delivery-overflow", NOW),
                None,
            )
            .expect_err("the ledger must refuse rather than forget"),
        WebhookRejection::ReplayLedgerExhausted,
        "a full ledger must fail closed instead of evicting a live entry"
    );

    // Unauthenticated traffic can never consume ledger capacity, because the
    // secret is checked before the ledger is touched.
    assert_eq!(
        guard
            .admit(
                &Method::POST,
                ROUTE_PATH,
                &delivery_headers("wrong-secret", "delivery-unauthenticated", NOW),
                None,
            )
            .expect_err("an unauthenticated delivery must be refused"),
        WebhookRejection::SecretMismatch
    );

    clock.set(NOW + 61);
    assert!(
        guard
            .admit(
                &Method::POST,
                ROUTE_PATH,
                &delivery_headers(ROUTE_SECRET, "delivery-later", NOW + 61),
                None,
            )
            .is_ok(),
        "expired entries must be reclaimed once replaying them would be stale"
    );
}

#[tokio::test]
async fn replayed_webhook_delivery_is_dispatched_exactly_once() {
    let server = spawn(two_route_guard_config()).await;
    let headers = wire_headers(ROUTE_SECRET, "delivery-replay", "1750000000");

    let first = send(server.address, "POST", ROUTE_PATH, &headers, &list_flows()).await;
    assert_eq!(first.status, 200);

    let replayed = send(server.address, "POST", ROUTE_PATH, &headers, &list_flows()).await;
    assert_eq!(replayed.status, 409, "a replayed delivery must be refused");
    assert_eq!(replayed.code(), "replayed_delivery");

    let replayed_on_canonical_path = send(
        server.address,
        "POST",
        CANONICAL_PATH,
        &headers,
        &list_flows(),
    )
    .await;
    assert_eq!(
        replayed_on_canonical_path.status, 409,
        "the canonical path must share the replay ledger of the custom path"
    );

    server.clock.set(NOW + 10_000);
    let stale = send(server.address, "POST", ROUTE_PATH, &headers, &list_flows()).await;
    assert_eq!(stale.status, 403);
    assert_eq!(stale.code(), "stale_delivery");

    assert_eq!(
        server.webhooks.calls().len(),
        1,
        "the duplicated delivery must reach TaskFlow exactly once"
    );
}

// ---------------------------------------------------------------------------
// Body limit
// ---------------------------------------------------------------------------

#[test]
fn oversized_webhook_body_is_refused_from_headers_alone() {
    let (guard, _clock) = guard(two_route_guard_config().with_max_body_bytes(1024), NOW);
    assert_eq!(guard.config().max_body_bytes(), 1024);

    assert_eq!(
        guard
            .admit(
                &Method::POST,
                ROUTE_PATH,
                &delivery_headers(ROUTE_SECRET, "delivery-huge", NOW),
                Some(64 * 1024 * 1024),
            )
            .expect_err("a declared oversized body must be refused"),
        WebhookRejection::DeclaredBodyTooLarge {
            declared_bytes: 64 * 1024 * 1024,
            limit_bytes: 1024
        },
        "the body limit must be decided from headers, before any byte is read"
    );

    let admitted = guard
        .admit(
            &Method::POST,
            ROUTE_PATH,
            &delivery_headers(ROUTE_SECRET, "delivery-exact", NOW),
            Some(1024),
        )
        .expect("a body exactly at the limit must be admitted");
    assert_eq!(admitted.max_body_bytes, 1024);
}

#[tokio::test]
async fn oversized_webhook_body_is_refused_whether_or_not_its_length_is_declared() {
    let server = spawn(two_route_guard_config().with_max_body_bytes(1024)).await;
    // Eight kibibytes is comfortably over the limit yet still fits in the socket
    // buffers, so the refusal is observed rather than racing the write.
    let oversized = serde_json::to_vec(&json!({
        "action": "create_flow",
        "goal": "x".repeat(8 * 1024),
    }))
    .expect("serialize oversized action");

    let declared = send(
        server.address,
        "POST",
        ROUTE_PATH,
        &wire_headers(ROUTE_SECRET, "delivery-declared", &NOW.to_string()),
        &oversized,
    )
    .await;
    assert_eq!(declared.status, 413);
    assert_eq!(declared.code(), "payload_too_large");

    let streamed = send_chunked(
        server.address,
        ROUTE_PATH,
        &wire_headers(ROUTE_SECRET, "delivery-streamed", &NOW.to_string()),
        &oversized,
    )
    .await;
    assert_eq!(
        streamed.status, 413,
        "an undeclared oversized body must still be capped"
    );
    assert_eq!(streamed.code(), "payload_too_large");

    let within_limit = send(
        server.address,
        "POST",
        ROUTE_PATH,
        &wire_headers(ROUTE_SECRET, "delivery-small", &NOW.to_string()),
        &list_flows(),
    )
    .await;
    assert_eq!(within_limit.status, 200);

    assert_eq!(
        server.webhooks.calls().len(),
        1,
        "no oversized body reached TaskFlow"
    );
}

// ---------------------------------------------------------------------------
// Session binding
// ---------------------------------------------------------------------------

#[test]
fn webhook_session_binding_refuses_a_cross_session_delivery() {
    let (guard, _clock) = guard(two_route_guard_config(), NOW);

    let mut bound = delivery_headers(ROUTE_SECRET, "delivery-bound", NOW);
    bound.insert(
        HeaderName::from_static(WEBHOOK_SESSION_HEADER),
        HeaderValue::from_static(ROUTE_SESSION),
    );
    let admitted = guard
        .admit(&Method::POST, ROUTE_PATH, &bound, None)
        .expect("the bound session must be admitted");
    assert_eq!(admitted.route_id, ROUTE_ID);
    assert_eq!(admitted.session_key, ROUTE_SESSION);

    let unclaimed = guard
        .admit(
            &Method::POST,
            ROUTE_PATH,
            &delivery_headers(ROUTE_SECRET, "delivery-unclaimed", NOW),
            None,
        )
        .expect("a delivery that claims no session inherits the route binding");
    assert_eq!(
        unclaimed.session_key, ROUTE_SESSION,
        "the guard, not the caller, decides which session a delivery drives"
    );

    let mut crossed = delivery_headers(ROUTE_SECRET, "delivery-crossed", NOW);
    crossed.insert(
        HeaderName::from_static(WEBHOOK_SESSION_HEADER),
        HeaderValue::from_static(OTHER_ROUTE_SESSION),
    );
    assert_eq!(
        guard
            .admit(&Method::POST, ROUTE_PATH, &crossed, None)
            .expect_err("a cross-session delivery must be refused"),
        WebhookRejection::SessionMismatch {
            expected: ROUTE_SESSION.to_owned(),
            presented: OTHER_ROUTE_SESSION.to_owned(),
        }
    );
    assert_eq!(
        guard
            .admit(&Method::POST, CANONICAL_PATH, &crossed, None)
            .expect_err("the canonical path must enforce the same binding"),
        WebhookRejection::SessionMismatch {
            expected: ROUTE_SESSION.to_owned(),
            presented: OTHER_ROUTE_SESSION.to_owned(),
        }
    );

    let refused = WebhookRejection::SessionMismatch {
        expected: ROUTE_SESSION.to_owned(),
        presented: OTHER_ROUTE_SESSION.to_owned(),
    };
    assert!(
        !refused.wire_message().contains(ROUTE_SESSION)
            && !refused.wire_message().contains(OTHER_ROUTE_SESSION),
        "a refusal must not echo any session key back to the caller"
    );

    // Refusing the binding must not consume the delivery id, so an integration
    // that is corrected and retried is not permanently locked out.
    let mut corrected = delivery_headers(ROUTE_SECRET, "delivery-crossed", NOW);
    corrected.insert(
        HeaderName::from_static(WEBHOOK_SESSION_HEADER),
        HeaderValue::from_static(ROUTE_SESSION),
    );
    assert!(
        guard
            .admit(&Method::POST, ROUTE_PATH, &corrected, None)
            .is_ok(),
        "a refused delivery must not burn its delivery id"
    );
}

#[tokio::test]
async fn cross_session_webhook_delivery_is_refused_before_dispatch() {
    let server = spawn(two_route_guard_config()).await;

    let crossed = send(
        server.address,
        "POST",
        ROUTE_PATH,
        &[
            (WEBHOOK_SECRET_HEADER, ROUTE_SECRET),
            (WEBHOOK_DELIVERY_HEADER, "delivery-crossed"),
            (WEBHOOK_TIMESTAMP_HEADER, "1750000000"),
            (WEBHOOK_SESSION_HEADER, OTHER_ROUTE_SESSION),
        ],
        &list_flows(),
    )
    .await;
    assert_eq!(crossed.status, 403);
    assert_eq!(crossed.code(), "session_mismatch");
    assert!(
        !String::from_utf8_lossy(&crossed.body).contains(ROUTE_SESSION),
        "the refusal leaked the bound session key"
    );
    assert!(
        server.webhooks.calls().is_empty(),
        "a cross-session delivery must never reach TaskFlow"
    );

    let bound = send(
        server.address,
        "POST",
        ROUTE_PATH,
        &[
            (WEBHOOK_SECRET_HEADER, ROUTE_SECRET),
            (WEBHOOK_DELIVERY_HEADER, "delivery-bound"),
            (WEBHOOK_TIMESTAMP_HEADER, "1750000000"),
            (WEBHOOK_SESSION_HEADER, ROUTE_SESSION),
        ],
        &list_flows(),
    )
    .await;
    assert_eq!(bound.status, 200);
    assert_eq!(server.webhooks.calls().len(), 1);
}

// ---------------------------------------------------------------------------
// TaskFlow dispatch
// ---------------------------------------------------------------------------

#[derive(serde::Deserialize)]
struct ActionCorpus {
    accepted: Vec<ActionCase>,
    rejected: Vec<ActionCase>,
}

#[derive(serde::Deserialize)]
struct ActionCase {
    name: String,
    action: Value,
}

#[tokio::test]
async fn guarded_route_dispatches_every_frozen_taskflow_action_and_refuses_the_rest() {
    let corpus: ActionCorpus = serde_json::from_str(
        &fs::read_to_string(fixture_path("taskflow-actions.json"))
            .expect("read the TaskFlow action corpus"),
    )
    .expect("parse the TaskFlow action corpus");
    assert_eq!(
        corpus.accepted.len(),
        15,
        "the corpus must exercise every frozen TaskFlow action"
    );
    assert!(corpus.rejected.len() >= 10);

    let server = spawn(two_route_guard_config()).await;

    for case in &corpus.accepted {
        let body = serde_json::to_vec(&case.action).expect("serialize action");
        let response = send(
            server.address,
            "POST",
            ROUTE_PATH,
            &wire_headers(ROUTE_SECRET, &format!("ok-{}", case.name), &NOW.to_string()),
            &body,
        )
        .await;
        assert_eq!(response.status, 200, "{} was not dispatched", case.name);
        let payload = response.json();
        assert_eq!(payload["ok"], json!(true), "{}", case.name);
        assert_eq!(payload["routeId"], json!(ROUTE_ID), "{}", case.name);
        assert_eq!(
            payload["result"]["action"], case.action,
            "{} was altered on the way to TaskFlow",
            case.name
        );
    }

    let dispatched = server.webhooks.calls();
    assert_eq!(dispatched.len(), corpus.accepted.len());
    for (case, (route_id, action)) in corpus.accepted.iter().zip(dispatched.iter()) {
        assert_eq!(route_id, ROUTE_ID, "{}", case.name);
        assert_eq!(
            action, &case.action,
            "{} reached TaskFlow with a different payload",
            case.name
        );
    }

    for case in &corpus.rejected {
        let body = serde_json::to_vec(&case.action).expect("serialize action");
        let response = send(
            server.address,
            "POST",
            ROUTE_PATH,
            &wire_headers(
                ROUTE_SECRET,
                &format!("bad-{}", case.name),
                &NOW.to_string(),
            ),
            &body,
        )
        .await;
        assert_eq!(response.status, 400, "{} was not refused", case.name);
        assert_eq!(response.code(), "invalid_request", "{}", case.name);
        assert_eq!(response.json()["ok"], json!(false), "{}", case.name);
    }

    assert_eq!(
        server.webhooks.calls().len(),
        corpus.accepted.len(),
        "a malformed action must never reach TaskFlow"
    );
}

#[tokio::test]
async fn taskflow_dispatch_failure_is_reported_with_its_outcome_code() {
    let server = spawn(two_route_guard_config()).await;
    server.webhooks.set_outcome(WebhookOutcome {
        status: 409,
        code: Some("revision_conflict".to_owned()),
        error: Some("expectedRevision is stale".to_owned()),
        result: json!({"currentRevision": 7}),
    });

    let response = send(
        server.address,
        "POST",
        ROUTE_PATH,
        &wire_headers(ROUTE_SECRET, "delivery-conflict", &NOW.to_string()),
        &serde_json::to_vec(&json!({
            "action": "finish_flow",
            "flowId": "flow-1",
            "expectedRevision": 3
        }))
        .expect("serialize action"),
    )
    .await;

    assert_eq!(response.status, 409);
    let payload = response.json();
    assert_eq!(payload["ok"], json!(false));
    assert_eq!(payload["routeId"], json!(ROUTE_ID));
    assert_eq!(payload["code"], json!("revision_conflict"));
    assert_eq!(payload["error"], json!("expectedRevision is stale"));
    assert_eq!(payload["result"], json!({"currentRevision": 7}));
    assert_eq!(server.webhooks.calls().len(), 1);
}

// ---------------------------------------------------------------------------
// Isolation
// ---------------------------------------------------------------------------

#[tokio::test]
async fn the_webhook_guard_leaves_every_other_route_untouched() {
    let guarded = spawn(two_route_guard_config()).await;
    let unguarded = spawn_unguarded().await;

    let probes = [
        ("GET", "/health", vec![]),
        ("GET", "/ready", vec![]),
        ("GET", "/v1/models", vec![]),
        (
            "GET",
            "/v1/models",
            vec![("Authorization", "Bearer operator-token")],
        ),
        ("GET", "/not-a-route", vec![]),
        ("POST", "/health", vec![]),
    ];

    for (method, path, headers) in probes {
        let with_guard = send(guarded.address, method, path, &headers, b"").await;
        let without_guard = send(unguarded.address, method, path, &headers, b"").await;
        assert_eq!(
            with_guard.status, without_guard.status,
            "{method} {path} changed status once the webhook guard was installed"
        );
        assert_eq!(
            with_guard.body, without_guard.body,
            "{method} {path} changed body once the webhook guard was installed"
        );
        assert_eq!(
            with_guard.headers.get("allow"),
            without_guard.headers.get("allow"),
            "{method} {path} changed its Allow header once the webhook guard was installed"
        );
    }

    let health = send(guarded.address, "GET", "/health", &[], b"").await;
    assert_eq!(health.status, 200, "the guard swallowed an unrelated route");
    let authenticated_models = send(
        guarded.address,
        "GET",
        "/v1/models",
        &[("Authorization", "Bearer operator-token")],
        b"",
    )
    .await;
    assert_eq!(authenticated_models.status, 200);
    let unauthenticated_models = send(guarded.address, "GET", "/v1/models", &[], b"").await;
    assert_eq!(
        unauthenticated_models.status, 401,
        "the guard must not weaken bearer authentication"
    );

    assert!(guarded.webhooks.calls().is_empty());
    assert!(unguarded.webhooks.calls().is_empty());
}

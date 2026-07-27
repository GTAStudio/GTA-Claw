//! Admin HTTP RPC dispatch contract.
//!
//! These tests exercise `POST /api/v1/admin/rpc` over real TCP sockets and
//! prove the three properties the surface exists to guarantee:
//!
//! 1. **Authentication.** A request that produces no verified caller is
//!    refused with `401` before any body is parsed and before the Gateway is
//!    reached, and a wrong credential is indistinguishable from a missing one.
//! 2. **Method policy.** The allowlist is fail-closed: only names listed
//!    verbatim, defined by the frozen Gateway registry, and classified as an
//!    operator scope are dispatched.
//! 3. **Error mapping.** Each failure class maps to its own status and stable
//!    code, and only a Gateway code outside the frozen table becomes a `500`.

use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::net::SocketAddr;
use std::path::Path;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use claw_http_api::{
    ADMIN_HTTP_RPC_METHODS, ADMIN_RPC_PATH, AdminFailure, AdminMethodPolicy, AdminPort,
    AdminRpcAuthRejection, AdminRpcAuthenticator, AdminRpcCaller, AdminRpcEnvelope, AdminRpcError,
    AdminRpcLimits, AdminRpcService, AdminSuccess, AuditPort, FnAuthenticator, PortError,
    PortErrorKind, PortFuture,
};
use claw_security::audit::{AuditEvent, AuditOutcome};
use claw_security::authorization::{Role, Scope, ScopeSet};
use serde::Deserialize;
use serde_json::{Value, json};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::task::JoinHandle;
use tokio::time::{sleep, timeout};
use tokio_util::sync::CancellationToken;

const OPERATOR_TOKEN: &str = "admin-operator-token";
const READ_ONLY_TOKEN: &str = "read-only-token";

// ---------------------------------------------------------------------------
// Fixtures
// ---------------------------------------------------------------------------

#[derive(Deserialize)]
struct ErrorMappingFixture {
    classes: Vec<ErrorClassRow>,
    dispatch_codes: Vec<DispatchCodeRow>,
}

#[derive(Deserialize)]
struct ErrorClassRow {
    class: String,
    status: u16,
    envelope: String,
    code: String,
}

#[derive(Deserialize)]
struct DispatchCodeRow {
    code: String,
    status: u16,
}

#[derive(Deserialize)]
struct MethodPolicyFixture {
    frozen_policy: Vec<MethodPolicyCase>,
    widened_policy: WidenedPolicyFixture,
}

#[derive(Deserialize)]
struct WidenedPolicyFixture {
    methods: Vec<String>,
    cases: Vec<MethodPolicyCase>,
}

#[derive(Deserialize)]
struct MethodPolicyCase {
    method: String,
    outcome: String,
    #[serde(default)]
    required_scope: Option<String>,
}

fn fixture<T: for<'de> Deserialize<'de>>(name: &str) -> T {
    let path = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests")
        .join("fixtures")
        .join("admin_rpc")
        .join(name);
    let source = fs::read_to_string(&path)
        .unwrap_or_else(|error| panic!("read fixture {}: {error}", path.display()));
    let source = source.strip_prefix('\u{feff}').unwrap_or(&source);
    serde_json::from_str(source)
        .unwrap_or_else(|error| panic!("parse fixture {}: {error}", path.display()))
}

// ---------------------------------------------------------------------------
// Adapters
// ---------------------------------------------------------------------------

/// An admin adapter whose behavior is driven entirely by the request params, so
/// one running server can produce every Gateway outcome.
#[derive(Default)]
struct ScriptedAdmin {
    calls: Mutex<Vec<String>>,
}

impl ScriptedAdmin {
    fn calls(&self) -> Vec<String> {
        self.calls.lock().expect("read dispatch log").clone()
    }
}

impl AdminPort for ScriptedAdmin {
    fn dispatch(
        &self,
        method: String,
        params: Option<Value>,
        _cancellation: CancellationToken,
    ) -> PortFuture<'_, Result<AdminSuccess, AdminFailure>> {
        self.calls
            .lock()
            .expect("record dispatch")
            .push(method.clone());
        Box::pin(async move {
            let params = params.unwrap_or(Value::Null);
            if let Some(sleep_ms) = params.get("sleepMs").and_then(Value::as_u64) {
                sleep(Duration::from_millis(sleep_ms)).await;
            }
            if let Some(code) = params.get("failCode").and_then(Value::as_str) {
                return Err(AdminFailure {
                    code: code.to_owned(),
                    message: format!("gateway refused {method}"),
                    details: Some(json!({"method": method})),
                    retryable: Some(false),
                    retry_after_ms: None,
                });
            }
            Ok(AdminSuccess {
                payload: json!({"method": method, "params": params}),
                meta: None,
            })
        })
    }
}

/// A durable audit adapter that can be made to fail, which is the only way the
/// authorization decision becomes unavailable.
struct RecordingAudit {
    events: Mutex<Vec<AuditEvent>>,
    offline: bool,
}

impl RecordingAudit {
    const fn online() -> Self {
        Self {
            events: Mutex::new(Vec::new()),
            offline: false,
        }
    }

    const fn offline() -> Self {
        Self {
            events: Mutex::new(Vec::new()),
            offline: true,
        }
    }

    fn events(&self) -> Vec<AuditEvent> {
        self.events.lock().expect("read audit log").clone()
    }
}

impl AuditPort for RecordingAudit {
    fn persist(&self, event: &AuditEvent) -> Result<(), PortError> {
        if self.offline {
            return Err(PortError::new(
                PortErrorKind::Unavailable,
                "audit sink offline",
            ));
        }
        self.events
            .lock()
            .expect("record audit event")
            .push(event.clone());
        Ok(())
    }
}

/// A stand-in for the authentication domain that owns `POST /api/v1/admin/rpc`.
///
/// The dispatch surface never inspects credentials itself: it only consumes the
/// `AdminRpcCaller` this returns, which is exactly the seam a dedicated admin
/// authenticator plugs into.
fn token_authenticator() -> Arc<dyn AdminRpcAuthenticator> {
    Arc::new(FnAuthenticator::new(|headers: &http::HeaderMap| {
        let Some(value) = headers.get(http::header::AUTHORIZATION) else {
            return Err(AdminRpcAuthRejection::Missing);
        };
        let value = value.to_str().map_err(|_| AdminRpcAuthRejection::Invalid)?;
        let token = value
            .strip_prefix("Bearer ")
            .ok_or(AdminRpcAuthRejection::Invalid)?;
        match token {
            OPERATOR_TOKEN => Ok(AdminRpcCaller::new(
                "operator",
                Role::Operator,
                ScopeSet::from_scopes([Scope::OperatorAdmin]),
            )),
            READ_ONLY_TOKEN => Ok(AdminRpcCaller::new(
                "reader",
                Role::Operator,
                ScopeSet::from_scopes([Scope::OperatorRead]),
            )),
            _ => Err(AdminRpcAuthRejection::Invalid),
        }
    }))
}

// ---------------------------------------------------------------------------
// Server harness
// ---------------------------------------------------------------------------

struct Server {
    address: SocketAddr,
    admin: Arc<ScriptedAdmin>,
    audit: Arc<RecordingAudit>,
    task: JoinHandle<()>,
}

impl Drop for Server {
    fn drop(&mut self) {
        self.task.abort();
    }
}

struct ServerOptions {
    policy: AdminMethodPolicy,
    limits: AdminRpcLimits,
    audit: Arc<RecordingAudit>,
}

impl Default for ServerOptions {
    fn default() -> Self {
        Self {
            policy: AdminMethodPolicy::frozen(),
            limits: AdminRpcLimits::default(),
            audit: Arc::new(RecordingAudit::online()),
        }
    }
}

async fn spawn(options: ServerOptions) -> Server {
    let admin = Arc::new(ScriptedAdmin::default());
    let audit = options.audit;
    let service = AdminRpcService::new(admin.clone(), audit.clone())
        .with_authenticator(token_authenticator())
        .with_policy(options.policy)
        .with_limits(options.limits);
    let listener = TcpListener::bind(SocketAddr::from(([127, 0, 0, 1], 0)))
        .await
        .expect("bind loopback listener");
    let address = listener.local_addr().expect("read bound address");
    let router = service.router();
    let task = tokio::spawn(async move {
        let _ = axum::serve(listener, router).await;
    });
    Server {
        address,
        admin,
        audit,
        task,
    }
}

struct HttpResponse {
    status: u16,
    headers: BTreeMap<String, String>,
    body: Vec<u8>,
}

impl HttpResponse {
    fn json(&self) -> Value {
        serde_json::from_slice(&self.body).unwrap_or_else(|error| {
            panic!(
                "response body is not JSON ({error}): {}",
                String::from_utf8_lossy(&self.body)
            )
        })
    }

    fn header(&self, name: &str) -> Option<&str> {
        self.headers.get(name).map(String::as_str)
    }
}

async fn send(
    address: SocketAddr,
    method: &str,
    token: Option<&str>,
    body: &[u8],
    declared_length: Option<usize>,
) -> HttpResponse {
    let mut stream = TcpStream::connect(address)
        .await
        .expect("connect to server");
    let mut head = format!(
        "{method} {ADMIN_RPC_PATH} HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\nContent-Type: application/json\r\nContent-Length: {}\r\n",
        declared_length.unwrap_or(body.len())
    );
    if let Some(token) = token {
        head.push_str("Authorization: Bearer ");
        head.push_str(token);
        head.push_str("\r\n");
    }
    head.push_str("\r\n");
    stream
        .write_all(head.as_bytes())
        .await
        .expect("write request head");
    stream.write_all(body).await.expect("write request body");
    stream.flush().await.expect("flush request");
    let mut raw = Vec::new();
    timeout(Duration::from_secs(10), stream.read_to_end(&mut raw))
        .await
        .expect("response arrived before the test deadline")
        .expect("read response");
    parse_response(&raw)
}

async fn post(address: SocketAddr, token: Option<&str>, body: &Value) -> HttpResponse {
    let encoded = serde_json::to_vec(body).expect("serialize request body");
    send(address, "POST", token, &encoded, None).await
}

fn parse_response(raw: &[u8]) -> HttpResponse {
    let split = raw
        .windows(4)
        .position(|window| window == b"\r\n\r\n")
        .expect("response carries a header terminator");
    let head = std::str::from_utf8(&raw[..split]).expect("response head is UTF-8");
    let body = raw[split + 4..].to_vec();
    let mut lines = head.split("\r\n");
    let status_line = lines.next().expect("response carries a status line");
    let status = status_line
        .split_whitespace()
        .nth(1)
        .expect("status line carries a code")
        .parse()
        .expect("status code is numeric");
    let mut headers = BTreeMap::new();
    for line in lines {
        if let Some((name, value)) = line.split_once(':') {
            headers.insert(name.trim().to_ascii_lowercase(), value.trim().to_owned());
        }
    }
    HttpResponse {
        status,
        headers,
        body,
    }
}

/// Exhaustively names one failure class.
///
/// The `match` is deliberately not wildcarded: adding a variant to
/// `AdminRpcError` fails compilation here until the fixture gains a reviewed
/// row for the new class.
const fn class_name(error: &AdminRpcError) -> &'static str {
    match error {
        AdminRpcError::Unauthenticated => "unauthenticated",
        AdminRpcError::Forbidden(_) => "forbidden",
        AdminRpcError::AuthorizationUnavailable => "authorization_unavailable",
        AdminRpcError::MethodNotAllowlisted { .. } => "method_not_allowlisted",
        AdminRpcError::MethodNotRegistered { .. } => "method_not_registered",
        AdminRpcError::MethodNotOperatorSurface { .. } => "method_not_operator_surface",
        AdminRpcError::MalformedRequest { .. } => "malformed_request",
        AdminRpcError::BodyTooLarge => "body_too_large",
        AdminRpcError::BodyTimeout => "body_timeout",
        AdminRpcError::DispatchTimeout => "dispatch_timeout",
        AdminRpcError::Dispatch(_) => "dispatch",
    }
}

fn every_error_class() -> Vec<AdminRpcError> {
    vec![
        AdminRpcError::Unauthenticated,
        AdminRpcError::Forbidden(Scope::OperatorAdmin),
        AdminRpcError::AuthorizationUnavailable,
        AdminRpcError::MethodNotAllowlisted {
            method: "chat.send".to_owned(),
        },
        AdminRpcError::MethodNotRegistered {
            method: "not.a.registry.method".to_owned(),
        },
        AdminRpcError::MethodNotOperatorSurface {
            method: "node.event".to_owned(),
        },
        AdminRpcError::MalformedRequest {
            message: "request body must be an object".to_owned(),
        },
        AdminRpcError::BodyTooLarge,
        AdminRpcError::BodyTimeout,
        AdminRpcError::DispatchTimeout,
        AdminRpcError::Dispatch(AdminFailure {
            code: "GATEWAY_CODE".to_owned(),
            message: "gateway refused".to_owned(),
            details: None,
            retryable: None,
            retry_after_ms: None,
        }),
    ]
}

// ---------------------------------------------------------------------------
// 1. Authentication
// ---------------------------------------------------------------------------

#[tokio::test]
async fn unauthenticated_admin_rpc_requests_are_refused_before_dispatch() {
    let server = spawn(ServerOptions::default()).await;
    let call = json!({"id":"rpc-auth","method":"status","params":{"verbose":true}});

    let anonymous = post(server.address, None, &call).await;
    assert_eq!(anonymous.status, 401);
    assert_eq!(
        anonymous.json(),
        json!({"ok":false,"error":{"type":"unauthorized","message":"Unauthorized"}})
    );
    assert_eq!(
        anonymous.header("www-authenticate"),
        Some("Bearer realm=\"admin\"")
    );
    assert_eq!(anonymous.header("cache-control"), Some("no-store"));

    let wrong_credential = post(server.address, Some("not-a-real-token"), &call).await;
    assert_eq!(wrong_credential.status, 401);
    assert_eq!(
        wrong_credential.json(),
        anonymous.json(),
        "a wrong credential must be indistinguishable from a missing one"
    );

    let empty_credential = post(server.address, Some(""), &call).await;
    assert_eq!(empty_credential.status, 401);
    assert_eq!(empty_credential.json(), anonymous.json());

    assert_eq!(
        server.admin.calls(),
        Vec::<String>::new(),
        "no unauthenticated request may reach the Gateway"
    );
    assert_eq!(
        server.audit.events(),
        Vec::new(),
        "no unauthenticated request may produce an authorization decision"
    );

    let authenticated = post(server.address, Some(OPERATOR_TOKEN), &call).await;
    assert_eq!(authenticated.status, 200);
    assert_eq!(
        authenticated.json(),
        json!({
            "id":"rpc-auth",
            "ok":true,
            "payload":{"method":"status","params":{"verbose":true}}
        })
    );
    assert_eq!(server.admin.calls(), vec!["status".to_owned()]);
    assert_eq!(server.audit.events().len(), 1);
}

#[tokio::test]
async fn admin_rpc_is_bound_to_post_only() {
    let server = spawn(ServerOptions::default()).await;
    let response = send(server.address, "GET", Some(OPERATOR_TOKEN), b"", None).await;
    assert_eq!(response.status, 405);
    assert_eq!(response.header("allow"), Some("POST"));
    assert_eq!(server.admin.calls(), Vec::<String>::new());
}

// ---------------------------------------------------------------------------
// 2. Method policy
// ---------------------------------------------------------------------------

#[tokio::test]
async fn admin_rpc_method_policy_is_fail_closed() {
    let cases: MethodPolicyFixture = fixture("method-policy.json");

    let frozen = AdminMethodPolicy::frozen();
    for case in &cases.frozen_policy {
        assert_policy_case(&frozen, case);
    }

    let widened = AdminMethodPolicy::new(cases.widened_policy.methods.iter().cloned());
    for case in &cases.widened_policy.cases {
        assert_policy_case(&widened, case);
    }

    assert!(
        cases
            .frozen_policy
            .iter()
            .any(|case| case.outcome == "not_allowlisted"),
        "the fixture must exercise the fail-closed default"
    );

    // Every allowlisted method must be a registry-defined operator method, so no
    // entry can quietly open the node or dynamic-plugin surface over HTTP.
    for method in frozen.methods() {
        frozen
            .required_scope(method)
            .unwrap_or_else(|error| panic!("{method} is allowlisted but refused: {error:?}"));
    }
    assert_eq!(
        frozen.methods().len(),
        ADMIN_HTTP_RPC_METHODS.len(),
        "the frozen policy is exactly the frozen allowlist"
    );
}

fn assert_policy_case(policy: &AdminMethodPolicy, case: &MethodPolicyCase) {
    let outcome = policy.required_scope(&case.method);
    match (case.outcome.as_str(), outcome) {
        ("allowed", Ok(scope)) => {
            let expected = case
                .required_scope
                .as_deref()
                .expect("an allowed case names its required scope");
            assert_eq!(
                scope.as_str(),
                expected,
                "{} resolved to the wrong scope",
                case.method
            );
        }
        ("not_allowlisted", Err(AdminRpcError::MethodNotAllowlisted { method }))
        | ("not_registered", Err(AdminRpcError::MethodNotRegistered { method }))
        | ("not_operator_surface", Err(AdminRpcError::MethodNotOperatorSurface { method })) => {
            assert_eq!(method, case.method);
        }
        (expected, actual) => panic!(
            "method {:?} expected outcome {expected} but produced {actual:?}",
            case.method
        ),
    }
}

#[tokio::test]
async fn admin_rpc_refuses_methods_outside_the_policy_over_http() {
    let server = spawn(ServerOptions::default()).await;

    let unlisted = post(
        server.address,
        Some(OPERATOR_TOKEN),
        &json!({"id":"rpc-unlisted","method":"chat.send"}),
    )
    .await;
    assert_eq!(unlisted.status, 400);
    assert_eq!(
        unlisted.json(),
        json!({
            "id":"rpc-unlisted",
            "ok":false,
            "error":{
                "code":"INVALID_REQUEST",
                "message":"admin HTTP RPC method is not supported: chat.send"
            }
        })
    );

    let unknown = post(
        server.address,
        Some(OPERATOR_TOKEN),
        &json!({"id":"rpc-unknown","method":"totally.unknown.method"}),
    )
    .await;
    assert_eq!(unknown.status, 400);
    assert_eq!(
        unknown.json()["error"]["code"],
        json!("INVALID_REQUEST"),
        "an unknown method is refused by the same fail-closed default"
    );

    let cased = post(
        server.address,
        Some(OPERATOR_TOKEN),
        &json!({"id":"rpc-cased","method":"Status"}),
    )
    .await;
    assert_eq!(cased.status, 400);

    assert_eq!(
        server.admin.calls(),
        Vec::<String>::new(),
        "a policy refusal must never reach the Gateway"
    );

    let listed = post(
        server.address,
        Some(OPERATOR_TOKEN),
        &json!({"id":"rpc-listed","method":"logs.tail"}),
    )
    .await;
    assert_eq!(listed.status, 200);
    assert_eq!(server.admin.calls(), vec!["logs.tail".to_owned()]);
}

#[tokio::test]
async fn admin_rpc_refuses_widened_policy_entries_the_registry_will_not_bless() {
    let cases: MethodPolicyFixture = fixture("method-policy.json");
    let server = spawn(ServerOptions {
        policy: AdminMethodPolicy::new(cases.widened_policy.methods.iter().cloned()),
        ..ServerOptions::default()
    })
    .await;

    let node_only = post(
        server.address,
        Some(OPERATOR_TOKEN),
        &json!({"id":"rpc-node","method":"node.event"}),
    )
    .await;
    assert_eq!(node_only.status, 403);
    assert_eq!(
        node_only.json(),
        json!({
            "ok":false,
            "error":{
                "type":"forbidden",
                "message":"method is not available to the trusted operator surface"
            }
        })
    );

    let dynamic = post(
        server.address,
        Some(OPERATOR_TOKEN),
        &json!({"id":"rpc-dynamic","method":"sessions.create"}),
    )
    .await;
    assert_eq!(dynamic.status, 403);

    let unregistered = post(
        server.address,
        Some(OPERATOR_TOKEN),
        &json!({"id":"rpc-unregistered","method":"not.a.registry.method"}),
    )
    .await;
    assert_eq!(unregistered.status, 400);
    assert_eq!(
        unregistered.json(),
        json!({
            "ok":false,
            "error":{
                "type":"invalid_request",
                "message":"method is not in the frozen Gateway registry"
            }
        })
    );

    assert_eq!(
        server.admin.calls(),
        Vec::<String>::new(),
        "allowlisting a name the registry rejects must not open dispatch"
    );
}

#[tokio::test]
async fn admin_rpc_self_describes_exactly_the_methods_it_will_dispatch() {
    let server = spawn(ServerOptions::default()).await;
    let response = post(
        server.address,
        Some(OPERATOR_TOKEN),
        &json!({"id":"rpc-commands","method":"commands.list"}),
    )
    .await;
    assert_eq!(response.status, 200);
    let advertised: Vec<String> =
        serde_json::from_value(response.json()["payload"]["methods"].clone())
            .expect("commands.list advertises a method list");
    assert_eq!(
        advertised,
        ADMIN_HTTP_RPC_METHODS
            .iter()
            .map(|method| (*method).to_owned())
            .collect::<Vec<_>>()
    );
    assert_eq!(
        advertised.iter().collect::<BTreeSet<_>>().len(),
        advertised.len(),
        "the allowlist carries no duplicate entry"
    );
    assert_eq!(
        server.admin.calls(),
        Vec::<String>::new(),
        "commands.list is answered from policy and never dispatched"
    );
}

#[tokio::test]
async fn admin_rpc_denies_an_allowlisted_method_the_caller_lacks_scope_for() {
    let server = spawn(ServerOptions::default()).await;

    let denied = post(
        server.address,
        Some(READ_ONLY_TOKEN),
        &json!({"id":"rpc-scope","method":"config.set","params":{}}),
    )
    .await;
    assert_eq!(denied.status, 403);
    assert_eq!(
        denied.json(),
        json!({"ok":false,"error":{"type":"forbidden","message":"missing scope: operator.admin"}})
    );
    assert_eq!(
        server.admin.calls(),
        Vec::<String>::new(),
        "a scope denial must never reach the Gateway"
    );
    let events = server.audit.events();
    assert_eq!(events.len(), 1, "the denial is durably audited");
    assert_eq!(events[0].outcome, AuditOutcome::Denied);

    let permitted = post(
        server.address,
        Some(READ_ONLY_TOKEN),
        &json!({"id":"rpc-scope-ok","method":"status"}),
    )
    .await;
    assert_eq!(
        permitted.status, 200,
        "the same caller keeps the methods its scope does cover"
    );
    assert_eq!(server.admin.calls(), vec!["status".to_owned()]);
}

// ---------------------------------------------------------------------------
// 3. Error mapping
// ---------------------------------------------------------------------------

#[tokio::test]
async fn admin_rpc_error_classes_map_to_their_own_status_and_code() {
    let mapping: ErrorMappingFixture = fixture("error-mapping.json");
    let rows: BTreeMap<&str, &ErrorClassRow> = mapping
        .classes
        .iter()
        .map(|row| (row.class.as_str(), row))
        .collect();
    assert_eq!(
        rows.len(),
        mapping.classes.len(),
        "the mapping table lists each class once"
    );

    let classes = every_error_class();
    let named: BTreeSet<&str> = classes.iter().map(class_name).collect();
    assert_eq!(
        named,
        rows.keys().copied().collect::<BTreeSet<_>>(),
        "the mapping table and the failure taxonomy must agree exactly"
    );

    for error in &classes {
        let row = rows[class_name(error)];
        assert_eq!(
            error.status().as_u16(),
            row.status,
            "class {} mapped to the wrong status",
            row.class
        );
        assert_eq!(
            error.code(),
            row.code,
            "class {} carries a wrong code",
            row.class
        );
        let envelope = match row.envelope.as_str() {
            "transport" => AdminRpcEnvelope::Transport,
            "rpc" => AdminRpcEnvelope::Rpc,
            other => panic!("unknown envelope {other} in the mapping table"),
        };
        assert_eq!(
            error.envelope(),
            envelope,
            "class {} used the wrong envelope",
            row.class
        );
        assert!(
            !error.message().is_empty(),
            "class {} carries no message",
            row.class
        );
    }

    let statuses: BTreeSet<u16> = classes
        .iter()
        .map(|error| error.status().as_u16())
        .collect();
    assert_eq!(
        statuses,
        BTreeSet::from([400, 401, 403, 408, 413, 500, 503, 504]),
        "the taxonomy must keep one status per meaning"
    );
    assert_eq!(
        classes
            .iter()
            .filter(|error| error.status().as_u16() == 500)
            .count(),
        1,
        "only an unrecognised Gateway code may be reported as an internal error"
    );
}

#[tokio::test]
async fn admin_rpc_maps_every_gateway_failure_code_over_http() {
    let mapping: ErrorMappingFixture = fixture("error-mapping.json");
    let server = spawn(ServerOptions::default()).await;

    for row in &mapping.dispatch_codes {
        let response = post(
            server.address,
            Some(OPERATOR_TOKEN),
            &json!({"id":"rpc-fail","method":"status","params":{"failCode":row.code}}),
        )
        .await;
        assert_eq!(
            response.status, row.status,
            "gateway code {} mapped to the wrong status",
            row.code
        );
        assert_eq!(
            response.json(),
            json!({
                "id":"rpc-fail",
                "ok":false,
                "error":{
                    "code":row.code,
                    "message":"gateway refused status",
                    "details":{"method":"status"},
                    "retryable":false
                }
            }),
            "gateway code {} rendered the wrong body",
            row.code
        );
    }

    let distinct: BTreeSet<u16> = mapping
        .dispatch_codes
        .iter()
        .map(|row| row.status)
        .collect();
    assert_eq!(
        distinct,
        BTreeSet::from([400, 401, 403, 404, 409, 429, 500, 503, 504]),
        "gateway failures must not collapse onto one status"
    );
    assert_eq!(
        server.admin.calls().len(),
        mapping.dispatch_codes.len(),
        "every mapped code came from a real dispatch"
    );
}

#[tokio::test]
async fn admin_rpc_maps_malformed_requests_without_reaching_the_gateway() {
    let server = spawn(ServerOptions::default()).await;

    let not_json = send(server.address, "POST", Some(OPERATOR_TOKEN), b"{oops", None).await;
    assert_eq!(not_json.status, 400);
    assert_eq!(
        not_json.json(),
        json!({"ok":false,"error":{"type":"invalid_request","message":"request body must be valid JSON"}})
    );

    let not_an_object = post(server.address, Some(OPERATOR_TOKEN), &json!([1, 2, 3])).await;
    assert_eq!(not_an_object.status, 400);
    assert_eq!(
        not_an_object.json(),
        json!({"ok":false,"error":{"type":"invalid_request","message":"request body must be an object"}})
    );

    for body in [
        json!({"id":"rpc-1"}),
        json!({"id":"rpc-1","method":""}),
        json!({"id":"rpc-1","method":"   "}),
        json!({"id":"rpc-1","method":42}),
    ] {
        let response = post(server.address, Some(OPERATOR_TOKEN), &body).await;
        assert_eq!(response.status, 400, "{body} was not refused");
        assert_eq!(
            response.json(),
            json!({"ok":false,"error":{"type":"invalid_request","message":"method must be a non-empty string"}})
        );
    }

    assert_eq!(server.admin.calls(), Vec::<String>::new());
}

#[tokio::test]
async fn admin_rpc_maps_oversized_bodies_to_payload_too_large() {
    let server = spawn(ServerOptions {
        limits: AdminRpcLimits {
            body_bytes: 64,
            ..AdminRpcLimits::default()
        },
        ..ServerOptions::default()
    })
    .await;

    let oversized = json!({"id":"rpc-big","method":"status","params":{"blob":"x".repeat(512)}});
    let response = post(server.address, Some(OPERATOR_TOKEN), &oversized).await;
    assert_eq!(response.status, 413);
    assert_eq!(
        response.json(),
        json!({"ok":false,"error":{"type":"invalid_request","message":"Payload too large"}})
    );
    assert_eq!(server.admin.calls(), Vec::<String>::new());

    let within_budget = post(
        server.address,
        Some(OPERATOR_TOKEN),
        &json!({"id":"rpc-small","method":"status"}),
    )
    .await;
    assert_eq!(within_budget.status, 200);
}

#[tokio::test]
async fn admin_rpc_maps_an_unfinished_body_to_request_timeout() {
    let server = spawn(ServerOptions {
        limits: AdminRpcLimits {
            body_timeout: Duration::from_millis(150),
            ..AdminRpcLimits::default()
        },
        ..ServerOptions::default()
    })
    .await;

    let response = send(
        server.address,
        "POST",
        Some(OPERATOR_TOKEN),
        b"{\"id\":\"rpc-slow\",\"method\":\"sta",
        Some(4096),
    )
    .await;
    assert_eq!(response.status, 408);
    assert_eq!(
        response.json(),
        json!({"ok":false,"error":{"type":"invalid_request","message":"request body timed out"}})
    );
    assert_eq!(server.admin.calls(), Vec::<String>::new());
}

#[tokio::test]
async fn admin_rpc_maps_a_slow_gateway_to_gateway_timeout() {
    let server = spawn(ServerOptions {
        limits: AdminRpcLimits {
            dispatch_timeout: Duration::from_millis(100),
            ..AdminRpcLimits::default()
        },
        ..ServerOptions::default()
    })
    .await;

    let response = post(
        server.address,
        Some(OPERATOR_TOKEN),
        &json!({"id":"rpc-slow","method":"status","params":{"sleepMs":5000}}),
    )
    .await;
    assert_eq!(response.status, 504);
    assert_eq!(
        response.json(),
        json!({
            "id":"rpc-slow",
            "ok":false,
            "error":{
                "code":"AGENT_TIMEOUT",
                "message":"gateway method timed out",
                "retryable":true
            }
        })
    );
    assert_eq!(server.admin.calls(), vec!["status".to_owned()]);
}

#[tokio::test]
async fn admin_rpc_refuses_to_decide_when_the_authorization_audit_is_unavailable() {
    let server = spawn(ServerOptions {
        audit: Arc::new(RecordingAudit::offline()),
        ..ServerOptions::default()
    })
    .await;

    let response = post(
        server.address,
        Some(OPERATOR_TOKEN),
        &json!({"id":"rpc-audit","method":"status"}),
    )
    .await;
    assert_eq!(response.status, 503);
    assert_eq!(
        response.json(),
        json!({"ok":false,"error":{"type":"unavailable","message":"authorization is unavailable"}})
    );
    assert_eq!(
        server.admin.calls(),
        Vec::<String>::new(),
        "an undecidable authorization must not fall open"
    );
}

#[tokio::test]
async fn admin_rpc_assigns_a_correlation_id_when_the_caller_omits_one() {
    let server = spawn(ServerOptions::default()).await;

    let first = post(
        server.address,
        Some(OPERATOR_TOKEN),
        &json!({"method":"status"}),
    )
    .await;
    assert_eq!(first.status, 200);
    let first_id = first.json()["id"]
        .as_str()
        .expect("a correlation id was assigned")
        .to_owned();
    assert!(first_id.starts_with("rpc_"), "unexpected id {first_id}");

    let second = post(
        server.address,
        Some(OPERATOR_TOKEN),
        &json!({"method":"chat.send"}),
    )
    .await;
    assert_eq!(second.status, 400);
    let second_id = second.json()["id"]
        .as_str()
        .expect("a refusal is correlated too")
        .to_owned();
    assert_ne!(
        first_id, second_id,
        "each call receives its own correlation id"
    );
}

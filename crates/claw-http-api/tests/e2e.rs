//! End-to-end contract tests over real TCP sockets.

use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::net::SocketAddr;
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

use claw_http_api::{
    ApiConfig, BearerAuthenticator, BearerCredential, DeterministicRuntime, GenerationOutput,
    HTTP_ENDPOINTS, HttpApi, InputMedia, InputMediaKind, InputMediaSource, ToolCall,
    ToolInvocation, ToolInvocationContext, Usage, WebhookRoute,
};
use claw_security::authorization::{Role, Scope, ScopeSet};
use http::HeaderValue;
use serde::Deserialize;
use serde_json::{Value, json};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::task::JoinHandle;
use tokio::time::{sleep, timeout};

struct Server {
    address: SocketAddr,
    mcp_address: SocketAddr,
    task: JoinHandle<()>,
    mcp_task: JoinHandle<()>,
    api: HttpApi,
}

#[derive(Deserialize)]
struct EndpointInventory {
    counts: EndpointCounts,
    items: Vec<EndpointInventoryItem>,
}

#[derive(Deserialize)]
struct EndpointCounts {
    total: usize,
}

#[derive(Deserialize)]
struct EndpointInventoryItem {
    method: String,
    path: String,
}

#[test]
fn registered_endpoint_set_exactly_matches_frozen_inventory() {
    let inventory_path = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join("..")
        .join("compat")
        .join("upstream")
        .join("inventories")
        .join("http-sse-endpoints.json");
    let source = fs::read_to_string(&inventory_path).expect("read frozen HTTP endpoint inventory");
    let source = source.strip_prefix('\u{feff}').unwrap_or(&source);
    let inventory: EndpointInventory =
        serde_json::from_str(source).expect("parse frozen HTTP endpoint inventory");

    let frozen = inventory
        .items
        .into_iter()
        .map(|endpoint| (endpoint.method, endpoint.path))
        .collect::<BTreeSet<_>>();
    let registered = HTTP_ENDPOINTS
        .iter()
        .map(|(method, path)| ((*method).to_owned(), (*path).to_owned()))
        .collect::<BTreeSet<_>>();

    assert_eq!(inventory.counts.total, 18);
    assert_eq!(frozen.len(), 18);
    assert_eq!(HTTP_ENDPOINTS.len(), 18);
    assert_eq!(registered.len(), 18);
    assert_eq!(registered, frozen);
}

impl Drop for Server {
    fn drop(&mut self) {
        self.task.abort();
        self.mcp_task.abort();
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

fn credential(token: &str, scopes: impl IntoIterator<Item = Scope>) -> BearerCredential {
    BearerCredential::new(token, Role::Operator, ScopeSet::from_scopes(scopes))
}

fn config() -> ApiConfig {
    let mut config = ApiConfig::new(BearerAuthenticator::new(vec![
        credential("operator-token", [Scope::OperatorAdmin]),
        credential("operator-two", [Scope::OperatorAdmin]),
        credential("read-token", [Scope::OperatorRead]),
        BearerCredential::new(
            "node-token",
            Role::Node,
            ScopeSet::from_scopes([Scope::OperatorAdmin]),
        ),
    ]));
    config.mcp_owner_authenticator =
        BearerAuthenticator::new(vec![credential("mcp-owner", [Scope::OperatorAdmin])]);
    config.mcp_authenticator =
        BearerAuthenticator::new(vec![credential("mcp-client", [Scope::OperatorRead])]);
    config.webhooks.insert(
        "zapier".to_owned(),
        WebhookRoute::new("zapier", "webhook-secret"),
    );
    config.limits.heartbeat_interval = Duration::from_secs(60);
    config
}

async fn spawn_with(config: ApiConfig, runtime: Arc<DeterministicRuntime>) -> Server {
    let api = HttpApi::new(config, runtime.services());
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind test listener");
    let address = listener.local_addr().expect("listener address");
    let mcp_listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind MCP test listener");
    let mcp_address = mcp_listener.local_addr().expect("MCP listener address");
    let serving_api = api.clone();
    let serving_mcp_api = api.clone();
    let task = tokio::spawn(async move {
        serving_api.serve(listener).await.expect("serve test API");
    });
    let mcp_task = tokio::spawn(async move {
        serving_mcp_api
            .serve_mcp(mcp_listener)
            .await
            .expect("serve test MCP API");
    });
    Server {
        address,
        mcp_address,
        task,
        mcp_task,
        api,
    }
}

async fn request(
    server: &Server,
    method: &str,
    path: &str,
    token: Option<&str>,
    extra_headers: &[(&str, &str)],
    body: &[u8],
) -> HttpResponse {
    request_at(server.address, method, path, token, extra_headers, body).await
}

async fn mcp_request(
    server: &Server,
    method: &str,
    token: Option<&str>,
    extra_headers: &[(&str, &str)],
    body: &[u8],
) -> HttpResponse {
    request_at(
        server.mcp_address,
        method,
        "/mcp",
        token,
        extra_headers,
        body,
    )
    .await
}

async fn request_at(
    address: SocketAddr,
    method: &str,
    path: &str,
    token: Option<&str>,
    extra_headers: &[(&str, &str)],
    body: &[u8],
) -> HttpResponse {
    let mut stream = TcpStream::connect(address)
        .await
        .expect("connect test server");
    let mut head = format!(
        "{method} {path} HTTP/1.1\r\nHost: {}\r\nConnection: close\r\nContent-Length: {}\r\n",
        address,
        body.len()
    );
    if let Some(token) = token {
        head.push_str(&format!("Authorization: Bearer {token}\r\n"));
    }
    for (name, value) in extra_headers {
        head.push_str(&format!("{name}: {value}\r\n"));
    }
    head.push_str("\r\n");
    stream
        .write_all(head.as_bytes())
        .await
        .expect("write request head");
    stream.write_all(body).await.expect("write request body");
    let mut raw = Vec::new();
    timeout(Duration::from_secs(3), stream.read_to_end(&mut raw))
        .await
        .expect("response timeout")
        .expect("read response");
    parse_response(&raw)
}

fn parse_response(raw: &[u8]) -> HttpResponse {
    let split = raw
        .windows(4)
        .position(|window| window == b"\r\n\r\n")
        .expect("HTTP header terminator");
    let head = std::str::from_utf8(&raw[..split]).expect("HTTP head UTF-8");
    let mut lines = head.split("\r\n");
    let status_line = lines.next().expect("status line");
    let status = status_line
        .split_whitespace()
        .nth(1)
        .expect("status code")
        .parse()
        .expect("numeric status");
    let headers = lines
        .map(|line| {
            let (name, value) = line.split_once(':').expect("header delimiter");
            (name.to_ascii_lowercase(), value.trim().to_owned())
        })
        .collect::<BTreeMap<_, _>>();
    let raw_body = &raw[split + 4..];
    let body = if headers
        .get("transfer-encoding")
        .is_some_and(|value| value.eq_ignore_ascii_case("chunked"))
    {
        decode_chunked(raw_body)
    } else {
        raw_body.to_vec()
    };
    HttpResponse {
        status,
        headers,
        body,
    }
}

fn decode_chunked(mut bytes: &[u8]) -> Vec<u8> {
    let mut decoded = Vec::new();
    loop {
        let end = bytes
            .windows(2)
            .position(|window| window == b"\r\n")
            .expect("chunk size terminator");
        let size_text = std::str::from_utf8(&bytes[..end]).expect("chunk size UTF-8");
        let size = usize::from_str_radix(
            size_text.split(';').next().expect("chunk size component"),
            16,
        )
        .expect("hex chunk size");
        bytes = &bytes[end + 2..];
        if size == 0 {
            break;
        }
        decoded.extend_from_slice(&bytes[..size]);
        bytes = &bytes[size + 2..];
    }
    decoded
}

fn json_body(value: Value) -> Vec<u8> {
    serde_json::to_vec(&value).expect("test JSON serializes")
}

fn watch_connect_body(nonce: &str, device_id: &str) -> Vec<u8> {
    json_body(json!({
        "minProtocol":4,
        "maxProtocol":4,
        "client":{
            "id":"openclaw-watchos",
            "version":"1.0",
            "platform":"watchOS 11",
            "deviceFamily":"Apple Watch",
            "mode":"node"
        },
        "caps":[],
        "commands":["device.info","device.status","system.notify"],
        "permissions":{"notifications":true},
        "role":"node",
        "scopes":[],
        "device":{
            "id":device_id,
            "publicKey":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
            "signature":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
            "signedAt":1,
            "nonce":nonce
        },
        "auth":{"bootstrapToken":"bootstrap"}
    }))
}

#[tokio::test]
async fn probes_reflect_real_dependency_state_and_hide_details_without_auth() {
    let runtime = DeterministicRuntime::new();
    let server = spawn_with(config(), runtime.clone()).await;
    let live = request(&server, "GET", "/health", None, &[], b"").await;
    assert_eq!(live.status, 200);
    assert_eq!(live.json(), json!({"ok":true,"status":"live"}));
    assert_eq!(
        live.headers.get("cache-control").map(String::as_str),
        Some("no-store")
    );

    runtime.set_ready(false);
    let hidden = request(&server, "GET", "/readyz", None, &[], b"").await;
    assert_eq!(hidden.status, 503);
    assert_eq!(hidden.json(), json!({"ready":false}));

    let detailed = request(&server, "GET", "/ready", Some("operator-token"), &[], b"").await;
    assert_eq!(detailed.status, 503);
    let detailed_json = detailed.json();
    assert_eq!(detailed_json["ready"], false);
    assert_eq!(detailed_json["failing"], json!(["provider"]));
    assert_eq!(
        detailed_json.as_object().expect("object").len(),
        3,
        "readiness details have exactly three fields"
    );
    assert!(detailed_json["uptimeMs"].as_u64().is_some());
}

#[tokio::test]
async fn cors_allows_only_explicit_origins_and_preserves_authentication() {
    let runtime = DeterministicRuntime::new();
    let mut cors_config = config();
    cors_config.cors_origins = vec![HeaderValue::from_static("https://client.example")];
    let server = spawn_with(cors_config, runtime).await;
    let allowed = request(
        &server,
        "OPTIONS",
        "/v1/models",
        None,
        &[
            ("Origin", "https://client.example"),
            ("Access-Control-Request-Method", "GET"),
            ("Access-Control-Request-Headers", "authorization"),
        ],
        b"",
    )
    .await;
    assert_eq!(allowed.status, 200);
    assert_eq!(
        allowed
            .headers
            .get("access-control-allow-origin")
            .map(String::as_str),
        Some("https://client.example")
    );
    assert_eq!(
        allowed
            .headers
            .get("access-control-allow-methods")
            .map(String::as_str),
        Some("GET,HEAD,POST,DELETE")
    );
    let denied = request(
        &server,
        "OPTIONS",
        "/v1/models",
        None,
        &[
            ("Origin", "https://attacker.example"),
            ("Access-Control-Request-Method", "GET"),
        ],
        b"",
    )
    .await;
    assert_eq!(denied.status, 200);
    assert!(!denied.headers.contains_key("access-control-allow-origin"));

    let unauthenticated = request(
        &server,
        "GET",
        "/v1/models",
        None,
        &[("Origin", "https://client.example")],
        b"",
    )
    .await;
    assert_eq!(unauthenticated.status, 401);
    assert_eq!(
        unauthenticated
            .headers
            .get("access-control-allow-origin")
            .map(String::as_str),
        Some("https://client.example")
    );
}

#[tokio::test]
async fn auth_models_embeddings_and_json_generation_match_contracts() {
    let runtime = DeterministicRuntime::new();
    let server = spawn_with(config(), runtime).await;
    let denied = request(&server, "GET", "/v1/models", None, &[], b"").await;
    assert_eq!(denied.status, 401);
    assert_eq!(
        denied.json(),
        json!({"error":{"message":"Unauthorized","type":"unauthorized"}})
    );
    let wrong_role = request(&server, "GET", "/v1/models", Some("node-token"), &[], b"").await;
    assert_eq!(wrong_role.status, 403);
    assert_eq!(
        wrong_role.json(),
        json!({
            "ok":false,
            "error":{"type":"forbidden","message":"missing scope: operator.read"}
        })
    );

    let models = request(
        &server,
        "GET",
        "/v1/models",
        Some("operator-token"),
        &[],
        b"",
    )
    .await;
    assert_eq!(models.status, 200);
    assert_eq!(
        models.json(),
        json!({
            "object":"list",
            "data":[
                {"id":"openclaw","object":"model","created":0,"owned_by":"openclaw","permission":[]},
                {"id":"openclaw/default","object":"model","created":0,"owned_by":"openclaw","permission":[]},
                {"id":"openclaw/main","object":"model","created":0,"owned_by":"openclaw","permission":[]}
            ]
        })
    );
    let model = request(
        &server,
        "GET",
        "/v1/models/openclaw%2Fmain",
        Some("operator-token"),
        &[],
        b"",
    )
    .await;
    assert_eq!(model.status, 200);
    assert_eq!(
        model.json(),
        json!({"id":"openclaw/main","object":"model","created":0,"owned_by":"openclaw","permission":[]})
    );
    let invalid_model = request(
        &server,
        "GET",
        "/v1/models/not-openclaw",
        Some("operator-token"),
        &[],
        b"",
    )
    .await;
    assert_eq!(invalid_model.status, 400);
    assert_eq!(
        invalid_model.json(),
        json!({"error":{"message":"Invalid model id.","type":"invalid_request_error"}})
    );
    let missing_model = request(
        &server,
        "GET",
        "/v1/models/openclaw%2Fmissing",
        Some("operator-token"),
        &[],
        b"",
    )
    .await;
    assert_eq!(missing_model.status, 404);
    assert_eq!(
        missing_model.json(),
        json!({"error":{
            "message":"Model 'openclaw/missing' not found.",
            "type":"invalid_request_error"
        }})
    );

    let embeddings = request(
        &server,
        "POST",
        "/v1/embeddings",
        Some("operator-token"),
        &[("Content-Type", "application/json")],
        &json_body(json!({"model":"openclaw","input":"hi","dimensions":2})),
    )
    .await;
    assert_eq!(embeddings.status, 200);
    assert_eq!(
        embeddings.json(),
        json!({
            "object":"list",
            "data":[{"object":"embedding","index":0,"embedding":[1.0,1.5]}],
            "model":"openclaw",
            "usage":{"prompt_tokens":0,"total_tokens":0}
        })
    );

    let chat = request(
        &server,
        "POST",
        "/v1/chat/completions",
        Some("operator-token"),
        &[("Content-Type", "application/json")],
        &json_body(json!({
            "model":"openclaw",
            "messages":[{"role":"user","content":"hello"}]
        })),
    )
    .await;
    assert_eq!(chat.status, 200);
    let chat_json = chat.json();
    assert_eq!(chat_json["object"], "chat.completion");
    assert_eq!(chat_json["model"], "openclaw");
    assert_eq!(
        chat_json["choices"],
        json!([{
            "index":0,
            "message":{"role":"assistant","content":"deterministic response"},
            "finish_reason":"stop"
        }])
    );
    assert_eq!(
        chat_json["usage"],
        json!({"prompt_tokens":3,"completion_tokens":2,"total_tokens":5})
    );
    assert!(
        chat_json["id"]
            .as_str()
            .is_some_and(|id| id.starts_with("chatcmpl_"))
    );
    assert!(chat_json["created"].as_u64().is_some());

    let responses = request(
        &server,
        "POST",
        "/v1/responses",
        Some("operator-token"),
        &[("Content-Type", "application/json")],
        &json_body(json!({"model":"openclaw","input":"hello"})),
    )
    .await;
    assert_eq!(responses.status, 200);
    let response_json = responses.json();
    assert_eq!(response_json["object"], "response");
    assert_eq!(response_json["status"], "completed");
    assert_eq!(response_json["model"], "openclaw");
    assert_eq!(
        response_json["output"][0]["content"],
        json!([{"type":"output_text","text":"deterministic response"}])
    );
    assert_eq!(response_json["output"][0]["phase"], "final_answer");
    assert_eq!(
        response_json["usage"],
        json!({"input_tokens":3,"output_tokens":2,"total_tokens":5})
    );
    assert_eq!(
        response_json.as_object().expect("response object").len(),
        7,
        "successful response omits error"
    );
}

#[tokio::test]
async fn chat_and_responses_sse_have_exact_framing_and_terminal_events() {
    let runtime = DeterministicRuntime::new();
    let server = spawn_with(config(), runtime).await;
    let chat = request(
        &server,
        "POST",
        "/v1/chat/completions",
        Some("operator-token"),
        &[("Content-Type", "application/json")],
        &json_body(json!({
            "model":"openclaw",
            "stream":true,
            "stream_options":{"include_usage":true},
            "messages":[{"role":"user","content":"hello"}]
        })),
    )
    .await;
    assert_eq!(chat.status, 200);
    assert_eq!(
        chat.headers.get("content-type").map(String::as_str),
        Some("text/event-stream; charset=utf-8")
    );
    let chat_blocks = chat
        .text()
        .split("\n\n")
        .filter(|block| !block.is_empty())
        .collect::<Vec<_>>();
    assert_eq!(chat_blocks.len(), 6);
    let chat_events = chat_blocks[..5]
        .iter()
        .map(|block| {
            let data = block.strip_prefix("data: ").expect("chat data prefix");
            serde_json::from_str::<Value>(data).expect("chat event JSON")
        })
        .collect::<Vec<_>>();
    assert_eq!(
        chat_events[0]["choices"][0]["delta"],
        json!({"role":"assistant"})
    );
    assert_eq!(
        chat_events[1]["choices"][0]["delta"],
        json!({"content":"deterministic "})
    );
    assert_eq!(
        chat_events[2]["choices"][0]["delta"],
        json!({"content":"response"})
    );
    assert_eq!(chat_events[3]["choices"][0]["finish_reason"], "stop");
    assert_eq!(chat_events[4]["choices"], json!([]));
    assert_eq!(
        chat_events[4]["usage"],
        json!({"prompt_tokens":3,"completion_tokens":2,"total_tokens":5})
    );
    assert_eq!(chat_blocks[5].as_bytes(), b"data: [DONE]");

    let responses = request(
        &server,
        "POST",
        "/v1/responses",
        Some("operator-token"),
        &[("Content-Type", "application/json")],
        &json_body(json!({"model":"openclaw","input":"hello","stream":true})),
    )
    .await;
    assert_eq!(responses.status, 200);
    let blocks = responses
        .text()
        .split("\n\n")
        .filter(|block| !block.is_empty())
        .collect::<Vec<_>>();
    assert_eq!(blocks.len(), 11);
    let mut event_types = Vec::new();
    for block in &blocks[..10] {
        let (event_line, data_line) = block.split_once('\n').expect("two-line response event");
        let event_type = event_line
            .strip_prefix("event: ")
            .expect("response event prefix");
        let data = data_line
            .strip_prefix("data: ")
            .expect("response data prefix");
        let parsed: Value = serde_json::from_str(data).expect("response event JSON");
        assert_eq!(parsed["type"], event_type);
        event_types.push(event_type);
    }
    assert_eq!(
        event_types,
        vec![
            "response.created",
            "response.in_progress",
            "response.output_item.added",
            "response.content_part.added",
            "response.output_text.delta",
            "response.output_text.delta",
            "response.output_text.done",
            "response.content_part.done",
            "response.output_item.done",
            "response.completed",
        ]
    );
    assert_eq!(blocks[10].as_bytes(), b"data: [DONE]");
}

#[tokio::test]
async fn tools_admin_mcp_and_webhooks_enforce_and_map_contracts() {
    let runtime = DeterministicRuntime::new();
    let server = spawn_with(config(), runtime.clone()).await;
    let tool = request(
        &server,
        "POST",
        "/tools/invoke",
        Some("operator-token"),
        &[
            ("Content-Type", "application/json"),
            ("x-openclaw-session-key", "header-session"),
            ("x-openclaw-agent-id", "header-agent"),
            ("x-openclaw-message-channel", "matrix"),
            ("x-openclaw-account-id", "account-1"),
            ("x-openclaw-message-to", "room-7"),
            ("x-openclaw-thread-id", "thread-2"),
        ],
        &json_body(json!({
            "name":"echo",
            "args":{"value":7},
            "action":"send",
            "sessionKey":"body-session",
            "agentId":"body-agent",
            "idempotencyKey":"idempotency-1",
            "dryRun":true
        })),
    )
    .await;
    assert_eq!(tool.status, 200);
    assert_eq!(tool.json(), json!({"ok":true,"result":{"value":7}}));
    assert_eq!(
        runtime
            .last_tool_invocation()
            .expect("read tool invocation")
            .expect("tool invocation recorded"),
        ToolInvocation {
            name: "echo".to_owned(),
            arguments: json!({"value":7}),
            action: Some("send".to_owned()),
            context: ToolInvocationContext {
                session_key: Some("body-session".to_owned()),
                agent_id: Some("body-agent".to_owned()),
                idempotency_key: Some("idempotency-1".to_owned()),
                message_channel: Some("matrix".to_owned()),
                account_id: Some("account-1".to_owned()),
                agent_to: Some("room-7".to_owned()),
                agent_thread_id: Some("thread-2".to_owned()),
                sender_is_owner: true,
                dry_run: true,
            }
        }
    );

    let admin = request(
        &server,
        "POST",
        "/api/v1/admin/rpc",
        Some("operator-token"),
        &[("Content-Type", "application/json")],
        &json_body(json!({"id":"rpc-1","method":"status","params":{"verbose":true}})),
    )
    .await;
    assert_eq!(admin.status, 200);
    assert_eq!(
        admin.json(),
        json!({
            "id":"rpc-1",
            "ok":true,
            "payload":{"method":"status","params":{"verbose":true}}
        })
    );
    assert_eq!(
        runtime.audit_events().expect("audit events").len(),
        2,
        "tool and admin authorizations are durably audited"
    );

    let denied_admin = request(
        &server,
        "POST",
        "/api/v1/admin/rpc",
        Some("operator-token"),
        &[("Content-Type", "application/json")],
        &json_body(json!({"id":"rpc-2","method":"chat.send"})),
    )
    .await;
    assert_eq!(denied_admin.status, 400);
    assert_eq!(
        denied_admin.json(),
        json!({
            "id":"rpc-2","ok":false,
            "error":{"code":"INVALID_REQUEST","message":"admin HTTP RPC method is not supported: chat.send"}
        })
    );
    let scope_denied = request(
        &server,
        "POST",
        "/api/v1/admin/rpc",
        Some("read-token"),
        &[("Content-Type", "application/json")],
        &json_body(json!({"id":"rpc-3","method":"config.set","params":{}})),
    )
    .await;
    assert_eq!(scope_denied.status, 403);
    assert_eq!(
        scope_denied.json(),
        json!({"ok":false,"error":{"type":"forbidden","message":"Forbidden"}})
    );
    assert_eq!(
        runtime.audit_events().expect("scope audit events").len(),
        3,
        "denied authorization is durably audited"
    );

    let main_listener_mcp = request(
        &server,
        "POST",
        "/mcp",
        Some("operator-token"),
        &[("Content-Type", "application/json")],
        b"{}",
    )
    .await;
    assert_eq!(main_listener_mcp.status, 404);
    let remote_origin = mcp_request(
        &server,
        "POST",
        Some("mcp-owner"),
        &[
            ("Content-Type", "application/json"),
            ("Origin", "https://attacker.example"),
        ],
        b"{}",
    )
    .await;
    assert_eq!(remote_origin.status, 403);
    assert_eq!(remote_origin.json(), json!({"error":"forbidden_origin"}));

    let mcp = mcp_request(
        &server,
        "POST",
        Some("mcp-owner"),
        &[("Content-Type", "application/json")],
        &json_body(json!({
            "jsonrpc":"2.0","id":1,"method":"initialize",
            "params":{"protocolVersion":"2024-11-05"}
        })),
    )
    .await;
    assert_eq!(mcp.status, 200);
    assert_eq!(
        mcp.json(),
        json!({
            "jsonrpc":"2.0","id":1,
            "result":{
                "protocolVersion":"2024-11-05",
                "capabilities":{"tools":{}},
                "serverInfo":{"name":"openclaw","version":"0.1.0"}
            }
        })
    );
    let mcp_call = mcp_request(
        &server,
        "POST",
        Some("mcp-client"),
        &[("Content-Type", "application/json")],
        &json_body(json!({
            "jsonrpc":"2.0","id":"call-1","method":"tools/call",
            "params":{"name":"echo","arguments":{"hello":"world"}}
        })),
    )
    .await;
    assert_eq!(mcp_call.status, 200);
    assert_eq!(
        mcp_call.json(),
        json!({
            "jsonrpc":"2.0","id":"call-1",
            "result":{"content":[{"type":"text","text":"{\"hello\":\"world\"}"}],"isError":false}
        })
    );

    let webhook_denied = request(
        &server,
        "POST",
        "/plugins/webhooks/zapier",
        None,
        &[("Content-Type", "application/json")],
        &json_body(json!({"action":"list_flows"})),
    )
    .await;
    assert_eq!(webhook_denied.status, 401);
    assert_eq!(webhook_denied.text(), "unauthorized");
    let webhook = request(
        &server,
        "POST",
        "/plugins/webhooks/zapier",
        None,
        &[
            ("Content-Type", "application/json"),
            ("x-openclaw-webhook-secret", "webhook-secret"),
        ],
        &json_body(json!({"action":"list_flows"})),
    )
    .await;
    assert_eq!(webhook.status, 200);
    assert_eq!(
        webhook.json(),
        json!({
            "ok":true,
            "routeId":"zapier",
            "result":{"routeId":"zapier","action":{"action":"list_flows"}}
        })
    );
    for invalid_body in [
        json!({"action":"list_flows","unexpected":true}),
        json!({
            "action":"run_task","flowId":"flow-1","runtime":"subagent",
            "task":"work","status":"queued","startedAt":1
        }),
    ] {
        let invalid_webhook = request(
            &server,
            "POST",
            "/plugins/webhooks/zapier",
            None,
            &[
                ("Content-Type", "application/json"),
                ("x-openclaw-webhook-secret", "webhook-secret"),
            ],
            &json_body(invalid_body),
        )
        .await;
        assert_eq!(invalid_webhook.status, 400);
        assert_eq!(
            invalid_webhook.json(),
            json!({"ok":false,"code":"invalid_request","error":"invalid request"})
        );
    }
}

#[tokio::test]
async fn tools_invoke_rejects_auth_schema_scope_and_maps_tool_errors() {
    let runtime = DeterministicRuntime::new();
    let server = spawn_with(config(), runtime).await;
    let unauthenticated = request(
        &server,
        "POST",
        "/tools/invoke",
        None,
        &[("Content-Type", "application/json")],
        &json_body(json!({"name":"echo","args":{}})),
    )
    .await;
    assert_eq!(unauthenticated.status, 401);
    assert_eq!(
        unauthenticated.json(),
        json!({"error":{"message":"Unauthorized","type":"unauthorized"}})
    );

    let scope_denied = request(
        &server,
        "POST",
        "/tools/invoke",
        Some("read-token"),
        &[("Content-Type", "application/json")],
        &json_body(json!({"name":"echo","args":{}})),
    )
    .await;
    assert_eq!(scope_denied.status, 403);
    assert_eq!(
        scope_denied.json(),
        json!({
            "ok":false,
            "error":{"type":"forbidden","message":"missing scope: operator.write"}
        })
    );

    let invalid = request(
        &server,
        "POST",
        "/tools/invoke",
        Some("operator-token"),
        &[("Content-Type", "application/json")],
        &json_body(json!({"args":{}})),
    )
    .await;
    assert_eq!(invalid.status, 400);
    assert_eq!(
        invalid.json(),
        json!({"error":{
            "message":"tools.invoke requires name",
            "type":"invalid_request"
        }})
    );

    let missing_tool = request(
        &server,
        "POST",
        "/tools/invoke",
        Some("operator-token"),
        &[("Content-Type", "application/json")],
        &json_body(json!({"name":"missing","args":{"value":7}})),
    )
    .await;
    assert_eq!(missing_tool.status, 404);
    assert_eq!(
        missing_tool.json(),
        json!({"ok":false,"error":{
            "type":"not_found",
            "message":"Tool not available: missing"
        }})
    );
}

#[tokio::test]
async fn malformed_oversized_timeout_and_disconnect_fail_safely() {
    let runtime = DeterministicRuntime::new();
    let mut limited = config();
    limited.limits.openai_body_bytes = 128;
    limited.limits.operation_timeout = Duration::from_millis(25);
    let server = spawn_with(limited, runtime.clone()).await;
    let malformed = request(
        &server,
        "POST",
        "/v1/chat/completions",
        Some("operator-token"),
        &[("Content-Type", "application/json")],
        br#"{"model":"openclaw","messages":["#,
    )
    .await;
    assert_eq!(malformed.status, 400);
    assert_eq!(malformed.json()["error"]["type"], "invalid_request_error");
    assert!(malformed.json()["error"]["message"].as_str().is_some());

    let oversized = request(
        &server,
        "POST",
        "/v1/chat/completions",
        Some("operator-token"),
        &[("Content-Type", "application/json")],
        &[b' '; 129],
    )
    .await;
    assert_eq!(oversized.status, 413);
    assert_eq!(
        oversized.json(),
        json!({"error":{"message":"Payload too large","type":"invalid_request_error"}})
    );
    let invalid_embedding = request(
        &server,
        "POST",
        "/v1/embeddings",
        Some("operator-token"),
        &[("Content-Type", "application/json")],
        &json_body(json!({"model":"openclaw","input":["valid",7]})),
    )
    .await;
    assert_eq!(invalid_embedding.status, 400);
    assert_eq!(
        invalid_embedding.json(),
        json!({"error":{
            "message":"`input` must be a string or an array of strings.",
            "type":"invalid_request_error"
        }})
    );

    runtime.set_delay(Duration::from_millis(100));
    let timed_out = request(
        &server,
        "POST",
        "/v1/chat/completions",
        Some("operator-token"),
        &[("Content-Type", "application/json")],
        &json_body(json!({
            "model":"openclaw",
            "messages":[{"role":"user","content":"hello"}]
        })),
    )
    .await;
    assert_eq!(timed_out.status, 504);
    assert_eq!(
        timed_out.json(),
        json!({"error":{"message":"request timed out","type":"api_error"}})
    );
    let embedding_timeout = request(
        &server,
        "POST",
        "/v1/embeddings",
        Some("operator-token"),
        &[("Content-Type", "application/json")],
        &json_body(json!({"model":"openclaw","input":"hello"})),
    )
    .await;
    assert_eq!(embedding_timeout.status, 504);
    assert_eq!(
        embedding_timeout.json(),
        json!({"error":{"message":"request timed out","type":"api_error"}})
    );

    let disconnect_runtime = DeterministicRuntime::new();
    disconnect_runtime.set_delay(Duration::from_secs(5));
    let mut disconnect_config = config();
    disconnect_config.limits.heartbeat_interval = Duration::from_millis(25);
    let disconnect_server = spawn_with(disconnect_config, disconnect_runtime.clone()).await;
    let mut stream = TcpStream::connect(disconnect_server.address)
        .await
        .expect("connect stream client");
    let body = json_body(json!({
        "model":"openclaw","stream":true,
        "messages":[{"role":"user","content":"hello"}]
    }));
    let head = format!(
        "POST /v1/chat/completions HTTP/1.1\r\nHost: {}\r\nAuthorization: Bearer operator-token\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n",
        disconnect_server.address,
        body.len()
    );
    stream.write_all(head.as_bytes()).await.expect("write head");
    stream.write_all(&body).await.expect("write body");
    let mut headers = Vec::new();
    let mut byte = [0_u8; 1];
    while !headers.ends_with(b"\r\n\r\n") {
        timeout(Duration::from_secs(1), stream.read_exact(&mut byte))
            .await
            .expect("stream header timeout")
            .expect("read stream header");
        headers.push(byte[0]);
    }
    let stream = stream.into_std().expect("convert disconnect socket");
    stream
        .shutdown(std::net::Shutdown::Both)
        .expect("abruptly shut down client socket");
    drop(stream);
    timeout(Duration::from_secs(1), async {
        while !disconnect_runtime.stream_was_cancelled() {
            sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .expect("provider cancellation propagated");
}

#[tokio::test]
async fn watch_transport_covers_challenge_connect_queue_poll_result_and_disconnect() {
    let runtime = DeterministicRuntime::new();
    let server = spawn_with(config(), runtime).await;
    let challenge = request(&server, "GET", "/api/nodes/watch/challenge", None, &[], b"").await;
    assert_eq!(challenge.status, 200);
    let challenge_json = challenge.json();
    assert_eq!(challenge_json["ok"], true);
    let nonce = challenge_json["nonce"]
        .as_str()
        .expect("challenge nonce")
        .to_owned();
    assert!(challenge_json["expiresAtMs"].as_u64().is_some());

    let connect = request(
        &server,
        "POST",
        "/api/nodes/watch/connect",
        None,
        &[("Content-Type", "application/json")],
        &watch_connect_body(&nonce, "watch-device-1"),
    )
    .await;
    assert_eq!(connect.status, 200, "{}", connect.text());
    let connect_json = connect.json();
    assert_eq!(connect_json["ok"], true);
    assert_eq!(connect_json["nodeId"], "watch-device-1");
    assert_eq!(connect_json["protocol"], 4);
    assert_eq!(connect_json["pollTimeoutMs"], 20_000);
    assert_eq!(connect_json["deviceToken"], "deterministic-device-token");
    let session_token = connect_json["sessionToken"]
        .as_str()
        .expect("session token")
        .to_owned();

    assert!(
        server
            .api
            .watch_handle()
            .send(
                "watch-device-1",
                "node.invoke.request",
                Some(json!({"id":"invoke-1"}))
            )
            .expect("enqueue")
    );
    let poll = request(
        &server,
        "POST",
        "/api/nodes/watch/poll",
        Some(&session_token),
        &[],
        b"",
    )
    .await;
    assert_eq!(poll.status, 200);
    assert_eq!(
        poll.json(),
        json!({
            "ok":true,
            "event":{"event":"node.invoke.request","payload":{"id":"invoke-1"}}
        })
    );

    let result = request(
        &server,
        "POST",
        "/api/nodes/watch/result",
        Some(&session_token),
        &[("Content-Type", "application/json")],
        &json_body(json!({"id":"invoke-1","ok":true,"payload":{"done":true}})),
    )
    .await;
    assert_eq!(result.status, 200);
    assert_eq!(result.json(), json!({"ok":true}));

    let disconnected = request(
        &server,
        "POST",
        "/api/nodes/watch/disconnect",
        Some(&session_token),
        &[],
        b"",
    )
    .await;
    assert_eq!(disconnected.status, 200);
    assert_eq!(disconnected.json(), json!({"ok":true}));
    let after_disconnect = request(
        &server,
        "POST",
        "/api/nodes/watch/poll",
        Some(&session_token),
        &[],
        b"",
    )
    .await;
    assert_eq!(after_disconnect.status, 401);
    assert_eq!(
        after_disconnect.json(),
        json!({"error":{"message":"Unauthorized","type":"unauthorized"}})
    );
}

#[tokio::test]
async fn watch_transport_consumes_challenges_times_out_polls_and_closes_overflowed_queues() {
    let runtime = DeterministicRuntime::new();
    let mut watch_config = config();
    watch_config.limits.watch_poll_timeout = Duration::from_millis(25);
    watch_config.limits.watch_queue_events = 1;
    let server = spawn_with(watch_config, runtime).await;
    let mut bounded_nonces = Vec::new();
    for _ in 0..9 {
        let bounded = request(&server, "GET", "/api/nodes/watch/challenge", None, &[], b"").await;
        assert_eq!(bounded.status, 200);
        bounded_nonces.push(
            bounded.json()["nonce"]
                .as_str()
                .expect("per-client challenge nonce")
                .to_owned(),
        );
    }
    let evicted = request(
        &server,
        "POST",
        "/api/nodes/watch/connect",
        None,
        &[("Content-Type", "application/json")],
        &watch_connect_body(&bounded_nonces[0], "watch-device-evicted"),
    )
    .await;
    assert_eq!(evicted.status, 401);
    let newest = request(
        &server,
        "POST",
        "/api/nodes/watch/connect",
        None,
        &[("Content-Type", "application/json")],
        &watch_connect_body(
            bounded_nonces.last().expect("newest challenge"),
            "watch-device-newest",
        ),
    )
    .await;
    assert_eq!(newest.status, 200);

    let challenge = request(&server, "GET", "/api/nodes/watch/challenge", None, &[], b"").await;
    let nonce = challenge.json()["nonce"]
        .as_str()
        .expect("bounded challenge nonce")
        .to_owned();
    let connect_body = watch_connect_body(&nonce, "watch-device-bounded");
    let connect = request(
        &server,
        "POST",
        "/api/nodes/watch/connect",
        None,
        &[("Content-Type", "application/json")],
        &connect_body,
    )
    .await;
    assert_eq!(connect.status, 200);
    let session_token = connect.json()["sessionToken"]
        .as_str()
        .expect("bounded session token")
        .to_owned();

    let replay = request(
        &server,
        "POST",
        "/api/nodes/watch/connect",
        None,
        &[("Content-Type", "application/json")],
        &connect_body,
    )
    .await;
    assert_eq!(replay.status, 401);
    assert_eq!(
        replay.json(),
        json!({"error":{"message":"Unauthorized","type":"unauthorized"}})
    );

    let empty_poll = request(
        &server,
        "POST",
        "/api/nodes/watch/poll",
        Some(&session_token),
        &[("Content-Type", "application/json")],
        b"{}",
    )
    .await;
    assert_eq!(empty_poll.status, 200);
    assert_eq!(empty_poll.json(), json!({"ok":true,"event":null}));

    assert!(
        server
            .api
            .watch_handle()
            .send(
                "watch-device-bounded",
                "node.invoke.request",
                Some(json!({"id":"invoke-1"}))
            )
            .expect("first bounded enqueue")
    );
    assert!(
        !server
            .api
            .watch_handle()
            .send(
                "watch-device-bounded",
                "node.invoke.request",
                Some(json!({"id":"invoke-2"}))
            )
            .expect("overflow enqueue")
    );
    let closed_poll = request(
        &server,
        "POST",
        "/api/nodes/watch/poll",
        Some(&session_token),
        &[("Content-Type", "application/json")],
        b"{}",
    )
    .await;
    assert_eq!(closed_poll.status, 401);
    assert_eq!(
        closed_poll.json(),
        json!({"error":{"message":"Unauthorized","type":"unauthorized"}})
    );
}

#[tokio::test]
async fn required_tool_choice_returns_structured_calls_on_both_openai_surfaces() {
    let runtime = DeterministicRuntime::new();
    runtime
        .set_output(GenerationOutput {
            text: "calling".to_owned(),
            tool_calls: vec![ToolCall {
                id: "call-1".to_owned(),
                name: "lookup".to_owned(),
                arguments: "{\"q\":\"rust\"}".to_owned(),
            }],
            usage: Usage {
                input_tokens: 4,
                output_tokens: 1,
                total_tokens: 5,
            },
        })
        .expect("set output");
    let server = spawn_with(config(), runtime).await;
    let chat = request(
        &server,
        "POST",
        "/v1/chat/completions",
        Some("operator-token"),
        &[("Content-Type", "application/json")],
        &json_body(json!({
            "model":"openclaw",
            "messages":[{"role":"user","content":"find rust"}],
            "tools":[{"type":"function","function":{"name":"lookup","parameters":{"type":"object"}}}],
            "tool_choice":"required"
        })),
    )
    .await;
    assert_eq!(chat.status, 200);
    assert_eq!(chat.json()["choices"][0]["finish_reason"], "tool_calls");
    assert_eq!(
        chat.json()["choices"][0]["message"]["tool_calls"],
        json!([{
            "id":"call-1","type":"function",
            "function":{"name":"lookup","arguments":"{\"q\":\"rust\"}"}
        }])
    );

    let responses = request(
        &server,
        "POST",
        "/v1/responses",
        Some("operator-token"),
        &[("Content-Type", "application/json")],
        &json_body(json!({
            "model":"openclaw",
            "input":"find rust",
            "tools":[{"type":"function","name":"lookup","parameters":{"type":"object"}}],
            "tool_choice":"required"
        })),
    )
    .await;
    assert_eq!(responses.status, 200);
    assert_eq!(responses.json()["status"], "incomplete");
    assert_eq!(responses.json()["output"][1]["type"], "function_call");
    assert_eq!(responses.json()["output"][1]["call_id"], "call-1");
    assert_eq!(responses.json()["output"][1]["name"], "lookup");
    assert_eq!(
        responses.json()["output"][1]["arguments"],
        "{\"q\":\"rust\"}"
    );
}

#[tokio::test]
async fn constrained_streams_fail_without_leaking_text_and_response_timeouts_fail() {
    let runtime = DeterministicRuntime::new();
    let server = spawn_with(config(), runtime).await;
    let required_tool = json!({
        "type":"function",
        "function":{"name":"lookup","parameters":{"type":"object"}}
    });
    let chat = request(
        &server,
        "POST",
        "/v1/chat/completions",
        Some("operator-token"),
        &[("Content-Type", "application/json")],
        &json_body(json!({
            "model":"openclaw",
            "messages":[{"role":"user","content":"find rust"}],
            "tools":[required_tool],
            "tool_choice":"required",
            "stream":true
        })),
    )
    .await;
    assert_eq!(chat.status, 200);
    let chat_blocks = chat
        .text()
        .split("\n\n")
        .filter(|block| !block.is_empty())
        .collect::<Vec<_>>();
    assert_eq!(chat_blocks.len(), 3);
    let role: Value = serde_json::from_str(
        chat_blocks[0]
            .strip_prefix("data: ")
            .expect("chat role data"),
    )
    .expect("chat role JSON");
    assert_eq!(role["choices"][0]["delta"], json!({"role":"assistant"}));
    let failure: Value = serde_json::from_str(
        chat_blocks[1]
            .strip_prefix("data: ")
            .expect("chat failure data"),
    )
    .expect("chat failure JSON");
    assert_eq!(
        failure,
        json!({"error":{
            "message":"The model did not call the required tool.",
            "type":"api_error"
        }})
    );
    assert_eq!(chat_blocks[2].as_bytes(), b"data: [DONE]");

    let responses = request(
        &server,
        "POST",
        "/v1/responses",
        Some("operator-token"),
        &[("Content-Type", "application/json")],
        &json_body(json!({
            "model":"openclaw",
            "input":"find rust",
            "tools":[{"type":"function","name":"lookup","parameters":{"type":"object"}}],
            "tool_choice":"required",
            "stream":true
        })),
    )
    .await;
    assert_eq!(responses.status, 200);
    let response_blocks = responses
        .text()
        .split("\n\n")
        .filter(|block| !block.is_empty())
        .collect::<Vec<_>>();
    assert_eq!(response_blocks.len(), 6);
    assert_eq!(
        response_blocks[4]
            .lines()
            .next()
            .expect("failure event line"),
        "event: response.failed"
    );
    let failed_response: Value = serde_json::from_str(
        response_blocks[4]
            .lines()
            .nth(1)
            .expect("failure data line")
            .strip_prefix("data: ")
            .expect("failure data prefix"),
    )
    .expect("failure response JSON");
    assert_eq!(failed_response["type"], "response.failed");
    assert_eq!(failed_response["response"]["status"], "failed");
    assert_eq!(failed_response["response"]["output"], json!([]));
    assert_eq!(
        failed_response["response"]["error"],
        json!({
            "code":"api_error",
            "message":"The model did not call the required tool."
        })
    );
    assert_eq!(response_blocks[5].as_bytes(), b"data: [DONE]");

    let timeout_runtime = DeterministicRuntime::new();
    timeout_runtime.set_delay(Duration::from_millis(100));
    let mut timeout_config = config();
    timeout_config.limits.operation_timeout = Duration::from_millis(20);
    let timeout_server = spawn_with(timeout_config, timeout_runtime).await;
    let timed_out = request(
        &timeout_server,
        "POST",
        "/v1/responses",
        Some("operator-token"),
        &[("Content-Type", "application/json")],
        &json_body(json!({"model":"openclaw","input":"hello","stream":true})),
    )
    .await;
    assert_eq!(timed_out.status, 200);
    let timeout_blocks = timed_out
        .text()
        .split("\n\n")
        .filter(|block| !block.is_empty())
        .collect::<Vec<_>>();
    assert_eq!(timeout_blocks.len(), 6);
    let timeout_failure: Value = serde_json::from_str(
        timeout_blocks[4]
            .lines()
            .nth(1)
            .expect("timeout data line")
            .strip_prefix("data: ")
            .expect("timeout data prefix"),
    )
    .expect("timeout response JSON");
    assert_eq!(timeout_failure["type"], "response.failed");
    assert_eq!(timeout_failure["response"]["status"], "failed");
    assert_eq!(
        timeout_failure["response"]["error"],
        json!({"code":"api_error","message":"request timed out"})
    );
    assert_eq!(timeout_blocks[5].as_bytes(), b"data: [DONE]");

    let non_stream_timeout = request(
        &timeout_server,
        "POST",
        "/v1/responses",
        Some("operator-token"),
        &[("Content-Type", "application/json")],
        &json_body(json!({"model":"openclaw","input":"hello"})),
    )
    .await;
    assert_eq!(non_stream_timeout.status, 504);
    let failed = non_stream_timeout.json();
    assert_eq!(failed["object"], "response");
    assert_eq!(failed["status"], "failed");
    assert_eq!(failed["model"], "openclaw");
    assert_eq!(failed["output"], json!([]));
    assert_eq!(
        failed["usage"],
        json!({"input_tokens":0,"output_tokens":0,"total_tokens":0})
    );
    assert_eq!(
        failed["error"],
        json!({"code":"api_error","message":"request timed out"})
    );
    assert!(
        failed["id"]
            .as_str()
            .is_some_and(|id| id.starts_with("resp_"))
    );
    assert!(failed["created_at"].as_u64().is_some());
    assert_eq!(failed.as_object().expect("failed response object").len(), 8);
}

#[tokio::test]
async fn restrictive_generation_parameters_are_enforced_or_rejected() {
    let runtime = DeterministicRuntime::new();
    let server = spawn_with(config(), runtime.clone()).await;

    let invalid_json = request(
        &server,
        "POST",
        "/v1/chat/completions",
        Some("operator-token"),
        &[("Content-Type", "application/json")],
        &json_body(json!({
            "model":"openclaw",
            "messages":[{"role":"user","content":"return JSON"}],
            "response_format":{"type":"json_object"}
        })),
    )
    .await;
    assert_eq!(invalid_json.status, 502);
    assert_eq!(
        invalid_json.json(),
        json!({"error":{
            "message":"The provider did not return the requested JSON object.",
            "type":"api_error"
        }})
    );

    let invalid_json_stream = request(
        &server,
        "POST",
        "/v1/chat/completions",
        Some("operator-token"),
        &[("Content-Type", "application/json")],
        &json_body(json!({
            "model":"openclaw",
            "messages":[{"role":"user","content":"return JSON"}],
            "response_format":{"type":"json_object"},
            "stream":true
        })),
    )
    .await;
    assert_eq!(invalid_json_stream.status, 200);
    let stream_blocks = invalid_json_stream
        .text()
        .split("\n\n")
        .filter(|block| !block.is_empty())
        .collect::<Vec<_>>();
    assert_eq!(stream_blocks.len(), 3);
    let stream_failure: Value = serde_json::from_str(
        stream_blocks[1]
            .strip_prefix("data: ")
            .expect("JSON constraint failure data"),
    )
    .expect("JSON constraint failure body");
    assert_eq!(
        stream_failure,
        json!({"error":{
            "message":"The provider did not return the requested JSON object.",
            "type":"api_error"
        }})
    );
    assert_eq!(stream_blocks[2].as_bytes(), b"data: [DONE]");
    assert!(
        !invalid_json_stream
            .text()
            .contains("deterministic response")
    );

    runtime
        .set_output(GenerationOutput {
            text: "{\"ok\":true}STOPsecret".to_owned(),
            tool_calls: Vec::new(),
            usage: Usage {
                input_tokens: 3,
                output_tokens: 2,
                total_tokens: 5,
            },
        })
        .expect("set constrained text output");
    let stopped = request(
        &server,
        "POST",
        "/v1/chat/completions",
        Some("operator-token"),
        &[("Content-Type", "application/json")],
        &json_body(json!({
            "model":"openclaw",
            "messages":[{"role":"user","content":"return JSON"}],
            "stop":"STOP",
            "response_format":{"type":"json_object"}
        })),
    )
    .await;
    assert_eq!(stopped.status, 200);
    assert_eq!(
        stopped.json()["choices"][0]["message"]["content"],
        "{\"ok\":true}"
    );

    let token_limited = request(
        &server,
        "POST",
        "/v1/chat/completions",
        Some("operator-token"),
        &[("Content-Type", "application/json")],
        &json_body(json!({
            "model":"openclaw",
            "messages":[{"role":"user","content":"short"}],
            "max_completion_tokens":1
        })),
    )
    .await;
    assert_eq!(token_limited.status, 502);
    assert_eq!(
        token_limited.json(),
        json!({"error":{
            "message":"The provider exceeded the requested output token limit.",
            "type":"api_error"
        }})
    );

    runtime
        .set_output(GenerationOutput {
            text: String::new(),
            tool_calls: vec![ToolCall {
                id: "call-forbidden".to_owned(),
                name: "lookup".to_owned(),
                arguments: "{}".to_owned(),
            }],
            usage: Usage {
                input_tokens: 3,
                output_tokens: 1,
                total_tokens: 4,
            },
        })
        .expect("set forbidden tool output");
    let no_tools = request(
        &server,
        "POST",
        "/v1/chat/completions",
        Some("operator-token"),
        &[("Content-Type", "application/json")],
        &json_body(json!({
            "model":"openclaw",
            "messages":[{"role":"user","content":"do not call tools"}],
            "tools":[{"type":"function","function":{
                "name":"lookup","parameters":{"type":"object"}
            }}],
            "tool_choice":"none"
        })),
    )
    .await;
    assert_eq!(no_tools.status, 502);
    assert_eq!(
        no_tools.json(),
        json!({"error":{
            "message":"The provider called a tool despite tool_choice being none.",
            "type":"api_error"
        }})
    );

    runtime
        .set_output(GenerationOutput {
            text: String::new(),
            tool_calls: vec![ToolCall {
                id: "call-rogue".to_owned(),
                name: "rogue".to_owned(),
                arguments: "{\"secret\":true}".to_owned(),
            }],
            usage: Usage {
                input_tokens: 3,
                output_tokens: 1,
                total_tokens: 4,
            },
        })
        .expect("set unsupplied tool output");
    for stream in [false, true] {
        let rogue = request(
            &server,
            "POST",
            "/v1/chat/completions",
            Some("operator-token"),
            &[("Content-Type", "application/json")],
            &json_body(json!({
                "model":"openclaw",
                "messages":[{"role":"user","content":"use only allowed"}],
                "tools":[{"type":"function","function":{
                    "name":"allowed","parameters":{"type":"object"}
                }}],
                "stream":stream
            })),
        )
        .await;
        if stream {
            assert_eq!(rogue.status, 200);
            let blocks = rogue
                .text()
                .split("\n\n")
                .filter(|block| !block.is_empty())
                .collect::<Vec<_>>();
            assert_eq!(blocks.len(), 3);
            let error: Value = serde_json::from_str(
                blocks[1]
                    .strip_prefix("data: ")
                    .expect("unsupplied tool failure data"),
            )
            .expect("unsupplied tool failure body");
            assert_eq!(
                error,
                json!({"error":{
                    "message":"The provider called a tool that was not supplied by the client.",
                    "type":"api_error"
                }})
            );
            assert_eq!(blocks[2].as_bytes(), b"data: [DONE]");
            assert!(!rogue.text().contains("call-rogue"));
            assert!(!rogue.text().contains("{\"secret\":true}"));
        } else {
            assert_eq!(rogue.status, 502);
            assert_eq!(
                rogue.json(),
                json!({"error":{
                    "message":"The provider called a tool that was not supplied by the client.",
                    "type":"api_error"
                }})
            );
        }
    }

    runtime
        .set_output(GenerationOutput {
            text: "calling twice".to_owned(),
            tool_calls: vec![
                ToolCall {
                    id: "call-1".to_owned(),
                    name: "lookup".to_owned(),
                    arguments: "{}".to_owned(),
                },
                ToolCall {
                    id: "call-2".to_owned(),
                    name: "lookup".to_owned(),
                    arguments: "{}".to_owned(),
                },
            ],
            usage: Usage {
                input_tokens: 3,
                output_tokens: 2,
                total_tokens: 5,
            },
        })
        .expect("set excessive tool output");
    let tool_limited = request(
        &server,
        "POST",
        "/v1/responses",
        Some("operator-token"),
        &[("Content-Type", "application/json")],
        &json_body(json!({
            "model":"openclaw",
            "input":"one call only",
            "tools":[{"type":"function","name":"lookup","parameters":{"type":"object"}}],
            "max_tool_calls":1
        })),
    )
    .await;
    assert_eq!(tool_limited.status, 502);
    assert_eq!(tool_limited.json()["status"], "failed");
    assert_eq!(tool_limited.json()["output"], json!([]));
    assert_eq!(
        tool_limited.json()["error"],
        json!({
            "code":"api_error",
            "message":"The provider exceeded the requested tool call limit."
        })
    );

    for (unsupported, message) in [
        (
            json!({
                "model":"openclaw","input":"strict",
                "tools":[{
                    "type":"function","name":"lookup",
                    "parameters":{"type":"object"},"strict":true
                }]
            }),
            "Invalid tools/tool_choice: invalid tool configuration",
        ),
        (
            json!({"model":"openclaw","input":"private","store":false}),
            "invalid request",
        ),
        (
            json!({"model":"openclaw","input":"bounded","truncation":"disabled"}),
            "invalid request",
        ),
    ] {
        let response = request(
            &server,
            "POST",
            "/v1/responses",
            Some("operator-token"),
            &[("Content-Type", "application/json")],
            &json_body(unsupported),
        )
        .await;
        assert_eq!(response.status, 400);
        assert_eq!(
            response.json(),
            json!({"error":{"message":message,"type":"invalid_request_error"}})
        );
    }

    let strict_chat = request(
        &server,
        "POST",
        "/v1/chat/completions",
        Some("operator-token"),
        &[("Content-Type", "application/json")],
        &json_body(json!({
            "model":"openclaw",
            "messages":[{"role":"user","content":"strict"}],
            "tools":[{"type":"function","function":{
                "name":"lookup","parameters":{"type":"object"},"strict":true
            }}]
        })),
    )
    .await;
    assert_eq!(strict_chat.status, 400);
    assert_eq!(
        strict_chat.json(),
        json!({"error":{
            "message":"Invalid tools/tool_choice: invalid tool configuration",
            "type":"invalid_request_error"
        }})
    );

    let unsupported_schema = request(
        &server,
        "POST",
        "/v1/chat/completions",
        Some("operator-token"),
        &[("Content-Type", "application/json")],
        &json_body(json!({
            "model":"openclaw",
            "messages":[{"role":"user","content":"schema"}],
            "response_format":{"type":"json_schema","json_schema":{"name":"answer"}}
        })),
    )
    .await;
    assert_eq!(unsupported_schema.status, 400);
    assert_eq!(
        unsupported_schema.json(),
        json!({"error":{
            "message":"Invalid response_format: only text and json_object are supported",
            "type":"invalid_request_error"
        }})
    );

    let unsupported_chat_field = request(
        &server,
        "POST",
        "/v1/chat/completions",
        Some("operator-token"),
        &[("Content-Type", "application/json")],
        &json_body(json!({
            "model":"openclaw",
            "messages":[{"role":"user","content":"one tool at a time"}],
            "parallel_tool_calls":false
        })),
    )
    .await;
    assert_eq!(unsupported_chat_field.status, 400);
    assert_eq!(
        unsupported_chat_field.json(),
        json!({"error":{
            "message":"unknown field `parallel_tool_calls`, expected one of `model`, `stream`, `stream_options`, `tools`, `tool_choice`, `messages`, `user`, `max_tokens`, `max_completion_tokens`, `temperature`, `top_p`, `response_format`, `frequency_penalty`, `presence_penalty`, `seed`, `stop`",
            "type":"invalid_request_error"
        }})
    );
}

#[tokio::test]
async fn responses_continuity_is_scoped_to_authenticated_subject_and_model() {
    let runtime = DeterministicRuntime::new();
    let server = spawn_with(config(), runtime.clone()).await;
    let first = request(
        &server,
        "POST",
        "/v1/responses",
        Some("operator-token"),
        &[("Content-Type", "application/json")],
        &json_body(json!({"model":"openclaw","input":"first"})),
    )
    .await;
    assert_eq!(first.status, 200);
    let first_id = first.json()["id"]
        .as_str()
        .expect("first response id")
        .to_owned();
    let first_session = runtime
        .last_generation_request()
        .expect("read first generation")
        .expect("first generation recorded")
        .session_id;

    let continued = request(
        &server,
        "POST",
        "/v1/responses",
        Some("operator-token"),
        &[("Content-Type", "application/json")],
        &json_body(json!({
            "model":"openclaw",
            "input":"continued",
            "previous_response_id":first_id
        })),
    )
    .await;
    assert_eq!(continued.status, 200);
    let continued_session = runtime
        .last_generation_request()
        .expect("read continued generation")
        .expect("continued generation recorded")
        .session_id;
    assert_eq!(continued_session, first_session);

    let isolated_subject = request(
        &server,
        "POST",
        "/v1/responses",
        Some("operator-two"),
        &[("Content-Type", "application/json")],
        &json_body(json!({
            "model":"openclaw",
            "input":"isolated",
            "previous_response_id":first_id
        })),
    )
    .await;
    assert_eq!(isolated_subject.status, 200);
    let isolated_subject_session = runtime
        .last_generation_request()
        .expect("read isolated subject generation")
        .expect("isolated subject generation recorded")
        .session_id;
    assert_ne!(isolated_subject_session, first_session);

    let isolated_model = request(
        &server,
        "POST",
        "/v1/responses",
        Some("operator-token"),
        &[("Content-Type", "application/json")],
        &json_body(json!({
            "model":"openclaw/main",
            "input":"model isolated",
            "previous_response_id":first_id
        })),
    )
    .await;
    assert_eq!(isolated_model.status, 200);
    let isolated_model_session = runtime
        .last_generation_request()
        .expect("read isolated model generation")
        .expect("isolated model generation recorded")
        .session_id;
    assert_ne!(isolated_model_session, first_session);
}

#[tokio::test]
async fn mcp_server_rejects_non_loopback_listener_bindings() {
    let runtime = DeterministicRuntime::new();
    let api = HttpApi::new(config(), runtime.services());
    let listener = TcpListener::bind("0.0.0.0:0")
        .await
        .expect("bind unspecified listener");
    let error = api
        .serve_mcp(listener)
        .await
        .expect_err("MCP rejects non-loopback listener");
    assert_eq!(error.kind(), std::io::ErrorKind::InvalidInput);
    assert_eq!(
        error.to_string(),
        "MCP listener must bind to a loopback address"
    );
}

#[tokio::test]
async fn generation_ports_receive_validated_parameters_media_and_strict_responses_input() {
    let runtime = DeterministicRuntime::new();
    runtime
        .set_output(GenerationOutput {
            text: "{\"ok\":true}".to_owned(),
            tool_calls: Vec::new(),
            usage: Usage {
                input_tokens: 3,
                output_tokens: 2,
                total_tokens: 5,
            },
        })
        .expect("set valid structured output");
    let server = spawn_with(config(), runtime.clone()).await;
    let chat = request(
        &server,
        "POST",
        "/v1/chat/completions",
        Some("operator-token"),
        &[("Content-Type", "application/json")],
        &json_body(json!({
            "model":"openclaw",
            "messages":[
                {"role":"system","content":"Be exact."},
                {"role":"user","content":[
                    {"type":"text","text":"inspect"},
                    {"type":"image_url","image_url":{"url":"data:image/png;base64,AQID"}}
                ]}
            ],
            "max_completion_tokens":32,
            "temperature":0.25,
            "top_p":0.75,
            "frequency_penalty":-0.5,
            "presence_penalty":0.5,
            "seed":7,
            "stop":["END"],
            "response_format":{"type":"json_object"}
        })),
    )
    .await;
    assert_eq!(chat.status, 200);
    let chat_request = runtime
        .last_generation_request()
        .expect("read chat request")
        .expect("chat request recorded");
    assert_eq!(chat_request.model, "openclaw");
    assert_eq!(chat_request.prompt, "user: inspect");
    assert_eq!(chat_request.instructions.as_deref(), Some("Be exact."));
    assert_eq!(
        chat_request.media,
        vec![InputMedia {
            kind: InputMediaKind::Image,
            source: InputMediaSource::Base64 {
                media_type: "image/png".to_owned(),
                data: "AQID".to_owned(),
                filename: None
            }
        }]
    );
    assert_eq!(chat_request.max_tokens, Some(32));
    assert_eq!(chat_request.temperature, Some(0.25));
    assert_eq!(chat_request.top_p, Some(0.75));
    assert_eq!(chat_request.frequency_penalty, Some(-0.5));
    assert_eq!(chat_request.presence_penalty, Some(0.5));
    assert_eq!(chat_request.seed, Some(7));
    assert_eq!(chat_request.stop, Some(vec!["END".to_owned()]));
    assert_eq!(
        chat_request.response_format,
        Some(json!({"type":"json_object"}))
    );

    let responses = request(
        &server,
        "POST",
        "/v1/responses",
        Some("operator-token"),
        &[("Content-Type", "application/json")],
        &json_body(json!({
            "model":"openclaw",
            "instructions":"Top-level.",
            "input":[
                {"type":"message","role":"developer","content":"System item."},
                {"type":"message","role":"user","content":[
                    {"type":"input_image","source":{
                        "type":"base64","media_type":"image/png","data":"AQID"
                    }},
                    {"type":"input_file","source":{
                        "type":"base64","media_type":"text/plain","data":"aGVsbG8=",
                        "filename":"note.txt"
                    }}
                ]}
            ]
        })),
    )
    .await;
    assert_eq!(responses.status, 200);
    let response_request = runtime
        .last_generation_request()
        .expect("read response request")
        .expect("response request recorded");
    assert_eq!(
        response_request.prompt,
        "user: User sent image(s) with no text."
    );
    assert_eq!(
        response_request.instructions.as_deref(),
        Some("Top-level.\n\nSystem item.")
    );
    assert_eq!(
        response_request.media,
        vec![
            InputMedia {
                kind: InputMediaKind::Image,
                source: InputMediaSource::Base64 {
                    media_type: "image/png".to_owned(),
                    data: "AQID".to_owned(),
                    filename: None
                }
            },
            InputMedia {
                kind: InputMediaKind::File,
                source: InputMediaSource::Base64 {
                    media_type: "text/plain".to_owned(),
                    data: "aGVsbG8=".to_owned(),
                    filename: Some("note.txt".to_owned())
                }
            }
        ]
    );

    let invalid = request(
        &server,
        "POST",
        "/v1/responses",
        Some("operator-token"),
        &[("Content-Type", "application/json")],
        &json_body(json!({
            "model":"openclaw",
            "input":[{
                "type":"message","role":"user",
                "content":[{"type":"input_text","text":"hello","extra":true}]
            }]
        })),
    )
    .await;
    assert_eq!(invalid.status, 400);
    assert_eq!(
        invalid.json(),
        json!({"error":{"message":"invalid request","type":"invalid_request_error"}})
    );

    let invalid_stop = request(
        &server,
        "POST",
        "/v1/chat/completions",
        Some("operator-token"),
        &[("Content-Type", "application/json")],
        &json_body(json!({
            "model":"openclaw",
            "messages":[{"role":"user","content":"hello"}],
            "stop":["1","2","3","4","5"]
        })),
    )
    .await;
    assert_eq!(invalid_stop.status, 400);
    assert_eq!(
        invalid_stop.json(),
        json!({"error":{
            "message":"Invalid stop: stop supports at most 4 sequences",
            "type":"invalid_request_error"
        }})
    );
}

//! End-to-end contract tests over real TCP sockets.

use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::net::SocketAddr;
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

use claw_http_api::{
    ApiConfig, BearerAuthenticator, BearerCredential, DeterministicRuntime, GenerationOutput,
    HTTP_ENDPOINTS, HttpApi, InputMedia, InputMediaKind, InputMediaSource, ServingStateHandle,
    ToolCall, ToolInvocation, ToolInvocationContext, Usage, WebhookRoute,
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

#[tokio::test]
async fn registered_endpoint_set_exactly_matches_frozen_inventory() {
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
        .iter()
        .map(|endpoint| (endpoint.method.clone(), endpoint.path.clone()))
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

    let runtime = DeterministicRuntime::new();
    let server = spawn_with(config(), runtime).await;
    for endpoint in &inventory.items {
        let path = endpoint
            .path
            .replace("{id}", "inventory-probe")
            .replace("{routeId}", "inventory-probe");
        let wrong_method = match endpoint.method.as_str() {
            "GET" => "POST",
            "POST" => "GET",
            method => panic!("unsupported frozen HTTP method {method}"),
        };
        let (address, token) = if endpoint.path == "/mcp" {
            (server.mcp_address, "mcp-owner")
        } else {
            (server.address, "operator-token")
        };
        let response = request_at(address, wrong_method, &path, Some(token), &[], b"").await;
        assert_eq!(
            response.status, 405,
            "{} {} was not bound to the expected method",
            endpoint.method, endpoint.path
        );
        let allowed = response
            .headers
            .get("allow")
            .unwrap_or_else(|| panic!("{} {} omitted Allow", endpoint.method, endpoint.path));
        assert!(
            allowed
                .split(',')
                .any(|method| method.trim() == endpoint.method),
            "{} {} returned Allow: {allowed}",
            endpoint.method,
            endpoint.path
        );
        assert!(
            allowed
                .split(',')
                .all(|method| method.trim() != wrong_method),
            "{} {} unexpectedly accepted {wrong_method}",
            endpoint.method,
            endpoint.path
        );
    }
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
    config.limits.heartbeat_interval = Duration::from_mins(1);
    config
}

async fn spawn_with(config: ApiConfig, runtime: Arc<DeterministicRuntime>) -> Server {
    spawn_with_serving(config, runtime, ServingStateHandle::serving()).await
}

async fn spawn_with_serving(
    config: ApiConfig,
    runtime: Arc<DeterministicRuntime>,
    serving: ServingStateHandle,
) -> Server {
    spawn_with_services(config, runtime.services(), serving).await
}

async fn spawn_with_services(
    config: ApiConfig,
    services: claw_http_api::ApiServices,
    serving: ServingStateHandle,
) -> Server {
    let api = HttpApi::with_serving_state(config, services, Arc::new(serving));
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
        head.push_str("Authorization: Bearer ");
        head.push_str(token);
        head.push_str("\r\n");
    }
    for (name, value) in extra_headers {
        head.push_str(name);
        head.push_str(": ");
        head.push_str(value);
        head.push_str("\r\n");
    }
    head.push_str("\r\n");
    stream
        .write_all(head.as_bytes())
        .await
        .expect("write request head");
    stream.write_all(body).await.expect("write request body");
    let raw = timeout(Duration::from_secs(3), read_complete_response(&mut stream))
        .await
        .expect("response timeout")
        .expect("read response");
    parse_response(&raw)
}

async fn read_complete_response(stream: &mut TcpStream) -> std::io::Result<Vec<u8>> {
    let mut raw = Vec::new();
    let mut buffer = [0_u8; 8 * 1024];
    loop {
        if let Some(length) = complete_response_length(&raw) {
            raw.truncate(length);
            return Ok(raw);
        }
        match stream.read(&mut buffer).await {
            Ok(0)
                if raw.windows(4).any(|window| window == b"\r\n\r\n")
                    && !has_explicit_response_framing(&raw) =>
            {
                return Ok(raw);
            }
            Ok(0) => {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::UnexpectedEof,
                    "connection closed before the complete HTTP response",
                ));
            }
            Ok(read) => raw.extend_from_slice(&buffer[..read]),
            Err(error) => {
                if let Some(length) = complete_response_length(&raw) {
                    raw.truncate(length);
                    return Ok(raw);
                }
                return Err(error);
            }
        }
    }
}

fn has_explicit_response_framing(raw: &[u8]) -> bool {
    let Some(split) = raw.windows(4).position(|window| window == b"\r\n\r\n") else {
        return false;
    };
    let Ok(head) = std::str::from_utf8(&raw[..split]) else {
        return false;
    };
    head.split("\r\n").skip(1).any(|line| {
        line.split_once(':').is_some_and(|(name, value)| {
            name.trim().eq_ignore_ascii_case("content-length")
                || (name.trim().eq_ignore_ascii_case("transfer-encoding")
                    && value
                        .split(',')
                        .any(|coding| coding.trim().eq_ignore_ascii_case("chunked")))
        })
    })
}

fn complete_response_length(raw: &[u8]) -> Option<usize> {
    let split = raw.windows(4).position(|window| window == b"\r\n\r\n")?;
    let body_start = split + 4;
    let head = std::str::from_utf8(&raw[..split]).ok()?;
    let headers = head
        .split("\r\n")
        .skip(1)
        .filter_map(|line| line.split_once(':'))
        .map(|(name, value)| (name.trim(), value.trim()));
    let mut content_length = None;
    let mut chunked = false;
    for (name, value) in headers {
        if name.eq_ignore_ascii_case("content-length") {
            content_length = value.parse::<usize>().ok();
        } else if name.eq_ignore_ascii_case("transfer-encoding") {
            chunked = value
                .split(',')
                .any(|coding| coding.trim().eq_ignore_ascii_case("chunked"));
        }
    }
    if chunked {
        return complete_chunked_length(&raw[body_start..])
            .and_then(|length| body_start.checked_add(length));
    }
    content_length.and_then(|length| {
        let total = body_start.checked_add(length)?;
        (raw.len() >= total).then_some(total)
    })
}

fn complete_chunked_length(bytes: &[u8]) -> Option<usize> {
    let mut offset = 0_usize;
    loop {
        let size_end = bytes
            .get(offset..)?
            .windows(2)
            .position(|window| window == b"\r\n")?;
        let size_text = std::str::from_utf8(bytes.get(offset..offset + size_end)?).ok()?;
        let size = usize::from_str_radix(size_text.split(';').next()?.trim(), 16).ok()?;
        offset = offset.checked_add(size_end + 2)?;
        if size == 0 {
            loop {
                let trailer_end = bytes
                    .get(offset..)?
                    .windows(2)
                    .position(|window| window == b"\r\n")?;
                offset = offset.checked_add(trailer_end + 2)?;
                if trailer_end == 0 {
                    return Some(offset);
                }
            }
        }
        let chunk_end = offset.checked_add(size)?;
        if bytes.get(chunk_end..chunk_end + 2)? != b"\r\n" {
            return None;
        }
        offset = chunk_end + 2;
    }
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

fn json_body(value: &Value) -> Vec<u8> {
    serde_json::to_vec(value).expect("test JSON serializes")
}

fn watch_connect_body(nonce: &str, device_id: &str) -> Vec<u8> {
    json_body(&json!({
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
    let live_alias = request(&server, "GET", "/healthz", None, &[], b"").await;
    assert_eq!(live_alias.status, 200);
    assert_eq!(live_alias.json(), json!({"ok":true,"status":"live"}));

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
        &json_body(&json!({"model":"openclaw","input":"hi","dimensions":2})),
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
        &json_body(&json!({
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
        &json_body(&json!({"model":"openclaw","input":"hello"})),
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
        &json_body(&json!({
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
        &json_body(&json!({"model":"openclaw","input":"hello","stream":true})),
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
        &json_body(&json!({
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
    let mut invocation = runtime
        .last_tool_invocation()
        .expect("read tool invocation")
        .expect("tool invocation recorded");
    let authority = invocation
        .context
        .authority
        .take()
        .expect("authenticated tool authority");
    assert_eq!(
        authority.source(),
        claw_application::ports::tool::InvocationSource::Http
    );
    assert!(authority.is_owner() && authority.can_execute());
    assert_eq!(
        authority.account(),
        None,
        "routing header is not an authenticated account"
    );
    assert_ne!(authority.subject(), "operator-token");
    assert!(!format!("{authority:?}").contains(authority.subject()));
    assert_eq!(
        invocation,
        ToolInvocation {
            name: "echo".to_owned(),
            arguments: json!({"value":7}),
            action: Some("send".to_owned()),
            context: ToolInvocationContext {
                authority: None,
                binding: None,
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
        &json_body(&json!({"id":"rpc-1","method":"status","params":{"verbose":true}})),
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
        &json_body(&json!({"id":"rpc-2","method":"chat.send"})),
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
        &json_body(&json!({"id":"rpc-3","method":"config.set","params":{}})),
    )
    .await;
    assert_eq!(scope_denied.status, 403);
    assert_eq!(
        scope_denied.json(),
        json!({"ok":false,"error":{"type":"forbidden","message":"missing scope: operator.admin"}})
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
        &json_body(&json!({
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
        &json_body(&json!({
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
        &json_body(&json!({"action":"list_flows"})),
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
        &json_body(&json!({"action":"list_flows"})),
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
            &json_body(&invalid_body),
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
        &json_body(&json!({"name":"echo","args":{}})),
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
        &json_body(&json!({"name":"echo","args":{}})),
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
        &json_body(&json!({"args":{}})),
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
        &json_body(&json!({"name":"missing","args":{"value":7}})),
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
async fn tools_outcome_unknown_and_timeouts_never_invite_http_or_mcp_replay() {
    struct UncertainTools {
        hangs: bool,
        calls: std::sync::atomic::AtomicUsize,
        cancellations: std::sync::Mutex<Vec<tokio_util::sync::CancellationToken>>,
    }
    impl claw_http_api::ToolPort for UncertainTools {
        fn list(
            &self,
        ) -> claw_http_api::PortFuture<
            '_,
            Result<Vec<claw_http_api::ToolDefinition>, claw_http_api::PortError>,
        > {
            Box::pin(async { Ok(Vec::new()) })
        }
        fn invoke(
            &self,
            _invocation: ToolInvocation,
            cancellation: tokio_util::sync::CancellationToken,
        ) -> claw_http_api::PortFuture<
            '_,
            Result<claw_http_api::ToolOutcome, claw_http_api::PortError>,
        > {
            self.calls
                .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            self.cancellations
                .lock()
                .expect("invocation tokens")
                .push(cancellation);
            Box::pin(async move {
                if self.hangs {
                    std::future::pending::<()>().await;
                }
                Err(claw_http_api::PortError::new(
                    claw_http_api::PortErrorKind::OutcomeUnknown,
                    "The write may have taken effect; do not repeat it automatically.",
                ))
            })
        }
    }
    for hangs in [false, true] {
        let tools = Arc::new(UncertainTools {
            hangs,
            calls: std::sync::atomic::AtomicUsize::new(0),
            cancellations: std::sync::Mutex::new(Vec::new()),
        });
        let mut services = DeterministicRuntime::new().services();
        services.tools = tools.clone();
        let mut config = config();
        config.limits.operation_timeout = Duration::from_millis(20);
        let server = spawn_with_services(config, services, ServingStateHandle::serving()).await;
        let response = request(
            &server,
            "POST",
            "/tools/invoke",
            Some("operator-token"),
            &[("Content-Type", "application/json")],
            &json_body(&json!({"name": "write", "args": {}})),
        )
        .await;
        assert_eq!(response.status, 409);
        assert_eq!(response.json()["error"]["type"], "outcome_unknown");
        assert_eq!(response.json()["error"]["retryable"], false);
        assert_eq!(response.json()["error"]["recoveryRequired"], true);
        let response = request_at(server.mcp_address, "POST", "/mcp", Some("mcp-owner"), &[("Content-Type", "application/json")], &json_body(&json!({"jsonrpc": "2.0", "id": 1, "method": "tools/call", "params": {"name": "write", "arguments": {}}}))).await;
        assert_eq!(response.status, 200);
        let result = response.json();
        assert_eq!(result["result"]["isError"], true);
        assert_eq!(
            result["result"]["_meta"]["gta-claw"]["error"]["type"],
            "outcome_unknown"
        );
        assert_eq!(
            result["result"]["_meta"]["gta-claw"]["error"]["retryable"],
            false
        );
        assert!(
            result["result"]["content"][0]["text"]
                .as_str()
                .expect("recovery message")
                .contains("Do not repeat it automatically")
        );
        assert_eq!(tools.calls.load(std::sync::atomic::Ordering::Relaxed), 2);
        assert!(
            tools
                .cancellations
                .lock()
                .expect("cancelled calls")
                .iter()
                .all(tokio_util::sync::CancellationToken::is_cancelled)
        );
    }
}

#[tokio::test]
async fn mcp_cancellation_targets_only_the_authenticated_active_request() {
    use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
    use tokio_util::sync::CancellationToken;

    async fn open_session_events(address: SocketAddr, session: &str) -> TcpStream {
        let mut events = TcpStream::connect(address)
            .await
            .expect("session SSE socket");
        let request = format!(
            "GET /mcp HTTP/1.1\r\nHost: {address}\r\nAuthorization: Bearer mcp-owner\r\nMcp-Session-Id: {session}\r\nConnection: close\r\n\r\n"
        );
        events
            .write_all(request.as_bytes())
            .await
            .expect("session SSE request");
        let mut head = Vec::new();
        timeout(Duration::from_secs(2), async {
            while !head.windows(4).any(|window| window == b"\r\n\r\n") {
                let mut buffer = [0; 512];
                let count = events.read(&mut buffer).await.expect("SSE headers");
                assert!(count > 0);
                head.extend_from_slice(&buffer[..count]);
                assert!(head.len() <= 8_192);
            }
        })
        .await
        .expect("SSE opened before deletion");
        assert!(String::from_utf8_lossy(&head).contains("200 OK"));
        events
    }

    struct WaitingTools {
        calls: AtomicUsize,
        started: tokio::sync::mpsc::Sender<CancellationToken>,
        wait_catalog: AtomicBool,
        catalog_started: tokio::sync::mpsc::Sender<()>,
    }
    impl claw_http_api::ToolPort for WaitingTools {
        fn list(
            &self,
        ) -> claw_http_api::PortFuture<
            '_,
            Result<Vec<claw_http_api::ToolDefinition>, claw_http_api::PortError>,
        > {
            Box::pin(async {
                if self.wait_catalog.load(Ordering::SeqCst) {
                    self.catalog_started
                        .send(())
                        .await
                        .expect("catalog observer");
                    std::future::pending::<()>().await;
                }
                Ok(Vec::new())
            })
        }
        fn invoke(
            &self,
            _invocation: ToolInvocation,
            cancellation: CancellationToken,
        ) -> claw_http_api::PortFuture<
            '_,
            Result<claw_http_api::ToolOutcome, claw_http_api::PortError>,
        > {
            self.calls.fetch_add(1, Ordering::SeqCst);
            Box::pin(async move {
                self.started
                    .send(cancellation.clone())
                    .await
                    .expect("test observer");
                cancellation.cancelled().await;
                Err(claw_http_api::PortError::new(
                    claw_http_api::PortErrorKind::OutcomeUnknown,
                    "Cancelled execution requires reconciliation",
                ))
            })
        }
    }

    let (started, mut observed) = tokio::sync::mpsc::channel(2);
    let (catalog_started, mut catalogs) = tokio::sync::mpsc::channel(1);
    let tools = Arc::new(WaitingTools {
        calls: AtomicUsize::new(0),
        started,
        wait_catalog: AtomicBool::new(false),
        catalog_started,
    });
    let mut services = DeterministicRuntime::new().services();
    services.tools = tools.clone();
    let mut settings = config();
    settings.limits.operation_timeout = Duration::from_secs(5);
    settings.mcp_owner_authenticator = BearerAuthenticator::new(vec![
        credential("mcp-owner", [Scope::OperatorAdmin]),
        credential("mcp-owner-two", [Scope::OperatorAdmin]),
    ]);
    let server = spawn_with_services(settings, services, ServingStateHandle::serving()).await;
    let address = server.mcp_address;
    let invocation = json!({"jsonrpc":"2.0","id":7,"method":"tools/call","params":{"name":"wait","arguments":{}}});
    let start_call = |token: &'static str| {
        let body = json_body(&invocation);
        tokio::spawn(async move {
            request_at(
                address,
                "POST",
                "/mcp",
                Some(token),
                &[("Content-Type", "application/json")],
                &body,
            )
            .await
        })
    };
    let first = start_call("mcp-owner");
    let first_token = timeout(Duration::from_secs(2), observed.recv())
        .await
        .expect("first call started")
        .expect("first token");
    let second = start_call("mcp-owner-two");
    let second_token = timeout(Duration::from_secs(2), observed.recv())
        .await
        .expect("second call started")
        .expect("second token");

    let notify = json!({"jsonrpc":"2.0","method":"notifications/cancelled","params":{"requestId":7,"reason":"private-client-reason"}});
    assert_eq!(
        mcp_request(
            &server,
            "POST",
            Some("mcp-client"),
            &[("Content-Type", "application/json")],
            &json_body(&notify)
        )
        .await
        .status,
        202
    );
    let mut wrong_type = notify.clone();
    wrong_type["params"]["requestId"] = json!("7");
    assert_eq!(
        mcp_request(
            &server,
            "POST",
            Some("mcp-owner"),
            &[("Content-Type", "application/json")],
            &json_body(&wrong_type)
        )
        .await
        .status,
        202
    );
    assert!(!first_token.is_cancelled());
    assert!(!second_token.is_cancelled());
    let duplicate = mcp_request(
        &server,
        "POST",
        Some("mcp-owner"),
        &[("Content-Type", "application/json")],
        &json_body(&invocation),
    )
    .await;
    assert_eq!(duplicate.json()["error"]["code"], -32600);
    for invalid_id in [json!(null), json!(1.5), json!("x".repeat(257)), json!([])] {
        let mut invalid = invocation.clone();
        invalid["id"] = invalid_id;
        assert_eq!(
            mcp_request(
                &server,
                "POST",
                Some("mcp-owner"),
                &[("Content-Type", "application/json")],
                &json_body(&invalid)
            )
            .await
            .json()["error"]["code"],
            -32600
        );
    }
    let mut missing_id = invocation.clone();
    missing_id
        .as_object_mut()
        .expect("request object")
        .remove("id");
    assert_eq!(
        mcp_request(
            &server,
            "POST",
            Some("mcp-owner"),
            &[("Content-Type", "application/json")],
            &json_body(&missing_id)
        )
        .await
        .json()["error"]["code"],
        -32600
    );
    assert_eq!(
        tools.calls.load(Ordering::SeqCst),
        2,
        "duplicate/invalid calls cannot invoke tools"
    );

    assert_eq!(
        mcp_request(
            &server,
            "POST",
            Some("mcp-owner"),
            &[("Content-Type", "application/json")],
            &json_body(&notify)
        )
        .await
        .status,
        202
    );
    let first_result = timeout(Duration::from_secs(2), first)
        .await
        .expect("first cancelled promptly")
        .expect("first task");
    assert!(first_token.is_cancelled());
    assert!(!second_token.is_cancelled());
    assert_eq!(
        first_result.json()["result"]["_meta"]["gta-claw"]["error"]["retryable"],
        false
    );
    assert!(!first_result.text().contains("private-client-reason"));
    assert_eq!(
        mcp_request(
            &server,
            "POST",
            Some("mcp-owner-two"),
            &[("Content-Type", "application/json")],
            &json_body(&notify)
        )
        .await
        .status,
        202
    );
    let second_result = timeout(Duration::from_secs(2), second)
        .await
        .expect("second cancelled promptly")
        .expect("second task");
    assert_eq!(
        second_result.json()["result"]["_meta"]["gta-claw"]["error"]["retryable"],
        false
    );

    let replacement = start_call("mcp-owner");
    let replacement_token = timeout(Duration::from_secs(2), observed.recv())
        .await
        .expect("replacement started")
        .expect("replacement token");
    assert!(!replacement_token.is_cancelled());
    assert_eq!(
        mcp_request(
            &server,
            "POST",
            Some("mcp-owner"),
            &[("Content-Type", "application/json")],
            &json_body(&notify)
        )
        .await
        .status,
        202
    );
    assert_eq!(
        timeout(Duration::from_secs(2), replacement)
            .await
            .expect("replacement cancelled")
            .expect("replacement task")
            .status,
        200
    );
    assert_eq!(tools.calls.load(Ordering::SeqCst), 3);

    let initialize = json!({"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-03-26","capabilities":{},"clientInfo":{"name":"session-fixture","version":"1"}}});
    for ambiguous in [
        br#"{"jsonrpc":"2.0","id":1,"id":2,"method":"tools/call","params":{"name":"wait","arguments":{}}}"#.as_slice(),
        br#"{"jsonrpc":"2.0","id":1,"method":"initialize","method":"tools/call","params":{"name":"wait","arguments":{}}}"#.as_slice(),
        br#"{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"wait","arguments":{"value":"private-duplicate-detail","value":"overridden"}}}"#.as_slice(),
        br#"{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-03-26","protocolVersion":"2024-11-05","clientInfo":{"name":"fixture","version":"1"},"capabilities":{}}}"#.as_slice(),
    ] {
        let response = mcp_request(&server, "POST", Some("mcp-owner"), &[("Content-Type", "application/json")], ambiguous).await;
        assert_eq!(response.status, 400);
        assert_eq!(response.json()["error"]["code"], -32700);
        assert!(!response.headers.contains_key("mcp-session-id"));
        assert!(!response.text().contains("private-duplicate-detail"));
    }
    for (pointer, invalid) in [
        ("/params/clientInfo", json!(null)),
        ("/params/capabilities", json!([])),
        ("/params/clientInfo/name", json!("")),
        ("/params/clientInfo/version", json!("x".repeat(129))),
        ("/params/protocolVersion", json!(1)),
        ("/params/protocolVersion", json!("line\nbreak")),
        ("/id", json!(null)),
    ] {
        let mut malformed = initialize.clone();
        *malformed.pointer_mut(pointer).expect("initialize field") = invalid;
        let response = mcp_request(
            &server,
            "POST",
            Some("mcp-owner"),
            &[("Content-Type", "application/json")],
            &json_body(&malformed),
        )
        .await;
        assert_eq!(response.json()["error"]["code"], -32602);
        assert!(!response.headers.contains_key("mcp-session-id"));
    }
    let mut missing = initialize.clone();
    missing["params"]
        .as_object_mut()
        .expect("parameters")
        .remove("capabilities");
    assert_eq!(
        mcp_request(
            &server,
            "POST",
            Some("mcp-owner"),
            &[("Content-Type", "application/json")],
            &json_body(&missing)
        )
        .await
        .json()["error"]["code"],
        -32602
    );
    assert_eq!(
        mcp_request(
            &server,
            "POST",
            Some("mcp-owner"),
            &[("Content-Type", "application/json")],
            &json_body(&json!([initialize.clone(), invocation.clone()]))
        )
        .await
        .status,
        400,
        "a malformed initialization batch cannot also invoke tools"
    );
    let legacy_initialize = mcp_request(&server, "POST", Some("mcp-owner"), &[("Content-Type", "application/json")], &json_body(&json!({"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2024-11-05"}}))).await;
    assert_eq!(legacy_initialize.status, 200);
    assert!(!legacy_initialize.headers.contains_key("mcp-session-id"));
    let mut session_ids = Vec::new();
    for _session in 0..2 {
        let response = mcp_request(
            &server,
            "POST",
            Some("mcp-owner"),
            &[("Content-Type", "application/json")],
            &json_body(&initialize),
        )
        .await;
        assert_eq!(response.status, 200);
        session_ids.push(
            response
                .headers
                .get("mcp-session-id")
                .expect("issued standard session header")
                .clone(),
        );
    }
    assert_ne!(session_ids[0], session_ids[1]);
    assert_eq!(
        mcp_request(
            &server,
            "POST",
            Some("mcp-owner"),
            &[
                ("Content-Type", "application/json"),
                ("Mcp-Session-Id", &session_ids[0])
            ],
            &json_body(&initialize)
        )
        .await
        .status,
        400
    );
    for session in &session_ids {
        let before = mcp_request(
            &server,
            "POST",
            Some("mcp-owner"),
            &[
                ("Content-Type", "application/json"),
                ("Mcp-Session-Id", session),
            ],
            &json_body(&invocation),
        )
        .await;
        assert_eq!(before.json()["error"]["code"], -32002);
        let invalid_notification =
            json!({"jsonrpc":"2.0","id":55,"method":"notifications/initialized"});
        assert_eq!(
            mcp_request(
                &server,
                "POST",
                Some("mcp-owner"),
                &[
                    ("Content-Type", "application/json"),
                    ("Mcp-Session-Id", session)
                ],
                &json_body(&invalid_notification)
            )
            .await
            .json()["error"]["code"],
            -32600
        );
        let initialized = json!({"jsonrpc":"2.0","method":"notifications/initialized"});
        assert_eq!(
            mcp_request(
                &server,
                "POST",
                Some("mcp-owner"),
                &[
                    ("Content-Type", "application/json"),
                    ("Mcp-Session-Id", session),
                    ("Mcp-Protocol-Version", "2024-11-05")
                ],
                &json_body(&initialized)
            )
            .await
            .status,
            400
        );
        let still_waiting = mcp_request(
            &server,
            "POST",
            Some("mcp-owner"),
            &[
                ("Content-Type", "application/json"),
                ("Mcp-Session-Id", session),
            ],
            &json_body(&invocation),
        )
        .await;
        assert_eq!(still_waiting.json()["error"]["code"], -32002);
        let ready = mcp_request(
            &server,
            "POST",
            Some("mcp-owner"),
            &[
                ("Content-Type", "application/json"),
                ("Mcp-Session-Id", session),
                ("Mcp-Protocol-Version", "2025-03-26"),
            ],
            &json_body(&initialized),
        )
        .await;
        assert_eq!(ready.status, 202);
        assert!(ready.body.is_empty());
        assert_eq!(
            mcp_request(
                &server,
                "POST",
                Some("mcp-owner"),
                &[
                    ("Content-Type", "application/json"),
                    ("Mcp-Session-Id", session),
                    ("Mcp-Protocol-Version", "2025-03-26"),
                    ("Mcp-Protocol-Version", "2025-03-26")
                ],
                &json_body(&invocation)
            )
            .await
            .status,
            400
        );
    }
    assert_eq!(
        tools.calls.load(Ordering::SeqCst),
        3,
        "pre-initialized, malformed and wrong-version requests never call tools"
    );
    let start_scoped = |session: String| {
        let body = json_body(&invocation);
        tokio::spawn(async move {
            request_at(
                address,
                "POST",
                "/mcp",
                Some("mcp-owner"),
                &[
                    ("Content-Type", "application/json"),
                    ("Mcp-Session-Id", &session),
                ],
                &body,
            )
            .await
        })
    };
    let scoped_first = start_scoped(session_ids[0].clone());
    let scoped_first_token = timeout(Duration::from_secs(2), observed.recv())
        .await
        .expect("first scoped call")
        .expect("first scoped token");
    let scoped_second = start_scoped(session_ids[1].clone());
    let scoped_second_token = timeout(Duration::from_secs(2), observed.recv())
        .await
        .expect("second scoped call")
        .expect("second scoped token");
    let legacy = start_call("mcp-owner");
    let legacy_token = timeout(Duration::from_secs(2), observed.recv())
        .await
        .expect("independent legacy call")
        .expect("legacy token");
    assert_eq!(
        mcp_request(
            &server,
            "POST",
            Some("mcp-client"),
            &[
                ("Content-Type", "application/json"),
                ("Mcp-Session-Id", &session_ids[0])
            ],
            &json_body(&notify)
        )
        .await
        .status,
        404
    );
    assert_eq!(
        mcp_request(
            &server,
            "POST",
            Some("mcp-owner"),
            &[
                ("Content-Type", "application/json"),
                ("Mcp-Session-Id", &session_ids[0]),
                ("Mcp-Session-Id", &session_ids[1])
            ],
            &json_body(&notify)
        )
        .await
        .status,
        404
    );
    assert_eq!(
        mcp_request(
            &server,
            "POST",
            Some("mcp-owner"),
            &[("Content-Type", "application/json")],
            &json_body(&notify)
        )
        .await
        .status,
        202
    );
    assert!(legacy_token.is_cancelled());
    assert!(!scoped_first_token.is_cancelled());
    assert!(!scoped_second_token.is_cancelled());
    timeout(Duration::from_secs(2), legacy)
        .await
        .expect("legacy cancelled independently")
        .expect("legacy task");

    let mut events = open_session_events(address, &session_ids[1]).await;
    let mut secondary_events = open_session_events(address, &session_ids[1]).await;
    assert_eq!(
        mcp_request(
            &server,
            "GET",
            Some("mcp-owner"),
            &[("Mcp-Session-Id", &session_ids[1])],
            b""
        )
        .await
        .status,
        429
    );

    assert_eq!(
        mcp_request(
            &server,
            "POST",
            Some("mcp-owner"),
            &[
                ("Content-Type", "application/json"),
                ("Mcp-Session-Id", &session_ids[0])
            ],
            &json_body(&notify)
        )
        .await
        .status,
        202
    );
    timeout(Duration::from_secs(2), scoped_first)
        .await
        .expect("first scoped cancelled")
        .expect("first scoped task");
    assert!(scoped_first_token.is_cancelled());
    assert!(!scoped_second_token.is_cancelled());
    assert_eq!(
        mcp_request(
            &server,
            "DELETE",
            Some("mcp-client"),
            &[("Mcp-Session-Id", &session_ids[1])],
            b""
        )
        .await
        .status,
        404
    );
    assert!(!scoped_second_token.is_cancelled());
    assert_eq!(
        mcp_request(
            &server,
            "DELETE",
            Some("mcp-owner"),
            &[("Mcp-Session-Id", &session_ids[1])],
            b""
        )
        .await
        .status,
        200
    );
    let closed = timeout(Duration::from_secs(2), scoped_second)
        .await
        .expect("session close cancelled call")
        .expect("second scoped task");
    assert!(scoped_second_token.is_cancelled());
    assert_eq!(
        closed.json()["result"]["_meta"]["gta-claw"]["error"]["retryable"],
        false
    );
    let mut tail = Vec::new();
    timeout(Duration::from_secs(2), events.read_to_end(&mut tail))
        .await
        .expect("session close ended SSE")
        .expect("SSE EOF");
    timeout(
        Duration::from_secs(2),
        secondary_events.read_to_end(&mut tail),
    )
    .await
    .expect("session close ended second SSE")
    .expect("second SSE EOF");
    assert_eq!(
        mcp_request(
            &server,
            "POST",
            Some("mcp-owner"),
            &[
                ("Content-Type", "application/json"),
                ("Mcp-Session-Id", &session_ids[1])
            ],
            &json_body(&invocation)
        )
        .await
        .status,
        404
    );
    assert_eq!(
        mcp_request(
            &server,
            "POST",
            Some("mcp-owner"),
            &[
                ("Content-Type", "application/json"),
                ("Mcp-Session-Id", &session_ids[0])
            ],
            &json_body(&json!({"jsonrpc":"2.0","id":2,"method":"tools/list"}))
        )
        .await
        .status,
        200,
        "other session remains usable"
    );
    assert_eq!(
        mcp_request(
            &server,
            "DELETE",
            Some("mcp-owner"),
            &[("Mcp-Session-Id", &session_ids[0])],
            b""
        )
        .await
        .status,
        200
    );
    assert_eq!(
        tools.calls.load(Ordering::SeqCst),
        6,
        "unknown/foreign/duplicate session headers cannot invoke another tool"
    );

    let response = mcp_request(
        &server,
        "POST",
        Some("mcp-owner"),
        &[("Content-Type", "application/json")],
        &json_body(&initialize),
    )
    .await;
    let session = response
        .headers
        .get("mcp-session-id")
        .expect("drain test session")
        .clone();
    assert_eq!(
        mcp_request(
            &server,
            "POST",
            Some("mcp-owner"),
            &[
                ("Content-Type", "application/json"),
                ("Mcp-Session-Id", &session)
            ],
            &json_body(&json!({"jsonrpc":"2.0","method":"notifications/initialized"}))
        )
        .await
        .status,
        202
    );
    let draining_call = start_scoped(session.clone());
    let draining_token = timeout(Duration::from_secs(2), observed.recv())
        .await
        .expect("draining call started")
        .expect("draining token");
    let draining_legacy = start_call("mcp-owner");
    let legacy_token = timeout(Duration::from_secs(2), observed.recv())
        .await
        .expect("draining legacy started")
        .expect("legacy drain token");
    let mut draining_events = open_session_events(address, &session).await;
    tools.wait_catalog.store(true, Ordering::SeqCst);
    let start_catalog = |request_id: u64| {
        let session = session.clone();
        tokio::spawn(async move {
            request_at(
                address,
                "POST",
                "/mcp",
                Some("mcp-owner"),
                &[
                    ("Content-Type", "application/json"),
                    ("Mcp-Session-Id", &session),
                ],
                &json_body(&json!({"jsonrpc":"2.0","id":request_id,"method":"tools/list"})),
            )
            .await
        })
    };
    let cancelled_catalog = start_catalog(9);
    timeout(Duration::from_secs(2), catalogs.recv())
        .await
        .expect("catalog started")
        .expect("catalog marker");
    assert_eq!(mcp_request(&server, "POST", Some("mcp-owner"), &[("Content-Type", "application/json"), ("Mcp-Session-Id", &session)], &json_body(&json!({"jsonrpc":"2.0","method":"notifications/cancelled","params":{"requestId":9}}))).await.status, 202);
    assert_eq!(
        timeout(Duration::from_secs(2), cancelled_catalog)
            .await
            .expect("catalog cancelled promptly")
            .expect("catalog task")
            .json()["error"]["code"],
        -32800
    );
    assert!(!draining_token.is_cancelled());
    let draining_catalog = start_catalog(10);
    timeout(Duration::from_secs(2), catalogs.recv())
        .await
        .expect("drain catalog started")
        .expect("drain catalog marker");
    let mut pending_body = TcpStream::connect(address).await.expect("pending MCP body");
    let pending_payload = json_body(&invocation);
    let pending_head = format!(
        "POST /mcp HTTP/1.1\r\nHost: {address}\r\nAuthorization: Bearer mcp-owner\r\nContent-Type: application/json\r\nContent-Length: {}\r\nMcp-Session-Id: {session}\r\nConnection: close\r\n\r\n",
        pending_payload.len()
    );
    pending_body
        .write_all(pending_head.as_bytes())
        .await
        .expect("pending headers");
    pending_body
        .write_all(&pending_payload[..1])
        .await
        .expect("partial body");
    server.api.mcp_shutdown_token().cancel();
    assert!(draining_token.is_cancelled());
    assert!(legacy_token.is_cancelled());
    assert_eq!(
        timeout(Duration::from_secs(2), draining_catalog)
            .await
            .expect("catalog drained promptly")
            .expect("drained catalog task")
            .json()["error"]["code"],
        -32800
    );
    for pending in [draining_call, draining_legacy] {
        let response = timeout(Duration::from_secs(2), pending)
            .await
            .expect("MCP call drained")
            .expect("drained task");
        assert_eq!(
            response.json()["result"]["_meta"]["gta-claw"]["error"]["retryable"],
            false
        );
    }
    let mut drained_bytes = Vec::new();
    timeout(
        Duration::from_secs(2),
        draining_events.read_to_end(&mut drained_bytes),
    )
    .await
    .expect("root drain ends SSE")
    .expect("drained SSE EOF");
    pending_body
        .write_all(&pending_payload[1..])
        .await
        .expect("complete raced body");
    let mut refused_bytes = Vec::new();
    timeout(
        Duration::from_secs(2),
        pending_body.read_to_end(&mut refused_bytes),
    )
    .await
    .expect("raced request refused")
    .expect("raced EOF");
    assert!(String::from_utf8_lossy(&refused_bytes).starts_with("HTTP/1.1 503"));
    assert_eq!(
        mcp_request(
            &server,
            "POST",
            Some("mcp-owner"),
            &[("Content-Type", "application/json")],
            &json_body(&initialize)
        )
        .await
        .status,
        503
    );
    assert_eq!(
        mcp_request(
            &server,
            "POST",
            Some("mcp-owner"),
            &[
                ("Content-Type", "application/json"),
                ("Mcp-Session-Id", &session)
            ],
            &json_body(&invocation)
        )
        .await
        .status,
        503
    );
    assert_eq!(tools.calls.load(Ordering::SeqCst), 8);
    assert_eq!(
        request(&server, "GET", "/health", None, &[], b"")
            .await
            .status,
        200,
        "MCP shutdown does not mutate unrelated HTTP serving state"
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
        &json_body(&json!({"model":"openclaw","input":["valid",7]})),
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
        &json_body(&json!({
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
        &json_body(&json!({"model":"openclaw","input":"hello"})),
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
    let body = json_body(&json!({
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
        &json_body(&json!({"id":"invoke-1","ok":true,"payload":{"done":true}})),
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
async fn known_partial_outputs_preserve_text_usage_and_terminal_on_all_http_surfaces() {
    let runtime = DeterministicRuntime::new();
    let server = spawn_with(config(), runtime.clone()).await;
    for (finish_reason, chat_reason, response_reason) in [
        (
            claw_http_api::GenerationFinishReason::Length,
            "length",
            "max_output_tokens",
        ),
        (
            claw_http_api::GenerationFinishReason::ContentFilter,
            "content_filter",
            "content_filter",
        ),
    ] {
        for text in ["partial {", ""] {
            runtime
                .set_output(GenerationOutput {
                    usage_reporting: claw_http_api::UsageReporting::Complete,
                    text: text.to_owned(),
                    tool_calls: Vec::new(),
                    finish_reason,
                    usage: Usage {
                        input_tokens: 4,
                        output_tokens: 3,
                        total_tokens: 7,
                    },
                })
                .expect("owned partial output");
            for path in ["/v1/chat/completions", "/v1/responses"] {
                for stream in [false, true] {
                    let body = if path == "/v1/responses" {
                        json!({"model":"openclaw","input":"owned request","stream":stream,"tools":[{"type":"function","name":"lookup","parameters":{"type":"object"}}],"tool_choice":"required"})
                    } else {
                        json!({"model":"openclaw","messages":[{"role":"user","content":"owned request"}],"stream":stream,"stream_options":{"include_usage":true},"response_format":{"type":"json_object"},"tools":[{"type":"function","function":{"name":"lookup","parameters":{"type":"object"}}}],"tool_choice":"required"})
                    };
                    let response = request(
                        &server,
                        "POST",
                        path,
                        Some("operator-token"),
                        &[("Content-Type", "application/json")],
                        &json_body(&body),
                    )
                    .await;
                    assert_eq!(response.status, 200, "{}", response.text());
                    if stream {
                        let encoded = response.text();
                        let events: Vec<Value> = encoded
                            .split("\n\n")
                            .filter_map(|block| {
                                block.lines().find_map(|line| line.strip_prefix("data: "))
                            })
                            .filter(|data| *data != "[DONE]")
                            .map(|data| serde_json::from_str(data).expect("owned JSON SSE event"))
                            .collect();
                        assert!(events.iter().all(|event| event.get("error").is_none()));
                        if path == "/v1/responses" {
                            assert!(!encoded.contains("event: response.completed"));
                            let terminals: Vec<_> = events
                                .iter()
                                .filter(|event| event["type"] == "response.incomplete")
                                .collect();
                            assert_eq!(terminals.len(), 1);
                            let terminal = &terminals[0]["response"];
                            assert_eq!(terminal["status"], "incomplete");
                            assert_eq!(terminal["incomplete_details"]["reason"], response_reason);
                            assert_eq!(terminal["usage"]["total_tokens"], 7);
                            assert_eq!(terminal["output"][0]["content"][0]["text"], text);
                            assert_eq!(terminal["output"][0]["status"], "incomplete");
                        } else {
                            let terminals: Vec<_> = events
                                .iter()
                                .filter_map(|event| event["choices"][0]["finish_reason"].as_str())
                                .collect();
                            assert_eq!(terminals, [chat_reason]);
                            let deltas: String = events
                                .iter()
                                .filter_map(|event| {
                                    event["choices"][0]["delta"]["content"].as_str()
                                })
                                .collect();
                            assert_eq!(deltas, text);
                            assert_eq!(
                                events.last().expect("usage event")["usage"]["total_tokens"],
                                7
                            );
                        }
                        assert!(!encoded.contains("No response from OpenClaw."));
                    } else {
                        let output = response.json();
                        assert_eq!(output["usage"]["total_tokens"], 7);
                        if path == "/v1/responses" {
                            assert_eq!(output["status"], "incomplete");
                            assert_eq!(output["incomplete_details"]["reason"], response_reason);
                            assert_eq!(output["output"][0]["content"][0]["text"], text);
                            assert_eq!(output["output"][0]["status"], "incomplete");
                        } else {
                            assert_eq!(output["choices"][0]["finish_reason"], chat_reason);
                            assert_eq!(output["choices"][0]["message"]["content"], text);
                        }
                    }
                }
            }
        }
    }
    runtime
        .set_output(GenerationOutput {
            text: String::new(),
            finish_reason: claw_http_api::GenerationFinishReason::Length,
            usage_reporting: claw_http_api::UsageReporting::Complete,
            tool_calls: vec![ToolCall {
                id: "private-partial-call".to_owned(),
                name: "lookup".to_owned(),
                arguments: "{\"private\":true}".to_owned(),
            }],
            usage: Usage {
                input_tokens: 4,
                output_tokens: 3,
                total_tokens: 7,
            },
        })
        .expect("malformed partial fixture");
    for path in ["/v1/chat/completions", "/v1/responses"] {
        for stream in [false, true] {
            let body = if path == "/v1/responses" {
                json!({"model":"openclaw","input":"owned request","stream":stream,"tools":[{"type":"function","name":"lookup","parameters":{"type":"object"}}]})
            } else {
                json!({"model":"openclaw","messages":[{"role":"user","content":"owned request"}],"stream":stream,"tools":[{"type":"function","function":{"name":"lookup","parameters":{"type":"object"}}}]})
            };
            let response = request(
                &server,
                "POST",
                path,
                Some("operator-token"),
                &[("Content-Type", "application/json")],
                &json_body(&body),
            )
            .await;
            assert_eq!(response.status, if stream { 200 } else { 502 });
            assert!(!response.text().contains("private-partial-call"));
            assert!(!response.text().contains("\\\"private\\\""));
            assert!(response.text().contains("partial provider result"));
        }
    }
}

#[tokio::test]
async fn required_tool_choice_returns_structured_calls_on_both_openai_surfaces() {
    let runtime = DeterministicRuntime::new();
    runtime
        .set_output(GenerationOutput {
            text: "calling".to_owned(),
            usage_reporting: claw_http_api::UsageReporting::Complete,
            finish_reason: claw_http_api::GenerationFinishReason::ToolCalls,
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
        &json_body(&json!({
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
        &json_body(&json!({
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
        &json_body(&json!({
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
        &json_body(&json!({
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
        &json_body(&json!({"model":"openclaw","input":"hello","stream":true})),
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
        &json_body(&json!({"model":"openclaw","input":"hello"})),
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
        &json_body(&json!({
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
        &json_body(&json!({
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
            usage_reporting: claw_http_api::UsageReporting::Complete,
            finish_reason: claw_http_api::GenerationFinishReason::Stop,
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
        &json_body(&json!({
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
        &json_body(&json!({
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
            finish_reason: claw_http_api::GenerationFinishReason::ToolCalls,
            usage_reporting: claw_http_api::UsageReporting::Complete,
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
        &json_body(&json!({
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
            finish_reason: claw_http_api::GenerationFinishReason::ToolCalls,
            usage_reporting: claw_http_api::UsageReporting::Complete,
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
            &json_body(&json!({
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
            usage_reporting: claw_http_api::UsageReporting::Complete,
            finish_reason: claw_http_api::GenerationFinishReason::ToolCalls,
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
        &json_body(&json!({
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
            &json_body(&unsupported),
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
        &json_body(&json!({
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
        &json_body(&json!({
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
        &json_body(&json!({
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
        &json_body(&json!({"model":"openclaw","input":"first"})),
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
        &json_body(&json!({
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
        &json_body(&json!({
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
        &json_body(&json!({
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
            usage_reporting: claw_http_api::UsageReporting::Complete,
            finish_reason: claw_http_api::GenerationFinishReason::Stop,
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
        &json_body(&json!({
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
        &json_body(&json!({
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
        &json_body(&json!({
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
        &json_body(&json!({
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

#[tokio::test]
async fn draining_rejects_new_main_api_work_before_dispatch() {
    let runtime = DeterministicRuntime::new();
    let serving = ServingStateHandle::serving();
    let server = spawn_with_serving(config(), runtime.clone(), serving.clone()).await;

    serving.begin_draining();

    let chat = request(
        &server,
        "POST",
        "/v1/chat/completions",
        Some("operator-token"),
        &[("Content-Type", "application/json")],
        &json_body(&json!({
            "model":"openclaw",
            "messages":[{"role":"user","content":"must not dispatch"}]
        })),
    )
    .await;
    assert_eq!(chat.status, 503);
    assert_eq!(
        chat.json(),
        json!({"error":{"message":"Service draining","type":"api_error"}})
    );
    assert_eq!(
        chat.headers.get("retry-after").map(String::as_str),
        Some("1")
    );
    assert!(
        runtime
            .last_generation_request()
            .expect("provider request lock")
            .is_none(),
        "draining traffic reached the provider"
    );

    let admin = request(
        &server,
        "POST",
        "/api/v1/admin/rpc",
        Some("operator-token"),
        &[("Content-Type", "application/json")],
        &json_body(&json!({"id":"drain","method":"status"})),
    )
    .await;
    assert_eq!(admin.status, 503);
    assert_eq!(
        admin.json(),
        json!({"ok":false,"error":{"type":"unavailable","message":"service is draining"}})
    );

    let webhook = request(
        &server,
        "POST",
        "/plugins/webhooks/zapier",
        None,
        &[("Content-Type", "application/json")],
        &json_body(&json!({"action":"list_flows"})),
    )
    .await;
    assert_eq!(webhook.status, 503);
    assert_eq!(
        webhook.json(),
        json!({"ok":false,"code":"unavailable","error":"service is draining"})
    );

    let liveness = request(&server, "GET", "/health", None, &[], b"").await;
    assert_eq!(liveness.status, 200);
    assert_eq!(liveness.json()["phase"], "draining");
}

#[tokio::test]
async fn watch_session_capacity_evicts_the_oldest_live_node() {
    let runtime = DeterministicRuntime::new();
    let mut watch_config = config();
    watch_config.limits.watch_sessions = 1;
    watch_config.limits.watch_poll_timeout = Duration::from_millis(25);
    let server = spawn_with(watch_config, runtime).await;

    let first = connect_watch(&server, "bounded-watch-1").await;
    let second = connect_watch(&server, "bounded-watch-2").await;

    let evicted = request(
        &server,
        "POST",
        "/api/nodes/watch/poll",
        Some(&first),
        &[],
        b"",
    )
    .await;
    assert_eq!(evicted.status, 401);
    assert!(
        !server
            .api
            .watch_handle()
            .send("bounded-watch-1", "node.invoke.request", None)
            .expect("old-node enqueue")
    );
    assert!(
        server
            .api
            .watch_handle()
            .send(
                "bounded-watch-2",
                "node.invoke.request",
                Some(json!({"id":"bounded"}))
            )
            .expect("new-node enqueue")
    );
    let current = request(
        &server,
        "POST",
        "/api/nodes/watch/poll",
        Some(&second),
        &[],
        b"",
    )
    .await;
    assert_eq!(current.status, 200);
    assert_eq!(
        current.json()["event"],
        json!({"event":"node.invoke.request","payload":{"id":"bounded"}})
    );

    let runtime = DeterministicRuntime::new();
    let mut reconnect_config = config();
    reconnect_config.limits.watch_sessions = 2;
    let reconnect_server = spawn_with(reconnect_config, runtime).await;
    let first_node = connect_watch(&reconnect_server, "reconnect-watch-1").await;
    let old_second = connect_watch(&reconnect_server, "reconnect-watch-2").await;
    let _new_second = connect_watch(&reconnect_server, "reconnect-watch-2").await;
    assert!(
        reconnect_server
            .api
            .watch_handle()
            .send(
                "reconnect-watch-1",
                "node.invoke.request",
                Some(json!({"id":"still-live"}))
            )
            .expect("unrelated node enqueue"),
        "reconnecting one node must not evict an unrelated session"
    );
    let unrelated = request(
        &reconnect_server,
        "POST",
        "/api/nodes/watch/poll",
        Some(&first_node),
        &[],
        b"",
    )
    .await;
    assert_eq!(unrelated.status, 200);
    assert_eq!(unrelated.json()["event"]["payload"]["id"], "still-live");
    let replaced = request(
        &reconnect_server,
        "POST",
        "/api/nodes/watch/poll",
        Some(&old_second),
        &[],
        b"",
    )
    .await;
    assert_eq!(replaced.status, 401);
}

async fn connect_watch(server: &Server, device_id: &str) -> String {
    let challenge = request(server, "GET", "/api/nodes/watch/challenge", None, &[], b"").await;
    let nonce = challenge.json()["nonce"]
        .as_str()
        .expect("watch challenge nonce")
        .to_owned();
    let connect = request(
        server,
        "POST",
        "/api/nodes/watch/connect",
        None,
        &[("Content-Type", "application/json")],
        &watch_connect_body(&nonce, device_id),
    )
    .await;
    assert_eq!(connect.status, 200, "{}", connect.text());
    connect.json()["sessionToken"]
        .as_str()
        .expect("watch session token")
        .to_owned()
}

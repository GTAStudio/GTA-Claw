//! Streamable HTTP interoperability tests.

use std::{
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
    time::Duration,
};

use axum::{
    Json, Router,
    extract::State,
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Response},
    routing::post,
};
use claw_mcp::client::{DiscardEvents, HttpClientConfig, McpClient, RejectSampling};
use secrecy::SecretString;
use serde_json::{Value, json};
use tokio_util::sync::CancellationToken;
use url::Url;

async fn fixture_handler(
    State(authenticated_requests): State<Arc<AtomicUsize>>,
    headers: HeaderMap,
    Json(request): Json<Value>,
) -> Response {
    if headers
        .get("authorization")
        .and_then(|value| value.to_str().ok())
        != Some("Bearer fixture-http-token")
    {
        return StatusCode::UNAUTHORIZED.into_response();
    }
    authenticated_requests.fetch_add(1, Ordering::SeqCst);
    let method = request
        .get("method")
        .and_then(Value::as_str)
        .expect("fixture request must have a method");
    let Some(id) = request.get("id").cloned() else {
        assert_eq!(method, "notifications/initialized");
        return StatusCode::ACCEPTED.into_response();
    };
    let result = match method {
        "initialize" => json!({
            "protocolVersion": "2025-06-18",
            "capabilities": {"tools": {}},
            "serverInfo": {
                "name": "gta-claw-http-fixture",
                "version": "0.1.0"
            }
        }),
        "tools/list" => json!({
            "tools": [{
                "name": "http-fixture",
                "description": "Confirms streamable HTTP",
                "inputSchema": {"type": "object"}
            }]
        }),
        other => panic!("unexpected fixture method: {other}"),
    };
    Json(json!({"jsonrpc": "2.0", "id": id, "result": result})).into_response()
}

#[tokio::test]
async fn streamable_http_discovers_capabilities_and_authenticates_requests() {
    let cancellation = CancellationToken::new();
    let authenticated_requests = Arc::new(AtomicUsize::new(0));
    let router = Router::new()
        .route("/mcp", post(fixture_handler))
        .with_state(authenticated_requests.clone());
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("local fixture listener must bind");
    let endpoint = Url::parse(&format!(
        "http://{}/mcp",
        listener
            .local_addr()
            .expect("local fixture address must resolve")
    ))
    .expect("fixture URL must parse");
    let server_cancellation = cancellation.clone();
    let server = tokio::spawn(async move {
        axum::serve(listener, router)
            .with_graceful_shutdown(server_cancellation.cancelled_owned())
            .await
            .expect("fixture server must run");
    });

    let mut client_config = HttpClientConfig::new(endpoint);
    client_config.bearer_token = Some(SecretString::new("fixture-http-token".into()));
    client_config.connect_timeout = Duration::from_secs(5);
    client_config.request_timeout = Duration::from_secs(5);
    let client = McpClient::connect_http(
        client_config,
        Arc::new(RejectSampling),
        Arc::new(DiscardEvents),
    )
    .await
    .expect("streamable HTTP must initialize");

    assert_eq!(
        client
            .server_info()
            .expect("server info must be retained")
            .server_info
            .name,
        "gta-claw-http-fixture"
    );
    let tools = client.list_tools().await.expect("tools/list must succeed");
    assert_eq!(tools.tools.len(), 1);
    assert_eq!(tools.tools[0].name, "http-fixture");
    client.close().await.expect("HTTP client must close");

    cancellation.cancel();
    server.await.expect("fixture task must join");
    assert_eq!(authenticated_requests.load(Ordering::SeqCst), 3);
}

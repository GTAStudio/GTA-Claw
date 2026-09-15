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
use claw_mcp::client::{
    ClientEventSink, DiscardEvents, HttpClientConfig, McpClient, McpClientEvent, RejectSampling,
};
use claw_mcp::model::CallToolRequestParams;
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
    let route = claw_mcp::HttpRoutePolicy::direct_loopback(client_config.endpoint.clone())
        .expect("explicit fixture route");
    let client = McpClient::connect_http_with_route(
        client_config,
        route,
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

#[tokio::test]
async fn expired_http_session_never_reinitializes_or_replays_an_inflight_tool() {
    #[derive(Default)]
    struct Effects {
        initializations: AtomicUsize,
        calls: AtomicUsize,
    }
    async fn handler(State(effects): State<Arc<Effects>>, Json(request): Json<Value>) -> Response {
        let Some(id) = request.get("id") else {
            return StatusCode::ACCEPTED.into_response();
        };
        match request["method"].as_str().expect("method") {
            "initialize" => {
                effects.initializations.fetch_add(1, Ordering::SeqCst);
                let mut response = Json(json!({"jsonrpc":"2.0","id":id,"result":{"protocolVersion":"2025-06-18","capabilities":{"tools":{}},"serverInfo":{"name":"expiry-fixture","version":"1"}}})).into_response();
                response.headers_mut().insert(
                    "mcp-session-id",
                    axum::http::HeaderValue::from_static("fixture-session"),
                );
                response
            }
            "tools/call" => {
                effects.calls.fetch_add(1, Ordering::SeqCst);
                StatusCode::NOT_FOUND.into_response()
            }
            other => panic!("unexpected fixture method {other}"),
        }
    }
    let effects = Arc::new(Effects::default());
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("owned listener");
    let endpoint = Url::parse(&format!(
        "http://{}/mcp",
        listener.local_addr().expect("address")
    ))
    .expect("endpoint");
    let router = Router::new()
        .route("/mcp", post(handler).delete(|| async { StatusCode::OK }))
        .with_state(Arc::clone(&effects));
    let stop = CancellationToken::new();
    let _cancel_on_drop = stop.clone().drop_guard();
    let server_stop = stop.clone();
    let server = tokio::spawn(async move {
        axum::serve(listener, router)
            .with_graceful_shutdown(server_stop.cancelled_owned())
            .await
            .expect("fixture serving");
    });
    let mut settings = HttpClientConfig::new(endpoint);
    settings.connect_timeout = Duration::from_secs(2);
    settings.request_timeout = Duration::from_secs(2);
    let client =
        McpClient::connect_http(settings, Arc::new(RejectSampling), Arc::new(DiscardEvents))
            .await
            .expect("initialize once");
    assert!(
        client
            .call_tool(CallToolRequestParams::new("effect"))
            .await
            .is_err()
    );
    client.close().await.expect("client drained");
    stop.cancel();
    server.await.expect("fixture joined");
    assert_eq!(
        effects.initializations.load(Ordering::SeqCst),
        1,
        "session expiry must not replay the handshake"
    );
    assert_eq!(
        effects.calls.load(Ordering::SeqCst),
        1,
        "a 404 response is not permission to repeat remote effects"
    );
}

#[tokio::test]
async fn resource_subscriptions_filter_notifications_and_never_replay_uncertain_transitions() {
    use claw_mcp::model::{
        ResourceUpdatedNotificationParam, SubscribeRequestParams, UnsubscribeRequestParams,
    };

    const URI: &str = "gta://subscription/owned";
    struct Events(tokio::sync::mpsc::UnboundedSender<McpClientEvent>);
    impl ClientEventSink for Events {
        fn emit(&self, event: McpClientEvent) {
            let _ = self.0.send(event);
        }
    }
    struct Fixture {
        mode: &'static str,
        subscriptions: AtomicUsize,
        unsubscriptions: AtomicUsize,
        started: tokio::sync::Notify,
        release: CancellationToken,
    }
    fn updates(result: Value, barrier: bool) -> Response {
        let mut messages = vec![
            json!({"jsonrpc":"2.0","method":"notifications/resources/updated","params":{"uri":URI,"_meta":{"private":"remote-event-marker"}}}),
            json!({"jsonrpc":"2.0","method":"notifications/resources/updated","params":{"uri":URI}}),
            json!({"jsonrpc":"2.0","method":"notifications/resources/updated","params":{"uri":"gta://subscription/unapproved"}}),
        ];
        if barrier {
            messages.push(json!({"jsonrpc":"2.0","method":"notifications/resources/list_changed"}));
        }
        messages.push(result);
        axum::response::Sse::new(futures_util::stream::iter(messages.into_iter().map(
            |message| {
                Ok::<_, std::convert::Infallible>(
                    axum::response::sse::Event::default().data(message.to_string()),
                )
            },
        )))
        .into_response()
    }
    async fn handler(State(fixture): State<Arc<Fixture>>, Json(request): Json<Value>) -> Response {
        let Some(id) = request.get("id") else {
            return StatusCode::ACCEPTED.into_response();
        };
        match request["method"].as_str().expect("method") {
            "initialize" => Json(json!({"jsonrpc":"2.0","id":id,"result":{"protocolVersion":"2025-03-26",
                "serverInfo":{"name":"subscription-fixture","version":"1"},"capabilities":{"tools":{},"resources":{"subscribe":fixture.mode != "unsupported"}}}})).into_response(),
            "resources/subscribe" | "resources/unsubscribe" => {
                let subscribing = request["method"] == "resources/subscribe";
                assert_eq!(request["params"]["uri"], URI);
                if subscribing { fixture.subscriptions.fetch_add(1, Ordering::SeqCst); }
                else { fixture.unsubscriptions.fetch_add(1, Ordering::SeqCst); }
                if (subscribing && fixture.mode == "cancel-subscribe") || (!subscribing && fixture.mode == "cancel-unsubscribe") {
                    fixture.started.notify_one();
                    fixture.release.cancelled().await;
                }
                let result = if (subscribing && fixture.mode == "failed-subscribe") || (!subscribing && fixture.mode == "failed-unsubscribe") {
                    json!({"jsonrpc":"2.0","id":id,"error":{"code":-32603,"message":"subscription refused"}})
                } else { json!({"jsonrpc":"2.0","id":id,"result":{}}) };
                updates(result, false)
            }
            "tools/call" => updates(json!({"jsonrpc":"2.0","id":id,"result":{"content":[],"isError":false}}), true),
            other => panic!("unexpected subscription fixture method {other}"),
        }
    }
    async fn probe(
        client: &McpClient,
        events: &mut tokio::sync::mpsc::UnboundedReceiver<McpClientEvent>,
    ) -> Vec<McpClientEvent> {
        client
            .call_tool(CallToolRequestParams::new("emit-resource-updates"))
            .await
            .expect("fixture update probe");
        tokio::time::timeout(Duration::from_secs(2), async {
            let mut updates = Vec::new();
            loop {
                let event = events.recv().await.expect("recorded event");
                if event == McpClientEvent::ResourcesChanged {
                    return updates;
                }
                updates.push(event);
            }
        })
        .await
        .expect("notification barrier")
    }

    for mode in [
        "success",
        "failed-subscribe",
        "cancel-subscribe",
        "failed-unsubscribe",
        "cancel-unsubscribe",
        "unsupported",
    ] {
        let fixture = Arc::new(Fixture {
            mode,
            subscriptions: AtomicUsize::new(0),
            unsubscriptions: AtomicUsize::new(0),
            started: tokio::sync::Notify::new(),
            release: CancellationToken::new(),
        });
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("owned subscription server");
        let endpoint = Url::parse(&format!(
            "http://{}/mcp",
            listener.local_addr().expect("address")
        ))
        .expect("endpoint");
        let router = Router::new()
            .route("/mcp", post(handler))
            .with_state(Arc::clone(&fixture));
        let stop = CancellationToken::new();
        let _cancel_on_drop = stop.clone().drop_guard();
        let _release_on_drop = fixture.release.clone().drop_guard();
        let server_stop = stop.clone();
        let server = tokio::spawn(async move {
            axum::serve(listener, router)
                .with_graceful_shutdown(server_stop.cancelled_owned())
                .await
                .expect("fixture serving");
        });
        let config = HttpClientConfig::new(endpoint.clone());
        let (sender, mut events) = tokio::sync::mpsc::unbounded_channel();
        let client = McpClient::connect_http_with_route(
            config,
            claw_mcp::HttpRoutePolicy::direct_loopback(endpoint).expect("route"),
            Arc::new(RejectSampling),
            Arc::new(Events(sender)),
        )
        .await
        .expect("subscription client");
        assert!(
            probe(&client, &mut events).await.is_empty(),
            "unsolicited updates are not accepted"
        );
        if mode == "cancel-subscribe" {
            let pending = client.subscribe(SubscribeRequestParams::new(URI));
            tokio::pin!(pending);
            tokio::select! {
                result = &mut pending => panic!("subscription finished before release: {result:?}"),
                () = fixture.started.notified() => {}
            }
        } else {
            let result = client.subscribe(SubscribeRequestParams::new(URI)).await;
            assert_eq!(
                result.is_ok(),
                !matches!(mode, "failed-subscribe" | "unsupported")
            );
        }
        if matches!(
            mode,
            "success" | "failed-unsubscribe" | "cancel-unsubscribe"
        ) {
            let coalesced = tokio::time::timeout(Duration::from_secs(2), events.recv())
                .await
                .expect("coalesced update")
                .expect("event");
            assert_eq!(
                coalesced,
                McpClientEvent::ResourceUpdated(ResourceUpdatedNotificationParam::new(URI))
            );
            assert!(
                client
                    .subscribe(SubscribeRequestParams::new(URI))
                    .await
                    .is_err(),
                "duplicate active subscription does not send"
            );
            assert_eq!(
                probe(&client, &mut events).await,
                vec![
                    McpClientEvent::ResourceUpdated(ResourceUpdatedNotificationParam::new(URI));
                    2
                ]
            );
            if mode == "cancel-unsubscribe" {
                let pending = client.unsubscribe(UnsubscribeRequestParams::new(URI));
                tokio::pin!(pending);
                tokio::select! {
                    result = &mut pending => panic!("unsubscribe finished before release: {result:?}"),
                    () = fixture.started.notified() => {}
                }
            } else {
                assert_eq!(
                    client
                        .unsubscribe(UnsubscribeRequestParams::new(URI))
                        .await
                        .is_ok(),
                    mode == "success"
                );
            }
        }
        fixture.release.cancel();
        assert!(
            probe(&client, &mut events).await.is_empty(),
            "late or unconfirmed updates are not forwarded"
        );
        if mode != "success" {
            assert!(
                client
                    .subscribe(SubscribeRequestParams::new(URI))
                    .await
                    .is_err()
            );
        }
        assert!(
            client
                .unsubscribe(UnsubscribeRequestParams::new(URI))
                .await
                .is_err()
        );
        assert_eq!(
            fixture.subscriptions.load(Ordering::SeqCst),
            usize::from(mode != "unsupported")
        );
        assert_eq!(
            fixture.unsubscriptions.load(Ordering::SeqCst),
            usize::from(matches!(
                mode,
                "success" | "failed-unsubscribe" | "cancel-unsubscribe"
            ))
        );
        client.close().await.expect("client closed");
        stop.cancel();
        server.await.expect("owned fixture joined");
    }
}

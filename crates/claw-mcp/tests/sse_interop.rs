//! Legacy SSE interoperability and reconnection tests.

use std::{
    convert::Infallible,
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, AtomicUsize, Ordering},
    },
    time::Duration,
};

use axum::{
    Json, Router,
    extract::State,
    http::{HeaderMap, StatusCode},
    response::sse::{Event, Sse},
    routing::{get, post},
};
use claw_mcp::{
    client::{DiscardEvents, McpClient, RejectSampling},
    sse::LegacySseConfig,
};
use futures_util::{Stream, StreamExt, stream};
use reqwest::header::{AUTHORIZATION, HeaderValue};
use serde_json::{Value, json};
use tokio::sync::mpsc;
use tokio_util::sync::CancellationToken;
use url::Url;

type EventSender = mpsc::Sender<Result<Event, Infallible>>;

#[derive(Clone)]
struct SseFixtureState {
    current: Arc<Mutex<Option<EventSender>>>,
    get_count: Arc<AtomicUsize>,
    authenticated_requests: Arc<AtomicUsize>,
    resumed_with_event_id: Arc<AtomicBool>,
}

impl SseFixtureState {
    fn authenticate(&self, headers: &HeaderMap) -> Result<(), StatusCode> {
        if headers
            .get(AUTHORIZATION)
            .and_then(|value| value.to_str().ok())
            != Some("Bearer fixture-sse-token")
        {
            return Err(StatusCode::UNAUTHORIZED);
        }
        self.authenticated_requests.fetch_add(1, Ordering::SeqCst);
        Ok(())
    }
}

async fn sse(
    State(state): State<SseFixtureState>,
    headers: HeaderMap,
) -> Result<Sse<impl Stream<Item = Result<Event, Infallible>>>, StatusCode> {
    state.authenticate(&headers)?;
    let connection = state.get_count.fetch_add(1, Ordering::SeqCst);
    if connection > 0
        && headers
            .get("last-event-id")
            .and_then(|value| value.to_str().ok())
            == Some("initialize-response")
    {
        state.resumed_with_event_id.store(true, Ordering::SeqCst);
    }
    let (sender, receiver) = mpsc::channel(8);
    *state
        .current
        .lock()
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)? = Some(sender);
    let endpoint = stream::once(async { Ok(Event::default().event("endpoint").data("/messages")) });
    let messages = stream::unfold(receiver, |mut receiver| async move {
        receiver.recv().await.map(|event| (event, receiver))
    });
    Ok(Sse::new(endpoint.chain(messages)))
}

async fn messages(
    State(state): State<SseFixtureState>,
    headers: HeaderMap,
    Json(request): Json<Value>,
) -> Result<StatusCode, StatusCode> {
    state.authenticate(&headers)?;
    let Some(method) = request.get("method").and_then(Value::as_str) else {
        return Err(StatusCode::BAD_REQUEST);
    };
    let response = match method {
        "initialize" => {
            let protocol_version = request
                .pointer("/params/protocolVersion")
                .cloned()
                .ok_or(StatusCode::BAD_REQUEST)?;
            Some((
                "initialize-response",
                json!({
                    "jsonrpc": "2.0",
                    "id": request["id"],
                    "result": {
                        "protocolVersion": protocol_version,
                        "capabilities": {"tools": {}},
                        "serverInfo": {
                            "name": "gta-claw-sse-fixture",
                            "version": "1.0.0"
                        }
                    }
                }),
                true,
            ))
        }
        "tools/list" => Some((
            "tools-response",
            json!({
                "jsonrpc": "2.0",
                "id": request["id"],
                "result": {
                    "tools": [{
                        "name": "sse-fixture",
                        "description": "Confirms legacy SSE",
                        "inputSchema": {"type": "object"}
                    }]
                }
            }),
            false,
        )),
        "notifications/initialized" => None,
        _ => return Err(StatusCode::NOT_IMPLEMENTED),
    };

    if let Some((event_id, response, disconnect)) = response {
        let sender = state
            .current
            .lock()
            .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?
            .clone()
            .ok_or(StatusCode::SERVICE_UNAVAILABLE)?;
        sender
            .send(Ok(Event::default()
                .event("message")
                .id(event_id)
                .data(response.to_string())))
            .await
            .map_err(|_| StatusCode::SERVICE_UNAVAILABLE)?;
        if disconnect {
            state
                .current
                .lock()
                .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?
                .take();
        }
    }
    Ok(StatusCode::ACCEPTED)
}

#[tokio::test]
async fn legacy_sse_reconnects_with_event_id_and_authenticates_get_and_post() {
    let state = SseFixtureState {
        current: Arc::new(Mutex::new(None)),
        get_count: Arc::new(AtomicUsize::new(0)),
        authenticated_requests: Arc::new(AtomicUsize::new(0)),
        resumed_with_event_id: Arc::new(AtomicBool::new(false)),
    };
    let router = Router::new()
        .route("/sse", get(sse))
        .route("/messages", post(messages))
        .with_state(state.clone());
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("local fixture listener must bind");
    let endpoint = Url::parse(&format!(
        "http://{}/sse",
        listener
            .local_addr()
            .expect("local fixture address must resolve")
    ))
    .expect("fixture URL must parse");
    let cancellation = CancellationToken::new();
    let server_cancellation = cancellation.clone();
    let server = tokio::spawn(async move {
        axum::serve(listener, router)
            .with_graceful_shutdown(server_cancellation.cancelled_owned())
            .await
            .expect("fixture server must run");
    });

    let mut config = LegacySseConfig::new(endpoint);
    let mut authorization = HeaderValue::from_static("Bearer fixture-sse-token");
    authorization.set_sensitive(true);
    config.headers.insert(AUTHORIZATION, authorization);
    config.request_timeout = Duration::from_secs(5);
    config.max_reconnects = 2;
    config.reconnect_delay = Duration::from_millis(10);
    let client = McpClient::connect_sse(config, Arc::new(RejectSampling), Arc::new(DiscardEvents))
        .await
        .expect("legacy SSE must initialize");

    tokio::time::timeout(Duration::from_secs(2), async {
        while state.get_count.load(Ordering::SeqCst) < 2 {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .expect("legacy SSE must reconnect after established stream closes");
    assert!(state.resumed_with_event_id.load(Ordering::SeqCst));

    let tools = client.list_tools().await.expect("tools/list must succeed");
    assert_eq!(tools.tools.len(), 1);
    assert_eq!(tools.tools[0].name, "sse-fixture");
    client.close().await.expect("SSE client must close");

    cancellation.cancel();
    server.await.expect("fixture task must join");
    assert!(state.authenticated_requests.load(Ordering::SeqCst) >= 5);
}

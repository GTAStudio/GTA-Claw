//! HTTP behaviour of the five watch-node transport endpoints.

use std::sync::Arc;
use std::time::Duration;

use axum::Router;
use axum::body::Body;
use axum::http::{Request, StatusCode};
use claw_gateway_http::{
    EnqueueOutcome, InMemoryResultSink, WATCH_CHALLENGE_PATH, WATCH_CONNECT_PATH,
    WATCH_DISCONNECT_PATH, WATCH_POLL_PATH, WATCH_RESULT_PATH, WatchLimits, WatchNodeRegistry,
    WatchNodeTransport, sign_challenge, watch_router,
};
use http_body_util::BodyExt;
use serde_json::{Value, json};
use tower::ServiceExt;

const NODE: &str = "watch-1";
const SECRET: &[u8] = b"node-shared-secret";

struct Reply {
    status: StatusCode,
    body: Value,
}

impl Reply {
    fn string(&self, field: &str) -> String {
        self.body[field]
            .as_str()
            .unwrap_or_else(|| panic!("field {field} is a string in {}", self.body))
            .to_owned()
    }
}

fn limits() -> WatchLimits {
    WatchLimits {
        challenge_ttl: Duration::from_secs(60),
        max_pending_challenges: 16,
        max_pending_challenges_per_node: 3,
        session_idle_timeout: Duration::from_secs(3_600),
        poll_timeout: Duration::from_secs(5),
        max_events_per_poll: 8,
        max_queued_events: 4,
        max_queued_bytes: 4_096,
        max_event_bytes: 512,
        max_body_bytes: 4_096,
    }
}

fn transport_with(limits: WatchLimits) -> (WatchNodeTransport, Arc<InMemoryResultSink>, Router) {
    let registry = WatchNodeRegistry::new();
    registry.register(NODE, SECRET.to_vec());
    let sink = InMemoryResultSink::new();
    let transport = WatchNodeTransport::new(limits, registry, sink.clone());
    let router = watch_router(transport.clone());
    (transport, sink, router)
}

async fn send(router: &Router, request: Request<Body>) -> Reply {
    let response = router
        .clone()
        .oneshot(request)
        .await
        .expect("watch response");
    let status = response.status();
    let bytes = response
        .into_body()
        .collect()
        .await
        .expect("watch body")
        .to_bytes();
    Reply {
        status,
        body: serde_json::from_slice(&bytes).expect("watch body is JSON"),
    }
}

fn get(uri: &str) -> Request<Body> {
    Request::builder()
        .method("GET")
        .uri(uri)
        .body(Body::empty())
        .expect("watch GET")
}

fn post(uri: &str, token: Option<&str>, body: &Value) -> Request<Body> {
    let mut builder = Request::builder()
        .method("POST")
        .uri(uri)
        .header("content-type", "application/json");
    if let Some(token) = token {
        builder = builder.header("authorization", format!("Bearer {token}"));
    }
    builder
        .body(Body::from(serde_json::to_vec(body).expect("watch request")))
        .expect("watch POST")
}

async fn mint_nonce(router: &Router) -> String {
    let reply = send(
        router,
        get(&format!("{WATCH_CHALLENGE_PATH}?nodeId={NODE}")),
    )
    .await;
    assert_eq!(reply.status, StatusCode::OK, "challenge: {}", reply.body);
    reply.string("nonce")
}

async fn open_session(router: &Router) -> String {
    let nonce = mint_nonce(router).await;
    let reply = send(
        router,
        post(
            WATCH_CONNECT_PATH,
            None,
            &json!({
                "nodeId": NODE,
                "nonce": nonce,
                "signature": sign_challenge(SECRET, &nonce),
            }),
        ),
    )
    .await;
    assert_eq!(reply.status, StatusCode::OK, "connect: {}", reply.body);
    reply.string("sessionToken")
}

#[tokio::test(start_paused = true)]
async fn watch_transport_covers_challenge_connect_disconnect_long_poll_result_authentication_and_queue_limits()
 {
    let (transport, sink, router) = transport_with(limits());

    // ---- challenge -------------------------------------------------------
    let missing = send(&router, get(WATCH_CHALLENGE_PATH)).await;
    assert_eq!(
        missing.status,
        StatusCode::BAD_REQUEST,
        "a challenge must name the node it binds to"
    );
    let nonce = mint_nonce(&router).await;
    assert!(!nonce.is_empty());
    assert_eq!(transport.pending_challenges(), 1);

    // ---- authentication: a forged signature is refused and burns nothing --
    let forged = send(
        &router,
        post(
            WATCH_CONNECT_PATH,
            None,
            &json!({
                "nodeId": NODE,
                "nonce": nonce,
                "signature": sign_challenge(b"wrong-secret", &nonce),
            }),
        ),
    )
    .await;
    assert_eq!(forged.status, StatusCode::UNAUTHORIZED);
    assert_eq!(forged.body["error"], "invalid signature");
    assert_eq!(
        transport.pending_challenges(),
        1,
        "a forged signature must not consume the nonce a real node still holds"
    );

    let unknown = send(
        &router,
        post(
            WATCH_CONNECT_PATH,
            None,
            &json!({
                "nodeId": "not-registered",
                "nonce": nonce,
                "signature": sign_challenge(SECRET, &nonce),
            }),
        ),
    )
    .await;
    assert_eq!(unknown.status, StatusCode::UNAUTHORIZED);
    assert_eq!(unknown.body["error"], "unknown node");

    // ---- connect ---------------------------------------------------------
    let connected = send(
        &router,
        post(
            WATCH_CONNECT_PATH,
            None,
            &json!({
                "nodeId": NODE,
                "nonce": nonce,
                "signature": sign_challenge(SECRET, &nonce),
            }),
        ),
    )
    .await;
    assert_eq!(connected.status, StatusCode::OK, "{}", connected.body);
    let token = connected.string("sessionToken");
    assert!(!connected.string("sessionId").is_empty());
    assert_eq!(connected.body["pollTimeoutMs"], 5_000);
    assert_eq!(connected.body["maxQueuedEvents"], 4);
    assert_eq!(transport.connected_nodes(), vec![NODE.to_owned()]);
    assert_eq!(
        transport.pending_challenges(),
        0,
        "a successful connect consumes its nonce"
    );

    let replayed = send(
        &router,
        post(
            WATCH_CONNECT_PATH,
            None,
            &json!({
                "nodeId": NODE,
                "nonce": nonce,
                "signature": sign_challenge(SECRET, &nonce),
            }),
        ),
    )
    .await;
    assert_eq!(
        replayed.status,
        StatusCode::UNAUTHORIZED,
        "a nonce is single use"
    );
    assert_eq!(replayed.body["error"], "unknown or expired challenge");

    // ---- authentication: every session route needs the session token ------
    for (path, body) in [
        (WATCH_POLL_PATH, json!({})),
        (WATCH_DISCONNECT_PATH, json!({})),
        (
            WATCH_RESULT_PATH,
            json!({"commandId": "c-1", "ok": true, "result": {}}),
        ),
    ] {
        let anonymous = send(&router, post(path, None, &body)).await;
        assert_eq!(anonymous.status, StatusCode::UNAUTHORIZED, "{path}");
        let forged = send(&router, post(path, Some("not-a-session-token"), &body)).await;
        assert_eq!(forged.status, StatusCode::UNAUTHORIZED, "{path}");
        assert_eq!(forged.body["error"], "unauthenticated", "{path}");
    }

    // ---- long poll: a queued event is delivered without waiting ----------
    assert_eq!(
        transport.enqueue(NODE, json!({"event": "device.info"})),
        EnqueueOutcome::Queued
    );
    let delivered = send(&router, post(WATCH_POLL_PATH, Some(&token), &json!({}))).await;
    assert_eq!(delivered.status, StatusCode::OK, "{}", delivered.body);
    assert_eq!(
        delivered.body["events"],
        json!([{"event": "device.info"}]),
        "the queued event is returned verbatim"
    );
    assert_eq!(delivered.body["dropped"], 0);
    assert_eq!(delivered.body["pending"], 0);

    // ---- long poll: an empty queue parks until the deadline --------------
    let parked = tokio::spawn({
        let router = router.clone();
        let token = token.clone();
        async move { send(&router, post(WATCH_POLL_PATH, Some(&token), &json!({}))).await }
    });
    for _ in 0..4 {
        tokio::task::yield_now().await;
    }
    assert!(
        !parked.is_finished(),
        "an empty poll must park instead of answering immediately"
    );
    // Enqueued from the Gateway side while the poll is parked; the transport
    // wakes the waiter rather than letting it run to the deadline.
    assert_eq!(
        transport.enqueue(NODE, json!({"event": "device.status"})),
        EnqueueOutcome::Queued
    );
    let woken = parked.await.expect("parked poll");
    assert_eq!(woken.status, StatusCode::OK, "{}", woken.body);
    assert_eq!(woken.body["events"], json!([{"event": "device.status"}]));

    // With nothing queued the poll runs to its deadline; virtual time makes
    // that instantaneous and exact rather than a real five-second sleep.
    let timed_out = send(&router, post(WATCH_POLL_PATH, Some(&token), &json!({}))).await;
    assert_eq!(timed_out.status, StatusCode::OK, "{}", timed_out.body);
    assert_eq!(timed_out.body["events"], json!([]));
    assert_eq!(timed_out.body["dropped"], 0);

    // ---- queue limits ----------------------------------------------------
    for index in 0..4 {
        assert_eq!(
            transport.enqueue(NODE, json!({"seq": index})),
            EnqueueOutcome::Queued,
            "event {index} fits inside the four-event queue"
        );
    }
    assert_eq!(
        transport.enqueue(NODE, json!({"seq": 4})),
        EnqueueOutcome::QueuedAfterEviction { dropped: 1 },
        "a full queue evicts its oldest event rather than growing"
    );
    assert_eq!(
        transport.enqueue(NODE, json!({"seq": 5})),
        EnqueueOutcome::QueuedAfterEviction { dropped: 1 }
    );
    let oversized = "x".repeat(1_024);
    assert_eq!(
        transport.enqueue(NODE, json!({"blob": oversized})),
        EnqueueOutcome::RejectedTooLarge {
            bytes: 1_035,
            limit: 512,
        },
        "an event larger than the per-event limit is never queued"
    );
    let overflowed = send(&router, post(WATCH_POLL_PATH, Some(&token), &json!({}))).await;
    assert_eq!(overflowed.status, StatusCode::OK, "{}", overflowed.body);
    assert_eq!(
        overflowed.body["events"],
        json!([{"seq": 2}, {"seq": 3}, {"seq": 4}, {"seq": 5}]),
        "the queue keeps the newest four events and never exceeds its bound"
    );
    assert_eq!(
        overflowed.body["dropped"], 2,
        "the node is told how many events the bound cost it"
    );
    assert_eq!(overflowed.body["pending"], 0);

    // ---- result ----------------------------------------------------------
    let reported = send(
        &router,
        post(
            WATCH_RESULT_PATH,
            Some(&token),
            &json!({"commandId": "c-1", "ok": true, "result": {"battery": 42}}),
        ),
    )
    .await;
    assert_eq!(reported.status, StatusCode::OK, "{}", reported.body);
    assert_eq!(reported.body["accepted"], true);
    assert_eq!(reported.body["nodeId"], NODE);
    let recorded = sink.recorded();
    assert_eq!(recorded.len(), 1);
    assert_eq!(recorded[0].0, NODE);
    assert_eq!(recorded[0].1.command_id, "c-1");
    assert_eq!(recorded[0].1.result, Some(json!({"battery": 42})));

    let contradictory = send(
        &router,
        post(
            WATCH_RESULT_PATH,
            Some(&token),
            &json!({"commandId": "c-2", "ok": false, "result": {"battery": 42}}),
        ),
    )
    .await;
    assert_eq!(
        contradictory.status,
        StatusCode::BAD_REQUEST,
        "a failure result may not carry a success payload"
    );
    assert_eq!(
        sink.recorded().len(),
        1,
        "a rejected result never reaches the sink"
    );

    // ---- disconnect ------------------------------------------------------
    let closed = send(
        &router,
        post(WATCH_DISCONNECT_PATH, Some(&token), &json!({})),
    )
    .await;
    assert_eq!(closed.status, StatusCode::OK, "{}", closed.body);
    assert_eq!(closed.body["closed"], true);
    assert!(transport.connected_nodes().is_empty());
    assert_eq!(
        transport.enqueue(NODE, json!({"event": "device.info"})),
        EnqueueOutcome::NotConnected,
        "a closed session releases its queue"
    );
    let after_close = send(&router, post(WATCH_POLL_PATH, Some(&token), &json!({}))).await;
    assert_eq!(
        after_close.status,
        StatusCode::UNAUTHORIZED,
        "a disconnected token is no longer a credential"
    );
}

#[tokio::test(start_paused = true)]
async fn watch_challenges_expire_and_are_bounded_per_node() {
    let (transport, _sink, router) = transport_with(limits());

    let stale = mint_nonce(&router).await;
    tokio::time::advance(Duration::from_secs(61)).await;
    let expired = send(
        &router,
        post(
            WATCH_CONNECT_PATH,
            None,
            &json!({
                "nodeId": NODE,
                "nonce": stale,
                "signature": sign_challenge(SECRET, &stale),
            }),
        ),
    )
    .await;
    assert_eq!(expired.status, StatusCode::UNAUTHORIZED);
    assert_eq!(expired.body["error"], "unknown or expired challenge");

    let mut nonces = Vec::new();
    for _ in 0..5 {
        nonces.push(mint_nonce(&router).await);
        tokio::time::advance(Duration::from_millis(1)).await;
    }
    assert_eq!(
        transport.pending_challenges(),
        3,
        "unconsumed challenges are capped per node"
    );
    let evicted = send(
        &router,
        post(
            WATCH_CONNECT_PATH,
            None,
            &json!({
                "nodeId": NODE,
                "nonce": nonces[0],
                "signature": sign_challenge(SECRET, &nonces[0]),
            }),
        ),
    )
    .await;
    assert_eq!(
        evicted.status,
        StatusCode::UNAUTHORIZED,
        "the oldest challenge is the one the cap discards"
    );
    let newest = nonces.last().expect("five nonces were minted").clone();
    let accepted = send(
        &router,
        post(
            WATCH_CONNECT_PATH,
            None,
            &json!({
                "nodeId": NODE,
                "nonce": newest,
                "signature": sign_challenge(SECRET, &newest),
            }),
        ),
    )
    .await;
    assert_eq!(
        accepted.status,
        StatusCode::OK,
        "the newest retained challenge still connects: {}",
        accepted.body
    );
}

#[tokio::test(start_paused = true)]
async fn watch_sessions_are_superseded_by_a_newer_poll_and_expire_when_idle() {
    let (_transport, _sink, router) = transport_with(limits());
    let token = open_session(&router).await;

    let first = tokio::spawn({
        let router = router.clone();
        let token = token.clone();
        async move { send(&router, post(WATCH_POLL_PATH, Some(&token), &json!({}))).await }
    });
    for _ in 0..4 {
        tokio::task::yield_now().await;
    }
    assert!(
        !first.is_finished(),
        "the first poll parks on an empty queue"
    );

    let second = send(&router, post(WATCH_POLL_PATH, Some(&token), &json!({}))).await;
    assert_eq!(second.status, StatusCode::OK, "{}", second.body);
    assert_eq!(second.body["events"], json!([]));

    let superseded = first.await.expect("the superseded poll");
    assert_eq!(
        superseded.status,
        StatusCode::CONFLICT,
        "a node that repolls without closing its first socket cannot pin two long polls"
    );
    assert_eq!(superseded.body["error"], "superseded by a newer poll");

    tokio::time::advance(Duration::from_secs(3_601)).await;
    let stale = send(&router, post(WATCH_POLL_PATH, Some(&token), &json!({}))).await;
    assert_eq!(
        stale.status,
        StatusCode::UNAUTHORIZED,
        "an idle session stops being a credential"
    );
}

#[tokio::test(start_paused = true)]
async fn watch_queue_limits_bound_bytes_as_well_as_event_count() {
    let byte_bound = WatchLimits {
        max_queued_events: 64,
        max_queued_bytes: 256,
        max_event_bytes: 128,
        ..limits()
    };
    let (transport, _sink, router) = transport_with(byte_bound);
    let token = open_session(&router).await;

    let padding = "y".repeat(80);
    let mut evictions = 0;
    for index in 0..6 {
        match transport.enqueue(NODE, json!({"seq": index, "pad": padding})) {
            EnqueueOutcome::Queued => {}
            EnqueueOutcome::QueuedAfterEviction { dropped } => evictions += dropped,
            other => panic!("unexpected enqueue outcome: {other:?}"),
        }
    }
    assert!(
        evictions > 0,
        "the byte bound must evict even though the event count bound is untouched"
    );

    let reply = send(&router, post(WATCH_POLL_PATH, Some(&token), &json!({}))).await;
    assert_eq!(reply.status, StatusCode::OK, "{}", reply.body);
    let events = reply.body["events"].as_array().expect("events array");
    assert!(
        !events.is_empty() && events.len() < 6,
        "the byte bound trims the queue without emptying it: {events:?}"
    );
    let retained: usize = events
        .iter()
        .map(|event| serde_json::to_vec(event).expect("event bytes").len())
        .sum();
    assert!(
        retained <= 256,
        "the retained queue never exceeded its byte bound: {retained}"
    );
    assert_eq!(
        reply.body["dropped"],
        Value::from(evictions),
        "every eviction is reported to the node exactly once"
    );

    let too_large = transport.enqueue(NODE, json!({"blob": "z".repeat(200)}));
    assert!(
        matches!(
            too_large,
            EnqueueOutcome::RejectedTooLarge { limit: 128, .. }
        ),
        "an oversized event is rejected rather than emptying the queue: {too_large:?}"
    );
}

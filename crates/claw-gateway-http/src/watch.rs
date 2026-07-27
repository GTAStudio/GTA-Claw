//! Bounded watch-node HTTP transport.
//!
//! A watch node cannot hold a socket open the way a desktop client does, so it
//! talks to the Gateway over five short HTTP requests instead of one duplex
//! connection:
//!
//! | Method | Path | Purpose |
//! | --- | --- | --- |
//! | `GET` | `/api/nodes/watch/challenge` | mint a single-use, expiring nonce |
//! | `POST` | `/api/nodes/watch/connect` | prove possession of the node secret and open a session |
//! | `POST` | `/api/nodes/watch/poll` | long poll for queued events |
//! | `POST` | `/api/nodes/watch/result` | report the outcome of an invoked command |
//! | `POST` | `/api/nodes/watch/disconnect` | close the session and release its queue |
//!
//! Every allocation the transport makes on behalf of an unauthenticated caller
//! is bounded: pending challenges are capped globally and per node, request
//! bodies are capped, and each session's event queue is capped by both event
//! count and serialized byte count.

use std::collections::{HashMap, VecDeque};
use std::sync::Arc;
use std::sync::Mutex;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::time::Duration;

use axum::Router;
use axum::body::Body;
use axum::extract::{Query, Request, State};
use axum::http::{HeaderMap, StatusCode, header};
use axum::response::Response;
use axum::routing::{get, post};
use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use ring::hmac;
use ring::rand::{SecureRandom, SystemRandom};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use tokio::sync::Notify;
use tokio::time::{Instant, sleep};

use crate::http_util::{json_response, lock};

/// Path that mints a single-use connect challenge.
pub const WATCH_CHALLENGE_PATH: &str = "/api/nodes/watch/challenge";
/// Path that opens an authenticated watch session.
pub const WATCH_CONNECT_PATH: &str = "/api/nodes/watch/connect";
/// Path that closes a watch session.
pub const WATCH_DISCONNECT_PATH: &str = "/api/nodes/watch/disconnect";
/// Path that long polls for queued events.
pub const WATCH_POLL_PATH: &str = "/api/nodes/watch/poll";
/// Path that reports a command result.
pub const WATCH_RESULT_PATH: &str = "/api/nodes/watch/result";

/// Method and path of every watch-node route, in frozen inventory order.
pub const WATCH_NODE_ENDPOINTS: [(&str, &str); 5] = [
    ("GET", WATCH_CHALLENGE_PATH),
    ("POST", WATCH_CONNECT_PATH),
    ("POST", WATCH_DISCONNECT_PATH),
    ("POST", WATCH_POLL_PATH),
    ("POST", WATCH_RESULT_PATH),
];

/// Width of every minted nonce and session token, in bytes drawn from the
/// operating system CSPRNG.
const RANDOM_TOKEN_BYTES: usize = 32;

/// Bounds every watch-node session and every unauthenticated allocation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct WatchLimits {
    /// How long a minted challenge stays usable.
    pub challenge_ttl: Duration,
    /// Total unconsumed challenges retained across all nodes.
    pub max_pending_challenges: usize,
    /// Unconsumed challenges retained for any single node.
    pub max_pending_challenges_per_node: usize,
    /// How long a session survives without an authenticated request.
    pub session_idle_timeout: Duration,
    /// How long an empty long poll waits before answering with no events.
    pub poll_timeout: Duration,
    /// Events returned by a single poll.
    pub max_events_per_poll: usize,
    /// Events retained per session queue.
    pub max_queued_events: usize,
    /// Serialized bytes retained per session queue.
    pub max_queued_bytes: usize,
    /// Serialized bytes accepted for a single event.
    pub max_event_bytes: usize,
    /// Request body bytes accepted on the POST routes.
    pub max_body_bytes: usize,
}

impl WatchLimits {
    /// Returns the largest single event this configuration can ever queue.
    #[must_use]
    pub const fn effective_event_limit(&self) -> usize {
        if self.max_event_bytes < self.max_queued_bytes {
            self.max_event_bytes
        } else {
            self.max_queued_bytes
        }
    }
}

impl Default for WatchLimits {
    fn default() -> Self {
        Self {
            challenge_ttl: Duration::from_secs(60),
            max_pending_challenges: 4_096,
            max_pending_challenges_per_node: 8,
            session_idle_timeout: Duration::from_secs(300),
            poll_timeout: Duration::from_secs(25),
            max_events_per_poll: 16,
            max_queued_events: 64,
            max_queued_bytes: 256 * 1024,
            max_event_bytes: 32 * 1024,
            max_body_bytes: 64 * 1024,
        }
    }
}

/// Directory of the watch nodes allowed to open a session.
#[derive(Clone, Default)]
pub struct WatchNodeRegistry {
    nodes: Arc<Mutex<HashMap<String, Vec<u8>>>>,
}

impl WatchNodeRegistry {
    /// Creates an empty registry, which admits no node at all.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Registers, or replaces, the shared secret of one node.
    pub fn register(&self, node_id: impl Into<String>, secret: impl Into<Vec<u8>>) {
        lock(&self.nodes).insert(node_id.into(), secret.into());
    }

    /// Removes a node, so its next connect attempt is rejected.
    pub fn revoke(&self, node_id: &str) -> bool {
        lock(&self.nodes).remove(node_id).is_some()
    }

    fn secret(&self, node_id: &str) -> Option<Vec<u8>> {
        lock(&self.nodes).get(node_id).cloned()
    }
}

/// Signs a challenge nonce the way a watch node must sign it to connect.
#[must_use]
pub fn sign_challenge(secret: &[u8], nonce: &str) -> String {
    let key = hmac::Key::new(hmac::HMAC_SHA256, secret);
    URL_SAFE_NO_PAD.encode(hmac::sign(&key, nonce.as_bytes()).as_ref())
}

/// Verifies a challenge signature against the nonce and secret it claims.
///
/// Comparison is constant time, and a signature that is not valid base64url is
/// rejected rather than treated as an empty tag.
#[must_use]
pub fn verify_challenge(secret: &[u8], nonce: &str, signature: &str) -> bool {
    let Ok(presented) = URL_SAFE_NO_PAD.decode(signature) else {
        return false;
    };
    let key = hmac::Key::new(hmac::HMAC_SHA256, secret);
    hmac::verify(&key, nonce.as_bytes(), &presented).is_ok()
}

/// One command result reported by a connected watch node.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct WatchCommandResult {
    /// Identifier of the command this result answers.
    pub command_id: String,
    /// Whether the command succeeded.
    pub ok: bool,
    /// Success payload, present only when [`WatchCommandResult::ok`] is true.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub result: Option<Value>,
    /// Failure reason, present only when [`WatchCommandResult::ok`] is false.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

impl WatchCommandResult {
    /// Returns whether the success and failure payloads match the `ok` flag.
    #[must_use]
    pub fn is_well_formed(&self) -> bool {
        if self.command_id.trim().is_empty() {
            return false;
        }
        if self.ok {
            self.error.is_none()
        } else {
            self.result.is_none() && self.error.as_ref().is_some_and(|e| !e.trim().is_empty())
        }
    }
}

/// Receives the command results reported by connected watch nodes.
pub trait WatchResultSink: Send + Sync + 'static {
    /// Handles one result, returning `false` when the command is unknown.
    fn handle(&self, node_id: &str, result: WatchCommandResult) -> bool;
}

/// Result sink that records everything it is given.
#[derive(Default)]
pub struct InMemoryResultSink {
    accepted: Mutex<Vec<(String, WatchCommandResult)>>,
}

impl InMemoryResultSink {
    /// Creates an empty sink.
    #[must_use]
    pub fn new() -> Arc<Self> {
        Arc::new(Self::default())
    }

    /// Returns every result recorded so far, in arrival order.
    #[must_use]
    pub fn recorded(&self) -> Vec<(String, WatchCommandResult)> {
        lock(&self.accepted).clone()
    }
}

impl WatchResultSink for InMemoryResultSink {
    fn handle(&self, node_id: &str, result: WatchCommandResult) -> bool {
        lock(&self.accepted).push((node_id.to_owned(), result));
        true
    }
}

/// Outcome of offering one event to a session queue.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum EnqueueOutcome {
    /// The event was queued without displacing anything.
    Queued,
    /// The event was queued after evicting the oldest queued events.
    QueuedAfterEviction {
        /// How many older events the queue limits forced out.
        dropped: usize,
    },
    /// The event alone exceeds the per-event limit and was never queued.
    RejectedTooLarge {
        /// Serialized size of the rejected event.
        bytes: usize,
        /// The largest event this transport can queue.
        limit: usize,
    },
    /// No session is currently open for the node.
    NotConnected,
}

impl EnqueueOutcome {
    /// Returns whether the event reached a session queue.
    #[must_use]
    pub const fn is_queued(self) -> bool {
        matches!(self, Self::Queued | Self::QueuedAfterEviction { .. })
    }
}

struct PendingChallenge {
    node_id: String,
    expires_at: Instant,
}

struct WatchSession {
    session_id: String,
    token: String,
    node_id: String,
    queue: Mutex<WatchQueue>,
    notify: Notify,
    closed: AtomicBool,
    last_seen: Mutex<Instant>,
    poll_generation: AtomicU64,
}

#[derive(Default)]
struct WatchQueue {
    events: VecDeque<QueuedEvent>,
    bytes: usize,
    dropped: u64,
}

struct QueuedEvent {
    value: Value,
    bytes: usize,
}

#[derive(Default)]
struct TransportState {
    challenges: HashMap<String, PendingChallenge>,
    sessions: HashMap<String, Arc<WatchSession>>,
    node_tokens: HashMap<String, String>,
}

/// Bounded watch-node transport shared by the HTTP routes and the Gateway.
#[derive(Clone)]
pub struct WatchNodeTransport {
    inner: Arc<TransportInner>,
}

struct TransportInner {
    limits: WatchLimits,
    registry: WatchNodeRegistry,
    sink: Arc<dyn WatchResultSink>,
    state: Mutex<TransportState>,
    rng: SystemRandom,
}

impl WatchNodeTransport {
    /// Creates a transport bound by `limits`, admitting only registered nodes.
    #[must_use]
    pub fn new(
        limits: WatchLimits,
        registry: WatchNodeRegistry,
        sink: Arc<dyn WatchResultSink>,
    ) -> Self {
        Self {
            inner: Arc::new(TransportInner {
                limits,
                registry,
                sink,
                state: Mutex::new(TransportState::default()),
                rng: SystemRandom::new(),
            }),
        }
    }

    /// Returns the bounds this transport enforces.
    #[must_use]
    pub fn limits(&self) -> &WatchLimits {
        &self.inner.limits
    }

    /// Returns the node directory this transport authenticates against.
    #[must_use]
    pub fn registry(&self) -> &WatchNodeRegistry {
        &self.inner.registry
    }

    /// Offers one event to the session of `node_id`.
    pub fn enqueue(&self, node_id: &str, event: Value) -> EnqueueOutcome {
        let Some(session) = self.session_for_node(node_id) else {
            return EnqueueOutcome::NotConnected;
        };
        let Ok(encoded) = serde_json::to_vec(&event) else {
            return EnqueueOutcome::RejectedTooLarge {
                bytes: usize::MAX,
                limit: self.inner.limits.effective_event_limit(),
            };
        };
        let bytes = encoded.len();
        let limit = self.inner.limits.effective_event_limit();
        if bytes > limit {
            return EnqueueOutcome::RejectedTooLarge { bytes, limit };
        }
        let mut queue = lock(&session.queue);
        let mut dropped = 0;
        while queue.events.len() + 1 > self.inner.limits.max_queued_events
            || queue.bytes + bytes > self.inner.limits.max_queued_bytes
        {
            let Some(evicted) = queue.events.pop_front() else {
                break;
            };
            queue.bytes = queue.bytes.saturating_sub(evicted.bytes);
            dropped += 1;
        }
        queue.events.push_back(QueuedEvent {
            value: event,
            bytes,
        });
        queue.bytes += bytes;
        queue.dropped = queue
            .dropped
            .saturating_add(u64::try_from(dropped).unwrap_or(u64::MAX));
        drop(queue);
        session.notify.notify_waiters();
        if dropped == 0 {
            EnqueueOutcome::Queued
        } else {
            EnqueueOutcome::QueuedAfterEviction { dropped }
        }
    }

    /// Returns the identifiers of every node with an open session.
    #[must_use]
    pub fn connected_nodes(&self) -> Vec<String> {
        let mut nodes: Vec<String> = lock(&self.inner.state)
            .node_tokens
            .keys()
            .cloned()
            .collect();
        nodes.sort_unstable();
        nodes
    }

    /// Returns how many minted challenges are still unconsumed.
    #[must_use]
    pub fn pending_challenges(&self) -> usize {
        lock(&self.inner.state).challenges.len()
    }

    /// Closes the session of `node_id`, waking any in-flight long poll.
    pub fn disconnect_node(&self, node_id: &str) -> bool {
        let Some(session) = self.session_for_node(node_id) else {
            return false;
        };
        self.close(&session);
        true
    }

    fn session_for_node(&self, node_id: &str) -> Option<Arc<WatchSession>> {
        let state = lock(&self.inner.state);
        let token = state.node_tokens.get(node_id)?;
        state.sessions.get(token).cloned()
    }

    /// Draws 256 bits from the operating system CSPRNG and encodes them as
    /// base64url.
    ///
    /// This is the only source of nonces and session tokens in this transport:
    /// there is no seeded, counter-based or caller-supplied alternative, so a
    /// nonce can never be a constant. If the CSPRNG fails the caller fails
    /// closed rather than falling back to anything weaker.
    fn random_token(&self) -> Option<String> {
        let mut bytes = [0_u8; RANDOM_TOKEN_BYTES];
        self.inner.rng.fill(&mut bytes).ok()?;
        Some(URL_SAFE_NO_PAD.encode(bytes))
    }

    fn issue_challenge(&self, node_id: &str) -> Option<(String, u64)> {
        let nonce = self.random_token()?;
        let now = Instant::now();
        let expires_at = now + self.inner.limits.challenge_ttl;
        let mut state = lock(&self.inner.state);
        state
            .challenges
            .retain(|_, challenge| challenge.expires_at > now);
        evict_oldest_while(&mut state.challenges, |challenges| {
            challenges
                .values()
                .filter(|challenge| challenge.node_id == node_id)
                .count()
                >= self.inner.limits.max_pending_challenges_per_node
        });
        evict_oldest_while(&mut state.challenges, |challenges| {
            challenges.len() >= self.inner.limits.max_pending_challenges
        });
        state.challenges.insert(
            nonce.clone(),
            PendingChallenge {
                node_id: node_id.to_owned(),
                expires_at,
            },
        );
        let ttl_ms = u64::try_from(self.inner.limits.challenge_ttl.as_millis()).unwrap_or(u64::MAX);
        Some((nonce, ttl_ms))
    }

    /// Consumes a challenge, which can succeed at most once per minted nonce.
    fn consume_challenge(&self, nonce: &str, node_id: &str) -> bool {
        let now = Instant::now();
        let mut state = lock(&self.inner.state);
        let consumed = state.challenges.remove(nonce);
        state
            .challenges
            .retain(|_, challenge| challenge.expires_at > now);
        consumed.is_some_and(|challenge| challenge.expires_at > now && challenge.node_id == node_id)
    }

    fn open_session(&self, node_id: &str) -> Option<Arc<WatchSession>> {
        let token = self.random_token()?;
        let session_id = self.random_token()?;
        let session = Arc::new(WatchSession {
            session_id,
            token: token.clone(),
            node_id: node_id.to_owned(),
            queue: Mutex::new(WatchQueue::default()),
            notify: Notify::new(),
            closed: AtomicBool::new(false),
            last_seen: Mutex::new(Instant::now()),
            poll_generation: AtomicU64::new(0),
        });
        let superseded = {
            let mut state = lock(&self.inner.state);
            let superseded = state
                .node_tokens
                .insert(node_id.to_owned(), token.clone())
                .and_then(|previous| state.sessions.remove(&previous));
            state.sessions.insert(token, session.clone());
            superseded
        };
        if let Some(previous) = superseded {
            previous.shut();
        }
        Some(session)
    }

    fn authenticate(&self, headers: &HeaderMap) -> Option<Arc<WatchSession>> {
        let token = bearer_token(headers)?;
        let session = lock(&self.inner.state).sessions.get(token).cloned()?;
        if session.closed.load(Ordering::Acquire)
            || session.idle_for() >= self.inner.limits.session_idle_timeout
        {
            self.close(&session);
            return None;
        }
        *lock(&session.last_seen) = Instant::now();
        Some(session)
    }

    fn close(&self, session: &Arc<WatchSession>) {
        {
            let mut state = lock(&self.inner.state);
            state.sessions.remove(&session.token);
            if state
                .node_tokens
                .get(&session.node_id)
                .is_some_and(|token| token == &session.token)
            {
                state.node_tokens.remove(&session.node_id);
            }
        }
        session.shut();
    }
}

fn evict_oldest_while(
    challenges: &mut HashMap<String, PendingChallenge>,
    full: impl Fn(&HashMap<String, PendingChallenge>) -> bool,
) {
    while full(challenges) {
        let Some(oldest) = challenges
            .iter()
            .min_by_key(|(nonce, challenge)| (challenge.expires_at, (*nonce).clone()))
            .map(|(nonce, _)| nonce.clone())
        else {
            return;
        };
        challenges.remove(&oldest);
    }
}

impl WatchSession {
    fn idle_for(&self) -> Duration {
        lock(&self.last_seen).elapsed()
    }

    fn shut(&self) {
        self.closed.store(true, Ordering::Release);
        let mut queue = lock(&self.queue);
        queue.events.clear();
        queue.bytes = 0;
        drop(queue);
        self.notify.notify_waiters();
    }

    fn take_batch(&self, max_events: usize) -> Option<PollBatch> {
        let mut queue = lock(&self.queue);
        if queue.events.is_empty() {
            let dropped = std::mem::take(&mut queue.dropped);
            return (dropped > 0).then_some(PollBatch {
                events: Vec::new(),
                dropped,
                pending: 0,
            });
        }
        let take = max_events.max(1).min(queue.events.len());
        let mut events = Vec::with_capacity(take);
        for _ in 0..take {
            let Some(event) = queue.events.pop_front() else {
                break;
            };
            queue.bytes = queue.bytes.saturating_sub(event.bytes);
            events.push(event.value);
        }
        let dropped = std::mem::take(&mut queue.dropped);
        Some(PollBatch {
            events,
            dropped,
            pending: queue.events.len(),
        })
    }
}

struct PollBatch {
    events: Vec<Value>,
    dropped: u64,
    pending: usize,
}

impl PollBatch {
    fn into_body(self) -> Value {
        json!({
            "ok": true,
            "events": self.events,
            "dropped": self.dropped,
            "pending": self.pending,
        })
    }

    fn empty_body() -> Value {
        json!({"ok": true, "events": [], "dropped": 0, "pending": 0})
    }
}

fn bearer_token(headers: &HeaderMap) -> Option<&str> {
    let value = headers.get(header::AUTHORIZATION)?.to_str().ok()?;
    let (scheme, token) = value.split_once(' ')?;
    if !scheme.eq_ignore_ascii_case("Bearer") {
        return None;
    }
    let token = token.trim();
    (!token.is_empty()).then_some(token)
}

fn unauthorized(reason: &str) -> Response {
    json_response(
        StatusCode::UNAUTHORIZED,
        json!({"ok": false, "error": reason}),
    )
}

fn bad_request(reason: &str) -> Response {
    json_response(
        StatusCode::BAD_REQUEST,
        json!({"ok": false, "error": reason}),
    )
}

async fn read_body(body: Body, limit: usize) -> Option<Vec<u8>> {
    axum::body::to_bytes(body, limit)
        .await
        .ok()
        .map(|bytes| bytes.to_vec())
}

/// Builds the five watch-node routes.
pub fn watch_router(transport: WatchNodeTransport) -> Router {
    Router::new()
        .route(WATCH_CHALLENGE_PATH, get(challenge))
        .route(WATCH_CONNECT_PATH, post(connect))
        .route(WATCH_DISCONNECT_PATH, post(disconnect))
        .route(WATCH_POLL_PATH, post(poll))
        .route(WATCH_RESULT_PATH, post(result))
        .with_state(transport)
}

#[derive(Deserialize)]
struct ChallengeQuery {
    #[serde(rename = "nodeId")]
    node_id: Option<String>,
}

async fn challenge(
    State(transport): State<WatchNodeTransport>,
    Query(query): Query<ChallengeQuery>,
) -> Response {
    let Some(node_id) = query.node_id.filter(|id| !id.trim().is_empty()) else {
        return bad_request("nodeId is required");
    };
    // The nonce is minted before the node is known to exist so an unregistered
    // identifier cannot be distinguished from a registered one by timing or by
    // status code; the signature check at connect is what actually admits it.
    let Some((nonce, ttl_ms)) = transport.issue_challenge(&node_id) else {
        return json_response(
            StatusCode::INTERNAL_SERVER_ERROR,
            json!({"ok": false, "error": "challenge unavailable"}),
        );
    };
    json_response(
        StatusCode::OK,
        json!({
            "ok": true,
            "nodeId": node_id,
            "nonce": nonce,
            "expiresInMs": ttl_ms,
        }),
    )
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct ConnectRequest {
    node_id: String,
    nonce: String,
    signature: String,
}

async fn connect(State(transport): State<WatchNodeTransport>, request: Request) -> Response {
    let Some(body) = read_body(request.into_body(), transport.inner.limits.max_body_bytes).await
    else {
        return bad_request("connect body exceeds the configured limit");
    };
    let Ok(connect) = serde_json::from_slice::<ConnectRequest>(&body) else {
        return bad_request("malformed connect body");
    };
    let Some(secret) = transport.inner.registry.secret(&connect.node_id) else {
        return unauthorized("unknown node");
    };
    if !verify_challenge(&secret, &connect.nonce, &connect.signature) {
        return unauthorized("invalid signature");
    }
    // Signature first, nonce second: a forged signature must never consume the
    // nonce a legitimate node is about to present.
    if !transport.consume_challenge(&connect.nonce, &connect.node_id) {
        return unauthorized("unknown or expired challenge");
    }
    let Some(session) = transport.open_session(&connect.node_id) else {
        return json_response(
            StatusCode::INTERNAL_SERVER_ERROR,
            json!({"ok": false, "error": "session unavailable"}),
        );
    };
    let limits = transport.inner.limits;
    json_response(
        StatusCode::OK,
        json!({
            "ok": true,
            "nodeId": session.node_id,
            "sessionId": session.session_id,
            "sessionToken": session.token,
            "pollTimeoutMs": u64::try_from(limits.poll_timeout.as_millis()).unwrap_or(u64::MAX),
            "maxQueuedEvents": limits.max_queued_events,
            "maxEventsPerPoll": limits.max_events_per_poll,
        }),
    )
}

async fn disconnect(State(transport): State<WatchNodeTransport>, request: Request) -> Response {
    let (parts, _body) = request.into_parts();
    let Some(session) = transport.authenticate(&parts.headers) else {
        return unauthorized("unauthenticated");
    };
    transport.close(&session);
    json_response(StatusCode::OK, json!({"ok": true, "closed": true}))
}

#[derive(Default, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct PollRequest {
    #[serde(default)]
    max_events: Option<usize>,
}

async fn poll(State(transport): State<WatchNodeTransport>, request: Request) -> Response {
    let (parts, body) = request.into_parts();
    let Some(session) = transport.authenticate(&parts.headers) else {
        return unauthorized("unauthenticated");
    };
    let limits = transport.inner.limits;
    let Some(body) = read_body(body, limits.max_body_bytes).await else {
        return bad_request("poll body exceeds the configured limit");
    };
    let poll = if body.iter().all(u8::is_ascii_whitespace) {
        PollRequest::default()
    } else {
        match serde_json::from_slice::<PollRequest>(&body) {
            Ok(poll) => poll,
            Err(_) => return bad_request("malformed poll body"),
        }
    };
    let max_events = poll
        .max_events
        .unwrap_or(limits.max_events_per_poll)
        .clamp(1, limits.max_events_per_poll);

    // A second poll on the same session supersedes the first, so a node that
    // retried without closing its previous socket cannot pin two long polls.
    let generation = session.poll_generation.fetch_add(1, Ordering::AcqRel) + 1;
    session.notify.notify_waiters();

    let deadline = sleep(limits.poll_timeout);
    tokio::pin!(deadline);
    loop {
        // Registered before the queue is inspected, so an event enqueued
        // between the inspection and the wait cannot be missed.
        let notified = session.notify.notified();
        tokio::pin!(notified);
        let _already_notified = notified.as_mut().enable();

        if session.closed.load(Ordering::Acquire) {
            return unauthorized("session closed");
        }
        if session.poll_generation.load(Ordering::Acquire) != generation {
            return json_response(
                StatusCode::CONFLICT,
                json!({"ok": false, "error": "superseded by a newer poll"}),
            );
        }
        if let Some(batch) = session.take_batch(max_events) {
            return json_response(StatusCode::OK, batch.into_body());
        }
        tokio::select! {
            () = &mut deadline => return json_response(StatusCode::OK, PollBatch::empty_body()),
            () = &mut notified => {}
        }
    }
}

async fn result(State(transport): State<WatchNodeTransport>, request: Request) -> Response {
    let (parts, body) = request.into_parts();
    let Some(session) = transport.authenticate(&parts.headers) else {
        return unauthorized("unauthenticated");
    };
    let limits = transport.inner.limits;
    let Some(body) = read_body(body, limits.max_body_bytes).await else {
        return bad_request("result body exceeds the configured limit");
    };
    let Ok(reported) = serde_json::from_slice::<WatchCommandResult>(&body) else {
        return bad_request("malformed command result");
    };
    if !reported.is_well_formed() {
        return bad_request("command result does not match its ok flag");
    }
    let accepted = transport.inner.sink.handle(&session.node_id, reported);
    json_response(
        StatusCode::OK,
        json!({"ok": true, "accepted": accepted, "nodeId": session.node_id}),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_result_payload_must_match_its_ok_flag() {
        let ok = WatchCommandResult {
            command_id: "c-1".to_owned(),
            ok: true,
            result: Some(json!({"battery": 42})),
            error: None,
        };
        assert!(ok.is_well_formed());
        let contradictory = WatchCommandResult {
            error: Some("boom".to_owned()),
            ..ok.clone()
        };
        assert!(!contradictory.is_well_formed());
        let failed = WatchCommandResult {
            command_id: "c-1".to_owned(),
            ok: false,
            result: None,
            error: Some("boom".to_owned()),
        };
        assert!(failed.is_well_formed());
        let unexplained = WatchCommandResult {
            error: None,
            ..failed.clone()
        };
        assert!(!unexplained.is_well_formed());
        let anonymous = WatchCommandResult {
            command_id: "   ".to_owned(),
            ..ok
        };
        assert!(!anonymous.is_well_formed());
    }
}

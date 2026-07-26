//! Bounded watchOS direct-node HTTP transport.

use std::collections::{HashMap, VecDeque};
use std::net::{IpAddr, SocketAddr};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use axum::extract::{ConnectInfo, Request, State};
use axum::http::{HeaderValue, StatusCode, header};
use axum::response::Response;
use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use claw_protocol::gateway::{ClientId, ClientMode, ConnectParams, GATEWAY_PROTOCOL_VERSION};
use ring::rand::{SecureRandom, SystemRandom};
use serde_json::{Value, json};
use tokio::sync::Notify;
use tokio::time::{sleep, timeout};

use crate::auth::bearer_token;
use crate::config::HttpLimits;
use crate::error::ApiError;
use crate::http_support::{
    CancelOnDrop, close_connection_response, drain_request_body, json_response, read_json,
    rejected_response,
};
use crate::ports::{PortError, WatchResultPort};
use crate::state::ApiState;

const MAX_PENDING_CHALLENGES: usize = 4_096;
const MAX_PENDING_CHALLENGES_PER_CLIENT: usize = 8;
const CHALLENGE_TTL: Duration = Duration::from_secs(60);
const WATCH_COMMANDS: [&str; 3] = ["device.info", "device.status", "system.notify"];

#[derive(Clone)]
pub(crate) struct WatchRuntime {
    inner: Arc<WatchRuntimeInner>,
}

struct WatchRuntimeInner {
    limits: HttpLimits,
    challenges: Mutex<HashMap<String, PendingChallenge>>,
    sessions: Mutex<HashMap<String, Arc<WatchSession>>>,
    node_tokens: Mutex<HashMap<String, String>>,
    results: Arc<dyn WatchResultPort>,
}

struct PendingChallenge {
    expires: Instant,
    client_ip: IpAddr,
}

struct WatchSession {
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
}

struct QueuedEvent {
    value: Value,
    bytes: usize,
}

impl WatchRuntime {
    pub(crate) fn new(limits: HttpLimits, results: Arc<dyn WatchResultPort>) -> Self {
        Self {
            inner: Arc::new(WatchRuntimeInner {
                limits,
                challenges: Mutex::new(HashMap::new()),
                sessions: Mutex::new(HashMap::new()),
                node_tokens: Mutex::new(HashMap::new()),
                results,
            }),
        }
    }

    fn issue_challenge(&self, client_ip: IpAddr) -> Result<(String, u64), ApiError> {
        let mut bytes = [0_u8; 32];
        SystemRandom::new()
            .fill(&mut bytes)
            .map_err(|_| internal_error())?;
        let nonce = URL_SAFE_NO_PAD.encode(bytes);
        let now = Instant::now();
        let mut challenges = self.inner.challenges.lock().map_err(|_| internal_error())?;
        challenges.retain(|_, challenge| challenge.expires > now);
        if challenges
            .values()
            .filter(|challenge| challenge.client_ip == client_ip)
            .count()
            >= MAX_PENDING_CHALLENGES_PER_CLIENT
            && let Some(oldest) = challenges
                .iter()
                .filter(|(_, challenge)| challenge.client_ip == client_ip)
                .min_by_key(|(_, challenge)| challenge.expires)
                .map(|(nonce, _)| nonce.clone())
        {
            challenges.remove(&oldest);
        }
        if challenges.len() >= MAX_PENDING_CHALLENGES
            && let Some(oldest) = challenges
                .iter()
                .min_by_key(|(_, challenge)| challenge.expires)
                .map(|(nonce, _)| nonce.clone())
        {
            challenges.remove(&oldest);
        }
        challenges.insert(
            nonce.clone(),
            PendingChallenge {
                expires: now + CHALLENGE_TTL,
                client_ip,
            },
        );
        let expires_at_ms = unix_millis().saturating_add(60_000);
        Ok((nonce, expires_at_ms))
    }

    fn consume_challenge(&self, nonce: &str, client_ip: IpAddr) -> Result<bool, ApiError> {
        let now = Instant::now();
        let mut challenges = self.inner.challenges.lock().map_err(|_| internal_error())?;
        let valid = challenges
            .remove(nonce)
            .is_some_and(|challenge| challenge.expires > now && challenge.client_ip == client_ip);
        challenges.retain(|_, challenge| challenge.expires > now);
        Ok(valid)
    }

    fn insert_session(&self, node_id: String) -> Result<Arc<WatchSession>, ApiError> {
        let token = random_token()?;
        let session = Arc::new(WatchSession {
            token: token.clone(),
            node_id: node_id.clone(),
            queue: Mutex::new(WatchQueue::default()),
            notify: Notify::new(),
            closed: AtomicBool::new(false),
            last_seen: Mutex::new(Instant::now()),
            poll_generation: AtomicU64::new(0),
        });
        let mut sessions = self.inner.sessions.lock().map_err(|_| internal_error())?;
        let mut node_tokens = self
            .inner
            .node_tokens
            .lock()
            .map_err(|_| internal_error())?;
        if let Some(previous_token) = node_tokens.insert(node_id, token.clone())
            && let Some(previous) = sessions.remove(&previous_token)
        {
            previous.close();
        }
        sessions.insert(token, session.clone());
        Ok(session)
    }

    fn session(&self, token: &str) -> Result<Option<Arc<WatchSession>>, ApiError> {
        let session = self
            .inner
            .sessions
            .lock()
            .map_err(|_| internal_error())?
            .get(token)
            .cloned();
        let Some(session) = session else {
            return Ok(None);
        };
        if session.closed.load(Ordering::Acquire)
            || session.expired(self.inner.limits.watch_idle_timeout)
        {
            self.close_session(&session)?;
            return Ok(None);
        }
        session.touch()?;
        Ok(Some(session))
    }

    fn close_session(&self, session: &WatchSession) -> Result<(), ApiError> {
        session.close();
        self.inner
            .sessions
            .lock()
            .map_err(|_| internal_error())?
            .remove(&session.token);
        let mut nodes = self
            .inner
            .node_tokens
            .lock()
            .map_err(|_| internal_error())?;
        if nodes
            .get(&session.node_id)
            .is_some_and(|token| token == &session.token)
        {
            nodes.remove(&session.node_id);
        }
        Ok(())
    }

    fn close_session_port(&self, session: &WatchSession) -> Result<(), PortError> {
        session.close();
        self.inner
            .sessions
            .lock()
            .map_err(|_| {
                PortError::new(crate::ports::PortErrorKind::Internal, "watch lock failed")
            })?
            .remove(&session.token);
        let mut nodes = self.inner.node_tokens.lock().map_err(|_| {
            PortError::new(crate::ports::PortErrorKind::Internal, "watch lock failed")
        })?;
        if nodes
            .get(&session.node_id)
            .is_some_and(|token| token == &session.token)
        {
            nodes.remove(&session.node_id);
        }
        Ok(())
    }

    fn enqueue(
        &self,
        node_id: &str,
        event: &str,
        payload: Option<Value>,
    ) -> Result<bool, PortError> {
        let token = self
            .inner
            .node_tokens
            .lock()
            .map_err(|_| {
                PortError::new(crate::ports::PortErrorKind::Internal, "watch lock failed")
            })?
            .get(node_id)
            .cloned();
        let Some(token) = token else {
            return Ok(false);
        };
        let session = self
            .inner
            .sessions
            .lock()
            .map_err(|_| {
                PortError::new(crate::ports::PortErrorKind::Internal, "watch lock failed")
            })?
            .get(&token)
            .cloned();
        let Some(session) = session else {
            return Ok(false);
        };
        let value = match payload {
            Some(payload) => json!({"event":event,"payload":payload}),
            None => json!({"event":event}),
        };
        let bytes = serde_json::to_vec(&value)
            .map_err(|_| {
                PortError::new(
                    crate::ports::PortErrorKind::InvalidRequest,
                    "event is not serializable",
                )
            })?
            .len();
        if bytes > self.inner.limits.watch_event_bytes {
            self.close_session_port(&session)?;
            return Ok(false);
        }
        let mut queue = session.queue.lock().map_err(|_| {
            PortError::new(crate::ports::PortErrorKind::Internal, "watch lock failed")
        })?;
        if queue.events.len() >= self.inner.limits.watch_queue_events
            || queue.bytes.saturating_add(bytes) > self.inner.limits.watch_queue_bytes
        {
            drop(queue);
            self.close_session_port(&session)?;
            return Ok(false);
        }
        queue.events.push_back(QueuedEvent { value, bytes });
        queue.bytes += bytes;
        drop(queue);
        session.notify.notify_waiters();
        Ok(true)
    }
}

impl WatchSession {
    fn touch(&self) -> Result<(), ApiError> {
        *self.last_seen.lock().map_err(|_| internal_error())? = Instant::now();
        Ok(())
    }

    fn expired(&self, idle: Duration) -> bool {
        self.last_seen
            .lock()
            .map_or(true, |last_seen| last_seen.elapsed() >= idle)
    }

    fn close(&self) {
        self.closed.store(true, Ordering::Release);
        if let Ok(mut queue) = self.queue.lock() {
            queue.events.clear();
            queue.bytes = 0;
        }
        self.notify.notify_waiters();
    }

    fn pop(&self) -> Result<Option<Value>, ApiError> {
        let mut queue = self.queue.lock().map_err(|_| internal_error())?;
        let event = queue.events.pop_front();
        if let Some(event) = event {
            queue.bytes = queue.bytes.saturating_sub(event.bytes);
            Ok(Some(event.value))
        } else {
            Ok(None)
        }
    }
}

/// Handle used by the Gateway server to deliver events to watch sessions.
#[derive(Clone)]
pub struct WatchNodeHandle {
    runtime: WatchRuntime,
}

impl WatchNodeHandle {
    pub(crate) fn new(runtime: WatchRuntime) -> Self {
        Self { runtime }
    }

    /// Enqueues one bounded event for a connected node.
    pub fn send(
        &self,
        node_id: &str,
        event: &str,
        payload: Option<Value>,
    ) -> Result<bool, PortError> {
        self.runtime.enqueue(node_id, event, payload)
    }
}

pub(crate) async fn challenge(
    State(state): State<ApiState>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
) -> Result<Response, ApiError> {
    let (nonce, expires_at_ms) = state.inner.watch.issue_challenge(peer.ip())?;
    let mut response = json_response(
        StatusCode::OK,
        json!({"ok":true,"nonce":nonce,"expiresAtMs":expires_at_ms}),
    );
    response
        .headers_mut()
        .insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    Ok(response)
}

pub(crate) async fn connect(
    State(state): State<ApiState>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    request: Request,
) -> Result<Response, ApiError> {
    let limits = &state.inner.config.limits;
    let connect: ConnectParams =
        read_json(request, limits.watch_body_bytes, limits.body_timeout).await?;
    validate_watch_connect(&connect)?;
    let nonce = connect
        .device
        .as_ref()
        .map(|device| device.nonce.as_str())
        .ok_or_else(unauthorized)?;
    if !state.inner.watch.consume_challenge(nonce, peer.ip())? {
        return Err(unauthorized());
    }
    let cancellation = tokio_util::sync::CancellationToken::new();
    let _cancel_on_drop = CancelOnDrop::new(&cancellation);
    let identity = timeout(
        limits.operation_timeout,
        state
            .inner
            .services
            .watch_auth
            .authenticate(connect, cancellation),
    )
    .await
    .map_err(|_| unauthorized())?
    .map_err(|_| unauthorized())?;
    let session = state.inner.watch.insert_session(identity.node_id.clone())?;
    let mut body = json!({
        "ok":true,
        "sessionToken":session.token,
        "nodeId":identity.node_id,
        "protocol":GATEWAY_PROTOCOL_VERSION.get(),
        "pollTimeoutMs":u64::try_from(limits.watch_poll_timeout.as_millis()).unwrap_or(u64::MAX)
    });
    if let Some(device_token) = identity.device_token {
        body["deviceToken"] = json!(device_token);
    }
    Ok(json_response(StatusCode::OK, body))
}

pub(crate) async fn poll(
    State(state): State<ApiState>,
    request: Request,
) -> Result<Response, ApiError> {
    let token = bearer_token(request.headers()).map(str::to_owned);
    let session = match authenticated_session(&state, token.as_deref()) {
        Ok(session) => session,
        Err(error) => {
            return Ok(rejected_response(
                request,
                state.inner.config.limits.watch_body_bytes,
                state.inner.config.limits.body_timeout,
                error,
            )
            .await);
        }
    };
    if let Err(error) = drain_request_body(
        request,
        state.inner.config.limits.watch_body_bytes,
        state.inner.config.limits.body_timeout,
    )
    .await
    {
        return Ok(close_connection_response(error));
    }
    if let Some(event) = session.pop()? {
        return Ok(json_response(
            StatusCode::OK,
            json!({"ok":true,"event":event}),
        ));
    }
    let generation = session.poll_generation.fetch_add(1, Ordering::AcqRel) + 1;
    session.notify.notify_waiters();
    let mut guard = PollDisconnectGuard {
        runtime: state.inner.watch.clone(),
        session: session.clone(),
        armed: true,
    };
    let deadline = sleep(state.inner.config.limits.watch_poll_timeout);
    tokio::pin!(deadline);
    loop {
        let notified = session.notify.notified();
        tokio::pin!(notified);
        tokio::select! {
            () = &mut deadline => {
                guard.armed = false;
                return Ok(json_response(StatusCode::OK, json!({"ok":true,"event":null})));
            }
            () = &mut notified => {
                if session.closed.load(Ordering::Acquire) {
                    guard.armed = false;
                    return Err(unauthorized());
                }
                if session.poll_generation.load(Ordering::Acquire) != generation {
                    guard.armed = false;
                    return Ok(json_response(
                        StatusCode::CONFLICT,
                        json!({"ok":false,"reason":"superseded poll"}),
                    ));
                }
                if let Some(event) = session.pop()? {
                    guard.armed = false;
                    return Ok(json_response(StatusCode::OK, json!({"ok":true,"event":event})));
                }
            }
        }
    }
}

struct PollDisconnectGuard {
    runtime: WatchRuntime,
    session: Arc<WatchSession>,
    armed: bool,
}

impl Drop for PollDisconnectGuard {
    fn drop(&mut self) {
        if self.armed {
            let _ = self.runtime.close_session(&self.session);
        }
    }
}

pub(crate) async fn disconnect(
    State(state): State<ApiState>,
    request: Request,
) -> Result<Response, ApiError> {
    let token = bearer_token(request.headers()).map(str::to_owned);
    let session = match authenticated_session(&state, token.as_deref()) {
        Ok(session) => session,
        Err(error) => {
            return Ok(rejected_response(
                request,
                state.inner.config.limits.watch_body_bytes,
                state.inner.config.limits.body_timeout,
                error,
            )
            .await);
        }
    };
    if let Err(error) = drain_request_body(
        request,
        state.inner.config.limits.watch_body_bytes,
        state.inner.config.limits.body_timeout,
    )
    .await
    {
        return Ok(close_connection_response(error));
    }
    state.inner.watch.close_session(&session)?;
    Ok(json_response(StatusCode::OK, json!({"ok":true})))
}

pub(crate) async fn result(
    State(state): State<ApiState>,
    request: Request,
) -> Result<Response, ApiError> {
    let token = bearer_token(request.headers()).map(str::to_owned);
    let session = token
        .as_deref()
        .map(|token| state.inner.watch.session(token))
        .transpose()?
        .flatten();
    let Some(session) = session else {
        return Ok(rejected_response(
            request,
            state.inner.config.limits.watch_body_bytes,
            state.inner.config.limits.body_timeout,
            unauthorized(),
        )
        .await);
    };
    let limits = &state.inner.config.limits;
    let value: Value = read_json(request, limits.watch_body_bytes, limits.body_timeout).await?;
    let valid = value.as_object().is_some_and(|body| {
        body.get("id").is_some_and(Value::is_string)
            && body.get("ok").is_some_and(Value::is_boolean)
    });
    if !valid {
        return Err(ApiError::openai(
            StatusCode::BAD_REQUEST,
            "invalid node invoke result",
            "invalid_request_error",
        ));
    }
    let cancellation = tokio_util::sync::CancellationToken::new();
    let _cancel_on_drop = CancelOnDrop::new(&cancellation);
    let accepted = timeout(
        limits.operation_timeout,
        state
            .inner
            .watch
            .inner
            .results
            .handle(session.node_id.clone(), value, cancellation),
    )
    .await
    .map_err(|_| internal_error())?
    .map_err(|_| internal_error())?;
    Ok(json_response(
        StatusCode::OK,
        if accepted {
            json!({"ok":true})
        } else {
            json!({"ok":true,"ignored":true})
        },
    ))
}

fn authenticated_session(
    state: &ApiState,
    token: Option<&str>,
) -> Result<Arc<WatchSession>, ApiError> {
    token
        .map(|token| state.inner.watch.session(token))
        .transpose()?
        .flatten()
        .ok_or_else(unauthorized)
}

fn validate_watch_connect(connect: &ConnectParams) -> Result<(), ApiError> {
    let role = connect.role.as_ref().map(|role| role.as_str());
    let scopes_empty = connect.scopes.as_ref().is_none_or(Vec::is_empty);
    let platform = connect.client.platform.as_str().to_ascii_lowercase();
    let family = connect
        .client
        .device_family
        .as_ref()
        .map(|value| value.as_str().to_ascii_lowercase());
    let commands = connect.commands.as_ref().map_or(&[][..], Vec::as_slice);
    let commands_valid = !commands.is_empty()
        && commands
            .iter()
            .all(|command| WATCH_COMMANDS.contains(&command.as_str()));
    let permissions_valid = connect.permissions.as_ref().is_none_or(|permissions| {
        permissions
            .keys()
            .all(|permission| permission.as_str() == "notifications")
    });
    let auth = connect.auth.as_ref();
    let credential_count = auth.map_or(0, |auth| {
        usize::from(
            auth.bootstrap_token
                .as_deref()
                .is_some_and(|value| !value.trim().is_empty()),
        ) + usize::from(
            auth.device_token
                .as_deref()
                .is_some_and(|value| !value.trim().is_empty()),
        ) + usize::from(auth.token.is_some())
            + usize::from(auth.password.is_some())
            + usize::from(auth.approval_runtime_token.is_some())
            + usize::from(auth.agent_runtime_identity_token.is_some())
    });
    let valid = connect.min_protocol.get() <= GATEWAY_PROTOCOL_VERSION.get()
        && connect.max_protocol.get() >= GATEWAY_PROTOCOL_VERSION.get()
        && role == Some("node")
        && scopes_empty
        && connect.client.id == ClientId::WatchOs
        && connect.client.mode == ClientMode::Node
        && platform.starts_with("watchos")
        && family.as_deref() == Some("apple watch")
        && connect.caps.as_ref().is_none_or(Vec::is_empty)
        && commands_valid
        && permissions_valid
        && connect.device.is_some()
        && credential_count == 1
        && auth.is_some_and(|auth| auth.bootstrap_token.is_some() || auth.device_token.is_some());
    if valid {
        Ok(())
    } else {
        Err(ApiError::openai(
            StatusCode::BAD_REQUEST,
            "unsupported watch node identity or capability surface",
            "invalid_request_error",
        ))
    }
}

fn random_token() -> Result<String, ApiError> {
    let mut bytes = [0_u8; 32];
    SystemRandom::new()
        .fill(&mut bytes)
        .map_err(|_| internal_error())?;
    Ok(URL_SAFE_NO_PAD.encode(bytes))
}

fn unix_millis() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |duration| {
            u64::try_from(duration.as_millis()).unwrap_or(u64::MAX)
        })
}

fn unauthorized() -> ApiError {
    ApiError::openai(StatusCode::UNAUTHORIZED, "Unauthorized", "unauthorized")
}

fn internal_error() -> ApiError {
    ApiError::openai(
        StatusCode::INTERNAL_SERVER_ERROR,
        "internal error",
        "api_error",
    )
}

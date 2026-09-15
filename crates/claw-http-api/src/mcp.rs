//! Bearer-authenticated streamable HTTP MCP loopback endpoint.

use std::collections::BTreeMap;
use std::convert::Infallible;
use std::net::{IpAddr, SocketAddr};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use axum::extract::{ConnectInfo, Request, State};
use axum::http::{HeaderValue, Method, StatusCode, header};
use axum::response::sse::{Event, KeepAlive, Sse};
use axum::response::{IntoResponse, Response};
use base64::Engine as _;
use ring::rand::SecureRandom as _;
use serde_json::{Value, json};
use tokio::sync::{Notify, OwnedSemaphorePermit, Semaphore, mpsc};
use tokio::time::timeout;
use tokio_stream::wrappers::ReceiverStream;
use tokio_util::sync::CancellationToken;
use url::Url;

use crate::auth::bearer_token;
use crate::error::{ApiError, json_rpc_error};
use crate::http_support::{json_response, read_body, rejected_response};
use crate::ports::{PortErrorKind, ToolInvocation, ToolInvocationContext, ToolOutcome};
use crate::state::ApiState;

const SUPPORTED_PROTOCOLS: [&str; 2] = ["2025-03-26", "2024-11-05"];
const MAX_ACTIVE_REQUESTS: usize = 256;
const MAX_ACTIVE_SUBJECT_REQUESTS: usize = 32;
const MCP_SESSION_HEADER: &str = "mcp-session-id";
const MCP_PROTOCOL_HEADER: &str = "mcp-protocol-version";
const MAX_MCP_SESSIONS: usize = 128;
const MAX_SUBJECT_SESSIONS: usize = 16;
const MAX_MCP_STREAMS: usize = 128;
const MAX_SESSION_STREAMS: usize = 2;
const MCP_SESSION_TTL: Duration = Duration::from_mins(30);

#[derive(Clone)]
struct McpSessionContext {
    id: String,
    cancellation: CancellationToken,
    streams: Arc<Semaphore>,
    initialized: Arc<AtomicBool>,
    protocol: &'static str,
}

impl McpSessionContext {
    fn initialize(&self) -> Result<(), SessionError> {
        if self.cancellation.is_cancelled() {
            return Err(SessionError::NotFound);
        }
        self.initialized.store(true, Ordering::Release);
        Ok(())
    }

    fn is_ready(&self) -> bool {
        self.initialized.load(Ordering::Acquire) && !self.cancellation.is_cancelled()
    }
}

struct McpSession {
    subject: String,
    touched: Instant,
    cancellation: CancellationToken,
    streams: Arc<Semaphore>,
    initialized: Arc<AtomicBool>,
    protocol: &'static str,
}

pub(crate) struct McpSessions {
    sessions: Arc<Mutex<BTreeMap<String, McpSession>>>,
    streams: Arc<Semaphore>,
    shutdown: CancellationToken,
    changed: Arc<Notify>,
    expiry_worker: Mutex<Option<tokio::task::JoinHandle<()>>>,
    idle_timeout: Duration,
}

impl Default for McpSessions {
    fn default() -> Self {
        Self::new(&CancellationToken::new())
    }
}

struct McpStreamPermit {
    _global: OwnedSemaphorePermit,
    _session: OwnedSemaphorePermit,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum SessionError {
    NotFound,
    Capacity,
    Unavailable,
    Protocol,
}

impl McpSessions {
    pub(crate) fn new(shutdown: &CancellationToken) -> Self {
        Self {
            sessions: Arc::new(Mutex::new(BTreeMap::new())),
            streams: Arc::new(Semaphore::new(MAX_MCP_STREAMS)),
            shutdown: shutdown.child_token(),
            changed: Arc::new(Notify::new()),
            expiry_worker: Mutex::new(None),
            idle_timeout: MCP_SESSION_TTL,
        }
    }

    fn start_expiry_worker(&self) -> Result<(), SessionError> {
        let Ok(runtime) = tokio::runtime::Handle::try_current() else {
            return Ok(());
        };
        let mut worker = self
            .expiry_worker
            .lock()
            .map_err(|_| SessionError::Unavailable)?;
        if worker
            .as_ref()
            .is_none_or(tokio::task::JoinHandle::is_finished)
        {
            let sessions = Arc::downgrade(&self.sessions);
            let changed = Arc::clone(&self.changed);
            let shutdown = self.shutdown.clone();
            let idle_timeout = self.idle_timeout;
            *worker = Some(runtime.spawn(async move {
                loop {
                    let notified = changed.notified();
                    let Some(table) = sessions.upgrade() else { return; };
                    let deadline = if let Ok(mut sessions) = table.lock() {
                        expire_sessions(&mut sessions, Instant::now(), idle_timeout);
                        sessions.values().filter_map(|session| session.touched.checked_add(idle_timeout)).min()
                    } else {
                        shutdown.cancel();
                        return;
                    };
                    drop(table);
                    if let Some(deadline) = deadline {
                        tokio::select! {
                            biased;
                            () = shutdown.cancelled() => return,
                            () = notified => {},
                            () = tokio::time::sleep_until(tokio::time::Instant::from_std(deadline)) => {},
                        }
                    } else {
                        tokio::select! { () = shutdown.cancelled() => return, () = notified => {} }
                    }
                }
            }));
        }
        drop(worker);
        Ok(())
    }

    #[cfg(test)]
    fn create(&self, subject: &str, now: Instant) -> Result<McpSessionContext, SessionError> {
        self.create_negotiated(subject, SUPPORTED_PROTOCOLS[0], now)
    }

    fn create_negotiated(
        &self,
        subject: &str,
        protocol: &'static str,
        now: Instant,
    ) -> Result<McpSessionContext, SessionError> {
        if !SUPPORTED_PROTOCOLS.contains(&protocol) {
            return Err(SessionError::Protocol);
        }
        self.start_expiry_worker()?;
        let mut random = [0; 32];
        ring::rand::SystemRandom::new()
            .fill(&mut random)
            .map_err(|_| SessionError::Unavailable)?;
        let id = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(random);
        let mut sessions = self
            .sessions
            .lock()
            .map_err(|_| SessionError::Unavailable)?;
        if self.shutdown.is_cancelled() {
            return Err(SessionError::Unavailable);
        }
        expire_sessions(&mut sessions, now, self.idle_timeout);
        if sessions.len() >= MAX_MCP_SESSIONS
            || sessions
                .values()
                .filter(|session| session.subject == subject)
                .count()
                >= MAX_SUBJECT_SESSIONS
        {
            return Err(SessionError::Capacity);
        }
        if sessions.contains_key(&id) {
            return Err(SessionError::Unavailable);
        }
        let cancellation = self.shutdown.child_token();
        let streams = Arc::new(Semaphore::new(MAX_SESSION_STREAMS));
        let initialized = Arc::new(AtomicBool::new(false));
        sessions.insert(
            id.clone(),
            McpSession {
                subject: subject.to_owned(),
                touched: now,
                cancellation: cancellation.clone(),
                streams: Arc::clone(&streams),
                initialized: Arc::clone(&initialized),
                protocol,
            },
        );
        drop(sessions);
        self.changed.notify_one();
        Ok(McpSessionContext {
            id,
            cancellation,
            streams,
            initialized,
            protocol,
        })
    }

    fn resolve(
        &self,
        id: &str,
        subject: &str,
        now: Instant,
    ) -> Result<McpSessionContext, SessionError> {
        if id.len() != 43
            || !id
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
        {
            return Err(SessionError::NotFound);
        }
        if self.shutdown.is_cancelled() {
            return Err(SessionError::Unavailable);
        }
        let mut sessions = self
            .sessions
            .lock()
            .map_err(|_| SessionError::Unavailable)?;
        expire_sessions(&mut sessions, now, self.idle_timeout);
        let session = sessions
            .get_mut(id)
            .filter(|session| session.subject == subject)
            .ok_or(SessionError::NotFound)?;
        session.touched = session.touched.max(now);
        let cancellation = session.cancellation.clone();
        let streams = Arc::clone(&session.streams);
        let initialized = Arc::clone(&session.initialized);
        let protocol = session.protocol;
        drop(sessions);
        self.changed.notify_one();
        Ok(McpSessionContext {
            id: id.to_owned(),
            cancellation,
            streams,
            initialized,
            protocol,
        })
    }

    fn close(&self, id: &str, subject: &str) -> Result<(), SessionError> {
        let mut sessions = self
            .sessions
            .lock()
            .map_err(|_| SessionError::Unavailable)?;
        if sessions
            .get(id)
            .is_none_or(|session| session.subject != subject)
        {
            return Err(SessionError::NotFound);
        }
        let session = sessions.remove(id).ok_or(SessionError::NotFound)?;
        drop(sessions);
        session.cancellation.cancel();
        self.changed.notify_one();
        Ok(())
    }

    fn acquire_stream(&self, session: &McpSessionContext) -> Result<McpStreamPermit, SessionError> {
        if self.shutdown.is_cancelled() || session.cancellation.is_cancelled() {
            return Err(SessionError::NotFound);
        }
        let global = Arc::clone(&self.streams)
            .try_acquire_owned()
            .map_err(|_| SessionError::Capacity)?;
        let local = Arc::clone(&session.streams)
            .try_acquire_owned()
            .map_err(|_| SessionError::Capacity)?;
        Ok(McpStreamPermit {
            _global: global,
            _session: local,
        })
    }
}

impl Drop for McpSessions {
    fn drop(&mut self) {
        self.shutdown.cancel();
        if let Ok(worker) = self.expiry_worker.get_mut()
            && let Some(worker) = worker.take()
        {
            worker.abort();
        }
        if let Ok(sessions) = self.sessions.lock() {
            for session in sessions.values() {
                session.cancellation.cancel();
            }
        }
    }
}

fn expire_sessions(
    sessions: &mut BTreeMap<String, McpSession>,
    now: Instant,
    idle_timeout: Duration,
) {
    sessions.retain(|_, session| {
        if now
            .checked_duration_since(session.touched)
            .is_some_and(|age| age >= idle_timeout)
        {
            session.cancellation.cancel();
            return false;
        }
        true
    });
}

#[derive(Default)]
pub(crate) struct McpRequests {
    active: Mutex<BTreeMap<(String, String, String), CancellationToken>>,
    shutdown: CancellationToken,
}

struct McpRequestGuard<'a> {
    requests: &'a McpRequests,
    key: (String, String, String),
    cancellation: CancellationToken,
}

impl McpRequests {
    pub(crate) const fn new(shutdown: CancellationToken) -> Self {
        Self {
            active: Mutex::new(BTreeMap::new()),
            shutdown,
        }
    }

    #[cfg(test)]
    fn register(&self, subject: &str, id: &Value) -> Result<McpRequestGuard<'_>, &'static str> {
        self.register_scoped(subject, id, None)
    }

    fn register_scoped(
        &self,
        subject: &str,
        id: &Value,
        session: Option<&McpSessionContext>,
    ) -> Result<McpRequestGuard<'_>, &'static str> {
        let (owner, request_id) = request_key(subject, id).ok_or("Invalid MCP request ID")?;
        if session.is_some_and(|session| session.cancellation.is_cancelled()) {
            return Err("MCP session is closed");
        }
        if session.is_some_and(|session| !session.is_ready()) {
            return Err("MCP session is not initialized");
        }
        let key = (
            owner,
            session.map_or_else(String::new, |session| session.id.clone()),
            request_id,
        );
        let mut active = self
            .active
            .lock()
            .map_err(|_| "MCP request registry is unavailable")?;
        if self.shutdown.is_cancelled() {
            return Err("MCP service is draining");
        }
        if active.contains_key(&key) {
            return Err("MCP request ID is already active");
        }
        if active.len() >= MAX_ACTIVE_REQUESTS
            || active
                .keys()
                .filter(|(owner, _, _)| owner == subject)
                .count()
                >= MAX_ACTIVE_SUBJECT_REQUESTS
        {
            return Err("MCP request capacity exceeded");
        }
        let cancellation = session.map_or_else(
            || self.shutdown.child_token(),
            |session| session.cancellation.child_token(),
        );
        active.insert(key.clone(), cancellation.clone());
        drop(active);
        Ok(McpRequestGuard {
            requests: self,
            key,
            cancellation,
        })
    }

    #[cfg(test)]
    fn cancel(&self, subject: &str, id: &Value) {
        self.cancel_scoped(subject, id, None);
    }

    fn cancel_scoped(&self, subject: &str, id: &Value, session: Option<&McpSessionContext>) {
        let Some((owner, request_id)) = request_key(subject, id) else {
            return;
        };
        let key = (
            owner,
            session.map_or_else(String::new, |session| session.id.clone()),
            request_id,
        );
        if let Ok(active) = self.active.lock()
            && let Some(cancellation) = active.get(&key)
        {
            cancellation.cancel();
        }
    }
}

impl Drop for McpRequestGuard<'_> {
    fn drop(&mut self) {
        self.cancellation.cancel();
        if let Ok(mut active) = self.requests.active.lock() {
            active.remove(&self.key);
        }
    }
}

fn request_key(subject: &str, id: &Value) -> Option<(String, String)> {
    match id {
        Value::String(value) if value.len() <= 256 && !value.chars().any(char::is_control) => {}
        Value::Number(value) if value.is_i64() || value.is_u64() => {}
        _ => return None,
    }
    Some((subject.to_owned(), id.to_string()))
}

pub(crate) async fn session_transport(
    State(state): State<ApiState>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    request: Request,
) -> Result<Response, ApiError> {
    if !request.headers().contains_key(MCP_SESSION_HEADER) {
        return Ok(rejected_response(
            request,
            state.inner.config.limits.mcp_body_bytes,
            state.inner.config.limits.body_timeout,
            ApiError::method("POST"),
        )
        .await);
    }
    handle(State(state), ConnectInfo(peer), request).await
}

pub(crate) async fn handle(
    State(state): State<ApiState>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    request: Request,
) -> Result<Response, ApiError> {
    if !peer.ip().is_loopback() {
        return Ok(rejected_response(
            request,
            state.inner.config.limits.mcp_body_bytes,
            state.inner.config.limits.body_timeout,
            ApiError::simple(StatusCode::FORBIDDEN, "forbidden"),
        )
        .await);
    }
    if let Err(error) = validate_browser_origin(request.headers()) {
        return Ok(rejected_response(
            request,
            state.inner.config.limits.mcp_body_bytes,
            state.inner.config.limits.body_timeout,
            error,
        )
        .await);
    }
    let principal = match authenticate(&state, request.headers()) {
        Ok(principal) => principal,
        Err(error) => {
            return Ok(rejected_response(
                request,
                state.inner.config.limits.mcp_body_bytes,
                state.inner.config.limits.body_timeout,
                error,
            )
            .await);
        }
    };
    if state.inner.mcp_shutdown.is_cancelled() {
        return Ok(rejected_response(
            request,
            state.inner.config.limits.mcp_body_bytes,
            state.inner.config.limits.body_timeout,
            ApiError::simple(StatusCode::SERVICE_UNAVAILABLE, "service_draining"),
        )
        .await);
    }
    let session = match resolve_session(&state, request.headers(), principal) {
        Ok(session) => session,
        Err(error) => {
            return Ok(rejected_response(
                request,
                state.inner.config.limits.mcp_body_bytes,
                state.inner.config.limits.body_timeout,
                error,
            )
            .await);
        }
    };
    match *request.method() {
        Method::GET => mcp_sse(&state, session.as_ref()),
        Method::DELETE => {
            if let Some(session) = session {
                let authority =
                    principal.tool_authority(claw_application::ports::tool::InvocationSource::Mcp);
                state
                    .inner
                    .mcp_sessions
                    .close(&session.id, authority.subject())
                    .map_err(session_error)?;
            }
            Ok(json_response(StatusCode::OK, &json!({"ok":true})))
        }
        Method::POST => post(state, request, principal, session).await,
        _ => Err(ApiError::method("GET, POST, DELETE")),
    }
}

fn resolve_session(
    state: &ApiState,
    headers: &axum::http::HeaderMap,
    principal: crate::auth::Principal,
) -> Result<Option<McpSessionContext>, ApiError> {
    let Some(header) = headers.get(MCP_SESSION_HEADER) else {
        return Ok(None);
    };
    if headers.get_all(MCP_SESSION_HEADER).iter().count() != 1 {
        return Err(session_error(SessionError::NotFound));
    }
    let id = header
        .to_str()
        .map_err(|_| session_error(SessionError::NotFound))?;
    let authority = principal.tool_authority(claw_application::ports::tool::InvocationSource::Mcp);
    let session = state
        .inner
        .mcp_sessions
        .resolve(id, authority.subject(), Instant::now())
        .map_err(session_error)?;
    if let Some(protocol) = headers.get(MCP_PROTOCOL_HEADER)
        && (headers.get_all(MCP_PROTOCOL_HEADER).iter().count() != 1
            || protocol.to_str().ok() != Some(session.protocol))
    {
        return Err(session_error(SessionError::Protocol));
    }
    Ok(Some(session))
}

fn session_error(error: SessionError) -> ApiError {
    match error {
        SessionError::NotFound => ApiError::simple(StatusCode::NOT_FOUND, "mcp_session_not_found"),
        SessionError::Capacity => {
            ApiError::simple(StatusCode::TOO_MANY_REQUESTS, "mcp_session_capacity")
        }
        SessionError::Unavailable => {
            ApiError::simple(StatusCode::SERVICE_UNAVAILABLE, "mcp_session_unavailable")
        }
        SessionError::Protocol => {
            ApiError::simple(StatusCode::BAD_REQUEST, "mcp_protocol_mismatch")
        }
    }
}

fn validate_browser_origin(headers: &axum::http::HeaderMap) -> Result<(), ApiError> {
    let Some(origin) = headers
        .get(header::ORIGIN)
        .and_then(|value| value.to_str().ok())
    else {
        return Ok(());
    };
    let origin = Url::parse(origin)
        .map_err(|_| ApiError::simple(StatusCode::FORBIDDEN, "forbidden_origin"))?;
    let local = origin.host_str().is_some_and(|host| {
        host.eq_ignore_ascii_case("localhost")
            || host
                .parse::<IpAddr>()
                .is_ok_and(|address| address.is_loopback())
    });
    if local && matches!(origin.scheme(), "http" | "https") {
        Ok(())
    } else {
        Err(ApiError::simple(StatusCode::FORBIDDEN, "forbidden_origin"))
    }
}

fn authenticate(
    state: &ApiState,
    headers: &axum::http::HeaderMap,
) -> Result<crate::auth::Principal, ApiError> {
    let token = bearer_token(headers).ok_or_else(unauthorized)?;
    if let Some(principal) = state
        .inner
        .config
        .mcp_owner_authenticator
        .authenticate_token(token)
    {
        return Ok(principal);
    }
    if let Some(principal) = state
        .inner
        .config
        .mcp_authenticator
        .authenticate_token(token)
    {
        return Ok(principal);
    }
    Err(unauthorized())
}

async fn read_mcp_value(
    request: Request,
    max_bytes: usize,
    deadline: Duration,
) -> Result<Value, ApiError> {
    let bytes = read_body(request, max_bytes, deadline).await?;
    let invalid = || ApiError::simple(StatusCode::BAD_REQUEST, "invalid_mcp_json");
    let encoded = std::str::from_utf8(&bytes)
        .map_err(|_| invalid())?
        .to_owned();
    let raw =
        claw_protocol::gateway::OpaqueJson::from_json_string(encoded).map_err(|_| invalid())?;
    claw_protocol::gateway::Codec::authenticated()
        .decode_opaque(&raw)
        .map_err(|_| invalid())
}

async fn post(
    state: ApiState,
    request: Request,
    principal: crate::auth::Principal,
    session: Option<McpSessionContext>,
) -> Result<Response, ApiError> {
    let content_type = request
        .headers()
        .get(header::CONTENT_TYPE)
        .and_then(|value| value.to_str().ok())
        .unwrap_or("");
    if !content_type.starts_with("application/json") {
        return Ok(rejected_response(
            request,
            state.inner.config.limits.mcp_body_bytes,
            state.inner.config.limits.body_timeout,
            json_response(
                StatusCode::UNSUPPORTED_MEDIA_TYPE,
                &json!({"error":"unsupported_media_type"}),
            ),
        )
        .await);
    }
    let limits = &state.inner.config.limits;
    let value = match read_mcp_value(request, limits.mcp_body_bytes, limits.body_timeout).await {
        Ok(value) => value,
        Err(error) if error.status == StatusCode::PAYLOAD_TOO_LARGE => {
            return Ok(json_response(
                StatusCode::PAYLOAD_TOO_LARGE,
                &json!({"error":"payload_too_large"}),
            ));
        }
        Err(error) if error.status == StatusCode::REQUEST_TIMEOUT => {
            return Ok(json_response(
                StatusCode::REQUEST_TIMEOUT,
                &json!({"error":"request_body_timeout"}),
            ));
        }
        Err(_) => {
            return Ok(json_response(
                StatusCode::BAD_REQUEST,
                &json_rpc_error(Value::Null, -32700, "Parse error"),
            ));
        }
    };
    if state.inner.mcp_shutdown.is_cancelled() {
        return Err(ApiError::simple(
            StatusCode::SERVICE_UNAVAILABLE,
            "service_draining",
        ));
    }
    let is_batch = value.is_array();
    let messages = match value {
        Value::Array(messages) if !messages.is_empty() => messages,
        Value::Array(_) => vec![Value::Null],
        message => vec![message],
    };
    if is_batch && messages.iter().any(requests_session_initialization) {
        return Err(ApiError::simple(
            StatusCode::BAD_REQUEST,
            "mcp_initialize_requires_single_request",
        ));
    }
    let initializing = !is_batch
        && messages.first().is_some_and(|message| {
            message.get("jsonrpc").and_then(Value::as_str) == Some("2.0")
                && requests_session_initialization(message)
                && message
                    .get("id")
                    .is_some_and(|id| request_key("", id).is_some())
        });
    if initializing && session.is_some() {
        return Err(ApiError::simple(
            StatusCode::BAD_REQUEST,
            "mcp_session_already_initialized",
        ));
    }
    let mut responses = Vec::new();
    for message in messages {
        if let Some(response) = handle_message(&state, message, principal, session.as_ref()).await {
            responses.push(response);
        }
    }
    if responses.is_empty() {
        if session.is_some() {
            return Ok(StatusCode::ACCEPTED.into_response());
        }
        return Ok(json_response(StatusCode::ACCEPTED, &Value::Null));
    }
    let body = if is_batch {
        Value::Array(responses)
    } else {
        responses.into_iter().next().unwrap_or(Value::Null)
    };
    let mut response = json_response(StatusCode::OK, &body);
    if initializing && body.get("result").is_some() {
        let authority =
            principal.tool_authority(claw_application::ports::tool::InvocationSource::Mcp);
        let protocol = SUPPORTED_PROTOCOLS
            .iter()
            .copied()
            .find(|protocol| body["result"]["protocolVersion"].as_str() == Some(*protocol))
            .ok_or_else(|| session_error(SessionError::Protocol))?;
        let issued = state
            .inner
            .mcp_sessions
            .create_negotiated(authority.subject(), protocol, Instant::now())
            .map_err(session_error)?;
        let header = HeaderValue::from_str(&issued.id)
            .map_err(|_| session_error(SessionError::Unavailable))?;
        response.headers_mut().insert(MCP_SESSION_HEADER, header);
    }
    Ok(response)
}

fn requests_session_initialization(message: &Value) -> bool {
    message.get("method").and_then(Value::as_str) == Some("initialize")
        && message
            .get("params")
            .and_then(Value::as_object)
            .is_some_and(|params| {
                params.contains_key("clientInfo") || params.contains_key("capabilities")
            })
}

fn valid_session_initialize(params: Option<&serde_json::Map<String, Value>>) -> bool {
    let Some(params) = params else {
        return false;
    };
    let bounded_label = |value: Option<&Value>, maximum: usize| {
        value.and_then(Value::as_str).is_some_and(|label| {
            !label.trim().is_empty()
                && label.len() <= maximum
                && !label.chars().any(char::is_control)
        })
    };
    bounded_label(params.get("protocolVersion"), 32)
        && params.get("capabilities").is_some_and(Value::is_object)
        && params
            .get("clientInfo")
            .and_then(Value::as_object)
            .is_some_and(|client| {
                bounded_label(client.get("name"), 128) && bounded_label(client.get("version"), 128)
            })
}

async fn handle_message(
    state: &ApiState,
    message: Value,
    principal: crate::auth::Principal,
    session: Option<&McpSessionContext>,
) -> Option<Value> {
    let Some(object) = message.as_object() else {
        return Some(json_rpc_error(Value::Null, -32600, "Invalid Request"));
    };
    let id = object
        .get("id")
        .filter(|id| id.is_null() || id.is_string() || id.is_number())
        .cloned()
        .unwrap_or(Value::Null);
    if state.inner.mcp_shutdown.is_cancelled() {
        return object
            .contains_key("id")
            .then(|| json_rpc_error(id, -32000, "MCP service is draining"));
    }
    if object.get("jsonrpc").and_then(Value::as_str) != Some("2.0") {
        return Some(json_rpc_error(id, -32600, "Invalid Request"));
    }
    let Some(method) = object.get("method").and_then(Value::as_str) else {
        return Some(json_rpc_error(id, -32600, "Invalid Request"));
    };
    let params = object.get("params").and_then(Value::as_object);
    if session.is_some_and(|session| !session.is_ready())
        && !matches!(method, "notifications/initialized" | "ping" | "initialize")
    {
        return object
            .contains_key("id")
            .then(|| json_rpc_error(id, -32002, "MCP session is not initialized"));
    }
    match method {
        "initialize" => {
            if session.is_some() {
                return Some(json_rpc_error(
                    id,
                    -32600,
                    "MCP session is already initialized",
                ));
            }
            if requests_session_initialization(&message)
                && (!valid_session_initialize(params) || request_key("", &id).is_none())
            {
                return Some(json_rpc_error(
                    id,
                    -32602,
                    "Invalid MCP initialization parameters",
                ));
            }
            let requested = params
                .and_then(|params| params.get("protocolVersion"))
                .and_then(Value::as_str)
                .unwrap_or("");
            let protocol = SUPPORTED_PROTOCOLS
                .iter()
                .copied()
                .find(|protocol| *protocol == requested)
                .unwrap_or(SUPPORTED_PROTOCOLS[0]);
            Some(rpc_result(
                &id,
                &json!({
                    "protocolVersion":protocol,
                    "capabilities":{"tools":{}},
                    "serverInfo":{"name":"openclaw","version":"0.1.0"}
                }),
            ))
        }
        "notifications/initialized" => {
            if let Some(session) = session {
                if object.contains_key("id")
                    || object
                        .get("params")
                        .is_some_and(|params| !params.is_object())
                {
                    return Some(json_rpc_error(
                        id,
                        -32600,
                        "Invalid initialized notification",
                    ));
                }
                if session.initialize().is_err() {
                    return None;
                }
            }
            None
        }
        "ping" if session.is_some() => {
            if request_key("", &id).is_none() {
                return Some(json_rpc_error(
                    Value::Null,
                    -32600,
                    "Invalid MCP request ID",
                ));
            }
            Some(rpc_result(&id, &json!({})))
        }
        "notifications/cancelled" => {
            if !object.contains_key("id")
                && let Some(request_id) = params.and_then(|params| params.get("requestId"))
            {
                let authority =
                    principal.tool_authority(claw_application::ports::tool::InvocationSource::Mcp);
                state
                    .inner
                    .mcp_requests
                    .cancel_scoped(authority.subject(), request_id, session);
            }
            None
        }
        "tools/list" => {
            let authority =
                principal.tool_authority(claw_application::ports::tool::InvocationSource::Mcp);
            let registered =
                match state
                    .inner
                    .mcp_requests
                    .register_scoped(authority.subject(), &id, session)
                {
                    Ok(registered) => registered,
                    Err(message) => return Some(json_rpc_error(id, -32600, message)),
                };
            tokio::select! {
                () = registered.cancellation.cancelled() => Some(json_rpc_error(id, -32800, "MCP request cancelled")),
                result = timeout(state.inner.config.limits.operation_timeout, state.inner.services.tools.list()) => {
                    match result {
                        Ok(Ok(tools)) => Some(rpc_result(&id, &json!({"tools":tools}))),
                        _ => Some(json_rpc_error(id, -32603, "Internal error")),
                    }
                }
            }
        }
        "tools/call" => {
            if request_key("", &id).is_none() {
                return Some(json_rpc_error(
                    Value::Null,
                    -32600,
                    "Invalid MCP request ID",
                ));
            }
            let name = params
                .and_then(|params| params.get("name"))
                .and_then(Value::as_str)
                .map_or("", str::trim);
            let arguments = params
                .and_then(|params| params.get("arguments"))
                .cloned()
                .unwrap_or_else(|| json!({}));
            if !arguments.is_object() {
                return Some(json_rpc_error(
                    id,
                    -32602,
                    "Invalid params: tools/call arguments must be an object",
                ));
            }
            if name.is_empty() {
                return Some(rpc_result(
                    &id,
                    &tool_call_error("Tool not available: unknown"),
                ));
            }
            let authority =
                principal.tool_authority(claw_application::ports::tool::InvocationSource::Mcp);
            let registered =
                match state
                    .inner
                    .mcp_requests
                    .register_scoped(authority.subject(), &id, session)
                {
                    Ok(registered) => registered,
                    Err(message) => return Some(json_rpc_error(id, -32600, message)),
                };
            let cancellation = registered.cancellation.clone();
            match timeout(
                state.inner.config.limits.operation_timeout,
                state.inner.services.tools.invoke(
                    ToolInvocation {
                        name: name.to_owned(),
                        arguments,
                        action: None,
                        context: ToolInvocationContext {
                            authority: Some(authority),
                            binding: None,
                            session_key: None,
                            agent_id: None,
                            idempotency_key: None,
                            message_channel: None,
                            account_id: None,
                            agent_to: None,
                            agent_thread_id: None,
                            sender_is_owner: principal
                                .scopes
                                .contains(claw_security::authorization::Scope::OperatorAdmin),
                            dry_run: false,
                        },
                    },
                    cancellation,
                ),
            )
            .await
            {
                Ok(Ok(outcome)) => Some(rpc_result(&id, &mcp_tool_result(outcome))),
                Ok(Err(error))
                    if matches!(
                        error.kind,
                        PortErrorKind::OutcomeUnknown | PortErrorKind::CommittedButNotDurable
                    ) =>
                {
                    let kind = if error.kind == PortErrorKind::OutcomeUnknown {
                        "outcome_unknown"
                    } else {
                        "committed_but_not_durable"
                    };
                    Some(rpc_result(
                        &id,
                        &tool_recovery_required(kind, &error.message),
                    ))
                }
                Ok(Err(error)) => Some(rpc_result(&id, &tool_call_error(&error.message))),
                Err(_) => Some(rpc_result(
                    &id,
                    &tool_recovery_required(
                        "outcome_unknown",
                        "Tool execution timed out with an unknown outcome.",
                    ),
                )),
            }
        }
        _ => Some(json_rpc_error(
            id,
            -32601,
            format!("Method not found: {method}"),
        )),
    }
}

fn rpc_result(id: &Value, result: &Value) -> Value {
    json!({"jsonrpc":"2.0","id":id,"result":result})
}

fn mcp_tool_result(outcome: ToolOutcome) -> Value {
    if !outcome.ok {
        if let Some(kind @ ("outcome_unknown" | "committed_but_not_durable")) =
            outcome.error_type.as_deref()
        {
            return tool_recovery_required(
                kind,
                outcome
                    .error_message
                    .as_deref()
                    .unwrap_or("Tool outcome requires reconciliation."),
            );
        }
        return tool_call_error(
            outcome
                .error_message
                .as_deref()
                .unwrap_or("tool execution failed"),
        );
    }
    let result = outcome.result.unwrap_or(Value::Null);
    let content = match result {
        Value::Object(ref object) if object.get("content").is_some_and(Value::is_array) => {
            object["content"].clone()
        }
        Value::String(text) => json!([{"type":"text","text":text}]),
        other => json!([{"type":"text","text":serde_json::to_string(&other).unwrap_or_default()}]),
    };
    json!({"content":content,"isError":false})
}

fn tool_call_error(message: &str) -> Value {
    json!({"content":[{"type":"text","text":message}],"isError":true})
}

fn tool_recovery_required(kind: &str, message: &str) -> Value {
    let message = format!(
        "{message}\nThe operation may already have taken effect. Do not repeat it automatically; reconcile recorded effects before retrying."
    );
    json!({
        "content": [{"type": "text", "text": message}], "isError": true,
        "_meta": {"gta-claw": {"error": {"type": kind, "retryable": false, "recoveryRequired": true}}}
    })
}

fn mcp_sse(state: &ApiState, session: Option<&McpSessionContext>) -> Result<Response, ApiError> {
    let session = session.ok_or_else(|| ApiError::method("POST"))?;
    let cancellation = session.cancellation.child_token();
    let producer_cancellation = cancellation.clone();
    let (sender, receiver) = mpsc::channel::<Result<Event, Infallible>>(1);
    let stream = McpStream {
        inner: ReceiverStream::new(receiver),
        cancellation,
        _permit: state
            .inner
            .mcp_sessions
            .acquire_stream(session)
            .map_err(session_error)?,
    };
    tokio::spawn(async move {
        if sender.send(Ok(Event::default().comment(""))).await.is_ok() {
            producer_cancellation.cancelled().await;
        }
    });
    let mut response = Sse::new(stream)
        .keep_alive(
            KeepAlive::new()
                .interval(state.inner.config.limits.heartbeat_interval)
                .text(""),
        )
        .into_response();
    response.headers_mut().insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static("text/event-stream; charset=utf-8"),
    );
    Ok(response)
}

struct McpStream {
    inner: ReceiverStream<Result<Event, Infallible>>,
    cancellation: CancellationToken,
    _permit: McpStreamPermit,
}

impl futures_core::Stream for McpStream {
    type Item = Result<Event, Infallible>;

    fn poll_next(
        mut self: std::pin::Pin<&mut Self>,
        context: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Option<Self::Item>> {
        std::pin::Pin::new(&mut self.inner).poll_next(context)
    }
}

impl Drop for McpStream {
    fn drop(&mut self) {
        self.cancellation.cancel();
    }
}

fn unauthorized() -> ApiError {
    ApiError::simple(StatusCode::UNAUTHORIZED, "unauthorized")
}

#[cfg(test)]
mod tests {
    use super::{
        MAX_ACTIVE_REQUESTS, MAX_ACTIVE_SUBJECT_REQUESTS, MAX_MCP_SESSIONS, MAX_SUBJECT_SESSIONS,
        MCP_SESSION_TTL, McpRequests, McpSessions, SessionError,
    };
    use serde_json::json;
    use std::time::Instant;

    #[test]
    fn mcp_out_of_order_request_timestamps_do_not_expire_or_backdate_sessions() {
        let sessions = McpSessions::default();
        let requests = McpRequests::default();
        let earlier = Instant::now();
        let latest = earlier + std::time::Duration::from_secs(2);
        let first = sessions
            .create("owner", latest)
            .expect("newer request creates first session");
        first.initialize().expect("initialized");
        let request = requests
            .register_scoped("owner", &json!(1), Some(&first))
            .expect("active request");
        let stream = sessions.acquire_stream(&first).expect("active stream");
        let _second = sessions
            .create("owner", earlier + std::time::Duration::from_secs(1))
            .expect("older request is processed later");
        assert!(
            !first.cancellation.is_cancelled(),
            "an older clock sample is not evidence of inactivity"
        );
        sessions
            .resolve(&first.id, "owner", earlier)
            .expect("delayed request resolves live session");
        assert_eq!(
            sessions
                .sessions
                .lock()
                .expect("table")
                .get(&first.id)
                .expect("first session")
                .touched,
            latest
        );
        {
            let mut table = sessions.sessions.lock().expect("table");
            super::expire_sessions(
                &mut table,
                (latest + MCP_SESSION_TTL)
                    .checked_sub(std::time::Duration::from_nanos(1))
                    .expect("one nanosecond before expiry"),
                MCP_SESSION_TTL,
            );
            assert!(table.contains_key(&first.id));
            assert!(!request.cancellation.is_cancelled());
            super::expire_sessions(&mut table, latest + MCP_SESSION_TTL, MCP_SESSION_TTL);
            assert!(!table.contains_key(&first.id));
            drop(table);
        }
        assert!(first.cancellation.is_cancelled());
        assert!(request.cancellation.is_cancelled());
        assert_eq!(
            sessions.streams.available_permits(),
            super::MAX_MCP_STREAMS - 1
        );
        drop(stream);
        drop(request);
        assert_eq!(sessions.streams.available_permits(), super::MAX_MCP_STREAMS);
    }

    #[tokio::test]
    async fn mcp_idle_sessions_cancel_without_new_requests_and_hold_active_permits_until_release() {
        let root = tokio_util::sync::CancellationToken::new();
        let mut sessions = McpSessions::new(&root);
        sessions.idle_timeout = std::time::Duration::from_millis(100);
        let requests = McpRequests::new(root.clone());
        let session = sessions
            .create("owner", Instant::now())
            .expect("owned session");
        session.initialize().expect("initialized");
        let request = requests
            .register_scoped("owner", &json!(1), Some(&session))
            .expect("active request");
        let stream = sessions
            .acquire_stream(&session)
            .expect("response body permit");
        tokio::time::timeout(
            std::time::Duration::from_secs(2),
            session.cancellation.cancelled(),
        )
        .await
        .expect("idle expiry without another HTTP request");
        assert!(request.cancellation.is_cancelled());
        assert!(!session.is_ready());
        assert!(sessions.sessions.lock().expect("registry").is_empty());
        assert_eq!(requests.active.lock().expect("active calls").len(), 1);
        assert_eq!(
            sessions.streams.available_permits(),
            super::MAX_MCP_STREAMS - 1
        );
        drop(request);
        drop(stream);
        assert!(requests.active.lock().expect("released calls").is_empty());
        assert_eq!(sessions.streams.available_permits(), super::MAX_MCP_STREAMS);
        let worker = sessions
            .expiry_worker
            .lock()
            .expect("worker slot")
            .take()
            .expect("one expiry worker");
        root.cancel();
        tokio::time::timeout(std::time::Duration::from_secs(1), worker)
            .await
            .expect("expiry worker drain")
            .expect("worker finished normally");
    }

    #[tokio::test]
    async fn mcp_idle_expiry_finishes_real_sse_body_and_releases_stream_capacity() {
        let runtime = crate::DeterministicRuntime::new();
        let mut config = crate::ApiConfig::new(crate::BearerAuthenticator::new(Vec::new()));
        config.limits.heartbeat_interval = std::time::Duration::from_secs(1);
        let mut state = crate::state::ApiState::with_serving_state(
            config,
            runtime.services(),
            std::sync::Arc::new(crate::ServingStateHandle::serving()),
        );
        std::sync::Arc::get_mut(&mut state.inner)
            .expect("new private state")
            .mcp_sessions
            .idle_timeout = std::time::Duration::from_millis(100);
        let session = state
            .inner
            .mcp_sessions
            .create("owner", Instant::now())
            .expect("live session");
        session.initialize().expect("initialized");
        let response = super::mcp_sse(&state, Some(&session)).expect("SSE response");
        assert_eq!(
            state.inner.mcp_sessions.streams.available_permits(),
            super::MAX_MCP_STREAMS - 1
        );
        let body = tokio::time::timeout(
            std::time::Duration::from_secs(2),
            axum::body::to_bytes(response.into_body(), 1024),
        )
        .await
        .expect("idle expiry closes the actual SSE body")
        .expect("bounded SSE");
        assert!(!body.is_empty());
        assert!(session.cancellation.is_cancelled());
        assert_eq!(
            state.inner.mcp_sessions.streams.available_permits(),
            super::MAX_MCP_STREAMS
        );
        let worker = state
            .inner
            .mcp_sessions
            .expiry_worker
            .lock()
            .expect("worker slot")
            .take()
            .expect("worker");
        state.inner.mcp_shutdown.cancel();
        worker.await.expect("expiry worker completed");
    }

    #[tokio::test]
    async fn mcp_expiry_worker_restarts_after_runtime_abort_and_uses_latest_activity() {
        let sessions = McpSessions::default();
        let first = sessions.create("owner", Instant::now()).expect("session");
        let mut worker = sessions
            .expiry_worker
            .lock()
            .expect("worker slot")
            .take()
            .expect("worker");
        worker.abort();
        assert!(
            (&mut worker)
                .await
                .expect_err("owned worker aborted")
                .is_cancelled()
        );
        *sessions
            .expiry_worker
            .lock()
            .expect("retained completed worker") = Some(worker);
        let second = sessions
            .create("other", Instant::now())
            .expect("next runtime session");
        sessions
            .sessions
            .lock()
            .expect("table")
            .get_mut(&second.id)
            .expect("session")
            .touched = Instant::now()
            .checked_sub(MCP_SESSION_TTL / 2)
            .expect("fixture clock supports recent history");
        sessions
            .resolve(&second.id, "other", Instant::now())
            .expect("latest activity wins before maintenance");
        sessions
            .sessions
            .lock()
            .expect("table")
            .get_mut(&first.id)
            .expect("first")
            .touched = Instant::now()
            .checked_sub(MCP_SESSION_TTL)
            .expect("fixture clock supports idle history");
        sessions.changed.notify_one();
        tokio::time::timeout(
            std::time::Duration::from_secs(1),
            first.cancellation.cancelled(),
        )
        .await
        .expect("new worker expires idle session");
        assert!(!second.cancellation.is_cancelled());
        sessions.close(&second.id, "other").expect("explicit close");
        let worker = sessions
            .expiry_worker
            .lock()
            .expect("worker slot")
            .take()
            .expect("replacement worker");
        drop(sessions);
        worker.await.expect("replacement worker completed");
    }

    #[tokio::test]
    async fn mcp_expiry_worker_does_not_cancel_an_active_or_other_owner_session() {
        let sessions = McpSessions::default();
        let first = sessions
            .create("first-owner", Instant::now())
            .expect("idle session");
        let second = sessions
            .create("second-owner", Instant::now())
            .expect("active session");
        sessions
            .sessions
            .lock()
            .expect("registry")
            .get_mut(&first.id)
            .expect("first")
            .touched = Instant::now()
            .checked_sub(MCP_SESSION_TTL)
            .expect("fixture clock supports idle history");
        sessions
            .resolve(&second.id, "second-owner", Instant::now())
            .expect("authenticated activity");
        tokio::time::timeout(
            std::time::Duration::from_secs(1),
            first.cancellation.cancelled(),
        )
        .await
        .expect("expired first session");
        assert!(!second.cancellation.is_cancelled());
        assert_eq!(sessions.sessions.lock().expect("registry").len(), 1);
        assert!(
            sessions
                .resolve(&second.id, "first-owner", Instant::now())
                .is_err()
        );
        let worker = sessions
            .expiry_worker
            .lock()
            .expect("worker slot")
            .take()
            .expect("worker");
        drop(sessions);
        assert!(second.cancellation.is_cancelled());
        tokio::time::timeout(std::time::Duration::from_secs(1), worker)
            .await
            .expect("drop cancels owned expiry work")
            .expect("worker finished");
    }

    #[test]
    fn mcp_drain_revokes_sessions_stateless_calls_and_streams_without_releasing_active_slots() {
        let shutdown = tokio_util::sync::CancellationToken::new();
        let sessions = McpSessions::new(&shutdown);
        let requests = McpRequests::new(shutdown.clone());
        let now = Instant::now();
        let session = sessions.create("owner", now).expect("session");
        session.initialize().expect("initialized");
        let legacy_call = requests.register("owner", &json!(1)).expect("legacy call");
        let bound_call = requests
            .register_scoped("owner", &json!(1), Some(&session))
            .expect("session call");
        let stream = sessions.acquire_stream(&session).expect("response permit");
        let stream_cancellation = session.cancellation.child_token();
        shutdown.cancel();
        assert!(legacy_call.cancellation.is_cancelled());
        assert!(bound_call.cancellation.is_cancelled());
        assert!(stream_cancellation.is_cancelled());
        assert!(!session.is_ready());
        assert!(session.initialize().is_err());
        assert!(requests.register("owner", &json!(2)).is_err());
        assert!(
            requests
                .register_scoped("owner", &json!(2), Some(&session))
                .is_err()
        );
        assert!(sessions.create("owner", now).is_err());
        assert!(sessions.resolve(&session.id, "owner", now).is_err());
        assert!(sessions.acquire_stream(&session).is_err());
        assert_eq!(requests.active.lock().expect("active table").len(), 2);
        assert_eq!(
            sessions.streams.available_permits(),
            super::MAX_MCP_STREAMS - 1
        );
        drop(legacy_call);
        drop(bound_call);
        drop(stream);
        assert!(requests.active.lock().expect("released table").is_empty());
        assert_eq!(sessions.streams.available_permits(), super::MAX_MCP_STREAMS);
    }

    #[test]
    fn mcp_stream_permits_bound_global_and_session_connections_until_body_release() {
        let sessions = McpSessions::default();
        let now = Instant::now();
        let first = sessions.create("owner", now).expect("first session");
        let primary = sessions.acquire_stream(&first).expect("primary stream");
        let secondary = sessions.acquire_stream(&first).expect("secondary stream");
        assert!(matches!(
            sessions.acquire_stream(&first),
            Err(SessionError::Capacity)
        ));
        sessions.close(&first.id, "owner").expect("close session");
        assert!(matches!(
            sessions.acquire_stream(&first),
            Err(SessionError::NotFound)
        ));
        assert_eq!(
            sessions.streams.available_permits(),
            super::MAX_MCP_STREAMS - 2
        );
        drop(primary);
        drop(secondary);
        assert_eq!(sessions.streams.available_permits(), super::MAX_MCP_STREAMS);
        let mut streams = Vec::new();
        let mut contexts = Vec::new();
        for index in 0..super::MAX_MCP_STREAMS {
            let context = sessions
                .create(&format!("owner-{index}"), now)
                .expect("bounded session");
            streams.push(
                sessions
                    .acquire_stream(&context)
                    .expect("bounded global stream"),
            );
            contexts.push(context);
        }
        assert!(matches!(
            sessions.acquire_stream(&contexts[0]),
            Err(SessionError::Capacity)
        ));
        drop(streams.pop());
        assert!(sessions.acquire_stream(&contexts[0]).is_ok());
        drop(streams);
        assert_eq!(sessions.streams.available_permits(), super::MAX_MCP_STREAMS);
    }

    #[test]
    fn mcp_sessions_bind_request_namespaces_and_close_expire_with_bounded_capacity() {
        let sessions = McpSessions::default();
        let now = Instant::now();
        let first = sessions.create("owner", now).expect("first session");
        let second = sessions.create("owner", now).expect("second session");
        assert!(!first.is_ready());
        assert!(!second.is_ready());
        first.initialize().expect("first initialized notification");
        second
            .initialize()
            .expect("second initialized notification");
        assert_ne!(first.id, second.id);
        assert_eq!(first.id.len(), 43);
        assert!(sessions.resolve(&first.id, "other", now).is_err());
        assert_eq!(
            sessions.close(&first.id, "other"),
            Err(SessionError::NotFound)
        );
        let requests = McpRequests::default();
        let first_call = requests
            .register_scoped("owner", &json!(1), Some(&first))
            .expect("first call");
        let second_call = requests
            .register_scoped("owner", &json!(1), Some(&second))
            .expect("same ID other session");
        let legacy_call = requests
            .register("owner", &json!(1))
            .expect("stateless namespace");
        requests.cancel_scoped("owner", &json!(1), Some(&first));
        assert!(first_call.cancellation.is_cancelled());
        assert!(!second_call.cancellation.is_cancelled());
        assert!(!legacy_call.cancellation.is_cancelled());
        sessions
            .close(&second.id, "owner")
            .expect("close owned session");
        assert!(second_call.cancellation.is_cancelled());
        assert!(sessions.resolve(&second.id, "owner", now).is_err());
        assert!(
            requests
                .register_scoped("owner", &json!(2), Some(&second))
                .is_err()
        );
        assert!(
            sessions
                .resolve(&first.id, "owner", now + MCP_SESSION_TTL)
                .is_err()
        );
        assert!(first.cancellation.is_cancelled());

        let bounded = McpSessions::default();
        for index in 0..MAX_MCP_SESSIONS {
            bounded
                .create(&format!("owner-{}", index / MAX_SUBJECT_SESSIONS), now)
                .expect("bounded session");
        }
        assert!(matches!(
            bounded.create("owner-0", now),
            Err(SessionError::Capacity)
        ));
        assert!(matches!(
            bounded.create("new-owner", now),
            Err(SessionError::Capacity)
        ));
        assert!(bounded.create("new-owner", now + MCP_SESSION_TTL).is_ok());
        drop(sessions);
        assert!(first.cancellation.is_cancelled());
        assert!(!legacy_call.cancellation.is_cancelled());
    }

    #[test]
    fn mcp_session_initialization_is_shared_pins_version_and_never_revives_closed_calls() {
        let sessions = McpSessions::default();
        let now = Instant::now();
        let session = sessions
            .create_negotiated("owner", "2024-11-05", now)
            .expect("supported protocol");
        let resolved = sessions
            .resolve(&session.id, "owner", now)
            .expect("same session");
        assert_eq!(resolved.protocol, "2024-11-05");
        let requests = McpRequests::default();
        assert!(
            requests
                .register_scoped("owner", &json!(1), Some(&resolved))
                .is_err()
        );
        session.initialize().expect("initialized");
        assert!(resolved.is_ready());
        let request = requests
            .register_scoped("owner", &json!(1), Some(&resolved))
            .expect("ready request");
        sessions.close(&session.id, "owner").expect("closed");
        assert!(!resolved.is_ready());
        assert!(resolved.initialize().is_err());
        assert!(request.cancellation.is_cancelled());
        assert!(matches!(
            sessions.create_negotiated("owner", "unexpected-version", now),
            Err(SessionError::Protocol)
        ));
    }

    #[test]
    fn mcp_active_requests_are_bounded_owned_exclusive_and_cancelled_on_drop() {
        let requests = McpRequests::default();
        let first = requests
            .register("first", &json!(1))
            .expect("first request");
        let other = requests
            .register("other", &json!(1))
            .expect("other principal");
        let text_id = requests
            .register("first", &json!("1"))
            .expect("distinct typed ID");
        assert!(requests.register("first", &json!(1)).is_err());
        requests.cancel("unknown", &json!(1));
        assert!(!first.cancellation.is_cancelled());
        requests.cancel("first", &json!(1));
        assert!(first.cancellation.is_cancelled());
        assert!(!other.cancellation.is_cancelled());
        assert!(!text_id.cancellation.is_cancelled());
        assert!(
            requests.register("first", &json!(1)).is_err(),
            "cancellation does not release a still-active call"
        );
        let token = other.cancellation.clone();
        drop(other);
        assert!(token.is_cancelled());
        drop(first);
        let replacement = requests
            .register("first", &json!(1))
            .expect("settled ID may be reused");
        assert!(!replacement.cancellation.is_cancelled());
        for invalid in [
            json!(null),
            json!(1.5),
            json!({}),
            json!([]),
            json!("x".repeat(257)),
            json!("line\nbreak"),
        ] {
            assert!(requests.register("first", &invalid).is_err());
        }
        let mut capacity = Vec::new();
        for index in 0..MAX_ACTIVE_SUBJECT_REQUESTS {
            capacity.push(
                requests
                    .register("bounded", &json!(index))
                    .expect("within subject quota"),
            );
        }
        assert!(
            requests
                .register("bounded", &json!(MAX_ACTIVE_SUBJECT_REQUESTS))
                .is_err()
        );
        drop(capacity);
        assert!(requests.register("bounded", &json!(0)).is_ok());

        let global = McpRequests::default();
        let mut entries = Vec::new();
        for index in 0..MAX_ACTIVE_REQUESTS {
            let subject = format!("principal-{}", index / MAX_ACTIVE_SUBJECT_REQUESTS);
            entries.push(
                global
                    .register(&subject, &json!(index))
                    .expect("within global capacity"),
            );
        }
        global.cancel("principal-0", &json!(0));
        assert!(entries[0].cancellation.is_cancelled());
        assert!(
            global.register("new-principal", &json!(1)).is_err(),
            "cancelled but unfinished calls still consume global capacity"
        );
        drop(entries.pop());
        assert!(global.register("new-principal", &json!(1)).is_ok());
    }
}

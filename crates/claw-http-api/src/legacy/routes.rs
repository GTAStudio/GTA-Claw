//! Route handlers and immutable state for the legacy facade.

use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::Instant;

use axum::Router;
use axum::extract::{ConnectInfo, RawQuery, Request, State};
use axum::http::{HeaderMap, HeaderName, HeaderValue, StatusCode, header};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use serde::Deserialize;
use serde_json::{Map, Value, json};
use tokio::time::timeout;
use tokio_util::sync::CancellationToken;
use tower_http::set_header::SetResponseHeaderLayer;

use super::config::{LegacyApiConfig, LegacyConfigError};
use super::ports::{
    LEGACY_ADMIN_ACTIONS, LegacyAdminAction, LegacyApiServices, LegacyChannelMessage,
    LegacyExecResult, LegacyTeamsRequestContext,
};
use super::rate_limit::RateLimiter;
use crate::auth::bearer_token;
use crate::http_support::{
    CancelOnDrop, close_connection_response, drain_request_body, json_response, read_json_value,
    rejected_response,
};
use crate::{PortError, PortErrorKind, ServingStatePort};

const CHAT_HELP: &str = "GTA-Claw HTTP Chat Help\n\nUse: POST /chat with JSON body\n- message (or text/prompt): your question\n- conversation_id (optional): keep context across turns\n\nExamples:\n1) {\"message\":\"hello\"}\n2) {\"message\":\"continue\",\"conversation_id\":\"demo-1\"}\n\nAuth:\n- If not authenticated, call GET /auth/device and complete GitHub Device Flow.";
const WHATSAPP_CHUNK_CHARS: usize = 3_500;
const LEGACY_EXEC_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(15);

#[derive(Clone)]
pub(super) struct LegacyState {
    inner: Arc<LegacyStateInner>,
}

struct LegacyStateInner {
    config: LegacyApiConfig,
    services: LegacyApiServices,
    serving: Arc<dyn ServingStatePort>,
    started: Instant,
    rate_limiter: RateLimiter,
}

impl LegacyState {
    pub(super) fn new(
        config: LegacyApiConfig,
        services: LegacyApiServices,
        serving: Arc<dyn ServingStatePort>,
    ) -> Result<Self, LegacyConfigError> {
        validate_config(&config, &services)?;
        let rate_limiter = RateLimiter::new(
            config.teams_rate_limit_per_minute,
            config.limits.rate_limit_clients,
            config.limits.rate_limit_idle_timeout,
        );
        Ok(Self {
            inner: Arc::new(LegacyStateInner {
                config,
                services,
                serving,
                started: Instant::now(),
                rate_limiter,
            }),
        })
    }
}

fn validate_config(
    config: &LegacyApiConfig,
    services: &LegacyApiServices,
) -> Result<(), LegacyConfigError> {
    if config.default_model.trim().is_empty() {
        return Err(LegacyConfigError::EmptyDefaultModel);
    }
    if config.teams_rate_limit_per_minute == 0
        || config.limits.body_bytes == 0
        || config.limits.rate_limit_clients == 0
        || config.limits.whatsapp_messages == 0
    {
        return Err(LegacyConfigError::ZeroLimit);
    }
    if config.channels.teams() && services.teams.is_none() {
        return Err(LegacyConfigError::MissingTeamsAdapter);
    }
    if config.channels.whatsapp() && (config.whatsapp.is_none() || services.whatsapp.is_none()) {
        return Err(LegacyConfigError::MissingWhatsAppAdapter);
    }
    Ok(())
}

pub(super) fn router(state: LegacyState) -> Router {
    let config = &state.inner.config;
    let mut router = Router::new()
        .route("/", get(root))
        .route("/health", get(health))
        .route("/healthz", get(live))
        .route("/ready", get(ready))
        .route("/readyz", get(ready))
        .route("/auth/device", get(device_auth))
        .route("/chat", post(chat));
    if config.channels.teams() {
        router = router.route("/api/messages", post(teams_messages));
    }
    if config.channels.whatsapp() {
        let path = config
            .whatsapp
            .as_ref()
            .expect("validated WhatsApp configuration")
            .webhook_path()
            .to_owned();
        router = router.route(&path, get(whatsapp_verify).post(whatsapp_incoming));
    }
    if config.admin_credential.is_some() {
        if state.inner.services.reload.is_some() {
            router = router.route("/admin/reload", post(admin_reload));
        }
        if state.inner.services.admin.is_some() {
            router = router
                .route("/admin/system", get(admin_system))
                .route("/admin/exec", post(admin_exec));
        }
    }
    router
        .layer(SetResponseHeaderLayer::if_not_present(
            HeaderName::from_static("x-content-type-options"),
            HeaderValue::from_static("nosniff"),
        ))
        .layer(SetResponseHeaderLayer::if_not_present(
            HeaderName::from_static("referrer-policy"),
            HeaderValue::from_static("no-referrer"),
        ))
        .with_state(state)
}

async fn root(State(state): State<LegacyState>) -> Response {
    let Ok(snapshot) = state.inner.services.runtime.snapshot() else {
        return legacy_error(StatusCode::INTERNAL_SERVER_ERROR, "Runtime unavailable");
    };
    let channels = state.inner.config.channels;
    let mut tips = Vec::with_capacity(2);
    if !snapshot.authenticated && state.inner.config.device_flow_enabled {
        tips.push("Authenticate first via GET /auth/device (or check logs for the user code).");
    }
    if !channels.any_enabled() {
        tips.push("No chat channels enabled. Use POST /chat directly for testing.");
    }
    json_response(
        StatusCode::OK,
        &json!({
            "service":"GTA-Claw",
            "status":"ok",
            "authenticated":snapshot.authenticated,
            "deviceFlowEnabled":state.inner.config.device_flow_enabled,
            "channels":channels,
            "endpoints":{
                "health":"GET /health",
                "deviceAuth":"GET /auth/device",
                "chat":"POST /chat"
            },
            "examples":{
                "chatCurl":"curl -X POST http://localhost:3978/chat -H \"Content-Type: application/json\" -d '{\"message\":\"hello\"}'"
            },
            "tips":tips
        }),
    )
}

async fn health(State(state): State<LegacyState>) -> Response {
    let Ok(snapshot) = state.inner.services.runtime.snapshot() else {
        return legacy_error(StatusCode::INTERNAL_SERVER_ERROR, "Runtime unavailable");
    };
    json_response(
        StatusCode::OK,
        &json!({
            "status":"ok",
            "uptime":state.inner.started.elapsed().as_secs(),
            "skills":snapshot.skill_count,
            "sessions":snapshot.session_count,
            "model":snapshot.active_model,
            "authenticated":snapshot.authenticated,
            "deviceFlowEnabled":state.inner.config.device_flow_enabled,
            "channels":state.inner.config.channels
        }),
    )
}

async fn live(State(state): State<LegacyState>) -> Response {
    let serving = state.inner.serving.serving_state();
    let body = if serving.accepts_work() {
        json!({"ok":true,"status":"live"})
    } else {
        json!({"ok":true,"status":"live","phase":serving.phase()})
    };
    no_store(json_response(StatusCode::OK, &body))
}

async fn ready(State(state): State<LegacyState>, request: Request) -> Response {
    let include_details = exact_admin(&state, request.headers());
    let serving = state.inner.serving.serving_state();
    let (dependencies_ready, mut failing, uptime_ms) =
        match state.inner.services.readiness.snapshot() {
            Ok(snapshot) => (snapshot.ready, snapshot.failing, snapshot.uptime_ms),
            Err(_) => (false, vec!["internal".to_owned()], 0),
        };
    if !serving.accepts_work() {
        failing.insert(0, serving.phase().to_owned());
    }
    let ready = serving.accepts_work() && dependencies_ready;
    let status = if ready {
        StatusCode::OK
    } else {
        StatusCode::SERVICE_UNAVAILABLE
    };
    let body = if include_details {
        json!({"ready":ready,"failing":failing,"uptimeMs":uptime_ms})
    } else {
        json!({"ready":ready})
    };
    no_store(json_response(status, &body))
}

async fn device_auth(State(state): State<LegacyState>) -> Response {
    if let Some(response) = refusal_while_draining(&state) {
        return response;
    }
    let Ok(snapshot) = state.inner.services.runtime.snapshot() else {
        return legacy_error(StatusCode::INTERNAL_SERVER_ERROR, "Runtime unavailable");
    };
    if snapshot.authenticated {
        return json_response(
            StatusCode::OK,
            &json!({"authenticated":true,"message":"Already authenticated."}),
        );
    }
    let Some(device_flow) = state
        .inner
        .config
        .device_flow_enabled
        .then(|| state.inner.services.device_flow.clone())
        .flatten()
    else {
        return json_response(
            StatusCode::BAD_REQUEST,
            &json!({
                "authenticated":false,
                "error":"Device Flow is disabled. Set DEVICE_FLOW_ENABLED=true and GITHUB_CLIENT_ID."
            }),
        );
    };
    let cancellation = CancellationToken::new();
    let _cancel_on_drop = CancelOnDrop::new(&cancellation);
    match timeout(
        state.inner.config.limits.operation_timeout,
        device_flow.instructions(cancellation),
    )
    .await
    {
        Ok(Ok(instructions)) => json_response(
            StatusCode::OK,
            &json!({"authenticated":false,"auth_instructions":instructions}),
        ),
        Ok(Err(_)) | Err(_) => legacy_error(
            StatusCode::INTERNAL_SERVER_ERROR,
            "Failed to get Device Flow instructions",
        ),
    }
}

async fn chat(
    State(state): State<LegacyState>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    request: Request,
) -> Response {
    if !state.inner.serving.serving_state().accepts_work() {
        return drain_for_refusal(&state, request, draining_error()).await;
    }
    let value = match read_legacy_json(&state, request).await {
        Ok(value) => value,
        Err(response) => return response,
    };
    let object = value.as_object();
    let message = first_string(object, &["message", "text", "prompt"]).map_or("", str::trim);
    if message.is_empty() {
        return legacy_error(StatusCode::BAD_REQUEST, "Missing 'message' field");
    }
    if message.eq_ignore_ascii_case("/help") || message.eq_ignore_ascii_case("/start") {
        return json_response(StatusCode::OK, &json!({"reply":CHAT_HELP}));
    }
    let Ok(snapshot) = state.inner.services.runtime.snapshot() else {
        return legacy_error(StatusCode::INTERNAL_SERVER_ERROR, "Internal error");
    };
    if !snapshot.authenticated {
        if let Some(device_flow) = state
            .inner
            .config
            .device_flow_enabled
            .then(|| state.inner.services.device_flow.clone())
            .flatten()
        {
            let cancellation = CancellationToken::new();
            let _cancel_on_drop = CancelOnDrop::new(&cancellation);
            return match timeout(
                state.inner.config.limits.operation_timeout,
                device_flow.instructions(cancellation),
            )
            .await
            {
                Ok(Ok(instructions)) => json_response(
                    StatusCode::UNAUTHORIZED,
                    &json!({"error":"Not authenticated","auth_instructions":instructions}),
                ),
                Ok(Err(_)) | Err(_) => {
                    legacy_error(StatusCode::INTERNAL_SERVER_ERROR, "Internal error")
                }
            };
        }
        return legacy_error(
            StatusCode::UNAUTHORIZED,
            "Not authenticated. Set GITHUB_TOKEN or enable Device Flow.",
        );
    }
    let conversation_id = first_string(object, &["conversation_id", "conversationId"])
        .map_or_else(|| format!("http-{}", peer.ip()), str::to_owned);
    let cancellation = CancellationToken::new();
    let _cancel_on_drop = CancelOnDrop::new(&cancellation);
    match timeout(
        state.inner.config.limits.operation_timeout,
        state
            .inner
            .services
            .runtime
            .chat(conversation_id, message.to_owned(), cancellation),
    )
    .await
    {
        Ok(Ok(reply)) => json_response(StatusCode::OK, &json!({"reply":reply})),
        Ok(Err(_)) | Err(_) => legacy_error(StatusCode::INTERNAL_SERVER_ERROR, "Internal error"),
    }
}

async fn teams_messages(
    State(state): State<LegacyState>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    request: Request,
) -> Response {
    if !state.inner.serving.serving_state().accepts_work() {
        return drain_for_refusal(&state, request, draining_error()).await;
    }
    let client = client_identity(&state, request.headers(), peer.ip());
    match state.inner.rate_limiter.is_allowed(&client) {
        Ok(true) => {}
        Ok(false) => {
            return drain_for_refusal(
                &state,
                request,
                legacy_error(StatusCode::TOO_MANY_REQUESTS, "Too many requests"),
            )
            .await;
        }
        Err(_) => {
            return drain_for_refusal(
                &state,
                request,
                legacy_error(StatusCode::INTERNAL_SERVER_ERROR, "Internal error"),
            )
            .await;
        }
    }
    let context = LegacyTeamsRequestContext::from_headers(request.headers());
    let activity = match read_legacy_json(&state, request).await {
        Ok(value) => value,
        Err(response) => return response,
    };
    let Ok(context) = context else {
        return legacy_error(StatusCode::BAD_REQUEST, "Invalid Authorization header");
    };
    let teams = state
        .inner
        .services
        .teams
        .as_ref()
        .expect("validated Teams adapter")
        .clone();
    let cancellation = CancellationToken::new();
    let _cancel_on_drop = CancelOnDrop::new(&cancellation);
    match timeout(
        state.inner.config.limits.operation_timeout,
        teams.handle_activity(context, activity, cancellation),
    )
    .await
    {
        Ok(Ok(())) => json_response(StatusCode::OK, &Value::Null),
        Ok(Err(_)) | Err(_) => legacy_error(StatusCode::INTERNAL_SERVER_ERROR, "Internal error"),
    }
}

async fn whatsapp_verify(
    State(state): State<LegacyState>,
    RawQuery(raw_query): RawQuery,
) -> Response {
    let mut mode = None;
    let mut token = None;
    let mut challenge = None;
    for (name, value) in
        url::form_urlencoded::parse(raw_query.as_deref().unwrap_or_default().as_bytes())
    {
        match name.as_ref() {
            "hub.mode" => mode = Some(value.into_owned()),
            "hub.verify_token" => token = Some(value.into_owned()),
            "hub.challenge" => challenge = Some(value.into_owned()),
            _ => {}
        }
    }
    let config = state
        .inner
        .config
        .whatsapp
        .as_ref()
        .expect("validated WhatsApp configuration");
    if mode.as_deref() == Some("subscribe")
        && token.as_deref().is_some_and(|token| config.verifies(token))
        && challenge.as_deref().is_some_and(|value| !value.is_empty())
    {
        let mut response = (StatusCode::OK, challenge.unwrap_or_default()).into_response();
        response
            .headers_mut()
            .insert(header::CONTENT_TYPE, HeaderValue::from_static("text/plain"));
        return response;
    }
    legacy_error(StatusCode::FORBIDDEN, "Forbidden")
}

async fn whatsapp_incoming(State(state): State<LegacyState>, request: Request) -> Response {
    if !state.inner.serving.serving_state().accepts_work() {
        return drain_for_refusal(&state, request, draining_error()).await;
    }
    let value = match read_legacy_json(&state, request).await {
        Ok(value) => value,
        Err(response) => return response,
    };
    let body: WhatsAppBody = match serde_json::from_value(value) {
        Ok(body) => body,
        Err(_) => {
            return legacy_error(StatusCode::BAD_REQUEST, "Webhook handling failed");
        }
    };
    let services = state
        .inner
        .services
        .whatsapp
        .as_ref()
        .expect("validated WhatsApp adapters")
        .clone();
    let cancellation = CancellationToken::new();
    let _cancel_on_drop = CancelOnDrop::new(&cancellation);
    match timeout(
        state.inner.config.limits.operation_timeout,
        process_whatsapp(&state, services, body, cancellation),
    )
    .await
    {
        Ok(Ok(())) => json_response(StatusCode::OK, &json!({"ok":true})),
        Ok(Err(_)) | Err(_) => {
            legacy_error(StatusCode::INTERNAL_SERVER_ERROR, "Webhook handling failed")
        }
    }
}

async fn admin_reload(State(state): State<LegacyState>, request: Request) -> Response {
    if !exact_admin(&state, request.headers()) {
        return drain_for_refusal(
            &state,
            request,
            legacy_error(StatusCode::FORBIDDEN, "Forbidden"),
        )
        .await;
    }
    if !state.inner.serving.serving_state().accepts_work() {
        return drain_for_refusal(&state, request, draining_error()).await;
    }
    if let Err(error) = drain_request_body(
        request,
        state.inner.config.limits.body_bytes,
        state.inner.config.limits.body_timeout,
    )
    .await
    {
        return close_connection_response(legacy_error(error.status, "Invalid request body"));
    }
    let reload = state
        .inner
        .services
        .reload
        .as_ref()
        .expect("registered reload adapter")
        .clone();
    let cancellation = CancellationToken::new();
    let _cancel_on_drop = CancelOnDrop::new(&cancellation);
    match timeout(
        state.inner.config.limits.operation_timeout,
        reload.reload(cancellation),
    )
    .await
    {
        Ok(Ok(result)) => json_response(
            StatusCode::OK,
            &json!({
                "message":"Reloaded",
                "skills":result.skill_count,
                "model":result.role_model.unwrap_or_else(||state.inner.config.default_model.clone())
            }),
        ),
        Ok(Err(super::ports::LegacyReloadError::InProgress)) => {
            legacy_error(StatusCode::CONFLICT, "Reload already in progress")
        }
        Ok(Err(super::ports::LegacyReloadError::Failed)) | Err(_) => {
            legacy_error(StatusCode::INTERNAL_SERVER_ERROR, "Reload failed")
        }
    }
}

async fn admin_system(
    State(state): State<LegacyState>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    request: Request,
) -> Response {
    if !admin_or_loopback(&state, request.headers(), peer.ip()) {
        return legacy_error(StatusCode::FORBIDDEN, "Forbidden");
    }
    let admin = state
        .inner
        .services
        .admin
        .as_ref()
        .expect("registered admin adapter")
        .clone();
    let cancellation = CancellationToken::new();
    let _cancel_on_drop = CancelOnDrop::new(&cancellation);
    match timeout(
        state.inner.config.limits.operation_timeout,
        admin.system_info(cancellation),
    )
    .await
    {
        Ok(Ok(info)) => {
            let body = serde_json::to_value(info).expect("legacy system info is serializable");
            json_response(StatusCode::OK, &body)
        }
        Ok(Err(_)) | Err(_) => legacy_error(StatusCode::INTERNAL_SERVER_ERROR, "Internal error"),
    }
}

async fn admin_exec(
    State(state): State<LegacyState>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    request: Request,
) -> Response {
    if !admin_or_loopback(&state, request.headers(), peer.ip()) {
        return drain_for_refusal(
            &state,
            request,
            legacy_error(StatusCode::FORBIDDEN, "Forbidden"),
        )
        .await;
    }
    if !state.inner.serving.serving_state().accepts_work() {
        return drain_for_refusal(&state, request, draining_error()).await;
    }
    let value = match read_legacy_json(&state, request).await {
        Ok(value) => value,
        Err(response) => return response,
    };
    let object = value.as_object();
    let action_name = object
        .and_then(|object| object.get("action"))
        .and_then(Value::as_str)
        .unwrap_or("");
    let Some(action) = LegacyAdminAction::parse(action_name) else {
        return json_response(
            StatusCode::BAD_REQUEST,
            &json!({
                "error":format!("Unknown action: {action_name}"),
                "allowed":LEGACY_ADMIN_ACTIONS
            }),
        );
    };
    let target = object
        .and_then(|object| object.get("target"))
        .and_then(Value::as_str)
        .map(sanitize_target)
        .filter(|target| !target.is_empty());
    let admin = state
        .inner
        .services
        .admin
        .as_ref()
        .expect("registered admin adapter")
        .clone();
    let cancellation = CancellationToken::new();
    let _cancel_on_drop = CancelOnDrop::new(&cancellation);
    let outcome = match timeout(
        state
            .inner
            .config
            .limits
            .operation_timeout
            .min(LEGACY_EXEC_TIMEOUT),
        admin.execute(action, target, cancellation),
    )
    .await
    {
        Ok(Ok(outcome)) => outcome,
        Ok(Err(error)) => LegacyExecResult {
            success: false,
            output: None,
            error: Some(error.message),
            stderr: None,
        },
        Err(_) => LegacyExecResult {
            success: false,
            output: None,
            error: Some("Command timed out".to_owned()),
            stderr: None,
        },
    };
    exec_response(action, outcome)
}

fn exec_response(action: LegacyAdminAction, mut outcome: LegacyExecResult) -> Response {
    truncate_option(&mut outcome.output, 10_000);
    truncate_option(&mut outcome.error, 500);
    truncate_option(
        &mut outcome.stderr,
        if outcome.success { 1_000 } else { 2_000 },
    );
    let mut body = Map::with_capacity(5);
    body.insert("action".to_owned(), json!(action.as_str()));
    body.insert("success".to_owned(), json!(outcome.success));
    if outcome.success {
        body.insert(
            "output".to_owned(),
            json!(outcome.output.unwrap_or_default()),
        );
    } else {
        body.insert(
            "error".to_owned(),
            json!(outcome.error.unwrap_or_else(|| "Command failed".to_owned())),
        );
    }
    if let Some(stderr) = outcome.stderr.filter(|stderr| !stderr.is_empty()) {
        body.insert("stderr".to_owned(), json!(stderr));
    }
    json_response(StatusCode::OK, &Value::Object(body))
}

async fn process_whatsapp(
    state: &LegacyState,
    services: super::ports::LegacyWhatsAppServices,
    body: WhatsAppBody,
    cancellation: CancellationToken,
) -> Result<(), PortError> {
    let mut traversed = 0_usize;
    for entry in body.entry {
        for change in entry.changes {
            for message in change.value.messages {
                traversed += 1;
                if traversed > state.inner.config.limits.whatsapp_messages {
                    return Err(PortError::new(
                        PortErrorKind::InvalidRequest,
                        "too many WhatsApp messages",
                    ));
                }
                if message.kind.as_deref() != Some("text") {
                    continue;
                }
                let Some(text) = message
                    .text
                    .and_then(|text| text.body)
                    .map(|text| text.trim().to_owned())
                    .filter(|text| !text.is_empty())
                else {
                    continue;
                };
                let Some(from) = message.from.filter(|from| !from.trim().is_empty()) else {
                    continue;
                };
                let reply = services
                    .messages
                    .process(
                        LegacyChannelMessage {
                            channel: "whatsapp",
                            conversation_id: format!("whatsapp:{from}"),
                            user_name: from.clone(),
                            text,
                        },
                        cancellation.clone(),
                    )
                    .await?;
                if reply.trim().is_empty() {
                    continue;
                }
                if reply.len() > state.inner.config.limits.body_bytes {
                    return Err(PortError::new(
                        PortErrorKind::InvalidRequest,
                        "WhatsApp reply exceeds the byte limit",
                    ));
                }
                for chunk in split_message(&reply, WHATSAPP_CHUNK_CHARS) {
                    services
                        .sender
                        .send_text(from.clone(), chunk, cancellation.clone())
                        .await?;
                }
            }
        }
    }
    Ok(())
}

fn split_message(text: &str, max_chars: usize) -> Vec<String> {
    if text.chars().count() <= max_chars {
        return vec![text.to_owned()];
    }
    let mut chunks = Vec::new();
    let mut remaining = text;
    while remaining.chars().count() > max_chars {
        let hard_end = byte_after_chars(remaining, max_chars);
        let candidate = &remaining[..hard_end];
        let mut split_at = candidate.rfind('\n').unwrap_or(0);
        if candidate[..split_at].chars().count() < max_chars / 2 {
            split_at = candidate.rfind(' ').unwrap_or(0);
        }
        if candidate[..split_at].chars().count() < max_chars * 3 / 10 {
            split_at = hard_end;
        }
        chunks.push(remaining[..split_at].to_owned());
        remaining = remaining[split_at..].trim_start();
    }
    if !remaining.is_empty() {
        chunks.push(remaining.to_owned());
    }
    chunks
}

fn byte_after_chars(value: &str, count: usize) -> usize {
    value
        .char_indices()
        .nth(count)
        .map_or(value.len(), |(index, _)| index)
}

fn first_string<'a>(object: Option<&'a Map<String, Value>>, names: &[&str]) -> Option<&'a str> {
    names.iter().find_map(|name| {
        object
            .and_then(|object| object.get(*name))
            .and_then(Value::as_str)
    })
}

fn client_identity(state: &LegacyState, headers: &HeaderMap, remote: IpAddr) -> String {
    if state.inner.config.trust_proxy
        && let Some(forwarded) = headers
            .get("x-forwarded-for")
            .and_then(|value| value.to_str().ok())
            .and_then(|value| value.split(',').next())
            .map(str::trim)
            .filter(|value| !value.is_empty() && value.len() <= 128)
    {
        return forwarded.to_owned();
    }
    remote.to_string()
}

fn exact_admin(state: &LegacyState, headers: &HeaderMap) -> bool {
    state
        .inner
        .config
        .admin_credential
        .as_ref()
        .zip(bearer_token(headers))
        .is_some_and(|(credential, token)| credential.verifies(token))
}

fn admin_or_loopback(state: &LegacyState, headers: &HeaderMap, peer: IpAddr) -> bool {
    exact_admin(state, headers) || is_loopback(peer)
}

fn is_loopback(peer: IpAddr) -> bool {
    match peer {
        IpAddr::V4(address) => address.is_loopback(),
        IpAddr::V6(address) => {
            address.is_loopback() || address.to_ipv4_mapped().is_some_and(|ip| ip.is_loopback())
        }
    }
}

fn sanitize_target(target: &str) -> String {
    target
        .chars()
        .filter(|character| {
            character.is_ascii_alphanumeric() || matches!(character, '_' | '-' | '.')
        })
        .collect()
}

fn truncate_option(value: &mut Option<String>, max_bytes: usize) {
    if let Some(value) = value {
        let mut boundary = value.len().min(max_bytes);
        while !value.is_char_boundary(boundary) {
            boundary -= 1;
        }
        value.truncate(boundary);
    }
}

fn refusal_while_draining(state: &LegacyState) -> Option<Response> {
    (!state.inner.serving.serving_state().accepts_work()).then(draining_error)
}

fn draining_error() -> Response {
    legacy_error(StatusCode::SERVICE_UNAVAILABLE, "Service draining")
}

async fn drain_for_refusal(state: &LegacyState, request: Request, response: Response) -> Response {
    rejected_response(
        request,
        state.inner.config.limits.body_bytes,
        state.inner.config.limits.body_timeout,
        response,
    )
    .await
}

async fn read_legacy_json(state: &LegacyState, request: Request) -> Result<Value, Response> {
    read_json_value(
        request,
        state.inner.config.limits.body_bytes,
        state.inner.config.limits.body_timeout,
    )
    .await
    .map_err(|error| {
        let status = error.status;
        let message = match status {
            StatusCode::PAYLOAD_TOO_LARGE => "Payload too large",
            StatusCode::REQUEST_TIMEOUT => "Request body timeout",
            _ => "Invalid request body",
        };
        let response = legacy_error(status, message);
        if matches!(
            status,
            StatusCode::PAYLOAD_TOO_LARGE | StatusCode::REQUEST_TIMEOUT
        ) {
            close_connection_response(response)
        } else {
            response
        }
    })
}

fn legacy_error(status: StatusCode, message: &str) -> Response {
    json_response(status, &json!({"error":message}))
}

fn no_store(mut response: Response) -> Response {
    response
        .headers_mut()
        .insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    response
}

#[derive(Deserialize, Default)]
struct WhatsAppBody {
    #[serde(default)]
    entry: Vec<WhatsAppEntry>,
}

#[derive(Deserialize, Default)]
struct WhatsAppEntry {
    #[serde(default)]
    changes: Vec<WhatsAppChange>,
}

#[derive(Deserialize, Default)]
struct WhatsAppChange {
    #[serde(default)]
    value: WhatsAppValue,
}

#[derive(Deserialize, Default)]
struct WhatsAppValue {
    #[serde(default)]
    messages: Vec<WhatsAppMessage>,
}

#[derive(Deserialize)]
struct WhatsAppMessage {
    from: Option<String>,
    #[serde(rename = "type")]
    kind: Option<String>,
    text: Option<WhatsAppText>,
}

#[derive(Deserialize)]
struct WhatsAppText {
    body: Option<String>,
}

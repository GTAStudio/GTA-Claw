//! Concrete adapters consumed by the legacy HTTP compatibility facade.

use std::collections::{BTreeMap, VecDeque};
use std::num::NonZeroUsize;
use std::process::{Command as BlockingCommand, Stdio};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex, PoisonError, RwLock};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use claw_channel_sdk::{
    Channel, ChannelCredential, ChannelError, CredentialBinding, CredentialKind, CredentialRequest,
    NetworkOrigin, OriginTrustError, OriginTrustStore, OutboundMessage, authorize_origin,
};
use claw_channels::{
    AuthenticationPrompt, DiagnosticLevel, DiagnosticSink, OperatorDiagnostic, SystemClock,
    TeamsAction, TeamsActivityHandler, TeamsActivityOutcome, WhatsAppChannel, WhatsAppSendRequest,
    WhatsAppTransport, segment_outbound_text_iter, verify_whatsapp_webhook_signature,
};
use claw_http_api::{
    LegacyAdminAction, LegacyChannelMessage, LegacyChannelMessagePort, LegacyDeviceFlowPort,
    LegacyExecResult, LegacyHostAdminPort, LegacyOsInfo, LegacyProcessInfo, LegacyProcessMemory,
    LegacySystemInfo, LegacyTeamsPort, LegacyTeamsRequestContext, LegacyWhatsAppPort, PortError,
    PortErrorKind, PortFuture,
};
use claw_provider_sdk::http::{Body, HttpRequest, HttpTransport, Method};
use claw_provider_sdk::{BoundSecret, CancelToken, Operation, Origin, SecretString};
use claw_providers::{DeviceFlow, DeviceFlowSession};
use jsonwebtoken::{Algorithm, DecodingKey, Validation, decode, decode_header};
use serde::Deserialize;
use serde::de::DeserializeOwned;
use serde_json::{Value, json};
use tokio::io::{AsyncRead, AsyncReadExt};
use tokio::process::Command;
use tokio::sync::Mutex as AsyncMutex;
use tokio::task::JoinHandle;
use tokio_util::sync::CancellationToken;
use url::Url;

use super::agent_runtime::AgentRuntime;
use super::http_api::Diagnostics;

const ADMIN_OUTPUT_LIMIT: usize = 1024 * 1024;
const TEAMS_OPENID_CONFIGURATION: &str =
    "https://login.botframework.com/v1/.well-known/openidconfiguration";
const TEAMS_JWT_CACHE_TTL: Duration = Duration::from_hours(1);
const TEAMS_JWT_DOCUMENT_LIMIT: usize = 1024 * 1024;

/// Activates a provider from a GitHub OAuth token obtained by Device Flow.
pub trait DeviceTokenActivator: Send + Sync {
    /// Builds and publishes the provider.
    fn activate(
        &self,
        token: SecretString,
        cancellation: CancelToken,
    ) -> PortFuture<'_, Result<(), PortError>>;
}

struct TerminationGuard(Arc<AtomicU64>);

impl Drop for TerminationGuard {
    fn drop(&mut self) {
        self.0.fetch_add(1, Ordering::SeqCst);
    }
}

struct DeviceInstructionsGuard {
    shared: Arc<RwLock<Option<String>>>,
    current: String,
}

impl DeviceInstructionsGuard {
    const fn new(shared: Arc<RwLock<Option<String>>>, current: String) -> Self {
        Self { shared, current }
    }
}

impl Drop for DeviceInstructionsGuard {
    fn drop(&mut self) {
        let mut instructions = self.shared.write().unwrap_or_else(PoisonError::into_inner);
        if instructions.as_deref() == Some(self.current.as_str()) {
            *instructions = None;
        }
    }
}

/// Task accounting for Device Flow shutdown.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DeviceTaskReport {
    /// Poll tasks accepted.
    pub spawned: u64,
    /// Poll tasks joined or aborted.
    pub terminated: u64,
    /// Poll task forcibly abandoned at the deadline.
    pub abandoned: u32,
}

/// Reusable Device Flow instructions plus one tracked bounded poller.
pub struct LegacyDeviceFlowAdapter {
    flow: Arc<DeviceFlowSession>,
    activator: Arc<dyn DeviceTokenActivator>,
    single_flight: AsyncMutex<()>,
    task: AsyncMutex<Option<JoinHandle<()>>>,
    active_cancel: AsyncMutex<Option<CancelToken>>,
    instructions: Arc<RwLock<Option<String>>>,
    diagnostics: Arc<Diagnostics>,
    stopping: AtomicBool,
    spawned: Arc<AtomicU64>,
    terminated: Arc<AtomicU64>,
}

impl Drop for LegacyDeviceFlowAdapter {
    fn drop(&mut self) {
        self.stopping.store(true, Ordering::Release);
        if let Ok(active) = self.active_cancel.try_lock()
            && let Some(cancel) = active.as_ref()
        {
            cancel.cancel();
        }
        if let Ok(task) = self.task.try_lock()
            && let Some(task) = task.as_ref()
        {
            task.abort();
        }
    }
}

impl LegacyDeviceFlowAdapter {
    /// Creates a Device Flow adapter.
    #[must_use]
    pub fn new(
        flow: DeviceFlow,
        activator: Arc<dyn DeviceTokenActivator>,
        instructions: Arc<RwLock<Option<String>>>,
        diagnostics: Arc<Diagnostics>,
    ) -> Arc<Self> {
        Arc::new(Self {
            flow: Arc::new(DeviceFlowSession::new(flow)),
            activator,
            single_flight: AsyncMutex::new(()),
            task: AsyncMutex::new(None),
            active_cancel: AsyncMutex::new(None),
            instructions,
            diagnostics,
            stopping: AtomicBool::new(false),
            spawned: Arc::new(AtomicU64::new(0)),
            terminated: Arc::new(AtomicU64::new(0)),
        })
    }

    /// Cancels and joins the active poller within `budget`.
    pub async fn shutdown(&self, budget: Duration) -> DeviceTaskReport {
        let started = Instant::now();
        self.stopping.store(true, Ordering::Release);
        let active_cancel = self.active_cancel.lock().await.take();
        if let Some(cancel) = active_cancel {
            cancel.cancel();
        }
        let _ = self.flow.clear().await;
        *self
            .instructions
            .write()
            .unwrap_or_else(PoisonError::into_inner) = None;
        let Ok(_single_flight) = tokio::time::timeout(budget, self.single_flight.lock()).await
        else {
            return DeviceTaskReport {
                spawned: self.spawned.load(Ordering::SeqCst),
                terminated: self.terminated.load(Ordering::SeqCst),
                abandoned: 1,
            };
        };
        let task = self.task.lock().await.take();
        let abandoned = if let Some(mut task) = task
            && tokio::time::timeout(budget.saturating_sub(started.elapsed()), &mut task)
                .await
                .is_err()
        {
            task.abort();
            let _ = task.await;
            1
        } else {
            0
        };
        DeviceTaskReport {
            spawned: self.spawned.load(Ordering::SeqCst),
            terminated: self.terminated.load(Ordering::SeqCst),
            abandoned,
        }
    }

    fn instructions_for(
        authorization: &claw_providers::github_copilot::DeviceAuthorization,
    ) -> String {
        format!(
            "Please authorize GTA-Claw with your GitHub account:\n1. Open: {}\n2. Enter code: **{}**",
            authorization.verification_uri, authorization.user_code
        )
    }
}

impl LegacyDeviceFlowPort for LegacyDeviceFlowAdapter {
    fn instructions(
        &self,
        cancellation: CancellationToken,
    ) -> PortFuture<'_, Result<String, PortError>> {
        Box::pin(async move {
            let _single_flight = self.single_flight.lock().await;
            if self.stopping.load(Ordering::Acquire) {
                return Err(PortError::new(
                    PortErrorKind::Unavailable,
                    "Device Flow is shutting down",
                ));
            }
            if let Some(pending) = self.flow.pending().await {
                return Ok(Self::instructions_for(&pending));
            }

            let active_cancel = self.active_cancel.lock().await.take();
            if let Some(cancel) = active_cancel {
                cancel.cancel();
            }
            let previous = self.task.lock().await.take();
            if let Some(previous) = previous {
                if !previous.is_finished() {
                    previous.abort();
                }
                let _ = previous.await;
            }

            let sdk_cancel = CancelToken::new();
            *self.active_cancel.lock().await = Some(sdk_cancel.clone());
            let authorization = tokio::select! {
                result = self.flow.begin(&sdk_cancel) => {
                    result.map_err(|error| provider_port_error(&error))?
                },
                () = cancellation.cancelled() => {
                    sdk_cancel.cancel();
                    return Err(PortError::new(PortErrorKind::Unavailable, "request cancelled"));
                }
            };
            if self.stopping.load(Ordering::Acquire) {
                sdk_cancel.cancel();
                return Err(PortError::new(
                    PortErrorKind::Unavailable,
                    "Device Flow is shutting down",
                ));
            }
            let instructions = Self::instructions_for(&authorization);
            *self
                .instructions
                .write()
                .unwrap_or_else(PoisonError::into_inner) = Some(instructions.clone());
            self.spawned.fetch_add(1, Ordering::SeqCst);

            let flow = Arc::clone(&self.flow);
            let activator = Arc::clone(&self.activator);
            let diagnostics = Arc::clone(&self.diagnostics);
            let terminated = Arc::clone(&self.terminated);
            let prompt_guard =
                DeviceInstructionsGuard::new(Arc::clone(&self.instructions), instructions.clone());
            let task = tokio::spawn(async move {
                let _guard = TerminationGuard(terminated);
                let _prompt_guard = prompt_guard;
                match flow
                    .activate_with(&sdk_cancel, |token, cancel| async {
                        activator.activate(token, cancel).await.map_err(|error| {
                            claw_provider_sdk::ProviderError::new(
                                claw_provider_sdk::ErrorKind::Server,
                                "github-copilot",
                                Operation::Authorize,
                                error.message,
                            )
                        })
                    })
                    .await
                {
                    Ok(()) => diagnostics.record("GitHub Device Flow activated the provider"),
                    Err(error) => diagnostics.record(format!(
                        "GitHub Device Flow polling ended: {}",
                        error.kind().as_str()
                    )),
                }
            });
            *self.task.lock().await = Some(task);
            Ok(instructions)
        })
    }
}

struct ChannelDiagnostics(Arc<Diagnostics>);

impl DiagnosticSink for ChannelDiagnostics {
    fn record(&mut self, diagnostic: OperatorDiagnostic<'_>) {
        self.0.record(format!("channel: {diagnostic}"));
        match diagnostic.level {
            DiagnosticLevel::Info => tracing::info!(
                channel = diagnostic.channel_id,
                code = %diagnostic.code,
                "channel diagnostic"
            ),
            DiagnosticLevel::Warning => tracing::warn!(
                channel = diagnostic.channel_id,
                code = %diagnostic.code,
                "channel diagnostic"
            ),
            DiagnosticLevel::Error => tracing::error!(
                channel = diagnostic.channel_id,
                code = %diagnostic.code,
                "channel diagnostic"
            ),
        }
    }
}

struct ExactOriginTrust {
    channel: &'static str,
    account: String,
    host: &'static str,
}

impl OriginTrustStore for ExactOriginTrust {
    fn is_enrolled(
        &self,
        channel_id: &str,
        account_id: &str,
        origin: &NetworkOrigin,
    ) -> Result<bool, OriginTrustError> {
        Ok(channel_id == self.channel
            && account_id == self.account
            && origin.host() == self.host
            && origin.port().is_none_or(|port| port == 443))
    }
}

fn official_origin(
    channel: &'static str,
    account: &str,
    host: &'static str,
) -> Result<claw_channel_sdk::ApprovedOrigin, PortError> {
    let origin = NetworkOrigin::https(host, None)
        .map_err(|error| invalid(format!("{channel} origin is invalid: {error}")))?;
    authorize_origin(
        &ExactOriginTrust {
            channel,
            account: account.to_owned(),
            host,
        },
        channel,
        account,
        &origin,
    )
    .map_err(|error| invalid(format!("{channel} origin is not enrolled: {error}")))
}

/// Teams activity adapter over the integrated channel state machine.
pub struct LegacyTeamsAdapter {
    runtime: Arc<AgentRuntime>,
    handler: Mutex<TeamsActivityHandler>,
    authentication: Arc<RwLock<Option<String>>>,
    diagnostics: Arc<Diagnostics>,
    transport: HttpTransport,
    app_id: String,
    app_password: SecretString,
    token: AsyncMutex<Option<CachedTeamsToken>>,
    jwt_keys: AsyncMutex<Option<CachedTeamsJwtKeys>>,
    jwt_last_refresh: AsyncMutex<Option<Instant>>,
    replies: Mutex<VecDeque<String>>,
}

enum PendingTeamsDispatch {
    Actions(Vec<TeamsAction>),
    Command(String),
}

#[derive(Clone)]
struct CachedTeamsToken {
    token: SecretString,
    expires_at: Instant,
}

struct CachedTeamsJwtKeys {
    issuer: String,
    keys: BTreeMap<String, TeamsRsaKey>,
    expires_at: Instant,
}

#[derive(Clone)]
struct TeamsRsaKey {
    modulus: String,
    exponent: String,
    endorsements: Vec<String>,
}

#[derive(Deserialize)]
struct TeamsOpenIdConfiguration {
    issuer: String,
    jwks_uri: String,
}

#[derive(Deserialize)]
struct TeamsJwkSet {
    keys: Vec<TeamsJwk>,
}

#[derive(Deserialize)]
struct TeamsJwk {
    kid: String,
    kty: String,
    n: String,
    e: String,
    #[serde(default)]
    alg: Option<String>,
    #[serde(rename = "use", default)]
    usage: Option<String>,
    #[serde(default)]
    endorsements: Vec<String>,
}

#[derive(Deserialize)]
struct TeamsClaims {
    serviceurl: String,
}

impl LegacyTeamsAdapter {
    /// Creates a Teams activity adapter.
    ///
    /// # Errors
    ///
    /// Returns an invalid-request error when the integrated Teams state machine
    /// rejects account routing or startup.
    pub fn new(
        runtime: Arc<AgentRuntime>,
        transport: HttpTransport,
        app_id: String,
        app_password: SecretString,
        authentication: Arc<RwLock<Option<String>>>,
        diagnostics: Arc<Diagnostics>,
    ) -> Result<Arc<Self>, PortError> {
        let action_capacity = NonZeroUsize::new(64)
            .ok_or_else(|| invalid("Teams action capacity must be non-zero"))?;
        let mut handler =
            TeamsActivityHandler::new(app_id.clone(), app_id.clone(), None, action_capacity)
                .map_err(|error| invalid(format!("Teams handler configuration: {error}")))?;
        handler
            .start(&mut ChannelDiagnostics(Arc::clone(&diagnostics)))
            .map_err(|error| invalid(format!("Teams handler startup: {error}")))?;
        Ok(Arc::new(Self {
            runtime,
            handler: Mutex::new(handler),
            authentication,
            diagnostics,
            transport,
            app_id,
            app_password,
            token: AsyncMutex::new(None),
            jwt_keys: AsyncMutex::new(None),
            jwt_last_refresh: AsyncMutex::new(None),
            replies: Mutex::new(VecDeque::with_capacity(16)),
        }))
    }

    /// Returns the most recent reply retained for transport diagnostics.
    #[must_use]
    pub fn last_reply(&self) -> Option<String> {
        self.replies
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .back()
            .cloned()
    }
}

impl LegacyTeamsPort for LegacyTeamsAdapter {
    fn handle_activity(
        &self,
        context: LegacyTeamsRequestContext,
        mut activity: Value,
        cancellation: CancellationToken,
    ) -> PortFuture<'_, Result<(), PortError>> {
        Box::pin(async move {
            self.verify_teams_request(&context, &activity, cancellation.clone())
                .await?;
            if let Some(sender) = activity.get_mut("from").and_then(Value::as_object_mut)
                && !sender.contains_key("id")
            {
                let id = sender
                    .get("name")
                    .and_then(Value::as_str)
                    .filter(|name| !name.trim().is_empty())
                    .unwrap_or("teams-user")
                    .to_owned();
                sender.insert("id".to_owned(), Value::String(id));
            }
            let conversation_id = activity
                .get("conversation")
                .and_then(Value::as_object)
                .and_then(|conversation| conversation.get("id"))
                .and_then(Value::as_str)
                .map(str::to_owned);
            let service_url = activity
                .get("serviceUrl")
                .and_then(Value::as_str)
                .map(str::to_owned);
            let payload = serde_json::to_vec(&activity)
                .map_err(|_| invalid("Teams activity encoding failed"))?;
            let instructions = self
                .authentication
                .read()
                .unwrap_or_else(PoisonError::into_inner)
                .clone();
            let mut conversation = self
                .runtime
                .conversation_with_cancellation(cancellation.clone());
            let pending = {
                let mut handler = self.handler.lock().map_err(|_| {
                    PortError::new(PortErrorKind::Internal, "Teams state unavailable")
                })?;
                let outcome = handler
                    .handle_activity(
                        &payload,
                        self.runtime.authenticated().then_some(&mut conversation),
                        instructions.as_deref().map_or(
                            AuthenticationPrompt::Unconfigured,
                            AuthenticationPrompt::Instructions,
                        ),
                        &mut ChannelDiagnostics(Arc::clone(&self.diagnostics)),
                    )
                    .map_err(|error| invalid(format!("Teams activity rejected: {error}")))?;
                match outcome {
                    TeamsActivityOutcome::Ignored => PendingTeamsDispatch::Actions(Vec::new()),
                    TeamsActivityOutcome::ActionsQueued { .. } => {
                        let mut actions = Vec::new();
                        while let Some(action) = handler.poll_action().map_err(|error| {
                            invalid(format!("Teams action drain failed: {error}"))
                        })? {
                            actions.push(action);
                        }
                        PendingTeamsDispatch::Actions(actions)
                    }
                    TeamsActivityOutcome::DeferredCommand(invocation) => {
                        PendingTeamsDispatch::Command(invocation.name)
                    }
                }
            };
            let actions = match pending {
                PendingTeamsDispatch::Actions(actions) => actions,
                PendingTeamsDispatch::Command(command) => {
                    let conversation_id = conversation_id
                        .as_deref()
                        .ok_or_else(|| invalid("Teams command has no conversation id"))?;
                    let reply = self
                        .runtime
                        .channel_command(conversation_id, &command)
                        .await?;
                    let mut actions = Vec::new();
                    for segment in segment_outbound_text_iter("msteams", &reply)
                        .map_err(|error| invalid(format!("Teams command segmentation: {error}")))?
                    {
                        let segment = segment.map_err(|error| {
                            invalid(format!("Teams command segmentation: {error}"))
                        })?;
                        actions.push(TeamsAction::Reply(segment.into_owned()));
                    }
                    actions
                }
            };
            if !actions.is_empty()
                && let (Some(service_url), Some(conversation_id)) =
                    (service_url.as_deref(), conversation_id.as_deref())
            {
                for action in &actions {
                    self.send_action(service_url, conversation_id, action, cancellation.clone())
                        .await?;
                }
            }
            let mut replies = self.replies.lock().map_err(|_| {
                PortError::new(PortErrorKind::Internal, "Teams reply state unavailable")
            })?;
            if replies.len() == 16 {
                replies.pop_front();
            }
            replies.extend(actions.into_iter().filter_map(|action| match action {
                TeamsAction::Typing => None,
                TeamsAction::Reply(reply) => Some(reply),
            }));
            drop(replies);
            Ok(())
        })
    }
}

impl LegacyTeamsAdapter {
    async fn verify_teams_request(
        &self,
        context: &LegacyTeamsRequestContext,
        activity: &Value,
        cancellation: CancellationToken,
    ) -> Result<(), PortError> {
        let authorization = context
            .authorization()
            .ok_or_else(|| invalid("Teams bearer authorization is required"))?;
        let token = authorization.bearer_token();
        let header =
            decode_header(token).map_err(|_| invalid("Teams bearer token header is invalid"))?;
        if header.alg != Algorithm::RS256 {
            return Err(invalid("Teams bearer token algorithm is not RS256"));
        }
        let key_id = header
            .kid
            .as_deref()
            .ok_or_else(|| invalid("Teams bearer token key id is missing"))?;
        let (issuer, key) = self.teams_signing_key(key_id, cancellation).await?;
        let decoding_key = DecodingKey::from_rsa_components(&key.modulus, &key.exponent)
            .map_err(|_| invalid("Teams signing key is invalid"))?;
        let mut validation = Validation::new(Algorithm::RS256);
        validation.set_audience(&[self.app_id.as_str()]);
        validation.set_issuer(&[issuer.as_str()]);
        validation.set_required_spec_claims(&["exp", "iss", "aud"]);
        validation.validate_nbf = true;
        validation.leeway = 60;
        let claims = decode::<TeamsClaims>(token, &decoding_key, &validation)
            .map_err(|_| invalid("Teams bearer token verification failed"))?
            .claims;
        if activity.get("channelId").and_then(Value::as_str) != Some("msteams") {
            return Err(invalid("Teams activity channel is not msteams"));
        }
        if !key
            .endorsements
            .iter()
            .any(|endorsement| endorsement == "msteams")
        {
            return Err(invalid("Teams signing key is not endorsed for msteams"));
        }
        let service_url = activity
            .get("serviceUrl")
            .and_then(Value::as_str)
            .ok_or_else(|| invalid("Teams activity has no service URL"))?;
        if claims.serviceurl.trim_end_matches('/') != service_url.trim_end_matches('/') {
            return Err(invalid(
                "Teams bearer token service URL does not match the activity",
            ));
        }
        Ok(())
    }

    async fn teams_signing_key(
        &self,
        key_id: &str,
        cancellation: CancellationToken,
    ) -> Result<(String, TeamsRsaKey), PortError> {
        let mut cached = self.jwt_keys.lock().await;
        if cached
            .as_ref()
            .is_some_and(|keys| Instant::now() >= keys.expires_at)
        {
            *cached = None;
        }
        if let Some(keys) = cached.as_ref()
            && let Some(key) = keys.keys.get(key_id)
        {
            return Ok((keys.issuer.clone(), key.clone()));
        }
        let had_cache = cached.is_some();
        let mut last_refresh = self.jwt_last_refresh.lock().await;
        if had_cache
            && last_refresh.is_some_and(|refresh| refresh.elapsed() < Duration::from_mins(1))
        {
            return Err(invalid("Teams bearer token key id is unknown"));
        }
        let loaded = self.load_teams_jwt_keys(cancellation).await?;
        let result = cache_refreshed_teams_keys(&mut cached, &mut last_refresh, loaded, key_id);
        drop(last_refresh);
        drop(cached);
        result
    }

    async fn load_teams_jwt_keys(
        &self,
        cancellation: CancellationToken,
    ) -> Result<CachedTeamsJwtKeys, PortError> {
        let metadata_url = Url::parse(TEAMS_OPENID_CONFIGURATION)
            .map_err(|_| invalid("Teams OpenID URL is invalid"))?;
        let metadata: TeamsOpenIdConfiguration = self
            .fetch_teams_json(metadata_url, cancellation.clone())
            .await?;
        if metadata.issuer.trim().is_empty() {
            return Err(invalid("Teams OpenID issuer is missing"));
        }
        let keys_url =
            Url::parse(&metadata.jwks_uri).map_err(|_| invalid("Teams JWKS URL is invalid"))?;
        if keys_url.scheme() != "https"
            || keys_url.host_str() != Some("login.botframework.com")
            || keys_url.username() != ""
            || keys_url.password().is_some()
        {
            return Err(invalid("Teams JWKS URL is not a trusted Bot Framework URL"));
        }
        let document: TeamsJwkSet = self.fetch_teams_json(keys_url, cancellation).await?;
        let keys: BTreeMap<String, TeamsRsaKey> = document
            .keys
            .into_iter()
            .filter(|key| {
                key.kty == "RSA"
                    && key
                        .alg
                        .as_deref()
                        .is_none_or(|algorithm| algorithm == "RS256")
                    && key.usage.as_deref().is_none_or(|usage| usage == "sig")
                    && !key.kid.is_empty()
                    && !key.n.is_empty()
                    && !key.e.is_empty()
            })
            .take(128)
            .map(|key| {
                (
                    key.kid,
                    TeamsRsaKey {
                        modulus: key.n,
                        exponent: key.e,
                        endorsements: key.endorsements,
                    },
                )
            })
            .collect();
        if keys.is_empty() {
            return Err(invalid("Teams JWKS contains no usable signing keys"));
        }
        Ok(CachedTeamsJwtKeys {
            issuer: metadata.issuer,
            keys,
            expires_at: Instant::now()
                .checked_add(TEAMS_JWT_CACHE_TTL)
                .unwrap_or_else(Instant::now),
        })
    }

    async fn fetch_teams_json<T: DeserializeOwned>(
        &self,
        url: Url,
        cancellation: CancellationToken,
    ) -> Result<T, PortError> {
        let request = HttpRequest::new(Method::Get, url)
            .header("accept", "application/json")
            .timeout(Duration::from_secs(15));
        let sdk_cancel = CancelToken::new();
        let response = tokio::select! {
            result = self.transport.send(
                "msteams-jwt",
                Operation::Authorize,
                request,
                &sdk_cancel,
            ) => result.map_err(|error| provider_port_error(&error))?,
            () = cancellation.cancelled() => {
                sdk_cancel.cancel();
                return Err(PortError::new(PortErrorKind::Unavailable, "request cancelled"));
            }
        };

        if !response.is_success() {
            return Err(PortError::new(
                PortErrorKind::Unavailable,
                format!(
                    "Teams identity endpoint returned HTTP {}",
                    response.status()
                ),
            ));
        }
        if response.body().len() > TEAMS_JWT_DOCUMENT_LIMIT {
            return Err(invalid("Teams identity document exceeds its byte limit"));
        }
        serde_json::from_slice(response.body())
            .map_err(|_| invalid("Teams identity document is invalid"))
    }

    async fn send_action(
        &self,
        service_url: &str,
        conversation_id: &str,
        action: &TeamsAction,
        cancellation: CancellationToken,
    ) -> Result<(), PortError> {
        let base = Url::parse(service_url).map_err(|_| invalid("Teams service URL is invalid"))?;
        let host = base
            .host_str()
            .ok_or_else(|| invalid("Teams service URL has no host"))?;
        if base.scheme() != "https"
            || !(host.eq_ignore_ascii_case("api.botframework.com")
                || host.to_ascii_lowercase().ends_with(".botframework.com")
                || host.to_ascii_lowercase().ends_with(".trafficmanager.net"))
        {
            return Err(invalid(
                "Teams service URL is not a trusted Bot Framework host",
            ));
        }
        let conversation =
            url::form_urlencoded::byte_serialize(conversation_id.as_bytes()).collect::<String>();
        let endpoint = Url::parse(&format!(
            "{}/v3/conversations/{conversation}/activities",
            base.as_str().trim_end_matches('/')
        ))
        .map_err(|_| invalid("Teams reply endpoint is invalid"))?;
        let token = self.access_token(cancellation.clone()).await?;
        let credential = BoundSecret::new(
            Origin::of(&endpoint)
                .map_err(|error| invalid(format!("Teams reply origin: {error}")))?,
            token,
        );
        let body = match action {
            TeamsAction::Typing => json!({"type":"typing"}),
            TeamsAction::Reply(text) => json!({"type":"message","text":text}),
        };
        let body = serde_json::to_string(&body)
            .map_err(|_| PortError::new(PortErrorKind::Internal, "Teams encoding failed"))?;
        let request = HttpRequest::new(Method::Post, endpoint)
            .header("accept", "application/json")
            .bound_secret_header("authorization", "Bearer ", &credential)
            .map_err(|_| invalid("Teams credential origin mismatch"))?
            .body(Body::Json(body))
            .timeout(Duration::from_secs(15));
        let sdk_cancel = CancelToken::new();
        let response = tokio::select! {
            result = self.transport.send(
                "msteams",
                Operation::Transport,
                request,
                &sdk_cancel,
            ) => result.map_err(|error| provider_port_error(&error))?,
            () = cancellation.cancelled() => {
                sdk_cancel.cancel();
                return Err(PortError::new(PortErrorKind::Unavailable, "request cancelled"));
            }
        };
        if !response.is_success() {
            return Err(PortError::new(
                PortErrorKind::Unavailable,
                format!("Teams reply returned HTTP {}", response.status()),
            ));
        }
        Ok(())
    }

    async fn access_token(
        &self,
        cancellation: CancellationToken,
    ) -> Result<SecretString, PortError> {
        let mut cached = self.token.lock().await;
        if let Some(token) = cached.as_ref()
            && Instant::now() < token.expires_at
        {
            return Ok(token.token.clone());
        }
        let endpoint =
            Url::parse("https://login.microsoftonline.com/botframework.com/oauth2/v2.0/token")
                .map_err(|_| invalid("Teams OAuth endpoint is invalid"))?;
        let form = url::form_urlencoded::Serializer::new(String::new())
            .append_pair("grant_type", "client_credentials")
            .append_pair("client_id", &self.app_id)
            .append_pair("client_secret", self.app_password.expose())
            .append_pair("scope", "https://api.botframework.com/.default")
            .finish();
        let request = HttpRequest::new(Method::Post, endpoint)
            .header("accept", "application/json")
            .body(Body::Form(form))
            .timeout(Duration::from_secs(15));
        let sdk_cancel = CancelToken::new();
        let response = tokio::select! {
            result = self.transport.send(
                "msteams-oauth",
                Operation::Authorize,
                request,
                &sdk_cancel,
            ) => result.map_err(|error| provider_port_error(&error))?,
            () = cancellation.cancelled() => {
                sdk_cancel.cancel();
                return Err(PortError::new(PortErrorKind::Unavailable, "request cancelled"));
            }
        };
        if !response.is_success() {
            return Err(PortError::new(
                PortErrorKind::Unavailable,
                format!("Teams OAuth returned HTTP {}", response.status()),
            ));
        }
        let value = serde_json::from_slice::<Value>(response.body()).map_err(|_| {
            PortError::new(PortErrorKind::Unavailable, "Teams OAuth response invalid")
        })?;
        let token = value
            .get("access_token")
            .and_then(Value::as_str)
            .filter(|token| !token.is_empty())
            .ok_or_else(|| {
                PortError::new(PortErrorKind::Unavailable, "Teams OAuth token missing")
            })?;
        let expires_in = value
            .get("expires_in")
            .and_then(Value::as_u64)
            .unwrap_or(3600);
        let token = SecretString::new(token);
        *cached = Some(CachedTeamsToken {
            token: token.clone(),
            expires_at: Instant::now()
                .checked_add(Duration::from_secs(expires_in.saturating_sub(60)))
                .unwrap_or_else(Instant::now),
        });
        drop(cached);
        Ok(token)
    }
}

struct GraphWhatsAppTransport {
    transport: HttpTransport,
    runtime: tokio::runtime::Handle,
    request_cancel: Arc<Mutex<Option<CancelToken>>>,
}

impl WhatsAppTransport for GraphWhatsAppTransport {
    fn send_text(
        &mut self,
        request: &WhatsAppSendRequest<'_>,
    ) -> Result<claw_channels::ProviderResponse, ChannelError> {
        let endpoint = Url::parse(&format!(
            "https://graph.facebook.com/v{}.0/{}/messages",
            request.api_version(),
            request.phone_number_id()
        ))
        .map_err(|_| {
            ChannelError::Configuration(
                claw_channel_sdk::ConfigurationError::InvalidAdapterConfiguration,
            )
        })?;
        let origin = Origin::of(&endpoint).map_err(|_| {
            ChannelError::Configuration(
                claw_channel_sdk::ConfigurationError::InvalidAdapterConfiguration,
            )
        })?;
        let credential = BoundSecret::new(origin, SecretString::new(request.access_token()));
        let body = serde_json::to_string(&json!({
            "messaging_product": request.messaging_product(),
            "to": request.to(),
            "type": "text",
            "text": {"body": request.text()},
        }))
        .map_err(|_| ChannelError::Protocol(claw_channel_sdk::ProtocolErrorKind::InvalidField))?;
        let http_request = HttpRequest::new(Method::Post, endpoint)
            .header("accept", "application/json")
            .bound_secret_header("authorization", "Bearer ", &credential)
            .map_err(|_| ChannelError::Authentication)?
            .body(Body::Json(body))
            .timeout(request.request_timeout());
        let cancel = self
            .request_cancel
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .clone()
            .ok_or(ChannelError::Transport(
                claw_channel_sdk::TransportErrorKind::Io,
            ))?;
        let response = self
            .runtime
            .block_on(async {
                self.transport
                    .send("whatsapp", Operation::Transport, http_request, &cancel)
                    .await
            })
            .map_err(|error| provider_channel_error(&error))?;
        Ok(claw_channels::ProviderResponse::new(
            response.status(),
            response.body().to_vec(),
        ))
    }
}

/// Origin-bound `WhatsApp` Graph API sender using the integrated channel state machine.
pub struct GraphWhatsAppAdapter {
    account_id: String,
    channel: Arc<AsyncMutex<WhatsAppChannel<GraphWhatsAppTransport, SystemClock>>>,
    credential: ChannelCredential,
    app_secret: ChannelCredential,
    request_cancel: Arc<Mutex<Option<CancelToken>>>,
    diagnostics: Arc<Diagnostics>,
}

struct WhatsAppRequestGuard {
    cancel: CancelToken,
    slot: Arc<Mutex<Option<CancelToken>>>,
}

impl Drop for WhatsAppRequestGuard {
    fn drop(&mut self) {
        self.cancel.cancel();
        *self.slot.lock().unwrap_or_else(PoisonError::into_inner) = None;
    }
}

impl GraphWhatsAppAdapter {
    /// Creates a sender for one configured phone-number identity.
    ///
    /// # Errors
    ///
    /// Returns a typed port error when the phone identifier cannot form the
    /// pinned Graph API URL or the credential cannot be bound to its origin.
    pub fn new(
        transport: HttpTransport,
        phone_number_id: &str,
        access_token: &SecretString,
        app_secret: &SecretString,
        diagnostics: Arc<Diagnostics>,
    ) -> Result<Arc<Self>, PortError> {
        if phone_number_id.is_empty()
            || !phone_number_id
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-'))
        {
            return Err(invalid("WhatsApp phone number id is invalid"));
        }
        let account_id = phone_number_id.to_owned();
        let origin = official_origin("whatsapp", &account_id, "graph.facebook.com")?;
        let credential = ChannelCredential::bind(
            access_token.expose(),
            CredentialRequest {
                channel_id: "whatsapp".to_owned(),
                account_id: account_id.clone(),
                kind: CredentialKind::Token,
                binding: CredentialBinding::Origin(origin.clone()),
            },
        )
        .map_err(|error| invalid(format!("WhatsApp credential binding failed: {error}")))?;
        let app_secret = ChannelCredential::bind(
            app_secret.expose(),
            CredentialRequest {
                channel_id: "whatsapp".to_owned(),
                account_id: account_id.clone(),
                kind: CredentialKind::WebhookSecret,
                binding: CredentialBinding::LocalOnly,
            },
        )
        .map_err(|error| invalid(format!("WhatsApp app-secret binding failed: {error}")))?;
        let inbound_capacity = NonZeroUsize::new(64)
            .ok_or_else(|| invalid("WhatsApp inbound capacity must be non-zero"))?;
        let request_cancel = Arc::new(Mutex::new(None));
        let mut channel = WhatsAppChannel::new(
            account_id.clone(),
            phone_number_id,
            origin,
            GraphWhatsAppTransport {
                transport,
                runtime: tokio::runtime::Handle::current(),
                request_cancel: Arc::clone(&request_cancel),
            },
            SystemClock,
            inbound_capacity,
        )
        .map_err(|error| invalid(format!("WhatsApp channel configuration failed: {error}")))?;
        channel
            .start(&mut ChannelDiagnostics(Arc::clone(&diagnostics)))
            .map_err(|error| invalid(format!("WhatsApp channel startup failed: {error}")))?;
        Ok(Arc::new(Self {
            account_id,
            channel: Arc::new(AsyncMutex::new(channel)),
            credential,
            app_secret,
            request_cancel,
            diagnostics,
        }))
    }
}

impl LegacyWhatsAppPort for GraphWhatsAppAdapter {
    fn verify_webhook_signature(&self, payload: &[u8], signature: &str) -> Result<bool, PortError> {
        verify_whatsapp_webhook_signature(&self.account_id, payload, signature, &self.app_secret)
            .map_err(|error| channel_port_error(&error))
    }

    fn handle_webhook(
        &self,
        payload: Vec<u8>,
        messages: Arc<dyn LegacyChannelMessagePort>,
        max_reply_bytes: usize,
        cancellation: CancellationToken,
    ) -> PortFuture<'_, Result<(), PortError>> {
        Box::pin(async move {
            if cancellation.is_cancelled() {
                return Err(PortError::new(
                    PortErrorKind::Unavailable,
                    "request cancelled",
                ));
            }
            let channel = tokio::select! {
                channel = Arc::clone(&self.channel).lock_owned() => channel,
                () = cancellation.cancelled() => {
                    return Err(PortError::new(
                        PortErrorKind::Unavailable,
                        "request cancelled",
                    ));
                }
            };
            let sdk_cancel = CancelToken::new();
            *self
                .request_cancel
                .lock()
                .unwrap_or_else(PoisonError::into_inner) = Some(sdk_cancel.clone());
            let _cancel_on_drop = WhatsAppRequestGuard {
                cancel: sdk_cancel.clone(),
                slot: Arc::clone(&self.request_cancel),
            };
            let credential = self.credential.clone();
            let diagnostics = Arc::clone(&self.diagnostics);
            let task_cancellation = cancellation.clone();
            let runtime = tokio::runtime::Handle::current();
            let mut task = tokio::task::spawn_blocking(move || {
                let mut channel = channel;
                channel
                    .handle_webhook(
                        &payload,
                        &credential,
                        |message| {
                            if task_cancellation.is_cancelled() {
                                return Err(ChannelError::Transport(
                                    claw_channel_sdk::TransportErrorKind::Io,
                                ));
                            }
                            let reply = runtime
                                .block_on(messages.process(
                                    LegacyChannelMessage {
                                        channel: "whatsapp",
                                        conversation_id: message.conversation_id.clone(),
                                        user_name: message.sender_id.clone(),
                                        text: message.text.clone().unwrap_or_default(),
                                    },
                                    task_cancellation.clone(),
                                ))
                                .map_err(|_| ChannelError::RemoteRejected { status: 503 })?;
                            if reply.len() > max_reply_bytes {
                                return Err(ChannelError::Protocol(
                                    claw_channel_sdk::ProtocolErrorKind::PayloadTooLarge,
                                ));
                            }
                            Ok(Some(reply))
                        },
                        &mut ChannelDiagnostics(Arc::clone(&diagnostics)),
                    )
                    .map(|_| ())
                    .map_err(|error| channel_port_error(&error))
            });
            tokio::select! {
                result = &mut task => {
                    result.map_err(|_| {
                        PortError::new(
                            PortErrorKind::Internal,
                            "WhatsApp webhook task failed",
                        )
                    })?
                }
                () = cancellation.cancelled() => {
                    sdk_cancel.cancel();
                    let _ = task.await;
                    Err(PortError::new(
                        PortErrorKind::Unavailable,
                        "request cancelled",
                    ))
                }
            }
        })
    }

    fn send_text(
        &self,
        to: String,
        text: String,
        cancellation: CancellationToken,
    ) -> PortFuture<'_, Result<(), PortError>> {
        Box::pin(async move {
            if to.trim().is_empty() || text.trim().is_empty() {
                return Err(invalid("WhatsApp destination and text are required"));
            }
            if cancellation.is_cancelled() {
                return Err(PortError::new(
                    PortErrorKind::Unavailable,
                    "request cancelled",
                ));
            }
            let channel = tokio::select! {
                channel = Arc::clone(&self.channel).lock_owned() => channel,
                () = cancellation.cancelled() => {
                    return Err(PortError::new(
                        PortErrorKind::Unavailable,
                        "request cancelled",
                    ));
                }
            };
            let sdk_cancel = CancelToken::new();
            *self
                .request_cancel
                .lock()
                .unwrap_or_else(PoisonError::into_inner) = Some(sdk_cancel.clone());
            let _cancel_on_drop = WhatsAppRequestGuard {
                cancel: sdk_cancel.clone(),
                slot: Arc::clone(&self.request_cancel),
            };
            let credential = self.credential.clone();
            let account_id = self.account_id.clone();
            let mut task = tokio::task::spawn_blocking(move || {
                let mut channel = channel;
                let segments = segment_outbound_text_iter("whatsapp", &text)
                    .map_err(|error| invalid(format!("WhatsApp segmentation failed: {error}")))?;
                for (index, segment) in segments.enumerate() {
                    let segment = segment.map_err(|error| {
                        invalid(format!("WhatsApp segmentation failed: {error}"))
                    })?;
                    channel
                        .send_outbound(
                            &OutboundMessage {
                                correlation_key: format!(
                                    "legacy-{:016x}-{index}",
                                    stable_text_hash(&text)
                                ),
                                account_id: account_id.clone(),
                                conversation_id: format!("whatsapp:{to}"),
                                text: Some(segment.into_owned()),
                                attachments: Vec::new(),
                                reply_to: None,
                            },
                            Some(&credential),
                        )
                        .map_err(|error| channel_port_error(&error))?;
                }
                Ok::<(), PortError>(())
            });
            tokio::select! {
                result = &mut task => {
                    result
                        .map_err(|_| PortError::new(
                            PortErrorKind::Internal,
                            "WhatsApp transport task failed",
                        ))??;
                    Ok(())
                }
                () = cancellation.cancelled() => {
                    sdk_cancel.cancel();
                    let _ = task.await;
                    Err(PortError::new(
                        PortErrorKind::Unavailable,
                        "request cancelled",
                    ))
                }
            }
        })
    }
}

/// Native process/host diagnostics and explicit allowlisted command execution.
#[derive(Debug)]
pub struct NativeLegacyHostAdmin {
    started: Instant,
}

impl NativeLegacyHostAdmin {
    /// Creates a host-admin adapter.
    #[must_use]
    pub fn new() -> Arc<Self> {
        Arc::new(Self {
            started: Instant::now(),
        })
    }
}

impl LegacyHostAdminPort for NativeLegacyHostAdmin {
    fn system_info(
        &self,
        cancellation: CancellationToken,
    ) -> PortFuture<'_, Result<LegacySystemInfo, PortError>> {
        let process_uptime = self.started.elapsed();
        Box::pin(async move {
            tokio::select! {
                result = tokio::task::spawn_blocking(move || system_info(process_uptime)) => {
                    Ok(result
                        .map_err(|_| PortError::new(PortErrorKind::Internal, "host probe task failed"))?)
                }
                () = cancellation.cancelled() => {
                    Err(PortError::new(PortErrorKind::Unavailable, "request cancelled"))
                }
            }
        })
    }

    fn execute(
        &self,
        action: LegacyAdminAction,
        target: Option<String>,
        cancellation: CancellationToken,
    ) -> PortFuture<'_, Result<LegacyExecResult, PortError>> {
        Box::pin(async move { execute_admin(action, target, cancellation).await })
    }
}

fn system_info(process_uptime: Duration) -> LegacySystemInfo {
    let rss = process_rss_mb();
    let (total_memory_mb, free_memory_mb) = host_memory_mb();
    LegacySystemInfo {
        node: LegacyProcessInfo {
            version: format!("gta-claw/{}", env!("CARGO_PKG_VERSION")),
            pid: std::process::id(),
            uptime_s: process_uptime.as_secs(),
            memory_mb: LegacyProcessMemory {
                rss,
                heap_used: 0,
                heap_total: 0,
            },
        },
        os: LegacyOsInfo {
            hostname: command_text("hostname", &[]).unwrap_or_else(|| "unknown".to_owned()),
            platform: std::env::consts::OS.to_owned(),
            arch: std::env::consts::ARCH.to_owned(),
            cpus: std::thread::available_parallelism().map_or(1, usize::from),
            total_memory_mb,
            free_memory_mb,
            uptime_s: host_uptime_s(),
            loadavg: load_average(),
        },
    }
}

async fn execute_admin(
    action: LegacyAdminAction,
    target: Option<String>,
    cancellation: CancellationToken,
) -> Result<LegacyExecResult, PortError> {
    let (program, arguments) = admin_argv(action, target)?;
    let mut command = Command::new(program);
    command
        .args(arguments)
        .kill_on_drop(true)
        .env_clear()
        .env("PATH", safe_executable_path())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    let mut child = command.spawn().map_err(|error| {
        PortError::new(
            PortErrorKind::Unavailable,
            format!("host command failed: {error}"),
        )
    })?;
    let stdout = child
        .stdout
        .take()
        .ok_or_else(|| PortError::new(PortErrorKind::Internal, "stdout pipe unavailable"))?;
    let stderr = child
        .stderr
        .take()
        .ok_or_else(|| PortError::new(PortErrorKind::Internal, "stderr pipe unavailable"))?;
    let run =
        async move { tokio::try_join!(child.wait(), read_limited(stdout), read_limited(stderr),) };
    let (status, stdout, stderr) = tokio::select! {
        result = run => result.map_err(|error| {
            PortError::new(PortErrorKind::Unavailable, format!("host command failed: {error}"))
        })?,
        () = cancellation.cancelled() => {
            return Err(PortError::new(PortErrorKind::Unavailable, "request cancelled"));
        }
    };
    let stdout = bounded_text(&stdout);
    let stderr = bounded_text(&stderr);
    Ok(if status.success() {
        LegacyExecResult {
            success: true,
            output: (!stdout.is_empty()).then_some(stdout),
            error: None,
            stderr: (!stderr.is_empty()).then_some(stderr),
        }
    } else {
        LegacyExecResult {
            success: false,
            output: None,
            error: Some(format!(
                "command exited with {}",
                status
                    .code()
                    .map_or_else(|| "signal".to_owned(), |code| code.to_string())
            )),
            stderr: (!stderr.is_empty()).then_some(stderr),
        }
    })
}

async fn read_limited(reader: impl AsyncRead + Unpin) -> std::io::Result<Vec<u8>> {
    let mut bytes = Vec::with_capacity(ADMIN_OUTPUT_LIMIT.min(64 * 1024));
    reader
        .take(u64::try_from(ADMIN_OUTPUT_LIMIT).unwrap_or(u64::MAX))
        .read_to_end(&mut bytes)
        .await?;
    Ok(bytes)
}

fn admin_argv(
    action: LegacyAdminAction,
    target: Option<String>,
) -> Result<(&'static str, Vec<String>), PortError> {
    let simple = |program, arguments: &[&str]| {
        Ok((
            program,
            arguments
                .iter()
                .map(|argument| (*argument).to_owned())
                .collect(),
        ))
    };
    match action {
        LegacyAdminAction::Uptime => simple("uptime", &[]),
        LegacyAdminAction::Disk => simple("df", &["-h"]),
        LegacyAdminAction::Memory if cfg!(target_os = "macos") => simple("vm_stat", &[]),
        LegacyAdminAction::Memory => simple("free", &["-m"]),
        LegacyAdminAction::Top => simple("ps", &["-axo", "pid,pcpu,pmem,comm"]),
        LegacyAdminAction::DockerPs => simple("docker", &["ps"]),
        LegacyAdminAction::DockerStats => simple("docker", &["stats", "--no-stream"]),
        LegacyAdminAction::DockerImages => simple("docker", &["images"]),
        LegacyAdminAction::DockerLogs => {
            let target = target
                .filter(|target| valid_command_target(target))
                .ok_or_else(|| invalid("docker_logs requires a safe target"))?;
            Ok((
                "docker",
                vec![
                    "logs".to_owned(),
                    "--tail".to_owned(),
                    "100".to_owned(),
                    target,
                ],
            ))
        }
        LegacyAdminAction::Netstat if cfg!(target_os = "linux") => simple("ss", &["-lntup"]),
        LegacyAdminAction::Netstat => simple("netstat", &["-an"]),
        LegacyAdminAction::Who => simple("who", &[]),
        LegacyAdminAction::Hostname => simple("hostname", &[]),
        LegacyAdminAction::Date => simple("date", &[]),
    }
}

fn cache_refreshed_teams_keys(
    cached: &mut Option<CachedTeamsJwtKeys>,
    last_refresh: &mut Option<Instant>,
    loaded: CachedTeamsJwtKeys,
    key_id: &str,
) -> Result<(String, TeamsRsaKey), PortError> {
    let issuer = loaded.issuer.clone();
    let key = loaded.keys.get(key_id).cloned();
    *cached = Some(loaded);
    *last_refresh = Some(Instant::now());
    key.map(|key| (issuer, key))
        .ok_or_else(|| invalid("Teams bearer token key id is unknown"))
}

fn valid_command_target(target: &str) -> bool {
    !target.is_empty()
        && target.len() <= 128
        && target
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-' | b'.'))
}

fn bounded_text(bytes: &[u8]) -> String {
    String::from_utf8_lossy(&bytes[..bytes.len().min(ADMIN_OUTPUT_LIMIT)]).into_owned()
}

fn command_text(program: &str, arguments: &[&str]) -> Option<String> {
    BlockingCommand::new(program)
        .args(arguments)
        .env_clear()
        .env("PATH", safe_executable_path())
        .output()
        .ok()
        .filter(|output| output.status.success())
        .map(|output| String::from_utf8_lossy(&output.stdout).trim().to_owned())
        .filter(|output| !output.is_empty())
}

fn safe_executable_path() -> String {
    if cfg!(windows) {
        let root = std::env::var("SystemRoot").unwrap_or_else(|_| r"C:\Windows".to_owned());
        format!(r"{root}\System32;{root}\System32\WindowsPowerShell\v1.0")
    } else {
        "/usr/local/bin:/usr/bin:/bin:/usr/sbin:/sbin".to_owned()
    }
}

fn process_rss_mb() -> u64 {
    if cfg!(target_os = "linux") {
        return std::fs::read_to_string("/proc/self/status")
            .ok()
            .and_then(|status| parse_kib_field(&status, "VmRSS:"))
            .map_or(0, |kib| kib / 1024);
    }
    command_text("ps", &["-o", "rss=", "-p", &std::process::id().to_string()])
        .and_then(|rss| rss.trim().parse::<u64>().ok())
        .map_or(0, |kib| kib / 1024)
}

fn host_memory_mb() -> (u64, u64) {
    if cfg!(target_os = "linux") {
        let memory = std::fs::read_to_string("/proc/meminfo").unwrap_or_default();
        return (
            parse_kib_field(&memory, "MemTotal:").map_or(0, |kib| kib / 1024),
            parse_kib_field(&memory, "MemAvailable:").map_or(0, |kib| kib / 1024),
        );
    }
    if cfg!(target_os = "macos") {
        let total = command_text("sysctl", &["-n", "hw.memsize"])
            .and_then(|bytes| bytes.parse::<u64>().ok())
            .map_or(0, |bytes| bytes / (1024 * 1024));
        let free = command_text("vm_stat", &[])
            .and_then(|text| parse_vm_stat_free(&text))
            .unwrap_or_default();
        return (total, free);
    }
    (0, 0)
}

fn host_uptime_s() -> u64 {
    if cfg!(target_os = "linux") {
        return std::fs::read_to_string("/proc/uptime")
            .ok()
            .and_then(|text| {
                text.split_whitespace()
                    .next()?
                    .split('.')
                    .next()?
                    .parse::<u64>()
                    .ok()
            })
            .unwrap_or_default();
    }
    if cfg!(target_os = "macos") {
        let boot = command_text("sysctl", &["-n", "kern.boottime"]).and_then(|text| {
            text.split("sec =")
                .nth(1)?
                .split(',')
                .next()?
                .trim()
                .parse()
                .ok()
        });
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_or(0, |duration| duration.as_secs());
        return boot.map_or(0, |boot: u64| now.saturating_sub(boot));
    }
    0
}

fn load_average() -> [f64; 3] {
    if cfg!(target_os = "linux") {
        let values = std::fs::read_to_string("/proc/loadavg").unwrap_or_default();
        return three_floats(&values);
    }
    if cfg!(target_os = "macos") {
        let values = command_text("sysctl", &["-n", "vm.loadavg"]).unwrap_or_default();
        return three_floats(values.trim_matches(['{', '}']));
    }
    [0.0; 3]
}

fn three_floats(value: &str) -> [f64; 3] {
    let mut values = value
        .split_whitespace()
        .filter_map(|field| field.parse::<f64>().ok());
    [
        values.next().unwrap_or_default(),
        values.next().unwrap_or_default(),
        values.next().unwrap_or_default(),
    ]
}

fn parse_kib_field(source: &str, name: &str) -> Option<u64> {
    source
        .lines()
        .find(|line| line.starts_with(name))?
        .split_whitespace()
        .nth(1)?
        .parse()
        .ok()
}

fn parse_vm_stat_free(source: &str) -> Option<u64> {
    let page_size = source
        .lines()
        .next()?
        .split("page size of ")
        .nth(1)?
        .split_whitespace()
        .next()?
        .parse::<u64>()
        .ok()?;
    let free_pages = source
        .lines()
        .find(|line| line.starts_with("Pages free:"))?
        .split_whitespace()
        .nth(2)?
        .trim_end_matches('.')
        .parse::<u64>()
        .ok()?;
    Some(free_pages.saturating_mul(page_size) / (1024 * 1024))
}

fn provider_port_error(error: &claw_provider_sdk::ProviderError) -> PortError {
    let kind = match error.kind() {
        claw_provider_sdk::ErrorKind::InvalidRequest => PortErrorKind::InvalidRequest,
        claw_provider_sdk::ErrorKind::Timeout => PortErrorKind::Timeout,
        claw_provider_sdk::ErrorKind::Unsupported => PortErrorKind::NotFound,
        _ => PortErrorKind::Unavailable,
    };
    PortError::new(kind, error.to_string())
}

fn provider_channel_error(error: &claw_provider_sdk::ProviderError) -> ChannelError {
    match error.kind() {
        claw_provider_sdk::ErrorKind::Authentication => ChannelError::Authentication,
        claw_provider_sdk::ErrorKind::RateLimit => ChannelError::RateLimited {
            retry_after: error.retry_after().unwrap_or(Duration::from_secs(1)),
        },
        claw_provider_sdk::ErrorKind::Timeout => {
            ChannelError::Transport(claw_channel_sdk::TransportErrorKind::Timeout)
        }
        claw_provider_sdk::ErrorKind::Transport => {
            ChannelError::Transport(claw_channel_sdk::TransportErrorKind::Connection)
        }
        claw_provider_sdk::ErrorKind::Protocol => {
            ChannelError::Protocol(claw_channel_sdk::ProtocolErrorKind::MalformedResponse)
        }
        _ => ChannelError::RemoteRejected { status: 503 },
    }
}

fn channel_port_error(error: &ChannelError) -> PortError {
    let kind = match error {
        ChannelError::InvalidMessage(_)
        | ChannelError::Configuration(_)
        | ChannelError::CredentialBinding(_)
        | ChannelError::Protocol(_) => PortErrorKind::InvalidRequest,
        ChannelError::RateLimited { .. }
        | ChannelError::Transport(_)
        | ChannelError::RemoteRejected { .. }
        | ChannelError::Authentication
        | ChannelError::Credential(_)
        | ChannelError::NotConnected { .. } => PortErrorKind::Unavailable,
        ChannelError::Unsupported(_) => PortErrorKind::NotFound,
        ChannelError::Lifecycle(_) => PortErrorKind::Internal,
    };
    PortError::new(kind, error.to_string())
}

fn stable_text_hash(value: &str) -> u64 {
    let mut hash = 0xcbf2_9ce4_8422_2325_u64;
    for byte in value.bytes() {
        hash ^= u64::from(byte);
        hash = hash.wrapping_mul(0x0000_0100_0000_01b3);
    }
    hash
}

fn invalid(message: impl Into<String>) -> PortError {
    PortError::new(PortErrorKind::InvalidRequest, message)
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;
    use std::sync::{Arc, Mutex, RwLock};
    use std::time::{Duration, Instant};

    use claw_provider_sdk::{CancelToken, SecretString};
    use claw_providers::github_copilot::DeviceAuthorization;

    use super::{
        CachedTeamsJwtKeys, DeviceInstructionsGuard, LegacyDeviceFlowAdapter, TeamsRsaKey,
        WhatsAppRequestGuard, cache_refreshed_teams_keys, official_origin, three_floats,
        valid_command_target,
    };

    #[test]
    fn host_helpers_are_bounded_and_deterministic() {
        let values = three_floats("1.0 2.5 3.75 extra");
        assert!((values[0] - 1.0).abs() < f64::EPSILON);
        assert!((values[1] - 2.5).abs() < f64::EPSILON);
        assert!((values[2] - 3.75).abs() < f64::EPSILON);
        assert!(valid_command_target("container_1.test"));
        assert!(!valid_command_target("../container"));
    }

    #[test]
    fn official_channel_origin_is_exactly_scoped() {
        let origin = official_origin("whatsapp", "account", "graph.facebook.com").expect("origin");
        assert_eq!(origin.channel_id(), "whatsapp");
        assert_eq!(origin.account_id(), "account");
    }

    #[test]
    fn device_instructions_are_reusable_and_contain_no_device_secret() {
        let pending = DeviceAuthorization {
            device_code: SecretString::new("secret-device-code"),
            user_code: "ABCD-EFGH".to_owned(),
            verification_uri: "https://github.com/login/device".to_owned(),
            expires_in: 900,
            interval: 5,
        };

        let instructions = LegacyDeviceFlowAdapter::instructions_for(&pending);

        assert!(instructions.contains("ABCD-EFGH"));
        assert!(instructions.contains("https://github.com/login/device"));
        assert!(!instructions.contains("secret-device-code"));
    }

    #[test]
    fn terminal_device_flow_clears_only_its_own_prompt() {
        let instructions = Arc::new(RwLock::new(Some("expired prompt".to_owned())));
        drop(DeviceInstructionsGuard::new(
            Arc::clone(&instructions),
            "expired prompt".to_owned(),
        ));
        assert!(instructions.read().expect("prompt lock").is_none());

        *instructions.write().expect("prompt lock") = Some("old prompt".to_owned());
        let guard =
            DeviceInstructionsGuard::new(Arc::clone(&instructions), "old prompt".to_owned());
        *instructions.write().expect("prompt lock") = Some("replacement prompt".to_owned());
        drop(guard);
        assert_eq!(
            instructions.read().expect("prompt lock").as_deref(),
            Some("replacement prompt")
        );
    }

    #[test]
    fn dropped_whatsapp_request_cancels_transport_and_clears_slot() {
        let cancel = CancelToken::new();
        let slot = Arc::new(Mutex::new(Some(cancel.clone())));
        drop(WhatsAppRequestGuard {
            cancel: cancel.clone(),
            slot: Arc::clone(&slot),
        });
        assert!(cancel.is_cancelled());
        assert!(slot.lock().expect("request slot").is_none());
    }

    #[test]
    fn an_unknown_rotated_key_still_publishes_the_refreshed_key_set() {
        let mut cached = None;
        let mut refreshed = None;
        let known = TeamsRsaKey {
            modulus: "modulus".to_owned(),
            exponent: "AQAB".to_owned(),
            endorsements: vec!["msteams".to_owned()],
        };
        let loaded = CachedTeamsJwtKeys {
            issuer: "https://api.botframework.com".to_owned(),
            keys: BTreeMap::from([("rotated".to_owned(), known.clone())]),
            expires_at: Instant::now() + Duration::from_mins(5),
        };

        let result =
            cache_refreshed_teams_keys(&mut cached, &mut refreshed, loaded, "still-unknown");
        let Err(error) = result else {
            panic!("the requested key remains unknown");
        };

        assert_eq!(error.to_string(), "Teams bearer token key id is unknown");
        assert!(refreshed.is_some());
        let published = cached.expect("the successful refresh is retained");
        assert_eq!(published.issuer, "https://api.botframework.com");
        assert_eq!(
            published.keys.get("rotated").map(|key| &key.modulus),
            Some(&known.modulus)
        );
    }
}

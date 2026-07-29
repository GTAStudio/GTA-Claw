//! Supervised Telegram and Discord channel transports.

use std::fmt::{self, Display, Formatter};
use std::future::Future;
use std::num::{NonZeroU32, NonZeroUsize};
use std::pin::Pin;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, PoisonError, RwLock};
use std::time::{Duration, Instant};

use claw_channel_sdk::{
    ApprovedOrigin, Channel, ChannelCredential, ChannelError, CredentialBinding, CredentialKind,
    CredentialRequest, InboundMessage, NetworkOrigin, OriginTrustError, OriginTrustStore,
    OutboundMessage, TransportErrorKind, authorize_origin,
};
use claw_channels::{
    AuthenticationPrompt, DiagnosticLevel, DiagnosticSink, DiscordChannel,
    DiscordCreateMessageRequest, DiscordGatewayRequest, DiscordPacketOutcome, DiscordTransport,
    DispatchInput, DispatchOutcome, MAX_PROVIDER_RESPONSE_BYTES, OperatorDiagnostic,
    ProviderResponse, SystemClock, TelegramChannel, TelegramPollRequest, TelegramSendRequest,
    TelegramTransport, dispatch_incoming, segment_outbound_text_iter,
};
use claw_provider_sdk::http::{
    Body, HttpRequest, HttpTransport, Method, ProxyPolicy, TransportConfig,
};
use claw_provider_sdk::{BoundSecret, CancelToken, Operation, Origin, SecretString};
use futures_util::{SinkExt, StreamExt};
use serde_json::json;
use tokio::sync::{mpsc, oneshot};
use tokio::task::{AbortHandle, JoinHandle};
use tokio_tungstenite::tungstenite::Message;
use tokio_util::sync::CancellationToken;
use tokio_util::task::TaskTracker;
use url::Url;

use super::agent_runtime::AgentRuntime;
use super::http_api::{DependencyReadiness, Diagnostics};

const CHANNEL_START_TIMEOUT: Duration = Duration::from_secs(20);
const CHANNEL_STOP_GRACE: Duration = Duration::from_secs(2);
const DISCORD_REPLY_MAX_ATTEMPTS: u32 = 3;
const TELEGRAM_READINESS_ATTEMPTS: u32 = 3;
const TELEGRAM_PERSISTENT_FAILURES: u32 = 3;

/// Configured Telegram worker.
pub struct TelegramSettings {
    /// Bot token.
    pub token: SecretString,
    /// Delay between polls.
    pub poll_interval: Duration,
}

/// Configured Discord worker.
pub struct DiscordSettings {
    /// Bot token.
    pub token: SecretString,
    /// Gateway WSS URL.
    pub gateway_url: String,
    /// Gateway intent bitset.
    pub intents: u64,
}

type TelegramProbeFuture<'a> = Pin<Box<dyn Future<Output = Result<(), ChannelError>> + Send + 'a>>;

trait TelegramReadinessProbe: Sync {
    fn probe<'a>(
        &'a self,
        credential: &'a ChannelCredential,
        origin: &'a ApprovedOrigin,
        cancellation: &'a CancellationToken,
    ) -> TelegramProbeFuture<'a>;
}

#[derive(Clone, Debug, Eq, PartialEq)]
enum TelegramReadinessError {
    Cancelled,
    Terminal(ChannelError),
    Persistent(ChannelError),
}

impl Display for TelegramReadinessError {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        match self {
            Self::Cancelled => formatter.write_str("Telegram readiness was cancelled"),
            Self::Terminal(error) => write!(formatter, "Telegram readiness failed: {error}"),
            Self::Persistent(error) => {
                write!(formatter, "Telegram readiness repeatedly failed: {error}")
            }
        }
    }
}

/// Shutdown accounting for live channel tasks.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct ChannelTaskReport {
    /// Workers accepted.
    pub spawned: u64,
    /// Workers that reached termination.
    pub terminated: u64,
    /// Workers aborted after the grace interval.
    pub abandoned: u32,
}

struct TerminationGuard(Arc<AtomicU64>);

impl Drop for TerminationGuard {
    fn drop(&mut self) {
        self.0.fetch_add(1, Ordering::SeqCst);
    }
}

struct ChildTaskGuard(Option<JoinHandle<()>>);

impl ChildTaskGuard {
    const fn new(task: JoinHandle<()>) -> Self {
        Self(Some(task))
    }

    async fn join(mut self) -> Result<(), tokio::task::JoinError> {
        match self.0.take() {
            Some(task) => task.await,
            None => Ok(()),
        }
    }
}

impl Drop for ChildTaskGuard {
    fn drop(&mut self) {
        if let Some(task) = self.0.take() {
            task.abort();
        }
    }
}

type RequestCancellations = Arc<Mutex<Vec<Arc<Mutex<Option<CancelToken>>>>>>;

/// Owns every polling/socket task started for configured channels.
pub struct ChannelSupervisor {
    cancellation: CancellationToken,
    tracker: TaskTracker,
    aborts: Mutex<Vec<AbortHandle>>,
    request_cancellations: RequestCancellations,
    spawned: u64,
    terminated: Arc<AtomicU64>,
}

struct ChannelStartGuard<'a> {
    cancellation: &'a CancellationToken,
    aborts: &'a Mutex<Vec<AbortHandle>>,
    request_cancellations: RequestCancellations,
    armed: bool,
}

impl ChannelStartGuard<'_> {
    const fn disarm(&mut self) {
        self.armed = false;
    }
}

impl Drop for ChannelStartGuard<'_> {
    fn drop(&mut self) {
        if !self.armed {
            return;
        }
        self.cancellation.cancel();
        cancel_requests(&self.request_cancellations);
        for abort in self
            .aborts
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .iter()
        {
            abort.abort();
        }
    }
}

impl Drop for ChannelSupervisor {
    fn drop(&mut self) {
        self.cancellation.cancel();
        cancel_requests(&self.request_cancellations);
        for abort in self
            .aborts
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .iter()
        {
            abort.abort();
        }
    }
}

fn cancel_requests(requests: &RequestCancellations) {
    for slot in requests
        .lock()
        .unwrap_or_else(PoisonError::into_inner)
        .iter()
    {
        if let Some(cancel) = slot.lock().unwrap_or_else(PoisonError::into_inner).as_ref() {
            cancel.cancel();
        }
    }
}

async fn wait_for_telegram_readiness<P: TelegramReadinessProbe>(
    probe: &P,
    credential: &ChannelCredential,
    origin: &ApprovedOrigin,
    cancellation: &CancellationToken,
    default_retry_after: Duration,
    max_attempts: u32,
) -> Result<(), TelegramReadinessError> {
    for attempt in 1..=max_attempts {
        let result = tokio::select! {
            biased;
            () = cancellation.cancelled() => return Err(TelegramReadinessError::Cancelled),
            result = probe.probe(credential, origin, cancellation) => result,
        };
        match result {
            Ok(()) => return Ok(()),
            Err(error) if telegram_failure_is_terminal(&error) => {
                return Err(TelegramReadinessError::Terminal(error));
            }
            Err(error) if attempt == max_attempts => {
                return Err(TelegramReadinessError::Persistent(error));
            }
            Err(error) => {
                let retry_after = error.retry_after().unwrap_or(default_retry_after);
                tokio::select! {
                    biased;
                    () = cancellation.cancelled() => {
                        return Err(TelegramReadinessError::Cancelled);
                    }
                    () = tokio::time::sleep(retry_after) => {}
                }
            }
        }
    }
    unreachable!("the non-zero readiness attempt loop always returns")
}

const fn telegram_failure_is_terminal(error: &ChannelError) -> bool {
    matches!(
        error,
        ChannelError::InvalidMessage(_)
            | ChannelError::Configuration(_)
            | ChannelError::Credential(_)
            | ChannelError::CredentialBinding(_)
            | ChannelError::Authentication
            | ChannelError::Protocol(_)
            | ChannelError::Unsupported(_)
            | ChannelError::Lifecycle(_)
            | ChannelError::NotConnected { .. }
            | ChannelError::RemoteRejected { status: 400..=499 }
    )
}

impl ChannelSupervisor {
    /// Builds and starts every configured channel.
    ///
    /// # Errors
    ///
    /// Returns a safe startup error when transport policy, credential binding,
    /// or the initial Discord connection cannot become live.
    #[allow(clippy::too_many_arguments)]
    pub async fn start(
        telegram: Option<TelegramSettings>,
        discord: Option<DiscordSettings>,
        runtime: Arc<AgentRuntime>,
        authentication: Arc<RwLock<Option<String>>>,
        proxy: ProxyPolicy,
        diagnostics: Arc<Diagnostics>,
        readiness: Arc<DependencyReadiness>,
        startup_cancellation: CancellationToken,
    ) -> Result<Self, String> {
        let cancellation = startup_cancellation.child_token();
        let tracker = TaskTracker::new();
        let terminated = Arc::new(AtomicU64::new(0));
        let aborts = Mutex::new(Vec::new());
        let request_cancellations = Arc::new(Mutex::new(Vec::new()));
        let mut start_guard = ChannelStartGuard {
            cancellation: &cancellation,
            aborts: &aborts,
            request_cancellations: Arc::clone(&request_cancellations),
            armed: true,
        };
        let mut spawned = 0_u64;
        readiness.set("channels", true);

        if let Some(settings) = telegram {
            let request_cancel = Arc::new(Mutex::new(None));
            let transport = TelegramHttpTransport::new(proxy.clone(), Arc::clone(&request_cancel))?;
            let account = "default";
            let origin = approved_origin("telegram", account, "api.telegram.org")?;
            let credential = bind_credential(
                "telegram",
                account,
                CredentialKind::Token,
                origin.clone(),
                &settings.token,
            )?;
            request_cancellations
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .push(Arc::clone(&request_cancel));
            match tokio::time::timeout(
                CHANNEL_START_TIMEOUT,
                wait_for_telegram_readiness(
                    &transport,
                    &credential,
                    &origin,
                    &cancellation,
                    settings.poll_interval,
                    TELEGRAM_READINESS_ATTEMPTS,
                ),
            )
            .await
            {
                Ok(Ok(())) => {}
                Ok(Err(error)) => return Err(error.to_string()),
                Err(_) => return Err("Telegram channel readiness timed out".to_owned()),
            }
            let inbound_capacity = NonZeroUsize::new(64)
                .ok_or_else(|| "Telegram inbound capacity must be non-zero".to_owned())?;
            let mut channel = TelegramChannel::new(
                account,
                origin,
                transport,
                SystemClock,
                inbound_capacity,
                settings.poll_interval,
            )
            .map_err(|error| error.to_string())?;
            channel
                .start(&mut ChannelDiagnostics(Arc::clone(&diagnostics)))
                .map_err(|error| error.to_string())?;
            let task_cancel = cancellation.clone();
            let task_runtime = Arc::clone(&runtime);
            let task_authentication = Arc::clone(&authentication);
            let task_diagnostics = Arc::clone(&diagnostics);
            let task_readiness = Arc::clone(&readiness);
            let task_terminated = Arc::clone(&terminated);
            let handle = tracker.spawn(async move {
                let _guard = TerminationGuard(task_terminated);
                run_telegram(
                    channel,
                    credential,
                    task_runtime,
                    task_authentication,
                    task_diagnostics,
                    task_readiness,
                    task_cancel,
                )
                .await;
            });
            aborts
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .push(handle.abort_handle());
            drop(handle);
            spawned = spawned.saturating_add(1);
        }

        if let Some(settings) = discord {
            let account = "default";
            let gateway_url =
                Url::parse(&settings.gateway_url).map_err(|_| "Discord Gateway URL is invalid")?;
            if gateway_url.scheme() != "wss" {
                return Err("Discord Gateway URL must use wss".to_owned());
            }
            let gateway_host = gateway_url
                .host_str()
                .ok_or("Discord Gateway URL has no host")?;
            if !proxy.rules().intercept(gateway_host, 443).is_direct() {
                return Err(
                    "Discord Gateway cannot start because its WebSocket transport cannot honor the selected proxy"
                        .to_owned(),
                );
            }
            let request_cancel = Arc::new(Mutex::new(None));
            let (transport, commands, event_tx, events) =
                DiscordTransportAdapter::new(proxy, Arc::clone(&request_cancel))?;
            let gateway_origin = approved_origin_dynamic("discord", account, gateway_host)?;
            let rest_origin = approved_origin("discord", account, "discord.com")?;
            let gateway_credential = bind_credential(
                "discord",
                account,
                CredentialKind::Token,
                gateway_origin.clone(),
                &settings.token,
            )?;
            let rest_credential = bind_credential(
                "discord",
                account,
                CredentialKind::Token,
                rest_origin.clone(),
                &settings.token,
            )?;
            let inbound_capacity = NonZeroUsize::new(64)
                .ok_or_else(|| "Discord inbound capacity must be non-zero".to_owned())?;
            let reconnect_attempts = NonZeroU32::new(10)
                .ok_or_else(|| "Discord reconnect attempts must be non-zero".to_owned())?;
            let reply_transport = transport.clone();
            let reply_origin = rest_origin.clone();
            let mut channel = DiscordChannel::new(
                account,
                settings.gateway_url,
                gateway_origin,
                rest_origin,
                settings.intents,
                transport,
                SystemClock,
                inbound_capacity,
                reconnect_attempts,
            )
            .map_err(|error| error.to_string())?;
            let started = Instant::now();
            channel
                .start(
                    started.elapsed(),
                    &mut ChannelDiagnostics(Arc::clone(&diagnostics)),
                )
                .map_err(|error| error.to_string())?;
            let socket_cancel = cancellation.clone();
            let socket_terminated = Arc::clone(&terminated);
            let socket = tracker.spawn(async move {
                let _guard = TerminationGuard(socket_terminated);
                run_discord_socket(commands, event_tx, socket_cancel).await;
            });
            aborts
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .push(socket.abort_handle());
            drop(socket);
            spawned = spawned.saturating_add(1);

            let (ready_tx, ready_rx) = oneshot::channel();
            let task_cancel = cancellation.clone();
            let task_runtime = Arc::clone(&runtime);
            let task_authentication = Arc::clone(&authentication);
            let task_diagnostics = Arc::clone(&diagnostics);
            let task_terminated = Arc::clone(&terminated);
            let channel_task = tracker.spawn(async move {
                let _guard = TerminationGuard(task_terminated);
                run_discord(
                    channel,
                    gateway_credential,
                    reply_transport,
                    reply_origin,
                    rest_credential,
                    events,
                    task_runtime,
                    task_authentication,
                    task_diagnostics,
                    task_cancel,
                    ready_tx,
                    started,
                )
                .await;
            });
            aborts
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .push(channel_task.abort_handle());
            drop(channel_task);
            request_cancellations
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .push(request_cancel);
            spawned = spawned.saturating_add(1);
            match tokio::time::timeout(CHANNEL_START_TIMEOUT, ready_rx).await {
                Ok(Ok(Ok(()))) => {}
                Ok(Ok(Err(error))) => {
                    cancellation.cancel();
                    return Err(error);
                }
                Ok(Err(_)) => {
                    cancellation.cancel();
                    return Err("Discord channel stopped before readiness".to_owned());
                }
                Err(_) => {
                    cancellation.cancel();
                    return Err("Discord channel readiness timed out".to_owned());
                }
            }
        }

        start_guard.disarm();
        drop(start_guard);
        Ok(Self {
            cancellation,
            tracker,
            aborts,
            request_cancellations,
            spawned,
            terminated,
        })
    }

    /// Cancels transports, joins workers, and aborts only after the grace interval.
    pub async fn shutdown(&self, budget: Duration) -> ChannelTaskReport {
        let started = Instant::now();
        self.cancellation.cancel();
        cancel_requests(&self.request_cancellations);
        self.tracker.close();
        let grace = std::cmp::min(CHANNEL_STOP_GRACE, budget / 2);
        let graceful = tokio::time::timeout(grace, self.tracker.wait())
            .await
            .is_ok();
        let mut abandoned = 0_u32;
        if !graceful {
            let aborts = self
                .aborts
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .clone();
            for abort in aborts {
                if !abort.is_finished() {
                    abort.abort();
                    abandoned = abandoned.saturating_add(1);
                }
            }
            let _ = tokio::time::timeout(
                budget.saturating_sub(started.elapsed()),
                self.tracker.wait(),
            )
            .await;
        }
        ChannelTaskReport {
            spawned: self.spawned,
            terminated: self.terminated.load(Ordering::SeqCst),
            abandoned,
        }
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

struct ExactOriginTrust<'a> {
    channel: &'a str,
    account: &'a str,
    host: &'a str,
}

impl OriginTrustStore for ExactOriginTrust<'_> {
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

fn approved_origin(
    channel: &str,
    account: &str,
    host: &'static str,
) -> Result<claw_channel_sdk::ApprovedOrigin, String> {
    approved_origin_dynamic(channel, account, host)
}

fn approved_origin_dynamic(
    channel: &str,
    account: &str,
    host: &str,
) -> Result<claw_channel_sdk::ApprovedOrigin, String> {
    let origin = NetworkOrigin::https(host, None).map_err(|error| error.to_string())?;
    authorize_origin(
        &ExactOriginTrust {
            channel,
            account,
            host,
        },
        channel,
        account,
        &origin,
    )
    .map_err(|error| error.to_string())
}

fn bind_credential(
    channel: &str,
    account: &str,
    kind: CredentialKind,
    origin: claw_channel_sdk::ApprovedOrigin,
    secret: &SecretString,
) -> Result<ChannelCredential, String> {
    ChannelCredential::bind(
        secret.expose(),
        CredentialRequest {
            channel_id: channel.to_owned(),
            account_id: account.to_owned(),
            kind,
            binding: CredentialBinding::Origin(origin),
        },
    )
    .map_err(|error| error.to_string())
}

struct RequestSlotGuard<'a> {
    slot: &'a Mutex<Option<CancelToken>>,
}

impl Drop for RequestSlotGuard<'_> {
    fn drop(&mut self) {
        *self.slot.lock().unwrap_or_else(PoisonError::into_inner) = None;
    }
}

struct RequestCancelGuard(CancelToken);

impl Drop for RequestCancelGuard {
    fn drop(&mut self) {
        self.0.cancel();
    }
}

fn blocking_http(
    transport: &HttpTransport,
    request: HttpRequest,
    operation: Operation,
    slot: &Mutex<Option<CancelToken>>,
) -> Result<claw_provider_sdk::http::HttpResponse, ChannelError> {
    let cancel = CancelToken::new();
    *slot.lock().unwrap_or_else(PoisonError::into_inner) = Some(cancel.clone());
    let _guard = RequestSlotGuard { slot };
    tokio::task::block_in_place(|| {
        tokio::runtime::Handle::current()
            .block_on(async { transport.send("channel", operation, request, &cancel).await })
    })
    .map_err(|error| provider_channel_error(&error))
}

fn blocking_http_with_cancellation(
    transport: &HttpTransport,
    request: HttpRequest,
    operation: Operation,
    slot: &Mutex<Option<CancelToken>>,
    cancellation: &CancellationToken,
) -> Result<claw_provider_sdk::http::HttpResponse, ChannelError> {
    let cancel = bind_request_cancellation(slot, cancellation)?;
    let _cancel_on_drop = RequestCancelGuard(cancel.clone());
    let _guard = RequestSlotGuard { slot };
    tokio::task::block_in_place(|| {
        tokio::runtime::Handle::current().block_on(async {
            tokio::select! {
                biased;
                () = cancellation.cancelled() => {
                    cancel.cancel();
                    Err(ChannelError::Transport(TransportErrorKind::Io))
                }
                response = transport.send("channel", operation, request, &cancel) => {
                    response.map_err(|error| provider_channel_error(&error))
                }
            }
        })
    })
}

fn bind_request_cancellation(
    slot: &Mutex<Option<CancelToken>>,
    cancellation: &CancellationToken,
) -> Result<CancelToken, ChannelError> {
    let cancel = CancelToken::new();
    let mut active = slot.lock().unwrap_or_else(PoisonError::into_inner);
    *active = Some(cancel.clone());
    if cancellation.is_cancelled() {
        cancel.cancel();
        *active = None;
        return Err(ChannelError::Transport(TransportErrorKind::Io));
    }
    drop(active);
    Ok(cancel)
}

struct TelegramHttpTransport {
    transport: HttpTransport,
    request_cancel: Arc<Mutex<Option<CancelToken>>>,
}

impl TelegramHttpTransport {
    fn new(
        proxy: ProxyPolicy,
        request_cancel: Arc<Mutex<Option<CancelToken>>>,
    ) -> Result<Self, String> {
        Ok(Self {
            transport: HttpTransport::with_config(&TransportConfig {
                proxy_policy: proxy,
                request_timeout: Duration::from_secs(35),
                ..TransportConfig::default()
            })
            .map_err(|error| error.to_string())?,
            request_cancel,
        })
    }

    async fn probe_request(
        &self,
        request: HttpRequest,
        cancellation: &CancellationToken,
    ) -> Result<ProviderResponse, ChannelError> {
        let cancel = bind_request_cancellation(self.request_cancel.as_ref(), cancellation)?;
        let _cancel_on_drop = RequestCancelGuard(cancel.clone());
        let _guard = RequestSlotGuard {
            slot: self.request_cancel.as_ref(),
        };
        let response = tokio::select! {
            biased;
            () = cancellation.cancelled() => {
                cancel.cancel();
                return Err(ChannelError::Transport(TransportErrorKind::Io));
            }
            response = self.transport.send(
                "telegram",
                Operation::Transport,
                request,
                &cancel,
            ) => response.map_err(|error| provider_channel_error(&error))?,
        };
        Ok(provider_response(&response))
    }
}

impl TelegramReadinessProbe for TelegramHttpTransport {
    fn probe<'a>(
        &'a self,
        credential: &'a ChannelCredential,
        origin: &'a ApprovedOrigin,
        cancellation: &'a CancellationToken,
    ) -> TelegramProbeFuture<'a> {
        Box::pin(async move {
            let (webhook_request, poll_request) = credential
                .expose_for_origin(
                    "telegram",
                    "default",
                    CredentialKind::Token,
                    origin,
                    telegram_readiness_requests,
                )
                .map_err(ChannelError::CredentialBinding)??;
            let webhook_response = self.probe_request(webhook_request, cancellation).await?;
            classify_telegram_webhook_probe_response(&webhook_response)?;
            let poll_response = self.probe_request(poll_request, cancellation).await?;
            classify_telegram_poll_probe_response(&poll_response)
        })
    }
}

fn telegram_readiness_requests(
    bot_token: &str,
) -> Result<(HttpRequest, HttpRequest), ChannelError> {
    let webhook_url = Url::parse(&format!(
        "https://api.telegram.org/bot{bot_token}/getWebhookInfo"
    ))
    .map_err(|_| ChannelError::Protocol(claw_channel_sdk::ProtocolErrorKind::InvalidField))?;
    let mut poll_url = Url::parse(&format!(
        "https://api.telegram.org/bot{bot_token}/getUpdates"
    ))
    .map_err(|_| ChannelError::Protocol(claw_channel_sdk::ProtocolErrorKind::InvalidField))?;
    {
        let mut query = poll_url.query_pairs_mut();
        query.append_pair("timeout", "0");
        query.append_pair("limit", "1");
    }
    Ok((
        HttpRequest::new(Method::Get, webhook_url)
            .header("accept", "application/json")
            .timeout(Duration::from_secs(10)),
        HttpRequest::new(Method::Get, poll_url)
            .header("accept", "application/json")
            .timeout(Duration::from_secs(10)),
    ))
}

impl TelegramTransport for TelegramHttpTransport {
    fn get_updates(
        &mut self,
        request: &TelegramPollRequest<'_>,
    ) -> Result<ProviderResponse, ChannelError> {
        let mut url = Url::parse(&format!(
            "https://api.telegram.org/bot{}/getUpdates",
            request.bot_token()
        ))
        .map_err(|_| ChannelError::Protocol(claw_channel_sdk::ProtocolErrorKind::InvalidField))?;
        {
            let mut query = url.query_pairs_mut();
            query.append_pair(
                "timeout",
                &request.long_poll_timeout().as_secs().to_string(),
            );
            if let Some(offset) = request.offset() {
                query.append_pair("offset", &offset.to_string());
            }
        }
        let response = blocking_http(
            &self.transport,
            HttpRequest::new(Method::Get, url).timeout(request.request_timeout()),
            Operation::Transport,
            &self.request_cancel,
        )?;
        Ok(provider_response(&response))
    }

    fn send_message(
        &mut self,
        request: &TelegramSendRequest<'_>,
    ) -> Result<ProviderResponse, ChannelError> {
        let url = Url::parse(&format!(
            "https://api.telegram.org/bot{}/sendMessage",
            request.bot_token()
        ))
        .map_err(|_| ChannelError::Protocol(claw_channel_sdk::ProtocolErrorKind::InvalidField))?;
        let body = serde_json::to_string(&json!({
            "chat_id": request.chat_id(),
            "text": request.text(),
            "disable_web_page_preview": request.disable_web_page_preview(),
        }))
        .map_err(|_| ChannelError::Protocol(claw_channel_sdk::ProtocolErrorKind::InvalidField))?;
        let response = blocking_http(
            &self.transport,
            HttpRequest::new(Method::Post, url)
                .header("accept", "application/json")
                .body(Body::Json(body))
                .timeout(request.request_timeout()),
            Operation::Transport,
            &self.request_cancel,
        )?;
        Ok(provider_response(&response))
    }
}

enum DiscordCommand {
    Open(String),
    Send(String),
    Close,
}

enum DiscordEvent {
    Opened,
    Packet(Vec<u8>),
    Closed,
}

#[derive(Clone)]
struct DiscordTransportAdapter {
    commands: mpsc::Sender<DiscordCommand>,
    transport: HttpTransport,
    request_cancel: Arc<Mutex<Option<CancelToken>>>,
}

type DiscordTransportParts = (
    DiscordTransportAdapter,
    mpsc::Receiver<DiscordCommand>,
    mpsc::Sender<DiscordEvent>,
    mpsc::Receiver<DiscordEvent>,
);

impl DiscordTransportAdapter {
    fn new(
        proxy: ProxyPolicy,
        request_cancel: Arc<Mutex<Option<CancelToken>>>,
    ) -> Result<DiscordTransportParts, String> {
        let (command_tx, command_rx) = mpsc::channel(32);
        let (event_tx, event_rx) = mpsc::channel(64);
        Ok((
            Self {
                commands: command_tx,
                transport: HttpTransport::with_config(&TransportConfig {
                    proxy_policy: proxy,
                    request_timeout: Duration::from_secs(10),
                    ..TransportConfig::default()
                })
                .map_err(|error| error.to_string())?,
                request_cancel,
            },
            command_rx,
            event_tx,
            event_rx,
        ))
    }

    fn create_message_request(
        bot_token: &str,
        channel_id: &str,
        content: &str,
    ) -> Result<HttpRequest, ChannelError> {
        let url = Url::parse(&format!(
            "https://discord.com/api/v10/channels/{channel_id}/messages"
        ))
        .map_err(|_| ChannelError::Protocol(claw_channel_sdk::ProtocolErrorKind::InvalidField))?;
        let credential = BoundSecret::new(
            Origin::of(&url).map_err(|_| ChannelError::Authentication)?,
            SecretString::new(bot_token),
        );
        let body = serde_json::to_string(&json!({"content":content})).map_err(|_| {
            ChannelError::Protocol(claw_channel_sdk::ProtocolErrorKind::InvalidField)
        })?;
        Ok(HttpRequest::new(Method::Post, url)
            .header("accept", "application/json")
            .bound_secret_header("authorization", "Bot ", &credential)
            .map_err(|_| ChannelError::Authentication)?
            .body(Body::Json(body))
            .timeout(Duration::from_secs(10)))
    }

    fn create_message_raw(
        &self,
        bot_token: &str,
        channel_id: &str,
        content: &str,
    ) -> Result<ProviderResponse, ChannelError> {
        let response = blocking_http(
            &self.transport,
            Self::create_message_request(bot_token, channel_id, content)?,
            Operation::Transport,
            &self.request_cancel,
        )?;
        Ok(provider_response(&response))
    }

    fn create_message_raw_with_cancellation(
        &self,
        bot_token: &str,
        channel_id: &str,
        content: &str,
        cancellation: &CancellationToken,
    ) -> Result<ProviderResponse, ChannelError> {
        let response = blocking_http_with_cancellation(
            &self.transport,
            Self::create_message_request(bot_token, channel_id, content)?,
            Operation::Transport,
            &self.request_cancel,
            cancellation,
        )?;
        Ok(provider_response(&response))
    }
}

impl DiscordTransport for DiscordTransportAdapter {
    fn open_gateway(&mut self, gateway_url: &str) -> Result<(), ChannelError> {
        self.commands
            .try_send(DiscordCommand::Open(gateway_url.to_owned()))
            .map_err(|_| ChannelError::RateLimited {
                retry_after: Duration::from_millis(100),
            })
    }

    fn close_gateway(&mut self) -> Result<(), ChannelError> {
        self.commands
            .try_send(DiscordCommand::Close)
            .map_err(|_| ChannelError::Transport(TransportErrorKind::Io))
    }

    fn send_gateway(&mut self, request: &DiscordGatewayRequest<'_>) -> Result<(), ChannelError> {
        let payload = match request.opcode() {
            2 => json!({
                "op": 2,
                "d": {
                    "token": request.bot_token().ok_or(ChannelError::Authentication)?,
                    "intents": request.intents().unwrap_or_default(),
                    "properties": {
                        "os": request.platform().unwrap_or(std::env::consts::OS),
                        "browser": request.client_label().unwrap_or("gta-claw"),
                        "device": request.client_label().unwrap_or("gta-claw"),
                    }
                }
            }),
            1 => json!({"op":1,"d":request.sequence()}),
            6 => json!({
                "op": 6,
                "d": {
                    "token": request.bot_token().ok_or(ChannelError::Authentication)?,
                    "session_id": request.session_id().ok_or(ChannelError::Protocol(
                        claw_channel_sdk::ProtocolErrorKind::MissingField,
                    ))?,
                    "seq": request.sequence().ok_or(ChannelError::Protocol(
                        claw_channel_sdk::ProtocolErrorKind::MissingField,
                    ))?,
                }
            }),
            _ => {
                return Err(ChannelError::Protocol(
                    claw_channel_sdk::ProtocolErrorKind::InvalidField,
                ));
            }
        };
        self.commands
            .try_send(DiscordCommand::Send(payload.to_string()))
            .map_err(|_| ChannelError::RateLimited {
                retry_after: Duration::from_millis(100),
            })
    }

    fn create_message(
        &mut self,
        request: &DiscordCreateMessageRequest<'_>,
    ) -> Result<ProviderResponse, ChannelError> {
        self.create_message_raw(request.bot_token(), request.channel_id(), request.content())
    }
}

async fn run_discord_socket(
    mut commands: mpsc::Receiver<DiscordCommand>,
    events: mpsc::Sender<DiscordEvent>,
    cancellation: CancellationToken,
) {
    loop {
        let command = tokio::select! {
            () = cancellation.cancelled() => return,
            command = commands.recv() => command,
        };
        let Some(DiscordCommand::Open(url)) = command else {
            if command.is_none() {
                return;
            }
            continue;
        };
        let Ok((socket, _response)) = tokio_tungstenite::connect_async(url).await else {
            let _ = events.send(DiscordEvent::Closed).await;
            continue;
        };
        let (mut writer, mut reader) = socket.split();
        if events.send(DiscordEvent::Opened).await.is_err() {
            return;
        }
        loop {
            tokio::select! {
                () = cancellation.cancelled() => {
                    let _ = writer.close().await;
                    return;
                }
                command = commands.recv() => match command {
                    Some(DiscordCommand::Send(payload)) => {
                        if writer.send(Message::Text(payload.into())).await.is_err() {
                            break;
                        }
                    }
                    Some(DiscordCommand::Close) => {
                        let _ = writer.close().await;
                        break;
                    }
                    Some(DiscordCommand::Open(_)) => {}
                    None => return,
                },
                message = reader.next() => match message {
                    Some(Ok(Message::Text(text))) => {
                        if events.send(DiscordEvent::Packet(text.as_bytes().to_vec())).await.is_err() {
                            return;
                        }
                    }
                    Some(Ok(Message::Binary(bytes))) => {
                        if events.send(DiscordEvent::Packet(bytes.to_vec())).await.is_err() {
                            return;
                        }
                    }
                    Some(Ok(Message::Ping(payload))) => {
                        if writer.send(Message::Pong(payload)).await.is_err() {
                            break;
                        }
                    }
                    Some(Ok(Message::Close(_)) | Err(_)) | None => break,
                    Some(Ok(_)) => {}
                }
            }
        }
        let _ = events.send(DiscordEvent::Closed).await;
    }
}

#[allow(clippy::too_many_arguments)]
async fn run_discord(
    mut channel: DiscordChannel<DiscordTransportAdapter, SystemClock>,
    gateway_credential: ChannelCredential,
    reply_transport: DiscordTransportAdapter,
    reply_origin: claw_channel_sdk::ApprovedOrigin,
    rest_credential: ChannelCredential,
    mut events: mpsc::Receiver<DiscordEvent>,
    runtime: Arc<AgentRuntime>,
    authentication: Arc<RwLock<Option<String>>>,
    diagnostics: Arc<Diagnostics>,
    cancellation: CancellationToken,
    ready: oneshot::Sender<Result<(), String>>,
    started: Instant,
) {
    let mut ready = Some(ready);
    let (inbound_tx, inbound_rx) = mpsc::channel(64);
    let dispatch_cancellation = cancellation.child_token();
    let dispatch_task = ChildTaskGuard::new(tokio::spawn(run_discord_dispatch(
        inbound_rx,
        reply_transport,
        reply_origin,
        rest_credential,
        Arc::clone(&runtime),
        Arc::clone(&authentication),
        Arc::clone(&diagnostics),
        dispatch_cancellation.clone(),
    )));
    let mut tick = tokio::time::interval(Duration::from_millis(250));
    tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    loop {
        tokio::select! {
            () = cancellation.cancelled() => break,
            event = events.recv() => {
                let Some(event) = event else {
                    break;
                };
                let result = match event {
                    DiscordEvent::Opened => channel.gateway_opened(
                        &mut ChannelDiagnostics(Arc::clone(&diagnostics)),
                    ).map(|()| None),
                    DiscordEvent::Packet(packet) => channel.handle_gateway_packet(
                        &packet,
                        started.elapsed(),
                        &gateway_credential,
                        &mut ChannelDiagnostics(Arc::clone(&diagnostics)),
                    ).map(Some),
                    DiscordEvent::Closed => channel.gateway_closed(
                        started.elapsed(),
                        &mut ChannelDiagnostics(Arc::clone(&diagnostics)),
                    ).map(|_| None),
                };
                match result {
                    Ok(Some(DiscordPacketOutcome::Ready)) => {
                        if let Some(ready) = ready.take() {
                            let _ = ready.send(Ok(()));
                        }
                    }
                    Ok(_) => {}
                    Err(error) => diagnostics.record(format!("Discord event failed: {error}")),
                }
                if let Err(error) = enqueue_discord(
                    &mut channel,
                    &inbound_tx,
                    &diagnostics,
                ) {
                    diagnostics.record(format!("Discord dispatch failed: {error}"));
                }
            }
            _ = tick.tick() => {
                if let Err(error) = channel.tick(
                    started.elapsed(),
                    &mut ChannelDiagnostics(Arc::clone(&diagnostics)),
                ) {
                    diagnostics.record(format!("Discord tick failed: {error}"));
                }
            }
        }
    }
    dispatch_cancellation.cancel();
    drop(inbound_tx);
    if let Err(error) = dispatch_task.join().await {
        diagnostics.record(format!("Discord dispatch task failed: {error}"));
    }
    let _ = channel.stop(&mut ChannelDiagnostics(Arc::clone(&diagnostics)));
    if let Some(ready) = ready {
        let _ = ready.send(Err("Discord stopped before READY".to_owned()));
    }
}

async fn run_telegram(
    mut channel: TelegramChannel<TelegramHttpTransport, SystemClock>,
    credential: ChannelCredential,
    runtime: Arc<AgentRuntime>,
    authentication: Arc<RwLock<Option<String>>>,
    diagnostics: Arc<Diagnostics>,
    readiness: Arc<DependencyReadiness>,
    cancellation: CancellationToken,
) {
    let mut consecutive_failures = 0_u32;
    loop {
        if cancellation.is_cancelled() {
            break;
        }
        let poll_result = channel.poll_once(
            &credential,
            &mut ChannelDiagnostics(Arc::clone(&diagnostics)),
        );
        let retry_after = match &poll_result {
            Ok(_) => {
                consecutive_failures = 0;
                readiness.set("channels", true);
                channel.poll_interval()
            }
            Err(error) => {
                consecutive_failures = consecutive_failures.saturating_add(1);
                diagnostics.record(format!("Telegram poll failed: {error}"));
                if telegram_failure_is_terminal(error) {
                    readiness.set("channels", false);
                    diagnostics.record("Telegram worker stopped after a terminal failure");
                    break;
                }
                if consecutive_failures >= TELEGRAM_PERSISTENT_FAILURES {
                    readiness.set("channels", false);
                }
                error
                    .retry_after()
                    .unwrap_or_else(|| channel.poll_interval())
            }
        };
        while let Ok(Some(message)) = channel.poll_inbound() {
            match process_inbound(
                &message,
                &runtime,
                &authentication,
                &diagnostics,
                cancellation.clone(),
            )
            .await
            {
                Ok(Some(reply)) => {
                    let segments = match segment_outbound_text_iter("telegram", &reply) {
                        Ok(segments) => segments,
                        Err(error) => {
                            diagnostics.record(format!("Telegram segmentation failed: {error}"));
                            continue;
                        }
                    };
                    for segment in segments {
                        let segment = match segment {
                            Ok(segment) => segment.into_owned(),
                            Err(error) => {
                                diagnostics
                                    .record(format!("Telegram segmentation failed: {error}"));
                                break;
                            }
                        };
                        if let Err(error) =
                            channel.send_outbound(&outbound(&message, segment), Some(&credential))
                        {
                            diagnostics.record(format!("Telegram send failed: {error}"));
                            break;
                        }
                    }
                }
                Ok(None) => {}
                Err(error) => diagnostics.record(format!("Telegram dispatch failed: {error}")),
            }
        }
        tokio::select! {
            () = cancellation.cancelled() => break,
            () = tokio::time::sleep(retry_after) => {}
        }
    }
    let _ = channel.stop(&mut ChannelDiagnostics(diagnostics));
}

fn enqueue_discord(
    channel: &mut DiscordChannel<DiscordTransportAdapter, SystemClock>,
    inbound: &mpsc::Sender<InboundMessage>,
    diagnostics: &Arc<Diagnostics>,
) -> Result<(), ChannelError> {
    while let Some(message) = channel.poll_inbound()? {
        if inbound.try_send(message).is_err() {
            diagnostics.record("Discord inbound dispatch queue is full");
            return Err(ChannelError::RateLimited {
                retry_after: Duration::from_millis(250),
            });
        }
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
async fn run_discord_dispatch(
    mut inbound: mpsc::Receiver<InboundMessage>,
    transport: DiscordTransportAdapter,
    origin: claw_channel_sdk::ApprovedOrigin,
    credential: ChannelCredential,
    runtime: Arc<AgentRuntime>,
    authentication: Arc<RwLock<Option<String>>>,
    diagnostics: Arc<Diagnostics>,
    cancellation: CancellationToken,
) {
    loop {
        let message = tokio::select! {
            () = cancellation.cancelled() => return,
            message = inbound.recv() => message,
        };
        let Some(message) = message else {
            return;
        };
        match process_inbound(
            &message,
            &runtime,
            &authentication,
            &diagnostics,
            cancellation.clone(),
        )
        .await
        {
            Ok(Some(reply)) => {
                if let Err(error) = send_discord_reply(
                    &transport,
                    &origin,
                    &credential,
                    &message,
                    &reply,
                    &cancellation,
                )
                .await
                {
                    diagnostics.record(format!("Discord reply failed: {error}"));
                }
            }
            Ok(None) => {}
            Err(error) => diagnostics.record(format!("Discord dispatch failed: {error}")),
        }
    }
}

trait DiscordReplyTransport: Sync {
    fn send_reply_raw(
        &self,
        bot_token: &str,
        channel_id: &str,
        content: &str,
        cancellation: &CancellationToken,
    ) -> Result<ProviderResponse, ChannelError>;
}

impl DiscordReplyTransport for DiscordTransportAdapter {
    fn send_reply_raw(
        &self,
        bot_token: &str,
        channel_id: &str,
        content: &str,
        cancellation: &CancellationToken,
    ) -> Result<ProviderResponse, ChannelError> {
        self.create_message_raw_with_cancellation(bot_token, channel_id, content, cancellation)
    }
}

async fn send_discord_reply<T: DiscordReplyTransport>(
    transport: &T,
    origin: &claw_channel_sdk::ApprovedOrigin,
    credential: &ChannelCredential,
    message: &InboundMessage,
    reply: &str,
    cancellation: &CancellationToken,
) -> Result<(), ChannelError> {
    let route =
        message
            .conversation_id
            .strip_prefix("discord:")
            .ok_or(ChannelError::Configuration(
                claw_channel_sdk::ConfigurationError::ConversationScopeMismatch,
            ))?;
    let (channel_id, _sender_id) = route.split_once(':').ok_or(ChannelError::Configuration(
        claw_channel_sdk::ConfigurationError::ConversationScopeMismatch,
    ))?;
    let segments = segment_outbound_text_iter("discord", reply).map_err(|_| {
        ChannelError::Configuration(
            claw_channel_sdk::ConfigurationError::InvalidAdapterConfiguration,
        )
    })?;
    for segment in segments {
        let segment = segment
            .map_err(|_| {
                ChannelError::Configuration(
                    claw_channel_sdk::ConfigurationError::InvalidAdapterConfiguration,
                )
            })?
            .into_owned();
        for attempt in 1..=DISCORD_REPLY_MAX_ATTEMPTS {
            if cancellation.is_cancelled() {
                return Err(ChannelError::Transport(TransportErrorKind::Io));
            }
            let response = credential
                .expose_for_origin(
                    "discord",
                    "default",
                    CredentialKind::Token,
                    origin,
                    |bot_token| {
                        transport.send_reply_raw(bot_token, channel_id, &segment, cancellation)
                    },
                )
                .map_err(ChannelError::CredentialBinding)??;
            require_provider_response_bounded(&response)?;
            match response.status() {
                200..=299 => break,
                401 | 403 => return Err(ChannelError::Authentication),
                429 => {
                    let retry_after = response
                        .retry_after()
                        .unwrap_or_else(|| Duration::from_secs(1));
                    if attempt == DISCORD_REPLY_MAX_ATTEMPTS {
                        return Err(ChannelError::RateLimited { retry_after });
                    }
                    tokio::select! {
                        biased;
                        () = cancellation.cancelled() => {
                            return Err(ChannelError::Transport(TransportErrorKind::Io));
                        }
                        () = tokio::time::sleep(retry_after) => {}
                    }
                }
                status => return Err(ChannelError::RemoteRejected { status }),
            }
        }
    }
    Ok(())
}

async fn process_inbound(
    message: &InboundMessage,
    runtime: &Arc<AgentRuntime>,
    authentication: &Arc<RwLock<Option<String>>>,
    diagnostics: &Arc<Diagnostics>,
    cancellation: CancellationToken,
) -> Result<Option<String>, ChannelError> {
    let text = message.text.as_deref().unwrap_or_default();
    let instructions = authentication
        .read()
        .unwrap_or_else(PoisonError::into_inner)
        .clone();
    let mut conversation = runtime.conversation_with_cancellation(cancellation);
    let outcome = dispatch_incoming(
        runtime.authenticated().then_some(&mut conversation),
        instructions.as_deref().map_or(
            AuthenticationPrompt::Unconfigured,
            AuthenticationPrompt::Instructions,
        ),
        claw_channels::COMMON_DISPATCH_POLICY,
        DispatchInput {
            channel_id: match message.channel_id.as_str() {
                "telegram" => "telegram",
                "discord" => "discord",
                _ => {
                    return Err(ChannelError::Configuration(
                        claw_channel_sdk::ConfigurationError::InvalidAdapterConfiguration,
                    ));
                }
            },
            account_id: &message.account_id,
            conversation_id: &message.conversation_id,
            sender_id: &message.sender_id,
            bot_mention: None,
            text,
        },
        &mut ChannelDiagnostics(Arc::clone(diagnostics)),
    )
    .map_err(|_| {
        ChannelError::Configuration(
            claw_channel_sdk::ConfigurationError::InvalidAdapterConfiguration,
        )
    })?;
    match outcome {
        DispatchOutcome::Ignored => Ok(None),
        DispatchOutcome::Reply { text, .. } => Ok(Some(text)),
        DispatchOutcome::DeferredCommand(invocation) => runtime
            .channel_command(&message.conversation_id, &invocation.name)
            .await
            .map(Some)
            .map_err(|_| ChannelError::RemoteRejected { status: 503 }),
    }
}

fn outbound(message: &InboundMessage, text: String) -> OutboundMessage {
    OutboundMessage {
        correlation_key: format!("reply:{}", message.id),
        account_id: message.account_id.clone(),
        conversation_id: message.conversation_id.clone(),
        text: Some(text),
        attachments: Vec::new(),
        reply_to: None,
    }
}

fn provider_response(response: &claw_provider_sdk::http::HttpResponse) -> ProviderResponse {
    let retry_after = response
        .header("retry-after")
        .and_then(parse_retry_after_header);
    ProviderResponse::with_retry_after(response.status(), response.body().to_vec(), retry_after)
}

fn parse_retry_after_header(value: &str) -> Option<Duration> {
    let value = value.trim();
    if let Ok(seconds) = value.parse::<u64>() {
        return Some(Duration::from_secs(seconds));
    }
    Duration::try_from_secs_f64(value.parse::<f64>().ok()?).ok()
}

fn require_provider_response_bounded(response: &ProviderResponse) -> Result<(), ChannelError> {
    if response.body().len() > MAX_PROVIDER_RESPONSE_BYTES {
        Err(ChannelError::Protocol(
            claw_channel_sdk::ProtocolErrorKind::PayloadTooLarge,
        ))
    } else {
        Ok(())
    }
}

fn parse_telegram_probe_response(
    response: &ProviderResponse,
) -> Result<serde_json::Value, ChannelError> {
    match response.status() {
        200..=299 => {
            require_provider_response_bounded(response)?;
            let body: serde_json::Value =
                serde_json::from_slice(response.body()).map_err(|_| {
                    ChannelError::Protocol(claw_channel_sdk::ProtocolErrorKind::MalformedResponse)
                })?;
            if body.get("ok").and_then(serde_json::Value::as_bool) == Some(true) {
                Ok(body)
            } else {
                Err(ChannelError::Protocol(
                    claw_channel_sdk::ProtocolErrorKind::InvalidField,
                ))
            }
        }
        401 | 403 => Err(ChannelError::Authentication),
        429 => {
            require_provider_response_bounded(response)?;
            let body_retry_after = serde_json::from_slice::<serde_json::Value>(response.body())
                .ok()
                .and_then(|body| {
                    body.get("parameters")
                        .and_then(|parameters| parameters.get("retry_after"))
                        .and_then(serde_json::Value::as_u64)
                })
                .map(Duration::from_secs);
            Err(ChannelError::RateLimited {
                retry_after: response
                    .retry_after()
                    .or(body_retry_after)
                    .unwrap_or_else(|| Duration::from_secs(1)),
            })
        }
        status => Err(ChannelError::RemoteRejected { status }),
    }
}

fn classify_telegram_webhook_probe_response(
    response: &ProviderResponse,
) -> Result<(), ChannelError> {
    let body = parse_telegram_probe_response(response)?;
    match body
        .get("result")
        .and_then(|result| result.get("url"))
        .and_then(serde_json::Value::as_str)
    {
        Some("") => Ok(()),
        Some(_) => Err(ChannelError::RemoteRejected { status: 409 }),
        None => Err(ChannelError::Protocol(
            claw_channel_sdk::ProtocolErrorKind::InvalidField,
        )),
    }
}

fn classify_telegram_poll_probe_response(response: &ProviderResponse) -> Result<(), ChannelError> {
    let body = parse_telegram_probe_response(response)?;
    if body.get("result").is_some_and(serde_json::Value::is_array) {
        Ok(())
    } else {
        Err(ChannelError::Protocol(
            claw_channel_sdk::ProtocolErrorKind::InvalidField,
        ))
    }
}

fn provider_channel_error(error: &claw_provider_sdk::ProviderError) -> ChannelError {
    match error.kind() {
        claw_provider_sdk::ErrorKind::Authentication => ChannelError::Authentication,
        claw_provider_sdk::ErrorKind::RateLimit => ChannelError::RateLimited {
            retry_after: error.retry_after().unwrap_or(Duration::from_secs(1)),
        },
        claw_provider_sdk::ErrorKind::Timeout => {
            ChannelError::Transport(TransportErrorKind::Timeout)
        }
        claw_provider_sdk::ErrorKind::Transport => {
            ChannelError::Transport(TransportErrorKind::Connection)
        }
        claw_provider_sdk::ErrorKind::Protocol => {
            ChannelError::Protocol(claw_channel_sdk::ProtocolErrorKind::MalformedResponse)
        }
        _ => ChannelError::RemoteRejected { status: 503 },
    }
}

#[cfg(test)]
mod tests {
    use std::collections::VecDeque;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::{Arc, Mutex, PoisonError};
    use std::time::{Duration, Instant};

    use claw_channel_sdk::{
        ApprovedOrigin, ChannelCredential, ChannelError, CredentialKind, InboundMessage,
        TransportErrorKind,
    };
    use claw_channels::ProviderResponse;
    use claw_provider_sdk::{CancelToken, SecretString};
    use tokio_util::sync::CancellationToken;
    use tokio_util::task::TaskTracker;

    use super::{
        ChannelStartGuard, DiscordReplyTransport, TelegramProbeFuture, TelegramReadinessError,
        TelegramReadinessProbe, approved_origin, bind_credential, bind_request_cancellation,
        cancel_requests, classify_telegram_poll_probe_response,
        classify_telegram_webhook_probe_response, parse_retry_after_header, send_discord_reply,
        telegram_readiness_requests, wait_for_telegram_readiness,
    };

    struct ScriptedTelegramProbe {
        results: Mutex<VecDeque<Result<(), ChannelError>>>,
        calls: AtomicUsize,
    }

    impl TelegramReadinessProbe for ScriptedTelegramProbe {
        fn probe<'a>(
            &'a self,
            _credential: &'a ChannelCredential,
            _origin: &'a ApprovedOrigin,
            _cancellation: &'a CancellationToken,
        ) -> TelegramProbeFuture<'a> {
            Box::pin(async move {
                self.calls.fetch_add(1, Ordering::SeqCst);
                self.results
                    .lock()
                    .unwrap_or_else(PoisonError::into_inner)
                    .pop_front()
                    .expect("scripted Telegram readiness result")
            })
        }
    }

    fn telegram_probe_credential() -> (ApprovedOrigin, ChannelCredential) {
        let origin = approved_origin("telegram", "default", "api.telegram.org").expect("origin");
        let credential = bind_credential(
            "telegram",
            "default",
            CredentialKind::Token,
            origin.clone(),
            &SecretString::new("telegram-secret"),
        )
        .expect("credential");
        (origin, credential)
    }

    struct ScriptedDiscordReplies {
        responses: Mutex<VecDeque<Result<ProviderResponse, ChannelError>>>,
        calls: AtomicUsize,
        cancel_on_call: AtomicUsize,
    }

    impl DiscordReplyTransport for ScriptedDiscordReplies {
        fn send_reply_raw(
            &self,
            bot_token: &str,
            channel_id: &str,
            content: &str,
            cancellation: &CancellationToken,
        ) -> Result<ProviderResponse, ChannelError> {
            assert_eq!(bot_token, "discord-secret");
            assert_eq!(channel_id, "room");
            assert_eq!(content, "reply");
            let call = self.calls.fetch_add(1, Ordering::SeqCst) + 1;
            if self.cancel_on_call.load(Ordering::SeqCst) == call {
                cancellation.cancel();
            }
            self.responses
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .pop_front()
                .expect("scripted Discord response")
        }
    }

    fn discord_reply_fixture(
        responses: VecDeque<Result<ProviderResponse, ChannelError>>,
    ) -> (
        ScriptedDiscordReplies,
        claw_channel_sdk::ApprovedOrigin,
        claw_channel_sdk::ChannelCredential,
        InboundMessage,
    ) {
        let origin = approved_origin("discord", "default", "discord.com").expect("origin");
        let credential = bind_credential(
            "discord",
            "default",
            CredentialKind::Token,
            origin.clone(),
            &SecretString::new("discord-secret"),
        )
        .expect("credential");
        (
            ScriptedDiscordReplies {
                responses: Mutex::new(responses),
                calls: AtomicUsize::new(0),
                cancel_on_call: AtomicUsize::new(0),
            },
            origin,
            credential,
            InboundMessage {
                id: "message-1".to_owned(),
                channel_id: "discord".to_owned(),
                account_id: "default".to_owned(),
                conversation_id: "discord:room:user".to_owned(),
                sender_id: "user".to_owned(),
                text: Some("question".to_owned()),
                attachments: Vec::new(),
                received_at_unix_ms: 1,
            },
        )
    }

    #[tokio::test]
    async fn dropping_channel_start_aborts_accepted_workers() {
        let cancellation = CancellationToken::new();
        let tracker = TaskTracker::new();
        let task = tracker.spawn(std::future::pending::<()>());
        let abort = task.abort_handle();
        let aborts = Mutex::new(vec![abort.clone()]);
        let request_cancel = CancelToken::new();
        let request_cancellations = Arc::new(Mutex::new(vec![Arc::new(Mutex::new(Some(
            request_cancel.clone(),
        )))]));
        drop(task);
        {
            let _guard = ChannelStartGuard {
                cancellation: &cancellation,
                aborts: &aborts,
                request_cancellations,
                armed: true,
            };
        }
        tokio::time::timeout(Duration::from_secs(1), async {
            while !abort.is_finished() {
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("worker abort finishes");
        assert!(cancellation.is_cancelled());
        assert!(request_cancel.is_cancelled());
        assert_eq!(
            aborts.lock().unwrap_or_else(PoisonError::into_inner).len(),
            1
        );
    }

    #[test]
    fn discord_request_cancellation_binding_closes_shutdown_races() {
        let cancellation = CancellationToken::new();
        let request_slot = Arc::new(Mutex::new(None));
        let request_cancel =
            bind_request_cancellation(request_slot.as_ref(), &cancellation).expect("bound request");
        let requests = Arc::new(Mutex::new(vec![Arc::clone(&request_slot)]));

        cancellation.cancel();
        cancel_requests(&requests);
        assert!(request_cancel.is_cancelled());

        let late_slot = Mutex::new(None);
        assert!(matches!(
            bind_request_cancellation(&late_slot, &cancellation),
            Err(ChannelError::Transport(TransportErrorKind::Io))
        ));
        assert!(
            late_slot
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .is_none()
        );
    }

    #[tokio::test]
    async fn discord_reply_honors_retry_after_and_retries_only_429() {
        let retry_after = Duration::from_millis(20);
        let (transport, origin, credential, message) = discord_reply_fixture(VecDeque::from([
            Ok(ProviderResponse::with_retry_after(
                429,
                Vec::new(),
                Some(retry_after),
            )),
            Ok(ProviderResponse::new(200, Vec::new())),
        ]));
        let started = Instant::now();

        send_discord_reply(
            &transport,
            &origin,
            &credential,
            &message,
            "reply",
            &CancellationToken::new(),
        )
        .await
        .expect("rate-limited reply recovers");

        assert!(started.elapsed() >= retry_after);
        assert_eq!(transport.calls.load(Ordering::SeqCst), 2);
    }

    #[tokio::test]
    async fn discord_reply_bounds_persistent_rate_limit_retries() {
        let retry_after = Duration::from_millis(1);
        let limited = || {
            Ok(ProviderResponse::with_retry_after(
                429,
                Vec::new(),
                Some(retry_after),
            ))
        };
        let (transport, origin, credential, message) =
            discord_reply_fixture(VecDeque::from([limited(), limited(), limited()]));

        assert_eq!(
            send_discord_reply(
                &transport,
                &origin,
                &credential,
                &message,
                "reply",
                &CancellationToken::new(),
            )
            .await,
            Err(ChannelError::RateLimited { retry_after })
        );
        assert_eq!(transport.calls.load(Ordering::SeqCst), 3);
    }

    #[tokio::test]
    async fn discord_reply_does_not_start_after_cancellation() {
        let (transport, origin, credential, message) =
            discord_reply_fixture(VecDeque::from([Ok(ProviderResponse::new(200, Vec::new()))]));
        let cancellation = CancellationToken::new();
        cancellation.cancel();

        assert_eq!(
            send_discord_reply(
                &transport,
                &origin,
                &credential,
                &message,
                "reply",
                &cancellation,
            )
            .await,
            Err(ChannelError::Transport(TransportErrorKind::Io))
        );
        assert_eq!(transport.calls.load(Ordering::SeqCst), 0);
    }

    #[tokio::test]
    async fn discord_reply_binds_cancellation_and_stops_before_retry() {
        let retry_after = Duration::from_secs(1);
        let (transport, origin, credential, message) = discord_reply_fixture(VecDeque::from([
            Ok(ProviderResponse::with_retry_after(
                429,
                Vec::new(),
                Some(retry_after),
            )),
            Ok(ProviderResponse::new(200, Vec::new())),
        ]));
        transport.cancel_on_call.store(1, Ordering::SeqCst);
        let cancellation = CancellationToken::new();

        assert_eq!(
            send_discord_reply(
                &transport,
                &origin,
                &credential,
                &message,
                "reply",
                &cancellation,
            )
            .await,
            Err(ChannelError::Transport(TransportErrorKind::Io))
        );
        assert!(cancellation.is_cancelled());
        assert_eq!(transport.calls.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn telegram_readiness_requires_a_success_and_honors_retry_after() {
        let retry_after = Duration::from_millis(20);
        let probe = ScriptedTelegramProbe {
            results: Mutex::new(VecDeque::from([
                Err(ChannelError::RateLimited { retry_after }),
                Ok(()),
            ])),
            calls: AtomicUsize::new(0),
        };
        let (origin, credential) = telegram_probe_credential();
        let started = Instant::now();

        wait_for_telegram_readiness(
            &probe,
            &credential,
            &origin,
            &CancellationToken::new(),
            Duration::from_millis(1),
            3,
        )
        .await
        .expect("probe eventually succeeds");

        assert!(started.elapsed() >= retry_after);
        assert_eq!(probe.calls.load(Ordering::SeqCst), 2);
    }

    #[tokio::test]
    async fn telegram_readiness_fails_fast_terminal_and_bounds_persistent_failure() {
        let (origin, credential) = telegram_probe_credential();
        let terminal_failure =
            classify_telegram_poll_probe_response(&ProviderResponse::new(409, Vec::new()))
                .expect_err("poll conflict is terminal");
        let terminal = ScriptedTelegramProbe {
            results: Mutex::new(VecDeque::from([Err(terminal_failure.clone()), Ok(())])),
            calls: AtomicUsize::new(0),
        };
        assert_eq!(
            wait_for_telegram_readiness(
                &terminal,
                &credential,
                &origin,
                &CancellationToken::new(),
                Duration::from_millis(1),
                3,
            )
            .await,
            Err(TelegramReadinessError::Terminal(terminal_failure))
        );
        assert_eq!(terminal.calls.load(Ordering::SeqCst), 1);

        let failure = ChannelError::Transport(TransportErrorKind::Timeout);
        let persistent = ScriptedTelegramProbe {
            results: Mutex::new(VecDeque::from([
                Err(failure.clone()),
                Err(failure.clone()),
                Err(failure.clone()),
            ])),
            calls: AtomicUsize::new(0),
        };
        assert_eq!(
            wait_for_telegram_readiness(
                &persistent,
                &credential,
                &origin,
                &CancellationToken::new(),
                Duration::from_millis(1),
                3,
            )
            .await,
            Err(TelegramReadinessError::Persistent(failure))
        );
        assert_eq!(persistent.calls.load(Ordering::SeqCst), 3);

        let cancelled_probe = ScriptedTelegramProbe {
            results: Mutex::new(VecDeque::from([Ok(())])),
            calls: AtomicUsize::new(0),
        };
        let cancellation = CancellationToken::new();
        cancellation.cancel();
        assert_eq!(
            wait_for_telegram_readiness(
                &cancelled_probe,
                &credential,
                &origin,
                &cancellation,
                Duration::from_millis(1),
                3,
            )
            .await,
            Err(TelegramReadinessError::Cancelled)
        );
        assert_eq!(cancelled_probe.calls.load(Ordering::SeqCst), 0);
    }

    #[test]
    fn telegram_readiness_requests_check_webhook_then_zero_timeout_polling() {
        let (webhook_request, poll_request) =
            telegram_readiness_requests("telegram-secret").expect("readiness requests");

        assert_eq!(
            webhook_request.url().path(),
            "/bottelegram-secret/getWebhookInfo"
        );
        assert_eq!(poll_request.url().path(), "/bottelegram-secret/getUpdates");
        assert_eq!(poll_request.url().query(), Some("timeout=0&limit=1"));
    }

    #[test]
    fn telegram_poll_probe_requires_a_bounded_result_array() {
        assert_eq!(
            classify_telegram_poll_probe_response(&ProviderResponse::new(
                200,
                br#"{"ok":true,"result":[]}"#.as_slice(),
            )),
            Ok(())
        );
        assert_eq!(
            classify_telegram_poll_probe_response(&ProviderResponse::new(
                200,
                br#"{"ok":false}"#.as_slice(),
            )),
            Err(ChannelError::Protocol(
                claw_channel_sdk::ProtocolErrorKind::InvalidField
            ))
        );
        assert_eq!(
            classify_telegram_poll_probe_response(&ProviderResponse::new(
                200,
                br#"{"ok":true,"result":{"id":1}}"#.as_slice(),
            )),
            Err(ChannelError::Protocol(
                claw_channel_sdk::ProtocolErrorKind::InvalidField
            ))
        );
    }

    #[test]
    fn telegram_webhook_probe_rejects_an_active_webhook() {
        assert_eq!(
            classify_telegram_webhook_probe_response(&ProviderResponse::new(
                200,
                br#"{"ok":true,"result":{"url":""}}"#.as_slice(),
            )),
            Ok(())
        );
        assert_eq!(
            classify_telegram_webhook_probe_response(&ProviderResponse::new(
                200,
                br#"{"ok":true,"result":{"url":"https://example.test/telegram"}}"#.as_slice(),
            )),
            Err(ChannelError::RemoteRejected { status: 409 })
        );
    }

    #[test]
    fn discord_fractional_retry_after_header_is_preserved() {
        assert_eq!(
            parse_retry_after_header("0.25"),
            Some(Duration::from_millis(250))
        );
        assert_eq!(
            parse_retry_after_header("17"),
            Some(Duration::from_secs(17))
        );
        assert_eq!(parse_retry_after_header("-1"), None);
        assert_eq!(parse_retry_after_header("NaN"), None);
    }
}

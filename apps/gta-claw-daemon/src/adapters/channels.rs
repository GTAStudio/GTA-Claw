//! Supervised Telegram and Discord channel transports.

use std::num::{NonZeroU32, NonZeroUsize};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, PoisonError, RwLock};
use std::time::{Duration, Instant};

use claw_channel_sdk::{
    Channel, ChannelCredential, ChannelError, CredentialBinding, CredentialKind, CredentialRequest,
    InboundMessage, NetworkOrigin, OriginTrustError, OriginTrustStore, OutboundMessage,
    TransportErrorKind, authorize_origin,
};
use claw_channels::{
    AuthenticationPrompt, DiagnosticLevel, DiagnosticSink, DiscordChannel,
    DiscordCreateMessageRequest, DiscordGatewayRequest, DiscordPacketOutcome, DiscordTransport,
    DispatchInput, DispatchOutcome, OperatorDiagnostic, ProviderResponse, SystemClock,
    TelegramChannel, TelegramPollRequest, TelegramSendRequest, TelegramTransport,
    dispatch_incoming, segment_outbound_text_iter,
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
use super::http_api::Diagnostics;

const CHANNEL_START_TIMEOUT: Duration = Duration::from_secs(20);
const CHANNEL_STOP_GRACE: Duration = Duration::from_secs(2);

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

/// Owns every polling/socket task started for configured channels.
pub struct ChannelSupervisor {
    cancellation: CancellationToken,
    tracker: TaskTracker,
    aborts: Mutex<Vec<AbortHandle>>,
    request_cancellations: Vec<Arc<Mutex<Option<CancelToken>>>>,
    spawned: u64,
    terminated: Arc<AtomicU64>,
}

struct ChannelStartGuard<'a> {
    cancellation: &'a CancellationToken,
    aborts: &'a Mutex<Vec<AbortHandle>>,
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
        for slot in &self.request_cancellations {
            if let Some(cancel) = slot.lock().unwrap_or_else(PoisonError::into_inner).as_ref() {
                cancel.cancel();
            }
        }
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
        startup_cancellation: CancellationToken,
    ) -> Result<Self, String> {
        let cancellation = startup_cancellation.child_token();
        let tracker = TaskTracker::new();
        let terminated = Arc::new(AtomicU64::new(0));
        let aborts = Mutex::new(Vec::new());
        let mut start_guard = ChannelStartGuard {
            cancellation: &cancellation,
            aborts: &aborts,
            armed: true,
        };
        let mut request_cancellations = Vec::new();
        let mut spawned = 0_u64;

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
            let task_terminated = Arc::clone(&terminated);
            let handle = tracker.spawn(async move {
                let _guard = TerminationGuard(task_terminated);
                run_telegram(
                    channel,
                    credential,
                    task_runtime,
                    task_authentication,
                    task_diagnostics,
                    task_cancel,
                )
                .await;
            });
            aborts
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .push(handle.abort_handle());
            drop(handle);
            request_cancellations.push(request_cancel);
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
            request_cancellations.push(request_cancel);
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
        for slot in &self.request_cancellations {
            if let Some(cancel) = slot.lock().unwrap_or_else(PoisonError::into_inner).as_ref() {
                cancel.cancel();
            }
        }
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

    fn create_message_raw(
        &self,
        bot_token: &str,
        channel_id: &str,
        content: &str,
    ) -> Result<ProviderResponse, ChannelError> {
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
        let http_request = HttpRequest::new(Method::Post, url)
            .header("accept", "application/json")
            .bound_secret_header("authorization", "Bot ", &credential)
            .map_err(|_| ChannelError::Authentication)?
            .body(Body::Json(body))
            .timeout(Duration::from_secs(10));
        let response = blocking_http(
            &self.transport,
            http_request,
            Operation::Transport,
            &self.request_cancel,
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
    cancellation: CancellationToken,
) {
    loop {
        if cancellation.is_cancelled() {
            break;
        }
        if let Err(error) = channel.poll_once(
            &credential,
            &mut ChannelDiagnostics(Arc::clone(&diagnostics)),
        ) {
            diagnostics.record(format!("Telegram poll failed: {error}"));
        }
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
            () = tokio::time::sleep(channel.poll_interval()) => {}
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
                if let Err(error) =
                    send_discord_reply(&transport, &origin, &credential, &message, &reply)
                {
                    diagnostics.record(format!("Discord reply failed: {error}"));
                }
            }
            Ok(None) => {}
            Err(error) => diagnostics.record(format!("Discord dispatch failed: {error}")),
        }
    }
}

fn send_discord_reply(
    transport: &DiscordTransportAdapter,
    origin: &claw_channel_sdk::ApprovedOrigin,
    credential: &ChannelCredential,
    message: &InboundMessage,
    reply: &str,
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
    credential
        .expose_for_origin(
            "discord",
            "default",
            CredentialKind::Token,
            origin,
            |bot_token| -> Result<(), ChannelError> {
                for segment in segments {
                    let segment = segment.map_err(|_| {
                        ChannelError::Configuration(
                            claw_channel_sdk::ConfigurationError::InvalidAdapterConfiguration,
                        )
                    })?;
                    let response =
                        transport.create_message_raw(bot_token, channel_id, segment.as_ref())?;
                    if !(200..300).contains(&response.status()) {
                        return Err(ChannelError::RemoteRejected {
                            status: response.status(),
                        });
                    }
                }
                Ok(())
            },
        )
        .map_err(ChannelError::CredentialBinding)?
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
        .and_then(|value| value.parse::<u64>().ok())
        .map(Duration::from_secs);
    ProviderResponse::with_retry_after(response.status(), response.body().to_vec(), retry_after)
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
    use std::sync::{Mutex, PoisonError};
    use std::time::Duration;

    use tokio_util::sync::CancellationToken;
    use tokio_util::task::TaskTracker;

    use super::ChannelStartGuard;

    #[tokio::test]
    async fn dropping_channel_start_aborts_accepted_workers() {
        let cancellation = CancellationToken::new();
        let tracker = TaskTracker::new();
        let task = tracker.spawn(std::future::pending::<()>());
        let abort = task.abort_handle();
        let aborts = Mutex::new(vec![abort.clone()]);
        drop(task);
        {
            let _guard = ChannelStartGuard {
                cancellation: &cancellation,
                aborts: &aborts,
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
        assert_eq!(
            aborts.lock().unwrap_or_else(PoisonError::into_inner).len(),
            1
        );
    }
}

//! Supervised Telegram and Discord channel transports.

use std::fmt::{self, Display, Formatter};
use std::future::Future;
use std::num::{NonZeroU32, NonZeroUsize};
use std::pin::Pin;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, PoisonError, RwLock};
use std::time::{Duration, Instant};

use claw_channel_sdk::{
    ApprovedOrigin, Channel, ChannelCredential, ChannelError, ConnectionState, CredentialBinding,
    CredentialKind, CredentialRequest, InboundMessage, NetworkOrigin, OriginTrustError,
    OriginTrustStore, OutboundMessage, TransportErrorKind, authorize_origin,
};
use claw_channels::{
    AuthenticationPrompt, DiagnosticLevel, DiagnosticSink, DiscordChannel,
    DiscordCreateMessageRequest, DiscordGatewayClose, DiscordGatewayRequest, DiscordPacketOutcome,
    DiscordTransport, DispatchInput, DispatchOutcome, MAX_PROVIDER_RESPONSE_BYTES,
    OperatorDiagnostic, ProviderResponse, SystemClock, TelegramChannel, TelegramPollRequest,
    TelegramSendRequest, TelegramTransport, dispatch_incoming, segment_outbound_text_iter,
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

struct TelegramPollIdentity {
    credential: ChannelCredential,
    binding: String,
}

impl TelegramPollIdentity {
    fn new(credential: ChannelCredential, origin: &ApprovedOrigin) -> Result<Self, String> {
        use sha2::{Digest, Sha256};
        let binding = credential
            .expose_for_origin(
                "telegram",
                origin.account_id(),
                CredentialKind::Token,
                origin,
                |token| {
                    const HEX: &[u8; 16] = b"0123456789abcdef";
                    let mut digest = Sha256::new();
                    digest.update(b"gta-claw/telegram-poll/v1");
                    for value in [origin.account_id(), &origin.as_str(), token] {
                        digest.update((value.len() as u64).to_le_bytes());
                        digest.update(value.as_bytes());
                    }
                    let mut encoded = String::with_capacity(64);
                    for byte in digest.finalize() {
                        encoded.push(char::from(HEX[usize::from(byte >> 4)]));
                        encoded.push(char::from(HEX[usize::from(byte & 15)]));
                    }
                    encoded
                },
            )
            .map_err(|_| "Telegram cursor credential binding is invalid".to_owned())?;
        Ok(Self {
            credential,
            binding,
        })
    }
}

struct DiscordResumeProgress {
    latest: Option<claw_state::DiscordResume>,
    settled: Option<claw_state::DiscordResume>,
    pending: std::collections::VecDeque<claw_state::DiscordResume>,
}

impl DiscordResumeProgress {
    fn new(resume: Option<claw_state::DiscordResume>) -> Self {
        Self {
            latest: resume.clone(),
            settled: resume,
            pending: std::collections::VecDeque::new(),
        }
    }

    fn observe(
        &mut self,
        resume: Option<claw_state::DiscordResume>,
        queued: usize,
    ) -> Result<(), &'static str> {
        if self.pending.len().saturating_add(queued) > 65
            || queued > 0 && resume.is_none()
            || !self.pending.is_empty()
                && self
                    .latest
                    .as_ref()
                    .map(claw_state::DiscordResume::session_id)
                    != resume.as_ref().map(claw_state::DiscordResume::session_id)
            || self
                .latest
                .as_ref()
                .zip(resume.as_ref())
                .is_some_and(|(old, next)| {
                    old.session_id() == next.session_id() && next.sequence() < old.sequence()
                })
        {
            return Err("Discord resume progress changed across unresolved messages");
        }
        if let Some(resume) = &resume {
            self.pending
                .extend(std::iter::repeat_n(resume.clone(), queued));
        }
        self.latest = resume;
        if self.pending.is_empty() {
            self.settled = self.latest.clone();
        }
        Ok(())
    }

    fn complete(
        &mut self,
        resume: &claw_state::DiscordResume,
        succeeded: bool,
    ) -> Result<(), &'static str> {
        if !succeeded || self.pending.front() != Some(resume) {
            return Err("Discord message did not settle at the expected resume sequence");
        }
        self.pending.pop_front();
        if self.pending.front() != Some(resume) {
            self.settled = if self.pending.is_empty() {
                self.latest.clone()
            } else {
                Some(resume.clone())
            };
        }
        Ok(())
    }
}

struct DiscordResumeCheckpoint {
    binding: String,
    revision: u64,
    saved: Option<claw_state::DiscordResume>,
    progress: DiscordResumeProgress,
}

impl DiscordResumeCheckpoint {
    async fn load(
        credential: &ChannelCredential,
        origin: &ApprovedOrigin,
        gateway_url: &str,
        intents: u64,
        runtime: &AgentRuntime,
    ) -> Result<Self, String> {
        use sha2::{Digest, Sha256};
        let binding = credential
            .expose_for_origin(
                "discord",
                origin.account_id(),
                CredentialKind::Token,
                origin,
                |token| {
                    const HEX: &[u8; 16] = b"0123456789abcdef";
                    let mut digest = Sha256::new();
                    digest.update(b"gta-claw/discord-resume/v1");
                    digest.update(intents.to_le_bytes());
                    for value in [origin.account_id(), gateway_url, token] {
                        digest.update((value.len() as u64).to_le_bytes());
                        digest.update(value.as_bytes());
                    }
                    let mut encoded = String::with_capacity(64);
                    for byte in digest.finalize() {
                        encoded.push(char::from(HEX[usize::from(byte >> 4)]));
                        encoded.push(char::from(HEX[usize::from(byte & 15)]));
                    }
                    encoded
                },
            )
            .map_err(|_| "Discord resume credential binding is invalid".to_owned())?;
        let (revision, saved) = runtime
            .discord_resume(&binding)
            .await
            .map_err(|_| "Discord resume checkpoint could not be loaded safely".to_owned())?;
        Ok(Self {
            binding,
            revision,
            progress: DiscordResumeProgress::new(saved.clone()),
            saved,
        })
    }

    async fn persist(&mut self, runtime: &AgentRuntime) -> Result<(), &'static str> {
        if self.saved != self.progress.settled {
            self.revision = runtime
                .save_discord_resume(&self.binding, self.revision, self.progress.settled.clone())
                .await
                .map_err(|_| "Discord resume checkpoint could not be committed")?;
            self.saved.clone_from(&self.progress.settled);
        }
        Ok(())
    }
}

struct DiscordInbound {
    message: InboundMessage,
    resume: claw_state::DiscordResume,
}

#[derive(Clone, Copy)]
enum ConfiguredChannel {
    Telegram,
    Discord,
}

#[derive(Clone)]
struct ChannelReadiness {
    dependency: Arc<DependencyReadiness>,
    telegram_configured: bool,
    discord_configured: bool,
}

impl ChannelReadiness {
    fn new(
        dependency: Arc<DependencyReadiness>,
        telegram_configured: bool,
        discord_configured: bool,
    ) -> Self {
        let readiness = Self {
            dependency,
            telegram_configured,
            discord_configured,
        };
        if telegram_configured {
            readiness.dependency.set("telegram", false);
        }
        if discord_configured {
            readiness.dependency.set("discord", false);
        }
        readiness
            .dependency
            .set("channels", !telegram_configured && !discord_configured);
        readiness
    }

    fn set(&self, channel: ConfiguredChannel, ready: bool) {
        let name = match channel {
            ConfiguredChannel::Telegram => "telegram",
            ConfiguredChannel::Discord => "discord",
        };
        let members = [
            self.telegram_configured.then_some("telegram"),
            self.discord_configured.then_some("discord"),
        ];
        self.dependency
            .set_and_aggregate(name, ready, "channels", members.into_iter().flatten());
    }

    fn set_discord_state(&self, state: ConnectionState, phase: claw_channels::DiscordGatewayPhase) {
        self.set(
            ConfiguredChannel::Discord,
            state == ConnectionState::Connected
                && phase == claw_channels::DiscordGatewayPhase::Ready,
        );
    }
}

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
        let channel_readiness = ChannelReadiness::new(
            Arc::clone(&readiness),
            telegram.is_some(),
            discord.is_some(),
        );

        if let Some(settings) = telegram {
            let request_cancel = Arc::new(Mutex::new(None));
            let transport = TelegramHttpTransport::new(proxy.clone(), Arc::clone(&request_cancel))?;
            let account = configured_account_id("telegram", &settings.token);
            let origin = approved_origin("telegram", &account, "api.telegram.org")?;
            let credential = bind_credential(
                "telegram",
                &account,
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
            let identity = TelegramPollIdentity::new(credential, &origin)?;
            let offset = runtime
                .telegram_poll_cursor(&identity.binding)
                .await
                .map_err(|_| "Telegram poll cursor could not be restored safely".to_owned())?;
            runtime.register_channel_account("telegram", &account)?;
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
                .restore_poll_cursor(offset)
                .map_err(|error| error.to_string())?;
            channel
                .start(&mut ChannelDiagnostics(Arc::clone(&diagnostics)))
                .map_err(|error| error.to_string())?;
            channel_readiness.set(ConfiguredChannel::Telegram, true);
            let task_cancel = cancellation.clone();
            let task_runtime = Arc::clone(&runtime);
            let task_authentication = Arc::clone(&authentication);
            let task_diagnostics = Arc::clone(&diagnostics);
            let task_readiness = channel_readiness.clone();
            let task_terminated = Arc::clone(&terminated);
            let handle = tracker.spawn(async move {
                let _guard = TerminationGuard(task_terminated);
                run_telegram(
                    channel,
                    identity,
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
            let account = configured_account_id("discord", &settings.token);
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
            let gateway_origin = approved_origin_dynamic("discord", &account, gateway_host)?;
            let rest_origin = approved_origin("discord", &account, "discord.com")?;
            let gateway_credential = bind_credential(
                "discord",
                &account,
                CredentialKind::Token,
                gateway_origin.clone(),
                &settings.token,
            )?;
            let rest_credential = bind_credential(
                "discord",
                &account,
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
            let checkpoint = DiscordResumeCheckpoint::load(
                &gateway_credential,
                &gateway_origin,
                &settings.gateway_url,
                settings.intents,
                &runtime,
            )
            .await?;
            runtime.register_channel_account("discord", &account)?;
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
            if let Some(saved) = &checkpoint.saved {
                channel
                    .restore_resume_state(
                        saved.session_id(),
                        saved.sequence(),
                        saved.resume_gateway_url(),
                    )
                    .map_err(|_| {
                        "Saved Discord resume state violates current origin or transport policy"
                            .to_owned()
                    })?;
            }
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
            let task_readiness = channel_readiness.clone();
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
                    task_readiness,
                    task_cancel,
                    ready_tx,
                    started,
                    checkpoint,
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

fn configured_account_id(channel: &str, secret: &SecretString) -> String {
    use sha2::{Digest, Sha256};
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut digest = Sha256::new();
    digest.update(b"gta-claw/configured-channel-account/v1");
    for value in [channel, secret.expose()] {
        digest.update((value.len() as u64).to_le_bytes());
        digest.update(value.as_bytes());
    }
    let mut account = String::with_capacity(68);
    account.push_str("bot-");
    for byte in digest.finalize() {
        account.push(char::from(HEX[usize::from(byte >> 4)]));
        account.push(char::from(HEX[usize::from(byte & 15)]));
    }
    account
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
                    origin.account_id(),
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
    Closed(DiscordGatewayClose),
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

    fn gateway_url_is_direct(&self, gateway_url: &str) -> bool {
        let Ok(url) = Url::parse(gateway_url) else {
            return false;
        };
        url.scheme() == "wss"
            && url.port_or_known_default() == Some(443)
            && url.host_str().is_some_and(|host| {
                self.transport
                    .proxy_rules()
                    .intercept(host, 443)
                    .is_direct()
            })
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
    fn gateway_url_allowed(&self, gateway_url: &str) -> bool {
        self.gateway_url_is_direct(gateway_url)
    }

    fn open_gateway(&mut self, gateway_url: &str) -> Result<(), ChannelError> {
        if !self.gateway_url_is_direct(gateway_url) {
            return Err(ChannelError::Configuration(
                claw_channel_sdk::ConfigurationError::InvalidAdapterConfiguration,
            ));
        }
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
            let _ = events
                .send(DiscordEvent::Closed(DiscordGatewayClose::transport_lost()))
                .await;
            continue;
        };
        let (mut writer, mut reader) = socket.split();
        if events.send(DiscordEvent::Opened).await.is_err() {
            return;
        }
        let mut close = DiscordGatewayClose::transport_lost();
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
                    Some(Ok(Message::Close(frame))) => {
                        close = frame.map_or_else(
                            DiscordGatewayClose::transport_lost,
                            |frame| DiscordGatewayClose::websocket(
                                u16::from(frame.code),
                                frame.reason.to_string(),
                            ),
                        );
                        break;
                    }
                    Some(Err(_)) | None => break,
                    Some(Ok(_)) => {}
                }
            }
        }
        let _ = events.send(DiscordEvent::Closed(close)).await;
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
    readiness: ChannelReadiness,
    cancellation: CancellationToken,
    ready: oneshot::Sender<Result<(), String>>,
    started: Instant,
    mut checkpoint: DiscordResumeCheckpoint,
) {
    let mut ready = Some(ready);
    let (inbound_tx, inbound_rx) = mpsc::channel(64);
    let (settled_tx, mut settled_rx) = mpsc::channel(64);
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
        settled_tx,
    )));
    let mut tick = tokio::time::interval(Duration::from_millis(250));
    tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    loop {
        tokio::select! {
            () = cancellation.cancelled() => break,
            settled = settled_rx.recv() => {
                let Some((resume, succeeded)) = settled else { break; };
                if let Err(error) = checkpoint.progress.complete(&resume, succeeded) {
                    diagnostics.record(error);
                    break;
                }
                if let Err(error) = checkpoint.persist(&runtime).await {
                    diagnostics.record(error);
                    break;
                }
            }
            event = events.recv() => {
                let Some(event) = event else {
                    break;
                };
                let result = match event {
                    DiscordEvent::Opened => channel.gateway_opened(
                        &mut ChannelDiagnostics(Arc::clone(&diagnostics)),
                    ).map(|()| None),
                    DiscordEvent::Packet(packet) => channel.handle_gateway_packet_with_admission(
                        &packet,
                        started.elapsed(),
                        &gateway_credential,
                        &mut ChannelDiagnostics(Arc::clone(&diagnostics)),
                        |message| tokio::task::block_in_place(|| {
                            tokio::runtime::Handle::current().block_on(runtime.admit_channel_message(message))
                        }).map_err(|_| ChannelError::RemoteRejected { status: 503 }),
                    ).map(Some),
                    DiscordEvent::Closed(close) => channel.gateway_closed_with(
                        started.elapsed(),
                        close,
                        &mut ChannelDiagnostics(Arc::clone(&diagnostics)),
                    ).map(|_| None),
                };
                readiness.set_discord_state(channel.state(), channel.phase());
                let became_ready = matches!(&result, Ok(Some(DiscordPacketOutcome::Ready)));
                if channel.session_id().is_none() && checkpoint.saved.is_some() {
                    let Ok(revision) = runtime.save_discord_resume(&checkpoint.binding, checkpoint.revision, None).await else {
                        diagnostics.record("Discord invalidated session could not be cleared durably");
                        break;
                    };
                    checkpoint.revision = revision;
                    checkpoint.saved = None;
                }
                match result {
                    Ok(_) => {}
                    Err(error) if channel.state() == ConnectionState::Closed => {
                        diagnostics.record(format!("Discord event failed terminally: {error}"));
                        if let Some(ready) = ready.take() {
                            let _ = ready.send(Err(error.to_string()));
                        }
                        break;
                    }
                    Err(error) => diagnostics.record(format!("Discord event failed: {error}")),
                }
                let resume = channel.session_id().zip(channel.sequence()).map(|(session, sequence)| claw_state::DiscordResume::new(session, sequence, channel.resume_gateway_url())).transpose();
                let Ok(resume) = resume else {
                    diagnostics.record("Discord supplied invalid resume checkpoint metadata");
                    break;
                };
                let queued = enqueue_discord(
                    &mut channel,
                    &inbound_tx,
                    &diagnostics,
                    &runtime,
                    resume.as_ref(),
                ).await;
                let Ok(queued) = queued else {
                    diagnostics.record("Discord dispatch could not be queued; resume checkpoint was not advanced");
                    break;
                };
                if let Err(error) = checkpoint.progress.observe(resume, queued) {
                    diagnostics.record(error);
                    let _ = runtime.save_discord_resume(&checkpoint.binding, checkpoint.revision, None).await;
                    break;
                }
                if let Err(error) = checkpoint.persist(&runtime).await {
                    diagnostics.record(error);
                    break;
                }
                if became_ready && let Some(ready) = ready.take() { let _ = ready.send(Ok(())); }
            }
            _ = tick.tick() => {
                let result = channel.tick(
                    started.elapsed(),
                    &mut ChannelDiagnostics(Arc::clone(&diagnostics)),
                );
                readiness.set_discord_state(channel.state(), channel.phase());
                if let Err(error) = result {
                    diagnostics.record(format!("Discord tick failed: {error}"));
                }
            }
        }
    }
    readiness.set(ConfiguredChannel::Discord, false);
    dispatch_cancellation.cancel();
    drop(inbound_tx);
    drop(settled_rx);
    if let Err(error) = dispatch_task.join().await {
        diagnostics.record(format!("Discord dispatch task failed: {error}"));
    }
    let _ = channel.stop(&mut ChannelDiagnostics(Arc::clone(&diagnostics)));
    if let Some(ready) = ready {
        let _ = ready.send(Err("Discord stopped before READY".to_owned()));
    }
}

async fn run_telegram<T: TelegramTransport>(
    mut channel: TelegramChannel<T, SystemClock>,
    identity: TelegramPollIdentity,
    runtime: Arc<AgentRuntime>,
    authentication: Arc<RwLock<Option<String>>>,
    diagnostics: Arc<Diagnostics>,
    readiness: ChannelReadiness,
    cancellation: CancellationToken,
) {
    let TelegramPollIdentity {
        credential,
        binding,
    } = identity;
    let mut consecutive_failures = 0_u32;
    loop {
        if cancellation.is_cancelled() {
            break;
        }
        let Ok(persisted) = runtime.telegram_poll_cursor(&binding).await else {
            diagnostics
                .record("Telegram poll cursor could not be checked; worker stopped before polling");
            break;
        };
        if persisted != channel.offset() {
            if persisted == 0 && channel.rewind_expired_poll_cursor().is_ok() {
                diagnostics.record("Telegram idle cursor expired; durable message claims remain in force during re-admission");
            } else {
                diagnostics.record(
                    "Telegram poll cursor changed concurrently; worker stopped before polling",
                );
                break;
            }
        }
        if cancellation.is_cancelled() {
            break;
        }
        let previous_offset = channel.offset();
        let poll_result = channel.poll_once_for_processing(
            &credential,
            &mut ChannelDiagnostics(Arc::clone(&diagnostics)),
            |message| {
                tokio::task::block_in_place(|| {
                    tokio::runtime::Handle::current()
                        .block_on(runtime.admit_channel_message(message))
                })
                .map_err(|_| ChannelError::RemoteRejected { status: 503 })
            },
        );
        let deferred_batch = poll_result.is_ok();
        let mut processed = deferred_batch;
        let retry_after = match &poll_result {
            Ok(_) => {
                consecutive_failures = 0;
                readiness.set(ConfiguredChannel::Telegram, true);
                channel.poll_interval()
            }
            Err(error) => {
                consecutive_failures = consecutive_failures.saturating_add(1);
                diagnostics.record(format!("Telegram poll failed: {error}"));
                if telegram_failure_is_terminal(error) {
                    readiness.set(ConfiguredChannel::Telegram, false);
                    diagnostics.record("Telegram worker stopped after a terminal failure");
                    break;
                }
                if consecutive_failures >= TELEGRAM_PERSISTENT_FAILURES {
                    readiness.set(ConfiguredChannel::Telegram, false);
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
                            processed = false;
                            continue;
                        }
                    };
                    let claim = match runtime.claim_channel_delivery(&message, &reply).await {
                        Ok(Some(claim)) => claim,
                        Ok(None) => continue,
                        Err(error) => {
                            diagnostics.record(format!(
                                "Telegram reply claim failed; no send attempted: {error}"
                            ));
                            processed = false;
                            continue;
                        }
                    };
                    let mut confirmed = true;
                    for (index, segment) in segments.enumerate() {
                        if index >= 1_024 {
                            confirmed = false;
                            break;
                        }
                        if cancellation.is_cancelled() {
                            confirmed = false;
                            break;
                        }
                        let segment = match segment {
                            Ok(segment) => segment.into_owned(),
                            Err(error) => {
                                diagnostics
                                    .record(format!("Telegram segmentation failed: {error}"));
                                confirmed = false;
                                break;
                            }
                        };
                        let outgoing = outbound(&message, segment);
                        match channel.send_outbound(&outgoing, Some(&credential)) {
                            Ok(receipt)
                                if receipt.state == claw_channel_sdk::DeliveryState::Accepted
                                    && receipt.remote_message_id.as_ref().is_some_and(|id| {
                                        id.parse::<u64>().is_ok_and(|id| id > 0)
                                    }) =>
                            {
                                if runtime
                                    .record_channel_delivery_receipt(
                                        &message,
                                        &claim,
                                        u32::try_from(index).expect("bounded segment index"),
                                        outgoing.text.as_deref().unwrap_or(""),
                                        receipt.remote_message_id.as_deref().unwrap_or(""),
                                    )
                                    .await
                                    .is_err()
                                {
                                    diagnostics.record("Telegram remote receipt could not be committed; delivery remains unknown");
                                    confirmed = false;
                                    break;
                                }
                            }
                            Ok(_) => {
                                diagnostics.record("Telegram send returned no valid message acknowledgement; delivery remains unknown");
                                confirmed = false;
                                break;
                            }
                            Err(error) => {
                                diagnostics.record(format!("Telegram send failed: {error}"));
                                confirmed = false;
                                break;
                            }
                        }
                    }
                    if let Err(error) = runtime
                        .finish_channel_delivery(&message, claim, confirmed)
                        .await
                    {
                        diagnostics.record(format!(
                            "Telegram reply outcome unconfirmed; automatic resend disabled: {error}"
                        ));
                        processed = false;
                    }
                    processed &= confirmed;
                }
                Ok(None) => {}
                Err(error) => {
                    diagnostics.record(format!("Telegram dispatch failed: {error}"));
                    processed = false;
                }
            }
        }
        if deferred_batch {
            if let Err(error) =
                channel.finish_polled_batch(processed && !cancellation.is_cancelled())
            {
                diagnostics.record(format!(
                    "Telegram batch could not be settled; no further poll: {error}"
                ));
                break;
            }
            if !processed {
                diagnostics.record("Telegram batch not fully processed; provider offset retained for durable re-admission");
            }
            if channel.offset() != previous_offset
                && runtime
                    .advance_telegram_poll_cursor(&binding, previous_offset, channel.offset())
                    .await
                    .is_err()
            {
                diagnostics.record("Telegram poll cursor could not be committed; worker stopped before acknowledging another batch");
                break;
            }
        }
        tokio::select! {
            () = cancellation.cancelled() => break,
            () = tokio::time::sleep(retry_after) => {}
        }
    }
    readiness.set(ConfiguredChannel::Telegram, false);
    let _ = channel.stop(&mut ChannelDiagnostics(diagnostics));
}

async fn enqueue_discord(
    channel: &mut DiscordChannel<DiscordTransportAdapter, SystemClock>,
    inbound: &mpsc::Sender<DiscordInbound>,
    diagnostics: &Arc<Diagnostics>,
    runtime: &AgentRuntime,
    resume: Option<&claw_state::DiscordResume>,
) -> Result<usize, ChannelError> {
    if !matches!(
        channel.phase(),
        claw_channels::DiscordGatewayPhase::Ready | claw_channels::DiscordGatewayPhase::Resuming
    ) {
        return Ok(0);
    }
    let mut queued = 0;
    while let Some(message) = channel.poll_admitted_inbound()? {
        if !runtime
            .admit_channel_message(&message)
            .await
            .map_err(|_| ChannelError::RemoteRejected { status: 503 })?
        {
            continue;
        }
        let resume = resume.cloned().ok_or(ChannelError::Protocol(
            claw_channel_sdk::ProtocolErrorKind::InvalidField,
        ))?;
        if inbound
            .try_send(DiscordInbound { message, resume })
            .is_err()
        {
            diagnostics.record(
                "Discord inbound dispatch queue is full; admitted input remains durably queued",
            );
            return Err(ChannelError::RateLimited {
                retry_after: Duration::from_millis(250),
            });
        }
        queued += 1;
    }
    Ok(queued)
}

#[allow(clippy::too_many_arguments)]
async fn run_discord_dispatch<T: DiscordReplyTransport + Send + 'static>(
    mut inbound: mpsc::Receiver<DiscordInbound>,
    transport: T,
    origin: claw_channel_sdk::ApprovedOrigin,
    credential: ChannelCredential,
    runtime: Arc<AgentRuntime>,
    authentication: Arc<RwLock<Option<String>>>,
    diagnostics: Arc<Diagnostics>,
    cancellation: CancellationToken,
    settled: mpsc::Sender<(claw_state::DiscordResume, bool)>,
) {
    loop {
        let message = tokio::select! {
            () = cancellation.cancelled() => return,
            message = inbound.recv() => message,
        };
        let Some(DiscordInbound { message, resume }) = message else {
            return;
        };
        let processed = match process_inbound(
            &message,
            &runtime,
            &authentication,
            &diagnostics,
            cancellation.clone(),
        )
        .await
        {
            Ok(Some(reply)) => {
                send_discord_reply_once(
                    &runtime,
                    &transport,
                    &origin,
                    &credential,
                    &message,
                    &reply,
                    &cancellation,
                )
                .await
            }
            Ok(None) => Ok(()),
            Err(error) => Err(error),
        };
        if let Err(error) = &processed {
            diagnostics.record(format!("Discord message processing failed: {error}"));
        }
        let succeeded = processed.is_ok();
        if settled.send((resume, succeeded)).await.is_err() || !succeeded {
            return;
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

async fn send_discord_reply_once<T: DiscordReplyTransport>(
    runtime: &AgentRuntime,
    transport: &T,
    origin: &claw_channel_sdk::ApprovedOrigin,
    credential: &ChannelCredential,
    message: &InboundMessage,
    reply: &str,
    cancellation: &CancellationToken,
) -> Result<(), ChannelError> {
    let claim = runtime
        .claim_channel_delivery(message, reply)
        .await
        .map_err(|_| ChannelError::RemoteRejected { status: 503 })?;
    let Some(claim) = claim else {
        return Ok(());
    };
    let result = send_discord_reply_recorded(
        transport,
        origin,
        credential,
        message,
        reply,
        cancellation,
        |segment, content, remote_id| {
            let claim = &claim;
            async move {
                runtime
                    .record_channel_delivery_receipt(message, claim, segment, &content, &remote_id)
                    .await
                    .map_err(|_| ChannelError::RemoteRejected { status: 503 })
            }
        },
    )
    .await;
    runtime
        .finish_channel_delivery(message, claim, result.is_ok())
        .await
        .map_err(|_| ChannelError::RemoteRejected { status: 503 })?;
    result
}

#[cfg(test)]
async fn send_discord_reply<T: DiscordReplyTransport>(
    transport: &T,
    origin: &claw_channel_sdk::ApprovedOrigin,
    credential: &ChannelCredential,
    message: &InboundMessage,
    reply: &str,
    cancellation: &CancellationToken,
) -> Result<(), ChannelError> {
    send_discord_reply_recorded(
        transport,
        origin,
        credential,
        message,
        reply,
        cancellation,
        |_, _, _| async { Ok(()) },
    )
    .await
}

async fn send_discord_reply_recorded<T, F, Receipt>(
    transport: &T,
    origin: &claw_channel_sdk::ApprovedOrigin,
    credential: &ChannelCredential,
    message: &InboundMessage,
    reply: &str,
    cancellation: &CancellationToken,
    mut record: F,
) -> Result<(), ChannelError>
where
    T: DiscordReplyTransport,
    F: FnMut(u32, String, String) -> Receipt,
    Receipt: Future<Output = Result<(), ChannelError>>,
{
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
    for (index, segment) in segments.enumerate() {
        let index = u32::try_from(index)
            .ok()
            .filter(|index| *index < 1_024)
            .ok_or(ChannelError::Protocol(
                claw_channel_sdk::ProtocolErrorKind::InvalidField,
            ))?;
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
                    &message.account_id,
                    CredentialKind::Token,
                    origin,
                    |bot_token| {
                        transport.send_reply_raw(bot_token, channel_id, &segment, cancellation)
                    },
                )
                .map_err(ChannelError::CredentialBinding)??;
            require_provider_response_bounded(&response)?;
            match response.status() {
                200..=299 => {
                    #[derive(serde::Deserialize)]
                    struct ReplyReceipt {
                        id: String,
                        channel_id: String,
                    }
                    let receipt: ReplyReceipt =
                        serde_json::from_slice(response.body()).map_err(|_| {
                            ChannelError::Protocol(
                                claw_channel_sdk::ProtocolErrorKind::MalformedResponse,
                            )
                        })?;
                    if receipt.channel_id != channel_id
                        || receipt.id.is_empty()
                        || receipt.id.len() > 20
                        || !receipt.id.bytes().all(|byte| byte.is_ascii_digit())
                        || !receipt.id.parse::<u64>().is_ok_and(|id| id > 0)
                    {
                        return Err(ChannelError::Protocol(
                            claw_channel_sdk::ProtocolErrorKind::InvalidField,
                        ));
                    }
                    record(index, segment.clone(), receipt.id).await?;
                    break;
                }
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
    let owned_message = message.clone();
    let owned_runtime = Arc::clone(runtime);
    let authentication = Arc::clone(authentication);
    let diagnostics = Arc::clone(diagnostics);
    let run = runtime
        .run_channel_message(message, async move {
            process_inbound_once(
                &owned_message,
                &owned_runtime,
                &authentication,
                &diagnostics,
                cancellation,
            )
            .await
            .map_err(|_| {
                claw_http_api::PortError::new(
                    claw_http_api::PortErrorKind::OutcomeUnknown,
                    "channel dispatch outcome requires reconciliation",
                )
            })
        })
        .await
        .map_err(|_| ChannelError::RemoteRejected { status: 503 })?;
    let result = run
        .result()
        .filter(|result| {
            run.phase() == claw_state::RunPhase::Finished && result.status() == "completed"
        })
        .ok_or(ChannelError::RemoteRejected { status: 409 })?;
    serde_json::from_str(result.text()).map_err(|_| ChannelError::RemoteRejected { status: 503 })
}

async fn process_inbound_once(
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
    let mut conversation = runtime
        .channel_conversation(message, cancellation)
        .map_err(|_| ChannelError::RemoteRejected { status: 403 })?;
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
            .authenticated_channel_command(message, &invocation.name)
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
        408 => Err(ChannelError::Transport(TransportErrorKind::Timeout)),
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
    #[test]
    fn configured_bot_accounts_are_stable_credential_and_channel_partitions() {
        let token = SecretString::new("fixture-account-secret");
        let first = super::configured_account_id("telegram", &token);
        assert_eq!(first, super::configured_account_id("telegram", &token));
        assert_ne!(first, super::configured_account_id("discord", &token));
        assert_ne!(
            first,
            super::configured_account_id(
                "telegram",
                &SecretString::new("different-account-secret")
            )
        );
        assert_eq!(first.len(), 68);
        assert!(!first.contains("fixture-account-secret"));
        let origin = approved_origin("telegram", &first, "api.telegram.org")
            .expect("partition-bound origin");
        let credential = bind_credential(
            "telegram",
            &first,
            CredentialKind::Token,
            origin.clone(),
            &token,
        )
        .expect("partition-bound credential");
        assert!(
            credential
                .expose_for_origin(
                    "telegram",
                    "default",
                    CredentialKind::Token,
                    &origin,
                    |_| ()
                )
                .is_err()
        );
        assert!(
            credential
                .expose_for_origin("telegram", &first, CredentialKind::Token, &origin, |_| ())
                .is_ok()
        );
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn discord_segment_receipts_survive_partial_delivery_and_closed_storage_stops_sends() {
        use crate::adapters::http_api::{
            EmptyModelTools, OperatorRuntimeStatus, ProviderHistoryConfig, SmokeProvider,
            SwappableProvider,
        };
        use crate::adapters::signed_plugins::PluginToolSurface;
        use sha2::{Digest, Sha256};

        struct OwnedRoot(std::path::PathBuf);
        impl Drop for OwnedRoot {
            fn drop(&mut self) {
                let _ = std::fs::remove_dir_all(&self.0);
            }
        }
        struct Receipts {
            calls: Arc<AtomicUsize>,
            mode: &'static str,
            runtime: Arc<super::AgentRuntime>,
        }
        impl super::DiscordReplyTransport for Receipts {
            fn send_reply_raw(
                &self,
                _: &str,
                channel: &str,
                _: &str,
                _: &CancellationToken,
            ) -> Result<ProviderResponse, ChannelError> {
                assert_eq!(channel, "room");
                let call = self.calls.fetch_add(1, Ordering::SeqCst) + 1;
                if self.mode == "partial" && call == 2 {
                    return Err(ChannelError::Transport(
                        claw_channel_sdk::TransportErrorKind::Io,
                    ));
                }
                if self.mode == "closed-storage" && call == 1 {
                    tokio::task::block_in_place(|| {
                        tokio::runtime::Handle::current().block_on(self.runtime.shutdown())
                    })
                    .expect("test-owned storage closes before receipt commit");
                }
                Ok(ProviderResponse::new(
                    200,
                    format!(r#"{{"id":"{call}","channel_id":"room"}}"#),
                ))
            }
        }

        let reply = "private-delivery-segment ".repeat(230);
        let segments: Vec<String> = claw_channels::segment_outbound_text_iter("discord", &reply)
            .expect("segments")
            .map(|segment| segment.expect("valid segment").into_owned())
            .collect();
        assert!(segments.len() >= 3);
        for mode in ["delivered", "partial", "closed-storage"] {
            let root = OwnedRoot(std::env::temp_dir().join(format!(
                    "claw-receipt-prefix-{}-{}",
                    std::process::id(),
                    std::time::SystemTime::now()
                        .duration_since(std::time::UNIX_EPOCH)
                        .expect("clock")
                        .as_nanos()
                )));
            std::fs::create_dir(&root.0).expect("owned state root");
            let diagnostics = Arc::new(super::Diagnostics::new(32));
            let provider = Arc::new(SwappableProvider::new(
                "gpt-4o",
                "receipt fixture",
                ProviderHistoryConfig::default(),
                Arc::new(EmptyModelTools),
                Arc::new(DependencyReadiness::new(["provider"])),
            ));
            provider
                .activate(Arc::new(
                    SmokeProvider::new().expect("local fixture provider"),
                ))
                .await
                .expect("activated");
            let plugins = PluginToolSurface::new(Arc::clone(&diagnostics));
            let runtime = super::AgentRuntime::new(
                Arc::clone(&provider),
                Arc::clone(&plugins),
                &root.0,
                "gpt-4o".to_owned(),
                0,
                8,
                Duration::from_secs(60),
                Arc::clone(&diagnostics),
            )
            .expect("actual runtime");
            let secret = SecretString::new("discord-fixture-secret");
            let account = super::configured_account_id("discord", &secret);
            let origin = approved_origin("discord", &account, "discord.com").expect("REST origin");
            let credential = bind_credential(
                "discord",
                &account,
                CredentialKind::Token,
                origin.clone(),
                &secret,
            )
            .expect("owned credential");
            let message = InboundMessage {
                id: "segment-message".to_owned(),
                channel_id: "discord".to_owned(),
                account_id: account.clone(),
                conversation_id: "discord:room:user".to_owned(),
                sender_id: "user".to_owned(),
                text: Some("request".to_owned()),
                attachments: Vec::new(),
                received_at_unix_ms: 1,
            };
            let retained_reply = reply.clone();
            let run = runtime
                .run_channel_message(&message, async move { Ok(Some(retained_reply)) })
                .await
                .expect("durable completed reply");
            let calls = Arc::new(AtomicUsize::new(0));
            let transport = Receipts {
                calls: Arc::clone(&calls),
                mode,
                runtime: Arc::clone(&runtime),
            };
            let mut foreign = message.clone();
            foreign.account_id = "default".to_owned();
            assert!(
                super::send_discord_reply(
                    &transport,
                    &origin,
                    &credential,
                    &foreign,
                    &reply,
                    &CancellationToken::new()
                )
                .await
                .is_err()
            );
            assert_eq!(
                calls.load(Ordering::SeqCst),
                0,
                "foreign account must not expose the configured credential or send bytes"
            );
            assert_eq!(
                super::send_discord_reply_once(
                    &runtime,
                    &transport,
                    &origin,
                    &credential,
                    &message,
                    &reply,
                    &CancellationToken::new()
                )
                .await
                .is_ok(),
                mode == "delivered"
            );
            let expected_sends = match mode {
                "delivered" => segments.len(),
                "partial" => 2,
                _ => 1,
            };
            assert_eq!(
                calls.load(Ordering::SeqCst),
                expected_sends,
                "{mode} stops at the first unrecorded segment"
            );
            let query = serde_json::json!({"nativeRecovery":{"channelId":"discord","accountId":account,"conversationId":"discord:room:user","senderId":"user","runId":run.id()}});
            let before = if mode == "closed-storage" {
                None
            } else {
                let response = runtime
                    .dispatch("channels.status", Some(&query), CancellationToken::new())
                    .await
                    .expect("live receipt query")
                    .expect("query result");
                runtime.shutdown().await.expect("runtime drain");
                Some(response)
            };
            drop(transport);
            drop(runtime);
            let reopened = super::AgentRuntime::new(
                provider,
                plugins,
                &root.0,
                "gpt-4o".to_owned(),
                0,
                8,
                Duration::from_secs(60),
                diagnostics,
            )
            .expect("reopened runtime");
            let response = reopened
                .dispatch("channels.status", Some(&query), CancellationToken::new())
                .await
                .expect("reopened receipt query")
                .expect("query result");
            if let Some(before) = before {
                assert_eq!(response, before);
            }
            assert_eq!(
                response["delivery"],
                if mode == "delivered" {
                    "delivered"
                } else {
                    "outcome_unknown"
                }
            );
            let receipts = response["deliveryReceipts"]
                .as_array()
                .expect("receipt metadata");
            assert_eq!(
                receipts.len(),
                match mode {
                    "delivered" => segments.len(),
                    "partial" => 1,
                    _ => 0,
                }
            );
            for (index, receipt) in receipts.iter().enumerate() {
                const HEX: &[u8; 16] = b"0123456789abcdef";
                let expected: String = Sha256::digest(segments[index].as_bytes())
                    .into_iter()
                    .flat_map(|byte| {
                        [
                            char::from(HEX[usize::from(byte >> 4)]),
                            char::from(HEX[usize::from(byte & 15)]),
                        ]
                    })
                    .collect();
                assert_eq!(receipt["segment"], index);
                assert_eq!(receipt["remoteMessageId"], (index + 1).to_string());
                assert_eq!(receipt["contentBytes"], segments[index].len());
                assert_eq!(receipt["contentSha256"], expected);
            }
            assert!(!response.to_string().contains("private-delivery-segment"));
            assert_eq!(response["contentIncluded"], false);
            assert_eq!(response["automaticReplay"], false);
            let mut after = query.clone();
            after["nativeRecovery"]["deliveryAfter"] = serde_json::json!(0);
            let page = reopened
                .dispatch("channels.status", Some(&after), CancellationToken::new())
                .await
                .expect("receipt cursor query")
                .expect("receipt page");
            assert_eq!(
                page["deliveryReceipts"].as_array().expect("page").len(),
                receipts.len().saturating_sub(1)
            );
            let mut wrong = query.clone();
            wrong["nativeRecovery"]["senderId"] = serde_json::json!("foreign");
            assert!(
                reopened
                    .dispatch("channels.status", Some(&wrong), CancellationToken::new())
                    .await
                    .is_err()
            );
            let retry_transport = Receipts {
                calls: Arc::clone(&calls),
                mode,
                runtime: Arc::clone(&reopened),
            };
            assert_eq!(
                super::send_discord_reply_once(
                    &reopened,
                    &retry_transport,
                    &origin,
                    &credential,
                    &message,
                    &reply,
                    &CancellationToken::new()
                )
                .await
                .is_ok(),
                mode == "delivered"
            );
            assert_eq!(
                calls.load(Ordering::SeqCst),
                expected_sends,
                "restart never replays delivery"
            );
            reopened.shutdown().await.expect("reopened runtime drain");
        }
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn discord_dispatch_checkpoints_only_the_completed_prefix_and_retains_unknown_delivery() {
        use crate::adapters::http_api::{
            EmptyModelTools, ProviderHistoryConfig, SmokeProvider, SwappableProvider,
        };
        use crate::adapters::signed_plugins::PluginToolSurface;
        struct OwnedRoot(std::path::PathBuf);
        impl Drop for OwnedRoot {
            fn drop(&mut self) {
                let _ = std::fs::remove_dir_all(&self.0);
            }
        }
        struct Replies {
            calls: Arc<AtomicUsize>,
            fail_second: bool,
        }
        impl super::DiscordReplyTransport for Replies {
            fn send_reply_raw(
                &self,
                _: &str,
                channel: &str,
                _: &str,
                _: &CancellationToken,
            ) -> Result<ProviderResponse, ChannelError> {
                assert_eq!(channel, "room");
                let count = self.calls.fetch_add(1, Ordering::SeqCst) + 1;
                if self.fail_second && count == 2 {
                    return Err(ChannelError::Transport(
                        claw_channel_sdk::TransportErrorKind::Io,
                    ));
                }
                Ok(ProviderResponse::new(
                    200,
                    br#"{"id":"42","channel_id":"room"}"#.as_slice(),
                ))
            }
        }
        for fail_second in [false, true] {
            let root = OwnedRoot(std::env::temp_dir().join(format!(
                    "claw-discord-dispatch-{}-{}",
                    std::process::id(),
                    std::time::SystemTime::now()
                        .duration_since(std::time::UNIX_EPOCH)
                        .expect("clock")
                        .as_nanos()
                )));
            std::fs::create_dir(&root.0).expect("owned state");
            let diagnostics = Arc::new(super::Diagnostics::new(32));
            let readiness = Arc::new(DependencyReadiness::new(["provider"]));
            let provider = Arc::new(SwappableProvider::new(
                "gpt-4o",
                "Discord fixture",
                ProviderHistoryConfig::default(),
                Arc::new(EmptyModelTools),
                readiness,
            ));
            provider
                .activate(Arc::new(SmokeProvider::new().expect("fixture provider")))
                .await
                .expect("activated");
            let plugins = PluginToolSurface::new(Arc::clone(&diagnostics));
            let runtime = super::AgentRuntime::new(
                Arc::clone(&provider),
                Arc::clone(&plugins),
                &root.0,
                "gpt-4o".to_owned(),
                0,
                8,
                Duration::from_secs(60),
                Arc::clone(&diagnostics),
            )
            .expect("actual runtime");
            let gateway_origin = approved_origin("discord", "default", "gateway.discord.gg")
                .expect("gateway origin");
            let origin = approved_origin("discord", "default", "discord.com").expect("rest origin");
            let credential = bind_credential(
                "discord",
                "default",
                CredentialKind::Token,
                gateway_origin.clone(),
                &SecretString::new("discord-fixture-secret"),
            )
            .expect("gateway credential");
            let reply_credential = bind_credential(
                "discord",
                "default",
                CredentialKind::Token,
                origin.clone(),
                &SecretString::new("discord-fixture-secret"),
            )
            .expect("reply credential");
            let mut checkpoint = super::DiscordResumeCheckpoint::load(
                &credential,
                &gateway_origin,
                "wss://gateway.discord.gg/?v=10&encoding=json",
                32_768,
                &runtime,
            )
            .await
            .expect("checkpoint");
            let initial =
                claw_state::DiscordResume::new("settled-session", 7, None).expect("ready snapshot");
            checkpoint
                .progress
                .observe(Some(initial), 0)
                .expect("READY");
            checkpoint.persist(&runtime).await.expect("durable READY");
            let (inbound, receiver) = tokio::sync::mpsc::channel(2);
            let (settled, mut observed) = tokio::sync::mpsc::channel(2);
            let mut messages = Vec::new();
            for sequence in [8, 9] {
                let resume = claw_state::DiscordResume::new("settled-session", sequence, None)
                    .expect("message snapshot");
                let message = InboundMessage {
                    id: format!("message-{sequence}"),
                    channel_id: "discord".to_owned(),
                    account_id: "default".to_owned(),
                    conversation_id: "discord:room:user".to_owned(),
                    sender_id: "user".to_owned(),
                    text: Some(format!("message {sequence}")),
                    attachments: Vec::new(),
                    received_at_unix_ms: 1,
                };
                assert!(
                    runtime
                        .admit_channel_message(&message)
                        .await
                        .expect("durable admission")
                );
                checkpoint
                    .progress
                    .observe(Some(resume.clone()), 1)
                    .expect("queued progress");
                messages.push(message.clone());
                inbound
                    .send(super::DiscordInbound { message, resume })
                    .await
                    .expect("queued message");
            }
            checkpoint
                .persist(&runtime)
                .await
                .expect("unsettled progress cannot advance");
            assert_eq!(
                runtime
                    .discord_resume(&checkpoint.binding)
                    .await
                    .expect("checkpoint before dispatch")
                    .1
                    .expect("saved")
                    .sequence(),
                7
            );
            drop(inbound);
            let calls = Arc::new(AtomicUsize::new(0));
            let worker = tokio::spawn(super::run_discord_dispatch(
                receiver,
                Replies {
                    calls: Arc::clone(&calls),
                    fail_second,
                },
                origin,
                reply_credential,
                Arc::clone(&runtime),
                Arc::new(std::sync::RwLock::new(None)),
                Arc::clone(&diagnostics),
                CancellationToken::new(),
                settled,
            ));
            for sequence in [8, 9] {
                let (resume, succeeded) =
                    tokio::time::timeout(Duration::from_secs(3), observed.recv())
                        .await
                        .expect("processing deadline")
                        .expect("dispatcher settlement");
                assert_eq!(resume.sequence(), sequence);
                assert_eq!(succeeded, !(fail_second && sequence == 9));
                if succeeded {
                    checkpoint
                        .progress
                        .complete(&resume, true)
                        .expect("ordered successful settlement");
                    checkpoint
                        .persist(&runtime)
                        .await
                        .expect("checkpoint after completed effect");
                } else {
                    assert!(checkpoint.progress.complete(&resume, false).is_err());
                }
            }
            worker.await.expect("dispatcher joined");
            assert_eq!(calls.load(Ordering::SeqCst), 2);
            let binding = checkpoint.binding.clone();
            assert_eq!(
                runtime
                    .discord_resume(&binding)
                    .await
                    .expect("settled prefix")
                    .1
                    .expect("saved prefix")
                    .sequence(),
                if fail_second { 8 } else { 9 }
            );
            runtime.shutdown().await.expect("runtime drain");
            drop(runtime);
            let reopened = super::AgentRuntime::new(
                provider,
                plugins,
                &root.0,
                "gpt-4o".to_owned(),
                0,
                8,
                Duration::from_secs(60),
                diagnostics,
            )
            .expect("reopened runtime");
            assert_eq!(
                reopened
                    .discord_resume(&binding)
                    .await
                    .expect("reopened prefix")
                    .1
                    .expect("resume")
                    .sequence(),
                if fail_second { 8 } else { 9 }
            );
            for message in &messages {
                assert!(
                    !reopened
                        .admit_channel_message(message)
                        .await
                        .expect("retained delivered or unknown input must not be sent again")
                );
            }
            reopened.shutdown().await.expect("reopened drain");
        }
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn discord_actual_worker_persists_ready_resumes_after_restart_and_clears_invalid_session()
    {
        use crate::adapters::http_api::{
            EmptyModelTools, ProviderHistoryConfig, SmokeProvider, SwappableProvider,
        };
        use crate::adapters::signed_plugins::PluginToolSurface;
        struct OwnedRoot(std::path::PathBuf);
        impl Drop for OwnedRoot {
            fn drop(&mut self) {
                let _ = std::fs::remove_dir_all(&self.0);
            }
        }
        let root = OwnedRoot(std::env::temp_dir().join(format!(
                "claw-discord-checkpoint-{}-{}",
                std::process::id(),
                std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .expect("clock")
                    .as_nanos()
            )));
        std::fs::create_dir(&root.0).expect("owned state root");
        let diagnostics = Arc::new(super::Diagnostics::new(32));
        let readiness = Arc::new(DependencyReadiness::new([
            "provider", "discord", "channels",
        ]));
        let provider = Arc::new(SwappableProvider::new(
            "gpt-4o",
            "Discord fixture",
            ProviderHistoryConfig::default(),
            Arc::new(EmptyModelTools),
            Arc::clone(&readiness),
        ));
        provider
            .activate(Arc::new(SmokeProvider::new().expect("fixture provider")))
            .await
            .expect("activated");
        let plugins = PluginToolSurface::new(Arc::clone(&diagnostics));
        let mut saved_revision = 0;
        for restart in [false, true] {
            let runtime = super::AgentRuntime::new(
                Arc::clone(&provider),
                Arc::clone(&plugins),
                &root.0,
                "gpt-4o".to_owned(),
                0,
                8,
                Duration::from_secs(60),
                Arc::clone(&diagnostics),
            )
            .expect("actual runtime");
            let gateway_origin = approved_origin("discord", "default", "gateway.discord.gg")
                .expect("gateway origin");
            let rest_origin =
                approved_origin("discord", "default", "discord.com").expect("rest origin");
            let credential = bind_credential(
                "discord",
                "default",
                CredentialKind::Token,
                gateway_origin.clone(),
                &SecretString::new("discord-fixture-secret"),
            )
            .expect("gateway credential");
            let rest_credential = bind_credential(
                "discord",
                "default",
                CredentialKind::Token,
                rest_origin.clone(),
                &SecretString::new("discord-fixture-secret"),
            )
            .expect("reply credential");
            let checkpoint = super::DiscordResumeCheckpoint::load(
                &credential,
                &gateway_origin,
                "wss://gateway.discord.gg/?v=10&encoding=json",
                32_768,
                &runtime,
            )
            .await
            .expect("restore checkpoint");
            let binding = checkpoint.binding.clone();
            assert_eq!(checkpoint.saved.is_some(), restart);
            assert_eq!(checkpoint.revision, saved_revision);
            let (transport, mut commands, event_sender, events) =
                DiscordTransportAdapter::new(ProxyPolicy::Disabled, Arc::new(Mutex::new(None)))
                    .expect("no-network transport command queues");
            let reply_transport = transport.clone();
            let mut channel = DiscordChannel::new(
                "default",
                "wss://gateway.discord.gg/?v=10&encoding=json",
                gateway_origin.clone(),
                rest_origin.clone(),
                32_768,
                transport,
                SystemClock,
                NonZeroUsize::new(4).expect("queue"),
                NonZeroU32::new(3).expect("reconnect budget"),
            )
            .expect("channel");
            if let Some(saved) = &checkpoint.saved {
                channel
                    .restore_resume_state(
                        saved.session_id(),
                        saved.sequence(),
                        saved.resume_gateway_url(),
                    )
                    .expect("validated saved session");
            }
            channel.start(Duration::ZERO, &mut ()).expect("start");
            assert!(matches!(
                commands.recv().await,
                Some(DiscordCommand::Open(_))
            ));
            let cancellation = CancellationToken::new();
            let (ready_sender, ready) = tokio::sync::oneshot::channel();
            let worker = tokio::spawn(super::run_discord(
                channel,
                credential,
                reply_transport,
                rest_origin,
                rest_credential,
                events,
                Arc::clone(&runtime),
                Arc::new(std::sync::RwLock::new(None)),
                Arc::clone(&diagnostics),
                ChannelReadiness::new(Arc::clone(&readiness), false, true),
                cancellation.clone(),
                ready_sender,
                Instant::now(),
                checkpoint,
            ));
            event_sender
                .send(super::DiscordEvent::Opened)
                .await
                .expect("socket opened");
            event_sender
                .send(super::DiscordEvent::Packet(
                    br#"{"op":10,"s":null,"d":{"heartbeat_interval":60000}}"#.to_vec(),
                ))
                .await
                .expect("hello");
            let identify = tokio::time::timeout(Duration::from_secs(3), commands.recv())
                .await
                .expect("worker handles HELLO");
            let Some(DiscordCommand::Send(encoded)) = identify else {
                panic!("identify/resume transport command");
            };
            let request: serde_json::Value =
                serde_json::from_str(&encoded).expect("gateway command");
            assert_eq!(request["op"], if restart { 6 } else { 2 });
            if restart {
                assert_eq!(request["d"]["session_id"], "saved-discord-session");
                assert_eq!(request["d"]["seq"], 7);
            }
            let ready_packet = if restart {
                br#"{"op":0,"t":"RESUMED","s":8,"d":{}}"#.as_slice()
            } else {
                br#"{"op":0,"t":"READY","s":7,"d":{"session_id":"saved-discord-session","resume_gateway_url":"wss://gateway-us-east1-b.discord.gg"}}"#.as_slice()
            };
            event_sender
                .send(super::DiscordEvent::Packet(ready_packet.to_vec()))
                .await
                .expect("ready event");
            tokio::time::timeout(Duration::from_secs(3), ready)
                .await
                .expect("worker readiness")
                .expect("ready sender")
                .expect("checkpoint committed before readiness");
            let (revision, saved) = runtime
                .discord_resume(&binding)
                .await
                .expect("persisted readiness");
            saved_revision = revision;
            assert_eq!(
                saved.expect("saved session").sequence(),
                if restart { 8 } else { 7 }
            );
            if restart {
                event_sender
                    .send(super::DiscordEvent::Closed(DiscordGatewayClose::websocket(
                        4010,
                        "fixture invalid shard",
                    )))
                    .await
                    .expect("terminal session invalidation");
            } else {
                cancellation.cancel();
            }
            tokio::time::timeout(Duration::from_secs(3), worker)
                .await
                .expect("worker drain deadline")
                .expect("worker joined");
            if restart {
                let (revision, cleared) = runtime
                    .discord_resume(&binding)
                    .await
                    .expect("invalid session tombstone");
                assert!(cleared.is_none());
                assert!(revision > saved_revision);
            }
            let other = bind_credential(
                "discord",
                "default",
                CredentialKind::Token,
                gateway_origin.clone(),
                &SecretString::new("different-fixture-secret"),
            )
            .expect("different credential");
            assert!(
                super::DiscordResumeCheckpoint::load(
                    &other,
                    &gateway_origin,
                    "wss://gateway.discord.gg/?v=10&encoding=json",
                    32_768,
                    &runtime
                )
                .await
                .expect("different credential checkpoint")
                .saved
                .is_none()
            );
            assert!(
                super::DiscordResumeCheckpoint::load(
                    &other,
                    &gateway_origin,
                    "wss://gateway.discord.gg/?v=10&encoding=json",
                    1,
                    &runtime
                )
                .await
                .expect("different intents checkpoint")
                .saved
                .is_none()
            );
            runtime.shutdown().await.expect("actual runtime drained");
            drop(runtime);
        }
    }

    #[test]
    fn discord_checkpoint_progress_cannot_pass_unsettled_or_out_of_order_messages() {
        let initial = claw_state::DiscordResume::new("session", 7, None).expect("initial");
        let first = claw_state::DiscordResume::new("session", 8, None).expect("first");
        let second = claw_state::DiscordResume::new("session", 9, None).expect("second");
        let ignored = claw_state::DiscordResume::new("session", 10, None).expect("ignored");
        let mut progress = super::DiscordResumeProgress::new(Some(initial.clone()));
        progress
            .observe(Some(first.clone()), 1)
            .expect("queued first");
        progress
            .observe(Some(second.clone()), 1)
            .expect("queued second");
        progress
            .observe(Some(ignored.clone()), 0)
            .expect("later ignored dispatch");
        assert_eq!(progress.settled, Some(initial));
        assert!(progress.complete(&second, true).is_err());
        progress.complete(&first, true).expect("first completed");
        assert_eq!(progress.settled, Some(first));
        assert!(progress.complete(&second, false).is_err());
        assert!(progress.observe(None, 0).is_err());
        progress.complete(&second, true).expect("second completed");
        assert_eq!(progress.settled, Some(ignored));
        progress
            .observe(None, 0)
            .expect("invalidated drained session");
        assert!(progress.settled.is_none());
        assert!(progress.observe(Some(second.clone()), 66).is_err());
        progress
            .observe(Some(second.clone()), 2)
            .expect("batch replay queued at RESUMED");
        progress
            .complete(&second, true)
            .expect("first replay completed");
        assert!(
            progress.settled.is_none(),
            "batch sequence cannot cross the second unresolved input"
        );
        progress
            .complete(&second, true)
            .expect("all replay messages completed");
        assert_eq!(progress.settled, Some(second));
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn telegram_processing_loop_retains_failed_delivery_batch_without_resending() {
        use super::{
            AgentRuntime, Diagnostics, TelegramChannel, TelegramPollRequest, TelegramSendRequest,
            TelegramTransport,
        };
        use crate::adapters::http_api::{
            EmptyModelTools, OperatorRuntimeStatus, ProviderHistoryConfig, SmokeProvider,
            SwappableProvider,
        };
        use crate::adapters::signed_plugins::PluginToolSurface;
        for (interfere, confirmed) in [(false, false), (true, false), (false, true)] {
            struct OwnedRoot(std::path::PathBuf);
            impl Drop for OwnedRoot {
                fn drop(&mut self) {
                    let _ = std::fs::remove_dir_all(&self.0);
                }
            }
            struct PollReplay {
                offsets: Arc<Mutex<Vec<Option<i64>>>>,
                sends: Arc<AtomicUsize>,
                cancellation: CancellationToken,
                interference: Option<(Arc<AgentRuntime>, String)>,
                confirmed: bool,
            }
            impl TelegramTransport for PollReplay {
                fn get_updates(
                    &mut self,
                    request: &TelegramPollRequest<'_>,
                ) -> Result<ProviderResponse, ChannelError> {
                    let mut offsets = self.offsets.lock().expect("recorded polls");
                    offsets.push(request.offset());
                    if offsets.len() <= 2 {
                        Ok(ProviderResponse::new(200, br#"{"ok":true,"result":[{"update_id":10,"message":{"message_id":1,"chat":{"id":-100},"from":{"id":7},"text":"process once"}}]}"#.as_slice()))
                    } else {
                        self.cancellation.cancel();
                        Ok(ProviderResponse::new(
                            200,
                            br#"{"ok":true,"result":[]}"#.as_slice(),
                        ))
                    }
                }
                fn send_message(
                    &mut self,
                    _: &TelegramSendRequest<'_>,
                ) -> Result<ProviderResponse, ChannelError> {
                    self.sends.fetch_add(1, Ordering::SeqCst);
                    if let Some((runtime, binding)) = self.interference.take() {
                        tokio::task::block_in_place(|| {
                            tokio::runtime::Handle::current()
                                .block_on(runtime.advance_telegram_poll_cursor(&binding, 0, 12))
                        })
                        .expect("concurrent cursor writer");
                    }
                    if self.confirmed {
                        Ok(ProviderResponse::new(
                            200,
                            br#"{"ok":true,"result":{"message_id":42}}"#.as_slice(),
                        ))
                    } else {
                        Err(ChannelError::Transport(
                            claw_channel_sdk::TransportErrorKind::Io,
                        ))
                    }
                }
            }
            let root = OwnedRoot(std::env::temp_dir().join(format!(
                    "claw-telegram-batch-{}-{}",
                    std::process::id(),
                    std::time::SystemTime::now()
                        .duration_since(std::time::UNIX_EPOCH)
                        .expect("clock")
                        .as_nanos()
                )));
            std::fs::create_dir(&root.0).expect("owned state root");
            let diagnostics = Arc::new(Diagnostics::new(32));
            let readiness = Arc::new(DependencyReadiness::new([
                "provider", "telegram", "channels",
            ]));
            let provider = Arc::new(SwappableProvider::new(
                "gpt-4o",
                "telegram processing fixture",
                ProviderHistoryConfig::default(),
                Arc::new(EmptyModelTools),
                Arc::clone(&readiness),
            ));
            provider
                .activate(Arc::new(SmokeProvider::new().expect("fixture provider")))
                .await
                .expect("activated");
            let plugins = PluginToolSurface::new(Arc::clone(&diagnostics));
            let runtime = AgentRuntime::new(
                Arc::clone(&provider),
                Arc::clone(&plugins),
                &root.0,
                "gpt-4o".to_owned(),
                0,
                8,
                Duration::from_secs(60),
                Arc::clone(&diagnostics),
            )
            .expect("actual runtime");
            let cancellation = CancellationToken::new();
            let offsets = Arc::new(Mutex::new(Vec::new()));
            let sends = Arc::new(AtomicUsize::new(0));
            let secret = SecretString::new("telegram-secret");
            let account = super::configured_account_id("telegram", &secret);
            let origin = approved_origin("telegram", &account, "api.telegram.org")
                .expect("configured origin");
            let credential = bind_credential(
                "telegram",
                &account,
                CredentialKind::Token,
                origin.clone(),
                &secret,
            )
            .expect("configured credential");
            let identity = super::TelegramPollIdentity::new(credential, &origin)
                .expect("credential-bound poll identity");
            let binding = identity.binding.clone();
            let mut channel = TelegramChannel::new(
                account.clone(),
                origin,
                PollReplay {
                    offsets: Arc::clone(&offsets),
                    sends: Arc::clone(&sends),
                    cancellation: cancellation.clone(),
                    interference: interfere.then(|| (Arc::clone(&runtime), binding.clone())),
                    confirmed,
                },
                super::SystemClock,
                std::num::NonZeroUsize::new(2).expect("queue"),
                Duration::from_millis(1),
            )
            .expect("channel");
            channel
                .start(&mut super::ChannelDiagnostics(Arc::clone(&diagnostics)))
                .expect("started");
            tokio::time::timeout(
                Duration::from_secs(3),
                super::run_telegram(
                    channel,
                    identity,
                    Arc::clone(&runtime),
                    Arc::new(std::sync::RwLock::new(None)),
                    Arc::clone(&diagnostics),
                    ChannelReadiness::new(Arc::clone(&readiness), true, false),
                    cancellation,
                ),
            )
            .await
            .expect("bounded actual processing loop");
            assert_eq!(
                *offsets.lock().expect("observed poll offsets"),
                if interfere {
                    vec![None]
                } else if confirmed {
                    vec![None, Some(11), Some(11)]
                } else {
                    vec![None, None, Some(11)]
                }
            );
            assert_eq!(
                sends.load(Ordering::SeqCst),
                1,
                "unknown delivery must never be attempted twice"
            );
            assert_eq!(runtime.operator_status()["sessions"]["managed"], 1);
            assert_eq!(
                runtime
                    .telegram_poll_cursor(&binding)
                    .await
                    .expect("saved settled cursor"),
                if interfere { 12 } else { 11 }
            );
            runtime.shutdown().await.expect("owned runtime drain");
            drop(runtime);
            let runtime = AgentRuntime::new(
                provider,
                plugins,
                &root.0,
                "gpt-4o".to_owned(),
                0,
                8,
                Duration::from_secs(60),
                Arc::clone(&diagnostics),
            )
            .expect("reopened actual runtime");
            let origin = approved_origin("telegram", &account, "api.telegram.org")
                .expect("same configured origin");
            let credential = bind_credential(
                "telegram",
                &account,
                CredentialKind::Token,
                origin.clone(),
                &secret,
            )
            .expect("same configured credential");
            let identity = super::TelegramPollIdentity::new(credential, &origin)
                .expect("same credential binding");
            assert_eq!(identity.binding, binding);
            let cancellation = CancellationToken::new();
            let mut channel = TelegramChannel::new(
                account.clone(),
                origin.clone(),
                PollReplay {
                    offsets: Arc::clone(&offsets),
                    sends: Arc::clone(&sends),
                    cancellation: cancellation.clone(),
                    interference: None,
                    confirmed,
                },
                super::SystemClock,
                std::num::NonZeroUsize::new(2).expect("queue"),
                Duration::from_millis(1),
            )
            .expect("restarted channel");
            channel
                .restore_poll_cursor(
                    runtime
                        .telegram_poll_cursor(&binding)
                        .await
                        .expect("restored cursor"),
                )
                .expect("pre-start cursor restoration");
            channel
                .start(&mut super::ChannelDiagnostics(Arc::clone(&diagnostics)))
                .expect("restarted");
            tokio::time::timeout(
                Duration::from_secs(3),
                super::run_telegram(
                    channel,
                    identity,
                    Arc::clone(&runtime),
                    Arc::new(std::sync::RwLock::new(None)),
                    diagnostics,
                    ChannelReadiness::new(readiness, true, false),
                    cancellation,
                ),
            )
            .await
            .expect("restarted actual loop");
            assert_eq!(
                *offsets.lock().expect("restarted poll offsets"),
                if interfere {
                    vec![None, Some(12), Some(12)]
                } else if confirmed {
                    vec![None, Some(11), Some(11), Some(11)]
                } else {
                    vec![None, None, Some(11), Some(11)]
                }
            );
            assert_eq!(sends.load(Ordering::SeqCst), 1);
            let message = InboundMessage {
                id: "1".to_owned(),
                channel_id: "telegram".to_owned(),
                account_id: account.clone(),
                conversation_id: "telegram:-100".to_owned(),
                sender_id: "7".to_owned(),
                text: Some("process once".to_owned()),
                attachments: Vec::new(),
                received_at_unix_ms: 0,
            };
            let run = runtime
                .run_channel_message(&message, async {
                    panic!("retained input must not execute again")
                })
                .await
                .expect("read retained run");
            let query = serde_json::json!({"nativeRecovery":{"channelId":"telegram","accountId":account,"conversationId":"telegram:-100","senderId":"7","runId":run.id()}});
            let response = runtime
                .dispatch("channels.status", Some(&query), CancellationToken::new())
                .await
                .expect("Telegram receipt query")
                .expect("receipt response");
            assert_eq!(
                response["delivery"],
                if confirmed {
                    "delivered"
                } else {
                    "outcome_unknown"
                }
            );
            assert_eq!(
                response["deliveryReceipts"]
                    .as_array()
                    .expect("receipt page")
                    .len(),
                usize::from(confirmed)
            );
            if confirmed {
                assert_eq!(response["deliveryReceipts"][0]["remoteMessageId"], "42");
                assert_eq!(response["deliveryReceipts"][0]["segment"], 0);
                assert_eq!(
                    response["deliveryReceipts"][0]["contentSha256"]
                        .as_str()
                        .expect("digest")
                        .len(),
                    64
                );
            }
            assert!(!response.to_string().contains("process once"));
            let other_credential = super::bind_credential(
                "telegram",
                &account,
                CredentialKind::Token,
                origin.clone(),
                &SecretString::new("different-telegram-secret"),
            )
            .expect("different fixture credential");
            let other = super::TelegramPollIdentity::new(other_credential, &origin)
                .expect("different binding");
            assert_ne!(other.binding, binding);
            assert_eq!(
                runtime
                    .telegram_poll_cursor(&other.binding)
                    .await
                    .expect("different credential starts independently"),
                0
            );
            runtime.shutdown().await.expect("reopened runtime drained");
        }
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn authenticated_channel_dispatch_isolates_account_history_and_reset() {
        use super::{AgentRuntime, Diagnostics, process_inbound, send_discord_reply_once};
        use crate::adapters::http_api::{
            EmptyModelTools, OperatorRuntimeStatus, ProviderHistoryConfig, SmokeProvider,
            SwappableProvider,
        };
        use crate::adapters::signed_plugins::PluginToolSurface;
        use std::sync::RwLock;

        struct OwnedRoot(std::path::PathBuf);
        impl Drop for OwnedRoot {
            fn drop(&mut self) {
                let _ = std::fs::remove_dir_all(&self.0);
            }
        }
        let root = OwnedRoot(std::env::temp_dir().join(format!(
                "claw-channel-runtime-{}-{}",
                std::process::id(),
                std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .expect("clock")
                    .as_nanos()
            )));
        std::fs::create_dir(&root.0).expect("owned channel state directory");
        let diagnostics = Arc::new(Diagnostics::new(32));
        let readiness = Arc::new(DependencyReadiness::new(["provider"]));
        let provider = Arc::new(SwappableProvider::new(
            "gpt-4o",
            "channel fixture role",
            ProviderHistoryConfig::default(),
            Arc::new(EmptyModelTools),
            readiness,
        ));
        provider
            .activate(Arc::new(
                SmokeProvider::new().expect("isolated smoke provider"),
            ))
            .await
            .expect("fixture provider activation");
        let plugins = PluginToolSurface::new(Arc::clone(&diagnostics));
        let runtime = AgentRuntime::new(
            Arc::clone(&provider),
            Arc::clone(&plugins),
            &root.0,
            "gpt-4o".to_owned(),
            0,
            8,
            Duration::from_secs(60),
            Arc::clone(&diagnostics),
        )
        .expect("real runtime composition");
        let legacy = claw_http_api::LegacyChannelMessage {
            channel: "whatsapp",
            account_id: "phone-one".to_owned(),
            message_id: "same-message".to_owned(),
            sender_id: "sender-one".to_owned(),
            conversation_id: "whatsapp:sender-one".to_owned(),
            user_name: "untrusted display name".to_owned(),
            text: "private-whatsapp-first".to_owned(),
        };
        let first = claw_http_api::LegacyChannelMessagePort::process_owned(
            Arc::clone(&runtime),
            legacy.clone(),
            CancellationToken::new(),
        )
        .await
        .expect("first owned WhatsApp input");
        let mut renamed = legacy.clone();
        renamed.user_name = "another display name".to_owned();
        let replay = claw_http_api::LegacyChannelMessagePort::process_owned(
            Arc::clone(&runtime),
            renamed,
            CancellationToken::new(),
        )
        .await
        .expect("display rename must still read original result");
        assert_eq!(first, replay);
        let mut other = legacy.clone();
        other.account_id = "phone-two".to_owned();
        other.text = "private-whatsapp-second".to_owned();
        let second = claw_http_api::LegacyChannelMessagePort::process_owned(
            Arc::clone(&runtime),
            other,
            CancellationToken::new(),
        )
        .await
        .expect("other verified phone account");
        assert!(
            second.contains("private-whatsapp-second")
                && !second.contains("private-whatsapp-first")
        );
        let mut malformed = legacy.clone();
        malformed.sender_id.clear();
        assert!(
            claw_http_api::LegacyChannelMessagePort::process_owned(
                Arc::clone(&runtime),
                malformed,
                CancellationToken::new()
            )
            .await
            .is_err()
        );
        let cancelled = CancellationToken::new();
        cancelled.cancel();
        assert!(
            claw_http_api::LegacyChannelMessagePort::process_owned(
                Arc::clone(&runtime),
                legacy,
                cancelled
            )
            .await
            .is_err()
        );
        assert_eq!(runtime.operator_status()["sessions"]["managed"], 2);
        let authentication = Arc::new(RwLock::new(None));
        let first_account = super::configured_account_id(
            "telegram",
            &SecretString::new("first-configured-bot-secret"),
        );
        let second_account = super::configured_account_id(
            "telegram",
            &SecretString::new("second-configured-bot-secret"),
        );
        runtime
            .register_channel_account("telegram", &first_account)
            .expect("configured first bot");
        let mut message = InboundMessage {
            id: "message-1".to_owned(),
            channel_id: "telegram".to_owned(),
            account_id: first_account.clone(),
            conversation_id: "telegram:42:7".to_owned(),
            sender_id: "7".to_owned(),
            text: Some("first-account-private-marker".to_owned()),
            attachments: Vec::new(),
            received_at_unix_ms: 1,
        };
        let first = process_inbound(
            &message,
            &runtime,
            &authentication,
            &diagnostics,
            CancellationToken::new(),
        )
        .await
        .expect("first actual channel dispatch")
        .expect("first reply");
        assert!(first.contains("first-account-private-marker"));
        let replay = process_inbound(
            &message,
            &runtime,
            &authentication,
            &diagnostics,
            CancellationToken::new(),
        )
        .await
        .expect("duplicate durable input")
        .expect("retained reply");
        assert_eq!(
            replay, first,
            "same provider message must not repeat the model or append another input"
        );
        let mut conflicting = message.clone();
        conflicting.text = Some("changed body under the same message ID".to_owned());
        assert!(
            process_inbound(
                &conflicting,
                &runtime,
                &authentication,
                &diagnostics,
                CancellationToken::new()
            )
            .await
            .is_err()
        );
        runtime
            .register_channel_account("telegram", &second_account)
            .expect("configured replacement bot");
        let accounts = runtime.operator_status()["configuredChannelAccounts"].clone();
        assert_eq!(accounts["partitions"]["telegram"], second_account);
        assert_eq!(accounts["credentialsIncluded"], false);
        assert_eq!(accounts["automaticHistoryAdoption"], false);
        assert!(!accounts.to_string().contains("configured-bot-secret"));
        message.account_id = second_account.clone();
        message.text = Some("second-account-private-marker".to_owned());
        let second = process_inbound(
            &message,
            &runtime,
            &authentication,
            &diagnostics,
            CancellationToken::new(),
        )
        .await
        .expect("second actual channel dispatch")
        .expect("second reply");
        assert!(
            second.contains("second-account-private-marker")
                && !second.contains("first-account-private-marker")
        );
        assert_eq!(runtime.operator_status()["sessions"]["managed"], 4);
        message.account_id = first_account;
        message.id = "message-3".to_owned();
        message.text = Some("/reset".to_owned());
        let reset = process_inbound(
            &message,
            &runtime,
            &authentication,
            &diagnostics,
            CancellationToken::new(),
        )
        .await
        .expect("own reset")
        .expect("reset reply");
        assert_eq!(reset, "Conversation reset.");
        assert_eq!(
            process_inbound(
                &message,
                &runtime,
                &authentication,
                &diagnostics,
                CancellationToken::new()
            )
            .await
            .expect("duplicate reset reads its retained result")
            .expect("reset result"),
            reset
        );
        assert_eq!(runtime.operator_status()["sessions"]["managed"], 3);
        message.account_id = second_account;
        message.id = "message-4".to_owned();
        message.text = Some("continue-second-account".to_owned());
        let retained = process_inbound(
            &message,
            &runtime,
            &authentication,
            &diagnostics,
            CancellationToken::new(),
        )
        .await
        .expect("second account continues")
        .expect("retained reply");
        assert!(
            retained.contains("second-account-private-marker")
                && !retained.contains("first-account-private-marker")
        );
        let mut delivery_cases = Vec::new();
        for confirmed in [true, false] {
            let response = if confirmed {
                Ok(ProviderResponse::new(
                    200,
                    br#"{"id":"123","channel_id":"room"}"#.to_vec(),
                ))
            } else {
                Err(ChannelError::Transport(TransportErrorKind::Io))
            };
            let (transport, origin, credential, mut message) =
                discord_reply_fixture(VecDeque::from([response]));
            message.id = format!("delivery-{confirmed}");
            runtime
                .run_channel_message(&message, async { Ok(Some("reply".to_owned())) })
                .await
                .expect("durable reply before transport");
            assert_eq!(
                send_discord_reply_once(
                    &runtime,
                    &transport,
                    &origin,
                    &credential,
                    &message,
                    "reply",
                    &CancellationToken::new()
                )
                .await
                .is_ok(),
                confirmed
            );
            assert_eq!(transport.calls.load(Ordering::SeqCst), 1);
            assert_eq!(
                send_discord_reply_once(
                    &runtime,
                    &transport,
                    &origin,
                    &credential,
                    &message,
                    "reply",
                    &CancellationToken::new()
                )
                .await
                .is_ok(),
                confirmed
            );
            assert_eq!(
                transport.calls.load(Ordering::SeqCst),
                1,
                "a repeated inbound message cannot repeat its transport attempt"
            );
            delivery_cases.push((transport, origin, credential, message, confirmed));
        }
        runtime.shutdown().await.expect("owned runtime drained");
        drop(runtime);
        let reopened = AgentRuntime::new(
            provider,
            plugins,
            &root.0,
            "gpt-4o".to_owned(),
            0,
            8,
            Duration::from_secs(60),
            diagnostics,
        )
        .expect("reopened real runtime");
        for (transport, origin, credential, message, confirmed) in delivery_cases {
            reopened
                .run_channel_message(&message, async {
                    panic!("a persisted message must not execute again after restart");
                })
                .await
                .expect("retained execution result");
            assert_eq!(
                send_discord_reply_once(
                    &reopened,
                    &transport,
                    &origin,
                    &credential,
                    &message,
                    "reply",
                    &CancellationToken::new()
                )
                .await
                .is_ok(),
                confirmed
            );
            assert_eq!(
                transport.calls.load(Ordering::SeqCst),
                1,
                "reopening cannot resend a confirmed or unknown reply"
            );
            let query = serde_json::json!({"nativeRecovery":{"channelId":message.channel_id,"accountId":message.account_id,"conversationId":message.conversation_id,"senderId":message.sender_id}});
            let status = reopened
                .dispatch("channels.status", Some(&query), CancellationToken::new())
                .await
                .expect("read-only native recovery")
                .expect("recovery response");
            assert_eq!(status["contentIncluded"], false);
            assert_eq!(status["automaticReplay"], false);
            assert_eq!(
                status["pendingResults"]
                    .as_array()
                    .expect("pending statuses")
                    .len(),
                1
            );
            assert_eq!(status["pendingResults"][0]["delivery"], "outcome_unknown");
            let mut wrong = query.clone();
            wrong["nativeRecovery"]["senderId"] = serde_json::json!("another-sender");
            wrong["nativeRecovery"]["runId"] = status["pendingResults"][0]["runId"].clone();
            assert!(
                reopened
                    .dispatch("channels.status", Some(&wrong), CancellationToken::new())
                    .await
                    .is_err()
            );
        }
        reopened.shutdown().await.expect("reopened runtime drained");
        drop(reopened);
    }

    use std::collections::VecDeque;
    use std::num::{NonZeroU32, NonZeroUsize};
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::{Arc, Mutex, PoisonError};
    use std::time::{Duration, Instant};

    use claw_channel_sdk::{
        ApprovedOrigin, ChannelCredential, ChannelError, ConnectionState, CredentialKind,
        InboundMessage, TransportErrorKind,
    };
    use claw_channels::{
        DiscordChannel, DiscordGatewayClose, DiscordGatewayPhase, DiscordPacketOutcome,
        ProviderResponse, SystemClock,
    };
    use claw_http_api::ReadinessPort;
    use claw_provider_sdk::http::ProxyPolicy;
    use claw_provider_sdk::{CancelToken, SecretString};
    use tokio_util::sync::CancellationToken;
    use tokio_util::task::TaskTracker;

    use super::{
        ChannelReadiness, ChannelStartGuard, ConfiguredChannel, DependencyReadiness,
        DiscordCommand, DiscordReplyTransport, DiscordTransportAdapter, TelegramProbeFuture,
        TelegramReadinessError, TelegramReadinessProbe, approved_origin, bind_credential,
        bind_request_cancellation, cancel_requests, classify_telegram_poll_probe_response,
        classify_telegram_webhook_probe_response, parse_retry_after_header, send_discord_reply,
        telegram_failure_is_terminal, telegram_readiness_requests, wait_for_telegram_readiness,
    };

    #[test]
    fn configured_channel_readiness_aggregates_without_cross_channel_overwrite() {
        let dependency = Arc::new(DependencyReadiness::new(["channels"]));
        let channels = ChannelReadiness::new(Arc::clone(&dependency), true, true);

        assert!(!dependency.snapshot().expect("snapshot").ready);
        channels.set(ConfiguredChannel::Telegram, true);
        assert!(!dependency.snapshot().expect("snapshot").ready);
        channels.set(ConfiguredChannel::Discord, true);
        assert!(dependency.snapshot().expect("snapshot").ready);

        channels.set(ConfiguredChannel::Discord, false);
        channels.set(ConfiguredChannel::Telegram, true);
        let snapshot = dependency.snapshot().expect("snapshot");
        assert!(!snapshot.ready);
        assert_eq!(snapshot.failing, ["channels", "discord"]);
    }

    #[test]
    fn discord_terminal_and_exhausted_states_clear_aggregate_readiness() {
        let dependency = Arc::new(DependencyReadiness::new(["channels"]));
        let channels = ChannelReadiness::new(Arc::clone(&dependency), true, true);
        channels.set(ConfiguredChannel::Telegram, true);
        channels.set(ConfiguredChannel::Discord, true);

        channels.set_discord_state(
            ConnectionState::Closed,
            DiscordGatewayPhase::ReconnectExhausted,
        );
        channels.set(ConfiguredChannel::Telegram, true);
        assert_eq!(
            dependency.snapshot().expect("terminal snapshot").failing,
            ["channels", "discord"]
        );

        channels.set(ConfiguredChannel::Discord, true);
        channels.set_discord_state(
            ConnectionState::Disconnected,
            DiscordGatewayPhase::ReconnectExhausted,
        );
        channels.set(ConfiguredChannel::Telegram, true);
        assert_eq!(
            dependency.snapshot().expect("exhausted snapshot").failing,
            ["channels", "discord"]
        );
    }

    #[tokio::test]
    async fn discord_adapter_async_resume_failure_falls_back_and_still_sends_resume() {
        let request_cancel = Arc::new(Mutex::new(None));
        let (transport, mut commands, _event_tx, _events) =
            DiscordTransportAdapter::new(ProxyPolicy::Disabled, request_cancel)
                .expect("Discord transport");
        let gateway_origin =
            approved_origin("discord", "default", "gateway.discord.gg").expect("Gateway origin");
        let rest_origin =
            approved_origin("discord", "default", "discord.com").expect("REST origin");
        let gateway_credential = bind_credential(
            "discord",
            "default",
            CredentialKind::Token,
            gateway_origin.clone(),
            &SecretString::new("discord-secret"),
        )
        .expect("Gateway credential");
        let mut channel = DiscordChannel::new(
            "default",
            "wss://gateway.discord.gg/?v=10&encoding=json",
            gateway_origin,
            rest_origin,
            32_768,
            transport,
            SystemClock,
            NonZeroUsize::new(2).expect("non-zero capacity"),
            NonZeroU32::new(3).expect("non-zero attempts"),
        )
        .expect("Discord channel");

        channel.start(Duration::ZERO, &mut ()).expect("start");
        match commands.recv().await {
            Some(DiscordCommand::Open(url)) => {
                assert_eq!(url, "wss://gateway.discord.gg/?v=10&encoding=json");
            }
            Some(_) | None => panic!("bootstrap open command expected"),
        }
        channel.gateway_opened(&mut ()).expect("bootstrap opened");
        assert_eq!(
            channel.handle_gateway_packet(
                br#"{"op":10,"t":null,"s":null,"d":{"heartbeat_interval":1000}}"#,
                Duration::ZERO,
                &gateway_credential,
                &mut (),
            ),
            Ok(DiscordPacketOutcome::Identified)
        );
        match commands.recv().await {
            Some(DiscordCommand::Send(payload)) => {
                assert_eq!(
                    serde_json::from_str::<serde_json::Value>(&payload).expect("IDENTIFY")["op"],
                    2
                );
            }
            Some(_) | None => panic!("IDENTIFY command expected"),
        }
        assert_eq!(
            channel.handle_gateway_packet(
                br#"{"op":0,"t":"READY","s":41,"d":{"session_id":"session","resume_gateway_url":"wss://gateway-us-east1-b.discord.gg"}}"#,
                Duration::ZERO,
                &gateway_credential,
                &mut (),
            ),
            Ok(DiscordPacketOutcome::Ready)
        );
        assert_eq!(
            channel.handle_gateway_packet(
                br#"{"op":7,"t":null,"s":null,"d":null}"#,
                Duration::from_secs(1),
                &gateway_credential,
                &mut (),
            ),
            Ok(DiscordPacketOutcome::ReconnectRequested)
        );
        assert!(matches!(commands.recv().await, Some(DiscordCommand::Close)));

        assert_eq!(channel.tick(Duration::from_secs(4), &mut ()), Ok(true));
        match commands.recv().await {
            Some(DiscordCommand::Open(url)) => {
                assert_eq!(
                    url,
                    "wss://gateway-us-east1-b.discord.gg?v=10&encoding=json"
                );
            }
            Some(_) | None => panic!("resume open command expected"),
        }
        assert_eq!(
            channel.gateway_closed_with(
                Duration::from_secs(4),
                DiscordGatewayClose::transport_lost(),
                &mut (),
            ),
            Ok(true)
        );
        assert_eq!(channel.session_id(), Some("session"));
        assert_eq!(channel.sequence(), Some(41));
        assert_eq!(channel.resume_gateway_url(), None);

        assert_eq!(channel.tick(Duration::from_secs(7), &mut ()), Ok(true));
        match commands.recv().await {
            Some(DiscordCommand::Open(url)) => {
                assert_eq!(url, "wss://gateway.discord.gg/?v=10&encoding=json");
            }
            Some(_) | None => panic!("bootstrap fallback command expected"),
        }
        channel.gateway_opened(&mut ()).expect("fallback opened");
        assert_eq!(
            channel.handle_gateway_packet(
                br#"{"op":10,"t":null,"s":null,"d":{"heartbeat_interval":1000}}"#,
                Duration::from_secs(7),
                &gateway_credential,
                &mut (),
            ),
            Ok(DiscordPacketOutcome::Identified)
        );
        match commands.recv().await {
            Some(DiscordCommand::Send(payload)) => {
                let resume =
                    serde_json::from_str::<serde_json::Value>(&payload).expect("RESUME payload");
                assert_eq!(resume["op"], 6);
                assert_eq!(resume["d"]["session_id"], "session");
                assert_eq!(resume["d"]["seq"], 41);
            }
            Some(_) | None => panic!("RESUME command expected"),
        }
    }

    #[tokio::test]
    async fn discord_resume_url_must_share_bootstrap_no_proxy_policy() {
        let request_cancel = Arc::new(Mutex::new(None));
        let proxy = ProxyPolicy::Explicit {
            url: "http://proxy.internal:3128".to_owned(),
            no_proxy: Some("gateway.discord.gg".to_owned()),
        };
        let (transport, mut commands, _event_tx, _events) =
            DiscordTransportAdapter::new(proxy, request_cancel).expect("Discord transport");
        assert!(transport.gateway_url_is_direct("wss://gateway.discord.gg/?v=10&encoding=json"));
        assert!(
            !transport
                .gateway_url_is_direct("wss://gateway-us-east1-b.discord.gg?v=10&encoding=json")
        );

        let gateway_origin =
            approved_origin("discord", "default", "gateway.discord.gg").expect("Gateway origin");
        let rest_origin =
            approved_origin("discord", "default", "discord.com").expect("REST origin");
        let gateway_credential = bind_credential(
            "discord",
            "default",
            CredentialKind::Token,
            gateway_origin.clone(),
            &SecretString::new("discord-secret"),
        )
        .expect("Gateway credential");
        let mut channel = DiscordChannel::new(
            "default",
            "wss://gateway.discord.gg/?v=10&encoding=json",
            gateway_origin,
            rest_origin,
            32_768,
            transport,
            SystemClock,
            NonZeroUsize::new(2).expect("non-zero capacity"),
            NonZeroU32::new(3).expect("non-zero attempts"),
        )
        .expect("Discord channel");

        channel.start(Duration::ZERO, &mut ()).expect("start");
        assert!(matches!(
            commands.recv().await,
            Some(DiscordCommand::Open(_))
        ));
        channel.gateway_opened(&mut ()).expect("opened");
        channel
            .handle_gateway_packet(
                br#"{"op":10,"t":null,"s":null,"d":{"heartbeat_interval":1000}}"#,
                Duration::ZERO,
                &gateway_credential,
                &mut (),
            )
            .expect("identified");
        assert!(matches!(
            commands.recv().await,
            Some(DiscordCommand::Send(_))
        ));
        assert_eq!(
            channel.handle_gateway_packet(
                br#"{"op":0,"t":"READY","s":41,"d":{"session_id":"session","resume_gateway_url":"wss://gateway-us-east1-b.discord.gg"}}"#,
                Duration::ZERO,
                &gateway_credential,
                &mut (),
            ),
            Ok(DiscordPacketOutcome::Ready)
        );
        assert_eq!(channel.resume_gateway_url(), None);

        channel
            .handle_gateway_packet(
                br#"{"op":7,"t":null,"s":null,"d":null}"#,
                Duration::from_secs(1),
                &gateway_credential,
                &mut (),
            )
            .expect("reconnect requested");
        assert!(matches!(commands.recv().await, Some(DiscordCommand::Close)));
        assert_eq!(channel.tick(Duration::from_secs(4), &mut ()), Ok(true));
        match commands.recv().await {
            Some(DiscordCommand::Open(url)) => {
                assert_eq!(url, "wss://gateway.discord.gg/?v=10&encoding=json");
            }
            Some(_) | None => panic!("bootstrap fallback expected"),
        }
        channel.gateway_opened(&mut ()).expect("fallback opened");
        channel
            .handle_gateway_packet(
                br#"{"op":10,"t":null,"s":null,"d":{"heartbeat_interval":1000}}"#,
                Duration::from_secs(4),
                &gateway_credential,
                &mut (),
            )
            .expect("resume sent");
        match commands.recv().await {
            Some(DiscordCommand::Send(payload)) => {
                let resume =
                    serde_json::from_str::<serde_json::Value>(&payload).expect("RESUME payload");
                assert_eq!(resume["op"], 6);
                assert_eq!(resume["d"]["session_id"], "session");
                assert_eq!(resume["d"]["seq"], 41);
            }
            Some(_) | None => panic!("RESUME command expected"),
        }
    }

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
            Ok(ProviderResponse::new(
                200,
                br#"{"id":"123","channel_id":"room"}"#.to_vec(),
            )),
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
    async fn discord_reply_requires_a_real_message_receipt_not_only_http_success() {
        for body in [
            b"".as_slice(),
            b"{}",
            br#"{"id":"123","channel_id":"other"}"#,
            br#"{"id":"0","channel_id":"room"}"#,
            br#"{"id":"not-a-snowflake","channel_id":"room"}"#,
        ] {
            let (transport, origin, credential, message) =
                discord_reply_fixture(VecDeque::from([Ok(ProviderResponse::new(
                    200,
                    body.to_vec(),
                ))]));
            assert!(
                send_discord_reply(
                    &transport,
                    &origin,
                    &credential,
                    &message,
                    "reply",
                    &CancellationToken::new()
                )
                .await
                .is_err()
            );
            assert_eq!(
                transport.calls.load(Ordering::SeqCst),
                1,
                "unconfirmed success must not be retried"
            );
        }
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
    async fn telegram_readiness_retries_http_408_as_timeout() {
        let failure =
            classify_telegram_poll_probe_response(&ProviderResponse::new(408, Vec::new()))
                .expect_err("408 is a timeout");
        assert_eq!(
            failure,
            ChannelError::Transport(TransportErrorKind::Timeout)
        );
        assert!(!telegram_failure_is_terminal(&failure));

        let probe = ScriptedTelegramProbe {
            results: Mutex::new(VecDeque::from([Err(failure), Ok(())])),
            calls: AtomicUsize::new(0),
        };
        let (origin, credential) = telegram_probe_credential();
        wait_for_telegram_readiness(
            &probe,
            &credential,
            &origin,
            &CancellationToken::new(),
            Duration::from_millis(1),
            2,
        )
        .await
        .expect("408 readiness retries");
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

//! Concrete adapters consumed by the legacy HTTP compatibility facade.

use std::collections::VecDeque;
use std::process::{Command as BlockingCommand, Stdio};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex, PoisonError};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use claw_channels::segment_outbound_text;
use claw_http_api::{
    LegacyAdminAction, LegacyChannelMessage, LegacyChannelMessagePort, LegacyDeviceFlowPort,
    LegacyExecResult, LegacyHostAdminPort, LegacyOsInfo, LegacyProcessInfo, LegacyProcessMemory,
    LegacySystemInfo, LegacyTeamsPort, LegacyWhatsAppPort, PortError, PortErrorKind, PortFuture,
};
use claw_provider_sdk::http::{Body, HttpRequest, HttpTransport, Method};
use claw_provider_sdk::{BoundSecret, CancelToken, Operation, Origin, SecretString};
use claw_providers::DeviceFlow;
use serde_json::{Value, json};
use tokio::io::{AsyncRead, AsyncReadExt};
use tokio::process::Command;
use tokio::sync::Mutex as AsyncMutex;
use tokio::task::JoinHandle;
use tokio_util::sync::CancellationToken;
use url::Url;

use super::http_api::Diagnostics;

const ADMIN_OUTPUT_LIMIT: usize = 1024 * 1024;
const WHATSAPP_SEND_TIMEOUT: Duration = Duration::from_secs(10);

/// Activates a provider from a GitHub OAuth token obtained by Device Flow.
pub trait DeviceTokenActivator: Send + Sync {
    /// Builds and publishes the provider.
    fn activate(&self, token: SecretString) -> PortFuture<'_, Result<(), PortError>>;
}

#[derive(Clone)]
struct PendingAuthorization {
    authorization: claw_providers::github_copilot::DeviceAuthorization,
    expires_at: Instant,
}

struct TerminationGuard(Arc<AtomicU64>);

impl Drop for TerminationGuard {
    fn drop(&mut self) {
        self.0.fetch_add(1, Ordering::SeqCst);
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
    flow: Arc<DeviceFlow>,
    activator: Arc<dyn DeviceTokenActivator>,
    pending: Arc<AsyncMutex<Option<PendingAuthorization>>>,
    single_flight: AsyncMutex<()>,
    task: AsyncMutex<Option<JoinHandle<()>>>,
    active_cancel: AsyncMutex<Option<CancelToken>>,
    diagnostics: Arc<Diagnostics>,
    stopping: AtomicBool,
    spawned: Arc<AtomicU64>,
    terminated: Arc<AtomicU64>,
}

impl LegacyDeviceFlowAdapter {
    /// Creates a Device Flow adapter.
    #[must_use]
    pub fn new(
        flow: DeviceFlow,
        activator: Arc<dyn DeviceTokenActivator>,
        diagnostics: Arc<Diagnostics>,
    ) -> Arc<Self> {
        Arc::new(Self {
            flow: Arc::new(flow),
            activator,
            pending: Arc::new(AsyncMutex::new(None)),
            single_flight: AsyncMutex::new(()),
            task: AsyncMutex::new(None),
            active_cancel: AsyncMutex::new(None),
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

    fn instructions_for(authorization: &PendingAuthorization) -> String {
        format!(
            "Please authorize GTA-Claw with your GitHub account:\n1. Open: {}\n2. Enter code: **{}**",
            authorization.authorization.verification_uri, authorization.authorization.user_code
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
            {
                let pending = self.pending.lock().await;
                if let Some(pending) = pending.as_ref()
                    && Instant::now() < pending.expires_at
                {
                    return Ok(Self::instructions_for(pending));
                }
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
                result = self.flow.start(&sdk_cancel) => {
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
            let pending = PendingAuthorization {
                expires_at: Instant::now()
                    .checked_add(Duration::from_secs(authorization.expires_in))
                    .unwrap_or_else(Instant::now),
                authorization,
            };
            let instructions = Self::instructions_for(&pending);
            *self.pending.lock().await = Some(pending.clone());
            self.spawned.fetch_add(1, Ordering::SeqCst);

            let flow = Arc::clone(&self.flow);
            let activator = Arc::clone(&self.activator);
            let pending_state = Arc::clone(&self.pending);
            let diagnostics = Arc::clone(&self.diagnostics);
            let terminated = Arc::clone(&self.terminated);
            let user_code = pending.authorization.user_code.clone();
            let task = tokio::spawn(async move {
                let _guard = TerminationGuard(terminated);
                match flow
                    .wait_for_token(&pending.authorization, &sdk_cancel)
                    .await
                {
                    Ok(token) => match activator.activate(token).await {
                        Ok(()) => diagnostics.record("GitHub Device Flow activated the provider"),
                        Err(error) => diagnostics.record(format!(
                            "GitHub Device Flow provider activation failed: {}",
                            error.message
                        )),
                    },
                    Err(error) => diagnostics.record(format!(
                        "GitHub Device Flow polling ended: {}",
                        error.kind().as_str()
                    )),
                }
                let mut current = pending_state.lock().await;
                if current
                    .as_ref()
                    .is_some_and(|pending| pending.authorization.user_code == user_code)
                {
                    *current = None;
                }
            });
            *self.task.lock().await = Some(task);
            Ok(instructions)
        })
    }
}

/// Teams activity adapter that normalizes inbound text through the shared runtime.
pub struct LegacyTeamsAdapter {
    messages: Arc<dyn LegacyChannelMessagePort>,
    transport: HttpTransport,
    app_id: String,
    app_password: SecretString,
    token: AsyncMutex<Option<CachedTeamsToken>>,
    replies: Mutex<VecDeque<String>>,
}

#[derive(Clone)]
struct CachedTeamsToken {
    token: SecretString,
    expires_at: Instant,
}

impl LegacyTeamsAdapter {
    /// Creates a Teams activity adapter.
    #[must_use]
    pub fn new(
        messages: Arc<dyn LegacyChannelMessagePort>,
        transport: HttpTransport,
        app_id: String,
        app_password: SecretString,
    ) -> Arc<Self> {
        Arc::new(Self {
            messages,
            transport,
            app_id,
            app_password,
            token: AsyncMutex::new(None),
            replies: Mutex::new(VecDeque::with_capacity(16)),
        })
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
        activity: Value,
        cancellation: CancellationToken,
    ) -> PortFuture<'_, Result<(), PortError>> {
        Box::pin(async move {
            let object = activity
                .as_object()
                .ok_or_else(|| invalid("Teams activity must be an object"))?;
            let kind = object
                .get("type")
                .and_then(Value::as_str)
                .unwrap_or_default();
            if !matches!(kind, "message" | "messageUpdate") {
                return Ok(());
            }
            let Some(text) = object
                .get("text")
                .and_then(Value::as_str)
                .map(str::trim)
                .filter(|text| !text.is_empty())
            else {
                return Ok(());
            };
            let conversation_id = object
                .get("conversation")
                .and_then(Value::as_object)
                .and_then(|conversation| conversation.get("id"))
                .and_then(Value::as_str)
                .filter(|id| !id.is_empty())
                .ok_or_else(|| invalid("Teams message has no conversation id"))?;
            let user_name = object
                .get("from")
                .and_then(Value::as_object)
                .and_then(|from| from.get("name"))
                .and_then(Value::as_str)
                .unwrap_or("Unknown");
            let service_url = object
                .get("serviceUrl")
                .and_then(Value::as_str)
                .map(str::to_owned);
            let reply = self
                .messages
                .process(
                    LegacyChannelMessage {
                        channel: "teams",
                        conversation_id: conversation_id.to_owned(),
                        user_name: user_name.to_owned(),
                        text: text.to_owned(),
                    },
                    cancellation.clone(),
                )
                .await?;
            if let Some(service_url) = service_url
                && !reply.trim().is_empty()
            {
                self.send_reply(&service_url, conversation_id, &reply, cancellation)
                    .await?;
            }
            let mut replies = self.replies.lock().map_err(|_| {
                PortError::new(PortErrorKind::Internal, "Teams reply state unavailable")
            })?;
            if replies.len() == 16 {
                replies.pop_front();
            }
            replies.push_back(reply);
            drop(replies);
            Ok(())
        })
    }
}

impl LegacyTeamsAdapter {
    async fn send_reply(
        &self,
        service_url: &str,
        conversation_id: &str,
        reply: &str,
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
        let segments = segment_outbound_text("msteams", reply)
            .map_err(|error| invalid(format!("Teams reply segmentation failed: {error}")))?;
        for segment in segments {
            let body = serde_json::to_string(&json!({
                "type": "message",
                "text": segment,
            }))
            .map_err(|_| PortError::new(PortErrorKind::Internal, "Teams encoding failed"))?;
            let request = HttpRequest::new(Method::Post, endpoint.clone())
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

/// Origin-bound `WhatsApp` Graph API sender.
pub struct GraphWhatsAppAdapter {
    transport: HttpTransport,
    endpoint: Url,
    credential: BoundSecret,
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
        access_token: SecretString,
    ) -> Result<Arc<Self>, PortError> {
        if phone_number_id.is_empty()
            || !phone_number_id
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-'))
        {
            return Err(invalid("WhatsApp phone number id is invalid"));
        }
        let endpoint = Url::parse(&format!(
            "https://graph.facebook.com/v20.0/{phone_number_id}/messages"
        ))
        .map_err(|_| invalid("WhatsApp Graph endpoint is invalid"))?;
        let origin =
            Origin::of(&endpoint).map_err(|error| invalid(format!("WhatsApp origin: {error}")))?;
        Ok(Arc::new(Self {
            transport,
            endpoint,
            credential: BoundSecret::new(origin, access_token),
        }))
    }
}

impl LegacyWhatsAppPort for GraphWhatsAppAdapter {
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
            let body = serde_json::to_string(&json!({
                "messaging_product": "whatsapp",
                "to": to,
                "type": "text",
                "text": {"body": text},
            }))
            .map_err(|_| PortError::new(PortErrorKind::Internal, "WhatsApp encoding failed"))?;
            let request = HttpRequest::new(Method::Post, self.endpoint.clone())
                .header("accept", "application/json")
                .bound_secret_header("authorization", "Bearer ", &self.credential)
                .map_err(|_| invalid("WhatsApp credential origin mismatch"))?
                .body(Body::Json(body))
                .timeout(WHATSAPP_SEND_TIMEOUT);
            let sdk_cancel = CancelToken::new();
            let response = tokio::select! {
                result = self.transport.send(
                    "whatsapp",
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
                    format!("WhatsApp Graph API returned HTTP {}", response.status()),
                ));
            }
            Ok(())
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

fn invalid(message: impl Into<String>) -> PortError {
    PortError::new(PortErrorKind::InvalidRequest, message)
}

#[cfg(test)]
mod tests {
    use std::time::{Duration, Instant};

    use claw_provider_sdk::SecretString;
    use claw_providers::github_copilot::DeviceAuthorization;

    use super::{
        LegacyDeviceFlowAdapter, LegacyTeamsAdapter, PendingAuthorization, three_floats,
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
    fn teams_adapter_starts_without_a_recorded_reply() {
        struct NoMessages;
        impl claw_http_api::LegacyChannelMessagePort for NoMessages {
            fn process(
                &self,
                _message: claw_http_api::LegacyChannelMessage,
                _cancellation: tokio_util::sync::CancellationToken,
            ) -> claw_http_api::PortFuture<'_, Result<String, claw_http_api::PortError>>
            {
                Box::pin(async { Ok("reply".to_owned()) })
            }
        }
        let adapter = LegacyTeamsAdapter::new(
            std::sync::Arc::new(NoMessages),
            claw_provider_sdk::http::HttpTransport::new().expect("transport"),
            "app".to_owned(),
            SecretString::new("password"),
        );
        assert_eq!(adapter.last_reply(), None);
    }

    #[test]
    fn device_instructions_are_reusable_and_contain_no_device_secret() {
        let pending = PendingAuthorization {
            authorization: DeviceAuthorization {
                device_code: SecretString::new("secret-device-code"),
                user_code: "ABCD-EFGH".to_owned(),
                verification_uri: "https://github.com/login/device".to_owned(),
                expires_in: 900,
                interval: 5,
            },
            expires_at: Instant::now() + Duration::from_mins(15),
        };

        let instructions = LegacyDeviceFlowAdapter::instructions_for(&pending);

        assert!(instructions.contains("ABCD-EFGH"));
        assert!(instructions.contains("https://github.com/login/device"));
        assert!(!instructions.contains("secret-device-code"));
    }
}

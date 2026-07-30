use std::error::Error;
use std::fmt::{self, Display, Formatter};
use std::sync::Arc;
use std::time::Duration;

use claw_gateway_client::{
    AuthorizationExpectation, ClientMetadata, ClientTimeouts, ConnectionState, GatewayClient,
    GatewayClientConfig, GatewayCredential, ReconnectPolicy,
};
use claw_observability::tracing;
use claw_protocol::gateway::{
    AUTHENTICATED_MAX_FRAME_BYTES, ClientId, ClientMode, Codec, GatewayMethodName, Name, RequestId,
    resolve_core_method,
};
use claw_security::authorization::{Role, Scope, ScopeSet};
use claw_security::identity::DeviceIdentity;
use rand_core::{TryCryptoRng, TryRng};
use ring::rand::{SecureRandom, SystemRandom};
use secrecy::SecretString;
use serde_json::{Value, json};
use tokio::sync::{mpsc, oneshot};
use tokio::task::JoinHandle;
use url::Url;

use crate::diagnostics::{bool_field, sanitize};
use crate::model::{Prompt, RunState, SessionSummary, ToolActivity, TranscriptEntry};

const MAX_SESSIONS: usize = 1_000;
const MAX_DIFF_LINES: usize = 10_000;
const MAX_ARTIFACTS: usize = 1_000;
const MAX_PREVIEW_LINES: usize = 2_000;
const MAX_EVENT_TEXT_BYTES: usize = 16 * 1024;
const MAX_LABEL_BYTES: usize = 1_024;
const WORKER_SHUTDOWN_GRACE: Duration = Duration::from_secs(1);

/// Scopes this client asks the Gateway to grant, in request order.
const REQUESTED_SCOPES: &str = "operator.read,operator.write,operator.approvals";

/// Runtime configuration for the Gateway worker.
#[derive(Clone)]
pub struct GatewayOptions {
    /// Gateway WebSocket endpoint.
    pub url: Url,
    /// Optional shared token.
    pub token: Option<String>,
}

/// Formats without the token. A derived `Debug` would put the shared secret into
/// any log line, panic message, or bug report that formats these options.
impl fmt::Debug for GatewayOptions {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("GatewayOptions")
            .field("url", &endpoint_label(&self.url))
            .field(
                "token",
                &if self.token.is_some() {
                    "<redacted>"
                } else {
                    "<none>"
                },
            )
            .finish()
    }
}

/// Renders an endpoint for humans without its userinfo, query, or fragment,
/// any of which can carry a credential.
#[must_use]
pub fn endpoint_label(url: &Url) -> String {
    let origin = url.origin();
    if origin.is_tuple() {
        origin.ascii_serialization()
    } else {
        url.scheme().to_owned()
    }
}

/// Commands sent from the render loop to background Gateway work.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum UiCommand {
    /// Reload session summaries.
    Refresh,
    /// Subscribe to and load one session.
    SelectSession(String),
    /// Load a session diff.
    LoadDiff(String),
    /// Load session artifacts.
    LoadArtifacts(String),
    /// Resolve an approval request.
    ResolveApproval {
        /// Approval identifier.
        id: String,
        /// Whether the request is approved.
        approved: bool,
    },
    /// Submit an answer to an agent question.
    Answer {
        /// Session identifier.
        session_id: String,
        /// Question identifier.
        question_id: String,
        /// User response.
        text: String,
    },
    /// Stop all Gateway work.
    Shutdown,
}

/// Data emitted by the background worker for synchronous model updates.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum WorkerEvent {
    /// Redaction-safe connection state.
    Connection(String),
    /// Complete session snapshot.
    Sessions(Vec<SessionSummary>),
    /// One streaming transcript item.
    Message(TranscriptEntry),
    /// One tool timeline item.
    Tool(ToolActivity),
    /// An approval or question.
    Prompt(Prompt),
    /// Unified diff lines.
    Diff(Vec<String>),
    /// Artifact labels.
    Artifacts(Vec<String>),
    /// Textual preview of the first artifact.
    ArtifactContent(Vec<String>),
    /// Non-fatal status or error text.
    Notice(String),
}

/// Starts Gateway work on the active Tokio runtime over bounded channels.
///
/// Whether the connection path is reported is decided by the process-wide
/// subscriber [`crate::diagnostics::install`] sets up, so this signature stays
/// free of a diagnostic channel and callers cannot route records anywhere else.
#[must_use]
pub fn spawn_gateway_worker(options: GatewayOptions) -> GatewayWorker {
    let (command_sender, command_receiver) = mpsc::channel(32);
    let (event_sender, event_receiver) = mpsc::channel(256);
    let (shutdown_sender, shutdown_receiver) = oneshot::channel();
    let endpoint = endpoint_label(&options.url);
    let task = tokio::spawn(async move {
        run_worker(
            options,
            command_receiver,
            event_sender,
            shutdown_receiver,
            endpoint,
        )
        .await;
    });
    GatewayWorker {
        commands: command_sender,
        events: event_receiver,
        shutdown: Some(shutdown_sender),
        task,
    }
}

/// Owned Gateway worker resources.
///
/// Keeping the task handle makes shutdown observable and prevents a failed
/// connection attempt from surviving after the terminal UI has exited.
pub struct GatewayWorker {
    /// Bounded command input.
    pub commands: mpsc::Sender<UiCommand>,
    /// Bounded event output.
    pub events: mpsc::Receiver<WorkerEvent>,
    shutdown: Option<oneshot::Sender<()>>,
    task: JoinHandle<()>,
}

/// How the background Gateway worker finished its shutdown.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum WorkerShutdown {
    /// Shutdown propagated through the client and the worker task joined.
    Cooperative,
    /// The worker exceeded its grace period and had to be aborted.
    ForcedAbort,
    /// The worker task panicked or was cancelled before the grace period ended.
    TaskFailed,
}

impl GatewayWorker {
    /// Cancels Gateway work and waits for a bounded graceful shutdown.
    pub async fn shutdown(mut self) -> WorkerShutdown {
        if let Some(shutdown) = self.shutdown.take() {
            let _ = shutdown.send(());
        }
        drop(self.commands);
        match tokio::time::timeout(WORKER_SHUTDOWN_GRACE, &mut self.task).await {
            Ok(Ok(())) => WorkerShutdown::Cooperative,
            Ok(Err(_)) => WorkerShutdown::TaskFailed,
            Err(_) => {
                self.task.abort();
                let _ = self.task.await;
                WorkerShutdown::ForcedAbort
            }
        }
    }
}

async fn run_worker(
    options: GatewayOptions,
    mut commands: mpsc::Receiver<UiCommand>,
    sender: mpsc::Sender<WorkerEvent>,
    mut shutdown: oneshot::Receiver<()>,
    endpoint: String,
) {
    tracing::debug!(
        action = "endpoint.resolve",
        outcome = "success",
        endpoint = sanitize(&endpoint),
        endpoint.scheme = options.url.scheme(),
        transport.tls = bool_field(options.url.scheme() == "wss"),
        // Only where the token came from is reportable; the token itself never
        // leaves `GatewayOptions`.
        auth.source = if options.token.is_some() {
            "environment"
        } else {
            "none"
        },
    );
    loop {
        if sender
            .send(WorkerEvent::Connection(
                "Gateway: connecting (bounded retries)".to_owned(),
            ))
            .await
            .is_err()
        {
            return;
        }
        match run_connection(
            options.clone(),
            &mut commands,
            &sender,
            &mut shutdown,
            &endpoint,
        )
        .await
        {
            Ok(ConnectionExit::Shutdown) => return,
            Ok(ConnectionExit::Disconnected) => {
                if !report_unavailable(&sender, &endpoint, "connection closed by the Gateway").await
                {
                    return;
                }
            }
            Err(error) => {
                if !report_unavailable(&sender, &endpoint, &error.to_string()).await {
                    return;
                }
            }
        }

        loop {
            tokio::select! {
                biased;
                _ = &mut shutdown => return,
                command = commands.recv() => {
                    match command {
                        Some(UiCommand::Refresh) => break,
                        Some(UiCommand::Shutdown) | None => return,
                        Some(_) => {
                            if sender.send(WorkerEvent::Notice(
                                "Gateway unavailable; press r to retry".to_owned()
                            )).await.is_err() {
                                return;
                            }
                        }
                    }
                }
            }
        }
    }
}

async fn report_unavailable(
    sender: &mpsc::Sender<WorkerEvent>,
    endpoint: &str,
    error: &str,
) -> bool {
    if sender
        .send(WorkerEvent::Connection(
            "Gateway: unavailable (press r to retry)".to_owned(),
        ))
        .await
        .is_err()
    {
        return false;
    }
    sender
        .send(WorkerEvent::Notice(format!(
            "Gateway: {} (tried {endpoint}; start the gateway or check --gateway, then press r)",
            bounded_text(error, MAX_LABEL_BYTES)
        )))
        .await
        .is_ok()
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ConnectionExit {
    Shutdown,
    Disconnected,
}

async fn run_connection(
    options: GatewayOptions,
    commands: &mut mpsc::Receiver<UiCommand>,
    sender: &mpsc::Sender<WorkerEvent>,
    shutdown: &mut oneshot::Receiver<()>,
    endpoint: &str,
) -> Result<ConnectionExit, WorkerError> {
    let identity = match generate_identity() {
        Ok(identity) => {
            // No part of the generated key material is reportable, so only the
            // mode is recorded.
            tracing::debug!(
                action = "identity.generate",
                outcome = "success",
                endpoint = sanitize(endpoint),
                identity.mode = "ephemeral",
            );
            Arc::new(identity)
        }
        Err(error) => {
            tracing::debug!(
                action = "identity.generate",
                outcome = "failure",
                endpoint = sanitize(endpoint),
                failure.reason = sanitize(&error.to_string()),
            );
            return Err(error);
        }
    };
    let mut config = GatewayClientConfig::new(options.url, identity);
    config.credential = options.token.map_or(GatewayCredential::None, |token| {
        GatewayCredential::Token(SecretString::from(token))
    });
    config.role = Role::Operator;
    config.scopes = ScopeSet::from_scopes([
        Scope::OperatorRead,
        Scope::OperatorWrite,
        Scope::OperatorApprovals,
    ]);
    config.authorization_expectation = AuthorizationExpectation::ExactRequested;
    config.client = ClientMetadata {
        id: ClientId::Tui,
        display_name: Some(Name::new("GTA Claw terminal", 64).expect("static client name")),
        version: Name::new(env!("CARGO_PKG_VERSION"), 64).expect("package version"),
        platform: Name::new(std::env::consts::OS, 64).expect("target OS"),
        device_family: None,
        model_identifier: None,
        mode: ClientMode::Ui,
        instance_id: None,
    };
    config.reconnect = ReconnectPolicy::Bounded {
        max_attempts: 2,
        initial_delay: Duration::from_millis(100),
        max_delay: Duration::from_millis(500),
        max_jitter: Duration::from_millis(50),
    };
    config.timeouts = ClientTimeouts {
        connect: Duration::from_secs(10),
        authentication: Duration::from_secs(10),
        request: Duration::from_secs(20),
        shutdown: Duration::from_secs(3),
    };

    let (client, mut gateway_events) = match GatewayClient::start(config) {
        Ok(started) => {
            tracing::debug!(
                action = "client.start",
                outcome = "success",
                endpoint = sanitize(endpoint),
                client.mode = "ui",
                scopes.requested = REQUESTED_SCOPES,
                expectation.mode = "exact_requested",
            );
            started
        }
        Err(error) => {
            let error = WorkerError(error.to_string());
            tracing::debug!(
                action = "client.start",
                outcome = "failure",
                endpoint = sanitize(endpoint),
                failure.reason = sanitize(&error.to_string()),
            );
            return Err(error);
        }
    };
    let ready_result = tokio::select! {
        biased;
        _ = &mut *shutdown => {
            let teardown = client
                .shutdown()
                .await
                .map_err(|error| WorkerError(error.to_string()));
            record_client_shutdown(endpoint, &teardown);
            return connection_exit_after_teardown(ConnectionExit::Shutdown, teardown);
        }
        ready = client.wait_ready() => ready,
    };
    let ready = match ready_result {
        Ok(ready) => ready,
        Err(error) => {
            let state = connection_label(&client.state());
            tracing::debug!(
                action = "connection.ready",
                outcome = "failure",
                endpoint = sanitize(endpoint),
                connection.state = state,
                failure.reason = sanitize(&error.to_string()),
            );
            let _ = client.shutdown().await;
            return Err(WorkerError(format!("{error} while {state}")));
        }
    };
    tracing::debug!(
        action = "connection.ready",
        outcome = "success",
        endpoint = sanitize(endpoint),
        protocol.negotiated = ready.info.protocol.get(),
    );
    tracing::debug!(
        action = "authorization.grant",
        outcome = "success",
        endpoint = sanitize(endpoint),
        role.granted = sanitize(&ready.info.role),
        scopes.granted = sanitize(&ready.info.scopes.join(",")),
        scopes.requested = REQUESTED_SCOPES,
        expectation.mode = "exact_requested",
    );
    tracing::trace!(
        action = "connection.epoch",
        outcome = "success",
        endpoint = sanitize(endpoint),
        connection.epoch = ready.epoch.get(),
        connection.max_payload_bytes = ready.info.max_payload_bytes,
    );
    if sender
        .send(WorkerEvent::Connection(format!(
            "Gateway: ready (protocol {}, epoch {})",
            ready.info.protocol.get(),
            ready.epoch.get()
        )))
        .await
        .is_err()
    {
        let _ = client.shutdown().await;
        return Err(WorkerError("render loop stopped".to_owned()));
    }

    let mut request_sequence = 1_u64;
    if let Err(error) = send_sessions(&client, sender, &mut request_sequence, endpoint).await {
        let _ = client.shutdown().await;
        return Err(error);
    }
    let outcome = loop {
        tokio::select! {
            biased;
            _ = &mut *shutdown => break ConnectionExit::Shutdown,
            command = commands.recv() => {
                let Some(command) = command else {
                    break ConnectionExit::Shutdown;
                };
                if matches!(command, UiCommand::Shutdown) {
                    break ConnectionExit::Shutdown;
                }
                if let Err(error) = handle_command(
                    &client,
                    sender,
                    &mut request_sequence,
                    command,
                    endpoint,
                ).await {
                    let _ = sender.send(WorkerEvent::Notice(error.to_string())).await;
                }
            }
            event = gateway_events.recv() => {
                let Some(event) = event else {
                    break ConnectionExit::Disconnected;
                };
                let frame = event.into_frame();
                if let Some(mapped) = map_gateway_event(&frame)
                    && sender.send(mapped).await.is_err()
                {
                    break ConnectionExit::Shutdown;
                }
            }
        }
    };
    let teardown = client
        .shutdown()
        .await
        .map_err(|error| WorkerError(error.to_string()));
    record_client_shutdown(endpoint, &teardown);
    connection_exit_after_teardown(outcome, teardown)
}

/// Reports one graceful client teardown without taking part in it.
///
/// The teardown result is borrowed, so which error wins stays a decision of
/// [`connection_exit_after_teardown`] alone.
fn record_client_shutdown(endpoint: &str, teardown: &Result<(), WorkerError>) {
    match teardown {
        Ok(()) => tracing::debug!(
            action = "client.shutdown",
            outcome = "success",
            endpoint = sanitize(endpoint),
        ),
        Err(error) => tracing::debug!(
            action = "client.shutdown",
            outcome = "failure",
            endpoint = sanitize(endpoint),
            failure.reason = sanitize(&error.to_string()),
        ),
    }
}

fn connection_exit_after_teardown(
    outcome: ConnectionExit,
    teardown: Result<(), WorkerError>,
) -> Result<ConnectionExit, WorkerError> {
    if outcome == ConnectionExit::Shutdown {
        return Ok(outcome);
    }
    teardown?;
    Ok(outcome)
}

async fn handle_command(
    client: &GatewayClient,
    sender: &mpsc::Sender<WorkerEvent>,
    sequence: &mut u64,
    command: UiCommand,
    endpoint: &str,
) -> Result<(), WorkerError> {
    match command {
        UiCommand::Refresh => send_sessions(client, sender, sequence, endpoint).await,
        UiCommand::SelectSession(session_id) => {
            let params = json!({"sessionId": session_id});
            let _ = request_json(client, sequence, "sessions.subscribe", &params, endpoint).await?;
            let _ = request_json(
                client,
                sequence,
                "sessions.messages.subscribe",
                &params,
                endpoint,
            )
            .await?;
            Ok(())
        }
        UiCommand::LoadDiff(session_id) => {
            let value = request_json(
                client,
                sequence,
                "sessions.diff",
                &json!({"sessionId": session_id}),
                endpoint,
            )
            .await?;
            let lines = value
                .get("diff")
                .and_then(Value::as_str)
                .unwrap_or_default()
                .lines()
                .take(MAX_DIFF_LINES)
                .map(|line| bounded_text(line, MAX_EVENT_TEXT_BYTES))
                .collect();
            sender
                .send(WorkerEvent::Diff(lines))
                .await
                .map_err(|_| WorkerError("render loop stopped".to_owned()))
        }
        UiCommand::LoadArtifacts(session_id) => {
            let value = request_json(
                client,
                sequence,
                "artifacts.list",
                &json!({"sessionId": session_id}),
                endpoint,
            )
            .await?;
            let entries = value
                .get("artifacts")
                .and_then(Value::as_array)
                .into_iter()
                .flatten()
                .take(MAX_ARTIFACTS)
                .filter_map(|item| {
                    let name = item
                        .get("name")
                        .or_else(|| item.get("path"))
                        .and_then(Value::as_str)
                        .map(|name| bounded_text(name, MAX_LABEL_BYTES))?;
                    let id = item
                        .get("id")
                        .or_else(|| item.get("artifactId"))
                        .or_else(|| item.get("path"))
                        .and_then(Value::as_str)
                        .map_or_else(|| name.clone(), |id| bounded_text(id, MAX_LABEL_BYTES));
                    Some((name, id))
                })
                .collect::<Vec<_>>();
            sender
                .send(WorkerEvent::Artifacts(
                    entries.iter().map(|(name, _)| name.clone()).collect(),
                ))
                .await
                .map_err(|_| WorkerError("render loop stopped".to_owned()))?;
            if let Some((_, artifact_id)) = entries.first() {
                let preview = request_json(
                    client,
                    sequence,
                    "artifacts.get",
                    &json!({"sessionId": session_id, "artifactId": artifact_id}),
                    endpoint,
                )
                .await?;
                sender
                    .send(WorkerEvent::ArtifactContent(artifact_preview(&preview)))
                    .await
                    .map_err(|_| WorkerError("render loop stopped".to_owned()))?;
            }
            Ok(())
        }
        UiCommand::ResolveApproval { id, approved } => {
            let _ = request_json(
                client,
                sequence,
                "approval.resolve",
                &json!({
                    "id": id,
                    "decision": if approved { "approve" } else { "deny" }
                }),
                endpoint,
            )
            .await?;
            sender
                .send(WorkerEvent::Notice(if approved {
                    "Approval accepted".to_owned()
                } else {
                    "Approval denied".to_owned()
                }))
                .await
                .map_err(|_| WorkerError("render loop stopped".to_owned()))
        }
        UiCommand::Answer {
            session_id,
            question_id,
            text,
        } => {
            let _ = request_json(
                client,
                sequence,
                "sessions.send",
                &json!({
                    "sessionId": session_id,
                    "questionId": question_id,
                    "message": text
                }),
                endpoint,
            )
            .await?;
            Ok(())
        }
        UiCommand::Shutdown => Ok(()),
    }
}

async fn send_sessions(
    client: &GatewayClient,
    sender: &mpsc::Sender<WorkerEvent>,
    sequence: &mut u64,
    endpoint: &str,
) -> Result<(), WorkerError> {
    let value = request_json(client, sequence, "sessions.list", &json!({}), endpoint).await?;
    sender
        .send(WorkerEvent::Sessions(parse_sessions(&value)))
        .await
        .map_err(|_| WorkerError("render loop stopped".to_owned()))
}

async fn request_json(
    client: &GatewayClient,
    sequence: &mut u64,
    method: &'static str,
    params: &Value,
    endpoint: &str,
) -> Result<Value, WorkerError> {
    let core = resolve_core_method(method)
        .ok_or_else(|| WorkerError(format!("frozen Gateway method missing: {method}")))?;
    let correlation = format!("gta-claw-tui-{}", *sequence);
    let request_id = RequestId::new(correlation.clone(), AUTHENTICATED_MAX_FRAME_BYTES)
        .map_err(|error| WorkerError(error.to_string()))?;
    *sequence = sequence.saturating_add(1);
    tracing::trace!(
        action = "rpc.request",
        outcome = "success",
        endpoint = sanitize(endpoint),
        rpc.method = method,
        rpc.request_id = correlation.as_str(),
    );
    let response = match client
        .request(request_id, GatewayMethodName::Core(core), params)
        .await
    {
        Ok(response) => response,
        Err(error) => {
            let error = WorkerError(error.to_string());
            tracing::debug!(
                action = "rpc.response",
                outcome = "failure",
                endpoint = sanitize(endpoint),
                rpc.method = method,
                failure.reason = sanitize(&error.to_string()),
            );
            return Err(error);
        }
    };
    if !response.ok() {
        let failure = response
            .error()
            .map_or("unknown", |error| error.code.as_str());
        tracing::debug!(
            action = "rpc.response",
            outcome = "failure",
            endpoint = sanitize(endpoint),
            rpc.method = method,
            rpc.error_code = sanitize(failure),
        );
        return Err(WorkerError(format!("{method} failed ({failure})")));
    }
    tracing::debug!(
        action = "rpc.response",
        outcome = "success",
        endpoint = sanitize(endpoint),
        rpc.method = method,
        rpc.ok = bool_field(true),
    );
    let Some(payload) = response.payload().value() else {
        return Ok(Value::Null);
    };
    Codec::authenticated()
        .decode_opaque::<Value>(payload)
        .map_err(|error| WorkerError(error.to_string()))
}

fn parse_sessions(value: &Value) -> Vec<SessionSummary> {
    let items = value
        .get("sessions")
        .or_else(|| value.get("items"))
        .and_then(Value::as_array)
        .or_else(|| value.as_array());
    items
        .into_iter()
        .flatten()
        .take(MAX_SESSIONS)
        .filter_map(|item| {
            let id = bounded_string_field(item, &["id", "sessionId", "key"], MAX_LABEL_BYTES)?;
            let title = bounded_string_field(item, &["title", "name", "label"], MAX_LABEL_BYTES)
                .unwrap_or_else(|| id.clone());
            let workspace =
                bounded_string_field(item, &["workspace", "cwd", "path"], MAX_LABEL_BYTES)
                    .unwrap_or_default();
            let state = bounded_string_field(item, &["state", "status"], 64)
                .map_or(RunState::Draft, |state| RunState::parse(&state));
            let progress = item
                .get("progress")
                .and_then(Value::as_u64)
                .and_then(|value| u8::try_from(value.min(100)).ok());
            Some(SessionSummary {
                id,
                title,
                workspace,
                state,
                progress,
            })
        })
        .collect()
}

fn map_gateway_event(frame: &claw_protocol::gateway::EventFrame) -> Option<WorkerEvent> {
    let event_name = frame.event().as_str().to_owned();
    if event_name == "sessions.changed" {
        return Some(WorkerEvent::Notice(
            "Sessions changed; press r to refresh".to_owned(),
        ));
    }
    let payload = frame
        .payload()
        .value()
        .and_then(|payload| Codec::authenticated().decode_opaque::<Value>(payload).ok())?;
    match event_name.as_str() {
        "session.message" | "chat" => {
            if payload.get("question").is_some() || payload.get("questionId").is_some() {
                Some(WorkerEvent::Prompt(Prompt::Question {
                    id: bounded_string_field(&payload, &["questionId", "id"], MAX_LABEL_BYTES)
                        .unwrap_or_default(),
                    text: bounded_string_field(
                        &payload,
                        &["question", "text", "message"],
                        MAX_EVENT_TEXT_BYTES,
                    )
                    .unwrap_or_else(|| "Agent is waiting for an answer".to_owned()),
                }))
            } else {
                Some(WorkerEvent::Message(TranscriptEntry {
                    role: bounded_string_field(&payload, &["role", "source"], 128)
                        .unwrap_or_else(|| "agent".to_owned()),
                    text: bounded_string_field(
                        &payload,
                        &["text", "message", "content"],
                        MAX_EVENT_TEXT_BYTES,
                    )
                    .unwrap_or_default(),
                }))
            }
        }
        "session.tool" | "session.operation" => Some(WorkerEvent::Tool(ToolActivity {
            name: bounded_string_field(&payload, &["tool", "name", "operation"], 128)
                .unwrap_or_else(|| "operation".to_owned()),
            status: bounded_string_field(&payload, &["status", "state"], 128)
                .unwrap_or_else(|| "running".to_owned()),
            summary: bounded_string_field(
                &payload,
                &["summary", "message", "description"],
                MAX_EVENT_TEXT_BYTES,
            )
            .unwrap_or_default(),
        })),
        "session.approval" | "exec.approval.requested" | "plugin.approval.requested" => {
            Some(WorkerEvent::Prompt(Prompt::Approval {
                id: bounded_string_field(&payload, &["approvalId", "id"], MAX_LABEL_BYTES)
                    .unwrap_or_default(),
                text: bounded_string_field(
                    &payload,
                    &["prompt", "command", "message"],
                    MAX_EVENT_TEXT_BYTES,
                )
                .unwrap_or_else(|| "Agent requests approval".to_owned()),
            }))
        }
        _ => None,
    }
}

fn string_field(value: &Value, names: &[&str]) -> Option<String> {
    names
        .iter()
        .find_map(|name| value.get(*name).and_then(Value::as_str))
        .map(ToOwned::to_owned)
}

fn bounded_string_field(value: &Value, names: &[&str], max_bytes: usize) -> Option<String> {
    names
        .iter()
        .find_map(|name| value.get(*name).and_then(Value::as_str))
        .map(|value| bounded_text(value, max_bytes))
}

fn bounded_text(value: &str, max_bytes: usize) -> String {
    if value.len() <= max_bytes {
        return value.to_owned();
    }
    let suffix = if max_bytes >= '…'.len_utf8() {
        "…"
    } else {
        ""
    };
    let mut end = max_bytes.saturating_sub(suffix.len()).min(value.len());
    while !value.is_char_boundary(end) {
        end = end.saturating_sub(1);
    }
    let mut bounded = value[..end].to_owned();
    bounded.push_str(suffix);
    bounded
}

fn artifact_preview(value: &Value) -> Vec<String> {
    let text = string_field(value, &["content", "text", "data"]).unwrap_or_else(|| {
        serde_json::to_string_pretty(value)
            .unwrap_or_else(|_| "Artifact preview unavailable".to_owned())
    });
    text.lines()
        .take(MAX_PREVIEW_LINES)
        .map(|line| bounded_text(line, MAX_EVENT_TEXT_BYTES))
        .collect()
}

fn generate_identity() -> Result<DeviceIdentity, WorkerError> {
    let random = SystemRandom::new();
    let mut rng = IdentityRandom(&random);
    DeviceIdentity::try_generate(&mut rng)
        .map_err(|_| WorkerError("secure randomness is unavailable".to_owned()))
}

struct IdentityRandom<'a>(&'a SystemRandom);

impl TryRng for IdentityRandom<'_> {
    type Error = RandomError;

    fn try_next_u32(&mut self) -> Result<u32, Self::Error> {
        let mut bytes = [0_u8; 4];
        self.try_fill_bytes(&mut bytes)?;
        Ok(u32::from_le_bytes(bytes))
    }

    fn try_next_u64(&mut self) -> Result<u64, Self::Error> {
        let mut bytes = [0_u8; 8];
        self.try_fill_bytes(&mut bytes)?;
        Ok(u64::from_le_bytes(bytes))
    }

    fn try_fill_bytes(&mut self, destination: &mut [u8]) -> Result<(), Self::Error> {
        self.0.fill(destination).map_err(|_| RandomError)
    }
}

impl TryCryptoRng for IdentityRandom<'_> {}

#[derive(Clone, Copy, Debug)]
struct RandomError;

impl Display for RandomError {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter.write_str("system random fill failed")
    }
}

impl Error for RandomError {}

#[derive(Debug)]
struct WorkerError(String);

impl Display for WorkerError {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.0)
    }
}

impl Error for WorkerError {}

/// Names a connection state for a user-facing notice.
const fn connection_label(state: &ConnectionState) -> &'static str {
    match state {
        ConnectionState::Starting => "starting",
        ConnectionState::Connecting => "connecting",
        ConnectionState::Authenticating => "authenticating",
        ConnectionState::Ready(_) => "ready",
        ConnectionState::Reconnecting { .. } => "reconnecting",
        ConnectionState::ResyncRequired(_) => "resync required",
        ConnectionState::AuthenticationFailed(_) => "authentication failed",
        ConnectionState::ProtocolFailed { .. } => "protocol failed",
        ConnectionState::ReconnectExhausted => "reconnect exhausted",
        ConnectionState::Stopped => "stopped",
    }
}

#[cfg(test)]
mod tests {
    use super::{ConnectionExit, WorkerError, connection_exit_after_teardown};

    #[test]
    fn shutdown_decision_wins_over_a_teardown_error() {
        let outcome = connection_exit_after_teardown(
            ConnectionExit::Shutdown,
            Err(WorkerError("simulated shutdown timeout".to_owned())),
        );

        assert!(matches!(outcome, Ok(ConnectionExit::Shutdown)));
    }
}

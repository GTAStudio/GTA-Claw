use std::error::Error;
use std::fmt::{self, Display, Formatter};
use std::sync::Arc;
use std::time::Duration;

use claw_gateway_client::{
    AuthorizationExpectation, ClientMetadata, ClientTimeouts, ConnectionState, GatewayClient,
    GatewayClientConfig, GatewayCredential, ReconnectPolicy,
};
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
use tokio::sync::mpsc;
use url::Url;

use crate::model::{Prompt, RunState, SessionSummary, ToolActivity, TranscriptEntry};

/// Runtime configuration for the Gateway worker.
#[derive(Clone, Debug)]
pub struct GatewayOptions {
    /// Gateway WebSocket endpoint.
    pub url: Url,
    /// Optional shared token.
    pub token: Option<String>,
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
#[must_use]
pub fn spawn_gateway_worker(
    options: GatewayOptions,
) -> (mpsc::Sender<UiCommand>, mpsc::Receiver<WorkerEvent>) {
    let (command_sender, command_receiver) = mpsc::channel(32);
    let (event_sender, event_receiver) = mpsc::channel(256);
    tokio::spawn(async move {
        if let Err(error) = run_worker(options, command_receiver, event_sender.clone()).await {
            let _ = event_sender
                .send(WorkerEvent::Notice(format!("Gateway: {error}")))
                .await;
        }
    });
    (command_sender, event_receiver)
}

async fn run_worker(
    options: GatewayOptions,
    mut commands: mpsc::Receiver<UiCommand>,
    sender: mpsc::Sender<WorkerEvent>,
) -> Result<(), WorkerError> {
    let identity = Arc::new(generate_identity()?);
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
    config.reconnect = ReconnectPolicy::default();
    config.timeouts = ClientTimeouts {
        connect: Duration::from_secs(10),
        authentication: Duration::from_secs(10),
        request: Duration::from_secs(20),
        shutdown: Duration::from_secs(3),
    };

    let (client, mut gateway_events) =
        GatewayClient::start(config).map_err(|error| WorkerError(error.to_string()))?;
    let ready = client
        .wait_ready()
        .await
        .map_err(|error| WorkerError(error.to_string()))?;
    sender
        .send(WorkerEvent::Connection(format!(
            "Gateway: ready (protocol {}, epoch {})",
            ready.info.protocol.get(),
            ready.epoch.get()
        )))
        .await
        .map_err(|_| WorkerError("render loop stopped".to_owned()))?;

    let mut request_sequence = 1_u64;
    send_sessions(&client, &sender, &mut request_sequence).await?;
    loop {
        tokio::select! {
            command = commands.recv() => {
                let Some(command) = command else {
                    break;
                };
                if matches!(command, UiCommand::Shutdown) {
                    break;
                }
                if let Err(error) = handle_command(
                    &client,
                    &sender,
                    &mut request_sequence,
                    command,
                ).await {
                    let _ = sender.send(WorkerEvent::Notice(error.to_string())).await;
                }
            }
            event = gateway_events.recv() => {
                let Some(event) = event else {
                    break;
                };
                if let Some(mapped) = map_gateway_event(event.into_frame())
                    && sender.send(mapped).await.is_err()
                {
                    break;
                }
            }
        }
    }
    client
        .shutdown()
        .await
        .map_err(|error| WorkerError(error.to_string()))
}

async fn handle_command(
    client: &GatewayClient,
    sender: &mpsc::Sender<WorkerEvent>,
    sequence: &mut u64,
    command: UiCommand,
) -> Result<(), WorkerError> {
    match command {
        UiCommand::Refresh => send_sessions(client, sender, sequence).await,
        UiCommand::SelectSession(session_id) => {
            let params = json!({"sessionId": session_id});
            let _ = request_json(client, sequence, "sessions.subscribe", &params).await?;
            let _ = request_json(client, sequence, "sessions.messages.subscribe", &params).await?;
            Ok(())
        }
        UiCommand::LoadDiff(session_id) => {
            let value = request_json(
                client,
                sequence,
                "sessions.diff",
                &json!({"sessionId": session_id}),
            )
            .await?;
            let lines = value
                .get("diff")
                .and_then(Value::as_str)
                .unwrap_or_default()
                .lines()
                .map(ToOwned::to_owned)
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
            )
            .await?;
            let entries = value
                .get("artifacts")
                .and_then(Value::as_array)
                .into_iter()
                .flatten()
                .filter_map(|item| {
                    let name = item
                        .get("name")
                        .or_else(|| item.get("path"))
                        .and_then(Value::as_str)
                        .map(ToOwned::to_owned)?;
                    let id = item
                        .get("id")
                        .or_else(|| item.get("artifactId"))
                        .or_else(|| item.get("path"))
                        .and_then(Value::as_str)
                        .unwrap_or(&name)
                        .to_owned();
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
) -> Result<(), WorkerError> {
    let value = request_json(client, sequence, "sessions.list", &json!({})).await?;
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
) -> Result<Value, WorkerError> {
    let core = resolve_core_method(method)
        .ok_or_else(|| WorkerError(format!("frozen Gateway method missing: {method}")))?;
    let request_id = RequestId::new(
        format!("gta-claw-tui-{}", *sequence),
        AUTHENTICATED_MAX_FRAME_BYTES,
    )
    .map_err(|error| WorkerError(error.to_string()))?;
    *sequence = sequence.saturating_add(1);
    let response = client
        .request(request_id, GatewayMethodName::Core(core), params)
        .await
        .map_err(|error| WorkerError(error.to_string()))?;
    if !response.ok() {
        let code = response
            .error()
            .map_or("unknown", |error| error.code.as_str());
        return Err(WorkerError(format!("{method} failed ({code})")));
    }
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
        .filter_map(|item| {
            let id = string_field(item, &["id", "sessionId", "key"])?;
            let title =
                string_field(item, &["title", "name", "label"]).unwrap_or_else(|| id.clone());
            let workspace = string_field(item, &["workspace", "cwd", "path"]).unwrap_or_default();
            let state = string_field(item, &["state", "status"])
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

fn map_gateway_event(frame: claw_protocol::gateway::EventFrame) -> Option<WorkerEvent> {
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
                    id: string_field(&payload, &["questionId", "id"]).unwrap_or_default(),
                    text: string_field(&payload, &["question", "text", "message"])
                        .unwrap_or_else(|| "Agent is waiting for an answer".to_owned()),
                }))
            } else {
                Some(WorkerEvent::Message(TranscriptEntry {
                    role: string_field(&payload, &["role", "source"])
                        .unwrap_or_else(|| "agent".to_owned()),
                    text: string_field(&payload, &["text", "message", "content"])
                        .unwrap_or_default(),
                }))
            }
        }
        "session.tool" | "session.operation" => Some(WorkerEvent::Tool(ToolActivity {
            name: string_field(&payload, &["tool", "name", "operation"])
                .unwrap_or_else(|| "operation".to_owned()),
            status: string_field(&payload, &["status", "state"])
                .unwrap_or_else(|| "running".to_owned()),
            summary: string_field(&payload, &["summary", "message", "description"])
                .unwrap_or_default(),
        })),
        "session.approval" | "exec.approval.requested" | "plugin.approval.requested" => {
            Some(WorkerEvent::Prompt(Prompt::Approval {
                id: string_field(&payload, &["approvalId", "id"]).unwrap_or_default(),
                text: string_field(&payload, &["prompt", "command", "message"])
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

fn artifact_preview(value: &Value) -> Vec<String> {
    const MAX_PREVIEW_LINES: usize = 2_000;
    let text = string_field(value, &["content", "text", "data"]).unwrap_or_else(|| {
        serde_json::to_string_pretty(value)
            .unwrap_or_else(|_| "Artifact preview unavailable".to_owned())
    });
    text.lines()
        .take(MAX_PREVIEW_LINES)
        .map(ToOwned::to_owned)
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

#[allow(dead_code)]
fn connection_label(state: &ConnectionState) -> &'static str {
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

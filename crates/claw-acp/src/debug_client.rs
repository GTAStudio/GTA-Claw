//! Subprocess ACP debug client.

use std::{
    collections::BTreeMap,
    fmt,
    future::Future,
    path::PathBuf,
    pin::Pin,
    process::Stdio,
    sync::{Arc, Mutex},
    time::Duration,
};

#[cfg(windows)]
use process_wrap::tokio::JobObject;
#[cfg(unix)]
use process_wrap::tokio::ProcessGroup;
use process_wrap::tokio::{ChildWrapper, CommandWrap, KillOnDrop};
use tokio::time::{sleep, timeout};
use tokio::{io::BufReader, process::Command};

use crate::{
    Error,
    error::{AcpInteropError, Result},
    protocol::{RpcPeer, decode, is_response_message, message_parts, read_message, response_id},
    schema,
    schema::{
        CancelNotification, CloseSessionRequest, CloseSessionResponse, ContentBlock,
        InitializeRequest, InitializeResponse, ListSessionsRequest, ListSessionsResponse,
        LoadSessionRequest, LoadSessionResponse, McpServer, NewSessionRequest, NewSessionResponse,
        PromptRequest, PromptResponse, ProtocolVersion, RequestPermissionOutcome,
        RequestPermissionRequest, RequestPermissionResponse, ResumeSessionRequest,
        ResumeSessionResponse, SessionConfigId, SessionConfigValueId, SessionId, SessionModeId,
        SessionNotification, SetSessionConfigOptionRequest, SetSessionConfigOptionResponse,
        SetSessionModeRequest, SetSessionModeResponse,
    },
};

const PROCESS_CLEANUP_TIMEOUT: Duration = Duration::from_secs(2);

/// Future returned by an ACP permission policy.
pub type PermissionFuture<'a> = Pin<
    Box<dyn Future<Output = std::result::Result<RequestPermissionResponse, Error>> + Send + 'a>,
>;

/// Policy for permission requests made by an ACP agent.
pub trait PermissionPolicy: Send + Sync + 'static {
    /// Selects a permission outcome.
    fn decide<'a>(&'a self, request: RequestPermissionRequest) -> PermissionFuture<'a>;
}

/// Permission policy that cancels every request.
#[derive(Debug, Default)]
pub struct DenyPermissions;

impl PermissionPolicy for DenyPermissions {
    fn decide<'a>(&'a self, _request: RequestPermissionRequest) -> PermissionFuture<'a> {
        Box::pin(async {
            Ok(RequestPermissionResponse::new(
                RequestPermissionOutcome::Cancelled,
            ))
        })
    }
}

/// Child-process configuration for the ACP debug client.
#[derive(Clone)]
pub struct DebugClientConfig {
    /// Agent executable.
    pub command: PathBuf,
    /// Agent arguments.
    pub arguments: Vec<String>,
    /// Agent environment additions.
    pub environment: BTreeMap<String, String>,
    /// Deadline for the complete scripted interaction.
    pub timeout: Duration,
}

impl fmt::Debug for DebugClientConfig {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("DebugClientConfig")
            .field("command", &self.command)
            .field("arguments", &self.arguments)
            .field("environment", &self.environment.keys().collect::<Vec<_>>())
            .field("timeout", &self.timeout)
            .finish()
    }
}

impl DebugClientConfig {
    /// Creates a debug client configuration.
    #[must_use]
    pub fn new(command: impl Into<PathBuf>) -> Self {
        Self {
            command: command.into(),
            arguments: Vec::new(),
            environment: BTreeMap::new(),
            timeout: Duration::from_secs(60),
        }
    }
}

#[derive(Debug)]
struct ProcessTreeAcpAgent {
    command: PathBuf,
    arguments: Vec<String>,
    environment: BTreeMap<String, String>,
    current_dir: PathBuf,
}

#[derive(Debug)]
struct ProcessTreeGuard(Box<dyn ChildWrapper>);

struct SpawnedAgent {
    child: ProcessTreeGuard,
    peer: RpcPeer,
    reader: tokio::task::JoinHandle<std::result::Result<(), Error>>,
    stderr_drain: tokio::task::JoinHandle<std::io::Result<()>>,
}

impl std::ops::Deref for ProcessTreeGuard {
    type Target = dyn ChildWrapper;

    fn deref(&self) -> &Self::Target {
        self.0.as_ref()
    }
}

impl std::ops::DerefMut for ProcessTreeGuard {
    fn deref_mut(&mut self) -> &mut Self::Target {
        self.0.as_mut()
    }
}

impl Drop for ProcessTreeGuard {
    fn drop(&mut self) {
        let _ = self.0.start_kill();
        for _ in 0..100 {
            match self.0.try_wait() {
                Ok(Some(_)) | Err(_) => return,
                Ok(None) => std::thread::sleep(Duration::from_millis(1)),
            }
        }
    }
}

impl ProcessTreeAcpAgent {
    fn spawn(
        self,
        notifications: Arc<Mutex<Vec<SessionNotification>>>,
        permissions: Arc<dyn PermissionPolicy>,
    ) -> std::result::Result<SpawnedAgent, Error> {
        let mut command = Command::new(&self.command);
        command
            .args(&self.arguments)
            .envs(&self.environment)
            .current_dir(&self.current_dir)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        let mut command = CommandWrap::from(command);
        command.wrap(KillOnDrop);
        #[cfg(windows)]
        command.wrap(JobObject);
        #[cfg(unix)]
        command.wrap(ProcessGroup::leader());
        let mut child = ProcessTreeGuard(command.spawn().map_err(acp_internal_error)?);
        let stdin = child
            .stdin()
            .take()
            .ok_or_else(|| acp_internal_error("ACP child stdin was not piped"))?;
        let stdout = child
            .stdout()
            .take()
            .ok_or_else(|| acp_internal_error("ACP child stdout was not piped"))?;
        let mut stderr = child
            .stderr()
            .take()
            .ok_or_else(|| acp_internal_error("ACP child stderr was not piped"))?;

        let stderr_drain = tokio::spawn(async move {
            tokio::io::copy(&mut stderr, &mut tokio::io::sink())
                .await
                .map(|_| ())
        });
        let peer = RpcPeer::new(stdin);
        let reader_peer = peer.clone();
        let reader = tokio::spawn(async move {
            read_client_messages(
                BufReader::new(stdout),
                reader_peer,
                notifications,
                permissions,
            )
            .await
        });
        Ok(SpawnedAgent {
            child,
            peer,
            reader,
            stderr_drain,
        })
    }
}

async fn read_client_messages(
    mut reader: BufReader<tokio::process::ChildStdout>,
    peer: RpcPeer,
    notifications: Arc<Mutex<Vec<SessionNotification>>>,
    permissions: Arc<dyn PermissionPolicy>,
) -> std::result::Result<(), Error> {
    let result = async {
        let mut frame = Vec::new();
        loop {
            let incoming = tokio::select! {
                biased;
                () = peer.disconnected() => break,
                message = read_message(&mut reader, &mut frame) => message,
            };
            if !peer.is_connected() {
                break;
            }
            let message = match incoming {
                Ok(Some(message)) => message,
                Ok(None) => break,
                Err(error) => {
                    let _ = peer
                        .respond::<serde_json::Value>(serde_json::Value::Null, Err(error.clone()))
                        .await;
                    return Err(error);
                }
            };
            if message.get("method").is_none() {
                if is_response_message(&message) {
                    let _ = peer.resolve_response(&message);
                } else {
                    peer.respond::<serde_json::Value>(
                        response_id(&message),
                        Err(Error::invalid_request()),
                    )
                    .await?;
                }
                continue;
            }
            let (method, params, id) = match message_parts(&message) {
                Ok(parts) => parts,
                Err(error) => {
                    peer.respond::<serde_json::Value>(response_id(&message), Err(error))
                        .await?;
                    continue;
                }
            };
            match (method, id) {
                ("session/update", None) => {
                    notifications
                        .lock()
                        .map_err(|_| {
                            Error::internal_error().data("debug notification lock poisoned")
                        })?
                        .push(decode(params)?);
                }
                ("session/request_permission", Some(id)) => {
                    let result = decode(params).map(|request| permissions.decide(request));
                    match result {
                        Ok(future) => peer.respond(id, future.await).await?,
                        Err(error) => {
                            peer.respond::<RequestPermissionResponse>(id, Err(error))
                                .await?;
                        }
                    }
                }
                (_, Some(id)) => {
                    peer.respond::<serde_json::Value>(id, Err(Error::method_not_found()))
                        .await?;
                }
                _ => {}
            }
        }
        Ok(())
    }
    .await;
    peer.mark_disconnected();
    result
}

fn acp_internal_error(error: impl fmt::Display) -> Error {
    Error::internal_error().data(error.to_string())
}

/// Script executed by the ACP debug client.
#[derive(Clone, Debug)]
pub struct DebugRunRequest {
    /// Working directory for the session.
    pub cwd: PathBuf,
    /// Prompt content.
    pub prompt: Vec<ContentBlock>,
    /// Existing session to load instead of creating a new session.
    pub load_session: Option<SessionId>,
    /// Existing session to resume without replaying history.
    pub resume_session: Option<SessionId>,
    /// Optional session mode to select before prompting.
    pub mode: Option<SessionModeId>,
    /// Session configuration values selected before prompting.
    pub config_options: Vec<(SessionConfigId, SessionConfigValueId)>,
    /// Optional delay before sending a cancellation notification.
    pub cancel_after: Option<Duration>,
    /// Optional MCP servers forwarded into session setup.
    pub mcp_servers: Vec<McpServer>,
    /// Whether to close the session after the turn.
    pub close_session: bool,
}

impl DebugRunRequest {
    /// Creates a debug run for a new session.
    #[must_use]
    pub fn new(cwd: impl Into<PathBuf>, prompt: Vec<ContentBlock>) -> Self {
        Self {
            cwd: cwd.into(),
            prompt,
            load_session: None,
            resume_session: None,
            mode: None,
            config_options: Vec::new(),
            cancel_after: None,
            mcp_servers: Vec::new(),
            close_session: true,
        }
    }
}

/// Result of one complete ACP debug interaction.
#[derive(Clone, Debug)]
pub struct DebugRunResult {
    /// Initialize response.
    pub initialize: InitializeResponse,
    /// Session exercised by the client.
    pub session_id: SessionId,
    /// Session list observed after setup when the agent advertises listing.
    pub sessions: Option<ListSessionsResponse>,
    /// Optional mode-change response.
    pub mode: Option<SetSessionModeResponse>,
    /// Configuration-change responses in request order.
    pub config_options: Vec<SetSessionConfigOptionResponse>,
    /// Prompt completion response.
    pub prompt: PromptResponse,
    /// Optional close response.
    pub close: Option<CloseSessionResponse>,
    /// Streamed session notifications in arrival order.
    pub notifications: Vec<SessionNotification>,
}

/// Rust-only ACP subprocess client for diagnostics and compatibility tests.
pub struct DebugClient {
    config: DebugClientConfig,
    permissions: Arc<dyn PermissionPolicy>,
}

impl fmt::Debug for DebugClient {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("DebugClient")
            .field("config", &self.config)
            .finish_non_exhaustive()
    }
}

impl DebugClient {
    /// Creates a debug client with an explicit permission policy.
    #[must_use]
    pub fn new(config: DebugClientConfig, permissions: Arc<dyn PermissionPolicy>) -> Self {
        Self {
            config,
            permissions,
        }
    }

    /// Executes initialize, setup, list, optional mode, prompt, and close operations.
    pub async fn run(&self, request: DebugRunRequest) -> Result<DebugRunResult> {
        let agent = ProcessTreeAcpAgent {
            command: self.config.command.clone(),
            arguments: self.config.arguments.clone(),
            environment: self.config.environment.clone(),
            current_dir: request.cwd.clone(),
        };
        let notifications = Arc::new(Mutex::new(Vec::new()));
        let timeout_duration = self.config.timeout;
        let SpawnedAgent {
            mut child,
            peer: connection,
            reader,
            stderr_drain,
        } = agent.spawn(Arc::clone(&notifications), Arc::clone(&self.permissions))?;
        let interaction = async move {
            let initialize: InitializeResponse = connection
                .request(
                    "initialize",
                    InitializeRequest::new(ProtocolVersion::V1).client_info(
                        schema::Implementation::new(
                            "gta-claw-acp-debug",
                            env!("CARGO_PKG_VERSION"),
                        ),
                    ),
                )
                .await?;
            if initialize.protocol_version != ProtocolVersion::V1 {
                return Err(Error::invalid_request()
                    .data("ACP agent selected an unsupported protocol version"));
            }

            let session_id = match (request.load_session, request.resume_session) {
                (Some(_), Some(_)) => {
                    return Err(Error::invalid_request()
                        .data("load_session and resume_session are mutually exclusive"));
                }
                (Some(session_id), None) => {
                    let _: LoadSessionResponse = connection
                        .request(
                            "session/load",
                            LoadSessionRequest::new(session_id.clone(), request.cwd.clone())
                                .mcp_servers(request.mcp_servers.clone()),
                        )
                        .await?;
                    session_id
                }
                (None, Some(session_id)) => {
                    let _: ResumeSessionResponse = connection
                        .request(
                            "session/resume",
                            ResumeSessionRequest::new(session_id.clone(), request.cwd.clone())
                                .mcp_servers(request.mcp_servers.clone()),
                        )
                        .await?;
                    session_id
                }
                (None, None) => {
                    let response: NewSessionResponse = connection
                        .request(
                            "session/new",
                            NewSessionRequest::new(request.cwd.clone())
                                .mcp_servers(request.mcp_servers.clone()),
                        )
                        .await?;
                    response.session_id
                }
            };

            let sessions = if initialize
                .agent_capabilities
                .session_capabilities
                .list
                .is_some()
            {
                Some(
                    connection
                        .request("session/list", ListSessionsRequest::new())
                        .await?,
                )
            } else {
                None
            };
            let mode = if let Some(mode) = request.mode {
                Some(
                    connection
                        .request(
                            "session/set_mode",
                            SetSessionModeRequest::new(session_id.clone(), mode),
                        )
                        .await?,
                )
            } else {
                None
            };
            let mut config_options = Vec::with_capacity(request.config_options.len());
            for (config_id, value) in request.config_options {
                config_options.push(
                    connection
                        .request(
                            "session/set_config_option",
                            SetSessionConfigOptionRequest::new(
                                session_id.clone(),
                                config_id,
                                value,
                            ),
                        )
                        .await?,
                );
            }

            let prompt_request = connection.request(
                "session/prompt",
                PromptRequest::new(session_id.clone(), request.prompt),
            );
            tokio::pin!(prompt_request);
            let prompt: PromptResponse = if let Some(delay) = request.cancel_after {
                tokio::select! {
                    result = &mut prompt_request => result?,
                    () = sleep(delay) => {
                        connection
                            .notify(
                                "session/cancel",
                                CancelNotification::new(session_id.clone()),
                            )
                            .await?;
                        prompt_request.await?
                    }
                }
            } else {
                prompt_request.await?
            };

            let close = if request.close_session
                && initialize
                    .agent_capabilities
                    .session_capabilities
                    .close
                    .is_some()
            {
                Some(
                    connection
                        .request(
                            "session/close",
                            CloseSessionRequest::new(session_id.clone()),
                        )
                        .await?,
                )
            } else {
                None
            };

            Ok((
                initialize,
                session_id,
                sessions,
                mode,
                config_options,
                prompt,
                close,
            ))
        };

        let outcome = timeout(timeout_duration, interaction)
            .await
            .map_err(|_| AcpInteropError::Timeout(timeout_duration))
            .and_then(|result| result.map_err(AcpInteropError::from));
        let cleanup = timeout(PROCESS_CLEANUP_TIMEOUT, Box::into_pin(child.kill())).await;
        reader.abort();
        let _ = reader.await;
        stderr_drain.abort();
        let _ = stderr_drain.await;
        let (initialize, session_id, sessions, mode, config_options, prompt, close) = outcome?;
        cleanup.map_err(|_| {
            AcpInteropError::Lifecycle("ACP process cleanup exceeded its deadline".into())
        })??;
        let notifications = notifications
            .lock()
            .map_err(|_| AcpInteropError::Lifecycle("debug notification lock poisoned".into()))?
            .clone();

        Ok(DebugRunResult {
            initialize,
            session_id,
            sessions,
            mode,
            config_options,
            prompt,
            close,
            notifications,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn debug_config_redacts_environment_values() {
        let mut config = DebugClientConfig::new("fixture-agent");
        config
            .environment
            .insert("ACCESS_TOKEN".into(), "test-token-value".into());

        let output = format!("{config:?}");

        assert!(!output.contains("test-token-value"));
        assert!(output.contains("ACCESS_TOKEN"));
    }
}

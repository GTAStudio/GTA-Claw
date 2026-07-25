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

use agent_client_protocol::{
    Agent, Client, ConnectTo, ConnectionTo, Lines,
    schema::{
        CancelNotification, CloseSessionRequest, CloseSessionResponse, ContentBlock,
        InitializeRequest, InitializeResponse, ListSessionsRequest, ListSessionsResponse,
        LoadSessionRequest, McpServer, NewSessionRequest, PromptRequest, PromptResponse,
        ProtocolVersion, RequestPermissionOutcome, RequestPermissionRequest,
        RequestPermissionResponse, ResumeSessionRequest, SessionConfigId, SessionConfigValueId,
        SessionId, SessionModeId, SessionNotification, SetSessionConfigOptionRequest,
        SetSessionConfigOptionResponse, SetSessionModeRequest, SetSessionModeResponse,
    },
};
#[cfg(windows)]
use process_wrap::tokio::JobObject;
#[cfg(unix)]
use process_wrap::tokio::ProcessGroup;
use process_wrap::tokio::{ChildWrapper, CommandWrap, KillOnDrop};
use tokio::time::{sleep, timeout};
use tokio::{
    io::{AsyncBufReadExt, AsyncWriteExt, BufReader},
    process::Command,
};

use crate::{
    error::{AcpInteropError, Result},
    schema,
};

/// Future returned by an ACP permission policy.
pub type PermissionFuture<'a> = Pin<
    Box<
        dyn Future<
                Output = std::result::Result<
                    RequestPermissionResponse,
                    agent_client_protocol::Error,
                >,
            > + Send
            + 'a,
    >,
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

impl ConnectTo<Client> for ProcessTreeAcpAgent {
    async fn connect_to(
        self,
        client: impl ConnectTo<Agent>,
    ) -> std::result::Result<(), agent_client_protocol::Error> {
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
        let incoming =
            futures_util::stream::unfold(BufReader::new(stdout).lines(), |mut lines| async move {
                match lines.next_line().await {
                    Ok(Some(line)) => Some((Ok(line), lines)),
                    Ok(None) => None,
                    Err(error) => Some((Err(error), lines)),
                }
            });
        let outgoing = futures_util::sink::unfold(stdin, |mut stdin, line: String| async move {
            stdin.write_all(line.as_bytes()).await?;
            stdin.write_all(b"\n").await?;
            stdin.flush().await?;
            Ok::<_, std::io::Error>(stdin)
        });
        let protocol = ConnectTo::<Client>::connect_to(Lines::new(outgoing, incoming), client);
        tokio::pin!(protocol);

        let outcome = tokio::select! {
            result = &mut protocol => result,
            status = child.wait() => match status {
                Ok(status) if status.success() => Ok(()),
                Ok(status) => Err(acp_internal_error(format!(
                    "ACP child exited with status {status}"
                ))),
                Err(error) => Err(acp_internal_error(error)),
            },
        };
        let cleanup = Box::into_pin(child.kill()).await;
        let drain = stderr_drain
            .await
            .map_err(acp_internal_error)
            .and_then(|result| result.map_err(acp_internal_error));

        match outcome {
            Err(error) => Err(error),
            Ok(()) => {
                cleanup.map_err(acp_internal_error)?;
                drain?;
                Ok(())
            }
        }
    }
}

fn acp_internal_error(error: impl fmt::Display) -> agent_client_protocol::Error {
    agent_client_protocol::Error::internal_error().data(error.to_string())
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
        let notification_sink = notifications.clone();
        let permissions = self.permissions.clone();
        let timeout_duration = self.config.timeout;

        let interaction = Client
            .builder()
            .name("gta-claw-acp-debug")
            .on_receive_notification(
                async move |notification: SessionNotification, _connection| {
                    notification_sink
                        .lock()
                        .map_err(|_| {
                            agent_client_protocol::Error::internal_error()
                                .data("debug notification lock poisoned")
                        })?
                        .push(notification);
                    Ok(())
                },
                agent_client_protocol::on_receive_notification!(),
            )
            .on_receive_request(
                async move |request: RequestPermissionRequest, responder, _connection| {
                    responder.respond_with_result(permissions.decide(request).await)
                },
                agent_client_protocol::on_receive_request!(),
            )
            .connect_with(agent, move |connection: ConnectionTo<Agent>| async move {
                let initialize = connection
                    .send_request(InitializeRequest::new(ProtocolVersion::V1).client_info(
                        schema::Implementation::new(
                            "gta-claw-acp-debug",
                            env!("CARGO_PKG_VERSION"),
                        ),
                    ))
                    .block_task()
                    .await?;
                if initialize.protocol_version != ProtocolVersion::V1 {
                    return Err(agent_client_protocol::Error::invalid_request()
                        .data("ACP agent selected an unsupported protocol version"));
                }

                let session_id = match (request.load_session, request.resume_session) {
                    (Some(_), Some(_)) => {
                        return Err(agent_client_protocol::Error::invalid_request()
                            .data("load_session and resume_session are mutually exclusive"));
                    }
                    (Some(session_id), None) => {
                        connection
                            .send_request(
                                LoadSessionRequest::new(session_id.clone(), request.cwd.clone())
                                    .mcp_servers(request.mcp_servers.clone()),
                            )
                            .block_task()
                            .await?;
                        session_id
                    }
                    (None, Some(session_id)) => {
                        connection
                            .send_request(
                                ResumeSessionRequest::new(session_id.clone(), request.cwd.clone())
                                    .mcp_servers(request.mcp_servers.clone()),
                            )
                            .block_task()
                            .await?;
                        session_id
                    }
                    (None, None) => {
                        connection
                            .send_request(
                                NewSessionRequest::new(request.cwd.clone())
                                    .mcp_servers(request.mcp_servers.clone()),
                            )
                            .block_task()
                            .await?
                            .session_id
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
                            .send_request(ListSessionsRequest::new())
                            .block_task()
                            .await?,
                    )
                } else {
                    None
                };
                let mode = if let Some(mode) = request.mode {
                    Some(
                        connection
                            .send_request(SetSessionModeRequest::new(session_id.clone(), mode))
                            .block_task()
                            .await?,
                    )
                } else {
                    None
                };
                let mut config_options = Vec::with_capacity(request.config_options.len());
                for (config_id, value) in request.config_options {
                    config_options.push(
                        connection
                            .send_request(SetSessionConfigOptionRequest::new(
                                session_id.clone(),
                                config_id,
                                value,
                            ))
                            .block_task()
                            .await?,
                    );
                }

                let cancellation = request.cancel_after.map(|delay| {
                    let connection = connection.clone();
                    let session_id = session_id.clone();
                    tokio::spawn(async move {
                        sleep(delay).await;
                        connection.send_notification(CancelNotification::new(session_id))
                    })
                });
                let prompt = connection
                    .send_request(PromptRequest::new(session_id.clone(), request.prompt))
                    .block_task()
                    .await?;
                if let Some(cancellation) = cancellation {
                    cancellation.abort();
                }

                let close = if request.close_session
                    && initialize
                        .agent_capabilities
                        .session_capabilities
                        .close
                        .is_some()
                {
                    Some(
                        connection
                            .send_request(CloseSessionRequest::new(session_id.clone()))
                            .block_task()
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
            });

        let (initialize, session_id, sessions, mode, config_options, prompt, close) =
            timeout(timeout_duration, interaction)
                .await
                .map_err(|_| AcpInteropError::Timeout(timeout_duration))??;
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

//! ACP stdio server bridge backed by GTA-Claw application ports.

use std::{future::Future, pin::Pin, sync::Arc};

use agent_client_protocol::{
    Agent, Client, ConnectionTo, Stdio,
    schema::{
        AgentCapabilities, CancelNotification, CloseSessionRequest, CloseSessionResponse,
        InitializeRequest, InitializeResponse, ListSessionsRequest, ListSessionsResponse,
        LoadSessionRequest, LoadSessionResponse, NewSessionRequest, NewSessionResponse,
        PromptRequest, PromptResponse, ProtocolVersion, RequestPermissionRequest,
        RequestPermissionResponse, ResumeSessionRequest, ResumeSessionResponse,
        SessionNotification, SessionUpdate, SetSessionConfigOptionRequest,
        SetSessionConfigOptionResponse, SetSessionModeRequest, SetSessionModeResponse,
    },
};

use crate::Result;

/// Future returned by an ACP backend operation.
pub type AcpFuture<'a, T> =
    Pin<Box<dyn Future<Output = std::result::Result<T, agent_client_protocol::Error>> + Send + 'a>>;

/// Request context used for streaming and permission callbacks.
#[derive(Clone)]
pub struct AcpSessionContext {
    connection: ConnectionTo<Client>,
}

impl std::fmt::Debug for AcpSessionContext {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("AcpSessionContext")
            .finish_non_exhaustive()
    }
}

impl AcpSessionContext {
    /// Streams one session update to the connected ACP client.
    pub fn notify(
        &self,
        session_id: impl Into<agent_client_protocol::schema::SessionId>,
        update: SessionUpdate,
    ) -> std::result::Result<(), agent_client_protocol::Error> {
        self.connection
            .send_notification(SessionNotification::new(session_id, update))
    }

    /// Requests an explicit permission decision from the ACP client.
    pub async fn request_permission(
        &self,
        request: RequestPermissionRequest,
    ) -> std::result::Result<RequestPermissionResponse, agent_client_protocol::Error> {
        self.connection.send_request(request).block_task().await
    }
}

/// GTA-Claw application port implemented by the ACP server bridge.
pub trait AcpBackend: Send + Sync + 'static {
    /// Creates a new ACP session.
    fn new_session<'a>(
        &'a self,
        request: NewSessionRequest,
        context: AcpSessionContext,
    ) -> AcpFuture<'a, NewSessionResponse>;
    /// Loads an existing ACP session and replays its history through notifications.
    fn load_session<'a>(
        &'a self,
        request: LoadSessionRequest,
        context: AcpSessionContext,
    ) -> AcpFuture<'a, LoadSessionResponse>;
    /// Resumes an existing ACP session.
    fn resume_session<'a>(
        &'a self,
        request: ResumeSessionRequest,
        context: AcpSessionContext,
    ) -> AcpFuture<'a, ResumeSessionResponse>;
    /// Lists persistent ACP sessions.
    fn list_sessions<'a>(
        &'a self,
        request: ListSessionsRequest,
    ) -> AcpFuture<'a, ListSessionsResponse>;
    /// Closes a session and releases its resources.
    fn close_session<'a>(
        &'a self,
        request: CloseSessionRequest,
    ) -> AcpFuture<'a, CloseSessionResponse>;
    /// Processes one prompt turn and streams intermediate updates.
    fn prompt<'a>(
        &'a self,
        request: PromptRequest,
        context: AcpSessionContext,
    ) -> AcpFuture<'a, PromptResponse>;
    /// Changes the active mode for one session.
    fn set_mode<'a>(
        &'a self,
        request: SetSessionModeRequest,
    ) -> AcpFuture<'a, SetSessionModeResponse>;
    /// Changes one session configuration option.
    fn set_config_option<'a>(
        &'a self,
        request: SetSessionConfigOptionRequest,
    ) -> AcpFuture<'a, SetSessionConfigOptionResponse>;
    /// Cancels active work in one session.
    fn cancel<'a>(&'a self, notification: CancelNotification) -> AcpFuture<'a, ()>;
}

/// ACP agent bridge serving GTA-Claw sessions over stdio.
pub struct AcpBridge {
    backend: Arc<dyn AcpBackend>,
    capabilities: AgentCapabilities,
}

impl std::fmt::Debug for AcpBridge {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("AcpBridge")
            .field("capabilities", &self.capabilities)
            .finish_non_exhaustive()
    }
}

impl AcpBridge {
    /// Creates an ACP bridge with explicitly advertised capabilities.
    #[must_use]
    pub fn new(backend: Arc<dyn AcpBackend>, capabilities: AgentCapabilities) -> Self {
        Self {
            backend,
            capabilities,
        }
    }

    /// Serves the ACP bridge over process stdio until the client disconnects.
    pub async fn serve_stdio(self) -> Result<()> {
        let initialize_capabilities = self.capabilities;
        let new_session_backend = self.backend.clone();
        let load_session_backend = self.backend.clone();
        let resume_session_backend = self.backend.clone();
        let list_sessions_backend = self.backend.clone();
        let close_session_backend = self.backend.clone();
        let prompt_backend = self.backend.clone();
        let set_mode_backend = self.backend.clone();
        let set_config_backend = self.backend.clone();
        let cancel_backend = self.backend;

        Agent
            .builder()
            .name("gta-claw-acp")
            .on_receive_request(
                async move |request: InitializeRequest, responder, _connection| {
                    let response = InitializeResponse::new(
                        if request.protocol_version == ProtocolVersion::V1 {
                            request.protocol_version
                        } else {
                            ProtocolVersion::V1
                        },
                    )
                    .agent_capabilities(initialize_capabilities.clone())
                    .agent_info(
                        agent_client_protocol::schema::Implementation::new(
                            "gta-claw",
                            env!("CARGO_PKG_VERSION"),
                        ),
                    );
                    responder.respond(response)
                },
                agent_client_protocol::on_receive_request!(),
            )
            .on_receive_request(
                async move |request: NewSessionRequest, responder, connection| {
                    responder.respond_with_result(
                        new_session_backend
                            .new_session(request, AcpSessionContext { connection })
                            .await,
                    )
                },
                agent_client_protocol::on_receive_request!(),
            )
            .on_receive_request(
                async move |request: LoadSessionRequest, responder, connection| {
                    responder.respond_with_result(
                        load_session_backend
                            .load_session(request, AcpSessionContext { connection })
                            .await,
                    )
                },
                agent_client_protocol::on_receive_request!(),
            )
            .on_receive_request(
                async move |request: ResumeSessionRequest, responder, connection| {
                    responder.respond_with_result(
                        resume_session_backend
                            .resume_session(request, AcpSessionContext { connection })
                            .await,
                    )
                },
                agent_client_protocol::on_receive_request!(),
            )
            .on_receive_request(
                async move |request: ListSessionsRequest, responder, _connection| {
                    responder
                        .respond_with_result(list_sessions_backend.list_sessions(request).await)
                },
                agent_client_protocol::on_receive_request!(),
            )
            .on_receive_request(
                async move |request: CloseSessionRequest, responder, _connection| {
                    responder
                        .respond_with_result(close_session_backend.close_session(request).await)
                },
                agent_client_protocol::on_receive_request!(),
            )
            .on_receive_request(
                async move |request: PromptRequest, responder, connection| {
                    let prompt_backend = prompt_backend.clone();
                    tokio::spawn(async move {
                        let result = prompt_backend
                            .prompt(request, AcpSessionContext { connection })
                            .await;
                        let _ = responder.respond_with_result(result);
                    });
                    Ok(())
                },
                agent_client_protocol::on_receive_request!(),
            )
            .on_receive_request(
                async move |request: SetSessionModeRequest, responder, _connection| {
                    responder.respond_with_result(set_mode_backend.set_mode(request).await)
                },
                agent_client_protocol::on_receive_request!(),
            )
            .on_receive_request(
                async move |request: SetSessionConfigOptionRequest, responder, _connection| {
                    responder
                        .respond_with_result(set_config_backend.set_config_option(request).await)
                },
                agent_client_protocol::on_receive_request!(),
            )
            .on_receive_notification(
                async move |notification: CancelNotification, _connection| {
                    cancel_backend.cancel(notification).await
                },
                agent_client_protocol::on_receive_notification!(),
            )
            .connect_to(Stdio::new())
            .await?;
        Ok(())
    }
}

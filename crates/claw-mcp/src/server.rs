//! GTA-Claw MCP server adapter.
#![expect(
    deprecated,
    reason = "rmcp deprecates MCP sampling per SEP-2577, but this server must keep offering it to clients that still request it"
)]

use std::future::{Future, ready};
use std::sync::Arc;

use rmcp::model::{
    CallToolRequestParams, CallToolResult, CompleteRequestParams, CompleteResult,
    CreateMessageRequestParams, CreateMessageResult, ErrorCode, GetPromptRequestParams,
    GetPromptResult, ListPromptsResult, ListResourceTemplatesResult, ListResourcesResult,
    ListToolsResult, PaginatedRequestParams, ReadResourceRequestParams, ReadResourceResult,
    ServerInfo, SubscribeRequestParams, UnsubscribeRequestParams,
};
use rmcp::service::{NotificationContext, RequestContext, RoleServer};
use rmcp::{ErrorData, Peer, ServerHandler, ServiceExt};
use tokio_util::sync::CancellationToken;

use crate::{error::Result, framing::BoundedIoTransport};

/// Request-scoped facilities available to a GTA-Claw MCP backend.
#[derive(Clone, Debug)]
pub struct OperationContext {
    /// Token cancelled by `notifications/cancelled` or connection shutdown.
    pub cancellation: CancellationToken,
    /// MCP peer used for sampling and outbound notifications.
    pub peer: Peer<RoleServer>,
}

impl From<RequestContext<RoleServer>> for OperationContext {
    fn from(context: RequestContext<RoleServer>) -> Self {
        Self {
            cancellation: context.ct,
            peer: context.peer,
        }
    }
}

/// GTA-Claw capabilities exposed through the MCP server.
///
/// Default methods are deliberately explicit: list methods return empty pages,
/// while operations that require a concrete application adapter return a JSON-RPC
/// method-not-found error.
pub trait McpBackend: Send + Sync + 'static {
    /// Returns server identity and negotiated capabilities.
    fn server_info(&self) -> ServerInfo;

    /// Lists available tools.
    fn list_tools(
        &self,
        _request: Option<PaginatedRequestParams>,
        _context: OperationContext,
    ) -> impl Future<Output = std::result::Result<ListToolsResult, ErrorData>> + Send {
        ready(Ok(ListToolsResult::default()))
    }

    /// Calls one tool.
    fn call_tool(
        &self,
        _request: CallToolRequestParams,
        _context: OperationContext,
    ) -> impl Future<Output = std::result::Result<CallToolResult, ErrorData>> + Send {
        ready(Err(method_not_found("tools/call is not configured")))
    }

    /// Lists available resources.
    fn list_resources(
        &self,
        _request: Option<PaginatedRequestParams>,
        _context: OperationContext,
    ) -> impl Future<Output = std::result::Result<ListResourcesResult, ErrorData>> + Send {
        ready(Ok(ListResourcesResult::default()))
    }

    /// Lists resource templates.
    fn list_resource_templates(
        &self,
        _request: Option<PaginatedRequestParams>,
        _context: OperationContext,
    ) -> impl Future<Output = std::result::Result<ListResourceTemplatesResult, ErrorData>> + Send
    {
        ready(Ok(ListResourceTemplatesResult::default()))
    }

    /// Reads one resource.
    fn read_resource(
        &self,
        _request: ReadResourceRequestParams,
        _context: OperationContext,
    ) -> impl Future<Output = std::result::Result<ReadResourceResult, ErrorData>> + Send {
        ready(Err(method_not_found("resources/read is not configured")))
    }

    /// Subscribes to updates for one resource.
    fn subscribe(
        &self,
        _request: SubscribeRequestParams,
        _context: OperationContext,
    ) -> impl Future<Output = std::result::Result<(), ErrorData>> + Send {
        ready(Err(method_not_found(
            "resources/subscribe is not configured",
        )))
    }

    /// Unsubscribes from updates for one resource.
    fn unsubscribe(
        &self,
        _request: UnsubscribeRequestParams,
        _context: OperationContext,
    ) -> impl Future<Output = std::result::Result<(), ErrorData>> + Send {
        ready(Err(method_not_found(
            "resources/unsubscribe is not configured",
        )))
    }

    /// Lists available prompts.
    fn list_prompts(
        &self,
        _request: Option<PaginatedRequestParams>,
        _context: OperationContext,
    ) -> impl Future<Output = std::result::Result<ListPromptsResult, ErrorData>> + Send {
        ready(Ok(ListPromptsResult::default()))
    }

    /// Resolves one prompt.
    fn get_prompt(
        &self,
        _request: GetPromptRequestParams,
        _context: OperationContext,
    ) -> impl Future<Output = std::result::Result<GetPromptResult, ErrorData>> + Send {
        ready(Err(method_not_found("prompts/get is not configured")))
    }

    /// Completes a prompt or resource argument.
    fn complete(
        &self,
        _request: CompleteRequestParams,
        _context: OperationContext,
    ) -> impl Future<Output = std::result::Result<CompleteResult, ErrorData>> + Send {
        ready(Ok(CompleteResult::default()))
    }

    /// Receives the post-handshake initialized notification.
    fn initialized(&self, _context: OperationContext) -> impl Future<Output = ()> + Send {
        ready(())
    }

    /// Receives a cancellation notification.
    fn cancelled(
        &self,
        _request_id: Option<rmcp::model::RequestId>,
        _reason: Option<String>,
        _context: OperationContext,
    ) -> impl Future<Output = ()> + Send {
        ready(())
    }
}

fn method_not_found(message: impl Into<String>) -> ErrorData {
    ErrorData::new(ErrorCode::METHOD_NOT_FOUND, message.into(), None)
}

/// MCP server handler backed by GTA-Claw application ports.
#[derive(Debug)]
pub struct GtaMcpServer<B> {
    backend: Arc<B>,
}

impl<B> GtaMcpServer<B> {
    /// Creates an MCP server from a GTA-Claw backend.
    #[must_use]
    pub const fn new(backend: Arc<B>) -> Self {
        Self { backend }
    }

    /// Requests model sampling from a connected client.
    ///
    /// # Errors
    ///
    /// Returns [`rmcp::service::ServiceError`] when the client declined the
    /// `sampling/createMessage` request with a JSON-RPC error (usually because it
    /// never advertised the sampling capability), when the connection closed
    /// before the client answered, or when the peer's request timeout elapsed.
    pub async fn sample(
        context: &OperationContext,
        request: CreateMessageRequestParams,
    ) -> std::result::Result<CreateMessageResult, rmcp::service::ServiceError> {
        context.peer.create_message(request).await
    }

    /// Announces that the tool list changed.
    ///
    /// # Errors
    ///
    /// Returns [`crate::error::McpError::Service`] when the notification cannot be
    /// handed to the transport — the peer has disconnected or the service worker
    /// has already shut down. Notifications carry no reply, so a successful send
    /// only means the bytes were queued.
    pub async fn notify_tools_changed(context: &OperationContext) -> Result<()> {
        context.peer.notify_tool_list_changed().await?;
        Ok(())
    }

    /// Announces that the resource list changed.
    ///
    /// # Errors
    ///
    /// Returns [`crate::error::McpError::Service`] when the peer has disconnected
    /// or the service worker has already shut down, so the notification could not
    /// be queued on the transport.
    pub async fn notify_resources_changed(context: &OperationContext) -> Result<()> {
        context.peer.notify_resource_list_changed().await?;
        Ok(())
    }

    /// Announces that the prompt list changed.
    ///
    /// # Errors
    ///
    /// Returns [`crate::error::McpError::Service`] when the peer has disconnected
    /// or the service worker has already shut down, so the notification could not
    /// be queued on the transport.
    pub async fn notify_prompts_changed(context: &OperationContext) -> Result<()> {
        context.peer.notify_prompt_list_changed().await?;
        Ok(())
    }
}

impl<B: McpBackend> ServerHandler for GtaMcpServer<B> {
    fn get_info(&self) -> ServerInfo {
        self.backend.server_info()
    }

    async fn list_tools(
        &self,
        request: Option<PaginatedRequestParams>,
        context: RequestContext<RoleServer>,
    ) -> std::result::Result<ListToolsResult, ErrorData> {
        self.backend.list_tools(request, context.into()).await
    }

    async fn call_tool(
        &self,
        request: CallToolRequestParams,
        context: RequestContext<RoleServer>,
    ) -> std::result::Result<CallToolResult, ErrorData> {
        self.backend.call_tool(request, context.into()).await
    }

    async fn list_resources(
        &self,
        request: Option<PaginatedRequestParams>,
        context: RequestContext<RoleServer>,
    ) -> std::result::Result<ListResourcesResult, ErrorData> {
        self.backend.list_resources(request, context.into()).await
    }

    async fn list_resource_templates(
        &self,
        request: Option<PaginatedRequestParams>,
        context: RequestContext<RoleServer>,
    ) -> std::result::Result<ListResourceTemplatesResult, ErrorData> {
        self.backend
            .list_resource_templates(request, context.into())
            .await
    }

    async fn read_resource(
        &self,
        request: ReadResourceRequestParams,
        context: RequestContext<RoleServer>,
    ) -> std::result::Result<ReadResourceResult, ErrorData> {
        self.backend.read_resource(request, context.into()).await
    }

    async fn subscribe(
        &self,
        request: SubscribeRequestParams,
        context: RequestContext<RoleServer>,
    ) -> std::result::Result<(), ErrorData> {
        self.backend.subscribe(request, context.into()).await
    }

    async fn unsubscribe(
        &self,
        request: UnsubscribeRequestParams,
        context: RequestContext<RoleServer>,
    ) -> std::result::Result<(), ErrorData> {
        self.backend.unsubscribe(request, context.into()).await
    }

    async fn list_prompts(
        &self,
        request: Option<PaginatedRequestParams>,
        context: RequestContext<RoleServer>,
    ) -> std::result::Result<ListPromptsResult, ErrorData> {
        self.backend.list_prompts(request, context.into()).await
    }

    async fn get_prompt(
        &self,
        request: GetPromptRequestParams,
        context: RequestContext<RoleServer>,
    ) -> std::result::Result<GetPromptResult, ErrorData> {
        self.backend.get_prompt(request, context.into()).await
    }

    async fn complete(
        &self,
        request: CompleteRequestParams,
        context: RequestContext<RoleServer>,
    ) -> std::result::Result<CompleteResult, ErrorData> {
        self.backend.complete(request, context.into()).await
    }

    async fn on_initialized(&self, context: NotificationContext<RoleServer>) {
        self.backend
            .initialized(OperationContext {
                cancellation: CancellationToken::new(),
                peer: context.peer,
            })
            .await;
    }

    async fn on_cancelled(
        &self,
        notification: rmcp::model::CancelledNotificationParam,
        context: NotificationContext<RoleServer>,
    ) {
        self.backend
            .cancelled(
                notification.request_id,
                notification.reason,
                OperationContext {
                    cancellation: CancellationToken::new(),
                    peer: context.peer,
                },
            )
            .await;
    }
}

/// Serves a GTA-Claw MCP backend over protocol-only standard IO.
///
/// # Errors
///
/// Returns [`crate::error::McpError::ServerInitialize`] when the client's
/// initialize request is rejected or standard input closes before it arrives.
/// Once serving, returns [`crate::error::McpError::Io`] when a client frame is
/// malformed JSON, is not UTF-8, or exceeds
/// [`crate::framing::DEFAULT_MAX_FRAME_BYTES`], and
/// [`crate::error::McpError::Join`] when the service worker panicked. A clean
/// end-of-input on stdin is a normal shutdown, not an error.
pub async fn serve_stdio<B: McpBackend>(backend: Arc<B>) -> Result<()> {
    let running = GtaMcpServer::new(backend)
        .serve(BoundedIoTransport::<RoleServer>::new(
            tokio::io::stdin(),
            tokio::io::stdout(),
        ))
        .await?;
    running.waiting().await?;
    Ok(())
}

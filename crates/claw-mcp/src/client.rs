//! MCP client facade spanning stdio, streamable HTTP, and legacy SSE transports.
#![expect(
    deprecated,
    reason = "rmcp deprecates MCP sampling and logging per SEP-2577, but this client must keep speaking both to servers that still use them"
)]

use std::{
    collections::HashMap, ffi::OsString, fmt, future::Future, io, path::PathBuf, pin::Pin,
    process::Stdio, sync::Arc, time::Duration,
};

use http::header::AUTHORIZATION;
#[cfg(windows)]
use process_wrap::tokio::JobObject;
#[cfg(unix)]
use process_wrap::tokio::ProcessGroup;
use process_wrap::tokio::{ChildWrapper, CommandWrap, KillOnDrop};
use rmcp::{
    ClientHandler, RoleClient, ServiceError, ServiceExt,
    model::{
        CallToolRequest, CallToolRequestParams, CallToolResult, ClientCapabilities, ClientInfo,
        ClientRequest, CompleteRequest, CompleteRequestParams, CompleteResult,
        CreateMessageRequestParams, CreateMessageResult, GetPromptRequest, GetPromptRequestParams,
        GetPromptResult, Implementation, ListPromptsRequest, ListPromptsResult,
        ListResourceTemplatesRequest, ListResourceTemplatesResult, ListResourcesRequest,
        ListResourcesResult, ListToolsRequest, ListToolsResult, LoggingMessageNotificationParam,
        ProgressNotificationParam, ReadResourceRequest, ReadResourceRequestParams,
        ReadResourceResult, ResourceUpdatedNotificationParam, ServerInfo, ServerResult,
        SubscribeRequest, SubscribeRequestParams, UnsubscribeRequest, UnsubscribeRequestParams,
    },
    service::{
        NotificationContext, PeerRequestOptions, RequestContext, RunningService, RxJsonRpcMessage,
        TxJsonRpcMessage,
    },
    transport::{
        StreamableHttpClientTransport, Transport,
        streamable_http_client::StreamableHttpClientTransportConfig,
    },
};
use secrecy::{ExposeSecret, SecretString};
use tokio::{io::sink, process::Command, task::JoinHandle, time::timeout};
use url::Url;

use crate::{
    error::McpError,
    framing::BoundedIoTransport,
    http_client::HttpClient,
    sse::{LegacySseConfig, LegacySseTransport},
};

const CLIENT_CLOSE_TIMEOUT: Duration = Duration::from_secs(5);
const REQUEST_CANCELLATION_GRACE: Duration = Duration::from_millis(250);
const STDERR_DRAIN_TIMEOUT: Duration = Duration::from_secs(1);

/// Future returned by an MCP sampling port.
pub type SamplingFuture<'a> =
    Pin<Box<dyn Future<Output = Result<CreateMessageResult, rmcp::ErrorData>> + Send + 'a>>;

/// GTA-Claw port used when an MCP server requests client-side sampling.
pub trait SamplingPort: Send + Sync + 'static {
    /// Whether initialize negotiation may advertise client-side sampling.
    ///
    /// This defaults to `false` so a sampling adapter must explicitly opt in.
    /// Implementations returning `true` must service [`Self::create_message`]
    /// requests rather than rejecting the method as unsupported.
    fn supports_sampling(&self) -> bool {
        false
    }

    /// Creates a model response for an MCP sampling request.
    fn create_message(&self, request: CreateMessageRequestParams) -> SamplingFuture<'_>;
}

/// Rejects sampling requests unless the application installs a sampling port.
#[derive(Debug, Default)]
pub struct RejectSampling;

impl SamplingPort for RejectSampling {
    fn create_message(&self, _request: CreateMessageRequestParams) -> SamplingFuture<'_> {
        Box::pin(async {
            Err(rmcp::ErrorData::method_not_found::<
                rmcp::model::CreateMessageRequestMethod,
            >())
        })
    }
}

/// Notifications emitted by a connected MCP server.
#[derive(Clone, Debug, PartialEq)]
#[non_exhaustive]
pub enum McpClientEvent {
    /// The tool catalog changed.
    ToolsChanged,
    /// The resource catalog changed.
    ResourcesChanged,
    /// The prompt catalog changed.
    PromptsChanged,
    /// A subscribed resource changed.
    ResourceUpdated(ResourceUpdatedNotificationParam),
    /// The server emitted a log message.
    Logging(LoggingMessageNotificationParam),
    /// A request reported progress.
    Progress(ProgressNotificationParam),
}

/// Synchronous sink for server notifications.
pub trait ClientEventSink: Send + Sync + 'static {
    /// Records one notification.
    fn emit(&self, event: McpClientEvent);
}

/// Event sink that discards notifications.
#[derive(Debug, Default)]
pub struct DiscardEvents;

impl ClientEventSink for DiscardEvents {
    fn emit(&self, _event: McpClientEvent) {}
}

#[derive(Clone)]
struct GtaClientHandler {
    sampling: Arc<dyn SamplingPort>,
    events: Arc<dyn ClientEventSink>,
}

impl ClientHandler for GtaClientHandler {
    fn get_info(&self) -> ClientInfo {
        let capabilities = if self.sampling.supports_sampling() {
            ClientCapabilities::builder().enable_sampling().build()
        } else {
            ClientCapabilities::default()
        };
        ClientInfo::new(
            capabilities,
            Implementation::new("gta-claw", env!("CARGO_PKG_VERSION")),
        )
    }

    fn create_message(
        &self,
        request: CreateMessageRequestParams,
        _context: RequestContext<RoleClient>,
    ) -> impl Future<Output = Result<CreateMessageResult, rmcp::ErrorData>> + Send + '_ {
        self.sampling.create_message(request)
    }

    fn on_tool_list_changed(
        &self,
        _context: NotificationContext<RoleClient>,
    ) -> impl Future<Output = ()> + Send + '_ {
        self.events.emit(McpClientEvent::ToolsChanged);
        std::future::ready(())
    }

    fn on_resource_list_changed(
        &self,
        _context: NotificationContext<RoleClient>,
    ) -> impl Future<Output = ()> + Send + '_ {
        self.events.emit(McpClientEvent::ResourcesChanged);
        std::future::ready(())
    }

    fn on_prompt_list_changed(
        &self,
        _context: NotificationContext<RoleClient>,
    ) -> impl Future<Output = ()> + Send + '_ {
        self.events.emit(McpClientEvent::PromptsChanged);
        std::future::ready(())
    }

    fn on_resource_updated(
        &self,
        params: ResourceUpdatedNotificationParam,
        _context: NotificationContext<RoleClient>,
    ) -> impl Future<Output = ()> + Send + '_ {
        self.events.emit(McpClientEvent::ResourceUpdated(params));
        std::future::ready(())
    }

    fn on_logging_message(
        &self,
        params: LoggingMessageNotificationParam,
        _context: NotificationContext<RoleClient>,
    ) -> impl Future<Output = ()> + Send + '_ {
        self.events.emit(McpClientEvent::Logging(params));
        std::future::ready(())
    }

    fn on_progress(
        &self,
        params: ProgressNotificationParam,
        _context: NotificationContext<RoleClient>,
    ) -> impl Future<Output = ()> + Send + '_ {
        self.events.emit(McpClientEvent::Progress(params));
        std::future::ready(())
    }
}

/// Configuration for a child MCP server connected through stdio.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct StdioClientConfig {
    /// Executable to spawn.
    pub program: PathBuf,
    /// Child-process arguments.
    pub arguments: Vec<OsString>,
    /// Environment variables added to the child.
    pub environment: HashMap<OsString, OsString>,
    /// Timeout for initialize negotiation.
    pub connect_timeout: Duration,
    /// Timeout applied to each MCP request.
    pub request_timeout: Duration,
    /// Maximum accepted newline-delimited JSON-RPC frame size.
    pub max_frame_bytes: usize,
}

impl StdioClientConfig {
    /// Creates a stdio client configuration.
    #[must_use]
    pub fn new(program: impl Into<PathBuf>) -> Self {
        Self {
            program: program.into(),
            arguments: Vec::new(),
            environment: HashMap::new(),
            connect_timeout: Duration::from_secs(15),
            request_timeout: Duration::from_secs(30),
            max_frame_bytes: crate::framing::DEFAULT_MAX_FRAME_BYTES,
        }
    }
}

/// Configuration for a streamable HTTP MCP server.
#[derive(Clone)]
pub struct HttpClientConfig {
    /// Server MCP endpoint.
    pub endpoint: Url,
    /// Optional bearer token.
    pub bearer_token: Option<SecretString>,
    /// Timeout for initialize negotiation.
    pub connect_timeout: Duration,
    /// Timeout applied to each MCP request.
    pub request_timeout: Duration,
}

impl fmt::Debug for HttpClientConfig {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("HttpClientConfig")
            .field("endpoint", &self.endpoint)
            .field(
                "bearer_token",
                &self.bearer_token.as_ref().map(|_| "[REDACTED]"),
            )
            .field("connect_timeout", &self.connect_timeout)
            .field("request_timeout", &self.request_timeout)
            .finish()
    }
}

impl HttpClientConfig {
    /// Creates a streamable HTTP client configuration.
    #[must_use]
    pub const fn new(endpoint: Url) -> Self {
        Self {
            endpoint,
            bearer_token: None,
            connect_timeout: Duration::from_secs(15),
            request_timeout: Duration::from_secs(30),
        }
    }
}

struct ChildTreeTransport {
    io: BoundedIoTransport<RoleClient>,
    child: Option<ChildTreeGuard>,
}

struct ChildTreeGuard(Box<dyn ChildWrapper>);

impl std::ops::Deref for ChildTreeGuard {
    type Target = dyn ChildWrapper;

    fn deref(&self) -> &Self::Target {
        self.0.as_ref()
    }
}

impl std::ops::DerefMut for ChildTreeGuard {
    fn deref_mut(&mut self) -> &mut Self::Target {
        self.0.as_mut()
    }
}

impl Drop for ChildTreeGuard {
    fn drop(&mut self) {
        terminate_and_reap(self.0.as_mut());
    }
}

impl Transport<RoleClient> for ChildTreeTransport {
    type Error = io::Error;

    fn send(
        &mut self,
        item: TxJsonRpcMessage<RoleClient>,
    ) -> impl Future<Output = Result<(), Self::Error>> + Send + 'static {
        self.io.send(item)
    }

    fn receive(&mut self) -> impl Future<Output = Option<RxJsonRpcMessage<RoleClient>>> + Send {
        self.io.receive()
    }

    fn close(&mut self) -> impl Future<Output = Result<(), Self::Error>> + Send {
        let io_close = self.io.close();
        let child = self.child.take();
        async move {
            let child_result = match child {
                Some(mut child) => Box::into_pin(child.kill()).await,
                None => Ok(()),
            };
            let io_result = io_close.await;
            child_result?;
            io_result
        }
    }
}

fn terminate_and_reap(child: &mut dyn ChildWrapper) {
    let _ = child.start_kill();
    for _ in 0..100 {
        match child.try_wait() {
            Ok(Some(_)) | Err(_) => return,
            Ok(None) => std::thread::sleep(Duration::from_millis(1)),
        }
    }
}

/// An initialized MCP client with negotiated server capabilities.
pub struct McpClient {
    service: RunningService<RoleClient, GtaClientHandler>,
    request_timeout: Duration,
    child_pid: Option<u32>,
    stderr_drain: Option<JoinHandle<()>>,
}

impl fmt::Debug for McpClient {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("McpClient")
            .field("server_info", &self.service.peer_info())
            .field("request_timeout", &self.request_timeout)
            .field("child_pid", &self.child_pid)
            .finish_non_exhaustive()
    }
}

impl McpClient {
    /// Connects to a child MCP server over stdio.
    ///
    /// # Errors
    ///
    /// Returns [`McpError::Protocol`] when `max_frame_bytes` is zero, when the
    /// child writes a frame that is malformed, not UTF-8, or larger than
    /// `max_frame_bytes`, when the child exits mid-frame, when the initialize
    /// response omits `serverInfo`, or when the child selects a protocol version
    /// this crate does not implement. Returns [`McpError::Io`] when the program
    /// cannot be spawned or its standard streams were not piped,
    /// [`McpError::Timeout`] when initialize negotiation exceeds
    /// `connect_timeout`, and [`McpError::ClientInitialize`] when the child
    /// rejects the initialize request itself.
    pub async fn connect_stdio(
        config: StdioClientConfig,
        sampling: Arc<dyn SamplingPort>,
        events: Arc<dyn ClientEventSink>,
    ) -> Result<Self, McpError> {
        if config.max_frame_bytes == 0 {
            return Err(McpError::Protocol(
                "MCP stdio frame limit must be greater than zero".into(),
            ));
        }
        let mut command = Command::new(&config.program);
        command
            .args(&config.arguments)
            .envs(&config.environment)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        let mut command = CommandWrap::from(command);
        command.wrap(KillOnDrop);
        #[cfg(windows)]
        command.wrap(JobObject);
        #[cfg(unix)]
        command.wrap(ProcessGroup::leader());
        let mut child = ChildTreeGuard(command.spawn().map_err(McpError::Io)?);
        let child_pid = child.id();
        let stdin = child
            .stdin()
            .take()
            .ok_or_else(|| McpError::Io(io::Error::other("MCP child stdin was not piped")))?;
        let stdout = child
            .stdout()
            .take()
            .ok_or_else(|| McpError::Io(io::Error::other("MCP child stdout was not piped")))?;
        let stderr_drain = child.stderr().take().map(|mut stderr| {
            tokio::spawn(async move {
                let mut destination = sink();
                let _ = tokio::io::copy(&mut stderr, &mut destination).await;
            })
        });
        let io = BoundedIoTransport::with_max_frame_bytes(stdout, stdin, config.max_frame_bytes);
        let diagnostics = io.diagnostics();
        let service = match connect_transport(
            ChildTreeTransport {
                io,
                child: Some(child),
            },
            config.connect_timeout,
            GtaClientHandler { sampling, events },
        )
        .await
        {
            Ok(service) => service,
            Err(error) => return Err(diagnostics.promote_after_disconnect(error).await),
        };
        Ok(Self {
            service,
            request_timeout: config.request_timeout,
            child_pid,
            stderr_drain,
        })
    }

    /// Connects to an MCP server using streamable HTTP.
    ///
    /// # Errors
    ///
    /// Returns [`McpError::Protocol`] when a bearer token is paired with an
    /// endpoint that is neither HTTPS nor a literal-loopback HTTP URL (which
    /// would leak the token in clear text), when the initialize response omits
    /// `serverInfo`, or when the server selects an unimplemented protocol
    /// version. Returns [`McpError::Http`] when TLS setup or the HTTP exchange
    /// fails, [`McpError::Timeout`] when initialize exceeds `connect_timeout`,
    /// and [`McpError::ClientInitialize`] when the server rejects initialize.
    pub async fn connect_http(
        config: HttpClientConfig,
        sampling: Arc<dyn SamplingPort>,
        events: Arc<dyn ClientEventSink>,
    ) -> Result<Self, McpError> {
        if config.bearer_token.is_some() && !crate::endpoint_allows_credentials(&config.endpoint) {
            return Err(McpError::Protocol(
                "authenticated MCP URLs must use HTTPS unless they are loopback HTTP URLs".into(),
            ));
        }
        let mut transport_config =
            StreamableHttpClientTransportConfig::with_uri(config.endpoint.as_str().to_owned());
        if let Some(token) = config.bearer_token.as_ref() {
            transport_config = transport_config.auth_header(token.expose_secret().to_owned());
        }
        let http = HttpClient::new(config.request_timeout)?;
        let transport = StreamableHttpClientTransport::with_client(http, transport_config);
        let service = connect_transport(
            transport,
            config.connect_timeout,
            GtaClientHandler { sampling, events },
        )
        .await?;
        Ok(Self {
            service,
            request_timeout: config.request_timeout,
            child_pid: None,
            stderr_drain: None,
        })
    }

    /// Connects to a legacy MCP HTTP+SSE server.
    ///
    /// # Errors
    ///
    /// Returns [`McpError::Protocol`] when an `Authorization` header is paired
    /// with an endpoint that is neither HTTPS nor a literal-loopback HTTP URL,
    /// when the SSE transport cannot be built (unusable endpoint or header
    /// value), when the server never sends its `endpoint` event, when the
    /// initialize response omits `serverInfo`, or when the server selects an
    /// unimplemented protocol version. Returns [`McpError::Timeout`] when
    /// initialize exceeds the configured request timeout and
    /// [`McpError::ClientInitialize`] when the server rejects initialize.
    pub async fn connect_sse(
        config: LegacySseConfig,
        sampling: Arc<dyn SamplingPort>,
        events: Arc<dyn ClientEventSink>,
    ) -> Result<Self, McpError> {
        if config.headers.contains_key(AUTHORIZATION)
            && !crate::endpoint_allows_credentials(&config.endpoint)
        {
            return Err(McpError::Protocol(
                "authenticated MCP URLs must use HTTPS unless they are loopback HTTP URLs".into(),
            ));
        }
        let connect_timeout = config.request_timeout;
        let request_timeout = config.request_timeout;
        let transport = LegacySseTransport::new(config)
            .map_err(|error| McpError::Protocol(error.to_string()))?;
        let service = connect_transport(
            transport,
            connect_timeout,
            GtaClientHandler { sampling, events },
        )
        .await?;
        Ok(Self {
            service,
            request_timeout,
            child_pid: None,
            stderr_drain: None,
        })
    }

    /// Returns the server's initialize result and negotiated capabilities.
    #[must_use]
    pub fn server_info(&self) -> Option<Arc<ServerInfo>> {
        self.service.peer_info()
    }

    /// Returns the child process identifier for stdio clients.
    #[must_use]
    pub const fn child_pid(&self) -> Option<u32> {
        self.child_pid
    }

    /// Lists tools advertised by the server.
    ///
    /// # Errors
    ///
    /// Returns [`McpError::Timeout`] when the server does not answer `tools/list`
    /// within the configured request timeout, and [`McpError::Service`] when the
    /// transport is already closed, the server replies with a JSON-RPC error, or
    /// it answers with a result that is not a tool listing.
    pub async fn list_tools(&self) -> Result<ListToolsResult, McpError> {
        match self
            .cancellable_request(ClientRequest::ListToolsRequest(ListToolsRequest::default()))
            .await?
        {
            ServerResult::ListToolsResult(result) => Ok(result),
            _ => Err(McpError::Service(ServiceError::UnexpectedResponse)),
        }
    }

    /// Calls one server tool.
    ///
    /// # Errors
    ///
    /// Returns [`McpError::Timeout`] when the tool does not finish within the
    /// configured request timeout — the request is cancelled on the wire first,
    /// and the grace period for that cancellation is included. Returns
    /// [`McpError::Service`] when the transport is already closed, the server
    /// rejects the call with a JSON-RPC error (unknown tool, invalid arguments),
    /// or it answers with a result that is not a tool result. A tool that runs to
    /// completion but reports failure is an `Ok` [`CallToolResult`] with
    /// `is_error` set, not an error here.
    pub async fn call_tool(
        &self,
        request: CallToolRequestParams,
    ) -> Result<CallToolResult, McpError> {
        match self
            .cancellable_request(ClientRequest::CallToolRequest(CallToolRequest::new(
                request,
            )))
            .await?
        {
            ServerResult::CallToolResult(result) => Ok(result),
            _ => Err(McpError::Service(ServiceError::UnexpectedResponse)),
        }
    }

    /// Lists server resources.
    ///
    /// # Errors
    ///
    /// Returns [`McpError::Timeout`] when the server does not answer
    /// `resources/list` within the configured request timeout, and
    /// [`McpError::Service`] when the transport is already closed, the server
    /// replies with a JSON-RPC error (typically because it does not advertise the
    /// resources capability), or it answers with a result of another type.
    pub async fn list_resources(&self) -> Result<ListResourcesResult, McpError> {
        match self
            .cancellable_request(ClientRequest::ListResourcesRequest(
                ListResourcesRequest::default(),
            ))
            .await?
        {
            ServerResult::ListResourcesResult(result) => Ok(result),
            _ => Err(McpError::Service(ServiceError::UnexpectedResponse)),
        }
    }

    /// Lists server resource templates.
    ///
    /// # Errors
    ///
    /// Returns [`McpError::Timeout`] when the server does not answer
    /// `resources/templates/list` within the configured request timeout, and
    /// [`McpError::Service`] when the transport is already closed, the server
    /// replies with a JSON-RPC error, or it answers with a result of another type.
    pub async fn list_resource_templates(&self) -> Result<ListResourceTemplatesResult, McpError> {
        match self
            .cancellable_request(ClientRequest::ListResourceTemplatesRequest(
                ListResourceTemplatesRequest::default(),
            ))
            .await?
        {
            ServerResult::ListResourceTemplatesResult(result) => Ok(result),
            _ => Err(McpError::Service(ServiceError::UnexpectedResponse)),
        }
    }

    /// Reads a server resource.
    ///
    /// # Errors
    ///
    /// Returns [`McpError::Timeout`] when the server does not answer
    /// `resources/read` within the configured request timeout, and
    /// [`McpError::Service`] when the transport is already closed, the server
    /// replies with a JSON-RPC error (unknown or unreadable URI), or it answers
    /// with a result that is not resource contents.
    pub async fn read_resource(
        &self,
        request: ReadResourceRequestParams,
    ) -> Result<ReadResourceResult, McpError> {
        match self
            .cancellable_request(ClientRequest::ReadResourceRequest(
                ReadResourceRequest::new(request),
            ))
            .await?
        {
            ServerResult::ReadResourceResult(result) => Ok(result),
            _ => Err(McpError::Service(ServiceError::UnexpectedResponse)),
        }
    }

    /// Subscribes to a server resource.
    ///
    /// # Errors
    ///
    /// Returns [`McpError::Timeout`] when the server does not acknowledge
    /// `resources/subscribe` within the configured request timeout, and
    /// [`McpError::Service`] when the transport is already closed, the server
    /// replies with a JSON-RPC error (unknown URI, or subscriptions unsupported),
    /// or it answers with anything other than an empty result.
    pub async fn subscribe(&self, request: SubscribeRequestParams) -> Result<(), McpError> {
        match self
            .cancellable_request(ClientRequest::SubscribeRequest(SubscribeRequest::new(
                request,
            )))
            .await?
        {
            ServerResult::EmptyResult(_) => Ok(()),
            _ => Err(McpError::Service(ServiceError::UnexpectedResponse)),
        }
    }

    /// Unsubscribes from a server resource.
    ///
    /// # Errors
    ///
    /// Returns [`McpError::Timeout`] when the server does not acknowledge
    /// `resources/unsubscribe` within the configured request timeout, and
    /// [`McpError::Service`] when the transport is already closed, the server
    /// replies with a JSON-RPC error (no such subscription), or it answers with
    /// anything other than an empty result.
    pub async fn unsubscribe(&self, request: UnsubscribeRequestParams) -> Result<(), McpError> {
        match self
            .cancellable_request(ClientRequest::UnsubscribeRequest(UnsubscribeRequest::new(
                request,
            )))
            .await?
        {
            ServerResult::EmptyResult(_) => Ok(()),
            _ => Err(McpError::Service(ServiceError::UnexpectedResponse)),
        }
    }

    /// Lists server prompts.
    ///
    /// # Errors
    ///
    /// Returns [`McpError::Timeout`] when the server does not answer
    /// `prompts/list` within the configured request timeout, and
    /// [`McpError::Service`] when the transport is already closed, the server
    /// replies with a JSON-RPC error (typically because it does not advertise the
    /// prompts capability), or it answers with a result of another type.
    pub async fn list_prompts(&self) -> Result<ListPromptsResult, McpError> {
        match self
            .cancellable_request(ClientRequest::ListPromptsRequest(
                ListPromptsRequest::default(),
            ))
            .await?
        {
            ServerResult::ListPromptsResult(result) => Ok(result),
            _ => Err(McpError::Service(ServiceError::UnexpectedResponse)),
        }
    }

    /// Gets a server prompt.
    ///
    /// # Errors
    ///
    /// Returns [`McpError::Timeout`] when the server does not answer
    /// `prompts/get` within the configured request timeout, and
    /// [`McpError::Service`] when the transport is already closed, the server
    /// replies with a JSON-RPC error (unknown prompt or missing required
    /// argument), or it answers with a result that is not a prompt.
    pub async fn get_prompt(
        &self,
        request: GetPromptRequestParams,
    ) -> Result<GetPromptResult, McpError> {
        match self
            .cancellable_request(ClientRequest::GetPromptRequest(GetPromptRequest::new(
                request,
            )))
            .await?
        {
            ServerResult::GetPromptResult(result) => Ok(result),
            _ => Err(McpError::Service(ServiceError::UnexpectedResponse)),
        }
    }

    /// Requests server-side argument completion.
    ///
    /// # Errors
    ///
    /// Returns [`McpError::Timeout`] when the server does not answer
    /// `completion/complete` within the configured request timeout, and
    /// [`McpError::Service`] when the transport is already closed, the server
    /// replies with a JSON-RPC error (typically because it does not advertise the
    /// completions capability), or it answers with a result of another type.
    pub async fn complete(
        &self,
        request: CompleteRequestParams,
    ) -> Result<CompleteResult, McpError> {
        match self
            .cancellable_request(ClientRequest::CompleteRequest(CompleteRequest::new(
                request,
            )))
            .await?
        {
            ServerResult::CompleteResult(result) => Ok(result),
            _ => Err(McpError::Service(ServiceError::UnexpectedResponse)),
        }
    }

    /// Gracefully closes the transport and waits for worker cleanup.
    ///
    /// # Errors
    ///
    /// Returns [`McpError::Join`] when the service worker task panicked or was
    /// cancelled, and [`McpError::Lifecycle`] when the worker did not finish
    /// within the five-second shutdown budget. A stdio child that ignores the
    /// closed pipe is still killed by the transport's process guard, so a
    /// [`McpError::Lifecycle`] here reports a slow shutdown, not a leaked child.
    pub async fn close(mut self) -> Result<(), McpError> {
        let closed = self
            .service
            .close_with_timeout(CLIENT_CLOSE_TIMEOUT)
            .await
            .map_err(McpError::Join)?;
        if let Some(mut stderr_drain) = self.stderr_drain.take()
            && timeout(STDERR_DRAIN_TIMEOUT, &mut stderr_drain)
                .await
                .is_err()
        {
            stderr_drain.abort();
            let _ = stderr_drain.await;
        }
        if closed.is_none() {
            return Err(McpError::Lifecycle(format!(
                "MCP client shutdown exceeded {}ms",
                CLIENT_CLOSE_TIMEOUT.as_millis()
            )));
        }
        Ok(())
    }

    async fn cancellable_request(&self, request: ClientRequest) -> Result<ServerResult, McpError> {
        let handle = timeout(
            self.request_timeout,
            self.service.send_cancellable_request(
                request,
                PeerRequestOptions::with_timeout(self.request_timeout),
            ),
        )
        .await
        .map_err(|_| McpError::Timeout(self.request_timeout))?
        .map_err(service_error_to_mcp)?;
        timeout(
            self.request_timeout
                .saturating_add(REQUEST_CANCELLATION_GRACE),
            handle.await_response(),
        )
        .await
        .map_err(|_| McpError::Timeout(self.request_timeout))?
        .map_err(cancellable_service_error_to_mcp)
    }
}

async fn connect_transport<T, E, A>(
    transport: T,
    deadline: Duration,
    handler: GtaClientHandler,
) -> Result<RunningService<RoleClient, GtaClientHandler>, McpError>
where
    T: rmcp::transport::IntoTransport<RoleClient, E, A>,
    E: std::error::Error + Send + Sync + 'static,
{
    let mut service = timeout(deadline, handler.serve(transport))
        .await
        .map_err(|_| McpError::Timeout(deadline))?
        .map_err(McpError::from)?;
    let protocol_version = service
        .peer_info()
        .ok_or_else(|| McpError::Protocol("initialize response omitted server info".into()))?
        .protocol_version
        .clone();
    if !rmcp::model::ProtocolVersion::KNOWN_VERSIONS.contains(&protocol_version) {
        service.close().await.map_err(McpError::Join)?;
        return Err(McpError::Protocol(format!(
            "server selected unsupported version {protocol_version}"
        )));
    }
    Ok(service)
}

const fn service_error_to_mcp(error: ServiceError) -> McpError {
    McpError::Service(error)
}

fn cancellable_service_error_to_mcp(error: ServiceError) -> McpError {
    match error {
        ServiceError::Timeout { timeout } => McpError::Timeout(timeout),
        other => McpError::Service(other),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn http_debug_output_redacts_bearer_token() {
        let mut config = HttpClientConfig::new(
            Url::parse("http://127.0.0.1:43210/mcp").expect("valid test URL"),
        );
        config.bearer_token = Some(SecretString::new("fixture-token".into()));

        let output = format!("{config:?}");

        assert!(!output.contains("fixture-token"));
        assert!(output.contains("[REDACTED]"));
    }
}

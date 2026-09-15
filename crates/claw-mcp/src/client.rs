//! MCP client facade spanning stdio, streamable HTTP, and legacy SSE transports.
#![expect(
    deprecated,
    reason = "rmcp deprecates MCP sampling and logging per SEP-2577, but this client must keep speaking both to servers that still use them"
)]

use std::{
    collections::{BTreeMap, HashMap},
    ffi::OsString,
    fmt,
    future::Future,
    io,
    path::PathBuf,
    pin::Pin,
    process::Stdio,
    sync::{Arc, Mutex},
    time::Duration,
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
    http_client::{HttpClient, HttpClientError},
    sse::{LegacySseConfig, LegacySseTransport},
};

const CLIENT_CLOSE_TIMEOUT: Duration = Duration::from_secs(5);
const REQUEST_CANCELLATION_GRACE: Duration = Duration::from_millis(250);
const STDERR_DRAIN_TIMEOUT: Duration = Duration::from_secs(1);
const MAX_RESOURCE_SUBSCRIPTIONS: usize = 32;

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
    subscriptions: Arc<ResourceSubscriptions>,
}

#[derive(Clone, Copy)]
enum SubscriptionState {
    Subscribing { changed: bool },
    Active,
    Unsubscribing,
    Unknown,
}

#[derive(Default)]
struct SubscriptionEntries {
    closed: bool,
    entries: BTreeMap<String, SubscriptionState>,
}

#[derive(Default)]
struct ResourceSubscriptions(Mutex<SubscriptionEntries>);

impl ResourceSubscriptions {
    fn begin(
        self: &Arc<Self>,
        uri: &str,
        subscribe: bool,
    ) -> Result<SubscriptionAttempt, McpError> {
        let parsed = Url::parse(uri)
            .map_err(|_| McpError::Protocol("MCP subscription URI must be absolute".into()))?;
        if uri.len() > 2048
            || parsed.as_str() != uri
            || !parsed.username().is_empty()
            || parsed.password().is_some()
            || parsed.fragment().is_some()
            || uri
                .chars()
                .any(|character| character.is_control() || character.is_whitespace())
        {
            return Err(McpError::Protocol(
                "MCP subscription URI is unsafe or ambiguous".into(),
            ));
        }
        let mut state = self
            .0
            .lock()
            .map_err(|_| McpError::Protocol("MCP subscription state unavailable".into()))?;
        if state.closed {
            return Err(McpError::Protocol(
                "MCP subscription connection is closed".into(),
            ));
        }
        if subscribe {
            if state.entries.len() >= MAX_RESOURCE_SUBSCRIPTIONS || state.entries.contains_key(uri)
            {
                return Err(McpError::Protocol(
                    "MCP subscription is duplicate, unresolved or over capacity".into(),
                ));
            }
            state.entries.insert(
                uri.to_owned(),
                SubscriptionState::Subscribing { changed: false },
            );
        } else {
            if !matches!(state.entries.get(uri), Some(SubscriptionState::Active)) {
                return Err(McpError::Protocol("MCP resource subscription is not confirmed active; close an uncertain connection".into()));
            }
            state
                .entries
                .insert(uri.to_owned(), SubscriptionState::Unsubscribing);
        }
        drop(state);
        Ok(SubscriptionAttempt {
            owner: Arc::clone(self),
            uri: uri.to_owned(),
            subscribe,
            completed: false,
        })
    }

    fn changed(&self, uri: &str) -> bool {
        let Ok(mut state) = self.0.lock() else {
            return false;
        };
        if state.closed {
            return false;
        }
        match state.entries.get_mut(uri) {
            Some(SubscriptionState::Subscribing { changed }) => {
                *changed = true;
                false
            }
            Some(SubscriptionState::Active) => true,
            Some(SubscriptionState::Unsubscribing | SubscriptionState::Unknown) | None => false,
        }
    }

    fn close(&self) {
        if let Ok(mut state) = self.0.lock() {
            state.closed = true;
            state.entries.clear();
        }
    }
}

struct SubscriptionAttempt {
    owner: Arc<ResourceSubscriptions>,
    uri: String,
    subscribe: bool,
    completed: bool,
}

impl SubscriptionAttempt {
    fn confirm(mut self) -> Result<bool, McpError> {
        let mut state = self
            .owner
            .0
            .lock()
            .map_err(|_| McpError::Protocol("MCP subscription state unavailable".into()))?;
        let changed = if self.subscribe {
            let Some(SubscriptionState::Subscribing { changed }) =
                state.entries.get(&self.uri).copied()
            else {
                return Err(McpError::Protocol(
                    "MCP subscription changed before confirmation".into(),
                ));
            };
            state
                .entries
                .insert(self.uri.clone(), SubscriptionState::Active);
            changed
        } else {
            if !matches!(
                state.entries.get(&self.uri),
                Some(SubscriptionState::Unsubscribing)
            ) {
                return Err(McpError::Protocol(
                    "MCP unsubscription changed before confirmation".into(),
                ));
            }
            state.entries.remove(&self.uri);
            false
        };
        drop(state);
        self.completed = true;
        Ok(changed)
    }
}

impl Drop for SubscriptionAttempt {
    fn drop(&mut self) {
        if !self.completed
            && let Ok(mut state) = self.owner.0.lock()
            && let Some(entry) = state.entries.get_mut(&self.uri)
        {
            *entry = SubscriptionState::Unknown;
        }
    }
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
        if self.subscriptions.changed(&params.uri) {
            self.events.emit(McpClientEvent::ResourceUpdated(
                ResourceUpdatedNotificationParam::new(params.uri),
            ));
        }
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
#[derive(Clone, PartialEq, Eq)]
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

impl fmt::Debug for StdioClientConfig {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("StdioClientConfig")
            .field("program", &self.program)
            .field("argument_count", &self.arguments.len())
            .field(
                "environment_keys",
                &self.environment.keys().collect::<Vec<_>>(),
            )
            .field("connect_timeout", &self.connect_timeout)
            .field("request_timeout", &self.request_timeout)
            .field("max_frame_bytes", &self.max_frame_bytes)
            .finish()
    }
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

    /// Derives a native-keyring reference for one reviewed executable and environment name.
    ///
    /// Environment names are normalized to uppercase to preserve Windows identity.
    /// This creates no credential and does not inspect or start the executable.
    ///
    /// # Errors
    /// Rejects invalid server IDs, noncanonical SHA-256 digests or environment names.
    pub fn keyring_reference(
        server_id: &str,
        program_sha256: &str,
        environment_name: &str,
    ) -> Result<String, McpError> {
        use sha2::{Digest as _, Sha256};

        const HEX: &[u8; 16] = b"0123456789abcdef";

        if server_id.is_empty()
            || server_id.len() > 64
            || !server_id
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-' | b'.'))
            || program_sha256.len() != 64
            || !program_sha256
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
            || environment_name.is_empty()
            || environment_name.len() > 64
            || !environment_name
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || byte == b'_')
        {
            return Err(McpError::Protocol(
                "MCP stdio credential binding is invalid".into(),
            ));
        }
        let mut digest = Sha256::new();
        digest.update(b"gta-claw.mcp-stdio-keyring-binding.v1\0");
        for component in [
            server_id,
            program_sha256,
            &environment_name.to_ascii_uppercase(),
        ] {
            digest.update(component.len().to_string().as_bytes());
            digest.update(b":");
            digest.update(component.as_bytes());
        }
        let encoded: String = digest
            .finalize()
            .iter()
            .flat_map(|byte| [HEX[usize::from(byte >> 4)], HEX[usize::from(byte & 15)]])
            .map(char::from)
            .collect();
        Ok(format!("keyring://gta-claw.mcp-stdio/{encoded}"))
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
    subscriptions: Arc<ResourceSubscriptions>,
    events: Arc<dyn ClientEventSink>,
}

impl Drop for McpClient {
    fn drop(&mut self) {
        self.subscriptions.close();
    }
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
        Self::connect_stdio_with_environment(config, sampling, events, false, None).await
    }

    /// Connects to a configured child with only its explicitly supplied environment.
    ///
    /// The host must approve the executable, arguments and environment before this call.
    ///
    /// # Errors
    /// Returns the same spawn, framing and handshake errors as [`Self::connect_stdio`].
    pub async fn connect_stdio_isolated(
        config: StdioClientConfig,
        sampling: Arc<dyn SamplingPort>,
        events: Arc<dyn ClientEventSink>,
    ) -> Result<Self, McpError> {
        Self::connect_stdio_with_environment(config, sampling, events, true, None).await
    }

    /// Connects to an isolated child in an explicitly approved absolute working directory.
    ///
    /// The host owns executable and directory pinning for the duration of this operation.
    ///
    /// # Errors
    /// Rejects relative executable/directory paths before spawn, or returns stdio transport errors.
    pub async fn connect_stdio_isolated_at(
        config: StdioClientConfig,
        directory: PathBuf,
        sampling: Arc<dyn SamplingPort>,
        events: Arc<dyn ClientEventSink>,
    ) -> Result<Self, McpError> {
        if !config.program.is_absolute() || !directory.is_absolute() {
            return Err(McpError::Protocol(
                "isolated MCP child requires absolute executable and working-directory paths"
                    .into(),
            ));
        }
        Self::connect_stdio_with_environment(config, sampling, events, true, Some(directory)).await
    }

    async fn connect_stdio_with_environment(
        config: StdioClientConfig,
        sampling: Arc<dyn SamplingPort>,
        events: Arc<dyn ClientEventSink>,
        clear_environment: bool,
        directory: Option<PathBuf>,
    ) -> Result<Self, McpError> {
        if config.max_frame_bytes == 0 {
            return Err(McpError::Protocol(
                "MCP stdio frame limit must be greater than zero".into(),
            ));
        }
        let mut command = Command::new(&config.program);
        if clear_environment {
            command.env_clear();
        }
        if let Some(directory) = directory {
            command.current_dir(directory);
        }
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
        let subscriptions = Arc::new(ResourceSubscriptions::default());
        let service = match connect_transport(
            ChildTreeTransport {
                io,
                child: Some(child),
            },
            config.connect_timeout,
            GtaClientHandler {
                sampling,
                events: Arc::clone(&events),
                subscriptions: Arc::clone(&subscriptions),
            },
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
            subscriptions,
            events,
        })
    }

    /// Connects to an MCP server using streamable HTTP.
    ///
    /// Session expiry is returned to the caller without reinitializing or replaying a request.
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
        Self::connect_http_routed(config, None, sampling, events).await
    }

    /// Connects using an exact enrolled endpoint and route without ambient proxy settings.
    ///
    /// # Errors
    /// Refuses a mismatched endpoint or the same authentication/transport failures as [`Self::connect_http`].
    pub async fn connect_http_with_route(
        config: HttpClientConfig,
        route: crate::HttpRoutePolicy,
        sampling: Arc<dyn SamplingPort>,
        events: Arc<dyn ClientEventSink>,
    ) -> Result<Self, McpError> {
        if &config.endpoint != route.endpoint() {
            return Err(McpError::Http(HttpClientError::RoutePolicy));
        }
        Self::connect_http_routed(config, Some(route), sampling, events).await
    }

    async fn connect_http_routed(
        config: HttpClientConfig,
        route: Option<crate::HttpRoutePolicy>,
        sampling: Arc<dyn SamplingPort>,
        events: Arc<dyn ClientEventSink>,
    ) -> Result<Self, McpError> {
        if config.bearer_token.is_some() && !crate::endpoint_allows_credentials(&config.endpoint) {
            return Err(McpError::Protocol(
                "authenticated MCP URLs must use HTTPS unless they are loopback HTTP URLs".into(),
            ));
        }
        let mut transport_config =
            StreamableHttpClientTransportConfig::with_uri(config.endpoint.as_str().to_owned())
                .reinit_on_expired_session(false);
        if let Some(token) = config.bearer_token.as_ref() {
            transport_config = transport_config.auth_header(token.expose_secret().to_owned());
        }
        let http = match route {
            Some(route) => HttpClient::with_route(config.request_timeout, route)?,
            None => HttpClient::new(config.request_timeout)?,
        };
        let transport = StreamableHttpClientTransport::with_client(http, transport_config);
        let subscriptions = Arc::new(ResourceSubscriptions::default());
        let service = connect_transport(
            transport,
            config.connect_timeout,
            GtaClientHandler {
                sampling,
                events: Arc::clone(&events),
                subscriptions: Arc::clone(&subscriptions),
            },
        )
        .await?;
        Ok(Self {
            service,
            request_timeout: config.request_timeout,
            child_pid: None,
            stderr_drain: None,
            subscriptions,
            events,
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
        let subscriptions = Arc::new(ResourceSubscriptions::default());
        let service = connect_transport(
            transport,
            connect_timeout,
            GtaClientHandler {
                sampling,
                events: Arc::clone(&events),
                subscriptions: Arc::clone(&subscriptions),
            },
        )
        .await?;
        Ok(Self {
            service,
            request_timeout,
            child_pid: None,
            stderr_drain: None,
            subscriptions,
            events,
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
    /// At most 32 subscriptions are retained per connection. Updates are admitted
    /// only for confirmed subscriptions; an update received while awaiting success
    /// is coalesced into one advisory notification. Failed or dropped attempts stay
    /// unresolved until the connection closes and are never automatically retried.
    ///
    /// # Errors
    ///
    /// Returns [`McpError::Timeout`] when the server does not acknowledge
    /// `resources/subscribe` within the configured request timeout, and
    /// [`McpError::Service`] when the transport is already closed, the server
    /// replies with a JSON-RPC error (unknown URI, or subscriptions unsupported),
    /// or it answers with anything other than an empty result.
    pub async fn subscribe(&self, request: SubscribeRequestParams) -> Result<(), McpError> {
        if !self.server_info().is_some_and(|info| {
            info.capabilities
                .resources
                .as_ref()
                .is_some_and(|resources| resources.subscribe == Some(true))
        }) {
            return Err(McpError::Protocol(
                "MCP server does not advertise resource subscriptions".into(),
            ));
        }
        let attempt = self.subscriptions.begin(&request.uri, true)?;
        let uri = request.uri.clone();
        match self
            .cancellable_request(ClientRequest::SubscribeRequest(SubscribeRequest::new(
                request,
            )))
            .await?
        {
            ServerResult::EmptyResult(_) => {
                if attempt.confirm()? && self.subscriptions.changed(&uri) {
                    self.events.emit(McpClientEvent::ResourceUpdated(
                        ResourceUpdatedNotificationParam::new(uri),
                    ));
                }
                Ok(())
            }
            _ => Err(McpError::Service(ServiceError::UnexpectedResponse)),
        }
    }

    /// Unsubscribes from a server resource.
    ///
    /// Local updates stop before the remote request is sent. Failure leaves an
    /// unresolved slot rather than reopening the stream or retrying automatically.
    ///
    /// # Errors
    ///
    /// Returns [`McpError::Timeout`] when the server does not acknowledge
    /// `resources/unsubscribe` within the configured request timeout, and
    /// [`McpError::Service`] when the transport is already closed, the server
    /// replies with a JSON-RPC error (no such subscription), or it answers with
    /// anything other than an empty result.
    pub async fn unsubscribe(&self, request: UnsubscribeRequestParams) -> Result<(), McpError> {
        let attempt = self.subscriptions.begin(&request.uri, false)?;
        match self
            .cancellable_request(ClientRequest::UnsubscribeRequest(UnsubscribeRequest::new(
                request,
            )))
            .await?
        {
            ServerResult::EmptyResult(_) => {
                attempt.confirm()?;
                Ok(())
            }
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
        self.subscriptions.close();
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
    fn resource_subscription_state_bounds_and_fences_unconfirmed_notifications() {
        let subscriptions = Arc::new(ResourceSubscriptions::default());
        let uri = "gta://fixture/resource";
        assert!(!subscriptions.changed(uri));
        let pending = subscriptions
            .begin(uri, true)
            .expect("pending subscription");
        assert!(!subscriptions.changed(uri));
        assert!(subscriptions.begin(uri, true).is_err());
        assert!(pending.confirm().expect("confirm subscription"));
        assert!(subscriptions.changed(uri));
        assert!(!subscriptions.changed("gta://other/resource"));
        let ending = subscriptions.begin(uri, false).expect("unsubscribe");
        assert!(!subscriptions.changed(uri));
        drop(ending);
        assert!(!subscriptions.changed(uri));
        assert!(subscriptions.begin(uri, false).is_err());
        assert!(subscriptions.begin(uri, true).is_err());
        for index in 1..MAX_RESOURCE_SUBSCRIPTIONS {
            drop(
                subscriptions
                    .begin(&format!("gta://fixture/{index}"), true)
                    .expect("bounded pending attempt"),
            );
        }
        assert!(subscriptions.begin("gta://fixture/overflow", true).is_err());
        subscriptions.close();
        assert!(subscriptions.0.lock().expect("state").entries.is_empty());
        assert!(subscriptions.begin(uri, true).is_err());
    }

    #[test]
    fn resource_subscription_success_releases_only_the_confirmed_uri() {
        let subscriptions = Arc::new(ResourceSubscriptions::default());
        for invalid in [
            "relative",
            "gta://user@fixture/resource",
            "gta://fixture/one/../resource",
            "gta://fixture/resource#fragment",
        ] {
            assert!(subscriptions.begin(invalid, true).is_err());
        }
        let uri = "gta://fixture/resource";
        assert!(
            !subscriptions
                .begin(uri, true)
                .expect("begin")
                .confirm()
                .expect("subscribed")
        );
        assert!(
            !subscriptions
                .begin(uri, false)
                .expect("end")
                .confirm()
                .expect("unsubscribed")
        );
        assert!(!subscriptions.changed(uri));
        let waiting = subscriptions
            .begin(uri, true)
            .expect("later explicit subscription");
        subscriptions.close();
        assert!(waiting.confirm().is_err());
    }

    #[test]
    fn stdio_keyring_reference_binds_server_executable_and_case_insensitive_environment() {
        let sha256 = "a".repeat(64);
        let reference = StdioClientConfig::keyring_reference("fixture", &sha256, "API_TOKEN")
            .expect("bound reference");
        assert_eq!(
            reference,
            "keyring://gta-claw.mcp-stdio/40a283599638f90cecef13594dbcfb48de901969a6ecfaf55a7dacd00887f5f3"
        );
        let account = reference
            .strip_prefix("keyring://gta-claw.mcp-stdio/")
            .expect("dedicated namespace");
        assert_eq!(account.len(), 64);
        assert!(
            account
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        );
        assert_eq!(
            reference,
            StdioClientConfig::keyring_reference("fixture", &sha256, "api_token")
                .expect("same Windows variable")
        );
        for (server, digest, variable) in [
            ("other", sha256.as_str(), "API_TOKEN"),
            (
                "fixture",
                "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
                "API_TOKEN",
            ),
            ("fixture", sha256.as_str(), "OTHER_TOKEN"),
        ] {
            assert_ne!(
                reference,
                StdioClientConfig::keyring_reference(server, digest, variable)
                    .expect("distinct binding")
            );
        }
        for (server, digest, variable) in [
            ("", sha256.as_str(), "API_TOKEN"),
            ("bad/server", sha256.as_str(), "API_TOKEN"),
            ("fixture", "not-a-sha", "API_TOKEN"),
            ("fixture", sha256.as_str(), ""),
            ("fixture", sha256.as_str(), "API=TOKEN"),
            ("fixture", sha256.as_str(), "API\nTOKEN"),
        ] {
            assert!(StdioClientConfig::keyring_reference(server, digest, variable).is_err());
        }
    }

    #[test]
    fn stdio_debug_output_redacts_arguments_and_environment_values() {
        let mut config = StdioClientConfig::new("owned-fixture");
        config.arguments.push("private-argument-content".into());
        config
            .environment
            .insert("EXPLICIT_VALUE".into(), "private-environment-value".into());
        let transport = crate::registry::ServerTransportConfig::Stdio {
            command: config.program.clone(),
            arguments: vec!["private-argument-content".to_owned()],
            environment: std::collections::BTreeMap::from([(
                "EXPLICIT_VALUE".to_owned(),
                "private-environment-value".to_owned(),
            )]),
        };
        for rendered in [format!("{config:?}"), format!("{transport:?}")] {
            assert!(!rendered.contains("private-argument-content"));
            assert!(!rendered.contains("private-environment-value"));
            assert!(rendered.contains("EXPLICIT_VALUE"));
            assert!(rendered.contains("argument_count: 1"));
        }
    }

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

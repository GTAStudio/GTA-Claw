//! Configuration and lifecycle registry for external MCP servers.

use std::{
    collections::{BTreeMap, HashMap},
    ffi::OsString,
    fmt,
    future::Future,
    path::PathBuf,
    pin::Pin,
    sync::{Arc, Mutex as StdMutex},
    time::Duration,
};

use http::header::{AUTHORIZATION, HeaderValue};
use rmcp::model::{ListToolsResult, ServerInfo};
use secrecy::{ExposeSecret, SecretString};
use serde::{Deserialize, Serialize};
use tokio::sync::{Mutex, RwLock};
use url::Url;

use crate::{
    client::{ClientEventSink, HttpClientConfig, McpClient, SamplingPort, StdioClientConfig},
    error::{McpError, Result},
    oauth::CredentialBinding,
    sse::LegacySseConfig,
};

const PROBE_CANCELLATION_GRACE: Duration = Duration::from_millis(250);

/// Future returned by registry authentication ports.
pub type RegistryFuture<'a, T> = Pin<Box<dyn Future<Output = Result<T>> + Send + 'a>>;

/// Registry bearer credential carrying its approved resource origin.
pub struct RegistryBearer {
    binding: CredentialBinding,
    token: SecretString,
}

impl RegistryBearer {
    /// Wraps a bearer token with the exact binding used to authorize it.
    #[must_use]
    pub fn new(binding: CredentialBinding, token: SecretString) -> Self {
        Self { binding, token }
    }

    fn into_token_for(self, expected: &CredentialBinding) -> Result<SecretString> {
        if self.binding != *expected {
            return Err(McpError::Protocol(
                "OAuth credential binding does not match the configured MCP origin".into(),
            ));
        }
        Ok(self.token)
    }
}

impl fmt::Debug for RegistryBearer {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RegistryBearer")
            .field("binding", &self.binding)
            .field("token", &"[REDACTED]")
            .finish()
    }
}

/// Authentication integration used by configured remote MCP servers.
pub trait RegistryAuthPort: Send + Sync + 'static {
    /// Returns a fresh bearer token for an origin-bound profile.
    fn bearer_token<'a>(
        &'a self,
        binding: &'a CredentialBinding,
    ) -> RegistryFuture<'a, RegistryBearer>;
    /// Starts an interactive login and returns the browser URL.
    fn login<'a>(&'a self, binding: &'a CredentialBinding) -> RegistryFuture<'a, Url>;
    /// Completes a previously started login callback.
    fn complete_login<'a>(
        &'a self,
        binding: &'a CredentialBinding,
        code: &'a str,
        state: &'a str,
    ) -> RegistryFuture<'a, ()>;
    /// Deletes credentials for an origin-bound profile.
    fn logout<'a>(&'a self, binding: &'a CredentialBinding) -> RegistryFuture<'a, ()>;
}

/// Authentication port that rejects operations when OAuth is not configured.
#[derive(Debug, Default)]
pub struct NoRegistryAuth;

impl RegistryAuthPort for NoRegistryAuth {
    fn bearer_token<'a>(
        &'a self,
        binding: &'a CredentialBinding,
    ) -> RegistryFuture<'a, RegistryBearer> {
        Box::pin(async move {
            Err(McpError::Protocol(format!(
                "OAuth profile is not configured: {}",
                binding.profile()
            )))
        })
    }

    fn login<'a>(&'a self, binding: &'a CredentialBinding) -> RegistryFuture<'a, Url> {
        Box::pin(async move {
            Err(McpError::Protocol(format!(
                "OAuth profile is not configured: {}",
                binding.profile()
            )))
        })
    }

    fn complete_login<'a>(
        &'a self,
        binding: &'a CredentialBinding,
        _code: &'a str,
        _state: &'a str,
    ) -> RegistryFuture<'a, ()> {
        Box::pin(async move {
            Err(McpError::Protocol(format!(
                "OAuth profile is not configured: {}",
                binding.profile()
            )))
        })
    }

    fn logout<'a>(&'a self, binding: &'a CredentialBinding) -> RegistryFuture<'a, ()> {
        Box::pin(async move {
            Err(McpError::Protocol(format!(
                "OAuth profile is not configured: {}",
                binding.profile()
            )))
        })
    }
}

/// Persistent storage port for MCP server configurations.
pub trait RegistryStore: Send + Sync + 'static {
    /// Loads all configured servers.
    fn load(&self) -> Result<Vec<ServerConfig>>;
    /// Atomically replaces all configured servers.
    fn save(&self, servers: &[ServerConfig]) -> Result<()>;
}

/// In-memory registry store for ephemeral runtimes and tests.
#[derive(Debug, Default)]
pub struct MemoryRegistryStore {
    servers: StdMutex<Vec<ServerConfig>>,
}

impl RegistryStore for MemoryRegistryStore {
    fn load(&self) -> Result<Vec<ServerConfig>> {
        self.servers
            .lock()
            .map_err(|_| McpError::Lifecycle("registry store lock poisoned".into()))
            .map(|servers| servers.clone())
    }

    fn save(&self, servers: &[ServerConfig]) -> Result<()> {
        *self
            .servers
            .lock()
            .map_err(|_| McpError::Lifecycle("registry store lock poisoned".into()))? =
            servers.to_vec();
        Ok(())
    }
}

/// Transport configuration for one external MCP server.
#[derive(Clone, Deserialize, Eq, PartialEq, Serialize)]
#[serde(tag = "transport", rename_all = "snake_case")]
#[non_exhaustive]
pub enum ServerTransportConfig {
    /// Child process connected through newline-delimited stdio.
    Stdio {
        /// Executable path.
        command: PathBuf,
        /// Process arguments.
        #[serde(default)]
        arguments: Vec<String>,
        /// Process environment additions.
        #[serde(default)]
        environment: BTreeMap<String, String>,
    },
    /// MCP streamable HTTP endpoint.
    Http {
        /// Endpoint URL.
        url: String,
    },
    /// Legacy MCP HTTP+SSE endpoint.
    Sse {
        /// SSE endpoint URL.
        url: String,
    },
}

impl fmt::Debug for ServerTransportConfig {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Stdio {
                command,
                arguments,
                environment,
            } => formatter
                .debug_struct("Stdio")
                .field("command", command)
                .field("arguments", arguments)
                .field(
                    "environment",
                    &environment.keys().map(String::as_str).collect::<Vec<_>>(),
                )
                .finish(),
            Self::Http { url } => formatter.debug_struct("Http").field("url", url).finish(),
            Self::Sse { url } => formatter.debug_struct("Sse").field("url", url).finish(),
        }
    }
}

/// Persistent configuration for one MCP server.
#[derive(Clone, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ServerConfig {
    /// Stable unique server name.
    pub name: String,
    /// Whether the registry should start this server.
    pub enabled: bool,
    /// Transport used to reach the server.
    pub transport: ServerTransportConfig,
    /// Optional OAuth credential profile for HTTP transports.
    pub auth_profile: Option<String>,
    /// Initialize handshake timeout in milliseconds.
    pub connect_timeout_ms: u64,
    /// Per-request timeout in milliseconds.
    pub request_timeout_ms: u64,
}

impl fmt::Debug for ServerConfig {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ServerConfig")
            .field("name", &self.name)
            .field("enabled", &self.enabled)
            .field("transport", &self.transport)
            .field("auth_profile", &self.auth_profile)
            .field("connect_timeout_ms", &self.connect_timeout_ms)
            .field("request_timeout_ms", &self.request_timeout_ms)
            .finish()
    }
}

impl ServerConfig {
    /// Creates a server configuration with bounded default timeouts.
    #[must_use]
    pub fn new(name: impl Into<String>, transport: ServerTransportConfig) -> Self {
        Self {
            name: name.into(),
            enabled: true,
            transport,
            auth_profile: None,
            connect_timeout_ms: 15_000,
            request_timeout_ms: 30_000,
        }
    }

    fn validate(&self) -> Result<()> {
        if self.name.trim().is_empty() {
            return Err(McpError::Protocol(
                "MCP server name must not be empty".into(),
            ));
        }
        if self.connect_timeout_ms == 0 || self.request_timeout_ms == 0 {
            return Err(McpError::Protocol(
                "MCP server timeouts must be greater than zero".into(),
            ));
        }
        match &self.transport {
            ServerTransportConfig::Stdio { command, .. } => {
                if command.as_os_str().is_empty() {
                    return Err(McpError::Protocol(
                        "MCP stdio command must not be empty".into(),
                    ));
                }
                if self.auth_profile.is_some() {
                    return Err(McpError::Protocol(
                        "OAuth profiles are only valid for remote MCP transports".into(),
                    ));
                }
                Ok(())
            }
            ServerTransportConfig::Http { url } | ServerTransportConfig::Sse { url } => {
                let parsed = Url::parse(url)?;
                if !matches!(parsed.scheme(), "http" | "https") {
                    return Err(McpError::Protocol(
                        "remote MCP URL must use HTTP or HTTPS".into(),
                    ));
                }
                if self.auth_profile.is_some() && !crate::endpoint_allows_credentials(&parsed) {
                    return Err(McpError::Protocol(
                        "authenticated MCP URLs must use HTTPS unless they are loopback HTTP URLs"
                            .into(),
                    ));
                }
                Ok(())
            }
        }
    }

    fn credential_binding(&self) -> Result<Option<CredentialBinding>> {
        let Some(profile) = self.auth_profile.as_deref() else {
            return Ok(None);
        };
        let url = match &self.transport {
            ServerTransportConfig::Http { url } | ServerTransportConfig::Sse { url } => {
                Url::parse(url)?
            }
            ServerTransportConfig::Stdio { .. } => {
                return Err(McpError::Protocol(
                    "OAuth profiles are only valid for remote MCP transports".into(),
                ));
            }
        };
        Ok(Some(CredentialBinding::new(profile, &url)?))
    }
}

/// Mutable fields accepted by the registry's configure operation.
#[derive(Clone, Debug, Default)]
pub struct ServerConfigPatch {
    /// Replacement transport.
    pub transport: Option<ServerTransportConfig>,
    /// Replacement enabled state.
    pub enabled: Option<bool>,
    /// Replacement OAuth profile. `Some(None)` clears it.
    pub auth_profile: Option<Option<String>>,
    /// Replacement initialize timeout.
    pub connect_timeout_ms: Option<u64>,
    /// Replacement request timeout.
    pub request_timeout_ms: Option<u64>,
}

/// Runtime lifecycle state for one configured server.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum ServerState {
    /// Configuration is disabled.
    Disabled,
    /// Server is configured but not connected.
    Stopped,
    /// A connection is being established.
    Starting,
    /// Initialize negotiation completed.
    Healthy,
    /// The most recent start or probe failed.
    Unhealthy,
}

/// Observable registry status for one server.
#[derive(Clone, Debug)]
pub struct ServerStatus {
    /// Stable server name.
    pub name: String,
    /// Current lifecycle state.
    pub state: ServerState,
    /// Last non-sensitive lifecycle error.
    pub last_error: Option<String>,
    /// Negotiated server information when connected.
    pub server_info: Option<Arc<ServerInfo>>,
    /// Child PID for stdio transports.
    pub child_pid: Option<u32>,
}

/// One registry doctor result.
#[derive(Clone, Debug)]
pub struct DoctorReport {
    /// Stable server name.
    pub name: String,
    /// Whether configuration and an active protocol probe succeeded.
    pub healthy: bool,
    /// Diagnostic message without credentials.
    pub message: String,
}

struct RegistryEntry {
    config: ServerConfig,
    client: Option<McpClient>,
    state: ServerState,
    last_error: Option<String>,
}

/// Persistent registry and lifecycle manager for external MCP servers.
pub struct McpRegistry {
    store: Arc<dyn RegistryStore>,
    auth: Arc<dyn RegistryAuthPort>,
    sampling: Arc<dyn SamplingPort>,
    events: Arc<dyn ClientEventSink>,
    entries: RwLock<BTreeMap<String, Arc<Mutex<RegistryEntry>>>>,
    operations: Mutex<()>,
}

impl fmt::Debug for McpRegistry {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("McpRegistry")
            .finish_non_exhaustive()
    }
}

impl McpRegistry {
    /// Loads a registry from persistent configuration.
    pub fn load(
        store: Arc<dyn RegistryStore>,
        auth: Arc<dyn RegistryAuthPort>,
        sampling: Arc<dyn SamplingPort>,
        events: Arc<dyn ClientEventSink>,
    ) -> Result<Self> {
        let mut entries = BTreeMap::new();
        for config in store.load()? {
            config.validate()?;
            if entries.contains_key(&config.name) {
                return Err(McpError::DuplicateServer(config.name));
            }
            let state = if config.enabled {
                ServerState::Stopped
            } else {
                ServerState::Disabled
            };
            entries.insert(
                config.name.clone(),
                Arc::new(Mutex::new(RegistryEntry {
                    config,
                    client: None,
                    state,
                    last_error: None,
                })),
            );
        }
        Ok(Self {
            store,
            auth,
            sampling,
            events,
            entries: RwLock::new(entries),
            operations: Mutex::new(()),
        })
    }

    /// Lists all configured servers in stable name order.
    pub async fn list(&self) -> Vec<ServerConfig> {
        let entries = self.entries.read().await;
        let handles = entries.values().cloned().collect::<Vec<_>>();
        drop(entries);
        let mut configs = Vec::with_capacity(handles.len());
        for handle in handles {
            configs.push(handle.lock().await.config.clone());
        }
        configs
    }

    /// Shows one server configuration.
    pub async fn show(&self, name: &str) -> Result<ServerConfig> {
        let entry = self.entry(name).await?;
        let config = entry.lock().await.config.clone();
        Ok(config)
    }

    /// Adds a new server configuration.
    pub async fn add(&self, config: ServerConfig) -> Result<()> {
        let _operation = self.operations.lock().await;
        config.validate()?;
        let mut entries = self.entries.write().await;
        if entries.contains_key(&config.name) {
            return Err(McpError::DuplicateServer(config.name));
        }
        let state = if config.enabled {
            ServerState::Stopped
        } else {
            ServerState::Disabled
        };
        entries.insert(
            config.name.clone(),
            Arc::new(Mutex::new(RegistryEntry {
                config,
                client: None,
                state,
                last_error: None,
            })),
        );
        drop(entries);
        self.persist().await
    }

    /// Replaces an existing server configuration.
    pub async fn set(&self, config: ServerConfig) -> Result<()> {
        let _operation = self.operations.lock().await;
        self.set_inner(config).await
    }

    async fn set_inner(&self, config: ServerConfig) -> Result<()> {
        config.validate()?;
        let old_config = self.show(&config.name).await?;
        let old_binding = old_config.credential_binding()?;
        let new_binding = config.credential_binding()?;
        self.stop_inner(&config.name).await?;
        if old_binding != new_binding
            && let Some(binding) = old_binding.as_ref()
        {
            self.auth.logout(binding).await?;
        }
        let entry = self.entry(&config.name).await?;
        let mut entry = entry.lock().await;
        entry.state = if config.enabled {
            ServerState::Stopped
        } else {
            ServerState::Disabled
        };
        entry.config = config;
        entry.last_error = None;
        drop(entry);
        self.persist().await
    }

    /// Updates selected fields of an existing server configuration.
    pub async fn configure(&self, name: &str, patch: ServerConfigPatch) -> Result<ServerConfig> {
        let _operation = self.operations.lock().await;
        let mut config = self.show(name).await?;
        if let Some(transport) = patch.transport {
            config.transport = transport;
        }
        if let Some(enabled) = patch.enabled {
            config.enabled = enabled;
        }
        if let Some(auth_profile) = patch.auth_profile {
            config.auth_profile = auth_profile;
        }
        if let Some(timeout) = patch.connect_timeout_ms {
            config.connect_timeout_ms = timeout;
        }
        if let Some(timeout) = patch.request_timeout_ms {
            config.request_timeout_ms = timeout;
        }
        self.set_inner(config.clone()).await?;
        Ok(config)
    }

    /// Removes a configured server and stops its process or transport.
    pub async fn unset(&self, name: &str) -> Result<ServerConfig> {
        let _operation = self.operations.lock().await;
        self.stop_inner(name).await?;
        let entry = self
            .entries
            .write()
            .await
            .remove(name)
            .ok_or_else(|| McpError::UnknownServer(name.to_owned()))?;
        let config = entry.lock().await.config.clone();
        self.persist().await?;
        Ok(config)
    }

    /// Enables and starts a configured server.
    pub async fn enable(&self, name: &str) -> Result<ServerStatus> {
        let _operation = self.operations.lock().await;
        {
            let entry = self.entry(name).await?;
            let mut entry = entry.lock().await;
            entry.config.enabled = true;
            entry.state = ServerState::Stopped;
        }
        self.persist().await?;
        self.start_inner(name).await
    }

    /// Disables and stops a configured server.
    pub async fn disable(&self, name: &str) -> Result<ServerStatus> {
        let _operation = self.operations.lock().await;
        self.stop_inner(name).await?;
        {
            let entry = self.entry(name).await?;
            let mut entry = entry.lock().await;
            entry.config.enabled = false;
            entry.state = ServerState::Disabled;
        }
        self.persist().await?;
        self.status(name).await
    }

    /// Starts one configured server and performs initialize negotiation.
    pub async fn start(&self, name: &str) -> Result<ServerStatus> {
        let _operation = self.operations.lock().await;
        self.start_inner(name).await
    }

    async fn start_inner(&self, name: &str) -> Result<ServerStatus> {
        let handle = self.entry(name).await?;
        let mut entry = handle.lock().await;
        if !entry.config.enabled {
            entry.state = ServerState::Disabled;
            return Err(McpError::Lifecycle(format!(
                "MCP server is disabled: {name}"
            )));
        }
        if entry.client.is_some() {
            return status_from_entry(&entry);
        }
        entry.state = ServerState::Starting;
        entry.last_error = None;
        let config = entry.config.clone();
        let binding = config.credential_binding()?;
        let bearer = if let Some(binding) = binding.as_ref() {
            match self.auth.bearer_token(binding).await {
                Ok(token) => match token.into_token_for(binding) {
                    Ok(token) => Some(token),
                    Err(error) => {
                        entry.state = ServerState::Unhealthy;
                        entry.last_error = Some(error.to_string());
                        return Err(error);
                    }
                },
                Err(error) => {
                    entry.state = ServerState::Unhealthy;
                    entry.last_error = Some(error.to_string());
                    return Err(error);
                }
            }
        } else {
            None
        };
        match self.connect(&config, bearer).await {
            Ok(client) => {
                entry.client = Some(client);
                entry.state = ServerState::Healthy;
                status_from_entry(&entry)
            }
            Err(error) => {
                entry.state = ServerState::Unhealthy;
                entry.last_error = Some(error.to_string());
                Err(error)
            }
        }
    }

    /// Stops one configured server and waits for transport cleanup.
    pub async fn stop(&self, name: &str) -> Result<ServerStatus> {
        let _operation = self.operations.lock().await;
        self.stop_inner(name).await
    }

    async fn stop_inner(&self, name: &str) -> Result<ServerStatus> {
        let handle = self.entry(name).await?;
        let mut entry = handle.lock().await;
        if let Some(client) = entry.client.take()
            && let Err(error) = client.close().await
        {
            entry.state = ServerState::Unhealthy;
            entry.last_error = Some(error.to_string());
            return Err(error);
        }
        entry.state = if entry.config.enabled {
            ServerState::Stopped
        } else {
            ServerState::Disabled
        };
        status_from_entry(&entry)
    }

    /// Stops and starts one configured server.
    pub async fn restart(&self, name: &str) -> Result<ServerStatus> {
        let _operation = self.operations.lock().await;
        self.stop_inner(name).await?;
        self.start_inner(name).await
    }

    /// Returns current runtime status.
    pub async fn status(&self, name: &str) -> Result<ServerStatus> {
        let entry = self.entry(name).await?;
        let status = status_from_entry(&*entry.lock().await)?;
        Ok(status)
    }

    /// Returns negotiated server capabilities.
    pub async fn capabilities(&self, name: &str) -> Result<Arc<ServerInfo>> {
        let entry = self.entry(name).await?;
        let entry = entry.lock().await;
        let client = entry
            .client
            .as_ref()
            .ok_or_else(|| McpError::Lifecycle(format!("MCP server is not running: {name}")))?;
        client.server_info().ok_or_else(|| {
            McpError::Lifecycle(format!("MCP server has no initialize result: {name}"))
        })
    }

    /// Refreshes and returns the server's tool catalog.
    pub async fn tools(&self, name: &str) -> Result<ListToolsResult> {
        let entry = self.entry(name).await?;
        let entry = entry.lock().await;
        let client = entry
            .client
            .as_ref()
            .ok_or_else(|| McpError::Lifecycle(format!("MCP server is not running: {name}")))?;
        client.list_tools().await
    }

    /// Probes a server, temporarily connecting when it is not already running.
    pub async fn probe(&self, name: &str) -> Result<ServerStatus> {
        let _operation = self.operations.lock().await;
        self.probe_inner(name).await
    }

    async fn probe_inner(&self, name: &str) -> Result<ServerStatus> {
        let originally_running = {
            let entry = self.entry(name).await?;
            entry.lock().await.client.is_some()
        };
        let status = self.start_inner(name).await?;
        let tools = self.tools(name).await;
        if !originally_running {
            if matches!(&tools, Err(McpError::Timeout(_))) {
                // The timeout queues an MCP cancellation notification. Give the
                // external server a bounded window to consume it before teardown.
                tokio::time::sleep(PROBE_CANCELLATION_GRACE).await;
            }
            let cleanup = self.stop_inner(name).await;
            if let Err(error) = tools {
                return Err(match cleanup {
                    Ok(_) => error,
                    Err(cleanup) => McpError::Lifecycle(format!(
                        "{error}; additionally failed to stop temporary probe connection: {cleanup}"
                    )),
                });
            }
            cleanup?;
        } else {
            tools?;
        }
        Ok(status)
    }

    /// Runs configuration validation and protocol probes for all enabled servers.
    pub async fn doctor(&self) -> Vec<DoctorReport> {
        let configs = self.list().await;
        let mut reports = Vec::with_capacity(configs.len());
        for config in configs {
            let report = if let Err(error) = config.validate() {
                DoctorReport {
                    name: config.name,
                    healthy: false,
                    message: error.to_string(),
                }
            } else if !config.enabled {
                DoctorReport {
                    name: config.name,
                    healthy: true,
                    message: "disabled configuration is valid".into(),
                }
            } else {
                match self.probe(&config.name).await {
                    Ok(_) => DoctorReport {
                        name: config.name,
                        healthy: true,
                        message: "initialize and tools/list succeeded".into(),
                    },
                    Err(error) => DoctorReport {
                        name: config.name,
                        healthy: false,
                        message: error.to_string(),
                    },
                }
            };
            reports.push(report);
        }
        reports
    }

    /// Starts OAuth login for one configured server.
    pub async fn login(&self, name: &str) -> Result<Url> {
        let config = self.show(name).await?;
        let binding = config.credential_binding()?.ok_or_else(|| {
            McpError::Protocol(format!("MCP server has no OAuth profile: {name}"))
        })?;
        self.auth.login(&binding).await
    }

    /// Completes OAuth login for one configured server.
    pub async fn complete_login(&self, name: &str, code: &str, state: &str) -> Result<()> {
        let config = self.show(name).await?;
        let binding = config.credential_binding()?.ok_or_else(|| {
            McpError::Protocol(format!("MCP server has no OAuth profile: {name}"))
        })?;
        self.auth.complete_login(&binding, code, state).await
    }

    /// Logs out one configured server and stops its authenticated connection.
    pub async fn logout(&self, name: &str) -> Result<()> {
        let _operation = self.operations.lock().await;
        self.stop_inner(name).await?;
        let config = self.show(name).await?;
        let binding = config.credential_binding()?.ok_or_else(|| {
            McpError::Protocol(format!("MCP server has no OAuth profile: {name}"))
        })?;
        self.auth.logout(&binding).await
    }

    /// Reloads persistent configuration, stopping all existing connections first.
    pub async fn reload(&self) -> Result<()> {
        let _operation = self.operations.lock().await;
        let names = self
            .entries
            .read()
            .await
            .keys()
            .cloned()
            .collect::<Vec<_>>();
        for name in names {
            self.stop_inner(&name).await?;
        }
        let configs = self.store.load()?;
        let mut replacement = BTreeMap::new();
        for config in configs {
            config.validate()?;
            if replacement.contains_key(&config.name) {
                return Err(McpError::DuplicateServer(config.name));
            }
            let state = if config.enabled {
                ServerState::Stopped
            } else {
                ServerState::Disabled
            };
            replacement.insert(
                config.name.clone(),
                Arc::new(Mutex::new(RegistryEntry {
                    config,
                    client: None,
                    state,
                    last_error: None,
                })),
            );
        }
        *self.entries.write().await = replacement;
        Ok(())
    }

    /// Starts every enabled configured server.
    pub async fn start_enabled(&self) -> Vec<(String, Result<ServerStatus>)> {
        let names = self
            .list()
            .await
            .into_iter()
            .filter(|config| config.enabled)
            .map(|config| config.name)
            .collect::<Vec<_>>();
        let mut results = Vec::with_capacity(names.len());
        for name in names {
            results.push((name.clone(), self.start(&name).await));
        }
        results
    }

    async fn connect(
        &self,
        config: &ServerConfig,
        bearer: Option<SecretString>,
    ) -> Result<McpClient> {
        let connect_timeout = Duration::from_millis(config.connect_timeout_ms);
        let request_timeout = Duration::from_millis(config.request_timeout_ms);
        match &config.transport {
            ServerTransportConfig::Stdio {
                command,
                arguments,
                environment,
            } => {
                if bearer.is_some() {
                    return Err(McpError::Protocol(
                        "OAuth profiles cannot be attached to stdio MCP servers".into(),
                    ));
                }
                let mut client_config = StdioClientConfig::new(command);
                client_config.arguments = arguments.iter().map(OsString::from).collect();
                client_config.environment = environment
                    .iter()
                    .map(|(key, value)| (OsString::from(key), OsString::from(value)))
                    .collect::<HashMap<_, _>>();
                client_config.connect_timeout = connect_timeout;
                client_config.request_timeout = request_timeout;
                McpClient::connect_stdio(client_config, self.sampling.clone(), self.events.clone())
                    .await
            }
            ServerTransportConfig::Http { url } => {
                let mut client_config = HttpClientConfig::new(Url::parse(url)?);
                client_config.bearer_token = bearer;
                client_config.connect_timeout = connect_timeout;
                client_config.request_timeout = request_timeout;
                McpClient::connect_http(client_config, self.sampling.clone(), self.events.clone())
                    .await
            }
            ServerTransportConfig::Sse { url } => {
                let mut client_config = LegacySseConfig::new(Url::parse(url)?);
                client_config.request_timeout = request_timeout;
                if let Some(token) = bearer {
                    let mut header =
                        HeaderValue::from_str(&format!("Bearer {}", token.expose_secret()))
                            .map_err(|_| {
                                McpError::Protocol(
                                    "OAuth token cannot be encoded as an HTTP header".into(),
                                )
                            })?;
                    header.set_sensitive(true);
                    client_config.headers.insert(AUTHORIZATION, header);
                }
                McpClient::connect_sse(client_config, self.sampling.clone(), self.events.clone())
                    .await
            }
        }
    }

    async fn entry(&self, name: &str) -> Result<Arc<Mutex<RegistryEntry>>> {
        self.entries
            .read()
            .await
            .get(name)
            .cloned()
            .ok_or_else(|| McpError::UnknownServer(name.to_owned()))
    }

    async fn persist(&self) -> Result<()> {
        self.store.save(&self.list().await)
    }
}

fn status_from_entry(entry: &RegistryEntry) -> Result<ServerStatus> {
    Ok(ServerStatus {
        name: entry.config.name.clone(),
        state: entry.state,
        last_error: entry.last_error.clone(),
        server_info: entry.client.as_ref().and_then(McpClient::server_info),
        child_pid: entry.client.as_ref().and_then(McpClient::child_pid),
    })
}

#[cfg(test)]
mod tests {
    #[derive(Debug, Default)]
    struct RecordingAuth {
        calls: StdMutex<Vec<String>>,
    }

    impl RegistryAuthPort for RecordingAuth {
        fn bearer_token<'a>(
            &'a self,
            binding: &'a CredentialBinding,
        ) -> RegistryFuture<'a, RegistryBearer> {
            Box::pin(async move {
                Ok(RegistryBearer::new(
                    binding.clone(),
                    SecretString::from(format!("bearer-for-{}", binding.profile())),
                ))
            })
        }

        fn login<'a>(&'a self, binding: &'a CredentialBinding) -> RegistryFuture<'a, Url> {
            self.calls.lock().expect("auth call lock").push(format!(
                "login:{}:{}",
                binding.profile(),
                binding.resource_origin()
            ));
            Box::pin(async {
                Url::parse("http://127.0.0.1/authorize")
                    .map_err(|error| McpError::Protocol(error.to_string()))
            })
        }

        fn complete_login<'a>(
            &'a self,
            binding: &'a CredentialBinding,
            _code: &'a str,
            _state: &'a str,
        ) -> RegistryFuture<'a, ()> {
            self.calls.lock().expect("auth call lock").push(format!(
                "complete:{}:{}",
                binding.profile(),
                binding.resource_origin()
            ));
            Box::pin(async { Ok(()) })
        }

        fn logout<'a>(&'a self, binding: &'a CredentialBinding) -> RegistryFuture<'a, ()> {
            self.calls.lock().expect("auth call lock").push(format!(
                "logout:{}:{}",
                binding.profile(),
                binding.resource_origin()
            ));
            Box::pin(async { Ok(()) })
        }
    }

    use super::*;
    use crate::client::{DiscardEvents, RejectSampling};

    fn build_registry(store: Arc<MemoryRegistryStore>) -> McpRegistry {
        McpRegistry::load(
            store,
            Arc::new(NoRegistryAuth),
            Arc::new(RejectSampling),
            Arc::new(DiscardEvents),
        )
        .expect("registry loads")
    }

    #[tokio::test]
    async fn add_configure_unset_and_reload_are_persistent() {
        let store = Arc::new(MemoryRegistryStore::default());
        let registry = build_registry(store.clone());
        let config = ServerConfig::new(
            "fixture",
            ServerTransportConfig::Http {
                url: "http://127.0.0.1:43210/mcp".into(),
            },
        );

        registry.add(config.clone()).await.expect("server added");
        assert_eq!(registry.list().await, vec![config.clone()]);
        assert_eq!(
            registry.show("fixture").await.expect("server shown"),
            config
        );

        let mut replacement = config;
        replacement.request_timeout_ms = 8_000;
        registry
            .set(replacement.clone())
            .await
            .expect("server replaced");
        assert_eq!(
            registry.show("fixture").await.expect("replacement shown"),
            replacement
        );

        let configured = registry
            .configure(
                "fixture",
                ServerConfigPatch {
                    enabled: Some(false),
                    request_timeout_ms: Some(4_000),
                    ..ServerConfigPatch::default()
                },
            )
            .await
            .expect("server configured");
        assert!(!configured.enabled);
        assert_eq!(configured.request_timeout_ms, 4_000);

        registry.reload().await.expect("registry reloaded");
        assert_eq!(
            registry
                .show("fixture")
                .await
                .expect("reloaded server shown"),
            configured
        );
        let reloaded = build_registry(store);
        assert_eq!(
            reloaded.show("fixture").await.expect("server shown"),
            configured
        );
        assert_eq!(
            reloaded
                .unset("fixture")
                .await
                .expect("server removed")
                .name,
            "fixture"
        );
        assert_eq!(reloaded.list().await, Vec::<ServerConfig>::new());
    }

    #[test]
    fn authenticated_remote_cleartext_transport_is_rejected() {
        let mut config = ServerConfig::new(
            "remote",
            ServerTransportConfig::Http {
                url: "http://mcp.example/rpc".into(),
            },
        );
        config.auth_profile = Some("work".into());

        assert_eq!(
            config
                .validate()
                .expect_err("remote cleartext bearer transport must fail")
                .to_string(),
            "MCP protocol violation: authenticated MCP URLs must use HTTPS unless they are loopback HTTP URLs"
        );

        config.transport = ServerTransportConfig::Http {
            url: "http://127.0.0.1:43210/rpc".into(),
        };
        config.validate().expect("loopback HTTP is allowed");
    }

    #[tokio::test]
    async fn login_completion_and_logout_delegate_to_the_configured_profile() {
        let auth = Arc::new(RecordingAuth::default());
        let registry = McpRegistry::load(
            Arc::new(MemoryRegistryStore::default()),
            auth.clone(),
            Arc::new(RejectSampling),
            Arc::new(DiscardEvents),
        )
        .expect("registry loads");
        let mut config = ServerConfig::new(
            "fixture",
            ServerTransportConfig::Http {
                url: "http://127.0.0.1:43210/mcp".into(),
            },
        );
        config.auth_profile = Some("fixture-auth".into());
        registry.add(config).await.expect("server added");

        assert_eq!(
            registry.login("fixture").await.expect("login URL").as_str(),
            "http://127.0.0.1/authorize"
        );
        registry
            .complete_login("fixture", "callback-code", "callback-state")
            .await
            .expect("login completed");
        registry.logout("fixture").await.expect("logout completed");
        assert_eq!(
            *auth.calls.lock().expect("auth call lock"),
            vec![
                "login:fixture-auth:http://127.0.0.1:43210",
                "complete:fixture-auth:http://127.0.0.1:43210",
                "logout:fixture-auth:http://127.0.0.1:43210"
            ]
        );
    }

    #[tokio::test]
    async fn changing_server_origin_invalidates_the_previous_credentials() {
        let auth = Arc::new(RecordingAuth::default());
        let registry = McpRegistry::load(
            Arc::new(MemoryRegistryStore::default()),
            auth.clone(),
            Arc::new(RejectSampling),
            Arc::new(DiscardEvents),
        )
        .expect("registry loads");
        let mut config = ServerConfig::new(
            "fixture",
            ServerTransportConfig::Http {
                url: "http://127.0.0.1:43210/mcp".into(),
            },
        );
        config.auth_profile = Some("fixture-auth".into());
        registry.add(config).await.expect("server added");

        registry
            .configure(
                "fixture",
                ServerConfigPatch {
                    transport: Some(ServerTransportConfig::Http {
                        url: "http://127.0.0.1:43211/mcp".into(),
                    }),
                    ..ServerConfigPatch::default()
                },
            )
            .await
            .expect("server origin changed");
        registry.login("fixture").await.expect("new-origin login");

        assert_eq!(
            *auth.calls.lock().expect("auth call lock"),
            vec![
                "logout:fixture-auth:http://127.0.0.1:43210",
                "login:fixture-auth:http://127.0.0.1:43211"
            ]
        );
    }

    #[test]
    fn debug_output_redacts_stdio_environment_values() {
        let config = ServerTransportConfig::Stdio {
            command: PathBuf::from("fixture-server"),
            arguments: vec!["--stdio".into()],
            environment: BTreeMap::from([("API_TOKEN".into(), "test-token-value".into())]),
        };

        let output = format!("{config:?}");

        assert!(!output.contains("test-token-value"));
        assert!(output.contains("API_TOKEN"));
    }
}

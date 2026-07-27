//! Production service composition over the shipped crate APIs.

use std::ffi::OsString;
use std::fmt::{self, Display, Formatter};
use std::io;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::path::PathBuf;
use std::sync::Arc;
use std::time::{Duration, Instant};

use claw_channels::{ExchangeSupport, ImplementationStatus, descriptor, exchange_support};
use claw_config::{
    ConfigSnapshot, LogLevel, MigrationDiagnostic, SecretRef, load_file,
    migrate_legacy_environment, to_json5,
};
use claw_gateway::{
    CredentialPolicy, Exposure, GatewayServer, GatewayServerConfig, ServerHandle,
    StaticAuthenticator,
};
use claw_http_api::{
    ApiConfig, ApiServices, BearerAuthenticator, BearerCredential, HttpApi, ServingStateHandle,
};
use claw_observability::{LogFormat, TelemetryConfig, TelemetryHandle};
use claw_provider_sdk::clock::{PseudoRandomJitter, SystemClock as ProviderClock};
use claw_provider_sdk::http::{
    HttpRequest, HttpTransport, Method, ProxyPolicy, TlsPolicy, TransportConfig,
};
use claw_provider_sdk::{CancelToken, Operation, Provider, SecretString};
use claw_providers::github_copilot::GitHubCopilotConfig;
use claw_providers::{GitHubCopilot, ProviderRuntime};
use claw_security::authorization::{Role, Scope, ScopeSet};
use secrecy::SecretString as GatewaySecret;
use serde_json::{Value, json};
use tokio::net::TcpListener;
use tokio::task::JoinSet;
use tokio_util::sync::CancellationToken;
use tracing::{error, info, warn};
use url::Url;

use crate::adapters::http_api::{
    AppliedReload, ConfigController, DependencyReadiness, Diagnostics, DurableSecurityAudit,
    OperatorAdmin, ProviderAdapter, SmokeProvider, UnavailableExternalPorts, UnavailableTools,
    copilot_request_timeout_ms, updates_enabled,
};

/// Whole-process shutdown ceiling.
pub const PRODUCTION_STOP_DEADLINE: Duration = Duration::from_secs(10);
const ROLE_RESPONSE_LIMIT: usize = 256 * 1024;
const DEFAULT_GATEWAY: SocketAddr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0);
const DEFAULT_MCP: SocketAddr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0);
const USAGE: &str = "usage: gta-claw-daemon [--probe | --check-config] [--config PATH] \
                     [--listen ADDRESS] [--gateway-listen ADDRESS] [--mcp-listen ADDRESS] \
                     [--state-dir PATH] [--tls-terminated-by-frontend] [--smoke]";

/// Top-level command selected by the process arguments.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CommandMode {
    /// Start the composed service.
    Serve,
    /// Print the native process health line and exit.
    Probe,
    /// Load and composition-check configuration without opening listeners.
    CheckConfig,
}

/// Parsed process command line.
#[derive(Clone, Debug)]
pub struct CommandLine {
    /// Selected mode.
    pub mode: CommandMode,
    /// Production service options.
    pub options: ProductionOptions,
}

impl CommandLine {
    /// Parses a complete command line without panicking on non-Unicode paths.
    ///
    /// # Errors
    ///
    /// Returns [`io::ErrorKind::InvalidInput`] for unknown, incomplete,
    /// non-Unicode, or mutually incompatible arguments.
    pub fn parse(arguments: impl IntoIterator<Item = OsString>) -> io::Result<Self> {
        let mut mode = CommandMode::Serve;
        let mut options = ProductionOptions::default();
        let mut arguments = arguments.into_iter();
        while let Some(argument) = arguments.next() {
            let Some(flag) = argument.to_str() else {
                return Err(usage_error());
            };
            match flag {
                "--probe" if mode == CommandMode::Serve => mode = CommandMode::Probe,
                "--check-config" if mode == CommandMode::Serve => mode = CommandMode::CheckConfig,
                "--config" => options.config_path = Some(required_path(&mut arguments, flag)?),
                "--state-dir" => options.state_dir = Some(required_path(&mut arguments, flag)?),
                "--listen" => options.http_listen = Some(required_address(&mut arguments, flag)?),
                "--gateway-listen" => {
                    options.gateway_listen = Some(required_address(&mut arguments, flag)?);
                }
                "--mcp-listen" => {
                    options.mcp_listen = Some(required_address(&mut arguments, flag)?);
                }
                "--tls-terminated-by-frontend" => options.tls_terminated_by_frontend = true,
                "--smoke" => options.smoke = true,
                _ => return Err(usage_error()),
            }
        }
        if mode != CommandMode::Serve
            && (options.http_listen.is_some()
                || options.gateway_listen.is_some()
                || options.mcp_listen.is_some()
                || options.smoke
                || options.tls_terminated_by_frontend)
        {
            return Err(usage_error());
        }
        Ok(Self { mode, options })
    }
}

fn required_path(
    arguments: &mut impl Iterator<Item = OsString>,
    flag: &str,
) -> io::Result<PathBuf> {
    arguments.next().map(PathBuf::from).ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("{flag} requires a path\n{USAGE}"),
        )
    })
}

fn required_address(
    arguments: &mut impl Iterator<Item = OsString>,
    flag: &str,
) -> io::Result<SocketAddr> {
    let value = arguments.next().ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("{flag} requires an address\n{USAGE}"),
        )
    })?;
    let value = value
        .to_str()
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, USAGE))?;
    value.parse().map_err(|error| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("{flag} has an invalid address: {error}\n{USAGE}"),
        )
    })
}

fn usage_error() -> io::Error {
    io::Error::new(io::ErrorKind::InvalidInput, USAGE)
}

/// Service construction options.
#[derive(Clone, Debug, Default)]
pub struct ProductionOptions {
    /// Strict JSON5 configuration file; legacy environment migration is used when absent.
    pub config_path: Option<PathBuf>,
    /// Main HTTP listener override.
    pub http_listen: Option<SocketAddr>,
    /// Gateway listener override.
    pub gateway_listen: Option<SocketAddr>,
    /// Loopback MCP listener override.
    pub mcp_listen: Option<SocketAddr>,
    /// Durable local state directory.
    pub state_dir: Option<PathBuf>,
    /// Explicit assertion that a frontend terminates TLS for routable binds.
    pub tls_terminated_by_frontend: bool,
    /// Use the local install-diagnostic provider.
    pub smoke: bool,
}

impl ProductionOptions {
    /// Loads strict file configuration or the audited legacy environment mapping.
    ///
    /// # Errors
    ///
    /// Returns a `config`-stage error when the file or migrated environment is
    /// not a complete valid typed configuration.
    pub fn load_config(&self) -> Result<LoadedConfig, ProductionError> {
        let configured_path = self
            .config_path
            .clone()
            .or_else(|| std::env::var_os("GTA_CLAW_CONFIG").map(PathBuf::from));
        if let Some(path) = configured_path {
            let snapshot =
                load_file(&path).map_err(|error| ProductionError::new("config", error))?;
            return Ok(LoadedConfig {
                snapshot,
                path: Some(path),
                source: "file",
                diagnostics: Vec::new(),
            });
        }

        let environment = std::env::vars_os()
            .filter_map(|(name, value)| Some((name.into_string().ok()?, value.into_string().ok()?)))
            .collect::<Vec<_>>();
        let migrated = migrate_legacy_environment(
            environment
                .iter()
                .map(|(name, value)| (name.as_str(), value.as_str())),
        )
        .map_err(|error| ProductionError::new("config", error))?;
        let diagnostics = migrated
            .diagnostics
            .into_iter()
            .map(|diagnostic| match diagnostic {
                MigrationDiagnostic::ManualRequired(mapping) => format!(
                    "{} requires manual migration to {}: {}",
                    mapping.legacy_env, mapping.target, mapping.reason
                ),
            })
            .collect();
        Ok(LoadedConfig {
            snapshot: migrated.config,
            path: None,
            source: "legacy-environment",
            diagnostics,
        })
    }

    fn state_dir(&self) -> Result<PathBuf, ProductionError> {
        if let Some(path) = self
            .state_dir
            .clone()
            .or_else(|| std::env::var_os("GTA_CLAW_STATE_DIR").map(PathBuf::from))
        {
            return Ok(path);
        }
        let home = std::env::var_os("HOME").ok_or_else(|| {
            ProductionError::message(
                "state",
                "HOME is unavailable; set --state-dir or GTA_CLAW_STATE_DIR",
            )
        })?;
        Ok(PathBuf::from(home).join(".gta-claw"))
    }
}

/// Loaded startup configuration and its reload source.
#[derive(Clone, Debug)]
pub struct LoadedConfig {
    /// Validated typed snapshot.
    pub snapshot: ConfigSnapshot,
    /// File to reread on reload, when configured.
    pub path: Option<PathBuf>,
    /// Stable source label.
    pub source: &'static str,
    /// Non-fatal migration diagnostics.
    pub diagnostics: Vec<String>,
}

/// Initializes the shared redacting telemetry subscriber from typed logging config.
///
/// # Errors
///
/// Returns a `logging`-stage error for an invalid format/filter or when another
/// global tracing subscriber is already installed.
pub fn init_telemetry(snapshot: &ConfigSnapshot) -> Result<TelemetryHandle, ProductionError> {
    let default_filter = match snapshot.core().logging().level() {
        LogLevel::Trace => "trace",
        LogLevel::Debug => "debug",
        LogLevel::Info => "info",
        LogLevel::Warn => "warn",
        LogLevel::Error | LogLevel::Fatal => "error",
    };
    let format = match std::env::var("GTA_CLAW_LOG_FORMAT").as_deref() {
        Ok("json") => LogFormat::Json,
        Ok("human") | Err(std::env::VarError::NotPresent) => LogFormat::Human,
        Ok(_) => {
            return Err(ProductionError::message(
                "logging",
                "GTA_CLAW_LOG_FORMAT must be `human` or `json`",
            ));
        }
        Err(error) => return Err(ProductionError::new("logging", error)),
    };
    claw_observability::init(&TelemetryConfig {
        format,
        default_filter: default_filter.to_owned(),
        filter_env: "GTA_CLAW_LOG".to_owned(),
    })
    .map_err(|error| ProductionError::new("logging", error))
}

/// One stage-qualified startup or runtime failure.
#[derive(Debug)]
pub struct ProductionError {
    stage: &'static str,
    detail: String,
}

impl ProductionError {
    fn new(stage: &'static str, error: impl Display) -> Self {
        Self {
            stage,
            detail: error.to_string(),
        }
    }

    fn message(stage: &'static str, detail: impl Into<String>) -> Self {
        Self {
            stage,
            detail: detail.into(),
        }
    }

    /// Returns the stable stage label.
    #[must_use]
    pub const fn stage(&self) -> &'static str {
        self.stage
    }
}

impl Display for ProductionError {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        write!(formatter, "{}: {}", self.stage, self.detail)
    }
}

impl std::error::Error for ProductionError {}

/// Remote or built-in role loaded before the provider becomes ready.
#[derive(Clone, Debug)]
struct RoleProfile {
    prompt: String,
    model: Option<String>,
}

/// Bound service addresses reported after readiness.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct BoundAddresses {
    /// Main HTTP API.
    pub http: SocketAddr,
    /// Gateway WebSocket server.
    pub gateway: SocketAddr,
    /// Loopback MCP HTTP endpoint.
    pub mcp: SocketAddr,
}

/// A complete production service after every dependency is live.
pub struct ProductionService {
    addresses: BoundAddresses,
    provider: Arc<ProviderAdapter>,
    readiness: Arc<DependencyReadiness>,
    serving: ServingStateHandle,
    config: Arc<ConfigController>,
    config_path: Option<PathBuf>,
    diagnostics: Arc<Diagnostics>,
    http_shutdown: CancellationToken,
    http_tasks: JoinSet<(&'static str, io::Result<()>)>,
    gateway: Option<ServerHandle>,
    terminated_http_tasks: u64,
}

impl ProductionService {
    /// Builds dependencies in fixed order, binds all ingress, then announces service.
    ///
    /// # Errors
    ///
    /// Returns a stage-qualified error before readiness when a dependency cannot
    /// be validated, contacted, or bound. Resources created by earlier stages
    /// are released before the error returns.
    pub async fn start(
        options: &ProductionOptions,
        loaded: LoadedConfig,
    ) -> Result<Self, ProductionError> {
        validate_exposure(options)?;
        let diagnostics = Arc::new(Diagnostics::new(256));
        diagnostics.record(format!("configuration loaded from {}", loaded.source));
        for diagnostic in &loaded.diagnostics {
            diagnostics.record(diagnostic.clone());
            warn!(stage = "config", message = %diagnostic);
        }

        let readiness = Arc::new(DependencyReadiness::new([
            "config", "audit", "role", "skills", "provider", "channels", "gateway", "http", "mcp",
        ]));
        readiness.set("config", true);
        info!(
            stage = "config",
            source = loaded.source,
            "validated configuration loaded"
        );

        let state_dir = options.state_dir()?;
        std::fs::create_dir_all(&state_dir)
            .map_err(|error| ProductionError::new("state", error))?;
        let audit = Arc::new(
            DurableSecurityAudit::open(
                &state_dir.join("security-audit.jsonl"),
                Arc::clone(&readiness),
            )
            .map_err(|error| ProductionError::new("audit", error))?,
        );
        readiness.set("audit", true);
        info!(stage = "audit", path = %state_dir.join("security-audit.jsonl").display(), "durable audit opened");

        let proxy = proxy_policy(&loaded.snapshot)?;
        diagnostics.record(proxy_diagnostic(&proxy));
        info!(stage = "proxy", policy = ?proxy, "shared provider transport policy selected");
        let role = if options.smoke {
            RoleProfile {
                prompt: "You are running the GTA Claw install diagnostic.".to_owned(),
                model: None,
            }
        } else {
            load_role(&loaded.snapshot, proxy.clone()).await?
        };
        readiness.set("role", true);
        info!(
            stage = "role",
            bytes = role.prompt.len(),
            model = role.model.as_deref().unwrap_or("configured-default"),
            "role loaded"
        );

        let skill_count = claw_skills::registry().len();
        readiness.set("skills", true);
        diagnostics.record(format!(
            "skills: 0 active, {skill_count} registered entries require native ports"
        ));
        info!(
            stage = "skills",
            registered = skill_count,
            active = 0,
            "skill inventory classified"
        );

        let channels = channel_statuses(&loaded.snapshot)?;
        readiness.set("channels", true);
        info!(
            stage = "channels",
            enabled = 0,
            "channel lifecycle validated"
        );

        let provider: Arc<dyn Provider> = if options.smoke {
            warn!(stage = "provider", "explicit smoke provider enabled");
            Arc::new(SmokeProvider::new().map_err(|error| ProductionError::new("provider", error))?)
        } else {
            Arc::new(build_copilot(&loaded.snapshot, proxy)?)
        };
        let configured_model = role
            .model
            .clone()
            .unwrap_or_else(|| loaded.snapshot.core().copilot().default_model().to_owned());
        let provider = Arc::new(ProviderAdapter::new(
            provider,
            configured_model,
            role.prompt,
            Arc::clone(&readiness),
        ));
        provider
            .initialize()
            .await
            .map_err(|error| ProductionError::new("provider-readiness", error))?;
        info!(
            stage = "provider",
            provider = provider.provider_name(),
            model = provider.default_model(),
            "provider is live"
        );

        let config = Arc::new(ConfigController::new(
            loaded.snapshot.clone(),
            Arc::clone(&provider),
            Arc::clone(&diagnostics),
        ));
        let updates_enabled = updates_enabled(&loaded.snapshot)
            .map_err(|error| ProductionError::message("updates", error))?;
        if updates_enabled {
            diagnostics.record(
                "signed update checks are enabled but require the external updater manifest API",
            );
        }
        let admin = Arc::new(OperatorAdmin::new(
            Arc::clone(&config),
            Arc::clone(&provider),
            Arc::clone(&readiness),
            Arc::clone(&diagnostics),
            channels,
            skill_count,
            updates_enabled,
        ));
        let external = Arc::new(UnavailableExternalPorts);
        let services = ApiServices {
            provider: Arc::clone(&provider) as Arc<dyn claw_http_api::ProviderPort>,
            readiness: Arc::clone(&readiness) as Arc<dyn claw_http_api::ReadinessPort>,
            tools: Arc::new(UnavailableTools),
            admin,
            watch_auth: Arc::clone(&external) as Arc<dyn claw_http_api::WatchAuthPort>,
            watch_results: Arc::clone(&external) as Arc<dyn claw_http_api::WatchResultPort>,
            webhooks: external,
            audit,
        };
        diagnostics
            .record("tools/watch/webhooks are unavailable until their public ports are composable");

        let serving = ServingStateHandle::starting();
        let admin_token = admin_token(&loaded.snapshot)?;
        if admin_token.is_none() {
            diagnostics.record(
                "protected HTTP routes are disabled; set GTA_CLAW_ADMIN_TOKEN to enable them",
            );
            warn!(
                stage = "http-auth",
                "protected HTTP routes have no bearer credential"
            );
        }
        let api = HttpApi::with_serving_state(
            api_config(admin_token),
            services,
            Arc::new(serving.clone()),
        );

        let http_requested = options.http_listen.unwrap_or_else(|| {
            SocketAddr::new(
                IpAddr::V4(Ipv4Addr::LOCALHOST),
                loaded.snapshot.core().server().port(),
            )
        });
        let gateway_requested = options.gateway_listen.unwrap_or(DEFAULT_GATEWAY);
        let mcp_requested = options.mcp_listen.unwrap_or(DEFAULT_MCP);
        if !mcp_requested.ip().is_loopback() {
            return Err(ProductionError::message(
                "mcp-bind",
                "the MCP listener must be loopback",
            ));
        }

        let gateway_config = GatewayServerConfig {
            exposure: if options.tls_terminated_by_frontend {
                Exposure::TlsTerminatedByFrontend
            } else {
                Exposure::LoopbackOnly
            },
            ..GatewayServerConfig::default()
        };
        let gateway_clock = Arc::new(claw_gateway::SystemClock);
        let gateway_credential = std::env::var("GTA_CLAW_GATEWAY_TOKEN")
            .ok()
            .filter(|token| !token.is_empty())
            .map_or(CredentialPolicy::None, |token| {
                CredentialPolicy::Token(GatewaySecret::from(token))
            });
        let gateway_authenticator = StaticAuthenticator::new(gateway_credential, gateway_clock);
        let devices = gateway_authenticator.devices();
        diagnostics.record(
            "gateway is bound with no paired devices; pairing persistence has no public composition adapter",
        );
        let gateway = GatewayServer::new(
            gateway_config,
            Arc::new(gateway_authenticator),
            Arc::new(devices),
        )
        .map_err(|error| ProductionError::new("gateway-build", error))?
        .bind(gateway_requested)
        .await
        .map_err(|error| ProductionError::new("gateway-bind", error))?;

        let http_listener = TcpListener::bind(http_requested)
            .await
            .map_err(|error| ProductionError::new("http-bind", error))?;
        let http_address = http_listener
            .local_addr()
            .map_err(|error| ProductionError::new("http-bind", error))?;
        let mcp_listener = TcpListener::bind(mcp_requested)
            .await
            .map_err(|error| ProductionError::new("mcp-bind", error))?;
        let mcp_address = mcp_listener
            .local_addr()
            .map_err(|error| ProductionError::new("mcp-bind", error))?;
        let gateway_address = gateway.local_address();

        let gateway = gateway.start();
        readiness.set("gateway", true);
        let http_shutdown = CancellationToken::new();
        let mut http_tasks = JoinSet::new();
        let main_shutdown = http_shutdown.clone();
        let main_router = api
            .router()
            .into_make_service_with_connect_info::<SocketAddr>();
        http_tasks.spawn(async move {
            (
                "http",
                axum::serve(http_listener, main_router)
                    .with_graceful_shutdown(main_shutdown.cancelled_owned())
                    .await,
            )
        });
        let mcp_shutdown = http_shutdown.clone();
        let mcp_router = api
            .mcp_router()
            .into_make_service_with_connect_info::<SocketAddr>();
        http_tasks.spawn(async move {
            (
                "mcp",
                axum::serve(mcp_listener, mcp_router)
                    .with_graceful_shutdown(mcp_shutdown.cancelled_owned())
                    .await,
            )
        });
        readiness.set("http", true);
        readiness.set("mcp", true);

        serving.begin_serving();
        let addresses = BoundAddresses {
            http: http_address,
            gateway: gateway_address,
            mcp: mcp_address,
        };
        diagnostics.record(format!(
            "ready: http={} gateway={} mcp={} provider={} model={}",
            addresses.http,
            addresses.gateway,
            addresses.mcp,
            provider.provider_name(),
            provider.default_model()
        ));
        info!(
            stage = "ready",
            http = %addresses.http,
            gateway = %addresses.gateway,
            mcp = %addresses.mcp,
            provider = provider.provider_name(),
            model = provider.default_model(),
            "all required dependencies are live"
        );

        Ok(Self {
            addresses,
            provider,
            readiness,
            serving,
            config,
            config_path: loaded.path,
            diagnostics,
            http_shutdown,
            http_tasks,
            gateway: Some(gateway),
            terminated_http_tasks: 0,
        })
    }

    /// Returns the actual listener addresses.
    #[must_use]
    pub const fn addresses(&self) -> BoundAddresses {
        self.addresses
    }

    /// Returns the provider identifier.
    #[must_use]
    pub fn provider_name(&self) -> &str {
        self.provider.provider_name()
    }

    /// Returns a compact operator status line.
    #[must_use]
    pub fn status_line(&self) -> String {
        let (model, generation) = self.config.model_generation();
        format!(
            "status ready={} http={} gateway={} mcp={} provider={} model={} config_generation={}",
            self.readiness.is_ready() && self.serving.state().accepts_work(),
            self.addresses.http,
            self.addresses.gateway,
            self.addresses.mcp,
            self.provider.provider_name(),
            model,
            generation
        )
    }

    /// Returns the currently committed configuration generation.
    #[must_use]
    pub fn config_generation(&self) -> u64 {
        self.config.generation()
    }

    /// Reloads the configured file transactionally.
    ///
    /// # Errors
    ///
    /// Returns a `reload`-stage error when no file was configured, the file
    /// cannot be read, or the candidate is rejected and rolled back.
    pub fn reload(&self) -> Result<AppliedReload, ProductionError> {
        let path = self.config_path.as_ref().ok_or_else(|| {
            ProductionError::message(
                "reload",
                "legacy-environment startup has no reloadable file; use --config",
            )
        })?;
        self.config
            .reload_file(path)
            .map_err(|error| ProductionError::message("reload", error))
    }

    /// Waits for an ingress task to exit without a stop request.
    pub async fn wait_for_failure(&mut self) -> ProductionError {
        match self.http_tasks.join_next().await {
            Some(result) => {
                self.terminated_http_tasks += 1;
                ProductionError::message("runtime", joined_http_result(result))
            }
            None => ProductionError::message("runtime", "all HTTP ingress tasks disappeared"),
        }
    }

    /// Quiesces ingress and joins every task within the process stop budget.
    pub async fn stop(mut self, fault: Option<String>) -> ProductionStopSummary {
        let started = Instant::now();
        self.serving.begin_draining();
        self.readiness.set("http", false);
        self.readiness.set("mcp", false);
        self.readiness.set("gateway", false);
        info!(stage = "shutdown", "readiness disabled; draining ingress");

        let mut abandoned = 0_u32;
        if let Some(gateway) = self.gateway.as_ref()
            && tokio::time::timeout(remaining(started), gateway.stop_accepting())
                .await
                .is_err()
        {
            abandoned += 1;
            warn!(
                stage = "shutdown",
                subsystem = "gateway",
                "quiesce deadline expired"
            );
        }

        self.http_shutdown.cancel();
        let http_drain = async {
            while let Some(result) = self.http_tasks.join_next().await {
                self.terminated_http_tasks += 1;
                if let Err(error) = normalize_http_result(result) {
                    warn!(stage = "shutdown", subsystem = "http", error = %error);
                    abandoned += 1;
                }
            }
        };
        if tokio::time::timeout(remaining(started), http_drain)
            .await
            .is_err()
        {
            let outstanding = self.http_tasks.len();
            abandoned = abandoned.saturating_add(u32::try_from(outstanding).unwrap_or(u32::MAX));
            self.http_tasks.abort_all();
            while self.http_tasks.join_next().await.is_some() {
                self.terminated_http_tasks += 1;
            }
            warn!(
                stage = "shutdown",
                subsystem = "http",
                outstanding,
                "forced HTTP task cancellation"
            );
        }

        let mut gateway_joined = false;
        if let Some(gateway) = self.gateway.take() {
            let mut task = tokio::spawn(gateway.shutdown());
            if tokio::time::timeout(remaining(started), &mut task)
                .await
                .is_ok()
            {
                gateway_joined = true;
            } else {
                task.abort();
                let _ = task.await;
                abandoned = abandoned.saturating_add(1);
                warn!(
                    stage = "shutdown",
                    subsystem = "gateway",
                    "forced gateway cancellation"
                );
            }
        }

        let spawned = 4_u64;
        let terminated = self
            .terminated_http_tasks
            .saturating_add(if gateway_joined { 2 } else { 0 });
        let deadline_expired = started.elapsed() >= PRODUCTION_STOP_DEADLINE;
        let clean = abandoned == 0 && terminated == spawned && !deadline_expired && fault.is_none();
        if clean {
            info!(
                stage = "shutdown",
                elapsed_ms = started.elapsed().as_millis(),
                "shutdown complete"
            );
        } else {
            error!(
                stage = "shutdown",
                abandoned, terminated, spawned, deadline_expired, "shutdown incomplete"
            );
        }
        ProductionStopSummary {
            clean,
            drained: 3,
            completed: 0,
            abandoned,
            spawned,
            terminated,
            deadline_expired,
            fault,
        }
    }

    /// Returns retained diagnostics for in-process acceptance tests.
    #[must_use]
    pub fn diagnostics(&self) -> Vec<String> {
        self.diagnostics.entries()
    }
}

impl std::fmt::Debug for ProductionService {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ProductionService")
            .field("addresses", &self.addresses)
            .field("provider", &self.provider.provider_name())
            .field("ready", &self.readiness.is_ready())
            .finish_non_exhaustive()
    }
}

/// Bounded shutdown accounting rendered to supervisors.
#[derive(Clone, Debug)]
pub struct ProductionStopSummary {
    clean: bool,
    drained: u32,
    completed: u32,
    abandoned: u32,
    spawned: u64,
    terminated: u64,
    deadline_expired: bool,
    fault: Option<String>,
}

impl ProductionStopSummary {
    pub(crate) const fn before_start() -> Self {
        Self {
            clean: true,
            drained: 0,
            completed: 0,
            abandoned: 0,
            spawned: 0,
            terminated: 0,
            deadline_expired: false,
            fault: None,
        }
    }

    /// Returns whether the run and drain were both clean.
    #[must_use]
    pub const fn is_clean(&self) -> bool {
        self.clean
    }

    /// Number of ingress services drained.
    #[must_use]
    pub const fn drained(&self) -> u32 {
        self.drained
    }

    /// Number of in-flight requests reported complete during drain.
    #[must_use]
    pub const fn completed(&self) -> u32 {
        self.completed
    }

    /// Number of services or tasks forcibly abandoned.
    #[must_use]
    pub const fn abandoned(&self) -> u32 {
        self.abandoned
    }

    /// Number of service tasks spawned.
    #[must_use]
    pub const fn spawned(&self) -> u64 {
        self.spawned
    }

    /// Number of service tasks joined.
    #[must_use]
    pub const fn terminated(&self) -> u64 {
        self.terminated
    }

    /// Returns whether the global deadline expired.
    #[must_use]
    pub const fn deadline_expired(&self) -> bool {
        self.deadline_expired
    }

    /// Returns the unexpected runtime fault, when one ended the run.
    #[must_use]
    pub fn fault(&self) -> Option<&str> {
        self.fault.as_deref()
    }
}

fn remaining(started: Instant) -> Duration {
    PRODUCTION_STOP_DEADLINE.saturating_sub(started.elapsed())
}

fn joined_http_result(
    result: Result<(&'static str, io::Result<()>), tokio::task::JoinError>,
) -> String {
    match normalize_http_result(result) {
        Ok(name) => format!("{name} ingress exited unexpectedly"),
        Err(error) => error,
    }
}

fn normalize_http_result(
    result: Result<(&'static str, io::Result<()>), tokio::task::JoinError>,
) -> Result<&'static str, String> {
    match result {
        Ok((name, Ok(()))) => Ok(name),
        Ok((name, Err(error))) => Err(format!("{name} ingress failed: {error}")),
        Err(error) => Err(format!("HTTP ingress task failed: {error}")),
    }
}

fn validate_exposure(options: &ProductionOptions) -> Result<(), ProductionError> {
    for (name, address) in [
        ("http", options.http_listen),
        ("gateway", options.gateway_listen),
    ] {
        if address.is_some_and(|address| !address.ip().is_loopback())
            && !options.tls_terminated_by_frontend
        {
            return Err(ProductionError::message(
                "network-policy",
                format!(
                    "{name} address is routable; pass --tls-terminated-by-frontend only behind a trusted TLS proxy"
                ),
            ));
        }
    }
    if options.smoke
        && [
            options.http_listen,
            options.gateway_listen,
            options.mcp_listen,
        ]
        .into_iter()
        .flatten()
        .any(|address| !address.ip().is_loopback())
    {
        return Err(ProductionError::message(
            "network-policy",
            "smoke mode is restricted to loopback listeners",
        ));
    }
    Ok(())
}

fn channel_statuses(snapshot: &ConfigSnapshot) -> Result<Vec<Value>, ProductionError> {
    let channels = snapshot.core().channels();
    let configured = [
        ("msteams", channels.teams().enabled()),
        ("telegram", channels.telegram().enabled()),
        ("discord", channels.discord().enabled()),
        ("whatsapp", channels.whatsapp().enabled()),
    ];
    let mut statuses = Vec::with_capacity(configured.len());
    for (id, enabled) in configured {
        let entry = descriptor(id).ok_or_else(|| {
            ProductionError::message(
                "channels",
                format!("{id} is absent from the channel registry"),
            )
        })?;
        let exchange =
            exchange_support(id).map_err(|error| ProductionError::new("channels", error))?;
        statuses.push(json!({
            "id": id,
            "enabled": enabled,
            "implementation": match entry.implementation {
                ImplementationStatus::Full => "full",
                ImplementationStatus::OutboundWebhook => "outbound_webhook",
                ImplementationStatus::RegistrationOnly => "registration_only",
            },
            "exchange": match exchange {
                ExchangeSupport::None => "none",
                ExchangeSupport::OutboundOnly => "outbound_only",
                ExchangeSupport::InboundOnly => "inbound_only",
                ExchangeSupport::Bidirectional => "bidirectional",
            },
        }));
        if enabled && exchange != ExchangeSupport::Bidirectional {
            return Err(ProductionError::message(
                "channels",
                format!(
                    "{id} is enabled but its Rust adapter is {exchange:?}; disable it or install a bidirectional native port"
                ),
            ));
        }
    }
    Ok(statuses)
}

fn api_config(admin_token: Option<String>) -> ApiConfig {
    let credentials = admin_token
        .map(|token| {
            BearerCredential::new(&token, Role::Operator, ScopeSet::from_scopes(Scope::ALL))
        })
        .into_iter()
        .collect();
    ApiConfig::new(BearerAuthenticator::new(credentials))
}

fn admin_token(snapshot: &ConfigSnapshot) -> Result<Option<String>, ProductionError> {
    if let Some(token) = std::env::var("GTA_CLAW_ADMIN_TOKEN")
        .ok()
        .filter(|token| !token.is_empty())
    {
        return Ok(Some(token));
    }
    let encoded = to_json5(snapshot).map_err(|error| ProductionError::new("http-auth", error))?;
    let value = json5::from_str::<Value>(&encoded)
        .map_err(|error| ProductionError::new("http-auth", error))?;
    let Some(reference) = value
        .get("core")
        .and_then(|core| core.get("admin"))
        .and_then(|admin| admin.get("bearer_token"))
        .and_then(Value::as_str)
    else {
        return Ok(None);
    };
    let reference = SecretRef::parse(reference)
        .map_err(|error| ProductionError::message("http-auth", error))?;
    Ok(Some(resolve_secret(&reference)?.expose().to_owned()))
}

fn resolve_secret(reference: &SecretRef) -> Result<SecretString, ProductionError> {
    let Some(name) = reference.as_str().strip_prefix("env:") else {
        return Err(ProductionError::message(
            "secrets",
            "this daemon build currently composes env: secret references only",
        ));
    };
    let value = std::env::var(name)
        .map_err(|_| ProductionError::message("secrets", format!("{name} is not available")))?;
    if value.is_empty() {
        return Err(ProductionError::message(
            "secrets",
            format!("{name} is empty"),
        ));
    }
    Ok(SecretString::new(value))
}

fn proxy_policy(snapshot: &ConfigSnapshot) -> Result<ProxyPolicy, ProductionError> {
    snapshot
        .core()
        .network()
        .proxy_url()
        .map(resolve_secret)
        .transpose()
        .map(|secret| {
            secret.map_or(ProxyPolicy::FromEnvironment, |secret| {
                ProxyPolicy::Explicit {
                    url: secret.expose().to_owned(),
                    no_proxy: std::env::var("NO_PROXY").ok(),
                }
            })
        })
}

fn proxy_diagnostic(policy: &ProxyPolicy) -> String {
    match policy {
        ProxyPolicy::FromEnvironment => {
            "proxy: environment policy (ALL_PROXY, HTTPS_PROXY, HTTP_PROXY, NO_PROXY)".to_owned()
        }
        ProxyPolicy::Disabled => "proxy: disabled".to_owned(),
        ProxyPolicy::Explicit { no_proxy, .. } => format!(
            "proxy: explicit redacted URL, no_proxy={}",
            no_proxy.is_some()
        ),
    }
}

async fn load_role(
    snapshot: &ConfigSnapshot,
    proxy: ProxyPolicy,
) -> Result<RoleProfile, ProductionError> {
    let url = Url::parse(snapshot.core().role().source_url())
        .map_err(|error| ProductionError::new("role", error))?;
    let tls_policy = if url.scheme() == "http"
        && url
            .host_str()
            .is_some_and(|host| matches!(host, "localhost" | "127.0.0.1" | "::1" | "[::1]"))
    {
        TlsPolicy::AllowLoopbackPlaintext
    } else {
        TlsPolicy::RequireHttps
    };
    let transport = HttpTransport::with_config(&TransportConfig {
        tls_policy,
        proxy_policy: proxy,
        request_timeout: Duration::from_secs(15),
        ..TransportConfig::default()
    })
    .map_err(|error| ProductionError::new("role-transport", error))?;
    let cancellation = CancelToken::new();
    let response = transport
        .send(
            "role-loader",
            Operation::Transport,
            HttpRequest::new(Method::Get, url)
                .header("accept", "application/json, text/plain")
                .timeout(Duration::from_secs(15)),
            &cancellation,
        )
        .await
        .map_err(|error| ProductionError::new("role-fetch", error))?;
    if !response.is_success() {
        return Err(ProductionError::message(
            "role-fetch",
            format!("role source returned HTTP {}", response.status()),
        ));
    }
    if response.body().len() > ROLE_RESPONSE_LIMIT {
        return Err(ProductionError::message(
            "role-fetch",
            format!("role response exceeds {ROLE_RESPONSE_LIMIT} bytes"),
        ));
    }
    let source = std::str::from_utf8(response.body())
        .map_err(|error| ProductionError::new("role-decode", error))?;
    let parsed = serde_json::from_str::<Value>(source).ok();
    let prompt = parsed
        .as_ref()
        .and_then(Value::as_object)
        .and_then(|object| {
            object
                .get("content")
                .and_then(Value::as_str)
                .or_else(|| object.get("prompt").and_then(Value::as_str))
        })
        .map_or_else(|| source.to_owned(), str::to_owned);
    if prompt.trim().is_empty() {
        return Err(ProductionError::message(
            "role-decode",
            "role prompt is empty",
        ));
    }
    let model = parsed
        .as_ref()
        .and_then(Value::as_object)
        .and_then(|object| object.get("model"))
        .and_then(Value::as_str)
        .map(str::to_owned);
    Ok(RoleProfile { prompt, model })
}

fn build_copilot(
    snapshot: &ConfigSnapshot,
    proxy: ProxyPolicy,
) -> Result<GitHubCopilot, ProductionError> {
    let auth = snapshot.core().auth();
    if auth.device_enabled() {
        return Err(ProductionError::message(
            "provider-auth",
            "device flow is configured but the shipped HTTP crate has no /auth/device composition port; supply an env-backed GitHub token for unattended startup",
        ));
    }
    let reference = auth.github_pat().ok_or_else(|| {
        ProductionError::message("provider-auth", "GitHub token reference is missing")
    })?;
    let token = resolve_secret(reference)?;
    let config = GitHubCopilotConfig::new(token)
        .map_err(|error| ProductionError::new("provider-build", error))?;
    let reliability = config.reliability;
    let provider = GitHubCopilot::new(config)
        .map_err(|error| ProductionError::new("provider-build", error))?;
    let request_timeout = Duration::from_millis(
        copilot_request_timeout_ms(snapshot)
            .map_err(|error| ProductionError::message("provider-config", error))?,
    );
    let transport = HttpTransport::with_config(&TransportConfig {
        proxy_policy: proxy,
        request_timeout,
        ..TransportConfig::default()
    })
    .map_err(|error| ProductionError::new("provider-proxy", error))?;
    Ok(provider.with_runtime(ProviderRuntime::with_parts(
        "github-copilot",
        transport,
        reliability,
        Arc::new(ProviderClock),
        Arc::new(PseudoRandomJitter::from_entropy()),
    )))
}

/// Runs the same non-network composition checks used before startup.
///
/// # Errors
///
/// Returns the same static configuration, secret-reference, channel-coverage,
/// state-directory, and exposure errors that startup would report before any
/// network operation.
pub fn check_configuration(
    options: &ProductionOptions,
    loaded: &LoadedConfig,
) -> Result<(), ProductionError> {
    validate_exposure(options)?;
    let _ = options.state_dir()?;
    let _ = proxy_policy(&loaded.snapshot)?;
    let _ = admin_token(&loaded.snapshot)?;
    let _ = updates_enabled(&loaded.snapshot)
        .map_err(|error| ProductionError::message("updates", error))?;
    let _ = channel_statuses(&loaded.snapshot)?;
    if !options.smoke {
        let auth = loaded.snapshot.core().auth();
        if auth.device_enabled() {
            return Err(ProductionError::message(
                "provider-auth",
                "device flow cannot yet be composed into unattended startup",
            ));
        }
        let reference = auth.github_pat().ok_or_else(|| {
            ProductionError::message("provider-auth", "GitHub token reference is missing")
        })?;
        let _ = resolve_secret(reference)?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::ffi::OsString;
    use std::io;

    use super::{CommandLine, CommandMode};

    #[test]
    fn the_full_command_line_is_parsed_without_a_framework() {
        let parsed = CommandLine::parse(
            [
                "--config",
                "config.json5",
                "--listen",
                "127.0.0.1:0",
                "--gateway-listen",
                "127.0.0.1:0",
                "--mcp-listen",
                "127.0.0.1:0",
                "--state-dir",
                "state",
                "--smoke",
            ]
            .into_iter()
            .map(OsString::from),
        )
        .expect("command parses");

        assert_eq!(parsed.mode, CommandMode::Serve);
        assert!(parsed.options.smoke);
        assert_eq!(parsed.options.http_listen.expect("HTTP address").port(), 0);
    }

    #[test]
    fn probe_cannot_be_combined_with_serving_flags() {
        let error = CommandLine::parse(["--probe", "--smoke"].into_iter().map(OsString::from))
            .expect_err("mixed mode must fail");

        assert_eq!(error.kind(), io::ErrorKind::InvalidInput);
    }
}

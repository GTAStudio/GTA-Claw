//! Production service composition over the shipped crate APIs.

use std::ffi::OsString;
use std::fmt::{self, Display, Formatter};
use std::io::{self, Read};
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, RwLock};
use std::time::{Duration, Instant};

use axum::extract::{Request, State};
use axum::middleware::Next;
use axum::response::Response;
use claw_channels::{ExchangeSupport, ImplementationStatus, descriptor, exchange_support};
use claw_config::{
    ConfigLayerKind, ConfigLayers, ConfigSnapshot, LogLevel, MigrationDiagnostic, ResolvedConfig,
    RoleDiagnostic, RoleDocumentOutcome, RoleFetchRequest, RoleResponse, RoleSourceFetcher,
    SecretRef, load_role as load_role_document, migrate_legacy_environment, to_json5,
};
use claw_crestodian::{Crestodian, RecoveryGuidance};
use claw_gateway::{CredentialPolicy, Exposure, GatewayServer, GatewayServerConfig, ServerHandle};
use claw_http_api::{
    ApiConfig, ApiServices, BearerAuthenticator, BearerCredential, HttpApi, LegacyAdminCredential,
    LegacyApiConfig, LegacyApiServices, LegacyChannelStatus, LegacyHttpApi, LegacyReloadError,
    LegacyReloadPort, LegacyReloadResult, LegacyRuntimePort, LegacyWhatsAppConfig,
    LegacyWhatsAppServices, PortError, PortErrorKind, PortFuture, ServingStateHandle,
};
use claw_observability::{LogFormat, TelemetryConfig, TelemetryHandle, TelemetryOutput};
use claw_provider_sdk::clock::{PseudoRandomJitter, SystemClock as ProviderClock};
use claw_provider_sdk::http::{
    HttpRequest, HttpTransport, Method, ProxyPolicy, TlsPolicy, TransportConfig,
};
use claw_provider_sdk::{
    CancelToken, CredentialKey, Operation, Provider, SecretStore as ProviderSecretStore,
    SecretString,
};
use claw_providers::github_copilot::{DeviceFlowConfig, GitHubCopilotConfig};
use claw_providers::{DeviceFlow, GitHubCopilot, ProviderRuntime};
use claw_security::authorization::{Role, Scope, ScopeSet};
use futures_util::StreamExt;
use secrecy::SecretString as GatewaySecret;
use serde_json::{Value, json};
use tokio::net::TcpListener;
use tokio::task::JoinSet;
use tokio_util::sync::CancellationToken;
use tracing::{debug, error, info, warn};
use url::Url;

use crate::adapters::agent_runtime::{AgentRuntime, RuntimeModelTools};
use crate::adapters::channels::{ChannelSupervisor, DiscordSettings, TelegramSettings};
use crate::adapters::gateway_pairing::{GatewayPairingAuthenticator, GatewayPairingStore};
use crate::adapters::http_api::{
    AppliedReload, ConfigController, DependencyReadiness, Diagnostics, DisabledExternalPorts,
    DurableSecurityAudit, GatewayPairingAdmin, ModelToolCatalog, OperatorAdmin, OperatorInventory,
    OperatorRuntimeStatus, ProviderHistoryConfig, SmokeProvider, SwappableProvider,
    copilot_request_timeout_ms, updates_enabled,
};
use crate::adapters::legacy::{
    DeviceTaskReport, DeviceTokenActivator, GraphWhatsAppAdapter, LegacyDeviceFlowAdapter,
    LegacyTeamsAdapter, NativeLegacyHostAdmin,
};
use crate::adapters::signed_plugins::SignedPluginRuntime;
use crate::adapters::updater::UpdateMonitor;

/// Whole-process shutdown ceiling.
pub const PRODUCTION_STOP_DEADLINE: Duration = Duration::from_secs(10);
const PLUGIN_ACTIVATION_CANCEL_GRACE: Duration = Duration::from_secs(2);
const DEFAULT_GATEWAY: SocketAddr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0);
const DEFAULT_MCP: SocketAddr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0);
/// Supported invocation, printed for `--help` and for a rejected command line.
pub const USAGE: &str = "usage: gta-claw-daemon [--probe | --check-config] [--config PATH] \
                     [--listen ADDRESS] [--legacy-listen ADDRESS] \
                     [--gateway-listen ADDRESS] [--mcp-listen ADDRESS] [--state-dir PATH] \
                     [--log-file PATH] [--tls-terminated-by-frontend] [--smoke]";

/// Top-level command selected by the process arguments.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CommandMode {
    /// Start the composed service.
    Serve,
    /// Print the native process health line and exit.
    Probe,
    /// Load and composition-check configuration without opening listeners.
    CheckConfig,
    /// Print the supported invocation and exit successfully.
    Help,
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
        let arguments: Vec<OsString> = arguments.into_iter().collect();

        // Scanned across the whole command line before anything is validated or
        // consumed, because position must not decide whether the question is
        // answered. Detecting it inside the loop below made `--nonsense --help`
        // a usage error, and made `--config --help` silently treat `--help` as
        // a file path — the flag was swallowed as the previous flag's value.
        if arguments
            .iter()
            .any(|argument| matches!(argument.to_str(), Some("--help" | "-h")))
        {
            return Ok(Self {
                mode: CommandMode::Help,
                options: ProductionOptions::default(),
            });
        }

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
                "--log-file" => options.log_file = Some(required_path(&mut arguments, flag)?),
                "--listen" => options.http_listen = Some(required_address(&mut arguments, flag)?),
                "--legacy-listen" => {
                    options.legacy_listen = Some(required_address(&mut arguments, flag)?);
                }
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
                || options.legacy_listen.is_some()
                || options.gateway_listen.is_some()
                || options.mcp_listen.is_some()
                || options.log_file.is_some()
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
    /// Legacy Node-compatible HTTP listener override.
    pub legacy_listen: Option<SocketAddr>,
    /// Gateway listener override.
    pub gateway_listen: Option<SocketAddr>,
    /// Loopback MCP listener override.
    pub mcp_listen: Option<SocketAddr>,
    /// Durable local state directory.
    pub state_dir: Option<PathBuf>,
    /// Ordinary telemetry output file; stderr is used when absent.
    pub log_file: Option<PathBuf>,
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
        let environment = process_environment();
        let configured_path = self
            .config_path
            .clone()
            .or_else(|| std::env::var_os("GTA_CLAW_CONFIG").map(PathBuf::from));
        if let Some(path) = configured_path {
            let recovery_guidance = self.recovery_guidance(&path);
            let resolved = resolve_file_config(&path, &environment).map_err(|error| {
                ProductionError::message(
                    "config",
                    format!(
                        "{error}; recovery_guidance={}",
                        recovery_guidance.map_or("unavailable", recovery_guidance_label)
                    ),
                )
            })?;
            return Ok(LoadedConfig {
                snapshot: resolved.config,
                path: Some(path),
                source: "layered-file",
                diagnostics: resolved.environment_diagnostics,
                applied_layers: resolved.applied_layers,
                recovery_guidance,
            });
        }

        let migrated = migrate_legacy_environment(
            environment
                .iter()
                .map(|(name, value)| (name.as_str(), value.as_str())),
        )
        .map_err(|error| ProductionError::new("config", error))?;
        let mut applied_layers = vec![ConfigLayerKind::BuiltIn];
        if migrated
            .diagnostics
            .iter()
            .any(|diagnostic| matches!(diagnostic, MigrationDiagnostic::Applied { .. }))
        {
            applied_layers.push(ConfigLayerKind::Environment);
        }
        Ok(LoadedConfig {
            snapshot: migrated.config,
            path: None,
            source: "legacy-environment",
            diagnostics: migrated.diagnostics,
            applied_layers,
            recovery_guidance: None,
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

    fn recovery_guidance(&self, config_path: &Path) -> Option<RecoveryGuidance> {
        let state_path = self.state_dir().ok()?.join("crestodian-state.json");
        Some(
            Crestodian::new(config_path.to_owned(), state_path)
                .inspect()
                .guidance(),
        )
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
    pub diagnostics: Vec<MigrationDiagnostic>,
    /// Configuration layers that contributed values.
    pub applied_layers: Vec<ConfigLayerKind>,
    /// Machine-readable recovery guidance for file-backed startup.
    pub recovery_guidance: Option<RecoveryGuidance>,
}

fn process_environment() -> Vec<(String, String)> {
    std::env::vars_os()
        .filter_map(|(name, value)| Some((name.into_string().ok()?, value.into_string().ok()?)))
        .collect()
}

fn resolve_file_config(
    path: &Path,
    environment: &[(String, String)],
) -> Result<ResolvedConfig, claw_config::LayeredConfigError> {
    ConfigLayers::new()
        .with_workspace_file(path)?
        .with_environment(environment.iter().cloned())
        .resolve()
}

const fn recovery_guidance_label(guidance: RecoveryGuidance) -> &'static str {
    match guidance {
        RecoveryGuidance::NoAction => "no_action",
        RecoveryGuidance::RunGuidedSetup => "run_guided_setup",
        RecoveryGuidance::RecoverFromBaseline => "recover_from_baseline",
        RecoveryGuidance::UseCompatibleBuild => "use_compatible_build",
    }
}

const fn config_layer_label(layer: ConfigLayerKind) -> &'static str {
    match layer {
        ConfigLayerKind::BuiltIn => "built_in",
        ConfigLayerKind::System => "system",
        ConfigLayerKind::User => "user",
        ConfigLayerKind::Workspace => "workspace",
        ConfigLayerKind::Environment => "environment",
        ConfigLayerKind::CommandLine => "command_line",
    }
}

/// Initializes the shared redacting telemetry subscriber from typed logging config.
///
/// # Errors
///
/// Returns a `logging`-stage error for an invalid format/filter, a file-open
/// failure, or when another global tracing subscriber is already installed.
pub fn init_telemetry(
    snapshot: &ConfigSnapshot,
    log_file: Option<&Path>,
) -> Result<TelemetryHandle, ProductionError> {
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
    let output = log_file.map_or(TelemetryOutput::Stderr, TelemetryOutput::file);
    claw_observability::init_with_output(
        &TelemetryConfig {
            format,
            default_filter: default_filter.to_owned(),
            filter_env: "GTA_CLAW_LOG".to_owned(),
        },
        output,
    )
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
    outcome: RoleDocumentOutcome,
    diagnostics: Vec<RoleDiagnostic>,
}

struct LegacySettings {
    device_flow_enabled: bool,
    channels: LegacyChannelStatus,
    teams: Option<LegacyTeamsSettings>,
    telegram: Option<TelegramSettings>,
    discord: Option<DiscordSettings>,
    whatsapp: Option<LegacyWhatsAppSettings>,
    teams_rate_limit_per_minute: u32,
    trust_proxy: bool,
    session_max_entries: usize,
    session_idle_timeout: Duration,
}

struct LegacyTeamsSettings {
    app_id: String,
    app_password: SecretString,
}

struct LegacyWhatsAppSettings {
    route: LegacyWhatsAppConfig,
    access_token: SecretString,
    phone_number_id: String,
}

/// Bound service addresses reported after readiness.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct BoundAddresses {
    /// Main HTTP API.
    pub http: SocketAddr,
    /// Legacy Node-compatible HTTP facade.
    pub legacy: SocketAddr,
    /// Gateway WebSocket server.
    pub gateway: SocketAddr,
    /// Loopback MCP HTTP endpoint.
    pub mcp: SocketAddr,
}

#[derive(Clone, Default)]
struct RequestAccounting {
    active: Arc<AtomicU64>,
    completed: Arc<AtomicU64>,
}

impl RequestAccounting {
    fn completed(&self) -> u64 {
        self.completed.load(Ordering::Acquire)
    }
}

struct RequestCompletionGuard(RequestAccounting);

impl Drop for RequestCompletionGuard {
    fn drop(&mut self) {
        self.0.active.fetch_sub(1, Ordering::AcqRel);
        self.0.completed.fetch_add(1, Ordering::AcqRel);
    }
}

async fn account_request(
    State(accounting): State<RequestAccounting>,
    request: Request,
    next: Next,
) -> Response {
    accounting.active.fetch_add(1, Ordering::AcqRel);
    let _guard = RequestCompletionGuard(accounting);
    next.run(request).await
}

struct CopilotDeviceActivator {
    provider: Arc<SwappableProvider>,
    proxy: ProxyPolicy,
    request_timeout: Duration,
}

impl DeviceTokenActivator for CopilotDeviceActivator {
    fn activate(
        &self,
        token: SecretString,
        cancellation: CancelToken,
    ) -> PortFuture<'_, Result<(), PortError>> {
        Box::pin(async move {
            let client = build_copilot_from_token(token, self.proxy.clone(), self.request_timeout)
                .map_err(|error| production_port_error(&error))?;
            self.provider
                .activate_with_cancel(Arc::new(client), cancellation)
                .await
                .map_err(|error| provider_port_error(&error))?;
            self.provider.mark_ready();
            Ok(())
        })
    }
}

struct DaemonLegacyReload {
    reload_lock: Arc<tokio::sync::Mutex<()>>,
    config: Arc<ConfigController>,
    provider: Arc<SwappableProvider>,
    runtime: Arc<AgentRuntime>,
    proxy: ProxyPolicy,
    diagnostics: Arc<Diagnostics>,
    skill_count: usize,
}

impl LegacyReloadPort for DaemonLegacyReload {
    fn reload(
        &self,
        cancellation: CancellationToken,
    ) -> PortFuture<'_, Result<LegacyReloadResult, LegacyReloadError>> {
        Box::pin(async move {
            let Ok(_reload) = self.reload_lock.try_lock() else {
                return Err(LegacyReloadError::InProgress);
            };
            let snapshot = self.config.snapshot().map_err(|error| {
                self.diagnostics
                    .record(format!("legacy reload snapshot failed: {error}"));
                LegacyReloadError::Failed
            })?;
            let role = tokio::select! {
                result = load_role(&snapshot, self.proxy.clone()) => {
                    result.map_err(|error| {
                        self.diagnostics.record(format!("legacy role reload failed: {error}"));
                        LegacyReloadError::Failed
                    })?
                }
                () = cancellation.cancelled() => return Err(LegacyReloadError::Failed),
            };
            let model = role
                .model
                .as_deref()
                .unwrap_or_else(|| snapshot.core().copilot().default_model());
            self.provider.set_default_model(model).map_err(|error| {
                self.diagnostics
                    .record(format!("legacy role model rejected: {error}"));
                LegacyReloadError::Failed
            })?;
            self.provider.set_role_prompt(&role.prompt);
            self.provider.clear_history();
            let report = self.runtime.reload_sessions().await;
            self.diagnostics.record(format!(
                "legacy runtime reload generation={} destroyed={} cancelled={} forced={}",
                report.generation, report.destroyed, report.cancelled_turns, report.forced_turns
            ));
            for diagnostic in &role.diagnostics {
                self.diagnostics
                    .record(format!("legacy role reload: {diagnostic}"));
            }
            Ok(LegacyReloadResult {
                role_model: role.model,
                skill_count: self.skill_count,
            })
        })
    }
}

/// A complete production service after every dependency is live.
pub struct ProductionService {
    addresses: BoundAddresses,
    provider: Arc<SwappableProvider>,
    readiness: Arc<DependencyReadiness>,
    serving: ServingStateHandle,
    config: Arc<ConfigController>,
    reload_lock: Arc<tokio::sync::Mutex<()>>,
    config_path: Option<PathBuf>,
    diagnostics: Arc<Diagnostics>,
    requests: RequestAccounting,
    http_shutdown: CancellationToken,
    http_tasks: JoinSet<(&'static str, io::Result<()>)>,
    gateway: Option<ServerHandle>,
    device_flow: Option<Arc<LegacyDeviceFlowAdapter>>,
    channels: ChannelSupervisor,
    agent_runtime: Arc<AgentRuntime>,
    updater: UpdateMonitor,
    plugins: Option<SignedPluginRuntime>,
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
        startup_cancellation: CancellationToken,
    ) -> Result<Self, ProductionError> {
        if startup_cancellation.is_cancelled() {
            return Err(startup_cancelled());
        }
        validate_exposure(options)?;
        let diagnostics = Arc::new(Diagnostics::new(256));
        diagnostics.record(format!("configuration loaded from {}", loaded.source));
        diagnostics.record(format!("configuration layers: {:?}", loaded.applied_layers));
        info!(
            stage = "config",
            layers = ?loaded.applied_layers,
            "configuration layers resolved"
        );
        let mut applied = 0_usize;
        let mut manual_required = 0_usize;
        let mut ignored_unknown = 0_usize;
        for diagnostic in &loaded.diagnostics {
            match diagnostic {
                MigrationDiagnostic::ManualRequired(mapping) => {
                    manual_required += 1;
                    diagnostics.record(diagnostic.to_string());
                    warn!(
                        stage = "config",
                        diagnostic = "manual_required",
                        legacy_env = mapping.legacy_env,
                        target = mapping.target,
                        reason = mapping.reason,
                    );
                }
                MigrationDiagnostic::Applied { legacy_env, target } => {
                    applied += 1;
                    diagnostics.record(diagnostic.to_string());
                    info!(stage = "config", diagnostic = "applied", legacy_env, target,);
                }
                MigrationDiagnostic::IgnoredUnknown { name } => {
                    ignored_unknown += 1;
                    debug!(
                        stage = "config",
                        diagnostic = "ignored_unknown",
                        environment_name = name,
                    );
                }
                _ => {
                    diagnostics.record("configuration emitted an unrecognized diagnostic");
                    warn!(stage = "config", diagnostic = "unrecognized");
                }
            }
        }
        if ignored_unknown > 0 {
            diagnostics.record(format!(
                "{ignored_unknown} non-configuration environment names ignored"
            ));
        }
        if let Some(guidance) = loaded.recovery_guidance {
            let guidance = recovery_guidance_label(guidance);
            diagnostics.record(format!("recovery guidance: {guidance}"));
            if guidance == "no_action" {
                info!(stage = "recovery", guidance);
            } else {
                warn!(stage = "recovery", guidance);
            }
        }
        let config_resolution = json!({
            "source": loaded.source,
            "layers": loaded
                .applied_layers
                .iter()
                .map(|layer| config_layer_label(*layer))
                .collect::<Vec<_>>(),
            "diagnostics": {
                "applied": applied,
                "manualRequired": manual_required,
                "ignoredUnknown": ignored_unknown,
            },
            "recoveryGuidance": loaded
                .recovery_guidance
                .map(recovery_guidance_label),
        });

        let readiness = Arc::new(DependencyReadiness::new([
            "config",
            "audit",
            "role",
            "skills",
            "provider",
            "runtime",
            "channels",
            "gateway",
            "http",
            "legacy-http",
            "mcp",
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
        let gateway_pairing = GatewayPairingStore::open(state_dir.join("gateway-pairings.json"))
            .map_err(|error| ProductionError::message("gateway-pairing", error))?;
        diagnostics.record(format!(
            "gateway pairing store opened with {} grants",
            gateway_pairing.len()
        ));
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
        let proxy_rules = proxy.rules();
        diagnostics.record(format!("proxy policy: {proxy:?}"));
        for diagnostic in proxy_rules.diagnostics() {
            diagnostics.record(format!("proxy: {diagnostic}"));
            warn!(stage = "proxy", diagnostic = %diagnostic);
        }
        if proxy_rules.fell_back_to_direct() {
            warn!(
                stage = "proxy",
                "configured proxy is unusable; traffic will go direct"
            );
        }
        info!(stage = "proxy", policy = ?proxy, "shared provider transport policy selected");
        let role = if options.smoke {
            RoleProfile {
                prompt: "You are running the GTA Claw install diagnostic.".to_owned(),
                model: None,
                outcome: RoleDocumentOutcome::LoadedPlainText,
                diagnostics: Vec::new(),
            }
        } else {
            tokio::select! {
                result = load_role(&loaded.snapshot, proxy.clone()) => result?,
                () = startup_cancellation.cancelled() => return Err(startup_cancelled()),
            }
        };
        for diagnostic in &role.diagnostics {
            diagnostics.record(format!("role: {diagnostic}"));
            warn!(stage = "role", diagnostic = %diagnostic);
        }
        readiness.set("role", true);
        info!(
            stage = "role",
            bytes = role.prompt.len(),
            model = role.model.as_deref().unwrap_or("configured-default"),
            outcome = role_outcome_label(role.outcome),
            "role loaded"
        );

        let registered_skill_count = claw_skills::registry().len();
        diagnostics.record(format!(
            "skills: {registered_skill_count} registered entries require native ports"
        ));
        info!(
            stage = "skills",
            registered = registered_skill_count,
            "skill inventory classified"
        );
        let plugin_diagnostics = Arc::clone(&diagnostics);
        let plugin_cancellation = claw_plugin_host::CancellationToken::new();
        let task_cancellation = plugin_cancellation.clone();
        let mut plugin_task = tokio::task::spawn_blocking(move || {
            SignedPluginRuntime::activate(&plugin_diagnostics, task_cancellation)
        });
        let plugins = tokio::select! {
            result = &mut plugin_task => {
                result
                    .map_err(|error| ProductionError::new("plugins", error))?
                    .map_err(|error| ProductionError::message("plugins", error))?
            }
            () = startup_cancellation.cancelled() => {
                plugin_cancellation.cancel();
                if tokio::time::timeout(
                    PLUGIN_ACTIVATION_CANCEL_GRACE,
                    &mut plugin_task,
                )
                .await
                .is_err()
                {
                    plugin_task.abort();
                    diagnostics.record(
                        "plugin activation did not stop within the cancellation grace period",
                    );
                }
                return Err(startup_cancelled());
            }
        };
        let plugin_tools = plugins.tools();
        let model_tools = RuntimeModelTools::new(Arc::clone(&plugin_tools));
        let active_skill_count = plugins.summary().activated();
        let plugin_activation = plugins.summary().as_json();
        diagnostics.record(format!("plugin activation report: {plugin_activation}"));
        info!(
            stage = "plugins",
            activated = active_skill_count,
            report = %plugin_activation,
            "signed plugin discovery completed"
        );
        readiness.set("skills", true);

        let mut legacy_settings = legacy_settings(&loaded.snapshot)?;
        let channels = channel_statuses(&legacy_settings)?;

        let configured_model = role
            .model
            .clone()
            .unwrap_or_else(|| loaded.snapshot.core().copilot().default_model().to_owned());
        let provider = Arc::new(SwappableProvider::new(
            configured_model.clone(),
            role.prompt,
            ProviderHistoryConfig {
                max_conversations: legacy_settings.session_max_entries,
                idle_timeout: legacy_settings.session_idle_timeout,
            },
            model_tools as Arc<dyn ModelToolCatalog>,
            Arc::clone(&readiness),
        ));
        let provider_to_activate: Option<Arc<dyn Provider>> = if options.smoke {
            warn!(stage = "provider", "explicit smoke provider enabled");
            Some(Arc::new(
                SmokeProvider::new().map_err(|error| ProductionError::new("provider", error))?,
            ))
        } else if loaded.snapshot.core().auth().github_pat().is_some() {
            Some(Arc::new(build_copilot(&loaded.snapshot, proxy.clone())?))
        } else {
            None
        };
        if let Some(provider_to_activate) = provider_to_activate {
            let activation_cancel = CancelToken::new();
            tokio::select! {
                result = provider.activate_with_cancel(
                    provider_to_activate,
                    activation_cancel.clone(),
                ) => {
                    result.map_err(|error| {
                        ProductionError::new("provider-readiness", error)
                    })?;
                }
                () = startup_cancellation.cancelled() => {
                    activation_cancel.cancel();
                    return Err(startup_cancelled());
                }
            }
            provider.mark_ready();
            info!(
                stage = "provider",
                provider = provider.provider_name(),
                model = provider.default_model(),
                "provider is live"
            );
        } else {
            diagnostics.record("provider authentication is pending GitHub Device Flow");
            warn!(
                stage = "provider",
                model = provider.default_model(),
                "provider authentication is pending"
            );
        }

        let config = Arc::new(ConfigController::new(
            loaded.snapshot.clone(),
            Arc::clone(&provider),
            Arc::clone(&diagnostics),
        ));
        let reload_lock = Arc::new(tokio::sync::Mutex::new(()));
        let agent_runtime = AgentRuntime::new(
            Arc::clone(&provider),
            Arc::clone(&plugin_tools),
            &state_dir,
            configured_model.clone(),
            active_skill_count,
            legacy_settings.session_max_entries,
            legacy_settings.session_idle_timeout,
            Arc::clone(&diagnostics),
        )
        .map_err(|error| ProductionError::message("runtime", error))?;
        let http_tools = agent_runtime.http_tools(Arc::clone(&plugin_tools));
        readiness.set("runtime", true);

        let channel_authentication = Arc::new(RwLock::new(None));
        let teams = if let Some(teams) = legacy_settings.teams.take() {
            let transport = HttpTransport::with_config(&TransportConfig {
                proxy_policy: proxy.clone(),
                request_timeout: Duration::from_secs(15),
                ..TransportConfig::default()
            })
            .map_err(|error| ProductionError::new("teams-transport", error))?;
            Some(
                LegacyTeamsAdapter::new(
                    Arc::clone(&agent_runtime),
                    transport,
                    teams.app_id,
                    teams.app_password,
                    Arc::clone(&channel_authentication),
                    Arc::clone(&diagnostics),
                )
                .map_err(|error| ProductionError::new("teams", error))?,
            )
        } else {
            None
        };
        let whatsapp = if let Some(whatsapp) = legacy_settings.whatsapp.take() {
            let transport = HttpTransport::with_config(&TransportConfig {
                proxy_policy: proxy.clone(),
                request_timeout: Duration::from_secs(10),
                ..TransportConfig::default()
            })
            .map_err(|error| ProductionError::new("whatsapp-transport", error))?;
            let sender = GraphWhatsAppAdapter::new(
                transport,
                &whatsapp.phone_number_id,
                &whatsapp.access_token,
                Arc::clone(&diagnostics),
            )
            .map_err(|error| ProductionError::new("whatsapp", error))?;
            Some((
                whatsapp.route,
                LegacyWhatsAppServices {
                    messages: Arc::clone(&agent_runtime)
                        as Arc<dyn claw_http_api::LegacyChannelMessagePort>,
                    sender,
                },
            ))
        } else {
            None
        };

        let request_timeout = Duration::from_millis(
            copilot_request_timeout_ms(&loaded.snapshot)
                .map_err(|error| ProductionError::message("provider-config", error))?,
        );
        let device_flow = if legacy_settings.device_flow_enabled {
            let flow = build_device_flow(&loaded.snapshot, proxy.clone())?;
            let activator = Arc::new(CopilotDeviceActivator {
                provider: Arc::clone(&provider),
                proxy: proxy.clone(),
                request_timeout,
            });
            Some(LegacyDeviceFlowAdapter::new(
                flow,
                activator,
                Arc::clone(&channel_authentication),
                Arc::clone(&diagnostics),
            ))
        } else {
            None
        };
        if let Some(flow) = device_flow.as_ref()
            && (teams.is_some()
                || whatsapp.is_some()
                || legacy_settings.telegram.is_some()
                || legacy_settings.discord.is_some())
            && !provider.is_active()
        {
            let instructions = tokio::select! {
                result = claw_http_api::LegacyDeviceFlowPort::instructions(
                    flow.as_ref(),
                    startup_cancellation.child_token(),
                ) => result.map_err(|error| ProductionError::new("device-flow", error))?,
                () = startup_cancellation.cancelled() => return Err(startup_cancelled()),
            };
            diagnostics.record(format!(
                "channel authentication instructions prepared ({} bytes)",
                instructions.len()
            ));
        }
        let enabled_channel_count = [
            legacy_settings.channels.teams(),
            legacy_settings.channels.telegram(),
            legacy_settings.channels.discord(),
            legacy_settings.channels.whatsapp(),
        ]
        .into_iter()
        .filter(|enabled| *enabled)
        .count();
        let channel_supervisor = tokio::select! {
            result = ChannelSupervisor::start(
                legacy_settings.telegram.take(),
                legacy_settings.discord.take(),
                Arc::clone(&agent_runtime),
                Arc::clone(&channel_authentication),
                proxy.clone(),
                Arc::clone(&diagnostics),
                startup_cancellation.clone(),
            ) => result.map_err(|error| ProductionError::message("channels", error))?,
            () = startup_cancellation.cancelled() => return Err(startup_cancelled()),
        };
        readiness.set("channels", true);
        info!(
            stage = "channels",
            enabled = enabled_channel_count,
            "channel lifecycles are live"
        );
        let reload = Arc::new(DaemonLegacyReload {
            reload_lock: Arc::clone(&reload_lock),
            config: Arc::clone(&config),
            provider: Arc::clone(&provider),
            runtime: Arc::clone(&agent_runtime),
            proxy: proxy.clone(),
            diagnostics: Arc::clone(&diagnostics),
            skill_count: active_skill_count,
        });
        let updates_enabled = updates_enabled(&loaded.snapshot)
            .map_err(|error| ProductionError::message("updates", error))?;
        let update_monitor =
            UpdateMonitor::start(updates_enabled, &proxy, Arc::clone(&diagnostics))
                .map_err(|error| ProductionError::message("updates", error))?;
        let admin = Arc::new(OperatorAdmin::new(
            Arc::clone(&config),
            Arc::clone(&provider),
            Arc::clone(&readiness),
            Arc::clone(&diagnostics),
            OperatorInventory::new(
                channels,
                registered_skill_count,
                active_skill_count,
                updates_enabled,
                config_resolution,
                plugin_activation,
                Arc::clone(&agent_runtime) as Arc<dyn OperatorRuntimeStatus>,
            ),
            Arc::clone(&reload_lock),
            Arc::clone(&gateway_pairing) as Arc<dyn GatewayPairingAdmin>,
        ));
        let admin_token = admin_token(&loaded.snapshot)?;
        let external = Arc::new(DisabledExternalPorts);
        let services = ApiServices {
            provider: Arc::clone(&provider) as Arc<dyn claw_http_api::ProviderPort>,
            readiness: Arc::clone(&readiness) as Arc<dyn claw_http_api::ReadinessPort>,
            tools: http_tools as Arc<dyn claw_http_api::ToolPort>,
            admin,
            watch_auth: Arc::clone(&external) as Arc<dyn claw_http_api::WatchAuthPort>,
            watch_results: Arc::clone(&external) as Arc<dyn claw_http_api::WatchResultPort>,
            webhooks: external,
            audit,
        };
        diagnostics.record("optional watch pairing and task-flow webhook routes are disabled");

        let serving = ServingStateHandle::starting();
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
            api_config(admin_token.clone()),
            services,
            Arc::new(serving.clone()),
        );
        let mut legacy_channels = LegacyChannelStatus::default();
        legacy_channels.set_teams(legacy_settings.channels.teams());
        legacy_channels.set_telegram(legacy_settings.channels.telegram());
        legacy_channels.set_discord(legacy_settings.channels.discord());
        legacy_channels.set_whatsapp(whatsapp.is_some());
        let legacy_config = LegacyApiConfig {
            device_flow_enabled: legacy_settings.device_flow_enabled,
            channels: legacy_channels,
            default_model: provider.default_model(),
            teams_rate_limit_per_minute: legacy_settings.teams_rate_limit_per_minute,
            trust_proxy: legacy_settings.trust_proxy,
            admin_credential: admin_token.as_deref().map(LegacyAdminCredential::new),
            whatsapp: whatsapp.as_ref().map(|(config, _)| config.clone()),
            ..LegacyApiConfig::default()
        };
        let legacy_services = LegacyApiServices {
            runtime: Arc::clone(&agent_runtime) as Arc<dyn LegacyRuntimePort>,
            readiness: Arc::clone(&readiness) as Arc<dyn claw_http_api::ReadinessPort>,
            device_flow: device_flow
                .as_ref()
                .map(|flow| Arc::clone(flow) as Arc<dyn claw_http_api::LegacyDeviceFlowPort>),
            teams: teams
                .as_ref()
                .map(|teams| Arc::clone(teams) as Arc<dyn claw_http_api::LegacyTeamsPort>),
            whatsapp: whatsapp.map(|(_, services)| services),
            reload: Some(reload),
            admin: admin_token.as_ref().map(|_| {
                NativeLegacyHostAdmin::new() as Arc<dyn claw_http_api::LegacyHostAdminPort>
            }),
        };
        let legacy_api = LegacyHttpApi::with_serving_state(
            legacy_config,
            legacy_services,
            Arc::new(serving.clone()),
        )
        .map_err(|error| ProductionError::new("legacy-http-build", error))?;

        let http_requested = options.http_listen.unwrap_or(DEFAULT_MCP);
        let legacy_requested = options.legacy_listen.unwrap_or_else(|| {
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
        let devices = gateway_pairing.devices();
        let gateway_authenticator = GatewayPairingAuthenticator::new(
            gateway_credential,
            gateway_clock,
            Arc::clone(&gateway_pairing),
        );
        diagnostics.record(format!(
            "gateway authorization loaded {} paired devices",
            gateway_pairing.len()
        ));
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
        let legacy_listener = TcpListener::bind(legacy_requested)
            .await
            .map_err(|error| ProductionError::new("legacy-http-bind", error))?;
        let legacy_address = legacy_listener
            .local_addr()
            .map_err(|error| ProductionError::new("legacy-http-bind", error))?;
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
        let requests = RequestAccounting::default();
        let mut http_tasks = JoinSet::new();
        let main_shutdown = http_shutdown.clone();
        let main_router = api
            .router()
            .layer(axum::middleware::from_fn_with_state(
                requests.clone(),
                account_request,
            ))
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
            .layer(axum::middleware::from_fn_with_state(
                requests.clone(),
                account_request,
            ))
            .into_make_service_with_connect_info::<SocketAddr>();
        http_tasks.spawn(async move {
            (
                "mcp",
                axum::serve(mcp_listener, mcp_router)
                    .with_graceful_shutdown(mcp_shutdown.cancelled_owned())
                    .await,
            )
        });
        let legacy_shutdown = http_shutdown.clone();
        let legacy_router = legacy_api
            .router()
            .layer(axum::middleware::from_fn_with_state(
                requests.clone(),
                account_request,
            ))
            .into_make_service_with_connect_info::<SocketAddr>();
        http_tasks.spawn(async move {
            (
                "legacy-http",
                axum::serve(legacy_listener, legacy_router)
                    .with_graceful_shutdown(legacy_shutdown.cancelled_owned())
                    .await,
            )
        });
        readiness.set("http", true);
        readiness.set("legacy-http", true);
        readiness.set("mcp", true);

        serving.begin_serving();
        let addresses = BoundAddresses {
            http: http_address,
            legacy: legacy_address,
            gateway: gateway_address,
            mcp: mcp_address,
        };
        diagnostics.record(format!(
            "ready: http={} legacy={} gateway={} mcp={} provider={} model={}",
            addresses.http,
            addresses.legacy,
            addresses.gateway,
            addresses.mcp,
            provider.provider_name(),
            provider.default_model()
        ));
        info!(
            stage = "ready",
            http = %addresses.http,
            legacy = %addresses.legacy,
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
            reload_lock,
            config_path: loaded.path,
            diagnostics,
            requests,
            http_shutdown,
            http_tasks,
            gateway: Some(gateway),
            device_flow,
            channels: channel_supervisor,
            agent_runtime,
            updater: update_monitor,
            plugins: Some(plugins),
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
    pub fn provider_name(&self) -> String {
        self.provider.provider_name()
    }

    /// Returns a compact operator status line.
    #[must_use]
    pub fn status_line(&self) -> String {
        let (model, generation) = self.config.model_generation();
        format!(
            "status ready={} http={} legacy={} gateway={} mcp={} provider={} model={} config_generation={}",
            self.readiness.is_ready() && self.serving.state().accepts_work(),
            self.addresses.http,
            self.addresses.legacy,
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
    pub async fn reload(&self) -> Result<AppliedReload, ProductionError> {
        let _reload = self.reload_lock.lock().await;
        let path = self.config_path.as_ref().ok_or_else(|| {
            ProductionError::message(
                "reload",
                "legacy-environment startup has no reloadable file; use --config",
            )
        })?;
        let resolved = resolve_file_config(path, &process_environment())
            .map_err(|error| ProductionError::new("reload", error))?;
        for diagnostic in &resolved.environment_diagnostics {
            match diagnostic {
                MigrationDiagnostic::Applied { .. } | MigrationDiagnostic::ManualRequired(_) => {
                    self.diagnostics.record(format!("reload: {diagnostic}"));
                }
                MigrationDiagnostic::IgnoredUnknown { .. } => {}
                _ => self
                    .diagnostics
                    .record("reload emitted an unrecognized configuration diagnostic"),
            }
        }
        let source =
            to_json5(&resolved.config).map_err(|error| ProductionError::new("reload", error))?;
        let applied = self
            .config
            .apply_json5(&source, &path.display().to_string())
            .map_err(|error| ProductionError::message("reload", error))?;
        let report = self.agent_runtime.reload_sessions().await;
        self.diagnostics.record(format!(
            "runtime reload generation={} destroyed={} cancelled={} forced={}",
            report.generation, report.destroyed, report.cancelled_turns, report.forced_turns
        ));
        Ok(applied)
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
        let completed_before_drain = self.requests.completed();
        self.serving.begin_draining();
        self.readiness.set("http", false);
        self.readiness.set("legacy-http", false);
        self.readiness.set("mcp", false);
        self.readiness.set("gateway", false);
        self.readiness.set("channels", false);
        self.readiness.set("runtime", false);
        self.readiness.set("provider", false);
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
        let completed_during_drain = self
            .requests
            .completed()
            .saturating_sub(completed_before_drain);

        let channel_report = self.channels.shutdown(remaining(started)).await;
        abandoned = abandoned.saturating_add(channel_report.abandoned);
        let updater_spawned = u64::from(self.updater.is_enabled());
        let updater_joined = self.updater.shutdown(remaining(started)).await;
        if !updater_joined {
            abandoned = abandoned.saturating_add(1);
            warn!(
                stage = "shutdown",
                subsystem = "updater",
                "update check deadline expired"
            );
        }

        let device_report = if let Some(device_flow) = self.device_flow.as_ref() {
            device_flow.shutdown(remaining(started)).await
        } else {
            DeviceTaskReport {
                spawned: 0,
                terminated: 0,
                abandoned: 0,
            }
        };
        abandoned = abandoned.saturating_add(device_report.abandoned);

        match tokio::time::timeout(remaining(started), self.agent_runtime.shutdown()).await {
            Ok(Ok(())) => info!(stage = "shutdown", subsystem = "runtime", "runtime stopped"),
            Ok(Err(error)) => {
                abandoned = abandoned.saturating_add(1);
                warn!(stage = "shutdown", subsystem = "runtime", error = %error);
            }
            Err(_) => {
                abandoned = abandoned.saturating_add(1);
                warn!(
                    stage = "shutdown",
                    subsystem = "runtime",
                    "runtime shutdown deadline expired"
                );
            }
        }
        self.provider.shutdown().await;

        let mut plugins_joined = false;
        let mut plugin_invocations_spawned = 0;
        let mut plugin_invocations_terminated = 0;
        if let Some(mut plugins) = self.plugins.take() {
            let report = plugins.drain_invocations(remaining(started)).await;
            plugin_invocations_spawned = report.spawned;
            plugin_invocations_terminated = report.terminated;
            if report.cancelled > 0 {
                warn!(
                    stage = "shutdown",
                    subsystem = "plugins",
                    cancelled = report.cancelled,
                    "cancelled plugin invocations after graceful drain"
                );
            }
            if report.abandoned {
                abandoned = abandoned.saturating_add(1);
                warn!(
                    stage = "shutdown",
                    subsystem = "plugins",
                    spawned = report.spawned,
                    terminated = report.terminated,
                    "plugin invocation drain deadline expired"
                );
                plugins.abandon_host();
            } else {
                let mut task = tokio::task::spawn_blocking(move || plugins.shutdown_host());
                match tokio::time::timeout(remaining(started), &mut task).await {
                    Ok(Ok(report)) => {
                        plugins_joined = true;
                        if report.failed > 0 {
                            abandoned = abandoned
                                .saturating_add(u32::try_from(report.failed).unwrap_or(u32::MAX));
                        }
                        info!(
                            stage = "shutdown",
                            subsystem = "plugins",
                            attempted = report.attempted,
                            failed = report.failed,
                            "plugin shutdown complete"
                        );
                    }
                    Ok(Err(error)) => {
                        abandoned = abandoned.saturating_add(1);
                        warn!(stage = "shutdown", subsystem = "plugins", error = %error);
                    }
                    Err(_) => {
                        task.abort();
                        abandoned = abandoned.saturating_add(1);
                        warn!(
                            stage = "shutdown",
                            subsystem = "plugins",
                            "plugin shutdown deadline expired"
                        );
                    }
                }
            }
        }

        let mut gateway_joined = false;
        if let Some(gateway) = self.gateway.take() {
            let mut task = tokio::spawn(gateway.shutdown());
            match tokio::time::timeout(remaining(started), &mut task).await {
                Ok(Ok(())) => gateway_joined = true,
                Ok(Err(error)) => {
                    abandoned = abandoned.saturating_add(1);
                    warn!(
                        stage = "shutdown",
                        subsystem = "gateway",
                        error = %error,
                        "gateway shutdown task failed"
                    );
                }
                Err(_) => {
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
        }

        let spawned = 6_u64
            .saturating_add(device_report.spawned)
            .saturating_add(channel_report.spawned)
            .saturating_add(updater_spawned)
            .saturating_add(plugin_invocations_spawned);
        let terminated = self
            .terminated_http_tasks
            .saturating_add(if gateway_joined { 2 } else { 0 })
            .saturating_add(u64::from(plugins_joined))
            .saturating_add(device_report.terminated)
            .saturating_add(channel_report.terminated)
            .saturating_add(u64::from(updater_spawned > 0 && updater_joined))
            .saturating_add(plugin_invocations_terminated);
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
            drained: 4,
            completed: u32::try_from(completed_during_drain).unwrap_or(u32::MAX),
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

fn startup_cancelled() -> ProductionError {
    ProductionError::message("startup", "startup was cancelled by the supervisor")
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
        ("legacy", options.legacy_listen),
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
            options.legacy_listen,
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

fn channel_statuses(settings: &LegacySettings) -> Result<Vec<Value>, ProductionError> {
    let configured = [
        ("msteams", settings.channels.teams()),
        ("telegram", settings.channels.telegram()),
        ("discord", settings.channels.discord()),
        ("whatsapp", settings.whatsapp.is_some()),
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
                ImplementationStatus::CompatibilityShim => "compatibility_shim",
                ImplementationStatus::RegistrationOnly => "registration_only",
            },
            "exchange": match exchange {
                ExchangeSupport::None => "none",
                ExchangeSupport::OutboundOnly => "outbound_only",
                ExchangeSupport::InboundOnly => "inbound_only",
                ExchangeSupport::Bidirectional => "bidirectional",
            },
            "legacyHttpAdapter": enabled && matches!(id, "msteams" | "whatsapp"),
            "nativeAdapter": enabled,
        }));
        if enabled && exchange != ExchangeSupport::Bidirectional {
            return Err(ProductionError::message(
                "channels",
                format!("{id} is enabled but the integrated registry reports {exchange:?}"),
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

fn legacy_settings(snapshot: &ConfigSnapshot) -> Result<LegacySettings, ProductionError> {
    let encoded =
        to_json5(snapshot).map_err(|error| ProductionError::new("legacy-config", error))?;
    let value = json5::from_str::<Value>(&encoded)
        .map_err(|error| ProductionError::new("legacy-config", error))?;
    let get = |path: &[&str]| {
        path.iter()
            .try_fold(&value, |value, field| value.get(*field))
    };
    let required_bool = |path: &[&str]| {
        get(path).and_then(Value::as_bool).ok_or_else(|| {
            ProductionError::message(
                "legacy-config",
                format!("{} is not a boolean", path.join(".")),
            )
        })
    };
    let required_u64 = |path: &[&str]| {
        get(path).and_then(Value::as_u64).ok_or_else(|| {
            ProductionError::message(
                "legacy-config",
                format!("{} is not an unsigned integer", path.join(".")),
            )
        })
    };
    let teams_enabled = required_bool(&["core", "channels", "teams", "enabled"])?;
    let telegram_enabled = required_bool(&["core", "channels", "telegram", "enabled"])?;
    let discord_enabled = required_bool(&["core", "channels", "discord", "enabled"])?;
    let whatsapp_enabled = required_bool(&["core", "channels", "whatsapp", "enabled"])?;
    let mut channels = LegacyChannelStatus::default();
    channels.set_teams(teams_enabled);
    channels.set_telegram(telegram_enabled);
    channels.set_discord(discord_enabled);
    channels.set_whatsapp(whatsapp_enabled);
    let teams = if teams_enabled {
        let app_id = get(&["core", "channels", "teams", "app_id"])
            .and_then(Value::as_str)
            .ok_or_else(|| ProductionError::message("legacy-config", "Teams app id is missing"))?;
        let password_reference = get(&["core", "channels", "teams", "app_password"])
            .and_then(Value::as_str)
            .ok_or_else(|| {
                ProductionError::message("legacy-config", "Teams app password is missing")
            })?;
        let password_reference = SecretRef::parse(password_reference)
            .map_err(|error| ProductionError::message("legacy-config", error))?;
        Some(LegacyTeamsSettings {
            app_id: app_id.to_owned(),
            app_password: resolve_secret(&password_reference)?,
        })
    } else {
        None
    };
    let telegram = if telegram_enabled {
        let token_reference = get(&["core", "channels", "telegram", "bot_token"])
            .and_then(Value::as_str)
            .ok_or_else(|| {
                ProductionError::message("legacy-config", "Telegram bot token is missing")
            })?;
        let token_reference = SecretRef::parse(token_reference)
            .map_err(|error| ProductionError::message("legacy-config", error))?;
        Some(TelegramSettings {
            token: resolve_secret(&token_reference)?,
            poll_interval: Duration::from_millis(required_u64(&[
                "core",
                "channels",
                "telegram",
                "poll_interval_ms",
            ])?),
        })
    } else {
        None
    };
    let discord = if discord_enabled {
        let token_reference = get(&["core", "channels", "discord", "bot_token"])
            .and_then(Value::as_str)
            .ok_or_else(|| {
                ProductionError::message("legacy-config", "Discord bot token is missing")
            })?;
        let token_reference = SecretRef::parse(token_reference)
            .map_err(|error| ProductionError::message("legacy-config", error))?;
        let gateway_url = get(&["core", "channels", "discord", "gateway_url"])
            .and_then(Value::as_str)
            .ok_or_else(|| {
                ProductionError::message("legacy-config", "Discord Gateway URL is missing")
            })?;
        Some(DiscordSettings {
            token: resolve_secret(&token_reference)?,
            gateway_url: gateway_url.to_owned(),
            intents: required_u64(&["core", "channels", "discord", "gateway_intents"])?,
        })
    } else {
        None
    };
    let whatsapp = if whatsapp_enabled {
        let verify_reference = get(&["core", "channels", "whatsapp", "verify_token"])
            .and_then(Value::as_str)
            .ok_or_else(|| {
                ProductionError::message("legacy-config", "WhatsApp verify token is missing")
            })?;
        let access_reference = get(&["core", "channels", "whatsapp", "access_token"])
            .and_then(Value::as_str)
            .ok_or_else(|| {
                ProductionError::message("legacy-config", "WhatsApp access token is missing")
            })?;
        let app_secret_reference = get(&["core", "channels", "whatsapp", "app_secret"])
            .and_then(Value::as_str)
            .ok_or_else(|| {
                ProductionError::message("legacy-config", "WhatsApp app secret is missing")
            })?;
        let verify_reference = SecretRef::parse(verify_reference)
            .map_err(|error| ProductionError::message("legacy-config", error))?;
        let access_reference = SecretRef::parse(access_reference)
            .map_err(|error| ProductionError::message("legacy-config", error))?;
        let app_secret_reference = SecretRef::parse(app_secret_reference)
            .map_err(|error| ProductionError::message("legacy-config", error))?;
        let verify_token = resolve_secret(&verify_reference)?;
        let access_token = resolve_secret(&access_reference)?;
        let app_secret = resolve_secret(&app_secret_reference)?;
        let path = get(&["core", "channels", "whatsapp", "webhook_path"])
            .and_then(Value::as_str)
            .ok_or_else(|| {
                ProductionError::message("legacy-config", "WhatsApp webhook path is missing")
            })?;
        let phone_number_id = get(&["core", "channels", "whatsapp", "phone_number_id"])
            .and_then(Value::as_str)
            .ok_or_else(|| {
                ProductionError::message("legacy-config", "WhatsApp phone number id is missing")
            })?;
        Some(LegacyWhatsAppSettings {
            route: LegacyWhatsAppConfig::new(
                path,
                verify_token.expose(),
                app_secret.expose(),
                phone_number_id,
            )
            .map_err(|error| ProductionError::new("legacy-config", error))?,
            access_token,
            phone_number_id: phone_number_id.to_owned(),
        })
    } else {
        None
    };
    Ok(LegacySettings {
        device_flow_enabled: snapshot.core().auth().device_enabled(),
        channels,
        teams,
        telegram,
        discord,
        whatsapp,
        teams_rate_limit_per_minute: u32::try_from(required_u64(&[
            "core",
            "server",
            "teams_rate_limit_per_minute",
        ])?)
        .map_err(|_| ProductionError::message("legacy-config", "Teams rate limit exceeds u32"))?,
        trust_proxy: required_bool(&["core", "server", "trust_proxy"])?,
        session_max_entries: usize::try_from(required_u64(&["core", "sessions", "max_entries"])?)
            .map_err(|_| {
            ProductionError::message("legacy-config", "session capacity exceeds usize")
        })?,
        session_idle_timeout: Duration::from_millis(required_u64(&["core", "sessions", "ttl_ms"])?),
    })
}

fn resolve_secret(reference: &SecretRef) -> Result<SecretString, ProductionError> {
    if let Some(name) = reference.as_str().strip_prefix("env:") {
        let value = std::env::var(name)
            .map_err(|_| ProductionError::message("secrets", format!("{name} is not available")))?;
        if value.is_empty() {
            return Err(ProductionError::message(
                "secrets",
                format!("{name} is empty"),
            ));
        }
        return Ok(SecretString::new(value));
    }
    if let Some(identifier) = reference
        .as_str()
        .strip_prefix("keyring://")
        .or_else(|| reference.as_str().strip_prefix("service://"))
    {
        let (service, account) = identifier.split_once('/').ok_or_else(|| {
            ProductionError::message("secrets", "platform secret reference is malformed")
        })?;
        let key = CredentialKey::new(service, account)
            .map_err(|error| ProductionError::new("secrets", error))?;
        return native_secret(&key)?.ok_or_else(|| {
            ProductionError::message("secrets", "platform credential is not available")
        });
    }
    if let Some(descriptor) = reference.as_str().strip_prefix("fd://") {
        #[cfg(unix)]
        {
            let descriptor = descriptor
                .parse::<u32>()
                .map_err(|_| ProductionError::message("secrets", "secret descriptor is invalid"))?;
            let file = std::fs::File::open(format!("/dev/fd/{descriptor}"))
                .map_err(|error| ProductionError::new("secrets", error))?;
            let mut value = String::new();
            file.take(1024 * 1024)
                .read_to_string(&mut value)
                .map_err(|error| ProductionError::new("secrets", error))?;
            while value.ends_with(['\r', '\n']) {
                value.pop();
            }
            if value.is_empty() {
                return Err(ProductionError::message(
                    "secrets",
                    "secret descriptor is empty",
                ));
            }
            return Ok(SecretString::new(value));
        }
        #[cfg(not(unix))]
        {
            let _ = descriptor;
            return Err(ProductionError::message(
                "secrets",
                "fd secret references are unavailable on this platform",
            ));
        }
    }
    Err(ProductionError::message(
        "secrets",
        "secret reference backend is not supported",
    ))
}

#[cfg(target_os = "macos")]
fn native_secret(key: &CredentialKey) -> Result<Option<SecretString>, ProductionError> {
    let store = claw_provider_sdk::secret::AppleKeychainStore::new()
        .map_err(|error| ProductionError::new("secrets", error))?;
    store
        .get(key)
        .map_err(|error| ProductionError::new("secrets", error))
}

#[cfg(target_os = "windows")]
fn native_secret(key: &CredentialKey) -> Result<Option<SecretString>, ProductionError> {
    let store = claw_provider_sdk::secret::WindowsCredentialManagerStore::new()
        .map_err(|error| ProductionError::new("secrets", error))?;
    store
        .get(key)
        .map_err(|error| ProductionError::new("secrets", error))
}

#[cfg(not(any(target_os = "macos", target_os = "windows")))]
fn native_secret(_key: &CredentialKey) -> Result<Option<SecretString>, ProductionError> {
    Err(ProductionError::message(
        "secrets",
        "native credential storage is unavailable on this platform",
    ))
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

struct TransportRoleFetcher {
    proxy: ProxyPolicy,
    runtime: tokio::runtime::Handle,
}

impl RoleSourceFetcher for TransportRoleFetcher {
    type Error = ProductionError;

    fn fetch(&mut self, request: RoleFetchRequest<'_>) -> Result<RoleResponse, Self::Error> {
        self.runtime
            .block_on(fetch_role_response(request, self.proxy.clone()))
    }
}

async fn load_role(
    snapshot: &ConfigSnapshot,
    proxy: ProxyPolicy,
) -> Result<RoleProfile, ProductionError> {
    let role_config = snapshot.core().role().clone();
    let runtime = tokio::runtime::Handle::current();
    tokio::task::spawn_blocking(move || {
        let mut fetcher = TransportRoleFetcher { proxy, runtime };
        let document = load_role_document(&mut fetcher, &role_config)
            .map_err(|error| ProductionError::new("role", error))?;
        Ok(RoleProfile {
            prompt: document.content().to_owned(),
            model: document.model().map(str::to_owned),
            outcome: document.outcome(),
            diagnostics: document.diagnostics().to_vec(),
        })
    })
    .await
    .map_err(|error| ProductionError::new("role", error))?
}

async fn fetch_role_response(
    request: RoleFetchRequest<'_>,
    proxy: ProxyPolicy,
) -> Result<RoleResponse, ProductionError> {
    let url =
        Url::parse(request.url()).map_err(|error| ProductionError::new("role-fetch", error))?;
    let tls_policy = if url.scheme() == "http"
        && url
            .host_str()
            .is_some_and(|host| matches!(host, "localhost" | "127.0.0.1" | "::1" | "[::1]"))
    {
        TlsPolicy::AllowLoopbackPlaintext
    } else {
        TlsPolicy::RequireHttps
    };
    let timeout = Duration::from_millis(request.timeout_ms());
    let transport = HttpTransport::with_config(&TransportConfig {
        tls_policy,
        proxy_policy: proxy,
        request_timeout: timeout,
        ..TransportConfig::default()
    })
    .map_err(|error| ProductionError::new("role-transport", error))?;
    let cancellation = CancelToken::new();
    let timeout_cancellation = cancellation.clone();
    let outcome = tokio::time::timeout(timeout, async move {
        let response = transport
            .send_streaming(
                "role-loader",
                Operation::Transport,
                HttpRequest::new(Method::Get, url)
                    .header("accept", request.accept())
                    .timeout(timeout),
                &cancellation,
            )
            .await
            .map_err(|error| ProductionError::new("role-fetch", error))?;
        let status = response.status();
        let content_type = response.header("content-type").map(str::to_owned);
        let declared_length = response
            .header("content-length")
            .and_then(|length| length.parse::<u64>().ok());
        if !(200..300).contains(&status)
            || declared_length.is_some_and(|length| {
                usize::try_from(length).map_or(true, |length| length > request.max_bytes())
            })
        {
            return Ok(role_response(
                status,
                content_type,
                declared_length,
                Vec::new(),
            ));
        }

        let mut body = Vec::with_capacity(
            declared_length
                .and_then(|length| usize::try_from(length).ok())
                .unwrap_or_default()
                .min(request.max_bytes()),
        );
        let mut chunks = response.into_chunks();
        while let Some(chunk) = chunks.next().await {
            let chunk = chunk.map_err(|error| ProductionError::new("role-fetch", error))?;
            if body.len().saturating_add(chunk.len()) > request.max_bytes() {
                return Err(ProductionError::message(
                    "role-fetch",
                    format!("role response exceeds {} bytes", request.max_bytes()),
                ));
            }
            body.extend_from_slice(&chunk);
        }
        Ok(role_response(status, content_type, declared_length, body))
    })
    .await;
    outcome.unwrap_or_else(|_| {
        timeout_cancellation.cancel();
        Err(ProductionError::message(
            "role-fetch",
            format!("role fetch exceeded {} ms", request.timeout_ms()),
        ))
    })
}

fn role_response(
    status: u16,
    content_type: Option<String>,
    declared_length: Option<u64>,
    body: Vec<u8>,
) -> RoleResponse {
    let mut response = RoleResponse::new(status, body);
    if let Some(content_type) = content_type {
        response = response.with_content_type(content_type);
    }
    if let Some(declared_length) = declared_length {
        response = response.with_declared_length(declared_length);
    }
    response
}

const fn role_outcome_label(outcome: RoleDocumentOutcome) -> &'static str {
    match outcome {
        RoleDocumentOutcome::LoadedJson => "loaded_json",
        RoleDocumentOutcome::LoadedPlainText => "loaded_plain_text",
    }
}

fn build_copilot(
    snapshot: &ConfigSnapshot,
    proxy: ProxyPolicy,
) -> Result<GitHubCopilot, ProductionError> {
    let auth = snapshot.core().auth();
    let reference = auth.github_pat().ok_or_else(|| {
        ProductionError::message("provider-auth", "GitHub token reference is missing")
    })?;
    let token = resolve_secret(reference)?;
    let request_timeout = Duration::from_millis(
        copilot_request_timeout_ms(snapshot)
            .map_err(|error| ProductionError::message("provider-config", error))?,
    );
    build_copilot_from_token(token, proxy, request_timeout)
}

fn build_copilot_from_token(
    token: SecretString,
    proxy: ProxyPolicy,
    request_timeout: Duration,
) -> Result<GitHubCopilot, ProductionError> {
    let config = GitHubCopilotConfig::new(token)
        .map_err(|error| ProductionError::new("provider-build", error))?;
    let reliability = config.reliability;
    let provider = GitHubCopilot::new(config)
        .map_err(|error| ProductionError::new("provider-build", error))?;
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

fn build_device_flow(
    snapshot: &ConfigSnapshot,
    proxy: ProxyPolicy,
) -> Result<DeviceFlow, ProductionError> {
    let mut config =
        DeviceFlowConfig::github().map_err(|error| ProductionError::new("device-flow", error))?;
    snapshot
        .core()
        .auth()
        .device_client_id()
        .ok_or_else(|| ProductionError::message("device-flow", "client id is missing"))?
        .clone_into(&mut config.client_id);
    "copilot".clone_into(&mut config.scope);
    let reliability = config.reliability;
    let flow =
        DeviceFlow::new(config).map_err(|error| ProductionError::new("device-flow", error))?;
    let transport = HttpTransport::with_config(&TransportConfig {
        tls_policy: TlsPolicy::RequireHttps,
        proxy_policy: proxy,
        request_timeout: Duration::from_secs(15),
        ..TransportConfig::default()
    })
    .map_err(|error| ProductionError::new("device-flow", error))?;
    Ok(flow.with_runtime(ProviderRuntime::with_parts(
        "github-copilot-device-flow",
        transport,
        reliability,
        Arc::new(ProviderClock),
        Arc::new(PseudoRandomJitter::from_entropy()),
    )))
}

fn provider_port_error(error: &claw_provider_sdk::ProviderError) -> PortError {
    let kind = match error.kind() {
        claw_provider_sdk::ErrorKind::InvalidRequest => PortErrorKind::InvalidRequest,
        claw_provider_sdk::ErrorKind::Timeout => PortErrorKind::Timeout,
        claw_provider_sdk::ErrorKind::Unsupported => PortErrorKind::NotFound,
        _ => PortErrorKind::Unavailable,
    };
    PortError::new(kind, error.to_string())
}

fn production_port_error(error: &ProductionError) -> PortError {
    PortError::new(PortErrorKind::Unavailable, error.to_string())
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
    let legacy_settings = legacy_settings(&loaded.snapshot)?;
    let _ = channel_statuses(&legacy_settings)?;
    if !options.smoke {
        let auth = loaded.snapshot.core().auth();
        if let Some(reference) = auth.github_pat() {
            let _ = resolve_secret(reference)?;
        } else if !auth.device_enabled() {
            return Err(ProductionError::message(
                "provider-auth",
                "GitHub token reference is missing and Device Flow is disabled",
            ));
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::ffi::OsString;
    use std::io;
    use std::path::PathBuf;
    use std::sync::atomic::{AtomicU64, Ordering};

    use claw_config::{ConfigLayerKind, MigrationDiagnostic, migrate_legacy_environment, to_json5};
    use claw_crestodian::RecoveryGuidance;

    use super::{CommandLine, CommandMode, ProductionOptions, resolve_file_config};

    static NEXT_ROOT: AtomicU64 = AtomicU64::new(0);

    #[test]
    fn the_full_command_line_is_parsed_without_a_framework() {
        let parsed = CommandLine::parse(
            [
                "--config",
                "config.json5",
                "--listen",
                "127.0.0.1:0",
                "--legacy-listen",
                "127.0.0.1:0",
                "--gateway-listen",
                "127.0.0.1:0",
                "--mcp-listen",
                "127.0.0.1:0",
                "--state-dir",
                "state",
                "--log-file",
                "logs/daemon.log",
                "--smoke",
            ]
            .into_iter()
            .map(OsString::from),
        )
        .expect("command parses");

        assert_eq!(parsed.mode, CommandMode::Serve);
        assert!(parsed.options.smoke);
        assert_eq!(parsed.options.http_listen.expect("HTTP address").port(), 0);
        assert_eq!(
            parsed.options.log_file,
            Some(PathBuf::from("logs/daemon.log"))
        );
    }

    #[test]
    fn probe_cannot_be_combined_with_serving_flags() {
        let error = CommandLine::parse(["--probe", "--smoke"].into_iter().map(OsString::from))
            .expect_err("mixed mode must fail");

        assert_eq!(error.kind(), io::ErrorKind::InvalidInput);
    }

    #[test]
    fn asking_for_help_is_not_a_usage_error() {
        for flag in ["--help", "-h"] {
            let parsed = CommandLine::parse(std::iter::once(OsString::from(flag)))
                .unwrap_or_else(|error| panic!("{flag} must parse, got {error}"));

            assert_eq!(parsed.mode, CommandMode::Help, "{flag}");
        }
    }

    #[test]
    fn help_is_answered_regardless_of_position() {
        // Every one of these reached a different failure before the scan was
        // hoisted out of the loop: the unsupported flag hit the catch-all, and
        // the value-taking flags swallowed `--help` as their own argument, so
        // `--config --help` treated the request as a file path.
        let orderings: [&[&str]; 7] = [
            &["--help", "--nonsense"],
            &["--nonsense", "--help"],
            &["--nonsense", "-h"],
            &["--config", "--help"],
            &["--listen", "--help"],
            &["--state-dir", "-h"],
            &["--probe", "--smoke", "--help"],
        ];

        for ordering in orderings {
            let parsed = CommandLine::parse(ordering.iter().copied().map(OsString::from))
                .unwrap_or_else(|error| panic!("{ordering:?} must parse, got {error}"));

            assert_eq!(parsed.mode, CommandMode::Help, "{ordering:?}");
        }
    }

    #[test]
    fn a_value_taking_flag_without_its_value_still_fails_without_help() {
        // The guard above must not turn every incomplete command line into a
        // help request; only an explicit `--help` does that.
        for flag in ["--config", "--listen", "--state-dir", "--log-file"] {
            let error = CommandLine::parse(std::iter::once(OsString::from(flag)))
                .expect_err("a flag missing its value must fail");

            assert_eq!(error.kind(), io::ErrorKind::InvalidInput, "{flag}");
        }
    }

    #[test]
    fn file_resolution_preserves_machine_diagnostics_and_recovery_guidance() {
        let root = std::env::temp_dir().join(format!(
            "gta-claw-config-resolution-{}-{}",
            std::process::id(),
            NEXT_ROOT.fetch_add(1, Ordering::Relaxed)
        ));
        std::fs::create_dir_all(&root).expect("temporary root is created");
        let path = root.join("config.json5");
        let snapshot = migrate_legacy_environment([
            ("GITHUB_TOKEN", "test"),
            ("ENABLE_TEAMS", "false"),
            ("AGENT_ROLE_URL", "https://example.test/role"),
        ])
        .expect("base configuration migrates")
        .config;
        std::fs::write(
            &path,
            to_json5(&snapshot).expect("configuration serializes"),
        )
        .expect("configuration is written");

        let resolved = resolve_file_config(
            &path,
            &[
                ("COPILOT_MODEL".to_owned(), "gpt-4.1".to_owned()),
                ("TYPO_PORT".to_owned(), "1234".to_owned()),
            ],
        )
        .expect("layers resolve");
        assert_eq!(
            resolved.applied_layers,
            vec![
                ConfigLayerKind::BuiltIn,
                ConfigLayerKind::Workspace,
                ConfigLayerKind::Environment,
            ]
        );
        assert!(resolved.environment_diagnostics.iter().any(|diagnostic| {
            matches!(
                diagnostic,
                MigrationDiagnostic::Applied {
                    legacy_env: "COPILOT_MODEL",
                    target: "copilot.default_model",
                }
            )
        }));
        assert!(resolved.environment_diagnostics.iter().any(|diagnostic| {
            matches!(
                diagnostic,
                MigrationDiagnostic::IgnoredUnknown { name } if name == "TYPO_PORT"
            )
        }));

        let options = ProductionOptions {
            state_dir: Some(root.clone()),
            ..ProductionOptions::default()
        };
        assert_eq!(
            options.recovery_guidance(&path),
            Some(RecoveryGuidance::RecoverFromBaseline)
        );
        std::fs::remove_dir_all(root).expect("temporary root is removed");
    }
}

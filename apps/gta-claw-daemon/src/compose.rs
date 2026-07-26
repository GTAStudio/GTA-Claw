//! The composition root.
//!
//! This is the only place in the daemon that knows which concrete adapter
//! satisfies which port. Everything else — including [`SessionService`], which
//! does the actual work — is written against traits.
//!
//! The assembly order is not folklore. It is derived: each subsystem declares
//! its dependencies, [`SubsystemHost`] topologically sorts them, and start-up
//! follows that order while shutdown follows its reverse with ingress quiesced
//! first. Adding a subsystem means declaring an edge, not editing a sequence.
//!
//! The Gateway ingress owns the real `claw-gateway` listener and protocol
//! server. Remaining deterministic adapters are seams for crates that have not
//! landed yet.

use std::fmt;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

use claw_application::composition::{
    AuthorityPort, Capability, CapabilitySet, Clock, CompositionError, ConfigPort,
    ContextAssemblyPort, CredentialName, DnsPort, EgressGuard, EgressPolicy, GatewayDispatch,
    GatewayRequest, GatewayResponse, GrantIssuer, HostPattern, HttpRoute, Lifecycle,
    LifecyclePhase, ModelName, ObservabilityPort, PersistencePort, Principal, ProcessClock,
    ProviderName, ProviderRegistryPort, ProviderTransportPort, RuntimeSettings, SecretStorePort,
    ServiceHandle, SessionEnginePort, SessionService, Severity, ShutdownReport, StartContext,
    Subsystem, SubsystemError, SubsystemHost, ToolName, ToolSurfacePort, TurnEventSink, TurnReport,
    well_known,
};
use claw_domain::SessionId;

use crate::adapters::engine::DeterministicEngine;
use crate::adapters::ingress::{GatewayIngress, LoopbackHttpApi, PortSubsystem};
use crate::adapters::model::{
    FakeTool, GuardedProviderRegistry, MemoryToolSurface, NoteContext, ProviderConfig,
    ScriptedTransport, reading_workspace,
};
use crate::adapters::plugins::PerActivationPluginHost;
use crate::adapters::state::{MemoryPersistence, MemorySecrets};
use crate::adapters::support::{LivePolicy, MemoryObservability, MutableConfig, TableDns, note};
use crate::runtime::{RuntimeHost, TaskLedger};

/// The credential the built-in provider presents.
const CREDENTIAL: &str = "primary-provider-key";

/// How long an authorization may live, whatever the policy asks for.
const MAX_AUTHORIZATION_TTL: Duration = Duration::from_secs(30);

/// What a completed run reports.
#[derive(Debug)]
pub struct StopSummary {
    shutdown: ShutdownReport,
    tasks: TaskLedger,
    phase: LifecyclePhase,
}

impl StopSummary {
    /// Returns the subsystem shutdown report.
    #[must_use]
    pub const fn shutdown(&self) -> &ShutdownReport {
        &self.shutdown
    }

    /// Returns the task ledger, which proves whether anything leaked.
    #[must_use]
    pub const fn tasks(&self) -> TaskLedger {
        self.tasks
    }

    /// Returns the phase the host finished in.
    #[must_use]
    pub const fn phase(&self) -> LifecyclePhase {
        self.phase
    }

    /// Returns whether the run ended with nothing abandoned and nothing leaked.
    #[must_use]
    pub fn is_clean(&self) -> bool {
        self.shutdown.is_clean() && self.tasks.is_settled() && self.phase == LifecyclePhase::Stopped
    }
}

/// Everything the daemon is built from, before it is started.
///
/// Exposed so integration tests can reach into an individual adapter and assert
/// what it saw. Production code only needs [`Daemon::start`] and
/// [`Daemon::stop`].
pub struct Daemon {
    runtime: RuntimeHost,
    host: SubsystemHost,
    settings: Arc<RuntimeSettings>,
    clock: Arc<dyn Clock>,
    service: Arc<SessionService>,
    config: Arc<MutableConfig>,
    policy: Arc<LivePolicy>,
    observability: Arc<MemoryObservability>,
    persistence: Arc<MemoryPersistence>,
    secrets: Arc<MemorySecrets>,
    providers: Arc<GuardedProviderRegistry>,
    transport: Arc<ScriptedTransport>,
    tools: Arc<MemoryToolSurface>,
    context: Arc<NoteContext>,
    plugins: Arc<PerActivationPluginHost>,
    gateway: Arc<GatewayIngress>,
    http: Arc<LoopbackHttpApi>,
    dns: Arc<TableDns>,
    started: bool,
}

impl Daemon {
    /// Starts building a daemon.
    #[must_use]
    pub fn builder() -> DaemonBuilder {
        DaemonBuilder::new()
    }

    /// Initializes and starts every subsystem in dependency order.
    ///
    /// # Errors
    ///
    /// Returns a [`CompositionError`] when a subsystem refuses to come up. Any
    /// subsystem already brought up has been torn down before this returns.
    pub async fn start(&mut self) -> Result<Vec<ServiceHandle>, CompositionError> {
        let context = StartContext::new(
            well_known::observability(),
            Arc::clone(&self.settings),
            self.runtime.spawner(),
            self.runtime.shutdown_signal(),
            Arc::clone(&self.clock),
        );

        let handles = self.host.start(&context).await?;
        if let Err(error) = self.provision_credentials().await {
            let failure = error.to_string();
            let shutdown = self.host.shutdown().await?;
            let tasks = self.runtime.shutdown().await;
            if !shutdown.is_clean() || !tasks.is_settled() {
                return Err(SubsystemError::internal(
                    well_known::providers(),
                    format!(
                        "startup failed ({failure}) and rollback was incomplete: {} abandoned, {} of {} tasks joined",
                        shutdown.abandoned(),
                        tasks.terminated(),
                        tasks.spawned(),
                    ),
                )
                .into());
            }
            return Err(error);
        }
        self.started = true;

        self.observability.record(note(
            well_known::observability(),
            Severity::Info,
            format!("started {} subsystems", handles.len()),
            self.clock.now(),
        ));

        Ok(handles)
    }

    /// Files each provider's credential against the origin that provider
    /// actually resolved to.
    ///
    /// Doing this from the resolved binding rather than from the configured URL
    /// is deliberate: the secret store then holds the checked addresses, so a
    /// later resolution that lands somewhere else cannot obtain the secret.
    async fn provision_credentials(&self) -> Result<(), CompositionError> {
        for binding in self.providers.bindings().await? {
            self.secrets.preload(
                binding.credential(),
                binding.origin().clone(),
                &format!("token-for-{}", binding.name()),
            );
        }

        Ok(())
    }

    /// Quiesces ingress, drains work, stops every subsystem and joins every
    /// spawned task.
    ///
    /// # Errors
    ///
    /// Returns a [`CompositionError`] when the host was not in a phase that can
    /// be stopped. Subsystem failures during shutdown are collected into the
    /// report rather than aborting it.
    pub async fn stop(&mut self) -> Result<StopSummary, CompositionError> {
        let shutdown = self.host.shutdown().await?;
        let tasks = self.runtime.shutdown().await;
        self.started = false;

        Ok(StopSummary {
            shutdown,
            tasks,
            phase: self.host.phase(),
        })
    }

    /// Returns the phase the composition is in.
    #[must_use]
    pub const fn phase(&self) -> LifecyclePhase {
        self.host.phase()
    }

    /// Returns the subsystem start order the plan derived.
    #[must_use]
    pub fn start_order(&self) -> Vec<String> {
        self.host
            .plan()
            .start_order()
            .iter()
            .map(|id| id.as_str().to_owned())
            .collect()
    }

    /// Returns the order ingress subsystems are quiesced in.
    #[must_use]
    pub fn quiesce_order(&self) -> Vec<String> {
        self.host
            .plan()
            .quiesce_order()
            .iter()
            .map(|id| id.as_str().to_owned())
            .collect()
    }

    /// Sends a request in through the Gateway ingress, as a client would.
    ///
    /// # Errors
    ///
    /// Returns whatever the ingress or the session service returned.
    pub async fn call_gateway(
        &self,
        request: GatewayRequest,
    ) -> Result<GatewayResponse, SubsystemError> {
        self.gateway.handle(request).await
    }

    /// Sends a request in through the HTTP ingress.
    ///
    /// # Errors
    ///
    /// Returns whatever the ingress or the session service returned.
    pub async fn call_http(
        &self,
        method: &str,
        path: &str,
        request: GatewayRequest,
    ) -> Result<(HttpRoute, GatewayResponse), SubsystemError> {
        self.http.handle(method, path, request).await
    }

    /// Runs a turn directly against the session service, bypassing ingress.
    ///
    /// # Errors
    ///
    /// Returns whatever the service returned.
    pub async fn run_turn(
        &self,
        principal: &Principal,
        session: &SessionId,
        prompt: &str,
        events: &dyn TurnEventSink,
    ) -> Result<TurnReport, SubsystemError> {
        self.service
            .run_turn(principal, session, prompt, events)
            .await
    }

    /// Returns the session service, which is also the Gateway dispatcher.
    #[must_use]
    pub fn service(&self) -> Arc<SessionService> {
        Arc::clone(&self.service)
    }

    /// Returns the runtime host owning the task tracker.
    #[must_use]
    pub const fn runtime(&self) -> &RuntimeHost {
        &self.runtime
    }

    /// Returns the mutable configuration adapter.
    #[must_use]
    pub fn config(&self) -> Arc<MutableConfig> {
        Arc::clone(&self.config)
    }

    /// Returns the live policy, so a test can change what is permitted.
    #[must_use]
    pub fn policy(&self) -> Arc<LivePolicy> {
        Arc::clone(&self.policy)
    }

    /// Returns the observability sink.
    #[must_use]
    pub fn observability(&self) -> Arc<MemoryObservability> {
        Arc::clone(&self.observability)
    }

    /// Returns the persistence adapter.
    #[must_use]
    pub fn persistence(&self) -> Arc<MemoryPersistence> {
        Arc::clone(&self.persistence)
    }

    /// Returns the secret store adapter.
    #[must_use]
    pub fn secrets(&self) -> Arc<MemorySecrets> {
        Arc::clone(&self.secrets)
    }

    /// Returns the provider registry adapter.
    #[must_use]
    pub fn providers(&self) -> Arc<GuardedProviderRegistry> {
        Arc::clone(&self.providers)
    }

    /// Returns the provider transport adapter.
    #[must_use]
    pub fn transport(&self) -> Arc<ScriptedTransport> {
        Arc::clone(&self.transport)
    }

    /// Returns the tool surface adapter.
    #[must_use]
    pub fn tools(&self) -> Arc<MemoryToolSurface> {
        Arc::clone(&self.tools)
    }

    /// Returns the context assembly adapter.
    #[must_use]
    pub fn context(&self) -> Arc<NoteContext> {
        Arc::clone(&self.context)
    }

    /// Returns the plugin host adapter.
    #[must_use]
    pub fn plugins(&self) -> Arc<PerActivationPluginHost> {
        Arc::clone(&self.plugins)
    }

    /// Returns the gateway ingress.
    #[must_use]
    pub fn gateway(&self) -> Arc<GatewayIngress> {
        Arc::clone(&self.gateway)
    }

    /// Returns the HTTP ingress.
    #[must_use]
    pub fn http(&self) -> Arc<LoopbackHttpApi> {
        Arc::clone(&self.http)
    }

    /// Returns the settings the composition was built with.
    ///
    /// The addresses in [`RuntimeSettings::listen`] are requested values. The
    /// Gateway service handle and [`GatewayIngress`](crate::adapters::ingress::GatewayIngress)
    /// report the addresses the operating system actually bound.
    #[must_use]
    pub fn settings(&self) -> Arc<RuntimeSettings> {
        Arc::clone(&self.settings)
    }

    /// Returns the resolver, so a test can change an answer mid-run.
    #[must_use]
    pub fn dns(&self) -> Arc<TableDns> {
        Arc::clone(&self.dns)
    }

    /// Returns whether the composition is currently started.
    #[must_use]
    pub const fn is_started(&self) -> bool {
        self.started
    }
}

impl std::fmt::Debug for Daemon {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("Daemon")
            .field("phase", &self.host.phase())
            .field("subsystems", &self.host.plan().len())
            .field("started", &self.started)
            .finish_non_exhaustive()
    }
}

/// Assembles a [`Daemon`].
///
/// `Debug` is hand-written because `provider_url` is credential-bearing. The
/// builder holds it before [`EgressGuard`](claw_application::composition::EgressGuard)
/// has rejected any userinfo it carries, so a derived `Debug` would print
/// `user:password@` for exactly as long as the value is unvalidated. The host
/// and addresses are printed instead, which are the useful diagnostics and
/// cannot carry a secret.
pub struct DaemonBuilder {
    clock: Option<Arc<dyn Clock>>,
    listen: Vec<SocketAddr>,
    provider_host: String,
    provider_url: String,
    provider_addresses: Vec<IpAddr>,
    authorization_ttl: Duration,
    context_budget: usize,
    notes: Vec<String>,
    extra: Vec<Arc<dyn Subsystem>>,
}

impl fmt::Debug for DaemonBuilder {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("DaemonBuilder")
            .field("listen", &self.listen)
            .field("provider_host", &self.provider_host)
            .field("provider_url", &"[REDACTED]")
            .field("provider_addresses", &self.provider_addresses)
            .field("authorization_ttl", &self.authorization_ttl)
            .field("context_budget", &self.context_budget)
            .field("notes", &self.notes)
            .field("extra_subsystems", &self.extra.len())
            .finish_non_exhaustive()
    }
}

impl DaemonBuilder {
    /// Creates a builder with the default in-memory topology.
    #[must_use]
    pub fn new() -> Self {
        Self {
            clock: None,
            listen: vec![SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0)],
            provider_host: "models.example.test".to_owned(),
            provider_url: "https://models.example.test/v1".to_owned(),
            provider_addresses: vec![IpAddr::V4(Ipv4Addr::new(203, 0, 113, 10))],
            authorization_ttl: Duration::from_secs(5),
            context_budget: 4 * 1024,
            notes: vec!["the operator prefers concise answers".to_owned()],
            extra: Vec::new(),
        }
    }

    /// Adds a subsystem the daemon does not build for itself.
    ///
    /// This is the seam for anything that owns a real resource — a bound
    /// `TcpListener` serving an HTTP router, for example. The subsystem is
    /// ordered by the dependencies its own [`SubsystemDescriptor`] declares,
    /// not by the order it is added in, and it is started, quiesced and shut
    /// down exactly like a built-in one. Its background work must be spawned
    /// through [`StartContext::spawner`] so it is counted in the task ledger,
    /// and it should stop when [`StartContext::shutdown`] fires.
    #[must_use]
    pub fn with_subsystem(mut self, subsystem: Arc<dyn Subsystem>) -> Self {
        self.extra.push(subsystem);
        self
    }

    /// Uses `clock` instead of the process clock.
    #[must_use]
    pub fn clock(mut self, clock: Arc<dyn Clock>) -> Self {
        self.clock = Some(clock);
        self
    }

    /// Sets the addresses ingress subsystems report as bound.
    #[must_use]
    pub fn listen(mut self, listen: Vec<SocketAddr>) -> Self {
        self.listen = listen;
        self
    }

    /// Sets how long an authorization is granted for.
    #[must_use]
    pub const fn authorization_ttl(mut self, ttl: Duration) -> Self {
        self.authorization_ttl = ttl;
        self
    }

    /// Sets the byte budget handed to context assembly.
    #[must_use]
    pub const fn context_budget(mut self, budget: usize) -> Self {
        self.context_budget = budget;
        self
    }

    /// Builds the daemon without starting it.
    ///
    /// # Errors
    ///
    /// Returns a [`CompositionError`] when the subsystem graph cannot be
    /// ordered, or a [`SubsystemError`] wrapped in one when a port is missing.
    pub fn build(self) -> Result<Daemon, CompositionError> {
        let clock = self
            .clock
            .unwrap_or_else(|| Arc::new(ProcessClock) as Arc<dyn Clock>);

        let provider = ProviderName::new("primary").expect("the literal satisfies the grammar");
        let model = ModelName::new("standard").expect("the literal satisfies the grammar");
        let credential =
            CredentialName::new(CREDENTIAL).expect("the literal satisfies the grammar");

        let settings = Arc::new(RuntimeSettings::new(
            self.listen,
            provider.clone(),
            model.clone(),
            4,
            Duration::from_secs(60),
            self.authorization_ttl,
        ));

        let dns = Arc::new(TableDns::new([(
            self.provider_host.clone(),
            self.provider_addresses,
        )]));

        let egress = Arc::new(EgressGuard::new(
            EgressPolicy::deny_all()
                .allow_host(HostPattern::parse(&self.provider_host))
                .with_max_resolution_age(Duration::from_secs(10)),
            Arc::clone(&dns) as Arc<dyn DnsPort>,
            Arc::clone(&clock),
        ));

        let config = Arc::new(MutableConfig::new((*settings).clone()));
        let observability = Arc::new(MemoryObservability::default());
        let persistence = Arc::new(MemoryPersistence::new());
        let secrets = Arc::new(MemorySecrets::new());
        let providers = Arc::new(GuardedProviderRegistry::new(
            vec![ProviderConfig::new(
                provider,
                self.provider_url,
                credential,
                vec![model],
            )],
            Arc::clone(&egress),
        ));
        let transport = Arc::new(ScriptedTransport::new());
        let tools = Arc::new(MemoryToolSurface::new([
            FakeTool::succeeding(
                ToolName::new("workspace.read").expect("the literal satisfies the grammar"),
                reading_workspace(),
                "the workspace contains one crate",
            ),
            FakeTool::failing(
                ToolName::new("workspace.write").expect("the literal satisfies the grammar"),
                CapabilitySet::from_capabilities([Capability::WriteWorkspace]),
                "the workspace is read only in this composition",
            ),
        ]));
        let context = Arc::new(NoteContext::new(self.notes));
        let plugins = Arc::new(PerActivationPluginHost::new());
        let policy = Arc::new(LivePolicy::new(self.authorization_ttl));

        // The lifecycle is created before anything that depends on its gate, so
        // the issuer and the host observe the same gate. A capability minted
        // against a different gate would survive this composition draining.
        let lifecycle = Lifecycle::new();
        let issuer = Arc::new(GrantIssuer::new(
            Arc::clone(&policy) as Arc<dyn AuthorityPort>,
            Arc::clone(&clock),
            lifecycle.epoch_gate(),
            MAX_AUTHORIZATION_TTL,
        ));

        let service = Arc::new(
            SessionService::builder()
                .config(Arc::clone(&config) as Arc<dyn ConfigPort>)
                .persistence(Arc::clone(&persistence) as Arc<dyn PersistencePort>)
                .secrets(Arc::clone(&secrets) as Arc<dyn SecretStorePort>)
                .providers(Arc::clone(&providers) as Arc<dyn ProviderRegistryPort>)
                .transport(Arc::clone(&transport) as Arc<dyn ProviderTransportPort>)
                .tools(Arc::clone(&tools) as Arc<dyn ToolSurfacePort>)
                .context(Arc::clone(&context) as Arc<dyn ContextAssemblyPort>)
                .engine(Arc::new(DeterministicEngine) as Arc<dyn SessionEnginePort>)
                .observability(Arc::clone(&observability) as Arc<dyn ObservabilityPort>)
                .issuer(Arc::clone(&issuer))
                .clock(Arc::clone(&clock))
                .context_budget(self.context_budget)
                .build()?,
        );

        let gateway = Arc::new(GatewayIngress::new(
            Arc::clone(&service) as Arc<dyn GatewayDispatch>
        ));
        let http = Arc::new(LoopbackHttpApi::new(
            Arc::clone(&service) as Arc<dyn GatewayDispatch>,
            default_routes(),
        ));

        // Declaring the graph, not the order. The order is derived from these
        // edges, so a new subsystem only has to say what it needs.
        let mut subsystems: Vec<Arc<dyn Subsystem>> = vec![
            Arc::new(PortSubsystem::new(well_known::observability(), &[])),
            Arc::new(PortSubsystem::new(
                well_known::config(),
                &[well_known::observability()],
            )),
            Arc::new(PortSubsystem::new(
                well_known::persistence(),
                &[well_known::config(), well_known::observability()],
            )),
            Arc::new(PortSubsystem::new(
                well_known::secrets(),
                &[well_known::config(), well_known::persistence()],
            )),
            Arc::new(PortSubsystem::new(
                well_known::egress(),
                &[well_known::config()],
            )),
            Arc::new(PortSubsystem::new(
                well_known::providers(),
                &[well_known::secrets(), well_known::egress()],
            )),
            Arc::new(PortSubsystem::new(
                well_known::tools(),
                &[well_known::config(), well_known::observability()],
            )),
            Arc::new(PortSubsystem::new(
                well_known::memory(),
                &[well_known::persistence()],
            )),
            Arc::new(PortSubsystem::new(
                well_known::plugin_host(),
                &[well_known::tools(), well_known::observability()],
            )),
            Arc::new(PortSubsystem::new(
                well_known::engine(),
                &[
                    well_known::providers(),
                    well_known::tools(),
                    well_known::memory(),
                    well_known::persistence(),
                    well_known::plugin_host(),
                ],
            )),
            Arc::clone(&gateway) as Arc<dyn Subsystem>,
            Arc::clone(&http) as Arc<dyn Subsystem>,
        ];

        subsystems.extend(self.extra);

        let host = SubsystemHost::with_lifecycle(subsystems, lifecycle)?;

        Ok(Daemon {
            runtime: RuntimeHost::new(),
            host,
            settings,
            clock,
            service,
            config,
            policy,
            observability,
            persistence,
            secrets,
            providers,
            transport,
            tools,
            context,
            plugins,
            gateway,
            http,
            dns,
            started: false,
        })
    }
}

impl Default for DaemonBuilder {
    fn default() -> Self {
        Self::new()
    }
}

/// The routes the HTTP surface answers on.
///
/// `claw-http-api` owns the real list of eighteen. These three are enough to
/// show that the composition passes a matched route object onward rather than
/// re-parsing the path.
fn default_routes() -> Vec<HttpRoute> {
    vec![
        HttpRoute::unary("POST", "/v1/sessions"),
        HttpRoute::streaming("POST", "/v1/sessions/stream"),
        HttpRoute::unary("GET", "/v1/health"),
    ]
}

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
//! # Replacing a stand-in with a real crate
//!
//! Each `Arc<dyn Port>` below is the seam. When `claw-gateway` lands, the
//! `LoopbackGateway` line becomes a `claw_gateway::Server` line and nothing else
//! changes — not the plan, not the shutdown path, not the session service. That
//! is the whole point of doing this before the crates exist.

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
use tokio::time::{Instant, timeout};

use crate::adapters::engine::DeterministicEngine;
use crate::adapters::ingress::{LoopbackGateway, LoopbackHttpApi, PortSubsystem};
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

/// How long [`Daemon::stop`] gives the whole teardown before it reports the
/// stop as incomplete and returns anyway.
///
/// Chosen to sit inside the supervisor's own patience:
/// `packaging/linux/systemd/gta-claw-daemon.service` sets `TimeoutStopSec=15s`
/// with `SendSIGKILL=yes`, so a daemon that took longer than that would be
/// killed mid-teardown and the operator would be left with no summary at all.
/// Expiring first means the daemon is the one that reports the failure, names
/// the phase it was stuck in, and still exits.
pub const STOP_DEADLINE: Duration = Duration::from_secs(10);

/// What a completed run reports.
#[derive(Debug)]
pub struct StopSummary {
    shutdown: ShutdownReport,
    tasks: TaskLedger,
    phase: LifecyclePhase,
    deadline_expired: bool,
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

    /// Returns whether the stop ran out of time.
    ///
    /// When this is true the teardown was abandoned part way through, so
    /// [`shutdown`](Self::shutdown) describes only the subsystems that had
    /// already been drained and [`phase`](Self::phase) names how far the
    /// composition got. The subsystem that did not return is the one after the
    /// last drained one.
    #[must_use]
    pub const fn deadline_expired(&self) -> bool {
        self.deadline_expired
    }

    /// Returns whether the run ended with nothing abandoned and nothing leaked.
    #[must_use]
    pub fn is_clean(&self) -> bool {
        !self.deadline_expired
            && self.shutdown.is_clean()
            && self.tasks.is_settled()
            && self.phase == LifecyclePhase::Stopped
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
    gateway: Arc<LoopbackGateway>,
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
        self.provision_credentials().await?;
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
    /// spawned task, within [`STOP_DEADLINE`].
    ///
    /// # Errors
    ///
    /// Returns a [`CompositionError`] when the host was not in a phase that can
    /// be stopped — a daemon that was never started, or one already stopped.
    /// Nothing has been torn down that was not torn down already, so this is a
    /// caller sequencing mistake and the process may still exit.
    ///
    /// Subsystem failures during shutdown are *not* errors here: they are
    /// collected into the report so that one uncooperative adapter cannot abort
    /// the teardown of the others, and they show up as
    /// [`StopSummary::is_clean`] returning false.
    pub async fn stop(&mut self) -> Result<StopSummary, CompositionError> {
        self.stop_within(STOP_DEADLINE).await
    }

    /// Stops the daemon, giving the whole teardown at most `budget`.
    ///
    /// The budget covers both halves — draining the subsystems and joining the
    /// tasks — because a supervisor's kill timer covers both too. Whatever the
    /// first half leaves is what the second half gets.
    ///
    /// Running out of time is reported, not raised: the returned summary has
    /// [`deadline_expired`](StopSummary::deadline_expired) set and is not
    /// clean, and the caller is expected to log it and exit rather than retry.
    /// Retrying is nonetheless safe — the abandoned teardown resumes where it
    /// stopped, calling `shutdown` exactly once per subsystem — which is what
    /// makes abandoning it defensible in the first place.
    ///
    /// # Errors
    ///
    /// As [`stop`](Self::stop): only a phase the host cannot be stopped from.
    pub async fn stop_within(&mut self, budget: Duration) -> Result<StopSummary, CompositionError> {
        let started = Instant::now();
        let outcome = timeout(budget, self.host.shutdown()).await;
        let deadline_expired = outcome.is_err();
        let shutdown = match outcome {
            Ok(report) => report?,
            // The teardown future has been dropped part way through. The host
            // records that itself, so a later stop finishes what this one
            // abandoned; what is lost here is only the report of the drains
            // that had already happened.
            Err(_elapsed) => ShutdownReport::default(),
        };

        // The tasks are joined even when the subsystems ran out of time, so
        // that the ledger describes the whole process rather than nothing, and
        // with whatever budget is left rather than none: a stop that has
        // already overrun must not then wait indefinitely here.
        let tasks = self
            .runtime
            .shutdown_within(budget.saturating_sub(started.elapsed()))
            .await;
        self.started = false;

        Ok(StopSummary {
            shutdown,
            tasks,
            phase: self.host.phase(),
            deadline_expired,
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
    pub fn gateway(&self) -> Arc<LoopbackGateway> {
        Arc::clone(&self.gateway)
    }

    /// Returns the HTTP ingress.
    #[must_use]
    pub fn http(&self) -> Arc<LoopbackHttpApi> {
        Arc::clone(&self.http)
    }

    /// Returns the settings the composition was built with.
    ///
    /// The addresses in [`RuntimeSettings::listen`] are *requested*, not bound.
    /// Nothing in this composition opens a socket, so a subsystem that owns a
    /// real listener is what turns them into something being accepted on.
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
/// builder holds it before [`EgressGuard`]
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
    /// ordered by the dependencies its own
    /// [`SubsystemDescriptor`](claw_application::composition::SubsystemDescriptor) declares,
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

        let (provider, model, credential) = fixed_names();

        let settings = Arc::new(RuntimeSettings::new(
            self.listen,
            provider.clone(),
            model.clone(),
            4,
            Duration::from_mins(1),
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
                tool_name("workspace.read"),
                reading_workspace(),
                "the workspace contains one crate",
            ),
            FakeTool::failing(
                tool_name("workspace.write"),
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

        let gateway = Arc::new(LoopbackGateway::new(
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

/// The provider, model and credential names this composition is fixed to.
///
/// Kept out of [`DaemonBuilder::build`] so that building a daemon contains no
/// fallible name construction: these three literals are the only ones, and
/// `the_fixed_names_satisfy_their_grammars` is what holds them to the grammars
/// their types enforce. A typo here fails that test rather than an operator's
/// start-up.
fn fixed_names() -> (ProviderName, ModelName, CredentialName) {
    (
        ProviderName::new("primary").expect("the literal satisfies the grammar"),
        ModelName::new("standard").expect("the literal satisfies the grammar"),
        CredentialName::new(CREDENTIAL).expect("the literal satisfies the grammar"),
    )
}

/// Names one of the built-in tools.
///
/// Private, and called only with the two literals in [`DaemonBuilder::build`];
/// both are pinned by `the_fixed_names_satisfy_their_grammars`.
fn tool_name(literal: &str) -> ToolName {
    ToolName::new(literal).expect("the literal satisfies the grammar")
}

#[cfg(test)]
mod tests {
    use super::{CREDENTIAL, fixed_names, tool_name};

    /// The composition builds these names without a fallback, so the daemon can
    /// only start if every one of them satisfies its type's grammar. Proving it
    /// here is what keeps `build` infallible in that respect.
    #[test]
    fn the_fixed_names_satisfy_their_grammars() {
        let (provider, model, credential) = fixed_names();

        assert_eq!(provider.as_str(), "primary");
        assert_eq!(model.as_str(), "standard");
        assert_eq!(credential.as_str(), CREDENTIAL);
        assert_eq!(tool_name("workspace.read").as_str(), "workspace.read");
        assert_eq!(tool_name("workspace.write").as_str(), "workspace.write");
    }
}

//! The service that turns a request into a turn, and the capability object a
//! turn runs against.
//!
//! This is the only place in the workspace that mints capabilities, and it is
//! the only place that knows how the ports fit together. Everything it does
//! follows one shape:
//!
//! ```text
//! read current settings -> resolve to validated objects -> authorize this
//! action, now -> redeem once -> act on the validated object
//! ```
//!
//! Note the order. Settings are read per turn rather than captured at start-up,
//! resolution happens before authorization so the authority is asked about a
//! concrete destination rather than a name, and the grant is redeemed by the
//! port that performs the action rather than by the caller that requested it.

use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

use claw_domain::SessionId;

use super::BoxFuture;
use super::authority::{Action, ActionRequest, GrantIssuer, Principal};
use super::clock::Clock;
use super::error::{SubsystemError, SubsystemErrorKind};
use super::id::{SubsystemId, well_known};
use super::ports::{
    ConfigPort, ContextAssemblyPort, CredentialRequest, GatewayDispatch, ObservabilityPort,
    PersistencePort, ProviderRegistryPort, ProviderTransportPort, SecretStorePort,
    SessionEnginePort, ToolSurfacePort, TurnEventSink,
};
use super::session::{
    AssembledContext, GatewayRequest, GatewayResponse, ModelName, ObservedEvent, ProviderBinding,
    ProviderCall, ProviderReply, ResolvedSession, SessionRecord, Severity, ToolBinding, ToolCall,
    ToolName, ToolOutcome, TurnEvent, TurnRecord, TurnRequest, TurnSummary,
};

/// The Gateway method that runs a turn.
pub const METHOD_SESSION_PROMPT: &str = "session.prompt";

/// The Gateway method that reports what is stored about a session.
pub const METHOD_SESSION_DESCRIBE: &str = "session.describe";

/// What one turn did.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TurnReport {
    summary: TurnSummary,
    revision: u64,
    provider_calls: u64,
    tool_calls: u64,
    events: u64,
}

impl TurnReport {
    /// Returns the completed turn.
    #[must_use]
    pub const fn summary(&self) -> &TurnSummary {
        &self.summary
    }

    /// Returns the session revision after the turn was recorded.
    #[must_use]
    pub const fn revision(&self) -> u64 {
        self.revision
    }

    /// Returns how many provider calls the turn made, each of which was
    /// separately authorized.
    #[must_use]
    pub const fn provider_calls(&self) -> u64 {
        self.provider_calls
    }

    /// Returns how many tools the turn ran, each of which was separately
    /// authorized.
    #[must_use]
    pub const fn tool_calls(&self) -> u64 {
        self.tool_calls
    }

    /// Returns how many events the turn emitted.
    #[must_use]
    pub const fn events(&self) -> u64 {
        self.events
    }
}

/// Everything a running turn is allowed to reach, and nothing else.
///
/// The engine is handed one of these instead of the ports themselves. It cannot
/// call a provider or a tool without going back through this object, and each
/// call here re-authorizes at the moment it is made. That is what stops one
/// decision at the top of a turn from covering every action inside it.
///
/// [`Self::call_tool`] takes a name, which looks like a violation of the
/// validated-object rule but is not: the name is resolved *inside* against the
/// catalogue captured for this turn, and only the resulting [`ToolBinding`]
/// crosses the port. The engine never gets to hand a raw name to `claw-tools`.
pub struct TurnCapabilities {
    subsystem: SubsystemId,
    principal: Principal,
    session: ResolvedSession,
    binding: ProviderBinding,
    model: ModelName,
    catalogue: Vec<ToolBinding>,
    issuer: Arc<GrantIssuer>,
    secrets: Arc<dyn SecretStorePort>,
    transport: Arc<dyn ProviderTransportPort>,
    tools: Arc<dyn ToolSurfacePort>,
    provider_calls: AtomicU64,
    tool_calls: AtomicU64,
}

impl TurnCapabilities {
    /// Returns the tools available for this turn.
    #[must_use]
    pub fn available_tools(&self) -> &[ToolBinding] {
        &self.catalogue
    }

    /// Returns the provider binding chosen for this turn.
    #[must_use]
    pub const fn binding(&self) -> &ProviderBinding {
        &self.binding
    }

    /// Returns the session this turn belongs to.
    #[must_use]
    pub const fn session(&self) -> &ResolvedSession {
        &self.session
    }

    /// Returns how many provider calls have been made so far.
    #[must_use]
    pub fn provider_calls(&self) -> u64 {
        self.provider_calls.load(Ordering::SeqCst)
    }

    /// Returns how many tools have been run so far.
    #[must_use]
    pub fn tool_calls(&self) -> u64 {
        self.tool_calls.load(Ordering::SeqCst)
    }

    fn request(&self, action: Action) -> ActionRequest {
        ActionRequest::new(self.subsystem.clone(), self.principal.clone(), action)
            .in_session(self.session.id().clone())
    }

    /// Calls the turn's provider.
    ///
    /// Three decisions are taken here and none of them is reused: releasing the
    /// credential, and then sending the call. The lease is checked against the
    /// binding's origin before it is used, so a secret store that returns a
    /// credential filed against a different origin is caught here rather than
    /// leaking the secret to the wrong host.
    ///
    /// # Errors
    ///
    /// Returns a [`SubsystemError`] when either decision is refused, when the
    /// credential is bound elsewhere, or when the provider call itself fails.
    pub async fn call_provider(
        &self,
        prompt: &str,
        context: &AssembledContext,
    ) -> Result<ProviderReply, SubsystemError> {
        let credential = self
            .issuer
            .issue(
                &self.request(Action::ReadCredential {
                    credential: self.binding.credential().clone(),
                }),
                CredentialRequest::new(
                    self.binding.credential().clone(),
                    self.binding.origin().clone(),
                ),
            )
            .await
            .map_err(|denial| SubsystemError::denied(well_known::secrets(), &denial))?;

        let lease = self.secrets.lease(credential).await?;

        if !lease.is_bound_to(self.binding.origin()) {
            return Err(SubsystemError::invalid(
                well_known::secrets(),
                format!(
                    "credential {} is bound to {} but the call targets {}",
                    lease.name(),
                    lease.origin().authority(),
                    self.binding.origin().authority()
                ),
            ));
        }

        let call = ProviderCall::new(
            self.binding.clone(),
            lease,
            self.model.clone(),
            context.clone(),
            prompt.to_owned(),
        );
        let grant = self
            .issuer
            .issue(
                &self.request(Action::CallProvider {
                    provider: self.binding.name().clone(),
                    model: self.model.clone(),
                }),
                call,
            )
            .await
            .map_err(|denial| SubsystemError::denied(well_known::providers(), &denial))?;

        self.provider_calls.fetch_add(1, Ordering::SeqCst);
        self.transport.send(grant).await
    }

    /// Runs one tool.
    ///
    /// # Errors
    ///
    /// Returns a [`SubsystemError`] when the tool is not in this turn's
    /// catalogue, when authorization is refused, or when the tool could not be
    /// run. A tool that ran and failed comes back as a failed [`ToolOutcome`].
    pub async fn call_tool(
        &self,
        name: &ToolName,
        arguments: String,
    ) -> Result<ToolOutcome, SubsystemError> {
        let binding = self
            .catalogue
            .iter()
            .find(|candidate| candidate.name() == name)
            .ok_or_else(|| {
                SubsystemError::not_found(
                    well_known::tools(),
                    format!("{name} is not available to this turn"),
                )
            })?
            .clone();

        let action = Action::InvokeTool {
            tool: binding.name().clone(),
            required: binding.required_capabilities().clone(),
        };
        let call = ToolCall::new(binding, self.session.clone(), arguments);
        let grant = self
            .issuer
            .issue(&self.request(action), call)
            .await
            .map_err(|denial| SubsystemError::denied(well_known::tools(), &denial))?;

        self.tool_calls.fetch_add(1, Ordering::SeqCst);
        self.tools.invoke(grant).await
    }
}

impl std::fmt::Debug for TurnCapabilities {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("TurnCapabilities")
            .field("session", self.session.id())
            .field("provider", self.binding.name())
            .field("model", &self.model)
            .field("tools", &self.catalogue.len())
            .finish_non_exhaustive()
    }
}

/// Counts events and forwards them, so the service can report how many a turn
/// produced without the sink having to.
struct CountingSink<'a> {
    inner: &'a dyn TurnEventSink,
    count: AtomicU64,
}

impl TurnEventSink for CountingSink<'_> {
    fn emit(&self, event: TurnEvent) {
        self.count.fetch_add(1, Ordering::SeqCst);
        self.inner.emit(event);
    }
}

/// Collects the ports a [`SessionService`] needs.
///
/// A builder rather than a constructor because a service needs ten
/// collaborators and a ten-argument function is unreadable and easy to get
/// wrong at a call site.
#[derive(Default)]
pub struct SessionServiceBuilder {
    config: Option<Arc<dyn ConfigPort>>,
    persistence: Option<Arc<dyn PersistencePort>>,
    secrets: Option<Arc<dyn SecretStorePort>>,
    providers: Option<Arc<dyn ProviderRegistryPort>>,
    transport: Option<Arc<dyn ProviderTransportPort>>,
    tools: Option<Arc<dyn ToolSurfacePort>>,
    context: Option<Arc<dyn ContextAssemblyPort>>,
    engine: Option<Arc<dyn SessionEnginePort>>,
    observability: Option<Arc<dyn ObservabilityPort>>,
    issuer: Option<Arc<GrantIssuer>>,
    clock: Option<Arc<dyn Clock>>,
    context_budget: Option<usize>,
}

macro_rules! builder_setters {
    ($($field:ident: $type:ty => $doc:literal;)+) => {
        $(
            #[doc = $doc]
            #[must_use]
            pub fn $field(mut self, port: $type) -> Self {
                self.$field = Some(port);
                self
            }
        )+
    };
}

impl SessionServiceBuilder {
    /// Creates an empty builder.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    builder_setters! {
        config: Arc<dyn ConfigPort> => "Supplies the configuration port.";
        persistence: Arc<dyn PersistencePort> => "Supplies the persistence port.";
        secrets: Arc<dyn SecretStorePort> => "Supplies the secret store port.";
        providers: Arc<dyn ProviderRegistryPort> => "Supplies the provider registry port.";
        transport: Arc<dyn ProviderTransportPort> => "Supplies the provider transport port.";
        tools: Arc<dyn ToolSurfacePort> => "Supplies the tool surface port.";
        context: Arc<dyn ContextAssemblyPort> => "Supplies the context assembly port.";
        engine: Arc<dyn SessionEnginePort> => "Supplies the session engine port.";
        observability: Arc<dyn ObservabilityPort> => "Supplies the observability port.";
        issuer: Arc<GrantIssuer> => "Supplies the grant issuer.";
        clock: Arc<dyn Clock> => "Supplies the clock.";
    }

    /// Sets the byte budget handed to context assembly, which defaults to 32 KiB.
    #[must_use]
    pub const fn context_budget(mut self, budget: usize) -> Self {
        self.context_budget = Some(budget);
        self
    }

    /// Builds the service.
    ///
    /// # Errors
    ///
    /// Returns a [`SubsystemError`] naming the first port that was not
    /// supplied, so a mis-wired composition fails at assembly rather than on the
    /// first request.
    pub fn build(self) -> Result<SessionService, SubsystemError> {
        fn require<T>(port: Option<T>, name: &str) -> Result<T, SubsystemError> {
            port.ok_or_else(|| {
                SubsystemError::invalid(
                    well_known::engine(),
                    format!("the composition did not supply the {name} port"),
                )
            })
        }

        Ok(SessionService {
            subsystem: well_known::engine(),
            config: require(self.config, "configuration")?,
            persistence: require(self.persistence, "persistence")?,
            secrets: require(self.secrets, "secret store")?,
            providers: require(self.providers, "provider registry")?,
            transport: require(self.transport, "provider transport")?,
            tools: require(self.tools, "tool surface")?,
            context: require(self.context, "context assembly")?,
            engine: require(self.engine, "session engine")?,
            observability: require(self.observability, "observability")?,
            issuer: require(self.issuer, "grant issuer")?,
            clock: require(self.clock, "clock")?,
            context_budget: self.context_budget.unwrap_or(32 * 1024),
        })
    }
}

impl std::fmt::Debug for SessionServiceBuilder {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("SessionServiceBuilder")
            .field("context_budget", &self.context_budget)
            .finish_non_exhaustive()
    }
}

/// Runs turns.
///
/// This is the composition's own subsystem: it implements
/// [`GatewayDispatch`], so every ingress crate can be handed one of these and
/// none of them has to know how a turn is assembled.
pub struct SessionService {
    subsystem: SubsystemId,
    config: Arc<dyn ConfigPort>,
    persistence: Arc<dyn PersistencePort>,
    secrets: Arc<dyn SecretStorePort>,
    providers: Arc<dyn ProviderRegistryPort>,
    transport: Arc<dyn ProviderTransportPort>,
    tools: Arc<dyn ToolSurfacePort>,
    context: Arc<dyn ContextAssemblyPort>,
    engine: Arc<dyn SessionEnginePort>,
    observability: Arc<dyn ObservabilityPort>,
    issuer: Arc<GrantIssuer>,
    clock: Arc<dyn Clock>,
    context_budget: usize,
}

impl SessionService {
    /// Starts building a service.
    #[must_use]
    pub fn builder() -> SessionServiceBuilder {
        SessionServiceBuilder::new()
    }

    fn request(&self, principal: &Principal, action: Action, session: &SessionId) -> ActionRequest {
        ActionRequest::new(self.subsystem.clone(), principal.clone(), action)
            .in_session(session.clone())
    }

    /// Resolves a session, creating it when it has never been seen.
    ///
    /// # Errors
    ///
    /// Returns a [`SubsystemError`] when persistence fails or the principal is
    /// not allowed to address the session.
    pub async fn open_session(
        &self,
        principal: &Principal,
        id: &SessionId,
    ) -> Result<ResolvedSession, SubsystemError> {
        let stored = self.persistence.load_session(id).await?;
        let revision = stored.as_ref().map_or(0, SessionRecord::revision);
        let candidate =
            ResolvedSession::new(id.clone(), principal.clone(), revision, self.clock.now());

        let grant = self
            .issuer
            .issue(&self.request(principal, Action::OpenSession, id), candidate)
            .await
            .map_err(|denial| SubsystemError::denied(self.subsystem.clone(), &denial))?;

        grant
            .redeem()
            .map_err(|denial| SubsystemError::denied(self.subsystem.clone(), &denial))
    }

    /// Runs one turn from start to durable record.
    ///
    /// # Errors
    ///
    /// Returns a [`SubsystemError`] when any step is refused or fails. Nothing
    /// is written when the turn does not complete: the transaction is only
    /// opened once the engine has returned.
    pub async fn run_turn(
        &self,
        principal: &Principal,
        id: &SessionId,
        prompt: &str,
        events: &dyn TurnEventSink,
    ) -> Result<TurnReport, SubsystemError> {
        let settings = self.config.settings().await?;
        let session = self.open_session(principal, id).await?;

        let binding = self
            .providers
            .resolve(settings.default_provider(), settings.default_model())
            .await?;
        let model = settings.default_model().clone();

        if !binding.offers(&model) {
            return Err(SubsystemError::invalid(
                well_known::providers(),
                format!("{} does not offer {model}", binding.name()),
            ));
        }

        let assembled = self
            .context
            .assemble(&session, prompt, self.context_budget)
            .await?;
        let catalogue = self.tools.catalogue(&session).await?;

        let deadline = self
            .clock
            .now()
            .checked_add(settings.turn_deadline())
            .ok_or_else(|| {
                SubsystemError::internal(
                    self.subsystem.clone(),
                    "the turn deadline overflowed the monotonic timeline",
                )
            })?;

        let capabilities = TurnCapabilities {
            subsystem: self.subsystem.clone(),
            principal: principal.clone(),
            session: session.clone(),
            binding: binding.clone(),
            model: model.clone(),
            catalogue,
            issuer: Arc::clone(&self.issuer),
            secrets: Arc::clone(&self.secrets),
            transport: Arc::clone(&self.transport),
            tools: Arc::clone(&self.tools),
            provider_calls: AtomicU64::new(0),
            tool_calls: AtomicU64::new(0),
        };

        let turn = TurnRequest::new(
            session.clone(),
            prompt.to_owned(),
            binding,
            model,
            assembled,
            deadline,
        );
        let grant = self
            .issuer
            .issue(&self.request(principal, Action::SubmitTurn, id), turn)
            .await
            .map_err(|denial| SubsystemError::denied(self.subsystem.clone(), &denial))?;

        let sink = CountingSink {
            inner: events,
            count: AtomicU64::new(0),
        };

        let summary = match self.engine.run_turn(grant, &capabilities, &sink).await {
            Ok(summary) => summary,
            Err(error) => {
                self.observability.record(ObservedEvent::new(
                    self.subsystem.clone(),
                    Severity::Error,
                    format!("turn in {id} failed: {error}"),
                    self.clock.now(),
                ));
                return Err(error);
            }
        };

        let revision = self
            .record_turn(principal, &session, prompt, &summary)
            .await?;

        self.observability.record(ObservedEvent::new(
            self.subsystem.clone(),
            Severity::Info,
            format!("turn in {id} completed at revision {revision}"),
            self.clock.now(),
        ));

        Ok(TurnReport {
            summary,
            revision,
            provider_calls: capabilities.provider_calls(),
            tool_calls: capabilities.tool_calls(),
            events: sink.count.load(Ordering::SeqCst),
        })
    }

    async fn record_turn(
        &self,
        principal: &Principal,
        session: &ResolvedSession,
        prompt: &str,
        summary: &TurnSummary,
    ) -> Result<u64, SubsystemError> {
        let grant = self
            .issuer
            .issue(
                &self.request(principal, Action::RecordTurn, session.id()),
                (),
            )
            .await
            .map_err(|denial| SubsystemError::denied(well_known::persistence(), &denial))?;
        grant
            .redeem()
            .map_err(|denial| SubsystemError::denied(well_known::persistence(), &denial))?;

        let revision = session.revision() + 1;
        let mut transaction = self.persistence.begin().await?;

        if let Err(error) =
            transaction.upsert_session(SessionRecord::new(session.id().clone(), revision, 1))
        {
            let _ = transaction.rollback().await;
            return Err(error);
        }

        if let Err(error) = transaction.append_turn(TurnRecord::new(
            session.id().clone(),
            revision,
            prompt.to_owned(),
            summary.response().to_owned(),
        )) {
            let _ = transaction.rollback().await;
            return Err(error);
        }

        transaction.commit().await?;

        Ok(revision)
    }

    async fn describe(
        &self,
        principal: &Principal,
        id: &SessionId,
    ) -> Result<GatewayResponse, SubsystemError> {
        let session = self.open_session(principal, id).await?;
        let turns = self
            .persistence
            .load_session(id)
            .await?
            .map_or(0, |record| record.turns());

        Ok(GatewayResponse::new(
            format!(
                "{} revision {} turns {turns}",
                session.id(),
                session.revision()
            ),
            0,
        ))
    }
}

/// Discards every event, for callers that only want the final answer.
#[derive(Clone, Copy, Debug, Default)]
pub struct DiscardEvents;

impl TurnEventSink for DiscardEvents {
    fn emit(&self, _event: TurnEvent) {}
}

impl GatewayDispatch for SessionService {
    fn dispatch(
        &self,
        request: GatewayRequest,
    ) -> BoxFuture<'_, Result<GatewayResponse, SubsystemError>> {
        Box::pin(async move {
            match request.method() {
                METHOD_SESSION_PROMPT => {
                    let report = self
                        .run_turn(
                            request.principal(),
                            request.session(),
                            request.payload(),
                            &DiscardEvents,
                        )
                        .await?;

                    Ok(GatewayResponse::new(
                        report.summary().response().to_owned(),
                        report.events(),
                    ))
                }
                METHOD_SESSION_DESCRIBE => {
                    self.describe(request.principal(), request.session()).await
                }
                unknown => Err(SubsystemError::new(
                    self.subsystem.clone(),
                    SubsystemErrorKind::NotFound,
                    format!("no such method: {unknown}"),
                )),
            }
        })
    }

    fn methods(&self) -> Vec<String> {
        let mut methods = vec![
            METHOD_SESSION_DESCRIBE.to_owned(),
            METHOD_SESSION_PROMPT.to_owned(),
        ];
        methods.sort_unstable();
        methods
    }
}

impl std::fmt::Debug for SessionService {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("SessionService")
            .field("subsystem", &self.subsystem)
            .field("context_budget", &self.context_budget)
            .field("config_generation", &self.config.generation())
            .finish_non_exhaustive()
    }
}

#[cfg(test)]
mod tests {
    use super::{DiscardEvents, SessionServiceBuilder, TurnReport};
    use crate::composition::error::SubsystemErrorKind;
    use crate::composition::ports::TurnEventSink;
    use crate::composition::session::{
        ModelName, ProviderName, ToolName, ToolOutcome, TurnEvent, TurnSummary,
    };

    #[test]
    fn a_builder_missing_a_port_names_that_port_instead_of_panicking() {
        let error = SessionServiceBuilder::new()
            .build()
            .expect_err("no ports were supplied");

        assert_eq!(error.kind(), SubsystemErrorKind::Invalid);
        assert_eq!(error.subsystem().as_str(), "engine");
        assert_eq!(
            error.detail(),
            "the composition did not supply the configuration port"
        );
    }

    #[test]
    fn discarding_events_accepts_every_variant_without_recording_anything() {
        let sink = DiscardEvents;

        sink.emit(TurnEvent::Started { sequence: 0 });
        sink.emit(TurnEvent::AssistantDelta {
            sequence: 1,
            text: "hello".to_owned(),
        });
        sink.emit(TurnEvent::ToolCompleted {
            sequence: 2,
            outcome: ToolOutcome::success(ToolName::new("noop").expect("valid"), String::new()),
        });
        sink.emit(TurnEvent::Finished {
            sequence: 3,
            summary: TurnSummary::new(
                "done".to_owned(),
                ProviderName::new("p").expect("valid"),
                ModelName::new("m").expect("valid"),
                0,
            ),
        });
    }

    #[test]
    fn a_report_exposes_each_count_separately() {
        let report = TurnReport {
            summary: TurnSummary::new(
                "answer".to_owned(),
                ProviderName::new("openai").expect("valid"),
                ModelName::new("gpt-5").expect("valid"),
                2,
            ),
            revision: 7,
            provider_calls: 3,
            tool_calls: 2,
            events: 11,
        };

        assert_eq!(report.summary().response(), "answer");
        assert_eq!(report.summary().tool_calls(), 2);
        assert_eq!(report.revision(), 7);
        assert_eq!(report.provider_calls(), 3);
        assert_eq!(report.tool_calls(), 2);
        assert_eq!(report.events(), 11);
    }
}

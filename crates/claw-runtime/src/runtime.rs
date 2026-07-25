//! The turn orchestrator.
//!
//! [`Runtime`] owns the only place in the crate that spawns tasks. Every task is registered with
//! a [`TaskTracker`] and every task observes a [`CancellationToken`], so
//! [`Runtime::shutdown`] provably joins all of them. All queues are bounded
//! [`tokio::sync::mpsc`] channels, pause/resume rides a [`tokio::sync::watch`], and each turn
//! reports its result through a [`tokio::sync::oneshot`].

use std::collections::HashMap;
use std::error::Error;
use std::fmt::{self, Display, Formatter};
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::Duration;

use claw_application::model::approval::{ApprovalDecision, ApprovalWithdrawal};
use claw_application::model::goal::GoalRecord;
use claw_application::model::ids::{ApprovalId, GoalId, IdentifierError, TurnId};
use claw_application::model::message::{AssistantMessage, PartialAssistantMessage, ToolCall};
use claw_application::model::session::{SessionEvent, SessionState};
use claw_application::ports::PortError;
use claw_application::ports::approval::ApprovalPort;
use claw_application::ports::clock::ClockPort;
use claw_application::ports::context::{
    BootstrapReason, ContextAssembly, ContextBootstrap, ContextCompaction, ContextEnginePort,
    ContextIngest, ContextItem, ContextMaintenance, ContextState,
};
use claw_application::ports::goal::GoalStorePort;
use claw_application::ports::provider::{ProviderPort, ProviderRequest};
use claw_application::ports::state::{SessionSnapshot, StatePort, TurnRecord};
use claw_application::ports::tool::{
    ToolDescriptor, ToolInvocation, ToolOutcome, ToolPort, ToolStatus,
};
use claw_domain::SessionId;
use tokio::sync::{mpsc, oneshot, watch};
use tokio_util::sync::CancellationToken;
use tokio_util::task::TaskTracker;

use crate::approval::{ApprovalBroker, ApprovalError};
use crate::command::{
    CommandEffect, CommandError, CommandRegistry, CommandSpec, DirectiveError, DirectiveRegistry,
    ScopeSet, TurnOptions,
};
use crate::goal::{GoalConfig, GoalError, GoalService};
use crate::session::{StateMachineError, TurnStateMachine};
use crate::stream::{StreamAssembler, StreamError, StreamEvent, StreamPayload};
use crate::suspend::{
    PrepareOutcome, PrepareRequest, SuspendError, SuspensionController, SuspensionStatus,
    WorkRefused,
};
use crate::tool::{ToolExecutionError, ToolExecutor, ToolExecutorConfig};

/// Tunable limits for one runtime instance.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RuntimeConfig {
    /// The capacity of every per-turn event channel.
    pub event_capacity: usize,
    /// How long an unanswered approval request survives.
    pub approval_timeout: Duration,
    /// How long a single tool call may run.
    pub tool_timeout: Duration,
    /// The most provider rounds one turn may take before it is blocked.
    pub max_rounds: u32,
    /// The token budget handed to the context engine.
    pub context_token_budget: u32,
    /// Durable goal limits.
    pub goals: GoalConfig,
}

impl Default for RuntimeConfig {
    fn default() -> Self {
        Self {
            event_capacity: 64,
            approval_timeout: Duration::from_secs(300),
            tool_timeout: Duration::from_secs(120),
            max_rounds: 16,
            context_token_budget: 128_000,
            goals: GoalConfig::default(),
        }
    }
}

/// Every outbound dependency the runtime needs.
#[derive(Clone)]
pub struct RuntimePorts {
    /// Wall-clock readings and delays.
    pub clock: Arc<dyn ClockPort>,
    /// The model provider.
    pub provider: Arc<dyn ProviderPort>,
    /// Session persistence.
    pub state: Arc<dyn StatePort>,
    /// Tool execution.
    pub tools: Arc<dyn ToolPort>,
    /// Approval presentation.
    pub approvals: Arc<dyn ApprovalPort>,
    /// Durable goal persistence.
    pub goals: Arc<dyn GoalStorePort>,
    /// Context assembly.
    pub context: Arc<dyn ContextEnginePort>,
}

impl fmt::Debug for RuntimePorts {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RuntimePorts")
            .finish_non_exhaustive()
    }
}

/// What one runtime event reports.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum RuntimeEventKind {
    /// The turn changed user-visible state.
    StateChanged {
        /// The state the turn left.
        from: SessionState,
        /// The state the turn entered.
        to: SessionState,
    },
    /// The provider stream produced an assembled event.
    Stream(StreamEvent),
    /// A tool call is waiting for an operator decision.
    AwaitingApproval {
        /// The call awaiting permission.
        call: ToolCall,
    },
    /// A tool call started running.
    ToolStarted {
        /// The call that started.
        call: ToolCall,
    },
    /// A tool call reached a terminal outcome.
    ToolFinished {
        /// The outcome.
        outcome: ToolOutcome,
    },
    /// A provider round finished.
    RoundFinished {
        /// The zero-based round index.
        round: u32,
        /// How many tool calls the round requested.
        tool_calls: usize,
    },
    /// The context engine shed context.
    ContextCompacted {
        /// How many items were removed.
        removed_items: u32,
        /// How many tokens were freed.
        reclaimed_tokens: u32,
    },
    /// The durable goal changed.
    GoalUpdated {
        /// The goal after the change.
        goal: GoalRecord,
    },
    /// The turn failed.
    Failed {
        /// A human-readable reason.
        reason: String,
    },
}

/// One event emitted while a turn runs.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RuntimeEvent {
    /// The session that produced the event.
    pub session_id: SessionId,
    /// The turn that produced the event.
    pub turn: TurnId,
    /// What happened.
    pub kind: RuntimeEventKind,
}

/// Everything a finished turn produced.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TurnOutcome {
    /// The session that ran the turn.
    pub session_id: SessionId,
    /// The turn identifier.
    pub turn: TurnId,
    /// The terminal state the turn reached.
    pub state: SessionState,
    /// The final assistant message, when one completed.
    pub message: Option<AssistantMessage>,
    /// The recoverable remains of an interrupted stream.
    pub partial: Option<PartialAssistantMessage>,
    /// How many provider rounds ran.
    pub rounds: u32,
    /// Every tool outcome, in execution order.
    pub tool_outcomes: Vec<ToolOutcome>,
}

/// A refused or failed runtime operation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum RuntimeError {
    /// A port failed.
    Port(PortError),
    /// The state machine refused a transition.
    State(StateMachineError),
    /// The provider violated the stream contract.
    Stream(StreamError),
    /// A tool could not be brokered.
    Tool(ToolExecutionError),
    /// A goal operation failed.
    Goal(GoalError),
    /// The approval broker failed.
    Approval(ApprovalError),
    /// The suspension controller refused the operation.
    Suspend(SuspendError),
    /// The runtime is quiescing and refuses new work.
    Quiescing(WorkRefused),
    /// A command line was rejected.
    Command(CommandError),
    /// A directive was rejected.
    Directive(DirectiveError),
    /// The runtime is shutting down.
    ShuttingDown,
    /// The session already has a turn in flight.
    TurnInFlight {
        /// The turn that holds the session.
        turn: TurnId,
    },
    /// No turn is running for that session.
    NoTurnInFlight,
    /// An identifier could not be minted.
    Identifier(IdentifierError),
    /// The turn task ended without reporting an outcome.
    Abandoned,
}

impl Display for RuntimeError {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        match self {
            Self::Port(error) => write!(formatter, "port failed: {error}"),
            Self::State(error) => write!(formatter, "state machine refused: {error}"),
            Self::Stream(error) => write!(formatter, "provider stream rejected: {error}"),
            Self::Tool(error) => write!(formatter, "tool failed: {error}"),
            Self::Goal(error) => write!(formatter, "goal failed: {error}"),
            Self::Approval(error) => write!(formatter, "approval failed: {error}"),
            Self::Suspend(error) => write!(formatter, "suspension failed: {error}"),
            Self::Quiescing(error) => Display::fmt(error, formatter),
            Self::Command(error) => write!(formatter, "command rejected: {error}"),
            Self::Directive(error) => write!(formatter, "directive rejected: {error}"),
            Self::ShuttingDown => formatter.write_str("the runtime is shutting down"),
            Self::TurnInFlight { turn } => {
                write!(formatter, "turn {turn} is already running for this session")
            }
            Self::NoTurnInFlight => formatter.write_str("no turn is running for this session"),
            Self::Identifier(error) => write!(formatter, "identifier rejected: {error}"),
            Self::Abandoned => formatter.write_str("the turn ended without reporting an outcome"),
        }
    }
}

impl Error for RuntimeError {}

macro_rules! runtime_error_from {
    ($($source:ty => $variant:ident),* $(,)?) => {
        $(
            impl From<$source> for RuntimeError {
                fn from(value: $source) -> Self {
                    Self::$variant(value)
                }
            }
        )*
    };
}

runtime_error_from! {
    PortError => Port,
    StateMachineError => State,
    StreamError => Stream,
    ToolExecutionError => Tool,
    GoalError => Goal,
    ApprovalError => Approval,
    SuspendError => Suspend,
    WorkRefused => Quiescing,
    CommandError => Command,
    DirectiveError => Directive,
    IdentifierError => Identifier,
}

/// The caller's view of a running turn.
#[derive(Debug)]
pub struct TurnHandle {
    session_id: SessionId,
    turn: TurnId,
    events: mpsc::Receiver<RuntimeEvent>,
    completion: oneshot::Receiver<Result<TurnOutcome, RuntimeError>>,
    cancel: CancellationToken,
}

impl TurnHandle {
    /// Returns the session running the turn.
    #[must_use]
    pub const fn session_id(&self) -> &SessionId {
        &self.session_id
    }

    /// Returns the turn identifier.
    #[must_use]
    pub const fn turn(&self) -> TurnId {
        self.turn
    }

    /// Requests cancellation of this turn only.
    pub fn cancel(&self) {
        self.cancel.cancel();
    }

    /// Returns the next event, or `None` once the turn stopped emitting.
    pub async fn next_event(&mut self) -> Option<RuntimeEvent> {
        self.events.recv().await
    }

    /// Drains every event emitted so far without waiting.
    #[must_use]
    pub fn drain_events(&mut self) -> Vec<RuntimeEvent> {
        let mut events = Vec::new();
        while let Ok(event) = self.events.try_recv() {
            events.push(event);
        }
        events
    }

    /// Waits for the turn to finish.
    ///
    /// # Errors
    ///
    /// Returns the turn's own failure, or [`RuntimeError::Abandoned`] when the task disappeared
    /// without reporting.
    pub async fn join(self) -> Result<TurnOutcome, RuntimeError> {
        match self.completion.await {
            Ok(result) => result,
            Err(_) => Err(RuntimeError::Abandoned),
        }
    }
}

/// What a dispatched command produced.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum CommandOutcome {
    /// The advertised commands the caller may run.
    Commands(Vec<CommandSpec>),
    /// Every persisted session.
    Sessions(Vec<SessionSnapshot>),
    /// Every tool the runtime can dispatch.
    Tools(Vec<ToolDescriptor>),
    /// The command was applied and produced no payload.
    Acknowledged,
    /// The session's durable goal.
    Goal(Option<GoalRecord>),
    /// The suspension status.
    Suspension(SuspensionStatus),
    /// The result of a suspend request.
    SuspensionPrepared(PrepareOutcome),
    /// The engine's report after a compaction pass.
    Compaction {
        /// How many items were removed.
        removed_items: u32,
        /// How many tokens were freed.
        reclaimed_tokens: u32,
    },
    /// The registry resolved a command this runtime does not implement.
    Unsupported {
        /// The command name.
        name: String,
    },
}

#[derive(Debug)]
struct LiveTurn {
    turn: TurnId,
    cancel: CancellationToken,
    paused: watch::Sender<bool>,
}

struct RuntimeInner {
    config: RuntimeConfig,
    ports: RuntimePorts,
    broker: ApprovalBroker,
    executor: ToolExecutor,
    goals: GoalService,
    suspension: SuspensionController,
    commands: CommandRegistry,
    directives: DirectiveRegistry,
    live: Mutex<HashMap<String, LiveTurn>>,
    shutdown: CancellationToken,
}

impl RuntimeInner {
    fn live(&self) -> MutexGuard<'_, HashMap<String, LiveTurn>> {
        self.live
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }
}

/// The agent execution runtime.
#[derive(Clone)]
pub struct Runtime {
    inner: Arc<RuntimeInner>,
    tracker: TaskTracker,
}

impl fmt::Debug for Runtime {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("Runtime")
            .field("live_turns", &self.inner.live().len())
            .field("tracked_tasks", &self.tracker.len())
            .field("shutting_down", &self.inner.shutdown.is_cancelled())
            .finish_non_exhaustive()
    }
}

impl Runtime {
    /// Creates a runtime over a set of ports.
    #[must_use]
    pub fn new(ports: RuntimePorts, config: RuntimeConfig) -> Self {
        let broker = ApprovalBroker::new(
            Arc::clone(&ports.approvals),
            Arc::clone(&ports.clock),
            config.approval_timeout,
        );
        let executor = ToolExecutor::new(
            Arc::clone(&ports.tools),
            broker.clone(),
            Arc::clone(&ports.clock),
            ToolExecutorConfig {
                call_timeout: config.tool_timeout,
            },
        );
        let goals = GoalService::new(
            Arc::clone(&ports.goals),
            Arc::clone(&ports.clock),
            config.goals,
        );
        let suspension = SuspensionController::new(Arc::clone(&ports.clock));

        Self {
            inner: Arc::new(RuntimeInner {
                config,
                ports,
                broker,
                executor,
                goals,
                suspension,
                commands: CommandRegistry::builtin(),
                directives: DirectiveRegistry::builtin(),
                live: Mutex::new(HashMap::new()),
                shutdown: CancellationToken::new(),
            }),
            tracker: TaskTracker::new(),
        }
    }

    /// Returns the approval broker, so hosts can answer requests out of band.
    #[must_use]
    pub fn approvals(&self) -> &ApprovalBroker {
        &self.inner.broker
    }

    /// Returns the durable goal service.
    #[must_use]
    pub fn goals(&self) -> &GoalService {
        &self.inner.goals
    }

    /// Returns the cooperative suspension controller.
    #[must_use]
    pub fn suspension(&self) -> &SuspensionController {
        &self.inner.suspension
    }

    /// Returns the command vocabulary.
    #[must_use]
    pub fn commands(&self) -> &CommandRegistry {
        &self.inner.commands
    }

    /// Returns the directive vocabulary.
    #[must_use]
    pub fn directives(&self) -> &DirectiveRegistry {
        &self.inner.directives
    }

    /// Returns how many turn tasks the tracker is still holding.
    ///
    /// After [`Runtime::shutdown`] resolves this is always zero, which is what the task-leak
    /// tests assert.
    #[must_use]
    pub fn tracked_tasks(&self) -> usize {
        self.tracker.len()
    }

    /// Submits one operator input, scanning it for inline directives first.
    ///
    /// # Errors
    ///
    /// Returns [`RuntimeError::Directive`] when the input carries a bad directive, and everything
    /// [`Runtime::submit_with`] can return.
    pub async fn submit(
        &self,
        session_id: &SessionId,
        input: &str,
    ) -> Result<TurnHandle, RuntimeError> {
        let scan = self.inner.directives.scan(input)?;
        let options = self.inner.directives.apply(&scan.directives)?;
        self.submit_with(session_id, &scan.body, options).await
    }

    /// Submits one operator input with explicit turn options.
    ///
    /// # Errors
    ///
    /// Returns [`RuntimeError::ShuttingDown`] after shutdown started,
    /// [`RuntimeError::Quiescing`] while the host is suspending, [`RuntimeError::TurnInFlight`]
    /// when the session is busy, and [`RuntimeError::Port`] when the state store fails.
    pub async fn submit_with(
        &self,
        session_id: &SessionId,
        input: &str,
        options: TurnOptions,
    ) -> Result<TurnHandle, RuntimeError> {
        if self.inner.shutdown.is_cancelled() {
            return Err(RuntimeError::ShuttingDown);
        }

        let permit = self.inner.suspension.admit()?;

        let snapshot = self.inner.ports.state.load_session(session_id).await?;
        let (turn, revision, reason) = match &snapshot {
            Some(existing) => (
                existing.turn.next(),
                existing.revision,
                BootstrapReason::Restart,
            ),
            None => (TurnId::FIRST, 0, BootstrapReason::NewSession),
        };

        let cancel = self.inner.shutdown.child_token();
        let (paused, pause_rx) = watch::channel(false);

        {
            let mut live = self.inner.live();
            if let Some(existing) = live.get(session_id.as_str()) {
                return Err(RuntimeError::TurnInFlight {
                    turn: existing.turn,
                });
            }
            live.insert(
                session_id.as_str().to_owned(),
                LiveTurn {
                    turn,
                    cancel: cancel.clone(),
                    paused,
                },
            );
        }

        let (events_tx, events_rx) = mpsc::channel(self.inner.config.event_capacity.max(1));
        let (completion_tx, completion_rx) = oneshot::channel();

        let execution = TurnExecution {
            inner: Arc::clone(&self.inner),
            session_id: session_id.clone(),
            turn,
            revision,
            reason,
            input: input.to_owned(),
            options,
            events: events_tx,
            cancel: cancel.clone(),
            pause: pause_rx,
        };

        let spawned = self.tracker.spawn(async move {
            let session_key = execution.session_id.as_str().to_owned();
            let inner = Arc::clone(&execution.inner);
            let result = execution.run().await;
            inner.live().remove(&session_key);
            // The permit is released here, after the live-turn entry is gone, so a suspend that
            // observes zero in-flight work also observes an empty live-turn map.
            drop(permit);
            let _ = completion_tx.send(result);
        });
        drop(spawned);

        Ok(TurnHandle {
            session_id: session_id.clone(),
            turn,
            events: events_rx,
            completion: completion_rx,
            cancel,
        })
    }

    /// Parses and executes one operator command line.
    ///
    /// # Errors
    ///
    /// Returns [`RuntimeError::Command`] when the line is rejected, and the port or service error
    /// raised by the command's effect.
    pub async fn dispatch_command(
        &self,
        session_id: &SessionId,
        line: &str,
        scopes: ScopeSet,
    ) -> Result<CommandOutcome, RuntimeError> {
        let invocation = self.inner.commands.parse(line, scopes)?;
        let effect = CommandRegistry::effect(&invocation)?;
        self.execute_effect(session_id, effect).await
    }

    /// Executes an already-resolved command effect.
    ///
    /// # Errors
    ///
    /// Returns the port or service error raised by the effect.
    pub async fn execute_effect(
        &self,
        session_id: &SessionId,
        effect: CommandEffect,
    ) -> Result<CommandOutcome, RuntimeError> {
        match effect {
            CommandEffect::ListCommands => Ok(CommandOutcome::Commands(
                self.inner.commands.specs().to_vec(),
            )),
            CommandEffect::ShowStatus => Ok(CommandOutcome::Sessions(
                self.inner.ports.state.list_sessions().await?,
            )),
            CommandEffect::ListTools => Ok(CommandOutcome::Tools(self.inner.executor.catalogue())),
            CommandEffect::CancelTurn => {
                let live = self.inner.live();
                let turn = live
                    .get(session_id.as_str())
                    .ok_or(RuntimeError::NoTurnInFlight)?;
                turn.cancel.cancel();
                Ok(CommandOutcome::Acknowledged)
            }
            CommandEffect::PauseTurn => self.set_paused(session_id, true),
            CommandEffect::ResumeTurn => self.set_paused(session_id, false),
            CommandEffect::ShowGoal => Ok(CommandOutcome::Goal(
                self.inner.goals.active(session_id).await?,
            )),
            CommandEffect::SetGoal(objective) => {
                let goal_id = self.mint_goal_id(session_id).await?;
                let record = self
                    .inner
                    .goals
                    .set(session_id, goal_id, &objective)
                    .await?;
                Ok(CommandOutcome::Goal(Some(record)))
            }
            CommandEffect::CloseGoal(status) => {
                let Some(active) = self.inner.goals.active(session_id).await? else {
                    return Ok(CommandOutcome::Goal(None));
                };
                let record = self.inner.goals.close(&active.goal_id, status).await?;
                Ok(CommandOutcome::Goal(Some(record)))
            }
            CommandEffect::Approve {
                approval_id,
                remember,
            } => self.settle_approval(
                &approval_id,
                if remember {
                    ApprovalDecision::approve_for_session()
                } else {
                    ApprovalDecision::approve_once()
                },
            ),
            CommandEffect::Deny {
                approval_id,
                remember,
            } => self.settle_approval(
                &approval_id,
                if remember {
                    ApprovalDecision::deny_for_session()
                } else {
                    ApprovalDecision::deny_once()
                },
            ),
            CommandEffect::CompactContext { reclaim_tokens } => {
                let report = self
                    .inner
                    .ports
                    .context
                    .compact(ContextCompaction {
                        session_id: session_id.clone(),
                        reclaim_tokens,
                        at: self.inner.ports.clock.now(),
                    })
                    .await?;
                Ok(CommandOutcome::Compaction {
                    removed_items: report.removed_items,
                    reclaimed_tokens: report.reclaimed_tokens,
                })
            }
            CommandEffect::SuspendPrepare { drain_seconds } => {
                let lease_id = claw_application::model::ids::LeaseId::new(format!(
                    "lease-{}",
                    self.inner.ports.clock.now().as_millis()
                ))?;
                let outcome = self
                    .inner
                    .suspension
                    .prepare(PrepareRequest {
                        lease_id,
                        reason: "operator requested suspension".to_owned(),
                        drain_timeout: Duration::from_secs(drain_seconds),
                        lease_ttl: Duration::from_secs(drain_seconds.saturating_mul(10).max(60)),
                    })
                    .await?;
                Ok(CommandOutcome::SuspensionPrepared(outcome))
            }
            CommandEffect::SuspendStatus => {
                Ok(CommandOutcome::Suspension(self.inner.suspension.status()))
            }
            CommandEffect::SuspendResume { lease_id } => {
                let lease_id = claw_application::model::ids::LeaseId::new(lease_id)?;
                Ok(CommandOutcome::Suspension(
                    self.inner.suspension.resume(&lease_id)?,
                ))
            }
            CommandEffect::SetModel(_) | CommandEffect::Custom { .. } => {
                Ok(CommandOutcome::Unsupported {
                    name: match effect {
                        CommandEffect::SetModel(_) => "model".to_owned(),
                        CommandEffect::Custom { name, .. } => name,
                        _ => unreachable!("only the two arms above reach here"),
                    },
                })
            }
        }
    }

    /// Cancels every live turn, withdraws every outstanding approval, and joins every task.
    ///
    /// After this resolves [`Runtime::tracked_tasks`] is zero: there are no detached tasks left.
    ///
    /// # Errors
    ///
    /// Returns [`RuntimeError::Approval`] when the approval adapter failed while being told the
    /// requests were withdrawn. Every task is still joined.
    pub async fn shutdown(&self) -> Result<(), RuntimeError> {
        self.inner.shutdown.cancel();
        let withdrawal = self
            .inner
            .broker
            .withdraw_all(ApprovalWithdrawal::Cancelled)
            .await;

        self.tracker.close();
        self.tracker.wait().await;

        withdrawal.map_err(RuntimeError::Approval)
    }

    fn set_paused(
        &self,
        session_id: &SessionId,
        paused: bool,
    ) -> Result<CommandOutcome, RuntimeError> {
        let live = self.inner.live();
        let turn = live
            .get(session_id.as_str())
            .ok_or(RuntimeError::NoTurnInFlight)?;
        turn.paused
            .send(paused)
            .map_err(|_| RuntimeError::NoTurnInFlight)?;
        Ok(CommandOutcome::Acknowledged)
    }

    fn settle_approval(
        &self,
        approval_id: &str,
        decision: ApprovalDecision,
    ) -> Result<CommandOutcome, RuntimeError> {
        let approval_id = ApprovalId::new(approval_id)?;
        self.inner.broker.resolve(&approval_id, decision)?;
        Ok(CommandOutcome::Acknowledged)
    }

    async fn mint_goal_id(&self, session_id: &SessionId) -> Result<GoalId, RuntimeError> {
        let existing = self.inner.goals.history(session_id).await?.len();
        Ok(GoalId::new(format!("goal-{}", existing + 1))?)
    }
}

struct TurnExecution {
    inner: Arc<RuntimeInner>,
    session_id: SessionId,
    turn: TurnId,
    revision: u64,
    reason: BootstrapReason,
    input: String,
    options: TurnOptions,
    events: mpsc::Sender<RuntimeEvent>,
    cancel: CancellationToken,
    pause: watch::Receiver<bool>,
}

impl TurnExecution {
    async fn run(mut self) -> Result<TurnOutcome, RuntimeError> {
        let mut machine = TurnStateMachine::new();
        let mut rounds = 0_u32;
        let mut tool_outcomes: Vec<ToolOutcome> = Vec::new();
        let mut message: Option<AssistantMessage> = None;
        let mut partial: Option<PartialAssistantMessage> = None;

        self.advance(&mut machine, SessionEvent::Enqueue).await?;
        self.advance(&mut machine, SessionEvent::Start).await?;

        let result = self
            .drive(
                &mut machine,
                &mut rounds,
                &mut tool_outcomes,
                &mut message,
                &mut partial,
            )
            .await;

        if let Err(error) = result {
            let reason = error.to_string();
            if machine.accepts(SessionEvent::Fail) {
                self.advance(&mut machine, SessionEvent::Fail).await?;
            }
            self.emit(RuntimeEventKind::Failed { reason }).await;
            self.persist_turn(machine.state(), message.clone(), partial.clone())
                .await?;
            return Err(error);
        }

        self.persist_turn(machine.state(), message.clone(), partial.clone())
            .await?;

        Ok(TurnOutcome {
            session_id: self.session_id.clone(),
            turn: self.turn,
            state: machine.state(),
            message,
            partial,
            rounds,
            tool_outcomes,
        })
    }

    async fn drive(
        &mut self,
        machine: &mut TurnStateMachine,
        rounds: &mut u32,
        tool_outcomes: &mut Vec<ToolOutcome>,
        message: &mut Option<AssistantMessage>,
        partial: &mut Option<PartialAssistantMessage>,
    ) -> Result<(), RuntimeError> {
        self.inner
            .ports
            .context
            .bootstrap(ContextBootstrap {
                session_id: self.session_id.clone(),
                reason: self.reason,
                token_budget: self.inner.config.context_token_budget,
                at: self.inner.ports.clock.now(),
            })
            .await?;

        if let Some(objective) = self.options.goal.clone() {
            let goal_id = GoalId::new(format!("goal-turn-{}", self.turn.ordinal()))?;
            let record = self
                .inner
                .goals
                .set(&self.session_id, goal_id, &objective)
                .await?;
            self.emit(RuntimeEventKind::GoalUpdated {
                goal: record.clone(),
            })
            .await;
        }

        if let Some(goal) = self.inner.goals.active(&self.session_id).await? {
            self.ingest(ContextItem::GoalStatement {
                objective: goal.objective,
            })
            .await?;
        }

        self.ingest(ContextItem::UserInput {
            text: self.input.clone(),
        })
        .await?;

        let tool_names: Vec<String> = if self.options.tools_enabled {
            self.inner
                .executor
                .catalogue()
                .into_iter()
                .map(|descriptor| descriptor.name)
                .collect()
        } else {
            Vec::new()
        };

        let mut changed_workspace = false;

        while *rounds < self.inner.config.max_rounds {
            if self.quiesce(machine).await? {
                return Ok(());
            }

            let round = *rounds;
            let assembled = self
                .inner
                .ports
                .context
                .assemble(ContextAssembly {
                    session_id: self.session_id.clone(),
                    turn: self.turn,
                    round,
                })
                .await?;

            let mut stream = self
                .inner
                .ports
                .provider
                .start_round(ProviderRequest {
                    session_id: self.session_id.clone(),
                    turn: self.turn,
                    round,
                    messages: assembled.messages,
                    tool_names: tool_names.clone(),
                })
                .await?;

            if machine.accepts(SessionEvent::Stream) {
                self.advance(machine, SessionEvent::Stream).await?;
            }

            let mut assembler = match partial.take() {
                Some(recovered) => {
                    StreamAssembler::resume(recovered, crate::stream::MAX_ASSEMBLED_BYTES)
                }
                None => StreamAssembler::new(),
            };
            let mut calls: Vec<ToolCall> = Vec::new();

            loop {
                let chunk = tokio::select! {
                    biased;
                    next = stream.next_chunk() => next?,
                    () = self.cancel.cancelled() => {
                        *partial = Some(assembler.into_partial());
                        self.advance(machine, SessionEvent::Cancel).await?;
                        return Ok(());
                    }
                };

                let Some(chunk) = chunk else {
                    break;
                };

                for event in assembler.push(chunk)? {
                    if let StreamPayload::ToolCallCompleted { call } = &event.payload {
                        calls.push(call.clone());
                    }
                    if !self.options.quiet
                        || !matches!(
                            event.payload,
                            StreamPayload::TextDelta { .. } | StreamPayload::ReasoningDelta { .. }
                        )
                    {
                        self.emit(RuntimeEventKind::Stream(event)).await;
                    }
                }
            }

            *rounds = rounds.saturating_add(1);

            let Some(completed) = assembler.finish() else {
                return Err(RuntimeError::Stream(StreamError::UnterminatedToolCall(
                    calls.first().map_or_else(
                        || {
                            claw_application::model::ids::ToolCallId::new("unknown")
                                .expect("the literal is a valid identifier")
                        },
                        |call| call.call_id.clone(),
                    ),
                )));
            };

            self.ingest(ContextItem::AssistantMessage {
                text: completed.text.clone(),
            })
            .await?;
            *message = Some(completed);

            self.emit(RuntimeEventKind::RoundFinished {
                round,
                tool_calls: calls.len(),
            })
            .await;

            if calls.is_empty() {
                let event = if changed_workspace {
                    SessionEvent::CompleteWithChanges
                } else {
                    SessionEvent::Complete
                };
                self.advance(machine, event).await?;
                return Ok(());
            }

            if !self.options.tools_enabled {
                self.advance(machine, SessionEvent::Block).await?;
                return Ok(());
            }

            for call in calls {
                let requires_approval = self
                    .inner
                    .executor
                    .describe(&call.name)
                    .is_some_and(|descriptor| descriptor.requires_approval)
                    && self
                        .inner
                        .broker
                        .remembered(&self.session_id, &call.name)
                        .is_none();

                if requires_approval {
                    self.advance(machine, SessionEvent::RequestApproval).await?;
                    self.emit(RuntimeEventKind::AwaitingApproval { call: call.clone() })
                        .await;
                } else {
                    self.emit(RuntimeEventKind::ToolStarted { call: call.clone() })
                        .await;
                }

                let outcome = self
                    .inner
                    .executor
                    .execute(
                        ToolInvocation {
                            session_id: self.session_id.clone(),
                            turn: self.turn,
                            call: call.clone(),
                        },
                        &self.cancel,
                    )
                    .await?;

                if requires_approval {
                    self.advance(machine, SessionEvent::ResolveApproval).await?;
                }

                changed_workspace |= outcome.changed_workspace;
                self.ingest(ContextItem::ToolResult {
                    tool_name: call.name.clone(),
                    output: outcome.output.clone(),
                    failed: outcome.status.is_failure(),
                })
                .await?;
                self.emit(RuntimeEventKind::ToolFinished {
                    outcome: outcome.clone(),
                })
                .await;

                let cancelled = outcome.status == ToolStatus::Cancelled;
                tool_outcomes.push(outcome);

                if cancelled || self.cancel.is_cancelled() {
                    self.advance(machine, SessionEvent::Cancel).await?;
                    return Ok(());
                }
            }

            let state = self
                .inner
                .ports
                .context
                .maintain(ContextMaintenance {
                    session_id: self.session_id.clone(),
                    at: self.inner.ports.clock.now(),
                })
                .await?;
            self.relieve_pressure(&state).await?;
        }

        self.advance(machine, SessionEvent::Block).await?;
        Ok(())
    }

    /// Applies a pending pause and waits for the resume, honouring cancellation.
    ///
    /// Returns `true` when the turn should stop because it was cancelled.
    async fn quiesce(&mut self, machine: &mut TurnStateMachine) -> Result<bool, RuntimeError> {
        if self.cancel.is_cancelled() {
            self.advance(machine, SessionEvent::Cancel).await?;
            return Ok(true);
        }

        if !*self.pause.borrow_and_update() {
            return Ok(false);
        }

        self.advance(machine, SessionEvent::Pause).await?;

        loop {
            let changed = tokio::select! {
                biased;
                changed = self.pause.changed() => changed,
                () = self.cancel.cancelled() => {
                    self.advance(machine, SessionEvent::Cancel).await?;
                    return Ok(true);
                }
            };

            if changed.is_err() {
                // The runtime dropped the pause sender, which only happens once the live-turn
                // entry is gone; treat it as a resume so the turn cannot wedge.
                self.advance(machine, SessionEvent::Resume).await?;
                return Ok(false);
            }

            if !*self.pause.borrow_and_update() {
                self.advance(machine, SessionEvent::Resume).await?;
                return Ok(false);
            }
        }
    }

    async fn relieve_pressure(&self, state: &ContextState) -> Result<(), RuntimeError> {
        if !state.needs_compaction {
            return Ok(());
        }

        let reclaim = state.used_tokens.saturating_sub(state.token_budget).max(1);
        let report = self
            .inner
            .ports
            .context
            .compact(ContextCompaction {
                session_id: self.session_id.clone(),
                reclaim_tokens: reclaim,
                at: self.inner.ports.clock.now(),
            })
            .await?;

        self.emit(RuntimeEventKind::ContextCompacted {
            removed_items: report.removed_items,
            reclaimed_tokens: report.reclaimed_tokens,
        })
        .await;
        Ok(())
    }

    async fn ingest(&self, item: ContextItem) -> Result<(), RuntimeError> {
        self.inner
            .ports
            .context
            .ingest(ContextIngest {
                session_id: self.session_id.clone(),
                turn: self.turn,
                item,
                at: self.inner.ports.clock.now(),
            })
            .await?;
        Ok(())
    }

    async fn advance(
        &mut self,
        machine: &mut TurnStateMachine,
        event: SessionEvent,
    ) -> Result<(), RuntimeError> {
        let from = machine.state();
        let to = machine.apply(event)?;
        self.persist_session(machine).await?;
        self.emit(RuntimeEventKind::StateChanged { from, to }).await;
        Ok(())
    }

    async fn persist_session(&mut self, machine: &TurnStateMachine) -> Result<(), RuntimeError> {
        let revision = self
            .inner
            .ports
            .state
            .save_session(SessionSnapshot {
                session_id: self.session_id.clone(),
                turn: self.turn,
                state: machine.state(),
                pre_pause_state: machine.pre_pause_state(),
                updated_at: self.inner.ports.clock.now(),
                revision: self.revision,
            })
            .await?;
        self.revision = revision;
        Ok(())
    }

    async fn persist_turn(
        &self,
        state: SessionState,
        message: Option<AssistantMessage>,
        partial: Option<PartialAssistantMessage>,
    ) -> Result<(), RuntimeError> {
        self.inner
            .ports
            .state
            .save_turn(TurnRecord {
                session_id: self.session_id.clone(),
                turn: self.turn,
                state,
                message,
                partial,
                updated_at: self.inner.ports.clock.now(),
            })
            .await?;
        Ok(())
    }

    async fn emit(&self, kind: RuntimeEventKind) {
        let event = RuntimeEvent {
            session_id: self.session_id.clone(),
            turn: self.turn,
            kind,
        };

        // A subscriber that stops reading must not be able to wedge shutdown, so the send races
        // the runtime-wide shutdown token rather than blocking forever.
        tokio::select! {
            biased;
            result = self.events.send(event) => {
                drop(result);
            }
            () = self.inner.shutdown.cancelled() => {}
        }
    }
}

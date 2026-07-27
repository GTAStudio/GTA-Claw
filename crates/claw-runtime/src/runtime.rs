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
use claw_application::model::ids::{ApprovalId, IdentifierError, TurnId};
use claw_application::model::message::{AssistantMessage, PartialAssistantMessage, ToolCall};
use claw_application::model::session::{SessionEvent, SessionState};
use claw_application::model::time::Timestamp;
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
use crate::goal_tool::{GOAL_TOOL_NAME, goal_tool_descriptor, parse_goal_action};
use crate::session::{StateMachineError, TurnStateMachine};
use crate::stream::{StreamAssembler, StreamError, StreamEvent, StreamPayload};
use crate::suspend::{
    PrepareOutcome, PrepareRequest, SuspendError, SuspensionController, SuspensionStatus,
    WorkPermit, WorkRefused,
};
use crate::tool::{ToolExecutionError, ToolExecutor, ToolExecutorConfig};

/// The `/model` argument that clears a session's model override.
///
/// It is matched case-insensitively, so `/model default` and `/model DEFAULT` both hand model
/// selection back to the provider adapter.
pub const DEFAULT_MODEL_ARGUMENT: &str = "default";

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
    /// Whether the model-callable goal tool is advertised and served.
    ///
    /// Turning this off hides [`GOAL_TOOL_NAME`] from the provider's tool list and from `/tools`,
    /// and makes a call to it fail like any other unknown tool.
    pub goal_tool_enabled: bool,
    /// Maximum number of conversation sessions retained in memory.
    pub session_capacity: usize,
    /// How long an idle conversation remains owned without being touched.
    pub session_idle_ttl: Duration,
    /// Grace period before a retiring turn is forcibly aborted.
    pub session_retire_timeout: Duration,
}

impl Default for RuntimeConfig {
    fn default() -> Self {
        Self {
            event_capacity: 64,
            approval_timeout: Duration::from_mins(5),
            tool_timeout: Duration::from_mins(2),
            max_rounds: 16,
            context_token_budget: 128_000,
            goals: GoalConfig::default(),
            goal_tool_enabled: true,
            session_capacity: 100,
            session_idle_ttl: Duration::from_hours(1),
            session_retire_timeout: Duration::from_secs(5),
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

/// Stable user-facing classification of a runtime failure.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RuntimeFailureClass {
    /// Capacity, optimistic concurrency, or reload fencing temporarily blocked work.
    Busy,
    /// An external adapter is unavailable.
    Unavailable,
    /// The requested entity does not exist.
    NotFound,
    /// Caller input or a provider stream violated a contract.
    InvalidRequest,
    /// The caller or host cancelled the work.
    Cancelled,
    /// An internal runtime invariant failed.
    Internal,
}

impl RuntimeFailureClass {
    /// Returns the stable wire-safe label.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Busy => "busy",
            Self::Unavailable => "unavailable",
            Self::NotFound => "not_found",
            Self::InvalidRequest => "invalid_request",
            Self::Cancelled => "cancelled",
            Self::Internal => "internal",
        }
    }

    /// Returns a detail-free message suitable for an end user.
    #[must_use]
    pub const fn user_message(self) -> &'static str {
        match self {
            Self::Busy => "This conversation is busy. Retry after the current work finishes.",
            Self::Unavailable => {
                "A required service is temporarily unavailable. Try again shortly."
            }
            Self::NotFound => "The requested runtime resource no longer exists.",
            Self::InvalidRequest => {
                "The request could not be processed. Check its input and retry."
            }
            Self::Cancelled => "The operation was cancelled.",
            Self::Internal => "The runtime could not complete the operation.",
        }
    }
}

/// Result of fencing and clearing conversation sessions for a reload.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SessionReloadReport {
    /// New generation assigned before stale work was cancelled.
    pub generation: u64,
    /// Number of idle and active sessions terminally removed.
    pub destroyed: usize,
    /// Number of active turns cancelled and joined.
    pub cancelled_turns: usize,
    /// Number of turns that ignored cancellation through the grace period and were aborted.
    pub forced_turns: usize,
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
    /// Every conversation slot is occupied by active work.
    SessionCapacityReached {
        /// Configured in-memory session capacity.
        capacity: usize,
    },
    /// The conversation is being terminally destroyed.
    SessionRetiring,
    /// A reload changed generation while session creation was awaiting I/O.
    ReloadFenced {
        /// Generation captured before the await.
        expected: u64,
        /// Generation active after the await.
        current: u64,
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
            Self::SessionCapacityReached { capacity } => {
                write!(
                    formatter,
                    "all {capacity} in-memory conversation slots are active"
                )
            }
            Self::SessionRetiring => {
                formatter.write_str("the conversation session is being destroyed")
            }
            Self::ReloadFenced { expected, current } => write!(
                formatter,
                "session creation was fenced by reload generation {expected} -> {current}"
            ),
            Self::NoTurnInFlight => formatter.write_str("no turn is running for this session"),
            Self::Identifier(error) => write!(formatter, "identifier rejected: {error}"),
            Self::Abandoned => formatter.write_str("the turn ended without reporting an outcome"),
        }
    }
}

impl Error for RuntimeError {}

impl RuntimeError {
    /// Returns the stable classification a user interface should present.
    #[must_use]
    pub const fn failure_class(&self) -> RuntimeFailureClass {
        match self {
            Self::Port(error) => classify_port_error(error),
            Self::Goal(error) => classify_goal_error(error),
            Self::Approval(error) | Self::Tool(ToolExecutionError::Approval(error)) => {
                classify_approval_error(error)
            }
            Self::Suspend(
                SuspendError::AlreadySuspended { .. } | SuspendError::AlreadyDraining { .. },
            )
            | Self::Quiescing(_)
            | Self::TurnInFlight { .. }
            | Self::SessionCapacityReached { .. }
            | Self::SessionRetiring
            | Self::ReloadFenced { .. } => RuntimeFailureClass::Busy,
            Self::Suspend(SuspendError::NotSuspended) | Self::NoTurnInFlight => {
                RuntimeFailureClass::NotFound
            }
            Self::Suspend(SuspendError::LeaseMismatch { .. })
            | Self::Stream(_)
            | Self::Command(_)
            | Self::Directive(_)
            | Self::Identifier(_) => RuntimeFailureClass::InvalidRequest,
            Self::ShuttingDown => RuntimeFailureClass::Cancelled,
            Self::State(_) | Self::Suspend(SuspendError::DeadlineOverflow) | Self::Abandoned => {
                RuntimeFailureClass::Internal
            }
        }
    }

    /// Returns a detail-free message suitable for an end user.
    #[must_use]
    pub const fn user_message(&self) -> &'static str {
        self.failure_class().user_message()
    }

    /// Returns whether retrying after the immediate condition clears can succeed.
    #[must_use]
    pub const fn is_retryable(&self) -> bool {
        matches!(
            self.failure_class(),
            RuntimeFailureClass::Busy | RuntimeFailureClass::Unavailable
        )
    }
}

const fn classify_port_error(error: &PortError) -> RuntimeFailureClass {
    match error {
        PortError::Unavailable(_) => RuntimeFailureClass::Unavailable,
        PortError::Conflict(_) => RuntimeFailureClass::Busy,
        PortError::NotFound(_) => RuntimeFailureClass::NotFound,
        PortError::Invalid(_) => RuntimeFailureClass::InvalidRequest,
        PortError::Cancelled => RuntimeFailureClass::Cancelled,
    }
}

const fn classify_approval_error(error: &ApprovalError) -> RuntimeFailureClass {
    match error {
        ApprovalError::Port(error) => classify_port_error(error),
        ApprovalError::Unknown(_) => RuntimeFailureClass::NotFound,
        ApprovalError::DeadlineOverflow | ApprovalError::Identifier(_) => {
            RuntimeFailureClass::Internal
        }
    }
}

const fn classify_goal_error(error: &GoalError) -> RuntimeFailureClass {
    match error {
        GoalError::Port(error) => classify_port_error(error),
        GoalError::Unknown(_) | GoalError::NoActiveGoal => RuntimeFailureClass::NotFound,
        GoalError::AlreadyClosed { .. } => RuntimeFailureClass::Busy,
        GoalError::NotATerminalStatus(_)
        | GoalError::InvalidObjective(_)
        | GoalError::InvalidNote(_)
        | GoalError::InvalidBudget
        | GoalError::UnusableGoalId(_) => RuntimeFailureClass::InvalidRequest,
    }
}

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
        self.completion
            .await
            .unwrap_or(Err(RuntimeError::Abandoned))
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
    ///
    /// Only [`CommandEffect::Custom`] reaches this: host-registered commands are dispatched by
    /// whoever registered them, not by this crate.
    Unsupported {
        /// The command name.
        name: String,
    },
    /// The session's provider model selection after a `/model` command.
    ModelSelected {
        /// The model now pinned for the session, or `None` once the override was cleared.
        model: Option<String>,
    },
    /// A conversation session reached terminal destruction.
    SessionDestroyed {
        /// Whether the runtime owned that conversation before the command.
        existed: bool,
    },
}

#[derive(Debug)]
struct LiveTurn {
    turn: TurnId,
    cancel: CancellationToken,
    /// Behind an [`Arc`] so [`Runtime::set_paused`] can lift the sender out of the live-turn map
    /// and release that lock before notifying the turn: `send` wakes the turn's watcher, and
    /// waking a task is work no other session should have to queue behind.
    paused: Arc<watch::Sender<bool>>,
    /// Fires only after ownership and the suspension permit are released.
    finished: CancellationToken,
    /// Installed immediately after spawn so retirement can force a stuck task down.
    abort: Arc<Mutex<TurnAbortState>>,
}

#[derive(Debug, Default)]
struct TurnAbortState {
    handle: Option<tokio::task::AbortHandle>,
    requested: bool,
}

#[derive(Debug)]
struct ManagedConversation {
    session_id: SessionId,
    last_access: Timestamp,
    access_order: u64,
    generation: u64,
    live: Option<LiveTurn>,
    model: Option<String>,
    retiring: bool,
}

#[derive(Debug)]
struct ConversationRegistry {
    entries: HashMap<String, ManagedConversation>,
    capacity: usize,
    idle_ttl: Duration,
    generation: u64,
    next_access: u64,
}

#[derive(Clone)]
struct RetiringTurn {
    cancel: CancellationToken,
    finished: CancellationToken,
    abort: Arc<Mutex<TurnAbortState>>,
}

struct RetirementAbortGuard {
    turns: Vec<RetiringTurn>,
    armed: bool,
}

impl RetirementAbortGuard {
    const fn new(turns: Vec<RetiringTurn>) -> Self {
        Self { turns, armed: true }
    }

    const fn disarm(&mut self) {
        self.armed = false;
    }
}

impl Drop for RetirementAbortGuard {
    fn drop(&mut self) {
        if !self.armed {
            return;
        }
        for turn in &self.turns {
            turn.cancel.cancel();
            if !turn.finished.is_cancelled() {
                request_turn_abort(&turn.abort);
            }
        }
    }
}

fn install_turn_abort(state: &Mutex<TurnAbortState>, handle: tokio::task::AbortHandle) {
    let abort = {
        let mut state = state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if state.requested {
            Some(handle)
        } else {
            state.handle = Some(handle);
            None
        }
    };
    if let Some(abort) = abort {
        abort.abort();
    }
}

fn request_turn_abort(state: &Mutex<TurnAbortState>) {
    let abort = {
        let mut state = state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        state.requested = true;
        state.handle.take()
    };
    if let Some(abort) = abort {
        abort.abort();
    }
}

struct Retirement {
    existed: bool,
    idle: Option<RetiredSession>,
    active: Option<RetiringTurn>,
}

#[derive(Clone)]
struct RetiredSession {
    session_id: SessionId,
    generation: u64,
}

struct ReloadPlan {
    generation: u64,
    idle: Vec<RetiredSession>,
    active: Vec<RetiringTurn>,
}

impl ConversationRegistry {
    fn new(capacity: usize, idle_ttl: Duration) -> Self {
        Self {
            entries: HashMap::new(),
            capacity: capacity.max(1),
            idle_ttl,
            generation: 0,
            next_access: 1,
        }
    }

    const fn generation(&self) -> u64 {
        self.generation
    }

    const fn next_access(&mut self) -> u64 {
        let access = self.next_access;
        self.next_access = self.next_access.saturating_add(1);
        access
    }

    fn sweep(&mut self, now: Timestamp) -> Vec<SessionId> {
        let idle_ttl = self.idle_ttl;
        let mut expired: Vec<String> = self
            .entries
            .iter()
            .filter(|(_, entry)| {
                entry.live.is_none()
                    && entry
                        .last_access
                        .checked_add(idle_ttl)
                        .is_some_and(|deadline| now > deadline)
            })
            .map(|(key, _)| key.clone())
            .collect();
        expired.sort();
        expired
            .into_iter()
            .filter_map(|key| self.entries.remove(&key))
            .map(|entry| entry.session_id)
            .collect()
    }

    fn claim(
        &mut self,
        session_id: &SessionId,
        expected_generation: u64,
        live: LiveTurn,
        now: Timestamp,
    ) -> Result<Option<SessionId>, RuntimeError> {
        if expected_generation != self.generation {
            return Err(RuntimeError::ReloadFenced {
                expected: expected_generation,
                current: self.generation,
            });
        }

        let key = session_id.as_str();
        if let Some(existing) = self.entries.get(key) {
            if existing.retiring {
                return Err(RuntimeError::SessionRetiring);
            }
            if let Some(turn) = existing.live.as_ref().map(|turn| turn.turn) {
                return Err(RuntimeError::TurnInFlight { turn });
            }
        }

        let evicted = if self.entries.contains_key(key) {
            None
        } else {
            self.make_room()?
        };
        let access_order = self.next_access();
        let entry = self
            .entries
            .entry(key.to_owned())
            .or_insert_with(|| ManagedConversation {
                session_id: session_id.clone(),
                last_access: now,
                access_order,
                generation: expected_generation,
                live: None,
                model: None,
                retiring: false,
            });
        entry.last_access = now;
        entry.access_order = access_order;
        entry.generation = expected_generation;
        entry.live = Some(live);
        Ok(evicted)
    }

    fn model(&mut self, session_id: &SessionId, now: Timestamp) -> Option<String> {
        let access_order = self.next_access();
        let entry = self.entries.get_mut(session_id.as_str())?;
        if entry.retiring {
            return None;
        }
        entry.last_access = now;
        entry.access_order = access_order;
        entry.model.clone()
    }

    fn set_model(
        &mut self,
        session_id: &SessionId,
        model: Option<String>,
        now: Timestamp,
    ) -> Result<Option<SessionId>, RuntimeError> {
        if self
            .entries
            .get(session_id.as_str())
            .is_some_and(|entry| entry.retiring)
        {
            return Err(RuntimeError::SessionRetiring);
        }
        let evicted = if self.entries.contains_key(session_id.as_str()) {
            None
        } else {
            self.make_room()?
        };
        let access_order = self.next_access();
        let entry = self
            .entries
            .entry(session_id.as_str().to_owned())
            .or_insert_with(|| ManagedConversation {
                session_id: session_id.clone(),
                last_access: now,
                access_order,
                generation: self.generation,
                live: None,
                model: None,
                retiring: false,
            });
        entry.last_access = now;
        entry.access_order = access_order;
        entry.model = model;
        Ok(evicted)
    }

    fn make_room(&mut self) -> Result<Option<SessionId>, RuntimeError> {
        if self.entries.len() < self.capacity {
            return Ok(None);
        }
        let candidate = self
            .entries
            .iter()
            .filter(|(_, entry)| entry.live.is_none() && !entry.retiring)
            .min_by(|(left_key, left), (right_key, right)| {
                left.access_order
                    .cmp(&right.access_order)
                    .then_with(|| left_key.cmp(right_key))
            })
            .map(|(key, _)| key.clone())
            .ok_or(RuntimeError::SessionCapacityReached {
                capacity: self.capacity,
            })?;
        Ok(self
            .entries
            .remove(&candidate)
            .map(|entry| entry.session_id))
    }

    fn release(
        &mut self,
        session_id: &SessionId,
        turn: TurnId,
        generation: u64,
        now: Timestamp,
    ) -> Option<SessionId> {
        let key = session_id.as_str();
        let access_order = self.next_access();
        let entry = self.entries.get_mut(key)?;
        if entry.generation != generation
            || entry.live.as_ref().is_none_or(|live| live.turn != turn)
        {
            return None;
        }
        entry.live = None;
        entry.last_access = now;
        entry.access_order = access_order;
        entry.retiring.then(|| entry.session_id.clone())
    }

    fn finish_retirement(&mut self, session_id: &SessionId, generation: u64) {
        let removable = self.entries.get(session_id.as_str()).is_some_and(|entry| {
            entry.retiring && entry.live.is_none() && entry.generation == generation
        });
        if removable {
            self.entries.remove(session_id.as_str());
        }
    }

    fn retire(&mut self, session_id: &SessionId) -> Retirement {
        // Fence every session creation that began before this terminal action.
        // Existing owned sessions remain valid; only claims still awaiting I/O
        // must retry against the new generation.
        self.generation = self.generation.saturating_add(1);
        let key = session_id.as_str();
        let Some(entry) = self.entries.get_mut(key) else {
            return Retirement {
                existed: false,
                idle: None,
                active: None,
            };
        };
        entry.model = None;
        entry.retiring = true;
        let active = entry.live.as_ref().map(|live| RetiringTurn {
            cancel: live.cancel.clone(),
            finished: live.finished.clone(),
            abort: Arc::clone(&live.abort),
        });
        let idle = active.is_none().then(|| RetiredSession {
            session_id: entry.session_id.clone(),
            generation: entry.generation,
        });
        Retirement {
            existed: true,
            idle,
            active,
        }
    }

    fn reload(&mut self) -> ReloadPlan {
        self.generation = self.generation.saturating_add(1);
        let mut idle = Vec::new();
        let mut active = Vec::new();
        for entry in self.entries.values_mut() {
            entry.model = None;
            entry.retiring = true;
            if let Some(live) = &entry.live {
                active.push(RetiringTurn {
                    cancel: live.cancel.clone(),
                    finished: live.finished.clone(),
                    abort: Arc::clone(&live.abort),
                });
            } else {
                idle.push(RetiredSession {
                    session_id: entry.session_id.clone(),
                    generation: entry.generation,
                });
            }
        }
        ReloadPlan {
            generation: self.generation,
            idle,
            active,
        }
    }

    fn clear(&mut self) -> Vec<SessionId> {
        self.entries
            .drain()
            .map(|(_, entry)| entry.session_id)
            .collect()
    }

    fn ids(&self) -> Vec<SessionId> {
        let mut ids: Vec<SessionId> = self
            .entries
            .values()
            .map(|entry| entry.session_id.clone())
            .collect();
        ids.sort_by(|left, right| left.as_str().cmp(right.as_str()));
        ids
    }

    fn live_count(&self) -> usize {
        self.entries
            .values()
            .filter(|entry| entry.live.is_some())
            .count()
    }
}

/// Releases a session's live-turn registration and its work permit when the turn task ends.
///
/// The turn task is spawned onto a [`TaskTracker`], so it normally runs to completion, but a task
/// future can also be dropped without ever finishing. Doing the cleanup in [`Drop`] rather than
/// after the `await` means an abandoned task cannot leave the session permanently registered as
/// having a turn in flight, which would make every later [`Runtime::submit`] return
/// [`RuntimeError::TurnInFlight`].
///
/// The permit is held in an [`Option`] so [`Drop::drop`] can release ownership first, then the
/// permit, and only then signal terminal completion. A destroy caller that observes `finished`
/// therefore also observes no live turn and no suspension work permit.
struct LiveTurnGuard {
    inner: Arc<RuntimeInner>,
    session_id: SessionId,
    turn: TurnId,
    generation: u64,
    finished: CancellationToken,
    permit: Option<WorkPermit>,
}

impl Drop for LiveTurnGuard {
    fn drop(&mut self) {
        let removed = self.inner.sessions().release(
            &self.session_id,
            self.turn,
            self.generation,
            self.inner.ports.clock.now(),
        );
        if let Some(session_id) = removed {
            self.inner.cleanup_sessions([session_id.clone()]);
            self.inner
                .sessions()
                .finish_retirement(&session_id, self.generation);
        }
        drop(self.permit.take());
        self.finished.cancel();
    }
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
    sessions: Mutex<ConversationRegistry>,
    shutdown: CancellationToken,
}

impl RuntimeInner {
    fn sessions(&self) -> MutexGuard<'_, ConversationRegistry> {
        self.sessions
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    fn cleanup_sessions(&self, session_ids: impl IntoIterator<Item = SessionId>) {
        for session_id in session_ids {
            let _forgotten = self.broker.forget_session(&session_id);
        }
    }

    /// Returns every tool name the provider may call this turn.
    fn tool_catalogue(&self) -> Vec<ToolDescriptor> {
        let mut catalogue = self.executor.catalogue();
        if self.config.goal_tool_enabled {
            catalogue.push(goal_tool_descriptor());
        }
        catalogue
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
        // Read out first: formatting must not hold the registry lock.
        let (live_turns, managed_sessions, generation) = {
            let sessions = self.inner.sessions();
            (
                sessions.live_count(),
                sessions.entries.len(),
                sessions.generation(),
            )
        };
        formatter
            .debug_struct("Runtime")
            .field("live_turns", &live_turns)
            .field("managed_sessions", &managed_sessions)
            .field("session_generation", &generation)
            .field("tracked_tasks", &self.tracker.len())
            .field("shutting_down", &self.inner.shutdown.is_cancelled())
            .finish_non_exhaustive()
    }
}

impl Runtime {
    /// Creates a runtime over a set of ports.
    #[must_use]
    pub fn new(ports: RuntimePorts, config: RuntimeConfig) -> Self {
        let session_capacity = config.session_capacity;
        let session_idle_ttl = config.session_idle_ttl;
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
                sessions: Mutex::new(ConversationRegistry::new(
                    session_capacity,
                    session_idle_ttl,
                )),
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

    /// Returns the model pinned for a session by `/model`, if any.
    ///
    /// A per-turn `!model` directive overrides this for that turn only and does not change what
    /// this returns.
    #[must_use]
    pub fn selected_model(&self, session_id: &SessionId) -> Option<String> {
        let _expired = self.sweep_sessions();
        self.inner
            .sessions()
            .model(session_id, self.inner.ports.clock.now())
    }

    /// Removes every strictly expired idle session and returns their identifiers.
    ///
    /// The same sweep runs before every session access; hosts may call this on a
    /// timer to reclaim idle entries even when no traffic arrives.
    #[must_use]
    pub fn sweep_sessions(&self) -> Vec<SessionId> {
        let expired = self.inner.sessions().sweep(self.inner.ports.clock.now());
        self.inner.cleanup_sessions(expired.iter().cloned());
        expired
    }

    /// Returns the currently owned conversation identifiers in lexical order.
    ///
    /// Reading the inventory performs strict TTL cleanup but does not refresh
    /// any individual session's LRU position.
    #[must_use]
    pub fn managed_session_ids(&self) -> Vec<SessionId> {
        let _expired = self.sweep_sessions();
        self.inner.sessions().ids()
    }

    /// Returns the generation used to fence asynchronous session creation.
    #[must_use]
    pub fn session_generation(&self) -> u64 {
        self.inner.sessions().generation()
    }

    /// Returns every tool the runtime can dispatch, including the model-callable goal tool.
    #[must_use]
    pub fn tool_catalogue(&self) -> Vec<ToolDescriptor> {
        self.inner.tool_catalogue()
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
        let _expired = self.sweep_sessions();
        let generation = self.session_generation();

        let snapshot = self.inner.ports.state.load_session(session_id).await?;
        let (turn, revision, reason) = snapshot.map_or(
            (TurnId::FIRST, 0, BootstrapReason::NewSession),
            |existing| {
                (
                    existing.turn.next(),
                    existing.revision,
                    BootstrapReason::Restart,
                )
            },
        );

        // `load_session` is the only await between the first check and the spawn, so re-checking
        // here closes the window in which `shutdown` could have closed the task tracker while this
        // call was parked. Past this point nothing yields, and the check happens before the
        // live-turn entry is inserted so the early return cannot strand the session.
        if self.inner.shutdown.is_cancelled() {
            return Err(RuntimeError::ShuttingDown);
        }
        let cancel = self.inner.shutdown.child_token();
        let (paused, pause_rx) = watch::channel(false);
        let paused = Arc::new(paused);
        let finished = CancellationToken::new();
        let abort = Arc::new(Mutex::new(TurnAbortState::default()));
        let evicted = self.inner.sessions().claim(
            session_id,
            generation,
            LiveTurn {
                turn,
                cancel: cancel.clone(),
                paused: Arc::clone(&paused),
                finished: finished.clone(),
                abort: Arc::clone(&abort),
            },
            self.inner.ports.clock.now(),
        )?;
        if let Some(evicted) = evicted {
            self.inner.cleanup_sessions([evicted]);
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

        let live_guard = LiveTurnGuard {
            inner: Arc::clone(&self.inner),
            session_id: session_id.clone(),
            turn,
            generation,
            finished,
            permit: Some(permit),
        };

        // The guard is captured by the task future itself rather than created inside it, so a task
        // that is dropped before it is ever polled still releases the session.
        let spawned = self.tracker.spawn(async move {
            let result = execution.run().await;
            drop(live_guard);
            let _ = completion_tx.send(result);
        });
        install_turn_abort(&abort, spawned.abort_handle());
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
            CommandEffect::ListTools => Ok(CommandOutcome::Tools(self.inner.tool_catalogue())),
            CommandEffect::CancelTurn => {
                // `CancellationToken::cancel` runs every registered waker, including the turn's
                // own cleanup path, which takes this same lock. The token is lifted out and the
                // guard released before it fires.
                let cancel = {
                    let sessions = self.inner.sessions();
                    sessions
                        .entries
                        .get(session_id.as_str())
                        .and_then(|session| session.live.as_ref())
                        .map(|turn| turn.cancel.clone())
                        .ok_or(RuntimeError::NoTurnInFlight)?
                };
                cancel.cancel();
                Ok(CommandOutcome::Acknowledged)
            }
            CommandEffect::PauseTurn => self.set_paused(session_id, true),
            CommandEffect::ResumeTurn => self.set_paused(session_id, false),
            CommandEffect::ShowGoal => Ok(CommandOutcome::Goal(
                self.inner.goals.active(session_id).await?,
            )),
            CommandEffect::SetGoal(objective) => {
                let record = self.inner.goals.start(session_id, &objective).await?;
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
            CommandEffect::SetModel(model) => Ok(CommandOutcome::ModelSelected {
                model: self.select_model(session_id, &model)?,
            }),
            CommandEffect::DestroySession => Ok(CommandOutcome::SessionDestroyed {
                existed: self.destroy_session(session_id).await,
            }),
            CommandEffect::Custom { name, .. } => Ok(CommandOutcome::Unsupported { name }),
        }
    }

    /// Terminally destroys one in-memory conversation session.
    ///
    /// An active turn is fenced, cancelled, and joined before this returns.
    /// Session-scoped model selection and remembered approvals are removed on
    /// every path. Durable state remains owned by [`StatePort`], whose current
    /// contract intentionally has no delete operation.
    ///
    pub async fn destroy_session(&self, session_id: &SessionId) -> bool {
        let _expired = self.sweep_sessions();
        let Retirement {
            existed,
            idle,
            active,
        } = self.inner.sessions().retire(session_id);
        if let Some(idle) = idle {
            self.inner.cleanup_sessions([idle.session_id.clone()]);
            self.inner
                .sessions()
                .finish_retirement(&idle.session_id, idle.generation);
        }
        if let Some(active) = active {
            let mut abort_guard = RetirementAbortGuard::new(vec![active.clone()]);
            active.cancel.cancel();
            if tokio::time::timeout(
                self.inner.config.session_retire_timeout,
                active.finished.cancelled(),
            )
            .await
            .is_err()
            {
                Self::abort_retiring_turn(&active).await;
            }
            abort_guard.disarm();
        }
        existed
    }

    /// Fences all existing sessions for a provider/role/tool reload.
    ///
    /// Idle sessions retain a tombstone through approval cleanup. Active turns
    /// are marked retiring, cancelled, and joined; their drop guards cannot
    /// reinsert the old generation. New conversations may start against the
    /// replacement while unrelated old turns drain.
    ///
    pub async fn reload_sessions(&self) -> SessionReloadReport {
        let plan = self.inner.sessions().reload();
        let destroyed = plan.idle.len().saturating_add(plan.active.len());
        let cancelled_turns = plan.active.len();
        for idle in &plan.idle {
            self.inner.cleanup_sessions([idle.session_id.clone()]);
            self.inner
                .sessions()
                .finish_retirement(&idle.session_id, idle.generation);
        }
        let mut abort_guard = RetirementAbortGuard::new(plan.active.clone());

        for active in &plan.active {
            active.cancel.cancel();
        }
        let graceful = tokio::time::timeout(self.inner.config.session_retire_timeout, async {
            for active in &plan.active {
                active.finished.cancelled().await;
            }
        })
        .await
        .is_ok();
        let mut forced_turns = 0_usize;
        if !graceful {
            for active in &plan.active {
                if !active.finished.is_cancelled() {
                    forced_turns = forced_turns.saturating_add(1);
                    Self::abort_retiring_turn(active).await;
                }
            }
        }
        abort_guard.disarm();

        SessionReloadReport {
            generation: plan.generation,
            destroyed,
            cancelled_turns,
            forced_turns,
        }
    }

    async fn abort_retiring_turn(active: &RetiringTurn) {
        request_turn_abort(&active.abort);
        active.finished.cancelled().await;
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
        let sessions = self.inner.sessions().clear();
        self.inner.cleanup_sessions(sessions);

        withdrawal.map_err(RuntimeError::Approval)
    }

    fn set_paused(
        &self,
        session_id: &SessionId,
        paused: bool,
    ) -> Result<CommandOutcome, RuntimeError> {
        // The sender is lifted out of the map so the watch notification — which wakes the turn
        // task — happens outside the live-turn lock every other session contends for.
        let sender = {
            let sessions = self.inner.sessions();
            sessions
                .entries
                .get(session_id.as_str())
                .and_then(|session| session.live.as_ref())
                .map(|turn| Arc::clone(&turn.paused))
                .ok_or(RuntimeError::NoTurnInFlight)?
        };
        sender
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

    /// Records or clears the session's provider model override.
    ///
    /// The literal argument [`DEFAULT_MODEL_ARGUMENT`], compared case-insensitively, clears the
    /// override so the provider adapter falls back to its own default.
    fn select_model(
        &self,
        session_id: &SessionId,
        requested: &str,
    ) -> Result<Option<String>, RuntimeError> {
        let _expired = self.sweep_sessions();
        let requested = requested.trim();
        let selected =
            (!requested.eq_ignore_ascii_case(DEFAULT_MODEL_ARGUMENT)).then(|| requested.to_owned());
        let evicted = self.inner.sessions().set_model(
            session_id,
            selected.clone(),
            self.inner.ports.clock.now(),
        )?;
        if let Some(evicted) = evicted {
            self.inner.cleanup_sessions([evicted]);
        }
        Ok(selected)
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
            let record = self.inner.goals.start(&self.session_id, &objective).await?;
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
                .tool_catalogue()
                .into_iter()
                .map(|descriptor| descriptor.name)
                .collect()
        } else {
            Vec::new()
        };

        // A `!model` directive wins for this turn only; otherwise the session's `/model` selection
        // applies. Resolved once so every round of the turn runs against the same model even if an
        // operator issues `/model` while the turn is streaming.
        let model = self.options.model.clone().or_else(|| {
            self.inner
                .sessions()
                .model(&self.session_id, self.inner.ports.clock.now())
        });

        let mut changed_workspace = false;

        while *rounds < self.inner.config.max_rounds {
            if self.quiesce(machine).await? {
                return Ok(());
            }

            let round = *rounds;
            let prompt = self
                .inner
                .ports
                .context
                .assemble(ContextAssembly {
                    session_id: self.session_id.clone(),
                    turn: self.turn,
                    round,
                })
                .await?;

            let opening = self.inner.ports.provider.start_round(ProviderRequest {
                session_id: self.session_id.clone(),
                turn: self.turn,
                round,
                messages: prompt.messages,
                tool_names: tool_names.clone(),
                model: model.clone(),
            });
            let mut stream = tokio::select! {
                biased;
                () = self.cancel.cancelled() => {
                    self.advance(machine, SessionEvent::Cancel).await?;
                    return Ok(());
                }
                opened = opening => opened?,
            };

            if machine.accepts(SessionEvent::Stream) {
                self.advance(machine, SessionEvent::Stream).await?;
            }

            let mut assembler = partial
                .take()
                .map_or_else(StreamAssembler::new, |recovered| {
                    StreamAssembler::resume(recovered, crate::stream::MAX_ASSEMBLED_BYTES)
                });
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
                if self.inner.config.goal_tool_enabled && call.name == GOAL_TOOL_NAME {
                    self.emit(RuntimeEventKind::ToolStarted { call: call.clone() })
                        .await;
                    let outcome = self.run_goal_tool(&call).await?;
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
                    tool_outcomes.push(outcome);

                    if self.cancel.is_cancelled() {
                        self.advance(machine, SessionEvent::Cancel).await?;
                        return Ok(());
                    }
                    continue;
                }

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

    /// Applies one model-authored goal-tool call.
    ///
    /// Argument and goal-service failures become a failed [`ToolOutcome`] rather than a turn
    /// failure, so a model that sends bad arguments is told about it and can retry within the same
    /// turn. Only an event-channel failure can abort the turn, and that is not reachable here.
    async fn run_goal_tool(&self, call: &ToolCall) -> Result<ToolOutcome, RuntimeError> {
        let action = match parse_goal_action(&call.arguments) {
            Ok(action) => action,
            Err(error) => return Ok(Self::failed_goal_call(call, &error)),
        };

        let record = match self.inner.goals.apply(&self.session_id, &action).await {
            Ok(record) => record,
            Err(error) => return Ok(Self::failed_goal_call(call, &error)),
        };

        self.emit(RuntimeEventKind::GoalUpdated {
            goal: record.clone(),
        })
        .await;

        Ok(ToolOutcome {
            call_id: call.call_id.clone(),
            status: ToolStatus::Ok,
            output: format!(
                "goal {} is {} at revision {}",
                record.goal_id, record.status, record.revision
            ),
            changed_workspace: false,
        })
    }

    fn failed_goal_call(call: &ToolCall, error: &dyn Error) -> ToolOutcome {
        ToolOutcome {
            call_id: call.call_id.clone(),
            status: ToolStatus::Failed,
            output: error.to_string(),
            changed_workspace: false,
        }
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
            () = self.cancel.cancelled() => {}
            () = self.inner.shutdown.cancelled() => {}
        }
    }
}

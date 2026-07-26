//! Deterministic in-memory adapters shared by the runtime's integration tests.
//!
//! Nothing here touches the operating system: time is a counter, the provider replays a script,
//! and every store is a map behind a mutex. That keeps the concurrency tests reproducible.

#![allow(dead_code)]

use std::collections::{HashMap, VecDeque};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::Duration;

use claw_application::model::approval::{ApprovalRequest, ApprovalWithdrawal};
use claw_application::model::goal::GoalRecord;
use claw_application::model::ids::{ApprovalId, GoalId, ToolCallId, TurnId};
use claw_application::model::message::ToolCall;
use claw_application::model::time::Timestamp;
use claw_application::ports::approval::ApprovalPort;
use claw_application::ports::clock::ClockPort;
use claw_application::ports::context::{
    AssembledContext, CompactionReport, ContextAssembly, ContextBootstrap, ContextCompaction,
    ContextEnginePort, ContextIngest, ContextItem, ContextMaintenance, ContextState,
};
use claw_application::ports::goal::GoalStorePort;
use claw_application::ports::provider::{
    PromptMessage, ProviderChunk, ProviderPort, ProviderRequest, ProviderStream,
};
use claw_application::ports::state::{SessionSnapshot, StatePort, TurnRecord};
use claw_application::ports::tool::{
    ToolDescriptor, ToolInvocation, ToolOutcome, ToolPort, ToolStatus,
};
use claw_application::ports::{PortError, PortFuture};
use claw_domain::SessionId;
use tokio::sync::{Notify, watch};

fn guard<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    mutex
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
}

/// Polls `future` exactly once with a waker that does nothing, without resolving it.
///
/// Tests that drive a future to completion cannot observe what happens when it is *dropped*
/// while parked, which is how a cancelled caller abandons it. This reaches the first await point
/// and hands the future back so the caller can drop it there.
pub(crate) fn poll_once<F: std::future::Future>(
    future: &mut std::pin::Pin<Box<F>>,
) -> std::task::Poll<F::Output> {
    let mut context = std::task::Context::from_waker(std::task::Waker::noop());
    future.as_mut().poll(&mut context)
}

/// A clock that only moves when a test moves it.
pub(crate) struct FakeClock {
    millis: Mutex<i64>,
    ticks: watch::Sender<u64>,
}

impl FakeClock {
    /// Creates a clock starting at `start_millis`.
    pub(crate) fn new(start_millis: i64) -> Arc<Self> {
        Arc::new(Self {
            millis: Mutex::new(start_millis),
            ticks: watch::channel(0).0,
        })
    }

    /// Moves the clock forward and wakes every sleeper.
    pub(crate) fn advance(&self, duration: Duration) {
        {
            let mut millis = guard(&self.millis);
            *millis =
                millis.saturating_add(i64::try_from(duration.as_millis()).unwrap_or(i64::MAX));
        }
        self.ticks.send_modify(|tick| *tick = tick.wrapping_add(1));
    }

    /// Returns the current reading in milliseconds.
    pub(crate) fn millis(&self) -> i64 {
        *guard(&self.millis)
    }
}

impl ClockPort for FakeClock {
    fn now(&self) -> Timestamp {
        Timestamp::from_millis(*guard(&self.millis))
    }

    fn sleep(&self, duration: Duration) -> PortFuture<'_, ()> {
        let deadline = self
            .now()
            .checked_add(duration)
            .unwrap_or_else(|| Timestamp::from_millis(i64::MAX));
        let mut ticks = self.ticks.subscribe();
        Box::pin(async move {
            loop {
                if self.now() >= deadline {
                    return;
                }
                if ticks.changed().await.is_err() {
                    std::future::pending::<()>().await;
                }
            }
        })
    }
}

/// One scripted provider round.
pub(crate) struct Round {
    chunks: Vec<ProviderChunk>,
    stall_at_end: bool,
}

impl Round {
    /// A round that replays `chunks` and then closes the stream.
    pub(crate) fn new(chunks: Vec<ProviderChunk>) -> Self {
        Self {
            chunks,
            stall_at_end: false,
        }
    }

    /// A round that replays `chunks` and then never produces anything again.
    pub(crate) fn stalling(chunks: Vec<ProviderChunk>) -> Self {
        Self {
            chunks,
            stall_at_end: true,
        }
    }
}

struct ScriptedStream {
    chunks: VecDeque<ProviderChunk>,
    stall_at_end: bool,
}

impl ProviderStream for ScriptedStream {
    fn next_chunk(&mut self) -> PortFuture<'_, Result<Option<ProviderChunk>, PortError>> {
        let next = self.chunks.pop_front();
        let stall = self.stall_at_end && next.is_none();
        Box::pin(async move {
            if stall {
                std::future::pending::<()>().await;
            }
            Ok(next)
        })
    }
}

/// A provider that replays a fixed script, one entry per round.
pub(crate) struct ScriptedProvider {
    rounds: Mutex<VecDeque<Round>>,
    requests: Mutex<Vec<ProviderRequest>>,
}

impl ScriptedProvider {
    /// Creates a provider from an ordered script.
    pub(crate) fn new(rounds: Vec<Round>) -> Arc<Self> {
        Arc::new(Self {
            rounds: Mutex::new(rounds.into()),
            requests: Mutex::new(Vec::new()),
        })
    }

    /// Returns every request the runtime made, in order.
    pub(crate) fn requests(&self) -> Vec<ProviderRequest> {
        guard(&self.requests).clone()
    }
}

impl ProviderPort for ScriptedProvider {
    fn start_round(
        &self,
        request: ProviderRequest,
    ) -> PortFuture<'_, Result<Box<dyn ProviderStream>, PortError>> {
        guard(&self.requests).push(request);
        let round = guard(&self.rounds).pop_front();
        Box::pin(async move {
            match round {
                Some(round) => Ok(Box::new(ScriptedStream {
                    chunks: round.chunks.into(),
                    stall_at_end: round.stall_at_end,
                }) as Box<dyn ProviderStream>),
                None => Err(PortError::Unavailable(
                    "the script ran out of rounds".to_owned(),
                )),
            }
        })
    }
}

#[derive(Default)]
struct StateData {
    sessions: HashMap<String, SessionSnapshot>,
    turns: HashMap<(String, u64), TurnRecord>,
    history: Vec<SessionSnapshot>,
}

/// An in-memory [`StatePort`] with real optimistic concurrency.
#[derive(Default)]
pub(crate) struct MemoryState {
    data: Mutex<StateData>,
}

impl MemoryState {
    /// Creates an empty store.
    pub(crate) fn new() -> Arc<Self> {
        Arc::new(Self::default())
    }

    /// Returns every snapshot ever written, in write order.
    pub(crate) fn history(&self) -> Vec<SessionSnapshot> {
        guard(&self.data).history.clone()
    }

    /// Returns the persisted turn record, if any.
    pub(crate) fn turn(&self, session_id: &SessionId, turn: TurnId) -> Option<TurnRecord> {
        guard(&self.data)
            .turns
            .get(&(session_id.as_str().to_owned(), turn.ordinal()))
            .cloned()
    }
}

impl StatePort for MemoryState {
    fn load_session(
        &self,
        session_id: &SessionId,
    ) -> PortFuture<'_, Result<Option<SessionSnapshot>, PortError>> {
        let found = guard(&self.data).sessions.get(session_id.as_str()).cloned();
        Box::pin(async move { Ok(found) })
    }

    fn save_session(&self, snapshot: SessionSnapshot) -> PortFuture<'_, Result<u64, PortError>> {
        let mut data = guard(&self.data);
        let key = snapshot.session_id.as_str().to_owned();
        let current = data
            .sessions
            .get(&key)
            .map_or(0, |existing| existing.revision);
        if current != snapshot.revision {
            let held = snapshot.revision;
            return Box::pin(async move {
                Err(PortError::Conflict(format!(
                    "expected revision {current}, caller held {held}"
                )))
            });
        }
        let next = current.saturating_add(1);
        let stored = SessionSnapshot {
            revision: next,
            ..snapshot
        };
        data.history.push(stored.clone());
        data.sessions.insert(key, stored);
        Box::pin(async move { Ok(next) })
    }

    fn save_turn(&self, record: TurnRecord) -> PortFuture<'_, Result<(), PortError>> {
        guard(&self.data).turns.insert(
            (record.session_id.as_str().to_owned(), record.turn.ordinal()),
            record,
        );
        Box::pin(async move { Ok(()) })
    }

    fn load_turn(
        &self,
        session_id: &SessionId,
        turn: TurnId,
    ) -> PortFuture<'_, Result<Option<TurnRecord>, PortError>> {
        let found = guard(&self.data)
            .turns
            .get(&(session_id.as_str().to_owned(), turn.ordinal()))
            .cloned();
        Box::pin(async move { Ok(found) })
    }

    fn list_sessions(&self) -> PortFuture<'_, Result<Vec<SessionSnapshot>, PortError>> {
        let mut sessions: Vec<SessionSnapshot> =
            guard(&self.data).sessions.values().cloned().collect();
        sessions.sort_by(|left, right| left.session_id.as_str().cmp(right.session_id.as_str()));
        Box::pin(async move { Ok(sessions) })
    }
}

/// An in-memory [`GoalStorePort`] that preserves insertion order.
#[derive(Default)]
pub(crate) struct MemoryGoals {
    goals: Mutex<Vec<GoalRecord>>,
    saves: AtomicUsize,
}

impl MemoryGoals {
    /// Creates an empty store.
    pub(crate) fn new() -> Arc<Self> {
        Arc::new(Self::default())
    }

    /// Returns how many writes the store accepted.
    pub(crate) fn saves(&self) -> usize {
        self.saves.load(Ordering::SeqCst)
    }
}

impl GoalStorePort for MemoryGoals {
    fn load(&self, goal_id: &GoalId) -> PortFuture<'_, Result<Option<GoalRecord>, PortError>> {
        let found = guard(&self.goals)
            .iter()
            .find(|record| &record.goal_id == goal_id)
            .cloned();
        Box::pin(async move { Ok(found) })
    }

    fn save(&self, record: GoalRecord) -> PortFuture<'_, Result<(), PortError>> {
        self.saves.fetch_add(1, Ordering::SeqCst);
        let mut goals = guard(&self.goals);
        let existing = goals
            .iter()
            .position(|existing| existing.goal_id == record.goal_id);
        let expected = existing.map_or(1, |index| goals[index].revision.saturating_add(1));
        if record.revision != expected {
            let held = record.revision;
            return Box::pin(async move {
                Err(PortError::Conflict(format!(
                    "expected revision {expected}, caller held {held}"
                )))
            });
        }
        match existing {
            Some(index) => goals[index] = record,
            None => goals.push(record),
        }
        Box::pin(async move { Ok(()) })
    }

    fn list_for_session(
        &self,
        session_id: &SessionId,
    ) -> PortFuture<'_, Result<Vec<GoalRecord>, PortError>> {
        let found: Vec<GoalRecord> = guard(&self.goals)
            .iter()
            .filter(|record| record.session_id.as_str() == session_id.as_str())
            .cloned()
            .collect();
        Box::pin(async move { Ok(found) })
    }
}

/// What a fake tool does when it is invoked.
#[derive(Clone, Debug)]
pub(crate) enum ToolBehaviour {
    /// Return successfully.
    Succeed {
        /// The output to report.
        output: String,
        /// Whether the call mutated the workspace.
        changed_workspace: bool,
    },
    /// Report a port failure.
    Fail(String),
    /// Never return, so only cancellation or the deadline can end the call.
    Hang,
    /// Return successfully, but only once the test opens the gate.
    Gated(Arc<Gate>),
}

/// A one-shot gate a test uses to hold a tool call open at a chosen moment.
#[derive(Debug, Default)]
pub(crate) struct Gate {
    open: Mutex<bool>,
    notify: Notify,
}

impl Gate {
    /// Creates a closed gate.
    pub(crate) fn new() -> Arc<Self> {
        Arc::new(Self::default())
    }

    /// Opens the gate, releasing every waiter.
    pub(crate) fn open(&self) {
        *guard(&self.open) = true;
        self.notify.notify_waiters();
    }

    async fn wait(&self) {
        loop {
            let notified = self.notify.notified();
            tokio::pin!(notified);
            notified.as_mut().enable();
            if *guard(&self.open) {
                return;
            }
            notified.await;
        }
    }
}

/// A [`ToolPort`] that records everything and behaves as configured.
pub(crate) struct RecordingTools {
    descriptors: Vec<ToolDescriptor>,
    behaviours: Mutex<HashMap<String, ToolBehaviour>>,
    invoked: Mutex<Vec<ToolCall>>,
    cancelled: Mutex<Vec<ToolCallId>>,
}

impl RecordingTools {
    /// Creates a tool adapter with the given catalogue and behaviours.
    pub(crate) fn new(
        descriptors: Vec<ToolDescriptor>,
        behaviours: Vec<(&str, ToolBehaviour)>,
    ) -> Arc<Self> {
        Arc::new(Self {
            descriptors,
            behaviours: Mutex::new(
                behaviours
                    .into_iter()
                    .map(|(name, behaviour)| (name.to_owned(), behaviour))
                    .collect(),
            ),
            invoked: Mutex::new(Vec::new()),
            cancelled: Mutex::new(Vec::new()),
        })
    }

    /// Returns every call the runtime dispatched, in order.
    pub(crate) fn invoked(&self) -> Vec<ToolCall> {
        guard(&self.invoked).clone()
    }

    /// Returns every call the runtime asked the adapter to tear down.
    pub(crate) fn cancelled(&self) -> Vec<ToolCallId> {
        guard(&self.cancelled).clone()
    }
}

impl ToolPort for RecordingTools {
    fn describe(&self) -> Vec<ToolDescriptor> {
        self.descriptors.clone()
    }

    fn invoke(&self, invocation: ToolInvocation) -> PortFuture<'_, Result<ToolOutcome, PortError>> {
        guard(&self.invoked).push(invocation.call.clone());
        let behaviour = guard(&self.behaviours)
            .get(&invocation.call.name)
            .cloned()
            .unwrap_or(ToolBehaviour::Succeed {
                output: "ok".to_owned(),
                changed_workspace: false,
            });
        let call_id = invocation.call.call_id;
        Box::pin(async move {
            match behaviour {
                ToolBehaviour::Succeed {
                    output,
                    changed_workspace,
                } => Ok(ToolOutcome {
                    call_id,
                    status: ToolStatus::Ok,
                    output,
                    changed_workspace,
                }),
                ToolBehaviour::Fail(reason) => Err(PortError::Invalid(reason)),
                ToolBehaviour::Hang => {
                    std::future::pending::<()>().await;
                    unreachable!("a hanging tool never resolves")
                }
                ToolBehaviour::Gated(gate) => {
                    gate.wait().await;
                    Ok(ToolOutcome {
                        call_id,
                        status: ToolStatus::Ok,
                        output: "gate opened".to_owned(),
                        changed_workspace: false,
                    })
                }
            }
        })
    }

    fn cancel(&self, call_id: &ToolCallId) -> PortFuture<'_, Result<(), PortError>> {
        guard(&self.cancelled).push(call_id.clone());
        Box::pin(async move { Ok(()) })
    }
}

/// What an approval adapter observed.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) enum ApprovalRecord {
    /// A request was shown to the operator.
    Presented(ApprovalId),
    /// A request was answered.
    Settled(ApprovalId),
    /// A request was taken back.
    Withdrawn(ApprovalId, ApprovalWithdrawal),
    /// A request was dismissed synchronously because its waiter was dropped.
    Abandoned(ApprovalId),
}

/// An [`ApprovalPort`] that records every notification.
#[derive(Default)]
pub(crate) struct RecordingApprovals {
    records: Mutex<Vec<ApprovalRecord>>,
}

impl RecordingApprovals {
    /// Creates an empty recorder.
    pub(crate) fn new() -> Arc<Self> {
        Arc::new(Self::default())
    }

    /// Returns every notification, in order.
    pub(crate) fn records(&self) -> Vec<ApprovalRecord> {
        guard(&self.records).clone()
    }
}

impl ApprovalPort for RecordingApprovals {
    fn present(&self, request: ApprovalRequest) -> PortFuture<'_, Result<(), PortError>> {
        guard(&self.records).push(ApprovalRecord::Presented(request.approval_id));
        Box::pin(async move { Ok(()) })
    }

    fn settle(&self, approval_id: &ApprovalId) -> PortFuture<'_, Result<(), PortError>> {
        guard(&self.records).push(ApprovalRecord::Settled(approval_id.clone()));
        Box::pin(async move { Ok(()) })
    }

    fn withdraw(
        &self,
        approval_id: &ApprovalId,
        reason: ApprovalWithdrawal,
    ) -> PortFuture<'_, Result<(), PortError>> {
        guard(&self.records).push(ApprovalRecord::Withdrawn(approval_id.clone(), reason));
        Box::pin(async move { Ok(()) })
    }

    fn abandon(&self, approval_id: &ApprovalId) {
        guard(&self.records).push(ApprovalRecord::Abandoned(approval_id.clone()));
    }
}

#[derive(Default)]
struct ContextData {
    items: Vec<ContextItem>,
    budget: u32,
    compacted: u32,
    bootstraps: u32,
}

/// A minimal but honest [`ContextEnginePort`].
///
/// Tokens are estimated as one per four bytes, which is enough for the runtime to exercise the
/// pressure and compaction paths deterministically.
#[derive(Default)]
pub(crate) struct SimpleContext {
    data: Mutex<ContextData>,
}

impl SimpleContext {
    /// Creates an empty engine.
    pub(crate) fn new() -> Arc<Self> {
        Arc::new(Self::default())
    }

    /// Returns every item the engine holds.
    pub(crate) fn items(&self) -> Vec<ContextItem> {
        guard(&self.data).items.clone()
    }

    /// Returns how many times the engine was bootstrapped.
    pub(crate) fn bootstraps(&self) -> u32 {
        guard(&self.data).bootstraps
    }

    fn tokens(items: &[ContextItem]) -> u32 {
        let bytes: usize = items
            .iter()
            .map(|item| match item {
                ContextItem::UserInput { text }
                | ContextItem::AssistantMessage { text }
                | ContextItem::SystemNote { text } => text.len(),
                ContextItem::GoalStatement { objective } => objective.len(),
                ContextItem::ToolResult {
                    tool_name, output, ..
                } => tool_name.len() + output.len(),
            })
            .sum();
        u32::try_from(bytes / 4).unwrap_or(u32::MAX)
    }

    fn snapshot(data: &ContextData) -> ContextState {
        let used = Self::tokens(&data.items);
        ContextState {
            item_count: u32::try_from(data.items.len()).unwrap_or(u32::MAX),
            used_tokens: used,
            token_budget: data.budget,
            needs_compaction: used > data.budget,
            compacted_items: data.compacted,
        }
    }
}

impl ContextEnginePort for SimpleContext {
    fn bootstrap(
        &self,
        request: ContextBootstrap,
    ) -> PortFuture<'_, Result<ContextState, PortError>> {
        let mut data = guard(&self.data);
        data.budget = request.token_budget;
        data.bootstraps = data.bootstraps.saturating_add(1);
        let state = Self::snapshot(&data);
        Box::pin(async move { Ok(state) })
    }

    fn ingest(&self, request: ContextIngest) -> PortFuture<'_, Result<ContextState, PortError>> {
        let mut data = guard(&self.data);
        data.items.push(request.item);
        let state = Self::snapshot(&data);
        Box::pin(async move { Ok(state) })
    }

    fn assemble(
        &self,
        _request: ContextAssembly,
    ) -> PortFuture<'_, Result<AssembledContext, PortError>> {
        let data = guard(&self.data);
        let messages: Vec<PromptMessage> = data
            .items
            .iter()
            .map(|item| match item {
                ContextItem::UserInput { text } => PromptMessage::User { text: text.clone() },
                ContextItem::AssistantMessage { text } => PromptMessage::Assistant {
                    text: text.clone(),
                    tool_calls: Vec::new(),
                },
                ContextItem::SystemNote { text } => PromptMessage::System { text: text.clone() },
                ContextItem::GoalStatement { objective } => PromptMessage::System {
                    text: format!("goal: {objective}"),
                },
                ContextItem::ToolResult {
                    tool_name,
                    output,
                    failed,
                } => PromptMessage::ToolResult {
                    call_id: ToolCallId::new(format!("result-{tool_name}"))
                        .expect("tool names produce valid identifiers"),
                    output: output.clone(),
                    failed: *failed,
                },
            })
            .collect();
        let assembled = AssembledContext {
            messages,
            state: Self::snapshot(&data),
        };
        Box::pin(async move { Ok(assembled) })
    }

    fn maintain(
        &self,
        _request: ContextMaintenance,
    ) -> PortFuture<'_, Result<ContextState, PortError>> {
        let data = guard(&self.data);
        let state = Self::snapshot(&data);
        Box::pin(async move { Ok(state) })
    }

    fn compact(
        &self,
        request: ContextCompaction,
    ) -> PortFuture<'_, Result<CompactionReport, PortError>> {
        let mut data = guard(&self.data);
        let before = Self::tokens(&data.items);
        let mut removed = 0_u32;
        while !data.items.is_empty()
            && before.saturating_sub(Self::tokens(&data.items)) < request.reclaim_tokens
        {
            data.items.remove(0);
            removed = removed.saturating_add(1);
        }
        data.compacted = data.compacted.saturating_add(removed);
        let after = Self::tokens(&data.items);
        let report = CompactionReport {
            removed_items: removed,
            reclaimed_tokens: before.saturating_sub(after),
            state: Self::snapshot(&data),
        };
        Box::pin(async move { Ok(report) })
    }
}

/// Builds a session identifier.
pub(crate) fn session(name: &str) -> SessionId {
    SessionId::new(name).expect("the test session name is valid")
}

/// Builds a tool call identifier.
pub(crate) fn call_id(name: &str) -> ToolCallId {
    ToolCallId::new(name).expect("the test call id is valid")
}

/// Builds a goal identifier.
pub(crate) fn goal_id(name: &str) -> GoalId {
    GoalId::new(name).expect("the test goal id is valid")
}

/// A plain read-only tool that never needs approval.
pub(crate) fn readonly_tool(name: &str) -> ToolDescriptor {
    ToolDescriptor {
        name: name.to_owned(),
        summary: format!("{name} (test)"),
        requires_approval: false,
        mutates_workspace: false,
    }
}

/// A mutating tool that always needs approval.
pub(crate) fn guarded_tool(name: &str) -> ToolDescriptor {
    ToolDescriptor {
        name: name.to_owned(),
        summary: format!("{name} (test, guarded)"),
        requires_approval: true,
        mutates_workspace: true,
    }
}

/// The chunk script for a round that only produces text.
pub(crate) fn text_round(text: &str) -> Round {
    Round::new(vec![
        ProviderChunk::TextDelta {
            text: text.to_owned(),
        },
        ProviderChunk::MessageEnd,
    ])
}

/// The chunk script for a round that requests one tool call.
pub(crate) fn tool_round(call: &str, tool: &str, arguments: &str) -> Round {
    Round::new(vec![
        ProviderChunk::ToolCallBegin {
            call_id: call_id(call),
            name: tool.to_owned(),
        },
        ProviderChunk::ToolCallArgumentsDelta {
            call_id: call_id(call),
            fragment: arguments.to_owned(),
        },
        ProviderChunk::ToolCallEnd {
            call_id: call_id(call),
        },
        ProviderChunk::MessageEnd,
    ])
}

/// Polls `predicate` until it holds, yielding between attempts.
///
/// Every wait is bounded so a broken runtime fails the test instead of hanging the suite.
pub(crate) async fn eventually(label: &str, mut predicate: impl FnMut() -> bool) {
    for _ in 0..2_000_u32 {
        if predicate() {
            return;
        }
        tokio::time::sleep(Duration::from_millis(1)).await;
    }
    panic!("timed out waiting for: {label}");
}

/// The identifier of the first turn, spelled out for readability in assertions.
pub(crate) const FIRST_TURN: TurnId = TurnId::FIRST;

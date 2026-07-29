//! A conformant in-memory [`ContextEnginePort`].
//!
//! The runtime ships one engine of its own so the SPI is not an interface with no implementers,
//! and so [`crate::context_engine::suite`] has a subject that is expected to pass every
//! requirement rather than only subjects that are expected to fail.
//!
//! It is deliberately simple: items are kept verbatim in arrival order, tokens are estimated at
//! one per four bytes, and compaction sheds the oldest *unpinned* items until it has freed what
//! it was asked for. Pinned items — system notes and goal statements — are the content the
//! engine committed to keeping, so neither maintenance nor compaction may drop them.

use std::sync::{Mutex, MutexGuard, PoisonError};

use claw_application::model::ids::ToolCallId;
use claw_application::ports::context::{
    AssembledContext, BootstrapReason, CompactionReport, ContextAssembly, ContextBootstrap,
    ContextCompaction, ContextEnginePort, ContextIngest, ContextItem, ContextMaintenance,
    ContextState,
};
use claw_application::ports::provider::PromptMessage;
use claw_application::ports::{PortError, PortFuture};
use claw_domain::SessionId;

/// The number of bytes the engine charges one token for.
const BYTES_PER_TOKEN: usize = 4;

/// Returns whether an item is content the engine promised to keep.
#[must_use]
pub const fn is_pinned(item: &ContextItem) -> bool {
    matches!(
        item,
        ContextItem::SystemNote { .. } | ContextItem::GoalStatement { .. }
    )
}

#[derive(Default)]
struct EngineState {
    session: Option<SessionId>,
    budget: u32,
    /// Goal context is structurally separate from ordinary history, so the
    /// turn-start clear/update synchronization path is O(1).
    goal: Option<ContextItem>,
    items: Vec<ContextItem>,
    /// Running sum of [`item_bytes`] over `goal` and `items`.
    ///
    /// Every state answer carries `used_tokens`, so recomputing the sum per answer made a session
    /// quadratic in the number of items it had ever ingested: 4096 ingests cost 3.43 ms, of which
    /// almost all was re-summing bytes the engine had already summed. Charging each mutation for
    /// its own delta makes the sum O(1) to read; the arithmetic is identical because tokens are
    /// derived from the *total* byte count, never from per-item rounding.
    bytes: usize,
    compacted: u32,
    #[cfg(test)]
    goal_sync_operations: u64,
}

impl EngineState {
    /// Appends one item and charges the running byte total for it.
    fn push(&mut self, item: ContextItem) {
        self.bytes = self.bytes.saturating_add(item_bytes(&item));
        self.items.push(item);
    }

    fn replace_goal(&mut self, replacement: Option<ContextItem>) {
        let previous_bytes = self.goal.as_ref().map_or(0, item_bytes);
        let replacement_bytes = replacement.as_ref().map_or(0, item_bytes);
        self.bytes = self
            .bytes
            .saturating_sub(previous_bytes)
            .saturating_add(replacement_bytes);
        self.goal = replacement;
        #[cfg(test)]
        {
            self.goal_sync_operations = self.goal_sync_operations.saturating_add(1);
        }
    }

    /// Drops every item and resets the running byte total with them.
    fn clear(&mut self) {
        self.goal = None;
        self.items.clear();
        self.bytes = 0;
        #[cfg(test)]
        {
            self.goal_sync_operations = 0;
        }
    }

    fn used_tokens(&self) -> u32 {
        Self::tokens(self.bytes)
    }

    fn tokens(bytes: usize) -> u32 {
        u32::try_from(bytes / BYTES_PER_TOKEN).unwrap_or(u32::MAX)
    }

    fn snapshot(&self) -> ContextState {
        let used = self.used_tokens();
        ContextState {
            item_count: u32::try_from(
                self.items
                    .len()
                    .saturating_add(usize::from(self.goal.is_some())),
            )
            .unwrap_or(u32::MAX),
            used_tokens: used,
            token_budget: self.budget,
            needs_compaction: used > self.budget,
            compacted_items: self.compacted,
        }
    }

    /// Returns the conflict an engine must raise when it is not open for `session_id`.
    fn ensure_open_for(&self, session_id: &SessionId) -> Result<(), PortError> {
        match &self.session {
            None => Err(PortError::Conflict(
                "the context engine has not been bootstrapped".to_owned(),
            )),
            Some(open) if open != session_id => Err(PortError::Conflict(format!(
                "the context engine is open for session {open}, not {session_id}"
            ))),
            Some(_) => Ok(()),
        }
    }
}

const fn item_bytes(item: &ContextItem) -> usize {
    match item {
        ContextItem::UserInput { text }
        | ContextItem::AssistantMessage { text }
        | ContextItem::SystemNote { text } => text.len(),
        ContextItem::GoalStatement { objective } => objective.len(),
        ContextItem::GoalCleared => 0,
        ContextItem::ToolResult {
            tool_name, output, ..
        } => tool_name.len() + output.len(),
    }
}

fn prompt_message(index: usize, item: &ContextItem) -> PromptMessage {
    match item {
        ContextItem::UserInput { text } => PromptMessage::User { text: text.clone() },
        ContextItem::AssistantMessage { text } => PromptMessage::Assistant {
            text: text.clone(),
            tool_calls: Vec::new(),
        },
        ContextItem::SystemNote { text } => PromptMessage::System { text: text.clone() },
        ContextItem::GoalStatement { objective } => PromptMessage::System {
            text: format!("goal: {objective}"),
        },
        ContextItem::GoalCleared => PromptMessage::System {
            text: String::new(),
        },
        ContextItem::ToolResult { output, failed, .. } => PromptMessage::ToolResult {
            call_id: ToolCallId::new(format!("context-item-{index}"))
                .expect("a generated context item identifier is always valid"),
            output: output.clone(),
            failed: *failed,
        },
    }
}

/// An in-memory context engine that satisfies every [`SpiRequirement`].
///
/// [`SpiRequirement`]: crate::context_engine::SpiRequirement
#[derive(Default)]
pub struct ReferenceContextEngine {
    state: Mutex<EngineState>,
}

impl ReferenceContextEngine {
    /// Creates a closed engine that must be bootstrapped before it answers anything.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Returns the goal first, followed by ordinary items in arrival order.
    #[must_use]
    pub fn items(&self) -> Vec<ContextItem> {
        let state = self.lock();
        let mut items = Vec::with_capacity(state.items.len().saturating_add(1));
        items.extend(state.goal.iter().cloned());
        items.extend(state.items.iter().cloned());
        items
    }

    /// Returns the session the engine is open for, if any.
    #[must_use]
    pub fn open_session(&self) -> Option<SessionId> {
        self.lock().session.clone()
    }

    #[cfg(test)]
    fn goal_sync_operations(&self) -> u64 {
        self.lock().goal_sync_operations
    }

    fn lock(&self) -> MutexGuard<'_, EngineState> {
        self.state.lock().unwrap_or_else(PoisonError::into_inner)
    }
}

impl ContextEnginePort for ReferenceContextEngine {
    fn bootstrap(
        &self,
        request: ContextBootstrap,
    ) -> PortFuture<'_, Result<ContextState, PortError>> {
        let mut state = self.lock();
        let outcome = match request.reason {
            BootstrapReason::NewSession => {
                state.clear();
                state.compacted = 0;
                state.session = Some(request.session_id);
                state.budget = request.token_budget;
                Ok(state.snapshot())
            }
            // A restart rehydrates an existing session, so it keeps whatever the engine holds and
            // only re-states the budget. Rebinding to a different session that way would silently
            // hand one session's context to another.
            BootstrapReason::Restart => match &state.session {
                Some(open) if *open != request.session_id => Err(PortError::Conflict(format!(
                    "the context engine is open for session {open}, not {}",
                    request.session_id
                ))),
                _ => {
                    state.session = Some(request.session_id);
                    state.budget = request.token_budget;
                    Ok(state.snapshot())
                }
            },
        };
        drop(state);
        Box::pin(async move { outcome })
    }

    fn ingest(&self, request: ContextIngest) -> PortFuture<'_, Result<ContextState, PortError>> {
        let mut state = self.lock();
        let outcome = state.ensure_open_for(&request.session_id).map(|()| {
            match request.item {
                item @ ContextItem::GoalStatement { .. } => state.replace_goal(Some(item)),
                ContextItem::GoalCleared => state.replace_goal(None),
                item => state.push(item),
            }
            state.snapshot()
        });
        drop(state);
        Box::pin(async move { outcome })
    }

    fn assemble(
        &self,
        request: ContextAssembly,
    ) -> PortFuture<'_, Result<AssembledContext, PortError>> {
        let state = self.lock();
        let outcome = state
            .ensure_open_for(&request.session_id)
            .map(|()| AssembledContext {
                messages: state
                    .goal
                    .iter()
                    .chain(state.items.iter())
                    .enumerate()
                    .map(|(index, item)| prompt_message(index, item))
                    .collect(),
                state: state.snapshot(),
            });
        drop(state);
        Box::pin(async move { outcome })
    }

    fn maintain(
        &self,
        request: ContextMaintenance,
    ) -> PortFuture<'_, Result<ContextState, PortError>> {
        let mut state = self.lock();
        let outcome = state.ensure_open_for(&request.session_id).map(|()| {
            // Upkeep collapses an unpinned item that repeats the one before it. Pinned items are
            // never candidates, so maintenance can only ever shrink the unpinned tail. `dedup_by`
            // compares each item against the previous *retained* one and compacts in place, which
            // is the same decision the old rebuild-into-a-second-vector loop made without the
            // second vector.
            let mut collapsed = 0_usize;
            state.items.dedup_by(|current, previous| {
                let repeats = !is_pinned(current) && current == previous;
                if repeats {
                    collapsed = collapsed.saturating_add(item_bytes(current));
                }
                repeats
            });
            state.bytes = state.bytes.saturating_sub(collapsed);
            state.snapshot()
        });
        drop(state);
        Box::pin(async move { outcome })
    }

    fn compact(
        &self,
        request: ContextCompaction,
    ) -> PortFuture<'_, Result<CompactionReport, PortError>> {
        let mut state = self.lock();
        let outcome = state.ensure_open_for(&request.session_id).map(|()| {
            // Shedding walks the unpinned items once, oldest first, stopping as soon as the
            // running byte total has freed what was asked for. The old loop re-summed every
            // remaining item and memmoved the tail of the vector once *per shed item*, so
            // compacting a 4096-item context cost 8.77 ms.
            let before = state.used_tokens();
            let mut freed = 0_usize;
            let mut shed = 0_usize;
            for item in &state.items {
                if before.saturating_sub(EngineState::tokens(state.bytes.saturating_sub(freed)))
                    >= request.reclaim_tokens
                {
                    break;
                }
                if is_pinned(item) {
                    continue;
                }
                freed = freed.saturating_add(item_bytes(item));
                shed = shed.saturating_add(1);
            }

            let mut remaining = shed;
            state.items.retain(|item| {
                if remaining > 0 && !is_pinned(item) {
                    remaining -= 1;
                    return false;
                }
                true
            });
            state.bytes = state.bytes.saturating_sub(freed);

            let removed = u32::try_from(shed).unwrap_or(u32::MAX);
            state.compacted = state.compacted.saturating_add(removed);
            CompactionReport {
                removed_items: removed,
                reclaimed_tokens: before.saturating_sub(state.used_tokens()),
                state: state.snapshot(),
            }
        });
        drop(state);
        Box::pin(async move { outcome })
    }
}

#[cfg(test)]
mod tests {
    use claw_application::model::ids::TurnId;
    use claw_application::model::time::Timestamp;
    use claw_application::ports::PortError;
    use claw_application::ports::context::{
        BootstrapReason, ContextBootstrap, ContextEnginePort, ContextIngest, ContextItem,
    };
    use claw_domain::SessionId;

    use super::{ReferenceContextEngine, is_pinned};

    fn session(name: &str) -> SessionId {
        SessionId::new(name).expect("the test session name is valid")
    }

    fn bootstrap(session_id: &SessionId, reason: BootstrapReason, budget: u32) -> ContextBootstrap {
        ContextBootstrap {
            session_id: session_id.clone(),
            reason,
            token_budget: budget,
            at: Timestamp::EPOCH,
        }
    }

    fn ingest(session_id: &SessionId, item: ContextItem) -> ContextIngest {
        ContextIngest {
            session_id: session_id.clone(),
            turn: TurnId::FIRST,
            item,
            at: Timestamp::EPOCH,
        }
    }

    #[test]
    fn only_notes_and_goals_are_pinned() {
        assert!(is_pinned(&ContextItem::SystemNote {
            text: "note".to_owned()
        }));
        assert!(is_pinned(&ContextItem::GoalStatement {
            objective: "ship".to_owned()
        }));
        assert!(!is_pinned(&ContextItem::UserInput {
            text: "hello".to_owned()
        }));
        assert!(!is_pinned(&ContextItem::AssistantMessage {
            text: "hi".to_owned()
        }));
        assert!(!is_pinned(&ContextItem::ToolResult {
            tool_name: "probe".to_owned(),
            output: "ok".to_owned(),
            failed: false,
        }));
    }

    #[tokio::test]
    async fn goal_updates_replace_and_clear_the_single_pinned_statement() {
        let engine = ReferenceContextEngine::new();
        let session_id = session("goal-lifecycle");
        engine
            .bootstrap(bootstrap(&session_id, BootstrapReason::NewSession, 128))
            .await
            .expect("bootstrap");

        for objective in ["first", "replacement"] {
            engine
                .ingest(ingest(
                    &session_id,
                    ContextItem::GoalStatement {
                        objective: objective.to_owned(),
                    },
                ))
                .await
                .expect("goal update");
        }
        assert_eq!(
            engine
                .items()
                .iter()
                .filter(|item| matches!(item, ContextItem::GoalStatement { .. }))
                .count(),
            1
        );
        assert_eq!(
            engine.items(),
            vec![ContextItem::GoalStatement {
                objective: "replacement".to_owned()
            }]
        );

        engine
            .ingest(ingest(&session_id, ContextItem::GoalCleared))
            .await
            .expect("goal clear");
        assert!(engine.items().is_empty());
    }

    #[tokio::test]
    async fn repeated_no_goal_sync_is_one_constant_time_operation_per_turn() {
        let engine = ReferenceContextEngine::new();
        let session_id = session("goal-sync-cost");
        engine
            .bootstrap(bootstrap(&session_id, BootstrapReason::NewSession, 100_000))
            .await
            .expect("bootstrap");
        for index in 0..1_000 {
            engine
                .ingest(ingest(
                    &session_id,
                    ContextItem::UserInput {
                        text: format!("history {index}"),
                    },
                ))
                .await
                .expect("history ingest");
        }

        for _ in 0..10_000 {
            engine
                .ingest(ingest(&session_id, ContextItem::GoalCleared))
                .await
                .expect("goal sync");
        }

        assert_eq!(engine.goal_sync_operations(), 10_000);
        assert_eq!(engine.items().len(), 1_000);
    }

    #[tokio::test]
    async fn a_restart_for_another_session_is_refused() {
        let engine = ReferenceContextEngine::new();
        engine
            .bootstrap(bootstrap(&session("one"), BootstrapReason::NewSession, 64))
            .await
            .expect("the first bootstrap succeeds");

        let error = engine
            .bootstrap(bootstrap(&session("two"), BootstrapReason::Restart, 64))
            .await
            .expect_err("a restart may not rebind the engine to another session");

        assert!(matches!(error, PortError::Conflict(_)));
        assert_eq!(engine.open_session(), Some(session("one")));
    }

    #[tokio::test]
    async fn maintenance_collapses_a_repeated_unpinned_item() {
        let session_id = session("upkeep");
        let engine = ReferenceContextEngine::new();
        engine
            .bootstrap(bootstrap(&session_id, BootstrapReason::NewSession, 1_000))
            .await
            .expect("bootstrap succeeds");
        let note = ContextItem::SystemNote {
            text: "pinned".to_owned(),
        };
        let echo = ContextItem::UserInput {
            text: "again".to_owned(),
        };
        for item in [note.clone(), note.clone(), echo.clone(), echo.clone()] {
            engine
                .ingest(ingest(&session_id, item))
                .await
                .expect("ingest succeeds");
        }

        let state = engine
            .maintain(claw_application::ports::context::ContextMaintenance {
                session_id: session_id.clone(),
                at: Timestamp::EPOCH,
            })
            .await
            .expect("maintenance succeeds");

        // Both pinned copies survive; the repeated unpinned one is collapsed.
        assert_eq!(state.item_count, 3);
        assert_eq!(engine.items(), vec![note.clone(), note, echo]);
    }
}

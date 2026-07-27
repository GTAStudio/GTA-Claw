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
    items: Vec<ContextItem>,
    compacted: u32,
}

impl EngineState {
    fn used_tokens(&self) -> u32 {
        Self::tokens(&self.items)
    }

    fn tokens(items: &[ContextItem]) -> u32 {
        let bytes: usize = items.iter().map(item_bytes).sum();
        u32::try_from(bytes / BYTES_PER_TOKEN).unwrap_or(u32::MAX)
    }

    fn snapshot(&self) -> ContextState {
        let used = self.used_tokens();
        ContextState {
            item_count: u32::try_from(self.items.len()).unwrap_or(u32::MAX),
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

    /// Returns every item the engine currently holds, in arrival order.
    #[must_use]
    pub fn items(&self) -> Vec<ContextItem> {
        self.lock().items.clone()
    }

    /// Returns the session the engine is open for, if any.
    #[must_use]
    pub fn open_session(&self) -> Option<SessionId> {
        self.lock().session.clone()
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
                state.items.clear();
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
            state.items.push(request.item);
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
                    .items
                    .iter()
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
            // never candidates, so maintenance can only ever shrink the unpinned tail.
            let mut kept: Vec<ContextItem> = Vec::with_capacity(state.items.len());
            for item in state.items.drain(..) {
                let repeats_previous =
                    !is_pinned(&item) && kept.last().is_some_and(|previous| *previous == item);
                if !repeats_previous {
                    kept.push(item);
                }
            }
            state.items = kept;
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
            let before = state.used_tokens();
            let mut removed = 0_u32;
            while before.saturating_sub(state.used_tokens()) < request.reclaim_tokens {
                let Some(oldest_unpinned) = state.items.iter().position(|item| !is_pinned(item))
                else {
                    break;
                };
                state.items.remove(oldest_unpinned);
                removed = removed.saturating_add(1);
            }
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

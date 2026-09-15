//! Tracked context mutations and durable checkpoint publication.

use std::collections::VecDeque;
use std::future::Future;
use std::sync::{Arc, Mutex};

use claw_application::ports::context::{
    AssembledContext, CompactionReport, ContextAssembly, ContextBootstrap, ContextCompaction,
    ContextEnginePort, ContextIngest, ContextMaintenance, ContextState,
};
use claw_application::ports::{PortError, PortFuture};
use claw_domain::SessionId;
use claw_state::DurableStateStore;
use tokio::sync::Semaphore;
use tokio_util::task::TaskTracker;

use super::agent_runtime::{MemoryCheckpoint, MemoryContextEngine};

pub(super) struct PersistentContextEngine {
    memory: Arc<MemoryContextEngine>,
    state: Arc<DurableStateStore>,
    serial: Arc<tokio::sync::Mutex<VecDeque<SessionId>>>,
    cache_capacity: usize,
    permits: Arc<Semaphore>,
    accepting: Mutex<bool>,
    tasks: TaskTracker,
}

impl PersistentContextEngine {
    pub(super) fn new(
        memory: Arc<MemoryContextEngine>,
        state: Arc<DurableStateStore>,
        cache_capacity: usize,
    ) -> Arc<Self> {
        Arc::new(Self {
            memory,
            state,
            serial: Arc::new(tokio::sync::Mutex::new(VecDeque::new())),
            cache_capacity: cache_capacity.clamp(1, 4096),
            permits: Arc::new(Semaphore::new(32)),
            accepting: Mutex::new(true),
            tasks: TaskTracker::new(),
        })
    }

    fn run<T, Work, WorkFuture>(
        &self,
        session: Option<SessionId>,
        work: Work,
    ) -> PortFuture<'_, Result<T, PortError>>
    where
        T: Send + 'static,
        Work:
            FnOnce(Arc<MemoryContextEngine>, Arc<DurableStateStore>) -> WorkFuture + Send + 'static,
        WorkFuture: Future<Output = Result<T, PortError>> + Send + 'static,
    {
        Box::pin(async move {
            let permit = Arc::clone(&self.permits)
                .try_acquire_owned()
                .map_err(|_| unavailable())?;
            let mut serial = Arc::clone(&self.serial).lock_owned().await;
            let task = {
                let accepting = self.accepting.lock().map_err(|_| unavailable())?;
                if !*accepting {
                    return Err(unavailable());
                }
                let memory = Arc::clone(&self.memory);
                let state = Arc::clone(&self.state);
                let capacity = self.cache_capacity;
                let task = self.tasks.spawn(async move {
                    let _permit = permit;
                    if let Some(session) = session {
                        if let Some(index) = serial.iter().position(|cached| cached == &session) {
                            serial.remove(index);
                        }
                        while serial.len() >= capacity {
                            if let Some(evicted) = serial.pop_front() {
                                memory.remove_session(&evicted);
                            }
                        }
                        if !memory.has_session(&session)
                            && let Some(saved) =
                                state.load_context::<MemoryCheckpoint>(&session).await?
                        {
                            memory.restore_checkpoint(&session, saved)?;
                        }
                        serial.push_back(session);
                    }
                    let _serial = serial;
                    work(memory, state).await
                });
                drop(accepting);
                task
            };
            task.await.map_err(|_| {
                PortError::Unavailable(
                    "context task failed; check its saved checkpoint before retry".to_owned(),
                )
            })?
        })
    }

    pub(super) async fn reset(&self, session: SessionId) -> Result<bool, PortError> {
        self.run(None, move |memory, state| async move {
            let stored = state.remove_session(&session).await?;
            let cached = memory.remove_session(&session);
            Ok(stored || cached)
        })
        .await
    }

    pub(super) async fn shutdown(&self) {
        {
            let mut accepting = self
                .accepting
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            *accepting = false;
            self.tasks.close();
            drop(accepting);
        }
        self.tasks.wait().await;
    }
}

fn unavailable() -> PortError {
    PortError::Unavailable("context checkpoint service is closed or at capacity".to_owned())
}

async fn checkpoint(
    memory: &MemoryContextEngine,
    state: &DurableStateStore,
    session: &SessionId,
) -> Result<(), PortError> {
    let snapshot = memory.checkpoint(session)?;
    if let Err(error) = state.save_context(session, snapshot).await {
        memory.remove_session(session);
        return Err(error);
    }
    Ok(())
}

impl ContextEnginePort for PersistentContextEngine {
    fn bootstrap(
        &self,
        request: ContextBootstrap,
    ) -> PortFuture<'_, Result<ContextState, PortError>> {
        self.run(
            Some(request.session_id.clone()),
            move |memory, state| async move {
                let session = request.session_id.clone();
                let result = memory.bootstrap(request).await?;
                checkpoint(&memory, &state, &session).await?;
                Ok(result)
            },
        )
    }

    fn ingest(&self, request: ContextIngest) -> PortFuture<'_, Result<ContextState, PortError>> {
        self.run(
            Some(request.session_id.clone()),
            move |memory, state| async move {
                let session = request.session_id.clone();
                let result = memory.ingest(request).await?;
                checkpoint(&memory, &state, &session).await?;
                Ok(result)
            },
        )
    }

    fn assemble(
        &self,
        request: ContextAssembly,
    ) -> PortFuture<'_, Result<AssembledContext, PortError>> {
        self.run(
            Some(request.session_id.clone()),
            move |memory, _state| async move { memory.assemble(request).await },
        )
    }

    fn maintain(
        &self,
        request: ContextMaintenance,
    ) -> PortFuture<'_, Result<ContextState, PortError>> {
        self.run(
            Some(request.session_id.clone()),
            move |memory, _state| async move { memory.maintain(request).await },
        )
    }

    fn compact(
        &self,
        request: ContextCompaction,
    ) -> PortFuture<'_, Result<CompactionReport, PortError>> {
        self.run(
            Some(request.session_id.clone()),
            move |memory, state| async move {
                let session = request.session_id.clone();
                let result = memory.compact(request).await?;
                checkpoint(&memory, &state, &session).await?;
                Ok(result)
            },
        )
    }
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicU64, Ordering};

    use claw_application::model::ids::TurnId;
    use claw_application::model::time::Timestamp;
    use claw_application::ports::context::{BootstrapReason, ContextItem};
    use claw_application::ports::provider::PromptMessage;

    use super::*;
    use crate::adapters::http_api::Diagnostics;

    static NEXT_ROOT: AtomicU64 = AtomicU64::new(0);

    struct TestRoot(std::path::PathBuf);

    impl Drop for TestRoot {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    #[tokio::test]
    async fn persistent_context_eviction_rehydrates_without_erasing_history() {
        let root = TestRoot(std::env::temp_dir().join(format!(
            "gta-claw-context-lru-{}-{}",
            std::process::id(),
            NEXT_ROOT.fetch_add(1, Ordering::Relaxed)
        )));
        std::fs::create_dir_all(&root.0).expect("fixture directory");
        let state = Arc::new(DurableStateStore::open(root.0.join("runtime.redb")).expect("state"));
        let memory = MemoryContextEngine::new(16, Arc::new(Diagnostics::new(8))).expect("memory");
        let context = PersistentContextEngine::new(Arc::clone(&memory), Arc::clone(&state), 1);
        let first = SessionId::new("first").expect("first session");
        let second = SessionId::new("second").expect("second session");
        for session in [&first, &second] {
            context
                .bootstrap(ContextBootstrap {
                    session_id: session.clone(),
                    reason: BootstrapReason::NewSession,
                    token_budget: 128,
                    at: Timestamp::from_millis(1),
                })
                .await
                .expect("bootstrap checkpoint");
            context
                .ingest(ContextIngest {
                    session_id: session.clone(),
                    turn: TurnId::FIRST,
                    item: ContextItem::UserInput {
                        text: format!("retained {}", session.as_str()),
                    },
                    at: Timestamp::from_millis(2),
                })
                .await
                .expect("durable message");
            if session == &first {
                let call_id = claw_application::model::ids::ToolCallId::new("owned-call")
                    .expect("call identity");
                for item in [
                    ContextItem::AssistantToolCalls {
                        text: String::new(),
                        tool_calls: vec![claw_application::model::message::ToolCall {
                            call_id: call_id.clone(),
                            name: "lookup".to_owned(),
                            arguments: "{}".to_owned(),
                        }],
                    },
                    ContextItem::ToolCallResult {
                        call_id,
                        tool_name: "lookup".to_owned(),
                        output: "owned result".to_owned(),
                        failed: false,
                    },
                ] {
                    context
                        .ingest(ContextIngest {
                            session_id: session.clone(),
                            turn: TurnId::FIRST,
                            item,
                            at: Timestamp::from_millis(3),
                        })
                        .await
                        .expect("durable typed context");
                }
            }
        }
        assert!(!memory.has_session(&first));
        assert!(memory.has_session(&second));
        assert!(
            state
                .load_context::<MemoryCheckpoint>(&first)
                .await
                .expect("saved first")
                .is_some()
        );
        let restored = context
            .assemble(ContextAssembly {
                session_id: first.clone(),
                turn: TurnId::FIRST,
                round: 0,
            })
            .await
            .expect("rehydration without a second bootstrap");
        assert!(restored.messages.iter().any(
            |message| matches!(message, PromptMessage::User { text } if text == "retained first")
        ));
        assert!(restored.messages.iter().any(|message| matches!(message, PromptMessage::Assistant { tool_calls, .. } if tool_calls.len() == 1 && tool_calls[0].call_id.as_str() == "owned-call" && tool_calls[0].arguments == "{}")));
        assert!(restored.messages.iter().any(|message| matches!(message, PromptMessage::ToolResult { call_id, output, .. } if call_id.as_str() == "owned-call" && output == "owned result")));
        assert!(memory.has_session(&first));
        assert!(!memory.has_session(&second));
        assert!(
            state
                .load_context::<MemoryCheckpoint>(&second)
                .await
                .expect("saved second")
                .is_some()
        );
        context.shutdown().await;
        state.shutdown().await;
        drop(context);
        drop(memory);
        drop(state);
        let state = Arc::new(
            DurableStateStore::open(root.0.join("runtime.redb")).expect("reopen stored context"),
        );
        let memory =
            MemoryContextEngine::new(16, Arc::new(Diagnostics::new(8))).expect("fresh memory");
        let context = PersistentContextEngine::new(memory, Arc::clone(&state), 1);
        context
            .bootstrap(ContextBootstrap {
                session_id: first.clone(),
                reason: BootstrapReason::Restart,
                token_budget: 128,
                at: Timestamp::from_millis(4),
            })
            .await
            .expect("restart context bootstrap");
        let reopened = context
            .assemble(ContextAssembly {
                session_id: first.clone(),
                turn: TurnId::FIRST,
                round: 1,
            })
            .await
            .expect("disk-restored typed history");
        assert!(reopened.messages.iter().any(|message| matches!(message, PromptMessage::Assistant { tool_calls, .. } if tool_calls.len() == 1 && tool_calls[0].call_id.as_str() == "owned-call")));
        assert!(reopened.messages.iter().any(|message| matches!(message, PromptMessage::ToolResult { call_id, output, failed:false } if call_id.as_str() == "owned-call" && output == "owned result")));
        assert!(context.reset(first.clone()).await.expect("explicit reset"));
        assert!(
            state
                .load_context::<MemoryCheckpoint>(&first)
                .await
                .expect("reset checkpoint")
                .is_none()
        );
        assert!(
            context
                .assemble(ContextAssembly {
                    session_id: first,
                    turn: TurnId::FIRST,
                    round: 0
                })
                .await
                .is_err()
        );
        context.shutdown().await;
        state.shutdown().await;
    }
}

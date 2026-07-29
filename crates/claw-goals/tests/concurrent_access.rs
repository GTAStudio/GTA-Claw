//! Deterministic concurrent mutations preserve every accepted transition.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Barrier};
use std::thread;

use claw_application::model::goal::{GoalRecord, GoalStatus};
use claw_application::model::ids::GoalId;
use claw_application::ports::goal::GoalStorePort;
use claw_application::ports::{PortError, PortFuture};
use claw_domain::SessionId;
use claw_goals::testing::{FixedClock, TempRoot, block_on, open_durable, session_id};
use claw_goals::{FileGoalStore, GoalCommandOutcome, execute_command, invoke_goal_tool};
use claw_runtime::{CommandRegistry, GoalConfig, GoalService, ScopeSet};

struct FirstLoadBarrierStore {
    inner: Arc<dyn GoalStorePort>,
    barrier: Arc<Barrier>,
    first_load: AtomicBool,
}

impl FirstLoadBarrierStore {
    fn new(inner: Arc<dyn GoalStorePort>, barrier: Arc<Barrier>) -> Self {
        Self {
            inner,
            barrier,
            first_load: AtomicBool::new(true),
        }
    }
}

impl GoalStorePort for FirstLoadBarrierStore {
    fn next_goal_ordinal(&self, session_id: &SessionId) -> PortFuture<'_, Result<u64, PortError>> {
        self.inner.next_goal_ordinal(session_id)
    }

    fn load(&self, goal_id: &GoalId) -> PortFuture<'_, Result<Option<GoalRecord>, PortError>> {
        let loaded = self.inner.load(goal_id);
        if self.first_load.swap(false, Ordering::SeqCst) {
            let barrier = Arc::clone(&self.barrier);
            return Box::pin(async move {
                let outcome = loaded.await;
                barrier.wait();
                outcome
            });
        }
        loaded
    }

    fn save(&self, record: GoalRecord) -> PortFuture<'_, Result<(), PortError>> {
        self.inner.save(record)
    }

    fn list_for_session(
        &self,
        session_id: &SessionId,
    ) -> PortFuture<'_, Result<Vec<GoalRecord>, PortError>> {
        self.inner.list_for_session(session_id)
    }
}

fn racing_service(root: &TempRoot, barrier: Arc<Barrier>) -> GoalService {
    let file_store = Arc::new(FileGoalStore::open(root.path()).expect("store opens"));
    let gated = Arc::new(FirstLoadBarrierStore::new(file_store, barrier));
    GoalService::new(
        gated,
        Arc::new(FixedClock::new(10_000)),
        GoalConfig::default(),
    )
}

#[test]
fn simultaneous_progress_writes_are_rebased_without_losing_either_note() {
    let root = TempRoot::new("concurrent-progress");
    let session = session_id("concurrent-progress");
    {
        let durable = open_durable(root.path(), 1_000);
        block_on(durable.service.start(&session, "preserve both steps")).expect("set");
    }

    let barrier = Arc::new(Barrier::new(2));
    let services = [
        racing_service(&root, Arc::clone(&barrier)),
        racing_service(&root, barrier),
    ];
    let workers = services
        .into_iter()
        .zip(["left step", "right step"])
        .map(|(service, note)| {
            let session = session.clone();
            thread::spawn(move || {
                block_on(invoke_goal_tool(
                    &service,
                    &session,
                    &format!("{{\"action\":\"progress\",\"note\":\"{note}\"}}"),
                ))
            })
        })
        .collect::<Vec<_>>();
    for worker in workers {
        worker
            .join()
            .expect("worker did not panic")
            .expect("the conflict is retried");
    }

    let durable = open_durable(root.path(), 100_000);
    let active = block_on(durable.service.active(&session))
        .expect("store answers")
        .expect("goal remains active");
    let mut notes = active
        .progress
        .iter()
        .map(|entry| entry.note.as_str())
        .collect::<Vec<_>>();
    notes.sort_unstable();
    assert_eq!(notes, vec!["left step", "right step"]);
    assert_eq!(active.revision, 3);
    assert_eq!(
        active
            .progress
            .iter()
            .map(|entry| entry.index)
            .collect::<Vec<_>>(),
        vec![0, 1]
    );
}

#[test]
fn simultaneous_close_commands_converge_without_an_operator_error() {
    let root = TempRoot::new("concurrent-close");
    let session = session_id("concurrent-close");
    {
        let durable = open_durable(root.path(), 1_000);
        block_on(durable.service.start(&session, "close once")).expect("set");
    }

    let barrier = Arc::new(Barrier::new(2));
    let services = [
        racing_service(&root, Arc::clone(&barrier)),
        racing_service(&root, barrier),
    ];
    #[expect(
        clippy::needless_collect,
        reason = "both workers must be spawned before either is joined or the read barrier deadlocks"
    )]
    let workers = services
        .into_iter()
        .map(|service| {
            let session = session.clone();
            thread::spawn(move || {
                block_on(execute_command(
                    &CommandRegistry::builtin(),
                    &service,
                    &session,
                    ScopeSet::all(),
                    "/goal-done",
                ))
            })
        })
        .collect::<Vec<_>>();
    let outcomes = workers
        .into_iter()
        .map(|worker| {
            worker
                .join()
                .expect("worker did not panic")
                .expect("both commands converge")
        })
        .collect::<Vec<_>>();

    assert_eq!(
        outcomes
            .iter()
            .filter(|outcome| matches!(outcome, GoalCommandOutcome::Closed(_)))
            .count(),
        1
    );
    assert_eq!(
        outcomes
            .iter()
            .filter(|outcome| matches!(outcome, GoalCommandOutcome::NothingToClose))
            .count(),
        1
    );

    let durable = open_durable(root.path(), 100_000);
    let history = block_on(durable.service.history(&session)).expect("history");
    assert_eq!(history.len(), 1);
    assert_eq!(history[0].status, GoalStatus::Achieved);
    assert_eq!(history[0].revision, 2);
}

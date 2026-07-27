//! Deterministic helpers for exercising a durable goal store.
//!
//! These are part of the crate's public surface on purpose. A durable store is only interesting
//! when something drives it across a restart, and the two things that takes — a clock that does
//! not depend on wall time and a way to await a port future without pulling in an async runtime —
//! are needed by every consumer that wants to assert the same property, not just by this crate's
//! own tests.

use std::future::Future;
use std::path::{Path, PathBuf};
use std::pin::pin;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::task::{Context, Poll, Waker};
use std::time::Duration;

use claw_application::model::goal::{GoalRecord, GoalStatus};
use claw_application::model::ids::GoalId;
use claw_application::model::time::Timestamp;
use claw_application::ports::PortError;
use claw_application::ports::PortFuture;
use claw_application::ports::clock::ClockPort;
use claw_application::ports::goal::GoalStorePort;
use claw_domain::SessionId;
use claw_runtime::{GoalConfig, GoalService};

use crate::budget::GoalBudget;
use crate::store::FileGoalStore;

/// Goal-store wrapper that injects one deterministic optimistic-concurrency conflict.
///
/// This is useful for proving a caller retries a fresh read/write transaction
/// without relying on scheduler timing.
pub struct ConflictOnceStore {
    inner: Arc<dyn GoalStorePort>,
    armed: AtomicU64,
    after_commit: bool,
}

impl std::fmt::Debug for ConflictOnceStore {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("ConflictOnceStore")
            .field("armed", &self.armed.load(Ordering::SeqCst))
            .field("after_commit", &self.after_commit)
            .finish_non_exhaustive()
    }
}

impl ConflictOnceStore {
    /// Wraps a store with one armed save conflict.
    #[must_use]
    pub fn new(inner: Arc<dyn GoalStorePort>) -> Self {
        Self {
            inner,
            armed: AtomicU64::new(1),
            after_commit: false,
        }
    }

    /// Wraps a store with one conflict reported after the delegated save commits.
    ///
    /// This models a multi-write operation whose first record committed before
    /// a later optimistic-concurrency check failed.
    #[must_use]
    pub fn after_commit(inner: Arc<dyn GoalStorePort>) -> Self {
        Self {
            inner,
            armed: AtomicU64::new(1),
            after_commit: true,
        }
    }

    /// Arms one conflict for the next save.
    pub fn arm(&self) {
        self.armed.store(1, Ordering::SeqCst);
    }
}

impl GoalStorePort for ConflictOnceStore {
    fn load(&self, goal_id: &GoalId) -> PortFuture<'_, Result<Option<GoalRecord>, PortError>> {
        self.inner.load(goal_id)
    }

    fn save(&self, record: GoalRecord) -> PortFuture<'_, Result<(), PortError>> {
        if self.armed.swap(0, Ordering::SeqCst) == 1 {
            if self.after_commit {
                let committed = self.inner.save(record);
                return Box::pin(async move {
                    committed.await?;
                    Err(PortError::Conflict(
                        "deterministic post-commit conflict".to_owned(),
                    ))
                });
            }
            return Box::pin(std::future::ready(Err(PortError::Conflict(
                "deterministic injected conflict".to_owned(),
            ))));
        }
        self.inner.save(record)
    }

    fn list_for_session(
        &self,
        session_id: &SessionId,
    ) -> PortFuture<'_, Result<Vec<GoalRecord>, PortError>> {
        self.inner.list_for_session(session_id)
    }
}

/// Runs a future to completion on the calling thread.
///
/// [`GoalStorePort`](claw_application::ports::goal::GoalStorePort) is asynchronous, but a local
/// filesystem adapter never yields: the futures it returns are already complete. Busy-polling is
/// therefore not a spin — the first poll returns `Ready` — and it keeps a durable-store consumer
/// from having to link an executor just to read a goal back.
///
/// # Panics
///
/// Panics if the future does not complete on the first poll, which for this crate's futures means
/// a caller passed something that genuinely needs an executor.
pub fn block_on<F: Future>(future: F) -> F::Output {
    let waker = Waker::noop();
    let mut context = Context::from_waker(waker);
    let mut future = pin!(future);
    match future.as_mut().poll(&mut context) {
        Poll::Ready(value) => value,
        Poll::Pending => panic!("claw_goals::testing::block_on needs an already-complete future"),
    }
}

/// A clock that never moves.
#[derive(Debug)]
pub struct FixedClock {
    millis: i64,
}

impl FixedClock {
    /// Creates a clock pinned to `millis` since the Unix epoch.
    #[must_use]
    pub const fn new(millis: i64) -> Self {
        Self { millis }
    }
}

impl ClockPort for FixedClock {
    fn now(&self) -> Timestamp {
        Timestamp::from_millis(self.millis)
    }

    fn sleep(&self, _duration: Duration) -> PortFuture<'_, ()> {
        Box::pin(std::future::ready(()))
    }
}

/// A clock that advances by a fixed step on every reading.
///
/// Goal history is ordered by the timestamps the service stamps on it, so a store test that used
/// a frozen clock could not tell "kept the order" from "happened to be stable".
#[derive(Debug)]
pub struct SteppingClock {
    next: AtomicU64,
    step: u64,
}

impl SteppingClock {
    /// Creates a clock that starts at `start` and advances `step` milliseconds per reading.
    #[must_use]
    pub const fn new(start: u64, step: u64) -> Self {
        Self {
            next: AtomicU64::new(start),
            step,
        }
    }

    /// Returns a clock suitable for most tests: starts at 1, advances a second at a time.
    #[must_use]
    pub const fn default_steps() -> Self {
        Self::new(1_000, 1_000)
    }
}

impl ClockPort for SteppingClock {
    fn now(&self) -> Timestamp {
        let millis = self.next.fetch_add(self.step, Ordering::SeqCst);
        Timestamp::from_millis(i64::try_from(millis).unwrap_or(i64::MAX))
    }

    fn sleep(&self, _duration: Duration) -> PortFuture<'_, ()> {
        Box::pin(std::future::ready(()))
    }
}

/// A directory that deletes itself when it is dropped.
///
/// Restart tests need a real directory on a real filesystem — that is the whole point — but they
/// must not leave one behind, and two tests running in parallel must not share one.
#[derive(Debug)]
pub struct TempRoot {
    path: PathBuf,
}

impl TempRoot {
    /// Creates a fresh, empty directory named after `label`.
    ///
    /// # Panics
    ///
    /// Panics if the directory cannot be created, which no test can proceed past.
    #[must_use]
    pub fn new(label: &str) -> Self {
        static COUNTER: AtomicU64 = AtomicU64::new(0);
        let ordinal = COUNTER.fetch_add(1, Ordering::SeqCst);
        let path = std::env::temp_dir().join(format!(
            "claw-goals-{label}-{}-{ordinal}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&path);
        std::fs::create_dir_all(&path).expect("the test temporary directory can be created");
        Self { path }
    }

    /// Returns the directory.
    #[must_use]
    pub fn path(&self) -> &Path {
        &self.path
    }
}

impl Drop for TempRoot {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.path);
    }
}

/// Builds a session identifier, panicking on an invalid one.
///
/// # Panics
///
/// Panics when `value` is not a valid session identifier.
#[must_use]
pub fn session_id(value: &str) -> SessionId {
    SessionId::new(value).expect("valid session identifier")
}

/// Builds a goal identifier, panicking on an invalid one.
///
/// # Panics
///
/// Panics when `value` is not a valid goal identifier.
#[must_use]
pub fn goal_id(value: &str) -> GoalId {
    GoalId::new(value).expect("valid goal identifier")
}

/// Builds a minimal active goal record for store-level tests.
///
/// # Panics
///
/// Panics when either identifier is invalid.
#[must_use]
pub fn record(session: &str, goal: &str, objective: &str, revision: u64) -> GoalRecord {
    GoalRecord {
        goal_id: goal_id(goal),
        session_id: session_id(session),
        objective: objective.to_owned(),
        status: GoalStatus::Active,
        progress: Vec::new(),
        created_at: Timestamp::from_millis(1),
        updated_at: Timestamp::from_millis(1),
        closed_at: None,
        compacted_entries: 0,
        revision,
    }
}

/// A durable goal service and the store underneath it.
///
/// Holding the store as well as the service is what makes a restart test possible to write
/// honestly: the store answers "what is on disk" while the service answers "what does the runtime
/// see", and a test can compare them.
#[derive(Debug)]
pub struct DurableGoals {
    /// The on-disk store.
    pub store: Arc<FileGoalStore>,
    /// The service the runtime drives.
    pub service: GoalService,
}

/// Opens a durable goal service over `root`.
///
/// Each call builds a brand-new store and service, which is exactly what a restart is: nothing
/// carries over except the directory.
///
/// # Panics
///
/// Panics when the directory cannot be opened as a goal store.
#[must_use]
pub fn open_durable(root: &Path, clock_start: u64) -> DurableGoals {
    open_durable_with(
        root,
        clock_start,
        GoalConfig::default(),
        GoalBudget::default(),
    )
}

/// Opens a durable goal service with explicit goal and storage limits.
///
/// # Panics
///
/// Panics when the directory cannot be opened as a goal store.
#[must_use]
pub fn open_durable_with(
    root: &Path,
    clock_start: u64,
    goals: GoalConfig,
    budget: GoalBudget,
) -> DurableGoals {
    let store = Arc::new(
        FileGoalStore::open_with_budget(root, budget).expect("the goal store opens over the root"),
    );
    let service = GoalService::new(
        Arc::clone(&store) as Arc<_>,
        Arc::new(SteppingClock::new(clock_start, 1_000)),
        goals,
    );
    DurableGoals { store, service }
}

#[cfg(test)]
mod tests {
    use super::{FixedClock, SteppingClock, TempRoot, block_on};
    use claw_application::model::time::Timestamp;
    use claw_application::ports::clock::ClockPort;

    #[test]
    fn block_on_returns_the_value_of_an_already_complete_future() {
        assert_eq!(block_on(std::future::ready(7)), 7);
    }

    #[test]
    fn a_fixed_clock_never_moves_and_a_stepping_clock_always_does() {
        let fixed = FixedClock::new(42);
        assert_eq!(fixed.now(), Timestamp::from_millis(42));
        assert_eq!(fixed.now(), Timestamp::from_millis(42));

        let stepping = SteppingClock::new(10, 5);
        assert_eq!(stepping.now(), Timestamp::from_millis(10));
        assert_eq!(stepping.now(), Timestamp::from_millis(15));
        assert_eq!(stepping.now(), Timestamp::from_millis(20));
    }

    #[test]
    fn a_temporary_root_is_created_fresh_and_removed_on_drop() {
        let path = {
            let root = TempRoot::new("self-test");
            std::fs::write(root.path().join("marker"), "x").expect("writable");
            assert!(root.path().join("marker").exists());
            root.path().to_path_buf()
        };

        assert!(!path.exists());
    }

    #[test]
    fn two_temporary_roots_never_collide() {
        let first = TempRoot::new("collision");
        let second = TempRoot::new("collision");

        assert_ne!(first.path(), second.path());
    }
}

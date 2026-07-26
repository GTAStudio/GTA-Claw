//! The tokio implementations of the composition's runtime ports.
//!
//! `claw-application` deliberately knows nothing about an async runtime.
//! Spawning and cancellation are ports, and this is where they are supplied.
//!
//! The important property here is provable: after [`RuntimeHost::shutdown`]
//! returns, every task ever spawned through [`TaskSpawner`] has run to
//! termination. That is enforced by a `TaskTracker` — which cannot report empty
//! while a tracked task is alive — and observed by a counter incremented from a
//! guard's `Drop`, so a task that is cancelled part way through still counts as
//! terminated. Comparing the spawn count with the termination count is therefore
//! a real leak check rather than a check that shutdown returned.

use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

use claw_application::composition::{
    BoxFuture, ShutdownSignal, SubsystemError, SubsystemId, TaskSpawner,
};
use tokio_util::sync::CancellationToken;
use tokio_util::task::TaskTracker;

/// Increments the termination counter however the task ended.
struct TerminationGuard(Arc<AtomicU64>);

impl Drop for TerminationGuard {
    fn drop(&mut self) {
        self.0.fetch_add(1, Ordering::SeqCst);
    }
}

/// Spawns tracked tasks onto the current tokio runtime.
#[derive(Clone, Debug)]
pub struct TrackedSpawner {
    tracker: TaskTracker,
    cancellation: CancellationToken,
    subsystem: SubsystemId,
    spawned: Arc<AtomicU64>,
    terminated: Arc<AtomicU64>,
}

impl TrackedSpawner {
    /// Creates a spawner over `tracker`, refusing to spawn once `cancellation`
    /// has fired.
    #[must_use]
    pub fn new(tracker: TaskTracker, cancellation: CancellationToken) -> Self {
        Self {
            tracker,
            cancellation,
            subsystem: SubsystemId::new("runtime").expect("the literal satisfies the grammar"),
            spawned: Arc::new(AtomicU64::new(0)),
            terminated: Arc::new(AtomicU64::new(0)),
        }
    }

    /// Returns how many tasks have been accepted.
    #[must_use]
    pub fn spawned(&self) -> u64 {
        self.spawned.load(Ordering::SeqCst)
    }

    /// Returns how many tasks have run to termination, whether they completed
    /// normally or were dropped during cancellation.
    #[must_use]
    pub fn terminated(&self) -> u64 {
        self.terminated.load(Ordering::SeqCst)
    }

    /// Returns how many tasks the tracker still holds.
    #[must_use]
    pub fn outstanding(&self) -> usize {
        self.tracker.len()
    }
}

impl TaskSpawner for TrackedSpawner {
    fn spawn(
        &self,
        name: &'static str,
        task: BoxFuture<'static, ()>,
    ) -> Result<(), SubsystemError> {
        if self.cancellation.is_cancelled() || self.tracker.is_closed() {
            return Err(SubsystemError::cancelled(self.subsystem.clone()));
        }

        let terminated = Arc::clone(&self.terminated);
        self.spawned.fetch_add(1, Ordering::SeqCst);

        self.tracker.spawn(async move {
            let _guard = TerminationGuard(terminated);
            let _ = name;
            task.await;
        });

        Ok(())
    }
}

/// A [`ShutdownSignal`] backed by a `CancellationToken`.
#[derive(Clone, Debug)]
pub struct TokenShutdown(CancellationToken);

impl TokenShutdown {
    /// Wraps `token`.
    #[must_use]
    pub const fn new(token: CancellationToken) -> Self {
        Self(token)
    }
}

impl ShutdownSignal for TokenShutdown {
    fn is_triggered(&self) -> bool {
        self.0.is_cancelled()
    }

    fn triggered(&self) -> BoxFuture<'_, ()> {
        Box::pin(self.0.cancelled())
    }
}

/// What the runtime observed while stopping.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct TaskLedger {
    spawned: u64,
    terminated: u64,
    outstanding: usize,
}

impl TaskLedger {
    /// Returns how many tasks were spawned during the run.
    #[must_use]
    pub const fn spawned(self) -> u64 {
        self.spawned
    }

    /// Returns how many of them reached termination.
    #[must_use]
    pub const fn terminated(self) -> u64 {
        self.terminated
    }

    /// Returns how many the tracker still held when shutdown returned.
    #[must_use]
    pub const fn outstanding(self) -> usize {
        self.outstanding
    }

    /// Returns whether every spawned task was joined and none was left behind.
    #[must_use]
    pub const fn is_settled(self) -> bool {
        self.spawned == self.terminated && self.outstanding == 0
    }
}

/// Owns the task tracker and the cancellation token for one daemon run.
#[derive(Clone, Debug)]
pub struct RuntimeHost {
    tracker: TaskTracker,
    cancellation: CancellationToken,
    spawner: Arc<TrackedSpawner>,
}

impl RuntimeHost {
    /// Creates a runtime host with a fresh tracker and token.
    #[must_use]
    pub fn new() -> Self {
        let tracker = TaskTracker::new();
        let cancellation = CancellationToken::new();
        let spawner = Arc::new(TrackedSpawner::new(tracker.clone(), cancellation.clone()));

        Self {
            tracker,
            cancellation,
            spawner,
        }
    }

    /// Returns the spawner subsystems are given.
    #[must_use]
    pub fn spawner(&self) -> Arc<dyn TaskSpawner> {
        Arc::clone(&self.spawner) as Arc<dyn TaskSpawner>
    }

    /// Returns the shutdown signal subsystems are given.
    #[must_use]
    pub fn shutdown_signal(&self) -> Arc<dyn ShutdownSignal> {
        Arc::new(TokenShutdown::new(self.cancellation.clone()))
    }

    /// Returns the cancellation token, for code that needs it directly.
    #[must_use]
    pub fn cancellation(&self) -> CancellationToken {
        self.cancellation.clone()
    }

    /// Asks every task to stop without waiting for them.
    pub fn request_stop(&self) {
        self.cancellation.cancel();
    }

    /// Cancels outstanding work and waits for every tracked task to terminate.
    ///
    /// Closing the tracker before waiting is what makes the wait terminate: a
    /// closed tracker refuses new registrations, so the set being waited on
    /// cannot grow while the wait is in progress.
    pub async fn shutdown(&self) -> TaskLedger {
        self.cancellation.cancel();
        self.tracker.close();
        self.tracker.wait().await;

        TaskLedger {
            spawned: self.spawner.spawned(),
            terminated: self.spawner.terminated(),
            outstanding: self.tracker.len(),
        }
    }
}

impl Default for RuntimeHost {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::time::Duration;

    use claw_application::composition::SubsystemErrorKind;

    use super::RuntimeHost;

    #[tokio::test]
    async fn every_spawned_task_is_joined_before_shutdown_returns() {
        let host = RuntimeHost::new();
        let spawner = host.spawner();
        let finished = Arc::new(AtomicU64::new(0));

        for _ in 0..16 {
            let finished = Arc::clone(&finished);
            spawner
                .spawn(
                    "worker",
                    Box::pin(async move {
                        tokio::time::sleep(Duration::from_millis(5)).await;
                        finished.fetch_add(1, Ordering::SeqCst);
                    }),
                )
                .expect("the daemon is running");
        }

        let ledger = host.shutdown().await;

        assert_eq!(ledger.spawned(), 16);
        assert_eq!(ledger.terminated(), 16);
        assert_eq!(ledger.outstanding(), 0);
        assert!(ledger.is_settled());
        assert_eq!(finished.load(Ordering::SeqCst), 16);
    }

    #[tokio::test]
    async fn a_task_cancelled_part_way_through_still_counts_as_terminated() {
        let host = RuntimeHost::new();
        let spawner = host.spawner();
        let signal = host.shutdown_signal();
        let reached_end = Arc::new(AtomicU64::new(0));

        for _ in 0..4 {
            let reached_end = Arc::clone(&reached_end);
            let signal = Arc::clone(&signal);
            spawner
                .spawn(
                    "waiter",
                    Box::pin(async move {
                        signal.triggered().await;
                        reached_end.fetch_add(1, Ordering::SeqCst);
                    }),
                )
                .expect("the daemon is running");
        }

        let ledger = host.shutdown().await;

        assert_eq!(ledger.spawned(), 4);
        assert_eq!(ledger.terminated(), 4);
        assert!(ledger.is_settled());
        assert_eq!(
            reached_end.load(Ordering::SeqCst),
            4,
            "the tasks observed the signal rather than being aborted"
        );
    }

    #[tokio::test]
    async fn spawning_after_shutdown_is_refused_instead_of_leaking() {
        let host = RuntimeHost::new();
        let spawner = host.spawner();

        let ledger = host.shutdown().await;
        assert!(ledger.is_settled());

        let error = spawner
            .spawn("late", Box::pin(async {}))
            .expect_err("the daemon has stopped");

        assert_eq!(error.kind(), SubsystemErrorKind::Cancelled);
        assert_eq!(error.subsystem().as_str(), "runtime");
        assert_eq!(host.shutdown().await.spawned(), 0);
    }

    #[tokio::test]
    async fn the_shutdown_signal_reports_before_and_after_it_fires() {
        let host = RuntimeHost::new();
        let signal = host.shutdown_signal();

        assert!(!signal.is_triggered());
        host.request_stop();
        assert!(signal.is_triggered());

        tokio::time::timeout(Duration::from_secs(1), signal.triggered())
            .await
            .expect("an already-triggered signal resolves immediately");
    }
}

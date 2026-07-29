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
//!
//! [`RuntimeHost::shutdown_within`] trades that guarantee for a bound, which is
//! what a process stop needs: tasks are asked to stop and never aborted, so a
//! task that ignores the signal would otherwise keep the process alive for as
//! long as it liked. The bounded form reports the difference in the ledger
//! rather than waiting it out.

use std::fmt::{self, Display, Formatter};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use claw_application::composition::{
    BoxFuture, ShutdownSignal, SubsystemError, SubsystemId, TaskSpawner,
};
use tokio::sync::Semaphore;
use tokio_util::sync::CancellationToken;
use tokio_util::task::TaskTracker;

/// The identifier this module's own errors are reported under.
///
/// The one fallible construction in this module lives here rather than in
/// [`TrackedSpawner::new`], so that the constructor a caller uses carries no
/// failure of its own; `the_runtime_identifier_satisfies_the_grammar` pins the
/// literal against the grammar it has to satisfy.
fn runtime_subsystem() -> SubsystemId {
    SubsystemId::new("runtime").expect("the literal satisfies the grammar")
}

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
    admission: Arc<Mutex<()>>,
    closing: Arc<AtomicBool>,
    subsystem: SubsystemId,
    spawned: Arc<AtomicU64>,
    terminated: Arc<AtomicU64>,
}

impl TrackedSpawner {
    /// Creates a spawner over `tracker`, refusing to spawn once `cancellation`
    /// has fired.
    #[must_use]
    pub fn new(tracker: TaskTracker, cancellation: CancellationToken) -> Self {
        Self::with_admission(
            tracker,
            cancellation,
            Arc::new(Mutex::new(())),
            Arc::new(AtomicBool::new(false)),
        )
    }

    fn with_admission(
        tracker: TaskTracker,
        cancellation: CancellationToken,
        admission: Arc<Mutex<()>>,
        closing: Arc<AtomicBool>,
    ) -> Self {
        Self {
            tracker,
            cancellation,
            admission,
            closing,
            subsystem: runtime_subsystem(),
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
        if self.closing.load(Ordering::Acquire) {
            return Err(SubsystemError::cancelled(self.subsystem.clone()));
        }
        let _admission = self
            .admission
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if self.closing.load(Ordering::Acquire)
            || self.cancellation.is_cancelled()
            || self.tracker.is_closed()
        {
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
    admission: Arc<Mutex<()>>,
    closing: Arc<AtomicBool>,
    spawner: Arc<TrackedSpawner>,
}

impl RuntimeHost {
    /// Creates a runtime host with a fresh tracker and token.
    #[must_use]
    pub fn new() -> Self {
        let tracker = TaskTracker::new();
        let cancellation = CancellationToken::new();
        let admission = Arc::new(Mutex::new(()));
        let closing = Arc::new(AtomicBool::new(false));
        let spawner = Arc::new(TrackedSpawner::with_admission(
            tracker.clone(),
            cancellation.clone(),
            Arc::clone(&admission),
            Arc::clone(&closing),
        ));

        Self {
            tracker,
            cancellation,
            admission,
            closing,
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
    ///
    /// The wait itself is unbounded, so this is for a caller that already has a
    /// deadline of its own. The daemon's last stop uses
    /// [`shutdown_within`](Self::shutdown_within) instead.
    pub async fn shutdown(&self) -> TaskLedger {
        self.close_admission();
        self.tracker.wait().await;

        self.ledger()
    }

    /// Cancels outstanding work and waits up to `budget` for every tracked task
    /// to terminate.
    ///
    /// A task is asked to stop, never aborted, so a task that ignores its
    /// shutdown signal would keep an unbounded wait — and therefore the whole
    /// process — alive for as long as it likes. This bounds that wait. Running
    /// out of budget is not an error to propagate: it is a fact about the run,
    /// and the returned ledger states it, because a task that never terminated
    /// is counted in [`spawned`](TaskLedger::spawned) and not in
    /// [`terminated`](TaskLedger::terminated) and leaves
    /// [`outstanding`](TaskLedger::outstanding) above zero. The caller reports
    /// an unsettled ledger as an unclean stop and exits anyway.
    pub async fn shutdown_within(&self, budget: Duration) -> TaskLedger {
        self.close_admission();

        // Deliberately not `?`-style handling: both outcomes continue to the
        // same ledger, which is what distinguishes them.
        let _ = tokio::time::timeout(budget, self.tracker.wait()).await;

        self.ledger()
    }

    /// Reads the three counters that make up one run's task accounting.
    fn ledger(&self) -> TaskLedger {
        TaskLedger {
            spawned: self.spawner.spawned(),
            terminated: self.spawner.terminated(),
            outstanding: self.tracker.len(),
        }
    }

    fn close_admission(&self) {
        self.closing.store(true, Ordering::Release);
        let _admission = self
            .admission
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        self.cancellation.cancel();
        self.tracker.close();
    }
}

impl Default for RuntimeHost {
    fn default() -> Self {
        Self::new()
    }
}

/// Failure to admit or join one owned blocking task.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum BlockingTaskError {
    /// Shutdown started before the task could be admitted.
    Cancelled,
    /// The bounded blocking task panicked or the runtime rejected it.
    Join(String),
}

impl Display for BlockingTaskError {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        match self {
            Self::Cancelled => formatter.write_str("blocking task admission was cancelled"),
            Self::Join(error) => write!(formatter, "blocking task failed: {error}"),
        }
    }
}

impl std::error::Error for BlockingTaskError {}

/// Bounded owner for filesystem, credential, and other blocking operations.
///
/// Every admitted closure is tracked independently of the future awaiting its
/// result. Dropping that future therefore cannot detach the closure: shutdown
/// either joins it or reports it in the returned [`TaskLedger`].
#[derive(Clone, Debug)]
pub struct BlockingTaskHost {
    tracker: TaskTracker,
    cancellation: CancellationToken,
    admission: Arc<Mutex<()>>,
    closing: Arc<AtomicBool>,
    permits: Arc<Semaphore>,
    spawned: Arc<AtomicU64>,
    terminated: Arc<AtomicU64>,
}

impl BlockingTaskHost {
    /// Creates a host with at most `parallelism` admitted closures running.
    #[must_use]
    pub fn new(parallelism: usize) -> Self {
        Self {
            tracker: TaskTracker::new(),
            cancellation: CancellationToken::new(),
            admission: Arc::new(Mutex::new(())),
            closing: Arc::new(AtomicBool::new(false)),
            permits: Arc::new(Semaphore::new(parallelism.max(1))),
            spawned: Arc::new(AtomicU64::new(0)),
            terminated: Arc::new(AtomicU64::new(0)),
        }
    }

    /// Runs one closure on Tokio's blocking pool under bounded admission.
    ///
    /// # Errors
    ///
    /// Returns [`BlockingTaskError::Cancelled`] once shutdown begins, or
    /// [`BlockingTaskError::Join`] if the admitted closure panics.
    pub async fn run<T, F>(&self, _name: &'static str, task: F) -> Result<T, BlockingTaskError>
    where
        T: Send + 'static,
        F: FnOnce() -> T + Send + 'static,
    {
        let permit = tokio::select! {
            permit = Arc::clone(&self.permits).acquire_owned() => {
                permit.map_err(|_| BlockingTaskError::Cancelled)?
            }
            () = self.cancellation.cancelled() => return Err(BlockingTaskError::Cancelled),
        };
        if self.closing.load(Ordering::Acquire) {
            return Err(BlockingTaskError::Cancelled);
        }
        let admission = self
            .admission
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if self.closing.load(Ordering::Acquire)
            || self.cancellation.is_cancelled()
            || self.tracker.is_closed()
        {
            return Err(BlockingTaskError::Cancelled);
        }
        let terminated = Arc::clone(&self.terminated);
        self.spawned.fetch_add(1, Ordering::SeqCst);
        let task = self.tracker.spawn_blocking(move || {
            let _guard = TerminationGuard(terminated);
            let _permit = permit;
            task()
        });
        drop(admission);
        task.await
            .map_err(|error| BlockingTaskError::Join(error.to_string()))
    }

    /// Prevents new admissions and asks waiters to stop.
    pub fn request_stop(&self) {
        self.close_admission();
    }

    /// Closes admission and waits for all owned blocking tasks up to `budget`.
    pub async fn shutdown_within(&self, budget: Duration) -> TaskLedger {
        self.close_admission();
        let _ = tokio::time::timeout(budget, self.tracker.wait()).await;
        self.ledger()
    }

    /// Returns current blocking-task accounting without changing admission.
    #[must_use]
    pub fn ledger(&self) -> TaskLedger {
        TaskLedger {
            spawned: self.spawned.load(Ordering::SeqCst),
            terminated: self.terminated.load(Ordering::SeqCst),
            outstanding: self.tracker.len(),
        }
    }

    pub(crate) fn record_abandoned(&self) {
        self.spawned.fetch_add(1, Ordering::SeqCst);
    }

    fn close_admission(&self) {
        self.closing.store(true, Ordering::Release);
        let _admission = self
            .admission
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        self.cancellation.cancel();
        self.tracker.close();
        self.permits.close();
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::time::Duration;

    use claw_application::composition::SubsystemErrorKind;

    use super::{BlockingTaskHost, RuntimeHost, runtime_subsystem};

    #[test]
    fn the_runtime_identifier_satisfies_the_grammar() {
        assert_eq!(runtime_subsystem().as_str(), "runtime");
    }

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

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn spawn_admission_is_serialized_with_close() {
        let host = RuntimeHost::new();
        let admission = host
            .admission
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let closing = Arc::clone(&host.closing);
        let shutdown_host = host.clone();
        let shutdown = tokio::spawn(async move { shutdown_host.shutdown().await });
        while !closing.load(Ordering::Acquire) {
            std::thread::yield_now();
        }

        let error = host
            .spawner()
            .spawn("too-late", Box::pin(async {}))
            .expect_err("close intent must fence later spawn admission");
        drop(admission);
        let ledger = shutdown.await.expect("shutdown task joins");

        assert_eq!(error.kind(), SubsystemErrorKind::Cancelled);
        assert!(ledger.is_settled());
        assert_eq!(ledger.spawned(), 0);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn blocked_owned_work_is_reported_until_it_really_terminates() {
        let host = BlockingTaskHost::new(1);
        let entered = Arc::new(std::sync::Barrier::new(2));
        let release = Arc::new(std::sync::Barrier::new(2));
        let task_host = host.clone();
        let task_entered = Arc::clone(&entered);
        let task_release = Arc::clone(&release);
        let task = tokio::spawn(async move {
            task_host
                .run("barrier", move || {
                    task_entered.wait();
                    task_release.wait();
                })
                .await
        });
        entered.wait();

        let ledger = host.shutdown_within(Duration::from_millis(25)).await;
        assert_eq!(ledger.spawned(), 1);
        assert_eq!(ledger.terminated(), 0);
        assert_eq!(ledger.outstanding(), 1);
        assert!(!ledger.is_settled());

        release.wait();
        task.await
            .expect("blocking task future joins")
            .expect("blocking task completes");
        let ledger = host.shutdown_within(Duration::from_secs(1)).await;
        assert!(ledger.is_settled());
        assert_eq!(ledger.terminated(), 1);
    }

    #[tokio::test]
    async fn explicitly_abandoned_owned_work_cannot_produce_a_clean_ledger() {
        let host = BlockingTaskHost::new(1);
        host.record_abandoned();

        let ledger = host.shutdown_within(Duration::from_secs(1)).await;

        assert_eq!(ledger.spawned(), 1);
        assert_eq!(ledger.terminated(), 0);
        assert_eq!(ledger.outstanding(), 0);
        assert!(!ledger.is_settled());
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

    /// A task that ignores its shutdown signal must not hold the process open.
    ///
    /// The unbounded `shutdown` would wait for this task for a full minute.
    /// Bounding the wait is what lets the daemon report the leak and exit
    /// instead of hanging with a supervisor's kill timer running.
    #[tokio::test]
    async fn a_task_that_ignores_cancellation_cannot_outlast_the_budget() {
        let host = RuntimeHost::new();

        host.spawner()
            .spawn(
                "deaf",
                Box::pin(async {
                    tokio::time::sleep(Duration::from_mins(1)).await;
                }),
            )
            .expect("the daemon is running");

        let ledger = tokio::time::timeout(
            Duration::from_secs(5),
            host.shutdown_within(Duration::from_millis(50)),
        )
        .await
        .expect("the bounded shutdown returns without waiting for the task");

        assert_eq!(ledger.spawned(), 1);
        assert_eq!(ledger.terminated(), 0, "the task did not stop, by design");
        assert_eq!(ledger.outstanding(), 1);
        assert!(
            !ledger.is_settled(),
            "an abandoned task must be reported as an unsettled ledger"
        );
    }

    /// The budget is a ceiling, not a delay.
    #[tokio::test]
    async fn a_cooperative_task_settles_the_bounded_shutdown_immediately() {
        let host = RuntimeHost::new();
        let signal = host.shutdown_signal();

        host.spawner()
            .spawn(
                "waiter",
                Box::pin(async move {
                    signal.triggered().await;
                }),
            )
            .expect("the daemon is running");

        let started = std::time::Instant::now();
        let ledger = host.shutdown_within(Duration::from_secs(30)).await;

        assert!(ledger.is_settled());
        assert_eq!(ledger.terminated(), 1);
        assert!(
            started.elapsed() < Duration::from_secs(5),
            "the bounded shutdown waited for the budget instead of for the task"
        );
    }
}

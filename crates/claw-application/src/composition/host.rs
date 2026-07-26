//! Driving a composition through its lifecycle.
//!
//! The host owns the *sequence*: which subsystem is touched, in what order, and
//! what happens when one of them refuses. It contains no async runtime and no
//! knowledge of any concrete subsystem, so the ordering rules can be tested
//! exhaustively against fakes and then reused verbatim by the daemon.
//!
//! Startup is all-or-nothing. If any subsystem fails to initialize or start,
//! everything already brought up is torn down in reverse order before the error
//! is returned, and the composition ends in
//! [`LifecyclePhase::Failed`]. A half-started daemon is never handed back to a
//! caller.
//!
//! Shutdown is best-effort and never stops early. Every subsystem gets its
//! [`Subsystem::quiesce`], [`Subsystem::drain`] and [`Subsystem::shutdown`]
//! calls even if an earlier one failed, because a subsystem that refuses to stop
//! must not be able to keep the ones behind it alive.
//!
//! Both lifecycle methods are cancellation-safe in the only sense Rust allows.
//! `Drop` cannot run asynchronous teardown, so instead of pretending it can,
//! [`SubsystemHost::start`] and [`SubsystemHost::shutdown`] guarantee that a
//! dropped future leaves the host in a state a later [`SubsystemHost::shutdown`]
//! can finish from. See [`InterruptGuard`].

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

use super::error::{CompositionError, SubsystemError};
use super::graph::CompositionPlan;
use super::id::SubsystemId;
use super::lifecycle::{EpochGate, Lifecycle, LifecyclePhase};
use super::subsystem::{DrainReport, ServiceHandle, StartContext, Subsystem};

/// What happened while the daemon was stopping.
///
/// Errors are collected rather than propagated so that one uncooperative
/// subsystem cannot abort the teardown of the others. Callers are expected to
/// report them and still exit.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct ShutdownReport {
    drains: Vec<DrainReport>,
    errors: Vec<SubsystemError>,
}

impl ShutdownReport {
    /// Returns each subsystem's drain result, in shutdown order.
    #[must_use]
    pub fn drains(&self) -> &[DrainReport] {
        &self.drains
    }

    /// Returns every error raised during teardown, in the order they happened.
    #[must_use]
    pub fn errors(&self) -> &[SubsystemError] {
        &self.errors
    }

    /// Returns whether every subsystem stopped without complaint and without
    /// abandoning work.
    #[must_use]
    pub fn is_clean(&self) -> bool {
        self.errors.is_empty() && self.drains.iter().all(DrainReport::is_clean)
    }

    /// Returns the total number of work items completed during the drain.
    #[must_use]
    pub fn completed(&self) -> u32 {
        self.drains.iter().map(DrainReport::completed).sum()
    }

    /// Returns the total number of work items abandoned during the drain.
    #[must_use]
    pub fn abandoned(&self) -> u32 {
        self.drains.iter().map(DrainReport::abandoned).sum()
    }
}

/// Records that a lifecycle future was dropped part way through, so a later
/// [`SubsystemHost::shutdown`] can finish the teardown it abandoned.
///
/// Both `start` and `shutdown` mutate state that outlives them — the phase, and
/// the record of which subsystems have been touched — and then await. An async
/// future can be dropped at any await point, so without this guard a cancelled
/// caller leaves the phase at `Initializing`, `Starting` or `Draining`. None of
/// those can reach `Draining` or `Stopping`, which means every subsystem that
/// had already run `initialize` keeps its resources and *no* code path can
/// release them: `shutdown` is refused by the phase check before `stop_all`
/// runs, and `start` is refused because the phase is no longer `Created`.
///
/// `Drop` cannot await, so this guard does not attempt teardown. It does the one
/// thing it can do synchronously: it flags the composition as interrupted.
/// [`SubsystemHost::shutdown`] reads that flag and tears down through the
/// `Failed` edges, which exist precisely for a composition that stopped
/// somewhere it cannot continue from.
///
/// The flag is shared through an [`Arc`] rather than borrowed from the host so
/// that arming it does not borrow `self`, which lets the guard stay alive across
/// the whole of `start` while the loop still uses `self`.
struct InterruptGuard {
    interrupted: Arc<AtomicBool>,
    armed: bool,
}

impl InterruptGuard {
    fn arm(interrupted: &Arc<AtomicBool>) -> Self {
        Self {
            interrupted: Arc::clone(interrupted),
            armed: true,
        }
    }

    /// Cancels the guard, because the operation reached a phase it can be
    /// resumed from deliberately.
    ///
    /// Call this only once every `await` that could leave torn state is behind
    /// you. In particular `start` disarms *after* its own `abort` has finished,
    /// not before, so that a caller dropped during the rollback is still
    /// recorded as interrupted.
    fn disarm(&mut self) {
        self.armed = false;
    }
}

impl Drop for InterruptGuard {
    fn drop(&mut self) {
        if self.armed {
            self.interrupted.store(true, Ordering::Release);
        }
    }
}

/// Holds the subsystems of one daemon and moves them through the lifecycle
/// together.
pub struct SubsystemHost {
    subsystems: Vec<Arc<dyn Subsystem>>,
    plan: CompositionPlan,
    lifecycle: Lifecycle,
    initialized: Vec<usize>,
    started: Vec<usize>,
    interrupted: Arc<AtomicBool>,
}

impl SubsystemHost {
    /// Builds a host from the subsystems that make up the daemon.
    ///
    /// The plan is computed here, before anything is touched, so a cycle or a
    /// dangling dependency is reported before any resource is acquired.
    ///
    /// # Errors
    ///
    /// Returns the [`CompositionError`] that made the composition unorderable.
    pub fn new(subsystems: Vec<Arc<dyn Subsystem>>) -> Result<Self, CompositionError> {
        Self::with_lifecycle(subsystems, Lifecycle::new())
    }

    /// Builds a host around a lifecycle that already exists.
    ///
    /// A composition root needs the [`EpochGate`] before it can build the
    /// [`GrantIssuer`](super::authority::GrantIssuer), and it needs the issuer
    /// before it can build the subsystems that depend on it. Creating the
    /// [`Lifecycle`] first breaks that cycle without letting anyone mint a
    /// second, unrelated gate: the issuer and this host observe the same one.
    ///
    /// # Errors
    ///
    /// Returns the [`CompositionError`] that made the composition unorderable.
    pub fn with_lifecycle(
        subsystems: Vec<Arc<dyn Subsystem>>,
        lifecycle: Lifecycle,
    ) -> Result<Self, CompositionError> {
        let descriptors: Vec<_> = subsystems
            .iter()
            .map(|subsystem| subsystem.descriptor())
            .collect();
        let plan = CompositionPlan::build(&descriptors)?;

        Ok(Self {
            subsystems,
            plan,
            lifecycle,
            initialized: Vec::new(),
            started: Vec::new(),
            interrupted: Arc::new(AtomicBool::new(false)),
        })
    }

    /// Returns the phase the composition is in.
    #[must_use]
    pub const fn phase(&self) -> LifecyclePhase {
        self.lifecycle.phase()
    }

    /// Returns the plan, so a caller can report the order it will use.
    #[must_use]
    pub const fn plan(&self) -> &CompositionPlan {
        &self.plan
    }

    /// Returns a handle to the epoch gate every capability is tied to.
    ///
    /// This must be handed to the [`GrantIssuer`](super::authority::GrantIssuer)
    /// before startup, because a capability minted against a different gate
    /// would not die when this composition drains.
    #[must_use]
    pub fn epoch_gate(&self) -> EpochGate {
        self.lifecycle.epoch_gate()
    }

    fn position_of(&self, id: &SubsystemId) -> usize {
        self.subsystems
            .iter()
            .position(|subsystem| subsystem.descriptor().id() == id)
            .expect("the plan is built from these subsystems, so every id resolves")
    }

    fn order(&self, ids: &[SubsystemId]) -> Vec<usize> {
        ids.iter().map(|id| self.position_of(id)).collect()
    }

    /// Initializes and starts every subsystem in dependency order.
    ///
    /// Returns each subsystem's [`ServiceHandle`] in start order.
    ///
    /// Dropping the returned future does not abandon the subsystems it already
    /// touched: the composition is flagged as interrupted, and a later
    /// [`shutdown`](Self::shutdown) tears them down. It cannot tear them down
    /// from `Drop` itself, because teardown is asynchronous.
    ///
    /// # Errors
    ///
    /// Returns [`CompositionError::SubsystemFailed`] carrying the first failure.
    /// Everything already brought up has been torn down by the time this
    /// returns.
    ///
    /// Returns [`CompositionError::PhaseTransition`] when a previous lifecycle
    /// future was dropped part way through and the resulting teardown has not
    /// been finished by a call to [`shutdown`](Self::shutdown) yet.
    pub async fn start(
        &mut self,
        context: &StartContext,
    ) -> Result<Vec<ServiceHandle>, CompositionError> {
        let start_order = self.order(self.plan.start_order());

        self.lifecycle.transition_to(LifecyclePhase::Initializing)?;

        // Armed for the whole of both loops. Every `await` below is a point the
        // caller can be cancelled at, and each one is past a mutation of
        // `initialized` or `started` that teardown depends on.
        let mut guard = InterruptGuard::arm(&self.interrupted);

        for position in &start_order {
            let subsystem = Arc::clone(&self.subsystems[*position]);
            let scoped = context.for_subsystem(subsystem.descriptor().id().clone());

            // Recorded before the call, not after: a subsystem that fails part
            // way through `initialize` may already hold resources, and the trait
            // contract requires `shutdown` to be called for it.
            self.initialized.push(*position);

            if let Err(error) = subsystem.initialize(&scoped).await {
                self.abort().await;
                // Disarmed only now: `abort` awaits, so a caller dropped during
                // the rollback must still be recorded as interrupted.
                guard.disarm();
                return Err(CompositionError::SubsystemFailed(error));
            }
        }

        self.lifecycle.transition_to(LifecyclePhase::Initialized)?;
        self.lifecycle.transition_to(LifecyclePhase::Starting)?;

        let mut handles = Vec::with_capacity(start_order.len());

        for position in &start_order {
            let subsystem = Arc::clone(&self.subsystems[*position]);
            let scoped = context.for_subsystem(subsystem.descriptor().id().clone());

            // Recorded before the call for the same reason: a failed `start` may
            // still have spawned background work that has to be drained.
            self.started.push(*position);

            match subsystem.start(&scoped).await {
                Ok(handle) => handles.push(handle),
                Err(error) => {
                    self.abort().await;
                    guard.disarm();
                    return Err(CompositionError::SubsystemFailed(error));
                }
            }
        }

        guard.disarm();
        self.lifecycle.transition_to(LifecyclePhase::Running)?;

        Ok(handles)
    }

    /// Tears down everything brought up so far, after a startup failure.
    async fn abort(&mut self) {
        self.fail_and_tear_down(&mut ShutdownReport::default())
            .await;
    }

    /// Moves to [`LifecyclePhase::Failed`] and stops everything recorded as
    /// touched, ending in [`LifecyclePhase::Stopped`].
    ///
    /// Used both for a startup failure and for finishing a teardown that an
    /// earlier dropped future abandoned, so both paths behave identically.
    async fn fail_and_tear_down(&mut self, report: &mut ShutdownReport) {
        if self.lifecycle.phase() != LifecyclePhase::Failed {
            self.lifecycle
                .transition_to(LifecyclePhase::Failed)
                .expect("every phase this is reachable from may fail");
        }

        self.quiesce_and_drain(report).await;
        self.stop_all(report).await;

        self.lifecycle
            .transition_to(LifecyclePhase::Stopping)
            .expect("failed may stop");
        self.lifecycle
            .transition_to(LifecyclePhase::Stopped)
            .expect("stopping may finish");
    }

    async fn quiesce_and_drain(&mut self, report: &mut ShutdownReport) {
        for position in self.order(&self.plan.quiesce_order()) {
            if !self.started.contains(&position) {
                continue;
            }

            if let Err(error) = self.subsystems[position].quiesce().await {
                report.errors.push(error);
            }
        }

        for position in self.order(&self.plan.shutdown_order()) {
            if !self.started.contains(&position) {
                continue;
            }

            // Struck off before the await rather than after, so a teardown
            // dropped at this point does not drain the same subsystem twice
            // when it is resumed.
            self.started.retain(|recorded| *recorded != position);

            match self.subsystems[position].drain().await {
                Ok(drained) => report.drains.push(drained),
                Err(error) => report.errors.push(error),
            }
        }
    }

    async fn stop_all(&mut self, report: &mut ShutdownReport) {
        for position in self.order(&self.plan.shutdown_order()) {
            if !self.initialized.contains(&position) {
                continue;
            }

            // `Subsystem::shutdown` is documented as the last call a subsystem
            // receives, so it must happen exactly once even if this future is
            // dropped mid-teardown and a later `shutdown` resumes the work.
            self.initialized.retain(|recorded| *recorded != position);

            if let Err(error) = self.subsystems[position].shutdown().await {
                report.errors.push(error);
            }
        }

        self.started.clear();
        self.initialized.clear();
    }

    /// Stops the daemon.
    ///
    /// The epoch gate shuts the instant the composition leaves
    /// [`LifecyclePhase::Running`], which is before any subsystem is asked to
    /// quiesce. Every capability minted during the run is therefore dead before
    /// teardown begins, not merely once it has finished.
    ///
    /// If an earlier lifecycle future — this one or [`start`](Self::start) — was
    /// dropped part way through, this finishes the teardown it abandoned,
    /// calling `shutdown` exactly once on every subsystem that still holds
    /// resources, and ends in [`LifecyclePhase::Stopped`].
    ///
    /// # Errors
    ///
    /// Returns the [`CompositionError`] produced by an illegal phase change,
    /// which can only happen if the host was not running.
    pub async fn shutdown(&mut self) -> Result<ShutdownReport, CompositionError> {
        let mut report = ShutdownReport::default();

        // Taken, not merely read: if this teardown is itself dropped, the guard
        // below sets the flag again so the next caller still sees it.
        if self.interrupted.swap(false, Ordering::AcqRel) {
            if self.lifecycle.phase() == LifecyclePhase::Stopped {
                return Ok(report);
            }

            let mut guard = InterruptGuard::arm(&self.interrupted);
            self.fail_and_tear_down(&mut report).await;
            guard.disarm();
            return Ok(report);
        }

        self.lifecycle.transition_to(LifecyclePhase::Draining)?;

        let mut guard = InterruptGuard::arm(&self.interrupted);
        self.quiesce_and_drain(&mut report).await;

        self.lifecycle.transition_to(LifecyclePhase::Stopping)?;
        self.stop_all(&mut report).await;
        guard.disarm();

        self.lifecycle.transition_to(LifecyclePhase::Stopped)?;

        Ok(report)
    }
}

impl std::fmt::Debug for SubsystemHost {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("SubsystemHost")
            .field("phase", &self.lifecycle.phase())
            .field("subsystems", &self.plan.len())
            .finish_non_exhaustive()
    }
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::{Arc, Mutex};

    use super::{ShutdownReport, SubsystemHost};
    use crate::composition::BoxFuture;
    use crate::composition::clock::ProcessClock;
    use crate::composition::error::{CompositionError, SubsystemError, SubsystemErrorKind};
    use crate::composition::id::SubsystemId;
    use crate::composition::lifecycle::LifecyclePhase;
    use crate::composition::session::{ModelName, ProviderName, RuntimeSettings};
    use crate::composition::subsystem::{
        DrainReport, ServiceHandle, StartContext, Subsystem, SubsystemDescriptor, SubsystemKind,
        TaskSpawner,
    };

    /// Appends `subsystem/step` for every call, so the whole ordering can be
    /// asserted as one sequence rather than one flag per subsystem.
    type Journal = Arc<Mutex<Vec<String>>>;

    /// Refuses to spawn, because no test here needs background work and a
    /// silently ignored spawn would hide a bug.
    #[derive(Debug)]
    struct NoSpawner;

    impl TaskSpawner for NoSpawner {
        fn spawn(
            &self,
            name: &'static str,
            _task: BoxFuture<'static, ()>,
        ) -> Result<(), SubsystemError> {
            Err(SubsystemError::internal(
                SubsystemId::new("host").expect("valid"),
                format!("this composition does not spawn, but {name} tried"),
            ))
        }
    }

    #[derive(Debug)]
    struct NeverShuttingDown(AtomicBool);

    impl crate::composition::ShutdownSignal for NeverShuttingDown {
        fn is_triggered(&self) -> bool {
            self.0.load(Ordering::SeqCst)
        }

        fn triggered(&self) -> BoxFuture<'_, ()> {
            Box::pin(std::future::pending())
        }
    }

    /// A subsystem that records every call and can be told to fail at one step.
    struct Recorder {
        id: SubsystemId,
        kind: SubsystemKind,
        dependencies: Vec<SubsystemId>,
        journal: Journal,
        fail_at: Option<&'static str>,
        park_at: Option<&'static str>,
        completed: u32,
    }

    impl Recorder {
        fn new(journal: &Journal, id: &str, dependencies: &[&str]) -> Self {
            Self {
                id: SubsystemId::new(id).expect("valid"),
                kind: SubsystemKind::Capability,
                dependencies: dependencies
                    .iter()
                    .map(|name| SubsystemId::new(*name).expect("valid"))
                    .collect(),
                journal: Arc::clone(journal),
                fail_at: None,
                park_at: None,
                completed: 0,
            }
        }

        const fn ingress(mut self) -> Self {
            self.kind = SubsystemKind::Ingress;
            self
        }

        const fn failing_at(mut self, step: &'static str) -> Self {
            self.fail_at = Some(step);
            self
        }

        /// Makes `step` never resolve, so a test can reach that await and then
        /// drop the lifecycle future there.
        const fn parking_at(mut self, step: &'static str) -> Self {
            self.park_at = Some(step);
            self
        }

        const fn completing(mut self, completed: u32) -> Self {
            self.completed = completed;
            self
        }

        /// Records the call, then parks or fails if this step was configured to.
        ///
        /// The journal entry is written before parking so a test can prove the
        /// await was reached, and distinguish "never called" from "called and
        /// still running".
        async fn note(&self, step: &'static str) -> Result<(), SubsystemError> {
            self.journal
                .lock()
                .expect("uncontended")
                .push(format!("{}/{step}", self.id));

            if self.park_at == Some(step) {
                std::future::pending::<()>().await;
            }

            if self.fail_at == Some(step) {
                return Err(SubsystemError::unavailable(
                    self.id.clone(),
                    format!("{step} was told to fail"),
                ));
            }

            Ok(())
        }
    }

    impl Subsystem for Recorder {
        fn descriptor(&self) -> SubsystemDescriptor {
            let mut descriptor = SubsystemDescriptor::new(self.id.clone(), self.kind);

            for dependency in &self.dependencies {
                descriptor = descriptor.depends_on(dependency.clone());
            }

            descriptor
        }

        fn initialize<'a>(
            &'a self,
            _context: &'a StartContext,
        ) -> BoxFuture<'a, Result<(), SubsystemError>> {
            Box::pin(async move { self.note("initialize").await })
        }

        fn start<'a>(
            &'a self,
            _context: &'a StartContext,
        ) -> BoxFuture<'a, Result<ServiceHandle, SubsystemError>> {
            Box::pin(async move {
                self.note("start").await?;
                Ok(ServiceHandle::inert(self.id.clone()))
            })
        }

        fn quiesce<'a>(&'a self) -> BoxFuture<'a, Result<(), SubsystemError>> {
            Box::pin(async move { self.note("quiesce").await })
        }

        fn drain<'a>(&'a self) -> BoxFuture<'a, Result<DrainReport, SubsystemError>> {
            Box::pin(async move {
                self.note("drain").await?;
                Ok(DrainReport::clean(self.id.clone(), self.completed))
            })
        }

        fn shutdown<'a>(&'a self) -> BoxFuture<'a, Result<(), SubsystemError>> {
            Box::pin(async move { self.note("shutdown").await })
        }
    }

    /// Polls `future` once with a waker that does nothing, leaving it parked at
    /// its first unresolved await so the caller can drop it there.
    fn poll_once<F: std::future::Future>(
        future: &mut std::pin::Pin<Box<F>>,
    ) -> std::task::Poll<F::Output> {
        let mut context = std::task::Context::from_waker(std::task::Waker::noop());
        future.as_mut().poll(&mut context)
    }

    fn context() -> StartContext {
        StartContext::new(
            SubsystemId::new("host").expect("valid"),
            Arc::new(RuntimeSettings::new(
                Vec::new(),
                ProviderName::new("p").expect("valid"),
                ModelName::new("m").expect("valid"),
                1,
                std::time::Duration::from_secs(1),
                std::time::Duration::from_secs(1),
            )),
            Arc::new(NoSpawner),
            Arc::new(NeverShuttingDown(AtomicBool::new(false))),
            Arc::new(ProcessClock),
        )
    }

    fn journal() -> Journal {
        Arc::new(Mutex::new(Vec::new()))
    }

    fn entries(journal: &Journal) -> Vec<String> {
        journal.lock().expect("uncontended").clone()
    }

    #[tokio::test]
    async fn a_full_run_touches_every_subsystem_in_the_documented_order() {
        let log = journal();
        let mut host = SubsystemHost::new(vec![
            Arc::new(Recorder::new(&log, "store", &[])),
            Arc::new(Recorder::new(&log, "engine", &["store"]).completing(2)),
            Arc::new(Recorder::new(&log, "gateway", &["engine"]).ingress()),
        ])
        .expect("the composition is orderable");

        assert_eq!(host.phase(), LifecyclePhase::Created);

        let handles = host.start(&context()).await.expect("startup succeeds");

        assert_eq!(host.phase(), LifecyclePhase::Running);
        assert_eq!(
            handles
                .iter()
                .map(|handle| handle.subsystem().as_str().to_owned())
                .collect::<Vec<_>>(),
            vec!["store", "engine", "gateway"]
        );

        let report = host.shutdown().await.expect("shutdown succeeds");

        assert_eq!(host.phase(), LifecyclePhase::Stopped);
        assert!(report.is_clean());
        assert_eq!(report.completed(), 2);
        assert_eq!(report.abandoned(), 0);
        assert_eq!(
            entries(&log),
            vec![
                "store/initialize",
                "engine/initialize",
                "gateway/initialize",
                "store/start",
                "engine/start",
                "gateway/start",
                "gateway/quiesce",
                "gateway/drain",
                "engine/drain",
                "store/drain",
                "gateway/shutdown",
                "engine/shutdown",
                "store/shutdown",
            ]
        );
    }

    /// Every ingress must stop accepting before *any* subsystem is drained.
    ///
    /// A composition with a single ingress cannot tell this apart from the much
    /// weaker "each ingress quiesces immediately before it is drained", because
    /// both produce the same journal. Two ingress subsystems separate them: the
    /// weaker ordering would interleave `gateway/quiesce` after `http-api/drain`.
    ///
    /// The distinction is not academic. An ingress that is still accepting while
    /// another is being drained lets the in-flight set grow during the drain, so
    /// a `DrainReport` counts a moving target.
    #[tokio::test]
    async fn every_ingress_is_quiesced_before_any_subsystem_is_drained() {
        let log = journal();
        let mut host = SubsystemHost::new(vec![
            Arc::new(Recorder::new(&log, "store", &[])),
            Arc::new(Recorder::new(&log, "gateway", &["store"]).ingress()),
            Arc::new(Recorder::new(&log, "http-api", &["store"]).ingress()),
        ])
        .expect("the composition is orderable");

        host.start(&context()).await.expect("startup succeeds");
        let report = host.shutdown().await.expect("shutdown succeeds");

        assert!(report.is_clean());

        let recorded = entries(&log);

        assert_eq!(
            recorded,
            vec![
                "store/initialize",
                "gateway/initialize",
                "http-api/initialize",
                "store/start",
                "gateway/start",
                "http-api/start",
                "http-api/quiesce",
                "gateway/quiesce",
                "http-api/drain",
                "gateway/drain",
                "store/drain",
                "http-api/shutdown",
                "gateway/shutdown",
                "store/shutdown",
            ]
        );

        // Stated as the invariant as well as the literal, so a future change that
        // reorders subsystems within a phase cannot silently weaken the property
        // this test exists to hold.
        let last_quiesce = recorded
            .iter()
            .rposition(|entry| entry.ends_with("/quiesce"))
            .expect("an ingress composition quiesces");
        let first_drain = recorded
            .iter()
            .position(|entry| entry.ends_with("/drain"))
            .expect("a shutdown drains");

        assert!(
            last_quiesce < first_drain,
            "{} was drained before {} stopped accepting: {recorded:?}",
            recorded[first_drain],
            recorded[last_quiesce]
        );
    }

    #[tokio::test]
    async fn a_failure_during_initialization_stops_everything_already_initialized() {
        let log = journal();
        let mut host = SubsystemHost::new(vec![
            Arc::new(Recorder::new(&log, "store", &[])),
            Arc::new(Recorder::new(&log, "engine", &["store"]).failing_at("initialize")),
            Arc::new(Recorder::new(&log, "gateway", &["engine"]).ingress()),
        ])
        .expect("the composition is orderable");

        let error = host
            .start(&context())
            .await
            .expect_err("initialization failed");

        match error {
            CompositionError::SubsystemFailed(failure) => {
                assert_eq!(failure.subsystem().as_str(), "engine");
                assert_eq!(failure.kind(), SubsystemErrorKind::Unavailable);
                assert_eq!(failure.detail(), "initialize was told to fail");
            }
            other => panic!("expected a subsystem failure, got {other}"),
        }

        assert_eq!(host.phase(), LifecyclePhase::Stopped);
        assert_eq!(
            entries(&log),
            vec![
                "store/initialize",
                "engine/initialize",
                "engine/shutdown",
                "store/shutdown",
            ],
            "gateway was never touched and nothing was drained because nothing started"
        );
    }

    #[tokio::test]
    async fn a_failure_during_start_drains_and_stops_what_was_already_serving() {
        let log = journal();
        let mut host = SubsystemHost::new(vec![
            Arc::new(Recorder::new(&log, "store", &[]).completing(1)),
            Arc::new(Recorder::new(&log, "engine", &["store"]).failing_at("start")),
            Arc::new(Recorder::new(&log, "gateway", &["engine"]).ingress()),
        ])
        .expect("the composition is orderable");

        let error = host.start(&context()).await.expect_err("start failed");

        assert!(matches!(error, CompositionError::SubsystemFailed(_)));
        assert_eq!(host.phase(), LifecyclePhase::Stopped);
        assert_eq!(
            entries(&log),
            vec![
                "store/initialize",
                "engine/initialize",
                "gateway/initialize",
                "store/start",
                "engine/start",
                "engine/drain",
                "store/drain",
                "gateway/shutdown",
                "engine/shutdown",
                "store/shutdown",
            ],
            "gateway never started so it is not drained, but everything initialized is stopped"
        );
    }

    #[tokio::test]
    async fn a_subsystem_that_refuses_to_stop_does_not_block_the_ones_behind_it() {
        let log = journal();
        let mut host = SubsystemHost::new(vec![
            Arc::new(Recorder::new(&log, "store", &[])),
            Arc::new(Recorder::new(&log, "engine", &["store"]).failing_at("shutdown")),
            Arc::new(Recorder::new(&log, "gateway", &["engine"]).ingress()),
        ])
        .expect("the composition is orderable");

        host.start(&context()).await.expect("startup succeeds");
        let report = host.shutdown().await.expect("shutdown still completes");

        assert!(!report.is_clean());
        assert_eq!(report.errors().len(), 1);
        assert_eq!(report.errors()[0].subsystem().as_str(), "engine");
        assert_eq!(host.phase(), LifecyclePhase::Stopped);
        assert!(
            entries(&log).contains(&"store/shutdown".to_owned()),
            "the subsystem behind the failure was still stopped"
        );
    }

    #[tokio::test]
    async fn capabilities_are_dead_before_the_first_subsystem_is_asked_to_quiesce() {
        let log = journal();
        let mut host = SubsystemHost::new(vec![Arc::new(
            Recorder::new(&log, "gateway", &[]).ingress(),
        )])
        .expect("the composition is orderable");
        let gate = host.epoch_gate();

        assert_eq!(gate.current(), None, "nothing is authorized before startup");
        host.start(&context()).await.expect("startup succeeds");

        let running_epoch = gate.current().expect("the gate opens when running");

        host.shutdown().await.expect("shutdown succeeds");

        assert_eq!(
            gate.current(),
            None,
            "the gate is shut once the daemon has stopped"
        );
        assert_eq!(running_epoch.get(), 1);
    }

    #[tokio::test]
    async fn shutting_down_a_composition_that_never_ran_is_refused_by_the_state_machine() {
        let log = journal();
        let mut host = SubsystemHost::new(vec![Arc::new(Recorder::new(&log, "store", &[]))])
            .expect("the composition is orderable");

        let error = host.shutdown().await.expect_err("created cannot drain");

        match error {
            CompositionError::Phase(transition) => {
                assert_eq!(transition.from(), LifecyclePhase::Created);
                assert_eq!(transition.to(), LifecyclePhase::Draining);
            }
            other => panic!("expected an illegal phase change, got {other}"),
        }

        assert!(entries(&log).is_empty());
    }

    /// The composition layer commits `initialized` and the phase, then awaits.
    /// If the caller is cancelled there, `abort` never runs, so the only thing
    /// that can still release those resources is a later `shutdown`. Every test
    /// above drives the future to completion, which is exactly why this needed
    /// its own test.
    #[tokio::test]
    async fn a_start_dropped_while_initializing_is_finished_by_a_later_shutdown() {
        let log = journal();
        let mut host = SubsystemHost::new(vec![
            Arc::new(Recorder::new(&log, "store", &[])),
            Arc::new(Recorder::new(&log, "engine", &["store"]).parking_at("initialize")),
            Arc::new(Recorder::new(&log, "gateway", &["engine"]).ingress()),
        ])
        .expect("the composition is orderable");

        let started = context();
        let mut starting = Box::pin(host.start(&started));
        assert!(
            poll_once(&mut starting).is_pending(),
            "engine parks inside initialize"
        );
        assert_eq!(
            entries(&log),
            vec!["store/initialize", "engine/initialize"],
            "store finished initializing and engine reached its await"
        );

        drop(starting);
        assert_eq!(host.phase(), LifecyclePhase::Initializing);

        let report = host
            .shutdown()
            .await
            .expect("an interrupted startup can still be stopped");

        assert_eq!(host.phase(), LifecyclePhase::Stopped);
        assert!(report.is_clean());
        assert_eq!(
            entries(&log),
            vec![
                "store/initialize",
                "engine/initialize",
                "engine/shutdown",
                "store/shutdown",
            ],
            "both subsystems that were touched are stopped, in reverse order, and \
             gateway is never touched because initialize never reached it"
        );
        assert!(
            report.drains().is_empty(),
            "nothing had started, so nothing is drained"
        );
    }

    #[tokio::test]
    async fn a_start_dropped_while_starting_is_finished_by_a_later_shutdown() {
        let log = journal();
        let mut host = SubsystemHost::new(vec![
            Arc::new(Recorder::new(&log, "store", &[])),
            Arc::new(Recorder::new(&log, "engine", &["store"]).parking_at("start")),
            Arc::new(Recorder::new(&log, "gateway", &["engine"]).ingress()),
        ])
        .expect("the composition is orderable");

        let started = context();
        let mut starting = Box::pin(host.start(&started));
        assert!(
            poll_once(&mut starting).is_pending(),
            "engine parks inside start"
        );

        drop(starting);
        assert_eq!(host.phase(), LifecyclePhase::Starting);

        let report = host
            .shutdown()
            .await
            .expect("an interrupted startup can still be stopped");

        assert_eq!(host.phase(), LifecyclePhase::Stopped);
        assert_eq!(
            entries(&log),
            vec![
                "store/initialize",
                "engine/initialize",
                "gateway/initialize",
                "store/start",
                "engine/start",
                "engine/drain",
                "store/drain",
                "gateway/shutdown",
                "engine/shutdown",
                "store/shutdown",
            ],
            "store and engine were recorded as started so they are drained; gateway \
             initialized but never started, so it is only shut down"
        );
        assert_eq!(
            report
                .drains()
                .iter()
                .map(|drain| drain.subsystem().as_str().to_owned())
                .collect::<Vec<_>>(),
            vec!["engine", "store"]
        );
    }

    /// `shutdown` has the same shape as `start`: it commits a phase change and
    /// then awaits. A teardown dropped mid-drain must be resumable, and resuming
    /// must not call `shutdown` on a subsystem that already received it, because
    /// the trait documents it as the last call a subsystem ever gets.
    #[tokio::test]
    async fn a_shutdown_dropped_mid_drain_is_resumed_without_stopping_anything_twice() {
        let log = journal();
        let mut host = SubsystemHost::new(vec![
            Arc::new(Recorder::new(&log, "store", &[])),
            Arc::new(Recorder::new(&log, "engine", &["store"]).parking_at("drain")),
            Arc::new(Recorder::new(&log, "gateway", &["engine"]).ingress()),
        ])
        .expect("the composition is orderable");

        host.start(&context()).await.expect("startup succeeds");
        log.lock().expect("uncontended").clear();

        let mut stopping = Box::pin(host.shutdown());
        assert!(
            poll_once(&mut stopping).is_pending(),
            "engine parks inside drain"
        );
        assert_eq!(
            entries(&log),
            vec!["gateway/quiesce", "gateway/drain", "engine/drain"],
            "gateway is the only ingress so it is the only one quiesced; the drain \
             reached engine and stopped there"
        );

        drop(stopping);
        assert_eq!(host.phase(), LifecyclePhase::Draining);

        // Polled rather than awaited, because the failure mode of striking a
        // subsystem off *after* its await instead of before is that the resumed
        // teardown re-enters engine's parked drain and never returns. Nothing in
        // this composition yields once engine is struck off, so a correct
        // teardown completes in a single poll and a regression is a clean
        // `Pending` rather than a hung suite.
        let mut resuming = Box::pin(host.shutdown());
        let resolved = poll_once(&mut resuming);
        drop(resuming);

        let report = match resolved {
            std::task::Poll::Ready(outcome) => {
                outcome.expect("an interrupted teardown can be finished")
            }
            std::task::Poll::Pending => {
                panic!("the resumed teardown re-entered a subsystem it had already drained")
            }
        };

        assert_eq!(host.phase(), LifecyclePhase::Stopped);
        assert_eq!(
            entries(&log),
            vec![
                "gateway/quiesce",
                "gateway/drain",
                "engine/drain",
                "store/drain",
                "gateway/shutdown",
                "engine/shutdown",
                "store/shutdown",
            ],
            "engine is not drained again because it was struck off before its await, \
             and every subsystem is shut down exactly once"
        );

        let shutdowns = entries(&log)
            .into_iter()
            .filter(|entry| entry.ends_with("/shutdown"))
            .count();
        assert_eq!(shutdowns, 3, "one shutdown per subsystem, no more");
        assert!(report.is_clean());
    }

    /// The interrupted composition must not be restartable, because its
    /// subsystems still hold the resources the abandoned startup gave them.
    ///
    /// `Subsystem::shutdown` is documented as the last call a subsystem
    /// receives. A teardown dropped *inside* one subsystem's `shutdown` must
    /// therefore not call it again when it resumes, which is why the position is
    /// struck off `initialized` before the await rather than after it.
    #[tokio::test]
    async fn a_teardown_dropped_inside_a_shutdown_does_not_call_that_shutdown_again() {
        let log = journal();
        let mut host = SubsystemHost::new(vec![
            Arc::new(Recorder::new(&log, "store", &[])),
            Arc::new(Recorder::new(&log, "engine", &["store"]).parking_at("shutdown")),
            Arc::new(Recorder::new(&log, "gateway", &["engine"]).ingress()),
        ])
        .expect("the composition is orderable");

        host.start(&context()).await.expect("startup succeeds");
        log.lock().expect("uncontended").clear();

        let mut stopping = Box::pin(host.shutdown());
        assert!(
            poll_once(&mut stopping).is_pending(),
            "engine parks inside shutdown"
        );
        assert_eq!(
            entries(&log),
            vec![
                "gateway/quiesce",
                "gateway/drain",
                "engine/drain",
                "store/drain",
                "gateway/shutdown",
                "engine/shutdown",
            ],
            "teardown reached engine's shutdown and stopped there"
        );

        drop(stopping);

        let mut resuming = Box::pin(host.shutdown());
        let resolved = poll_once(&mut resuming);
        drop(resuming);

        let report = match resolved {
            std::task::Poll::Ready(outcome) => {
                outcome.expect("an interrupted teardown can be finished")
            }
            std::task::Poll::Pending => {
                panic!("the resumed teardown called shutdown on engine a second time")
            }
        };

        assert_eq!(host.phase(), LifecyclePhase::Stopped);
        assert_eq!(
            entries(&log),
            vec![
                "gateway/quiesce",
                "gateway/drain",
                "engine/drain",
                "store/drain",
                "gateway/shutdown",
                "engine/shutdown",
                "store/shutdown",
            ],
            "store is the only subsystem left to stop, and engine is never revisited"
        );
        assert!(report.is_clean());
    }

    /// The interrupted composition must not be restartable, because its
    /// subsystems still hold the resources the abandoned startup gave them.
    #[tokio::test]
    async fn an_interrupted_startup_cannot_be_started_again_before_it_is_stopped() {
        let log = journal();
        let mut host = SubsystemHost::new(vec![
            Arc::new(Recorder::new(&log, "store", &[])),
            Arc::new(Recorder::new(&log, "engine", &["store"]).parking_at("initialize")),
        ])
        .expect("the composition is orderable");

        let started = context();
        let mut starting = Box::pin(host.start(&started));
        assert!(poll_once(&mut starting).is_pending());
        drop(starting);

        let error = host
            .start(&context())
            .await
            .expect_err("a half-started composition cannot be started again");

        match error {
            CompositionError::Phase(transition) => {
                assert_eq!(transition.from(), LifecyclePhase::Initializing);
                assert_eq!(transition.to(), LifecyclePhase::Initializing);
            }
            other => panic!("expected an illegal phase change, got {other}"),
        }

        assert_eq!(
            entries(&log),
            vec!["store/initialize", "engine/initialize"],
            "the refused restart touched nothing"
        );
    }

    /// Once the interrupted teardown has been finished, the flag must be spent:
    /// a further `shutdown` has to go back to being refused by the state
    /// machine rather than silently succeeding forever.
    #[tokio::test]
    async fn the_interrupted_flag_is_spent_by_the_shutdown_that_acts_on_it() {
        let log = journal();
        let mut host = SubsystemHost::new(vec![
            Arc::new(Recorder::new(&log, "store", &[])),
            Arc::new(Recorder::new(&log, "engine", &["store"]).parking_at("initialize")),
        ])
        .expect("the composition is orderable");

        let started = context();
        let mut starting = Box::pin(host.start(&started));
        assert!(poll_once(&mut starting).is_pending());
        drop(starting);

        host.shutdown()
            .await
            .expect("the interrupted startup stops");
        assert_eq!(host.phase(), LifecyclePhase::Stopped);

        let error = host
            .shutdown()
            .await
            .expect_err("a stopped composition cannot be stopped again");

        match error {
            CompositionError::Phase(transition) => {
                assert_eq!(transition.from(), LifecyclePhase::Stopped);
                assert_eq!(transition.to(), LifecyclePhase::Draining);
            }
            other => panic!("expected an illegal phase change, got {other}"),
        }
    }

    #[test]
    fn a_cycle_is_reported_before_any_subsystem_is_touched() {
        let log = journal();
        let error = SubsystemHost::new(vec![
            Arc::new(Recorder::new(&log, "a", &["b"])),
            Arc::new(Recorder::new(&log, "b", &["a"])),
        ])
        .expect_err("the composition is not orderable");

        assert!(matches!(error, CompositionError::DependencyCycle(_)));
        assert!(entries(&log).is_empty());
    }

    #[test]
    fn an_empty_report_is_clean_and_counts_nothing() {
        let report = ShutdownReport::default();

        assert!(report.is_clean());
        assert_eq!(report.completed(), 0);
        assert_eq!(report.abandoned(), 0);
        assert!(report.drains().is_empty());
        assert!(report.errors().is_empty());
    }
}

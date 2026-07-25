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

use std::sync::Arc;

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

/// Holds the subsystems of one daemon and moves them through the lifecycle
/// together.
pub struct SubsystemHost {
    subsystems: Vec<Arc<dyn Subsystem>>,
    plan: CompositionPlan,
    lifecycle: Lifecycle,
    initialized: Vec<usize>,
    started: Vec<usize>,
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
    /// # Errors
    ///
    /// Returns [`CompositionError::SubsystemFailed`] carrying the first failure.
    /// Everything already brought up has been torn down by the time this
    /// returns.
    pub async fn start(
        &mut self,
        context: &StartContext,
    ) -> Result<Vec<ServiceHandle>, CompositionError> {
        let start_order = self.order(self.plan.start_order());

        self.lifecycle.transition_to(LifecyclePhase::Initializing)?;

        for position in &start_order {
            let subsystem = Arc::clone(&self.subsystems[*position]);
            let scoped = context.for_subsystem(subsystem.descriptor().id().clone());

            // Recorded before the call, not after: a subsystem that fails part
            // way through `initialize` may already hold resources, and the trait
            // contract requires `shutdown` to be called for it.
            self.initialized.push(*position);

            if let Err(error) = subsystem.initialize(&scoped).await {
                self.abort().await;
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
                    return Err(CompositionError::SubsystemFailed(error));
                }
            }
        }

        self.lifecycle.transition_to(LifecyclePhase::Running)?;

        Ok(handles)
    }

    /// Tears down everything brought up so far, after a startup failure.
    async fn abort(&mut self) {
        self.lifecycle
            .transition_to(LifecyclePhase::Failed)
            .expect("every non-terminal phase may fail");

        let mut report = ShutdownReport::default();
        self.quiesce_and_drain(&mut report).await;
        self.stop_all(&mut report).await;

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
    /// # Errors
    ///
    /// Returns the [`CompositionError`] produced by an illegal phase change,
    /// which can only happen if the host was not running.
    pub async fn shutdown(&mut self) -> Result<ShutdownReport, CompositionError> {
        self.lifecycle.transition_to(LifecyclePhase::Draining)?;

        let mut report = ShutdownReport::default();
        self.quiesce_and_drain(&mut report).await;

        self.lifecycle.transition_to(LifecyclePhase::Stopping)?;
        self.stop_all(&mut report).await;
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

        const fn completing(mut self, completed: u32) -> Self {
            self.completed = completed;
            self
        }

        fn note(&self, step: &str) -> Result<(), SubsystemError> {
            self.journal
                .lock()
                .expect("uncontended")
                .push(format!("{}/{step}", self.id));

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
            Box::pin(async move { self.note("initialize") })
        }

        fn start<'a>(
            &'a self,
            _context: &'a StartContext,
        ) -> BoxFuture<'a, Result<ServiceHandle, SubsystemError>> {
            Box::pin(async move {
                self.note("start")?;
                Ok(ServiceHandle::inert(self.id.clone()))
            })
        }

        fn quiesce<'a>(&'a self) -> BoxFuture<'a, Result<(), SubsystemError>> {
            Box::pin(async move { self.note("quiesce") })
        }

        fn drain<'a>(&'a self) -> BoxFuture<'a, Result<DrainReport, SubsystemError>> {
            Box::pin(async move {
                self.note("drain")?;
                Ok(DrainReport::clean(self.id.clone(), self.completed))
            })
        }

        fn shutdown<'a>(&'a self) -> BoxFuture<'a, Result<(), SubsystemError>> {
            Box::pin(async move { self.note("shutdown") })
        }
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

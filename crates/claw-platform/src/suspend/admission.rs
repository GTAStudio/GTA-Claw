//! The process-wide admission fence that makes suspension refuse-only.
//!
//! Upstream keeps this state in a global singleton
//! (`src/process/gateway-work-admission.ts`) and detects nesting with an
//! `AsyncLocalStorage`. Rust has no ambient async context, so this port is an
//! explicit object: a host owns one [`WorkAdmission`] and takes a
//! [`RootWorkLease`] per root request or timer tick. Nesting is expressed by
//! passing the parent lease around rather than by inspecting ambient state.
//!
//! The fence has exactly three phases. `Accepting` admits new root work.
//! `Preparing` is held while a suspension inspects the host and can still be
//! rolled back. `Prepared` is held while a suspension lease exists. Both closed
//! phases *refuse* new work; nothing is queued and nothing is cancelled, which
//! is what makes the suspension cooperative and reversible.

use std::collections::BTreeSet;
use std::fmt::{self, Display, Formatter};
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};

/// Milliseconds a refused caller is asked to wait before retrying.
pub const ROOT_WORK_RETRY_AFTER_MS: u64 = 1_000;

/// The gateway methods that stay callable while the fence is closed.
///
/// Refusing these would strand the controller that prepared the suspension: it
/// could never poll status and never resume.
pub const SUSPEND_CONTROL_METHODS: [&str; 3] = [
    "gateway.suspend.prepare",
    "gateway.suspend.status",
    "gateway.suspend.resume",
];

/// Returns whether `method` may still be dispatched while the fence is closed.
#[must_use]
pub fn is_method_allowed_during_suspension(method: &str) -> bool {
    SUSPEND_CONTROL_METHODS.contains(&method)
}

fn count_of(len: usize) -> u64 {
    u64::try_from(len).unwrap_or(u64::MAX)
}

/// The phase of the process-wide suspension fence.
#[derive(Clone, Copy, Debug, Default, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum AdmissionPhase {
    /// New root work is admitted.
    #[default]
    Accepting,
    /// A suspension is inspecting the host and can still roll back.
    Preparing,
    /// A suspension lease is held.
    Prepared,
}

impl AdmissionPhase {
    /// Returns the wire literal reported in refusal diagnostics.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Accepting => "accepting",
            Self::Preparing => "preparing",
            Self::Prepared => "prepared",
        }
    }

    /// Returns whether the phase refuses new root work.
    #[must_use]
    pub const fn is_closed(self) -> bool {
        !matches!(self, Self::Accepting)
    }
}

impl Display for AdmissionPhase {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

/// Why the fence refused new root work.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum RefusalReason {
    /// A cooperative suspension is preparing or prepared.
    GatewaySuspending,
    /// The host is draining for restart and will not accept work again.
    GatewayRestarting,
}

impl RefusalReason {
    /// Returns the wire literal reported in refusal diagnostics.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::GatewaySuspending => "gateway-suspending",
            Self::GatewayRestarting => "gateway-restarting",
        }
    }

    /// Returns whether the refusal will be lifted without a restart.
    #[must_use]
    pub const fn is_reversible(self) -> bool {
        matches!(self, Self::GatewaySuspending)
    }
}

impl Display for RefusalReason {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

/// A refusal of new root work, carrying everything a caller needs to retry.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct AdmissionRefusal {
    reason: RefusalReason,
    phase: AdmissionPhase,
    retry_after_ms: u64,
}

impl AdmissionRefusal {
    /// Returns why the work was refused.
    #[must_use]
    pub const fn reason(&self) -> RefusalReason {
        self.reason
    }

    /// Returns the fence phase observed at refusal time.
    #[must_use]
    pub const fn phase(&self) -> AdmissionPhase {
        self.phase
    }

    /// Returns how long the caller should wait before retrying.
    #[must_use]
    pub const fn retry_after_ms(&self) -> u64 {
        self.retry_after_ms
    }
}

impl Display for AdmissionRefusal {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "root work refused: reason={} phase={} retryAfterMs={}",
            self.reason, self.phase, self.retry_after_ms
        )
    }
}

#[derive(Debug)]
struct AdmissionState {
    phase: AdmissionPhase,
    restart_draining: bool,
    suspend_generation: u64,
    next_root_id: u64,
    active_root_work: BTreeSet<u64>,
}

impl AdmissionState {
    const fn refusal(&self) -> Option<AdmissionRefusal> {
        if self.restart_draining {
            return Some(AdmissionRefusal {
                reason: RefusalReason::GatewayRestarting,
                phase: self.phase,
                retry_after_ms: ROOT_WORK_RETRY_AFTER_MS,
            });
        }
        if self.phase.is_closed() {
            return Some(AdmissionRefusal {
                reason: RefusalReason::GatewaySuspending,
                phase: self.phase,
                retry_after_ms: ROOT_WORK_RETRY_AFTER_MS,
            });
        }
        None
    }
}

/// The host's admission fence.
///
/// Wrap one in an [`Arc`] per process and share it between the request
/// dispatcher and the suspension coordinator.
#[derive(Debug)]
pub struct WorkAdmission {
    state: Mutex<AdmissionState>,
}

impl Default for WorkAdmission {
    fn default() -> Self {
        Self::new()
    }
}

impl WorkAdmission {
    /// Creates an open fence with no active root work.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            state: Mutex::new(AdmissionState {
                phase: AdmissionPhase::Accepting,
                restart_draining: false,
                suspend_generation: 0,
                next_root_id: 1,
                active_root_work: BTreeSet::new(),
            }),
        }
    }

    fn state(&self) -> MutexGuard<'_, AdmissionState> {
        self.state.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// Returns the current fence phase.
    #[must_use]
    pub fn phase(&self) -> AdmissionPhase {
        self.state().phase
    }

    /// Returns whether the host is draining for restart.
    #[must_use]
    pub fn is_restart_draining(&self) -> bool {
        self.state().restart_draining
    }

    /// Returns whether new root work is currently refused.
    #[must_use]
    pub fn is_closed(&self) -> bool {
        self.state().refusal().is_some()
    }

    /// Returns the refusal a new root request would receive, if any.
    #[must_use]
    pub fn refusal(&self) -> Option<AdmissionRefusal> {
        self.state().refusal()
    }

    /// Returns the number of admitted root leases still outstanding.
    #[must_use]
    pub fn active_root_work(&self) -> u64 {
        count_of(self.state().active_root_work.len())
    }

    /// Returns the outstanding root leases other than `lease`.
    ///
    /// The request that runs `gateway.suspend.prepare` holds a lease of its
    /// own, and counting it would make every preparation look busy.
    #[must_use]
    pub fn active_root_work_excluding(&self, lease: &RootWorkLease) -> u64 {
        let state = self.state();
        let total = count_of(state.active_root_work.len());
        if state.active_root_work.contains(&lease.id) {
            total.saturating_sub(1)
        } else {
            total
        }
    }

    /// Closes the fence one way for an in-process restart.
    ///
    /// A restart supersedes a reversible suspension: any live suspend lease is
    /// invalidated so its owner stops believing it fenced the host, and the
    /// scheduler is deliberately *not* resumed on the way out.
    pub fn mark_restart_draining(&self) {
        let mut state = self.state();
        state.restart_draining = true;
        if state.phase.is_closed() {
            state.phase = AdmissionPhase::Accepting;
            state.suspend_generation += 1;
        }
    }

    /// Admits one root request or timer tick, or refuses it.
    ///
    /// # Errors
    ///
    /// Returns an [`AdmissionRefusal`] carrying
    /// [`RefusalReason::GatewayRestarting`] when the host has been marked
    /// draining for restart, and [`RefusalReason::GatewaySuspending`] when a
    /// cooperative suspension holds the fence in `Preparing` or `Prepared`.
    /// Nothing is queued in either case: the caller is expected to answer its
    /// own peer with a retryable error carrying the refusal's
    /// [`retry_after_ms`](AdmissionRefusal::retry_after_ms).
    pub fn try_begin_root_work(self: &Arc<Self>) -> Result<RootWorkLease, AdmissionRefusal> {
        let mut state = self.state();
        if let Some(refusal) = state.refusal() {
            return Err(refusal);
        }
        let id = state.next_root_id;
        state.next_root_id += 1;
        state.active_root_work.insert(id);
        drop(state);
        Ok(RootWorkLease {
            admission: Arc::clone(self),
            id,
        })
    }

    /// Atomically closes admission before a suspension inspects the host.
    ///
    /// Returns `None` when the host is already draining or another suspension
    /// owns the fence, which is the `gateway-draining` busy answer upstream.
    pub fn try_begin_suspend(self: &Arc<Self>) -> Option<SuspendLease> {
        let mut state = self.state();
        if state.restart_draining || state.phase.is_closed() {
            return None;
        }
        state.phase = AdmissionPhase::Preparing;
        state.suspend_generation += 1;
        let generation = state.suspend_generation;
        drop(state);
        Some(SuspendLease {
            admission: Arc::clone(self),
            generation,
        })
    }

    fn release_root_work(&self, id: u64) {
        self.state().active_root_work.remove(&id);
    }

    fn transition(&self, generation: u64, expected: AdmissionPhase, next: AdmissionPhase) -> bool {
        let mut state = self.state();
        if state.suspend_generation != generation || state.phase != expected {
            return false;
        }
        state.phase = next;
        true
    }

    fn is_generation_active(&self, generation: u64) -> bool {
        let state = self.state();
        state.suspend_generation == generation && state.phase.is_closed()
    }
}

/// An admitted root request or timer tick.
///
/// Dropping the lease releases it, so a panicking handler cannot leave the
/// host looking permanently busy.
#[derive(Debug)]
pub struct RootWorkLease {
    admission: Arc<WorkAdmission>,
    id: u64,
}

impl RootWorkLease {
    /// Returns the process-unique identity of this lease.
    #[must_use]
    pub const fn id(&self) -> u64 {
        self.id
    }

    /// Releases the lease. Equivalent to dropping it.
    pub fn release(self) {}
}

impl Drop for RootWorkLease {
    fn drop(&mut self) {
        self.admission.release_root_work(self.id);
    }
}

/// Ownership of the closed fence for the lifetime of one suspension.
///
/// Every transition is fenced by a generation counter, so a lease that has
/// been superseded — by a restart drain, or by a later suspension — can never
/// reopen admission that now belongs to someone else.
#[derive(Debug)]
pub struct SuspendLease {
    admission: Arc<WorkAdmission>,
    generation: u64,
}

impl SuspendLease {
    /// Promotes an inspected host from `Preparing` to `Prepared`.
    ///
    /// Returns `false` when the lease was superseded during preparation.
    #[must_use = "a false commit means the fence now belongs to someone else"]
    pub fn commit(&self) -> bool {
        self.admission.transition(
            self.generation,
            AdmissionPhase::Preparing,
            AdmissionPhase::Prepared,
        )
    }

    /// Reopens admission from `Preparing` after a refused preparation.
    ///
    /// Returns `false` when the lease was superseded, in which case the fence
    /// is already owned by a restart drain or a later suspension and must not
    /// be reopened on this lease's behalf.
    #[must_use = "a false rollback means the fence now belongs to someone else"]
    pub fn rollback(&self) -> bool {
        self.admission.transition(
            self.generation,
            AdmissionPhase::Preparing,
            AdmissionPhase::Accepting,
        )
    }

    /// Reopens admission from `Prepared` after a resume or an expiry.
    ///
    /// Returns `false` when the lease was superseded, in which case the fence
    /// is already owned by a restart drain or a later suspension and must not
    /// be reopened on this lease's behalf.
    #[must_use = "a false release means the fence now belongs to someone else"]
    pub fn release(&self) -> bool {
        self.admission.transition(
            self.generation,
            AdmissionPhase::Prepared,
            AdmissionPhase::Accepting,
        )
    }

    /// Returns whether this lease still owns the closed fence.
    ///
    /// The upstream coordinator is told about invalidation through a callback.
    /// Polling is equivalent at every observation point and cannot deadlock
    /// against the coordinator's own lock, so this port polls instead.
    #[must_use]
    pub fn is_active(&self) -> bool {
        self.admission.is_generation_active(self.generation)
    }
}

impl Drop for SuspendLease {
    fn drop(&mut self) {
        // A dropped lease has no owner left to resume the host, so the fence
        // must not stay closed on its behalf. Both transitions are generation
        // fenced, so a superseded lease still changes nothing.
        if !self.release() {
            let _ = self.rollback();
        }
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use super::{
        AdmissionPhase, RefusalReason, SUSPEND_CONTROL_METHODS, WorkAdmission,
        is_method_allowed_during_suspension,
    };

    #[test]
    fn an_open_fence_admits_root_work() {
        let admission = Arc::new(WorkAdmission::new());

        let lease = admission
            .try_begin_root_work()
            .expect("an open fence admits root work");

        assert_eq!(admission.phase(), AdmissionPhase::Accepting);
        assert_eq!(admission.active_root_work(), 1);
        assert_eq!(admission.active_root_work_excluding(&lease), 0);
        assert!(!admission.is_closed());

        lease.release();

        assert_eq!(admission.active_root_work(), 0);
    }

    #[test]
    fn preparing_and_prepared_both_refuse_new_root_work() {
        let admission = Arc::new(WorkAdmission::new());
        let lease = admission
            .try_begin_suspend()
            .expect("an open fence yields a suspend lease");

        assert_eq!(admission.phase(), AdmissionPhase::Preparing);
        let refusal = admission
            .try_begin_root_work()
            .expect_err("preparing refuses root work");
        assert_eq!(refusal.reason(), RefusalReason::GatewaySuspending);
        assert_eq!(refusal.phase(), AdmissionPhase::Preparing);

        assert!(lease.commit());

        assert_eq!(admission.phase(), AdmissionPhase::Prepared);
        let refusal = admission
            .try_begin_root_work()
            .expect_err("prepared refuses root work");
        assert_eq!(refusal.phase(), AdmissionPhase::Prepared);

        assert!(lease.release());
        assert!(admission.try_begin_root_work().is_ok());
    }

    #[test]
    fn a_second_suspension_cannot_take_a_closed_fence() {
        let admission = Arc::new(WorkAdmission::new());
        let first = admission.try_begin_suspend().expect("first lease");

        assert!(admission.try_begin_suspend().is_none());

        assert!(first.rollback());

        assert!(admission.try_begin_suspend().is_some());
    }

    #[test]
    fn a_superseded_lease_can_never_reopen_admission() {
        let admission = Arc::new(WorkAdmission::new());
        let stale = admission.try_begin_suspend().expect("first lease");
        assert!(stale.commit());

        admission.mark_restart_draining();

        assert!(!stale.is_active());
        assert!(!stale.release());
        assert!(!stale.rollback());
        assert!(!stale.commit());
        let refusal = admission
            .try_begin_root_work()
            .expect_err("restart drain refuses root work");
        assert_eq!(refusal.reason(), RefusalReason::GatewayRestarting);
        assert!(!refusal.reason().is_reversible());
    }

    #[test]
    fn restart_draining_blocks_new_suspensions() {
        let admission = Arc::new(WorkAdmission::new());

        admission.mark_restart_draining();

        assert!(admission.try_begin_suspend().is_none());
        assert!(admission.is_restart_draining());
        assert!(admission.is_closed());
    }

    #[test]
    fn dropping_a_lease_reopens_the_fence_from_either_closed_phase() {
        let admission = Arc::new(WorkAdmission::new());

        drop(admission.try_begin_suspend().expect("preparing lease"));
        assert_eq!(admission.phase(), AdmissionPhase::Accepting);

        let lease = admission.try_begin_suspend().expect("second lease");
        assert!(lease.commit());
        drop(lease);

        assert_eq!(admission.phase(), AdmissionPhase::Accepting);
    }

    #[test]
    fn only_the_three_suspend_control_methods_survive_a_closed_fence() {
        for method in SUSPEND_CONTROL_METHODS {
            assert!(is_method_allowed_during_suspension(method));
        }

        assert!(!is_method_allowed_during_suspension("send"));
        assert!(!is_method_allowed_during_suspension(
            "gateway.restart.request"
        ));
        assert!(!is_method_allowed_during_suspension("gateway.suspend"));
    }

    #[test]
    fn phase_and_reason_render_the_upstream_wire_literals() {
        assert_eq!(AdmissionPhase::Accepting.as_str(), "accepting");
        assert_eq!(AdmissionPhase::Preparing.as_str(), "preparing");
        assert_eq!(AdmissionPhase::Prepared.as_str(), "prepared");
        assert_eq!(
            RefusalReason::GatewaySuspending.as_str(),
            "gateway-suspending"
        );
        assert_eq!(
            RefusalReason::GatewayRestarting.as_str(),
            "gateway-restarting"
        );
    }
}

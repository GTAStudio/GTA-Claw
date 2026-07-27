//! The cooperative suspension coordinator.
//!
//! Preparation is atomic and refuse-only. In order:
//!
//! 1. close the admission fence, so no *new* root work can start;
//! 2. pause the scheduler, so no timer can start work behind the fence;
//! 3. read the host's activity once;
//! 4. if anything is still running, resume the scheduler and reopen the fence,
//!    and answer `busy` with the blockers that were found;
//! 5. otherwise commit the fence and hand out a lease with a deadline.
//!
//! Rollback always resumes the scheduler *before* reopening admission. The
//! other order would let newly admitted work run against a paused scheduler.
//! When the scheduler refuses to resume, the coordinator stays fail-closed in
//! [`SuspendCoordinator::is_recovering`] rather than reopening a host it can no
//! longer drive.
//!
//! The lease is a deadline, not a promise: if the caller never resumes, the
//! host un-suspends itself when the lease expires. Expiry is evaluated against
//! the injected [`Clock`], which is why none of this needs a timer thread and
//! why its tests need no sleeps.

use std::fmt::{self, Debug, Display, Formatter};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};
use std::time::{SystemTime, UNIX_EPOCH};

use super::active_work::{ActiveWorkInspector, ActiveWorkSnapshot, Blocker};
use super::admission::{SuspendLease, WorkAdmission};
use super::clock::{Clock, SystemClock};

/// How long a prepared suspension survives without being resumed.
pub const SUSPEND_TTL_MS: u64 = 2 * 60_000;

/// How long a refused caller is asked to wait before preparing again.
pub const SUSPEND_RETRY_AFTER_MS: u64 = 20_000;

/// How long a caller is asked to wait while scheduler recovery is pending.
pub const SCHEDULER_RECOVERY_RETRY_MS: u64 = 1_000;

/// The scheduler refused to pause or resume.
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct SchedulerError {
    message: String,
}

impl SchedulerError {
    /// Describes a scheduler failure.
    #[must_use]
    pub fn new(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
        }
    }

    /// Returns the failure description.
    #[must_use]
    pub fn message(&self) -> &str {
        &self.message
    }
}

impl Display for SchedulerError {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        write!(formatter, "gateway scheduler error: {}", self.message)
    }
}

impl std::error::Error for SchedulerError {}

/// Stops and restarts the host's own timers for the duration of a suspension.
///
/// Closing the admission fence stops new *inbound* work; pausing the scheduler
/// stops the host starting work by itself. A suspension needs both.
pub trait Scheduler: Debug + Send + Sync {
    /// Stops scheduling new runs.
    ///
    /// # Errors
    ///
    /// Returns an error when scheduling could not be paused, which refuses the
    /// preparation without closing the host.
    fn pause(&self) -> Result<(), SchedulerError>;

    /// Resumes scheduling.
    ///
    /// # Errors
    ///
    /// Returns an error when scheduling could not be resumed, which holds the
    /// admission fence closed until a later retry succeeds.
    fn resume(&self) -> Result<(), SchedulerError>;
}

/// A scheduler for hosts that have no timers of their own.
#[derive(Clone, Copy, Debug, Default)]
pub struct NoopScheduler;

impl Scheduler for NoopScheduler {
    fn pause(&self) -> Result<(), SchedulerError> {
        Ok(())
    }

    fn resume(&self) -> Result<(), SchedulerError> {
        Ok(())
    }
}

/// Mints the opaque identifier a caller quotes back to status and resume.
pub trait SuspensionIds: Debug + Send + Sync {
    /// Returns an identifier that has never been used by this host before.
    fn next_id(&self) -> String;
}

/// The longest suspension token the upstream schema accepts.
pub const MAX_SUSPENSION_TOKEN_LEN: usize = 128;

/// Returns whether `token` is a valid `requestId` or `suspensionId`.
///
/// This is the upstream `SuspensionTokenSchema` rule — non-empty, at most
/// [`MAX_SUSPENSION_TOKEN_LEN`] UTF-16 code units, and containing at least one
/// non-whitespace character. A transport validates parameters with this before
/// dispatching to the coordinator, exactly as the upstream RPC handler does.
#[must_use]
pub fn is_valid_suspension_token(token: &str) -> bool {
    let length: usize = token.chars().map(char::len_utf16).sum();
    (1..=MAX_SUSPENSION_TOKEN_LEN).contains(&length)
        && token.chars().any(|character| !character.is_whitespace())
}

/// Process-unique suspension identifiers.
///
/// The identifier only has to be unguessable enough that a stale controller
/// cannot resume a suspension it does not own, and unique enough that a
/// restarted host never reuses one. A per-process seed plus a counter gives
/// both without taking a UUID dependency.
#[derive(Debug)]
pub struct ProcessSuspensionIds {
    seed: u64,
    counter: AtomicU64,
}

impl Default for ProcessSuspensionIds {
    fn default() -> Self {
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_or(0, |elapsed| {
                u64::try_from(elapsed.as_nanos()).unwrap_or(u64::MAX)
            });
        Self {
            seed: nanos ^ (u64::from(std::process::id()) << 32),
            counter: AtomicU64::new(0),
        }
    }
}

impl SuspensionIds for ProcessSuspensionIds {
    fn next_id(&self) -> String {
        let ordinal = self.counter.fetch_add(1, Ordering::SeqCst);
        format!("{:016x}-{ordinal:08x}", self.seed)
    }
}

/// Why a preparation was refused.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum BusyReason {
    /// The host still has work in flight.
    ActiveWork,
    /// The host is already draining, for a restart or another suspension.
    GatewayDraining,
}

impl BusyReason {
    /// Returns the upstream wire literal for this reason.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::ActiveWork => "active-work",
            Self::GatewayDraining => "gateway-draining",
        }
    }
}

impl Display for BusyReason {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

/// The answer to `gateway.suspend.prepare`.
#[derive(Clone, Debug, Eq, PartialEq)]
#[must_use]
pub enum PrepareOutcome {
    /// The host is idle and fenced until `expires_at_ms`.
    Ready {
        /// The identifier to quote to status and resume.
        suspension_id: String,
        /// The Unix millisecond deadline after which the lease self-releases.
        expires_at_ms: u64,
        /// The aggregate activity observed while fenced, which is zero.
        active_count: u64,
        /// The blockers observed while fenced, which is empty.
        blockers: Vec<Blocker>,
    },
    /// The host could not be fenced, and nothing was changed.
    Busy {
        /// Why the preparation was refused.
        reason: BusyReason,
        /// How long to wait before preparing again.
        retry_after_ms: u64,
        /// The aggregate activity that refused the preparation.
        active_count: u64,
        /// The individual blockers that refused the preparation.
        blockers: Vec<Blocker>,
    },
    /// A different request already owns a lease.
    ///
    /// Upstream reports this as a retryable `UNAVAILABLE` transport error
    /// rather than as a `gateway.suspend.prepare` result.
    Conflict {
        /// When the owning lease expires.
        expires_at_ms: u64,
    },
    /// The scheduler could not be driven, so the host stays fenced.
    ///
    /// Upstream reports this as a retryable `UNAVAILABLE` transport error.
    Recovering {
        /// How long to wait before trying again.
        retry_after_ms: u64,
    },
}

impl PrepareOutcome {
    /// Returns the status literal this outcome reports.
    #[must_use]
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::Ready { .. } => "ready",
            Self::Busy { .. } => "busy",
            Self::Conflict { .. } => "conflict",
            Self::Recovering { .. } => "recovering",
        }
    }

    /// Returns the lease identifier when the host was fenced.
    #[must_use]
    pub fn suspension_id(&self) -> Option<&str> {
        match self {
            Self::Ready { suspension_id, .. } => Some(suspension_id),
            _ => None,
        }
    }

    /// Returns the blockers reported by a `ready` or `busy` outcome.
    #[must_use]
    pub fn blockers(&self) -> &[Blocker] {
        match self {
            Self::Ready { blockers, .. } | Self::Busy { blockers, .. } => blockers,
            _ => &[],
        }
    }
}

/// The answer to `gateway.suspend.status`.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
#[must_use]
pub enum StatusOutcome {
    /// No suspension is prepared; the host is serving traffic.
    Running,
    /// The quoted suspension is prepared until `expires_at_ms`.
    Ready {
        /// When the lease expires.
        expires_at_ms: u64,
    },
    /// A different suspension is prepared.
    ///
    /// Upstream reports this as a retryable `UNAVAILABLE` transport error.
    Conflict {
        /// When the owning lease expires.
        expires_at_ms: u64,
    },
    /// The scheduler could not be driven, so the host stays fenced.
    Recovering {
        /// How long to wait before asking again.
        retry_after_ms: u64,
    },
}

impl StatusOutcome {
    /// Returns the status literal this outcome reports.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Running => "running",
            Self::Ready { .. } => "ready",
            Self::Conflict { .. } => "conflict",
            Self::Recovering { .. } => "recovering",
        }
    }
}

/// The answer to `gateway.suspend.resume`.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
#[must_use]
pub enum ResumeOutcome {
    /// The quoted suspension was released and the host is serving again.
    Resumed,
    /// Nothing was prepared, so the host was already serving.
    ///
    /// Resume is idempotent by design: a controller that crashes after
    /// resuming, or after its lease expired, must be able to retry safely.
    AlreadyRunning,
    /// A different suspension is prepared, so nothing was released.
    ///
    /// Upstream reports this as an `INVALID_REQUEST` transport error.
    Mismatch,
    /// The scheduler could not be resumed, so the host stays fenced.
    Recovering {
        /// How long to wait before trying again.
        retry_after_ms: u64,
    },
}

impl ResumeOutcome {
    /// Returns whether the host is serving traffic after this outcome.
    #[must_use]
    pub const fn is_running(self) -> bool {
        matches!(self, Self::Resumed | Self::AlreadyRunning)
    }

    /// Returns the wire `resumed` flag, when the call succeeded.
    #[must_use]
    pub const fn resumed(self) -> Option<bool> {
        match self {
            Self::Resumed => Some(true),
            Self::AlreadyRunning => Some(false),
            _ => None,
        }
    }
}

#[derive(Debug)]
struct HeldSuspension {
    request_id: String,
    suspension_id: String,
    expires_at_ms: u64,
    snapshot: ActiveWorkSnapshot,
    lease: SuspendLease,
}

#[derive(Debug, Default)]
enum CoordinatorState {
    #[default]
    Idle,
    Held(Box<HeldSuspension>),
    /// The scheduler failed to resume. The lease is kept so the fence stays
    /// closed, and so a later retry can reopen it once the host is drivable.
    Recovering {
        lease: SuspendLease,
        retry_at_ms: u64,
    },
}

/// Owns at most one cooperative suspension of this host.
#[derive(Debug)]
pub struct SuspendCoordinator {
    admission: Arc<WorkAdmission>,
    scheduler: Arc<dyn Scheduler>,
    inspector: Arc<dyn ActiveWorkInspector>,
    clock: Arc<dyn Clock>,
    ids: Arc<dyn SuspensionIds>,
    ttl_ms: u64,
    state: Mutex<CoordinatorState>,
}

impl SuspendCoordinator {
    /// Creates a coordinator over `admission` using the process wall clock.
    #[must_use]
    pub fn new(
        admission: Arc<WorkAdmission>,
        scheduler: Arc<dyn Scheduler>,
        inspector: Arc<dyn ActiveWorkInspector>,
    ) -> Self {
        Self {
            admission,
            scheduler,
            inspector,
            clock: Arc::new(SystemClock),
            ids: Arc::new(ProcessSuspensionIds::default()),
            ttl_ms: SUSPEND_TTL_MS,
            state: Mutex::new(CoordinatorState::Idle),
        }
    }

    /// Replaces the clock that lease expiry is measured against.
    #[must_use]
    pub fn with_clock(mut self, clock: Arc<dyn Clock>) -> Self {
        self.clock = clock;
        self
    }

    /// Replaces the suspension identifier source.
    #[must_use]
    pub fn with_suspension_ids(mut self, ids: Arc<dyn SuspensionIds>) -> Self {
        self.ids = ids;
        self
    }

    /// Replaces the lease lifetime.
    #[must_use]
    pub const fn with_ttl_ms(mut self, ttl_ms: u64) -> Self {
        self.ttl_ms = ttl_ms;
        self
    }

    /// Returns the admission fence this coordinator closes.
    #[must_use]
    pub fn admission(&self) -> &Arc<WorkAdmission> {
        &self.admission
    }

    /// Returns the lease lifetime in milliseconds.
    #[must_use]
    pub const fn ttl_ms(&self) -> u64 {
        self.ttl_ms
    }

    fn state(&self) -> MutexGuard<'_, CoordinatorState> {
        self.state.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// Prepares, or renews, a cooperative suspension for `request_id`.
    pub fn prepare(&self, request_id: &str) -> PrepareOutcome {
        let request_id = request_id.trim();
        let mut state = self.state();
        if !self.normalize(&mut state) {
            return PrepareOutcome::Recovering {
                retry_after_ms: SCHEDULER_RECOVERY_RETRY_MS,
            };
        }

        if let CoordinatorState::Held(held) = &mut *state {
            if held.request_id != request_id {
                return PrepareOutcome::Conflict {
                    expires_at_ms: held.expires_at_ms,
                };
            }
            // The same controller asking again renews its own lease, so a slow
            // host suspension is not cut short by a retry.
            held.expires_at_ms = self.clock.now_ms().saturating_add(self.ttl_ms);
            return PrepareOutcome::Ready {
                suspension_id: held.suspension_id.clone(),
                expires_at_ms: held.expires_at_ms,
                active_count: held.snapshot.active_count(),
                blockers: held.snapshot.blockers().to_vec(),
            };
        }

        let Some(lease) = self.admission.try_begin_suspend() else {
            return self.busy(BusyReason::GatewayDraining, self.capture());
        };

        if self.scheduler.pause().is_err() {
            lease.rollback();
            return PrepareOutcome::Recovering {
                retry_after_ms: SCHEDULER_RECOVERY_RETRY_MS,
            };
        }

        let snapshot = self.capture();
        if !snapshot.is_idle() {
            // Rollback resumes the scheduler before reopening admission; the
            // other order would admit work the host could not schedule.
            if self.scheduler.resume().is_err() {
                *state = self.enter_recovery(lease);
                return PrepareOutcome::Recovering {
                    retry_after_ms: SCHEDULER_RECOVERY_RETRY_MS,
                };
            }
            lease.rollback();
            return self.busy(BusyReason::ActiveWork, snapshot);
        }

        if !lease.commit() {
            // Only a restart drain can supersede a lease mid-preparation, and
            // a host being shut down must not have its scheduler restarted.
            return self.busy(BusyReason::GatewayDraining, snapshot);
        }

        let suspension_id = self.ids.next_id();
        let expires_at_ms = self.clock.now_ms().saturating_add(self.ttl_ms);
        let outcome = PrepareOutcome::Ready {
            suspension_id: suspension_id.clone(),
            expires_at_ms,
            active_count: snapshot.active_count(),
            blockers: snapshot.blockers().to_vec(),
        };
        *state = CoordinatorState::Held(Box::new(HeldSuspension {
            request_id: request_id.to_owned(),
            suspension_id,
            expires_at_ms,
            snapshot,
            lease,
        }));
        outcome
    }

    /// Reports the state of the suspension identified by `suspension_id`.
    pub fn status(&self, suspension_id: &str) -> StatusOutcome {
        let suspension_id = suspension_id.trim();
        let mut state = self.state();
        if !self.normalize(&mut state) {
            return StatusOutcome::Recovering {
                retry_after_ms: SCHEDULER_RECOVERY_RETRY_MS,
            };
        }
        match &*state {
            CoordinatorState::Held(held) if held.suspension_id == suspension_id => {
                StatusOutcome::Ready {
                    expires_at_ms: held.expires_at_ms,
                }
            }
            CoordinatorState::Held(held) => StatusOutcome::Conflict {
                expires_at_ms: held.expires_at_ms,
            },
            _ => StatusOutcome::Running,
        }
    }

    /// Releases the suspension identified by `suspension_id`.
    pub fn resume(&self, suspension_id: &str) -> ResumeOutcome {
        let suspension_id = suspension_id.trim();
        let mut state = self.state();
        if !self.normalize(&mut state) {
            return ResumeOutcome::Recovering {
                retry_after_ms: SCHEDULER_RECOVERY_RETRY_MS,
            };
        }

        match std::mem::take(&mut *state) {
            CoordinatorState::Held(held) if held.suspension_id == suspension_id => {
                match self.scheduler.resume() {
                    Ok(()) => {
                        held.lease.release();
                        ResumeOutcome::Resumed
                    }
                    Err(_) => {
                        *state = self.enter_recovery(held.lease);
                        ResumeOutcome::Recovering {
                            retry_after_ms: SCHEDULER_RECOVERY_RETRY_MS,
                        }
                    }
                }
            }
            other => {
                let mismatch = matches!(other, CoordinatorState::Held(_));
                *state = other;
                if mismatch {
                    ResumeOutcome::Mismatch
                } else {
                    ResumeOutcome::AlreadyRunning
                }
            }
        }
    }

    /// Drives lease expiry and scheduler recovery without an inbound request.
    ///
    /// Every entry point normalises state first, so a host that only serves
    /// `gateway.suspend.*` never needs this. A host that wants its fence to
    /// reopen promptly after an abandoned lease calls this from its own timer.
    ///
    /// A pending scheduler recovery is retried no more often than
    /// [`SCHEDULER_RECOVERY_RETRY_MS`], the same backoff the caller is told to
    /// use, so polling cannot hammer a wedged scheduler.
    ///
    /// Returns `false` while scheduler recovery is still pending.
    pub fn poll(&self) -> bool {
        let mut state = self.state();
        self.normalize(&mut state)
    }

    /// Returns whether the fence is held closed by a failing scheduler.
    #[must_use]
    pub fn is_recovering(&self) -> bool {
        matches!(&*self.state(), CoordinatorState::Recovering { .. })
    }

    fn enter_recovery(&self, lease: SuspendLease) -> CoordinatorState {
        CoordinatorState::Recovering {
            lease,
            retry_at_ms: self
                .clock
                .now_ms()
                .saturating_add(SCHEDULER_RECOVERY_RETRY_MS),
        }
    }

    fn capture(&self) -> ActiveWorkSnapshot {
        ActiveWorkSnapshot::capture(self.inspector.as_ref())
    }

    fn busy(&self, reason: BusyReason, snapshot: ActiveWorkSnapshot) -> PrepareOutcome {
        PrepareOutcome::Busy {
            reason,
            retry_after_ms: SUSPEND_RETRY_AFTER_MS,
            active_count: snapshot.active_count(),
            blockers: snapshot.into_blockers(),
        }
    }

    /// Retires an expired or superseded lease and retries pending recovery.
    ///
    /// Returns `false` when the coordinator is still recovering, which is the
    /// only state that answers every request with `recovering`.
    fn normalize(&self, state: &mut CoordinatorState) -> bool {
        let (next, usable) = match std::mem::take(state) {
            CoordinatorState::Idle => (CoordinatorState::Idle, true),
            CoordinatorState::Recovering { lease, retry_at_ms } => {
                if self.clock.now_ms() < retry_at_ms {
                    // Back off exactly as long as the caller was told to, so a
                    // polling controller cannot hammer a wedged scheduler.
                    (CoordinatorState::Recovering { lease, retry_at_ms }, false)
                } else {
                    match self.scheduler.resume() {
                        Ok(()) => {
                            lease.release();
                            (CoordinatorState::Idle, true)
                        }
                        Err(_) => (self.enter_recovery(lease), false),
                    }
                }
            }
            CoordinatorState::Held(held) => {
                if !held.lease.is_active() {
                    // A restart drain superseded this lease. The host is going
                    // away, so its scheduler is deliberately left paused.
                    (CoordinatorState::Idle, true)
                } else if self.clock.now_ms() >= held.expires_at_ms {
                    match self.scheduler.resume() {
                        Ok(()) => {
                            held.lease.release();
                            (CoordinatorState::Idle, true)
                        }
                        Err(_) => (self.enter_recovery(held.lease), false),
                    }
                } else {
                    (CoordinatorState::Held(held), true)
                }
            }
        };
        *state = next;
        usable
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use super::super::active_work::IdleInspector;
    use super::super::admission::WorkAdmission;
    use super::super::clock::ManualClock;
    use super::{
        MAX_SUSPENSION_TOKEN_LEN, NoopScheduler, PrepareOutcome, ProcessSuspensionIds,
        ResumeOutcome, SchedulerError, StatusOutcome, SuspendCoordinator, SuspensionIds,
        is_valid_suspension_token,
    };

    fn coordinator(clock: &ManualClock) -> SuspendCoordinator {
        SuspendCoordinator::new(
            Arc::new(WorkAdmission::new()),
            Arc::new(NoopScheduler),
            Arc::new(IdleInspector),
        )
        .with_clock(Arc::new(clock.clone()))
    }

    #[test]
    fn process_suspension_ids_never_repeat() {
        let ids = ProcessSuspensionIds::default();

        let first = ids.next_id();
        let second = ids.next_id();

        assert_ne!(first, second);
        assert!(is_valid_suspension_token(&first));
        assert!(is_valid_suspension_token(&second));
    }

    #[test]
    fn suspension_tokens_follow_the_upstream_schema_rule() {
        assert!(is_valid_suspension_token("request-1"));
        assert!(is_valid_suspension_token(" x "));
        assert!(is_valid_suspension_token(
            &"x".repeat(MAX_SUSPENSION_TOKEN_LEN)
        ));

        assert!(!is_valid_suspension_token(""));
        assert!(!is_valid_suspension_token("   "));
        assert!(!is_valid_suspension_token("\t\n"));
        assert!(!is_valid_suspension_token(
            &"x".repeat(MAX_SUSPENSION_TOKEN_LEN + 1)
        ));
        assert!(
            !is_valid_suspension_token(&"🙂".repeat(MAX_SUSPENSION_TOKEN_LEN / 2 + 1)),
            "the limit counts UTF-16 code units, as the upstream schema does"
        );
    }

    #[test]
    fn a_lease_is_stamped_with_the_injected_clock() {
        let clock = ManualClock::new(1_000);
        let coordinator = coordinator(&clock).with_ttl_ms(5_000);

        let outcome = coordinator.prepare("request-1");

        assert_eq!(outcome.as_str(), "ready");
        let PrepareOutcome::Ready { expires_at_ms, .. } = outcome else {
            panic!("an idle host prepares");
        };
        assert_eq!(expires_at_ms, 6_000);
    }

    #[test]
    fn a_trimmed_identifier_still_matches_its_lease() {
        let clock = ManualClock::new(0);
        let coordinator = coordinator(&clock);
        let outcome = coordinator.prepare("  request-1  ");
        let suspension_id = outcome
            .suspension_id()
            .expect("an idle host prepares")
            .to_owned();

        assert!(matches!(
            coordinator.status(&format!("  {suspension_id} ")),
            StatusOutcome::Ready { .. }
        ));
        assert_eq!(coordinator.prepare("request-1").as_str(), "ready");
        assert_eq!(coordinator.resume(&suspension_id), ResumeOutcome::Resumed);
    }

    #[test]
    fn scheduler_errors_describe_themselves() {
        let error = SchedulerError::new("cron is wedged");

        assert_eq!(error.message(), "cron is wedged");
        assert_eq!(error.to_string(), "gateway scheduler error: cron is wedged");
    }

    #[test]
    fn resume_reports_the_wire_resumed_flag() {
        assert_eq!(ResumeOutcome::Resumed.resumed(), Some(true));
        assert_eq!(ResumeOutcome::AlreadyRunning.resumed(), Some(false));
        assert_eq!(ResumeOutcome::Mismatch.resumed(), None);
        assert!(!ResumeOutcome::Mismatch.is_running());
        assert!(ResumeOutcome::AlreadyRunning.is_running());
    }
}

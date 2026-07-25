//! Cooperative host suspension.
//!
//! Mirrors the frozen `gateway.suspend.prepare` / `gateway.suspend.status` /
//! `gateway.suspend.resume` triple. The host asks the runtime to quiesce; the runtime stops
//! admitting new work, waits for in-flight work to drain, and hands back a lease. The host later
//! resumes with that lease. Nothing is force-killed: every in-flight unit runs to completion.

use std::error::Error;
use std::fmt::{self, Display, Formatter};
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::Duration;

use claw_application::model::ids::LeaseId;
use claw_application::model::time::Timestamp;
use claw_application::ports::clock::ClockPort;
use tokio::sync::Notify;

/// The lifecycle phase of the host suspension handshake.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum SuspensionPhase {
    /// New work is admitted normally.
    Active,
    /// New work is refused while in-flight work finishes.
    Draining,
    /// No work is in flight and the host holds a lease.
    Suspended,
}

impl SuspensionPhase {
    /// Every phase in lifecycle order.
    pub const ALL: [Self; 3] = [Self::Active, Self::Draining, Self::Suspended];

    /// Returns the stable wire label for this phase.
    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            Self::Active => "active",
            Self::Draining => "draining",
            Self::Suspended => "suspended",
        }
    }

    /// Returns whether new work may start in this phase.
    #[must_use]
    pub const fn admits_work(self) -> bool {
        matches!(self, Self::Active)
    }
}

impl Display for SuspensionPhase {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.label())
    }
}

/// The lease a suspended host must present to resume.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SuspendLease {
    /// The lease identifier.
    pub lease_id: LeaseId,
    /// Why the host asked for suspension.
    pub reason: String,
    /// When the lease was granted.
    pub granted_at: Timestamp,
    /// When the lease expires and the runtime self-resumes.
    pub expires_at: Timestamp,
}

/// An observation of the suspension controller.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SuspensionStatus {
    /// The current phase.
    pub phase: SuspensionPhase,
    /// The number of work permits currently outstanding.
    pub in_flight: usize,
    /// The lease held by the host, when one exists.
    pub lease: Option<SuspendLease>,
    /// When the observation was taken.
    pub observed_at: Timestamp,
}

/// A request to quiesce the runtime.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PrepareRequest {
    /// The lease identifier the host wants to hold.
    pub lease_id: LeaseId,
    /// Why the host is suspending; echoed back in the status.
    pub reason: String,
    /// How long in-flight work may take to drain before the request is refused.
    pub drain_timeout: Duration,
    /// How long the granted lease stays valid.
    pub lease_ttl: Duration,
}

/// The result of a prepare request.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum PrepareOutcome {
    /// The runtime is quiesced and the host holds the lease.
    Suspended(SuspendLease),
    /// Work did not drain in time; the runtime resumed admitting work.
    DrainTimedOut {
        /// How many permits were still outstanding when the deadline passed.
        in_flight: usize,
    },
}

/// A refused suspension operation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum SuspendError {
    /// A different lease already owns the suspension.
    AlreadySuspended {
        /// The lease that owns it.
        lease_id: LeaseId,
    },
    /// A prepare is already draining.
    AlreadyDraining {
        /// The lease that is draining.
        lease_id: LeaseId,
    },
    /// The runtime is not suspended, so there is nothing to resume.
    NotSuspended,
    /// The presented lease is not the lease that owns the suspension.
    LeaseMismatch {
        /// The lease that owns the suspension.
        expected: LeaseId,
        /// The lease that was presented.
        presented: LeaseId,
    },
    /// A deadline could not be represented.
    DeadlineOverflow,
}

impl Display for SuspendError {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        match self {
            Self::AlreadySuspended { lease_id } => {
                write!(formatter, "already suspended under lease {lease_id}")
            }
            Self::AlreadyDraining { lease_id } => {
                write!(formatter, "already draining under lease {lease_id}")
            }
            Self::NotSuspended => formatter.write_str("the runtime is not suspended"),
            Self::LeaseMismatch {
                expected,
                presented,
            } => write!(
                formatter,
                "lease {presented} does not own the suspension held by {expected}"
            ),
            Self::DeadlineOverflow => formatter.write_str("suspension deadline overflowed"),
        }
    }
}

impl Error for SuspendError {}

/// The reason [`SuspensionController::admit`] refused to start work.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct WorkRefused {
    /// The phase that refused the work.
    pub phase: SuspensionPhase,
}

impl Display for WorkRefused {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "the runtime is {} and refuses new work",
            self.phase
        )
    }
}

impl Error for WorkRefused {}

#[derive(Debug)]
struct ControllerState {
    phase: SuspensionPhase,
    in_flight: usize,
    lease: Option<SuspendLease>,
}

/// An RAII token proving one unit of work is in flight.
///
/// Dropping the permit decrements the in-flight count and wakes a draining prepare, so work that
/// panics or is cancelled still releases the runtime.
#[derive(Debug)]
pub struct WorkPermit {
    shared: Arc<Shared>,
}

impl Drop for WorkPermit {
    fn drop(&mut self) {
        let drained = {
            let mut state = Shared::lock(&self.shared.state);
            state.in_flight = state.in_flight.saturating_sub(1);
            state.in_flight == 0
        };
        if drained {
            self.shared.drained.notify_waiters();
        }
    }
}

/// Rolls a committed `Draining` transition back when [`SuspensionController::prepare`] is
/// dropped instead of resolved.
///
/// `prepare` commits the phase change and installs its lease, releases the lock, and then awaits
/// the drain. A future may be dropped at any await point, and without this guard a dropped
/// `prepare` would strand the controller in `Draining` forever: [`SuspensionController::admit`]
/// refuses all work, another `prepare` returns [`SuspendError::AlreadyDraining`],
/// [`SuspensionController::resume`] returns [`SuspendError::NotSuspended`], and lease expiry only
/// fires in `Suspended`. Only a process restart would recover.
///
/// The guard is armed for exactly the window between committing the transition and reaching a
/// decision about it, and `prepare` disarms it on every path that reaches a decision — including
/// the drain-timeout path, whose rollback is a deliberate outcome rather than an unwind.
#[derive(Debug)]
struct DrainGuard {
    shared: Arc<Shared>,
    lease_id: LeaseId,
    armed: bool,
}

impl DrainGuard {
    /// Commits the `Draining` transition and returns the guard that owns rolling it back.
    ///
    /// The caller must already hold `state` and must have checked that the phase is `Active`.
    fn arm(shared: &Arc<Shared>, state: &mut ControllerState, lease: SuspendLease) -> Self {
        let lease_id = lease.lease_id.clone();
        state.phase = SuspensionPhase::Draining;
        state.lease = Some(lease);
        Self {
            shared: Arc::clone(shared),
            lease_id,
            armed: true,
        }
    }

    /// Hands ownership of the transition back to the caller.
    ///
    /// Must be called before the controller mutex is taken, because [`Drop`] locks the same
    /// non-reentrant mutex.
    fn disarm(&mut self) {
        self.armed = false;
    }
}

impl Drop for DrainGuard {
    fn drop(&mut self) {
        if !self.armed {
            return;
        }
        let mut state = Shared::lock(&self.shared.state);
        // Roll back only the transition this guard installed. `Draining` blocks every other
        // transition today, so nothing else can be holding the phase, but that is an invariant of
        // the current control flow rather than of the type; checking the lease identity keeps the
        // rollback correct if a third transition is ever added.
        let owned = state.phase == SuspensionPhase::Draining
            && state
                .lease
                .as_ref()
                .is_some_and(|lease| lease.lease_id == self.lease_id);
        if owned {
            state.phase = SuspensionPhase::Active;
            state.lease = None;
        }
    }
}

#[derive(Debug)]
struct Shared {
    state: Mutex<ControllerState>,
    drained: Notify,
}

impl Shared {
    fn lock(mutex: &Mutex<ControllerState>) -> MutexGuard<'_, ControllerState> {
        mutex
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }
}

/// Coordinates the cooperative suspend/resume handshake.
#[derive(Clone)]
pub struct SuspensionController {
    shared: Arc<Shared>,
    clock: Arc<dyn ClockPort>,
}

impl fmt::Debug for SuspensionController {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        let state = Shared::lock(&self.shared.state);
        formatter
            .debug_struct("SuspensionController")
            .field("phase", &state.phase)
            .field("in_flight", &state.in_flight)
            .finish_non_exhaustive()
    }
}

impl SuspensionController {
    /// Creates an active controller.
    #[must_use]
    pub fn new(clock: Arc<dyn ClockPort>) -> Self {
        Self {
            shared: Arc::new(Shared {
                state: Mutex::new(ControllerState {
                    phase: SuspensionPhase::Active,
                    in_flight: 0,
                    lease: None,
                }),
                drained: Notify::new(),
            }),
            clock,
        }
    }

    /// Returns a permit for one unit of work, or refuses it while the runtime is quiescing.
    ///
    /// # Errors
    ///
    /// Returns [`WorkRefused`] when the controller is draining or suspended.
    pub fn admit(&self) -> Result<WorkPermit, WorkRefused> {
        let mut state = Shared::lock(&self.shared.state);
        self.expire_locked(&mut state);
        if !state.phase.admits_work() {
            return Err(WorkRefused { phase: state.phase });
        }
        state.in_flight = state.in_flight.saturating_add(1);
        drop(state);
        Ok(WorkPermit {
            shared: Arc::clone(&self.shared),
        })
    }

    /// Returns the current suspension status, expiring a stale lease first.
    #[must_use]
    pub fn status(&self) -> SuspensionStatus {
        let mut state = Shared::lock(&self.shared.state);
        self.expire_locked(&mut state);
        SuspensionStatus {
            phase: state.phase,
            in_flight: state.in_flight,
            lease: state.lease.clone(),
            observed_at: self.clock.now(),
        }
    }

    /// Quiesces the runtime, waiting for in-flight work to drain.
    ///
    /// Dropping the returned future rolls the `Draining` transition back to `Active` and releases
    /// the lease, so a cancelled suspension cannot wedge the controller.
    ///
    /// # Errors
    ///
    /// Returns [`SuspendError::AlreadyDraining`] or [`SuspendError::AlreadySuspended`] when
    /// another lease owns the handshake, and [`SuspendError::DeadlineOverflow`] when the drain or
    /// lease deadline cannot be represented.
    pub async fn prepare(&self, request: PrepareRequest) -> Result<PrepareOutcome, SuspendError> {
        let granted_at = self.clock.now();
        let drain_deadline = granted_at
            .checked_add(request.drain_timeout)
            .ok_or(SuspendError::DeadlineOverflow)?;
        let expires_at = granted_at
            .checked_add(request.lease_ttl)
            .ok_or(SuspendError::DeadlineOverflow)?;

        let mut guard = {
            let mut state = Shared::lock(&self.shared.state);
            self.expire_locked(&mut state);
            match state.phase {
                SuspensionPhase::Draining => {
                    let lease_id = state
                        .lease
                        .as_ref()
                        .map_or_else(|| request.lease_id.clone(), |lease| lease.lease_id.clone());
                    return Err(SuspendError::AlreadyDraining { lease_id });
                }
                SuspensionPhase::Suspended => {
                    let lease_id = state
                        .lease
                        .as_ref()
                        .map_or_else(|| request.lease_id.clone(), |lease| lease.lease_id.clone());
                    return Err(SuspendError::AlreadySuspended { lease_id });
                }
                SuspensionPhase::Active => {}
            }
            DrainGuard::arm(
                &self.shared,
                &mut state,
                SuspendLease {
                    lease_id: request.lease_id.clone(),
                    reason: request.reason.clone(),
                    granted_at,
                    expires_at,
                },
            )
        };

        let drained = self.wait_for_drain(drain_deadline).await;

        // The drain reached a decision, so ownership of the transition returns here for both
        // outcomes: a drained runtime becomes `Suspended`, and a timed-out drain deliberately
        // returns to `Active` without a lease. Disarming before the lock is taken keeps `Drop`
        // from re-entering the same non-reentrant mutex.
        guard.disarm();

        let mut state = Shared::lock(&self.shared.state);
        if drained {
            state.phase = SuspensionPhase::Suspended;
            let lease = state.lease.clone().unwrap_or(SuspendLease {
                lease_id: request.lease_id,
                reason: request.reason,
                granted_at,
                expires_at,
            });
            Ok(PrepareOutcome::Suspended(lease))
        } else {
            state.phase = SuspensionPhase::Active;
            state.lease = None;
            Ok(PrepareOutcome::DrainTimedOut {
                in_flight: state.in_flight,
            })
        }
    }

    /// Releases the suspension held by `lease_id`.
    ///
    /// # Errors
    ///
    /// Returns [`SuspendError::NotSuspended`] when no lease is held and
    /// [`SuspendError::LeaseMismatch`] when a different lease owns the suspension.
    pub fn resume(&self, lease_id: &LeaseId) -> Result<SuspensionStatus, SuspendError> {
        let mut state = Shared::lock(&self.shared.state);
        self.expire_locked(&mut state);

        let Some(held) = state.lease.clone() else {
            return Err(SuspendError::NotSuspended);
        };
        if state.phase != SuspensionPhase::Suspended {
            return Err(SuspendError::NotSuspended);
        }
        if &held.lease_id != lease_id {
            return Err(SuspendError::LeaseMismatch {
                expected: held.lease_id,
                presented: lease_id.clone(),
            });
        }

        state.phase = SuspensionPhase::Active;
        state.lease = None;
        Ok(SuspensionStatus {
            phase: state.phase,
            in_flight: state.in_flight,
            lease: None,
            observed_at: self.clock.now(),
        })
    }

    /// Waits until the in-flight count reaches zero or the deadline passes.
    ///
    /// The waiter is registered *before* the count is read, so a permit dropped between the read
    /// and the await still wakes this task.
    async fn wait_for_drain(&self, deadline: Timestamp) -> bool {
        loop {
            let notified = self.shared.drained.notified();
            tokio::pin!(notified);
            // Register the waiter before reading the count so a permit dropped between the read
            // and the await cannot be missed.
            notified.as_mut().enable();

            if Shared::lock(&self.shared.state).in_flight == 0 {
                return true;
            }

            tokio::select! {
                biased;
                () = &mut notified => {
                    if Shared::lock(&self.shared.state).in_flight == 0 {
                        return true;
                    }
                }
                () = self.clock.sleep_until(deadline) => {
                    return Shared::lock(&self.shared.state).in_flight == 0;
                }
            }
        }
    }

    /// Drops an expired lease so a crashed host cannot wedge the runtime forever.
    fn expire_locked(&self, state: &mut ControllerState) {
        if state.phase != SuspensionPhase::Suspended {
            return;
        }
        let Some(lease) = state.lease.as_ref() else {
            return;
        };
        if self.clock.now() >= lease.expires_at {
            state.phase = SuspensionPhase::Active;
            state.lease = None;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn lease_id(name: &str) -> LeaseId {
        LeaseId::new(name).expect("the test lease id is valid")
    }

    fn lease(name: &str) -> SuspendLease {
        SuspendLease {
            lease_id: lease_id(name),
            reason: "host update".to_owned(),
            granted_at: Timestamp::from_millis(0),
            expires_at: Timestamp::from_millis(60_000),
        }
    }

    /// An active controller with one unit of work outstanding, so a real `prepare` would park.
    fn active_shared() -> Arc<Shared> {
        Arc::new(Shared {
            state: Mutex::new(ControllerState {
                phase: SuspensionPhase::Active,
                in_flight: 1,
                lease: None,
            }),
            drained: Notify::new(),
        })
    }

    /// Commits the transition the way `prepare` does and hands back the guard that owns it.
    fn arm(shared: &Arc<Shared>, held: SuspendLease) -> DrainGuard {
        let mut state = Shared::lock(&shared.state);
        DrainGuard::arm(shared, &mut state, held)
    }

    #[test]
    fn arming_the_guard_commits_the_draining_transition() {
        let shared = active_shared();
        let mut guard = arm(&shared, lease("lease-a"));

        let state = Shared::lock(&shared.state);
        assert_eq!(state.phase, SuspensionPhase::Draining);
        assert_eq!(state.lease, Some(lease("lease-a")));
        assert_eq!(state.in_flight, 1);
        drop(state);

        guard.disarm();
    }

    #[test]
    fn an_armed_guard_rolls_the_transition_it_installed_back_to_active() {
        let shared = active_shared();
        let guard = arm(&shared, lease("lease-b"));
        drop(guard);

        let state = Shared::lock(&shared.state);
        assert_eq!(state.phase, SuspensionPhase::Active);
        assert_eq!(state.lease, None);
        // The rollback releases the phase, never the work that is still running.
        assert_eq!(state.in_flight, 1);
    }

    #[test]
    fn a_disarmed_guard_leaves_the_transition_in_place() {
        let shared = active_shared();
        let mut guard = arm(&shared, lease("lease-c"));
        guard.disarm();
        drop(guard);

        let state = Shared::lock(&shared.state);
        assert_eq!(state.phase, SuspensionPhase::Draining);
        assert_eq!(state.lease, Some(lease("lease-c")));
    }

    #[test]
    fn a_guard_whose_lease_was_replaced_leaves_the_replacement_alone() {
        let shared = active_shared();
        let guard = arm(&shared, lease("lease-d"));

        // A hypothetical third transition parks a different lease in `Draining` before the
        // abandoned prepare unwinds. The guard must not roll back state it does not own.
        Shared::lock(&shared.state).lease = Some(lease("lease-e"));
        drop(guard);

        let state = Shared::lock(&shared.state);
        assert_eq!(state.phase, SuspensionPhase::Draining);
        assert_eq!(state.lease, Some(lease("lease-e")));
    }

    #[test]
    fn a_guard_whose_phase_moved_on_leaves_the_new_phase_alone() {
        let shared = active_shared();
        let guard = arm(&shared, lease("lease-f"));

        Shared::lock(&shared.state).phase = SuspensionPhase::Suspended;
        drop(guard);

        let state = Shared::lock(&shared.state);
        assert_eq!(state.phase, SuspensionPhase::Suspended);
        assert_eq!(state.lease, Some(lease("lease-f")));
    }
}

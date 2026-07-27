//! Serving lifecycle behind the Gateway liveness and readiness probes.
//!
//! Liveness and readiness answer two different questions, and the difference
//! only becomes visible while the process is draining: a draining Gateway is
//! still alive and must keep serving in-flight work, but it must stop being
//! routed new work. Modelling the drain as a distinct phase — rather than as a
//! readiness dependency that happens to fail — is what lets the two probe
//! families disagree at exactly the right moment.

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU8, Ordering};
use std::time::Duration;

use tokio::time::Instant;

/// Serving phase of the Gateway HTTP surface.
///
/// The phases are ordered and a lifecycle only ever moves forward through them,
/// so a drain can never be undone by a late "I am ready now" report from a
/// subsystem that finished starting after shutdown began.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum ServingState {
    /// The process is up but has not finished wiring its subsystems.
    Starting,
    /// The process is serving traffic normally.
    Serving,
    /// The process is shutting down gracefully and must not receive new work.
    Draining,
    /// The process has stopped serving.
    Stopped,
}

impl ServingState {
    /// Every phase, in lifecycle order.
    pub const ALL: [Self; 4] = [Self::Starting, Self::Serving, Self::Draining, Self::Stopped];

    /// Returns the wire name reported by the probe endpoints.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Starting => "starting",
            Self::Serving => "serving",
            Self::Draining => "draining",
            Self::Stopped => "stopped",
        }
    }

    /// Returns whether the process is still alive, which stays true across a drain.
    #[must_use]
    pub const fn is_live(self) -> bool {
        !matches!(self, Self::Stopped)
    }

    /// Returns whether the process is draining.
    #[must_use]
    pub const fn is_draining(self) -> bool {
        matches!(self, Self::Draining)
    }

    /// Returns whether the process may be routed new work.
    #[must_use]
    pub const fn accepts_new_work(self) -> bool {
        matches!(self, Self::Serving)
    }

    /// Returns the reason a readiness probe reports for this phase, if any.
    #[must_use]
    pub const fn readiness_reason(self) -> Option<&'static str> {
        match self {
            Self::Serving => None,
            other => Some(other.as_str()),
        }
    }

    const fn rank(self) -> u8 {
        match self {
            Self::Starting => 0,
            Self::Serving => 1,
            Self::Draining => 2,
            Self::Stopped => 3,
        }
    }

    const fn from_rank(rank: u8) -> Self {
        match rank {
            0 => Self::Starting,
            1 => Self::Serving,
            2 => Self::Draining,
            _ => Self::Stopped,
        }
    }
}

/// Shared, cloneable handle to the serving phase of one Gateway process.
#[derive(Clone, Debug)]
pub struct GatewayLifecycle {
    inner: Arc<LifecycleInner>,
}

#[derive(Debug)]
struct LifecycleInner {
    state: AtomicU8,
    started: Instant,
}

impl GatewayLifecycle {
    /// Creates a lifecycle that has not finished starting yet.
    #[must_use]
    pub fn starting() -> Self {
        Self::at(ServingState::Starting)
    }

    /// Creates a lifecycle that is already serving traffic.
    #[must_use]
    pub fn serving() -> Self {
        Self::at(ServingState::Serving)
    }

    fn at(state: ServingState) -> Self {
        Self {
            inner: Arc::new(LifecycleInner {
                state: AtomicU8::new(state.rank()),
                started: Instant::now(),
            }),
        }
    }

    /// Returns the current serving phase.
    #[must_use]
    pub fn state(&self) -> ServingState {
        ServingState::from_rank(self.inner.state.load(Ordering::Acquire))
    }

    /// Returns how long this lifecycle has existed.
    #[must_use]
    pub fn uptime(&self) -> Duration {
        self.inner.started.elapsed()
    }

    /// Marks the process as serving. Returns `false` once a drain has begun.
    pub fn mark_serving(&self) -> bool {
        self.advance_to(ServingState::Serving)
    }

    /// Begins a graceful drain. Returns `false` when the drain already began.
    pub fn begin_draining(&self) -> bool {
        self.advance_to(ServingState::Draining)
    }

    /// Marks the process as stopped. Returns `false` when it already stopped.
    pub fn mark_stopped(&self) -> bool {
        self.advance_to(ServingState::Stopped)
    }

    fn advance_to(&self, target: ServingState) -> bool {
        let mut observed = self.inner.state.load(Ordering::Acquire);
        loop {
            if ServingState::from_rank(observed) >= target {
                return false;
            }
            match self.inner.state.compare_exchange_weak(
                observed,
                target.rank(),
                Ordering::AcqRel,
                Ordering::Acquire,
            ) {
                Ok(_) => return true,
                Err(actual) => observed = actual,
            }
        }
    }
}

impl Default for GatewayLifecycle {
    fn default() -> Self {
        Self::starting()
    }
}

/// One named dependency a readiness probe consults.
pub trait ReadinessCheck: Send + Sync + 'static {
    /// Returns the dependency name reported in the `failing` list.
    fn name(&self) -> &str;

    /// Returns whether the dependency is currently usable.
    fn is_ready(&self) -> bool;
}

/// Readiness dependency whose state is flipped by the subsystem that owns it.
#[derive(Debug)]
pub struct ReadinessFlag {
    name: String,
    ready: AtomicBool,
}

impl ReadinessFlag {
    /// Creates a dependency in the given initial state.
    #[must_use]
    pub fn new(name: impl Into<String>, ready: bool) -> Arc<Self> {
        Arc::new(Self {
            name: name.into(),
            ready: AtomicBool::new(ready),
        })
    }

    /// Publishes a new dependency state.
    pub fn set_ready(&self, ready: bool) {
        self.ready.store(ready, Ordering::Release);
    }
}

impl ReadinessCheck for ReadinessFlag {
    fn name(&self) -> &str {
        &self.name
    }

    fn is_ready(&self) -> bool {
        self.ready.load(Ordering::Acquire)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn lifecycle_phases_only_move_forward() {
        let lifecycle = GatewayLifecycle::starting();
        assert_eq!(lifecycle.state(), ServingState::Starting);
        assert!(lifecycle.mark_serving());
        assert_eq!(lifecycle.state(), ServingState::Serving);
        assert!(lifecycle.begin_draining());
        assert!(!lifecycle.begin_draining());
        assert!(
            !lifecycle.mark_serving(),
            "a late readiness report must not cancel a drain"
        );
        assert_eq!(lifecycle.state(), ServingState::Draining);
        assert!(lifecycle.mark_stopped());
        assert_eq!(lifecycle.state(), ServingState::Stopped);
    }

    #[test]
    fn phase_ranks_round_trip_and_classify_liveness_separately_from_readiness() {
        for state in ServingState::ALL {
            assert_eq!(ServingState::from_rank(state.rank()), state);
        }
        assert!(ServingState::Draining.is_live());
        assert!(!ServingState::Draining.accepts_new_work());
        assert!(!ServingState::Stopped.is_live());
        assert_eq!(ServingState::Serving.readiness_reason(), None);
        assert_eq!(
            ServingState::Draining.readiness_reason(),
            Some("draining"),
            "a drain must be reported as the readiness failure reason"
        );
    }
}

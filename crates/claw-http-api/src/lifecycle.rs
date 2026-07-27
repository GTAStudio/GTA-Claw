//! The host's own serving state, as seen by the liveness and readiness probes.
//!
//! Dependency health answers "can the things I talk to accept work?" and already
//! arrives through [`ReadinessPort`](crate::ReadinessPort). This port answers the
//! separate question "am *I* still willing to take new work?", which is what
//! turns a graceful shutdown into a readiness failure before the listener closes.
//!
//! The two questions are deliberately distinct. A draining host is perfectly
//! healthy and every dependency it has may be green; it simply must stop being
//! routed to. Folding drain into [`ReadinessPort`](crate::ReadinessPort) would
//! force hosts to fabricate a failing dependency to express it.
//!
//! # Relationship to `claw-application`
//!
//! [`ServingState`] is the projection of `claw_application::composition::LifecyclePhase`
//! that probes actually need, and nothing more. A composition root wires the two
//! together in one line, with no phase table to keep in sync:
//!
//! ```
//! use claw_http_api::{ServingState, ServingStatePort};
//!
//! struct Composition {
//!     // Stands in for `claw_application::composition::LifecyclePhase`.
//!     phase_label: &'static str,
//!     accepts_work: bool,
//! }
//!
//! impl ServingStatePort for Composition {
//!     fn serving_state(&self) -> ServingState {
//!         // With a real lifecycle: `ServingState::new(phase.label(), phase.accepts_work())`.
//!         ServingState::new(self.phase_label, self.accepts_work)
//!     }
//! }
//!
//! let draining = Composition { phase_label: "draining", accepts_work: false };
//! assert!(!draining.serving_state().accepts_work());
//! assert_eq!(draining.serving_state().phase(), "draining");
//! ```
//!
//! Because the port carries the label rather than a copy of the enum, phases
//! added upstream need no change here.

use std::sync::Arc;
use std::sync::atomic::{AtomicU8, Ordering};

/// The stable phase label reported while the host is serving normally.
pub const PHASE_RUNNING: &str = "running";
/// The stable phase label reported while the host has not begun serving.
pub const PHASE_STARTING: &str = "starting";
/// The stable phase label reported while the host is draining.
pub const PHASE_DRAINING: &str = "draining";

/// What the host reports about its own willingness to serve traffic.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ServingState {
    phase: &'static str,
    accepts_work: bool,
}

impl ServingState {
    /// Builds a serving state from a stable phase label and whether work is accepted.
    ///
    /// The label is surfaced verbatim to authenticated readiness callers, so it
    /// must be a stable identifier rather than prose.
    #[must_use]
    pub const fn new(phase: &'static str, accepts_work: bool) -> Self {
        Self {
            phase,
            accepts_work,
        }
    }

    /// The host is serving and accepting new work.
    #[must_use]
    pub const fn serving() -> Self {
        Self::new(PHASE_RUNNING, true)
    }

    /// The host is finishing in-flight work and refusing new work.
    #[must_use]
    pub const fn draining() -> Self {
        Self::new(PHASE_DRAINING, false)
    }

    /// Returns the stable phase label.
    #[must_use]
    pub const fn phase(self) -> &'static str {
        self.phase
    }

    /// Returns whether the host still accepts new work.
    ///
    /// This alone decides readiness; the label only explains the answer.
    #[must_use]
    pub const fn accepts_work(self) -> bool {
        self.accepts_work
    }
}

impl Default for ServingState {
    fn default() -> Self {
        Self::serving()
    }
}

/// Supplies the host's serving state rather than assuming it always serves.
pub trait ServingStatePort: Send + Sync {
    /// Returns the serving state at this instant.
    fn serving_state(&self) -> ServingState;
}

/// A cloneable, externally driven serving state for hosts without a full lifecycle.
///
/// Every clone shares one cell, so the composition root can hand a clone to
/// [`HttpApi::with_serving_state`](crate::HttpApi::with_serving_state) and keep
/// one to drive from its shutdown path. Transitions are monotonic: a host that
/// has announced a drain cannot silently return to service, because a load
/// balancer that has already been told to stop routing must not be flapped back.
#[derive(Clone, Debug)]
pub struct ServingStateHandle {
    phase: Arc<AtomicU8>,
}

const PHASE_ORDER_STARTING: u8 = 0;
const PHASE_ORDER_RUNNING: u8 = 1;
const PHASE_ORDER_DRAINING: u8 = 2;

impl ServingStateHandle {
    /// Creates a handle that has not begun serving yet.
    #[must_use]
    pub fn starting() -> Self {
        Self {
            phase: Arc::new(AtomicU8::new(PHASE_ORDER_STARTING)),
        }
    }

    /// Creates a handle that is already serving.
    #[must_use]
    pub fn serving() -> Self {
        Self {
            phase: Arc::new(AtomicU8::new(PHASE_ORDER_RUNNING)),
        }
    }

    /// Advances to serving, unless a drain has already begun.
    pub fn begin_serving(&self) {
        self.advance_to(PHASE_ORDER_RUNNING);
    }

    /// Advances to draining. Readiness fails from the next probe onward.
    pub fn begin_draining(&self) {
        self.advance_to(PHASE_ORDER_DRAINING);
    }

    fn advance_to(&self, target: u8) {
        self.phase.fetch_max(target, Ordering::SeqCst);
    }

    /// Returns the current serving state.
    #[must_use]
    pub fn state(&self) -> ServingState {
        match self.phase.load(Ordering::SeqCst) {
            PHASE_ORDER_STARTING => ServingState::new(PHASE_STARTING, false),
            PHASE_ORDER_DRAINING => ServingState::draining(),
            _ => ServingState::serving(),
        }
    }
}

impl Default for ServingStateHandle {
    fn default() -> Self {
        Self::serving()
    }
}

impl ServingStatePort for ServingStateHandle {
    fn serving_state(&self) -> ServingState {
        self.state()
    }
}

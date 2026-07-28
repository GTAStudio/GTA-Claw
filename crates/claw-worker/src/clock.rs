//! Wall-clock time as an injectable port.
//!
//! Admission expiry is a security decision, so it is never read from the host
//! clock in a test. [`ManualClock`] lets a test move time by an exact number of
//! milliseconds instead of sleeping, which keeps the expiry proofs
//! deterministic and instantaneous.

use std::fmt::Debug;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

/// Supplies Unix wall-clock milliseconds to the admission controller.
pub trait Clock: Debug + Send + Sync {
    /// Returns the current Unix time in milliseconds.
    fn unix_millis(&self) -> u64;
}

/// The process wall clock.
#[derive(Clone, Copy, Debug, Default)]
pub struct SystemClock;

impl Clock for SystemClock {
    fn unix_millis(&self) -> u64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_or(0, |elapsed| {
                u64::try_from(elapsed.as_millis()).unwrap_or(u64::MAX)
            })
    }
}

/// A clock whose value only changes when a caller advances it.
///
/// Clones share one counter, so a controller holding an [`Arc`] of this clock
/// observes advances made through any handle.
#[derive(Clone, Debug)]
pub struct ManualClock {
    millis: Arc<AtomicU64>,
}

impl ManualClock {
    /// Creates a clock pinned at `millis`.
    #[must_use]
    pub fn new(millis: u64) -> Self {
        Self {
            millis: Arc::new(AtomicU64::new(millis)),
        }
    }

    /// Advances the clock and returns the new value, saturating at [`u64::MAX`].
    #[expect(
        clippy::must_use_candidate,
        reason = "advancing the shared counter is the point of the call; the new instant is a \
                  convenience that callers who only need to move time legitimately drop"
    )]
    pub fn advance(&self, millis: u64) -> u64 {
        let mut current = self.millis.load(Ordering::SeqCst);
        loop {
            let next = current.saturating_add(millis);
            match self.millis.compare_exchange_weak(
                current,
                next,
                Ordering::SeqCst,
                Ordering::SeqCst,
            ) {
                Ok(_) => return next,
                Err(observed) => current = observed,
            }
        }
    }

    /// Moves the clock to an exact instant, which may be earlier than the
    /// current one.
    ///
    /// Rewinding is deliberately expressible: a host whose clock steps
    /// backwards is a real condition the admission controller has to survive.
    pub fn set(&self, millis: u64) {
        self.millis.store(millis, Ordering::SeqCst);
    }
}

impl Clock for ManualClock {
    fn unix_millis(&self) -> u64 {
        self.millis.load(Ordering::SeqCst)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn manual_clock_reports_exactly_what_was_set_and_advanced() {
        let clock = ManualClock::new(1_700_000_000_000);
        assert_eq!(clock.unix_millis(), 1_700_000_000_000);
        assert_eq!(clock.advance(2_500), 1_700_000_002_500);
        assert_eq!(clock.unix_millis(), 1_700_000_002_500);
    }

    #[test]
    fn manual_clock_shares_one_counter_across_clones() {
        let clock = ManualClock::new(10);
        let clone = clock.clone();
        clone.advance(5);
        assert_eq!(clock.unix_millis(), 15);
    }

    #[test]
    fn manual_clock_saturates_instead_of_wrapping_back_into_validity() {
        let clock = ManualClock::new(u64::MAX - 1);
        assert_eq!(clock.advance(1_000), u64::MAX);
        assert_eq!(clock.unix_millis(), u64::MAX);
    }

    #[test]
    fn manual_clock_can_be_rewound_to_an_exact_instant() {
        let clock = ManualClock::new(1_000);
        clock.set(400);
        assert_eq!(clock.unix_millis(), 400);
    }

    #[test]
    fn system_clock_is_after_the_2020_epoch() {
        assert!(SystemClock.unix_millis() > 1_577_836_800_000);
    }
}

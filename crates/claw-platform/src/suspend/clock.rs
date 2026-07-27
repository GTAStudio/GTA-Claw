//! The millisecond clock behind every suspension deadline.
//!
//! Lease expiry is a deadline, and a deadline tested with a real sleep is a
//! flaky test. Time is therefore a port: production wires [`SystemClock`] and
//! tests wire [`ManualClock`], which only moves when a test moves it.

use std::fmt::Debug;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

/// Supplies Unix wall-clock milliseconds to the suspension coordinator.
pub trait Clock: Debug + Send + Sync {
    /// Returns the current Unix time in milliseconds.
    fn now_ms(&self) -> u64;
}

/// The process wall clock.
#[derive(Clone, Copy, Debug, Default)]
pub struct SystemClock;

impl Clock for SystemClock {
    fn now_ms(&self) -> u64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_or(0, |elapsed| {
                u64::try_from(elapsed.as_millis()).unwrap_or(u64::MAX)
            })
    }
}

/// A clock whose value only changes when a test advances it.
///
/// Clones share one reading, so a test can hand one clone to the coordinator
/// and keep another to drive time forward.
#[derive(Clone, Debug, Default)]
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

    /// Advances the clock and returns the new reading.
    pub fn advance(&self, millis: u64) -> u64 {
        self.millis.fetch_add(millis, Ordering::SeqCst) + millis
    }

    /// Pins the clock to `millis`.
    pub fn set(&self, millis: u64) {
        self.millis.store(millis, Ordering::SeqCst);
    }
}

impl Clock for ManualClock {
    fn now_ms(&self) -> u64 {
        self.millis.load(Ordering::SeqCst)
    }
}

#[cfg(test)]
mod tests {
    use super::{Clock, ManualClock, SystemClock};

    #[test]
    fn manual_clock_reports_exactly_what_was_set_and_advanced() {
        let clock = ManualClock::new(1_700_000_000_000);

        assert_eq!(clock.now_ms(), 1_700_000_000_000);
        assert_eq!(clock.advance(2_500), 1_700_000_002_500);
        assert_eq!(clock.now_ms(), 1_700_000_002_500);

        clock.set(7);

        assert_eq!(clock.now_ms(), 7);
    }

    #[test]
    fn manual_clock_clones_share_one_reading() {
        let clock = ManualClock::new(10);
        let clone = clock.clone();

        clone.advance(5);

        assert_eq!(clock.now_ms(), 15);
    }

    #[test]
    fn system_clock_is_after_the_2020_epoch() {
        assert!(SystemClock.now_ms() > 1_577_836_800_000);
    }
}

//! Trusted time source consulted by every permission decision.
//!
//! A timestamp captured once and reused for a whole invocation is a permission
//! bypass: a tool that reaches a second resource minutes later would be judged
//! against the moment it started, so an expiring grant would never expire while
//! anything was in flight. Time is therefore a *port*, not a value, and the
//! authorization gate reads it again for every resource it evaluates.
//!
//! [`MonotonicClock`] additionally refuses to let observed time move backwards,
//! so a host whose wall clock is stepped backwards, deliberately or otherwise,
//! cannot resurrect an already-expired grant.

use std::fmt::Debug;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

/// Source of the current Unix time in milliseconds.
///
/// Implementations must be cheap: the gate calls this on every authorization,
/// including every redirect hop.
pub trait Clock: Debug {
    /// Returns the current Unix time in milliseconds.
    fn unix_millis(&self) -> u64;
}

impl<T: Clock + ?Sized> Clock for &T {
    fn unix_millis(&self) -> u64 {
        (**self).unix_millis()
    }
}

/// Clock backed by the host wall clock.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct SystemClock;

impl SystemClock {
    /// Creates the host clock.
    #[must_use]
    pub const fn new() -> Self {
        Self
    }
}

impl Clock for SystemClock {
    fn unix_millis(&self) -> u64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .ok()
            .and_then(|elapsed| u64::try_from(elapsed.as_millis()).ok())
            // A host clock set before 1970 must not read as "no time at all",
            // which would make every expiry check trivially pass.
            .unwrap_or(u64::MAX)
    }
}

/// Clock that never reports an earlier instant than it already reported.
///
/// Wrapping the host clock means a backwards step cannot revive a grant that
/// has already been observed as expired.
#[derive(Debug)]
pub struct MonotonicClock<C: Clock> {
    inner: C,
    floor: AtomicU64,
}

impl<C: Clock> MonotonicClock<C> {
    /// Wraps another clock.
    #[must_use]
    pub const fn new(inner: C) -> Self {
        Self {
            inner,
            floor: AtomicU64::new(0),
        }
    }

    /// Returns the highest instant observed so far.
    #[must_use]
    pub fn high_water_mark(&self) -> u64 {
        self.floor.load(Ordering::SeqCst)
    }
}

impl<C: Clock> Clock for MonotonicClock<C> {
    fn unix_millis(&self) -> u64 {
        let observed = self.inner.unix_millis();
        let previous = self.floor.fetch_max(observed, Ordering::SeqCst);
        previous.max(observed)
    }
}

/// Clock whose value is set by the caller.
///
/// It exists so tests can move time deliberately instead of sleeping, and so a
/// host that already tracks its own time can supply it.
#[derive(Debug)]
pub struct FixedClock {
    millis: AtomicU64,
}

impl FixedClock {
    /// Creates a clock reading `millis`.
    #[must_use]
    pub const fn new(millis: u64) -> Self {
        Self {
            millis: AtomicU64::new(millis),
        }
    }

    /// Replaces the reported instant.
    pub fn set(&self, millis: u64) {
        self.millis.store(millis, Ordering::SeqCst);
    }

    /// Moves the reported instant forward, saturating at the maximum.
    pub fn advance(&self, millis: u64) {
        let _ = self
            .millis
            .fetch_update(Ordering::SeqCst, Ordering::SeqCst, |current| {
                Some(current.saturating_add(millis))
            });
    }
}

impl Clock for FixedClock {
    fn unix_millis(&self) -> u64 {
        self.millis.load(Ordering::SeqCst)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[derive(Debug)]
    struct ScriptedClock {
        readings: std::sync::Mutex<Vec<u64>>,
    }

    impl Clock for ScriptedClock {
        fn unix_millis(&self) -> u64 {
            let mut readings = self.readings.lock().expect("the scripted clock is intact");
            if readings.is_empty() {
                return 0;
            }
            readings.remove(0)
        }
    }

    #[test]
    fn a_fixed_clock_reports_exactly_what_was_set() {
        let clock = FixedClock::new(1_700_000_000_000);
        assert_eq!(clock.unix_millis(), 1_700_000_000_000);
        clock.set(42);
        assert_eq!(clock.unix_millis(), 42);
        clock.advance(8);
        assert_eq!(clock.unix_millis(), 50);
    }

    #[test]
    fn advancing_a_fixed_clock_saturates_instead_of_wrapping() {
        let clock = FixedClock::new(u64::MAX - 1);
        clock.advance(1_000);
        assert_eq!(clock.unix_millis(), u64::MAX);
    }

    #[test]
    fn a_monotonic_clock_refuses_a_backwards_step() {
        let scripted = ScriptedClock {
            readings: std::sync::Mutex::new(vec![5_000, 4_000, 4_500, 6_000]),
        };
        let clock = MonotonicClock::new(scripted);
        assert_eq!(clock.unix_millis(), 5_000);
        assert_eq!(clock.unix_millis(), 5_000);
        assert_eq!(clock.unix_millis(), 5_000);
        assert_eq!(clock.unix_millis(), 6_000);
        assert_eq!(clock.high_water_mark(), 6_000);
    }

    #[test]
    fn the_system_clock_is_after_the_2024_epoch_and_moves_forward() {
        let clock = SystemClock::new();
        let first = clock.unix_millis();
        assert!(first > 1_704_067_200_000, "observed {first}");
        assert!(first < u64::MAX);
        std::thread::sleep(std::time::Duration::from_millis(5));
        assert!(clock.unix_millis() >= first);
    }
}

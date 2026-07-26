//! Time as a port, so every deadline in the composition can be driven by tests.

use std::fmt::{self, Debug, Display, Formatter};
use std::sync::OnceLock;
use std::time::{Duration, Instant};

/// A point on a monotonic timeline, measured from an unspecified origin.
///
/// This is deliberately not [`std::time::SystemTime`]: expiry decisions must not
/// move when the wall clock is adjusted. It is also not [`std::time::Instant`],
/// because that cannot be constructed at an arbitrary offset and so cannot be
/// faked in a test.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct MonotonicInstant(Duration);

impl MonotonicInstant {
    /// The origin of the timeline.
    pub const ORIGIN: Self = Self(Duration::ZERO);

    /// Creates an instant `millis` milliseconds after the origin.
    #[must_use]
    pub const fn from_millis(millis: u64) -> Self {
        Self(Duration::from_millis(millis))
    }

    /// Creates an instant `elapsed` after the origin.
    #[must_use]
    pub const fn from_origin(elapsed: Duration) -> Self {
        Self(elapsed)
    }

    /// Returns the offset from the origin.
    #[must_use]
    pub const fn since_origin(self) -> Duration {
        self.0
    }

    /// Returns the instant `span` later, or `None` on overflow.
    #[must_use]
    pub fn checked_add(self, span: Duration) -> Option<Self> {
        self.0.checked_add(span).map(Self)
    }

    /// Returns how much later `self` is than `earlier`, saturating at zero.
    #[must_use]
    pub fn saturating_since(self, earlier: Self) -> Duration {
        self.0.saturating_sub(earlier.0)
    }
}

impl Display for MonotonicInstant {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        write!(formatter, "+{}ms", self.0.as_millis())
    }
}

/// Reads the monotonic timeline.
///
/// Implementations must be cheap and must never block: the composition calls
/// [`Clock::now`] on every authorization decision precisely so that no decision
/// is ever made against a stale reading.
pub trait Clock: Send + Sync + 'static {
    /// Returns the current instant.
    fn now(&self) -> MonotonicInstant;
}

impl Debug for dyn Clock {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter.write_str("Clock")
    }
}

/// A [`Clock`] backed by [`std::time::Instant`], anchored the first time it is
/// read anywhere in the process.
///
/// Anchoring is process-wide, so two `ProcessClock` values agree with each
/// other and instants taken from one are comparable with the other.
#[derive(Clone, Copy, Debug, Default)]
pub struct ProcessClock;

impl Clock for ProcessClock {
    fn now(&self) -> MonotonicInstant {
        static ORIGIN: OnceLock<Instant> = OnceLock::new();

        MonotonicInstant::from_origin(ORIGIN.get_or_init(Instant::now).elapsed())
    }
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use super::{Clock, MonotonicInstant, ProcessClock};

    #[test]
    fn instants_order_by_their_offset_from_the_origin() {
        let earlier = MonotonicInstant::from_millis(10);
        let later = MonotonicInstant::from_millis(11);

        assert!(later > earlier);
        assert_eq!(later.saturating_since(earlier), Duration::from_millis(1));
    }

    #[test]
    fn subtracting_a_later_instant_saturates_instead_of_wrapping() {
        let earlier = MonotonicInstant::from_millis(10);
        let later = MonotonicInstant::from_millis(40);

        assert_eq!(earlier.saturating_since(later), Duration::ZERO);
    }

    #[test]
    fn adding_a_span_moves_forward_by_exactly_that_span() {
        let start = MonotonicInstant::from_millis(1_000);

        assert_eq!(
            start
                .checked_add(Duration::from_millis(250))
                .expect("no overflow"),
            MonotonicInstant::from_millis(1_250)
        );
    }

    #[test]
    fn adding_a_span_that_overflows_reports_none_rather_than_wrapping() {
        let start = MonotonicInstant::from_origin(Duration::new(u64::MAX, 0));

        assert_eq!(start.checked_add(Duration::from_secs(1)), None);
    }

    #[test]
    fn the_origin_is_the_zero_offset() {
        assert_eq!(MonotonicInstant::ORIGIN.since_origin(), Duration::ZERO);
        assert_eq!(MonotonicInstant::ORIGIN.to_string(), "+0ms");
        assert_eq!(MonotonicInstant::from_millis(1_500).to_string(), "+1500ms");
    }

    #[test]
    fn the_process_clock_never_moves_backwards() {
        let clock = ProcessClock;
        let first = clock.now();
        let second = clock.now();
        let third = ProcessClock.now();

        assert!(second >= first);
        assert!(third >= second);
    }
}

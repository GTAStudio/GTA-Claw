//! Clock-independent time values used by application ports.

use std::fmt::{self, Display, Formatter};
use std::time::Duration;

use serde::{Deserialize, Serialize};

/// A wall-clock instant expressed as milliseconds since the Unix epoch.
#[derive(
    Clone, Copy, Debug, Default, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize,
)]
#[serde(transparent)]
pub struct Timestamp(i64);

impl Timestamp {
    /// The Unix epoch.
    pub const EPOCH: Self = Self(0);

    /// Creates a timestamp from milliseconds since the Unix epoch.
    #[must_use]
    pub const fn from_millis(millis: i64) -> Self {
        Self(millis)
    }

    /// Returns milliseconds since the Unix epoch.
    #[must_use]
    pub const fn as_millis(self) -> i64 {
        self.0
    }

    /// Returns this instant advanced by `duration`, or `None` on overflow.
    #[must_use]
    pub fn checked_add(self, duration: Duration) -> Option<Self> {
        let millis = i64::try_from(duration.as_millis()).ok()?;
        self.0.checked_add(millis).map(Self)
    }

    /// Returns the duration from `self` to `later`, or `None` when `later` precedes `self`.
    #[must_use]
    pub fn duration_until(self, later: Self) -> Option<Duration> {
        let delta = later.0.checked_sub(self.0)?;
        u64::try_from(delta).ok().map(Duration::from_millis)
    }
}

impl Display for Timestamp {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        write!(formatter, "{}ms", self.0)
    }
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use super::Timestamp;

    #[test]
    fn timestamps_advance_by_duration() {
        let start = Timestamp::from_millis(1_000);

        assert_eq!(
            start.checked_add(Duration::from_millis(250)),
            Some(Timestamp::from_millis(1_250))
        );
    }

    #[test]
    fn timestamp_addition_detects_overflow() {
        let start = Timestamp::from_millis(i64::MAX);

        assert_eq!(start.checked_add(Duration::from_millis(1)), None);
        assert_eq!(Timestamp::EPOCH.checked_add(Duration::MAX), None);
    }

    #[test]
    fn duration_until_rejects_reversed_order() {
        let earlier = Timestamp::from_millis(10);
        let later = Timestamp::from_millis(40);

        assert_eq!(
            earlier.duration_until(later),
            Some(Duration::from_millis(30))
        );
        assert_eq!(later.duration_until(earlier), None);
    }

    #[test]
    fn timestamps_render_millis() {
        assert_eq!(Timestamp::from_millis(-5).to_string(), "-5ms");
    }
}

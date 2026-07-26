//! The clock port, which makes every runtime deadline testable.

use std::time::Duration;

use super::PortFuture;
use crate::model::time::Timestamp;

/// Supplies wall-clock readings and delays.
///
/// Every runtime deadline flows through this port so tests can drive time deterministically
/// instead of sleeping.
pub trait ClockPort: Send + Sync + 'static {
    /// Returns the current wall-clock instant.
    fn now(&self) -> Timestamp;

    /// Completes once `duration` of clock time has elapsed.
    fn sleep(&self, duration: Duration) -> PortFuture<'_, ()>;

    /// Completes once the clock reaches `deadline`, immediately if it already has.
    fn sleep_until(&self, deadline: Timestamp) -> PortFuture<'_, ()> {
        match self.now().duration_until(deadline) {
            Some(duration) => self.sleep(duration),
            None => Box::pin(std::future::ready(())),
        }
    }
}

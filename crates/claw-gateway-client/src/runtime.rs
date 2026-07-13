use std::future::Future;
use std::pin::Pin;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use crate::config::ReconnectPolicy;

/// Injectable clock, sleeper, and jitter source used by reconnect/authentication.
pub trait ClientRuntime: Send + Sync + 'static {
    /// Returns current Unix time in milliseconds.
    fn unix_millis(&self) -> u64;

    /// Sleeps without blocking the async executor.
    fn sleep(&self, duration: Duration) -> Pin<Box<dyn Future<Output = ()> + Send + 'static>>;

    /// Returns additive jitter in the inclusive range from zero through `maximum`.
    fn jitter(&self, maximum: Duration) -> Duration;

    /// Optional scheduling barrier before an authenticated application write.
    ///
    /// Production runtimes normally use the no-op default. Deterministic tests
    /// can pause the single writer without mocking the WebSocket transport.
    fn before_application_write(&self) -> Pin<Box<dyn Future<Output = ()> + Send + 'static>> {
        Box::pin(async {})
    }
}

/// Production runtime backed by Tokio time and a process-local jitter state.
#[derive(Debug)]
pub struct SystemRuntime {
    jitter_state: AtomicU64,
}

impl Default for SystemRuntime {
    fn default() -> Self {
        let seed = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_or(0x9e37_79b9_7f4a_7c15, |duration| {
                u64::try_from(duration.as_nanos()).unwrap_or(u64::MAX)
            });
        Self {
            jitter_state: AtomicU64::new(seed | 1),
        }
    }
}

impl ClientRuntime for SystemRuntime {
    fn unix_millis(&self) -> u64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_or(0, |duration| {
                u64::try_from(duration.as_millis()).unwrap_or(u64::MAX)
            })
    }

    fn sleep(&self, duration: Duration) -> Pin<Box<dyn Future<Output = ()> + Send + 'static>> {
        Box::pin(tokio::time::sleep(duration))
    }

    fn jitter(&self, maximum: Duration) -> Duration {
        if maximum.is_zero() {
            return Duration::ZERO;
        }
        let mut current = self.jitter_state.load(Ordering::Relaxed);
        loop {
            let mut next = current;
            next ^= next << 13;
            next ^= next >> 7;
            next ^= next << 17;
            match self.jitter_state.compare_exchange_weak(
                current,
                next,
                Ordering::Relaxed,
                Ordering::Relaxed,
            ) {
                Ok(_) => {
                    let maximum_nanos = maximum.as_nanos();
                    let nanos = u128::from(next) % maximum_nanos.saturating_add(1);
                    return duration_from_nanos(nanos);
                }
                Err(observed) => current = observed,
            }
        }
    }
}

pub(crate) fn reconnect_delay(
    policy: ReconnectPolicy,
    attempt: u32,
    runtime: &dyn ClientRuntime,
) -> Option<Duration> {
    let ReconnectPolicy::Bounded {
        max_attempts,
        initial_delay,
        max_delay,
        max_jitter,
    } = policy
    else {
        return None;
    };
    if attempt == 0 || attempt > max_attempts {
        return None;
    }
    let shift = attempt.saturating_sub(1).min(31);
    let multiplier = 1_u32 << shift;
    let base = initial_delay.saturating_mul(multiplier).min(max_delay);
    Some(base.saturating_add(runtime.jitter(max_jitter)))
}

fn duration_from_nanos(nanos: u128) -> Duration {
    let seconds = nanos / 1_000_000_000;
    let subsecond_nanos = nanos % 1_000_000_000;
    Duration::new(
        u64::try_from(seconds).unwrap_or(u64::MAX),
        u32::try_from(subsecond_nanos).expect("subsecond remainder fits u32"),
    )
}

#[cfg(test)]
mod tests {
    use std::sync::Mutex;

    use super::*;

    struct DeterministicRuntime {
        jitters: Mutex<Vec<Duration>>,
    }

    impl ClientRuntime for DeterministicRuntime {
        fn unix_millis(&self) -> u64 {
            42
        }

        fn sleep(&self, _duration: Duration) -> Pin<Box<dyn Future<Output = ()> + Send + 'static>> {
            Box::pin(async {})
        }

        fn jitter(&self, maximum: Duration) -> Duration {
            let jitter = self.jitters.lock().expect("jitter lock").remove(0);
            assert!(jitter <= maximum);
            jitter
        }
    }

    #[test]
    fn exponential_backoff_and_jitter_are_deterministic_and_bounded() {
        let runtime = DeterministicRuntime {
            jitters: Mutex::new(vec![
                Duration::from_millis(1),
                Duration::from_millis(2),
                Duration::from_millis(3),
                Duration::from_millis(4),
            ]),
        };
        let policy = ReconnectPolicy::Bounded {
            max_attempts: 4,
            initial_delay: Duration::from_millis(10),
            max_delay: Duration::from_millis(25),
            max_jitter: Duration::from_millis(5),
        };
        let actual = (1..=4)
            .map(|attempt| reconnect_delay(policy, attempt, &runtime).expect("retry"))
            .collect::<Vec<_>>();
        assert_eq!(
            actual,
            [
                Duration::from_millis(11),
                Duration::from_millis(22),
                Duration::from_millis(28),
                Duration::from_millis(29),
            ]
        );
        assert_eq!(reconnect_delay(policy, 5, &runtime), None);
        assert_eq!(reconnect_delay(ReconnectPolicy::Never, 1, &runtime), None);
    }
}

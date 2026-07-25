//! Clock and jitter ports, so reliability policies are deterministically testable.

use std::future::Future;
use std::pin::Pin;
use std::sync::Mutex;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

/// A boxed future returned by [`Clock::sleep`].
pub type SleepFuture = Pin<Box<dyn Future<Output = ()> + Send + 'static>>;

/// Time source used by retry and circuit-breaking policies.
///
/// Production code uses [`SystemClock`]. Tests use [`ManualClock`], which never
/// sleeps in real time and records every requested delay.
pub trait Clock: Send + Sync {
    /// Returns milliseconds since the Unix epoch.
    fn now_millis(&self) -> u64;

    /// Returns the current wall-clock time, used for `Retry-After` timestamps.
    fn now(&self) -> SystemTime;

    /// Waits for `duration`.
    fn sleep(&self, duration: Duration) -> SleepFuture;
}

/// The real system clock backed by `tokio::time`.
#[derive(Clone, Copy, Debug, Default)]
pub struct SystemClock;

impl Clock for SystemClock {
    fn now_millis(&self) -> u64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_or(0, |elapsed| {
                u64::try_from(elapsed.as_millis()).unwrap_or(u64::MAX)
            })
    }

    fn now(&self) -> SystemTime {
        SystemTime::now()
    }

    fn sleep(&self, duration: Duration) -> SleepFuture {
        Box::pin(tokio::time::sleep(duration))
    }
}

#[derive(Debug, Default)]
struct ManualState {
    now_millis: u64,
    sleeps: Vec<Duration>,
}

/// A virtual clock for deterministic tests.
///
/// [`ManualClock::sleep`] returns immediately but advances virtual time by the
/// requested duration and appends it to [`ManualClock::recorded_sleeps`].
#[derive(Debug, Default)]
pub struct ManualClock {
    state: Mutex<ManualState>,
}

impl ManualClock {
    /// Creates a clock positioned at `now_millis` since the Unix epoch.
    #[must_use]
    pub fn new(now_millis: u64) -> Self {
        Self {
            state: Mutex::new(ManualState {
                now_millis,
                sleeps: Vec::new(),
            }),
        }
    }

    /// Advances virtual time without recording a sleep.
    pub fn advance(&self, duration: Duration) {
        let mut state = self.state.lock().expect("manual clock mutex");
        state.now_millis = state
            .now_millis
            .saturating_add(u64::try_from(duration.as_millis()).unwrap_or(u64::MAX));
    }

    /// Returns every duration passed to [`Clock::sleep`], in call order.
    #[must_use]
    pub fn recorded_sleeps(&self) -> Vec<Duration> {
        self.state
            .lock()
            .expect("manual clock mutex")
            .sleeps
            .clone()
    }
}

impl Clock for ManualClock {
    fn now_millis(&self) -> u64 {
        self.state.lock().expect("manual clock mutex").now_millis
    }

    fn now(&self) -> SystemTime {
        UNIX_EPOCH + Duration::from_millis(self.now_millis())
    }

    fn sleep(&self, duration: Duration) -> SleepFuture {
        {
            let mut state = self.state.lock().expect("manual clock mutex");
            state.sleeps.push(duration);
            state.now_millis = state
                .now_millis
                .saturating_add(u64::try_from(duration.as_millis()).unwrap_or(u64::MAX));
        }
        Box::pin(std::future::ready(()))
    }
}

/// Source of the randomized component of exponential backoff.
pub trait JitterSource: Send + Sync {
    /// Returns a value in `[0.0, 1.0]`.
    fn next_unit_interval(&self) -> f64;
}

/// A `xorshift64*` generator, seeded once per policy instance.
///
/// This is not a cryptographic generator; it exists only to decorrelate retry
/// schedules across concurrent callers.
#[derive(Debug)]
pub struct PseudoRandomJitter {
    state: Mutex<u64>,
}

impl PseudoRandomJitter {
    /// Creates a generator from an explicit seed.
    ///
    /// A zero seed is replaced, because `xorshift64*` has a fixed point at zero.
    #[must_use]
    pub fn new(seed: u64) -> Self {
        Self {
            state: Mutex::new(if seed == 0 {
                0x9E37_79B9_7F4A_7C15
            } else {
                seed
            }),
        }
    }

    /// Creates a generator seeded from the current time and a process-wide
    /// counter, which decorrelates concurrently constructed policies.
    #[must_use]
    pub fn from_entropy() -> Self {
        use std::sync::atomic::{AtomicU64, Ordering};

        static COUNTER: AtomicU64 = AtomicU64::new(0);
        let nanos: u64 = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_or(0, |elapsed| elapsed.subsec_nanos().into());
        let millis = SystemClock.now_millis();
        let sequence = COUNTER.fetch_add(1, Ordering::Relaxed);
        Self::new(millis.rotate_left(17) ^ nanos.rotate_left(33) ^ sequence.wrapping_mul(0x9E37))
    }
}

impl JitterSource for PseudoRandomJitter {
    fn next_unit_interval(&self) -> f64 {
        let mut state = self.state.lock().expect("jitter mutex");
        let mut value = *state;
        value ^= value >> 12;
        value ^= value << 25;
        value ^= value >> 27;
        *state = value;
        let scrambled = value.wrapping_mul(0x2545_F491_4F6C_DD1D);
        // 53 bits is the exact mantissa width of f64, so the quotient is exact.
        let mantissa = scrambled >> 11;
        mantissa as f64 / ((1_u64 << 53) as f64)
    }
}

/// A jitter source that always returns the same fraction.
#[derive(Clone, Copy, Debug)]
pub struct FixedJitter(f64);

impl FixedJitter {
    /// Creates a fixed source, clamping `fraction` into `[0.0, 1.0]`.
    #[must_use]
    pub fn new(fraction: f64) -> Self {
        Self(fraction.clamp(0.0, 1.0))
    }
}

impl JitterSource for FixedJitter {
    fn next_unit_interval(&self) -> f64 {
        self.0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn manual_clock_advances_virtual_time_and_records_every_sleep() {
        let clock = ManualClock::new(1_000);
        assert_eq!(clock.now_millis(), 1_000);
        assert_eq!(clock.now(), UNIX_EPOCH + Duration::from_millis(1_000));

        clock.sleep(Duration::from_millis(250)).await;
        clock.sleep(Duration::from_secs(2)).await;
        clock.advance(Duration::from_millis(50));

        assert_eq!(
            clock.recorded_sleeps(),
            vec![Duration::from_millis(250), Duration::from_secs(2)]
        );
        assert_eq!(clock.now_millis(), 1_000 + 250 + 2_000 + 50);
    }

    #[test]
    fn system_clock_time_sources_agree() {
        let clock = SystemClock;
        let millis = clock.now_millis();
        let system = clock
            .now()
            .duration_since(UNIX_EPOCH)
            .expect("after the epoch");
        let system_millis = u64::try_from(system.as_millis()).expect("fits");
        assert!(system_millis >= millis);
        assert!(system_millis - millis < 5_000);
    }

    #[test]
    fn pseudo_random_jitter_stays_in_range_and_is_seed_reproducible() {
        let first = PseudoRandomJitter::new(0xDEAD_BEEF);
        let second = PseudoRandomJitter::new(0xDEAD_BEEF);
        let mut samples = Vec::new();
        for _ in 0..1_000 {
            let value = first.next_unit_interval();
            assert!((0.0..=1.0).contains(&value), "{value}");
            assert!((value - second.next_unit_interval()).abs() < f64::EPSILON);
            samples.push(value);
        }
        let distinct = samples
            .iter()
            .map(|value| (value * 1_000.0) as u64)
            .collect::<std::collections::BTreeSet<_>>();
        assert!(
            distinct.len() > 500,
            "generator collapsed: {}",
            distinct.len()
        );
        let mean = samples.iter().sum::<f64>() / samples.len() as f64;
        assert!((0.4..0.6).contains(&mean), "biased generator: {mean}");
    }

    #[test]
    fn zero_seed_is_replaced_so_the_generator_does_not_stall() {
        let jitter = PseudoRandomJitter::new(0);
        let first = jitter.next_unit_interval();
        let second = jitter.next_unit_interval();
        assert!((first - second).abs() > f64::EPSILON);
    }

    #[test]
    fn fixed_jitter_clamps_out_of_range_input() {
        assert!((FixedJitter::new(0.25).next_unit_interval() - 0.25).abs() < f64::EPSILON);
        assert!(FixedJitter::new(-1.0).next_unit_interval().abs() < f64::EPSILON);
        assert!((FixedJitter::new(9.0).next_unit_interval() - 1.0).abs() < f64::EPSILON);
    }
}

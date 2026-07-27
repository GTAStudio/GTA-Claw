//! Circuit breaker that stops hammering an unhealthy provider.

use std::sync::{Mutex, PoisonError};
use std::time::Duration;

use crate::error::{ErrorKind, Operation, ProviderError};

/// Circuit-breaker configuration.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CircuitBreakerConfig {
    /// Consecutive tripping failures that open the circuit.
    pub failure_threshold: u32,
    /// How long the circuit stays open before a probe is allowed.
    pub open_duration: Duration,
    /// Number of probe calls admitted while half-open.
    pub half_open_probes: u32,
    /// Consecutive probe successes required to close the circuit again.
    pub success_threshold: u32,
}

impl Default for CircuitBreakerConfig {
    fn default() -> Self {
        Self {
            failure_threshold: 5,
            open_duration: Duration::from_secs(30),
            half_open_probes: 1,
            success_threshold: 1,
        }
    }
}

/// Observable state of a [`CircuitBreaker`].
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CircuitState {
    /// Requests flow normally.
    Closed,
    /// Requests are rejected until the open window elapses.
    Open,
    /// A limited number of probe requests are admitted.
    HalfOpen,
}

#[derive(Debug)]
struct BreakerState {
    state: CircuitState,
    consecutive_failures: u32,
    consecutive_successes: u32,
    opened_at_millis: u64,
    probes_in_flight: u32,
}

/// A per-provider circuit breaker.
///
/// The breaker is driven by an explicit millisecond timestamp so that tests can
/// exercise the recovery schedule with [`crate::clock::ManualClock`] instead of
/// real time.
#[derive(Debug)]
pub struct CircuitBreaker {
    provider: String,
    config: CircuitBreakerConfig,
    inner: Mutex<BreakerState>,
}

impl CircuitBreaker {
    /// Creates a closed breaker for `provider`.
    #[must_use]
    pub fn new(provider: impl Into<String>, config: CircuitBreakerConfig) -> Self {
        Self {
            provider: provider.into(),
            config,
            inner: Mutex::new(BreakerState {
                state: CircuitState::Closed,
                consecutive_failures: 0,
                consecutive_successes: 0,
                opened_at_millis: 0,
                probes_in_flight: 0,
            }),
        }
    }

    /// Returns the state the breaker would report at `now_millis`.
    #[must_use]
    pub fn state(&self, now_millis: u64) -> CircuitState {
        let mut inner = self.lock();
        Self::refresh(&mut inner, &self.config, now_millis);
        inner.state
    }

    /// Asks permission to issue a request.
    ///
    /// # Errors
    ///
    /// Returns an [`ErrorKind::CircuitOpen`] error while the circuit is open, or
    /// while the half-open probe budget is already in use.
    pub fn acquire(
        &self,
        operation: Operation,
        now_millis: u64,
    ) -> Result<CircuitPermit<'_>, ProviderError> {
        let mut inner = self.lock();
        Self::refresh(&mut inner, &self.config, now_millis);
        let admitted = match inner.state {
            CircuitState::Closed => Ok(()),
            CircuitState::HalfOpen => {
                if inner.probes_in_flight >= self.config.half_open_probes {
                    Err("half-open probe budget exhausted")
                } else {
                    inner.probes_in_flight += 1;
                    Ok(())
                }
            }
            CircuitState::Open => Err("circuit is open after repeated failures"),
        };
        // The error is built outside the critical section: allocating and
        // sanitizing a `ProviderError` under the breaker lock would serialize
        // every caller of an unhealthy provider behind that allocation, which is
        // exactly when the most callers arrive.
        drop(inner);
        match admitted {
            Ok(()) => Ok(CircuitPermit { breaker: self }),
            Err(detail) => Err(self.rejection(operation, detail)),
        }
    }

    /// Records a successful call.
    pub fn record_success(&self, now_millis: u64) {
        let mut inner = self.lock();
        inner.consecutive_failures = 0;
        inner.probes_in_flight = inner.probes_in_flight.saturating_sub(1);
        match inner.state {
            CircuitState::HalfOpen => {
                inner.consecutive_successes += 1;
                if inner.consecutive_successes >= self.config.success_threshold {
                    inner.state = CircuitState::Closed;
                    inner.consecutive_successes = 0;
                    inner.probes_in_flight = 0;
                }
            }
            CircuitState::Closed => inner.consecutive_successes = 0,
            CircuitState::Open => {
                // A late success from a request issued before the trip does not
                // reopen the gate; the open window still has to elapse.
                let _ = now_millis;
            }
        }
    }

    /// Records a failure, opening the circuit once the threshold is crossed.
    ///
    /// Only failures for which [`ErrorKind::trips_circuit`] holds affect the
    /// breaker; client-side mistakes are ignored.
    pub fn record_failure(&self, kind: ErrorKind, now_millis: u64) {
        let mut inner = self.lock();
        inner.probes_in_flight = inner.probes_in_flight.saturating_sub(1);
        if !kind.trips_circuit() {
            return;
        }
        inner.consecutive_successes = 0;
        match inner.state {
            CircuitState::HalfOpen => {
                inner.state = CircuitState::Open;
                inner.opened_at_millis = now_millis;
                inner.probes_in_flight = 0;
            }
            CircuitState::Closed => {
                inner.consecutive_failures += 1;
                if inner.consecutive_failures >= self.config.failure_threshold {
                    inner.state = CircuitState::Open;
                    inner.opened_at_millis = now_millis;
                    inner.consecutive_failures = 0;
                }
            }
            CircuitState::Open => inner.opened_at_millis = now_millis,
        }
    }

    /// Locks the breaker, recovering from a poisoned mutex.
    ///
    /// Nothing inside a critical section can panic, so poisoning can only come
    /// from a panic elsewhere in the process. Refusing to serve every later
    /// request because of that would turn one unrelated panic into a permanent
    /// provider outage.
    fn lock(&self) -> std::sync::MutexGuard<'_, BreakerState> {
        self.inner.lock().unwrap_or_else(PoisonError::into_inner)
    }

    fn rejection(&self, operation: Operation, detail: &str) -> ProviderError {
        ProviderError::new(ErrorKind::CircuitOpen, &self.provider, operation, detail)
    }

    fn refresh(inner: &mut BreakerState, config: &CircuitBreakerConfig, now_millis: u64) {
        if inner.state == CircuitState::Open {
            let elapsed = now_millis.saturating_sub(inner.opened_at_millis);
            let window = u64::try_from(config.open_duration.as_millis()).unwrap_or(u64::MAX);
            if elapsed >= window {
                inner.state = CircuitState::HalfOpen;
                inner.probes_in_flight = 0;
                inner.consecutive_successes = 0;
            }
        }
    }
}

/// Proof that the circuit admitted one call.
///
/// The permit exists to make the admit/report pairing explicit at call sites; it
/// carries no drop behaviour, because success and failure must be reported
/// distinctly.
#[derive(Debug)]
pub struct CircuitPermit<'a> {
    breaker: &'a CircuitBreaker,
}

impl CircuitPermit<'_> {
    /// Reports a successful call.
    pub fn success(self, now_millis: u64) {
        self.breaker.record_success(now_millis);
    }

    /// Reports a failed call.
    pub fn failure(self, kind: ErrorKind, now_millis: u64) {
        self.breaker.record_failure(kind, now_millis);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn breaker() -> CircuitBreaker {
        CircuitBreaker::new(
            "openai",
            CircuitBreakerConfig {
                failure_threshold: 3,
                open_duration: Duration::from_secs(1),
                half_open_probes: 1,
                success_threshold: 2,
            },
        )
    }

    #[test]
    fn circuit_opens_only_after_the_configured_consecutive_failures() {
        let breaker = breaker();
        for step in 0..2 {
            let permit = breaker.acquire(Operation::Complete, step).expect("closed");
            permit.failure(ErrorKind::Server, step);
            assert_eq!(breaker.state(step), CircuitState::Closed);
        }
        let permit = breaker.acquire(Operation::Complete, 2).expect("closed");
        permit.failure(ErrorKind::Server, 2);
        assert_eq!(breaker.state(2), CircuitState::Open);

        let error = breaker
            .acquire(Operation::Complete, 3)
            .expect_err("open circuit rejects");
        assert_eq!(error.kind(), ErrorKind::CircuitOpen);
        assert_eq!(error.provider(), "openai");
        assert_eq!(error.detail(), "circuit is open after repeated failures");
    }

    #[test]
    fn a_success_resets_the_consecutive_failure_counter() {
        let breaker = breaker();
        breaker.record_failure(ErrorKind::Server, 0);
        breaker.record_failure(ErrorKind::Server, 1);
        breaker.record_success(2);
        breaker.record_failure(ErrorKind::Server, 3);
        breaker.record_failure(ErrorKind::Server, 4);
        assert_eq!(breaker.state(4), CircuitState::Closed);
        breaker.record_failure(ErrorKind::Server, 5);
        assert_eq!(breaker.state(5), CircuitState::Open);
    }

    #[test]
    fn non_tripping_failures_never_open_the_circuit() {
        let breaker = breaker();
        for kind in [
            ErrorKind::Authentication,
            ErrorKind::RateLimit,
            ErrorKind::Quota,
            ErrorKind::InvalidRequest,
            ErrorKind::Cancelled,
            ErrorKind::CircuitOpen,
            ErrorKind::Unsupported,
        ] {
            for step in 0..10 {
                breaker.record_failure(kind, step);
            }
            assert_eq!(breaker.state(10), CircuitState::Closed, "{kind}");
        }
    }

    #[test]
    fn open_circuit_becomes_half_open_exactly_at_the_window_boundary() {
        let breaker = breaker();
        for step in 0..3 {
            breaker.record_failure(ErrorKind::Transport, step);
        }
        assert_eq!(breaker.state(2), CircuitState::Open);
        assert_eq!(breaker.state(1_001), CircuitState::Open);
        assert_eq!(breaker.state(1_002), CircuitState::HalfOpen);
    }

    #[test]
    fn half_open_admits_only_the_configured_probe_budget() {
        let breaker = breaker();
        for step in 0..3 {
            breaker.record_failure(ErrorKind::Transport, step);
        }
        let first = breaker
            .acquire(Operation::Complete, 1_002)
            .expect("half-open probe");
        let error = breaker
            .acquire(Operation::Complete, 1_003)
            .expect_err("second probe is refused");
        assert_eq!(error.kind(), ErrorKind::CircuitOpen);
        assert_eq!(error.detail(), "half-open probe budget exhausted");
        first.success(1_004);
    }

    #[test]
    fn half_open_needs_the_full_success_threshold_before_closing() {
        let breaker = breaker();
        for step in 0..3 {
            breaker.record_failure(ErrorKind::Transport, step);
        }
        let probe = breaker.acquire(Operation::Complete, 1_002).expect("probe");
        probe.success(1_002);
        assert_eq!(breaker.state(1_002), CircuitState::HalfOpen);

        let probe = breaker.acquire(Operation::Complete, 1_003).expect("probe");
        probe.success(1_003);
        assert_eq!(breaker.state(1_003), CircuitState::Closed);
    }

    #[test]
    fn a_failed_probe_reopens_the_circuit_for_a_fresh_window() {
        let breaker = breaker();
        for step in 0..3 {
            breaker.record_failure(ErrorKind::Transport, step);
        }
        let probe = breaker.acquire(Operation::Complete, 1_002).expect("probe");
        probe.failure(ErrorKind::Server, 1_002);
        assert_eq!(breaker.state(1_002), CircuitState::Open);
        assert_eq!(breaker.state(2_001), CircuitState::Open);
        assert_eq!(breaker.state(2_002), CircuitState::HalfOpen);
    }
}

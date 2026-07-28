//! Circuit breaker that stops hammering an unhealthy provider.

use std::sync::{Arc, Mutex, PoisonError};
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
    probe_epoch: u64,
}

#[derive(Clone, Copy, Debug)]
struct PermitAdmission {
    probe: bool,
    probe_epoch: u64,
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
                probe_epoch: 0,
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
        let probe = self.admit(operation, now_millis)?;
        Ok(CircuitPermit {
            breaker: self,
            admission: probe,
            reported: false,
        })
    }

    /// Asks permission to issue a request and returns an owned permit.
    ///
    /// Owned permits can travel with a streaming body and report its terminal
    /// outcome after the call that opened it has returned.
    ///
    /// # Errors
    ///
    /// Returns the same rejection as [`CircuitBreaker::acquire`].
    pub fn acquire_owned(
        self: &Arc<Self>,
        operation: Operation,
        now_millis: u64,
    ) -> Result<OwnedCircuitPermit, ProviderError> {
        let probe = self.admit(operation, now_millis)?;
        Ok(OwnedCircuitPermit {
            breaker: Arc::clone(self),
            admission: probe,
            reported: false,
        })
    }

    fn admit(
        &self,
        operation: Operation,
        now_millis: u64,
    ) -> Result<PermitAdmission, ProviderError> {
        let mut inner = self.lock();
        Self::refresh(&mut inner, &self.config, now_millis);
        let admitted = match inner.state {
            CircuitState::Closed => Ok(PermitAdmission {
                probe: false,
                probe_epoch: inner.probe_epoch,
            }),
            CircuitState::HalfOpen => {
                if inner.probes_in_flight >= self.config.half_open_probes {
                    Err("half-open probe budget exhausted")
                } else {
                    inner.probes_in_flight += 1;
                    Ok(PermitAdmission {
                        probe: true,
                        probe_epoch: inner.probe_epoch,
                    })
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
            Ok(probe) => Ok(probe),
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

    fn permit_success(&self, admission: PermitAdmission, now_millis: u64) {
        let mut inner = self.lock();
        if admission.probe
            && inner.state == CircuitState::HalfOpen
            && inner.probe_epoch == admission.probe_epoch
        {
            inner.probes_in_flight = inner.probes_in_flight.saturating_sub(1);
            inner.consecutive_failures = 0;
            inner.consecutive_successes = inner.consecutive_successes.saturating_add(1);
            if inner.consecutive_successes >= self.config.success_threshold {
                inner.state = CircuitState::Closed;
                inner.consecutive_successes = 0;
                inner.probes_in_flight = 0;
            }
        } else if !admission.probe
            && inner.state == CircuitState::Closed
            && inner.probe_epoch == admission.probe_epoch
        {
            inner.consecutive_failures = 0;
            inner.consecutive_successes = 0;
        } else {
            // A result admitted in an older state cannot participate in the
            // current half-open recovery epoch.
            let _ = now_millis;
        }
    }

    fn permit_failure(&self, admission: PermitAdmission, kind: ErrorKind, now_millis: u64) {
        let mut inner = self.lock();
        if admission.probe {
            if inner.state != CircuitState::HalfOpen || inner.probe_epoch != admission.probe_epoch {
                return;
            }
            inner.probes_in_flight = inner.probes_in_flight.saturating_sub(1);
            if !kind.trips_circuit() {
                return;
            }
            inner.consecutive_successes = 0;
            inner.state = CircuitState::Open;
            inner.opened_at_millis = now_millis;
            inner.probes_in_flight = 0;
            return;
        }

        if inner.state != CircuitState::Closed
            || inner.probe_epoch != admission.probe_epoch
            || !kind.trips_circuit()
        {
            return;
        }
        inner.consecutive_successes = 0;
        inner.consecutive_failures = inner.consecutive_failures.saturating_add(1);
        if inner.consecutive_failures >= self.config.failure_threshold {
            inner.state = CircuitState::Open;
            inner.opened_at_millis = now_millis;
            inner.consecutive_failures = 0;
        }
    }

    fn abandon_probe(&self, admission: PermitAdmission) {
        let mut inner = self.lock();
        if admission.probe
            && inner.state == CircuitState::HalfOpen
            && inner.probe_epoch == admission.probe_epoch
        {
            inner.probes_in_flight = inner.probes_in_flight.saturating_sub(1);
        }
    }

    fn refresh(inner: &mut BreakerState, config: &CircuitBreakerConfig, now_millis: u64) {
        if inner.state == CircuitState::Open {
            let elapsed = now_millis.saturating_sub(inner.opened_at_millis);
            let window = u64::try_from(config.open_duration.as_millis()).unwrap_or(u64::MAX);
            if elapsed >= window {
                inner.state = CircuitState::HalfOpen;
                inner.probes_in_flight = 0;
                inner.consecutive_successes = 0;
                inner.probe_epoch = inner.probe_epoch.saturating_add(1);
            }
        }
    }
}

/// Proof that the circuit admitted one call.
///
/// The permit exists to make the admit/report pairing explicit at call sites; it
#[derive(Debug)]
pub struct CircuitPermit<'a> {
    breaker: &'a CircuitBreaker,
    admission: PermitAdmission,
    reported: bool,
}

impl CircuitPermit<'_> {
    /// Reports a successful call.
    pub fn success(mut self, now_millis: u64) {
        self.reported = true;
        self.breaker.permit_success(self.admission, now_millis);
    }

    /// Reports a failed call.
    pub fn failure(mut self, kind: ErrorKind, now_millis: u64) {
        self.reported = true;
        self.breaker
            .permit_failure(self.admission, kind, now_millis);
    }
}

impl Drop for CircuitPermit<'_> {
    fn drop(&mut self) {
        if !self.reported {
            self.breaker.abandon_probe(self.admission);
        }
    }
}

/// Owned proof that a circuit admitted one potentially long-lived call.
#[derive(Debug)]
pub struct OwnedCircuitPermit {
    breaker: Arc<CircuitBreaker>,
    admission: PermitAdmission,
    reported: bool,
}

impl OwnedCircuitPermit {
    /// Reports a successful call.
    pub fn success(mut self, now_millis: u64) {
        self.reported = true;
        self.breaker.permit_success(self.admission, now_millis);
    }

    /// Reports a failed call.
    pub fn failure(mut self, kind: ErrorKind, now_millis: u64) {
        self.reported = true;
        self.breaker
            .permit_failure(self.admission, kind, now_millis);
    }
}

impl Drop for OwnedCircuitPermit {
    fn drop(&mut self) {
        if !self.reported {
            self.breaker.abandon_probe(self.admission);
        }
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
    fn dropping_an_unreported_half_open_probe_releases_the_budget() {
        let breaker = breaker();
        for step in 0..3 {
            breaker.record_failure(ErrorKind::Transport, step);
        }
        let probe = breaker.acquire(Operation::Ping, 1_002).expect("probe");
        assert!(
            breaker.acquire(Operation::Ping, 1_002).is_err(),
            "the only probe slot is held"
        );
        drop(probe);
        assert!(
            breaker.acquire(Operation::Ping, 1_002).is_ok(),
            "abandoning a probe must not wedge half-open recovery"
        );
    }

    #[test]
    fn a_stale_closed_call_cannot_complete_a_half_open_probe() {
        let breaker = CircuitBreaker::new(
            "openai",
            CircuitBreakerConfig {
                failure_threshold: 1,
                open_duration: Duration::from_secs(1),
                half_open_probes: 1,
                success_threshold: 1,
            },
        );
        let stale = breaker
            .acquire(Operation::StreamCompletion, 0)
            .expect("admitted while closed");
        let stale_failure = breaker
            .acquire(Operation::Complete, 0)
            .expect("also admitted before the outage");
        breaker.record_failure(ErrorKind::Server, 0);
        assert_eq!(breaker.state(0), CircuitState::Open);

        assert_eq!(breaker.state(1_000), CircuitState::HalfOpen);
        let probe = breaker.acquire(Operation::Ping, 1_000).expect("real probe");
        stale.success(1_000);
        assert_eq!(
            breaker.state(1_000),
            CircuitState::HalfOpen,
            "the pre-outage stream is not the recovery probe"
        );
        assert!(
            breaker.acquire(Operation::Ping, 1_000).is_err(),
            "the real probe still owns the only probe slot"
        );

        probe.success(1_001);
        assert_eq!(breaker.state(1_001), CircuitState::Closed);
        stale_failure.failure(ErrorKind::Server, 1_002);
        assert_eq!(
            breaker.state(1_002),
            CircuitState::Closed,
            "a pre-outage failure cannot reopen a recovered circuit"
        );
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

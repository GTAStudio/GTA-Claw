//! Retry policy with exponential backoff, jitter and `Retry-After` support.

use std::future::Future;
use std::time::Duration;

use crate::cancel::CancelToken;
use crate::clock::{Clock, JitterSource};
use crate::error::{ErrorKind, Operation, ProviderError};

/// How the randomized component of a backoff delay is applied.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum JitterMode {
    /// Use the exact exponential delay with no randomization.
    None,
    /// Sample uniformly from `[0, delay]` (AWS "full jitter").
    Full,
    /// Sample uniformly from `[delay / 2, delay]` (AWS "equal jitter").
    Equal,
}

/// Bounded exponential-backoff configuration.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RetryPolicy {
    /// Total number of attempts, including the first one. Must be at least 1.
    pub max_attempts: u32,
    /// Delay before the second attempt.
    pub initial_backoff: Duration,
    /// Upper bound applied to the computed exponential delay.
    pub max_backoff: Duration,
    /// Growth factor per attempt, expressed in hundredths (200 means 2.0x).
    pub multiplier_centi: u32,
    /// Randomization applied on top of the exponential delay.
    pub jitter: JitterMode,
    /// Whether a server-supplied `Retry-After` overrides the computed delay.
    pub respect_retry_after: bool,
    /// Ceiling applied to a server-supplied `Retry-After`.
    pub max_retry_after: Duration,
}

impl Default for RetryPolicy {
    fn default() -> Self {
        Self {
            max_attempts: 4,
            initial_backoff: Duration::from_millis(500),
            max_backoff: Duration::from_secs(30),
            multiplier_centi: 200,
            jitter: JitterMode::Full,
            respect_retry_after: true,
            max_retry_after: Duration::from_mins(2),
        }
    }
}

impl RetryPolicy {
    /// A policy that never retries.
    #[must_use]
    pub const fn never() -> Self {
        Self {
            max_attempts: 1,
            initial_backoff: Duration::ZERO,
            max_backoff: Duration::ZERO,
            multiplier_centi: 100,
            jitter: JitterMode::None,
            respect_retry_after: false,
            max_retry_after: Duration::ZERO,
        }
    }

    /// Returns the un-jittered exponential delay before attempt `attempt`.
    ///
    /// `attempt` is 1-based, so `base_backoff(1)` is the delay between the first
    /// and second attempt. The result is clamped to [`RetryPolicy::max_backoff`].
    #[must_use]
    pub fn base_backoff(&self, attempt: u32) -> Duration {
        if attempt == 0 {
            return Duration::ZERO;
        }
        let mut delay = self.initial_backoff;
        for _ in 1..attempt {
            let scaled = delay
                .as_nanos()
                .saturating_mul(u128::from(self.multiplier_centi))
                / 100;
            if scaled >= self.max_backoff.as_nanos() {
                return self.max_backoff;
            }
            // A multiplier of 100 or less never reaches the ceiling, so without
            // this the loop would spin up to `u32::MAX` times computing the same
            // delay. Once a step stops making progress, every later step repeats
            // it, and the answer is already known.
            if scaled == delay.as_nanos() {
                break;
            }
            delay = Duration::from_nanos(u64::try_from(scaled).unwrap_or(u64::MAX));
        }
        delay.min(self.max_backoff)
    }

    /// Returns the delay to wait before attempt `attempt + 1`.
    ///
    /// A `retry_after` hint wins over the computed exponential delay when
    /// [`RetryPolicy::respect_retry_after`] is set, and is never jittered:
    /// the server named an exact time. The hint is always clamped to
    /// [`RetryPolicy::max_retry_after`], so an upstream that answers
    /// `Retry-After: 86400` cannot park the caller for a day.
    #[must_use]
    pub fn delay_for(
        &self,
        attempt: u32,
        retry_after: Option<Duration>,
        jitter: &dyn JitterSource,
    ) -> Duration {
        if self.respect_retry_after
            && let Some(hint) = retry_after
        {
            return hint.min(self.max_retry_after);
        }
        let base = self.base_backoff(attempt);
        match self.jitter {
            JitterMode::None => base,
            JitterMode::Full => scale(base, jitter.next_unit_interval()),
            JitterMode::Equal => {
                let half = base / 2;
                half + scale(half, jitter.next_unit_interval())
            }
        }
    }
}

/// Multiplies `duration` by `fraction`, treating `fraction` as clamped to
/// `[0, 1]`.
///
/// A [`JitterSource`] is a trait a caller implements, so `fraction` is
/// untrusted: a negative, out-of-range or `NaN` sample is folded to the low end
/// of the window rather than producing a nonsensical or panicking delay. The
/// result is never longer than `duration`, so a jittered delay can never exceed
/// the exponential delay it randomizes.
fn scale(duration: Duration, fraction: f64) -> Duration {
    if !fraction.is_finite() || fraction <= 0.0 {
        return Duration::ZERO;
    }
    if fraction >= 1.0 {
        return duration;
    }
    Duration::try_from_secs_f64(duration.as_secs_f64() * fraction)
        .unwrap_or(duration)
        .min(duration)
}

/// Outcome of one attempt, as seen by [`RetryExecutor::run`].
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AttemptOutcome {
    /// The attempt succeeded.
    Succeeded,
    /// The attempt failed and the executor slept before retrying.
    RetriedAfter(Duration),
    /// The attempt failed and no further attempt was made.
    GaveUp,
}

/// Drives an operation under a [`RetryPolicy`].
pub struct RetryExecutor<'a> {
    policy: RetryPolicy,
    clock: &'a dyn Clock,
    jitter: &'a dyn JitterSource,
}

impl<'a> RetryExecutor<'a> {
    /// Creates an executor bound to a policy, clock and jitter source.
    #[must_use]
    pub fn new(policy: RetryPolicy, clock: &'a dyn Clock, jitter: &'a dyn JitterSource) -> Self {
        Self {
            policy,
            clock,
            jitter,
        }
    }

    /// Runs `operation` until it succeeds, becomes non-retryable, or exhausts
    /// the attempt budget.
    ///
    /// `operation` receives the 1-based attempt number. The executor observes
    /// `cancel` before every attempt and before every sleep, so a cancelled
    /// caller never waits out a backoff delay.
    ///
    /// # Errors
    ///
    /// Returns the last [`ProviderError`] produced by `operation`, or a
    /// [`ErrorKind::Cancelled`] error when the token fired.
    pub async fn run<F, Fut, T>(
        &self,
        provider: &str,
        operation_kind: Operation,
        cancel: &CancelToken,
        mut operation: F,
    ) -> Result<T, ProviderError>
    where
        F: FnMut(u32) -> Fut,
        Fut: Future<Output = Result<T, ProviderError>>,
    {
        let attempts = self.policy.max_attempts.max(1);
        let mut last_error = None;
        for attempt in 1..=attempts {
            if cancel.is_cancelled() {
                return Err(ProviderError::new(
                    ErrorKind::Cancelled,
                    provider,
                    operation_kind,
                    "cancelled before attempt",
                ));
            }
            match operation(attempt).await {
                Ok(value) => return Ok(value),
                Err(error) => {
                    let retryable = error.is_retryable() && attempt < attempts;
                    if !retryable {
                        return Err(error);
                    }
                    let delay = self
                        .policy
                        .delay_for(attempt, error.retry_after(), self.jitter);
                    last_error = Some(error);
                    if cancel.is_cancelled() {
                        break;
                    }
                    if !delay.is_zero() {
                        tokio::select! {
                            biased;
                            () = cancel.cancelled() => break,
                            () = self.clock.sleep(delay) => {}
                        }
                    }
                }
            }
        }
        Err(last_error.unwrap_or_else(|| {
            ProviderError::new(
                ErrorKind::Cancelled,
                provider,
                operation_kind,
                "cancelled during backoff",
            )
        }))
    }
}

#[cfg(test)]
mod tests {
    use std::cell::RefCell;

    use super::*;
    use crate::clock::{FixedJitter, ManualClock};

    fn failure(kind: ErrorKind) -> ProviderError {
        ProviderError::new(kind, "test", Operation::Complete, "synthetic")
    }

    #[test]
    fn base_backoff_grows_geometrically_and_saturates_at_the_ceiling() {
        let policy = RetryPolicy {
            max_attempts: 8,
            initial_backoff: Duration::from_millis(100),
            max_backoff: Duration::from_secs(1),
            multiplier_centi: 300,
            jitter: JitterMode::None,
            respect_retry_after: false,
            max_retry_after: Duration::ZERO,
        };
        assert_eq!(policy.base_backoff(0), Duration::ZERO);
        assert_eq!(policy.base_backoff(1), Duration::from_millis(100));
        assert_eq!(policy.base_backoff(2), Duration::from_millis(300));
        assert_eq!(policy.base_backoff(3), Duration::from_millis(900));
        assert_eq!(policy.base_backoff(4), Duration::from_secs(1));
        assert_eq!(policy.base_backoff(40), Duration::from_secs(1));
    }

    #[test]
    fn a_backoff_that_stops_growing_terminates_instead_of_iterating_per_attempt() {
        // A multiplier of 100 or less never reaches `max_backoff`, so the loop
        // has no ceiling to return from and runs once per attempt. `attempt`
        // is a caller-supplied `u32`, so a policy like this would otherwise
        // burn billions of iterations recomputing the same delay.
        let flat = RetryPolicy {
            max_attempts: 5,
            initial_backoff: Duration::from_millis(250),
            max_backoff: Duration::from_mins(1),
            multiplier_centi: 100,
            jitter: JitterMode::None,
            respect_retry_after: false,
            max_retry_after: Duration::ZERO,
        };
        assert_eq!(flat.base_backoff(u32::MAX), Duration::from_millis(250));

        let shrinking = RetryPolicy {
            multiplier_centi: 0,
            ..flat
        };
        assert_eq!(shrinking.base_backoff(u32::MAX), Duration::ZERO);

        let zeroed = RetryPolicy {
            initial_backoff: Duration::ZERO,
            multiplier_centi: 200,
            ..flat
        };
        assert_eq!(zeroed.base_backoff(u32::MAX), Duration::ZERO);
    }

    #[test]
    fn jitter_modes_produce_the_documented_windows() {
        let policy = RetryPolicy {
            max_attempts: 5,
            initial_backoff: Duration::from_millis(400),
            max_backoff: Duration::from_mins(1),
            multiplier_centi: 200,
            jitter: JitterMode::None,
            respect_retry_after: false,
            max_retry_after: Duration::ZERO,
        };
        let zero = FixedJitter::new(0.0);
        let half = FixedJitter::new(0.5);
        let one = FixedJitter::new(1.0);

        assert_eq!(
            policy.delay_for(2, None, &half),
            Duration::from_millis(800),
            "JitterMode::None ignores the jitter source"
        );

        let full = RetryPolicy {
            jitter: JitterMode::Full,
            ..policy
        };
        assert_eq!(full.delay_for(2, None, &zero), Duration::ZERO);
        assert_eq!(full.delay_for(2, None, &half), Duration::from_millis(400));
        assert_eq!(full.delay_for(2, None, &one), Duration::from_millis(800));

        let equal = RetryPolicy {
            jitter: JitterMode::Equal,
            ..policy
        };
        assert_eq!(equal.delay_for(2, None, &zero), Duration::from_millis(400));
        assert_eq!(equal.delay_for(2, None, &half), Duration::from_millis(600));
        assert_eq!(equal.delay_for(2, None, &one), Duration::from_millis(800));
    }

    #[test]
    fn retry_after_overrides_backoff_and_is_capped() {
        let policy = RetryPolicy {
            max_attempts: 5,
            initial_backoff: Duration::from_millis(100),
            max_backoff: Duration::from_mins(1),
            multiplier_centi: 200,
            jitter: JitterMode::Full,
            respect_retry_after: true,
            max_retry_after: Duration::from_secs(10),
        };
        let jitter = FixedJitter::new(0.0);
        assert_eq!(
            policy.delay_for(1, Some(Duration::from_secs(3)), &jitter),
            Duration::from_secs(3)
        );
        assert_eq!(
            policy.delay_for(1, Some(Duration::from_mins(10)), &jitter),
            Duration::from_secs(10)
        );

        let ignoring = RetryPolicy {
            respect_retry_after: false,
            jitter: JitterMode::None,
            ..policy
        };
        assert_eq!(
            ignoring.delay_for(1, Some(Duration::from_secs(3)), &jitter),
            Duration::from_millis(100)
        );
    }

    #[tokio::test]
    async fn executor_sleeps_the_exact_backoff_schedule_on_a_fake_clock() {
        let clock = ManualClock::new(0);
        let jitter = FixedJitter::new(1.0);
        let policy = RetryPolicy {
            max_attempts: 4,
            initial_backoff: Duration::from_millis(200),
            max_backoff: Duration::from_secs(30),
            multiplier_centi: 200,
            jitter: JitterMode::None,
            respect_retry_after: true,
            max_retry_after: Duration::from_mins(1),
        };
        let executor = RetryExecutor::new(policy, &clock, &jitter);
        let attempts = RefCell::new(Vec::new());

        let error = executor
            .run(
                "test",
                Operation::Complete,
                &CancelToken::new(),
                |attempt| {
                    attempts.borrow_mut().push(attempt);
                    async move { Err::<(), _>(failure(ErrorKind::Server)) }
                },
            )
            .await
            .expect_err("every attempt fails");

        assert_eq!(error.kind(), ErrorKind::Server);
        assert_eq!(*attempts.borrow(), vec![1, 2, 3, 4]);
        assert_eq!(
            clock.recorded_sleeps(),
            vec![
                Duration::from_millis(200),
                Duration::from_millis(400),
                Duration::from_millis(800),
            ]
        );
        assert_eq!(clock.now_millis(), 1_400);
    }

    #[tokio::test]
    async fn executor_honours_retry_after_from_the_error() {
        let clock = ManualClock::new(0);
        let jitter = FixedJitter::new(0.0);
        let executor = RetryExecutor::new(RetryPolicy::default(), &clock, &jitter);

        let error = executor
            .run(
                "test",
                Operation::Complete,
                &CancelToken::new(),
                |_| async {
                    Err::<(), _>(
                        ProviderError::new(
                            ErrorKind::RateLimit,
                            "test",
                            Operation::Complete,
                            "slow down",
                        )
                        .with_retry_after(Duration::from_secs(7)),
                    )
                },
            )
            .await
            .expect_err("rate limited");

        assert_eq!(error.kind(), ErrorKind::RateLimit);
        assert_eq!(
            clock.recorded_sleeps(),
            vec![
                Duration::from_secs(7),
                Duration::from_secs(7),
                Duration::from_secs(7),
            ]
        );
    }

    #[tokio::test]
    async fn non_retryable_failures_stop_immediately() {
        let clock = ManualClock::new(0);
        let jitter = FixedJitter::new(0.0);
        let executor = RetryExecutor::new(RetryPolicy::default(), &clock, &jitter);
        let calls = RefCell::new(0_u32);

        for kind in [
            ErrorKind::Authentication,
            ErrorKind::Quota,
            ErrorKind::InvalidRequest,
            ErrorKind::Protocol,
            ErrorKind::Unsupported,
            ErrorKind::Cancelled,
            ErrorKind::CircuitOpen,
        ] {
            *calls.borrow_mut() = 0;
            let error = executor
                .run("test", Operation::Complete, &CancelToken::new(), |_| {
                    *calls.borrow_mut() += 1;
                    async move { Err::<(), _>(failure(kind)) }
                })
                .await
                .expect_err("failure");
            assert_eq!(error.kind(), kind);
            assert_eq!(*calls.borrow(), 1, "{kind} must not be retried");
        }
        assert!(clock.recorded_sleeps().is_empty());
    }

    #[tokio::test]
    async fn success_after_a_transient_failure_returns_the_value() {
        let clock = ManualClock::new(0);
        let jitter = FixedJitter::new(0.5);
        let executor = RetryExecutor::new(RetryPolicy::default(), &clock, &jitter);

        let value = executor
            .run(
                "test",
                Operation::Complete,
                &CancelToken::new(),
                |attempt| async move {
                    if attempt < 3 {
                        Err(failure(ErrorKind::Transport))
                    } else {
                        Ok(attempt)
                    }
                },
            )
            .await
            .expect("third attempt succeeds");

        assert_eq!(value, 3);
        assert_eq!(clock.recorded_sleeps().len(), 2);
    }

    #[tokio::test]
    async fn cancellation_before_the_first_attempt_short_circuits() {
        let clock = ManualClock::new(0);
        let jitter = FixedJitter::new(0.0);
        let executor = RetryExecutor::new(RetryPolicy::default(), &clock, &jitter);
        let calls = RefCell::new(0_u32);

        let error = executor
            .run(
                "test",
                Operation::Complete,
                &CancelToken::cancelled_token(),
                |_| {
                    *calls.borrow_mut() += 1;
                    async { Err::<(), _>(failure(ErrorKind::Server)) }
                },
            )
            .await
            .expect_err("cancelled");

        assert_eq!(error.kind(), ErrorKind::Cancelled);
        assert_eq!(*calls.borrow(), 0);
        assert!(clock.recorded_sleeps().is_empty());
    }

    #[tokio::test]
    async fn cancellation_during_backoff_stops_the_schedule() {
        let clock = ManualClock::new(0);
        let jitter = FixedJitter::new(0.0);
        let executor = RetryExecutor::new(RetryPolicy::default(), &clock, &jitter);
        let cancel = CancelToken::new();
        let calls = RefCell::new(0_u32);

        let error = executor
            .run("test", Operation::Complete, &cancel, |_| {
                *calls.borrow_mut() += 1;
                cancel.cancel();
                async { Err::<(), _>(failure(ErrorKind::Server)) }
            })
            .await
            .expect_err("cancelled during backoff");

        assert_eq!(error.kind(), ErrorKind::Server);
        assert_eq!(*calls.borrow(), 1);
        assert!(clock.recorded_sleeps().is_empty());
    }

    #[test]
    fn never_policy_makes_exactly_one_attempt() {
        let policy = RetryPolicy::never();
        assert_eq!(policy.max_attempts, 1);
        assert_eq!(
            policy.delay_for(1, Some(Duration::from_secs(5)), &FixedJitter::new(1.0)),
            Duration::ZERO
        );
    }
}

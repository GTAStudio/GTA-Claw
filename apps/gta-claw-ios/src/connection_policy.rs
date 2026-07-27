//! Mobile-specific bounds for Gateway connection work.

use std::error::Error;
use std::fmt::{self, Display, Formatter};
use std::time::Duration;

use claw_gateway_client::{ClientTimeouts, GatewayClientConfig, ReconnectPolicy};

const MAX_CONNECT_TIMEOUT: Duration = Duration::from_secs(30);
const MAX_AUTHENTICATION_TIMEOUT: Duration = Duration::from_secs(30);
const MAX_REQUEST_TIMEOUT: Duration = Duration::from_mins(2);
const MAX_SHUTDOWN_TIMEOUT: Duration = Duration::from_secs(10);
const MAX_RECONNECT_ATTEMPTS: u32 = 5;
const MAX_RECONNECT_DELAY: Duration = Duration::from_secs(30);
const MAX_RECONNECT_JITTER: Duration = Duration::from_secs(2);

/// Bounded lifecycle timeouts chosen by the iOS host application.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct IosTimeoutPolicy {
    connect: Duration,
    authentication: Duration,
    request: Duration,
    shutdown: Duration,
}

impl IosTimeoutPolicy {
    /// Default timeout bounds for an interactive iOS session.
    pub const MOBILE_DEFAULT: Self = Self {
        connect: Duration::from_secs(8),
        authentication: Duration::from_secs(8),
        request: Duration::from_secs(20),
        shutdown: Duration::from_secs(2),
    };

    /// Creates a timeout policy after applying mobile upper bounds.
    ///
    /// # Errors
    ///
    /// Returns [`ConnectionPolicyError`] when any timeout is zero or exceeds the
    /// maximum this client permits.
    pub fn new(
        connect: Duration,
        authentication: Duration,
        request: Duration,
        shutdown: Duration,
    ) -> Result<Self, ConnectionPolicyError> {
        validate_timeout("connect", connect, MAX_CONNECT_TIMEOUT)?;
        validate_timeout("authentication", authentication, MAX_AUTHENTICATION_TIMEOUT)?;
        validate_timeout("request", request, MAX_REQUEST_TIMEOUT)?;
        validate_timeout("shutdown", shutdown, MAX_SHUTDOWN_TIMEOUT)?;
        Ok(Self {
            connect,
            authentication,
            request,
            shutdown,
        })
    }

    /// Returns the TCP, TLS, and WebSocket opening timeout.
    #[must_use]
    pub const fn connect(self) -> Duration {
        self.connect
    }

    /// Returns the Gateway authentication timeout.
    #[must_use]
    pub const fn authentication(self) -> Duration {
        self.authentication
    }

    /// Returns the default request timeout.
    #[must_use]
    pub const fn request(self) -> Duration {
        self.request
    }

    /// Returns the close and task-shutdown timeout.
    #[must_use]
    pub const fn shutdown(self) -> Duration {
        self.shutdown
    }

    const fn into_gateway(self) -> ClientTimeouts {
        ClientTimeouts {
            connect: self.connect,
            authentication: self.authentication,
            request: self.request,
            shutdown: self.shutdown,
        }
    }
}

impl Default for IosTimeoutPolicy {
    fn default() -> Self {
        Self::MOBILE_DEFAULT
    }
}

/// Foreground retry behavior for transient Gateway transport failures.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum IosRetryPolicy {
    /// Do not reconnect after a transport loss.
    Never,
    /// Retry a bounded number of times with bounded exponential backoff.
    Bounded {
        /// Maximum attempts after the failed connection.
        max_attempts: u32,
        /// Delay before the first retry.
        initial_delay: Duration,
        /// Maximum exponential delay before jitter.
        max_delay: Duration,
        /// Maximum additive runtime jitter.
        max_jitter: Duration,
    },
}

impl IosRetryPolicy {
    /// Default retry bounds for an interactive foreground iOS session.
    pub const MOBILE_DEFAULT: Self = Self::Bounded {
        max_attempts: 4,
        initial_delay: Duration::from_millis(500),
        max_delay: Duration::from_secs(8),
        max_jitter: Duration::from_millis(250),
    };

    /// Creates a bounded retry policy suitable for a foreground mobile session.
    ///
    /// # Errors
    ///
    /// Returns [`ConnectionPolicyError`] for zero or excessive attempt counts,
    /// zero delays, an initial delay greater than the maximum, or delays above
    /// the iOS client caps.
    pub fn bounded(
        max_attempts: u32,
        initial_delay: Duration,
        max_delay: Duration,
        max_jitter: Duration,
    ) -> Result<Self, ConnectionPolicyError> {
        if max_attempts == 0 {
            return Err(ConnectionPolicyError::ZeroReconnectAttempts);
        }
        if max_attempts > MAX_RECONNECT_ATTEMPTS {
            return Err(ConnectionPolicyError::TooManyReconnectAttempts {
                actual: max_attempts,
                limit: MAX_RECONNECT_ATTEMPTS,
            });
        }
        validate_delay("initial reconnect", initial_delay, MAX_RECONNECT_DELAY)?;
        validate_delay("maximum reconnect", max_delay, MAX_RECONNECT_DELAY)?;
        if initial_delay > max_delay {
            return Err(ConnectionPolicyError::InitialDelayExceedsMaximum);
        }
        if max_jitter > MAX_RECONNECT_JITTER {
            return Err(ConnectionPolicyError::DelayTooLong {
                field: "reconnect jitter",
                actual: max_jitter,
                limit: MAX_RECONNECT_JITTER,
            });
        }
        Ok(Self::Bounded {
            max_attempts,
            initial_delay,
            max_delay,
            max_jitter,
        })
    }

    /// Returns the upper bound on cumulative sleep before retries.
    ///
    /// Connection and authentication time are bounded separately by
    /// [`IosTimeoutPolicy`]. Backgrounding or losing the network stops this
    /// budget immediately through [`crate::IosSessionModel`].
    #[must_use]
    pub fn maximum_retry_sleep(self) -> Duration {
        let Self::Bounded {
            max_attempts,
            initial_delay,
            max_delay,
            max_jitter,
        } = self
        else {
            return Duration::ZERO;
        };

        let mut delay = initial_delay;
        let mut total = Duration::ZERO;
        for _ in 0..max_attempts {
            total = total.saturating_add(delay).saturating_add(max_jitter);
            delay = delay.saturating_mul(2).min(max_delay);
        }
        total
    }

    const fn into_gateway(self) -> ReconnectPolicy {
        match self {
            Self::Never => ReconnectPolicy::Never,
            Self::Bounded {
                max_attempts,
                initial_delay,
                max_delay,
                max_jitter,
            } => ReconnectPolicy::Bounded {
                max_attempts,
                initial_delay,
                max_delay,
                max_jitter,
            },
        }
    }
}

impl Default for IosRetryPolicy {
    fn default() -> Self {
        Self::MOBILE_DEFAULT
    }
}

/// Complete bounded connection policy applied to every iOS Gateway profile.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct IosConnectionPolicy {
    timeouts: IosTimeoutPolicy,
    retries: IosRetryPolicy,
}

impl IosConnectionPolicy {
    /// Default policy for an interactive iOS session.
    pub const MOBILE_DEFAULT: Self = Self {
        timeouts: IosTimeoutPolicy::MOBILE_DEFAULT,
        retries: IosRetryPolicy::MOBILE_DEFAULT,
    };

    /// Combines independently validated timeout and retry policies.
    #[must_use]
    pub const fn new(timeouts: IosTimeoutPolicy, retries: IosRetryPolicy) -> Self {
        Self { timeouts, retries }
    }

    /// Returns the lifecycle timeout policy.
    #[must_use]
    pub const fn timeouts(self) -> IosTimeoutPolicy {
        self.timeouts
    }

    /// Returns the foreground retry policy.
    #[must_use]
    pub const fn retries(self) -> IosRetryPolicy {
        self.retries
    }

    pub(crate) const fn apply(self, config: &mut GatewayClientConfig) {
        config.timeouts = self.timeouts.into_gateway();
        config.reconnect = self.retries.into_gateway();
    }
}

impl Default for IosConnectionPolicy {
    fn default() -> Self {
        Self::MOBILE_DEFAULT
    }
}

/// An iOS connection policy that could waste unbounded user time or resources.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ConnectionPolicyError {
    /// A lifecycle timeout was zero.
    ZeroTimeout {
        /// Operation whose timeout was invalid.
        field: &'static str,
    },
    /// A lifecycle timeout exceeded the mobile cap.
    TimeoutTooLong {
        /// Operation whose timeout was invalid.
        field: &'static str,
        /// Supplied timeout.
        actual: Duration,
        /// Maximum accepted timeout.
        limit: Duration,
    },
    /// A bounded policy requested no attempts.
    ZeroReconnectAttempts,
    /// The retry count exceeded the mobile cap.
    TooManyReconnectAttempts {
        /// Supplied count.
        actual: u32,
        /// Maximum accepted count.
        limit: u32,
    },
    /// A reconnect delay was zero.
    ZeroDelay {
        /// Delay whose value was invalid.
        field: &'static str,
    },
    /// A reconnect delay exceeded the mobile cap.
    DelayTooLong {
        /// Delay whose value was invalid.
        field: &'static str,
        /// Supplied delay.
        actual: Duration,
        /// Maximum accepted delay.
        limit: Duration,
    },
    /// The first delay was greater than the backoff ceiling.
    InitialDelayExceedsMaximum,
}

impl Display for ConnectionPolicyError {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        match self {
            Self::ZeroTimeout { field } => {
                write!(formatter, "{field} timeout must be greater than zero")
            }
            Self::TimeoutTooLong {
                field,
                actual,
                limit,
            } => write!(
                formatter,
                "{field} timeout of {actual:?} exceeds the iOS limit of {limit:?}"
            ),
            Self::ZeroReconnectAttempts => {
                formatter.write_str("bounded reconnect policy must allow at least one attempt")
            }
            Self::TooManyReconnectAttempts { actual, limit } => write!(
                formatter,
                "{actual} reconnect attempts exceed the iOS limit of {limit}"
            ),
            Self::ZeroDelay { field } => {
                write!(formatter, "{field} delay must be greater than zero")
            }
            Self::DelayTooLong {
                field,
                actual,
                limit,
            } => write!(
                formatter,
                "{field} delay of {actual:?} exceeds the iOS limit of {limit:?}"
            ),
            Self::InitialDelayExceedsMaximum => formatter
                .write_str("initial reconnect delay must not exceed the maximum reconnect delay"),
        }
    }
}

impl Error for ConnectionPolicyError {}

fn validate_timeout(
    field: &'static str,
    actual: Duration,
    limit: Duration,
) -> Result<(), ConnectionPolicyError> {
    if actual.is_zero() {
        return Err(ConnectionPolicyError::ZeroTimeout { field });
    }
    if actual > limit {
        return Err(ConnectionPolicyError::TimeoutTooLong {
            field,
            actual,
            limit,
        });
    }
    Ok(())
}

fn validate_delay(
    field: &'static str,
    actual: Duration,
    limit: Duration,
) -> Result<(), ConnectionPolicyError> {
    if actual.is_zero() {
        return Err(ConnectionPolicyError::ZeroDelay { field });
    }
    if actual > limit {
        return Err(ConnectionPolicyError::DelayTooLong {
            field,
            actual,
            limit,
        });
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use super::{
        ConnectionPolicyError, IosConnectionPolicy, IosRetryPolicy, IosTimeoutPolicy,
        MAX_CONNECT_TIMEOUT, MAX_RECONNECT_ATTEMPTS,
    };

    #[test]
    fn the_mobile_default_has_a_small_finite_retry_window() {
        let policy = IosConnectionPolicy::default();

        assert_eq!(policy.timeouts().connect(), Duration::from_secs(8));
        assert_eq!(
            policy.retries().maximum_retry_sleep(),
            Duration::from_millis(8_500)
        );
        assert!(matches!(
            policy.retries(),
            IosRetryPolicy::Bounded {
                max_attempts: 4,
                ..
            }
        ));
    }

    #[test]
    fn timeout_policy_refuses_zero_and_excessive_values() {
        let zero = IosTimeoutPolicy::new(
            Duration::ZERO,
            Duration::from_secs(1),
            Duration::from_secs(1),
            Duration::from_secs(1),
        );
        assert_eq!(
            zero,
            Err(ConnectionPolicyError::ZeroTimeout { field: "connect" })
        );

        let too_long = IosTimeoutPolicy::new(
            MAX_CONNECT_TIMEOUT + Duration::from_millis(1),
            Duration::from_secs(1),
            Duration::from_secs(1),
            Duration::from_secs(1),
        );
        assert!(matches!(
            too_long,
            Err(ConnectionPolicyError::TimeoutTooLong {
                field: "connect",
                ..
            })
        ));
    }

    #[test]
    fn retry_policy_refuses_unbounded_mobile_work() {
        assert_eq!(
            IosRetryPolicy::bounded(
                0,
                Duration::from_millis(1),
                Duration::from_secs(1),
                Duration::ZERO,
            ),
            Err(ConnectionPolicyError::ZeroReconnectAttempts)
        );
        assert_eq!(
            IosRetryPolicy::bounded(
                MAX_RECONNECT_ATTEMPTS + 1,
                Duration::from_millis(1),
                Duration::from_secs(1),
                Duration::ZERO,
            ),
            Err(ConnectionPolicyError::TooManyReconnectAttempts {
                actual: MAX_RECONNECT_ATTEMPTS + 1,
                limit: MAX_RECONNECT_ATTEMPTS,
            })
        );
    }

    #[test]
    fn retry_sleep_is_zero_when_retries_are_disabled() {
        assert_eq!(IosRetryPolicy::Never.maximum_retry_sleep(), Duration::ZERO);
    }
}

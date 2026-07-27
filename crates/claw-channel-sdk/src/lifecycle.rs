//! Connection lifecycle contracts shared by every channel adapter.
//!
//! Channels differ in transport but not in lifecycle: something opens a
//! session, the session survives for a while, it drops, and something decides
//! whether to open it again. Modelling that once means a reconnect bug is
//! fixed in one place, and it keeps the one asymmetry that matters explicit —
//! reopening a session is always safe to repeat, whereas resending a message is
//! only safe when the channel positively says so.

use std::error::Error;
use std::fmt::{self, Display, Formatter};

use crate::{BackoffSleeper, ChannelError, RetryPolicy};

/// Observable connection state of one channel session.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub enum ConnectionState {
    /// No session is open and none is being opened.
    #[default]
    Disconnected,
    /// A session is being opened.
    Connecting,
    /// A session is open and can exchange messages.
    Connected,
    /// A session dropped and another attempt is scheduled.
    Reconnecting,
    /// The channel was shut down and will never reconnect.
    Closed,
}

impl ConnectionState {
    /// Returns whether messages may be exchanged in this state.
    #[must_use]
    pub const fn can_exchange(self) -> bool {
        matches!(self, Self::Connected)
    }

    /// Returns whether this state is terminal.
    #[must_use]
    pub const fn is_terminal(self) -> bool {
        matches!(self, Self::Closed)
    }

    /// Applies one lifecycle event, rejecting every transition not in the table.
    ///
    /// The rejection is the point: an adapter that reports `Established` twice,
    /// or reconnects after shutdown, has a defect that must surface as an error
    /// rather than as a silently repaired state.
    pub const fn apply(self, event: LifecycleEvent) -> Result<Self, IllegalTransition> {
        let next = match (self, event) {
            (Self::Disconnected | Self::Reconnecting, LifecycleEvent::ConnectRequested) => {
                Self::Connecting
            }
            (Self::Connecting, LifecycleEvent::Established) => Self::Connected,
            (Self::Connecting | Self::Connected, LifecycleEvent::ConnectionLost)
            | (
                Self::Connecting | Self::Connected | Self::Reconnecting,
                LifecycleEvent::DisconnectRequested,
            ) => Self::Disconnected,
            (Self::Disconnected, LifecycleEvent::ReconnectScheduled) => Self::Reconnecting,
            (
                Self::Disconnected | Self::Connecting | Self::Connected | Self::Reconnecting,
                LifecycleEvent::ShutdownRequested,
            ) => Self::Closed,
            _ => return Err(IllegalTransition { from: self, event }),
        };
        Ok(next)
    }
}

/// An event that may change a channel's connection state.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum LifecycleEvent {
    /// A session open was started.
    ConnectRequested,
    /// A session finished opening.
    Established,
    /// An opening or open session failed.
    ConnectionLost,
    /// Another attempt was scheduled after a failure.
    ReconnectScheduled,
    /// A deliberate, resumable disconnect was requested.
    DisconnectRequested,
    /// A terminal shutdown was requested.
    ShutdownRequested,
}

/// A lifecycle event that the state machine refuses in the current state.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct IllegalTransition {
    /// State the channel was in.
    pub from: ConnectionState,
    /// Event that was rejected.
    pub event: LifecycleEvent,
}

impl Display for IllegalTransition {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "channel lifecycle event {:?} is illegal in state {:?}",
            self.event, self.from
        )
    }
}

impl Error for IllegalTransition {}

/// Transport port that opens and closes one channel session.
///
/// Keeping this separate from [`crate::Channel`] is what makes reconnection
/// testable without a network: a fixture session can fail a scripted number of
/// times and then succeed.
pub trait ChannelSession {
    /// Opens one session, blocking until it is usable or has failed.
    fn open(&mut self) -> Result<(), ChannelError>;

    /// Closes the session. Implementations must tolerate repeated calls.
    fn close(&mut self) -> Result<(), ChannelError>;
}

/// Receives every accepted lifecycle transition.
pub trait LifecycleObserver {
    /// Called after a transition is accepted, never for a rejected one.
    fn on_transition(&mut self, from: ConnectionState, event: LifecycleEvent, to: ConnectionState);
}

impl LifecycleObserver for () {
    fn on_transition(
        &mut self,
        _from: ConnectionState,
        _event: LifecycleEvent,
        _to: ConnectionState,
    ) {
    }
}

/// Drives one channel session through connect, reconnect and shutdown.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ConnectionSupervisor {
    state: ConnectionState,
    policy: RetryPolicy,
}

impl ConnectionSupervisor {
    /// Creates a disconnected supervisor bound to one retry policy.
    #[must_use]
    pub const fn new(policy: RetryPolicy) -> Self {
        Self {
            state: ConnectionState::Disconnected,
            policy,
        }
    }

    /// Returns the current connection state.
    #[must_use]
    pub const fn state(&self) -> ConnectionState {
        self.state
    }

    /// Opens a session, retrying transient failures with bounded backoff.
    ///
    /// Unlike [`crate::send_with_retry`], no per-channel safety declaration is
    /// consulted. Opening a session delivers nothing, so a repeated attempt
    /// cannot duplicate a message; only a retryable failure and a remaining
    /// attempt are required.
    pub fn connect(
        &mut self,
        session: &mut impl ChannelSession,
        sleeper: &mut impl BackoffSleeper,
        observer: &mut impl LifecycleObserver,
    ) -> Result<(), ChannelError> {
        let mut delay = self.policy.initial_delay;
        for attempt in 1..=self.policy.max_attempts.get() {
            self.transition(LifecycleEvent::ConnectRequested, observer)?;
            let error = match session.open() {
                Ok(()) => return self.transition(LifecycleEvent::Established, observer),
                Err(error) => error,
            };
            self.transition(LifecycleEvent::ConnectionLost, observer)?;
            if !error.is_retryable() || attempt == self.policy.max_attempts.get() {
                return Err(error);
            }
            self.transition(LifecycleEvent::ReconnectScheduled, observer)?;
            sleeper.sleep(
                error
                    .retry_after()
                    .unwrap_or(delay)
                    .min(self.policy.max_delay),
            );
            delay = delay
                .saturating_mul(self.policy.multiplier.get())
                .min(self.policy.max_delay);
        }
        unreachable!("a non-zero retry policy always performs at least one attempt")
    }

    /// Records that an open session dropped without a deliberate request.
    pub fn connection_lost(
        &mut self,
        observer: &mut impl LifecycleObserver,
    ) -> Result<(), ChannelError> {
        self.transition(LifecycleEvent::ConnectionLost, observer)
    }

    /// Closes the session while leaving reconnection available.
    pub fn disconnect(
        &mut self,
        session: &mut impl ChannelSession,
        observer: &mut impl LifecycleObserver,
    ) -> Result<(), ChannelError> {
        self.transition(LifecycleEvent::DisconnectRequested, observer)?;
        session.close()
    }

    /// Closes the session permanently.
    ///
    /// The state moves before the transport call so a failing close cannot
    /// leave a supervisor that believes it is still connected.
    pub fn shutdown(
        &mut self,
        session: &mut impl ChannelSession,
        observer: &mut impl LifecycleObserver,
    ) -> Result<(), ChannelError> {
        self.transition(LifecycleEvent::ShutdownRequested, observer)?;
        session.close()
    }

    fn transition(
        &mut self,
        event: LifecycleEvent,
        observer: &mut impl LifecycleObserver,
    ) -> Result<(), ChannelError> {
        let from = self.state;
        let to = from.apply(event).map_err(ChannelError::Lifecycle)?;
        self.state = to;
        observer.on_transition(from, event, to);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use std::num::NonZeroU32;
    use std::time::Duration;

    use super::*;

    #[derive(Debug, Default)]
    struct CountingSession {
        opens: usize,
        closes: usize,
    }

    impl ChannelSession for CountingSession {
        fn open(&mut self) -> Result<(), ChannelError> {
            self.opens += 1;
            Ok(())
        }

        fn close(&mut self) -> Result<(), ChannelError> {
            self.closes += 1;
            Ok(())
        }
    }

    #[derive(Debug, Default)]
    struct NoSleep;

    impl BackoffSleeper for NoSleep {
        fn sleep(&mut self, _delay: Duration) {}
    }

    fn policy() -> RetryPolicy {
        RetryPolicy::new(
            NonZeroU32::new(2).expect("non-zero attempts"),
            Duration::from_millis(1),
            Duration::from_millis(4),
            NonZeroU32::new(2).expect("non-zero multiplier"),
        )
        .expect("valid retry policy")
    }

    #[test]
    fn repeated_and_out_of_order_lifecycle_requests_are_refused_without_touching_the_session() {
        let mut supervisor = ConnectionSupervisor::new(policy());
        let mut session = CountingSession::default();

        assert_eq!(
            supervisor.disconnect(&mut session, &mut ()),
            Err(ChannelError::Lifecycle(IllegalTransition {
                from: ConnectionState::Disconnected,
                event: LifecycleEvent::DisconnectRequested,
            })),
        );
        assert_eq!(session.closes, 0);

        assert_eq!(
            supervisor.connect(&mut session, &mut NoSleep, &mut ()),
            Ok(())
        );
        assert_eq!(supervisor.state(), ConnectionState::Connected);
        assert_eq!(
            supervisor.connect(&mut session, &mut NoSleep, &mut ()),
            Err(ChannelError::Lifecycle(IllegalTransition {
                from: ConnectionState::Connected,
                event: LifecycleEvent::ConnectRequested,
            })),
        );
        assert_eq!(
            session.opens, 1,
            "a refused connect must not reopen a session"
        );

        assert_eq!(supervisor.shutdown(&mut session, &mut ()), Ok(()));
        assert_eq!(supervisor.state(), ConnectionState::Closed);
        assert_eq!(
            supervisor.connection_lost(&mut ()),
            Err(ChannelError::Lifecycle(IllegalTransition {
                from: ConnectionState::Closed,
                event: LifecycleEvent::ConnectionLost,
            })),
        );
        assert_eq!(session.closes, 1);
    }
}

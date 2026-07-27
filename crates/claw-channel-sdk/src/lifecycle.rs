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
    ///
    /// # Errors
    ///
    /// Returns [`IllegalTransition`] carrying this state and the refused event
    /// whenever the pair is not in the table: any event other than
    /// [`LifecycleEvent::ShutdownRequested`] once the channel is
    /// [`Self::Closed`], a second [`LifecycleEvent::Established`] while already
    /// [`Self::Connected`], a [`LifecycleEvent::ConnectionLost`] or
    /// [`LifecycleEvent::DisconnectRequested`] while nothing is open, and a
    /// [`LifecycleEvent::ConnectRequested`] while a session is already opening
    /// or open.
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
    ///
    /// # Errors
    ///
    /// Implementations return the failure that stopped the session from
    /// opening: [`ChannelError::Transport`] when the socket was refused, timed
    /// out, could not be resolved, or failed TLS; [`ChannelError::Credential`]
    /// when the credential this channel needs is missing from the secret store;
    /// [`ChannelError::Authentication`] when the provider rejected it; and
    /// [`ChannelError::Configuration`] when the adapter was built without a
    /// usable endpoint or account. Only errors for which
    /// [`ChannelError::is_retryable`] holds cause
    /// [`ConnectionSupervisor::connect`] to attempt another open.
    fn open(&mut self) -> Result<(), ChannelError>;

    /// Closes the session. Implementations must tolerate repeated calls.
    ///
    /// # Errors
    ///
    /// Implementations return [`ChannelError::Transport`] when the close could
    /// not be completed cleanly, for example a socket shutdown that failed.
    /// Closing an already-closed session is not one of those cases and must
    /// return `Ok`, because the supervisor calls this once per requested
    /// disconnect and once again on shutdown.
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
    ///
    /// # Errors
    ///
    /// - [`ChannelError::Lifecycle`] when connecting is illegal in the current
    ///   state: the channel is already `Connecting` or `Connected`, or it was
    ///   shut down and is `Closed` for good. The session is never touched in
    ///   that case.
    /// - The error [`ChannelSession::open`] returned, once it is not retryable
    ///   or the attempt budget in the retry policy is spent. This is the error
    ///   an operator sees when a channel will not start: a missing credential,
    ///   a rejected token, or a transport that never came up.
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
    ///
    /// # Errors
    ///
    /// Returns [`ChannelError::Lifecycle`] when no session could have dropped,
    /// meaning the channel is `Disconnected`, already `Reconnecting`, or
    /// `Closed`. A caller seeing this reported a loss twice or reported one for
    /// a channel it never opened.
    pub fn connection_lost(
        &mut self,
        observer: &mut impl LifecycleObserver,
    ) -> Result<(), ChannelError> {
        self.transition(LifecycleEvent::ConnectionLost, observer)
    }

    /// Closes the session while leaving reconnection available.
    ///
    /// # Errors
    ///
    /// - [`ChannelError::Lifecycle`] when there is nothing to disconnect: the
    ///   channel is already `Disconnected` or permanently `Closed`. The
    ///   transport is not touched, so a refused disconnect cannot close a
    ///   session another caller still owns.
    /// - The error [`ChannelSession::close`] returned. The state has already
    ///   moved to `Disconnected` at that point, so the supervisor never claims
    ///   a session that failed to close is still usable.
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
    ///
    /// # Errors
    ///
    /// - [`ChannelError::Lifecycle`] when the channel is already `Closed`, so a
    ///   second shutdown cannot re-close a transport that has been handed back.
    /// - The error [`ChannelSession::close`] returned. The channel is `Closed`
    ///   either way and will never reconnect.
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

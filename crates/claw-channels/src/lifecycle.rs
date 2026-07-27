//! Connection lifecycle enforcement around any channel adapter.
//!
//! [`SupervisedChannel`] pairs an adapter with the transport session that must
//! be open for it to work. The pairing is what makes the contract testable
//! without a network, and it is also what stops a dropped session from being
//! discovered only when a message silently disappears: an exchange attempted
//! outside [`ConnectionState::Connected`] fails immediately and says so.

use claw_channel_sdk::{
    BackoffSleeper, Channel, ChannelCredential, ChannelError, ChannelSession, ConnectionState,
    ConnectionSupervisor, DeliveryAcknowledgement, InboundMessage, LifecycleObserver,
    OutboundMessage, OutboundRetrySafety, RetryPolicy,
};

/// A channel adapter whose message exchange is gated on an open session.
#[derive(Debug)]
pub struct SupervisedChannel<C, S> {
    inner: C,
    session: S,
    supervisor: ConnectionSupervisor,
}

impl<C, S> SupervisedChannel<C, S> {
    /// Pairs an adapter with the session that carries it.
    #[must_use]
    pub const fn new(inner: C, session: S, policy: RetryPolicy) -> Self {
        Self {
            inner,
            session,
            supervisor: ConnectionSupervisor::new(policy),
        }
    }

    /// Returns the current connection state.
    #[must_use]
    pub const fn state(&self) -> ConnectionState {
        self.supervisor.state()
    }

    /// Returns the wrapped adapter for inspection.
    #[must_use]
    pub const fn inner(&self) -> &C {
        &self.inner
    }

    /// Returns the wrapped session for inspection.
    #[must_use]
    pub const fn session(&self) -> &S {
        &self.session
    }
}

impl<C, S: ChannelSession> SupervisedChannel<C, S> {
    /// Opens the session, retrying transient failures with bounded backoff.
    pub fn connect(
        &mut self,
        sleeper: &mut impl BackoffSleeper,
        observer: &mut impl LifecycleObserver,
    ) -> Result<(), ChannelError> {
        self.supervisor
            .connect(&mut self.session, sleeper, observer)
    }

    /// Records that the session dropped on its own.
    pub fn connection_lost(
        &mut self,
        observer: &mut impl LifecycleObserver,
    ) -> Result<(), ChannelError> {
        self.supervisor.connection_lost(observer)
    }

    /// Closes the session while leaving reconnection available.
    pub fn disconnect(
        &mut self,
        observer: &mut impl LifecycleObserver,
    ) -> Result<(), ChannelError> {
        self.supervisor.disconnect(&mut self.session, observer)
    }

    /// Closes the session permanently.
    pub fn shutdown(&mut self, observer: &mut impl LifecycleObserver) -> Result<(), ChannelError> {
        self.supervisor.shutdown(&mut self.session, observer)
    }

    fn require_open_session(&self) -> Result<(), ChannelError> {
        if self.supervisor.state().can_exchange() {
            Ok(())
        } else {
            Err(ChannelError::NotConnected {
                state: self.supervisor.state(),
            })
        }
    }
}

impl<C: Channel, S: ChannelSession> Channel for SupervisedChannel<C, S> {
    fn id(&self) -> &str {
        self.inner.id()
    }

    fn poll_inbound(&mut self) -> Result<Option<InboundMessage>, ChannelError> {
        self.require_open_session()?;
        self.inner.poll_inbound()
    }

    fn outbound_retry_safety(&self) -> OutboundRetrySafety {
        self.inner.outbound_retry_safety()
    }

    fn send_outbound(
        &mut self,
        message: &OutboundMessage,
        credential: Option<&ChannelCredential>,
    ) -> Result<DeliveryAcknowledgement, ChannelError> {
        self.require_open_session()?;
        self.inner.send_outbound(message, credential)
    }
}

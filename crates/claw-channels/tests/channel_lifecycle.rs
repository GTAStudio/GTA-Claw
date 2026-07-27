//! Connection lifecycle contracts for official channel adapters.

mod support;

use std::collections::VecDeque;
use std::num::NonZeroU32;
use std::time::Duration;

use claw_channel_sdk::{
    BackoffSleeper, Channel, ChannelCredential, ChannelError, ChannelSession, ConnectionState,
    DeliveryAcknowledgement, DeliveryState, IllegalTransition, InboundMessage, LifecycleEvent,
    LifecycleObserver, OutboundMessage, RetryPolicy, TransportErrorKind,
};
use claw_channels::{QaChannel, SupervisedChannel, UnixClock, descriptor};

use support::frozen_channel_ids;

const STATES: [ConnectionState; 5] = [
    ConnectionState::Disconnected,
    ConnectionState::Connecting,
    ConnectionState::Connected,
    ConnectionState::Reconnecting,
    ConnectionState::Closed,
];

const EVENTS: [LifecycleEvent; 6] = [
    LifecycleEvent::ConnectRequested,
    LifecycleEvent::Established,
    LifecycleEvent::ConnectionLost,
    LifecycleEvent::ReconnectScheduled,
    LifecycleEvent::DisconnectRequested,
    LifecycleEvent::ShutdownRequested,
];

/// The complete accepted transition relation, written independently of the
/// implementation so a change to either side has to be justified against the
/// other.
const ACCEPTED: [(ConnectionState, LifecycleEvent, ConnectionState); 13] = [
    (
        ConnectionState::Disconnected,
        LifecycleEvent::ConnectRequested,
        ConnectionState::Connecting,
    ),
    (
        ConnectionState::Disconnected,
        LifecycleEvent::ReconnectScheduled,
        ConnectionState::Reconnecting,
    ),
    (
        ConnectionState::Disconnected,
        LifecycleEvent::ShutdownRequested,
        ConnectionState::Closed,
    ),
    (
        ConnectionState::Connecting,
        LifecycleEvent::Established,
        ConnectionState::Connected,
    ),
    (
        ConnectionState::Connecting,
        LifecycleEvent::ConnectionLost,
        ConnectionState::Disconnected,
    ),
    (
        ConnectionState::Connecting,
        LifecycleEvent::DisconnectRequested,
        ConnectionState::Disconnected,
    ),
    (
        ConnectionState::Connecting,
        LifecycleEvent::ShutdownRequested,
        ConnectionState::Closed,
    ),
    (
        ConnectionState::Connected,
        LifecycleEvent::ConnectionLost,
        ConnectionState::Disconnected,
    ),
    (
        ConnectionState::Connected,
        LifecycleEvent::DisconnectRequested,
        ConnectionState::Disconnected,
    ),
    (
        ConnectionState::Connected,
        LifecycleEvent::ShutdownRequested,
        ConnectionState::Closed,
    ),
    (
        ConnectionState::Reconnecting,
        LifecycleEvent::ConnectRequested,
        ConnectionState::Connecting,
    ),
    (
        ConnectionState::Reconnecting,
        LifecycleEvent::DisconnectRequested,
        ConnectionState::Disconnected,
    ),
    (
        ConnectionState::Reconnecting,
        LifecycleEvent::ShutdownRequested,
        ConnectionState::Closed,
    ),
];

#[derive(Clone, Copy, Debug)]
struct FixedClock(u64);

impl UnixClock for FixedClock {
    fn now_unix_ms(&self) -> u64 {
        self.0
    }
}

#[derive(Debug)]
struct IdChannel(&'static str);

impl Channel for IdChannel {
    fn id(&self) -> &str {
        self.0
    }

    fn poll_inbound(&mut self) -> Result<Option<InboundMessage>, ChannelError> {
        Ok(None)
    }

    fn send_outbound(
        &mut self,
        message: &OutboundMessage,
        _credential: Option<&ChannelCredential>,
    ) -> Result<DeliveryAcknowledgement, ChannelError> {
        message.validate().map_err(ChannelError::InvalidMessage)?;
        Ok(DeliveryAcknowledgement {
            correlation_key: message.correlation_key.clone(),
            remote_message_id: None,
            state: DeliveryState::Accepted,
            accepted_at_unix_ms: 3,
        })
    }
}

#[derive(Debug)]
struct ScriptedSession {
    results: VecDeque<Result<(), ChannelError>>,
    opens: usize,
    closes: usize,
}

impl ScriptedSession {
    fn new(results: impl IntoIterator<Item = Result<(), ChannelError>>) -> Self {
        Self {
            results: results.into_iter().collect(),
            opens: 0,
            closes: 0,
        }
    }

    fn always_open() -> Self {
        Self::new([Ok(()), Ok(()), Ok(()), Ok(())])
    }
}

impl ChannelSession for ScriptedSession {
    fn open(&mut self) -> Result<(), ChannelError> {
        self.opens += 1;
        self.results.pop_front().expect("scripted open result")
    }

    fn close(&mut self) -> Result<(), ChannelError> {
        self.closes += 1;
        Ok(())
    }
}

#[derive(Debug, Default)]
struct RecordingObserver(Vec<(ConnectionState, LifecycleEvent, ConnectionState)>);

impl LifecycleObserver for RecordingObserver {
    fn on_transition(&mut self, from: ConnectionState, event: LifecycleEvent, to: ConnectionState) {
        self.0.push((from, event, to));
    }
}

#[derive(Debug, Default)]
struct RecordingSleeper(Vec<Duration>);

impl BackoffSleeper for RecordingSleeper {
    fn sleep(&mut self, delay: Duration) {
        self.0.push(delay);
    }
}

fn policy(max_attempts: u32) -> RetryPolicy {
    RetryPolicy::new(
        NonZeroU32::new(max_attempts).expect("non-zero attempts"),
        Duration::from_millis(10),
        Duration::from_millis(40),
        NonZeroU32::new(2).expect("non-zero multiplier"),
    )
    .expect("valid retry policy")
}

fn outbound() -> OutboundMessage {
    OutboundMessage {
        correlation_key: "delivery-1".to_owned(),
        account_id: "primary".to_owned(),
        conversation_id: "room-1".to_owned(),
        text: Some("hello".to_owned()),
        attachments: Vec::new(),
        reply_to: None,
    }
}

#[test]
fn connection_state_machine_accepts_exactly_the_contract_transitions() {
    for from in STATES {
        for event in EVENTS {
            let expected = ACCEPTED
                .iter()
                .find(|(state, accepted, _)| *state == from && *accepted == event)
                .map(|(_, _, to)| *to);
            assert_eq!(
                from.apply(event),
                expected.ok_or(IllegalTransition { from, event }),
                "{from:?} + {event:?}"
            );
        }
    }

    assert_eq!(ACCEPTED.len(), 13);
    assert!(
        ACCEPTED
            .iter()
            .all(|(from, _, _)| *from != ConnectionState::Closed),
        "shutdown must be terminal"
    );
    for state in STATES {
        assert_eq!(
            state.can_exchange(),
            state == ConnectionState::Connected,
            "{state:?}"
        );
        assert_eq!(
            state.is_terminal(),
            state == ConnectionState::Closed,
            "{state:?}"
        );
    }
    assert_eq!(ConnectionState::default(), ConnectionState::Disconnected);
}

#[test]
fn transient_open_failures_reconnect_with_bounded_backoff() {
    let mut channel = SupervisedChannel::new(
        IdChannel("qa-channel"),
        ScriptedSession::new([
            Err(ChannelError::Transport(TransportErrorKind::Timeout)),
            Err(ChannelError::RateLimited {
                retry_after: Duration::from_millis(500),
            }),
            Ok(()),
        ]),
        policy(4),
    );
    let mut sleeper = RecordingSleeper::default();
    let mut observer = RecordingObserver::default();

    assert_eq!(channel.connect(&mut sleeper, &mut observer), Ok(()));
    assert_eq!(channel.state(), ConnectionState::Connected);
    assert_eq!(channel.session().opens, 3);
    assert_eq!(
        sleeper.0,
        vec![Duration::from_millis(10), Duration::from_millis(40)],
        "the provider delay must be clamped to the policy maximum"
    );
    assert_eq!(
        observer.0,
        vec![
            (
                ConnectionState::Disconnected,
                LifecycleEvent::ConnectRequested,
                ConnectionState::Connecting
            ),
            (
                ConnectionState::Connecting,
                LifecycleEvent::ConnectionLost,
                ConnectionState::Disconnected
            ),
            (
                ConnectionState::Disconnected,
                LifecycleEvent::ReconnectScheduled,
                ConnectionState::Reconnecting
            ),
            (
                ConnectionState::Reconnecting,
                LifecycleEvent::ConnectRequested,
                ConnectionState::Connecting
            ),
            (
                ConnectionState::Connecting,
                LifecycleEvent::ConnectionLost,
                ConnectionState::Disconnected
            ),
            (
                ConnectionState::Disconnected,
                LifecycleEvent::ReconnectScheduled,
                ConnectionState::Reconnecting
            ),
            (
                ConnectionState::Reconnecting,
                LifecycleEvent::ConnectRequested,
                ConnectionState::Connecting
            ),
            (
                ConnectionState::Connecting,
                LifecycleEvent::Established,
                ConnectionState::Connected
            ),
        ]
    );
}

#[test]
fn unrecoverable_and_exhausted_open_failures_stop_reconnecting() {
    let mut unrecoverable = SupervisedChannel::new(
        IdChannel("qa-channel"),
        ScriptedSession::new([Err(ChannelError::Authentication)]),
        policy(3),
    );
    let mut sleeper = RecordingSleeper::default();
    assert_eq!(
        unrecoverable.connect(&mut sleeper, &mut ()),
        Err(ChannelError::Authentication)
    );
    assert_eq!(unrecoverable.session().opens, 1);
    assert!(sleeper.0.is_empty());
    assert_eq!(unrecoverable.state(), ConnectionState::Disconnected);

    let mut exhausted = SupervisedChannel::new(
        IdChannel("qa-channel"),
        ScriptedSession::new([
            Err(ChannelError::Transport(TransportErrorKind::Connection)),
            Err(ChannelError::Transport(TransportErrorKind::Connection)),
            Err(ChannelError::Transport(TransportErrorKind::Connection)),
        ]),
        policy(3),
    );
    let mut sleeper = RecordingSleeper::default();
    assert_eq!(
        exhausted.connect(&mut sleeper, &mut ()),
        Err(ChannelError::Transport(TransportErrorKind::Connection))
    );
    assert_eq!(exhausted.session().opens, 3);
    assert_eq!(
        sleeper.0,
        vec![Duration::from_millis(10), Duration::from_millis(20)]
    );
    assert_eq!(exhausted.state(), ConnectionState::Disconnected);
}

#[test]
fn messages_are_refused_until_a_session_is_open_and_forever_after_shutdown() {
    let mut channel = SupervisedChannel::new(
        QaChannel::new("primary", FixedClock(64)).expect("valid QA adapter"),
        ScriptedSession::always_open(),
        policy(2),
    );
    let mut sleeper = RecordingSleeper::default();
    let mut observer = RecordingObserver::default();

    assert_eq!(channel.id(), "qa-channel");
    assert_eq!(
        channel.send_outbound(&outbound(), None),
        Err(ChannelError::NotConnected {
            state: ConnectionState::Disconnected
        })
    );
    assert_eq!(
        channel.poll_inbound(),
        Err(ChannelError::NotConnected {
            state: ConnectionState::Disconnected
        })
    );

    assert_eq!(channel.connect(&mut sleeper, &mut observer), Ok(()));
    assert_eq!(
        channel.send_outbound(&outbound(), None),
        Ok(DeliveryAcknowledgement {
            correlation_key: "delivery-1".to_owned(),
            remote_message_id: Some("qa-1".to_owned()),
            state: DeliveryState::Delivered,
            accepted_at_unix_ms: 64,
        })
    );
    assert_eq!(channel.poll_inbound(), Ok(None));

    assert_eq!(channel.disconnect(&mut observer), Ok(()));
    assert_eq!(channel.state(), ConnectionState::Disconnected);
    assert_eq!(channel.session().closes, 1);
    assert_eq!(
        channel.send_outbound(&outbound(), None),
        Err(ChannelError::NotConnected {
            state: ConnectionState::Disconnected
        })
    );

    assert_eq!(channel.connect(&mut sleeper, &mut observer), Ok(()));
    assert_eq!(channel.state(), ConnectionState::Connected);
    assert_eq!(channel.connection_lost(&mut observer), Ok(()));
    assert_eq!(channel.state(), ConnectionState::Disconnected);
    assert_eq!(
        channel.send_outbound(&outbound(), None),
        Err(ChannelError::NotConnected {
            state: ConnectionState::Disconnected
        })
    );

    assert_eq!(channel.shutdown(&mut observer), Ok(()));
    assert_eq!(channel.state(), ConnectionState::Closed);
    assert_eq!(channel.session().closes, 2);
    assert_eq!(
        channel.send_outbound(&outbound(), None),
        Err(ChannelError::NotConnected {
            state: ConnectionState::Closed
        })
    );
    assert_eq!(
        channel.connect(&mut sleeper, &mut observer),
        Err(ChannelError::Lifecycle(IllegalTransition {
            from: ConnectionState::Closed,
            event: LifecycleEvent::ConnectRequested,
        })),
        "a shut down channel must never reconnect"
    );
    assert_eq!(channel.session().opens, 2);
    assert!(sleeper.0.is_empty());
    assert_eq!(channel.inner().outbound().len(), 1);
}

#[test]
fn every_frozen_channel_is_gated_by_the_same_session_lifecycle() {
    let frozen_ids = frozen_channel_ids();
    assert!(!frozen_ids.is_empty());

    for id in &frozen_ids {
        let entry = descriptor(id).unwrap_or_else(|| panic!("frozen channel {id} is unregistered"));
        let mut channel = SupervisedChannel::new(
            IdChannel(entry.id),
            ScriptedSession::always_open(),
            policy(2),
        );
        let mut sleeper = RecordingSleeper::default();

        assert_eq!(channel.id(), id);
        assert_eq!(channel.state(), ConnectionState::Disconnected);
        assert_eq!(
            channel.send_outbound(&outbound(), None),
            Err(ChannelError::NotConnected {
                state: ConnectionState::Disconnected
            }),
            "{id}"
        );
        assert_eq!(channel.connect(&mut sleeper, &mut ()), Ok(()), "{id}");
        assert!(channel.send_outbound(&outbound(), None).is_ok(), "{id}");
        assert_eq!(channel.shutdown(&mut ()), Ok(()), "{id}");
        assert_eq!(
            channel.send_outbound(&outbound(), None),
            Err(ChannelError::NotConnected {
                state: ConnectionState::Closed
            }),
            "{id}"
        );
        assert!(sleeper.0.is_empty(), "{id}");
    }
}

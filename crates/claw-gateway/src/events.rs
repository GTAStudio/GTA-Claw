//! The frozen Gateway event catalog, its visibility policy, and the fan-out bus.
//!
//! # Sequencing model
//!
//! The bus assigns every publication a process-wide monotonic ordinal. That
//! ordinal is *not* the wire `seq`: subscribers are scope-filtered, so a wire
//! sequence derived from the bus ordinal would show spurious gaps to clients.
//! Each connection therefore assigns its own consecutive wire sequence for the
//! broadcasts it actually writes, which is exactly what
//! [`claw_protocol::gateway::EventSequenceTracker`] requires.
//!
//! The bus ordinal is what makes *server-side* gap detection precise: when a
//! subscriber's bounded queue overflows, the bus records the ordinal of the
//! first publication it could not enqueue and terminates that subscription, so
//! the connection learns it has an incomplete view instead of silently skipping
//! events.

use std::collections::BTreeSet;
use std::sync::Arc;
use std::sync::Mutex;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};

use claw_protocol::gateway::{
    EventFrame, EventName, EventSequence, OpaqueField, OpaqueJson, OperatorScope, Role,
    StateVersion, core_events, resolve_core_event,
};
use serde::Serialize;
use tokio::sync::mpsc;

use crate::error::EncodeError;

/// Identity assigned to one accepted connection.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct ConnectionId(u64);

impl ConnectionId {
    /// Creates a connection identity.
    #[must_use]
    pub const fn new(value: u64) -> Self {
        Self(value)
    }

    /// Returns the numeric identity.
    #[must_use]
    pub const fn get(self) -> u64 {
        self.0
    }
}

/// Who is entitled to observe one catalogued event.
///
/// The frozen inventory carries event *names* only; it declares no per-event
/// authorization descriptor. This policy is therefore this crate's own,
/// deliberately conservative reading of the upstream families: approvals,
/// pairing, and terminal streams are restricted, node-directed events never
/// reach operators, and everything else needs at least `operator.read`.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum EventVisibility {
    /// Emitted during the pre-authentication handshake only; never broadcast.
    Handshake,
    /// Delivered to every authenticated connection regardless of role.
    AllAuthenticated,
    /// Delivered to node-role connections only.
    Node,
    /// Delivered to operator connections holding this scope.
    Operator(OperatorScope),
}

impl EventVisibility {
    /// Reports whether an authenticated principal may observe this event.
    #[must_use]
    pub fn admits(self, role: Role, granted: &[OperatorScope]) -> bool {
        match self {
            Self::Handshake => false,
            Self::AllAuthenticated => role != Role::Worker,
            Self::Node => role == Role::Node,
            Self::Operator(required) => role == Role::Operator && satisfies(granted, required),
        }
    }
}

/// Reports whether `granted` satisfies `required` under the Gateway scope implications.
///
/// `operator.admin` satisfies every scope and `operator.write` additionally
/// satisfies `operator.read`; no other implication exists.
#[must_use]
pub fn satisfies(granted: &[OperatorScope], required: OperatorScope) -> bool {
    granted.contains(&OperatorScope::Admin)
        || granted.contains(&required)
        || (required == OperatorScope::Read && granted.contains(&OperatorScope::Write))
}

/// Returns the visibility policy for one catalogued event identity.
///
/// Returns `None` for any identity outside the frozen 33-event catalog.
#[must_use]
pub fn event_visibility(event: &str) -> Option<EventVisibility> {
    let visibility = match event {
        "connect.challenge" => EventVisibility::Handshake,
        "tick" | "shutdown" | "heartbeat" => EventVisibility::AllAuthenticated,
        "node.invoke.request" => EventVisibility::Node,
        "session.approval"
        | "exec.approval.requested"
        | "exec.approval.resolved"
        | "plugin.approval.requested"
        | "plugin.approval.resolved" => EventVisibility::Operator(OperatorScope::Approvals),
        "node.pair.requested"
        | "node.pair.resolved"
        | "device.pair.requested"
        | "device.pair.resolved" => EventVisibility::Operator(OperatorScope::Pairing),
        "terminal.data" | "terminal.exit" => EventVisibility::Operator(OperatorScope::Admin),
        "agent"
        | "chat"
        | "session.message"
        | "session.operation"
        | "session.tool"
        | "sessions.changed"
        | "presence"
        | "talk.mode"
        | "talk.event"
        | "health"
        | "cron"
        | "task"
        | "task.suggestion"
        | "node.presence"
        | "voicewake.changed"
        | "voicewake.routing.changed"
        | "update.available" => EventVisibility::Operator(OperatorScope::Read),
        _ => return None,
    };
    Some(visibility)
}

/// Returns every catalogued event identity paired with its visibility policy.
#[must_use]
pub fn event_catalog() -> Vec<(&'static str, EventVisibility)> {
    core_events()
        .iter()
        .map(|event| {
            let name = event.name();
            let visibility = event_visibility(name)
                .expect("every frozen catalog event has an explicit visibility policy");
            (name, visibility)
        })
        .collect()
}

/// Topic groups a connection can opt out of at runtime.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TopicGroup {
    /// `sessions.changed`, `session.approval`, `session.operation`, `session.tool`.
    SessionLifecycle,
    /// `session.message`.
    SessionMessages,
}

impl TopicGroup {
    /// Returns the topic group an event belongs to, when it belongs to one.
    #[must_use]
    pub fn for_event(event: &str) -> Option<Self> {
        match event {
            "sessions.changed" | "session.approval" | "session.operation" | "session.tool" => {
                Some(Self::SessionLifecycle)
            }
            "session.message" => Some(Self::SessionMessages),
            _ => None,
        }
    }
}

/// Per-connection subscription filter applied before fan-out.
///
/// Both groups start subscribed with no session allowlist, so a client that
/// never calls a subscription method observes the full broadcast stream it is
/// authorized for. `unsubscribe` narrows; `subscribe` re-widens.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TopicFilter {
    lifecycle: bool,
    messages: bool,
    sessions: BTreeSet<String>,
}

impl Default for TopicFilter {
    fn default() -> Self {
        Self {
            lifecycle: true,
            messages: true,
            sessions: BTreeSet::new(),
        }
    }
}

impl TopicFilter {
    /// Subscribes a topic group, optionally restricting it to specific sessions.
    ///
    /// Supplying session identities adds them to the allowlist. An empty
    /// allowlist means "every session".
    pub fn subscribe(&mut self, group: TopicGroup, sessions: impl IntoIterator<Item = String>) {
        match group {
            TopicGroup::SessionLifecycle => self.lifecycle = true,
            TopicGroup::SessionMessages => self.messages = true,
        }
        self.sessions.extend(sessions);
    }

    /// Unsubscribes a topic group, or removes specific sessions from the allowlist.
    pub fn unsubscribe(&mut self, group: TopicGroup, sessions: &[String]) {
        if sessions.is_empty() {
            match group {
                TopicGroup::SessionLifecycle => self.lifecycle = false,
                TopicGroup::SessionMessages => self.messages = false,
            }
            return;
        }
        for session in sessions {
            self.sessions.remove(session);
        }
    }

    /// Returns the session allowlist; empty means unrestricted.
    #[must_use]
    pub fn sessions(&self) -> &BTreeSet<String> {
        &self.sessions
    }

    /// Reports whether this filter admits an envelope.
    #[must_use]
    pub fn admits(&self, envelope: &EventEnvelope) -> bool {
        let Some(group) = TopicGroup::for_event(envelope.name()) else {
            return true;
        };
        let subscribed = match group {
            TopicGroup::SessionLifecycle => self.lifecycle,
            TopicGroup::SessionMessages => self.messages,
        };
        if !subscribed {
            return false;
        }
        match envelope.session_id() {
            None => true,
            Some(session) => self.sessions.is_empty() || self.sessions.contains(session),
        }
    }
}

/// Who a published event is addressed to.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum EventAudience {
    /// Every subscriber admitted by the event's visibility policy and filter.
    Broadcast,
    /// Exactly one connection, which must still be admitted by the policy.
    Connection(ConnectionId),
}

#[derive(Debug)]
struct EnvelopeInner {
    name: &'static str,
    event: EventName,
    payload: OpaqueJson,
    encoded_len: usize,
    audience: EventAudience,
    visibility: EventVisibility,
    session_id: Option<String>,
    state_version: Option<StateVersion>,
    ordinal: EventSequence,
}

/// One published event with its routing metadata.
#[derive(Clone, Debug)]
pub struct EventEnvelope {
    inner: Arc<EnvelopeInner>,
}

impl EventEnvelope {
    /// Returns the exact catalogued event identity.
    #[must_use]
    pub fn name(&self) -> &'static str {
        self.inner.name
    }

    /// Returns the bus publication ordinal.
    #[must_use]
    pub fn ordinal(&self) -> EventSequence {
        self.inner.ordinal
    }

    /// Returns the routing audience.
    #[must_use]
    pub fn audience(&self) -> EventAudience {
        self.inner.audience
    }

    /// Returns the visibility policy applied at publication time.
    #[must_use]
    pub fn visibility(&self) -> EventVisibility {
        self.inner.visibility
    }

    /// Returns the session identity used for allowlist filtering.
    #[must_use]
    pub fn session_id(&self) -> Option<&str> {
        self.inner.session_id.as_deref()
    }

    /// Returns the encoded payload byte length used for queue accounting.
    #[must_use]
    pub fn encoded_len(&self) -> usize {
        self.inner.encoded_len
    }

    /// Builds the wire frame, attaching `seq` only to broadcasts.
    #[must_use]
    pub fn to_frame(&self, sequence: EventSequence) -> EventFrame {
        let sequence = match self.inner.audience {
            EventAudience::Broadcast => Some(sequence),
            EventAudience::Connection(_) => None,
        };
        EventFrame::new(
            self.inner.event.clone(),
            OpaqueField::Value(self.inner.payload.clone()),
            sequence,
            self.inner.state_version,
        )
    }
}

/// A catalogued event awaiting publication.
#[derive(Clone, Debug)]
pub struct EventDraft {
    name: &'static str,
    event: EventName,
    payload: OpaqueJson,
    encoded_len: usize,
    audience: EventAudience,
    visibility: EventVisibility,
    session_id: Option<String>,
    state_version: Option<StateVersion>,
}

impl EventDraft {
    /// Creates a broadcast draft for a catalogued event identity.
    ///
    /// Fails when the identity is outside the frozen 33-event catalog, when the
    /// identity is handshake-only, or when the payload cannot be serialized.
    pub fn broadcast<T: Serialize>(event: &str, payload: &T) -> Result<Self, EventError> {
        Self::build(event, payload, EventAudience::Broadcast)
    }

    /// Creates a draft addressed to exactly one connection.
    pub fn targeted<T: Serialize>(
        event: &str,
        payload: &T,
        connection: ConnectionId,
    ) -> Result<Self, EventError> {
        Self::build(event, payload, EventAudience::Connection(connection))
    }

    fn build<T: Serialize>(
        event: &str,
        payload: &T,
        audience: EventAudience,
    ) -> Result<Self, EventError> {
        let descriptor =
            resolve_core_event(event).ok_or_else(|| EventError::UnknownEvent(event.to_owned()))?;
        let visibility = event_visibility(descriptor.name())
            .expect("every frozen catalog event has an explicit visibility policy");
        if visibility == EventVisibility::Handshake {
            return Err(EventError::HandshakeOnly(descriptor.name()));
        }
        let json = serde_json::to_string(payload).map_err(EncodeError::from)?;
        let encoded_len = json.len();
        let payload: OpaqueJson = serde_json::from_str(&json).map_err(EncodeError::from)?;
        Ok(Self {
            name: descriptor.name(),
            event: EventName::Core(descriptor),
            payload,
            encoded_len,
            audience,
            visibility,
            session_id: None,
            state_version: None,
        })
    }

    /// Attaches the session identity used by subscription allowlists.
    #[must_use]
    pub fn with_session(mut self, session_id: impl Into<String>) -> Self {
        self.session_id = Some(session_id.into());
        self
    }

    /// Attaches snapshot subtree versions.
    #[must_use]
    pub const fn with_state_version(mut self, state_version: StateVersion) -> Self {
        self.state_version = Some(state_version);
        self
    }

    /// Returns the catalogued event identity.
    #[must_use]
    pub const fn name(&self) -> &'static str {
        self.name
    }
}

/// A publication or catalog failure.
#[derive(Clone, Debug)]
pub enum EventError {
    /// The identity is outside the frozen 33-event catalog.
    UnknownEvent(String),
    /// The identity is only emitted by the pre-authentication handshake.
    HandshakeOnly(&'static str),
    /// The payload could not be encoded.
    Encode(EncodeError),
}

impl std::fmt::Display for EventError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::UnknownEvent(name) => write!(formatter, "unknown gateway event `{name}`"),
            Self::HandshakeOnly(name) => {
                write!(formatter, "`{name}` is only emitted during the handshake")
            }
            Self::Encode(error) => std::fmt::Display::fmt(error, formatter),
        }
    }
}

impl std::error::Error for EventError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Encode(error) => Some(error),
            _ => None,
        }
    }
}

impl From<EncodeError> for EventError {
    fn from(error: EncodeError) -> Self {
        Self::Encode(error)
    }
}

#[derive(Debug)]
struct LagState {
    first_missed: AtomicU64,
    queued_bytes: AtomicUsize,
}

#[derive(Debug)]
struct Subscriber {
    id: ConnectionId,
    role: Role,
    scopes: Vec<OperatorScope>,
    filter: Arc<Mutex<TopicFilter>>,
    sender: mpsc::Sender<EventEnvelope>,
    lag: Arc<LagState>,
}

#[derive(Debug)]
struct BusInner {
    ordinal: AtomicU64,
    subscribers: Mutex<Vec<Subscriber>>,
    queue_capacity: usize,
    queue_bytes: usize,
}

/// A bounded, scope-filtered event fan-out bus.
#[derive(Clone, Debug)]
pub struct EventBus {
    inner: Arc<BusInner>,
}

impl EventBus {
    /// Creates a bus with explicit per-subscriber queue bounds.
    ///
    /// # Panics
    ///
    /// Panics when either bound is zero; [`crate::config::GatewayServerConfig`]
    /// rejects zero bounds before a server is constructed.
    #[must_use]
    pub fn new(queue_capacity: usize, queue_bytes: usize) -> Self {
        assert!(queue_capacity > 0, "event queue capacity must be positive");
        assert!(queue_bytes > 0, "event queue byte bound must be positive");
        Self {
            inner: Arc::new(BusInner {
                ordinal: AtomicU64::new(0),
                subscribers: Mutex::new(Vec::new()),
                queue_capacity,
                queue_bytes,
            }),
        }
    }

    fn subscribers(&self) -> std::sync::MutexGuard<'_, Vec<Subscriber>> {
        self.inner
            .subscribers
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    /// Registers one authenticated connection and returns its subscription.
    ///
    /// Re-registering the same [`ConnectionId`] replaces the previous
    /// subscription, which closes the previous receiver.
    pub fn subscribe(
        &self,
        id: ConnectionId,
        role: Role,
        scopes: Vec<OperatorScope>,
        filter: Arc<Mutex<TopicFilter>>,
    ) -> EventSubscription {
        let (sender, receiver) = mpsc::channel(self.inner.queue_capacity);
        let lag = Arc::new(LagState {
            first_missed: AtomicU64::new(0),
            queued_bytes: AtomicUsize::new(0),
        });
        let mut subscribers = self.subscribers();
        subscribers.retain(|subscriber| subscriber.id != id);
        subscribers.push(Subscriber {
            id,
            role,
            scopes,
            filter,
            sender,
            lag: Arc::clone(&lag),
        });
        drop(subscribers);
        EventSubscription {
            id,
            receiver,
            lag,
            bus: self.clone(),
        }
    }

    /// Removes one subscription, closing its receiver.
    pub fn unsubscribe(&self, id: ConnectionId) {
        self.subscribers().retain(|subscriber| subscriber.id != id);
    }

    /// Replaces the role and scopes fan-out uses for one subscriber.
    ///
    /// Returns `true` when a live subscription was updated. This is how a
    /// connection whose authorization narrowed stops being *considered* for
    /// events it may no longer see, rather than being handed them and
    /// filtering afterwards.
    pub fn reauthorize(&self, id: ConnectionId, role: Role, scopes: Vec<OperatorScope>) -> bool {
        let mut subscribers = self.subscribers();
        let Some(subscriber) = subscribers
            .iter_mut()
            .find(|subscriber| subscriber.id == id)
        else {
            return false;
        };
        subscriber.role = role;
        subscriber.scopes = scopes;
        drop(subscribers);
        true
    }

    /// Returns the number of live subscriptions.
    #[must_use]
    pub fn subscriber_count(&self) -> usize {
        self.subscribers().len()
    }

    /// Returns the last assigned publication ordinal, or zero before the first.
    #[must_use]
    pub fn last_ordinal(&self) -> u64 {
        self.inner.ordinal.load(Ordering::Acquire)
    }

    /// Publishes a draft and returns the assigned publication ordinal.
    ///
    /// Fan-out never blocks: a subscriber whose bounded queue would overflow is
    /// recorded as lagging from this ordinal and its subscription is closed.
    pub fn publish(&self, draft: EventDraft) -> EventSequence {
        let ordinal = self.inner.ordinal.fetch_add(1, Ordering::AcqRel) + 1;
        let ordinal = EventSequence::new(ordinal).expect("bus ordinals start at one");
        let envelope = EventEnvelope {
            inner: Arc::new(EnvelopeInner {
                name: draft.name,
                event: draft.event,
                payload: draft.payload,
                encoded_len: draft.encoded_len,
                audience: draft.audience,
                visibility: draft.visibility,
                session_id: draft.session_id,
                state_version: draft.state_version,
                ordinal,
            }),
        };

        let mut subscribers = self.subscribers();
        let mut lagged = Vec::new();
        for subscriber in subscribers.iter() {
            if let EventAudience::Connection(target) = envelope.audience()
                && target != subscriber.id
            {
                continue;
            }
            if !envelope
                .visibility()
                .admits(subscriber.role, &subscriber.scopes)
            {
                continue;
            }
            let admitted = subscriber
                .filter
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .admits(&envelope);
            if !admitted {
                continue;
            }
            let queued = subscriber.lag.queued_bytes.load(Ordering::Acquire);
            // An empty queue always admits one envelope so that a single event
            // larger than the whole byte budget cannot permanently poison a
            // subscriber; the bound only throttles accumulation.
            let would_exceed_bytes = queued > 0
                && queued.saturating_add(envelope.encoded_len()) > self.inner.queue_bytes;
            if would_exceed_bytes || subscriber.sender.try_send(envelope.clone()).is_err() {
                subscriber
                    .lag
                    .first_missed
                    .compare_exchange(0, ordinal.get(), Ordering::AcqRel, Ordering::Acquire)
                    .ok();
                lagged.push(subscriber.id);
            } else {
                subscriber
                    .lag
                    .queued_bytes
                    .fetch_add(envelope.encoded_len(), Ordering::AcqRel);
            }
        }
        if !lagged.is_empty() {
            subscribers.retain(|subscriber| !lagged.contains(&subscriber.id));
        }
        drop(subscribers);
        ordinal
    }
}

/// One delivery observed by a subscribed connection.
#[derive(Clone, Debug)]
pub enum Delivery {
    /// An event the connection is entitled to write.
    Event(EventEnvelope),
    /// The bounded queue overflowed; the connection's view is incomplete.
    Lagged {
        /// Bus ordinal of the first publication that could not be enqueued.
        first_missed: EventSequence,
    },
    /// The subscription was removed and no gap was recorded.
    Closed,
}

/// A live subscription owned by one connection task.
#[derive(Debug)]
pub struct EventSubscription {
    id: ConnectionId,
    receiver: mpsc::Receiver<EventEnvelope>,
    lag: Arc<LagState>,
    bus: EventBus,
}

impl EventSubscription {
    /// Returns the owning connection identity.
    #[must_use]
    pub const fn connection_id(&self) -> ConnectionId {
        self.id
    }

    /// Awaits the next delivery.
    ///
    /// Every envelope already enqueued before a gap is delivered first, so the
    /// connection writes everything it legitimately received and only then
    /// observes [`Delivery::Lagged`].
    pub async fn recv(&mut self) -> Delivery {
        match self.receiver.recv().await {
            Some(envelope) => {
                self.lag
                    .queued_bytes
                    .fetch_sub(envelope.encoded_len(), Ordering::AcqRel);
                Delivery::Event(envelope)
            }
            None => match self.lag.first_missed.load(Ordering::Acquire) {
                0 => Delivery::Closed,
                missed => Delivery::Lagged {
                    first_missed: EventSequence::new(missed)
                        .expect("recorded ordinals are always positive"),
                },
            },
        }
    }

    /// Takes one already-queued delivery without waiting.
    ///
    /// Returns `None` when nothing is queued and the subscription is still
    /// open. This is how a connection flushes the events it legitimately
    /// received before it stops for an unrelated reason such as shutdown.
    pub fn try_recv(&mut self) -> Option<Delivery> {
        match self.receiver.try_recv() {
            Ok(envelope) => {
                self.lag
                    .queued_bytes
                    .fetch_sub(envelope.encoded_len(), Ordering::AcqRel);
                Some(Delivery::Event(envelope))
            }
            Err(mpsc::error::TryRecvError::Empty) => None,
            Err(mpsc::error::TryRecvError::Disconnected) => {
                Some(match self.lag.first_missed.load(Ordering::Acquire) {
                    0 => Delivery::Closed,
                    missed => Delivery::Lagged {
                        first_missed: EventSequence::new(missed)
                            .expect("recorded ordinals are always positive"),
                    },
                })
            }
        }
    }
}

impl Drop for EventSubscription {
    fn drop(&mut self) {
        self.bus.unsubscribe(self.id);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn filter() -> Arc<Mutex<TopicFilter>> {
        Arc::new(Mutex::new(TopicFilter::default()))
    }

    #[test]
    fn catalog_covers_every_frozen_event_exactly_once() {
        let catalog = event_catalog();
        assert_eq!(catalog.len(), 33);
        let names: BTreeSet<&str> = catalog.iter().map(|(name, _)| *name).collect();
        assert_eq!(names.len(), 33);
        assert!(names.contains("connect.challenge"));
        assert!(names.contains("update.available"));
    }

    #[test]
    fn visibility_policy_is_pinned_for_each_family() {
        assert_eq!(
            event_visibility("connect.challenge"),
            Some(EventVisibility::Handshake)
        );
        assert_eq!(
            event_visibility("tick"),
            Some(EventVisibility::AllAuthenticated)
        );
        assert_eq!(
            event_visibility("node.invoke.request"),
            Some(EventVisibility::Node)
        );
        assert_eq!(
            event_visibility("exec.approval.requested"),
            Some(EventVisibility::Operator(OperatorScope::Approvals))
        );
        assert_eq!(
            event_visibility("device.pair.resolved"),
            Some(EventVisibility::Operator(OperatorScope::Pairing))
        );
        assert_eq!(
            event_visibility("terminal.data"),
            Some(EventVisibility::Operator(OperatorScope::Admin))
        );
        assert_eq!(
            event_visibility("sessions.changed"),
            Some(EventVisibility::Operator(OperatorScope::Read))
        );
        assert_eq!(event_visibility("not.an.event"), None);
    }

    #[test]
    fn scope_implications_are_admin_all_and_write_implies_read() {
        assert!(satisfies(&[OperatorScope::Admin], OperatorScope::Pairing));
        assert!(satisfies(&[OperatorScope::Write], OperatorScope::Read));
        assert!(!satisfies(&[OperatorScope::Read], OperatorScope::Write));
        assert!(!satisfies(
            &[OperatorScope::Write],
            OperatorScope::Approvals
        ));
        assert!(!satisfies(&[], OperatorScope::Read));
        assert!(satisfies(&[OperatorScope::Pairing], OperatorScope::Pairing));
    }

    #[test]
    fn node_role_never_observes_operator_events() {
        let approvals = EventVisibility::Operator(OperatorScope::Approvals);
        assert!(!approvals.admits(Role::Node, &[OperatorScope::Admin]));
        assert!(approvals.admits(Role::Operator, &[OperatorScope::Approvals]));
        assert!(EventVisibility::Node.admits(Role::Node, &[]));
        assert!(!EventVisibility::Node.admits(Role::Operator, &[OperatorScope::Admin]));
        assert!(!EventVisibility::Handshake.admits(Role::Operator, &[OperatorScope::Admin]));
        assert!(!EventVisibility::AllAuthenticated.admits(Role::Worker, &[]));
    }

    #[test]
    fn handshake_only_events_cannot_be_published() {
        let error = EventDraft::broadcast("connect.challenge", &serde_json::json!({}))
            .expect_err("handshake events are refused");
        assert!(matches!(
            error,
            EventError::HandshakeOnly("connect.challenge")
        ));
    }

    #[test]
    fn unknown_events_cannot_be_published() {
        let error = EventDraft::broadcast("sessions.exploded", &serde_json::json!({}))
            .expect_err("unknown events are refused");
        match error {
            EventError::UnknownEvent(name) => assert_eq!(name, "sessions.exploded"),
            other => panic!("expected UnknownEvent, got {other}"),
        }
    }

    #[tokio::test]
    async fn ordinals_increase_by_exactly_one_per_publication() {
        let bus = EventBus::new(8, 4096);
        let first = bus.publish(
            EventDraft::broadcast("tick", &serde_json::json!({ "ts": 1 })).expect("draft"),
        );
        let second = bus.publish(
            EventDraft::broadcast("tick", &serde_json::json!({ "ts": 2 })).expect("draft"),
        );
        assert_eq!(first.get(), 1);
        assert_eq!(second.get(), 2);
        assert_eq!(bus.last_ordinal(), 2);
    }

    #[tokio::test]
    async fn scope_filtering_excludes_unentitled_subscribers() {
        let bus = EventBus::new(8, 4096);
        let mut reader = bus.subscribe(
            ConnectionId::new(1),
            Role::Operator,
            vec![OperatorScope::Read],
            filter(),
        );
        let mut approver = bus.subscribe(
            ConnectionId::new(2),
            Role::Operator,
            vec![OperatorScope::Approvals],
            filter(),
        );
        bus.publish(
            EventDraft::broadcast("exec.approval.requested", &serde_json::json!({ "id": "a" }))
                .expect("draft"),
        );
        bus.publish(EventDraft::broadcast("tick", &serde_json::json!({ "ts": 9 })).expect("draft"));

        match approver.recv().await {
            Delivery::Event(envelope) => assert_eq!(envelope.name(), "exec.approval.requested"),
            other => panic!("approver missed the approval event: {other:?}"),
        }
        match reader.recv().await {
            Delivery::Event(envelope) => {
                assert_eq!(envelope.name(), "tick");
                assert_eq!(envelope.ordinal().get(), 2);
            }
            other => panic!("reader should have received only the tick: {other:?}"),
        }
    }

    #[tokio::test]
    async fn targeted_events_reach_only_the_addressed_connection() {
        let bus = EventBus::new(8, 4096);
        let mut first = bus.subscribe(ConnectionId::new(1), Role::Node, Vec::new(), filter());
        let mut second = bus.subscribe(ConnectionId::new(2), Role::Node, Vec::new(), filter());
        bus.publish(
            EventDraft::targeted(
                "node.invoke.request",
                &serde_json::json!({ "id": "i1" }),
                ConnectionId::new(2),
            )
            .expect("draft"),
        );
        bus.publish(EventDraft::broadcast("tick", &serde_json::json!({ "ts": 3 })).expect("draft"));

        match second.recv().await {
            Delivery::Event(envelope) => assert_eq!(envelope.name(), "node.invoke.request"),
            other => panic!("target missed its invocation: {other:?}"),
        }
        match first.recv().await {
            Delivery::Event(envelope) => assert_eq!(envelope.name(), "tick"),
            other => panic!("non-target should only see the tick: {other:?}"),
        }
    }

    #[tokio::test]
    async fn targeted_frames_omit_seq_and_broadcast_frames_carry_it() {
        let bus = EventBus::new(4, 4096);
        let mut subscription =
            bus.subscribe(ConnectionId::new(7), Role::Node, Vec::new(), filter());
        bus.publish(
            EventDraft::targeted(
                "node.invoke.request",
                &serde_json::json!({ "id": "i1" }),
                ConnectionId::new(7),
            )
            .expect("draft"),
        );
        bus.publish(EventDraft::broadcast("tick", &serde_json::json!({ "ts": 4 })).expect("draft"));

        let wire = EventSequence::new(1).expect("positive");
        match subscription.recv().await {
            Delivery::Event(envelope) => assert_eq!(envelope.to_frame(wire).sequence(), None),
            other => panic!("expected the targeted event: {other:?}"),
        }
        match subscription.recv().await {
            Delivery::Event(envelope) => {
                assert_eq!(envelope.to_frame(wire).sequence(), Some(wire));
            }
            other => panic!("expected the broadcast event: {other:?}"),
        }
    }

    #[tokio::test]
    async fn queue_overflow_records_the_first_missed_ordinal_after_draining() {
        let bus = EventBus::new(2, 1_000_000);
        let mut subscription =
            bus.subscribe(ConnectionId::new(1), Role::Node, Vec::new(), filter());
        for ts in 1..=3 {
            bus.publish(
                EventDraft::broadcast("tick", &serde_json::json!({ "ts": ts })).expect("draft"),
            );
        }
        for expected in 1..=2_u64 {
            match subscription.recv().await {
                Delivery::Event(envelope) => assert_eq!(envelope.ordinal().get(), expected),
                other => panic!("expected buffered event {expected}: {other:?}"),
            }
        }
        match subscription.recv().await {
            Delivery::Lagged { first_missed } => assert_eq!(first_missed.get(), 3),
            other => panic!("expected a recorded gap at ordinal 3: {other:?}"),
        }
    }

    #[tokio::test]
    async fn byte_bound_triggers_a_gap_before_the_slot_bound() {
        let bus = EventBus::new(64, 48);
        let mut subscription =
            bus.subscribe(ConnectionId::new(1), Role::Node, Vec::new(), filter());
        let payload = serde_json::json!({ "ts": 1, "padding": "0123456789012345678901234567890" });
        assert!(serde_json::to_string(&payload).expect("json").len() > 24);
        bus.publish(EventDraft::broadcast("tick", &payload).expect("draft"));
        bus.publish(EventDraft::broadcast("tick", &payload).expect("draft"));
        match subscription.recv().await {
            Delivery::Event(envelope) => assert_eq!(envelope.ordinal().get(), 1),
            other => panic!("expected the first event: {other:?}"),
        }
        match subscription.recv().await {
            Delivery::Lagged { first_missed } => assert_eq!(first_missed.get(), 2),
            other => panic!("expected a byte-bound gap at ordinal 2: {other:?}"),
        }
    }

    #[tokio::test]
    async fn draining_frees_queue_bytes_for_later_publications() {
        let bus = EventBus::new(4, 64);
        let mut subscription =
            bus.subscribe(ConnectionId::new(1), Role::Node, Vec::new(), filter());
        let payload = serde_json::json!({ "ts": 1, "padding": "01234567890123456789" });
        bus.publish(EventDraft::broadcast("tick", &payload).expect("draft"));
        match subscription.recv().await {
            Delivery::Event(envelope) => assert_eq!(envelope.ordinal().get(), 1),
            other => panic!("expected the first event: {other:?}"),
        }
        bus.publish(EventDraft::broadcast("tick", &payload).expect("draft"));
        match subscription.recv().await {
            Delivery::Event(envelope) => assert_eq!(envelope.ordinal().get(), 2),
            other => panic!("draining should have freed the byte budget: {other:?}"),
        }
    }

    #[tokio::test]
    async fn unsubscribing_closes_without_recording_a_gap() {
        let bus = EventBus::new(4, 4096);
        let mut subscription =
            bus.subscribe(ConnectionId::new(1), Role::Node, Vec::new(), filter());
        bus.unsubscribe(ConnectionId::new(1));
        assert!(matches!(subscription.recv().await, Delivery::Closed));
        assert_eq!(bus.subscriber_count(), 0);
    }

    #[tokio::test]
    async fn dropping_a_subscription_deregisters_it_from_the_bus() {
        let bus = EventBus::new(4, 4096);
        let subscription = bus.subscribe(ConnectionId::new(1), Role::Node, Vec::new(), filter());
        assert_eq!(bus.subscriber_count(), 1);
        drop(subscription);
        assert_eq!(bus.subscriber_count(), 0);
    }

    #[tokio::test]
    async fn topic_filter_blocks_unsubscribed_lifecycle_events() {
        let bus = EventBus::new(8, 4096);
        let shared = filter();
        let mut subscription = bus.subscribe(
            ConnectionId::new(1),
            Role::Operator,
            vec![OperatorScope::Read],
            Arc::clone(&shared),
        );
        shared
            .lock()
            .expect("filter lock")
            .unsubscribe(TopicGroup::SessionLifecycle, &[]);
        bus.publish(
            EventDraft::broadcast("sessions.changed", &serde_json::json!({ "id": "s1" }))
                .expect("draft"),
        );
        bus.publish(EventDraft::broadcast("tick", &serde_json::json!({ "ts": 1 })).expect("draft"));
        match subscription.recv().await {
            Delivery::Event(envelope) => assert_eq!(envelope.name(), "tick"),
            other => panic!("lifecycle event should have been filtered: {other:?}"),
        }
    }

    #[tokio::test]
    async fn session_allowlist_restricts_message_delivery() {
        let bus = EventBus::new(8, 4096);
        let shared = filter();
        let mut subscription = bus.subscribe(
            ConnectionId::new(1),
            Role::Operator,
            vec![OperatorScope::Read],
            Arc::clone(&shared),
        );
        shared
            .lock()
            .expect("filter lock")
            .subscribe(TopicGroup::SessionMessages, ["s-allowed".to_owned()]);
        bus.publish(
            EventDraft::broadcast("session.message", &serde_json::json!({ "text": "no" }))
                .expect("draft")
                .with_session("s-blocked"),
        );
        bus.publish(
            EventDraft::broadcast("session.message", &serde_json::json!({ "text": "yes" }))
                .expect("draft")
                .with_session("s-allowed"),
        );
        match subscription.recv().await {
            Delivery::Event(envelope) => {
                assert_eq!(envelope.session_id(), Some("s-allowed"));
                assert_eq!(envelope.ordinal().get(), 2);
            }
            other => panic!("only the allowlisted session should arrive: {other:?}"),
        }
    }

    #[test]
    fn topic_filter_default_admits_every_group() {
        let filter = TopicFilter::default();
        assert!(filter.sessions().is_empty());
        let draft = EventDraft::broadcast("session.message", &serde_json::json!({}))
            .expect("draft")
            .with_session("s1");
        let envelope = EventEnvelope {
            inner: Arc::new(EnvelopeInner {
                name: draft.name,
                event: draft.event,
                payload: draft.payload,
                encoded_len: draft.encoded_len,
                audience: draft.audience,
                visibility: draft.visibility,
                session_id: draft.session_id,
                state_version: draft.state_version,
                ordinal: EventSequence::new(1).expect("positive"),
            }),
        };
        assert!(filter.admits(&envelope));
    }

    #[test]
    fn unsubscribing_named_sessions_only_narrows_the_allowlist() {
        let mut filter = TopicFilter::default();
        filter.subscribe(
            TopicGroup::SessionMessages,
            ["a".to_owned(), "b".to_owned()],
        );
        filter.unsubscribe(TopicGroup::SessionMessages, &["a".to_owned()]);
        assert_eq!(
            filter.sessions().iter().cloned().collect::<Vec<String>>(),
            vec!["b".to_owned()]
        );
    }
}

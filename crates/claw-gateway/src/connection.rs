//! Per-connection lifecycle: handshake, dispatch loop, event delivery, close.
//!
//! The handshake reads straight from the socket under a single bounded timeout.
//! Only once the hello response has been written does the read half move into a
//! dedicated task feeding a bounded channel — `fastwebsockets` reads are not
//! cancel-safe, so the authenticated loop must never `select!` directly on one.
//! Splitting the phases this way also means the pre-authentication byte cap and
//! the authenticated byte cap are applied by construction rather than by racing
//! a shared limit against an in-flight read.
//!
//! Broadcast sequence numbers are assigned *per connection*, strictly
//! consecutively from one, over exactly the broadcasts this connection is
//! entitled to and actually writes. The bus ordinal is a separate global
//! counter used only for gap reporting, so a connection that is not admitted to
//! an event never observes a hole in its own `seq` stream.

use std::sync::{Arc, Mutex, PoisonError};

use claw_protocol::gateway::{
    AUTHENTICATED_MAX_FRAME_BYTES, AuthenticationDecision, AuthenticationPort,
    AuthenticationRequest, Codec, ConnectErrorDetailCode, ConnectParams, CoreErrorCode, ErrorCode,
    ErrorMessage, ErrorShape, EventFrame, EventName, EventSequence, Frame,
    GATEWAY_PROTOCOL_VERSION, HandshakeRejection, HelloAuth, HelloFeatures, HelloOk, HelloOkKind,
    HelloPolicy, HelloServer, Name, Negotiation, NegotiationError, NonNegativeInteger, OpaqueField,
    OpaqueJson, OperatorScope, PREAUTH_MAX_FRAME_BYTES, PositiveInteger, RequestId, ResponseFrame,
    Role, Snapshot, StateVersion, core_events, resolve_core_event,
};
use serde::Serialize;
use serde_json::{Value, json};
use tokio::net::TcpStream;
use tokio::sync::{mpsc, watch};
use tokio::time::{Instant, MissedTickBehavior, interval_at, timeout};

use crate::auth::issue_challenge;
use crate::authority::AuthorizationSource;
use crate::clock::Clock;
use crate::config::ValidatedConfig;
use crate::directory::{ConnectionDirectory, ConnectionInfo, compatibility_identity};
use crate::dispatch::{MethodContext, MethodRegistry};
use crate::error::{
    ConnectionClose, DispatchError, EncodeError, HandshakeError, StoreError, WireError,
};
use crate::events::{ConnectionId, Delivery, EventBus, TopicFilter};
use crate::store::GatewayStore;
use crate::transport::{self, Inbound, MessageReader, ServerRead, ServerWrite};

/// Bounded inbound queue depth between the reader task and the dispatch loop.
const INBOUND_QUEUE_DEPTH: usize = 1;
/// Upper bound on any error message this server puts on the wire.
const MAX_ERROR_MESSAGE_BYTES: usize = 512;
/// Payload written with every server ping.
const PING_PAYLOAD: &[u8] = b"gtw";
/// Capability identity advertised to every authenticated peer.
const CORE_CAPABILITY: &str = "gateway.core";

/// Shared services one connection needs.
#[derive(Clone)]
pub struct ConnectionServices {
    /// Validated server configuration.
    pub config: Arc<ValidatedConfig>,
    /// Frozen method registry with installed handlers.
    pub registry: Arc<MethodRegistry>,
    /// Persistence port.
    pub store: Arc<dyn GatewayStore>,
    /// Event fan-out bus.
    pub events: EventBus,
    /// Wall-clock port.
    pub clock: Arc<dyn Clock>,
    /// Live authenticated connection directory.
    pub directory: ConnectionDirectory,
    /// Authentication port driving the negotiation reducer.
    pub authenticator: Arc<dyn AuthenticationPort + Send + Sync>,
    /// Authorization currency port consulted before every later action.
    pub authorization: Arc<dyn AuthorizationSource>,
}

impl std::fmt::Debug for ConnectionServices {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("ConnectionServices")
            .field("config", &self.config)
            .field("methods", &self.registry.len())
            .field("subscribers", &self.events.subscriber_count())
            .field("connections", &self.directory.len())
            .finish_non_exhaustive()
    }
}

/// Serves one accepted TCP connection to completion.
///
/// Returns the typed reason the connection ended. A close frame is always
/// attempted before returning, bounded by the configured close timeout.
pub async fn serve(
    stream: TcpStream,
    id: ConnectionId,
    services: ConnectionServices,
    shutdown: watch::Receiver<bool>,
) -> ConnectionClose {
    let limits = *services.config.limits();
    let timeouts = *services.config.timeouts();

    let socket = match timeout(
        timeouts.http_upgrade,
        transport::accept(stream, limits.max_http_upgrade_bytes),
    )
    .await
    {
        Ok(Ok(socket)) => socket,
        Ok(Err(error)) => return ConnectionClose::HandshakeRejected(error.to_string()),
        Err(_) => return ConnectionClose::HandshakeRejected(HandshakeError::TimedOut.to_string()),
    };

    let (mut read, mut write) = transport::split(socket);
    let negotiated = timeout(
        timeouts.handshake,
        negotiate(id, &services, &mut read, &mut write),
    )
    .await;

    let outcome = match negotiated {
        Err(_) => ConnectionClose::HandshakeTimeout,
        Ok(Err(close)) => close,
        Ok(Ok(session)) => {
            let (sender, mut inbound) = mpsc::channel(INBOUND_QUEUE_DEPTH);
            let reader = tokio::spawn(read_loop(read, sender));
            let outcome =
                dispatch_loop(id, &services, &mut write, &mut inbound, session, shutdown).await;
            inbound.close();
            reader.abort();
            outcome
        }
    };

    services.directory.remove(id);
    services.events.unsubscribe(id);
    let _ = timeout(
        timeouts.close,
        transport::write_close(&mut write, outcome.close_code(), outcome.close_reason()),
    )
    .await;
    outcome
}

/// Drains the authenticated read half into a bounded channel.
///
/// The channel depth is the connection's inbound backpressure: a peer cannot
/// queue another request while the previous one is still being served.
async fn read_loop(mut read: ServerRead, sender: mpsc::Sender<Result<Inbound, WireError>>) {
    let mut reader = MessageReader::new();
    loop {
        let message = reader.read(&mut read, AUTHENTICATED_MAX_FRAME_BYTES).await;
        let terminal = matches!(message, Err(_) | Ok(Inbound::Close(_)));
        if sender.send(message).await.is_err() || terminal {
            return;
        }
    }
}

/// Everything the dispatch loop needs that only exists after a successful hello.
#[derive(Debug)]
struct Session {
    role: Role,
    scopes: Vec<OperatorScope>,
    device_id: String,
    filter: Arc<Mutex<TopicFilter>>,
    /// Authorization generation this snapshot was last validated against.
    authorized_at: u64,
}

/// Re-evaluates a connection's authorization against the grant in force now.
///
/// The handshake decides whether a device may connect. It does not decide
/// whether that device may still act minutes later, so this runs before every
/// request the connection makes and before every event it is about to be
/// written — the moment of the action, not the moment of the handshake.
///
/// Two properties matter more than the mechanism:
///
/// * Scopes may only **narrow**. The connection keeps the intersection of what
///   it presented at the handshake with what the directory grants now, so a
///   directory change can take privilege away from a live connection but can
///   never hand it one it did not ask for and prove at connect time.
/// * A withdrawn pairing or a changed role ends the connection. Those are not
///   narrowings of an existing identity, so there is nothing safe to keep.
///
/// The generation is read *before* the grant and stored afterwards. In that
/// order a concurrent change can only cause a redundant re-check; the reverse
/// order could pair a fresh generation with grant data read before the change
/// and keep a revoked grant alive.
fn revalidate(
    id: ConnectionId,
    services: &ConnectionServices,
    session: &mut Session,
) -> Result<(), ConnectionClose> {
    let generation = services.authorization.generation();
    if generation == session.authorized_at {
        return Ok(());
    }
    let revoked = || ConnectionClose::AuthorizationRevoked {
        device_id: session.device_id.clone(),
    };
    let Some(grant) = services.authorization.current_grant(&session.device_id) else {
        return Err(revoked());
    };
    if grant.role != session.role {
        return Err(revoked());
    }
    let retained: Vec<OperatorScope> = session
        .scopes
        .iter()
        .copied()
        .filter(|scope| grant.scopes.contains(scope))
        .collect();
    let narrowed = retained.len() != session.scopes.len();
    session.scopes = retained;
    session.authorized_at = generation;
    if narrowed {
        services
            .events
            .reauthorize(id, session.role, session.scopes.clone());
    }
    Ok(())
}

async fn dispatch_loop(
    id: ConnectionId,
    services: &ConnectionServices,
    write: &mut ServerWrite,
    inbound: &mut mpsc::Receiver<Result<Inbound, WireError>>,
    mut session: Session,
    mut shutdown: watch::Receiver<bool>,
) -> ConnectionClose {
    let timeouts = *services.config.timeouts();
    let max_unanswered = services.config.limits().max_unanswered_pings;
    let mut subscription = services.events.subscribe(
        id,
        session.role,
        session.scopes.clone(),
        Arc::clone(&session.filter),
    );
    let codec = Codec::authenticated();
    let mut broadcast_seq: u64 = 0;
    let mut unanswered_pings: u32 = 0;
    let mut ping_timer = interval_at(
        Instant::now() + timeouts.ping_interval,
        timeouts.ping_interval,
    );
    ping_timer.set_missed_tick_behavior(MissedTickBehavior::Delay);

    loop {
        tokio::select! {
            biased;
            changed = shutdown.changed() => {
                if changed.is_err() || *shutdown.borrow() {
                    // Flush what this subscriber already legitimately received
                    // — including the broadcast `shutdown` event, which the
                    // handle publishes before it signals — and only then close.
                    // The drain is bounded by the queue capacity so a
                    // concurrent publisher cannot delay the close indefinitely.
                    let capacity = services.config.limits().event_queue_capacity;
                    for _ in 0..capacity {
                        let Some(delivery) = subscription.try_recv() else {
                            break;
                        };
                        if let Err(close) =
                            deliver(write, &codec, &mut broadcast_seq, services, &session, delivery).await
                        {
                            return close;
                        }
                    }
                    return ConnectionClose::ServerShutdown;
                }
            }
            message = inbound.recv() => {
                if let Err(close) = revalidate(id, services, &mut session) {
                    return close;
                }
                match handle_inbound(id, services, write, &codec, &session, message).await {
                    Ok(()) => unanswered_pings = 0,
                    Err(close) => return close,
                }
            }
            delivery = subscription.recv() => {
                if let Err(close) = revalidate(id, services, &mut session) {
                    return close;
                }
                match deliver(write, &codec, &mut broadcast_seq, services, &session, delivery).await {
                    Ok(()) => {}
                    Err(close) => return close,
                }
            }
            _ = ping_timer.tick() => {
                // An otherwise idle connection is revalidated here, so a
                // revoked device is closed within one ping interval rather
                // than lingering until it next chooses to speak.
                if let Err(close) = revalidate(id, services, &mut session) {
                    return close;
                }
                if unanswered_pings >= max_unanswered {
                    return ConnectionClose::Unresponsive;
                }
                unanswered_pings = unanswered_pings.saturating_add(1);
                if let Err(error) = transport::write_ping(write, PING_PAYLOAD.to_vec()).await {
                    return ConnectionClose::Transport(error);
                }
            }
        }
    }
}

async fn deliver(
    write: &mut ServerWrite,
    codec: &Codec,
    broadcast_seq: &mut u64,
    services: &ConnectionServices,
    session: &Session,
    delivery: Delivery,
) -> Result<(), ConnectionClose> {
    match delivery {
        Delivery::Event(envelope) => {
            // The bus filtered this envelope against the subscriber's scopes at
            // publication time. Authorization can have narrowed in between, so
            // the entitlement is checked again here, against the session as it
            // stands at the instant the bytes would go out. Dropping the
            // envelope costs no sequence number, so the peer's own `seq` stream
            // stays consecutive and it never learns an event existed.
            if !envelope.visibility().admits(session.role, &session.scopes) {
                return Ok(());
            }
            *broadcast_seq = broadcast_seq.saturating_add(1);
            let Ok(sequence) = EventSequence::new(*broadcast_seq) else {
                return Err(ConnectionClose::ProtocolViolation(
                    "broadcast sequence space is exhausted".to_owned(),
                ));
            };
            write_frame(write, codec, &Frame::Event(envelope.to_frame(sequence))).await
        }
        Delivery::Lagged { first_missed } => Err(ConnectionClose::SlowConsumer {
            dropped: services
                .events
                .last_ordinal()
                .saturating_sub(first_missed.get())
                .saturating_add(1),
        }),
        Delivery::Closed => Err(ConnectionClose::ServerShutdown),
    }
}

async fn handle_inbound(
    id: ConnectionId,
    services: &ConnectionServices,
    write: &mut ServerWrite,
    codec: &Codec,
    session: &Session,
    message: Option<Result<Inbound, WireError>>,
) -> Result<(), ConnectionClose> {
    let message = match message {
        None => return Err(ConnectionClose::Transport(WireError::Closed)),
        Some(Err(error)) => return Err(close_for_wire_error(error)),
        Some(Ok(message)) => message,
    };
    match message {
        Inbound::Close(_) => Err(ConnectionClose::PeerClosed),
        Inbound::Ping(payload) => transport::write_pong(write, payload)
            .await
            .map_err(ConnectionClose::Transport),
        Inbound::Pong(_) => Ok(()),
        Inbound::Text(bytes) => serve_request(id, services, write, codec, session, &bytes).await,
    }
}

async fn serve_request(
    id: ConnectionId,
    services: &ConnectionServices,
    write: &mut ServerWrite,
    codec: &Codec,
    session: &Session,
    bytes: &[u8],
) -> Result<(), ConnectionClose> {
    let Ok(frame) = codec.decode(bytes) else {
        return Err(ConnectionClose::ProtocolViolation(
            "inbound frame failed strict decoding".to_owned(),
        ));
    };
    let Frame::Request(request) = frame else {
        return Err(ConnectionClose::ProtocolViolation(
            "authenticated peers may only send request frames".to_owned(),
        ));
    };
    let request_id = request.id().clone();
    let requested = request.method().as_str().to_owned();

    let Some(method) = services.registry.canonical_name(&requested) else {
        return respond_error(
            write,
            codec,
            &request_id,
            &DispatchError::UnknownMethod(requested),
        )
        .await;
    };
    if method == "connect" {
        return respond_error(
            write,
            codec,
            &request_id,
            &DispatchError::HandshakeAlreadyComplete,
        )
        .await;
    }
    let params = match request.params().value() {
        None => Value::Null,
        Some(raw) => match codec.decode_opaque::<Value>(raw) {
            Ok(value) => value,
            Err(error) => {
                return respond_error(
                    write,
                    codec,
                    &request_id,
                    &DispatchError::InvalidParams {
                        method: method.to_owned(),
                        detail: error.to_string(),
                    },
                )
                .await;
            }
        },
    };

    let context = MethodContext {
        method,
        connection: id,
        role: session.role,
        scopes: &session.scopes,
        device_id: &session.device_id,
        store: services.store.as_ref(),
        events: &services.events,
        clock: services.clock.as_ref(),
        directory: &services.directory,
        filter: &session.filter,
        server_version: services.config.server_version().as_str(),
    };
    match services.registry.dispatch(context, params).await {
        Ok(value) => respond_ok(write, codec, &request_id, &value).await,
        Err(error) => respond_error(write, codec, &request_id, &error).await,
    }
}

async fn respond_ok(
    write: &mut ServerWrite,
    codec: &Codec,
    id: &RequestId,
    value: &Value,
) -> Result<(), ConnectionClose> {
    let Ok(payload) = to_opaque(value) else {
        return Err(ConnectionClose::ProtocolViolation(
            "handler produced an unencodable result".to_owned(),
        ));
    };
    let frame = Frame::Response(ResponseFrame::new(
        id.clone(),
        true,
        OpaqueField::Value(payload),
        None,
    ));
    write_frame(write, codec, &frame).await
}

async fn respond_error(
    write: &mut ServerWrite,
    codec: &Codec,
    id: &RequestId,
    error: &DispatchError,
) -> Result<(), ConnectionClose> {
    let Ok(shape) = error_shape(error) else {
        return Err(ConnectionClose::ProtocolViolation(
            "dispatch error could not be encoded".to_owned(),
        ));
    };
    let frame = Frame::Response(ResponseFrame::new(
        id.clone(),
        false,
        OpaqueField::Omitted,
        Some(shape),
    ));
    write_frame(write, codec, &frame).await
}

async fn write_frame(
    write: &mut ServerWrite,
    codec: &Codec,
    frame: &Frame,
) -> Result<(), ConnectionClose> {
    let Ok(bytes) = codec.encode(frame) else {
        return Err(ConnectionClose::MessageTooLarge {
            limit: AUTHENTICATED_MAX_FRAME_BYTES,
        });
    };
    transport::write_text(write, bytes)
        .await
        .map_err(ConnectionClose::Transport)
}

fn error_shape(error: &DispatchError) -> Result<ErrorShape, EncodeError> {
    let details = match error {
        DispatchError::NotImplemented { method, scope } => Some(json!({
            "method": method,
            "scope": scope,
            "catalogued": true,
        })),
        DispatchError::Unauthorized(denial) => Some(json!({ "reason": denial.to_string() })),
        DispatchError::NotFound { kind, id } => Some(json!({ "kind": kind, "id": id })),
        DispatchError::ResourceExhausted { resource, limit } => {
            Some(json!({ "resource": resource, "limit": limit }))
        }
        DispatchError::InvalidParams { method, detail } => {
            Some(json!({ "method": method, "detail": detail }))
        }
        DispatchError::Store(StoreError::Conflict { id }) => Some(json!({ "conflict": id })),
        DispatchError::Store(StoreError::CapacityExceeded { collection, limit }) => {
            Some(json!({ "resource": collection, "limit": limit }))
        }
        DispatchError::UnknownMethod(_)
        | DispatchError::Store(StoreError::Backend(_))
        | DispatchError::HandshakeAlreadyComplete => None,
    };
    Ok(ErrorShape {
        code: ErrorCode::new(error.wire_code(), PREAUTH_MAX_FRAME_BYTES)?,
        message: ErrorMessage::new(bounded(&error.to_string()), PREAUTH_MAX_FRAME_BYTES)?,
        details: match details {
            None => OpaqueField::Omitted,
            Some(value) => OpaqueField::Value(to_opaque(&value)?),
        },
        retryable: Some(error.retryable()),
        retry_after_ms: None,
    })
}

fn close_for_wire_error(error: WireError) -> ConnectionClose {
    match error {
        WireError::MessageTooLarge { limit, .. } => ConnectionClose::MessageTooLarge { limit },
        WireError::BinaryMessage => {
            ConnectionClose::ProtocolViolation("binary messages are not accepted".to_owned())
        }
        WireError::InvalidUtf8 => {
            ConnectionClose::ProtocolViolation("text message is not valid UTF-8".to_owned())
        }
        WireError::Protocol(detail) => ConnectionClose::ProtocolViolation(detail.to_owned()),
        WireError::Closed | WireError::Read | WireError::Write => ConnectionClose::Transport(error),
    }
}

/// Records the accepted role and scopes while delegating to the real port.
///
/// The reducer deliberately keeps its authentication result private, but the
/// hello payload has to mirror it exactly, so the decision is captured on the
/// way through instead of being recomputed.
struct RecordingPort<'a> {
    inner: &'a (dyn AuthenticationPort + Send + Sync),
    accepted: Mutex<Option<(Role, Vec<OperatorScope>)>>,
}

impl AuthenticationPort for RecordingPort<'_> {
    fn authenticate(&self, request: AuthenticationRequest<'_>) -> AuthenticationDecision {
        let decision = self.inner.authenticate(request);
        if let AuthenticationDecision::Accepted { role, scopes, .. } = &decision {
            *self.accepted.lock().unwrap_or_else(PoisonError::into_inner) =
                Some((*role, scopes.clone()));
        }
        decision
    }
}

async fn negotiate(
    id: ConnectionId,
    services: &ConnectionServices,
    read: &mut ServerRead,
    write: &mut ServerWrite,
) -> Result<Session, ConnectionClose> {
    let preauth = Codec::preauthentication();
    let Ok(challenge) = issue_challenge(services.clock.as_ref()) else {
        return Err(ConnectionClose::HandshakeRejected(
            "challenge nonce could not be generated".to_owned(),
        ));
    };
    let event = resolve_core_event("connect.challenge")
        .expect("the frozen catalog always contains connect.challenge");
    let payload = to_opaque(&challenge).map_err(handshake_failure)?;
    let frame = Frame::Event(EventFrame::new(
        EventName::Core(event),
        OpaqueField::Value(payload),
        None,
        None,
    ));
    let bytes = preauth
        .encode(&frame)
        .map_err(|error| handshake_failure(error.into()))?;
    transport::write_text(write, bytes)
        .await
        .map_err(ConnectionClose::Transport)?;

    let mut negotiation = Negotiation::challenge_sent(challenge);
    let bytes = read_handshake_text(read).await?;
    let Ok(frame) = preauth.decode(&bytes) else {
        return Err(ConnectionClose::ProtocolViolation(
            "connect frame failed strict decoding".to_owned(),
        ));
    };
    let Frame::Request(request) = frame else {
        return Err(ConnectionClose::ProtocolViolation(
            "the first frame must be a connect request".to_owned(),
        ));
    };
    let request_id = request.id().clone();
    let params = preauth.decode_connect(&request).ok();
    if let Err(error) = negotiation.receive_first(Frame::Request(request), &preauth) {
        return Err(reject(write, &preauth, &request_id, &negotiation, &error).await);
    }
    let Some(params) = params else {
        return Err(ConnectionClose::ProtocolViolation(
            "connect params failed strict decoding".to_owned(),
        ));
    };

    let compatibility = match negotiation.check_protocol() {
        Ok(compatibility) => compatibility,
        Err(error) => return Err(reject(write, &preauth, &request_id, &negotiation, &error).await),
    };

    let port = RecordingPort {
        inner: services.authenticator.as_ref(),
        accepted: Mutex::new(None),
    };
    // Read the generation *before* the decision, so a revocation racing this
    // handshake is caught on the connection's first action rather than being
    // masked by a generation captured after the grant was already read.
    let authorized_at = services.authorization.generation();
    if let Err(error) = negotiation.authenticate_with(&port) {
        return Err(reject(write, &preauth, &request_id, &negotiation, &error).await);
    }
    let Some((role, scopes)) = port
        .accepted
        .into_inner()
        .unwrap_or_else(PoisonError::into_inner)
    else {
        return Err(ConnectionClose::HandshakeRejected(
            "authentication port accepted without reporting a role".to_owned(),
        ));
    };
    let device_id = params
        .device
        .as_ref()
        .map(|device| device.id.as_str().to_owned())
        .unwrap_or_default();

    let hello = build_hello(id, services, role, &scopes).map_err(handshake_failure)?;
    negotiation
        .prepare_hello(hello)
        .map_err(|error| ConnectionClose::HandshakeRejected(error.to_string()))?;
    let hello = negotiation
        .hello()
        .expect("a prepared hello is always readable")
        .clone();
    let payload = to_opaque(&hello).map_err(handshake_failure)?;
    let frame = Frame::Response(ResponseFrame::new(
        request_id,
        true,
        OpaqueField::Value(payload),
        None,
    ));
    let bytes = preauth
        .encode(&frame)
        .map_err(|error| handshake_failure(error.into()))?;
    transport::write_text(write, bytes)
        .await
        .map_err(ConnectionClose::Transport)?;
    negotiation
        .mark_hello_sent()
        .and_then(|()| negotiation.mark_ready())
        .map_err(|error| ConnectionClose::HandshakeRejected(error.to_string()))?;

    services.directory.insert(ConnectionInfo {
        id,
        role,
        scopes: scopes.clone(),
        device_id: device_id.clone(),
        client_id: params.client.id.as_str().to_owned(),
        client_mode: params.client.mode.as_str().to_owned(),
        client_version: params.client.version.as_str().to_owned(),
        protocol: u16::try_from(GATEWAY_PROTOCOL_VERSION.get())
            .expect("the pinned protocol version fits in a u16"),
        compatibility: compatibility_identity(compatibility),
        connected_at_ms: services.clock.unix_millis(),
        commands: command_claims(&params, role),
    });

    Ok(Session {
        role,
        scopes,
        device_id,
        filter: Arc::new(Mutex::new(TopicFilter::default())),
        authorized_at,
    })
}

fn handshake_failure(error: EncodeError) -> ConnectionClose {
    ConnectionClose::HandshakeRejected(error.to_string())
}

fn command_claims(params: &ConnectParams, role: Role) -> Vec<String> {
    if role != Role::Node {
        return Vec::new();
    }
    params.commands.as_ref().map_or_else(Vec::new, |commands| {
        commands
            .iter()
            .map(|command| command.as_str().to_owned())
            .collect()
    })
}

async fn read_handshake_text(read: &mut ServerRead) -> Result<Vec<u8>, ConnectionClose> {
    let mut reader = MessageReader::new();
    match reader.read(read, PREAUTH_MAX_FRAME_BYTES).await {
        Err(error) => Err(close_for_wire_error(error)),
        Ok(Inbound::Text(bytes)) => Ok(bytes),
        Ok(Inbound::Close(_)) => Err(ConnectionClose::PeerClosed),
        Ok(Inbound::Ping(_) | Inbound::Pong(_)) => Err(ConnectionClose::ProtocolViolation(
            "control frames are not accepted before the connect request".to_owned(),
        )),
    }
}

async fn reject(
    write: &mut ServerWrite,
    codec: &Codec,
    id: &RequestId,
    negotiation: &Negotiation,
    error: &NegotiationError,
) -> ConnectionClose {
    let Some(rejection) = negotiation.rejection() else {
        return ConnectionClose::ProtocolViolation(error.to_string());
    };
    let Ok(shape) = rejection_shape(rejection) else {
        return ConnectionClose::HandshakeRejected(rejection.message().to_owned());
    };
    let frame = Frame::Response(ResponseFrame::new(
        id.clone(),
        false,
        OpaqueField::Omitted,
        Some(shape),
    ));
    if let Ok(bytes) = codec.encode(&frame) {
        let _ = transport::write_text(write, bytes).await;
    }
    ConnectionClose::HandshakeRejected(rejection.message().to_owned())
}

fn rejection_shape(rejection: &HandshakeRejection) -> Result<ErrorShape, EncodeError> {
    let retryable = rejection.code() == ConnectErrorDetailCode::AuthRateLimited;
    let details = match rejection.pairing_details() {
        Some(pairing) => to_opaque(pairing)?,
        None => to_opaque(&json!({
            "code": rejection.code().as_str(),
            "retryable": retryable,
            "pauseReconnect": !retryable,
        }))?,
    };
    Ok(ErrorShape {
        code: ErrorCode::new(
            connect_error_code(rejection.code()),
            PREAUTH_MAX_FRAME_BYTES,
        )?,
        message: ErrorMessage::new(bounded(rejection.message()), PREAUTH_MAX_FRAME_BYTES)?,
        details: OpaqueField::Value(details),
        retryable: Some(retryable),
        retry_after_ms: None,
    })
}

/// Maps a connect detail code onto the top-level `res` error code.
///
/// `UNAVAILABLE` is reserved for rate limiting, because the reference client
/// treats a retryable `UNAVAILABLE` connect failure as a transport hiccup and
/// reconnects; every other rejection must terminate the attempt.
const fn connect_error_code(code: ConnectErrorDetailCode) -> &'static str {
    match code {
        ConnectErrorDetailCode::AuthRateLimited => CoreErrorCode::Unavailable.as_str(),
        ConnectErrorDetailCode::PairingRequired => CoreErrorCode::NotPaired.as_str(),
        ConnectErrorDetailCode::ProtocolMismatch => "PROTOCOL_MISMATCH",
        _ => "UNAUTHORIZED",
    }
}

fn build_hello(
    id: ConnectionId,
    services: &ConnectionServices,
    role: Role,
    scopes: &[OperatorScope],
) -> Result<HelloOk, EncodeError> {
    let methods = services
        .registry
        .advertised_names()
        .into_iter()
        .map(|name| Name::new(name, PREAUTH_MAX_FRAME_BYTES))
        .collect::<Result<Vec<_>, _>>()?;
    let events = core_events()
        .iter()
        .map(|event| Name::new(event.name(), PREAUTH_MAX_FRAME_BYTES))
        .collect::<Result<Vec<_>, _>>()?;
    let scope_names = scopes
        .iter()
        .map(|scope| Name::new(scope.as_str(), PREAUTH_MAX_FRAME_BYTES))
        .collect::<Result<Vec<_>, _>>()?;
    let tick_interval_ms =
        u64::try_from(services.config.timeouts().tick_interval.as_millis()).unwrap_or(u64::MAX);
    let max_payload = u64::try_from(AUTHENTICATED_MAX_FRAME_BYTES).unwrap_or(u64::MAX);
    let max_buffered =
        u64::try_from(services.config.limits().event_queue_bytes).unwrap_or(u64::MAX);
    Ok(HelloOk {
        kind: HelloOkKind::HelloOk,
        protocol: GATEWAY_PROTOCOL_VERSION,
        server: HelloServer {
            version: services.config.server_version().clone(),
            conn_id: Name::new(format!("conn-{}", id.get()), PREAUTH_MAX_FRAME_BYTES)?,
        },
        features: HelloFeatures {
            methods,
            events,
            capabilities: Some(vec![Name::new(CORE_CAPABILITY, PREAUTH_MAX_FRAME_BYTES)?]),
        },
        snapshot: Snapshot {
            presence: Vec::new(),
            health: to_opaque(&json!({ "status": "ok" }))?,
            state_version: StateVersion {
                presence: NonNegativeInteger::new(0),
                health: NonNegativeInteger::new(0),
            },
            uptime_ms: NonNegativeInteger::new(0),
            config_path: None,
            state_dir: None,
            session_defaults: None,
            auth_mode: None,
            update_available: None,
        },
        control_ui_tabs: None,
        plugin_surface_urls: None,
        auth: HelloAuth {
            device_token: None,
            role: Name::new(role.as_str(), PREAUTH_MAX_FRAME_BYTES)?,
            scopes: scope_names,
            issued_at_ms: None,
            device_tokens: None,
        },
        policy: HelloPolicy {
            max_payload: positive(max_payload, "max_payload")?,
            max_buffered_bytes: positive(max_buffered, "max_buffered_bytes")?,
            tick_interval_ms: positive(tick_interval_ms, "tick_interval_ms")?,
        },
    })
}

fn positive(value: u64, field: &str) -> Result<PositiveInteger, EncodeError> {
    PositiveInteger::new(value)
        .map_err(|_| EncodeError::Json(format!("hello policy field `{field}` must be positive")))
}

fn to_opaque<T: Serialize>(value: &T) -> Result<OpaqueJson, EncodeError> {
    let json = serde_json::to_string(value)?;
    Ok(serde_json::from_str(&json)?)
}

fn bounded(message: &str) -> String {
    if message.len() <= MAX_ERROR_MESSAGE_BYTES {
        return message.to_owned();
    }
    let mut end = MAX_ERROR_MESSAGE_BYTES;
    while end > 0 && !message.is_char_boundary(end) {
        end -= 1;
    }
    message[..end].to_owned()
}

#[cfg(test)]
mod tests {
    use claw_protocol::gateway::{
        AuthorizationError, PairingRequiredCode, PairingRequiredDetails, PairingRequiredReason,
    };

    use super::*;

    fn parse_details(shape: &ErrorShape) -> Value {
        serde_json::from_str(
            shape
                .details
                .value()
                .expect("this error always carries details")
                .as_json(),
        )
        .expect("encoded details are valid JSON")
    }

    #[test]
    fn a_rate_limited_rejection_is_the_only_retryable_connect_failure() {
        let limited = HandshakeRejection::new(ConnectErrorDetailCode::AuthRateLimited, "slow down");
        let shape = rejection_shape(&limited).expect("rate-limit rejections encode");
        assert_eq!(shape.code.as_str(), "UNAVAILABLE");
        assert_eq!(shape.retryable, Some(true));
        assert_eq!(parse_details(&shape)["pauseReconnect"], Value::from(false));

        let denied = HandshakeRejection::new(
            ConnectErrorDetailCode::AuthScopeMismatch,
            "device is not granted operator.admin",
        );
        let shape = rejection_shape(&denied).expect("scope rejections encode");
        assert_eq!(shape.code.as_str(), "UNAUTHORIZED");
        assert_eq!(shape.retryable, Some(false));
        let details = parse_details(&shape);
        assert_eq!(details["code"], Value::from("AUTH_SCOPE_MISMATCH"));
        assert_eq!(details["pauseReconnect"], Value::from(true));
    }

    #[test]
    fn a_protocol_mismatch_keeps_its_own_top_level_code() {
        assert_eq!(
            connect_error_code(ConnectErrorDetailCode::ProtocolMismatch),
            "PROTOCOL_MISMATCH"
        );
        assert_eq!(
            connect_error_code(ConnectErrorDetailCode::PairingRequired),
            "NOT_PAIRED"
        );
        assert_eq!(
            connect_error_code(ConnectErrorDetailCode::DeviceAuthInvalid),
            "UNAUTHORIZED"
        );
        assert_eq!(
            connect_error_code(ConnectErrorDetailCode::AuthRateLimited),
            "UNAVAILABLE"
        );
    }

    #[test]
    fn a_pairing_rejection_carries_the_full_pairing_detail_object() {
        let details = PairingRequiredDetails {
            code: PairingRequiredCode::PairingRequired,
            reason: Some(PairingRequiredReason::NotPaired),
            request_id: None,
            remediation_hint: None,
            recommended_next_step: None,
            retryable: Some(false),
            pause_reconnect: Some(true),
            device_id: Some("dev-1".to_owned()),
            requested_role: Some("operator".to_owned()),
            requested_scopes: Some(vec!["operator.read".to_owned()]),
            approved_roles: None,
            approved_scopes: None,
        };
        let shape = rejection_shape(&HandshakeRejection::pairing("pair me", details))
            .expect("pairing rejections encode");
        assert_eq!(shape.code.as_str(), "NOT_PAIRED");
        let parsed = parse_details(&shape);
        assert_eq!(parsed["code"], Value::from("PAIRING_REQUIRED"));
        assert_eq!(parsed["reason"], Value::from("not-paired"));
        assert_eq!(parsed["deviceId"], Value::from("dev-1"));
        assert_eq!(parsed["pauseReconnect"], Value::from(true));
        assert_eq!(
            parsed["requestedScopes"],
            Value::from(vec![Value::from("operator.read")])
        );
    }

    #[test]
    fn dispatch_errors_render_their_catalogued_code_and_details() {
        let shape = error_shape(&DispatchError::NotImplemented {
            method: "agents.list".to_owned(),
            scope: "operator.read",
        })
        .expect("not-implemented errors encode");
        assert_eq!(shape.code.as_str(), "NOT_IMPLEMENTED");
        assert_eq!(shape.retryable, Some(false));
        let parsed = parse_details(&shape);
        assert_eq!(parsed["method"], Value::from("agents.list"));
        assert_eq!(parsed["scope"], Value::from("operator.read"));
        assert_eq!(parsed["catalogued"], Value::from(true));
    }

    #[test]
    fn unauthorized_dispatch_errors_never_leak_details_beyond_the_denial_reason() {
        let shape = error_shape(&DispatchError::Unauthorized(
            AuthorizationError::MissingScope {
                method: "sessions.create".to_owned(),
                required: OperatorScope::Write,
            },
        ))
        .expect("authorization denials encode");
        assert_eq!(shape.code.as_str(), "UNAUTHORIZED");
        assert_eq!(shape.retryable, Some(false));
        let parsed = parse_details(&shape);
        assert_eq!(parsed.as_object().map(serde_json::Map::len), Some(1));
        assert!(parsed["reason"].is_string());
    }

    #[test]
    fn store_failures_are_retryable_and_carry_no_details() {
        let shape = error_shape(&DispatchError::Store(crate::error::StoreError::Backend(
            "disk offline".to_owned(),
        )))
        .expect("store failures encode");
        assert_eq!(shape.code.as_str(), "UNAVAILABLE");
        assert_eq!(shape.retryable, Some(true));
        assert_eq!(shape.details, OpaqueField::Omitted);
    }

    #[test]
    fn error_messages_are_truncated_on_a_character_boundary() {
        let long = "é".repeat(MAX_ERROR_MESSAGE_BYTES);
        let truncated = bounded(&long);
        assert!(truncated.len() <= MAX_ERROR_MESSAGE_BYTES);
        assert_eq!(truncated.chars().count(), MAX_ERROR_MESSAGE_BYTES / 2);
        assert_eq!(bounded("short"), "short");
    }

    #[test]
    fn wire_errors_map_onto_distinct_close_reasons() {
        assert_eq!(
            close_for_wire_error(WireError::MessageTooLarge {
                limit: 64,
                actual: 65
            }),
            ConnectionClose::MessageTooLarge { limit: 64 }
        );
        assert_eq!(
            close_for_wire_error(WireError::BinaryMessage),
            ConnectionClose::ProtocolViolation("binary messages are not accepted".to_owned())
        );
        assert_eq!(
            close_for_wire_error(WireError::InvalidUtf8),
            ConnectionClose::ProtocolViolation("text message is not valid UTF-8".to_owned())
        );
        assert_eq!(
            close_for_wire_error(WireError::Read),
            ConnectionClose::Transport(WireError::Read)
        );
    }

    /// Builds services whose only meaningful collaborator is the directory.
    fn services_over(devices: &crate::authority::DeviceDirectory) -> ConnectionServices {
        let clock: Arc<dyn Clock> = Arc::new(crate::clock::ManualClock::new(1_700_000_000_000));
        let config = crate::config::GatewayServerConfig::default()
            .validate()
            .expect("the default configuration is valid");
        ConnectionServices {
            config: Arc::new(config),
            registry: Arc::new(crate::methods::registry().expect("every handler installs")),
            store: Arc::new(crate::store::InMemoryGatewayStore::new(8, 8)),
            events: EventBus::new(8, 8192),
            clock: Arc::clone(&clock),
            directory: ConnectionDirectory::new(),
            authenticator: Arc::new(crate::auth::StaticAuthenticator::new(
                crate::auth::CredentialPolicy::None,
                clock,
            )),
            authorization: Arc::new(devices.clone()),
        }
    }

    fn session_of(role: Role, scopes: &[OperatorScope], authorized_at: u64) -> Session {
        Session {
            role,
            scopes: scopes.to_vec(),
            device_id: "device-a".to_owned(),
            filter: Arc::new(Mutex::new(TopicFilter::default())),
            authorized_at,
        }
    }

    #[test]
    fn an_unchanged_generation_leaves_the_snapshot_alone() {
        let devices = crate::authority::DeviceDirectory::new();
        devices.pair(
            "device-a",
            crate::auth::Grant::new(Role::Operator, [OperatorScope::Admin]),
        );
        let services = services_over(&devices);
        let mut session = session_of(Role::Operator, &[OperatorScope::Read], devices.generation());

        revalidate(ConnectionId::new(1), &services, &mut session)
            .expect("nothing changed, so nothing is revoked");
        assert_eq!(session.scopes, vec![OperatorScope::Read]);
        assert_eq!(session.authorized_at, 1);
    }

    #[test]
    fn a_withdrawn_pairing_closes_the_connection() {
        let devices = crate::authority::DeviceDirectory::new();
        devices.pair(
            "device-a",
            crate::auth::Grant::new(Role::Operator, [OperatorScope::Admin]),
        );
        let services = services_over(&devices);
        let mut session = session_of(
            Role::Operator,
            &[OperatorScope::Admin],
            devices.generation(),
        );

        assert!(devices.revoke("device-a"));
        assert_eq!(
            revalidate(ConnectionId::new(1), &services, &mut session),
            Err(ConnectionClose::AuthorizationRevoked {
                device_id: "device-a".to_owned()
            })
        );
    }

    #[test]
    fn a_changed_role_closes_the_connection() {
        let devices = crate::authority::DeviceDirectory::new();
        devices.pair(
            "device-a",
            crate::auth::Grant::new(Role::Operator, [OperatorScope::Admin]),
        );
        let services = services_over(&devices);
        let mut session = session_of(
            Role::Operator,
            &[OperatorScope::Admin],
            devices.generation(),
        );

        devices.pair("device-a", crate::auth::Grant::new(Role::Node, []));
        assert_eq!(
            revalidate(ConnectionId::new(1), &services, &mut session),
            Err(ConnectionClose::AuthorizationRevoked {
                device_id: "device-a".to_owned()
            })
        );
    }

    #[test]
    fn a_narrowed_grant_removes_exactly_the_scopes_that_were_taken_away() {
        let devices = crate::authority::DeviceDirectory::new();
        devices.pair(
            "device-a",
            crate::auth::Grant::new(
                Role::Operator,
                [
                    OperatorScope::Read,
                    OperatorScope::Write,
                    OperatorScope::Admin,
                ],
            ),
        );
        let services = services_over(&devices);
        let mut session = session_of(
            Role::Operator,
            &[
                OperatorScope::Read,
                OperatorScope::Write,
                OperatorScope::Admin,
            ],
            devices.generation(),
        );

        devices.pair(
            "device-a",
            crate::auth::Grant::new(Role::Operator, [OperatorScope::Read]),
        );
        revalidate(ConnectionId::new(1), &services, &mut session)
            .expect("narrowing keeps the connection open");

        assert_eq!(session.scopes, vec![OperatorScope::Read]);
        assert_eq!(session.authorized_at, 2);
    }

    #[test]
    fn a_widened_grant_never_reaches_a_connection_that_did_not_present_it() {
        let devices = crate::authority::DeviceDirectory::new();
        devices.pair(
            "device-a",
            crate::auth::Grant::new(Role::Operator, [OperatorScope::Read]),
        );
        let services = services_over(&devices);
        let mut session = session_of(Role::Operator, &[OperatorScope::Read], devices.generation());

        devices.pair(
            "device-a",
            crate::auth::Grant::new(Role::Operator, [OperatorScope::Read, OperatorScope::Admin]),
        );
        revalidate(ConnectionId::new(1), &services, &mut session)
            .expect("widening is not a reason to close");

        assert_eq!(
            session.scopes,
            vec![OperatorScope::Read],
            "a live connection must not inherit a scope it never proved at connect time"
        );
    }

    #[test]
    fn a_node_with_no_scopes_survives_an_unrelated_directory_change() {
        let devices = crate::authority::DeviceDirectory::new();
        devices.pair("device-a", crate::auth::Grant::new(Role::Node, []));
        let services = services_over(&devices);
        let mut session = session_of(Role::Node, &[], devices.generation());

        devices.pair(
            "device-b",
            crate::auth::Grant::new(Role::Operator, [OperatorScope::Admin]),
        );
        revalidate(ConnectionId::new(1), &services, &mut session)
            .expect("another device's pairing is not this device's revocation");

        assert_eq!(session.role, Role::Node);
        assert!(session.scopes.is_empty());
        assert_eq!(session.authorized_at, 2);
    }

    #[test]
    fn narrowing_also_narrows_what_the_event_bus_will_consider_the_connection_for() {
        let devices = crate::authority::DeviceDirectory::new();
        devices.pair(
            "device-a",
            crate::auth::Grant::new(Role::Operator, [OperatorScope::Admin]),
        );
        let services = services_over(&devices);
        let id = ConnectionId::new(7);
        let mut session = session_of(
            Role::Operator,
            &[OperatorScope::Admin],
            devices.generation(),
        );
        let mut subscription = services.events.subscribe(
            id,
            session.role,
            session.scopes.clone(),
            Arc::clone(&session.filter),
        );

        devices.pair(
            "device-a",
            crate::auth::Grant::new(Role::Operator, [OperatorScope::Read]),
        );
        revalidate(id, &services, &mut session).expect("narrowing keeps the connection open");

        let draft = crate::events::EventDraft::broadcast(
            "terminal.exit",
            &json!({ "sessionId": "s-1", "code": 0 }),
        )
        .expect("terminal.exit is catalogued");
        services.events.publish(draft);

        assert!(
            subscription.try_recv().is_none(),
            "an admin-scoped event reached a connection whose admin scope was withdrawn"
        );
    }
}

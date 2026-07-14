use std::collections::{HashMap, HashSet};
use std::num::NonZeroU64;
use std::sync::{Arc, RwLock};
use std::time::Duration;

use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use claw_protocol::gateway::{
    AUTHENTICATED_MAX_FRAME_BYTES, AuthCredentials, ChallengeNonce, ClientInfo, Codec,
    ConnectErrorDetailCode, ConnectParams, ConnectRecoveryNextStep, CoreErrorCode, DeviceProof,
    DevicePublicKey as WirePublicKey, DeviceSignature as WireSignature, EventSequenceError,
    EventSequenceTracker, Frame, GATEWAY_PROTOCOL_VERSION, GatewayMethodName, Name,
    NonNegativeInteger, OpaqueJson, OperatorScope, PREAUTH_MAX_FRAME_BYTES, RequestId,
    ResponseFrame, resolve_core_method,
};
use claw_security::identity::GatewayDeviceSigningInput;
use secrecy::{ExposeSecret, SecretString};
use serde::{Deserialize, Serialize};
use tokio::sync::{Mutex, OwnedSemaphorePermit, Semaphore, mpsc, oneshot, watch};
use tokio_util::sync::CancellationToken;
use tokio_util::task::TaskTracker;

use crate::config::{AuthorizationExpectation, GatewayClientConfig, GatewayCredential};
use crate::error::{
    AuthenticationFailure, BackpressureError, ConnectionEpoch, ConnectionInfo, ConnectionState,
    GatewayClientError, GatewayEvent, IssuedDeviceToken, ProtocolFailure, ReadyConnection,
    ResyncRequired, TransportFailure,
};
use crate::runtime::{ClientRuntime, SystemRuntime, reconnect_delay};
use crate::transport::{self, Inbound, MessageReader, WireFailure};

const CONNECT_REQUEST_ID: &str = "gateway-connect";
const INBOUND_QUEUE_CAPACITY: usize = 1;
const MAX_ISSUED_DEVICE_TOKENS: usize = 16;

/// Cloneable handle to one reconnecting Gateway transport task.
#[derive(Clone)]
pub struct GatewayClient {
    inner: Arc<ClientInner>,
}

struct ClientInner {
    active: Arc<RwLock<Option<ActiveConnection>>>,
    state: watch::Receiver<ConnectionState>,
    cancellation: CancellationToken,
    tasks: TaskTracker,
    permits: Arc<Semaphore>,
    serialization_bytes: Arc<Semaphore>,
    outbound_bytes: Arc<Semaphore>,
    request_timeout: Duration,
    shutdown_timeout: Duration,
    codec: Codec,
    runtime: Arc<dyn ClientRuntime>,
    issued_device_tokens: Arc<Mutex<Vec<IssuedDeviceToken>>>,
}

#[derive(Clone)]
struct ActiveConnection {
    epoch: ConnectionEpoch,
    commands: mpsc::Sender<Command>,
    max_payload_bytes: usize,
}

/// Exclusive receiver for the bounded Gateway event queue.
pub struct GatewayEventStream {
    receiver: mpsc::Receiver<GatewayEvent>,
}

impl GatewayEventStream {
    /// Receives the next strict event, or `None` after the client task stops.
    pub async fn recv(&mut self) -> Option<GatewayEvent> {
        self.receiver.recv().await
    }
}

impl GatewayClient {
    /// Starts a client using the production clock, Tokio sleeper, and jitter source.
    pub fn start(
        config: GatewayClientConfig,
    ) -> Result<(Self, GatewayEventStream), GatewayClientError> {
        Self::start_with_runtime(config, Arc::new(SystemRuntime::default()))
    }

    /// Starts a client with injectable time and jitter for deterministic operation/tests.
    pub fn start_with_runtime(
        config: GatewayClientConfig,
        runtime: Arc<dyn ClientRuntime>,
    ) -> Result<(Self, GatewayEventStream), GatewayClientError> {
        config
            .validate()
            .map_err(GatewayClientError::Configuration)?;
        let (event_tx, event_rx) = mpsc::channel(config.limits.event_queue_capacity);
        let (state_tx, state_rx) = watch::channel(ConnectionState::Starting);
        let cancellation = CancellationToken::new();
        let tasks = TaskTracker::new();
        let active = Arc::new(RwLock::new(None));
        let permits = Arc::new(Semaphore::new(config.limits.max_in_flight_requests));
        let serialization_bytes = Arc::new(Semaphore::new(AUTHENTICATED_MAX_FRAME_BYTES));
        let outbound_bytes = Arc::new(Semaphore::new(config.limits.outbound_queue_bytes));
        let issued_device_tokens = Arc::new(Mutex::new(Vec::new()));
        let latest_device_token = Arc::new(Mutex::new(None));
        let inner = Arc::new(ClientInner {
            active: Arc::clone(&active),
            state: state_rx,
            cancellation: cancellation.clone(),
            tasks: tasks.clone(),
            permits,
            serialization_bytes,
            outbound_bytes,
            request_timeout: config.timeouts.request,
            shutdown_timeout: config.timeouts.shutdown,
            codec: Codec::authenticated(),
            runtime: Arc::clone(&runtime),
            issued_device_tokens: Arc::clone(&issued_device_tokens),
        });
        let resources = SupervisorResources {
            active,
            events: event_tx,
            states: state_tx,
            cancellation,
            tasks: tasks.clone(),
            event_bytes: Arc::new(Semaphore::new(config.limits.event_queue_bytes)),
            issued_device_tokens,
            latest_device_token,
        };
        tasks.spawn(supervise(config, runtime, resources));
        Ok((Self { inner }, GatewayEventStream { receiver: event_rx }))
    }

    /// Returns the latest bounded lifecycle state.
    #[must_use]
    pub fn state(&self) -> ConnectionState {
        self.inner.state.borrow().clone()
    }

    /// Subscribes to lifecycle state changes without an event history buffer.
    #[must_use]
    pub fn subscribe_state(&self) -> watch::Receiver<ConnectionState> {
        self.inner.state.clone()
    }

    /// Takes all device tokens issued by successful server hellos.
    ///
    /// The returned secrecy wrapper can be handed to a platform persistence
    /// adapter. Bootstrap authentication also adopts this token for reconnect.
    pub async fn take_issued_device_tokens(&self) -> Vec<IssuedDeviceToken> {
        std::mem::take(&mut *self.inner.issued_device_tokens.lock().await)
    }

    /// Waits until authentication succeeds or a terminal state is reached.
    pub async fn wait_ready(&self) -> Result<ReadyConnection, GatewayClientError> {
        let mut receiver = self.inner.state.clone();
        loop {
            match receiver.borrow().clone() {
                ConnectionState::Ready(ready) => return Ok(ready),
                ConnectionState::AuthenticationFailed(error) => {
                    return Err(GatewayClientError::Authentication(error));
                }
                ConnectionState::ResyncRequired(reason) => {
                    return Err(GatewayClientError::Protocol(
                        ProtocolFailure::ResyncRequired(reason),
                    ));
                }
                ConnectionState::ProtocolFailed { category } => {
                    return Err(GatewayClientError::Protocol(
                        ProtocolFailure::WebSocketProtocol(category),
                    ));
                }
                ConnectionState::ReconnectExhausted => {
                    return Err(GatewayClientError::ReconnectExhausted);
                }
                ConnectionState::Stopped => return Err(GatewayClientError::Cancelled),
                ConnectionState::Starting
                | ConnectionState::Connecting
                | ConnectionState::Authenticating
                | ConnectionState::Reconnecting { .. } => {}
            }
            receiver
                .changed()
                .await
                .map_err(|_| GatewayClientError::Cancelled)?;
        }
    }

    /// Sends one typed, strictly encoded request without any automatic replay.
    pub async fn request<T>(
        &self,
        id: RequestId,
        method: GatewayMethodName,
        params: &T,
    ) -> Result<ResponseFrame, GatewayClientError>
    where
        T: Serialize + ?Sized,
    {
        self.request_with_timeout(id, method, params, self.inner.request_timeout)
            .await
    }

    /// Sends one request only on the explicitly observed Ready epoch.
    pub async fn request_for_epoch<T>(
        &self,
        expected_epoch: ConnectionEpoch,
        id: RequestId,
        method: GatewayMethodName,
        params: &T,
    ) -> Result<ResponseFrame, GatewayClientError>
    where
        T: Serialize + ?Sized,
    {
        self.request_with_timeout_for_epoch(
            expected_epoch,
            id,
            method,
            params,
            self.inner.request_timeout,
        )
        .await
    }

    /// Sends one typed request with an explicit caller deadline.
    pub async fn request_with_timeout<T>(
        &self,
        id: RequestId,
        method: GatewayMethodName,
        params: &T,
        timeout: Duration,
    ) -> Result<ResponseFrame, GatewayClientError>
    where
        T: Serialize + ?Sized,
    {
        let connection = self
            .active_connection()
            .ok_or(GatewayClientError::NotReady)?;
        self.request_with_connection(connection, id, method, params, timeout)
            .await
    }

    /// Sends one deadline-bounded request only on the explicitly observed Ready epoch.
    pub async fn request_with_timeout_for_epoch<T>(
        &self,
        expected_epoch: ConnectionEpoch,
        id: RequestId,
        method: GatewayMethodName,
        params: &T,
        timeout: Duration,
    ) -> Result<ResponseFrame, GatewayClientError>
    where
        T: Serialize + ?Sized,
    {
        let connection = self.connection_for_epoch(expected_epoch)?;
        self.request_with_connection(connection, id, method, params, timeout)
            .await
    }

    async fn request_with_connection<T>(
        &self,
        connection: ActiveConnection,
        id: RequestId,
        method: GatewayMethodName,
        params: &T,
        timeout: Duration,
    ) -> Result<ResponseFrame, GatewayClientError>
    where
        T: Serialize + ?Sized,
    {
        if timeout.is_zero() {
            return Err(GatewayClientError::RequestTimedOut(id));
        }
        let expected_epoch = connection.epoch;
        let max_payload_bytes = connection.max_payload_bytes;
        let permit = Arc::clone(&self.inner.permits)
            .try_acquire_owned()
            .map_err(|_| GatewayClientError::Backpressure(BackpressureError::InFlightLimit))?;
        let serialization_permits =
            u32::try_from(max_payload_bytes).expect("protocol payload cap fits u32");
        let serialization_permit = Arc::clone(&self.inner.serialization_bytes)
            .try_acquire_many_owned(serialization_permits)
            .map_err(|_| {
                GatewayClientError::Backpressure(BackpressureError::SerializationSaturated)
            })?;
        let bytes = self.inner.codec.encode_request(&id, &method, params)?;
        if bytes.len() > max_payload_bytes {
            return Err(GatewayClientError::Protocol(
                ProtocolFailure::OutboundMessageTooLarge {
                    actual: bytes.len(),
                    limit: max_payload_bytes,
                },
            ));
        }
        let byte_permits =
            u32::try_from(bytes.len().max(1)).expect("protocol payload cap fits u32");
        let byte_permit = Arc::clone(&self.inner.outbound_bytes)
            .try_acquire_many_owned(byte_permits)
            .map_err(|_| {
                GatewayClientError::Backpressure(BackpressureError::CommandBytesSaturated)
            })?;
        drop(serialization_permit);
        let deadline = tokio::time::Instant::now() + timeout;
        tokio::select! {
            () = self.inner.cancellation.cancelled() => {
                return Err(GatewayClientError::Cancelled);
            }
            () = tokio::time::sleep_until(deadline) => {
                return Err(GatewayClientError::RequestTimedOut(id));
            }
            () = self.inner.runtime.before_request_enqueue() => {}
        }
        if self.current_epoch() != Some(expected_epoch) {
            return Err(Self::connection_changed(expected_epoch));
        }
        let (completion, response) = oneshot::channel();
        connection
            .commands
            .try_send(Command::Request {
                epoch: expected_epoch,
                id: id.clone(),
                bytes,
                completion,
                deadline,
                _permit: permit,
                _byte_permit: byte_permit,
            })
            .map_err(|error| match error {
                mpsc::error::TrySendError::Full(_) => {
                    GatewayClientError::Backpressure(BackpressureError::CommandQueueSaturated)
                }
                mpsc::error::TrySendError::Closed(_) => Self::connection_changed(expected_epoch),
            })?;
        tokio::select! {
            () = self.inner.cancellation.cancelled() => Err(GatewayClientError::Cancelled),
            result = tokio::time::timeout_at(deadline, response) => {
                match result {
                    Ok(Ok(Ok(response)))
                        if response.epoch == expected_epoch
                            && self.current_epoch() == Some(expected_epoch) =>
                    {
                        Ok(response.frame)
                    }
                    Ok(Ok(Ok(_))) | Ok(Err(_)) => Err(Self::connection_changed(expected_epoch)),
                    Ok(Ok(Err(error))) => Err(error),
                    Err(_) => Err(GatewayClientError::RequestTimedOut(id)),
                }
            }
        }
    }

    fn active_connection(&self) -> Option<ActiveConnection> {
        self.inner
            .active
            .read()
            .expect("active Gateway connection lock")
            .clone()
    }

    fn connection_for_epoch(
        &self,
        expected_epoch: ConnectionEpoch,
    ) -> Result<ActiveConnection, GatewayClientError> {
        match self.active_connection() {
            Some(connection) if connection.epoch == expected_epoch => Ok(connection),
            Some(_) | None => Err(Self::connection_changed(expected_epoch)),
        }
    }

    fn current_epoch(&self) -> Option<ConnectionEpoch> {
        self.inner
            .active
            .read()
            .expect("active Gateway connection lock")
            .as_ref()
            .map(|connection| connection.epoch)
    }

    const fn connection_changed(expected: ConnectionEpoch) -> GatewayClientError {
        GatewayClientError::ConnectionChanged { expected }
    }

    /// Cancels pending work, performs a bounded close, and waits for every tracked task.
    pub async fn shutdown(&self) -> Result<(), GatewayClientError> {
        self.inner.cancellation.cancel();
        self.inner.tasks.close();
        let wait_timeout = self
            .inner
            .shutdown_timeout
            .saturating_add(Duration::from_millis(100));
        tokio::time::timeout(wait_timeout, self.inner.tasks.wait())
            .await
            .map_err(|_| GatewayClientError::ShutdownTimedOut)
    }
}

impl Drop for GatewayClient {
    fn drop(&mut self) {
        if Arc::strong_count(&self.inner) == 1 {
            self.inner.cancellation.cancel();
        }
    }
}

enum Command {
    Request {
        epoch: ConnectionEpoch,
        id: RequestId,
        bytes: Vec<u8>,
        completion: oneshot::Sender<Result<EpochResponse, GatewayClientError>>,
        deadline: tokio::time::Instant,
        _permit: OwnedSemaphorePermit,
        _byte_permit: OwnedSemaphorePermit,
    },
}

struct EpochResponse {
    epoch: ConnectionEpoch,
    frame: ResponseFrame,
}

struct PendingRequest {
    completion: oneshot::Sender<Result<EpochResponse, GatewayClientError>>,
    _permit: OwnedSemaphorePermit,
}

struct SessionOutcome {
    result: Result<(), GatewayClientError>,
    was_ready: bool,
}

struct SupervisorResources {
    active: Arc<RwLock<Option<ActiveConnection>>>,
    events: mpsc::Sender<GatewayEvent>,
    states: watch::Sender<ConnectionState>,
    cancellation: CancellationToken,
    tasks: TaskTracker,
    event_bytes: Arc<Semaphore>,
    issued_device_tokens: Arc<Mutex<Vec<IssuedDeviceToken>>>,
    latest_device_token: Arc<Mutex<Option<SecretString>>>,
}

struct EpochAllocator {
    next: u64,
}

impl EpochAllocator {
    const fn new() -> Self {
        Self { next: 1 }
    }

    fn allocate(&mut self) -> Option<ConnectionEpoch> {
        let value = NonZeroU64::new(self.next)?;
        self.next = self.next.checked_add(1).unwrap_or(0);
        Some(ConnectionEpoch::new(value))
    }
}

async fn supervise(
    mut config: GatewayClientConfig,
    runtime: Arc<dyn ClientRuntime>,
    resources: SupervisorResources,
) {
    let mut retry = 0_u32;
    let mut corrective_device_retry_used = false;
    let mut epochs = EpochAllocator::new();
    loop {
        set_state(&resources.states, ConnectionState::Connecting);
        let outcome =
            run_connection(&mut config, Arc::clone(&runtime), &mut epochs, &resources).await;
        match outcome.result {
            Err(GatewayClientError::Cancelled) | Ok(()) => {
                set_state(&resources.states, ConnectionState::Stopped);
                break;
            }
            Err(GatewayClientError::Authentication(error)) => {
                if error.device_retry_recommended()
                    && !corrective_device_retry_used
                    && matches!(config.credential, GatewayCredential::Token(_))
                {
                    let replacement = resources
                        .latest_device_token
                        .lock()
                        .await
                        .as_ref()
                        .map(|token| SecretString::from(token.expose_secret().to_owned()));
                    if let Some(replacement) = replacement {
                        config.credential = GatewayCredential::DeviceToken(replacement);
                        corrective_device_retry_used = true;
                        retry = retry.saturating_add(1);
                        let Some(delay) =
                            reconnect_delay(config.reconnect, retry, runtime.as_ref())
                        else {
                            set_state(&resources.states, ConnectionState::ReconnectExhausted);
                            break;
                        };
                        set_state(
                            &resources.states,
                            ConnectionState::Reconnecting {
                                attempt: retry,
                                delay,
                            },
                        );
                        if wait_to_reconnect(runtime.as_ref(), delay, &resources.cancellation).await
                        {
                            continue;
                        }
                        set_state(&resources.states, ConnectionState::Stopped);
                        break;
                    }
                }
                set_state(
                    &resources.states,
                    ConnectionState::AuthenticationFailed(error),
                );
                break;
            }
            Err(GatewayClientError::Protocol(ProtocolFailure::ResyncRequired(reason))) => {
                set_state(&resources.states, ConnectionState::ResyncRequired(reason));
                break;
            }
            Err(GatewayClientError::Protocol(error)) => {
                set_state(
                    &resources.states,
                    ConnectionState::ProtocolFailed {
                        category: error.category(),
                    },
                );
                break;
            }
            Err(GatewayClientError::Transport(_)) => {
                if outcome.was_ready {
                    retry = 0;
                }
                retry = retry.saturating_add(1);
                let Some(delay) = reconnect_delay(config.reconnect, retry, runtime.as_ref()) else {
                    set_state(&resources.states, ConnectionState::ReconnectExhausted);
                    break;
                };
                set_state(
                    &resources.states,
                    ConnectionState::Reconnecting {
                        attempt: retry,
                        delay,
                    },
                );
                if !wait_to_reconnect(runtime.as_ref(), delay, &resources.cancellation).await {
                    set_state(&resources.states, ConnectionState::Stopped);
                    break;
                }
            }
            Err(_) => {
                set_state(
                    &resources.states,
                    ConnectionState::ProtocolFailed {
                        category: "unexpected client failure",
                    },
                );
                break;
            }
        }
    }
}

async fn wait_to_reconnect(
    runtime: &dyn ClientRuntime,
    delay: Duration,
    cancellation: &CancellationToken,
) -> bool {
    let sleeper = runtime.sleep(delay);
    tokio::pin!(sleeper);
    tokio::select! {
        () = cancellation.cancelled() => false,
        () = &mut sleeper => true,
    }
}

async fn run_connection(
    config: &mut GatewayClientConfig,
    runtime: Arc<dyn ClientRuntime>,
    epochs: &mut EpochAllocator,
    resources: &SupervisorResources,
) -> SessionOutcome {
    let opening = tokio::time::timeout(config.timeouts.connect, transport::connect(&config.url));
    let mut socket = tokio::select! {
        () = resources.cancellation.cancelled() => {
            return SessionOutcome {
                result: Err(GatewayClientError::Cancelled),
                was_ready: false,
            };
        }
        result = opening => match result {
            Ok(Ok(connection)) => connection,
            Ok(Err(error)) => {
                return SessionOutcome {
                    result: Err(GatewayClientError::Transport(error)),
                    was_ready: false,
                };
            }
            Err(_) => {
                return SessionOutcome {
                    result: Err(GatewayClientError::Transport(TransportFailure::TimedOut)),
                    was_ready: false,
                };
            }
        }
    };
    set_state(&resources.states, ConnectionState::Authenticating);
    let mut reader = MessageReader::new();
    let authentication = tokio::time::timeout(
        config.timeouts.authentication,
        authenticate(config, runtime.as_ref(), &mut socket, &mut reader),
    );
    let authenticated = tokio::select! {
        () = resources.cancellation.cancelled() => {
            bounded_close(&mut socket, config.timeouts.shutdown).await;
            return SessionOutcome {
                result: Err(GatewayClientError::Cancelled),
                was_ready: false,
            };
        }
        result = authentication => match result {
            Ok(Ok(authenticated)) => authenticated,
            Ok(Err(error)) => {
                return SessionOutcome {
                    result: Err(error),
                    was_ready: false,
                };
            }
            Err(_) => {
                bounded_close(&mut socket, config.timeouts.shutdown).await;
                return SessionOutcome {
                    result: Err(GatewayClientError::Transport(TransportFailure::TimedOut)),
                    was_ready: false,
                };
            }
        }
    };
    if !authenticated.issued_device_tokens.is_empty() {
        *resources.issued_device_tokens.lock().await = authenticated.issued_device_tokens;
    }
    if let Some(token) = authenticated.reconnect_device_token {
        *resources.latest_device_token.lock().await =
            Some(SecretString::from(token.expose_secret().to_owned()));
        if matches!(
            config.credential,
            GatewayCredential::BootstrapToken(_) | GatewayCredential::DeviceToken(_)
        ) {
            config.credential = GatewayCredential::DeviceToken(token);
        }
    }
    let Some(epoch) = epochs.allocate() else {
        bounded_close(&mut socket, config.timeouts.shutdown).await;
        return SessionOutcome {
            result: Err(GatewayClientError::Protocol(
                ProtocolFailure::ConnectionEpochExhausted,
            )),
            was_ready: false,
        };
    };
    let (command_tx, command_rx) = mpsc::channel(config.limits.command_queue_capacity);
    publish_ready(
        resources,
        ActiveConnection {
            epoch,
            commands: command_tx,
            max_payload_bytes: authenticated.max_payload_bytes,
        },
        ReadyConnection {
            epoch,
            info: authenticated.info.clone(),
        },
    );
    let result = run_ready(
        socket,
        ReadySession {
            epoch,
            max_payload_bytes: authenticated.max_payload_bytes,
            tick_interval: authenticated.tick_interval,
        },
        config,
        command_rx,
        resources,
        Arc::clone(&runtime),
    )
    .await;
    SessionOutcome {
        result,
        was_ready: true,
    }
}

struct Authenticated {
    info: ConnectionInfo,
    max_payload_bytes: usize,
    tick_interval: Duration,
    reconnect_device_token: Option<SecretString>,
    issued_device_tokens: Vec<IssuedDeviceToken>,
}

#[derive(Clone, Copy)]
struct ReadySession {
    epoch: ConnectionEpoch,
    max_payload_bytes: usize,
    tick_interval: Duration,
}

async fn authenticate(
    config: &GatewayClientConfig,
    runtime: &dyn ClientRuntime,
    socket: &mut transport::GatewaySocket,
    reader: &mut MessageReader,
) -> Result<Authenticated, GatewayClientError> {
    let preauth = Codec::preauthentication();
    let challenge_bytes = reader
        .read_text(socket, PREAUTH_MAX_FRAME_BYTES)
        .await
        .map_err(map_wire_failure)?;
    let challenge_event = match preauth.decode(&challenge_bytes)? {
        Frame::Event(event) => event,
        Frame::Request(_) | Frame::Response(_) => {
            return Err(GatewayClientError::Protocol(
                ProtocolFailure::ExpectedChallenge,
            ));
        }
    };
    let challenge = preauth
        .decode_challenge(&challenge_event)
        .map_err(GatewayClientError::from)?;
    let connect_id = RequestId::new(CONNECT_REQUEST_ID, PREAUTH_MAX_FRAME_BYTES)
        .expect("static connect request id is valid");
    let connect_method = GatewayMethodName::Core(
        resolve_core_method("connect").expect("P02a registry contains connect"),
    );
    let params = build_connect_params(config, runtime, &challenge.nonce)?;
    let bytes = preauth.encode_request(&connect_id, &connect_method, &params)?;
    transport::write_text(socket, bytes)
        .await
        .map_err(GatewayClientError::Transport)?;
    let hello_bytes = reader
        .read_text(socket, PREAUTH_MAX_FRAME_BYTES)
        .await
        .map_err(map_wire_failure)?;
    let response = preauth
        .decode_response(&hello_bytes, &connect_id)
        .map_err(GatewayClientError::from)?;
    if !response.ok() {
        let recovery = connect_recovery(&preauth, &response);
        let detail_code = recovery.as_ref().map(|recovery| recovery.code);
        if detail_code == Some(ConnectErrorDetailCode::ProtocolMismatch) {
            return Err(GatewayClientError::Protocol(
                ProtocolFailure::HandshakeRejected(ConnectErrorDetailCode::ProtocolMismatch),
            ));
        }
        if response.error().is_some_and(|error| {
            error.retryable == Some(true) && error.code.core() == Some(CoreErrorCode::Unavailable)
        }) || recovery
            .as_ref()
            .is_some_and(|recovery| recovery.allows_retry())
        {
            return Err(GatewayClientError::Transport(TransportFailure::Closed));
        }
        return Err(GatewayClientError::Authentication(
            AuthenticationFailure::new(
                detail_code,
                recovery
                    .as_ref()
                    .is_some_and(|recovery| recovery.recommends_device_retry()),
            ),
        ));
    }
    let hello = preauth
        .decode_hello(&response)
        .map_err(GatewayClientError::from)?;
    if hello.protocol != GATEWAY_PROTOCOL_VERSION {
        return Err(GatewayClientError::Protocol(
            ProtocolFailure::HelloProtocol {
                received: hello.protocol.get(),
            },
        ));
    }
    if hello.auth.role.as_str() != config.role.as_str() {
        return Err(GatewayClientError::Protocol(
            ProtocolFailure::HelloAuthenticationMismatch,
        ));
    }
    let mut effective_scope_identities = HashSet::new();
    for scope in &hello.auth.scopes {
        if OperatorScope::from_identity(scope.as_str()).is_none()
            || !effective_scope_identities.insert(scope.as_str())
        {
            return Err(GatewayClientError::Protocol(
                ProtocolFailure::HelloAuthenticationMismatch,
            ));
        }
    }
    if config.authorization_expectation == AuthorizationExpectation::ExactRequested {
        let requested_scope_identities = config
            .scopes
            .iter()
            .map(claw_security::authorization::Scope::as_str)
            .collect::<HashSet<_>>();
        if effective_scope_identities != requested_scope_identities {
            return Err(GatewayClientError::Protocol(
                ProtocolFailure::HelloAuthenticationMismatch,
            ));
        }
    }
    let server_max = usize::try_from(hello.policy.max_payload.get()).unwrap_or(usize::MAX);
    let max_payload_bytes = server_max.min(AUTHENTICATED_MAX_FRAME_BYTES);
    let tick_interval = Duration::from_millis(hello.policy.tick_interval_ms.get());
    let hello_role = hello.auth.role.as_str().to_owned();
    let hello_scopes = hello
        .auth
        .scopes
        .iter()
        .map(|scope| scope.as_str().to_owned())
        .collect::<Vec<_>>();
    let reconnect_device_token = hello
        .auth
        .device_token
        .as_ref()
        .map(|token| SecretString::from(token.as_str().to_owned()));
    let raw_issued_count = usize::from(hello.auth.device_token.is_some())
        + hello.auth.device_tokens.as_ref().map_or(0, Vec::len);
    if raw_issued_count > MAX_ISSUED_DEVICE_TOKENS {
        return Err(GatewayClientError::Protocol(
            ProtocolFailure::HelloAuthenticationMismatch,
        ));
    }
    let mut issued_device_tokens = Vec::new();
    if let Some(token) = &hello.auth.device_token {
        issued_device_tokens.push(IssuedDeviceToken::new(
            SecretString::from(token.as_str().to_owned()),
            hello_role.clone(),
            hello_scopes.clone().into(),
            hello.auth.issued_at_ms.map(NonNegativeInteger::get),
        ));
    }
    if let Some(tokens) = &hello.auth.device_tokens {
        for token in tokens {
            if issued_device_tokens
                .iter()
                .any(|existing| existing.token().expose_secret() == token.device_token.as_str())
            {
                continue;
            }
            issued_device_tokens.push(IssuedDeviceToken::new(
                SecretString::from(token.device_token.as_str().to_owned()),
                token.role.as_str().to_owned(),
                token
                    .scopes
                    .iter()
                    .map(|scope| scope.as_str().to_owned())
                    .collect::<Vec<_>>()
                    .into(),
                Some(token.issued_at_ms.get()),
            ));
        }
    }
    let info = ConnectionInfo {
        protocol: hello.protocol,
        server_version: hello.server.version.as_str().to_owned(),
        connection_id: hello.server.conn_id.as_str().to_owned(),
        role: hello_role,
        scopes: hello_scopes.into(),
        advertised_method_count: hello.features.methods.len(),
        advertised_event_count: hello.features.events.len(),
        max_payload_bytes,
    };
    Ok(Authenticated {
        info,
        max_payload_bytes,
        tick_interval,
        reconnect_device_token,
        issued_device_tokens,
    })
}

fn build_connect_params(
    config: &GatewayClientConfig,
    runtime: &dyn ClientRuntime,
    nonce: &ChallengeNonce,
) -> Result<ConnectParams, GatewayClientError> {
    let role =
        Name::new(config.role.as_str(), PREAUTH_MAX_FRAME_BYTES).expect("closed role is valid");
    let scopes = config
        .scopes
        .iter()
        .map(|scope| {
            Name::new(scope.as_str(), PREAUTH_MAX_FRAME_BYTES).expect("closed scope is valid")
        })
        .collect::<Vec<_>>();
    let signed_at = runtime.unix_millis();
    let signature = config
        .identity
        .sign_gateway_device(GatewayDeviceSigningInput {
            client_id: config.client.id.as_str(),
            client_mode: config.client.mode.as_str(),
            role: config.role,
            scopes: config.scopes,
            signed_at_unix_millis: signed_at,
            token: signature_token(&config.credential),
            nonce: nonce.as_str(),
            platform: config.client.platform.as_str(),
            device_family: config.client.device_family.as_ref().map(Name::as_str),
        });
    let device = DeviceProof {
        id: Name::new(
            config.identity.device_id().gateway_wire_id(),
            PREAUTH_MAX_FRAME_BYTES,
        )
        .expect("device id is non-empty"),
        public_key: WirePublicKey::new(
            URL_SAFE_NO_PAD.encode(config.identity.public_key().as_bytes()),
            PREAUTH_MAX_FRAME_BYTES,
        )
        .expect("encoded public key is non-empty"),
        signature: WireSignature::new(
            URL_SAFE_NO_PAD.encode(signature.to_bytes()),
            PREAUTH_MAX_FRAME_BYTES,
        )
        .expect("encoded signature is non-empty"),
        signed_at: NonNegativeInteger::new(signed_at),
        nonce: nonce.clone(),
    };
    Ok(ConnectParams {
        min_protocol: config.min_protocol,
        max_protocol: config.max_protocol,
        client: ClientInfo {
            id: config.client.id,
            display_name: config.client.display_name.clone(),
            version: config.client.version.clone(),
            platform: config.client.platform.clone(),
            device_family: config.client.device_family.clone(),
            model_identifier: config.client.model_identifier.clone(),
            mode: config.client.mode,
            instance_id: config.client.instance_id.clone(),
        },
        caps: Some(config.capabilities.clone()),
        commands: config.commands.clone(),
        permissions: config.permissions.clone(),
        path_env: None,
        role: Some(role),
        scopes: Some(scopes),
        device: Some(device),
        auth: wire_credentials(&config.credential),
        locale: None,
        user_agent: None,
    })
}

fn signature_token(credential: &GatewayCredential) -> Option<&SecretString> {
    match credential {
        GatewayCredential::Token(token)
        | GatewayCredential::BootstrapToken(token)
        | GatewayCredential::DeviceToken(token) => Some(token),
        GatewayCredential::None | GatewayCredential::Password(_) => None,
    }
}

fn wire_credentials(credential: &GatewayCredential) -> Option<AuthCredentials> {
    let mut auth = AuthCredentials::default();
    match credential {
        GatewayCredential::None => return None,
        GatewayCredential::Token(token) => {
            auth.token = Some(token.expose_secret().to_owned());
        }
        GatewayCredential::Password(password) => {
            auth.password = Some(password.expose_secret().to_owned());
        }
        GatewayCredential::BootstrapToken(token) => {
            auth.bootstrap_token = Some(token.expose_secret().to_owned());
        }
        GatewayCredential::DeviceToken(token) => {
            let token = token.expose_secret().to_owned();
            auth.token = Some(token.clone());
            auth.device_token = Some(token);
        }
    }
    Some(auth)
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct ConnectRecoveryProbe {
    code: ConnectErrorDetailCode,
    #[serde(default)]
    retryable: Option<bool>,
    #[serde(default)]
    pause_reconnect: Option<bool>,
    #[serde(default)]
    recommended_next_step: Option<ConnectRecoveryNextStep>,
    #[serde(default)]
    can_retry_with_device_token: Option<bool>,
}

impl ConnectRecoveryProbe {
    fn allows_retry(&self) -> bool {
        self.code != ConnectErrorDetailCode::AuthTokenMismatch
            && self.retryable == Some(true)
            && self.pause_reconnect != Some(true)
            && (self.pause_reconnect == Some(false)
                || self.recommended_next_step == Some(ConnectRecoveryNextStep::WaitThenRetry)
                || self.code == ConnectErrorDetailCode::AuthRateLimited)
    }

    fn recommends_device_retry(&self) -> bool {
        self.code == ConnectErrorDetailCode::AuthTokenMismatch
            && (self.can_retry_with_device_token == Some(true)
                || self.recommended_next_step
                    == Some(ConnectRecoveryNextStep::RetryWithDeviceToken))
    }
}

fn connect_recovery(codec: &Codec, response: &ResponseFrame) -> Option<ConnectRecoveryProbe> {
    let details: &OpaqueJson = response.error()?.details.value()?;
    codec.decode_opaque::<ConnectRecoveryProbe>(details).ok()
}

async fn run_ready(
    socket: transport::GatewaySocket,
    session: ReadySession,
    config: &GatewayClientConfig,
    mut commands: mpsc::Receiver<Command>,
    resources: &SupervisorResources,
    runtime: Arc<dyn ClientRuntime>,
) -> Result<(), GatewayClientError> {
    let (mut read, mut write) = transport::split(socket);
    let reader_cancellation = resources.cancellation.child_token();
    let (inbound_tx, mut inbound_rx) = mpsc::channel(INBOUND_QUEUE_CAPACITY);
    let reader_token = reader_cancellation.clone();
    let reader_task = resources.tasks.spawn(async move {
        let mut reader = MessageReader::new();
        loop {
            let inbound = tokio::select! {
                () = reader_token.cancelled() => break,
                result = reader.read_split(&mut read, session.max_payload_bytes) => result,
            };
            let terminal = matches!(inbound, Ok(Inbound::Close(_)) | Err(_));
            let sent = tokio::select! {
                () = reader_token.cancelled() => false,
                result = inbound_tx.send(inbound) => result.is_ok(),
            };
            if terminal || !sent {
                break;
            }
        }
    });
    let codec = Codec::authenticated();
    let mut pending = HashMap::<RequestId, PendingRequest>::new();
    let mut completed = CompletedIds::new(config.limits.completed_id_capacity);
    let mut abandoned = CompletedIds::new(config.limits.completed_id_capacity);
    let mut sequences = EventSequenceTracker::new();
    let command_policy = CommandPolicy {
        max_payload_bytes: session.max_payload_bytes,
        max_in_flight: config.limits.max_in_flight_requests,
        identifier_capacity: config.limits.completed_id_capacity,
        write_timeout: config.timeouts.request,
    };
    let mut cleanup = tokio::time::interval(Duration::from_millis(100));
    cleanup.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    let watchdog_timeout = session.tick_interval.saturating_mul(3);
    let watchdog = tokio::time::sleep(watchdog_timeout);
    tokio::pin!(watchdog);
    let result = loop {
        tokio::select! {
            () = resources.cancellation.cancelled() => {
                let _ = tokio::time::timeout(
                    config.timeouts.shutdown,
                    transport::close_split(&mut write),
                ).await;
                break Err(GatewayClientError::Cancelled);
            }
            _ = cleanup.tick() => {
                remove_cancelled(&mut pending, &mut abandoned);
            }
            () = &mut watchdog => {
                break Err(GatewayClientError::Transport(TransportFailure::TimedOut));
            }
            command = commands.recv() => {
                let Some(command) = command else {
                    break Err(GatewayClientError::Cancelled);
                };
                let context = CommandContext {
                    epoch: session.epoch,
                    policy: command_policy,
                    cancellation: &resources.cancellation,
                    runtime: runtime.as_ref(),
                    completed: &completed,
                    abandoned: &abandoned,
                };
                if let Err(error) = handle_command(
                    command,
                    &mut write,
                    &context,
                    &mut pending,
                ).await {
                    break Err(error);
                }
            }
            inbound = inbound_rx.recv() => {
                let Some(inbound) = inbound else {
                    break Err(GatewayClientError::Transport(TransportFailure::Closed));
                };
                watchdog.as_mut().reset(tokio::time::Instant::now() + watchdog_timeout);
                match inbound {
                    Ok(Inbound::Text(bytes)) => {
                        let mut context = InboundContext {
                            epoch: session.epoch,
                            pending: &mut pending,
                            completed: &mut completed,
                            abandoned: &mut abandoned,
                            sequences: &mut sequences,
                            resources,
                        };
                        if let Err(error) = handle_inbound(
                            &codec,
                            &bytes,
                            &mut context,
                        ) {
                            break Err(error);
                        }
                    }
                    Ok(Inbound::Ping(payload)) => {
                        let pong = tokio::time::timeout(
                            config.timeouts.request,
                            transport::write_pong(&mut write, payload),
                        );
                        let pong = tokio::select! {
                            () = resources.cancellation.cancelled() => {
                                break Err(GatewayClientError::Cancelled);
                            }
                            result = pong => result,
                        };
                        match pong {
                            Ok(Ok(())) => {}
                            Ok(Err(error)) => {
                                break Err(GatewayClientError::Transport(error));
                            }
                            Err(_) => {
                                break Err(GatewayClientError::Transport(
                                    TransportFailure::TimedOut,
                                ));
                            }
                        }
                    }
                    Ok(Inbound::Pong(payload)) => drop(payload),
                    Ok(Inbound::Close(close)) => {
                        let _ = tokio::time::timeout(
                            config.timeouts.shutdown,
                            transport::reply_close(&mut write, &close),
                        )
                        .await;
                        if close.is_normal() {
                            break Ok(());
                        }
                        if close.is_transient() {
                            break Err(GatewayClientError::Transport(
                                TransportFailure::PeerClosed { code: close.code() },
                            ));
                        }
                        break Err(GatewayClientError::Protocol(ProtocolFailure::PeerClose {
                            code: close.code(),
                        }));
                    }
                    Err(error) => break Err(map_wire_failure(error)),
                }
            }
        }
    };
    clear_active(&resources.active, session.epoch);
    reader_cancellation.cancel();
    let _ = reader_task.await;
    fail_pending(
        &mut pending,
        matches!(result, Err(GatewayClientError::Cancelled)),
        session.epoch,
    );
    result
}

#[derive(Clone, Copy)]
struct CommandPolicy {
    max_payload_bytes: usize,
    max_in_flight: usize,
    identifier_capacity: usize,
    write_timeout: Duration,
}

struct CommandContext<'a> {
    epoch: ConnectionEpoch,
    policy: CommandPolicy,
    cancellation: &'a CancellationToken,
    runtime: &'a dyn ClientRuntime,
    completed: &'a CompletedIds,
    abandoned: &'a CompletedIds,
}

async fn handle_command(
    command: Command,
    write: &mut transport::GatewayWriteHalf,
    context: &CommandContext<'_>,
    pending: &mut HashMap<RequestId, PendingRequest>,
) -> Result<(), GatewayClientError> {
    let Command::Request {
        epoch,
        id,
        bytes,
        mut completion,
        deadline,
        _permit,
        _byte_permit,
    } = command;
    if epoch != context.epoch {
        let _ = completion.send(Err(GatewayClientError::ConnectionChanged {
            expected: epoch,
        }));
        return Ok(());
    }
    if completion.is_closed() || tokio::time::Instant::now() >= deadline {
        return Ok(());
    }
    if pending.contains_key(&id)
        || context.completed.contains(&id)
        || context.abandoned.contains(&id)
    {
        let error = GatewayClientError::Protocol(ProtocolFailure::DuplicateRequest(id));
        let _ = completion.send(Err(error));
        return Ok(());
    }
    if pending.len() >= context.policy.max_in_flight {
        let _ = completion.send(Err(GatewayClientError::Backpressure(
            BackpressureError::InFlightLimit,
        )));
        return Ok(());
    }
    if pending.len() + context.completed.len() + context.abandoned.len()
        >= context.policy.identifier_capacity
    {
        let _ = completion.send(Err(GatewayClientError::Backpressure(
            BackpressureError::IdentifierCapacity,
        )));
        return Ok(());
    }
    if bytes.len() > context.policy.max_payload_bytes {
        let _ = completion.send(Err(GatewayClientError::Protocol(
            ProtocolFailure::OutboundMessageTooLarge {
                actual: bytes.len(),
                limit: context.policy.max_payload_bytes,
            },
        )));
        return Ok(());
    }
    let write_result = tokio::select! {
        () = context.cancellation.cancelled() => {
            let _ = completion.send(Err(GatewayClientError::Cancelled));
            return Err(GatewayClientError::Cancelled);
        }
        () = completion.closed() => {
            return Err(GatewayClientError::Transport(TransportFailure::Closed));
        }
        () = tokio::time::sleep_until(deadline) => {
            return Err(GatewayClientError::Transport(TransportFailure::TimedOut));
        }
        result = tokio::time::timeout(context.policy.write_timeout, async {
            context.runtime.before_application_write().await;
            transport::write_text_split(write, bytes).await
        }) => result,
    };
    match write_result {
        Ok(Ok(())) => {}
        Ok(Err(error)) => {
            let _ = completion.send(Err(GatewayClientError::Transport(error)));
            return Err(GatewayClientError::Transport(error));
        }
        Err(_) => {
            let _ = completion.send(Err(GatewayClientError::Transport(
                TransportFailure::TimedOut,
            )));
            return Err(GatewayClientError::Transport(TransportFailure::TimedOut));
        }
    }
    if completion.is_closed() || tokio::time::Instant::now() >= deadline {
        return Err(GatewayClientError::Transport(TransportFailure::Closed));
    }
    pending.insert(
        id,
        PendingRequest {
            completion,
            _permit,
        },
    );
    Ok(())
}

struct InboundContext<'a> {
    epoch: ConnectionEpoch,
    pending: &'a mut HashMap<RequestId, PendingRequest>,
    completed: &'a mut CompletedIds,
    abandoned: &'a mut CompletedIds,
    sequences: &'a mut EventSequenceTracker,
    resources: &'a SupervisorResources,
}

fn handle_inbound(
    codec: &Codec,
    bytes: &[u8],
    context: &mut InboundContext<'_>,
) -> Result<(), GatewayClientError> {
    match codec.decode(bytes)? {
        Frame::Response(response) => {
            let id = response.id().clone();
            if let Some(request) = context.pending.remove(&id) {
                context.completed.insert(id);
                let _ = request.completion.send(Ok(EpochResponse {
                    epoch: context.epoch,
                    frame: response,
                }));
                Ok(())
            } else if context.completed.contains(&id) {
                Err(GatewayClientError::Protocol(
                    ProtocolFailure::DuplicateResponse(id),
                ))
            } else if context.abandoned.remove(&id) {
                context.completed.insert(id);
                Ok(())
            } else {
                Err(GatewayClientError::Protocol(
                    ProtocolFailure::UnknownResponse(id),
                ))
            }
        }
        Frame::Event(event) => {
            if let Err(error) = context.sequences.observe(event.sequence()) {
                let reason = match error {
                    EventSequenceError::Gap { expected, received } => {
                        ResyncRequired::Gap { expected, received }
                    }
                    EventSequenceError::NonMonotonic { last, received } if last == received => {
                        ResyncRequired::Duplicate { sequence: received }
                    }
                    EventSequenceError::NonMonotonic { last, received } => {
                        ResyncRequired::Regression { last, received }
                    }
                    EventSequenceError::Overflow { last } => ResyncRequired::Regression {
                        last,
                        received: last,
                    },
                };
                return Err(GatewayClientError::Protocol(
                    ProtocolFailure::ResyncRequired(reason),
                ));
            }
            if context.resources.events.is_closed() {
                return Ok(());
            }
            let encoded_bytes = u32::try_from(bytes.len().max(1)).map_err(|_| {
                GatewayClientError::Protocol(ProtocolFailure::ResyncRequired(
                    ResyncRequired::EventQueueSaturated,
                ))
            })?;
            let byte_permit = Arc::clone(&context.resources.event_bytes)
                .try_acquire_many_owned(encoded_bytes)
                .map_err(|_| {
                    GatewayClientError::Protocol(ProtocolFailure::ResyncRequired(
                        ResyncRequired::EventQueueSaturated,
                    ))
                })?;
            match context
                .resources
                .events
                .try_send(GatewayEvent::new(event, byte_permit))
            {
                Ok(()) | Err(mpsc::error::TrySendError::Closed(_)) => Ok(()),
                Err(mpsc::error::TrySendError::Full(_)) => Err(GatewayClientError::Protocol(
                    ProtocolFailure::ResyncRequired(ResyncRequired::EventQueueSaturated),
                )),
            }
        }
        Frame::Request(_) => Err(GatewayClientError::Protocol(
            ProtocolFailure::UnexpectedServerRequest,
        )),
    }
}

struct CompletedIds {
    ids: HashSet<RequestId>,
}

impl CompletedIds {
    fn new(capacity: usize) -> Self {
        Self {
            ids: HashSet::with_capacity(capacity),
        }
    }

    fn contains(&self, id: &RequestId) -> bool {
        self.ids.contains(id)
    }

    fn len(&self) -> usize {
        self.ids.len()
    }

    fn insert(&mut self, id: RequestId) {
        self.ids.insert(id);
    }

    fn remove(&mut self, id: &RequestId) -> bool {
        if !self.ids.remove(id) {
            return false;
        }
        true
    }
}

fn remove_cancelled(
    pending: &mut HashMap<RequestId, PendingRequest>,
    abandoned: &mut CompletedIds,
) {
    let cancelled = pending
        .iter()
        .filter(|(_, request)| request.completion.is_closed())
        .map(|(id, _)| id.clone())
        .collect::<Vec<_>>();
    for id in cancelled {
        pending.remove(&id);
        abandoned.insert(id);
    }
}

fn fail_pending(
    pending: &mut HashMap<RequestId, PendingRequest>,
    cancelled: bool,
    epoch: ConnectionEpoch,
) {
    for (_, request) in pending.drain() {
        let error = if cancelled {
            GatewayClientError::Cancelled
        } else {
            GatewayClientError::ConnectionChanged { expected: epoch }
        };
        let _ = request.completion.send(Err(error));
    }
}

fn map_wire_failure(error: WireFailure) -> GatewayClientError {
    match error {
        WireFailure::Transport(error) => GatewayClientError::Transport(error),
        WireFailure::Protocol(error) => GatewayClientError::Protocol(error),
        WireFailure::Close(close) if close.is_transient() => {
            GatewayClientError::Transport(TransportFailure::PeerClosed { code: close.code() })
        }
        WireFailure::Close(close) => {
            GatewayClientError::Protocol(ProtocolFailure::PeerClose { code: close.code() })
        }
    }
}

async fn bounded_close(socket: &mut transport::GatewaySocket, timeout: Duration) {
    let _ = tokio::time::timeout(timeout, transport::close(socket)).await;
}

fn set_state(states: &watch::Sender<ConnectionState>, state: ConnectionState) {
    states.send_replace(state);
}

fn publish_ready(
    resources: &SupervisorResources,
    connection: ActiveConnection,
    ready: ReadyConnection,
) {
    let mut active = resources
        .active
        .write()
        .expect("active Gateway connection lock");
    *active = Some(connection);
    resources.states.send_replace(ConnectionState::Ready(ready));
}

fn clear_active(active: &RwLock<Option<ActiveConnection>>, epoch: ConnectionEpoch) {
    let mut active = active.write().expect("active Gateway connection lock");
    if active
        .as_ref()
        .is_some_and(|connection| connection.epoch == epoch)
    {
        *active = None;
    }
}

#[cfg(test)]
mod tests {
    use super::EpochAllocator;

    #[test]
    fn connection_epoch_exhaustion_fails_closed_without_wrapping() {
        let mut epochs = EpochAllocator { next: u64::MAX };
        assert_eq!(
            epochs.allocate().expect("last epoch").get(),
            u64::MAX,
            "the final non-zero epoch remains usable"
        );
        assert!(epochs.allocate().is_none());
        assert!(epochs.allocate().is_none());
    }
}

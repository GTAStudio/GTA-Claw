use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use std::time::Duration;

use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use claw_protocol::gateway::{
    AUTHENTICATED_MAX_FRAME_BYTES, AuthCredentials, ChallengeNonce, ClientInfo, Codec,
    ConnectErrorDetailCode, ConnectParams, ConnectRecoveryNextStep, CoreErrorCode, DeviceProof,
    DevicePublicKey as WirePublicKey, DeviceSignature as WireSignature, EventSequenceError,
    EventSequenceTracker, Frame, GATEWAY_PROTOCOL_VERSION, GatewayMethodName, Name,
    NonNegativeInteger, OpaqueJson, PREAUTH_MAX_FRAME_BYTES, RequestId, ResponseFrame,
    resolve_core_method,
};
use claw_security::identity::GatewayDeviceSigningInput;
use secrecy::{ExposeSecret, SecretString};
use serde::{Deserialize, Serialize};
use tokio::sync::{Mutex, OwnedSemaphorePermit, Semaphore, mpsc, oneshot, watch};
use tokio_util::sync::CancellationToken;
use tokio_util::task::TaskTracker;

use crate::config::{GatewayClientConfig, GatewayCredential};
use crate::error::{
    AuthenticationFailure, BackpressureError, ConnectionInfo, ConnectionState, GatewayClientError,
    GatewayEvent, IssuedDeviceToken, ProtocolFailure, ResyncRequired, TransportFailure,
};
use crate::runtime::{ClientRuntime, SystemRuntime, reconnect_delay};
use crate::transport::{self, Inbound, MessageReader, WireFailure};

const CONNECT_REQUEST_ID: &str = "gateway-connect";
const INBOUND_QUEUE_CAPACITY: usize = 1;

/// Cloneable handle to one reconnecting Gateway transport task.
#[derive(Clone)]
pub struct GatewayClient {
    inner: Arc<ClientInner>,
}

struct ClientInner {
    commands: mpsc::Sender<Command>,
    state: watch::Receiver<ConnectionState>,
    cancellation: CancellationToken,
    tasks: TaskTracker,
    permits: Arc<Semaphore>,
    request_timeout: Duration,
    shutdown_timeout: Duration,
    codec: Codec,
    issued_device_tokens: Arc<Mutex<Vec<IssuedDeviceToken>>>,
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
        let (command_tx, command_rx) = mpsc::channel(config.limits.command_queue_capacity);
        let (event_tx, event_rx) = mpsc::channel(config.limits.event_queue_capacity);
        let (state_tx, state_rx) = watch::channel(ConnectionState::Starting);
        let cancellation = CancellationToken::new();
        let tasks = TaskTracker::new();
        let permits = Arc::new(Semaphore::new(config.limits.max_in_flight_requests));
        let issued_device_tokens = Arc::new(Mutex::new(Vec::new()));
        let inner = Arc::new(ClientInner {
            commands: command_tx,
            state: state_rx,
            cancellation: cancellation.clone(),
            tasks: tasks.clone(),
            permits,
            request_timeout: config.timeouts.request,
            shutdown_timeout: config.timeouts.shutdown,
            codec: Codec::authenticated(),
            issued_device_tokens: Arc::clone(&issued_device_tokens),
        });
        let resources = SupervisorResources {
            events: event_tx,
            states: state_tx,
            cancellation,
            tasks: tasks.clone(),
            event_bytes: Arc::new(Semaphore::new(config.limits.event_queue_bytes)),
            issued_device_tokens,
        };
        tasks.spawn(supervise(config, runtime, command_rx, resources));
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
    pub async fn wait_ready(&self) -> Result<ConnectionInfo, GatewayClientError> {
        let mut receiver = self.inner.state.clone();
        loop {
            match receiver.borrow().clone() {
                ConnectionState::Ready(info) => return Ok(info),
                ConnectionState::AuthenticationFailed(error) => {
                    return Err(GatewayClientError::Authentication(error));
                }
                ConnectionState::ResyncRequired(reason) => {
                    return Err(GatewayClientError::Protocol(
                        ProtocolFailure::ResyncRequired(reason),
                    ));
                }
                ConnectionState::ProtocolFailed => {
                    return Err(GatewayClientError::Protocol(
                        ProtocolFailure::WebSocketProtocol,
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
        if !matches!(*self.inner.state.borrow(), ConnectionState::Ready(_)) {
            return Err(GatewayClientError::NotReady);
        }
        let permit = Arc::clone(&self.inner.permits)
            .try_acquire_owned()
            .map_err(|_| GatewayClientError::Backpressure(BackpressureError::InFlightLimit))?;
        let bytes = self.inner.codec.encode_request(&id, &method, params)?;
        let (completion, response) = oneshot::channel();
        self.inner
            .commands
            .try_send(Command::Request {
                id: id.clone(),
                bytes,
                completion,
                _permit: permit,
            })
            .map_err(|error| match error {
                mpsc::error::TrySendError::Full(_) => {
                    GatewayClientError::Backpressure(BackpressureError::CommandQueueSaturated)
                }
                mpsc::error::TrySendError::Closed(_) => GatewayClientError::Cancelled,
            })?;
        tokio::select! {
            () = self.inner.cancellation.cancelled() => Err(GatewayClientError::Cancelled),
            result = tokio::time::timeout(self.inner.request_timeout, response) => {
                match result {
                    Ok(Ok(response)) => response,
                    Ok(Err(_)) => Err(GatewayClientError::DisconnectedNotReplayed),
                    Err(_) => Err(GatewayClientError::RequestTimedOut(id)),
                }
            }
        }
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
        id: RequestId,
        bytes: Vec<u8>,
        completion: oneshot::Sender<Result<ResponseFrame, GatewayClientError>>,
        _permit: OwnedSemaphorePermit,
    },
}

struct PendingRequest {
    completion: oneshot::Sender<Result<ResponseFrame, GatewayClientError>>,
    _permit: OwnedSemaphorePermit,
}

struct SessionOutcome {
    result: Result<(), GatewayClientError>,
    was_ready: bool,
}

struct SupervisorResources {
    events: mpsc::Sender<GatewayEvent>,
    states: watch::Sender<ConnectionState>,
    cancellation: CancellationToken,
    tasks: TaskTracker,
    event_bytes: Arc<Semaphore>,
    issued_device_tokens: Arc<Mutex<Vec<IssuedDeviceToken>>>,
}

async fn supervise(
    mut config: GatewayClientConfig,
    runtime: Arc<dyn ClientRuntime>,
    mut commands: mpsc::Receiver<Command>,
    resources: SupervisorResources,
) {
    let mut retry = 0_u32;
    loop {
        set_state(&resources.states, ConnectionState::Connecting);
        let outcome =
            run_connection(&mut config, Arc::clone(&runtime), &mut commands, &resources).await;
        drain_commands(&mut commands, GatewayClientError::DisconnectedNotReplayed);
        match outcome.result {
            Err(GatewayClientError::Cancelled) | Ok(()) => {
                set_state(&resources.states, ConnectionState::Stopped);
                break;
            }
            Err(GatewayClientError::Authentication(error)) => {
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
            Err(GatewayClientError::Protocol(_)) => {
                set_state(&resources.states, ConnectionState::ProtocolFailed);
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
                if !wait_to_reconnect(
                    runtime.as_ref(),
                    delay,
                    &mut commands,
                    &resources.cancellation,
                )
                .await
                {
                    set_state(&resources.states, ConnectionState::Stopped);
                    break;
                }
            }
            Err(_) => {
                set_state(&resources.states, ConnectionState::ProtocolFailed);
                break;
            }
        }
    }
}

async fn wait_to_reconnect(
    runtime: &dyn ClientRuntime,
    delay: Duration,
    commands: &mut mpsc::Receiver<Command>,
    cancellation: &CancellationToken,
) -> bool {
    let sleeper = runtime.sleep(delay);
    tokio::pin!(sleeper);
    loop {
        tokio::select! {
            () = cancellation.cancelled() => return false,
            () = &mut sleeper => return true,
            command = commands.recv() => {
                match command {
                    Some(command) => reject_command(command, GatewayClientError::NotReady),
                    None => return false,
                }
            }
        }
    }
}

async fn run_connection(
    config: &mut GatewayClientConfig,
    runtime: Arc<dyn ClientRuntime>,
    commands: &mut mpsc::Receiver<Command>,
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
        resources.issued_device_tokens.lock().await.extend(
            authenticated.issued_device_tokens.iter().map(|issued| {
                IssuedDeviceToken::new(
                    SecretString::from(issued.token.clone()),
                    issued.role.clone(),
                    issued.scopes.clone().into(),
                    issued.issued_at_unix_millis,
                )
            }),
        );
    }
    if let Some(token) = authenticated.reconnect_device_token.as_deref()
        && matches!(config.credential, GatewayCredential::BootstrapToken(_))
    {
        config.credential = GatewayCredential::DeviceToken(SecretString::from(token.to_owned()));
    }
    set_state(
        &resources.states,
        ConnectionState::Ready(authenticated.info.clone()),
    );
    let result = run_ready(
        socket,
        authenticated.max_payload_bytes,
        config,
        commands,
        resources,
        authenticated.tick_interval,
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
    reconnect_device_token: Option<String>,
    issued_device_tokens: Vec<IssuedTokenData>,
}

struct IssuedTokenData {
    token: String,
    role: String,
    scopes: Vec<String>,
    issued_at_unix_millis: Option<u64>,
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
        }) || recovery.is_some_and(|recovery| recovery.allows_retry())
        {
            return Err(GatewayClientError::Transport(TransportFailure::Closed));
        }
        return Err(GatewayClientError::Authentication(
            AuthenticationFailure::new(detail_code),
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
    let expected_role = config.role.as_str();
    let expected_scopes = config
        .scopes
        .iter()
        .map(|scope| scope.as_str())
        .collect::<Vec<_>>();
    if hello.auth.role.as_str() != expected_role
        || hello
            .auth
            .scopes
            .iter()
            .map(Name::as_str)
            .ne(expected_scopes.iter().copied())
    {
        return Err(GatewayClientError::Protocol(
            ProtocolFailure::HelloAuthenticationMismatch,
        ));
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
        .map(|token| token.as_str().to_owned());
    let mut issued_device_tokens = Vec::new();
    if let Some(token) = &hello.auth.device_token {
        issued_device_tokens.push(IssuedTokenData {
            token: token.as_str().to_owned(),
            role: hello_role.clone(),
            scopes: hello_scopes.clone(),
            issued_at_unix_millis: hello.auth.issued_at_ms.map(NonNegativeInteger::get),
        });
    }
    if let Some(tokens) = &hello.auth.device_tokens {
        issued_device_tokens.extend(tokens.iter().map(|token| {
            IssuedTokenData {
                token: token.device_token.as_str().to_owned(),
                role: token.role.as_str().to_owned(),
                scopes: token
                    .scopes
                    .iter()
                    .map(|scope| scope.as_str().to_owned())
                    .collect(),
                issued_at_unix_millis: Some(token.issued_at_ms.get()),
            }
        }));
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
}

impl ConnectRecoveryProbe {
    fn allows_retry(&self) -> bool {
        self.retryable == Some(true)
            && self.pause_reconnect != Some(true)
            && (self.pause_reconnect == Some(false)
                || self.recommended_next_step == Some(ConnectRecoveryNextStep::WaitThenRetry)
                || self.code == ConnectErrorDetailCode::AuthRateLimited)
    }
}

fn connect_recovery(codec: &Codec, response: &ResponseFrame) -> Option<ConnectRecoveryProbe> {
    let details: &OpaqueJson = response.error()?.details.value()?;
    codec.decode_opaque::<ConnectRecoveryProbe>(details).ok()
}

async fn run_ready(
    socket: transport::GatewaySocket,
    max_payload_bytes: usize,
    config: &GatewayClientConfig,
    commands: &mut mpsc::Receiver<Command>,
    resources: &SupervisorResources,
    tick_interval: Duration,
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
                result = reader.read_split(&mut read, max_payload_bytes) => result,
            };
            let terminal = matches!(inbound, Ok(Inbound::Close) | Err(_));
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
        max_payload_bytes,
        max_in_flight: config.limits.max_in_flight_requests,
        identifier_capacity: config.limits.completed_id_capacity,
        write_timeout: config.timeouts.request,
    };
    let mut cleanup = tokio::time::interval(Duration::from_millis(100));
    cleanup.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    let watchdog_timeout = tick_interval.saturating_mul(3);
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
                if let Err(error) = handle_command(
                    command,
                    &mut write,
                    command_policy,
                    &resources.cancellation,
                    &mut pending,
                    &completed,
                    &abandoned,
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
                        if let Err(error) = handle_inbound(
                            &codec,
                            &bytes,
                            &mut pending,
                            &mut completed,
                            &mut abandoned,
                            &mut sequences,
                            resources,
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
                    Ok(Inbound::Pong) => {}
                    Ok(Inbound::Close) => {
                        let _ = tokio::time::timeout(
                            config.timeouts.shutdown,
                            transport::close_split(&mut write),
                        )
                        .await;
                        break Err(GatewayClientError::Transport(TransportFailure::Closed));
                    }
                    Err(error) => break Err(map_wire_failure(error)),
                }
            }
        }
    };
    reader_cancellation.cancel();
    let _ = reader_task.await;
    fail_pending(
        &mut pending,
        matches!(result, Err(GatewayClientError::Cancelled)),
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

async fn handle_command(
    command: Command,
    write: &mut transport::GatewayWriteHalf,
    policy: CommandPolicy,
    cancellation: &CancellationToken,
    pending: &mut HashMap<RequestId, PendingRequest>,
    completed: &CompletedIds,
    abandoned: &CompletedIds,
) -> Result<(), GatewayClientError> {
    let Command::Request {
        id,
        bytes,
        completion,
        _permit,
    } = command;
    if pending.contains_key(&id) || completed.contains(&id) || abandoned.contains(&id) {
        let error = GatewayClientError::Protocol(ProtocolFailure::DuplicateRequest(id));
        let _ = completion.send(Err(error));
        return Ok(());
    }
    if pending.len() >= policy.max_in_flight {
        let _ = completion.send(Err(GatewayClientError::Backpressure(
            BackpressureError::InFlightLimit,
        )));
        return Ok(());
    }
    if pending.len() + completed.len() + abandoned.len() >= policy.identifier_capacity {
        let _ = completion.send(Err(GatewayClientError::Backpressure(
            BackpressureError::IdentifierCapacity,
        )));
        return Ok(());
    }
    if bytes.len() > policy.max_payload_bytes {
        let _ = completion.send(Err(GatewayClientError::Protocol(
            ProtocolFailure::OutboundMessageTooLarge {
                actual: bytes.len(),
                limit: policy.max_payload_bytes,
            },
        )));
        return Ok(());
    }
    let write_result = tokio::select! {
        () = cancellation.cancelled() => {
            let _ = completion.send(Err(GatewayClientError::Cancelled));
            return Err(GatewayClientError::Cancelled);
        }
        result = tokio::time::timeout(
            policy.write_timeout,
            transport::write_text_split(write, bytes),
        ) => result,
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
    pending.insert(
        id,
        PendingRequest {
            completion,
            _permit,
        },
    );
    Ok(())
}

fn handle_inbound(
    codec: &Codec,
    bytes: &[u8],
    pending: &mut HashMap<RequestId, PendingRequest>,
    completed: &mut CompletedIds,
    abandoned: &mut CompletedIds,
    sequences: &mut EventSequenceTracker,
    resources: &SupervisorResources,
) -> Result<(), GatewayClientError> {
    match codec.decode(bytes)? {
        Frame::Response(response) => {
            let id = response.id().clone();
            if let Some(request) = pending.remove(&id) {
                completed.insert(id);
                let _ = request.completion.send(Ok(response));
                Ok(())
            } else if completed.contains(&id) {
                Err(GatewayClientError::Protocol(
                    ProtocolFailure::DuplicateResponse(id),
                ))
            } else if abandoned.remove(&id) {
                completed.insert(id);
                Ok(())
            } else {
                Err(GatewayClientError::Protocol(
                    ProtocolFailure::UnknownResponse(id),
                ))
            }
        }
        Frame::Event(event) => {
            if let Err(error) = sequences.observe(event.sequence()) {
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
            if resources.events.is_closed() {
                return Ok(());
            }
            let encoded_bytes = u32::try_from(bytes.len().max(1)).map_err(|_| {
                GatewayClientError::Protocol(ProtocolFailure::ResyncRequired(
                    ResyncRequired::EventQueueSaturated,
                ))
            })?;
            let byte_permit = Arc::clone(&resources.event_bytes)
                .try_acquire_many_owned(encoded_bytes)
                .map_err(|_| {
                    GatewayClientError::Protocol(ProtocolFailure::ResyncRequired(
                        ResyncRequired::EventQueueSaturated,
                    ))
                })?;
            match resources
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

fn fail_pending(pending: &mut HashMap<RequestId, PendingRequest>, cancelled: bool) {
    for (_, request) in pending.drain() {
        let error = if cancelled {
            GatewayClientError::Cancelled
        } else {
            GatewayClientError::DisconnectedNotReplayed
        };
        let _ = request.completion.send(Err(error));
    }
}

fn reject_command(command: Command, error: GatewayClientError) {
    let Command::Request { completion, .. } = command;
    let _ = completion.send(Err(error));
}

fn drain_commands(commands: &mut mpsc::Receiver<Command>, error: GatewayClientError) {
    let mut first = Some(error);
    while let Ok(command) = commands.try_recv() {
        reject_command(
            command,
            first
                .take()
                .unwrap_or(GatewayClientError::DisconnectedNotReplayed),
        );
    }
}

fn map_wire_failure(error: WireFailure) -> GatewayClientError {
    match error {
        WireFailure::Transport(error) => GatewayClientError::Transport(error),
        WireFailure::Protocol(error) => GatewayClientError::Protocol(error),
    }
}

async fn bounded_close(socket: &mut transport::GatewaySocket, timeout: Duration) {
    let _ = tokio::time::timeout(timeout, transport::close(socket)).await;
}

fn set_state(states: &watch::Sender<ConnectionState>, state: ConnectionState) {
    states.send_replace(state);
}

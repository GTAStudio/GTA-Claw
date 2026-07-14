use std::error::Error;
use std::fmt::{self, Display, Formatter};
use std::sync::{Arc, mpsc as std_mpsc};
use std::thread::{self, JoinHandle};
use std::time::Duration;

use claw_gateway_client::{
    ClientLimits, ClientTimeouts, ConnectionState, GatewayClient, GatewayClientConfig,
    GatewayClientError, GatewayCredential, ReconnectPolicy,
};
use claw_protocol::gateway::{
    AUTHENTICATED_MAX_FRAME_BYTES, GatewayMethodName, RequestId, resolve_core_method,
};
use claw_security::authorization::{Scope, ScopeSet};
use claw_security::identity::DeviceIdentity;
use getrandom::{SysRng, rand_core::UnwrapErr};
use serde_json::json;
use tokio::runtime::Builder;
use tokio::sync::{mpsc, oneshot};
use tokio::task::JoinHandle as TokioJoinHandle;
use tokio_util::sync::CancellationToken;

use crate::onboarding::{
    AttemptUpdate, ConnectRequest, OnboardingModel, SubmissionRejection, UserError, ViewSnapshot,
};

const COMMAND_QUEUE_CAPACITY: usize = 8;
const ATTEMPT_EVENT_CAPACITY: usize = 16;
const MAX_SESSION_DEVICE_TOKENS: usize = 32;
const ATTEMPT_STOP_TIMEOUT: Duration = Duration::from_millis(2_500);
const CONTROLLER_STOP_TIMEOUT: Duration = Duration::from_secs(4);

type ViewSink = Arc<dyn Fn(ViewSnapshot) + Send + Sync + 'static>;
type GatewayEventObserver = Arc<dyn Fn() + Send + Sync + 'static>;

enum ControllerCommand {
    Connect {
        request: ConnectRequest,
        completion: Option<oneshot::Sender<ConnectDisposition>>,
    },
    RejectSubmission(SubmissionRejection),
    Cancel,
    Disconnect,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ConnectDisposition {
    Started,
    IgnoredBusy,
}

#[derive(Clone)]
pub(crate) struct ControllerSender {
    commands: mpsc::Sender<ControllerCommand>,
    close: CancellationToken,
}

impl ControllerSender {
    pub(crate) fn connect(&self, request: ConnectRequest) -> Result<(), CommandRejection> {
        self.enqueue_connect(request, None)
    }

    fn enqueue_connect(
        &self,
        request: ConnectRequest,
        completion: Option<oneshot::Sender<ConnectDisposition>>,
    ) -> Result<(), CommandRejection> {
        self.commands
            .try_send(ControllerCommand::Connect {
                request,
                completion,
            })
            .map_err(CommandRejection::from_send)
    }

    #[cfg(test)]
    fn connect_observed(
        &self,
        request: ConnectRequest,
    ) -> Result<oneshot::Receiver<ConnectDisposition>, CommandRejection> {
        let (completion, observed) = oneshot::channel();
        self.enqueue_connect(request, Some(completion))?;
        Ok(observed)
    }

    pub(crate) fn cancel(&self) -> Result<(), CommandRejection> {
        self.commands
            .try_send(ControllerCommand::Cancel)
            .map_err(CommandRejection::from_send)
    }

    pub(crate) fn reject_submission(
        &self,
        rejection: SubmissionRejection,
    ) -> Result<(), CommandRejection> {
        self.commands
            .try_send(ControllerCommand::RejectSubmission(rejection))
            .map_err(CommandRejection::from_send)
    }

    pub(crate) fn disconnect(&self) -> Result<(), CommandRejection> {
        self.commands
            .try_send(ControllerCommand::Disconnect)
            .map_err(CommandRejection::from_send)
    }

    pub(crate) fn close(&self) {
        self.close.cancel();
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum CommandRejection {
    Busy,
    Closed,
}

impl CommandRejection {
    fn from_send(error: mpsc::error::TrySendError<ControllerCommand>) -> Self {
        match error {
            mpsc::error::TrySendError::Full(_) => Self::Busy,
            mpsc::error::TrySendError::Closed(_) => Self::Closed,
        }
    }

    pub(crate) fn user_error(self) -> UserError {
        match self {
            Self::Busy => UserError::input(
                "desktop.command-queue-busy",
                "The bounded desktop command queue is busy.",
                "Wait for the current action or cancel it before retrying.",
            ),
            Self::Closed => UserError::input(
                "desktop.controller-closed",
                "The desktop Gateway controller has already stopped.",
                "Restart the application before connecting again.",
            ),
        }
    }
}

pub(crate) struct DesktopController {
    sender: ControllerSender,
    completion: std_mpsc::Receiver<()>,
    thread: Option<JoinHandle<()>>,
}

impl DesktopController {
    pub(crate) fn spawn(
        sink: impl Fn(ViewSnapshot) + Send + Sync + 'static,
    ) -> Result<Self, ControllerStartError> {
        Self::spawn_inner(Arc::new(sink), None)
    }

    fn spawn_inner(
        sink: ViewSink,
        event_observer: Option<GatewayEventObserver>,
    ) -> Result<Self, ControllerStartError> {
        let runtime = Builder::new_multi_thread()
            .worker_threads(2)
            .thread_name("gta-claw-gateway")
            .enable_all()
            .build()
            .map_err(ControllerStartError)?;
        let (commands, receiver) = mpsc::channel(COMMAND_QUEUE_CAPACITY);
        let close = CancellationToken::new();
        let sender = ControllerSender {
            commands,
            close: close.clone(),
        };
        let (completion_tx, completion) = std_mpsc::sync_channel(1);
        let thread = thread::Builder::new()
            .name("gta-claw-controller".to_owned())
            .spawn(move || {
                runtime.block_on(controller_loop(receiver, close, sink, event_observer));
                let _ = completion_tx.send(());
            })
            .map_err(ControllerStartError)?;
        Ok(Self {
            sender,
            completion,
            thread: Some(thread),
        })
    }

    #[cfg(test)]
    fn spawn_with_event_observer(
        sink: impl Fn(ViewSnapshot) + Send + Sync + 'static,
        event_observer: impl Fn() + Send + Sync + 'static,
    ) -> Result<Self, ControllerStartError> {
        Self::spawn_inner(Arc::new(sink), Some(Arc::new(event_observer)))
    }

    pub(crate) fn sender(&self) -> ControllerSender {
        self.sender.clone()
    }

    pub(crate) fn shutdown(mut self) -> Result<(), ControllerShutdownError> {
        self.sender.close();
        self.completion
            .recv_timeout(CONTROLLER_STOP_TIMEOUT)
            .map_err(|_| ControllerShutdownError::TimedOut)?;
        if let Some(thread) = self.thread.take() {
            thread
                .join()
                .map_err(|_| ControllerShutdownError::Panicked)?;
        }
        Ok(())
    }
}

impl Drop for DesktopController {
    fn drop(&mut self) {
        self.sender.close();
    }
}

#[derive(Debug)]
pub(crate) struct ControllerStartError(std::io::Error);

impl Display for ControllerStartError {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter.write_str("failed to start the bounded desktop Gateway controller")
    }
}

impl Error for ControllerStartError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        Some(&self.0)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum ControllerShutdownError {
    TimedOut,
    Panicked,
}

impl Display for ControllerShutdownError {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::TimedOut => "desktop Gateway controller shutdown timed out",
            Self::Panicked => "desktop Gateway controller thread panicked",
        })
    }
}

impl Error for ControllerShutdownError {}

struct ActiveAttempt {
    cancellation: CancellationToken,
    task: TokioJoinHandle<()>,
}

async fn controller_loop(
    mut commands: mpsc::Receiver<ControllerCommand>,
    close: CancellationToken,
    sink: ViewSink,
    event_observer: Option<GatewayEventObserver>,
) {
    let mut model = OnboardingModel::default();
    publish(&sink, &model);
    let (attempt_events, mut events) = mpsc::channel(ATTEMPT_EVENT_CAPACITY);
    let mut active: Option<ActiveAttempt> = None;
    let mut session_identity: Option<Arc<DeviceIdentity>> = None;

    loop {
        tokio::select! {
            biased;
            () = close.cancelled() => {
                let generation = model.start_disconnect();
                publish(&sink, &model);
                stop_attempt(active.take()).await;
                drop(session_identity.take());
                model.finish_disconnect(generation);
                publish(&sink, &model);
                break;
            }
            command = commands.recv() => {
                let Some(command) = command else {
                    let generation = model.start_disconnect();
                    publish(&sink, &model);
                    stop_attempt(active.take()).await;
                    drop(session_identity.take());
                    model.finish_disconnect(generation);
                    publish(&sink, &model);
                    break;
                };
                match command {
                    ControllerCommand::Connect {
                        request,
                        completion,
                    } => {
                        if !model.can_start_connection() {
                            complete_connect(completion, ConnectDisposition::IgnoredBusy);
                            continue;
                        }
                        let endpoint = request.endpoint_display().to_owned();
                        let generation = model.begin(endpoint);
                        publish(&sink, &model);
                        stop_attempt(active.take()).await;
                        let identity = Arc::clone(session_identity.get_or_insert_with(|| {
                            let mut rng = UnwrapErr(SysRng);
                            Arc::new(DeviceIdentity::generate(&mut rng))
                        }));
                        model.apply(
                            generation,
                            AttemptUpdate::IdentityCreated(format!(
                                "{} (session only)",
                                identity.device_id()
                            )),
                        );
                        publish(&sink, &model);
                        let cancellation = CancellationToken::new();
                        let task = tokio::spawn(run_attempt(
                            generation,
                            request,
                            identity,
                            cancellation.clone(),
                            attempt_events.clone(),
                            event_observer.clone(),
                        ));
                        active = Some(ActiveAttempt { cancellation, task });
                        complete_connect(completion, ConnectDisposition::Started);
                    }
                    ControllerCommand::RejectSubmission(rejection) => {
                        if !model.can_start_connection() {
                            continue;
                        }
                        stop_attempt(active.take()).await;
                        model.reject_submission(rejection.endpoint_display, rejection.error);
                        publish(&sink, &model);
                    }
                    ControllerCommand::Cancel | ControllerCommand::Disconnect => {
                        let generation = model.start_disconnect();
                        publish(&sink, &model);
                        stop_attempt(active.take()).await;
                        session_identity = None;
                        model.finish_disconnect(generation);
                        publish(&sink, &model);
                    }
                }
            }
            event = events.recv() => {
                if let Some((generation, update)) = event
                    && model.apply(generation, update)
                {
                    publish(&sink, &model);
                }
            }
        }
    }
}

fn complete_connect(
    completion: Option<oneshot::Sender<ConnectDisposition>>,
    disposition: ConnectDisposition,
) {
    if let Some(completion) = completion {
        let _ = completion.send(disposition);
    }
}

fn publish(sink: &ViewSink, model: &OnboardingModel) {
    sink(model.snapshot());
}

async fn stop_attempt(active: Option<ActiveAttempt>) {
    let Some(mut active) = active else {
        return;
    };
    active.cancellation.cancel();
    if tokio::time::timeout(ATTEMPT_STOP_TIMEOUT, &mut active.task)
        .await
        .is_err()
    {
        active.task.abort();
        let _ = active.task.await;
    }
}

async fn run_attempt(
    generation: u64,
    request: ConnectRequest,
    identity: Arc<DeviceIdentity>,
    cancellation: CancellationToken,
    updates: mpsc::Sender<(u64, AttemptUpdate)>,
    event_observer: Option<GatewayEventObserver>,
) {
    let (url, token) = request.into_parts();
    let mut config = GatewayClientConfig::new(url, identity);
    config.credential = token.map_or(GatewayCredential::None, GatewayCredential::Token);
    config.scopes = ScopeSet::from_scopes([Scope::OperatorRead]);
    config.limits = ClientLimits {
        max_in_flight_requests: 4,
        command_queue_capacity: 8,
        outbound_queue_bytes: 64 * 1024,
        event_queue_capacity: 16,
        event_queue_bytes: 64 * 1024,
        completed_id_capacity: 32,
    };
    config.timeouts = ClientTimeouts {
        connect: Duration::from_secs(8),
        authentication: Duration::from_secs(8),
        request: Duration::from_secs(5),
        shutdown: Duration::from_secs(2),
    };
    config.reconnect = ReconnectPolicy::Bounded {
        max_attempts: 3,
        initial_delay: Duration::from_millis(250),
        max_delay: Duration::from_secs(2),
        max_jitter: Duration::from_millis(100),
    };

    let (client, mut gateway_events) = match GatewayClient::start(config) {
        Ok(client) => client,
        Err(error) => {
            let _ = send_update(
                &updates,
                generation,
                AttemptUpdate::Failed(UserError::from_gateway(&error)),
            )
            .await;
            return;
        }
    };
    let mut states = client.subscribe_state();
    let mut health_sequence = 0_u64;
    let mut issued_tokens = Vec::new();
    let mut event_stream_open = true;

    let initial_state = states.borrow_and_update().clone();
    let mut terminal = apply_client_state(
        generation,
        &client,
        &updates,
        initial_state,
        &mut health_sequence,
        &mut issued_tokens,
        &cancellation,
    )
    .await;
    while !terminal {
        tokio::select! {
            () = cancellation.cancelled() => break,
            changed = states.changed() => {
                if changed.is_err() {
                    let final_state = states.borrow_and_update().clone();
                    let _ = apply_client_state(
                        generation,
                        &client,
                        &updates,
                        final_state,
                        &mut health_sequence,
                        &mut issued_tokens,
                        &cancellation,
                    )
                    .await;
                    break;
                }
                let state = states.borrow_and_update().clone();
                terminal = apply_client_state(
                    generation,
                    &client,
                    &updates,
                    state,
                    &mut health_sequence,
                    &mut issued_tokens,
                    &cancellation,
                )
                .await;
            }
            event = gateway_events.recv(), if event_stream_open => {
                match event {
                    Some(_) => {
                        if let Some(observer) = &event_observer {
                            observer();
                        }
                    }
                    None => event_stream_open = false,
                }
            }
        }
    }
    let shutdown = client.shutdown().await;
    if !cancellation.is_cancelled()
        && let Err(error) = shutdown
    {
        let _ = send_update(
            &updates,
            generation,
            AttemptUpdate::Failed(UserError::from_gateway(&error)),
        )
        .await;
    }
    drop(issued_tokens);
}

async fn apply_client_state(
    generation: u64,
    client: &GatewayClient,
    updates: &mpsc::Sender<(u64, AttemptUpdate)>,
    state: ConnectionState,
    health_sequence: &mut u64,
    issued_tokens: &mut Vec<claw_gateway_client::IssuedDeviceToken>,
    cancellation: &CancellationToken,
) -> bool {
    let terminal = matches!(
        &state,
        ConnectionState::ResyncRequired(_)
            | ConnectionState::AuthenticationFailed(_)
            | ConnectionState::ProtocolFailed { .. }
            | ConnectionState::ReconnectExhausted
            | ConnectionState::Stopped
    );
    let mut health_failure = false;
    let update = match state {
        ConnectionState::Starting | ConnectionState::Connecting => Some(AttemptUpdate::Connecting),
        ConnectionState::Authenticating => Some(AttemptUpdate::Authenticating),
        ConnectionState::Reconnecting { attempt, .. } => {
            Some(AttemptUpdate::Reconnecting { attempt })
        }
        ConnectionState::Ready(info) => {
            if !has_exact_read_scope(&info) {
                health_failure = true;
                Some(AttemptUpdate::Failed(UserError::from_gateway(
                    &GatewayClientError::Protocol(
                        claw_gateway_client::ProtocolFailure::HelloAuthenticationMismatch,
                    ),
                )))
            } else {
                *health_sequence = health_sequence.wrapping_add(1);
                if send_update(updates, generation, AttemptUpdate::Ready(info))
                    .await
                    .is_err()
                {
                    return true;
                }
                let mut newly_issued = client.take_issued_device_tokens().await;
                issued_tokens.append(&mut newly_issued);
                issued_tokens.truncate(MAX_SESSION_DEVICE_TOKENS);
                let health = run_health_probe(client, generation, *health_sequence);
                let result = tokio::select! {
                    () = cancellation.cancelled() => return true,
                    result = health => result,
                };
                match result {
                    Ok(()) => Some(AttemptUpdate::Healthy),
                    Err(
                        GatewayClientError::DisconnectedNotReplayed
                        | GatewayClientError::NotReady
                        | GatewayClientError::Cancelled,
                    ) => None,
                    Err(error) => {
                        health_failure = true;
                        Some(AttemptUpdate::Failed(UserError::from_gateway(&error)))
                    }
                }
            }
        }
        ConnectionState::ResyncRequired(reason) => Some(AttemptUpdate::Failed(
            UserError::from_gateway(&GatewayClientError::Protocol(
                claw_gateway_client::ProtocolFailure::ResyncRequired(reason),
            )),
        )),
        ConnectionState::AuthenticationFailed(error) => Some(AttemptUpdate::Failed(
            UserError::from_gateway(&GatewayClientError::Authentication(error)),
        )),
        ConnectionState::ProtocolFailed { category } => Some(AttemptUpdate::Failed(
            UserError::from_gateway(&GatewayClientError::Protocol(
                claw_gateway_client::ProtocolFailure::WebSocketProtocol(category),
            )),
        )),
        ConnectionState::ReconnectExhausted => Some(AttemptUpdate::Failed(
            UserError::from_gateway(&GatewayClientError::ReconnectExhausted),
        )),
        ConnectionState::Stopped => Some(AttemptUpdate::Failed(UserError::from_gateway(
            &GatewayClientError::Transport(claw_gateway_client::TransportFailure::Closed),
        ))),
    };
    if let Some(update) = update {
        let _ = send_update(updates, generation, update).await;
    }
    terminal || health_failure
}

fn has_exact_read_scope(info: &claw_gateway_client::ConnectionInfo) -> bool {
    info.scopes.len() == 1 && info.scopes[0] == Scope::OperatorRead.as_str()
}

async fn run_health_probe(
    client: &GatewayClient,
    generation: u64,
    sequence: u64,
) -> Result<(), GatewayClientError> {
    let id = RequestId::new(
        format!("desktop-health-{generation}-{sequence}"),
        AUTHENTICATED_MAX_FRAME_BYTES,
    )
    .expect("bounded diagnostic request identifier");
    let method = GatewayMethodName::Core(
        resolve_core_method("health").expect("pinned Gateway registry contains health"),
    );
    let response = client
        .request_with_timeout(id, method, &json!({}), Duration::from_secs(5))
        .await?;
    if response.ok() {
        Ok(())
    } else {
        Err(GatewayClientError::Protocol(
            claw_gateway_client::ProtocolFailure::WebSocketProtocol(
                "health response reported failure",
            ),
        ))
    }
}

async fn send_update(
    updates: &mpsc::Sender<(u64, AttemptUpdate)>,
    generation: u64,
    update: AttemptUpdate,
) -> Result<(), ()> {
    updates.send((generation, update)).await.map_err(|_| ())
}

#[cfg(test)]
mod tests {
    use std::sync::Barrier;
    use std::sync::Mutex;
    use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
    use std::time::Instant;

    use fastwebsockets::Frame;
    use url::Url;

    use super::*;
    use crate::onboarding::{OnboardingPhase, UserErrorKind};
    use crate::test_gateway::{
        TestGateway, count_text_until_close, handler, receive_connect, receive_request,
        send_challenge, send_connect_error, send_health, send_health_failure, send_hello,
        send_hello_with_scopes, send_json, wait_for_close,
    };

    type Snapshots = Arc<Mutex<Vec<ViewSnapshot>>>;

    fn controller_with_snapshots() -> (DesktopController, Snapshots) {
        let snapshots = Arc::new(Mutex::new(Vec::new()));
        let sink = Arc::clone(&snapshots);
        let controller = DesktopController::spawn(move |snapshot| {
            sink.lock().expect("snapshots").push(snapshot);
        })
        .expect("controller");
        (controller, snapshots)
    }

    fn request(url: &Url) -> ConnectRequest {
        ConnectRequest::prepare(
            url.as_str().trim_end_matches('/').to_owned(),
            "desktop-session-token".to_owned(),
            true,
        )
        .expect("request")
    }

    async fn wait_snapshot(
        snapshots: &Snapshots,
        predicate: impl Fn(&ViewSnapshot) -> bool,
    ) -> ViewSnapshot {
        tokio::time::timeout(Duration::from_secs(6), async {
            loop {
                if let Some(snapshot) = snapshots
                    .lock()
                    .expect("snapshots")
                    .iter()
                    .rev()
                    .find(|snapshot| predicate(snapshot))
                    .cloned()
                {
                    return snapshot;
                }
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        })
        .await
        .expect("snapshot timeout")
    }

    fn assert_authenticated_summary_cleared(snapshot: &ViewSnapshot) {
        assert_eq!(snapshot.server(), "Not connected");
        assert_eq!(snapshot.protocol(), "Not negotiated");
        assert_eq!(snapshot.role(), "Not authenticated");
        assert_eq!(snapshot.scopes(), "No effective scopes");
        assert_eq!(snapshot.health(), "Not healthy - connection failed");
        assert!(!snapshot.health().contains("Healthy"));
    }

    #[test]
    fn command_rejections_are_typed_bounded_and_actionable() {
        for rejection in [CommandRejection::Busy, CommandRejection::Closed] {
            let error = rejection.user_error();
            assert!(error.message().len() <= 240);
            assert!(!error.action().is_empty());
        }
    }

    #[test]
    fn close_without_an_attempt_joins_the_runtime_thread() {
        let snapshots = Arc::new(Mutex::new(Vec::new()));
        let sink = Arc::clone(&snapshots);
        let controller = DesktopController::spawn(move |snapshot| {
            sink.lock().expect("snapshots").push(snapshot);
        })
        .expect("controller");
        controller.shutdown().expect("bounded shutdown");
        assert_eq!(
            snapshots
                .lock()
                .expect("snapshots")
                .last()
                .expect("snapshot")
                .phase(),
            crate::onboarding::OnboardingPhase::Disconnected
        );
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn real_gateway_authenticates_probes_health_and_discards_issued_token() {
        let gateway = TestGateway::spawn(handler(|mut socket, _| async move {
            send_challenge(&mut socket).await;
            let (connect, params) = receive_connect(&mut socket).await;
            let requested_scopes = params
                .scopes
                .as_ref()
                .expect("requested scopes")
                .iter()
                .map(|scope| scope.as_str())
                .collect::<Vec<_>>();
            assert_eq!(requested_scopes, ["operator.read"]);
            assert!(
                params
                    .auth
                    .as_ref()
                    .and_then(|auth| auth.token.as_ref())
                    .is_some()
            );
            send_hello(&mut socket, &connect, &params, 4, "desktop-success", true).await;
            let health = receive_request(&mut socket).await;
            assert!(health.id().as_str().starts_with("desktop-health-"));
            send_health(&mut socket, &health).await;
            wait_for_close(&mut socket).await;
        }))
        .await;
        let (controller, snapshots) = controller_with_snapshots();
        controller
            .sender()
            .connect(request(&gateway.url))
            .expect("connect");

        let ready = wait_snapshot(&snapshots, |snapshot| {
            snapshot.phase() == OnboardingPhase::Ready
        })
        .await;
        assert_eq!(ready.server(), "desktop-test-gateway");
        assert_eq!(ready.protocol(), "Gateway v4");
        assert_eq!(ready.role(), "operator");
        assert_eq!(ready.scopes(), "operator.read");
        assert_eq!(ready.health(), "Healthy - safe RPC completed");
        let rendered = format!("{ready:?}");
        assert!(!rendered.contains("desktop-session-token"));
        assert!(!rendered.contains("issued-device-secret"));
        assert!(!rendered.contains("must-never-render"));

        controller.sender().disconnect().expect("disconnect");
        wait_snapshot(&snapshots, |snapshot| {
            snapshot.phase() == OnboardingPhase::Disconnected
                && snapshot.identity() == "Discarded on disconnect"
        })
        .await;
        controller.shutdown().expect("shutdown");
        gateway.shutdown().await;
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn rejects_empty_extra_and_admin_effective_scopes_before_health() {
        let cases: [(&[&str], &str); 4] = [
            (&[], "empty"),
            (&["operator.read", "operator.write"], "extra"),
            (&["operator.write"], "write"),
            (&["operator.admin"], "admin"),
        ];
        for (scopes, marker) in cases {
            let application_requests = Arc::new(AtomicUsize::new(0));
            let counted_requests = Arc::clone(&application_requests);
            let gateway = TestGateway::spawn(handler(move |mut socket, _| {
                let counted_requests = Arc::clone(&counted_requests);
                async move {
                    send_challenge(&mut socket).await;
                    let (connect, params) = receive_connect(&mut socket).await;
                    send_hello_with_scopes(
                        &mut socket,
                        &connect,
                        &params,
                        4,
                        marker,
                        false,
                        scopes,
                    )
                    .await;
                    count_text_until_close(&mut socket, counted_requests).await;
                }
            }))
            .await;
            let (controller, snapshots) = controller_with_snapshots();
            controller
                .sender()
                .connect(request(&gateway.url))
                .expect("connect");
            let failed = wait_snapshot(&snapshots, |snapshot| {
                snapshot.phase() == OnboardingPhase::Failed
            })
            .await;
            assert_eq!(
                failed.error().expect("scope error").code(),
                "gateway.protocol-scope"
            );
            assert_authenticated_summary_cleared(&failed);
            controller.shutdown().expect("shutdown");
            gateway.shutdown().await;
            assert_eq!(application_requests.load(Ordering::SeqCst), 0);
        }
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn duplicate_queued_connect_keeps_first_token_and_single_attempt() {
        let tokens = Arc::new(Mutex::new(Vec::new()));
        let captured_tokens = Arc::clone(&tokens);
        let gateway = TestGateway::spawn(handler(move |mut socket, _| {
            let captured_tokens = Arc::clone(&captured_tokens);
            async move {
                send_challenge(&mut socket).await;
                let (connect, params) = receive_connect(&mut socket).await;
                captured_tokens.lock().expect("tokens").push(
                    params
                        .auth
                        .as_ref()
                        .and_then(|auth| auth.token.as_ref())
                        .cloned(),
                );
                send_hello(&mut socket, &connect, &params, 4, "first-attempt", false).await;
                let health = receive_request(&mut socket).await;
                send_health(&mut socket, &health).await;
                wait_for_close(&mut socket).await;
            }
        }))
        .await;

        let entered_initial_publish = Arc::new(Barrier::new(2));
        let release_initial_publish = Arc::new(Barrier::new(2));
        let block_first_publish = Arc::new(AtomicBool::new(true));
        let entered = Arc::clone(&entered_initial_publish);
        let release = Arc::clone(&release_initial_publish);
        let block = Arc::clone(&block_first_publish);
        let snapshots = Arc::new(Mutex::new(Vec::new()));
        let sink = Arc::clone(&snapshots);
        let controller = DesktopController::spawn(move |snapshot| {
            if block.swap(false, Ordering::SeqCst) {
                entered.wait();
                release.wait();
            }
            sink.lock().expect("snapshots").push(snapshot);
        })
        .expect("controller");
        entered_initial_publish.wait();

        let sender = controller.sender();
        let first_observed = sender
            .connect_observed(
                ConnectRequest::prepare(
                    gateway.url.as_str().trim_end_matches('/').to_owned(),
                    "first-token".to_owned(),
                    true,
                )
                .expect("first request"),
            )
            .expect("queue first");
        let duplicate_observed = sender
            .connect_observed(
                ConnectRequest::prepare(
                    gateway.url.as_str().trim_end_matches('/').to_owned(),
                    String::new(),
                    true,
                )
                .expect("duplicate request"),
            )
            .expect("queue duplicate");
        release_initial_publish.wait();
        assert_eq!(
            first_observed.await.expect("first command observed"),
            ConnectDisposition::Started
        );
        assert_eq!(
            duplicate_observed
                .await
                .expect("duplicate command observed"),
            ConnectDisposition::IgnoredBusy
        );

        wait_snapshot(&snapshots, |snapshot| {
            snapshot.phase() == OnboardingPhase::Ready
        })
        .await;
        let connections = Arc::clone(&gateway.connections);
        controller.shutdown().expect("shutdown");
        gateway.shutdown().await;
        assert_eq!(connections.load(Ordering::SeqCst), 1);
        assert_eq!(
            tokens.lock().expect("tokens").as_slice(),
            &[Some("first-token".to_owned())]
        );
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn auth_pairing_and_protocol_failures_are_typed_without_raw_payloads() {
        for (detail_code, expected_kind, expected_code) in [
            (
                "AUTH_TOKEN_MISMATCH",
                UserErrorKind::Authentication,
                "gateway.authentication",
            ),
            (
                "PAIRING_REQUIRED",
                UserErrorKind::Pairing,
                "gateway.pairing-required",
            ),
            (
                "PROTOCOL_MISMATCH",
                UserErrorKind::Protocol,
                "gateway.protocol",
            ),
        ] {
            let gateway = TestGateway::spawn(handler(move |mut socket, _| async move {
                send_challenge(&mut socket).await;
                let (connect, _) = receive_connect(&mut socket).await;
                send_connect_error(&mut socket, &connect, detail_code).await;
            }))
            .await;
            let (controller, snapshots) = controller_with_snapshots();
            controller
                .sender()
                .connect(request(&gateway.url))
                .expect("connect");
            let failed = wait_snapshot(&snapshots, |snapshot| {
                matches!(
                    snapshot.phase(),
                    OnboardingPhase::Failed | OnboardingPhase::PairingRequired
                )
            })
            .await;
            let error = failed.error().expect("typed error");
            assert_eq!(error.kind(), expected_kind);
            assert_eq!(error.code(), expected_code);
            let rendered = format!("{failed:?}");
            assert!(!rendered.contains("raw server detail"));
            assert!(!rendered.contains(detail_code));
            controller.shutdown().expect("shutdown");
            gateway.shutdown().await;
        }
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn pairing_retry_reuses_the_same_session_only_identity() {
        let device_ids = Arc::new(Mutex::new(Vec::new()));
        let captured_ids = Arc::clone(&device_ids);
        let gateway = TestGateway::spawn(handler(move |mut socket, index| {
            let captured_ids = Arc::clone(&captured_ids);
            async move {
                send_challenge(&mut socket).await;
                let (connect, params) = receive_connect(&mut socket).await;
                captured_ids.lock().expect("device ids").push(
                    params
                        .device
                        .as_ref()
                        .expect("device proof")
                        .id
                        .as_str()
                        .to_owned(),
                );
                if index == 0 {
                    send_connect_error(&mut socket, &connect, "PAIRING_REQUIRED").await;
                } else {
                    send_hello(&mut socket, &connect, &params, 4, "desktop-paired", false).await;
                    let health = receive_request(&mut socket).await;
                    send_health(&mut socket, &health).await;
                    wait_for_close(&mut socket).await;
                }
            }
        }))
        .await;
        let (controller, snapshots) = controller_with_snapshots();
        let sender = controller.sender();
        sender
            .connect(request(&gateway.url))
            .expect("first connect");
        wait_snapshot(&snapshots, |snapshot| {
            snapshot.phase() == OnboardingPhase::PairingRequired
        })
        .await;
        sender
            .connect(request(&gateway.url))
            .expect("pairing retry");
        wait_snapshot(&snapshots, |snapshot| {
            snapshot.phase() == OnboardingPhase::Ready
        })
        .await;
        let ids = device_ids.lock().expect("device ids").clone();
        assert_eq!(ids.len(), 2);
        assert_eq!(ids[0], ids[1]);
        controller.shutdown().expect("shutdown");
        gateway.shutdown().await;
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn normal_peer_close_cannot_leave_a_stale_ready_snapshot() {
        let gateway = TestGateway::spawn(handler(|mut socket, _| async move {
            send_challenge(&mut socket).await;
            let (connect, params) = receive_connect(&mut socket).await;
            send_hello(
                &mut socket,
                &connect,
                &params,
                4,
                "desktop-normal-close",
                false,
            )
            .await;
            let health = receive_request(&mut socket).await;
            send_health(&mut socket, &health).await;
            socket
                .write_frame(Frame::close(1000, b"normal close"))
                .await
                .expect("close");
            socket.flush().await.expect("flush");
        }))
        .await;
        let (controller, snapshots) = controller_with_snapshots();
        controller
            .sender()
            .connect(request(&gateway.url))
            .expect("connect");
        wait_snapshot(&snapshots, |snapshot| {
            snapshot.phase() == OnboardingPhase::Ready
        })
        .await;
        let failed = wait_snapshot(&snapshots, |snapshot| {
            snapshot.phase() == OnboardingPhase::Failed
        })
        .await;
        assert_eq!(
            failed.error().expect("close error").code(),
            "gateway.transport-closed"
        );
        assert_authenticated_summary_cleared(&failed);
        controller.shutdown().expect("shutdown");
        gateway.shutdown().await;
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn health_failure_clears_authenticated_summary_and_raw_payload() {
        let gateway = TestGateway::spawn(handler(|mut socket, _| async move {
            send_challenge(&mut socket).await;
            let (connect, params) = receive_connect(&mut socket).await;
            send_hello(
                &mut socket,
                &connect,
                &params,
                4,
                "desktop-health-failure",
                false,
            )
            .await;
            let health = receive_request(&mut socket).await;
            send_health_failure(&mut socket, &health).await;
            wait_for_close(&mut socket).await;
        }))
        .await;
        let (controller, snapshots) = controller_with_snapshots();
        controller
            .sender()
            .connect(request(&gateway.url))
            .expect("connect");
        let failed = wait_snapshot(&snapshots, |snapshot| {
            snapshot.phase() == OnboardingPhase::Failed
        })
        .await;
        assert_authenticated_summary_cleared(&failed);
        assert!(!format!("{failed:?}").contains("raw health failure"));
        controller.shutdown().expect("shutdown");
        gateway.shutdown().await;
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn stable_ready_events_do_not_trigger_additional_health_probes() {
        let additional_requests = Arc::new(AtomicUsize::new(0));
        let counted_requests = Arc::clone(&additional_requests);
        let gateway = TestGateway::spawn(handler(move |mut socket, _| {
            let counted_requests = Arc::clone(&counted_requests);
            async move {
                send_challenge(&mut socket).await;
                let (connect, params) = receive_connect(&mut socket).await;
                send_hello(
                    &mut socket,
                    &connect,
                    &params,
                    4,
                    "desktop-stable-ready",
                    false,
                )
                .await;
                let health = receive_request(&mut socket).await;
                send_health(&mut socket, &health).await;
                send_json(
                    &mut socket,
                    serde_json::json!({
                        "type": "event",
                        "event": "tick",
                        "payload": {"ts": 1_700_000_000_100_u64},
                        "seq": 1
                    }),
                )
                .await;
                count_text_until_close(&mut socket, counted_requests).await;
            }
        }))
        .await;
        let snapshots = Arc::new(Mutex::new(Vec::new()));
        let sink = Arc::clone(&snapshots);
        let (event_consumed, observed_event) = oneshot::channel();
        let event_consumed = Arc::new(Mutex::new(Some(event_consumed)));
        let event_observer = Arc::clone(&event_consumed);
        let controller = DesktopController::spawn_with_event_observer(
            move |snapshot| {
                sink.lock().expect("snapshots").push(snapshot);
            },
            move || {
                if let Some(observed) = event_observer.lock().expect("event observer").take() {
                    let _ = observed.send(());
                }
            },
        )
        .expect("controller");
        controller
            .sender()
            .connect(request(&gateway.url))
            .expect("connect");
        wait_snapshot(&snapshots, |snapshot| {
            snapshot.phase() == OnboardingPhase::Ready
        })
        .await;
        tokio::time::timeout(Duration::from_secs(2), observed_event)
            .await
            .expect("event branch timeout")
            .expect("event branch closed");
        controller.shutdown().expect("shutdown");
        gateway.shutdown().await;
        assert_eq!(additional_requests.load(Ordering::SeqCst), 0);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn transient_reconnect_runs_a_fresh_health_request_without_replay() {
        let health_ids = Arc::new(Mutex::new(Vec::new()));
        let captured_ids = Arc::clone(&health_ids);
        let gateway = TestGateway::spawn(handler(move |mut socket, index| {
            let captured_ids = Arc::clone(&captured_ids);
            async move {
                send_challenge(&mut socket).await;
                let (connect, params) = receive_connect(&mut socket).await;
                send_hello(
                    &mut socket,
                    &connect,
                    &params,
                    4,
                    "desktop-reused-connection-id",
                    false,
                )
                .await;
                let health = receive_request(&mut socket).await;
                captured_ids
                    .lock()
                    .expect("health ids")
                    .push(health.id().as_str().to_owned());
                if index == 0 {
                    socket
                        .write_frame(Frame::close(1012, b"transient restart"))
                        .await
                        .expect("close");
                    socket.flush().await.expect("flush");
                } else {
                    send_health(&mut socket, &health).await;
                    wait_for_close(&mut socket).await;
                }
            }
        }))
        .await;
        let (controller, snapshots) = controller_with_snapshots();
        controller
            .sender()
            .connect(request(&gateway.url))
            .expect("connect");
        wait_snapshot(&snapshots, |snapshot| {
            snapshot.phase() == OnboardingPhase::Reconnecting
        })
        .await;
        wait_snapshot(&snapshots, |snapshot| {
            snapshot.phase() == OnboardingPhase::Ready
        })
        .await;
        let ids = health_ids.lock().expect("health ids").clone();
        assert_eq!(ids.len(), 2);
        assert_ne!(ids[0], ids[1]);
        assert!(gateway.connections.load(Ordering::SeqCst) >= 2);
        controller.shutdown().expect("shutdown");
        gateway.shutdown().await;
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn stalled_server_cancel_and_close_are_bounded_with_no_late_ui_mutation() {
        let gateway = TestGateway::spawn(handler(|mut socket, _| async move {
            wait_for_close(&mut socket).await;
        }))
        .await;
        let (controller, snapshots) = controller_with_snapshots();
        controller
            .sender()
            .connect(request(&gateway.url))
            .expect("connect");
        wait_snapshot(&snapshots, |snapshot| {
            snapshot.phase() == OnboardingPhase::Authenticating
        })
        .await;
        let started = Instant::now();
        controller.sender().cancel().expect("cancel");
        wait_snapshot(&snapshots, |snapshot| {
            snapshot.phase() == OnboardingPhase::Disconnected
                && snapshot.identity() == "Discarded on disconnect"
        })
        .await;
        assert!(started.elapsed() < Duration::from_secs(3));
        let count_after_cancel = snapshots.lock().expect("snapshots").len();
        tokio::time::sleep(Duration::from_millis(200)).await;
        {
            let all = snapshots.lock().expect("snapshots");
            assert!(
                all[count_after_cancel..]
                    .iter()
                    .all(|snapshot| snapshot.phase() == OnboardingPhase::Disconnected)
            );
        }
        controller.shutdown().expect("shutdown");
        gateway.shutdown().await;
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn rapid_connect_cancel_connect_keeps_only_the_new_generation() {
        let stalled = TestGateway::spawn(handler(|mut socket, _| async move {
            wait_for_close(&mut socket).await;
        }))
        .await;
        let ready_gateway = TestGateway::spawn(handler(|mut socket, _| async move {
            send_challenge(&mut socket).await;
            let (connect, params) = receive_connect(&mut socket).await;
            send_hello(
                &mut socket,
                &connect,
                &params,
                4,
                "desktop-rapid-ready",
                false,
            )
            .await;
            let health = receive_request(&mut socket).await;
            send_health(&mut socket, &health).await;
            wait_for_close(&mut socket).await;
        }))
        .await;
        let (controller, snapshots) = controller_with_snapshots();
        let sender = controller.sender();
        sender
            .connect(request(&stalled.url))
            .expect("first connect");
        wait_snapshot(&snapshots, |snapshot| {
            snapshot.phase() == OnboardingPhase::Authenticating
        })
        .await;
        sender.cancel().expect("cancel");
        sender
            .connect(request(&ready_gateway.url))
            .expect("second connect");
        let ready = wait_snapshot(&snapshots, |snapshot| {
            snapshot.phase() == OnboardingPhase::Ready
                && snapshot.endpoint() == ready_gateway.url.as_str()
        })
        .await;
        assert_eq!(ready.endpoint(), ready_gateway.url.as_str());
        controller.shutdown().expect("shutdown");
        stalled.shutdown().await;
        ready_gateway.shutdown().await;
    }
}

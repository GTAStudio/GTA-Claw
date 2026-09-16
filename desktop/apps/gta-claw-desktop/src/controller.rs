use std::error::Error;
use std::fmt::{self, Display, Formatter};
use std::path::PathBuf;
use std::sync::{Arc, mpsc as std_mpsc};
use std::thread::{self, JoinHandle};
use std::time::Duration;

use claw_gateway_client::{
    AuthorizationExpectation, ClientLimits, ClientRuntime, ClientTimeouts, ConnectionEpoch,
    ConnectionState, GatewayClient, GatewayClientConfig, GatewayClientError, GatewayCredential,
    GatewayEvent, GatewayEventStream, ReadyConnection, ReconnectPolicy,
};
use claw_protocol::gateway::{
    AUTHENTICATED_MAX_FRAME_BYTES, GatewayMethodName, RequestId, resolve_core_method,
};
use claw_security::authorization::{Scope, ScopeSet};
use claw_security::identity::DeviceIdentity;
use getrandom::{SysRng, rand_core::UnwrapErr};
use serde_json::{Value, json};
use tokio::runtime::Builder;
use tokio::sync::{mpsc, oneshot, watch};
use tokio::task::{JoinHandle as TokioJoinHandle, JoinSet};
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
type GatewayEventObserver = Arc<dyn Fn(&GatewayEvent) + Send + Sync + 'static>;
type HealthObserverFuture =
    std::pin::Pin<Box<dyn std::future::Future<Output = ()> + Send + 'static>>;
type HealthSuccessObserver = Arc<dyn Fn() -> HealthObserverFuture + Send + Sync + 'static>;
type AttemptStopObserver = Arc<dyn Fn() + Send + Sync + 'static>;
type GatewayRuntime = Arc<dyn ClientRuntime>;
type ProductSink = Arc<dyn Fn(ProductUpdate) + Send + Sync + 'static>;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct ProductConnection {
    pub(crate) generation: u64,
    pub(crate) epoch: u64,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) enum LocalConfigurationAction {
    Inspect,
    PrepareModel {
        destination: PathBuf,
        expected_sha256: String,
        model: String,
    },
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct LocalConfigurationRequest {
    pub(crate) sequence: u64,
    pub(crate) source: PathBuf,
    pub(crate) action: LocalConfigurationAction,
}

#[derive(Debug)]
pub(crate) enum LocalConfigurationResult {
    Inspected(Box<claw_platform::configuration::ProviderConfiguration>),
    Prepared(Box<claw_platform::configuration::PreparedProviderConfiguration>),
}

pub(crate) enum ProductUpdate {
    LocalConfiguration {
        request: LocalConfigurationRequest,
        result:
            Result<LocalConfigurationResult, claw_platform::configuration::ConfigurationFileError>,
    },
    Reset {
        generation: u64,
    },
    Ready {
        connection: ProductConnection,
    },
    Unavailable {
        generation: u64,
    },
    HistoryStarted {
        connection: ProductConnection,
        request: u64,
        session: String,
    },
    HistoryFinished {
        connection: ProductConnection,
        request: u64,
        payload: Option<Value>,
    },
    Response {
        connection: ProductConnection,
        method: &'static str,
        params: Value,
        payload: Value,
    },
    Event {
        connection: ProductConnection,
        name: String,
        payload: Value,
    },
    Failed {
        connection: ProductConnection,
        method: &'static str,
        params: Value,
        definitive: bool,
    },
}

struct ProductCommand {
    connection: ProductConnection,
    method: &'static str,
    params: Value,
    memory: bool,
}

#[derive(Clone, Default)]
struct AttemptObservers {
    gateway_event: Option<GatewayEventObserver>,
    health_success: Option<HealthSuccessObserver>,
    product: Option<ProductSink>,
}

enum ControllerCommand {
    Connect {
        request: ConnectRequest,
        completion: Option<oneshot::Sender<ConnectDisposition>>,
    },
    RejectSubmission(SubmissionRejection),
    Product(ProductCommand),
    LocalConfiguration(LocalConfigurationRequest),
    Cancel,
    Disconnect,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ConnectDisposition {
    Started,
    IgnoredBusy,
    Closed,
}

#[derive(Clone)]
pub(crate) struct ControllerSender {
    commands: mpsc::Sender<ControllerCommand>,
    close: CancellationToken,
}

impl ControllerSender {
    pub(crate) fn local_configuration(
        &self,
        request: LocalConfigurationRequest,
    ) -> Result<(), CommandRejection> {
        if request.sequence == 0 || request.source.as_os_str().len() > 4096 {
            return Err(CommandRejection::Busy);
        }
        if let LocalConfigurationAction::PrepareModel {
            destination,
            expected_sha256,
            model,
        } = &request.action
            && (destination.as_os_str().len() > 4096
                || expected_sha256.len() != 64
                || model.len() > 256)
        {
            return Err(CommandRejection::Busy);
        }
        self.commands
            .try_send(ControllerCommand::LocalConfiguration(request))
            .map_err(|error| CommandRejection::from_send(&error))
    }

    pub(crate) fn product_request(
        &self,
        connection: ProductConnection,
        method: &'static str,
        params: Value,
    ) -> Result<(), CommandRejection> {
        if method == "chat.send" && params["message"].as_str().is_some_and(has_direct_tool_line) {
            return Err(CommandRejection::DirectTool);
        }
        self.enqueue_product(connection, method, params, false)
    }

    pub(crate) fn memory_request(
        &self,
        connection: ProductConnection,
        params: Value,
    ) -> Result<(), CommandRejection> {
        if memory_action(&params).is_none() {
            return Err(CommandRejection::DirectTool);
        }
        self.enqueue_product(connection, "chat.send", params, true)
    }

    fn enqueue_product(
        &self,
        connection: ProductConnection,
        method: &'static str,
        params: Value,
        memory: bool,
    ) -> Result<(), CommandRejection> {
        if !matches!(
            method,
            "sessions.list"
                | "sessions.get"
                | "models.list"
                | "agent.wait"
                | "chat.send"
                | "chat.history"
                | "chat.abort"
                | "approval.resolve"
                | "exec.approval.list"
                | "exec.approval.get"
        ) || params.to_string().len() > 64 * 1024
        {
            return Err(CommandRejection::Busy);
        }
        self.commands
            .try_send(ControllerCommand::Product(ProductCommand {
                connection,
                method,
                params,
                memory,
            }))
            .map_err(|error| CommandRejection::from_send(&error))
    }

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
            .map_err(|error| CommandRejection::from_send(&error))
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
            .map_err(|error| CommandRejection::from_send(&error))
    }

    pub(crate) fn reject_submission(
        &self,
        rejection: SubmissionRejection,
    ) -> Result<(), CommandRejection> {
        self.commands
            .try_send(ControllerCommand::RejectSubmission(rejection))
            .map_err(|error| CommandRejection::from_send(&error))
    }

    pub(crate) fn disconnect(&self) -> Result<(), CommandRejection> {
        self.commands
            .try_send(ControllerCommand::Disconnect)
            .map_err(|error| CommandRejection::from_send(&error))
    }

    pub(crate) fn close(&self) {
        self.close.cancel();
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum CommandRejection {
    Busy,
    Closed,
    DirectTool,
}

impl CommandRejection {
    const fn from_send(error: &mpsc::error::TrySendError<ControllerCommand>) -> Self {
        match error {
            mpsc::error::TrySendError::Full(_) => Self::Busy,
            mpsc::error::TrySendError::Closed(_) => Self::Closed,
        }
    }

    pub(crate) fn user_error(self) -> UserError {
        match self {
            Self::DirectTool => UserError::input(
                "desktop.direct-tool-input",
                "Direct tools require a valid explicit memory command.",
                "Use the memory controls with a saved device identity. No command was sent.",
            ),
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
    pub(crate) fn spawn_product(
        sink: impl Fn(ViewSnapshot) + Send + Sync + 'static,
        product: impl Fn(ProductUpdate) + Send + Sync + 'static,
    ) -> Result<Self, ControllerStartError> {
        Self::spawn_inner(
            Arc::new(sink),
            AttemptObservers {
                product: Some(Arc::new(product)),
                ..AttemptObservers::default()
            },
            None,
            None,
        )
    }

    #[cfg(test)]
    pub(crate) fn spawn(
        sink: impl Fn(ViewSnapshot) + Send + Sync + 'static,
    ) -> Result<Self, ControllerStartError> {
        Self::spawn_inner(Arc::new(sink), AttemptObservers::default(), None, None)
    }

    fn spawn_inner(
        sink: ViewSink,
        observers: AttemptObservers,
        gateway_runtime: Option<GatewayRuntime>,
        attempt_stop_observer: Option<AttemptStopObserver>,
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
                runtime.block_on(controller_loop(
                    receiver,
                    close,
                    sink,
                    observers,
                    gateway_runtime,
                    attempt_stop_observer,
                ));
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
        event_observer: impl Fn(&GatewayEvent) + Send + Sync + 'static,
    ) -> Result<Self, ControllerStartError> {
        Self::spawn_inner(
            Arc::new(sink),
            AttemptObservers {
                gateway_event: Some(Arc::new(event_observer)),
                health_success: None,
                product: None,
            },
            None,
            None,
        )
    }

    #[cfg(test)]
    fn spawn_with_gateway_runtime(
        sink: impl Fn(ViewSnapshot) + Send + Sync + 'static,
        gateway_runtime: GatewayRuntime,
    ) -> Result<Self, ControllerStartError> {
        Self::spawn_inner(
            Arc::new(sink),
            AttemptObservers::default(),
            Some(gateway_runtime),
            None,
        )
    }

    #[cfg(test)]
    fn spawn_with_stop_observer(
        sink: impl Fn(ViewSnapshot) + Send + Sync + 'static,
        attempt_stop_observer: impl Fn() + Send + Sync + 'static,
    ) -> Result<Self, ControllerStartError> {
        Self::spawn_inner(
            Arc::new(sink),
            AttemptObservers::default(),
            None,
            Some(Arc::new(attempt_stop_observer)),
        )
    }

    #[cfg(test)]
    fn spawn_with_health_success_observer<F, Fut>(
        sink: impl Fn(ViewSnapshot) + Send + Sync + 'static,
        health_success_observer: F,
    ) -> Result<Self, ControllerStartError>
    where
        F: Fn() -> Fut + Send + Sync + 'static,
        Fut: std::future::Future<Output = ()> + Send + 'static,
    {
        Self::spawn_inner(
            Arc::new(sink),
            AttemptObservers {
                gateway_event: None,
                health_success: Some(Arc::new(move || Box::pin(health_success_observer()))),
                product: None,
            },
            None,
            None,
        )
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
    product: mpsc::Sender<ProductCommand>,
}

async fn controller_loop(
    mut commands: mpsc::Receiver<ControllerCommand>,
    close: CancellationToken,
    sink: ViewSink,
    observers: AttemptObservers,
    gateway_runtime: Option<GatewayRuntime>,
    attempt_stop_observer: Option<AttemptStopObserver>,
) {
    let mut model = OnboardingModel::default();
    publish(&sink, &model);
    let (attempt_events, mut events) = mpsc::channel(ATTEMPT_EVENT_CAPACITY);
    let mut active: Option<ActiveAttempt> = None;
    let mut session_identity: Option<Arc<DeviceIdentity>> = None;
    let mut local_configuration_tasks = JoinSet::new();

    loop {
        tokio::select! {
            biased;
            () = close.cancelled() => {
                let generation = model.start_disconnect();
                publish(&sink, &model);
                stop_attempt(active.take(), attempt_stop_observer.as_ref()).await;
                drain_local_configuration_tasks(&mut local_configuration_tasks,observers.product.as_ref()).await;
                drop(session_identity.take());
                model.finish_disconnect(generation);
                publish(&sink, &model);
                break;
            }
            command = commands.recv() => {
                let Some(command) = command else {
                    let generation = model.start_disconnect();
                    publish(&sink, &model);
                    stop_attempt(active.take(), attempt_stop_observer.as_ref()).await;
                    drain_local_configuration_tasks(&mut local_configuration_tasks,observers.product.as_ref()).await;
                    drop(session_identity.take());
                    model.finish_disconnect(generation);
                    publish(&sink, &model);
                    break;
                };
                match command {
                    ControllerCommand::LocalConfiguration(request) => {
                        if local_configuration_tasks.is_empty() {
                            local_configuration_tasks.spawn(async move {
                                let target = request.clone();
                                let result = tokio::task::spawn_blocking(move || perform_local_configuration(&target)).await
                                    .unwrap_or(Err(claw_platform::configuration::ConfigurationFileError {
                                        message:"Local configuration worker ended without confirmation; preserve any candidate file",output_may_exist:true,
                                    }));
                                ProductUpdate::LocalConfiguration {request,result}
                            });
                        } else if let Some(product) = &observers.product {
                            product(ProductUpdate::LocalConfiguration {request,result:Err(claw_platform::configuration::ConfigurationFileError {
                                message:"Local configuration work is already in progress",output_may_exist:false,
                            })});
                        }
                    }
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
                        if let Some(product) = &observers.product { product(ProductUpdate::Reset { generation }); }
                        publish(&sink, &model);
                        stop_attempt(active.take(), attempt_stop_observer.as_ref()).await;
                        if close.is_cancelled() {
                            complete_connect(completion, ConnectDisposition::Closed);
                            continue;
                        }
                        let identity = Arc::clone(session_identity.get_or_insert_with(|| {
                            let mut rng = UnwrapErr(SysRng);
                            Arc::new(DeviceIdentity::generate(&mut rng))
                        }));
                        if !request.remember_device() { model.apply(
                            generation,
                            AttemptUpdate::IdentityCreated(format!(
                                "{} (session only)",
                                identity.device_id()
                            )),
                        ); }
                        publish(&sink, &model);
                        let cancellation = CancellationToken::new();
                        let (product, product_commands) = mpsc::channel(8);
                        let task = tokio::spawn(run_attempt(
                            generation,
                            request,
                            identity,
                            AttemptControl { cancellation: cancellation.clone(), product_commands },
                            attempt_events.clone(),
                            observers.clone(),
                            gateway_runtime.clone(),
                        ));
                        active = Some(ActiveAttempt { cancellation, task, product });
                        complete_connect(completion, ConnectDisposition::Started);
                    }
                    ControllerCommand::RejectSubmission(rejection) => {
                        if !model.can_start_connection() {
                            continue;
                        }
                        stop_attempt(active.take(), attempt_stop_observer.as_ref()).await;
                        model.reject_submission(rejection.endpoint_display, rejection.error);
                        publish(&sink, &model);
                    }
                    ControllerCommand::Cancel | ControllerCommand::Disconnect => {
                        let generation = model.start_disconnect();
                        if let Some(product) = &observers.product { product(ProductUpdate::Reset { generation }); }
                        publish(&sink, &model);
                        stop_attempt(active.take(), attempt_stop_observer.as_ref()).await;
                        session_identity = None;
                        model.finish_disconnect(generation);
                        publish(&sink, &model);
                    }
                    ControllerCommand::Product(command) => {
                        let connection = command.connection;
                        let method = command.method;
                        let params = command.params.clone();
                        let forwarded = active.as_ref().is_some_and(|active| active.product.try_send(command).is_ok());
                        if !forwarded && let Some(product) = &observers.product {
                            product(ProductUpdate::Failed { connection, method, params, definitive: true });
                        }
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
            result = local_configuration_tasks.join_next(), if !local_configuration_tasks.is_empty() => {
                if let Some(result) = result { publish_local_configuration_result(result,observers.product.as_ref()); }
            }
        }
    }
}

fn perform_local_configuration(
    request: &LocalConfigurationRequest,
) -> Result<LocalConfigurationResult, claw_platform::configuration::ConfigurationFileError> {
    use claw_platform::configuration::{ProviderEdit, inspect_provider, prepare_provider};
    match &request.action {
        LocalConfigurationAction::Inspect => inspect_provider(&request.source)
            .map(Box::new)
            .map(LocalConfigurationResult::Inspected),
        LocalConfigurationAction::PrepareModel {
            destination,
            expected_sha256,
            model,
        } => prepare_provider(
            &request.source,
            destination,
            expected_sha256,
            ProviderEdit::ExactModel(model),
        )
        .map(Box::new)
        .map(LocalConfigurationResult::Prepared),
    }
}

fn publish_local_configuration_result(
    result: Result<ProductUpdate, tokio::task::JoinError>,
    product: Option<&ProductSink>,
) {
    if let (Ok(update), Some(product)) = (result, product) {
        product(update);
    }
}

async fn drain_local_configuration_tasks(
    tasks: &mut JoinSet<ProductUpdate>,
    product: Option<&ProductSink>,
) {
    while let Some(result) = tasks.join_next().await {
        publish_local_configuration_result(result, product);
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

async fn stop_attempt(
    active: Option<ActiveAttempt>,
    attempt_stop_observer: Option<&AttemptStopObserver>,
) {
    let Some(mut active) = active else {
        return;
    };
    active.cancellation.cancel();
    if let Some(observer) = attempt_stop_observer {
        observer();
    }
    if tokio::time::timeout(ATTEMPT_STOP_TIMEOUT, &mut active.task)
        .await
        .is_err()
    {
        active.task.abort();
        let _ = active.task.await;
    }
}

struct AttemptControl {
    cancellation: CancellationToken,
    product_commands: mpsc::Receiver<ProductCommand>,
}

async fn run_attempt(
    generation: u64,
    request: ConnectRequest,
    identity: Arc<DeviceIdentity>,
    control: AttemptControl,
    updates: mpsc::Sender<(u64, AttemptUpdate)>,
    observers: AttemptObservers,
    gateway_runtime: Option<GatewayRuntime>,
) {
    let AttemptControl {
        cancellation,
        mut product_commands,
    } = control;
    let remembered = request.remember_device();
    let (url, token) = request.into_parts();
    let identity = if remembered {
        let endpoint = url.as_str().to_owned();
        let stored = tokio::task::spawn_blocking(move || {
            let store = claw_platform::identity::native_store()?;
            let root = claw_platform::identity::native_lock_directory()?;
            claw_platform::identity::DeviceProfile::new(&endpoint, "desktop", root)?
                .load_or_create(store.as_ref())
        });
        let result = tokio::select! {
            biased;
            () = cancellation.cancelled() => return,
            result = stored => result,
        };
        let Ok(Ok(identity)) = result else {
            let _ = send_update(
                &updates,
                generation,
                AttemptUpdate::Failed(UserError::input(
                    "identity.storage-unavailable",
                    "The saved device identity could not be loaded safely.",
                    "Check system credential storage; no temporary identity was substituted.",
                )),
            )
            .await;
            return;
        };
        let _ = send_update(
            &updates,
            generation,
            AttemptUpdate::IdentityCreated(format!(
                "{} (native credential store)",
                identity.device_id()
            )),
        )
        .await;
        Arc::new(identity)
    } else {
        identity
    };
    let mut config = GatewayClientConfig::new(url, identity);
    config.credential = token.map_or(GatewayCredential::None, GatewayCredential::Token);
    let product_mode = observers.product.is_some();
    config.scopes = if product_mode {
        ScopeSet::from_scopes([
            Scope::OperatorRead,
            Scope::OperatorWrite,
            Scope::OperatorApprovals,
        ])
    } else {
        ScopeSet::from_scopes([Scope::OperatorRead])
    };
    config.authorization_expectation = AuthorizationExpectation::ExactRequested;
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

    let started = match gateway_runtime {
        Some(runtime) => GatewayClient::start_with_runtime(config, runtime),
        None => GatewayClient::start(config),
    };
    let (client, mut gateway_events) = match started {
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
    let mut event_stream_open = true;
    let context = AttemptContext {
        generation,
        client: &client,
        updates: &updates,
        cancellation: &cancellation,
        health_success_observer: observers.health_success.as_ref(),
        product_mode,
        product: observers.product.as_ref(),
    };
    let mut progress = AttemptProgress {
        last_ready_epoch: None,
        healthy_epoch: None,
        issued_tokens: Vec::new(),
    };

    let mut pending_state = Some(states.borrow_and_update().clone());
    let mut terminal = false;
    let mut product_tasks = JoinSet::new();
    let mut product_sequence = 0_u64;
    while !terminal {
        if let Some(state) = pending_state.take() {
            let mut streams = AttemptStreams {
                states: &mut states,
                gateway_events: &mut gateway_events,
                event_stream_open: &mut event_stream_open,
                event_observer: observers.gateway_event.as_ref(),
            };
            match apply_client_state(&context, state, &mut progress, &mut streams).await {
                StateApplication::Continue => {}
                StateApplication::ContinueWith(state) => pending_state = Some(state),
                StateApplication::Terminal => terminal = true,
            }
            continue;
        }
        tokio::select! {
            biased;
            () = cancellation.cancelled() => break,
            _ = states.changed() => {
                pending_state = Some(states.borrow_and_update().clone());
            }
            event = gateway_events.recv(), if event_stream_open => {
                if let (Some(event), Some(product), Some(epoch)) = (event.as_ref(), observers.product.as_ref(), progress.healthy_epoch) {
                    let frame = event.frame();
                    if event.epoch() == epoch
                        && matches!(frame.event().as_str(), "chat" | "session.operation" | "session.tool" | "exec.approval.requested" | "exec.approval.resolved" | "sessions.changed")
                        && let Some(payload) = frame.payload().value()
                        && let Ok(payload) = serde_json::from_str(payload.as_json())
                    {
                        product(ProductUpdate::Event { connection: ProductConnection { generation, epoch: event.epoch().get() }, name: frame.event().as_str().to_owned(), payload });
                    }
                }
                observe_gateway_event(
                    event,
                    &mut event_stream_open,
                    observers.gateway_event.as_ref(),
                );
            }
            command = product_commands.recv(), if product_mode => {
                let Some(command) = command else { break };
                let Some(product) = observers.product.as_ref() else { continue };
                let connection = command.connection;
                let epoch = progress.healthy_epoch.filter(|epoch| connection.generation == generation && connection.epoch == epoch.get());
                let Some(epoch) = epoch.filter(|_| product_tasks.len() < 4 && product_sequence != u64::MAX) else {
                    product(ProductUpdate::Failed { connection, method: command.method, params: command.params, definitive: true });
                    continue;
                };
                product_sequence += 1;
                let request_id = RequestId::new(format!("desktop-{generation}-{product_sequence}"), AUTHENTICATED_MAX_FRAME_BYTES).expect("bounded native request identity");
                let method = GatewayMethodName::Core(resolve_core_method(command.method).expect("closed product command catalog"));
                let client = client.clone();
                let product = Arc::clone(product);
                let history = command.method == "chat.history";
                let sequence = product_sequence;
                if history {
                    product(ProductUpdate::HistoryStarted { connection, request: sequence, session: command.params["sessionKey"].as_str().unwrap_or_default().to_owned() });
                }
                product_tasks.spawn(async move {
                    if command.memory {
                        let health_id = RequestId::new(format!("desktop-memory-health-{generation}-{sequence}"), AUTHENTICATED_MAX_FRAME_BYTES).expect("bounded memory health identity");
                        let supported = if remembered {
                            let health = client.request_for_epoch(epoch, health_id, GatewayMethodName::Core(resolve_core_method("health").expect("health method")), &json!({})).await;
                            health.ok().filter(claw_protocol::gateway::ResponseFrame::ok)
                                .and_then(|response| response.payload().value().and_then(|payload| serde_json::from_str::<Value>(payload.as_json()).ok()))
                                .is_some_and(|health| memory_capabilities_match(&health, memory_action(&command.params).as_deref()))
                        } else { false };
                        if !supported {
                            product(ProductUpdate::Failed { connection, method: command.method, params: command.params, definitive: true });
                            return;
                        }
                    }
                    let response = client.request_for_epoch(epoch, request_id, method, &command.params).await;
                    if history {
                        let payload = response.ok().filter(claw_protocol::gateway::ResponseFrame::ok).and_then(|response| response.payload().value().and_then(|payload| serde_json::from_str::<Value>(payload.as_json()).ok())).filter(Value::is_object);
                        product(ProductUpdate::HistoryFinished { connection, request: sequence, payload });
                        return;
                    }
                    match response {
                        Ok(response) if response.ok() => {
                            if let Some(payload) = response.payload().value().and_then(|payload| serde_json::from_str::<Value>(payload.as_json()).ok()).filter(Value::is_object) {
                                product(ProductUpdate::Response { connection, method: command.method, params: command.params, payload });
                            } else {
                                product(ProductUpdate::Failed { connection, method: command.method, params: command.params, definitive: false });
                            }
                        }
                        response => {
                            let definitive = match &response {
                                Ok(response) => response.error().is_some_and(|error| matches!(error.code.as_str(), "INVALID_REQUEST" | "UNAUTHORIZED" | "NOT_FOUND" | "METHOD_NOT_FOUND" | "NOT_IMPLEMENTED")),
                                Err(GatewayClientError::NotReady | GatewayClientError::Backpressure(_)) => true,
                                Err(_) => false,
                            };
                            product(ProductUpdate::Failed { connection, method: command.method, params: command.params, definitive });
                        }
                    }
                });
            }
            completed = product_tasks.join_next(), if !product_tasks.is_empty() => {
                if completed.is_some_and(|result| result.is_err()) { terminal = true; }
            }
        }
    }
    product_tasks.abort_all();
    while product_tasks.join_next().await.is_some() {}
    if let Some(product) = &observers.product {
        product(ProductUpdate::Unavailable { generation });
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
    drop(progress.issued_tokens);
}

enum StateApplication {
    Continue,
    ContinueWith(ConnectionState),
    Terminal,
}

fn has_direct_tool_line(text: &str) -> bool {
    text.lines().any(|line| {
        line.trim_start()
            .get(..5)
            .is_some_and(|prefix| prefix.eq_ignore_ascii_case("!tool"))
    })
}

fn memory_action(params: &Value) -> Option<String> {
    let message = params["message"]
        .as_str()
        .filter(|message| message.len() <= 16 * 1024)?;
    let raw = claw_protocol::gateway::OpaqueJson::from_json_string(
        message.strip_prefix("!tool ")?.to_owned(),
    )
    .ok()?;
    let envelope: Value = claw_protocol::gateway::Codec::authenticated()
        .decode_opaque(&raw)
        .ok()?;
    if envelope["name"] != "memory_notes"
        || !envelope["arguments"].is_object()
        || envelope.as_object()?.len() != 2
        || params["sessionKey"].as_str().is_none_or(|session| {
            session.is_empty() || session.len() > 128 || session.chars().any(char::is_control)
        })
        || params["idempotencyKey"].as_str().is_none_or(|key| {
            key.is_empty() || key.len() > 128 || key.chars().any(char::is_control)
        })
        || params.as_object()?.len() != 3
    {
        return None;
    }
    let action = envelope["arguments"]["action"].as_str()?;
    matches!(
        action,
        "list" | "get" | "search" | "save" | "delete" | "export" | "import"
    )
    .then(|| action.to_owned())
}

fn memory_capabilities_match(health: &Value, action: Option<&str>) -> bool {
    let direct = &health["native"]["directTool"];
    let memory = &health["native"]["explicitMemory"];
    action.is_some()
        && health["ok"] == true
        && health["protocol"] == 4
        && health["native"]["schemaVersion"] == 1
        && direct["version"] == 1
        && direct["prefix"] == "!tool "
        && direct["modelInvoked"] == false
        && direct["authenticated"] == true
        && direct["durableRuns"] == true
        && direct["accepting"] == true
        && direct["approvalPolicy"] == "per-tool"
        && memory["enabled"] == true
        && memory["accepting"] == true
        && memory["requiresApproval"] == true
        && memory["partition"] == "source/subject/account"
        && memory["automaticContextInjection"] == false
        && (!matches!(action, Some("export" | "import")) || memory["archiveSchemaVersion"] == 1)
}

enum HealthWait {
    Completed(Result<(), GatewayClientError>),
    StateChanged(ConnectionState),
    Cancelled,
}

struct AttemptContext<'a> {
    generation: u64,
    client: &'a GatewayClient,
    updates: &'a mpsc::Sender<(u64, AttemptUpdate)>,
    cancellation: &'a CancellationToken,
    health_success_observer: Option<&'a HealthSuccessObserver>,
    product_mode: bool,
    product: Option<&'a ProductSink>,
}

struct AttemptProgress {
    last_ready_epoch: Option<ConnectionEpoch>,
    healthy_epoch: Option<ConnectionEpoch>,
    issued_tokens: Vec<claw_gateway_client::IssuedDeviceToken>,
}

struct AttemptStreams<'a> {
    states: &'a mut watch::Receiver<ConnectionState>,
    gateway_events: &'a mut GatewayEventStream,
    event_stream_open: &'a mut bool,
    event_observer: Option<&'a GatewayEventObserver>,
}

async fn apply_client_state(
    context: &AttemptContext<'_>,
    state: ConnectionState,
    progress: &mut AttemptProgress,
    streams: &mut AttemptStreams<'_>,
) -> StateApplication {
    if !matches!(state, ConnectionState::Ready(_)) {
        progress.healthy_epoch = None;
        if let Some(product) = context.product {
            product(ProductUpdate::Unavailable {
                generation: context.generation,
            });
        }
    }
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
        ConnectionState::Ready(ready) => {
            if progress.last_ready_epoch == Some(ready.epoch) {
                None
            } else if !(if context.product_mode {
                ready.info.role == "operator"
                    && ready.info.scopes.len() == 3
                    && ["operator.read", "operator.write", "operator.approvals"]
                        .into_iter()
                        .all(|scope| ready.info.scopes.iter().any(|granted| granted == scope))
            } else {
                has_exact_read_scope(&ready)
            }) {
                health_failure = true;
                Some(AttemptUpdate::Failed(UserError::from_gateway(
                    &GatewayClientError::Protocol(
                        claw_gateway_client::ProtocolFailure::HelloAuthenticationMismatch,
                    ),
                )))
            } else {
                progress.last_ready_epoch = Some(ready.epoch);
                if send_update(
                    context.updates,
                    context.generation,
                    AttemptUpdate::Ready(ready.info.clone()),
                )
                .await
                .is_err()
                {
                    return StateApplication::Terminal;
                }
                let mut newly_issued = context.client.take_issued_device_tokens().await;
                progress.issued_tokens.append(&mut newly_issued);
                progress.issued_tokens.truncate(MAX_SESSION_DEVICE_TOKENS);
                match wait_for_health_while_draining(context, ready.epoch, streams).await {
                    HealthWait::Cancelled => return StateApplication::Terminal,
                    HealthWait::StateChanged(state) => {
                        return StateApplication::ContinueWith(state);
                    }
                    HealthWait::Completed(Ok(())) => {
                        progress.healthy_epoch = Some(ready.epoch);
                        if let Some(product) = context.product {
                            product(ProductUpdate::Ready {
                                connection: ProductConnection {
                                    generation: context.generation,
                                    epoch: ready.epoch.get(),
                                },
                            });
                        }
                        Some(AttemptUpdate::Healthy)
                    }
                    HealthWait::Completed(Err(
                        GatewayClientError::DisconnectedNotReplayed
                        | GatewayClientError::ConnectionChanged { .. }
                        | GatewayClientError::NotReady
                        | GatewayClientError::Cancelled,
                    )) => None,
                    HealthWait::Completed(Err(error)) => {
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
        let _ = send_update(context.updates, context.generation, update).await;
    }
    if terminal || health_failure {
        StateApplication::Terminal
    } else {
        StateApplication::Continue
    }
}

async fn wait_for_health_while_draining(
    context: &AttemptContext<'_>,
    epoch: ConnectionEpoch,
    streams: &mut AttemptStreams<'_>,
) -> HealthWait {
    let health = run_health_probe(context.client, context.generation, epoch);
    tokio::pin!(health);
    loop {
        tokio::select! {
            biased;
            () = context.cancellation.cancelled() => return HealthWait::Cancelled,
            result = &mut health => {
                if result.is_ok()
                    && let Some(observer) = context.health_success_observer
                {
                    observer().await;
                }
                return HealthWait::Completed(result);
            }
            changed = streams.states.changed() => {
                let state = streams.states.borrow_and_update().clone();
                if changed.is_err() || !is_ready_epoch(&state, epoch) {
                    return HealthWait::StateChanged(state);
                }
            }
            event = streams.gateway_events.recv(), if *streams.event_stream_open => {
                observe_gateway_event(
                    event,
                    streams.event_stream_open,
                    streams.event_observer,
                );
            }
        }
    }
}

fn observe_gateway_event(
    event: Option<GatewayEvent>,
    event_stream_open: &mut bool,
    event_observer: Option<&GatewayEventObserver>,
) {
    match event {
        Some(event) => {
            if let Some(observer) = event_observer {
                observer(&event);
            }
        }
        None => *event_stream_open = false,
    }
}

fn is_ready_epoch(state: &ConnectionState, epoch: ConnectionEpoch) -> bool {
    matches!(state, ConnectionState::Ready(ready) if ready.epoch == epoch)
}

fn has_exact_read_scope(ready: &ReadyConnection) -> bool {
    ready.scopes.len() == 1 && ready.scopes[0] == Scope::OperatorRead.as_str()
}

async fn run_health_probe(
    client: &GatewayClient,
    generation: u64,
    epoch: ConnectionEpoch,
) -> Result<(), GatewayClientError> {
    let id = RequestId::new(
        format!("desktop-health-{generation}-epoch-{}", epoch.get()),
        AUTHENTICATED_MAX_FRAME_BYTES,
    )
    .expect("bounded diagnostic request identifier");
    let method = GatewayMethodName::Core(
        resolve_core_method("health").expect("pinned Gateway registry contains health"),
    );
    let response = client
        .request_with_timeout_for_epoch(epoch, id, method, &json!({}), Duration::from_secs(5))
        .await?;
    let healthy_payload = response
        .payload()
        .value()
        .and_then(|payload| serde_json::from_str::<serde_json::Value>(payload.as_json()).ok())
        .and_then(|payload| payload.get("ok").and_then(serde_json::Value::as_bool))
        == Some(true);
    if response.ok() && healthy_payload {
        Ok(())
    } else {
        Err(GatewayClientError::Protocol(
            claw_gateway_client::ProtocolFailure::WebSocketProtocol(
                "health response did not confirm readiness",
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
    #[test]
    fn native_memory_health_requires_model_free_approved_durable_identity_scope() {
        let health = serde_json::json!({"ok":true,"protocol":4,"native":{"schemaVersion":1,"directTool":{"version":1,"prefix":"!tool ","modelInvoked":false,"authenticated":true,"durableRuns":true,"approvalPolicy":"per-tool","accepting":true},"explicitMemory":{"enabled":true,"accepting":true,"requiresApproval":true,"partition":"source/subject/account","automaticContextInjection":false,"archiveSchemaVersion":1}}});
        assert!(super::memory_capabilities_match(&health, Some("save")));
        assert!(super::memory_capabilities_match(&health, Some("export")));
        for field in [
            "/ok",
            "/protocol",
            "/native/schemaVersion",
            "/native/directTool/version",
            "/native/directTool/prefix",
            "/native/directTool/modelInvoked",
            "/native/directTool/authenticated",
            "/native/directTool/durableRuns",
            "/native/directTool/approvalPolicy",
            "/native/directTool/accepting",
            "/native/explicitMemory/enabled",
            "/native/explicitMemory/accepting",
            "/native/explicitMemory/requiresApproval",
            "/native/explicitMemory/partition",
            "/native/explicitMemory/automaticContextInjection",
            "/native/explicitMemory/archiveSchemaVersion",
        ] {
            let mut changed = health.clone();
            *changed.pointer_mut(field).expect("capability field") = serde_json::Value::Null;
            assert!(
                !super::memory_capabilities_match(&changed, Some("export")),
                "{field}"
            );
        }
        assert!(super::has_direct_tool_line("line\n !TOOL= {}"));
        assert!(!super::has_direct_tool_line("ordinary message"));
    }

    use std::future::Future;
    use std::pin::Pin;
    use std::sync::Barrier;
    use std::sync::Mutex;
    use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
    use std::time::Instant;

    use fastwebsockets::Frame;
    use tokio::sync::{Notify, Semaphore};
    use url::Url;

    use super::*;
    use crate::onboarding::{OnboardingPhase, UserErrorKind};
    use crate::test_gateway::{
        TestGateway, count_text_until_close, handler, receive_connect, receive_request,
        send_challenge, send_connect_error, send_health, send_health_failure, send_health_payload,
        send_hello, send_hello_with_scopes, send_json, wait_for_close,
    };
    use claw_gateway_client::SystemRuntime;

    type Snapshots = Arc<Mutex<Vec<ViewSnapshot>>>;

    struct EpochGateRuntime {
        system: SystemRuntime,
        gate_next: AtomicBool,
        entered: Notify,
        release: Arc<Semaphore>,
    }

    impl EpochGateRuntime {
        fn new() -> Arc<Self> {
            Arc::new(Self {
                system: SystemRuntime::default(),
                gate_next: AtomicBool::new(true),
                entered: Notify::new(),
                release: Arc::new(Semaphore::new(0)),
            })
        }

        async fn wait_until_blocked(&self) {
            tokio::time::timeout(Duration::from_secs(2), self.entered.notified())
                .await
                .expect("health request reached epoch gate");
        }

        fn unblock(&self) {
            self.release.add_permits(1);
        }
    }

    impl ClientRuntime for EpochGateRuntime {
        fn unix_millis(&self) -> u64 {
            self.system.unix_millis()
        }

        fn sleep(&self, duration: Duration) -> Pin<Box<dyn Future<Output = ()> + Send + 'static>> {
            self.system.sleep(duration)
        }

        fn jitter(&self, maximum: Duration) -> Duration {
            self.system.jitter(maximum)
        }

        fn before_request_enqueue(&self) -> Pin<Box<dyn Future<Output = ()> + Send + 'static>> {
            if self.gate_next.swap(false, Ordering::SeqCst) {
                self.entered.notify_one();
                let release = Arc::clone(&self.release);
                Box::pin(async move {
                    release
                        .acquire_owned()
                        .await
                        .expect("epoch gate remains open")
                        .forget();
                })
            } else {
                Box::pin(async {})
            }
        }
    }

    fn controller_with_snapshots() -> (DesktopController, Snapshots) {
        let snapshots = Arc::new(Mutex::new(Vec::new()));
        let sink = Arc::clone(&snapshots);
        let controller = DesktopController::spawn(move |snapshot| {
            sink.lock().expect("snapshots").push(snapshot);
        })
        .expect("controller");
        (controller, snapshots)
    }

    fn controller_with_runtime(runtime: Arc<EpochGateRuntime>) -> (DesktopController, Snapshots) {
        let snapshots = Arc::new(Mutex::new(Vec::new()));
        let sink = Arc::clone(&snapshots);
        let controller = DesktopController::spawn_with_gateway_runtime(
            move |snapshot| {
                sink.lock().expect("snapshots").push(snapshot);
            },
            runtime as GatewayRuntime,
        )
        .expect("controller");
        (controller, snapshots)
    }

    fn request(url: &Url) -> ConnectRequest {
        ConnectRequest::prepare(
            url.as_str().trim_end_matches('/'),
            "desktop-session-token".to_owned(),
            true,
        )
        .expect("request")
    }

    async fn wait_snapshot(
        snapshots: &Snapshots,
        predicate: impl Fn(&ViewSnapshot) -> bool + Send + Sync,
    ) -> ViewSnapshot {
        tokio::time::timeout(Duration::from_secs(6), async {
            loop {
                let matched = snapshots
                    .lock()
                    .expect("snapshots")
                    .iter()
                    .rev()
                    .find(|snapshot| predicate(snapshot))
                    .cloned();
                if let Some(snapshot) = matched {
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
    async fn close_during_retry_teardown_never_spawns_a_replacement_attempt() {
        let gateway = TestGateway::spawn(handler(|mut socket, index| async move {
            assert_eq!(index, 0, "close must prevent a replacement connection");
            send_challenge(&mut socket).await;
            let (connect, params) = receive_connect(&mut socket).await;
            send_hello(
                &mut socket,
                &connect,
                &params,
                4,
                "desktop-close-retry-race",
                false,
            )
            .await;
            let health = receive_request(&mut socket).await;
            send_health_failure(&mut socket, &health).await;
            wait_for_close(&mut socket).await;
        }))
        .await;
        let snapshots = Arc::new(Mutex::new(Vec::new()));
        let sink = Arc::clone(&snapshots);
        let stop_entered = Arc::new(Barrier::new(2));
        let stop_release = Arc::new(Barrier::new(2));
        let observed_entered = Arc::clone(&stop_entered);
        let observed_release = Arc::clone(&stop_release);
        let controller = DesktopController::spawn_with_stop_observer(
            move |snapshot| {
                sink.lock().expect("snapshots").push(snapshot);
            },
            move || {
                observed_entered.wait();
                observed_release.wait();
            },
        )
        .expect("controller");
        let sender = controller.sender();
        sender
            .connect(request(&gateway.url))
            .expect("initial connect");
        wait_snapshot(&snapshots, |snapshot| {
            snapshot.phase() == OnboardingPhase::Failed
        })
        .await;

        let retry = sender
            .connect_observed(request(&gateway.url))
            .expect("retry queued");
        stop_entered.wait();
        sender.close();
        stop_release.wait();
        assert_eq!(
            tokio::time::timeout(Duration::from_secs(2), retry)
                .await
                .expect("retry acknowledgement")
                .expect("controller acknowledgement"),
            ConnectDisposition::Closed
        );
        controller.shutdown().expect("bounded shutdown");
        assert_eq!(gateway.connections.load(Ordering::SeqCst), 1);
        assert_eq!(
            snapshots
                .lock()
                .expect("snapshots")
                .last()
                .expect("snapshot")
                .phase(),
            OnboardingPhase::Disconnected
        );
        gateway.shutdown().await;
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn product_gateway_reconnect_rejects_commands_from_the_previous_epoch() {
        let restart = Arc::new(Notify::new());
        let request_restart = Arc::clone(&restart);
        let gateway = TestGateway::spawn(handler(move |mut socket, index| {
            let restart = Arc::clone(&restart);
            async move {
                send_challenge(&mut socket).await;
                let (connect, params) = receive_connect(&mut socket).await;
                send_hello(&mut socket, &connect, &params, 4, "reused-product-connection", false).await;
                let health = receive_request(&mut socket).await;
                send_health(&mut socket, &health).await;
                if index == 0 {
                    restart.notified().await;
                    socket.write_frame(Frame::close(1012, b"fixture restart")).await.expect("close first epoch");
                    socket.flush().await.expect("flush close");
                } else {
                    let request = receive_request(&mut socket).await;
                    assert_eq!(request.method().as_str(), "chat.send", "stale approval must not reach the new socket");
                    send_json(&mut socket, json!({"type": "res", "id": request.id().as_str(), "ok": true, "payload": {"runId": "new-run"}})).await;
                    send_json(&mut socket, json!({"type": "event", "event": "chat", "seq": 1, "payload": {"runId": "new-run", "sessionId": "native-session", "status": "completed", "text": "new epoch"}})).await;
                    wait_for_close(&mut socket).await;
                }
            }
        })).await;
        let (updates, mut observed) = mpsc::channel(32);
        let controller = DesktopController::spawn_product(
            |_| {},
            move |update| {
                assert!(updates.try_send(update).is_ok(), "test update queue");
            },
        )
        .expect("controller");
        controller
            .sender()
            .connect(request(&gateway.url))
            .expect("connect");
        let first = tokio::time::timeout(Duration::from_secs(3), async {
            loop {
                if let ProductUpdate::Ready { connection } =
                    observed.recv().await.expect("ready update")
                {
                    break connection;
                }
            }
        })
        .await
        .expect("initial readiness");
        request_restart.notify_one();
        let second = tokio::time::timeout(Duration::from_secs(3), async {
            loop {
                if let ProductUpdate::Ready { connection } =
                    observed.recv().await.expect("reconnect update")
                {
                    break connection;
                }
            }
        })
        .await
        .expect("reconnected readiness");
        assert_eq!(first.generation, second.generation);
        assert!(second.epoch > first.epoch);
        controller
            .sender()
            .product_request(
                first,
                "approval.resolve",
                json!({"id": "approval-1", "decision": "approve"}),
            )
            .expect("stale command queued");
        controller.sender().product_request(second, "chat.send", json!({"sessionKey": "native-session", "message": "new request", "idempotencyKey": "new-1"})).expect("fresh command queued");
        tokio::time::timeout(Duration::from_secs(3), async {
            let mut rejected = false;
            let mut received = false;
            let mut event_received = false;
            while !(rejected && received && event_received) {
                match observed.recv().await.expect("product result") {
                    ProductUpdate::Failed {
                        connection,
                        method: "approval.resolve",
                        ..
                    } => {
                        assert_eq!(connection, first);
                        rejected = true;
                    }
                    ProductUpdate::Response {
                        connection,
                        method: "chat.send",
                        payload,
                        ..
                    } => {
                        assert_eq!(connection, second);
                        assert_eq!(payload["runId"], "new-run");
                        received = true;
                    }
                    ProductUpdate::Event {
                        connection, name, ..
                    } if name == "chat" => {
                        assert_eq!(connection, second);
                        event_received = true;
                    }
                    ProductUpdate::Failed { .. } => panic!("fresh request failed"),
                    _ => {}
                }
            }
        })
        .await
        .expect("epoch rejection and fresh delivery");
        controller.shutdown().expect("shutdown");
        gateway.shutdown().await;
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    #[cfg(windows)]
    async fn product_memory_gateway_preflights_on_the_same_epoch_and_never_falls_back_to_chat() {
        struct ProfileCleanup(claw_platform::identity::DeviceProfile);
        impl Drop for ProfileCleanup {
            fn drop(&mut self) {
                if let Ok(store) = claw_platform::identity::native_store() {
                    let _ = self.0.forget(store.as_ref());
                }
            }
        }
        for scenario in [
            "list",
            "get",
            "search",
            "save",
            "delete",
            "export",
            "import",
            "unsupported",
            "disabled",
            "model",
            "archive-missing",
            "ephemeral",
            "stale",
            "raw",
        ] {
            let submit = matches!(
                scenario,
                "list" | "get" | "search" | "save" | "delete" | "export" | "import"
            );
            let arguments = match scenario {
                "get" => json!({"action":"get","id":"Note"}),
                "search" => json!({"action":"search","query":"private query","limit":8}),
                "save" => {
                    json!({"action":"save","id":"Note","kind":"preference","content":"private note\n!goal {}","expectedRevision":0})
                }
                "delete" => json!({"action":"delete","id":"Note","expectedRevision":1}),
                "export" | "archive-missing" => json!({"action":"export","revision":0}),
                "import" => {
                    json!({"action":"import","expectedRevision":0,"overwrite":true,"archive":{"schemaVersion":1,"notebook":{"revision":0,"entries":[]}}})
                }
                _ => json!({"action":"list"}),
            };
            let message = format!(
                "!tool {}",
                json!({"name":"memory_notes","arguments":arguments})
            );
            let expected_message = message.clone();
            let calls = Arc::new(std::sync::atomic::AtomicUsize::new(0));
            let received = Arc::clone(&calls);
            let gateway = TestGateway::spawn(handler(move |mut socket, _| {
                let expected_message = expected_message.clone();
                let calls = Arc::clone(&received);
                async move {
                    send_challenge(&mut socket).await;
                    let (connect, params) = receive_connect(&mut socket).await;
                    send_hello(&mut socket, &connect, &params, 4, "native-memory-fixture", false).await;
                    let initial = receive_request(&mut socket).await;
                    assert_eq!(initial.method().as_str(), "health");
                    send_health(&mut socket, &initial).await;
                    if !matches!(scenario, "ephemeral" | "stale" | "raw") {
                        let health = receive_request(&mut socket).await;
                        assert_eq!(health.method().as_str(), "health");
                        assert_ne!(health.id(), initial.id());
                        let mut payload = json!({"ok":true,"protocol":4,"native":{"schemaVersion":1,"directTool":{"version":1,"prefix":"!tool ","modelInvoked":false,"authenticated":true,"durableRuns":true,"approvalPolicy":"per-tool","accepting":true},"explicitMemory":{"enabled":true,"accepting":true,"requiresApproval":true,"partition":"source/subject/account","automaticContextInjection":false,"archiveSchemaVersion":1}}});
                        match scenario {
                            "unsupported" => payload = json!({"ok":true,"protocol":4}),
                            "disabled" => payload["native"]["explicitMemory"]["enabled"] = json!(false),
                            "model" => payload["native"]["directTool"]["modelInvoked"] = json!(true),
                            "archive-missing" => { let _ = payload["native"]["explicitMemory"].as_object_mut().expect("memory summary").remove("archiveSchemaVersion"); }
                            _ => {}
                        }
                        send_json(&mut socket, json!({"type":"res","id":health.id().as_str(),"ok":true,"payload":payload})).await;
                    }
                    if submit {
                        let request = receive_request(&mut socket).await;
                        assert_eq!(request.method().as_str(), "chat.send");
                        let params: Value = serde_json::from_str(request.params().value().expect("send params").as_json()).expect("JSON");
                        assert_eq!(params, json!({"sessionKey":"memory-session","message":expected_message,"idempotencyKey":"original-memory-key"}));
                        calls.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                        send_json(&mut socket, json!({"type":"res","id":request.id().as_str(),"ok":true,"payload":{"status":"accepted","durable":true,"sessionId":"memory-session","runId":"a".repeat(64),"revision":1,"phase":"queued"}})).await;
                    }
                    loop {
                        match socket.read_frame().await {
                            Ok(frame) if frame.opcode == fastwebsockets::OpCode::Text => { calls.fetch_add(1, std::sync::atomic::Ordering::SeqCst); }
                            Ok(frame) if frame.opcode == fastwebsockets::OpCode::Close => break,
                            Ok(_) => {}
                            Err(_) => break,
                        }
                    }
                }
            })).await;
            let cleanup = ProfileCleanup(
                claw_platform::identity::DeviceProfile::new(
                    gateway.url.as_str(),
                    "desktop",
                    claw_platform::identity::native_lock_directory()
                        .expect("native coordination root"),
                )
                .expect("test endpoint profile"),
            );
            let (updates, mut observed) = mpsc::channel(16);
            let controller = DesktopController::spawn_product(
                |_| {},
                move |update| {
                    updates.try_send(update).expect("bounded product events");
                },
            )
            .expect("controller");
            controller
                .sender()
                .connect(request(&gateway.url).with_remembered_device(scenario != "ephemeral"))
                .expect("connect");
            let connection = tokio::time::timeout(Duration::from_secs(4), async {
                loop {
                    if let ProductUpdate::Ready { connection } =
                        observed.recv().await.expect("ready update")
                    {
                        break connection;
                    }
                }
            })
            .await
            .expect("memory readiness");
            let params = json!({"sessionKey":"memory-session","message":message,"idempotencyKey":"original-memory-key"});
            if scenario == "raw" {
                assert_eq!(
                    controller
                        .sender()
                        .product_request(connection, "chat.send", params),
                    Err(CommandRejection::DirectTool)
                );
            } else {
                let connection = if scenario == "stale" {
                    ProductConnection {
                        epoch: connection.epoch + 1,
                        ..connection
                    }
                } else {
                    connection
                };
                controller
                    .sender()
                    .memory_request(connection, params.clone())
                    .expect("typed memory enqueue");
                tokio::time::timeout(Duration::from_secs(4), async {
                    loop {
                        match observed.recv().await.expect("memory outcome") {
                            ProductUpdate::Response {
                                method: "chat.send",
                                params: returned,
                                ..
                            } => {
                                assert!(submit, "{scenario}");
                                assert_eq!(returned, params);
                                break;
                            }
                            ProductUpdate::Failed {
                                method: "chat.send",
                                params: returned,
                                definitive,
                                ..
                            } => {
                                assert!(!submit, "{scenario}");
                                assert!(definitive);
                                assert_eq!(returned, params);
                                break;
                            }
                            _ => {}
                        }
                    }
                })
                .await
                .expect("bounded memory outcome");
            }
            controller.shutdown().expect("controller shutdown");
            gateway.shutdown().await;
            assert_eq!(
                calls.load(std::sync::atomic::Ordering::SeqCst),
                usize::from(submit),
                "{scenario}"
            );
            drop(cleanup);
        }
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn product_model_catalogue_uses_real_transport_and_preserves_read_refresh_boundaries() {
        const DIGEST: &str = "5aca7507e51d7b59883eab0c7b8b449ec54d626a0c89bf39a00adfc763e1dfc3";
        for scenario in [
            "full",
            "pages",
            "unavailable",
            "bad-page",
            "refresh",
            "refresh-refused",
            "wrong-receipt",
            "availability-disabled",
            "availability-authentication_pending",
            "availability-not_initialized",
            "availability-retired",
            "availability-private-remote-error",
            "availability-refused",
            "availability-ready",
        ] {
            let availability = scenario.strip_prefix("availability-");
            let paged = scenario == "pages";
            let refresh = matches!(scenario, "refresh" | "refresh-refused" | "wrong-receipt");
            let digest = if paged {
                "a".repeat(64)
            } else {
                DIGEST.to_owned()
            };
            let calls = Arc::new(std::sync::atomic::AtomicUsize::new(0));
            let captured = Arc::clone(&calls);
            let expected_digest = digest.clone();
            let gateway = TestGateway::spawn(handler(move |mut socket, _| {
                let calls = Arc::clone(&captured);
                let digest = expected_digest.clone();
                async move {
                    send_challenge(&mut socket).await;
                    let (connect, params) = receive_connect(&mut socket).await;
                    send_hello(&mut socket, &connect, &params, 4, "models-gateway", false).await;
                    let health = receive_request(&mut socket).await;
                    send_health(&mut socket, &health).await;
                    let model = json!({"id":"fixture-model","displayName":"Fixture model","contextWindow":null,"maxOutputTokens":null,"advertisedCapabilities":["completion"]});
                    let mut page = json!({"schemaVersion":1,"available":true,"offset":0,"endOffset":if paged {8} else {1},"nextOffset":if paged {Some(8)} else {None},
                        "totalModels":if paged {9} else {1},"sha256":digest,"provider":"fixture","providerGeneration":1,"selectedModel":"fixture-model",
                        "selectionPinned":true,"observedAtMs":12345,"source":"provider_sdk_catalogue","liveCapabilitiesVerified":false,
                        "selectionChanged":false,"networkContacted":false,"models":[model.clone()]});
                    if paged {
                        let models: Vec<_> = (0..8).map(|ordinal| {
                            let mut entry = model.clone();
                            if ordinal > 0 {entry["id"] = json!(format!("fixture-model-{ordinal}"));}
                            entry
                        }).collect();
                        page["models"] = json!(models);
                    }
                    if scenario == "unavailable" {page = json!({"schemaVersion":1,"available":false,"selectionChanged":false,"networkContacted":false});}
                    if scenario == "bad-page" {page["models"][0]["displayName"] = json!("private-substituted-label");}
                    if let Some(reason) = availability.filter(|reason| *reason != "ready") {
                        page = json!({"schemaVersion":1,"available":false,"unavailableReason":reason,"selectionChanged":false,"networkContacted":false});
                    }
                    for ordinal in 0..if paged || refresh {2} else {1} {
                        let request = receive_request(&mut socket).await;
                        calls.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                        assert_eq!(request.method().as_str(), "models.list");
                        let actual: Value = serde_json::from_str(request.params().value().expect("params").as_json()).expect("request JSON");
                        if ordinal == 0 {
                            let mut expected = json!({"nativeCatalogPage":{"offset":0}});
                            if availability.is_some() {expected["nativeCatalogPage"]["includeAvailability"] = json!(true);}
                            assert_eq!(actual, expected);
                        } else if paged {
                            assert_eq!(actual, json!({"nativeCatalogPage":{"offset":8,"sha256":digest}}));
                            page["offset"] = json!(8); page["endOffset"] = json!(9); page["nextOffset"] = Value::Null;
                            let mut last = model.clone(); last["id"] = json!("fixture-model-8");
                            page["models"] = json!([last]);
                        } else {
                            assert_eq!(actual, json!({"nativeCatalogRefresh":{"sha256":digest}}));
                            page = json!({"schemaVersion":1,"refreshed":true,"provider":"fixture","providerGeneration":1,"requestedSha256":digest,
                                "selectedModel":"fixture-model","totalModels":1,"selectionChanged":false,"networkContacted":true,"inferenceInvoked":false});
                            if scenario == "wrong-receipt" {page["requestedSha256"] = json!("b".repeat(64));}
                        }
                        if ordinal == 1 && scenario == "refresh-refused" || scenario == "availability-refused" {
                            send_json(&mut socket, json!({"type":"res","id":request.id().as_str(),"ok":false,"error":{"code":"INVALID_REQUEST","message":"private-remote-error"}})).await;
                        } else {send_json(&mut socket, json!({"type":"res","id":request.id().as_str(),"ok":true,"payload":page})).await;}
                    }
                    loop {match socket.read_frame().await {
                        Ok(frame) if frame.opcode == fastwebsockets::OpCode::Text => {calls.fetch_add(1, std::sync::atomic::Ordering::SeqCst);}
                        Ok(frame) if frame.opcode == fastwebsockets::OpCode::Close => break,
                        Ok(_) => {}, Err(_) => break,
                    }}
                }
            })).await;
            let (updates, mut observed) = mpsc::channel(16);
            let controller = DesktopController::spawn_product(
                |_| {},
                move |update| {
                    updates.try_send(update).expect("bounded updates");
                },
            )
            .expect("controller");
            controller
                .sender()
                .connect(request(&gateway.url))
                .expect("connect");
            let mut state = crate::product_state::ProductState::native();
            let connection = tokio::time::timeout(Duration::from_secs(3), async {
                loop {
                    let update = observed.recv().await.expect("ready update");
                    if let ProductUpdate::Ready { connection } = update {
                        state.apply_native(ProductUpdate::Ready { connection });
                        break connection;
                    }
                    state.apply_native(update);
                }
            })
            .await
            .expect("ready deadline");
            while state.next_native_query().is_some() {}
            for action in if availability.is_some() {
                vec![3]
            } else if paged {
                vec![0, 1]
            } else if refresh {
                vec![0, 2]
            } else {
                vec![0]
            } {
                let params = state
                    .native_model_catalogue(action)
                    .expect("valid model command");
                controller
                    .sender()
                    .product_request(connection, "models.list", params.clone())
                    .expect("catalogue queued");
                state.native_model_catalogue_enqueued(&params);
                assert!(
                    state.native_model_catalogue(0).is_none(),
                    "single pending request"
                );
                tokio::time::timeout(Duration::from_secs(3), async {
                    loop {
                        let update = observed.recv().await.expect("model outcome");
                        let complete = matches!(
                            update,
                            ProductUpdate::Response {
                                method: "models.list",
                                ..
                            } | ProductUpdate::Failed {
                                method: "models.list",
                                ..
                            }
                        );
                        state.apply_native(update);
                        if complete {
                            break;
                        }
                    }
                })
                .await
                .expect("model response deadline");
                if action == 0 && scenario != "unavailable" && scenario != "bad-page" {
                    assert!(
                        state
                            .model_catalogue_text()
                            .contains("Selected: fixture-model (pinned)")
                    );
                    assert!(
                        state
                            .model_catalogue_text()
                            .contains("Context: not reported")
                    );
                }
            }
            let text = state.model_catalogue_text();
            match scenario {
                "availability-disabled" => {
                    assert!(text.contains("Provider is explicitly disabled"));
                }
                "availability-authentication_pending" => {
                    assert!(text.contains("Provider authentication is pending"));
                }
                "availability-not_initialized" => {
                    assert!(text.contains("Provider catalogue is not initialized"));
                }
                "availability-retired" => assert!(text.contains("Provider has been shut down")),
                "availability-private-remote-error" | "availability-refused" => {
                    assert!(text.contains("could not be verified"));
                }
                "pages" => assert!(
                    text.contains("fixture-model-8") && state.native_model_catalogue(1).is_none()
                ),
                "unavailable" => assert!(
                    text.contains("unavailable") && state.native_model_catalogue(2).is_none()
                ),
                "bad-page" => assert!(
                    text.contains("could not be verified") && !text.contains("substituted-label")
                ),
                "refresh" => assert!(
                    text.contains("Catalogue refreshed")
                        && !text.contains("fixture-model")
                        && state.native_model_catalogue(2).is_none()
                ),
                "refresh-refused" | "wrong-receipt" => assert!(
                    text.contains("could not be verified")
                        && text.contains("Selected: fixture-model")
                ),
                _ => assert!(text.contains("Source: provider SDK catalogue")),
            }
            assert!(!text.contains("private-remote-error"));
            assert!(state.native_model_catalogue(0).is_some());
            assert!(state.transcript().is_empty() && state.next_native_query().is_none());
            assert_eq!(
                state.selected_run().state,
                crate::product_state::RunState::Draft
            );
            controller.shutdown().expect("controller shutdown");
            gateway.shutdown().await;
            assert_eq!(
                calls.load(std::sync::atomic::Ordering::SeqCst),
                if paged || refresh { 2 } else { 1 },
                "{scenario}: no inference or ACK"
            );
        }
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn local_configuration_shutdown_waits_for_started_work_and_reports_once() {
        let (release, held) = tokio::sync::oneshot::channel();
        let (entered, started) = tokio::sync::oneshot::channel();
        let (finished, observed) = tokio::sync::oneshot::channel();
        let deliveries = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let captured = Arc::clone(&deliveries);
        let sink: ProductSink = Arc::new(move |update| {
            assert!(matches!(
                update,
                ProductUpdate::LocalConfiguration {
                    request: LocalConfigurationRequest { sequence: 9, .. },
                    ..
                }
            ));
            captured.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        });
        let mut tasks = JoinSet::new();
        tasks.spawn(async move {
            entered.send(()).expect("entered task");
            held.await.expect("explicit release");
            ProductUpdate::LocalConfiguration {
                request: LocalConfigurationRequest {
                    sequence: 9,
                    source: PathBuf::from("owned-fixture"),
                    action: LocalConfigurationAction::Inspect,
                },
                result: Err(claw_platform::configuration::ConfigurationFileError {
                    message: "synthetic completion",
                    output_may_exist: false,
                }),
            }
        });
        started.await.expect("task started");
        let mut observed = observed;
        let draining = tokio::spawn(async move {
            drain_local_configuration_tasks(&mut tasks, Some(&sink)).await;
            finished.send(()).expect("drained");
        });
        tokio::task::yield_now().await;
        assert!(matches!(
            observed.try_recv(),
            Err(tokio::sync::oneshot::error::TryRecvError::Empty)
        ));
        assert_eq!(deliveries.load(std::sync::atomic::Ordering::SeqCst), 0);
        release.send(()).expect("finish held operation");
        tokio::time::timeout(Duration::from_secs(3), observed)
            .await
            .expect("bounded drain")
            .expect("drain confirmed");
        draining.await.expect("drain joined");
        assert_eq!(deliveries.load(std::sync::atomic::Ordering::SeqCst), 1);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn local_configuration_controller_creates_candidates_without_gateway() {
        struct OwnedRoot(PathBuf);
        impl Drop for OwnedRoot {
            fn drop(&mut self) {
                let _ = std::fs::remove_dir_all(&self.0);
            }
        }
        let root = OwnedRoot(std::env::temp_dir().join(format!(
                "claw-controller-config-{}-{}",
                std::process::id(),
                std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .expect("clock")
                    .as_nanos()
            )));
        std::fs::create_dir(&root.0).expect("owned test root");
        let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("no network witness");
        listener.set_nonblocking(true).expect("nonblocking");
        let origin = format!("http://{}", listener.local_addr().expect("origin"));
        let original=json!({"schema_version":1,"core":{"role":{"source_url":format!("{origin}/role")},"channels":{"teams":{"enabled":false}},
            "auth":{},"server":{},"logging":{},"sessions":{},"copilot":{},"legacy":{},"updates":{},"admin":{},"network":{},
            "provider":{"kind":"openai","model":"before-model","api_key":"env:UNRESOLVED_LOCAL_CONFIG_KEY","base_url":format!("{origin}/v1/")}}}).to_string();
        for scenario in [
            "valid",
            "source-drift",
            "existing-target",
            "invalid-model",
            "close-after-accept",
        ] {
            let directory = root.0.join(scenario);
            std::fs::create_dir(&directory).expect("case directory");
            let source = directory.join("source.json5");
            let target = directory.join("candidate.json5");
            std::fs::write(&source, &original).expect("source");
            if scenario == "existing-target" {
                std::fs::write(&target, b"preserve-original-target").expect("existing");
            }
            let (updates, mut observed) = mpsc::channel(8);
            let controller = DesktopController::spawn_product(
                |_| {},
                move |update| {
                    assert!(updates.try_send(update).is_ok());
                },
            )
            .expect("controller");
            let inspected = LocalConfigurationRequest {
                sequence: 1,
                source: source.clone(),
                action: LocalConfigurationAction::Inspect,
            };
            controller
                .sender()
                .local_configuration(inspected.clone())
                .expect("inspect queued");
            let update = tokio::time::timeout(Duration::from_secs(3), observed.recv())
                .await
                .expect("bounded inspection")
                .expect("inspection update");
            let ProductUpdate::LocalConfiguration {
                request,
                result: Ok(LocalConfigurationResult::Inspected(configuration)),
            } = update
            else {
                panic!("expected actual local inspection")
            };
            assert_eq!(request, inspected);
            assert_eq!(
                configuration
                    .snapshot
                    .core()
                    .provider()
                    .expect("provider")
                    .model(),
                Some("before-model")
            );
            let changed = original.replace("before-model", "external-model");
            if scenario == "source-drift" {
                std::fs::write(&source, &changed).expect("owned source edit");
            }
            let request = LocalConfigurationRequest {
                sequence: 2,
                source: source.clone(),
                action: LocalConfigurationAction::PrepareModel {
                    destination: target.clone(),
                    expected_sha256: configuration.source_sha256,
                    model: if scenario == "invalid-model" {
                        "bad model"
                    } else {
                        "selected-model"
                    }
                    .to_owned(),
                },
            };
            controller
                .sender()
                .local_configuration(request.clone())
                .expect("prepare queued");
            let update = tokio::time::timeout(Duration::from_secs(3), observed.recv())
                .await
                .expect("bounded candidate")
                .expect("candidate update");
            let ProductUpdate::LocalConfiguration {
                request: returned,
                result,
            } = update
            else {
                panic!("unexpected gateway event for local task")
            };
            assert_eq!(returned, request);
            if matches!(scenario, "valid" | "close-after-accept") {
                let Ok(LocalConfigurationResult::Prepared(prepared)) = result else {
                    panic!("expected created candidate");
                };
                let reread = claw_platform::configuration::inspect_provider(&target)
                    .expect("verified candidate file");
                assert_eq!(prepared.candidate_sha256, reread.source_sha256);
                assert_eq!(
                    reread
                        .snapshot
                        .core()
                        .provider()
                        .expect("selected provider")
                        .model(),
                    Some("selected-model")
                );
                assert_eq!(
                    reread
                        .snapshot
                        .core()
                        .provider()
                        .expect("provider")
                        .api_key(),
                    configuration
                        .snapshot
                        .core()
                        .provider()
                        .expect("original provider")
                        .api_key()
                );
            } else {
                assert!(result.is_err());
                if scenario == "existing-target" {
                    assert_eq!(
                        std::fs::read(&target).expect("preserved target"),
                        b"preserve-original-target"
                    );
                } else {
                    assert!(!target.exists());
                }
            }
            assert_eq!(
                std::fs::read_to_string(&source).expect("source preserved"),
                if scenario == "source-drift" {
                    changed.as_str()
                } else {
                    original.as_str()
                }
            );
            if scenario == "close-after-accept" {
                let waiting = LocalConfigurationRequest {
                    sequence: 3,
                    source: target.clone(),
                    action: LocalConfigurationAction::Inspect,
                };
                controller
                    .sender()
                    .local_configuration(waiting.clone())
                    .expect("last inspect queued");
                let result = tokio::time::timeout(Duration::from_secs(3), observed.recv())
                    .await
                    .expect("last inspection")
                    .expect("last update");
                let ProductUpdate::LocalConfiguration {
                    request,
                    result: Ok(LocalConfigurationResult::Inspected(_)),
                } = result
                else {
                    panic!("inspection result")
                };
                assert_eq!(request, waiting);
            }
            controller.shutdown().expect("tracked local work shutdown");
            assert!(
                matches!(listener.accept(),Err(error) if error.kind()==std::io::ErrorKind::WouldBlock)
            );
        }
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn product_accounting_pages_use_real_transport_and_existing_digest_without_ack() {
        for scenario in ["valid", "corrupt", "session", "refused"] {
            let calls = Arc::new(std::sync::atomic::AtomicUsize::new(0));
            let captured = Arc::clone(&calls);
            let gateway = TestGateway::spawn(handler(move |mut socket, _| {
                let calls = Arc::clone(&captured);
                async move {
                    send_challenge(&mut socket).await;
                    let (connect, params) = receive_connect(&mut socket).await;
                    send_hello(&mut socket, &connect, &params, 4, "accounting-gateway", false).await;
                    let health = receive_request(&mut socket).await;
                    send_health(&mut socket, &health).await;
                    let tokens = json!({"inputTokens":0,"outputTokens":0,"totalTokens":0,"cachedInputTokens":0,"reasoningTokens":0});
                    let summary = json!({"available":true,"recordedRounds":1,"completeCounterRounds":1,"partialCounterRounds":0,"unreportedRounds":0,
                        "allPrimaryCountersReported":true,"observedTokens":tokens,"aggregationOverflow":false,"costCalculated":false,"billingReconciled":false,
                        "recordSource":"terminal_turn","attemptsMayBeUnsent":true});
                    let terminal = receive_request(&mut socket).await;
                    calls.fetch_add(1,std::sync::atomic::Ordering::SeqCst);
                    assert_eq!(terminal.method().as_str(),"agent.wait");
                    let params:Value = serde_json::from_str(terminal.params().value().expect("params").as_json()).expect("JSON");
                    assert_eq!(params,json!({"runId":"a".repeat(64)}));
                    send_json(&mut socket,json!({"type":"res","id":terminal.id().as_str(),"ok":true,"payload":{
                        "runId":"a".repeat(64),"sessionId":"native-session","phase":"outcome_unknown","status":"outcome_unknown","turn":0,"revision":4,"durable":true,
                        "result":{"status":"outcome_unknown","text":"retained result"},"providerAccounting":summary}})).await;
                    let page_request = receive_request(&mut socket).await;
                    calls.fetch_add(1,std::sync::atomic::Ordering::SeqCst);
                    assert_eq!(page_request.method().as_str(),"agent.wait");
                    let params:Value = serde_json::from_str(page_request.params().value().expect("params").as_json()).expect("JSON");
                    assert_eq!(params,json!({"runId":"a".repeat(64),"accountingPage":{"revision":4,"offset":0}}));
                    let mut page = json!({"runId":"a".repeat(64),"sessionId":"native-session","revision":4,"turn":0,"status":"outcome_unknown",
                        "durable":true,"acknowledged":false,"automaticReplay":false,"accounting":{"available":true,"offset":0,"endOffset":1,"nextOffset":null,"totalRounds":1,
                            "sha256":"72f1a001eed81051e5e48f6d0e7c3a08e188144fb539af4e5908f51820c571a3","summary":summary,
                            "rounds":[{"round":0,"response":{"provider":"fixture","model":"fixture-model","responseId":"response-123","usageReporting":"complete","finishReason":"stop","observedTokens":tokens}}]}});
                    if scenario == "corrupt" {page["accounting"]["rounds"][0]["response"]["model"] = json!("substituted-private-model");}
                    if scenario == "session" {page["sessionId"] = json!("another-session");}
                    if scenario == "refused" {
                        send_json(&mut socket,json!({"type":"res","id":page_request.id().as_str(),"ok":false,"error":{"code":"UNAVAILABLE","message":"fixture refusal"}})).await;
                    } else {
                        send_json(&mut socket,json!({"type":"res","id":page_request.id().as_str(),"ok":true,"payload":page})).await;
                    }
                    loop {
                        match socket.read_frame().await {
                            Ok(frame) if frame.opcode == fastwebsockets::OpCode::Text => {calls.fetch_add(1,std::sync::atomic::Ordering::SeqCst);}
                            Ok(frame) if frame.opcode == fastwebsockets::OpCode::Close => break,
                            Ok(_) => {}, Err(_) => break,
                        }
                    }
                }
            })).await;
            let (updates, mut observed) = mpsc::channel(16);
            let controller = DesktopController::spawn_product(
                |_| {},
                move |update| {
                    updates.try_send(update).expect("bounded product queue");
                },
            )
            .expect("controller");
            controller
                .sender()
                .connect(request(&gateway.url))
                .expect("connect");
            let mut state = crate::product_state::ProductState::native();
            let connection = tokio::time::timeout(Duration::from_secs(3), async {
                loop {
                    let update = observed.recv().await.expect("ready update");
                    if let ProductUpdate::Ready { connection } = update {
                        state.apply_native(ProductUpdate::Ready { connection });
                        break connection;
                    }
                    state.apply_native(update);
                }
            })
            .await
            .expect("ready deadline");
            controller
                .sender()
                .product_request(connection, "agent.wait", json!({"runId":"a".repeat(64)}))
                .expect("read terminal");
            tokio::time::timeout(Duration::from_secs(3), async {
                loop {
                    let update = observed.recv().await.expect("terminal update");
                    let finished = matches!(
                        update,
                        ProductUpdate::Response {
                            method: "agent.wait",
                            ..
                        }
                    );
                    state.apply_native(update);
                    if finished {
                        break;
                    }
                }
            })
            .await
            .expect("terminal deadline");
            while state.next_native_query().is_some() {}
            let transcript = state.transcript().to_vec();
            let params = state.native_accounting(false).expect("owned page request");
            controller
                .sender()
                .product_request(connection, "agent.wait", params.clone())
                .expect("page queued");
            state.native_accounting_enqueued(&params);
            tokio::time::timeout(Duration::from_secs(3), async {
                loop {
                    let update = observed.recv().await.expect("page update");
                    let finished = matches!(
                        update,
                        ProductUpdate::Response {
                            method: "agent.wait",
                            ..
                        } | ProductUpdate::Failed {
                            method: "agent.wait",
                            ..
                        }
                    );
                    state.apply_native(update);
                    if finished {
                        break;
                    }
                }
            })
            .await
            .expect("page deadline");
            let display = state.accounting_summary();
            assert_eq!(
                state.selected_run().state,
                crate::product_state::RunState::OutcomeUnknown
            );
            assert_eq!(state.transcript(), transcript.as_slice());
            assert!(
                state.next_native_query().is_none(),
                "no accounting ACK or replay"
            );
            assert!(
                state.native_accounting(false).is_some(),
                "explicit reread remains available"
            );
            assert!(state.native_accounting(true).is_none());
            if scenario == "valid" {
                assert!(display.contains("verified complete page"), "{display}");
                assert!(display.contains("Round 0: fixture / fixture-model"));
                assert!(display.contains("Response: response-123"));
                assert!(display.contains("Tokens (complete): 0"));
            } else {
                assert!(
                    display.contains("could not be verified"),
                    "{scenario}: {display}"
                );
                assert!(
                    !display.contains("response-123")
                        && !display.contains("substituted-private-model")
                );
            }
            controller.shutdown().expect("controller shutdown");
            gateway.shutdown().await;
            assert_eq!(
                calls.load(std::sync::atomic::Ordering::SeqCst),
                2,
                "{scenario}"
            );
        }
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn product_gateway_uses_exact_scopes_and_transports_chat_without_local_success() {
        let gateway = TestGateway::spawn(handler(|mut socket, _| async move {
            send_challenge(&mut socket).await;
            let (connect, params) = receive_connect(&mut socket).await;
            let scopes = params.scopes.as_ref().expect("requested scopes").iter()
                .map(claw_protocol::gateway::Name::as_str).collect::<std::collections::BTreeSet<_>>();
            assert_eq!(scopes, std::collections::BTreeSet::from(["operator.read", "operator.write", "operator.approvals"]));
            send_hello(&mut socket, &connect, &params, 4, "product-gateway", false).await;
            let health = receive_request(&mut socket).await;
            send_health(&mut socket, &health).await;
            let chat = receive_request(&mut socket).await;
            assert_eq!(chat.method().as_str(), "chat.send");
            let payload: Value = serde_json::from_str(chat.params().value().expect("params").as_json()).expect("JSON");
            assert_eq!(payload["message"], "native request");
            assert_eq!(payload["idempotencyKey"], "client-request-1");
            send_json(&mut socket, json!({"type": "res", "id": chat.id().as_str(), "ok": true, "payload": {"runId": "run-one", "status": "accepted", "durable": false}})).await;
            send_json(&mut socket, json!({"type": "event", "event": "chat", "seq": 1, "payload": {"runId": "run-one", "sessionId": "native-session", "status": "completed", "text": "server result"}})).await;
            wait_for_close(&mut socket).await;
        })).await;
        let (updates, mut observed) = mpsc::channel(16);
        let controller = DesktopController::spawn_product(
            |_| {},
            move |update| {
                assert!(
                    updates.try_send(update).is_ok(),
                    "bounded test update queue overflowed"
                );
            },
        )
        .expect("product controller");
        controller
            .sender()
            .connect(request(&gateway.url))
            .expect("connect");
        let connection = tokio::time::timeout(Duration::from_secs(3), async {
            loop {
                if let ProductUpdate::Ready { connection } =
                    observed.recv().await.expect("controller updates")
                {
                    break connection;
                }
            }
        })
        .await
        .expect("product readiness deadline");
        controller.sender().product_request(connection, "chat.send", json!({"sessionKey": "native-session", "message": "native request", "idempotencyKey": "client-request-1"})).expect("send queued");
        tokio::time::timeout(Duration::from_secs(3), async {
            let mut response_seen = false;
            let mut event_seen = false;
            while !(response_seen && event_seen) {
                match observed.recv().await.expect("product result") {
                    ProductUpdate::Response {
                        method: "chat.send",
                        payload,
                        ..
                    } => {
                        assert_eq!(payload["runId"], "run-one");
                        response_seen = true;
                    }
                    ProductUpdate::Event { name, payload, .. } if name == "chat" => {
                        assert_eq!(payload["text"], "server result");
                        event_seen = true;
                    }
                    ProductUpdate::Failed { .. } => panic!("product transport failed"),
                    _ => {}
                }
            }
        })
        .await
        .expect("product result deadline");
        controller.shutdown().expect("product controller shutdown");
        gateway.shutdown().await;
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
                .map(claw_protocol::gateway::Name::as_str)
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
                    gateway.url.as_str().trim_end_matches('/'),
                    "first-token".to_owned(),
                    true,
                )
                .expect("first request"),
            )
            .expect("queue first");
        let duplicate_observed = sender
            .connect_observed(
                ConnectRequest::prepare(
                    gateway.url.as_str().trim_end_matches('/'),
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
    async fn response_before_close_preserves_ready_before_later_epoch_failure() {
        let health_accepted = Arc::new(Semaphore::new(0));
        let release_ready = Arc::new(Semaphore::new(0));
        let close_epoch_a = Arc::new(Semaphore::new(0));
        let epoch_b_connected = Arc::new(Semaphore::new(0));
        let health_ids = Arc::new(Mutex::new(Vec::new()));
        let unexpected_epoch_b_health = Arc::new(AtomicUsize::new(0));
        let server_close_epoch_a = Arc::clone(&close_epoch_a);
        let server_epoch_b_connected = Arc::clone(&epoch_b_connected);
        let server_health_ids = Arc::clone(&health_ids);
        let counted_epoch_b_health = Arc::clone(&unexpected_epoch_b_health);
        let gateway = TestGateway::spawn(handler(move |mut socket, index| {
            let server_close_epoch_a = Arc::clone(&server_close_epoch_a);
            let server_epoch_b_connected = Arc::clone(&server_epoch_b_connected);
            let server_health_ids = Arc::clone(&server_health_ids);
            let counted_epoch_b_health = Arc::clone(&counted_epoch_b_health);
            async move {
                if index == 1 {
                    server_epoch_b_connected.add_permits(1);
                }
                send_challenge(&mut socket).await;
                let (connect, params) = receive_connect(&mut socket).await;
                if index == 0 {
                    send_hello(
                        &mut socket,
                        &connect,
                        &params,
                        4,
                        "desktop-response-wins",
                        false,
                    )
                    .await;
                    let health = receive_request(&mut socket).await;
                    server_health_ids
                        .lock()
                        .expect("health ids")
                        .push(health.id().as_str().to_owned());
                    send_health(&mut socket, &health).await;
                    server_close_epoch_a
                        .acquire()
                        .await
                        .expect("close gate remains open")
                        .forget();
                    socket
                        .write_frame(Frame::close(1012, b"restart after response"))
                        .await
                        .expect("close epoch A");
                    socket.flush().await.expect("flush epoch A close");
                } else {
                    send_hello_with_scopes(
                        &mut socket,
                        &connect,
                        &params,
                        4,
                        "desktop-response-wins",
                        false,
                        &["operator.admin"],
                    )
                    .await;
                    count_text_until_close(&mut socket, counted_epoch_b_health).await;
                }
            }
        }))
        .await;
        let snapshots = Arc::new(Mutex::new(Vec::new()));
        let sink = Arc::clone(&snapshots);
        let observed_health = Arc::clone(&health_accepted);
        let ready_release = Arc::clone(&release_ready);
        let controller = DesktopController::spawn_with_health_success_observer(
            move |snapshot| {
                sink.lock().expect("snapshots").push(snapshot);
            },
            move || {
                let observed_health = Arc::clone(&observed_health);
                let ready_release = Arc::clone(&ready_release);
                async move {
                    observed_health.add_permits(1);
                    ready_release
                        .acquire()
                        .await
                        .expect("Ready release semaphore remains open")
                        .forget();
                }
            },
        )
        .expect("controller");
        controller
            .sender()
            .connect(request(&gateway.url))
            .expect("connect");
        tokio::time::timeout(Duration::from_secs(2), health_accepted.acquire())
            .await
            .expect("health response must complete")
            .expect("health acceptance semaphore remains open")
            .forget();
        close_epoch_a.add_permits(1);
        tokio::time::timeout(Duration::from_secs(2), epoch_b_connected.acquire())
            .await
            .expect("epoch B must connect before Ready processing resumes")
            .expect("epoch B semaphore remains open")
            .forget();
        release_ready.add_permits(1);
        wait_snapshot(&snapshots, |snapshot| {
            snapshot.phase() == OnboardingPhase::Ready
        })
        .await;
        let failed = wait_snapshot(&snapshots, |snapshot| {
            snapshot.phase() == OnboardingPhase::Failed
        })
        .await;
        assert_eq!(
            failed.error().expect("epoch B scope error").code(),
            "gateway.protocol-scope"
        );
        assert_authenticated_summary_cleared(&failed);
        let (ready_index, failed_index, ready_count) = {
            let snapshots = snapshots.lock().expect("snapshots");
            (
                snapshots
                    .iter()
                    .position(|snapshot| snapshot.phase() == OnboardingPhase::Ready),
                snapshots
                    .iter()
                    .position(|snapshot| snapshot.phase() == OnboardingPhase::Failed),
                snapshots
                    .iter()
                    .filter(|snapshot| snapshot.phase() == OnboardingPhase::Ready)
                    .count(),
            )
        };
        let ready_index = ready_index.expect("response A must produce Ready");
        let failed_index = failed_index.expect("epoch B must fail closed");
        assert!(ready_index < failed_index);
        assert_eq!(ready_count, 1);
        assert_eq!(
            health_ids.lock().expect("health ids").as_slice(),
            &["desktop-health-1-epoch-1"]
        );
        assert_eq!(unexpected_epoch_b_health.load(Ordering::SeqCst), 0);
        controller.shutdown().expect("shutdown");
        gateway.shutdown().await;
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn close_before_health_response_never_publishes_ready() {
        let gateway = TestGateway::spawn(handler(|mut socket, _| async move {
            send_challenge(&mut socket).await;
            let (connect, params) = receive_connect(&mut socket).await;
            send_hello(
                &mut socket,
                &connect,
                &params,
                4,
                "desktop-close-wins",
                false,
            )
            .await;
            let _health = receive_request(&mut socket).await;
            socket
                .write_frame(Frame::close(1000, b"close before response"))
                .await
                .expect("close before health");
            socket.flush().await.expect("flush close");
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
            failed.error().expect("close error").code(),
            "gateway.transport-closed"
        );
        assert_authenticated_summary_cleared(&failed);
        assert_eq!(
            snapshots
                .lock()
                .expect("snapshots")
                .iter()
                .filter(|snapshot| snapshot.phase() == OnboardingPhase::Ready)
                .count(),
            0
        );
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
    async fn health_payload_requires_canonical_ok_true() {
        for payload in [
            serde_json::json!({}),
            serde_json::json!({"ok": false}),
            serde_json::json!({"ok": "true"}),
        ] {
            let gateway = TestGateway::spawn(handler(move |mut socket, _| {
                let payload = payload.clone();
                async move {
                    send_challenge(&mut socket).await;
                    let (connect, params) = receive_connect(&mut socket).await;
                    send_hello(
                        &mut socket,
                        &connect,
                        &params,
                        4,
                        "desktop-invalid-health-payload",
                        false,
                    )
                    .await;
                    let health = receive_request(&mut socket).await;
                    send_health_payload(&mut socket, &health, payload).await;
                    wait_for_close(&mut socket).await;
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
            assert_authenticated_summary_cleared(&failed);
            controller.shutdown().expect("shutdown");
            gateway.shutdown().await;
        }
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
            move |_| {
                let observed = event_observer.lock().expect("event observer").take();
                if let Some(observed) = observed {
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
    async fn health_probe_drains_sequenced_event_burst_before_ready() {
        const EVENT_COUNT: u64 = 32;

        let event_acks = Arc::new(Semaphore::new(0));
        let server_acks = Arc::clone(&event_acks);
        let health_ids = Arc::new(Mutex::new(Vec::new()));
        let server_health_ids = Arc::clone(&health_ids);
        let gateway = TestGateway::spawn(handler(move |mut socket, _| {
            let server_acks = Arc::clone(&server_acks);
            let server_health_ids = Arc::clone(&server_health_ids);
            async move {
                send_challenge(&mut socket).await;
                let (connect, params) = receive_connect(&mut socket).await;
                send_hello(
                    &mut socket,
                    &connect,
                    &params,
                    4,
                    "desktop-event-burst",
                    false,
                )
                .await;
                let health = receive_request(&mut socket).await;
                server_health_ids
                    .lock()
                    .expect("health ids")
                    .push(health.id().as_str().to_owned());
                for sequence in 1..=EVENT_COUNT {
                    send_json(
                        &mut socket,
                        serde_json::json!({
                            "type": "event",
                            "event": "tick",
                            "payload": {"ts": 1_700_000_000_100_u64 + sequence},
                            "seq": sequence
                        }),
                    )
                    .await;
                    tokio::time::timeout(Duration::from_secs(2), server_acks.acquire())
                        .await
                        .expect("desktop must drain events while health is pending")
                        .expect("event acknowledgement semaphore remains open")
                        .forget();
                }
                send_health(&mut socket, &health).await;
                wait_for_close(&mut socket).await;
            }
        }))
        .await;
        let snapshots = Arc::new(Mutex::new(Vec::new()));
        let sink = Arc::clone(&snapshots);
        let observed_sequences = Arc::new(Mutex::new(Vec::new()));
        let recorded_sequences = Arc::clone(&observed_sequences);
        let observer_acks = Arc::clone(&event_acks);
        let controller = DesktopController::spawn_with_event_observer(
            move |snapshot| {
                sink.lock().expect("snapshots").push(snapshot);
            },
            move |event| {
                let sequence = event
                    .frame()
                    .sequence()
                    .expect("test sends sequenced broadcasts")
                    .get();
                recorded_sequences
                    .lock()
                    .expect("event sequences")
                    .push(sequence);
                observer_acks.add_permits(1);
            },
        )
        .expect("controller");
        controller
            .sender()
            .connect(request(&gateway.url))
            .expect("connect");
        let ready = wait_snapshot(&snapshots, |snapshot| {
            snapshot.phase() == OnboardingPhase::Ready
        })
        .await;
        assert_eq!(ready.health(), "Healthy - safe RPC completed");
        assert_eq!(
            observed_sequences
                .lock()
                .expect("event sequences")
                .as_slice(),
            &(1..=EVENT_COUNT).collect::<Vec<_>>()
        );
        assert_eq!(
            health_ids.lock().expect("health ids").as_slice(),
            &["desktop-health-1-epoch-1"]
        );
        let (ready_count, any_failed) = {
            let snapshots = snapshots.lock().expect("snapshots");
            (
                snapshots
                    .iter()
                    .filter(|snapshot| snapshot.phase() == OnboardingPhase::Ready)
                    .count(),
                snapshots
                    .iter()
                    .any(|snapshot| snapshot.phase() == OnboardingPhase::Failed),
            )
        };
        assert_eq!(ready_count, 1);
        assert!(!any_failed);
        controller.shutdown().expect("shutdown");
        gateway.shutdown().await;
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
        assert!(ids[0].contains("-epoch-1"));
        assert!(ids[1].contains("-epoch-2"));
        assert!(gateway.connections.load(Ordering::SeqCst) >= 2);
        assert_eq!(
            snapshots
                .lock()
                .expect("snapshots")
                .iter()
                .filter(|snapshot| snapshot.phase() == OnboardingPhase::Ready)
                .count(),
            1
        );
        controller.shutdown().expect("shutdown");
        gateway.shutdown().await;
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn epoch_gate_blocks_stale_health_and_invalid_reused_id_gets_no_health() {
        let runtime = EpochGateRuntime::new();
        let handler_runtime = Arc::clone(&runtime);
        let invalid_health = Arc::new(AtomicUsize::new(0));
        let counted_invalid_health = Arc::clone(&invalid_health);
        let gateway = TestGateway::spawn(handler(move |mut socket, index| {
            let runtime = Arc::clone(&handler_runtime);
            let counted_invalid_health = Arc::clone(&counted_invalid_health);
            async move {
                send_challenge(&mut socket).await;
                let (connect, params) = receive_connect(&mut socket).await;
                if index == 0 {
                    send_hello(
                        &mut socket,
                        &connect,
                        &params,
                        4,
                        "desktop-reused-connection-id",
                        false,
                    )
                    .await;
                    runtime.wait_until_blocked().await;
                    socket
                        .write_frame(Frame::close(1012, b"transient restart"))
                        .await
                        .expect("close epoch A");
                    socket.flush().await.expect("flush epoch A close");
                    runtime.unblock();
                } else {
                    send_hello_with_scopes(
                        &mut socket,
                        &connect,
                        &params,
                        4,
                        "desktop-reused-connection-id",
                        false,
                        &["operator.admin"],
                    )
                    .await;
                    count_text_until_close(&mut socket, counted_invalid_health).await;
                }
            }
        }))
        .await;
        let (controller, snapshots) = controller_with_runtime(runtime);
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
        assert_eq!(invalid_health.load(Ordering::SeqCst), 0);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn epoch_gate_allows_one_fresh_health_before_reused_id_becomes_ready() {
        let runtime = EpochGateRuntime::new();
        let handler_runtime = Arc::clone(&runtime);
        let health_ids = Arc::new(Mutex::new(Vec::new()));
        let captured_health_ids = Arc::clone(&health_ids);
        let gateway = TestGateway::spawn(handler(move |mut socket, index| {
            let runtime = Arc::clone(&handler_runtime);
            let captured_health_ids = Arc::clone(&captured_health_ids);
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
                if index == 0 {
                    runtime.wait_until_blocked().await;
                    socket
                        .write_frame(Frame::close(1012, b"transient restart"))
                        .await
                        .expect("close epoch A");
                    socket.flush().await.expect("flush epoch A close");
                    runtime.unblock();
                } else {
                    let health = receive_request(&mut socket).await;
                    captured_health_ids
                        .lock()
                        .expect("health ids")
                        .push(health.id().as_str().to_owned());
                    send_health(&mut socket, &health).await;
                    wait_for_close(&mut socket).await;
                }
            }
        }))
        .await;
        let (controller, snapshots) = controller_with_runtime(runtime);
        controller
            .sender()
            .connect(request(&gateway.url))
            .expect("connect");
        let ready = wait_snapshot(&snapshots, |snapshot| {
            snapshot.phase() == OnboardingPhase::Ready
        })
        .await;
        assert_eq!(ready.health(), "Healthy - safe RPC completed");
        let ids = health_ids.lock().expect("health ids").clone();
        assert_eq!(ids.len(), 1);
        assert!(ids[0].contains("-epoch-2"));
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
        let settled_after_cancel = {
            let all = snapshots.lock().expect("snapshots");
            all[count_after_cancel..]
                .iter()
                .all(|snapshot| snapshot.phase() == OnboardingPhase::Disconnected)
        };
        assert!(settled_after_cancel);
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

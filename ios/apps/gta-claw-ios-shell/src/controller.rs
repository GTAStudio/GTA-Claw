//! Bounded background ownership of one iOS Gateway connection.

use std::fmt::{self, Display, Formatter};
use std::sync::{Arc, Mutex, PoisonError};

use claw_gateway_client::{ConnectionState, GatewayClient, GatewayClientConfig};
use claw_security::authorization::Scope;
use claw_security::identity::DeviceIdentity;
use getrandom::SysRng;
use gta_claw_ios::{
    AppRunState, ConnectionAttempt, CredentialKey, GatewayEndpoint, IosAction, IosClientIdentity,
    IosCredential, IosGatewayProfile, IosNetworkPath, IosSessionModel, IosStatusKind,
    IosViewSnapshot, ObservedAuthorization, PersistedCredentialKind, TransportDirective,
    UnobservedDeviceProbe, delete_host_credential, load_host_credential, save_host_credential,
};
use tokio::runtime::Runtime;
use tokio::sync::mpsc;
use tokio::task::JoinHandle;
use tokio_util::sync::CancellationToken;

use crate::host::HostBoundaries;

const COMMAND_QUEUE_CAPACITY: usize = 4;

pub(crate) type SnapshotSink = Arc<dyn Fn(UiUpdate) + Send + Sync>;
type WorkerSender = mpsc::UnboundedSender<(u64, WorkerUpdate)>;

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) enum UiUpdate {
    Core(Arc<IosViewSnapshot>),
    Shell(Box<UiSnapshot>),
    FormError(String),
}

impl UiUpdate {
    fn shell(snapshot: UiSnapshot) -> Self {
        Self::Shell(Box::new(snapshot))
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum Tone {
    Neutral,
    Progress,
    Success,
    Warning,
    Danger,
}

#[derive(Clone, Debug, Eq, PartialEq)]
#[expect(
    clippy::struct_excessive_bools,
    reason = "these are independent Slint control bindings: an attempt can be busy and cancellable, a ready connection is disconnectable, and errors are orthogonal"
)]
pub(crate) struct UiSnapshot {
    pub(crate) title: String,
    pub(crate) detail: String,
    pub(crate) status_label: String,
    pub(crate) tone: Tone,
    pub(crate) endpoint: String,
    pub(crate) server: String,
    pub(crate) protocol: String,
    pub(crate) authorization: String,
    pub(crate) available_actions: String,
    pub(crate) revision: String,
    pub(crate) run_state: String,
    pub(crate) network_path: String,
    pub(crate) should_resume: bool,
    pub(crate) busy: bool,
    pub(crate) can_connect: bool,
    pub(crate) can_cancel: bool,
    pub(crate) can_disconnect: bool,
    pub(crate) has_error: bool,
    pub(crate) error_action: String,
}

impl UiSnapshot {
    pub(crate) fn initial() -> Self {
        Self {
            title: "Not connected".to_owned(),
            detail: "Enter a Gateway address to begin.".to_owned(),
            status_label: "Idle".to_owned(),
            tone: Tone::Neutral,
            endpoint: "No Gateway selected".to_owned(),
            server: "-".to_owned(),
            protocol: "-".to_owned(),
            authorization: "Nothing confirmed".to_owned(),
            available_actions: "No actions confirmed".to_owned(),
            revision: "0".to_owned(),
            run_state: "inactive".to_owned(),
            network_path: "checking network".to_owned(),
            should_resume: false,
            busy: false,
            can_connect: true,
            can_cancel: false,
            can_disconnect: false,
            has_error: false,
            error_action: String::new(),
        }
    }

    fn disconnected(endpoint: String) -> Self {
        Self {
            endpoint,
            title: "Disconnected".to_owned(),
            detail: "The connection was closed.".to_owned(),
            status_label: "Stopped".to_owned(),
            ..Self::initial()
        }
    }

    fn failure(title: impl Into<String>, detail: impl Into<String>, action: &str) -> Self {
        Self {
            title: title.into(),
            detail: detail.into(),
            status_label: "Needs attention".to_owned(),
            tone: Tone::Danger,
            has_error: true,
            error_action: action.to_owned(),
            ..Self::initial()
        }
    }

    fn fatal(title: impl Into<String>, detail: impl Into<String>, action: &str) -> Self {
        Self {
            can_connect: false,
            can_cancel: false,
            can_disconnect: false,
            ..Self::failure(title, detail, action)
        }
    }

    pub(crate) fn from_core(snapshot: &IosViewSnapshot) -> Self {
        let tone = match snapshot.status() {
            IosStatusKind::Neutral => Tone::Neutral,
            IosStatusKind::Progress => Tone::Progress,
            IosStatusKind::Ready => Tone::Success,
            IosStatusKind::Warning => Tone::Warning,
            IosStatusKind::Failed => Tone::Danger,
        };
        let status_label = match snapshot.status() {
            IosStatusKind::Neutral => "Idle",
            IosStatusKind::Progress => "Working",
            IosStatusKind::Ready => "Connected",
            IosStatusKind::Warning => "Degraded",
            IosStatusKind::Failed => "Failed",
        };
        let authorization = snapshot.authorization().map_or_else(
            || "Nothing confirmed".to_owned(),
            ObservedAuthorization::summary,
        );
        let actions = IosAction::ALL
            .into_iter()
            .filter(|action| snapshot.permits(*action))
            .map(IosAction::label)
            .collect::<Vec<_>>();
        Self {
            title: snapshot.title().to_owned(),
            detail: snapshot.detail().to_owned(),
            status_label: status_label.to_owned(),
            tone,
            endpoint: snapshot.endpoint().to_string(),
            server: snapshot.server_version().unwrap_or("-").to_owned(),
            protocol: snapshot
                .protocol()
                .map_or_else(|| "-".to_owned(), |value| format!("v{}", value.get())),
            authorization,
            available_actions: if actions.is_empty() {
                "No actions confirmed".to_owned()
            } else {
                actions.join(", ")
            },
            revision: snapshot.revision().to_string(),
            run_state: snapshot.run_state().label().to_owned(),
            network_path: snapshot.network_path().label().to_owned(),
            should_resume: snapshot.should_resume(),
            busy: snapshot.busy(),
            can_connect: snapshot.can_connect(),
            can_cancel: snapshot.can_cancel(),
            can_disconnect: snapshot.can_disconnect(),
            has_error: snapshot.status() == IosStatusKind::Failed,
            error_action: if snapshot.status() == IosStatusKind::Failed {
                "Check the address and credential, then try again.".to_owned()
            } else {
                String::new()
            },
        }
    }
}

enum Command {
    Connect { endpoint: String, token: String },
    Disconnect,
    RunState(AppRunState),
    NetworkPath(IosNetworkPath),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum CommandError {
    QueueFull,
    Stopped,
}

impl Display for CommandError {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::QueueFull => "The app is still handling the previous action.",
            Self::Stopped => "The connection service has stopped. Restart the app.",
        })
    }
}

impl std::error::Error for CommandError {}

#[derive(Clone, Debug)]
pub(crate) struct ControllerHandle {
    sender: mpsc::Sender<Command>,
}

impl ControllerHandle {
    pub(crate) fn connect(&self, endpoint: String, token: String) -> Result<(), CommandError> {
        self.send(Command::Connect { endpoint, token })
    }

    pub(crate) fn disconnect(&self) -> Result<(), CommandError> {
        self.send(Command::Disconnect)
    }

    pub(crate) fn set_run_state(&self, state: AppRunState) -> Result<(), CommandError> {
        self.send(Command::RunState(state))
    }

    pub(crate) fn set_network_path(&self, path: IosNetworkPath) -> Result<(), CommandError> {
        self.send(Command::NetworkPath(path))
    }

    fn send(&self, command: Command) -> Result<(), CommandError> {
        self.sender.try_send(command).map_err(|error| match error {
            mpsc::error::TrySendError::Full(_) => CommandError::QueueFull,
            mpsc::error::TrySendError::Closed(_) => CommandError::Stopped,
        })
    }
}

#[derive(Debug)]
pub(crate) struct IosController {
    handle: ControllerHandle,
    _runtime: Runtime,
}

impl IosController {
    pub(crate) fn start(
        sink: SnapshotSink,
        host: Arc<HostBoundaries>,
    ) -> Result<Self, std::io::Error> {
        let runtime = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(2)
            .enable_all()
            .thread_name("gta-claw-ios-gateway")
            .build()?;
        let (commands_tx, commands_rx) = mpsc::channel(COMMAND_QUEUE_CAPACITY);
        runtime.spawn(run(commands_rx, sink, host));
        Ok(Self {
            handle: ControllerHandle {
                sender: commands_tx,
            },
            _runtime: runtime,
        })
    }

    pub(crate) fn handle(&self) -> ControllerHandle {
        self.handle.clone()
    }
}

struct PreparedConnection {
    config: GatewayClientConfig,
    intent: ConnectionIntent,
}

struct ConnectionIntent {
    endpoint: GatewayEndpoint,
    credential_key: CredentialKey,
    has_token: bool,
    model: IosSessionModel,
    published_revision: Arc<Mutex<Option<u64>>>,
}

#[derive(Debug)]
struct PreparationError {
    title: String,
    detail: String,
    action: &'static str,
}

impl PreparationError {
    fn new(title: impl Into<String>, detail: impl Into<String>, action: &'static str) -> Self {
        Self {
            title: title.into(),
            detail: detail.into(),
            action,
        }
    }

    fn into_snapshot(self) -> UiSnapshot {
        UiSnapshot::failure(self.title, self.detail, self.action)
    }
}

fn prepare_connection(
    endpoint: &str,
    token: &str,
    session_identity: &mut Option<Arc<DeviceIdentity>>,
    host: &HostBoundaries,
) -> Result<PreparedConnection, PreparationError> {
    let endpoint = GatewayEndpoint::parse(endpoint).map_err(|error| {
        PreparationError::new(
            "Check the Gateway address",
            error.to_string(),
            "Use a wss:// address without credentials, query text, or a fragment.",
        )
    })?;
    let credential = if token.trim().is_empty() {
        IosCredential::none()
    } else {
        IosCredential::token(token).map_err(|error| {
            PreparationError::new(
                "Check the credential",
                error.to_string(),
                "Use a bounded token without control characters.",
            )
        })?
    };
    let credential_key = CredentialKey::parse("gta-claw-manual-gateway").map_err(|error| {
        PreparationError::new(
            "Credential host key is invalid",
            error.to_string(),
            "Restart the app; the bounded shell credential key is not usable.",
        )
    })?;
    let has_token = credential.kind() == gta_claw_ios::IosCredentialKind::Token;
    let identity = IosClientIdentity::observe(&UnobservedDeviceProbe).map_err(|error| {
        PreparationError::new(
            "Device identity unavailable",
            error.to_string(),
            "Restart the app. This build will not substitute guessed device metadata.",
        )
    })?;
    let device = if let Some(device) = session_identity.as_ref() {
        Arc::clone(device)
    } else {
        let generated = DeviceIdentity::try_generate(&mut SysRng).map_err(|error| {
            PreparationError::new(
                "Secure randomness unavailable",
                error.to_string(),
                "Restart the app. A connection cannot start without a fresh signing identity.",
            )
        })?;
        Arc::clone(session_identity.insert(Arc::new(generated)))
    };
    if has_token {
        save_host_credential(host.credentials(), &credential_key, &credential).map_err(
            |error| {
                PreparationError::new(
                    "Credential host facility failed",
                    error.to_string(),
                    "Retry without persistence or attach a working Keychain adapter.",
                )
            },
        )?;
    } else {
        delete_host_credential(
            host.credentials(),
            &credential_key,
            PersistedCredentialKind::Token,
        )
        .unwrap_or_else(|never| match never {});
    }
    let profile = IosGatewayProfile::new(endpoint.clone(), credential, identity, device)
        .requesting([Scope::OperatorRead]);
    let model = profile.session_model();
    let config = profile.into_client_config();
    Ok(PreparedConnection {
        config,
        intent: ConnectionIntent {
            endpoint,
            credential_key,
            has_token,
            model,
            published_revision: Arc::new(Mutex::new(None)),
        },
    })
}

fn resume_config(
    intent: &ConnectionIntent,
    session_identity: Option<&Arc<DeviceIdentity>>,
    host: &HostBoundaries,
) -> Result<GatewayClientConfig, PreparationError> {
    let credential = if intent.has_token {
        load_host_credential(
            host.credentials(),
            &intent.credential_key,
            PersistedCredentialKind::Token,
        )
        .map_err(|error| {
            PreparationError::new(
                "Credential host facility failed",
                error.to_string(),
                "Unlock or repair the host credential facility, then retry.",
            )
        })?
        .ok_or_else(|| {
            PreparationError::new(
                "Session credential is unavailable",
                "The process-local credential host no longer contains the retained token.",
                "Enter the token again.",
            )
        })?
    } else {
        IosCredential::none()
    };
    let identity = IosClientIdentity::observe(&UnobservedDeviceProbe).map_err(|error| {
        PreparationError::new(
            "Device identity unavailable",
            error.to_string(),
            "Restart the app. This build will not substitute guessed device metadata.",
        )
    })?;
    let device = session_identity.cloned().ok_or_else(|| {
        PreparationError::new(
            "Session identity is unavailable",
            "The controller lost its process identity before transport resume.",
            "Restart the app and connect again.",
        )
    })?;
    Ok(
        IosGatewayProfile::new(intent.endpoint.clone(), credential, identity, device)
            .requesting([Scope::OperatorRead])
            .into_client_config(),
    )
}

fn changed_snapshot(intent: &ConnectionIntent) -> Option<Arc<IosViewSnapshot>> {
    changed_model_snapshot(&intent.model, &intent.published_revision)
}

fn changed_model_snapshot(
    model: &IosSessionModel,
    published_revision: &Arc<Mutex<Option<u64>>>,
) -> Option<Arc<IosViewSnapshot>> {
    let mut published = published_revision
        .lock()
        .unwrap_or_else(PoisonError::into_inner);
    let snapshot = published.map_or_else(
        || Some(model.snapshot()),
        |known| model.snapshot_if_changed(known),
    )?;
    *published = Some(snapshot.revision());
    drop(published);
    Some(snapshot)
}

struct ActiveConnection {
    generation: u64,
    attempt_id: u64,
    cancellation: CancellationToken,
    task: JoinHandle<WorkerResult>,
}

type WorkerResult = Result<(), WorkerFailure>;

struct WorkerFailure {
    snapshot: Box<UiSnapshot>,
    poisons_controller: bool,
}

impl WorkerFailure {
    fn recoverable(snapshot: UiSnapshot) -> Self {
        Self {
            snapshot: Box::new(snapshot),
            poisons_controller: false,
        }
    }

    fn poisoned(snapshot: UiSnapshot) -> Self {
        Self {
            snapshot: Box::new(snapshot),
            poisons_controller: true,
        }
    }
}

enum WorkerUpdate {
    Changed,
    Finished,
}

async fn run(mut commands: mpsc::Receiver<Command>, sink: SnapshotSink, host: Arc<HostBoundaries>) {
    let (updates_tx, mut updates_rx) = mpsc::unbounded_channel::<(u64, WorkerUpdate)>();
    let mut active: Option<ActiveConnection> = None;
    let mut intent: Option<ConnectionIntent> = None;
    let mut session_identity: Option<Arc<DeviceIdentity>> = None;
    let mut run_state = AppRunState::Inactive;
    let mut network_path = IosNetworkPath::Unknown;
    let mut poisoned = false;
    let mut next_worker_generation = 0_u64;
    sink(UiUpdate::shell(UiSnapshot::initial()));

    loop {
        tokio::select! {
            command = commands.recv() => {
                let Some(command) = command else { break };
                match command {
                    Command::Connect { endpoint, token } => {
                        if poisoned {
                            sink(UiUpdate::shell(UiSnapshot::fatal(
                                "Connection service requires restart",
                                "A previous transport did not stop cleanly.",
                                "Restart the app before connecting again.",
                            )));
                            continue;
                        }
                        if active.is_some() {
                            sink(UiUpdate::FormError(
                                "A connection is already active. Disconnect it before starting another."
                                    .to_owned(),
                            ));
                            continue;
                        }
                        if let Some(previous) = intent.take() {
                            clear_retained_credential(&previous, &host);
                        }
                        let prepared = match prepare_connection(
                            &endpoint,
                            &token,
                            &mut session_identity,
                            &host,
                        ) {
                            Ok(prepared) => prepared,
                            Err(error) => {
                                sink(UiUpdate::shell(error.into_snapshot()));
                                continue;
                            }
                        };
                        let session = prepared.intent;
                        let _directive = session.model.set_run_state(run_state);
                        let _directive = session.model.set_network_path(network_path);
                        if let Some(snapshot) = changed_snapshot(&session) {
                            sink(UiUpdate::Core(snapshot));
                        }
                        match start_transport(
                            prepared.config,
                            &session,
                            allocate_worker_generation(&mut next_worker_generation),
                            &updates_tx,
                            &sink,
                        ) {
                            Ok(connection) => {
                                active = Some(connection);
                                intent = Some(session);
                            }
                            Err(error) => {
                                sink(UiUpdate::Shell(error));
                                clear_retained_credential(&session, &host);
                            }
                        }
                    }
                    Command::Disconnect => {
                        if poisoned {
                            if let Some(session) = intent.take() {
                                clear_retained_credential(&session, &host);
                            }
                            continue;
                        }
                        if let Some(session) = intent.as_ref() {
                            let directive = session.model.request_disconnect();
                            process_directive(
                                directive,
                                session,
                                &mut active,
                                &mut poisoned,
                                DirectiveContext {
                                    session_identity: session_identity.as_ref(),
                                    host: &host,
                                    updates: &updates_tx,
                                    sink: &sink,
                                    next_worker_generation: &mut next_worker_generation,
                                },
                            )
                            .await;
                            clear_retained_credential(session, &host);
                            if !poisoned
                                && let Some(snapshot) = changed_snapshot(session)
                            {
                                sink(UiUpdate::Core(snapshot));
                            }
                            intent = None;
                        } else {
                            sink(UiUpdate::shell(UiSnapshot::disconnected(
                                "No Gateway selected".to_owned(),
                            )));
                        }
                    }
                    Command::RunState(state) => {
                        run_state = state;
                        if poisoned {
                            continue;
                        }
                        if let Some(session) = intent.as_ref() {
                            let directive = session.model.set_run_state(state);
                            if let Some(snapshot) = changed_snapshot(session) {
                                sink(UiUpdate::Core(snapshot));
                            }
                            process_directive(
                                directive,
                                session,
                                &mut active,
                                &mut poisoned,
                                DirectiveContext {
                                    session_identity: session_identity.as_ref(),
                                    host: &host,
                                    updates: &updates_tx,
                                    sink: &sink,
                                    next_worker_generation: &mut next_worker_generation,
                                },
                            )
                            .await;
                        }
                    }
                    Command::NetworkPath(path) => {
                        network_path = path;
                        if poisoned {
                            continue;
                        }
                        if let Some(session) = intent.as_ref() {
                            let directive = session.model.set_network_path(path);
                            if let Some(snapshot) = changed_snapshot(session) {
                                sink(UiUpdate::Core(snapshot));
                            }
                            process_directive(
                                directive,
                                session,
                                &mut active,
                                &mut poisoned,
                                DirectiveContext {
                                    session_identity: session_identity.as_ref(),
                                    host: &host,
                                    updates: &updates_tx,
                                    sink: &sink,
                                    next_worker_generation: &mut next_worker_generation,
                                },
                            )
                            .await;
                        }
                    }
                }
            }
            update = updates_rx.recv() => {
                let Some((generation, update)) = update else { break };
                if active.as_ref().map(|connection| connection.generation) != Some(generation) {
                    continue;
                }
                let finished = matches!(update, WorkerUpdate::Finished)
                    || active.as_ref().is_some_and(|connection| connection.task.is_finished());
                let mut publish_core = true;
                if finished {
                    let result = match active.take() {
                        Some(connection) => join_connection(connection).await,
                        None => Ok(()),
                    };
                    if let Err(failure) = result {
                        poisoned |= failure.poisons_controller;
                        sink(UiUpdate::Shell(failure.snapshot));
                        publish_core = false;
                    }
                }
                if publish_core
                    && let Some(session) = intent.as_ref()
                    && let Some(snapshot) = changed_snapshot(session)
                {
                    sink(UiUpdate::Core(snapshot));
                }
            }
        }
    }

    if let Err(failure) = stop_connection(active.take()).await {
        sink(UiUpdate::Shell(failure.snapshot));
    }
}

fn start_transport(
    config: GatewayClientConfig,
    intent: &ConnectionIntent,
    generation: u64,
    updates: &WorkerSender,
    sink: &SnapshotSink,
) -> Result<ActiveConnection, Box<UiSnapshot>> {
    let attempt = intent.model.begin_attempt().map_err(|error| {
        Box::new(UiSnapshot::failure(
            "Connection unavailable",
            error.to_string(),
            "The host lifecycle and network-path preconditions must be satisfied before retrying.",
        ))
    })?;
    let attempt_id = attempt.id();
    if let Some(snapshot) = changed_snapshot(intent) {
        sink(UiUpdate::Core(snapshot));
    }
    let cancellation = CancellationToken::new();
    let task = tokio::spawn(run_connection(
        generation,
        config,
        attempt,
        cancellation.clone(),
        updates.clone(),
    ));
    Ok(ActiveConnection {
        generation,
        attempt_id,
        cancellation,
        task,
    })
}

struct DirectiveContext<'a> {
    session_identity: Option<&'a Arc<DeviceIdentity>>,
    host: &'a HostBoundaries,
    updates: &'a WorkerSender,
    sink: &'a SnapshotSink,
    next_worker_generation: &'a mut u64,
}

async fn process_directive(
    mut directive: TransportDirective,
    intent: &ConnectionIntent,
    active: &mut Option<ActiveConnection>,
    poisoned: &mut bool,
    context: DirectiveContext<'_>,
) {
    loop {
        match directive {
            TransportDirective::None => return,
            TransportDirective::Stop { attempt_id, .. } => {
                if active.as_ref().map(|connection| connection.attempt_id) == Some(attempt_id)
                    && let Err(failure) = stop_connection(active.take()).await
                {
                    *poisoned |= failure.poisons_controller;
                    if failure.poisons_controller {
                        let _directive = intent.model.request_disconnect();
                        (context.sink)(UiUpdate::Shell(failure.snapshot));
                        return;
                    }
                    (context.sink)(UiUpdate::Shell(failure.snapshot));
                }
                if let Some(snapshot) = changed_snapshot(intent) {
                    (context.sink)(UiUpdate::Core(snapshot));
                }
                directive = intent.model.reconcile();
            }
            TransportDirective::Resume { .. } => {
                if active.is_none() && !*poisoned {
                    match resume_config(intent, context.session_identity, context.host) {
                        Ok(config) => {
                            match start_transport(
                                config,
                                intent,
                                allocate_worker_generation(context.next_worker_generation),
                                context.updates,
                                context.sink,
                            ) {
                                Ok(connection) => *active = Some(connection),
                                Err(snapshot) => (context.sink)(UiUpdate::Shell(snapshot)),
                            }
                        }
                        Err(error) => (context.sink)(UiUpdate::shell(error.into_snapshot())),
                    }
                }
                return;
            }
        }
    }
}

const fn allocate_worker_generation(next: &mut u64) -> u64 {
    *next = next.wrapping_add(1);
    *next
}

fn clear_retained_credential(intent: &ConnectionIntent, host: &HostBoundaries) {
    if intent.has_token {
        delete_host_credential(
            host.credentials(),
            &intent.credential_key,
            PersistedCredentialKind::Token,
        )
        .unwrap_or_else(|never| match never {});
    }
}

async fn stop_connection(connection: Option<ActiveConnection>) -> Result<(), WorkerFailure> {
    let Some(connection) = connection else {
        return Ok(());
    };
    connection.cancellation.cancel();
    join_connection(connection).await
}

async fn join_connection(connection: ActiveConnection) -> Result<(), WorkerFailure> {
    match connection.task.await {
        Ok(Ok(())) => Ok(()),
        Ok(Err(failure)) => Err(failure),
        Err(error) => Err(WorkerFailure::poisoned(UiSnapshot::fatal(
            "Connection task did not stop",
            error.to_string(),
            "Restart the app before starting another connection.",
        ))),
    }
}

const fn terminal(state: &ConnectionState) -> bool {
    matches!(
        state,
        ConnectionState::ResyncRequired(_)
            | ConnectionState::AuthenticationFailed(_)
            | ConnectionState::ProtocolFailed { .. }
            | ConnectionState::ReconnectExhausted
            | ConnectionState::Stopped
    )
}

async fn run_connection(
    generation: u64,
    config: GatewayClientConfig,
    attempt: ConnectionAttempt,
    cancellation: CancellationToken,
    updates: WorkerSender,
) -> WorkerResult {
    let (client, mut events) = match GatewayClient::start(config) {
        Ok(started) => started,
        Err(error) => {
            drop(attempt);
            let _ = updates.send((generation, WorkerUpdate::Finished));
            return Err(WorkerFailure::recoverable(UiSnapshot::failure(
                "Connection could not start",
                error.to_string(),
                "Check the address and restart the app if the service is unavailable.",
            )));
        }
    };
    let mut attempt = Some(attempt);
    let mut states = client.subscribe_state();
    let mut device_tokens_drained = false;

    let _observation = attempt
        .as_ref()
        .expect("the connection attempt is held until transport shutdown")
        .observe(client.state());
    let _ = updates.send((generation, WorkerUpdate::Changed));

    loop {
        let state = tokio::select! {
            biased;
            () = cancellation.cancelled() => {
                let _ = updates.send((generation, WorkerUpdate::Finished));
                match client.shutdown().await {
                    Ok(()) => {
                        if let Some(attempt) = attempt.as_ref() {
                            let _observation = attempt.observe(ConnectionState::Stopped);
                        }
                        drop(attempt.take());
                        return Ok(());
                    }
                    Err(error) => {
                        return Err(shutdown_failure(error));
                    }
                }
            }
            changed = states.changed() => {
                if changed.is_err() {
                    let snapshot = UiSnapshot::failure(
                        "Connection state stream closed",
                        "The Gateway service stopped without a final lifecycle state.",
                        "Reconnect. If this repeats, restart the app.",
                    );
                    let _ = updates.send((generation, WorkerUpdate::Finished));
                    client.shutdown().await.map_err(shutdown_failure)?;
                    return Err(WorkerFailure::recoverable(snapshot));
                }
                states.borrow_and_update().clone()
            }
            event = events.recv() => {
                if event.is_none() {
                    let snapshot = UiSnapshot::failure(
                        "Gateway event stream closed",
                        "The bounded event stream ended before the connection stopped.",
                        "Reconnect. No event was silently discarded.",
                    );
                    let _ = updates.send((generation, WorkerUpdate::Finished));
                    client.shutdown().await.map_err(shutdown_failure)?;
                    return Err(WorkerFailure::recoverable(snapshot));
                }
                continue;
            }
        };

        let _observation = attempt
            .as_ref()
            .expect("the connection attempt is held until a terminal state")
            .observe(state.clone());
        if matches!(state, ConnectionState::Ready(_)) && !device_tokens_drained {
            drop(client.take_issued_device_tokens().await);
            device_tokens_drained = true;
        }
        let terminal = terminal(&state);
        if terminal {
            drop(attempt.take());
        }
        if terminal {
            let _ = updates.send((generation, WorkerUpdate::Finished));
            if let Err(error) = client.shutdown().await {
                return Err(shutdown_failure(error));
            }
            return Ok(());
        }
        let _ = updates.send((generation, WorkerUpdate::Changed));
    }
}

fn shutdown_failure(error: impl Display) -> WorkerFailure {
    WorkerFailure::poisoned(UiSnapshot::fatal(
        "Disconnect did not finish",
        error.to_string(),
        "The bounded shutdown failed; restart the app before reconnecting.",
    ))
}

#[cfg(test)]
mod tests {
    use std::sync::{Arc, Mutex, PoisonError};

    use claw_gateway_client::{ConnectionState, GatewayCredential};
    use gta_claw_ios::{
        AppRunState, GatewayEndpoint, IosNetworkInterface, IosNetworkPath, IosNetworkRoute,
        IosSessionModel, TransportDirective, TransportResumeReason,
    };
    use tokio::sync::mpsc;
    use tokio_util::sync::CancellationToken;

    use crate::host::HostBoundaries;

    use super::{
        ActiveConnection, DirectiveContext, SnapshotSink, Tone, UiSnapshot, UiUpdate,
        WorkerFailure, allocate_worker_generation, changed_snapshot, prepare_connection,
        process_directive, resume_config,
    };

    #[test]
    fn initial_snapshot_is_actionable_and_not_busy() {
        let snapshot = UiSnapshot::initial();
        assert!(snapshot.can_connect);
        assert!(!snapshot.busy);
        assert_eq!(snapshot.tone, Tone::Neutral);
    }

    #[test]
    fn worker_generations_do_not_reuse_model_local_attempt_ids() {
        let mut generation = 0;
        assert_eq!(allocate_worker_generation(&mut generation), 1);
        assert_eq!(allocate_worker_generation(&mut generation), 2);
    }

    #[test]
    fn credential_bearing_endpoint_is_not_echoed_back() {
        let secret = "never-render-this";
        let host = HostBoundaries::new();
        let Err(error) = prepare_connection(
            &format!("wss://gateway.example?token={secret}"),
            "",
            &mut None,
            &host,
        ) else {
            panic!("credential-bearing URL must fail");
        };
        assert!(!error.detail.contains(secret));
        assert!(error.into_snapshot().has_error);
    }

    #[test]
    fn reconnects_reuse_one_process_identity() {
        let mut identity = None;
        let host = HostBoundaries::new();
        let first = prepare_connection("ws://127.0.0.1:1", "", &mut identity, &host)
            .expect("loopback profile is valid");
        let first_id = first.config.identity.device_id();
        let second = prepare_connection("ws://127.0.0.1:1", "", &mut identity, &host)
            .expect("second loopback profile is valid");

        assert_eq!(second.config.identity.device_id(), first_id);
    }

    #[test]
    fn resume_reloads_the_token_through_the_host_store() {
        let mut identity = None;
        let host = HostBoundaries::new();
        let prepared =
            prepare_connection("ws://127.0.0.1:1", "session-token", &mut identity, &host)
                .expect("loopback profile is valid");
        let resumed = resume_config(&prepared.intent, identity.as_ref(), &host)
            .expect("host credential reload succeeds");

        assert!(matches!(resumed.credential, GatewayCredential::Token(_)));
    }

    #[test]
    fn core_progress_snapshot_enables_cancel_only() {
        let endpoint = GatewayEndpoint::parse("wss://gateway.example").expect("valid endpoint");
        let model = IosSessionModel::new(&endpoint);
        let _directive = model.set_run_state(AppRunState::Foreground);
        let _directive = model.set_network_path(IosNetworkPath::Satisfied(IosNetworkRoute::new(
            1,
            IosNetworkInterface::Other,
        )));
        let attempt = model.begin_attempt().expect("first attempt starts");
        let _observation = attempt.observe(ConnectionState::Connecting);
        let snapshot = UiSnapshot::from_core(&model.snapshot());

        assert!(snapshot.busy);
        assert!(snapshot.can_cancel);
        assert!(!snapshot.can_connect);
        assert!(!snapshot.can_disconnect);
        assert_eq!(snapshot.tone, Tone::Progress);
    }

    #[test]
    fn terminal_snapshot_enables_reconnect_after_attempt_release() {
        let endpoint = GatewayEndpoint::parse("wss://gateway.example").expect("valid endpoint");
        let model = IosSessionModel::new(&endpoint);
        let _directive = model.set_run_state(AppRunState::Foreground);
        let _directive = model.set_network_path(IosNetworkPath::Satisfied(IosNetworkRoute::new(
            1,
            IosNetworkInterface::Other,
        )));
        let attempt = model.begin_attempt().expect("first attempt starts");
        let _observation = attempt.observe(ConnectionState::ReconnectExhausted);
        assert!(!model.snapshot().can_connect());

        drop(attempt);
        assert!(model.snapshot().can_connect());
    }

    #[test]
    fn snapshot_publication_uses_core_revisions() {
        let host = HostBoundaries::new();
        let prepared = prepare_connection("ws://127.0.0.1:1", "", &mut None, &host)
            .expect("loopback profile is valid");

        let first = changed_snapshot(&prepared.intent).expect("first snapshot is published");
        assert!(changed_snapshot(&prepared.intent).is_none());
        let _directive = prepared.intent.model.set_run_state(AppRunState::Foreground);
        let second = changed_snapshot(&prepared.intent).expect("changed snapshot is published");
        assert_ne!(first.revision(), second.revision());
        assert_eq!(
            prepared.intent.model.snapshot().revision(),
            second.revision()
        );
    }

    #[test]
    fn stopped_attempt_is_dropped_before_resume_reconciliation() {
        let endpoint = GatewayEndpoint::parse("wss://gateway.example").expect("valid endpoint");
        let model = IosSessionModel::new(&endpoint);
        let _directive = model.set_run_state(AppRunState::Foreground);
        let _directive = model.set_network_path(IosNetworkPath::Satisfied(IosNetworkRoute::new(
            1,
            IosNetworkInterface::Other,
        )));
        let attempt = model.begin_attempt().expect("attempt starts");
        let attempt_id = attempt.id();
        let _observation = attempt.observe(ConnectionState::Connecting);

        assert!(matches!(
            model.set_run_state(AppRunState::Background),
            TransportDirective::Stop {
                attempt_id: stopped,
                ..
            } if stopped == attempt_id
        ));
        assert_eq!(
            model.set_run_state(AppRunState::Foreground),
            TransportDirective::None,
            "resume stays blocked while the stopped guard is still held"
        );
        drop(attempt);
        assert_eq!(
            model.reconcile(),
            TransportDirective::Resume {
                reason: TransportResumeReason::ReturnedToForeground
            }
        );
    }

    #[tokio::test]
    async fn shutdown_failure_clears_resume_instead_of_overlapping_transports() {
        let host = Arc::new(HostBoundaries::new());
        let mut identity = None;
        let prepared =
            prepare_connection("ws://127.0.0.1:1", "session-token", &mut identity, &host)
                .expect("loopback profile is valid");
        let _directive = prepared.intent.model.set_run_state(AppRunState::Foreground);
        let _directive = prepared
            .intent
            .model
            .set_network_path(IosNetworkPath::Satisfied(IosNetworkRoute::new(
                1,
                IosNetworkInterface::Other,
            )));
        let attempt = prepared
            .intent
            .model
            .begin_attempt()
            .expect("attempt starts");
        let attempt_id = attempt.id();
        let _observation = attempt.observe(ConnectionState::Connecting);
        let stop = prepared.intent.model.set_run_state(AppRunState::Background);
        let cancellation = CancellationToken::new();
        let task = tokio::spawn(async move {
            drop(attempt);
            Err(WorkerFailure::poisoned(UiSnapshot::fatal(
                "Disconnect did not finish",
                "fixture timeout",
                "Restart the app.",
            )))
        });
        let mut active = Some(ActiveConnection {
            generation: 1,
            attempt_id,
            cancellation,
            task,
        });
        let (updates_tx, _updates_rx) = mpsc::unbounded_channel();
        let delivered = Arc::new(Mutex::new(Vec::new()));
        let delivered_for_sink = Arc::clone(&delivered);
        let sink: SnapshotSink = Arc::new(move |update| {
            delivered_for_sink
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .push(update);
        });
        let mut poisoned = false;
        let mut next_worker_generation = 1;

        process_directive(
            stop,
            &prepared.intent,
            &mut active,
            &mut poisoned,
            DirectiveContext {
                session_identity: identity.as_ref(),
                host: &host,
                updates: &updates_tx,
                sink: &sink,
                next_worker_generation: &mut next_worker_generation,
            },
        )
        .await;

        assert!(active.is_none());
        assert!(poisoned);
        assert_eq!(
            prepared.intent.model.set_run_state(AppRunState::Foreground),
            TransportDirective::None
        );
        assert_eq!(prepared.intent.model.reconcile(), TransportDirective::None);
        assert!(
            delivered
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .iter()
                .any(|update| matches!(update, UiUpdate::Shell(snapshot) if !snapshot.can_connect))
        );
    }
}

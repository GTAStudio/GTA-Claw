//! Bounded background ownership of one iOS Gateway connection.

use std::fmt::{self, Display, Formatter};
use std::sync::Arc;
use std::time::Duration;

use claw_gateway_client::{
    ClientLimits, ClientTimeouts, ConnectionState, GatewayClient, GatewayClientConfig,
    ReconnectPolicy,
};
use claw_security::authorization::Scope;
use claw_security::identity::DeviceIdentity;
use getrandom::SysRng;
use gta_claw_ios::{
    ConnectionAttempt, GatewayEndpoint, IosAction, IosClientIdentity, IosCredential,
    IosGatewayProfile, IosSessionModel, IosStatusKind, IosViewSnapshot, ObservedAuthorization,
    UnobservedDeviceProbe,
};
use tokio::runtime::Runtime;
use tokio::sync::mpsc;
use tokio::task::JoinHandle;
use tokio_util::sync::CancellationToken;

const COMMAND_QUEUE_CAPACITY: usize = 4;
const UPDATE_QUEUE_CAPACITY: usize = 24;

pub(crate) type SnapshotSink = Arc<dyn Fn(UiSnapshot) + Send + Sync>;

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

    fn from_core(snapshot: &IosViewSnapshot) -> Self {
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
    pub(crate) fn start(sink: SnapshotSink) -> Result<Self, std::io::Error> {
        let runtime = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(2)
            .enable_all()
            .thread_name("gta-claw-ios-gateway")
            .build()?;
        let (commands_tx, commands_rx) = mpsc::channel(COMMAND_QUEUE_CAPACITY);
        runtime.spawn(run(commands_rx, sink));
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
    model: IosSessionModel,
    endpoint: String,
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
    let profile = IosGatewayProfile::new(endpoint, credential, identity, device)
        .requesting([Scope::OperatorRead]);
    let model = profile.session_model();
    let endpoint = profile.endpoint_summary().to_string();
    let mut config = profile.into_client_config();
    config.limits = ClientLimits {
        max_in_flight_requests: 4,
        command_queue_capacity: 8,
        outbound_queue_bytes: 32 * 1024,
        event_queue_capacity: 16,
        event_queue_bytes: 64 * 1024,
        completed_id_capacity: 32,
    };
    config.timeouts = ClientTimeouts {
        connect: Duration::from_secs(15),
        authentication: Duration::from_secs(15),
        request: Duration::from_secs(20),
        shutdown: Duration::from_secs(3),
    };
    config.reconnect = ReconnectPolicy::Bounded {
        max_attempts: 4,
        initial_delay: Duration::from_millis(500),
        max_delay: Duration::from_secs(8),
        max_jitter: Duration::from_millis(250),
    };
    Ok(PreparedConnection {
        config,
        model,
        endpoint,
    })
}

struct ActiveConnection {
    endpoint: String,
    cancellation: CancellationToken,
    task: JoinHandle<()>,
}

enum WorkerUpdate {
    Snapshot(UiSnapshot),
    Finished(UiSnapshot),
}

async fn run(mut commands: mpsc::Receiver<Command>, sink: SnapshotSink) {
    let (updates_tx, mut updates_rx) = mpsc::channel::<(u64, WorkerUpdate)>(UPDATE_QUEUE_CAPACITY);
    let mut generation = 0_u64;
    let mut active: Option<ActiveConnection> = None;
    let mut session_identity: Option<Arc<DeviceIdentity>> = None;
    sink(UiSnapshot::initial());

    loop {
        tokio::select! {
            command = commands.recv() => {
                let Some(command) = command else { break };
                match command {
                    Command::Connect { endpoint, token } => {
                        if active.is_some() {
                            sink(UiSnapshot::failure(
                                "Connection already active",
                                "Stop the current connection before starting another.",
                                "Use Cancel or Disconnect, then try again.",
                            ));
                            continue;
                        }
                        generation = generation.wrapping_add(1);
                        let prepared =
                            match prepare_connection(&endpoint, &token, &mut session_identity) {
                            Ok(prepared) => prepared,
                            Err(error) => {
                                sink(error.into_snapshot());
                                continue;
                            }
                            };
                        let attempt = match prepared.model.begin_attempt() {
                            Ok(attempt) => attempt,
                            Err(error) => {
                                sink(UiSnapshot::failure(
                                    "Connection already starting",
                                    error.to_string(),
                                    "Wait for the current attempt to finish.",
                                ));
                                continue;
                            }
                        };
                        sink(UiSnapshot::from_core(&prepared.model.snapshot()));
                        let cancellation = CancellationToken::new();
                        let task = tokio::spawn(run_connection(
                            generation,
                            prepared.config,
                            prepared.model,
                            attempt,
                            cancellation.clone(),
                            updates_tx.clone(),
                        ));
                        active = Some(ActiveConnection {
                            endpoint: prepared.endpoint,
                            cancellation,
                            task,
                        });
                    }
                    Command::Disconnect => {
                        let endpoint = active
                            .as_ref()
                            .map_or_else(|| "No Gateway selected".to_owned(), |value| value.endpoint.clone());
                        stop_connection(active.take()).await;
                        generation = generation.wrapping_add(1);
                        sink(UiSnapshot::disconnected(endpoint));
                    }
                }
            }
            update = updates_rx.recv() => {
                let Some((update_generation, update)) = update else { break };
                if update_generation != generation {
                    continue;
                }
                match update {
                    WorkerUpdate::Snapshot(snapshot) => sink(snapshot),
                    WorkerUpdate::Finished(snapshot) => {
                        if let Some(connection) = active.take()
                            && let Err(error) = connection.task.await
                        {
                            eprintln!("iOS Gateway worker join failed: {error}");
                        }
                        sink(snapshot);
                    }
                }
            }
        }
    }

    stop_connection(active.take()).await;
}

async fn stop_connection(connection: Option<ActiveConnection>) {
    let Some(connection) = connection else {
        return;
    };
    connection.cancellation.cancel();
    if let Err(error) = connection.task.await {
        eprintln!("iOS Gateway worker join failed during shutdown: {error}");
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
    model: IosSessionModel,
    attempt: ConnectionAttempt,
    cancellation: CancellationToken,
    updates: mpsc::Sender<(u64, WorkerUpdate)>,
) {
    let (client, mut events) = match GatewayClient::start(config) {
        Ok(started) => started,
        Err(error) => {
            drop(attempt);
            let _ = updates
                .send((
                    generation,
                    WorkerUpdate::Finished(UiSnapshot::failure(
                        "Connection could not start",
                        error.to_string(),
                        "Check the address and restart the app if the service is unavailable.",
                    )),
                ))
                .await;
            return;
        }
    };
    let mut attempt = Some(attempt);
    let mut states = client.subscribe_state();
    let mut device_tokens_drained = false;

    model.observe(client.state());
    if updates
        .send((
            generation,
            WorkerUpdate::Snapshot(UiSnapshot::from_core(&model.snapshot())),
        ))
        .await
        .is_err()
    {
        let _ = client.shutdown().await;
        return;
    }

    loop {
        let state = tokio::select! {
            biased;
            () = cancellation.cancelled() => {
                match client.shutdown().await {
                    Ok(()) => {
                        model.observe(ConnectionState::Stopped);
                        drop(attempt.take());
                        let _ = updates.send((
                            generation,
                            WorkerUpdate::Finished(UiSnapshot::from_core(&model.snapshot())),
                        )).await;
                    }
                    Err(error) => {
                        let _ = updates.send((
                            generation,
                            WorkerUpdate::Finished(UiSnapshot::failure(
                                "Disconnect did not finish",
                                error.to_string(),
                                "The bounded shutdown timed out; restart the app before reconnecting.",
                            )),
                        )).await;
                    }
                }
                return;
            }
            changed = states.changed() => {
                if changed.is_err() {
                    let snapshot = UiSnapshot::failure(
                        "Connection state stream closed",
                        "The Gateway service stopped without a final lifecycle state.",
                        "Reconnect. If this repeats, restart the app.",
                    );
                    let _ = updates.send((generation, WorkerUpdate::Finished(snapshot))).await;
                    let _ = client.shutdown().await;
                    return;
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
                    let _ = updates.send((generation, WorkerUpdate::Finished(snapshot))).await;
                    let _ = client.shutdown().await;
                    return;
                }
                continue;
            }
        };

        model.observe(state.clone());
        if matches!(state, ConnectionState::Ready(_)) {
            drop(attempt.take());
            if !device_tokens_drained {
                drop(client.take_issued_device_tokens().await);
                device_tokens_drained = true;
            }
        }
        let snapshot = UiSnapshot::from_core(&model.snapshot());
        if terminal(&state) {
            drop(attempt.take());
            let _ = updates
                .send((generation, WorkerUpdate::Finished(snapshot)))
                .await;
            if let Err(error) = client.shutdown().await {
                eprintln!("iOS Gateway terminal shutdown failed: {error}");
            }
            return;
        }
        if updates
            .send((generation, WorkerUpdate::Snapshot(snapshot)))
            .await
            .is_err()
        {
            let _ = client.shutdown().await;
            return;
        }
    }
}

#[cfg(test)]
mod tests {
    use claw_gateway_client::ConnectionState;
    use gta_claw_ios::{GatewayEndpoint, IosSessionModel};

    use super::{Tone, UiSnapshot, prepare_connection};

    #[test]
    fn initial_snapshot_is_actionable_and_not_busy() {
        let snapshot = UiSnapshot::initial();
        assert!(snapshot.can_connect);
        assert!(!snapshot.busy);
        assert_eq!(snapshot.tone, Tone::Neutral);
    }

    #[test]
    fn credential_bearing_endpoint_is_not_echoed_back() {
        let secret = "never-render-this";
        let Err(error) = prepare_connection(
            &format!("wss://gateway.example?token={secret}"),
            "",
            &mut None,
        ) else {
            panic!("credential-bearing URL must fail");
        };
        assert!(!error.detail.contains(secret));
        assert!(error.into_snapshot().has_error);
    }

    #[test]
    fn reconnects_reuse_one_process_identity() {
        let mut identity = None;
        let first = prepare_connection("ws://127.0.0.1:1", "", &mut identity)
            .expect("loopback profile is valid");
        let first_id = first.config.identity.device_id();
        let second = prepare_connection("ws://127.0.0.1:1", "", &mut identity)
            .expect("second loopback profile is valid");

        assert_eq!(second.config.identity.device_id(), first_id);
    }

    #[test]
    fn core_progress_snapshot_enables_cancel_only() {
        let endpoint = GatewayEndpoint::parse("wss://gateway.example").expect("valid endpoint");
        let model = IosSessionModel::new(&endpoint);
        let _attempt = model.begin_attempt().expect("first attempt starts");
        model.observe(ConnectionState::Connecting);
        let snapshot = UiSnapshot::from_core(&model.snapshot());

        assert!(snapshot.busy);
        assert!(snapshot.can_cancel);
        assert!(!snapshot.can_connect);
        assert!(!snapshot.can_disconnect);
        assert_eq!(snapshot.tone, Tone::Progress);
    }
}

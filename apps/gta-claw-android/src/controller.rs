//! Tokio-side Gateway ownership, kept free of Slint and of Android APIs.
//!
//! The UI thread only ever sends commands and receives rendered snapshots, so
//! this whole module compiles and is exercised on the development host.

use std::error::Error;
use std::fmt::{self, Debug, Display, Formatter};
use std::sync::{Arc, Mutex, PoisonError};
use std::time::Duration;

use claw_application::{Application, SystemProbe};
use claw_gateway_client::{GatewayClient, GatewayEventStream};
use claw_platform::NativeSystemProbe;
use claw_protocol::ServerEvent;
use claw_security::identity::DeviceIdentity;
use tokio::runtime::Runtime;
use tokio::sync::{mpsc, watch};
use tokio::task::JoinHandle;
use tokio_util::sync::CancellationToken;

use crate::onboarding::{
    AttemptUpdate, ConnectRequest, DiagnosticCode, RemedyKind, SubmissionRejection, UserError,
    ViewModel, ViewSnapshot,
};
use crate::platform::{
    AppLifecycle, ConnectionBlocker, DiscoveryReadiness, IdentityPersistence, NetworkStatus,
    PlatformCapabilities, PlatformFacilities, PortablePlatformFacilities, connection_blocker,
};
use crate::session::{AttemptSlot, SHUTDOWN_TIMEOUT, build_client_config_for_attempt};

/// Bounded command queue depth between the UI thread and the Gateway task.
const COMMAND_QUEUE_CAPACITY: usize = 8;

/// Bounded update queue depth between one attempt and the controller loop.
const UPDATE_QUEUE_CAPACITY: usize = 8;

/// Hard ceiling for joining an attempt after cancellation.
const ATTEMPT_JOIN_TIMEOUT: Duration =
    Duration::from_secs(SHUTDOWN_TIMEOUT.as_secs().saturating_add(2));

/// Hard ceiling for acknowledged terminal lifecycle shutdown.
const CONTROLLER_SHUTDOWN_TIMEOUT: Duration =
    Duration::from_secs(SHUTDOWN_TIMEOUT.as_secs().saturating_add(3));

/// Final ceiling for terminating runtime tasks after a failed controller join.
const RUNTIME_SHUTDOWN_TIMEOUT: Duration = Duration::from_secs(1);

/// Receives every rendered snapshot. Implementations must not block.
pub type SnapshotSink = Arc<dyn Fn(ViewSnapshot) + Send + Sync>;

/// A command the UI thread asks the Gateway task to perform.
enum ControllerCommand {
    Connect(ConnectRequest),
    Reject(SubmissionRejection),
    Disconnect,
    Retry,
    NetworkChanged(NetworkStatus),
    DiscoveryReadinessChanged(DiscoveryReadiness),
}

impl Debug for ControllerCommand {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        match self {
            Self::Connect(request) => formatter.debug_tuple("Connect").field(request).finish(),
            Self::Reject(rejection) => formatter.debug_tuple("Reject").field(rejection).finish(),
            Self::Disconnect => formatter.write_str("Disconnect"),
            Self::Retry => formatter.write_str("Retry"),
            Self::NetworkChanged(network) => formatter
                .debug_tuple("NetworkChanged")
                .field(network)
                .finish(),
            Self::DiscoveryReadinessChanged(readiness) => formatter
                .debug_tuple("DiscoveryReadinessChanged")
                .field(readiness)
                .finish(),
        }
    }
}

/// A lifecycle transition reported by the Android activity.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ActivityLifecycleEvent {
    /// The activity started or resumed.
    Foreground,
    /// The activity paused.
    Paused,
    /// The activity stopped.
    Stopped,
    /// The activity was destroyed and cannot resume.
    Destroyed,
}

impl ActivityLifecycleEvent {
    const fn app_lifecycle(self) -> AppLifecycle {
        match self {
            Self::Foreground => AppLifecycle::Foreground,
            Self::Paused | Self::Stopped | Self::Destroyed => AppLifecycle::Background,
        }
    }
}

#[derive(Debug)]
struct LifecycleSender {
    current: Mutex<ActivityLifecycleEvent>,
    events: mpsc::UnboundedSender<ActivityLifecycleEvent>,
    shutdown_completed: watch::Receiver<bool>,
}

impl LifecycleSender {
    fn new(
        events: mpsc::UnboundedSender<ActivityLifecycleEvent>,
        shutdown_completed: watch::Receiver<bool>,
    ) -> Self {
        Self {
            current: Mutex::new(ActivityLifecycleEvent::Foreground),
            events,
            shutdown_completed,
        }
    }
}

/// Proof that the controller processed terminal destruction and finished cleanup.
#[derive(Debug)]
pub struct DestroyAcknowledgement {
    completed: watch::Receiver<bool>,
}

impl DestroyAcknowledgement {
    async fn wait(mut self) -> Result<(), ControllerShutdownError> {
        while !*self.completed.borrow_and_update() {
            self.completed
                .changed()
                .await
                .map_err(|_| ControllerShutdownError::AcknowledgementDropped)?;
        }
        Ok(())
    }
}

/// A command that could not be queued.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CommandRejection {
    /// The Gateway task already has the maximum number of queued commands.
    QueueFull,
    /// The Gateway task has stopped.
    Stopped,
}

impl CommandRejection {
    /// Returns the operator-facing form.
    #[must_use]
    pub fn user_error(self) -> UserError {
        match self {
            Self::QueueFull => UserError::diagnostic(
                DiagnosticCode::ControllerBusy,
                RemedyKind::Wait,
                "The app is still handling the previous action.",
                "Wait a moment, then try again.",
            ),
            Self::Stopped => UserError::diagnostic(
                DiagnosticCode::ControllerStopped,
                RemedyKind::RestartApp,
                "The connection service has stopped.",
                "Restart the app.",
            ),
        }
    }
}

impl Display for CommandRejection {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::QueueFull => "controller command queue is full",
            Self::Stopped => "controller has stopped",
        })
    }
}

impl Error for CommandRejection {}

/// A terminal Android controller shutdown failure.
#[derive(Debug)]
pub enum ControllerShutdownError {
    /// The control loop did not acknowledge and finish within its hard ceiling.
    Timeout,
    /// The control loop ended without acknowledging destruction.
    AcknowledgementDropped,
    /// The control loop task panicked or was cancelled.
    Task(tokio::task::JoinError),
}

impl Display for ControllerShutdownError {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        match self {
            Self::Timeout => formatter.write_str("Android controller shutdown timed out"),
            Self::AcknowledgementDropped => {
                formatter.write_str("Android controller dropped destruction acknowledgement")
            }
            Self::Task(error) => write!(formatter, "Android controller task failed: {error}"),
        }
    }
}

impl Error for ControllerShutdownError {}

/// A cloneable, non-blocking handle usable from a native shell event loop.
#[derive(Clone, Debug)]
pub struct ControllerHandle {
    commands: mpsc::Sender<ControllerCommand>,
    lifecycle: Arc<LifecycleSender>,
}

impl ControllerHandle {
    /// Queues a validated connection request.
    ///
    /// # Errors
    ///
    /// Returns [`CommandRejection::QueueFull`] when the Gateway task already
    /// has `COMMAND_QUEUE_CAPACITY` commands waiting, and
    /// [`CommandRejection::Stopped`] when the control loop has ended and the
    /// command channel is closed. Nothing is ever blocked on or dropped
    /// silently: this is called from the UI thread, which must not wait.
    pub fn connect(&self, request: ConnectRequest) -> Result<(), CommandRejection> {
        self.send(ControllerCommand::Connect(request))
    }

    /// Queues a rejected submission so the failure is rendered on the same path.
    ///
    /// # Errors
    ///
    /// Returns [`CommandRejection::QueueFull`] when the Gateway task already
    /// has `COMMAND_QUEUE_CAPACITY` commands waiting, and
    /// [`CommandRejection::Stopped`] when the control loop has ended and the
    /// command channel is closed.
    pub fn reject(&self, rejection: SubmissionRejection) -> Result<(), CommandRejection> {
        self.send(ControllerCommand::Reject(rejection))
    }

    /// Queues a disconnect.
    ///
    /// # Errors
    ///
    /// Returns [`CommandRejection::QueueFull`] when the Gateway task already
    /// has `COMMAND_QUEUE_CAPACITY` commands waiting, and
    /// [`CommandRejection::Stopped`] when the control loop has ended and the
    /// command channel is closed. A `Stopped` disconnect needs no retry: the
    /// loop cancels and joins any live attempt as it ends.
    pub fn disconnect(&self) -> Result<(), CommandRejection> {
        self.send(ControllerCommand::Disconnect)
    }

    /// Retries the retained request without asking the operator to re-enter it.
    ///
    /// This is a no-op when there is no retained failed request. If the app is
    /// backgrounded or offline, the intent remains queued until its blocker
    /// clears.
    ///
    /// # Errors
    ///
    /// Returns [`CommandRejection`] when the command cannot be queued.
    pub fn retry(&self) -> Result<(), CommandRejection> {
        self.send(ControllerCommand::Retry)
    }

    /// Reports that the Android activity entered the foreground.
    ///
    /// # Errors
    ///
    /// Returns [`CommandRejection`] when the command cannot be queued.
    pub fn app_foregrounded(&self) -> Result<(), CommandRejection> {
        self.lifecycle_changed(ActivityLifecycleEvent::Foreground)
    }

    /// Reports that the Android activity paused.
    ///
    /// A live socket is cancelled and its request is retained for foreground
    /// resume, avoiding radio and retry work while the activity is suspended.
    ///
    /// # Errors
    ///
    /// Returns [`CommandRejection`] when the command cannot be queued.
    pub fn app_paused(&self) -> Result<(), CommandRejection> {
        self.lifecycle_changed(ActivityLifecycleEvent::Paused)
    }

    /// Reports that the Android activity stopped.
    ///
    /// # Errors
    ///
    /// Returns [`CommandRejection`] when the controller has stopped.
    pub fn app_stopped(&self) -> Result<(), CommandRejection> {
        self.lifecycle_changed(ActivityLifecycleEvent::Stopped)
    }

    /// Reports that the Android activity was destroyed.
    ///
    /// Destruction is terminal and cannot be replaced by a later lifecycle
    /// callback. Delivery is independent of the bounded command queue.
    ///
    /// # Errors
    ///
    /// Returns [`CommandRejection`] when the controller has stopped.
    pub fn app_destroyed(&self) -> Result<DestroyAcknowledgement, CommandRejection> {
        self.send_lifecycle(ActivityLifecycleEvent::Destroyed)?;
        Ok(DestroyAcknowledgement {
            completed: self.lifecycle.shutdown_completed.clone(),
        })
    }

    /// Reports that the Android activity left the foreground.
    ///
    /// Prefer [`Self::app_paused`] or [`Self::app_stopped`] when the native
    /// callback is known.
    ///
    /// # Errors
    ///
    /// Returns [`CommandRejection`] when the controller has stopped.
    pub fn app_backgrounded(&self) -> Result<(), CommandRejection> {
        self.app_paused()
    }

    /// Reports an exact Android activity lifecycle transition.
    ///
    /// Duplicate transitions are coalesced, pause and stop retain their order,
    /// and destruction is terminal. This non-blocking path is independent of
    /// the normal bounded command queue.
    ///
    /// # Errors
    ///
    /// Returns [`CommandRejection::Stopped`] when the controller has stopped.
    pub fn lifecycle_changed(&self, event: ActivityLifecycleEvent) -> Result<(), CommandRejection> {
        self.send_lifecycle(event)
    }

    /// Reports the latest Android default-network status.
    ///
    /// Duplicate reports are coalesced. A changed usable network restarts the
    /// socket immediately, while an unavailable network suspends it without
    /// spending reconnect attempts. Android Internet validation is reported for
    /// diagnostics but does not block an isolated local Gateway.
    ///
    /// # Errors
    ///
    /// Returns [`CommandRejection`] when the command cannot be queued.
    pub fn network_changed(&self, status: NetworkStatus) -> Result<(), CommandRejection> {
        self.send(ControllerCommand::NetworkChanged(status))
    }

    /// Reports a changed discovery precondition from the platform adapter.
    ///
    /// # Errors
    ///
    /// Returns [`CommandRejection`] when the command cannot be queued.
    pub fn discovery_readiness_changed(
        &self,
        readiness: DiscoveryReadiness,
    ) -> Result<(), CommandRejection> {
        self.send(ControllerCommand::DiscoveryReadinessChanged(readiness))
    }

    fn send(&self, command: ControllerCommand) -> Result<(), CommandRejection> {
        self.commands
            .try_send(command)
            .map_err(|error| match error {
                mpsc::error::TrySendError::Full(_) => CommandRejection::QueueFull,
                mpsc::error::TrySendError::Closed(_) => CommandRejection::Stopped,
            })
    }

    fn send_lifecycle(&self, event: ActivityLifecycleEvent) -> Result<(), CommandRejection> {
        let mut current = self
            .lifecycle
            .current
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        if *current == ActivityLifecycleEvent::Destroyed || *current == event {
            return Ok(());
        }
        self.lifecycle
            .events
            .send(event)
            .map_err(|_| CommandRejection::Stopped)?;
        *current = event;
        Ok(())
    }
}

/// Owns the Tokio runtime and the single Gateway control loop.
///
/// The native shell must finish with [`Self::shutdown`], which waits for
/// destruction acknowledgement and joins the control task before this runtime
/// is dropped. Field order remains a fallback safety boundary: senders and the
/// task handle are dropped before runtime teardown.
#[derive(Debug)]
pub struct AndroidController {
    handle: ControllerHandle,
    control: JoinHandle<()>,
    runtime: Runtime,
}

impl AndroidController {
    /// Starts the control loop on a dedicated multi-threaded runtime.
    ///
    /// # Errors
    ///
    /// Returns the underlying I/O error when the Tokio runtime cannot start.
    pub fn start(sink: SnapshotSink) -> Result<Self, std::io::Error> {
        Self::start_with_platform(sink, Arc::new(PortablePlatformFacilities))
    }

    /// Starts the controller with shell-supplied platform facilities.
    ///
    /// # Errors
    ///
    /// Returns the underlying I/O error when the Tokio runtime cannot start.
    pub fn start_with_platform(
        sink: SnapshotSink,
        platform: Arc<dyn PlatformFacilities>,
    ) -> Result<Self, std::io::Error> {
        let runtime = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(2)
            .enable_all()
            .thread_name("gta-claw-gateway")
            .build()?;
        let (commands_tx, commands_rx) = mpsc::channel(COMMAND_QUEUE_CAPACITY);
        let (lifecycle_tx, lifecycle_rx) = mpsc::unbounded_channel();
        let (shutdown_tx, shutdown_rx) = watch::channel(false);
        let lifecycle = Arc::new(LifecycleSender::new(lifecycle_tx, shutdown_rx));
        let control = runtime.spawn(run_with_platform(
            commands_rx,
            lifecycle_rx,
            shutdown_tx,
            sink,
            platform,
        ));
        Ok(Self {
            handle: ControllerHandle {
                commands: commands_tx,
                lifecycle,
            },
            control,
            runtime,
        })
    }

    /// Returns the handle the UI thread uses to issue commands.
    #[must_use]
    pub fn handle(&self) -> ControllerHandle {
        self.handle.clone()
    }

    /// Returns the Tokio runtime handle for adapters that need to spawn work.
    #[must_use]
    pub const fn runtime(&self) -> &Runtime {
        &self.runtime
    }

    /// Waits for acknowledged destruction and joins the control loop.
    ///
    /// # Errors
    ///
    /// Returns [`ControllerShutdownError`] if acknowledgement is lost, the
    /// control task fails, or the hard shutdown ceiling expires.
    pub fn shutdown(
        self,
        acknowledgement: DestroyAcknowledgement,
    ) -> Result<(), ControllerShutdownError> {
        let Self {
            handle,
            mut control,
            runtime,
        } = self;
        drop(handle);
        let acknowledgement = acknowledgement.wait();
        tokio::pin!(acknowledgement);
        let result = runtime.block_on(async {
            tokio::time::timeout(CONTROLLER_SHUTDOWN_TIMEOUT, async {
                acknowledgement.as_mut().await?;
                (&mut control)
                    .await
                    .map_err(ControllerShutdownError::Task)
            })
            .await
            .map_err(|_| ControllerShutdownError::Timeout)?
        });
        if result.is_err() {
            control.abort();
        }
        runtime.shutdown_timeout(RUNTIME_SHUTDOWN_TIMEOUT);
        result
    }
}

/// Renders the application core's health through the platform port.
///
/// This is the composition point: the Android shell owns no platform detection
/// of its own, it supplies a [`SystemProbe`] to [`Application`] and renders the
/// event the core produces.
#[must_use]
pub fn runtime_summary<P: SystemProbe>(probe: P) -> String {
    match Application::new(probe).health() {
        ServerEvent::Healthy { runtime } => runtime.to_string(),
        ServerEvent::Ready { protocol_version } => format!("protocol v{protocol_version}"),
    }
}

/// Returns the core protocol version this shell was built against.
#[must_use]
pub fn core_protocol_summary<P: SystemProbe>(probe: P) -> String {
    match Application::new(probe).ready() {
        ServerEvent::Ready { protocol_version } => format!("v{protocol_version}"),
        ServerEvent::Healthy { runtime } => runtime.to_string(),
    }
}

/// Returns the native runtime identity line shown in the Android shell.
#[must_use]
pub fn native_runtime_summary() -> String {
    runtime_summary(NativeSystemProbe)
}

struct ActiveAttempt {
    generation: u64,
    cancellation: CancellationToken,
    task: JoinHandle<()>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum AttemptDirective {
    None,
    Start,
    Stop,
    Restart,
}

#[derive(Debug)]
struct MobileRunPolicy {
    lifecycle: AppLifecycle,
    network: NetworkStatus,
    requested: bool,
    active: bool,
    resume_pending: bool,
}

impl MobileRunPolicy {
    const fn new() -> Self {
        Self {
            lifecycle: AppLifecycle::Foreground,
            network: NetworkStatus::Unknown,
            requested: false,
            active: false,
            resume_pending: false,
        }
    }

    const fn blocker(&self) -> Option<ConnectionBlocker> {
        connection_blocker(self.lifecycle, self.network)
    }

    const fn request_connection(&mut self) -> AttemptDirective {
        self.requested = true;
        self.resume_pending = true;
        if self.blocker().is_some() {
            if self.active {
                self.active = false;
                AttemptDirective::Stop
            } else {
                AttemptDirective::None
            }
        } else if self.active {
            self.resume_pending = false;
            AttemptDirective::Restart
        } else {
            self.active = true;
            self.resume_pending = false;
            AttemptDirective::Start
        }
    }

    const fn retry(&mut self) -> AttemptDirective {
        if !self.requested || self.active {
            return AttemptDirective::None;
        }
        self.resume_pending = true;
        if self.blocker().is_some() {
            AttemptDirective::None
        } else {
            self.active = true;
            self.resume_pending = false;
            AttemptDirective::Start
        }
    }

    const fn disconnect(&mut self) -> AttemptDirective {
        self.requested = false;
        self.resume_pending = false;
        if self.active {
            self.active = false;
            AttemptDirective::Stop
        } else {
            AttemptDirective::None
        }
    }

    fn set_lifecycle(&mut self, lifecycle: AppLifecycle) -> AttemptDirective {
        if self.lifecycle == lifecycle {
            return AttemptDirective::None;
        }
        self.lifecycle = lifecycle;
        self.reconcile(false)
    }

    fn set_network(&mut self, network: NetworkStatus) -> AttemptDirective {
        if self.network == network {
            return AttemptDirective::None;
        }
        let route_changed = usable_route_changed(self.network, network);
        self.network = network;
        self.reconcile(route_changed)
    }

    const fn reconcile(&mut self, restart_active: bool) -> AttemptDirective {
        if self.blocker().is_some() {
            if self.active {
                self.active = false;
                self.resume_pending = self.requested;
                AttemptDirective::Stop
            } else {
                AttemptDirective::None
            }
        } else if self.active && restart_active {
            AttemptDirective::Restart
        } else if !self.active && self.requested && self.resume_pending {
            self.active = true;
            self.resume_pending = false;
            AttemptDirective::Start
        } else {
            AttemptDirective::None
        }
    }

    const fn attempt_finished(&mut self) {
        self.active = false;
        self.resume_pending = false;
    }
}

fn usable_route_changed(before: NetworkStatus, after: NetworkStatus) -> bool {
    match (before, after) {
        (
            NetworkStatus::Available {
                transport: old_transport,
                generation: old_generation,
                ..
            },
            NetworkStatus::Available {
                transport: new_transport,
                generation: new_generation,
                ..
            },
        ) => old_generation != new_generation || old_transport != new_transport,
        _ => false,
    }
}

struct SnapshotPublisher {
    last: Option<ViewSnapshot>,
}

impl SnapshotPublisher {
    const fn new() -> Self {
        Self { last: None }
    }

    fn publish(&mut self, model: &ViewModel, sink: &SnapshotSink) {
        let snapshot = model.snapshot();
        if self.last.as_ref() == Some(&snapshot) {
            return;
        }
        sink(snapshot.clone());
        self.last = Some(snapshot);
    }
}

#[cfg(test)]
async fn run(commands: mpsc::Receiver<ControllerCommand>, sink: SnapshotSink) {
    let (lifecycle_tx, lifecycle_rx) = mpsc::unbounded_channel();
    let (shutdown_tx, shutdown_rx) = watch::channel(false);
    let _lifecycle = LifecycleSender::new(lifecycle_tx, shutdown_rx);
    run_with_platform(
        commands,
        lifecycle_rx,
        shutdown_tx,
        sink,
        Arc::new(PortablePlatformFacilities),
    )
    .await;
}

async fn run_with_platform(
    mut commands: mpsc::Receiver<ControllerCommand>,
    mut lifecycle: mpsc::UnboundedReceiver<ActivityLifecycleEvent>,
    shutdown_completed: watch::Sender<bool>,
    sink: SnapshotSink,
    platform: Arc<dyn PlatformFacilities>,
) {
    let mut capabilities = platform.capabilities();
    let mut model = ViewModel::with_platform(capabilities);
    let slot = Arc::new(AttemptSlot::new());
    let (updates_tx, mut updates_rx) = mpsc::channel::<(u64, AttemptUpdate)>(UPDATE_QUEUE_CAPACITY);
    let mut identity: Option<Arc<DeviceIdentity>> = None;
    let mut request: Option<Arc<ConnectRequest>> = None;
    let mut active: Option<ActiveAttempt> = None;
    let mut policy = MobileRunPolicy::new();
    let mut publisher = SnapshotPublisher::new();
    let mut destroyed = false;

    publisher.publish(&model, &sink);

    loop {
        tokio::select! {
            biased;
            lifecycle_event = lifecycle.recv() => {
                let Some(event) = lifecycle_event else { break };
                if event == ActivityLifecycleEvent::Destroyed {
                    destroyed = true;
                    let directive = policy.disconnect();
                    model.set_environment(AppLifecycle::Background, policy.network);
                    model.request_stop();
                    publisher.publish(&model, &sink);
                    if matches!(directive, AttemptDirective::Stop) {
                        stop_attempt(active.take()).await;
                    }
                    break;
                }

                let directive = policy.set_lifecycle(event.app_lifecycle());
                model.set_environment(policy.lifecycle, policy.network);
                match directive {
                    AttemptDirective::Stop => {
                        model.suspend(
                            policy.blocker().expect("a lifecycle stop has a blocker"),
                        );
                        publisher.publish(&model, &sink);
                        stop_attempt(active.take()).await;
                    }
                    AttemptDirective::Start => {
                        if let Some(retained) = request.as_ref() {
                            let launched = start_requested_attempt(
                                false,
                                retained,
                                &mut active,
                                &mut model,
                                &mut identity,
                                platform.as_ref(),
                                capabilities,
                                &slot,
                                &updates_tx,
                            )
                            .await;
                            if !launched {
                                policy.attempt_finished();
                            }
                        }
                    }
                    AttemptDirective::None | AttemptDirective::Restart => {}
                }
                publisher.publish(&model, &sink);
            }
            command = commands.recv() => {
                let Some(command) = command else { break };
                match command {
                    ControllerCommand::Connect(next_request) => {
                        request = Some(Arc::new(next_request));
                        let directive = policy.request_connection();
                        if let Some(blocker) = policy.blocker() {
                            let retained = request.as_ref().expect("request was just stored");
                            model.defer(retained, blocker);
                            publisher.publish(&model, &sink);
                            if matches!(directive, AttemptDirective::Stop) {
                                stop_attempt(active.take()).await;
                            }
                        } else if matches!(
                            directive,
                            AttemptDirective::Start | AttemptDirective::Restart
                        ) {
                            let launched = start_requested_attempt(
                                matches!(directive, AttemptDirective::Restart),
                                request.as_ref().expect("request was just stored"),
                                &mut active,
                                &mut model,
                                &mut identity,
                                platform.as_ref(),
                                capabilities,
                                &slot,
                                &updates_tx,
                            )
                            .await;
                            if !launched {
                                policy.attempt_finished();
                            }
                        }
                    }
                    ControllerCommand::Reject(rejection) => {
                        if !policy.active && !policy.resume_pending {
                            let generation = model.generation();
                            model.apply(
                                generation,
                                AttemptUpdate::Failed(UserError::from_rejection(rejection)),
                            );
                        }
                    }
                    ControllerCommand::Disconnect => {
                        let directive = policy.disconnect();
                        model.request_stop();
                        publisher.publish(&model, &sink);
                        if matches!(directive, AttemptDirective::Stop) {
                            stop_attempt(active.take()).await;
                        }
                        request = None;
                    }
                    ControllerCommand::Retry => {
                        let directive = policy.retry();
                        if let Some(retained) = request.as_ref() {
                            if let Some(blocker) = policy.blocker() {
                                model.defer(retained, blocker);
                            } else if matches!(directive, AttemptDirective::Start) {
                                let launched = start_requested_attempt(
                                    false,
                                    retained,
                                    &mut active,
                                    &mut model,
                                    &mut identity,
                                    platform.as_ref(),
                                    capabilities,
                                    &slot,
                                    &updates_tx,
                                )
                                .await;
                                if !launched {
                                    policy.attempt_finished();
                                }
                            }
                        }
                    }
                    ControllerCommand::NetworkChanged(network) => {
                        let directive = policy.set_network(network);
                        model.set_environment(policy.lifecycle, policy.network);
                        match directive {
                            AttemptDirective::Stop => {
                                model.suspend(
                                    policy.blocker().expect("a network stop has a blocker"),
                                );
                                publisher.publish(&model, &sink);
                                stop_attempt(active.take()).await;
                            }
                            AttemptDirective::Start | AttemptDirective::Restart => {
                                if let Some(retained) = request.as_ref() {
                                    let launched = start_requested_attempt(
                                        matches!(directive, AttemptDirective::Restart),
                                        retained,
                                        &mut active,
                                        &mut model,
                                        &mut identity,
                                        platform.as_ref(),
                                        capabilities,
                                        &slot,
                                        &updates_tx,
                                    )
                                    .await;
                                    if !launched {
                                        policy.attempt_finished();
                                    }
                                }
                            }
                            AttemptDirective::None => {}
                        }
                    }
                    ControllerCommand::DiscoveryReadinessChanged(readiness) => {
                        capabilities = PlatformCapabilities::new(
                            capabilities.identity_persistence(),
                            readiness,
                        );
                        model.set_platform_capabilities(capabilities);
                    }
                }
                publisher.publish(&model, &sink);
            }
            update = updates_rx.recv() => {
                let Some((generation, update)) = update else { break };
                let current = generation == model.generation();
                let terminal = matches!(update, AttemptUpdate::Failed(_) | AttemptUpdate::Stopped);
                let changed = model.apply(generation, update);
                if changed {
                    publisher.publish(&model, &sink);
                }
                if current
                    && terminal
                    && active
                        .as_ref()
                        .is_some_and(|attempt| attempt.generation == generation)
                {
                    policy.attempt_finished();
                    stop_attempt(active.take()).await;
                }
            }
        }
    }

    stop_attempt(active.take()).await;
    if destroyed {
        let _ = shutdown_completed.send(true);
    }
}

#[expect(
    clippy::too_many_arguments,
    reason = "the arguments are the controller's independently owned resources; grouping them \
              would create a second state owner solely to cross this async boundary"
)]
async fn start_requested_attempt(
    restart: bool,
    request: &Arc<ConnectRequest>,
    active: &mut Option<ActiveAttempt>,
    model: &mut ViewModel,
    identity: &mut Option<Arc<DeviceIdentity>>,
    platform: &dyn PlatformFacilities,
    capabilities: PlatformCapabilities,
    slot: &Arc<AttemptSlot>,
    updates: &mpsc::Sender<(u64, AttemptUpdate)>,
) -> bool {
    let generation = model.begin(request);
    if restart {
        stop_attempt(active.take()).await;
    }

    let device = if let Some(existing) = identity {
        Arc::clone(existing)
    } else {
        let fresh = match platform.device_identity() {
            Ok(fresh) => fresh,
            Err(error) => {
                model.apply(
                    generation,
                    AttemptUpdate::Failed(UserError::from_identity_failure(error)),
                );
                return false;
            }
        };
        Arc::clone(identity.insert(fresh))
    };
    let persistence = match capabilities.identity_persistence() {
        IdentityPersistence::SessionOnly => "session only",
        IdentityPersistence::DeviceBacked => "device backed",
    };
    model.apply(
        generation,
        AttemptUpdate::IdentityCreated(format!("{} ({persistence})", device.device_id())),
    );

    let cancellation = CancellationToken::new();
    let task = tokio::spawn(run_attempt(
        generation,
        Arc::clone(request),
        device,
        Arc::clone(slot),
        cancellation.clone(),
        updates.clone(),
    ));
    *active = Some(ActiveAttempt {
        generation,
        cancellation,
        task,
    });
    true
}

async fn stop_attempt(attempt: Option<ActiveAttempt>) {
    let Some(mut attempt) = attempt else { return };
    attempt.cancellation.cancel();
    if tokio::time::timeout(ATTEMPT_JOIN_TIMEOUT, &mut attempt.task)
        .await
        .is_err()
    {
        attempt.task.abort();
        // Aborting drops the future at its suspension point, which releases its
        // `AttemptLease` even when the transport failed to shut down promptly.
        let _ = attempt.task.await;
    }
}

async fn run_attempt(
    generation: u64,
    request: Arc<ConnectRequest>,
    identity: Arc<DeviceIdentity>,
    slot: Arc<AttemptSlot>,
    cancellation: CancellationToken,
    updates: mpsc::Sender<(u64, AttemptUpdate)>,
) {
    let Some(_lease) = slot.acquire(generation) else {
        let _ = send_attempt_update(
            &cancellation,
            &updates,
            (
                generation,
                AttemptUpdate::Failed(UserError::diagnostic(
                    DiagnosticCode::ControllerBusy,
                    RemedyKind::Wait,
                    "Another connection attempt is still finishing.",
                    "Wait for it to stop, then try again.",
                )),
            ),
        )
        .await;
        return;
    };

    let config = build_client_config_for_attempt(&request, identity);
    let (client, events) = match GatewayClient::start(config) {
        Ok(started) => started,
        Err(error) => {
            let _ = send_attempt_update(
                &cancellation,
                &updates,
                (
                    generation,
                    AttemptUpdate::Failed(UserError::from_gateway(&error)),
                ),
            )
            .await;
            return;
        }
    };

    drive_attempt(generation, &client, events, &cancellation, &updates).await;

    // A bounded close, and then the lease drops with this frame.
    let _ = client.shutdown().await;
}

async fn drive_attempt(
    generation: u64,
    client: &GatewayClient,
    mut events: GatewayEventStream,
    cancellation: &CancellationToken,
    updates: &mpsc::Sender<(u64, AttemptUpdate)>,
) {
    let mut states = client.subscribe_state();
    let mut last_ready_epoch = None;

    let initial = states.borrow_and_update().clone();
    if !publish_connection_state(
        generation,
        client,
        &initial,
        cancellation,
        updates,
        &mut last_ready_epoch,
    )
    .await
    {
        return;
    }

    loop {
        let state = tokio::select! {
            biased;
            () = cancellation.cancelled() => return,
            changed = states.changed() => {
                if changed.is_err() {
                    return;
                }
                states.borrow_and_update().clone()
            }
            event = events.recv() => {
                // Broadcast events are drained to keep the bounded queue from
                // saturating the transport. This shell does not render them yet.
                if event.is_none() {
                    return;
                }
                continue;
            }
        };
        if !publish_connection_state(
            generation,
            client,
            &state,
            cancellation,
            updates,
            &mut last_ready_epoch,
        )
        .await
        {
            return;
        }
    }
}

async fn publish_connection_state(
    generation: u64,
    client: &GatewayClient,
    state: &claw_gateway_client::ConnectionState,
    cancellation: &CancellationToken,
    updates: &mpsc::Sender<(u64, AttemptUpdate)>,
    last_ready_epoch: &mut Option<u64>,
) -> bool {
    let update = AttemptUpdate::from_connection_state(state);
    let terminal = matches!(update, AttemptUpdate::Failed(_) | AttemptUpdate::Stopped);
    let ready_epoch = match &update {
        AttemptUpdate::Ready(summary) => Some(summary.connection_epoch()),
        AttemptUpdate::IdentityCreated(_)
        | AttemptUpdate::Connecting
        | AttemptUpdate::Authenticating
        | AttemptUpdate::Reconnecting { .. }
        | AttemptUpdate::Failed(_)
        | AttemptUpdate::Stopped => None,
    };
    if !send_attempt_update(cancellation, updates, (generation, update)).await {
        return false;
    }
    if let Some(epoch) = ready_epoch
        && *last_ready_epoch != Some(epoch)
    {
        *last_ready_epoch = Some(epoch);
        // Every ready epoch can issue a replacement device token. This core has
        // no token store, so drain and drop each epoch rather than only the first.
        drop(client.take_issued_device_tokens().await);
    }
    !terminal
}

async fn send_attempt_update(
    cancellation: &CancellationToken,
    updates: &mpsc::Sender<(u64, AttemptUpdate)>,
    update: (u64, AttemptUpdate),
) -> bool {
    tokio::select! {
        biased;
        () = cancellation.cancelled() => false,
        result = updates.send(update) => result.is_ok(),
    }
}

#[cfg(test)]
mod tests {
    use std::sync::{Arc, Mutex};
    use std::time::{Duration, Instant};

    use claw_application::SystemProbe;
    use claw_platform::NativeSystemProbe;
    use claw_protocol::RuntimeDescriptor;
    use claw_security::identity::DeviceIdentity;
    use tokio::sync::{mpsc, watch};

    use super::{
        ActivityLifecycleEvent, AndroidController, AttemptDirective, COMMAND_QUEUE_CAPACITY,
        CommandRejection, ControllerCommand, ControllerHandle, LifecycleSender, MobileRunPolicy,
        SnapshotSink, core_protocol_summary, native_runtime_summary, run, run_with_platform,
        runtime_summary, send_attempt_update,
    };
    use crate::onboarding::{
        ConnectRequest, DiagnosticCode, RemedyKind, SubmissionRejection, ViewSnapshot,
    };
    use crate::platform::{
        AppLifecycle, DiscoveryReadiness, IdentityFailure, IdentityPersistence, NetworkStatus,
        NetworkTransport, PlatformCapabilities, PlatformFacilities, PortablePlatformFacilities,
    };

    #[derive(Debug)]
    struct FixedProbe;

    impl SystemProbe for FixedProbe {
        fn runtime(&self) -> RuntimeDescriptor {
            RuntimeDescriptor::new("android", "aarch64")
        }
    }

    struct FailingPlatform;

    impl PlatformFacilities for FailingPlatform {
        fn device_identity(&self) -> Result<Arc<DeviceIdentity>, IdentityFailure> {
            Err(IdentityFailure::StorageLocked)
        }

        fn capabilities(&self) -> PlatformCapabilities {
            PlatformCapabilities::new(
                IdentityPersistence::DeviceBacked,
                DiscoveryReadiness::ManualAddressOnly,
            )
        }
    }

    const fn online(generation: u64, metered: bool) -> NetworkStatus {
        NetworkStatus::Available {
            transport: NetworkTransport::Wifi,
            metered,
            validated: true,
            generation,
        }
    }

    #[test]
    fn the_shell_reports_whatever_the_platform_port_supplies() {
        let summary = runtime_summary(FixedProbe);

        assert_eq!(
            summary, "android-aarch64",
            "the shell must render the port's runtime rather than its own guess, got {summary:?}"
        );
    }

    #[test]
    fn the_native_probe_is_the_one_wired_into_the_shell() {
        let summary = native_runtime_summary();
        let expected = format!("{}-{}", std::env::consts::OS, std::env::consts::ARCH);

        assert_eq!(
            summary, expected,
            "the shell must report the compilation target through NativeSystemProbe, got {summary:?}"
        );
    }

    #[test]
    fn the_core_protocol_version_is_taken_from_the_application_core() {
        let summary = core_protocol_summary(NativeSystemProbe);

        assert_eq!(
            summary,
            format!("v{}", claw_protocol::PROTOCOL_VERSION),
            "the shell must not restate the protocol version independently, got {summary:?}"
        );
    }

    #[test]
    fn command_debug_never_reproduces_the_token() {
        let request =
            ConnectRequest::prepare("wss://gateway.example.com", "super-secret-token", false)
                .expect("a valid request");
        let command = ControllerCommand::Connect(request);

        let rendered = format!("{command:?}");

        assert!(
            !rendered.contains("super-secret-token"),
            "the queued command Debug leaked the token: {rendered}"
        );
        assert!(
            rendered.contains("gateway.example.com"),
            "the queued command Debug must still identify the endpoint: {rendered}"
        );
    }

    #[test]
    fn rejected_submissions_render_through_the_same_error_surface() {
        let command = ControllerCommand::Reject(SubmissionRejection::UnsupportedScheme);

        let rendered = format!("{command:?}");

        assert!(
            rendered.contains("UnsupportedScheme"),
            "the rejection must survive queuing intact: {rendered}"
        );
    }

    #[test]
    fn queue_rejections_carry_an_action_the_operator_can_take() {
        for rejection in [CommandRejection::QueueFull, CommandRejection::Stopped] {
            let error = rejection.user_error();

            assert!(
                !error.action().is_empty(),
                "{rejection:?} must tell the operator what to do, got {error:?}"
            );
        }
    }

    #[test]
    fn lifecycle_delivery_bypasses_a_saturated_command_queue() {
        let (commands_tx, _commands_rx) = mpsc::channel(COMMAND_QUEUE_CAPACITY);
        let (lifecycle_tx, mut lifecycle_rx) = mpsc::unbounded_channel();
        let (_shutdown_tx, shutdown_rx) = watch::channel(false);
        let handle = ControllerHandle {
            commands: commands_tx,
            lifecycle: Arc::new(LifecycleSender::new(lifecycle_tx, shutdown_rx)),
        };

        for _ in 0..COMMAND_QUEUE_CAPACITY {
            handle.retry().expect("fill the normal command queue");
        }
        assert_eq!(
            handle.retry(),
            Err(CommandRejection::QueueFull),
            "the fixture must saturate the normal command queue"
        );

        handle.app_paused().expect("pause bypasses saturation");
        handle.app_stopped().expect("stop bypasses saturation");
        handle.app_destroyed().expect("destroy bypasses saturation");

        assert_eq!(lifecycle_rx.try_recv(), Ok(ActivityLifecycleEvent::Paused));
        assert_eq!(lifecycle_rx.try_recv(), Ok(ActivityLifecycleEvent::Stopped));
        assert_eq!(
            lifecycle_rx.try_recv(),
            Ok(ActivityLifecycleEvent::Destroyed)
        );
        assert!(
            lifecycle_rx.try_recv().is_err(),
            "only the three distinct transitions must be queued"
        );
    }

    #[test]
    fn lifecycle_updates_coalesce_duplicates_and_destruction_is_terminal() {
        let (commands_tx, _commands_rx) = mpsc::channel(COMMAND_QUEUE_CAPACITY);
        let (lifecycle_tx, mut lifecycle_rx) = mpsc::unbounded_channel();
        let (_shutdown_tx, shutdown_rx) = watch::channel(false);
        let handle = ControllerHandle {
            commands: commands_tx,
            lifecycle: Arc::new(LifecycleSender::new(lifecycle_tx, shutdown_rx)),
        };

        handle
            .app_foregrounded()
            .expect("duplicate initial foreground");
        handle.app_paused().expect("pause");
        handle.app_paused().expect("duplicate pause");
        handle.app_stopped().expect("stop");
        handle.app_stopped().expect("duplicate stop");
        handle.app_foregrounded().expect("foreground");
        handle.app_destroyed().expect("destroy");
        handle
            .app_foregrounded()
            .expect("late foreground is safely ignored");
        let delivered = std::iter::from_fn(|| lifecycle_rx.try_recv().ok()).collect::<Vec<_>>();
        assert_eq!(
            delivered,
            vec![
                ActivityLifecycleEvent::Paused,
                ActivityLifecycleEvent::Stopped,
                ActivityLifecycleEvent::Foreground,
                ActivityLifecycleEvent::Destroyed,
            ]
        );
        assert!(
            lifecycle_rx.try_recv().is_err(),
            "duplicates and callbacks after destruction must be coalesced"
        );
    }

    #[test]
    fn destroy_ends_the_controller_with_a_saturated_normal_queue() {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("a current-thread runtime");

        runtime.block_on(async {
            let (commands_tx, commands_rx) = mpsc::channel(COMMAND_QUEUE_CAPACITY);
            let (lifecycle_tx, lifecycle_rx) = mpsc::unbounded_channel();
            let (shutdown_tx, shutdown_rx) = watch::channel(false);
            let handle = ControllerHandle {
                commands: commands_tx,
                lifecycle: Arc::new(LifecycleSender::new(lifecycle_tx, shutdown_rx)),
            };
            for _ in 0..COMMAND_QUEUE_CAPACITY {
                handle.retry().expect("fill the normal command queue");
            }
            let acknowledgement = handle
                .app_destroyed()
                .expect("destroy bypasses the saturated queue");

            let sink: SnapshotSink = Arc::new(|_| {});
            let control = tokio::spawn(run_with_platform(
                commands_rx,
                lifecycle_rx,
                shutdown_tx,
                sink,
                Arc::new(PortablePlatformFacilities),
            ));
            tokio::time::timeout(Duration::from_secs(1), async {
                acknowledgement
                    .wait()
                    .await
                    .expect("destruction is acknowledged after cleanup");
                control.await.expect("the controller must not panic");
            })
                .await
                .expect("destroy acknowledgement and task join must be bounded");

            assert_eq!(
                handle.retry(),
                Err(CommandRejection::Stopped),
                "destruction must close the normal command path"
            );
        });
    }

    #[test]
    fn owned_controller_shutdown_awaits_acknowledgement_and_task_join() {
        let controller =
            AndroidController::start(Arc::new(|_| {})).expect("controller runtime starts");
        let handle = controller.handle();
        for _ in 0..COMMAND_QUEUE_CAPACITY {
            handle.retry().expect("fill the normal command queue");
        }
        let acknowledgement = handle
            .app_destroyed()
            .expect("destroy bypasses the saturated queue");
        drop(handle);

        let started = Instant::now();
        controller
            .shutdown(acknowledgement)
            .expect("controller acknowledges destruction and joins");
        assert!(
            started.elapsed() < Duration::from_secs(1),
            "controller cleanup should finish well inside its hard ceiling"
        );
    }

    #[test]
    fn backgrounding_stops_once_and_foregrounding_resumes_once() {
        let mut policy = MobileRunPolicy::new();

        assert_eq!(
            policy.request_connection(),
            AttemptDirective::Start,
            "the initial foreground request must start"
        );
        assert_eq!(
            policy.set_lifecycle(AppLifecycle::Background),
            AttemptDirective::Stop,
            "backgrounding must stop the live socket"
        );
        assert_eq!(
            policy.set_lifecycle(AppLifecycle::Background),
            AttemptDirective::None,
            "duplicate lifecycle callbacks must be coalesced"
        );
        assert_eq!(
            policy.set_lifecycle(AppLifecycle::Foreground),
            AttemptDirective::Start,
            "foregrounding must resume the retained request"
        );
        assert_eq!(
            policy.set_lifecycle(AppLifecycle::Foreground),
            AttemptDirective::None,
            "a duplicate foreground callback must not start another socket"
        );
    }

    #[test]
    fn offline_time_does_not_spend_attempts_and_recovery_starts_once() {
        let mut policy = MobileRunPolicy::new();

        assert_eq!(
            policy.set_network(NetworkStatus::Unavailable),
            AttemptDirective::None
        );
        assert_eq!(
            policy.request_connection(),
            AttemptDirective::None,
            "an offline request must be retained without opening a socket"
        );
        assert_eq!(
            policy.set_network(NetworkStatus::Unavailable),
            AttemptDirective::None,
            "duplicate offline callbacks must not do work"
        );
        assert_eq!(
            policy.set_network(online(1, false)),
            AttemptDirective::Start,
            "the retained request must start when connectivity becomes usable"
        );
    }

    #[test]
    fn only_a_real_usable_route_change_restarts_the_socket() {
        let mut policy = MobileRunPolicy::new();
        assert_eq!(policy.request_connection(), AttemptDirective::Start);
        assert_eq!(
            policy.set_network(online(1, false)),
            AttemptDirective::None,
            "attaching the first monitor observation must not disrupt a live socket"
        );
        assert_eq!(
            policy.set_network(online(1, true)),
            AttemptDirective::None,
            "a metering update on the same route must not churn the radio"
        );
        assert_eq!(
            policy.set_network(online(2, true)),
            AttemptDirective::Restart,
            "a new Android default-network generation must replace the stale socket"
        );
    }

    #[test]
    fn terminal_attempts_never_auto_retry_on_unrelated_platform_callbacks() {
        let mut policy = MobileRunPolicy::new();
        assert_eq!(policy.request_connection(), AttemptDirective::Start);
        policy.attempt_finished();

        assert_eq!(
            policy.set_lifecycle(AppLifecycle::Background),
            AttemptDirective::None
        );
        assert_eq!(
            policy.set_lifecycle(AppLifecycle::Foreground),
            AttemptDirective::None,
            "foregrounding must not retry a terminal authentication or protocol failure"
        );
        assert_eq!(
            policy.set_network(online(2, false)),
            AttemptDirective::None,
            "network callbacks must not revive a terminal attempt"
        );
        assert_eq!(
            policy.retry(),
            AttemptDirective::Start,
            "only an explicit retry may revive the retained terminal request"
        );
    }

    #[test]
    fn cancellation_interrupts_an_update_blocked_on_the_bounded_queue() {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("a current-thread runtime");

        runtime.block_on(async {
            let (updates_tx, mut updates_rx) = mpsc::channel(1);
            updates_tx
                .send((1, crate::onboarding::AttemptUpdate::Connecting))
                .await
                .expect("fill the update queue");
            let cancellation = tokio_util::sync::CancellationToken::new();
            cancellation.cancel();

            let sent = tokio::time::timeout(
                Duration::from_millis(100),
                send_attempt_update(
                    &cancellation,
                    &updates_tx,
                    (1, crate::onboarding::AttemptUpdate::Authenticating),
                ),
            )
            .await
            .expect("cancellation must interrupt a blocked update send");

            assert!(!sent, "a cancelled attempt must not enqueue another update");
            assert!(
                updates_rx.recv().await.is_some(),
                "the original queue item must remain intact"
            );
        });
    }

    #[test]
    fn injected_platform_failures_reach_the_binding_snapshot_without_socket_work() {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("a current-thread runtime");
        let snapshots = Arc::new(Mutex::new(Vec::<ViewSnapshot>::new()));
        let collected = Arc::clone(&snapshots);
        let sink: SnapshotSink = Arc::new(move |snapshot| {
            collected
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .push(snapshot);
        });
        let observed = Arc::clone(&snapshots);

        runtime.block_on(async move {
            let (commands_tx, commands_rx) = mpsc::channel(COMMAND_QUEUE_CAPACITY);
            let (lifecycle_tx, lifecycle_rx) = mpsc::unbounded_channel();
            let (shutdown_tx, shutdown_rx) = watch::channel(false);
            let _lifecycle = LifecycleSender::new(lifecycle_tx, shutdown_rx);
            let control = tokio::spawn(run_with_platform(
                commands_rx,
                lifecycle_rx,
                shutdown_tx,
                sink,
                Arc::new(FailingPlatform),
            ));
            commands_tx
                .send(ControllerCommand::Connect(
                    ConnectRequest::prepare(
                        "wss://gateway.example.com",
                        "never-render-this-token",
                        false,
                    )
                    .expect("valid request"),
                ))
                .await
                .expect("queue connect");
            tokio::time::timeout(Duration::from_secs(1), async {
                loop {
                    if observed
                        .lock()
                        .unwrap_or_else(std::sync::PoisonError::into_inner)
                        .len()
                        >= 2
                    {
                        break;
                    }
                    tokio::task::yield_now().await;
                }
            })
            .await
            .expect("identity failure must render promptly");
            drop(commands_tx);
            control.await.expect("controller exits");
        });

        let failure = snapshots
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .last()
            .cloned()
            .expect("failure snapshot");
        let remedy = failure.remedy().expect("identity failure remedy");
        assert_eq!(remedy.diagnostic_code(), DiagnosticCode::IdentityLocked);
        assert_eq!(remedy.kind(), RemedyKind::Retry);
        assert!(
            !format!("{failure:?}").contains("never-render-this-token"),
            "platform failure snapshot leaked the retained token: {failure:?}"
        );
    }

    /// `AndroidController` documents that dropping it closes the command channel
    /// and *that* is what ends the control loop, ahead of runtime teardown. The
    /// promise is only worth anything if a closed channel actually ends the
    /// loop, so that half is pinned here; the field order in `AndroidController`
    /// is what puts the channel close first.
    #[test]
    fn closing_the_command_channel_ends_the_control_loop() {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("a current-thread runtime");
        let (commands_tx, commands_rx) = mpsc::channel(COMMAND_QUEUE_CAPACITY);
        let renders = Arc::new(Mutex::new(0_usize));
        let counted = Arc::clone(&renders);
        let sink: SnapshotSink = Arc::new(move |_| {
            *counted
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner) += 1;
        });

        runtime.block_on(async move {
            let control_loop = tokio::spawn(run(commands_rx, sink));
            drop(commands_tx);
            // Without the `break` on a closed channel this waits out the timeout
            // instead, which on a phone is a task that outlives its owner.
            tokio::time::timeout(Duration::from_secs(5), control_loop)
                .await
                .expect("dropping the last handle must end the control loop")
                .expect("the control loop must end without panicking");
        });

        let rendered = *renders
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        assert_eq!(
            rendered, 1,
            "the loop must render exactly its initial snapshot and then stop, got {rendered}"
        );
    }

    #[test]
    fn a_handle_outliving_the_loop_refuses_commands_instead_of_queueing_them() {
        let (commands_tx, commands_rx) = mpsc::channel(COMMAND_QUEUE_CAPACITY);
        let (lifecycle_tx, lifecycle_rx) = mpsc::unbounded_channel();
        let (_shutdown_tx, shutdown_rx) = watch::channel(false);
        let handle = ControllerHandle {
            commands: commands_tx,
            lifecycle: Arc::new(LifecycleSender::new(lifecycle_tx, shutdown_rx)),
        };
        drop(commands_rx);
        drop(lifecycle_rx);

        let rejection = handle
            .disconnect()
            .expect_err("a disconnect must not be accepted by a loop that has ended");

        assert_eq!(
            rejection,
            CommandRejection::Stopped,
            "a closed channel is a stopped controller, not a full queue, got {rejection:?}"
        );
    }
}

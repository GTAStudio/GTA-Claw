//! Tokio-side Gateway ownership, kept free of Slint and of Android APIs.
//!
//! The UI thread only ever sends commands and receives rendered snapshots, so
//! this whole module compiles and is exercised on the development host.

use std::error::Error;
use std::fmt::{self, Debug, Display, Formatter};
use std::sync::Arc;

use claw_application::{Application, SystemProbe};
use claw_gateway_client::{GatewayClient, GatewayEventStream};
use claw_platform::NativeSystemProbe;
use claw_protocol::ServerEvent;
use claw_security::identity::DeviceIdentity;
use tokio::runtime::Runtime;
use tokio::sync::mpsc;
use tokio::task::JoinHandle;
use tokio_util::sync::CancellationToken;

use crate::identity::generate_session_identity;
use crate::onboarding::{
    AttemptUpdate, ConnectRequest, SubmissionRejection, UserError, ViewModel, ViewSnapshot,
};
use crate::session::{AttemptSlot, build_client_config};

/// Bounded command queue depth between the UI thread and the Gateway task.
const COMMAND_QUEUE_CAPACITY: usize = 8;

/// Bounded update queue depth between one attempt and the controller loop.
const UPDATE_QUEUE_CAPACITY: usize = 32;

/// Receives every rendered snapshot. Implementations must not block.
pub type SnapshotSink = Arc<dyn Fn(ViewSnapshot) + Send + Sync>;

/// A command the UI thread asks the Gateway task to perform.
enum ControllerCommand {
    Connect(ConnectRequest),
    Reject(SubmissionRejection),
    Disconnect,
}

impl Debug for ControllerCommand {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        match self {
            Self::Connect(request) => formatter.debug_tuple("Connect").field(request).finish(),
            Self::Reject(rejection) => formatter.debug_tuple("Reject").field(rejection).finish(),
            Self::Disconnect => formatter.write_str("Disconnect"),
        }
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
            Self::QueueFull => UserError::new(
                "The app is still handling the previous action.",
                "Wait a moment, then try again.",
            ),
            Self::Stopped => {
                UserError::new("The connection service has stopped.", "Restart the app.")
            }
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

/// A cloneable, non-blocking handle usable from the Slint event loop.
#[derive(Clone, Debug)]
pub struct ControllerHandle {
    commands: mpsc::Sender<ControllerCommand>,
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

    fn send(&self, command: ControllerCommand) -> Result<(), CommandRejection> {
        self.commands
            .try_send(command)
            .map_err(|error| match error {
                mpsc::error::TrySendError::Full(_) => CommandRejection::QueueFull,
                mpsc::error::TrySendError::Closed(_) => CommandRejection::Stopped,
            })
    }
}

/// Owns the Tokio runtime and the single Gateway control loop.
///
/// Dropping this closes the command channel, which ends the control loop, which
/// cancels and joins any live attempt before the runtime itself is torn down.
///
/// That sequence is load-bearing on a phone: an attempt abandoned by runtime
/// teardown instead of by cancellation gets no chance to close its socket, so
/// the field order below is part of the contract. Rust drops fields in
/// declaration order, so `handle` — the controller's own command sender — must
/// stay ahead of `runtime`. Reversing them would tear the runtime down first
/// and make the documented shutdown unreachable.
#[derive(Debug)]
pub struct AndroidController {
    handle: ControllerHandle,
    runtime: Runtime,
}

impl AndroidController {
    /// Starts the control loop on a dedicated multi-threaded runtime.
    ///
    /// # Errors
    ///
    /// Returns the underlying I/O error when the Tokio runtime cannot start.
    pub fn start(sink: SnapshotSink) -> Result<Self, std::io::Error> {
        let runtime = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(2)
            .enable_all()
            .thread_name("gta-claw-gateway")
            .build()?;
        let (commands_tx, commands_rx) = mpsc::channel(COMMAND_QUEUE_CAPACITY);
        runtime.spawn(run(commands_rx, sink));
        Ok(Self {
            handle: ControllerHandle {
                commands: commands_tx,
            },
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
    cancellation: CancellationToken,
    task: JoinHandle<()>,
}

async fn run(mut commands: mpsc::Receiver<ControllerCommand>, sink: SnapshotSink) {
    let mut model = ViewModel::new();
    let slot = Arc::new(AttemptSlot::new());
    let (updates_tx, mut updates_rx) = mpsc::channel::<(u64, AttemptUpdate)>(UPDATE_QUEUE_CAPACITY);
    let mut identity: Option<Arc<DeviceIdentity>> = None;
    let mut active: Option<ActiveAttempt> = None;

    sink(model.snapshot());

    loop {
        tokio::select! {
            command = commands.recv() => {
                let Some(command) = command else { break };
                match command {
                    ControllerCommand::Connect(request) => {
                        if !model.can_start_connection() {
                            continue;
                        }
                        stop_attempt(active.take()).await;
                        let generation = model.begin(&request);
                        let device = if let Some(existing) = &identity {
                            Arc::clone(existing)
                        } else {
                            let Ok(fresh) = generate_session_identity() else {
                                // Connecting anyway would mean signing with
                                // key material we could not prove was random.
                                // `RandomnessUnavailable` is a unit type, so
                                // there is no further detail to carry.
                                model.apply(
                                    generation,
                                    AttemptUpdate::Failed(UserError::new(
                                        "This device could not generate a secure identity.",
                                        "Restart the app. If it keeps failing, the device's \
                                         random number generator is unavailable and it cannot \
                                         connect safely.",
                                    )),
                                );
                                sink(model.snapshot());
                                continue;
                            };
                            Arc::clone(identity.insert(Arc::new(fresh)))
                        };
                        model.apply(
                            generation,
                            AttemptUpdate::IdentityCreated(format!(
                                "{} (session only)",
                                device.device_id()
                            )),
                        );
                        sink(model.snapshot());
                        let cancellation = CancellationToken::new();
                        let task = tokio::spawn(run_attempt(
                            generation,
                            request,
                            device,
                            Arc::clone(&slot),
                            cancellation.clone(),
                            updates_tx.clone(),
                        ));
                        active = Some(ActiveAttempt { cancellation, task });
                    }
                    ControllerCommand::Reject(rejection) => {
                        // A rejected submission takes the same render path as a
                        // transport failure so the operator sees one error surface.
                        let generation = model.generation();
                        model.apply(
                            generation,
                            AttemptUpdate::Failed(UserError::from_rejection(rejection)),
                        );
                        sink(model.snapshot());
                    }
                    ControllerCommand::Disconnect => {
                        stop_attempt(active.take()).await;
                        model.request_stop();
                        sink(model.snapshot());
                    }
                }
            }
            update = updates_rx.recv() => {
                let Some((generation, update)) = update else { break };
                if model.apply(generation, update) {
                    sink(model.snapshot());
                }
            }
        }
    }

    stop_attempt(active.take()).await;
}

async fn stop_attempt(attempt: Option<ActiveAttempt>) {
    let Some(attempt) = attempt else { return };
    attempt.cancellation.cancel();
    // The attempt future is dropped at whatever suspension point it reached; its
    // `AttemptLease` releases the slot on that drop, not on completion.
    let _ = attempt.task.await;
}

async fn run_attempt(
    generation: u64,
    request: ConnectRequest,
    identity: Arc<DeviceIdentity>,
    slot: Arc<AttemptSlot>,
    cancellation: CancellationToken,
    updates: mpsc::Sender<(u64, AttemptUpdate)>,
) {
    let Some(_lease) = slot.acquire(generation) else {
        let _ = updates
            .send((
                generation,
                AttemptUpdate::Failed(UserError::new(
                    "Another connection attempt is still finishing.",
                    "Wait for it to stop, then try again.",
                )),
            ))
            .await;
        return;
    };

    let config = build_client_config(request, identity);
    let (client, events) = match GatewayClient::start(config) {
        Ok(started) => started,
        Err(error) => {
            let _ = updates
                .send((
                    generation,
                    AttemptUpdate::Failed(UserError::from_gateway(&error)),
                ))
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
    let mut announced_ready = false;

    loop {
        let update = tokio::select! {
            biased;
            () = cancellation.cancelled() => return,
            changed = states.changed() => {
                if changed.is_err() {
                    return;
                }
                let state = states.borrow_and_update().clone();
                AttemptUpdate::from_connection_state(&state)
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

        let terminal = matches!(update, AttemptUpdate::Failed(_) | AttemptUpdate::Stopped);
        let ready = matches!(update, AttemptUpdate::Ready(_));
        if updates.send((generation, update)).await.is_err() {
            return;
        }
        if ready && !announced_ready {
            announced_ready = true;
            // The transport retains device tokens until a caller takes them.
            // This shell has no credential storage, so it takes and drops them
            // rather than letting the bounded buffer grow. See CREDENTIAL_NOTICE.
            drop(client.take_issued_device_tokens().await);
        }
        if terminal {
            return;
        }
    }
}

#[cfg(test)]
mod tests {
    use std::sync::{Arc, Mutex};
    use std::time::Duration;

    use claw_application::SystemProbe;
    use claw_platform::NativeSystemProbe;
    use claw_protocol::RuntimeDescriptor;
    use tokio::sync::mpsc;

    use super::{
        COMMAND_QUEUE_CAPACITY, CommandRejection, ControllerCommand, ControllerHandle,
        SnapshotSink, core_protocol_summary, native_runtime_summary, run, runtime_summary,
    };
    use crate::onboarding::{ConnectRequest, SubmissionRejection};

    #[derive(Debug)]
    struct FixedProbe;

    impl SystemProbe for FixedProbe {
        fn runtime(&self) -> RuntimeDescriptor {
            RuntimeDescriptor::new("android", "aarch64")
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
        let handle = ControllerHandle {
            commands: commands_tx,
        };
        drop(commands_rx);

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

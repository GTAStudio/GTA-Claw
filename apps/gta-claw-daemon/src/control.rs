//! Process-level control: argument parsing, the ready contract, and the ways a
//! run ends.
//!
//! The daemon stops for an operating-system stop signal or an explicit
//! `shutdown` line on the control channel. Reaching the end of the control
//! channel is *not* one of them — a daemon started with its standard input
//! closed must keep serving, which is what the process-lifecycle test asserts.
//!
//! Both of the signals a supervisor uses are handled, and the distinction
//! matters: `SIGTERM` is what `systemd` (`KillSignal=SIGTERM` in
//! `packaging/linux/systemd/gta-claw-daemon.service`), `docker stop` and
//! `kubectl delete` send, while `SIGINT` is what an interactive Ctrl-C sends.
//! Handling only the latter would leave the packaged service to die at the
//! default disposition, with no drain and no stop summary.

use std::io::{self, Write};
use std::path::PathBuf;

use claw_application::Application;
use claw_platform::NativeSystemProbe;
use claw_state::{
    ProcessSignalCounter, StateStore, StoreConfig, initialize_linux_protected_offline,
    prepare_linux_protected_offline, provision_linux_protected_offline,
};
use tokio::io::{AsyncBufReadExt, BufReader};

use crate::compose::{Daemon, StopSummary};

/// The control word that ends a run.
pub const SHUTDOWN_COMMAND: &str = "shutdown";

const LEGACY_USAGE: &str = "usage: gta-claw-daemon [--probe]";
const HELP: &str = "\
usage: gta-claw-daemon [--probe] [--state-profile <portable-private|linux-protected> --state-path <absolute-path>]
       gta-claw-daemon --provision-linux-protected --state-path <absolute-namespace> --service-uid <nonzero-uid> --service-gid <nonzero-gid>
       gta-claw-daemon --initialize-linux-protected --state-path <absolute-namespace> --service-uid <nonzero-uid> --service-gid <nonzero-gid>
       gta-claw-daemon --prepare-linux-protected --state-path <absolute-namespace> --service-uid <nonzero-uid> --service-gid <nonzero-gid>
       gta-claw-daemon --help";

/// How the daemon was asked to run.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DaemonMode {
    /// Serve until told to stop.
    Serve,
    /// Report health once and exit.
    Probe,
    /// Provision a Linux-protected namespace without opening SQLite.
    ProvisionLinuxProtected,
    /// Initialize a provisioned Linux-protected namespace offline.
    InitializeLinuxProtected,
    /// Provision and initialize a Linux-protected namespace offline.
    PrepareLinuxProtected,
    /// Print command-line help.
    Help,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum RequestedStateProfile {
    PortablePrivate,
    LinuxProtected,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct StateSelection {
    profile: RequestedStateProfile,
    path: PathBuf,
}

impl StateSelection {
    fn config(&self) -> StoreConfig {
        match self.profile {
            RequestedStateProfile::PortablePrivate => StoreConfig::new(&self.path),
            RequestedStateProfile::LinuxProtected => StoreConfig::linux_protected(&self.path),
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct DaemonCommand {
    mode: DaemonMode,
    state: Option<StateSelection>,
    initialize_namespace: Option<PathBuf>,
    service_uid: Option<u32>,
    service_gid: Option<u32>,
}

/// Why a run ended.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum StopTrigger {
    /// A supervisor asked the process to terminate.
    ///
    /// `SIGTERM` on unix; a console close or system shutdown on Windows.
    Terminate,
    /// An operating-system interrupt arrived.
    ///
    /// `SIGINT` on unix; Ctrl-C or Ctrl-Break on Windows.
    Interrupt,
    /// The control channel carried [`SHUTDOWN_COMMAND`].
    Control,
}

impl StopTrigger {
    /// Returns the word used when reporting the reason.
    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            Self::Terminate => "terminate",
            Self::Interrupt => "interrupt",
            Self::Control => "control",
        }
    }
}

/// The operating-system stop signals, installed and held for a whole run.
///
/// Installed *before* the daemon starts serving, so a supervisor that stops the
/// process during startup is still observed rather than being left to the
/// default disposition. Dropping this value uninstalls the handlers.
pub struct StopSignals {
    #[cfg(unix)]
    terminate: tokio::signal::unix::Signal,
    #[cfg(unix)]
    interrupt: tokio::signal::unix::Signal,
    #[cfg(windows)]
    ctrl_c: tokio::signal::windows::CtrlC,
    #[cfg(windows)]
    ctrl_break: tokio::signal::windows::CtrlBreak,
    #[cfg(windows)]
    ctrl_close: tokio::signal::windows::CtrlClose,
    #[cfg(windows)]
    ctrl_shutdown: tokio::signal::windows::CtrlShutdown,
}

impl StopSignals {
    /// Installs the handlers.
    ///
    /// # Errors
    ///
    /// Returns an [`io::Error`] when a handler cannot be installed. Reporting
    /// that here rather than at stop time means the failure is visible before
    /// the daemon claims to be ready.
    #[cfg(unix)]
    pub fn install() -> io::Result<Self> {
        use tokio::signal::unix::{SignalKind, signal};

        Ok(Self {
            terminate: signal(SignalKind::terminate())?,
            interrupt: signal(SignalKind::interrupt())?,
        })
    }

    /// Installs the handlers.
    ///
    /// # Errors
    ///
    /// Returns an [`io::Error`] when a handler cannot be installed.
    #[cfg(windows)]
    pub fn install() -> io::Result<Self> {
        use tokio::signal::windows::{ctrl_break, ctrl_c, ctrl_close, ctrl_shutdown};

        Ok(Self {
            ctrl_c: ctrl_c()?,
            ctrl_break: ctrl_break()?,
            ctrl_close: ctrl_close()?,
            ctrl_shutdown: ctrl_shutdown()?,
        })
    }

    /// Waits for whichever stop signal arrives first.
    ///
    /// A signal stream that ends is treated as "this signal will never arrive"
    /// rather than as a stop, so a closed stream cannot shut the daemon down.
    #[cfg(unix)]
    pub async fn recv(&mut self) -> StopTrigger {
        tokio::select! {
            Some(()) = self.terminate.recv() => StopTrigger::Terminate,
            Some(()) = self.interrupt.recv() => StopTrigger::Interrupt,
            else => std::future::pending().await,
        }
    }

    /// Waits for whichever stop signal arrives first.
    ///
    /// A signal stream that ends is treated as "this signal will never arrive"
    /// rather than as a stop, so a closed stream cannot shut the daemon down.
    #[cfg(windows)]
    pub async fn recv(&mut self) -> StopTrigger {
        tokio::select! {
            Some(()) = self.ctrl_close.recv() => StopTrigger::Terminate,
            Some(()) = self.ctrl_shutdown.recv() => StopTrigger::Terminate,
            Some(()) = self.ctrl_c.recv() => StopTrigger::Interrupt,
            Some(()) = self.ctrl_break.recv() => StopTrigger::Interrupt,
            else => std::future::pending().await,
        }
    }
}

fn parse_error(reason: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidInput, format!("{reason}\n{HELP}"))
}

fn required_value(
    arguments: &mut impl Iterator<Item = String>,
    flag: &'static str,
) -> io::Result<String> {
    match arguments.next() {
        Some(value) if !value.starts_with("--") => Ok(value),
        _ => Err(parse_error(match flag {
            "--state-profile" => "missing value for --state-profile",
            "--state-path" => "missing value for --state-path",
            "--service-uid" => "missing value for --service-uid",
            "--service-gid" => "missing value for --service-gid",
            _ => "missing option value",
        })),
    }
}

fn parse_nonzero_id(value: &str, flag: &'static str) -> io::Result<u32> {
    let parsed = value.parse::<u32>().map_err(|_| {
        parse_error(match flag {
            "--service-uid" => "--service-uid must be a nonzero decimal u32",
            "--service-gid" => "--service-gid must be a nonzero decimal u32",
            _ => "service identity must be a nonzero decimal u32",
        })
    })?;
    if parsed == 0 || parsed == u32::MAX {
        return Err(parse_error(match flag {
            "--service-uid" => "--service-uid must be a nonzero decimal u32",
            "--service-gid" => "--service-gid must be a nonzero decimal u32",
            _ => "service identity must be a nonzero decimal u32",
        }));
    }
    Ok(parsed)
}

fn parse_command<I, S>(arguments: I) -> io::Result<DaemonCommand>
where
    I: IntoIterator<Item = S>,
    S: Into<String>,
{
    let mut arguments = arguments.into_iter().map(Into::into);
    let mut probe = false;
    let mut provision = false;
    let mut initialize = false;
    let mut prepare = false;
    let mut help = false;
    let mut profile = None;
    let mut path = None;
    let mut service_uid = None;
    let mut service_gid = None;

    while let Some(argument) = arguments.next() {
        match argument.as_str() {
            "--probe" if !probe => probe = true,
            "--probe" => return Err(parse_error("duplicate --probe")),
            "--provision-linux-protected" if !provision => provision = true,
            "--provision-linux-protected" => {
                return Err(parse_error("duplicate --provision-linux-protected"));
            }
            "--initialize-linux-protected" if !initialize => initialize = true,
            "--initialize-linux-protected" => {
                return Err(parse_error("duplicate --initialize-linux-protected"));
            }
            "--prepare-linux-protected" if !prepare => prepare = true,
            "--prepare-linux-protected" => {
                return Err(parse_error("duplicate --prepare-linux-protected"));
            }
            "--help" if !help => help = true,
            "--help" => return Err(parse_error("duplicate --help")),
            "--state-profile" if profile.is_none() => {
                profile = Some(
                    match required_value(&mut arguments, "--state-profile")?.as_str() {
                        "portable-private" => RequestedStateProfile::PortablePrivate,
                        "linux-protected" => RequestedStateProfile::LinuxProtected,
                        _ => {
                            return Err(parse_error(
                                "--state-profile must be portable-private or linux-protected",
                            ));
                        }
                    },
                );
            }
            "--state-profile" => return Err(parse_error("duplicate --state-profile")),
            "--state-path" if path.is_none() => {
                let value = PathBuf::from(required_value(&mut arguments, "--state-path")?);
                if !value.is_absolute() {
                    return Err(parse_error("--state-path must be absolute"));
                }
                path = Some(value);
            }
            "--state-path" => return Err(parse_error("duplicate --state-path")),
            "--service-uid" if service_uid.is_none() => {
                let value = required_value(&mut arguments, "--service-uid")?;
                service_uid = Some(parse_nonzero_id(&value, "--service-uid")?);
            }
            "--service-uid" => return Err(parse_error("duplicate --service-uid")),
            "--service-gid" if service_gid.is_none() => {
                let value = required_value(&mut arguments, "--service-gid")?;
                service_gid = Some(parse_nonzero_id(&value, "--service-gid")?);
            }
            "--service-gid" => return Err(parse_error("duplicate --service-gid")),
            _ => return Err(io::Error::new(io::ErrorKind::InvalidInput, LEGACY_USAGE)),
        }
    }

    if help {
        if probe
            || provision
            || initialize
            || prepare
            || profile.is_some()
            || path.is_some()
            || service_uid.is_some()
            || service_gid.is_some()
        {
            return Err(parse_error(
                "--help cannot be combined with other arguments",
            ));
        }
        return Ok(DaemonCommand {
            mode: DaemonMode::Help,
            state: None,
            initialize_namespace: None,
            service_uid: None,
            service_gid: None,
        });
    }

    let privileged_mode_count = u8::from(provision) + u8::from(initialize) + u8::from(prepare);
    if privileged_mode_count > 1 {
        return Err(parse_error(
            "LinuxProtected provisioning modes cannot be combined",
        ));
    }
    if privileged_mode_count == 1 {
        if probe {
            return Err(parse_error(
                "LinuxProtected provisioning modes cannot be combined with --probe",
            ));
        }
        if profile == Some(RequestedStateProfile::PortablePrivate) {
            return Err(parse_error(
                "LinuxProtected provisioning modes are incompatible with portable-private",
            ));
        }
        let namespace = path
            .ok_or_else(|| parse_error("LinuxProtected provisioning modes require --state-path"))?;
        let service_uid = service_uid.ok_or_else(|| {
            parse_error("LinuxProtected provisioning modes require --service-uid")
        })?;
        let service_gid = service_gid.ok_or_else(|| {
            parse_error("LinuxProtected provisioning modes require --service-gid")
        })?;
        return Ok(DaemonCommand {
            mode: if provision {
                DaemonMode::ProvisionLinuxProtected
            } else if initialize {
                DaemonMode::InitializeLinuxProtected
            } else {
                DaemonMode::PrepareLinuxProtected
            },
            state: None,
            initialize_namespace: Some(namespace),
            service_uid: Some(service_uid),
            service_gid: Some(service_gid),
        });
    }

    if service_uid.is_some() || service_gid.is_some() {
        return Err(parse_error(
            "--service-uid and --service-gid require a LinuxProtected provisioning mode",
        ));
    }
    let state = match (profile, path) {
        (None, None) => None,
        (Some(profile), Some(path)) => Some(StateSelection { profile, path }),
        (Some(_), None) => return Err(parse_error("--state-profile requires --state-path")),
        (None, Some(_)) => return Err(parse_error("--state-path requires --state-profile")),
    };
    Ok(DaemonCommand {
        mode: if probe {
            DaemonMode::Probe
        } else {
            DaemonMode::Serve
        },
        state,
        initialize_namespace: None,
        service_uid: None,
        service_gid: None,
    })
}

/// Parses the command line and returns the requested mode.
///
/// # Errors
///
/// Returns an [`io::Error`] with kind [`io::ErrorKind::InvalidInput`] when the
/// arguments are not a supported combination.
pub fn parse_mode<I, S>(arguments: I) -> io::Result<DaemonMode>
where
    I: IntoIterator<Item = S>,
    S: Into<String>,
{
    parse_command(arguments).map(|command| command.mode)
}

/// Writes the one-shot health line.
///
/// # Errors
///
/// Returns an [`io::Error`] when the output cannot be written.
pub fn probe(mut output: impl Write) -> io::Result<()> {
    let application = Application::new(NativeSystemProbe);

    writeln!(output, "{}", application.health())?;
    output.flush()?;
    Ok(())
}

fn announce_ready(mut output: impl Write) -> io::Result<()> {
    let application = Application::new(NativeSystemProbe);

    writeln!(output, "{}", application.ready())?;
    writeln!(output, "{}", application.health())?;
    output.flush()?;
    Ok(())
}

#[cfg(target_os = "linux")]
fn notify_systemd_ready_to(socket_name: &std::ffi::OsStr) -> io::Result<()> {
    use std::os::linux::net::SocketAddrExt as _;
    use std::os::unix::ffi::OsStrExt as _;
    use std::os::unix::net::{SocketAddr, UnixDatagram};

    let bytes = socket_name.as_bytes();
    let address = if let Some(abstract_name) = bytes.strip_prefix(b"@") {
        SocketAddr::from_abstract_name(abstract_name)?
    } else {
        SocketAddr::from_pathname(std::path::Path::new(socket_name))?
    };
    let socket = UnixDatagram::unbound()?;
    socket.send_to_addr(b"READY=1", &address)?;
    Ok(())
}

fn notify_systemd_ready() -> io::Result<()> {
    #[cfg(target_os = "linux")]
    {
        if let Some(socket_name) = std::env::var_os("NOTIFY_SOCKET") {
            return notify_systemd_ready_to(&socket_name);
        }
    }
    Ok(())
}

/// Reads the control channel until it carries a shutdown request.
///
/// Resolves to `None` when the channel ends without one, which the caller must
/// treat as "never stop for this reason" rather than as a stop.
pub async fn await_control(reader: impl tokio::io::AsyncRead + Unpin) -> Option<StopTrigger> {
    let mut lines = BufReader::new(reader).lines();

    while let Ok(Some(line)) = lines.next_line().await {
        if line.trim().eq_ignore_ascii_case(SHUTDOWN_COMMAND) {
            return Some(StopTrigger::Control);
        }
    }

    None
}

/// Waits for whichever stop reason arrives first.
///
/// Takes the signals by reference because they must have been installed before
/// the daemon started serving; see [`StopSignals::install`].
pub async fn await_stop(
    signals: &mut StopSignals,
    control: impl tokio::io::AsyncRead + Unpin,
) -> StopTrigger {
    tokio::select! {
        trigger = signals.recv() => trigger,
        trigger = await_control(control) => {
            match trigger {
                Some(trigger) => trigger,
                // The channel ended. Park here rather than returning, so an
                // inherited null stdin cannot shut the daemon down.
                None => std::future::pending().await,
            }
        }
    }
}

/// Runs the daemon until it is told to stop.
///
/// Emits the ready and health lines the supervisor waits for, then the stop
/// summary, so a caller can tell a clean shutdown from an abandoned one without
/// parsing anything ambiguous.
///
/// # Errors
///
/// Returns an error when a stop-signal handler cannot be installed, when the
/// composition cannot be built or started, or when the output cannot be
/// written.
pub async fn serve(
    mut output: impl Write,
    control: impl tokio::io::AsyncRead + Unpin,
) -> Result<StopSummary, Box<dyn std::error::Error>> {
    // Installed before anything is started. A supervisor that stops the process
    // during startup is then still observed, instead of the signal reaching the
    // default disposition and killing the process mid-start with no drain.
    let mut signals = StopSignals::install()?;
    let mut daemon = Daemon::builder().build()?;

    daemon.start().await?;

    if let Err(primary) = announce_ready(&mut output).and_then(|()| notify_systemd_ready()) {
        return match daemon.stop().await {
            Ok(summary) if summary.is_clean() => Err(Box::new(primary)),
            Ok(summary) => Err(Box::new(io::Error::other(format!(
                "{primary}; shutdown left work behind: {} abandoned, {} of {} tasks joined",
                summary.shutdown().abandoned(),
                summary.tasks().terminated(),
                summary.tasks().spawned(),
            )))),
            Err(stop) => Err(Box::new(io::Error::other(format!(
                "{primary}; daemon stop failed: {stop}"
            )))),
        };
    }

    let trigger = await_stop(&mut signals, control).await;
    let summary = daemon.stop().await?;

    writeln!(
        output,
        "stopped reason={} clean={} drained={} completed={} abandoned={} tasks={}/{}",
        trigger.label(),
        summary.is_clean(),
        summary.shutdown().drains().len(),
        summary.shutdown().completed(),
        summary.shutdown().abandoned(),
        summary.tasks().terminated(),
        summary.tasks().spawned(),
    )?;
    output.flush()?;

    Ok(summary)
}

fn state_failure(operation: &'static str, error: impl std::fmt::Display) -> io::Error {
    io::Error::other(format!("{operation} failed: {error}"))
}

fn append_failure(failure: &mut Option<io::Error>, next: io::Error) {
    *failure = Some(match failure.take() {
        Some(primary) => io::Error::other(format!("{primary}; {next}")),
        None => next,
    });
}

async fn close_after_failure(
    store: StateStore,
    operation: &'static str,
    primary: impl std::fmt::Display,
) -> io::Error {
    match store.close().await {
        Ok(_) => state_failure(operation, primary),
        Err(close) => io::Error::other(format!(
            "{operation} failed: {primary}; state close failed: {close}"
        )),
    }
}

async fn probe_with_state(selection: &StateSelection, mut output: impl Write) -> io::Result<()> {
    let store = StateStore::open(selection.config())
        .await
        .map_err(|error| state_failure("state open", error))?;
    let report = match store.health().await {
        Ok(report) => report,
        Err(error) => return Err(close_after_failure(store, "state health", error).await),
    };
    if !report.is_healthy() {
        return Err(close_after_failure(store, "state health", "database is not ready").await);
    }
    store
        .close()
        .await
        .map_err(|error| state_failure("state close", error))?;
    probe(&mut output)
}

#[derive(Default)]
struct ShutdownState {
    signals: u8,
    control: bool,
    listener_error: Option<String>,
}

impl ShutdownState {
    fn observe(&mut self, result: io::Result<()>) -> bool {
        let first = !self.requested();
        match result {
            Ok(()) => {
                self.signals = self.signals.saturating_add(1);
            }
            Err(error) => self.listener_error = Some(error.to_string()),
        }
        first && self.requested()
    }

    fn observe_control(&mut self) -> bool {
        let first = !self.requested();
        self.control = true;
        first
    }

    const fn requested(&self) -> bool {
        self.signals > 0 || self.control || self.listener_error.is_some()
    }

    fn terminal_error(&self) -> Option<io::Error> {
        if let Some(error) = &self.listener_error {
            Some(io::Error::other(format!(
                "shutdown signal listener failed: {error}"
            )))
        } else if self.signals >= 2 {
            Some(io::Error::other("shutdown escalated after a second signal"))
        } else {
            None
        }
    }

    fn combine(&self, primary: io::Error) -> io::Error {
        match self.terminal_error() {
            Some(shutdown) => io::Error::other(format!("{primary}; {shutdown}")),
            None => primary,
        }
    }
}

fn report_lifecycle_transition(transition: &str) {
    let mut stderr = io::stderr().lock();
    let _ = writeln!(stderr, "gta-claw lifecycle {transition}");
    let _ = stderr.flush();
}

fn observe_shutdown(shutdown: &mut ShutdownState, result: io::Result<()>) {
    if shutdown.observe(result) {
        report_lifecycle_transition("shutdown-requested");
    }
}

fn observe_control_shutdown(shutdown: &mut ShutdownState) {
    if shutdown.observe_control() {
        report_lifecycle_transition("shutdown-requested");
    }
}

async fn report_first_pending<F: std::future::Future>(
    future: F,
    transition: &'static str,
) -> F::Output {
    tokio::pin!(future);
    let mut reported = false;
    std::future::poll_fn(|context| match future.as_mut().poll(context) {
        std::task::Poll::Pending => {
            if !reported {
                report_lifecycle_transition(transition);
                reported = true;
            }
            std::task::Poll::Pending
        }
        std::task::Poll::Ready(output) => std::task::Poll::Ready(output),
    })
    .await
}

struct ShutdownSignals {
    counter: ProcessSignalCounter,
}

impl ShutdownSignals {
    fn new() -> io::Result<Self> {
        Ok(Self {
            counter: ProcessSignalCounter::install()?,
        })
    }

    async fn wait(&mut self) -> io::Result<()> {
        self.counter.wait_next().await
    }

    fn drain(&mut self, shutdown: &mut ShutdownState) {
        while self.counter.take_next() {
            observe_shutdown(shutdown, Ok(()));
        }
    }

    fn mark_ready(&mut self, shutdown: &mut ShutdownState) -> bool {
        self.drain(shutdown);
        if shutdown.requested() {
            return false;
        }
        if self.counter.mark_ready() {
            true
        } else {
            while !self.counter.take_next() {
                std::hint::spin_loop();
            }
            observe_shutdown(shutdown, Ok(()));
            self.drain(shutdown);
            false
        }
    }

    fn commit_clean_exit(&self) -> bool {
        self.counter.commit_clean_exit()
    }
}

async fn run_state_phase<F: std::future::Future>(
    signals: &mut ShutdownSignals,
    shutdown: &mut ShutdownState,
    future: F,
) -> F::Output {
    tokio::pin!(future);
    loop {
        if shutdown.listener_error.is_some() {
            return future.as_mut().await;
        }
        tokio::select! {
            biased;
            signal = signals.wait() => observe_shutdown(shutdown, signal),
            output = future.as_mut() => {
                signals.drain(shutdown);
                return output;
            },
        }
    }
}

async fn announce_readiness_or_shutdown(
    signals: &mut ShutdownSignals,
    shutdown: &mut ShutdownState,
    output: &mut impl Write,
) -> io::Result<bool> {
    if shutdown.requested() {
        return Ok(false);
    }
    signals.drain(shutdown);
    if shutdown.requested() || !signals.mark_ready(shutdown) {
        Ok(false)
    } else {
        announce_ready(output)?;
        Ok(true)
    }
}

async fn close_state_store(
    signals: &mut ShutdownSignals,
    shutdown: &mut ShutdownState,
    store: StateStore,
) -> io::Result<()> {
    let close = run_state_phase(
        signals,
        shutdown,
        report_first_pending(store.close(), "state-close-pending"),
    )
    .await;
    signals.drain(shutdown);
    match (close, shutdown.terminal_error()) {
        (Ok(_), None) if signals.commit_clean_exit() => Ok(()),
        (Ok(_), None) => {
            signals.drain(shutdown);
            Err(shutdown
                .terminal_error()
                .unwrap_or_else(|| io::Error::other("shutdown escalation won the clean-exit race")))
        }
        (Ok(_), Some(shutdown)) => Err(shutdown),
        (Err(close), None) => Err(state_failure("state close", close)),
        (Err(close), Some(shutdown)) => Err(io::Error::other(format!(
            "state close failed: {close}; {shutdown}"
        ))),
    }
}

async fn close_state_store_after_failure(
    signals: &mut ShutdownSignals,
    shutdown: &mut ShutdownState,
    store: StateStore,
    operation: &'static str,
    primary: impl std::fmt::Display,
) -> io::Error {
    let primary = state_failure(operation, primary);
    match close_state_store(signals, shutdown, store).await {
        Ok(()) => primary,
        Err(close) => io::Error::other(format!("{primary}; {close}")),
    }
}

async fn await_state_shutdown(
    signals: &mut ShutdownSignals,
    shutdown: &mut ShutdownState,
    control: impl tokio::io::AsyncRead + Unpin,
) {
    let control = await_control(control);
    tokio::pin!(control);
    tokio::select! {
        biased;
        signal = signals.wait() => observe_shutdown(shutdown, signal),
        trigger = &mut control => {
            match trigger {
                Some(StopTrigger::Control) => observe_control_shutdown(shutdown),
                Some(_) => unreachable!("the control channel only produces control shutdowns"),
                None => observe_shutdown(shutdown, signals.wait().await),
            }
        }
    }
}

fn dirty_shutdown(summary: &StopSummary) -> Option<io::Error> {
    (!summary.is_clean()).then(|| {
        io::Error::other(format!(
            "shutdown left work behind: {} abandoned, {} of {} tasks joined",
            summary.shutdown().abandoned(),
            summary.tasks().terminated(),
            summary.tasks().spawned(),
        ))
    })
}

async fn finish_state_run(
    daemon: &mut Daemon,
    store: StateStore,
    signals: &mut ShutdownSignals,
    shutdown: &mut ShutdownState,
    mut failure: Option<io::Error>,
) -> io::Result<()> {
    match run_state_phase(signals, shutdown, daemon.stop()).await {
        Ok(summary) => {
            if let Some(error) = dirty_shutdown(&summary) {
                append_failure(&mut failure, error);
            }
        }
        Err(error) => append_failure(
            &mut failure,
            io::Error::other(format!("daemon stop failed: {error}")),
        ),
    }

    if let Err(error) = close_state_store(signals, shutdown, store).await {
        append_failure(&mut failure, error);
    }

    match failure {
        Some(error) => Err(error),
        None => Ok(()),
    }
}

async fn finish_failed_start(
    daemon: &Daemon,
    store: StateStore,
    signals: &mut ShutdownSignals,
    shutdown: &mut ShutdownState,
    start: impl std::fmt::Display,
) -> io::Error {
    let mut failure = Some(state_failure("daemon start", start));
    let tasks = run_state_phase(signals, shutdown, daemon.runtime().shutdown()).await;
    if !tasks.is_settled() {
        append_failure(
            &mut failure,
            io::Error::other(format!(
                "daemon start cleanup left {} of {} tasks unjoined",
                tasks.spawned().saturating_sub(tasks.terminated()),
                tasks.spawned(),
            )),
        );
    }
    if let Err(error) = close_state_store(signals, shutdown, store).await {
        append_failure(&mut failure, error);
    }
    failure.expect("the start failure is always retained")
}

async fn serve_with_state(
    selection: &StateSelection,
    mut output: impl Write,
    control: impl tokio::io::AsyncRead + Unpin,
) -> io::Result<()> {
    let mut signals = ShutdownSignals::new()?;
    let mut shutdown = ShutdownState::default();
    let opened = run_state_phase(
        &mut signals,
        &mut shutdown,
        report_first_pending(StateStore::open(selection.config()), "state-open-pending"),
    )
    .await;
    let store = opened.map_err(|error| {
        let primary = state_failure("state open", error);
        shutdown.combine(primary)
    })?;

    if shutdown.requested() {
        return close_state_store(&mut signals, &mut shutdown, store).await;
    }

    let health = run_state_phase(&mut signals, &mut shutdown, store.health()).await;
    let report = match health {
        Ok(report) => report,
        Err(error) => {
            return Err(close_state_store_after_failure(
                &mut signals,
                &mut shutdown,
                store,
                "state health",
                error,
            )
            .await);
        }
    };
    if !report.is_healthy() {
        return Err(close_state_store_after_failure(
            &mut signals,
            &mut shutdown,
            store,
            "state health",
            "database is not ready",
        )
        .await);
    }
    if shutdown.requested() {
        return close_state_store(&mut signals, &mut shutdown, store).await;
    }

    let mut daemon = match Daemon::builder().build() {
        Ok(daemon) => daemon,
        Err(error) => {
            return Err(close_state_store_after_failure(
                &mut signals,
                &mut shutdown,
                store,
                "daemon composition",
                error,
            )
            .await);
        }
    };
    if let Err(error) = run_state_phase(&mut signals, &mut shutdown, daemon.start()).await {
        return Err(finish_failed_start(&daemon, store, &mut signals, &mut shutdown, error).await);
    }
    if shutdown.requested() {
        return finish_state_run(&mut daemon, store, &mut signals, &mut shutdown, None).await;
    }

    match announce_readiness_or_shutdown(&mut signals, &mut shutdown, &mut output).await {
        Ok(true) => {}
        Ok(false) => {
            return finish_state_run(&mut daemon, store, &mut signals, &mut shutdown, None).await;
        }
        Err(error) => {
            return finish_state_run(
                &mut daemon,
                store,
                &mut signals,
                &mut shutdown,
                Some(state_failure("announce daemon readiness", error)),
            )
            .await;
        }
    }

    signals.drain(&mut shutdown);
    if shutdown.requested() {
        return finish_state_run(&mut daemon, store, &mut signals, &mut shutdown, None).await;
    }
    if let Err(error) = notify_systemd_ready() {
        return finish_state_run(
            &mut daemon,
            store,
            &mut signals,
            &mut shutdown,
            Some(state_failure("notify systemd readiness", error)),
        )
        .await;
    }
    signals.drain(&mut shutdown);
    if !shutdown.requested() {
        await_state_shutdown(&mut signals, &mut shutdown, control).await;
    }

    finish_state_run(&mut daemon, store, &mut signals, &mut shutdown, None).await
}

/// Parses and executes one daemon command.
///
/// The default and `--probe` paths retain the composition-root behavior. An
/// explicit state profile wraps that same serving composition in the audited
/// state open, health, lifetime-lock, and close protocol.
///
/// # Errors
///
/// Returns command-line, state, composition, lifecycle, or output failures.
pub fn run<I, S>(arguments: I, mut output: impl Write) -> Result<(), Box<dyn std::error::Error>>
where
    I: IntoIterator<Item = S>,
    S: Into<String>,
{
    let command = parse_command(arguments)?;
    match command.mode {
        DaemonMode::Serve => {
            let runtime = daemon_runtime()?;
            if let Some(selection) = &command.state {
                runtime.block_on(async {
                    serve_with_state(selection, &mut output, tokio::io::stdin()).await
                })?;
            } else {
                let summary =
                    runtime.block_on(async { serve(&mut output, tokio::io::stdin()).await })?;
                if let Some(error) = dirty_shutdown(&summary) {
                    return Err(Box::new(error));
                }
            }
        }
        DaemonMode::Probe => {
            if let Some(selection) = &command.state {
                daemon_runtime()?.block_on(probe_with_state(selection, &mut output))?;
            } else {
                probe(&mut output)?;
            }
        }
        DaemonMode::ProvisionLinuxProtected => {
            let namespace = command
                .initialize_namespace
                .expect("validated provisioning namespace");
            let service_uid = command.service_uid.expect("validated service UID");
            let service_gid = command.service_gid.expect("validated service GID");
            provision_linux_protected_offline(namespace, service_uid, service_gid)?;
            writeln!(output, "Provisioned")?;
            output.flush()?;
        }
        DaemonMode::InitializeLinuxProtected => {
            let namespace = command
                .initialize_namespace
                .expect("validated initializer namespace");
            let service_uid = command.service_uid.expect("validated service UID");
            let service_gid = command.service_gid.expect("validated service GID");
            let result = initialize_linux_protected_offline(namespace, service_uid, service_gid)?;
            writeln!(output, "{result:?}")?;
            output.flush()?;
        }
        DaemonMode::PrepareLinuxProtected => {
            let namespace = command
                .initialize_namespace
                .expect("validated preparation namespace");
            let service_uid = command.service_uid.expect("validated service UID");
            let service_gid = command.service_gid.expect("validated service GID");
            let result = prepare_linux_protected_offline(namespace, service_uid, service_gid)?;
            writeln!(output, "{result:?}")?;
            output.flush()?;
        }
        DaemonMode::Help => {
            writeln!(output, "{HELP}")?;
            output.flush()?;
        }
    }

    Ok(())
}

fn daemon_runtime() -> io::Result<tokio::runtime::Runtime> {
    tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .map_err(|error| io::Error::other(format!("create daemon runtime failed: {error}")))
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    #[cfg(target_os = "linux")]
    use super::notify_systemd_ready_to;
    use super::{
        DaemonMode, HELP, LEGACY_USAGE, RequestedStateProfile, SHUTDOWN_COMMAND, StopSignals,
        StopTrigger, await_control, await_stop, parse_command, parse_mode, probe, run,
    };

    #[test]
    fn normal_mode_is_persistent_and_probe_is_explicit() {
        assert_eq!(
            parse_mode(std::iter::empty::<String>()).expect("default mode"),
            DaemonMode::Serve
        );
        assert_eq!(
            parse_mode(["--probe"]).expect("probe mode"),
            DaemonMode::Probe
        );
    }

    #[test]
    fn unsupported_arguments_are_rejected() {
        let error = parse_mode(["--serve"]).expect_err("unknown mode must fail");

        assert_eq!(error.kind(), std::io::ErrorKind::InvalidInput);
        assert_eq!(error.to_string(), LEGACY_USAGE);
    }

    #[test]
    fn explicit_state_profiles_require_one_absolute_path() {
        let root = if cfg!(windows) { r"C:\state" } else { "/state" };
        let portable = parse_command([
            "--probe",
            "--state-profile",
            "portable-private",
            "--state-path",
            root,
        ])
        .expect("portable probe parses");
        assert_eq!(
            portable.state.expect("portable state").profile,
            RequestedStateProfile::PortablePrivate
        );
        let protected = parse_command(["--state-profile", "linux-protected", "--state-path", root])
            .expect("protected serve parses");
        assert_eq!(
            protected.state.expect("protected state").profile,
            RequestedStateProfile::LinuxProtected
        );

        for arguments in [
            vec!["--state-profile", "portable-private"],
            vec!["--state-path", root],
            vec![
                "--state-profile",
                "portable-private",
                "--state-path",
                "relative",
            ],
            vec![
                "--state-profile",
                "portable-private",
                "--state-profile",
                "portable-private",
                "--state-path",
                root,
            ],
            vec![
                "--state-profile",
                "portable-private",
                "--state-path",
                root,
                "--state-path",
                root,
            ],
        ] {
            assert!(parse_command(arguments).is_err());
        }
    }

    #[test]
    fn privileged_state_modes_require_nonzero_identity_and_have_no_conflicts() {
        let root = if cfg!(windows) { r"C:\state" } else { "/state" };
        for (flag, mode) in [
            (
                "--provision-linux-protected",
                DaemonMode::ProvisionLinuxProtected,
            ),
            (
                "--initialize-linux-protected",
                DaemonMode::InitializeLinuxProtected,
            ),
            (
                "--prepare-linux-protected",
                DaemonMode::PrepareLinuxProtected,
            ),
        ] {
            let command = parse_command([
                flag,
                "--state-profile",
                "linux-protected",
                "--state-path",
                root,
                "--service-uid",
                "1001",
                "--service-gid",
                "1002",
            ])
            .expect("privileged state mode parses");
            assert_eq!(command.mode, mode);
        }

        for arguments in [
            vec![
                "--initialize-linux-protected",
                "--probe",
                "--state-path",
                root,
                "--service-uid",
                "1001",
                "--service-gid",
                "1002",
            ],
            vec![
                "--initialize-linux-protected",
                "--state-profile",
                "portable-private",
                "--state-path",
                root,
                "--service-uid",
                "1001",
                "--service-gid",
                "1002",
            ],
            vec![
                "--initialize-linux-protected",
                "--prepare-linux-protected",
                "--state-path",
                root,
                "--service-uid",
                "1001",
                "--service-gid",
                "1002",
            ],
            vec![
                "--provision-linux-protected",
                "--state-path",
                root,
                "--service-uid",
                "0",
                "--service-gid",
                "1002",
            ],
            vec![
                "--initialize-linux-protected",
                "--state-path",
                root,
                "--service-uid",
                "1001",
            ],
        ] {
            assert!(parse_command(arguments).is_err());
        }
    }

    #[test]
    fn help_and_legacy_unknown_argument_diagnostics_are_stable() {
        let mut output = Vec::new();
        run(["--help"], &mut output).expect("help succeeds");
        assert_eq!(
            String::from_utf8(output).expect("help is UTF-8"),
            format!("{HELP}\n")
        );

        let error = parse_command(["--serve"]).expect_err("unknown mode must fail");
        assert_eq!(error.kind(), std::io::ErrorKind::InvalidInput);
        assert_eq!(error.to_string(), LEGACY_USAGE);
    }

    #[test]
    fn a_probe_emits_health_and_nothing_else() {
        let mut output = Vec::new();

        probe(&mut output).expect("the probe succeeds");

        let text = String::from_utf8(output).expect("output is UTF-8");
        let lines: Vec<&str> = text.lines().collect();

        assert_eq!(lines.len(), 1);
        assert!(lines[0].starts_with("healthy runtime="));
    }

    #[tokio::test]
    async fn the_control_channel_stops_the_run_on_the_shutdown_word() {
        let input = format!("status\n{SHUTDOWN_COMMAND}\nignored\n");

        let trigger = await_control(input.as_bytes()).await;

        assert_eq!(trigger, Some(StopTrigger::Control));
    }

    #[tokio::test]
    async fn the_shutdown_word_is_matched_without_regard_to_case_or_padding() {
        let trigger = await_control("  ShUtDoWn  \n".as_bytes()).await;

        assert_eq!(trigger, Some(StopTrigger::Control));
    }

    #[tokio::test]
    async fn a_control_channel_that_ends_is_not_a_stop() {
        let trigger =
            tokio::time::timeout(Duration::from_secs(1), await_control("status\n".as_bytes()))
                .await
                .expect("reading a finite channel terminates");

        assert_eq!(trigger, None);
    }

    #[test]
    fn every_stop_reason_is_reported_differently() {
        assert_eq!(StopTrigger::Terminate.label(), "terminate");
        assert_eq!(StopTrigger::Interrupt.label(), "interrupt");
        assert_eq!(StopTrigger::Control.label(), "control");

        let labels = [
            StopTrigger::Terminate.label(),
            StopTrigger::Interrupt.label(),
            StopTrigger::Control.label(),
        ];
        let mut unique = labels.to_vec();
        unique.sort_unstable();
        unique.dedup();
        assert_eq!(
            unique.len(),
            labels.len(),
            "two stop reasons share a label, so a supervisor cannot tell them apart"
        );

        assert_ne!(StopTrigger::Terminate, StopTrigger::Interrupt);
        assert_ne!(StopTrigger::Terminate, StopTrigger::Control);
        assert_ne!(StopTrigger::Interrupt, StopTrigger::Control);
    }

    /// A supervisor stop must not be reported as an interactive interrupt.
    ///
    /// `systemd`, `docker stop` and `kubectl delete` all send `SIGTERM`, so
    /// collapsing it onto `interrupt` would make the packaged service's stop
    /// reason indistinguishable from a developer pressing Ctrl-C.
    #[test]
    fn a_supervisor_termination_is_not_labelled_as_an_interrupt() {
        assert_ne!(
            StopTrigger::Terminate.label(),
            StopTrigger::Interrupt.label()
        );
    }

    /// Installing the handlers must succeed before the daemon claims readiness.
    ///
    /// Runs on a current-thread runtime because the handlers are registered
    /// against the runtime's signal driver, which is what `serve` does too.
    #[tokio::test]
    async fn the_stop_signal_handlers_install_on_this_platform() {
        let signals = StopSignals::install().expect("stop-signal handlers install");

        drop(signals);
    }

    /// The control channel must still win when no signal arrives.
    ///
    /// Guards the `select!` rewrite: if the signal arm resolved eagerly rather
    /// than parking, this would report a signal reason instead of `control`.
    #[tokio::test]
    async fn a_control_shutdown_still_stops_when_no_signal_arrives() {
        let mut signals = StopSignals::install().expect("stop-signal handlers install");

        let trigger = tokio::time::timeout(
            Duration::from_secs(5),
            await_stop(&mut signals, "shutdown\n".as_bytes()),
        )
        .await
        .expect("the control channel resolves the stop");

        assert_eq!(trigger, StopTrigger::Control);
    }

    /// An idle control channel and no signal must not resolve to anything.
    ///
    /// The positive control above proves this fixture *can* report a stop, so a
    /// timeout here means "nothing stopped it", not "the fixture is inert".
    #[tokio::test]
    async fn neither_an_ended_channel_nor_silence_stops_the_daemon() {
        let mut signals = StopSignals::install().expect("stop-signal handlers install");

        let outcome = tokio::time::timeout(
            Duration::from_millis(250),
            await_stop(&mut signals, "status\n".as_bytes()),
        )
        .await;

        assert!(
            outcome.is_err(),
            "the daemon stopped for {outcome:?} without a signal or a shutdown line"
        );
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn systemd_readiness_uses_the_configured_notify_socket() {
        use std::os::linux::net::SocketAddrExt as _;
        use std::os::unix::net::{SocketAddr, UnixDatagram};

        let name = format!(
            "gta-claw-notify-{}-{}",
            std::process::id(),
            std::thread::current().name().unwrap_or("unnamed")
        );
        let address =
            SocketAddr::from_abstract_name(name.as_bytes()).expect("create readiness address");
        let receiver = UnixDatagram::bind_addr(&address).expect("bind readiness receiver");
        receiver
            .set_read_timeout(Some(Duration::from_secs(2)))
            .expect("bound readiness timeout");

        let socket_name = std::ffi::OsString::from(format!("@{name}"));
        notify_systemd_ready_to(&socket_name).expect("send readiness notification");

        let mut buffer = [0_u8; 32];
        let bytes = receiver.recv(&mut buffer).expect("receive readiness");
        assert_eq!(&buffer[..bytes], b"READY=1");
    }
}

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

use claw_application::Application;
use claw_platform::NativeSystemProbe;
use tokio::io::{AsyncBufReadExt, BufReader, Lines};
use tokio_util::sync::CancellationToken;

use crate::compose::{Daemon, STOP_DEADLINE, StopSummary};
use crate::production::{
    LoadedConfig, ProductionOptions, ProductionService, ProductionStopSummary,
};

/// The control word that ends a run.
pub const SHUTDOWN_COMMAND: &str = "shutdown";

/// How the daemon was asked to run.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DaemonMode {
    /// Serve until told to stop.
    Serve,
    /// Report health once and exit.
    Probe,
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
/// default disposition.
///
/// # A second signal during the drain
///
/// The handlers stay installed for the rest of the process: tokio registers a
/// process-wide handler the first time a signal kind is asked for and never
/// removes it, so dropping this value only stops *this* code from being told.
/// A supervisor that loses patience and sends a second `SIGTERM` while the
/// drain is in progress therefore cannot kill the process — the signal is
/// delivered to a stream nobody is reading, the drain finishes, and the stop
/// summary is still printed. The bound on how long that can take is
/// [`STOP_DEADLINE`], not the operator's
/// patience.
pub struct StopSignals {
    #[cfg(unix)]
    terminate: tokio::signal::unix::Signal,
    #[cfg(unix)]
    interrupt: tokio::signal::unix::Signal,
    #[cfg(unix)]
    reload: tokio::signal::unix::Signal,
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
    /// Returns an [`io::Error`] when a handler cannot be installed — no signal
    /// driver on this runtime, or the process is out of the resources tokio
    /// needs to register one. Reporting it here rather than at stop time means
    /// the failure is visible before the daemon claims to be ready, so a
    /// supervisor sees a start-up failure instead of a process that looks
    /// healthy and then ignores `SIGTERM`. It is an environment fault, not a
    /// configuration one: a restart will reproduce it.
    #[cfg(unix)]
    pub fn install() -> io::Result<Self> {
        use tokio::signal::unix::{SignalKind, signal};

        Ok(Self {
            terminate: signal(SignalKind::terminate())?,
            interrupt: signal(SignalKind::interrupt())?,
            reload: signal(SignalKind::hangup())?,
        })
    }

    /// Installs the handlers.
    ///
    /// # Errors
    ///
    /// Returns an [`io::Error`] when a handler cannot be installed; see the
    /// unix documentation of this method for what an operator should conclude.
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
        loop {
            if let SignalEvent::Stop(trigger) = self.recv_event().await {
                return trigger;
            }
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

    /// Waits for a stop or reload signal.
    #[cfg(unix)]
    pub async fn recv_event(&mut self) -> SignalEvent {
        tokio::select! {
            Some(()) = self.terminate.recv() => SignalEvent::Stop(StopTrigger::Terminate),
            Some(()) = self.interrupt.recv() => SignalEvent::Stop(StopTrigger::Interrupt),
            Some(()) = self.reload.recv() => SignalEvent::Reload,
            else => std::future::pending().await,
        }
    }

    /// Waits for a stop signal on platforms without `SIGHUP`.
    #[cfg(windows)]
    pub async fn recv_event(&mut self) -> SignalEvent {
        SignalEvent::Stop(self.recv().await)
    }
}

/// One operating-system lifecycle event.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SignalEvent {
    /// Stop for the enclosed reason.
    Stop(StopTrigger),
    /// Reload the configured file.
    Reload,
}

#[derive(Debug)]
enum ControlEvent {
    Stop,
    Reload,
    Status,
    Ignored,
}

struct ControlChannel<R> {
    lines: Lines<BufReader<R>>,
    open: bool,
}

impl<R> ControlChannel<R>
where
    R: tokio::io::AsyncRead + Unpin,
{
    fn new(reader: R) -> Self {
        Self {
            lines: BufReader::new(reader).lines(),
            open: true,
        }
    }

    async fn recv(&mut self) -> ControlEvent {
        if !self.open {
            return std::future::pending().await;
        }
        match self.lines.next_line().await {
            Ok(Some(line)) if line.trim().eq_ignore_ascii_case(SHUTDOWN_COMMAND) => {
                ControlEvent::Stop
            }
            Ok(Some(line)) if line.trim().eq_ignore_ascii_case("reload") => ControlEvent::Reload,
            Ok(Some(line)) if line.trim().eq_ignore_ascii_case("status") => ControlEvent::Status,
            Ok(Some(_)) => ControlEvent::Ignored,
            Ok(None) | Err(_) => {
                self.open = false;
                std::future::pending().await
            }
        }
    }
}

/// Parses the command line.
///
/// # Errors
///
/// Returns an [`io::Error`] with kind [`io::ErrorKind::InvalidInput`] when the
/// arguments are not a supported combination — anything other than no arguments
/// at all or exactly `--probe`. The message is the usage line, and an operator
/// must fix the invocation: a restart will fail identically.
pub fn parse_mode<I, S>(arguments: I) -> io::Result<DaemonMode>
where
    I: IntoIterator<Item = S>,
    S: Into<String>,
{
    let mut arguments = arguments.into_iter().map(Into::into);
    let first = arguments.next();
    let second = arguments.next();

    match (first.as_deref(), second) {
        (None, None) => Ok(DaemonMode::Serve),
        (Some("--probe"), None) => Ok(DaemonMode::Probe),
        _ => Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "usage: gta-claw-daemon [--probe]",
        )),
    }
}

/// Writes the one-shot health line.
///
/// This is what `ExecStartPre` runs, so its exit status gates the service: a
/// failure here stops the unit before the real daemon is started.
///
/// # Errors
///
/// Returns an [`io::Error`] when the health line cannot be written or flushed,
/// which means the pipe the supervisor was reading has already been closed. The
/// probe itself cannot fail; nothing about the host is inspected that could be
/// unavailable.
pub fn probe(mut output: impl Write) -> io::Result<()> {
    let application = Application::new(NativeSystemProbe);

    writeln!(output, "{}", application.health())?;
    output.flush()?;
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
/// The stop itself is bounded by [`STOP_DEADLINE`], so this returns even when a
/// subsystem refuses to: an expired deadline comes back as a summary that is
/// not [`clean`](StopSummary::is_clean) rather than as a process that never
/// exits.
///
/// # Errors
///
/// Returns an error before the ready line when the run cannot start, which an
/// operator should read as "this will happen again on restart, fix it":
///
/// * a stop-signal handler that cannot be installed — an environment fault;
/// * a composition that cannot be built — a subsystem graph with a cycle or a
///   missing port, which is a defect in this binary rather than in the
///   deployment;
/// * a subsystem that refuses to start. Everything already brought up has been
///   torn down and every task it spawned has been joined before this returns.
///
/// Returns an error after the ready line only when the ready, health or summary
/// line cannot be written — a closed or full standard output, meaning the
/// supervisor that was reading it has gone away.
///
/// A shutdown that left work behind is *not* an error here: it is reported in
/// the returned summary, because the caller has to print that summary before
/// deciding what the exit status should be.
pub async fn serve(
    mut output: impl Write,
    control: impl tokio::io::AsyncRead + Unpin,
) -> Result<StopSummary, Box<dyn std::error::Error>> {
    // Installed before anything is started. A supervisor that stops the process
    // during startup is then still observed, instead of the signal reaching the
    // default disposition and killing the process mid-start with no drain.
    let mut signals = StopSignals::install()?;
    let application = Application::new(NativeSystemProbe);
    let mut daemon = Daemon::builder().build()?;

    if let Err(error) = daemon.start().await {
        // The subsystems that came up have been torn down by `start` itself,
        // but the tasks they spawned are this side's to account for: without
        // this they would be dropped by the runtime at process exit, which is
        // exactly the detached teardown the task ledger exists to rule out.
        daemon.runtime().shutdown_within(STOP_DEADLINE).await;

        return Err(Box::new(error));
    }

    writeln!(output, "{}", application.ready())?;
    writeln!(output, "{}", application.health())?;
    output.flush()?;

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

/// Runs the bound production service until a stop request or supervised fault.
///
/// Unlike [`serve`], this path owns real HTTP, MCP, and Gateway listeners. End
/// of file on the control channel still does not stop it, but it is not parked:
/// the ingress tasks remain supervised and an unexpected exit becomes a
/// non-clean process result.
///
/// # Errors
///
/// Returns a startup error before readiness when signal installation or service
/// composition fails. After readiness, returns an output error only after the
/// service has been drained.
pub async fn serve_production(
    mut output: impl Write,
    control: impl tokio::io::AsyncRead + Unpin,
    options: &ProductionOptions,
    loaded: LoadedConfig,
) -> Result<ProductionStopSummary, Box<dyn std::error::Error>> {
    let mut signals = StopSignals::install()?;
    let application = Application::new(NativeSystemProbe);
    let mut control = ControlChannel::new(control);
    let startup_cancellation = CancellationToken::new();
    let startup = ProductionService::start(options, loaded, startup_cancellation.clone());
    tokio::pin!(startup);
    let mut reload_deferred = false;
    let mut service = loop {
        enum StartupEvent<T> {
            Started(T),
            Signal(SignalEvent),
            Control(ControlEvent),
        }
        let event = tokio::select! {
            result = &mut startup => StartupEvent::Started(result),
            signal = signals.recv_event() => StartupEvent::Signal(signal),
            control = control.recv() => StartupEvent::Control(control),
        };
        match event {
            StartupEvent::Started(result) => break result?,
            StartupEvent::Signal(SignalEvent::Stop(trigger)) => {
                startup_cancellation.cancel();
                let summary = match startup.as_mut().await {
                    Ok(service) => service.stop(None).await,
                    Err(_) => ProductionStopSummary::before_start(),
                };
                write_production_stop(&mut output, trigger.label(), &summary)?;
                return Ok(summary);
            }
            StartupEvent::Control(ControlEvent::Stop) => {
                startup_cancellation.cancel();
                let summary = match startup.as_mut().await {
                    Ok(service) => service.stop(None).await,
                    Err(_) => ProductionStopSummary::before_start(),
                };
                write_production_stop(&mut output, StopTrigger::Control.label(), &summary)?;
                return Ok(summary);
            }
            StartupEvent::Signal(SignalEvent::Reload)
            | StartupEvent::Control(ControlEvent::Reload) => {
                reload_deferred = true;
                writeln!(output, "reload deferred phase=starting")?;
                output.flush()?;
            }
            StartupEvent::Control(ControlEvent::Status) => {
                writeln!(output, "status ready=false phase=starting")?;
                output.flush()?;
            }
            StartupEvent::Control(ControlEvent::Ignored) => {
                writeln!(output, "control ignored")?;
                output.flush()?;
            }
        }
    };
    if reload_deferred {
        let reload_write =
            writeln!(output, "{}", reload_line(&service).await).and_then(|()| output.flush());
        if let Err(error) = reload_write {
            let _ = service
                .stop(Some(format!("supervisor output failed: {error}")))
                .await;
            return Err(Box::new(error));
        }
    }
    let addresses = service.addresses();

    let startup_write = (|| -> io::Result<()> {
        writeln!(output, "{}", application.ready())?;
        writeln!(output, "{}", application.health())?;
        writeln!(
            output,
            "service http={} legacy={} gateway={} mcp={} provider={} config_generation={}",
            addresses.http,
            addresses.legacy,
            addresses.gateway,
            addresses.mcp,
            service.provider_name(),
            service.config_generation(),
        )?;
        output.flush()
    })();
    if let Err(error) = startup_write {
        let _ = service
            .stop(Some(format!("supervisor output failed: {error}")))
            .await;
        return Err(Box::new(error));
    }

    let (reason, fault) = loop {
        enum Event {
            Signal(SignalEvent),
            Control(ControlEvent),
            Fault(crate::production::ProductionError),
        }
        let event = tokio::select! {
            signal = signals.recv_event() => Event::Signal(signal),
            control = control.recv() => Event::Control(control),
            fault = service.wait_for_failure() => Event::Fault(fault),
        };
        match event {
            Event::Signal(SignalEvent::Stop(trigger)) => {
                break (trigger.label(), None);
            }
            Event::Control(ControlEvent::Stop) => {
                break (StopTrigger::Control.label(), None);
            }
            Event::Fault(error) => {
                break ("runtime", Some(error.to_string()));
            }
            Event::Signal(SignalEvent::Reload) | Event::Control(ControlEvent::Reload) => {
                let line = reload_line(&service).await;
                if let Err(error) = writeln!(output, "{line}").and_then(|()| output.flush()) {
                    break (
                        "runtime",
                        Some(format!("supervisor output failed: {error}")),
                    );
                }
            }
            Event::Control(ControlEvent::Status) => {
                if let Err(error) =
                    writeln!(output, "{}", service.status_line()).and_then(|()| output.flush())
                {
                    break (
                        "runtime",
                        Some(format!("supervisor output failed: {error}")),
                    );
                }
            }
            Event::Control(ControlEvent::Ignored) => {
                if let Err(error) =
                    writeln!(output, "control ignored").and_then(|()| output.flush())
                {
                    break (
                        "runtime",
                        Some(format!("supervisor output failed: {error}")),
                    );
                }
            }
        }
    };

    let summary = service.stop(fault).await;
    write_production_stop(&mut output, reason, &summary)?;
    Ok(summary)
}

async fn reload_line(service: &ProductionService) -> String {
    match service.reload().await {
        Ok(applied) => format!(
            "reloaded generation={} changed={}",
            applied.generation,
            if applied.changed.is_empty() {
                "none".to_owned()
            } else {
                applied.changed.join(",")
            }
        ),
        Err(error) => format!(
            "reload rejected generation={} reason={error}",
            service.config_generation()
        ),
    }
}

fn write_production_stop(
    output: &mut impl Write,
    reason: &str,
    summary: &ProductionStopSummary,
) -> io::Result<()> {
    writeln!(
        output,
        "stopped reason={} clean={} drained={} completed={} abandoned={} tasks={}/{}",
        reason,
        summary.is_clean(),
        summary.drained(),
        summary.completed(),
        summary.abandoned(),
        summary.terminated(),
        summary.spawned(),
    )?;
    output.flush()
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use super::{
        DaemonMode, SHUTDOWN_COMMAND, StopSignals, StopTrigger, await_control, await_stop,
        parse_mode, probe,
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
        let trigger = await_control(&b"  ShUtDoWn  \n"[..]).await;

        assert_eq!(trigger, Some(StopTrigger::Control));
    }

    #[tokio::test]
    async fn a_control_channel_that_ends_is_not_a_stop() {
        let trigger = tokio::time::timeout(Duration::from_secs(1), await_control(&b"status\n"[..]))
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
            await_stop(&mut signals, &b"shutdown\n"[..]),
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
            await_stop(&mut signals, &b"status\n"[..]),
        )
        .await;

        assert!(
            outcome.is_err(),
            "the daemon stopped for {outcome:?} without a signal or a shutdown line"
        );
    }
}

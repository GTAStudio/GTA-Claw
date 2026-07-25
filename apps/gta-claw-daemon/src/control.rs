//! Process-level control: argument parsing, the ready contract, and the two
//! ways a run ends.
//!
//! The daemon stops for exactly two reasons: an operating-system interrupt, or
//! an explicit `shutdown` line on the control channel. Reaching the end of the
//! control channel is *not* one of them — a daemon started with its standard
//! input closed must keep serving, which is what the process-lifecycle test
//! asserts.

use std::io::{self, Write};

use claw_application::Application;
use claw_platform::NativeSystemProbe;
use tokio::io::{AsyncBufReadExt, BufReader};

use crate::compose::{Daemon, StopSummary};

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
    /// An operating-system interrupt arrived.
    Interrupt,
    /// The control channel carried [`SHUTDOWN_COMMAND`].
    Control,
}

impl StopTrigger {
    /// Returns the word used when reporting the reason.
    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            Self::Interrupt => "interrupt",
            Self::Control => "control",
        }
    }
}

/// Parses the command line.
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
/// # Errors
///
/// Returns an [`io::Error`] when the output cannot be written.
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
/// # Errors
///
/// Returns an [`io::Error`] when the interrupt handler cannot be installed.
pub async fn await_stop(control: impl tokio::io::AsyncRead + Unpin) -> io::Result<StopTrigger> {
    let interrupt = tokio::signal::ctrl_c();

    tokio::select! {
        result = interrupt => {
            result?;
            Ok(StopTrigger::Interrupt)
        }
        trigger = await_control(control) => {
            match trigger {
                Some(trigger) => Ok(trigger),
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
/// Returns an error when the composition cannot be built or started, when the
/// stop signal cannot be awaited, or when the output cannot be written.
pub async fn serve(
    mut output: impl Write,
    control: impl tokio::io::AsyncRead + Unpin,
) -> Result<StopSummary, Box<dyn std::error::Error>> {
    let application = Application::new(NativeSystemProbe);
    let mut daemon = Daemon::builder().build()?;

    daemon.start().await?;

    writeln!(output, "{}", application.ready())?;
    writeln!(output, "{}", application.health())?;
    output.flush()?;

    let trigger = await_stop(control).await?;
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

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use super::{DaemonMode, SHUTDOWN_COMMAND, StopTrigger, await_control, parse_mode, probe};

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
    fn the_two_stop_reasons_are_reported_differently() {
        assert_eq!(StopTrigger::Interrupt.label(), "interrupt");
        assert_eq!(StopTrigger::Control.label(), "control");
        assert_ne!(StopTrigger::Interrupt, StopTrigger::Control);
    }
}

//! Headless GTA Claw daemon bootstrap.
//!
//! # What the exit status means to a supervisor
//!
//! * `0` — the run ended for a reason the operator asked for: a stop signal or
//!   a `shutdown` line on the control channel. Every subsystem drained and
//!   every spawned task was joined. Restarting is safe and nothing was lost.
//! * `1` before `ready protocol=1` is printed — start-up failed. The message on
//!   standard error names the stage: an argument that is not a supported
//!   combination and a composition that cannot be ordered are both operator
//!   errors that a restart will reproduce exactly, so fix the invocation rather
//!   than restarting. A stop-signal handler that cannot be installed is an
//!   environment fault of the same kind.
//! * `1` after the `stopped ...` line is printed — the daemon shut down but
//!   could not prove the shutdown was complete: work was abandoned, a task was
//!   not joined, or the stop deadline expired. The process has exited and a
//!   restart is safe, but the summary line names what was left behind and that
//!   is a defect in the subsystem it names, not a configuration mistake.
//!
//! The process never exits by signal: the handlers installed by
//! [`serve`](gta_claw_daemon::control::serve) turn `SIGTERM` and `SIGINT` into
//! a drain, so `137`/`143` from this binary would mean a supervisor lost
//! patience and sent `SIGKILL`.

use std::io;
use std::time::{Duration, Instant};

use claw_observability::TelemetryHandle;
use gta_claw_daemon::control::{
    SignalEvent, StopSignals, probe, report_pre_start_stop_with_deadline,
    serve_production_preinstalled_with_reload,
};
use gta_claw_daemon::production::{
    CommandLine, CommandMode, PRODUCTION_STOP_DEADLINE, USAGE, check_configuration, init_telemetry,
};
use gta_claw_daemon::runtime::BlockingTaskHost;

/// How long the process waits at exit for blocking work that cannot be
/// cancelled.
///
/// Dropping a tokio runtime waits for every blocking task, and the control
/// channel's read is one: `tokio::io::stdin` performs its reads on the blocking
/// pool, and a read parked on a pipe that a supervisor holds open never
/// returns. Waiting for it would hang the process *after* a clean drain, with
/// the stop summary already printed — the exact failure the drain exists to
/// avoid. This bounds that wait instead.
const BLOCKING_TEARDOWN_GRACE: Duration = Duration::from_millis(250);

async fn shutdown_pre_start_telemetry(
    blocking: &BlockingTaskHost,
    telemetry: Option<TelemetryHandle>,
    budget: Duration,
) -> &'static str {
    let Some(telemetry) = telemetry else {
        return "not-configured";
    };
    let shutdown = blocking.run("telemetry-shutdown", move || {
        let shutdown = telemetry.shutdown().map_err(|error| error.to_string());
        let writer = telemetry
            .take_writer_failure()
            .map_err(|error| error.to_string())?;
        shutdown?;
        if let Some(error) = writer {
            return Err(error.to_string());
        }
        Ok::<(), String>(())
    });
    match tokio::time::timeout(budget, shutdown).await {
        Ok(Ok(Ok(()))) => "clean",
        Ok(Ok(Err(_)) | Err(_)) | Err(_) => "failed",
    }
}

fn main() -> std::process::ExitCode {
    // Parsed before the runtime exists. Answering `--help` must not depend on
    // being able to start a thread pool, and a rejected command line should not
    // pay for one either.
    let command = match CommandLine::parse(std::env::args_os().skip(1)) {
        Ok(command) => command,
        Err(error) => {
            eprintln!("gta-claw-daemon: {error}");
            return std::process::ExitCode::FAILURE;
        }
    };

    if command.mode == CommandMode::Help {
        println!("{USAGE}");
        return std::process::ExitCode::SUCCESS;
    }

    // Built by hand rather than with `#[tokio::main]` so that the runtime is
    // still owned here after `run` returns, which is what makes the bounded
    // teardown below possible.
    let runtime = match tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
    {
        Ok(runtime) => runtime,
        Err(error) => {
            eprintln!("gta-claw-daemon: {error}");
            return std::process::ExitCode::FAILURE;
        }
    };

    let outcome = runtime.block_on(run(command));

    runtime.shutdown_timeout(BLOCKING_TEARDOWN_GRACE);

    // Returning `Result` from `main` would report the error with `Debug`, which
    // prints the wrapper struct around the message instead of the message the
    // module contract promises on standard error.
    match outcome {
        Ok(()) => std::process::ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("gta-claw-daemon: {error}");
            std::process::ExitCode::FAILURE
        }
    }
}

#[allow(clippy::future_not_send)] // The process owns this future on `Runtime::block_on`.
async fn run(command: CommandLine) -> Result<(), Box<dyn std::error::Error>> {
    match command.mode {
        // Answered in `main` before the runtime is built.
        CommandMode::Help => {}
        CommandMode::Probe => {
            probe(io::stdout().lock())?;
        }
        CommandMode::CheckConfig => {
            let blocking = BlockingTaskHost::new(2);
            let loaded = command.options.load_config_owned(&blocking).await?;
            let options = command.options.clone();
            let checked = loaded.clone();
            blocking
                .run("config-check", move || {
                    check_configuration(&options, &checked)
                })
                .await??;
            let ledger = blocking.shutdown_within(PRODUCTION_STOP_DEADLINE).await;
            if !ledger.is_settled() {
                return Err(Box::new(io::Error::other(format!(
                    "configuration check left blocking work behind: {} of {} tasks joined",
                    ledger.terminated(),
                    ledger.spawned(),
                ))));
            }
            println!("configuration valid source={}", loaded.source);
        }
        CommandMode::Serve => {
            // Installed before configuration, credential, telemetry, or state
            // filesystem work. A stop received during any of those stages is
            // queued by Tokio instead of taking the process's default action.
            let mut signals = StopSignals::install()?;
            let mut reload_deferred = false;
            let blocking = BlockingTaskHost::new(4);
            let config_blocking = blocking.clone();
            let config = command.options.load_config_owned(&config_blocking);
            tokio::pin!(config);
            let loaded = loop {
                tokio::select! {
                    loaded = &mut config => break loaded?,
                    event = signals.recv_event() => match event {
                        SignalEvent::Reload => reload_deferred = true,
                        SignalEvent::Stop(trigger) => {
                            let deadline = Instant::now() + PRODUCTION_STOP_DEADLINE;
                            blocking.request_stop();
                            let ledger = blocking
                                .shutdown_within(
                                    deadline.saturating_duration_since(Instant::now()),
                                )
                                .await;
                            let summary = report_pre_start_stop_with_deadline(
                                io::stdout(),
                                trigger,
                                ledger,
                                "not-configured",
                                Instant::now() >= deadline,
                            )
                            .await?;
                            if summary.is_clean() {
                                return Ok(());
                            }
                            return Err(Box::new(io::Error::other(format!(
                                "startup cancellation left work behind: {} of {} tasks joined",
                                summary.terminated(),
                                summary.spawned(),
                            ))));
                        }
                    },
                }
            };
            let snapshot = loaded.snapshot.clone();
            let log_file = command.options.log_file.clone();
            let telemetry_blocking = blocking.clone();
            let telemetry = telemetry_blocking.run("telemetry-init", move || {
                init_telemetry(&snapshot, log_file.as_deref())
            });
            tokio::pin!(telemetry);
            let telemetry = loop {
                tokio::select! {
                    telemetry = &mut telemetry => break telemetry??,
                    event = signals.recv_event() => match event {
                        SignalEvent::Reload => reload_deferred = true,
                        SignalEvent::Stop(trigger) => {
                            let deadline = Instant::now() + PRODUCTION_STOP_DEADLINE;
                            let telemetry = tokio::time::timeout(
                                deadline.saturating_duration_since(Instant::now()),
                                &mut telemetry,
                            )
                            .await;
                            let (telemetry, outcome) = match telemetry {
                                Ok(Ok(Ok(telemetry))) => (Some(telemetry), "pending"),
                                Ok(Ok(Err(_)) | Err(_)) | Err(_) => (None, "failed"),
                            };
                            let outcome = if telemetry.is_some() {
                                shutdown_pre_start_telemetry(
                                    &blocking,
                                    telemetry,
                                    deadline.saturating_duration_since(Instant::now()),
                                )
                                .await
                            } else {
                                outcome
                            };
                            blocking.request_stop();
                            let ledger = blocking
                                .shutdown_within(
                                    deadline.saturating_duration_since(Instant::now()),
                                )
                                .await;
                            let summary = report_pre_start_stop_with_deadline(
                                io::stdout(),
                                trigger,
                                ledger,
                                outcome,
                                Instant::now() >= deadline,
                            )
                            .await?;
                            if summary.is_clean() {
                                return Ok(());
                            }
                            return Err(Box::new(io::Error::other(format!(
                                "startup cancellation left work behind: {} of {} tasks joined",
                                summary.terminated(),
                                summary.spawned(),
                            ))));
                        }
                    },
                }
            };
            // `stdout()`, not `stdout().lock()`: a lock taken here would be held
            // for the whole run, so any other thread that printed would block
            // until the daemon exited. Each `writeln!` takes the lock for the
            // length of one line instead, and this daemon has one writer.
            let service = serve_production_preinstalled_with_reload(
                io::stdout(),
                tokio::io::stdin(),
                &command.options,
                loaded,
                signals,
                blocking,
                Some(telemetry),
                reload_deferred,
            )
            .await;
            let mut failures = Vec::new();

            match service {
                Ok(summary) if !summary.is_clean() => {
                    failures.push(summary.fault().map_or_else(
                        || {
                            if summary.deadline_expired() {
                                format!(
                                    "shutdown did not finish within its deadline: {} of {} service tasks joined",
                                    summary.terminated(),
                                    summary.spawned(),
                                )
                            } else {
                                format!(
                                    "shutdown left work behind: {} abandoned, {} of {} tasks joined",
                                    summary.abandoned(),
                                    summary.terminated(),
                                    summary.spawned(),
                                )
                            }
                        },
                        |fault| format!("runtime supervision failed: {fault}"),
                    ));
                }
                Ok(_) => {}
                Err(error) => failures.push(format!("service failed: {error}")),
            }
            failures.sort_unstable();
            failures.dedup();
            if !failures.is_empty() {
                return Err(Box::new(io::Error::other(failures.join("; "))));
            }
        }
    }

    Ok(())
}

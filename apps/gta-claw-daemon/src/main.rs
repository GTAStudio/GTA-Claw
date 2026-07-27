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
use std::time::Duration;

use gta_claw_daemon::control::{DaemonMode, parse_mode, probe, serve};

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

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Built by hand rather than with `#[tokio::main]` so that the runtime is
    // still owned here after `run` returns, which is what makes the bounded
    // teardown below possible.
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()?;

    let outcome = runtime.block_on(run());

    runtime.shutdown_timeout(BLOCKING_TEARDOWN_GRACE);

    outcome
}

async fn run() -> Result<(), Box<dyn std::error::Error>> {
    // `args_os`, not `args`: the latter panics part way through iteration when
    // an argument is not valid Unicode, which would turn a mistyped invocation
    // into a panic instead of the usage error below. Nothing this daemon
    // accepts is non-Unicode, so a lossy conversion cannot swallow a valid
    // argument — it can only fail to match one that was never valid.
    let arguments = std::env::args_os()
        .skip(1)
        .map(|argument| argument.to_string_lossy().into_owned());

    match parse_mode(arguments)? {
        DaemonMode::Probe => {
            probe(io::stdout().lock())?;
        }
        DaemonMode::Serve => {
            // `stdout()`, not `stdout().lock()`: a lock taken here would be held
            // for the whole run, so any other thread that printed would block
            // until the daemon exited. Each `writeln!` takes the lock for the
            // length of one line instead, and this daemon has one writer.
            let summary = serve(io::stdout(), tokio::io::stdin()).await?;

            if !summary.is_clean() {
                let error = if summary.deadline_expired() {
                    io::Error::other(format!(
                        "shutdown did not finish within its deadline: the composition is {:?}, {} of {} tasks joined",
                        summary.phase(),
                        summary.tasks().terminated(),
                        summary.tasks().spawned(),
                    ))
                } else {
                    io::Error::other(format!(
                        "shutdown left work behind: {} abandoned, {} of {} tasks joined",
                        summary.shutdown().abandoned(),
                        summary.tasks().terminated(),
                        summary.tasks().spawned(),
                    ))
                };

                return Err(Box::<dyn std::error::Error>::from(error));
            }
        }
    }

    Ok(())
}

//! GTA Claw command-line process entry point.

use std::ffi::OsString;
use std::process::ExitCode;
use std::time::Duration;

const RUNTIME_SHUTDOWN_TIMEOUT: Duration = Duration::from_millis(250);

fn main() -> ExitCode {
    run_process(std::env::args_os().skip(1), |_| {})
}

fn run_process(
    arguments: impl IntoIterator<Item = OsString>,
    initialize: impl FnOnce(&tokio::runtime::Runtime),
) -> ExitCode {
    let runtime = match tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
    {
        Ok(runtime) => runtime,
        Err(_) => {
            eprintln!("error: could not initialize the async runtime");
            return ExitCode::from(8);
        }
    };
    initialize(&runtime);
    let exit_code = runtime.block_on(gta_claw_cli::entrypoint(arguments));
    runtime.shutdown_timeout(RUNTIME_SHUTDOWN_TIMEOUT);
    exit_code
}

#[cfg(test)]
mod tests {
    use std::process::{Command, Stdio};
    use std::time::{Duration, Instant};

    use super::run_process;

    #[test]
    fn bounded_runtime_teardown_exits_a_subprocess_with_stuck_blocking_work() {
        let mut child = Command::new(std::env::current_exe().expect("test executable"))
            .args([
                "--ignored",
                "--exact",
                "tests::stuck_blocking_work_subprocess_helper",
            ])
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .expect("helper process starts");
        let started = Instant::now();
        loop {
            if let Some(status) = child.try_wait().expect("helper process status") {
                assert!(status.success());
                assert!(started.elapsed() < Duration::from_secs(2));
                break;
            }
            if started.elapsed() >= Duration::from_secs(2) {
                child.kill().expect("terminate hung helper");
                panic!("runtime teardown exceeded its process bound");
            }
            std::thread::sleep(Duration::from_millis(10));
        }
    }

    #[test]
    #[ignore = "subprocess helper for bounded runtime teardown"]
    fn stuck_blocking_work_subprocess_helper() {
        let exit = run_process(["health".into()], |runtime| {
            runtime.spawn_blocking(|| {
                loop {
                    std::thread::park();
                }
            });
        });
        assert_eq!(exit, std::process::ExitCode::SUCCESS);
    }
}

//! GTA Claw command-line process entry point.

use std::process::ExitCode;

fn main() -> ExitCode {
    gta_claw_cli::run_process(std::env::args_os().skip(1))
}

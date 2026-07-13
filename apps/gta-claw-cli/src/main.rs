//! GTA Claw command-line process entry point.

use std::process::ExitCode;

#[tokio::main]
async fn main() -> ExitCode {
    gta_claw_cli::entrypoint(std::env::args_os().skip(1)).await
}

//! Headless GTA Claw daemon bootstrap.

use std::io;

use gta_claw_daemon::control::{DaemonMode, parse_mode, probe, serve};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    match parse_mode(std::env::args().skip(1))? {
        DaemonMode::Probe => {
            probe(io::stdout().lock())?;
        }
        DaemonMode::Serve => {
            let summary = serve(io::stdout().lock(), tokio::io::stdin()).await?;

            if !summary.is_clean() {
                let error = io::Error::other(format!(
                    "shutdown left work behind: {} abandoned, {} of {} tasks joined",
                    summary.shutdown().abandoned(),
                    summary.tasks().terminated(),
                    summary.tasks().spawned(),
                ));

                return Err(Box::<dyn std::error::Error>::from(error));
            }
        }
    }

    Ok(())
}

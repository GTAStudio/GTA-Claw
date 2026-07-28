//! GTA Claw terminal executable.

use std::process::ExitCode;

use gta_claw_tui::{Options, run};

fn main() -> ExitCode {
    let options = match Options::parse(std::env::args_os()) {
        Ok(options) => options,
        Err(message) => {
            // Requested help is not an error: it belongs on stdout so it can be
            // piped into a pager or grep like every other tool's help.
            if message.starts_with("Usage:") {
                println!("{message}");
                return ExitCode::SUCCESS;
            }
            eprintln!("{message}");
            return ExitCode::from(2);
        }
    };
    let runtime = match tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .thread_name("gta-claw-tui")
        .build()
    {
        Ok(runtime) => runtime,
        Err(error) => {
            eprintln!("failed to start async runtime: {error}");
            return ExitCode::FAILURE;
        }
    };
    match runtime.block_on(run(options)) {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            gta_claw_tui::terminal::best_effort_restore();
            eprintln!("gta-claw-tui: {error}");
            ExitCode::FAILURE
        }
    }
}

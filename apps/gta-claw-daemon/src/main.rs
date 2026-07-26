//! Headless GTA Claw daemon composition bootstrap.

use gta_claw_daemon::control::run;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    run(std::env::args().skip(1), std::io::stdout().lock())
}

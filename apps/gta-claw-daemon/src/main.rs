//! Headless GTA Claw daemon bootstrap.

use std::io::{self, Write};

use claw_application::Application;
use claw_platform::NativeSystemProbe;
use claw_protocol::ClientCommand;

fn run(mut output: impl Write) -> Result<(), Box<dyn std::error::Error>> {
    let application = Application::new(NativeSystemProbe);

    writeln!(output, "{}", application.ready())?;
    writeln!(output, "{}", application.handle(ClientCommand::Health)?)?;
    Ok(())
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    run(io::stdout().lock())
}

#[cfg(test)]
mod tests {
    use super::run;

    #[test]
    fn daemon_bootstrap_emits_ready_and_health_events() {
        let mut output = Vec::new();

        run(&mut output).expect("daemon bootstrap succeeds");

        let output = String::from_utf8(output).expect("output is UTF-8");
        assert!(output.starts_with("ready protocol=1\nhealthy runtime="));
    }
}

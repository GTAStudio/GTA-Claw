//! Command-line adapter for the headless GTA Claw application.

use std::io::{self, Write};

use claw_application::Application;
use claw_platform::NativeSystemProbe;
use claw_protocol::parse_command;

fn run<I, S>(arguments: I, mut output: impl Write) -> Result<(), Box<dyn std::error::Error>>
where
    I: IntoIterator<Item = S>,
    S: Into<String>,
{
    let command = parse_command(arguments)?;
    let application = Application::new(NativeSystemProbe);
    let event = application.handle(command)?;

    writeln!(output, "{event}")?;
    Ok(())
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    run(std::env::args().skip(1), io::stdout().lock())
}

#[cfg(test)]
mod tests {
    use super::run;

    #[test]
    fn health_command_reaches_the_application() {
        let mut output = Vec::new();

        run(["health"], &mut output).expect("health command succeeds");

        let output = String::from_utf8(output).expect("output is UTF-8");
        assert!(output.starts_with("healthy runtime="));
    }

    #[test]
    fn send_command_reports_validated_message() {
        let mut output = Vec::new();

        run(["send", "session-9", "hello"], &mut output).expect("send command succeeds");

        assert_eq!(
            String::from_utf8(output).expect("output is UTF-8"),
            "accepted session=session-9 bytes=5\n"
        );
    }
}

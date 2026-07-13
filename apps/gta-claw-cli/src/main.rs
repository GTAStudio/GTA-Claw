//! Command-line adapter for the headless GTA Claw application.

use std::io::{self, Write};
use std::process::ExitCode;

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

fn main() -> ExitCode {
    match run(std::env::args().skip(1), io::stdout().lock()) {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("error: {error}");
            ExitCode::FAILURE
        }
    }
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
    fn send_command_is_rejected_without_a_transport() {
        let mut output = Vec::new();

        let error = run(["send", "session-9", "hello"], &mut output)
            .expect_err("send must fail without a transport");

        assert_eq!(
            error.to_string(),
            "unsupported operation: message transport is not configured"
        );
        assert!(output.is_empty());
    }
}

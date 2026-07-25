//! Headless GTA Claw daemon bootstrap.

use std::io::{self, Write};

use claw_application::Application;
use claw_platform::NativeSystemProbe;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum DaemonMode {
    Serve,
    Probe,
}

fn parse_mode<I, S>(arguments: I) -> io::Result<DaemonMode>
where
    I: IntoIterator<Item = S>,
    S: Into<String>,
{
    let mut arguments = arguments.into_iter().map(Into::into);
    let first = arguments.next();
    let second = arguments.next();

    match (first.as_deref(), second) {
        (None, None) => Ok(DaemonMode::Serve),
        (Some("--probe"), None) => Ok(DaemonMode::Probe),
        _ => Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "usage: gta-claw-daemon [--probe]",
        )),
    }
}

fn probe(mut output: impl Write) -> io::Result<()> {
    let application = Application::new(NativeSystemProbe);

    writeln!(output, "{}", application.health())?;
    output.flush()?;
    Ok(())
}

fn serve(mut output: impl Write) -> io::Result<()> {
    let application = Application::new(NativeSystemProbe);

    writeln!(output, "{}", application.ready())?;
    writeln!(output, "{}", application.health())?;
    output.flush()?;

    loop {
        std::thread::park();
    }
}

fn run<I, S>(arguments: I, output: impl Write) -> Result<(), Box<dyn std::error::Error>>
where
    I: IntoIterator<Item = S>,
    S: Into<String>,
{
    match parse_mode(arguments)? {
        DaemonMode::Serve => serve(output)?,
        DaemonMode::Probe => probe(output)?,
    }

    Ok(())
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    run(std::env::args().skip(1), io::stdout().lock())
}

#[cfg(test)]
mod tests {
    use super::{DaemonMode, parse_mode, run};

    #[test]
    fn normal_mode_is_persistent_and_probe_is_explicit() {
        assert_eq!(
            parse_mode(std::iter::empty::<String>()).expect("default mode"),
            DaemonMode::Serve
        );
        assert_eq!(
            parse_mode(["--probe"]).expect("probe mode"),
            DaemonMode::Probe
        );
    }

    #[test]
    fn one_shot_probe_emits_only_health() {
        let mut output = Vec::new();

        run(["--probe"], &mut output).expect("daemon probe succeeds");

        let output = String::from_utf8(output).expect("output is UTF-8");
        assert!(output.starts_with("healthy runtime="));
        assert!(!output.contains("ready protocol="));
    }

    #[test]
    fn unsupported_arguments_are_rejected() {
        let error = parse_mode(["--serve"]).expect_err("unknown mode must fail");

        assert_eq!(error.kind(), std::io::ErrorKind::InvalidInput);
    }
}

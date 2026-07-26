//! Headless GTA Claw daemon bootstrap.

mod runtime;
mod server;
mod settings;

use std::error::Error;
use std::fmt::{self, Display, Formatter};
use std::io::{self, Write};
use std::net::SocketAddr;
use std::process::ExitCode;

use claw_application::Application;
use claw_http_api::{ApiConfig, BearerAuthenticator, HttpApi};
use claw_platform::NativeSystemProbe;
use tokio::net::TcpListener;

use crate::runtime::DaemonRuntime;
use crate::server::ShutdownSignals;
use crate::settings::DaemonSettings;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum DaemonMode {
    Serve,
    Probe,
}

/// The listener could not be bound, so the process must not claim readiness.
#[derive(Debug)]
struct BindError {
    address: SocketAddr,
    source: io::Error,
}

impl Display for BindError {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        write!(formatter, "cannot bind {}: {}", self.address, self.source)
    }
}

impl Error for BindError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        Some(&self.source)
    }
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

/// Builds the HTTP adapter configuration.
///
/// No bearer credentials are installed. `claw_config` records the administrator
/// token as a secret reference without a public accessor, so this process
/// cannot resolve one, and the protected surfaces answer `401` until it can.
fn api_config() -> ApiConfig {
    ApiConfig::new(BearerAuthenticator::default())
}

fn serve(mut output: impl Write) -> Result<(), Box<dyn Error>> {
    let variables = settings::process_environment();
    let settings = settings::load(
        variables
            .iter()
            .map(|(name, value)| (name.as_str(), value.as_str())),
    )?;

    let mut diagnostics = io::stderr().lock();
    for manual in settings.manual_migrations() {
        let _ = writeln!(
            diagnostics,
            "gta-claw-daemon: manual migration required: {manual}"
        );
    }
    drop(diagnostics);

    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()?;

    runtime.block_on(serve_bound(&settings, &mut output))
}

async fn serve_bound(
    settings: &DaemonSettings,
    mut output: impl Write,
) -> Result<(), Box<dyn Error>> {
    let address = settings.listen_address();
    let listener = TcpListener::bind(address)
        .await
        .map_err(|source| BindError { address, source })?;
    let bound = listener
        .local_addr()
        .map_err(|source| BindError { address, source })?;
    let signals = ShutdownSignals::register()?;

    let api = HttpApi::new(api_config(), DaemonRuntime::new().services());
    let application = Application::new(NativeSystemProbe);

    writeln!(output, "{}", application.ready())?;
    writeln!(output, "{}", application.health())?;
    writeln!(
        output,
        "listening address={bound} domain={}",
        settings.public_domain()
    )?;
    output.flush()?;

    let reason = server::serve(listener, api.router(), signals).await?;

    writeln!(output, "shutdown signal={reason}")?;
    output.flush()?;
    Ok(())
}

fn run<I, S>(arguments: I, output: impl Write) -> Result<(), Box<dyn Error>>
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

fn main() -> ExitCode {
    match run(std::env::args().skip(1), io::stdout().lock()) {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            let _ = writeln!(io::stderr(), "gta-claw-daemon: {error}");
            ExitCode::FAILURE
        }
    }
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

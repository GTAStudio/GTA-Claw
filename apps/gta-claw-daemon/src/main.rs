//! Headless GTA Claw daemon bootstrap.

use std::io::{self, Write};
use std::path::PathBuf;

use claw_application::Application;
use claw_platform::NativeSystemProbe;
use claw_state::{
    ProcessSignalCounter, StateStore, StoreConfig, initialize_linux_protected_offline,
};

const LEGACY_USAGE: &str = "usage: gta-claw-daemon [--probe]";
const HELP: &str = "\
usage: gta-claw-daemon [--probe] [--state-profile <portable-private|linux-protected> --state-path <absolute-path>]
       gta-claw-daemon --initialize-linux-protected --state-path <absolute-namespace> --service-uid <nonzero-uid> --service-gid <nonzero-gid>
       gta-claw-daemon --help";

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum DaemonMode {
    Serve,
    Probe,
    InitializeLinuxProtected,
    Help,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum RequestedStateProfile {
    PortablePrivate,
    LinuxProtected,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct StateSelection {
    profile: RequestedStateProfile,
    path: PathBuf,
}

impl StateSelection {
    fn config(&self) -> StoreConfig {
        match self.profile {
            RequestedStateProfile::PortablePrivate => StoreConfig::new(&self.path),
            RequestedStateProfile::LinuxProtected => StoreConfig::linux_protected(&self.path),
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct DaemonCommand {
    mode: DaemonMode,
    state: Option<StateSelection>,
    initialize_namespace: Option<PathBuf>,
    service_uid: Option<u32>,
    service_gid: Option<u32>,
}

fn parse_error(reason: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidInput, format!("{reason}\n{HELP}"))
}

fn required_value(
    arguments: &mut impl Iterator<Item = String>,
    flag: &'static str,
) -> io::Result<String> {
    match arguments.next() {
        Some(value) if !value.starts_with("--") => Ok(value),
        _ => Err(parse_error(match flag {
            "--state-profile" => "missing value for --state-profile",
            "--state-path" => "missing value for --state-path",
            "--service-uid" => "missing value for --service-uid",
            "--service-gid" => "missing value for --service-gid",
            _ => "missing option value",
        })),
    }
}

fn parse_nonzero_id(value: &str, flag: &'static str) -> io::Result<u32> {
    let parsed = value.parse::<u32>().map_err(|_| {
        parse_error(match flag {
            "--service-uid" => "--service-uid must be a nonzero decimal u32",
            "--service-gid" => "--service-gid must be a nonzero decimal u32",
            _ => "service identity must be a nonzero decimal u32",
        })
    })?;
    if parsed == 0 {
        return Err(parse_error(match flag {
            "--service-uid" => "--service-uid must be a nonzero decimal u32",
            "--service-gid" => "--service-gid must be a nonzero decimal u32",
            _ => "service identity must be a nonzero decimal u32",
        }));
    }
    Ok(parsed)
}

fn parse_command<I, S>(arguments: I) -> io::Result<DaemonCommand>
where
    I: IntoIterator<Item = S>,
    S: Into<String>,
{
    let mut arguments = arguments.into_iter().map(Into::into);
    let mut probe = false;
    let mut initialize = false;
    let mut help = false;
    let mut profile = None;
    let mut path = None;
    let mut service_uid = None;
    let mut service_gid = None;

    while let Some(argument) = arguments.next() {
        match argument.as_str() {
            "--probe" if !probe => probe = true,
            "--probe" => return Err(parse_error("duplicate --probe")),
            "--initialize-linux-protected" if !initialize => initialize = true,
            "--initialize-linux-protected" => {
                return Err(parse_error("duplicate --initialize-linux-protected"));
            }
            "--help" if !help => help = true,
            "--help" => return Err(parse_error("duplicate --help")),
            "--state-profile" if profile.is_none() => {
                profile = Some(
                    match required_value(&mut arguments, "--state-profile")?.as_str() {
                        "portable-private" => RequestedStateProfile::PortablePrivate,
                        "linux-protected" => RequestedStateProfile::LinuxProtected,
                        _ => {
                            return Err(parse_error(
                                "--state-profile must be portable-private or linux-protected",
                            ));
                        }
                    },
                );
            }
            "--state-profile" => return Err(parse_error("duplicate --state-profile")),
            "--state-path" if path.is_none() => {
                let value = PathBuf::from(required_value(&mut arguments, "--state-path")?);
                if !value.is_absolute() {
                    return Err(parse_error("--state-path must be absolute"));
                }
                path = Some(value);
            }
            "--state-path" => return Err(parse_error("duplicate --state-path")),
            "--service-uid" if service_uid.is_none() => {
                let value = required_value(&mut arguments, "--service-uid")?;
                service_uid = Some(parse_nonzero_id(&value, "--service-uid")?);
            }
            "--service-uid" => return Err(parse_error("duplicate --service-uid")),
            "--service-gid" if service_gid.is_none() => {
                let value = required_value(&mut arguments, "--service-gid")?;
                service_gid = Some(parse_nonzero_id(&value, "--service-gid")?);
            }
            "--service-gid" => return Err(parse_error("duplicate --service-gid")),
            _ => return Err(io::Error::new(io::ErrorKind::InvalidInput, LEGACY_USAGE)),
        }
    }

    if help {
        if probe
            || initialize
            || profile.is_some()
            || path.is_some()
            || service_uid.is_some()
            || service_gid.is_some()
        {
            return Err(parse_error(
                "--help cannot be combined with other arguments",
            ));
        }
        return Ok(DaemonCommand {
            mode: DaemonMode::Help,
            state: None,
            initialize_namespace: None,
            service_uid: None,
            service_gid: None,
        });
    }

    if initialize {
        if probe {
            return Err(parse_error(
                "--initialize-linux-protected cannot be combined with --probe",
            ));
        }
        if profile == Some(RequestedStateProfile::PortablePrivate) {
            return Err(parse_error(
                "--initialize-linux-protected is incompatible with portable-private",
            ));
        }
        let namespace =
            path.ok_or_else(|| parse_error("--initialize-linux-protected requires --state-path"))?;
        let service_uid = service_uid
            .ok_or_else(|| parse_error("--initialize-linux-protected requires --service-uid"))?;
        let service_gid = service_gid
            .ok_or_else(|| parse_error("--initialize-linux-protected requires --service-gid"))?;
        return Ok(DaemonCommand {
            mode: DaemonMode::InitializeLinuxProtected,
            state: None,
            initialize_namespace: Some(namespace),
            service_uid: Some(service_uid),
            service_gid: Some(service_gid),
        });
    }

    if service_uid.is_some() || service_gid.is_some() {
        return Err(parse_error(
            "--service-uid and --service-gid require --initialize-linux-protected",
        ));
    }
    let state = match (profile, path) {
        (None, None) => None,
        (Some(profile), Some(path)) => Some(StateSelection { profile, path }),
        (Some(_), None) => return Err(parse_error("--state-profile requires --state-path")),
        (None, Some(_)) => return Err(parse_error("--state-path requires --state-profile")),
    };
    Ok(DaemonCommand {
        mode: if probe {
            DaemonMode::Probe
        } else {
            DaemonMode::Serve
        },
        state,
        initialize_namespace: None,
        service_uid: None,
        service_gid: None,
    })
}

fn probe(mut output: impl Write) -> io::Result<()> {
    let application = Application::new(NativeSystemProbe);

    writeln!(output, "{}", application.health())?;
    output.flush()?;
    Ok(())
}

fn announce_ready(mut output: impl Write) -> io::Result<()> {
    let application = Application::new(NativeSystemProbe);

    writeln!(output, "{}", application.ready())?;
    writeln!(output, "{}", application.health())?;
    output.flush()?;
    Ok(())
}

fn serve(mut output: impl Write) -> io::Result<()> {
    announce_ready(&mut output)?;

    loop {
        std::thread::park();
    }
}

fn state_runtime() -> io::Result<tokio::runtime::Runtime> {
    tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .map_err(|error| io::Error::other(format!("create state runtime failed: {error}")))
}

fn state_failure(operation: &'static str, error: impl std::fmt::Display) -> io::Error {
    io::Error::other(format!("{operation} failed: {error}"))
}

fn close_after_failure(
    runtime: &tokio::runtime::Runtime,
    store: StateStore,
    operation: &'static str,
    primary: impl std::fmt::Display,
) -> io::Error {
    match runtime.block_on(store.close()) {
        Ok(_) => state_failure(operation, primary),
        Err(close) => io::Error::other(format!(
            "{operation} failed: {primary}; state close failed: {close}"
        )),
    }
}

fn probe_with_state(selection: &StateSelection, mut output: impl Write) -> io::Result<()> {
    let runtime = state_runtime()?;
    let store = runtime
        .block_on(StateStore::open(selection.config()))
        .map_err(|error| state_failure("state open", error))?;
    let health = runtime.block_on(store.health());
    let report = match health {
        Ok(report) => report,
        Err(error) => return Err(close_after_failure(&runtime, store, "state health", error)),
    };
    if !report.is_healthy() {
        return Err(close_after_failure(
            &runtime,
            store,
            "state health",
            "database is not ready",
        ));
    }
    runtime
        .block_on(store.close())
        .map_err(|error| state_failure("state close", error))?;
    probe(&mut output)
}

fn serve_with_state(selection: &StateSelection, mut output: impl Write) -> io::Result<()> {
    let runtime = state_runtime()?;
    let mut signals = runtime.block_on(async { ShutdownSignals::new() })?;
    let mut shutdown = ShutdownState::default();
    let opened = runtime.block_on(run_state_phase(
        &mut signals,
        &mut shutdown,
        StateStore::open(selection.config()),
    ));
    let store = opened.map_err(|error| {
        let primary = state_failure("state open", error);
        shutdown.combine(primary)
    })?;
    if shutdown.requested() {
        return close_state_store(&runtime, &mut signals, &mut shutdown, store);
    }
    let health = runtime.block_on(run_state_phase(&mut signals, &mut shutdown, store.health()));
    let report = match health {
        Ok(report) => report,
        Err(error) => {
            return Err(close_state_store_after_failure(
                &runtime,
                &mut signals,
                &mut shutdown,
                store,
                "state health",
                error,
            ));
        }
    };
    if !report.is_healthy() {
        return Err(close_state_store_after_failure(
            &runtime,
            &mut signals,
            &mut shutdown,
            store,
            "state health",
            "database is not ready",
        ));
    }
    if shutdown.requested() {
        return close_state_store(&runtime, &mut signals, &mut shutdown, store);
    }
    match runtime.block_on(announce_readiness_or_shutdown(
        &mut signals,
        &mut shutdown,
        &mut output,
    )) {
        Ok(true) => {}
        Ok(false) => {
            return close_state_store(&runtime, &mut signals, &mut shutdown, store);
        }
        Err(error) => {
            return Err(close_state_store_after_failure(
                &runtime,
                &mut signals,
                &mut shutdown,
                store,
                "announce daemon readiness",
                error,
            ));
        }
    }
    observe_shutdown(&mut shutdown, runtime.block_on(signals.wait()));
    close_state_store(&runtime, &mut signals, &mut shutdown, store)
}

async fn announce_readiness_or_shutdown(
    signals: &mut ShutdownSignals,
    shutdown: &mut ShutdownState,
    output: &mut impl Write,
) -> io::Result<bool> {
    if shutdown.requested() {
        return Ok(false);
    }
    signals.drain(shutdown);
    if shutdown.requested() || !signals.mark_ready(shutdown) {
        Ok(false)
    } else {
        announce_ready(output)?;
        Ok(true)
    }
}

#[derive(Default)]
struct ShutdownState {
    signals: u8,
    listener_error: Option<String>,
}

impl ShutdownState {
    fn observe(&mut self, result: io::Result<()>) -> bool {
        let first = !self.requested();
        match result {
            Ok(()) => {
                self.signals = self.signals.saturating_add(1);
            }
            Err(error) => self.listener_error = Some(error.to_string()),
        }
        first && self.requested()
    }

    const fn requested(&self) -> bool {
        self.signals > 0 || self.listener_error.is_some()
    }

    fn terminal_error(&self) -> Option<io::Error> {
        if let Some(error) = &self.listener_error {
            Some(io::Error::other(format!(
                "shutdown signal listener failed: {error}"
            )))
        } else if self.signals >= 2 {
            Some(io::Error::other("shutdown escalated after a second signal"))
        } else {
            None
        }
    }

    fn combine(&self, primary: io::Error) -> io::Error {
        match self.terminal_error() {
            Some(shutdown) => io::Error::other(format!("{primary}; {shutdown}")),
            None => primary,
        }
    }
}

fn observe_shutdown(shutdown: &mut ShutdownState, result: io::Result<()>) {
    if shutdown.observe(result) {
        let _ = std::thread::Builder::new()
            .name("claw-shutdown-diagnostic".to_owned())
            .spawn(|| {
                let _ = writeln!(io::stderr().lock(), "shutdown requested");
            });
    }
}

async fn run_state_phase<F: std::future::Future>(
    signals: &mut ShutdownSignals,
    shutdown: &mut ShutdownState,
    future: F,
) -> F::Output {
    tokio::pin!(future);
    loop {
        if shutdown.listener_error.is_some() {
            return future.as_mut().await;
        }
        tokio::select! {
            biased;
            signal = signals.wait() => observe_shutdown(shutdown, signal),
            output = future.as_mut() => {
                signals.drain(shutdown);
                return output;
            },
        }
    }
}

fn close_state_store(
    runtime: &tokio::runtime::Runtime,
    signals: &mut ShutdownSignals,
    shutdown: &mut ShutdownState,
    store: StateStore,
) -> io::Result<()> {
    let close = runtime.block_on(run_state_phase(signals, shutdown, store.close()));
    signals.drain(shutdown);
    match (close, shutdown.terminal_error()) {
        (Ok(_), None) if signals.commit_clean_exit() => Ok(()),
        (Ok(_), None) => {
            signals.drain(shutdown);
            Err(shutdown
                .terminal_error()
                .unwrap_or_else(|| io::Error::other("shutdown escalation won the clean-exit race")))
        }
        (Ok(_), Some(shutdown)) => Err(shutdown),
        (Err(close), None) => Err(state_failure("state close", close)),
        (Err(close), Some(shutdown)) => Err(io::Error::other(format!(
            "state close failed: {close}; {shutdown}"
        ))),
    }
}

fn close_state_store_after_failure(
    runtime: &tokio::runtime::Runtime,
    signals: &mut ShutdownSignals,
    shutdown: &mut ShutdownState,
    store: StateStore,
    operation: &'static str,
    primary: impl std::fmt::Display,
) -> io::Error {
    let primary = state_failure(operation, primary);
    match close_state_store(runtime, signals, shutdown, store) {
        Ok(()) => primary,
        Err(close) => io::Error::other(format!("{primary}; {close}")),
    }
}

struct ShutdownSignals {
    counter: ProcessSignalCounter,
}

impl ShutdownSignals {
    fn new() -> io::Result<Self> {
        Ok(Self {
            counter: ProcessSignalCounter::install()?,
        })
    }

    async fn wait(&mut self) -> io::Result<()> {
        self.counter.wait_next().await
    }

    fn drain(&mut self, shutdown: &mut ShutdownState) {
        while self.counter.take_next() {
            observe_shutdown(shutdown, Ok(()));
        }
    }

    fn mark_ready(&mut self, shutdown: &mut ShutdownState) -> bool {
        self.drain(shutdown);
        if shutdown.requested() {
            return false;
        }
        if self.counter.mark_ready() {
            true
        } else {
            while !self.counter.take_next() {
                std::hint::spin_loop();
            }
            observe_shutdown(shutdown, Ok(()));
            self.drain(shutdown);
            false
        }
    }

    fn commit_clean_exit(&self) -> bool {
        self.counter.commit_clean_exit()
    }
}

fn run<I, S>(arguments: I, mut output: impl Write) -> Result<(), Box<dyn std::error::Error>>
where
    I: IntoIterator<Item = S>,
    S: Into<String>,
{
    let command = parse_command(arguments)?;
    match command.mode {
        DaemonMode::Serve => match command.state {
            Some(selection) => serve_with_state(&selection, &mut output)?,
            None => serve(&mut output)?,
        },
        DaemonMode::Probe => match command.state {
            Some(selection) => probe_with_state(&selection, &mut output)?,
            None => probe(&mut output)?,
        },
        DaemonMode::InitializeLinuxProtected => {
            let namespace = command
                .initialize_namespace
                .expect("validated initializer namespace");
            let service_uid = command.service_uid.expect("validated service UID");
            let service_gid = command.service_gid.expect("validated service GID");
            let result = initialize_linux_protected_offline(namespace, service_uid, service_gid)?;
            writeln!(output, "{result:?}")?;
            output.flush()?;
        }
        DaemonMode::Help => {
            writeln!(output, "{HELP}")?;
            output.flush()?;
        }
    }

    Ok(())
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    run(std::env::args().skip(1), io::stdout().lock())
}

#[cfg(test)]
mod tests {
    use super::{DaemonMode, HELP, LEGACY_USAGE, RequestedStateProfile, parse_command, run};

    #[test]
    fn normal_mode_is_persistent_and_probe_is_explicit() {
        assert_eq!(
            parse_command(std::iter::empty::<String>())
                .expect("default mode")
                .mode,
            DaemonMode::Serve
        );
        assert_eq!(
            parse_command(["--probe"]).expect("probe mode").mode,
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
    fn explicit_state_profiles_require_one_absolute_path() {
        let root = if cfg!(windows) { r"C:\state" } else { "/state" };
        let portable = parse_command([
            "--probe",
            "--state-profile",
            "portable-private",
            "--state-path",
            root,
        ])
        .expect("portable probe parses");
        assert_eq!(
            portable.state.expect("portable state").profile,
            RequestedStateProfile::PortablePrivate
        );
        let protected = parse_command(["--state-profile", "linux-protected", "--state-path", root])
            .expect("protected serve parses");
        assert_eq!(
            protected.state.expect("protected state").profile,
            RequestedStateProfile::LinuxProtected
        );

        for arguments in [
            vec!["--state-profile", "portable-private"],
            vec!["--state-path", root],
            vec![
                "--state-profile",
                "portable-private",
                "--state-path",
                "relative",
            ],
            vec![
                "--state-profile",
                "portable-private",
                "--state-profile",
                "portable-private",
                "--state-path",
                root,
            ],
            vec![
                "--state-profile",
                "portable-private",
                "--state-path",
                root,
                "--state-path",
                root,
            ],
        ] {
            assert!(parse_command(arguments).is_err());
        }
    }

    #[test]
    fn initializer_requires_nonzero_identity_and_has_no_mode_conflicts() {
        let root = if cfg!(windows) { r"C:\state" } else { "/state" };
        let command = parse_command([
            "--initialize-linux-protected",
            "--state-path",
            root,
            "--service-uid",
            "1001",
            "--service-gid",
            "1002",
        ])
        .expect("initializer parses");
        assert_eq!(command.mode, DaemonMode::InitializeLinuxProtected);

        for arguments in [
            vec![
                "--initialize-linux-protected",
                "--probe",
                "--state-path",
                root,
                "--service-uid",
                "1001",
                "--service-gid",
                "1002",
            ],
            vec![
                "--initialize-linux-protected",
                "--state-profile",
                "portable-private",
                "--state-path",
                root,
                "--service-uid",
                "1001",
                "--service-gid",
                "1002",
            ],
            vec![
                "--initialize-linux-protected",
                "--state-path",
                root,
                "--service-uid",
                "0",
                "--service-gid",
                "1002",
            ],
            vec![
                "--initialize-linux-protected",
                "--state-path",
                root,
                "--service-uid",
                "1001",
            ],
        ] {
            assert!(parse_command(arguments).is_err());
        }
    }

    #[test]
    fn help_and_legacy_unknown_argument_diagnostics_are_stable() {
        let mut output = Vec::new();
        run(["--help"], &mut output).expect("help succeeds");
        assert_eq!(
            String::from_utf8(output).expect("help is UTF-8"),
            format!("{HELP}\n")
        );

        let error = parse_command(["--serve"]).expect_err("unknown mode must fail");
        assert_eq!(error.kind(), std::io::ErrorKind::InvalidInput);
        assert_eq!(error.to_string(), LEGACY_USAGE);
    }
}

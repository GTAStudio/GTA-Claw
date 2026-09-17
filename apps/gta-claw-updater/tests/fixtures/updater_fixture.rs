//! Child-process driver for the updater's crash and concurrency tests.
//!
//! Every durability window these tests need is *inside* one updater call: a
//! journal that is durable before the swap, a target that has just been moved
//! aside, a staging directory another run already holds. None of that is
//! reachable from a parent process that only sees whole library calls, so the
//! tests drive this binary and let it stop or fail exactly where the window is.

use std::ffi::OsString;
use std::path::PathBuf;
use std::process::ExitCode;

use gta_claw_updater::{
    InjectedFault, InstallMode, InstallTarget, UpdateDecision, Updater, arm_injected_fault,
};
use semver::Version;
use url::Url;

fn main() -> ExitCode {
    let arguments = match Arguments::parse(std::env::args_os()) {
        Ok(arguments) => arguments,
        Err(message) => {
            eprintln!("gta-claw-updater-fixture: {message}");
            return ExitCode::from(2);
        }
    };
    let runtime = match tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
    {
        Ok(runtime) => runtime,
        Err(error) => {
            eprintln!("gta-claw-updater-fixture: runtime: {error}");
            return ExitCode::from(2);
        }
    };
    match runtime.block_on(run(arguments)) {
        Ok(message) => {
            println!("ok: {message}");
            ExitCode::SUCCESS
        }
        Err(message) => {
            println!("error: {message}");
            ExitCode::FAILURE
        }
    }
}

async fn run(arguments: Arguments) -> Result<String, String> {
    if let Some(fault) = arguments.fault {
        arm_injected_fault(fault);
    }
    let updater = Updater::with_public_key_and_state(
        arguments.public_key,
        "x86_64-fixture-target",
        arguments.state,
    )
    .map_err(|error| error.to_string())?;

    if arguments.mode == Mode::Check {
        write_marker(arguments.marker.as_ref())?;
        return match updater
            .check(&arguments.manifest, &arguments.current)
            .await
            .map_err(|error| error.to_string())?
        {
            UpdateDecision::Current { version } => Ok(format!("current {version}")),
            UpdateDecision::Available { version, .. } => Ok(format!("available {version}")),
        };
    }

    let target = InstallTarget::new(arguments.target, InstallMode::Executable)
        .map_err(|error| error.to_string())?;
    let update = match updater
        .check(&arguments.manifest, &arguments.current)
        .await
        .map_err(|error| error.to_string())?
    {
        UpdateDecision::Available { update, .. } => update,
        UpdateDecision::Current { version } => {
            return Err(format!(
                "expected an available update, got current {version}"
            ));
        }
    };

    write_marker(arguments.marker.as_ref())?;
    let verified = updater
        .download(&update, &target)
        .await
        .map_err(|error| error.to_string())?;
    if arguments.mode == Mode::Download {
        return Ok(format!("downloaded {}", verified.path().display()));
    }

    let destination = match arguments.install_target {
        Some(path) => {
            InstallTarget::new(path, InstallMode::Executable).map_err(|error| error.to_string())?
        }
        None => target,
    };
    updater
        .install(verified, &destination)
        .await
        .map(|outcome| format!("installed {outcome:?}"))
        .map_err(|error| error.to_string())
}

/// Signals the parent test that the next library call is about to start.
fn write_marker(marker: Option<&PathBuf>) -> Result<(), String> {
    let Some(marker) = marker else {
        return Ok(());
    };
    std::fs::write(marker, b"started").map_err(|error| format!("marker: {error}"))
}

#[derive(Clone, Copy, Eq, PartialEq)]
enum Mode {
    Check,
    Download,
    Install,
}

struct Arguments {
    mode: Mode,
    state: PathBuf,
    target: PathBuf,
    install_target: Option<PathBuf>,
    manifest: Url,
    current: Version,
    public_key: [u8; 32],
    marker: Option<PathBuf>,
    fault: Option<InjectedFault>,
}

impl Arguments {
    fn parse<I>(values: I) -> Result<Self, String>
    where
        I: IntoIterator<Item = OsString>,
    {
        let mut values = values.into_iter();
        let _program = values.next();
        let mode = match values.next() {
            Some(mode) => match mode.to_string_lossy().as_ref() {
                "check" => Mode::Check,
                "download" => Mode::Download,
                "install" => Mode::Install,
                unknown => return Err(format!("unknown mode: {unknown}")),
            },
            None => return Err("a mode is required".to_owned()),
        };
        let mut state = None;
        let mut target = None;
        let mut install_target = None;
        let mut manifest = None;
        let mut current = None;
        let mut public_key = None;
        let mut marker = None;
        let mut fault = None;
        while let Some(argument) = values.next() {
            let name = argument.to_string_lossy().into_owned();
            let mut value = || {
                values
                    .next()
                    .ok_or_else(|| format!("{name} requires a value"))
            };
            match argument.to_string_lossy().as_ref() {
                "--state" => state = Some(PathBuf::from(value()?)),
                "--target" => target = Some(PathBuf::from(value()?)),
                "--install-target" => install_target = Some(PathBuf::from(value()?)),
                "--manifest" => manifest = Some(value()?),
                "--current" => current = Some(value()?),
                "--public-key" => public_key = Some(value()?),
                "--marker" => marker = Some(PathBuf::from(value()?)),
                "--fault" => fault = Some(parse_fault(&value()?.to_string_lossy())?),
                unknown => return Err(format!("unknown argument: {unknown}")),
            }
        }
        Ok(Self {
            mode,
            state: state.ok_or_else(|| "--state is required".to_owned())?,
            target: target.unwrap_or_else(|| PathBuf::from("unused-install-target")),
            install_target,
            manifest: manifest
                .ok_or_else(|| "--manifest is required".to_owned())
                .and_then(|value| {
                    Url::parse(&value.to_string_lossy())
                        .map_err(|error| format!("invalid manifest URL: {error}"))
                })?,
            current: current
                .ok_or_else(|| "--current is required".to_owned())
                .and_then(|value| {
                    Version::parse(&value.to_string_lossy())
                        .map_err(|error| format!("invalid current version: {error}"))
                })?,
            public_key: public_key
                .ok_or_else(|| "--public-key is required".to_owned())
                .and_then(|value| decode_public_key(&value.to_string_lossy()))?,
            marker,
            fault,
        })
    }
}

fn parse_fault(value: &str) -> Result<InjectedFault, String> {
    match value {
        "exit-after-swap-prepared" => Ok(InjectedFault::ExitAfterSwapPrepared),
        "exit-after-swap-committed" => Ok(InjectedFault::ExitAfterSwapCommitted),
        "fail-new-state-directory-sync" => Ok(InjectedFault::FailNewStateDirectorySync),
        "fail-parent-sync-after-swap" => Ok(InjectedFault::FailParentSyncAfterSwap),
        unknown => Err(format!("unknown fault: {unknown}")),
    }
}

fn decode_public_key(value: &str) -> Result<[u8; 32], String> {
    let bytes = value.as_bytes();
    if bytes.len() != 64 {
        return Err("--public-key must be 64 hex characters".to_owned());
    }
    let mut key = [0_u8; 32];
    for (index, pair) in bytes.chunks_exact(2).enumerate() {
        key[index] = (hex_nibble(pair[0])? << 4) | hex_nibble(pair[1])?;
    }
    Ok(key)
}

fn hex_nibble(value: u8) -> Result<u8, String> {
    match value {
        b'0'..=b'9' => Ok(value - b'0'),
        b'a'..=b'f' => Ok(value - b'a' + 10),
        _ => Err("--public-key must be lowercase hex".to_owned()),
    }
}

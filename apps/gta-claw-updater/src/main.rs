//! GTA Claw standalone signed updater executable.

use std::ffi::OsString;
use std::path::PathBuf;
use std::process::ExitCode;

use gta_claw_updater::{InstallMode, InstallTarget, UpdateOutcome, Updater};
use semver::Version;
use url::Url;

fn main() -> ExitCode {
    let arguments = match Arguments::parse(std::env::args_os()) {
        Ok(arguments) => arguments,
        Err(message) => {
            eprintln!("{message}");
            return if message.starts_with("Usage:") {
                ExitCode::SUCCESS
            } else {
                ExitCode::from(2)
            };
        }
    };
    let runtime = match tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .thread_name("gta-claw-updater")
        .build()
    {
        Ok(runtime) => runtime,
        Err(error) => {
            eprintln!("failed to start updater runtime: {error}");
            return ExitCode::FAILURE;
        }
    };
    match runtime.block_on(execute(arguments)) {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("gta-claw-updater: {error}");
            ExitCode::FAILURE
        }
    }
}

async fn execute(arguments: Arguments) -> Result<(), String> {
    let target =
        InstallTarget::new(arguments.target, platform_mode()).map_err(|error| error.to_string())?;
    let updater = Updater::production(target_triple()).map_err(|error| error.to_string())?;
    match updater
        .execute(&arguments.manifest, &arguments.current, &target)
        .await
        .map_err(|error| error.to_string())?
    {
        UpdateOutcome::SystemManaged => {
            println!("GTA Claw updates are managed by the system package manager.");
        }
        UpdateOutcome::Current(version) => {
            println!("GTA Claw {version} is current.");
        }
        UpdateOutcome::Installed(version) => {
            println!("GTA Claw {version} installed successfully.");
        }
        UpdateOutcome::RestartRequired {
            version,
            staged_path,
        } => {
            println!(
                "GTA Claw {version} is verified at {}. Close the running application and run the updater again; elevation was not attempted.",
                staged_path.display()
            );
        }
    }
    Ok(())
}

struct Arguments {
    manifest: Url,
    current: Version,
    target: PathBuf,
}

impl Arguments {
    fn parse<I>(values: I) -> Result<Self, String>
    where
        I: IntoIterator<Item = OsString>,
    {
        let mut values = values.into_iter();
        let _program = values.next();
        let mut manifest = None;
        let mut current = None;
        let mut target = None;
        while let Some(argument) = values.next() {
            match argument.to_string_lossy().as_ref() {
                "--manifest" => {
                    manifest = Some(
                        values
                            .next()
                            .ok_or_else(|| "--manifest requires a URL".to_owned())?,
                    );
                }
                "--current" => {
                    current = Some(
                        values
                            .next()
                            .ok_or_else(|| "--current requires a version".to_owned())?,
                    );
                }
                "--target" => {
                    target = Some(PathBuf::from(
                        values
                            .next()
                            .ok_or_else(|| "--target requires a path".to_owned())?,
                    ));
                }
                "--help" | "-h" => return Err(help_text().to_owned()),
                unknown => return Err(format!("unknown argument: {unknown}\n{}", help_text())),
            }
        }
        let manifest = manifest
            .ok_or_else(|| format!("--manifest is required\n{}", help_text()))
            .and_then(|value| {
                Url::parse(&value.to_string_lossy())
                    .map_err(|error| format!("invalid manifest URL: {error}"))
            })?;
        let current = current
            .ok_or_else(|| format!("--current is required\n{}", help_text()))
            .and_then(|value| {
                Version::parse(&value.to_string_lossy())
                    .map_err(|error| format!("invalid current version: {error}"))
            })?;
        let target = target.ok_or_else(|| format!("--target is required\n{}", help_text()))?;
        Ok(Self {
            manifest,
            current,
            target,
        })
    }
}

const fn platform_mode() -> InstallMode {
    if cfg!(target_os = "linux") {
        InstallMode::LinuxPackage
    } else if cfg!(target_os = "macos") {
        InstallMode::MacOsBundle
    } else {
        InstallMode::Executable
    }
}

fn target_triple() -> String {
    let architecture = std::env::consts::ARCH;
    let os = if cfg!(target_os = "windows") {
        "pc-windows-msvc"
    } else if cfg!(target_os = "macos") {
        "apple-darwin"
    } else {
        "unknown-linux-gnu"
    };
    format!("{architecture}-{os}")
}

fn help_text() -> &'static str {
    "Usage: gta-claw-updater --manifest URL --current VERSION --target PATH"
}

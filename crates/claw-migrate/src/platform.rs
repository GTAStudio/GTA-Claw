use std::env;
use std::path::{Path, PathBuf};

/// Host path convention used for migration discovery.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum HostPlatform {
    /// Windows roaming application-data conventions.
    Windows,
    /// macOS Application Support conventions.
    MacOs,
    /// Linux/XDG conventions.
    Linux,
}

/// Injectable platform path source.
///
/// Tests should use their own implementation rooted in temporary directories;
/// providers never consult a real user profile when this port is supplied.
pub trait PlatformPaths {
    /// Host convention.
    fn platform(&self) -> HostPlatform;
    /// User home directory.
    fn home_dir(&self) -> &Path;
    /// Platform configuration root (`APPDATA`, Application Support, or XDG).
    fn config_dir(&self) -> &Path;
    /// Platform data root (`LOCALAPPDATA`, Application Support, or XDG).
    fn data_dir(&self) -> &Path;
    /// Optional Codex home override, normally sourced from `CODEX_HOME`.
    fn codex_home(&self) -> Option<&Path> {
        None
    }
}

/// Paths discovered from the current process environment.
#[derive(Clone, Debug)]
pub struct SystemPlatformPaths {
    platform: HostPlatform,
    home: PathBuf,
    config: PathBuf,
    data: PathBuf,
    codex_home: Option<PathBuf>,
}

impl SystemPlatformPaths {
    /// Resolves paths for the current host.
    ///
    /// Returns `None` when no trustworthy home directory can be determined.
    #[must_use]
    pub fn discover() -> Option<Self> {
        let home =
            env::var_os(if cfg!(windows) { "USERPROFILE" } else { "HOME" }).map(PathBuf::from)?;
        if cfg!(windows) {
            let config = env::var_os("APPDATA")
                .map(PathBuf::from)
                .unwrap_or_else(|| home.join("AppData").join("Roaming"));
            let data = env::var_os("LOCALAPPDATA")
                .map(PathBuf::from)
                .unwrap_or_else(|| home.join("AppData").join("Local"));
            Some(Self {
                platform: HostPlatform::Windows,
                home,
                config,
                data,
                codex_home: env::var_os("CODEX_HOME").map(PathBuf::from),
            })
        } else if cfg!(target_os = "macos") {
            let support = home.join("Library").join("Application Support");
            Some(Self {
                platform: HostPlatform::MacOs,
                home,
                config: support.clone(),
                data: support,
                codex_home: env::var_os("CODEX_HOME").map(PathBuf::from),
            })
        } else {
            let config = env::var_os("XDG_CONFIG_HOME")
                .map(PathBuf::from)
                .unwrap_or_else(|| home.join(".config"));
            let data = env::var_os("XDG_DATA_HOME")
                .map(PathBuf::from)
                .unwrap_or_else(|| home.join(".local").join("share"));
            Some(Self {
                platform: HostPlatform::Linux,
                home,
                config,
                data,
                codex_home: env::var_os("CODEX_HOME").map(PathBuf::from),
            })
        }
    }

    /// Constructs explicit paths, primarily for adapters and cross-platform tests.
    #[must_use]
    pub fn from_parts(
        platform: HostPlatform,
        home: PathBuf,
        config: PathBuf,
        data: PathBuf,
    ) -> Self {
        Self {
            platform,
            home,
            config,
            data,
            codex_home: None,
        }
    }

    /// Adds an explicit Codex home override.
    #[must_use]
    pub fn with_codex_home(mut self, codex_home: PathBuf) -> Self {
        self.codex_home = Some(codex_home);
        self
    }
}

impl PlatformPaths for SystemPlatformPaths {
    fn platform(&self) -> HostPlatform {
        self.platform
    }

    fn home_dir(&self) -> &Path {
        &self.home
    }

    fn config_dir(&self) -> &Path {
        &self.config
    }

    fn data_dir(&self) -> &Path {
        &self.data
    }

    fn codex_home(&self) -> Option<&Path> {
        self.codex_home.as_deref()
    }
}

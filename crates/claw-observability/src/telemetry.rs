//! Tracing subscriber initialization.

use std::fmt;
use std::fs::{File, OpenOptions};
use std::io::{self, Write};
use std::path::{Path, PathBuf};

use tracing_subscriber::EnvFilter;
use tracing_subscriber::layer::SubscriberExt;
use tracing_subscriber::util::SubscriberInitExt;

use crate::redaction::RedactingLayer;

/// Ordinary log output format.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub enum LogFormat {
    /// Newline-delimited structured JSON.
    Json,
    /// Human-readable single-line output.
    #[default]
    Human,
}

/// Destination for ordinary telemetry records.
///
/// There is deliberately no stdout variant: machine-readable command output
/// must remain uncontaminated by diagnostics.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub enum TelemetryOutput {
    /// Process standard error.
    #[default]
    Stderr,
    /// Append to a file, creating it when it does not exist.
    File(PathBuf),
}

impl TelemetryOutput {
    /// Creates a file output without opening it.
    #[must_use]
    pub fn file(path: impl Into<PathBuf>) -> Self {
        Self::File(path.into())
    }

    /// Returns the configured file path, or `None` for standard error.
    #[must_use]
    pub fn path(&self) -> Option<&Path> {
        match self {
            Self::Stderr => None,
            Self::File(path) => Some(path),
        }
    }

    fn open(&self) -> Result<TelemetryWriter, TelemetryError> {
        match self {
            Self::Stderr => Ok(TelemetryWriter::Stderr(io::stderr())),
            Self::File(path) => OpenOptions::new()
                .create(true)
                .append(true)
                .open(path)
                .map(TelemetryWriter::File)
                .map_err(|error| TelemetryError::output_open(path, &error)),
        }
    }

    fn description(&self) -> String {
        self.path().map_or_else(
            || "stderr".to_owned(),
            |path| format!("'{}'", path.display()),
        )
    }
}

/// Tracing initialization settings.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TelemetryConfig {
    /// Output representation.
    pub format: LogFormat,
    /// Default filter when the environment variable is absent.
    pub default_filter: String,
    /// Environment variable containing tracing-subscriber filter directives.
    pub filter_env: String,
}

impl Default for TelemetryConfig {
    fn default() -> Self {
        Self {
            format: LogFormat::Human,
            default_filter: "info".to_owned(),
            filter_env: "GTA_CLAW_LOG".to_owned(),
        }
    }
}

/// Stable category for a [`TelemetryError`].
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum TelemetryErrorKind {
    /// The configured filter environment variable could not be read.
    FilterEnvironment,
    /// The selected filter directives are invalid.
    InvalidFilter,
    /// The selected telemetry output could not be opened.
    OutputOpen,
    /// A global tracing subscriber could not be installed.
    SubscriberInstall,
    /// The active telemetry writer or its lock failed.
    Writer,
}

/// Failure while configuring or writing ordinary telemetry.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TelemetryError {
    kind: TelemetryErrorKind,
    message: String,
    path: Option<PathBuf>,
    io_kind: Option<io::ErrorKind>,
}

impl TelemetryError {
    const fn new(kind: TelemetryErrorKind, message: String) -> Self {
        Self {
            kind,
            message,
            path: None,
            io_kind: None,
        }
    }

    fn output_open(path: &Path, error: &io::Error) -> Self {
        Self {
            kind: TelemetryErrorKind::OutputOpen,
            message: format!("cannot open telemetry output '{}': {error}", path.display()),
            path: Some(path.to_path_buf()),
            io_kind: Some(error.kind()),
        }
    }

    fn writer(output: &TelemetryOutput, message: &str) -> Self {
        Self {
            kind: TelemetryErrorKind::Writer,
            message: format!(
                "telemetry writer for {} failed: {message}",
                output.description()
            ),
            path: output.path().map(Path::to_path_buf),
            io_kind: None,
        }
    }

    /// Returns the stable failure category.
    #[must_use]
    pub const fn kind(&self) -> TelemetryErrorKind {
        self.kind
    }

    /// Returns the affected output path when one exists.
    #[must_use]
    pub fn path(&self) -> Option<&Path> {
        self.path.as_deref()
    }

    /// Returns the underlying I/O category for file-open failures.
    #[must_use]
    pub const fn io_kind(&self) -> Option<io::ErrorKind> {
        self.io_kind
    }

    /// Returns the actionable diagnostic message.
    #[must_use]
    pub fn message(&self) -> &str {
        &self.message
    }
}

impl fmt::Display for TelemetryError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.message)
    }
}

impl std::error::Error for TelemetryError {}

#[derive(Debug)]
enum TelemetryWriter {
    Stderr(io::Stderr),
    File(File),
    #[cfg(test)]
    Failing,
}

impl Write for TelemetryWriter {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        match self {
            Self::Stderr(stderr) => stderr.write(bytes),
            Self::File(file) => file.write(bytes),
            #[cfg(test)]
            Self::Failing => Err(io::Error::other("forced telemetry write failure")),
        }
    }

    fn flush(&mut self) -> io::Result<()> {
        match self {
            Self::Stderr(stderr) => stderr.flush(),
            Self::File(file) => file.flush(),
            #[cfg(test)]
            Self::Failing => Err(io::Error::other("forced telemetry flush failure")),
        }
    }
}

/// Health handle for the active telemetry writer.
#[derive(Clone, Debug)]
pub struct TelemetryHandle {
    layer: RedactingLayer<TelemetryWriter>,
    output: TelemetryOutput,
}

impl TelemetryHandle {
    /// Returns the configured output destination.
    #[must_use]
    pub const fn output(&self) -> &TelemetryOutput {
        &self.output
    }

    /// Returns and clears the latest ordinary-log writer failure.
    ///
    /// # Errors
    ///
    /// Returns a [`TelemetryErrorKind::Writer`] error carrying `telemetry writer
    /// lock poisoned` when a thread panicked while holding the log writer mutex,
    /// which means records emitted around that panic were dropped.
    pub fn take_writer_error(&self) -> Result<Option<String>, TelemetryError> {
        self.layer
            .take_error()
            .map_err(|message| TelemetryError::writer(&self.output, &message))
    }

    /// Returns and clears the latest writer failure as a typed error.
    ///
    /// # Errors
    ///
    /// Returns a [`TelemetryErrorKind::Writer`] error when the shared writer
    /// lock is poisoned.
    pub fn take_writer_failure(&self) -> Result<Option<TelemetryError>, TelemetryError> {
        self.layer
            .take_error()
            .map(|failure| failure.map(|message| TelemetryError::writer(&self.output, &message)))
            .map_err(|message| TelemetryError::writer(&self.output, &message))
    }

    /// Flushes telemetry and closes the ordinary-log writer to new records.
    ///
    /// The result is deterministic and shared by every clone of this handle.
    /// Call this after application tasks that can emit telemetry have stopped.
    /// Repeated calls return the same result without flushing again.
    ///
    /// # Errors
    ///
    /// Returns [`TelemetryError`] when an earlier write failed, the final flush
    /// fails, or the writer lock is poisoned. An attempted event after shutdown
    /// is reported separately by [`Self::take_writer_error`] and never rewrites
    /// this method's completed result.
    pub fn shutdown(&self) -> Result<(), TelemetryError> {
        self.layer
            .shutdown()
            .map_err(|message| TelemetryError::writer(&self.output, &message))
    }
}

/// Installs the global redacting tracing subscriber.
///
/// Filter directives use `tracing-subscriber` syntax, including per-module
/// directives such as `info,claw_gateway=debug,hyper=warn`.
/// The returned [`TelemetryHandle`] should be retained and shut down after all
/// telemetry-producing tasks have completed.
///
/// # Errors
///
/// Returns [`TelemetryError`] when the filter environment variable named by
/// [`TelemetryConfig::filter_env`] is set to a value that is not valid Unicode,
/// when the resulting directives are not accepted by
/// [`EnvFilter`], or when a global subscriber
/// has already been installed by this process. An absent variable is not an
/// error: [`TelemetryConfig::default_filter`] is used instead.
pub fn init(config: &TelemetryConfig) -> Result<TelemetryHandle, TelemetryError> {
    init_with_output(config, TelemetryOutput::default())
}

/// Installs the global redacting tracing subscriber with an explicit output.
///
/// [`TelemetryOutput::File`] is opened in append mode before the subscriber is
/// installed. Its parent directory must already exist. An open failure is
/// returned and never falls back to stderr.
///
/// # Errors
///
/// Returns the same filter and subscriber errors as [`init`], plus a typed
/// [`TelemetryErrorKind::OutputOpen`] failure when a file output cannot be
/// opened.
pub fn init_with_output(
    config: &TelemetryConfig,
    output: TelemetryOutput,
) -> Result<TelemetryHandle, TelemetryError> {
    let (filter, layer, handle) = prepare(config, output)?;
    tracing_subscriber::registry()
        .with(filter)
        .with(layer)
        .try_init()
        .map_err(|error| {
            TelemetryError::new(
                TelemetryErrorKind::SubscriberInstall,
                format!("cannot install tracing subscriber: {error}"),
            )
        })?;
    Ok(handle)
}

fn prepare(
    config: &TelemetryConfig,
    output: TelemetryOutput,
) -> Result<(EnvFilter, RedactingLayer<TelemetryWriter>, TelemetryHandle), TelemetryError> {
    let directives = match std::env::var(&config.filter_env) {
        Ok(value) => value,
        Err(std::env::VarError::NotPresent) => config.default_filter.clone(),
        Err(error) => {
            return Err(TelemetryError::new(
                TelemetryErrorKind::FilterEnvironment,
                format!("cannot read {}: {error}", config.filter_env),
            ));
        }
    };
    let filter = EnvFilter::try_new(&directives).map_err(|error| {
        TelemetryError::new(
            TelemetryErrorKind::InvalidFilter,
            format!("invalid tracing filter in {}: {error}", config.filter_env),
        )
    })?;
    let writer = output.open()?;
    let layer = RedactingLayer::new(config.format, writer);
    let handle = TelemetryHandle {
        layer: layer.clone(),
        output,
    };
    Ok((filter, layer, handle))
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::io;
    use std::path::PathBuf;
    use std::sync::atomic::{AtomicU64, Ordering};

    use serde_json::Value;
    use tracing_subscriber::layer::SubscriberExt as _;

    use super::{
        LogFormat, TelemetryConfig, TelemetryErrorKind, TelemetryHandle, TelemetryOutput,
        TelemetryWriter, init_with_output, prepare,
    };
    use crate::redaction::{REDACTED, RedactingLayer};

    static NEXT_FILE: AtomicU64 = AtomicU64::new(0);

    fn temporary_path(name: &str) -> PathBuf {
        std::env::temp_dir().join(format!(
            "claw-telemetry-{}-{}-{name}",
            std::process::id(),
            NEXT_FILE.fetch_add(1, Ordering::Relaxed)
        ))
    }

    fn json_config() -> TelemetryConfig {
        TelemetryConfig {
            format: LogFormat::Json,
            default_filter: "info".to_owned(),
            filter_env: "GTA_CLAW_TELEMETRY_TEST_FILTER_MUST_BE_UNSET".to_owned(),
        }
    }

    #[test]
    fn defaults_are_stable() {
        assert_eq!(
            TelemetryConfig::default(),
            TelemetryConfig {
                format: LogFormat::Human,
                default_filter: "info".to_owned(),
                filter_env: "GTA_CLAW_LOG".to_owned(),
            }
        );
        assert_eq!(TelemetryOutput::default(), TelemetryOutput::Stderr);
        assert!(TelemetryOutput::default().path().is_none());
        assert!(matches!(
            TelemetryOutput::default().open().expect("open stderr"),
            TelemetryWriter::Stderr(_)
        ));
    }

    #[test]
    fn file_output_receives_redacted_events_and_shares_shutdown() {
        let path = temporary_path("events.jsonl");
        fs::write(&path, "existing\n").expect("seed telemetry file");
        let output = TelemetryOutput::file(&path);
        let (filter, layer, handle) =
            prepare(&json_config(), output.clone()).expect("prepare file telemetry");
        let cloned = handle.clone();
        let subscriber = tracing_subscriber::registry().with(filter).with(layer);

        tracing::subscriber::with_default(subscriber, || {
            tracing::info!(
                session_id = "s-1",
                api_token = "must-not-appear",
                "file event"
            );
        });
        handle.shutdown().expect("flush file telemetry");
        cloned.shutdown().expect("shared shutdown is idempotent");

        assert_eq!(handle.output(), &output);
        let content = fs::read_to_string(&path).expect("read telemetry file");
        let lines = content.lines().collect::<Vec<_>>();
        assert_eq!(lines.len(), 2);
        assert_eq!(lines[0], "existing");
        let event: Value = serde_json::from_str(lines[1]).expect("JSON telemetry");
        assert_eq!(event["fields"]["message"], "file event");
        assert_eq!(event["fields"]["session_id"], "s-1");
        assert_eq!(event["fields"]["api_token"], REDACTED);
        assert!(!content.contains("must-not-appear"));
        drop(cloned);
        drop(handle);
        fs::remove_file(path).expect("remove telemetry file");
    }

    #[test]
    fn file_open_failures_are_typed_without_fallback() {
        let missing_parent = temporary_path("missing-parent");
        let path = missing_parent.join("events.jsonl");
        let error = init_with_output(&json_config(), TelemetryOutput::file(&path))
            .expect_err("missing parent must fail");

        assert_eq!(error.kind(), TelemetryErrorKind::OutputOpen);
        assert_eq!(error.path(), Some(path.as_path()));
        assert_eq!(error.io_kind(), Some(io::ErrorKind::NotFound));
        assert!(error.message().contains("cannot open telemetry output"));
        assert!(!path.exists());
    }

    #[test]
    fn runtime_writer_failures_are_typed() {
        let path = temporary_path("failing.jsonl");
        let output = TelemetryOutput::file(&path);
        let layer = RedactingLayer::new(LogFormat::Json, TelemetryWriter::Failing);
        let handle = TelemetryHandle {
            layer: layer.clone(),
            output,
        };
        let subscriber = tracing_subscriber::registry().with(layer);
        tracing::subscriber::with_default(subscriber, || {
            tracing::info!("writer failure");
        });

        let error = handle
            .take_writer_failure()
            .expect("writer health lock")
            .expect("typed writer failure");
        assert_eq!(error.kind(), TelemetryErrorKind::Writer);
        assert_eq!(error.path(), Some(path.as_path()));
        assert_eq!(error.io_kind(), None);
        assert!(error.message().contains("forced telemetry write failure"));
    }
}

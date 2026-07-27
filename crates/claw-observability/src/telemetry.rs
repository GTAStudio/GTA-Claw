//! Tracing subscriber initialization.

use std::fmt;
use std::io;

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

/// Failure while configuring the global telemetry subscriber.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TelemetryError(String);

impl fmt::Display for TelemetryError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.0)
    }
}

impl std::error::Error for TelemetryError {}

/// Health handle for the active telemetry writer.
#[derive(Clone, Debug)]
pub struct TelemetryHandle {
    layer: RedactingLayer<io::Stderr>,
}

impl TelemetryHandle {
    /// Returns and clears the latest ordinary-log writer failure.
    ///
    /// # Errors
    ///
    /// Returns [`TelemetryError`] carrying `telemetry writer lock poisoned`
    /// when a thread panicked while holding the log writer mutex, which means
    /// records emitted around that panic were dropped.
    pub fn take_writer_error(&self) -> Result<Option<String>, TelemetryError> {
        self.layer.take_error().map_err(TelemetryError)
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
        self.layer.shutdown().map_err(TelemetryError)
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
    let directives = match std::env::var(&config.filter_env) {
        Ok(value) => value,
        Err(std::env::VarError::NotPresent) => config.default_filter.clone(),
        Err(error) => {
            return Err(TelemetryError(format!(
                "cannot read {}: {error}",
                config.filter_env
            )));
        }
    };
    let filter = EnvFilter::try_new(&directives).map_err(|error| {
        TelemetryError(format!(
            "invalid tracing filter in {}: {error}",
            config.filter_env
        ))
    })?;
    let layer = RedactingLayer::new(config.format, io::stderr());
    tracing_subscriber::registry()
        .with(filter)
        .with(layer.clone())
        .try_init()
        .map_err(|error| TelemetryError(format!("cannot install tracing subscriber: {error}")))?;
    Ok(TelemetryHandle { layer })
}

#[cfg(test)]
mod tests {
    use super::{LogFormat, TelemetryConfig};

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
    }
}

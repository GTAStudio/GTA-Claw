//! Opt-in structured diagnostics for the Gateway path.
//!
//! The rendered result of `gateway health` is one verdict. This module makes
//! the path to that verdict observable when the user asks for it with `-v`,
//! without changing a single byte of the default output: nothing is emitted at
//! all unless verbosity was raised explicitly, and the subscriber
//! [`claw_observability`] installs writes to standard error — or to the file
//! `--log-file` names — never to standard output, where the `--json` summary
//! lives.
//!
//! Events are ordinary `tracing` records emitted through
//! [`claw_observability::tracing`]. Two consequences of that pipeline drive
//! everything below:
//!
//! * Field *values* pass through the crate's redacting layer, message text does
//!   not. Every value therefore travels as a structured field, and no call site
//!   formats a value into a message.
//! * The subscriber's `EnvFilter` is the verbosity gate. A stage event is
//!   `debug`, per-request detail is `trace`, and [`Verbosity`] selects the
//!   matching filter directive, so there is no second gate to keep in step.

use std::io;
use std::path::Path;
use std::sync::OnceLock;

use claw_observability::telemetry::{
    self, LogFormat, TelemetryConfig, TelemetryError, TelemetryErrorKind, TelemetryOutput,
};
use claw_observability::tracing;

use crate::DiagnosticFailure;

/// Stable status reported when `--log-file` names a destination that cannot be
/// opened.
pub(crate) const LOG_FILE_UNUSABLE: &str = "log_file_unusable";

/// Endpoint field used before validation has produced a safe origin.
const UNRESOLVED_ENDPOINT: &str = "<unresolved-endpoint>";

/// Upper bound on one rendered field value.
///
/// Matches the diagnostic's existing bound on peer-derived output text so a
/// long value cannot be used to flood the diagnostic stream.
const MAX_FIELD_BYTES: usize = 256;

/// How much of the Gateway path is reported.
#[derive(Clone, Copy, Debug, Default, Eq, Ord, PartialEq, PartialOrd)]
pub(crate) enum Verbosity {
    /// Nothing is emitted. Output is byte-identical to an uninstrumented run.
    #[default]
    Off,
    /// One record per stage of the connection.
    Basic,
    /// Adds correlation identifiers and per-stage bounds.
    Detailed,
}

impl Verbosity {
    /// Default `tracing` filter directive matching this level.
    ///
    /// The directive names this binary's own target rather than a bare level.
    /// A bare `trace` would also switch on every dependency that logs, and
    /// `tracing-subscriber` bridges the `log` crate by default, so a bare level
    /// puts third-party records such as `mio::poll` on the same stream as these
    /// diagnostics — mixing two formats and burying the connection story.
    /// Everything outside this crate stays off unless `GTA_CLAW_LOG` asks for
    /// it explicitly.
    const fn filter_directive(self) -> &'static str {
        match self {
            Self::Off => "off",
            Self::Basic => "gta_claw_cli=debug",
            Self::Detailed => "gta_claw_cli=trace",
        }
    }
}

/// Replaces characters that could forge or reorder a diagnostic line.
///
/// JSON encoding already escapes C0 controls, so this is not about framing: it
/// is about what a terminal renders. Bidirectional overrides and line/paragraph
/// separators survive JSON escaping and can make a peer-supplied value display
/// as something else entirely, so they are folded to `.` along with every other
/// control character. The result is then truncated on a character boundary.
///
/// The redacting layer decides whether a value may be shown at all; this decides
/// what the shown value can do to the reader's terminal. Apply it to every
/// peer-derived value.
pub(crate) fn sanitize(value: &str) -> String {
    let mut sanitized = String::with_capacity(value.len().min(MAX_FIELD_BYTES));
    for character in value.chars() {
        let replacement = if character.is_control()
            || matches!(
                character,
                '\u{200e}' | '\u{200f}' | '\u{2028}' | '\u{2029}'
                    | '\u{202a}'..='\u{202e}'
                    | '\u{2066}'..='\u{2069}'
            ) {
            '.'
        } else {
            character
        };
        if sanitized.len() + replacement.len_utf8() > MAX_FIELD_BYTES {
            break;
        }
        sanitized.push(replacement);
    }
    sanitized
}

/// Renders a boolean as one stable field value.
pub(crate) const fn bool_field(value: bool) -> &'static str {
    if value { "true" } else { "false" }
}

/// The diagnostic channel for one CLI invocation.
///
/// The channel owns the verbosity decision and the endpoint every event is
/// attributed to. Emission itself is the `tracing` macros at each call site,
/// because a macro's field names must be literals and a stage's fields are the
/// point of the record.
pub(crate) struct Diagnostics {
    level: Verbosity,
    endpoint: OnceLock<String>,
}

impl Diagnostics {
    /// Builds the channel for a parsed verbosity.
    ///
    /// Construction installs nothing. [`Self::install`] is the one place a
    /// subscriber is configured, so a caller can always name the endpoint on a
    /// channel whose destination turned out to be unusable.
    pub(crate) const fn for_verbosity(level: Verbosity) -> Self {
        Self {
            level,
            endpoint: OnceLock::new(),
        }
    }

    /// Installs the shared redacting `tracing` subscriber for this process.
    ///
    /// This is the only place output is configured. `claw-observability` applies
    /// `GTA_CLAW_LOG` over the directive chosen here, so a user can widen or
    /// narrow the filter without this binary growing its own logging path.
    ///
    /// Without `--log-file` the destination is standard error, exactly as it is
    /// without the flag. At [`Verbosity::Off`] no subscriber is installed at all
    /// — and no file is opened — so every `tracing` macro in the process stays a
    /// no-op and neither stream is touched.
    ///
    /// # Errors
    ///
    /// Returns a usage failure when `--log-file` names a destination that cannot
    /// be opened. Standard error is deliberately not used instead: the user
    /// named where the records go, and writing them somewhere they are not
    /// looking is worse than not writing them at all.
    pub(crate) fn install(&self, log_file: Option<&Path>) -> Result<(), DiagnosticFailure> {
        if self.level == Verbosity::Off {
            return Ok(());
        }
        let config = TelemetryConfig {
            format: LogFormat::Json,
            default_filter: self.level.filter_directive().to_owned(),
            ..TelemetryConfig::default()
        };
        // The default destination is `init`, which is standard error. Only an
        // explicit path reaches `init_with_output`.
        let installed = log_file.map_or_else(
            || telemetry::init(&config),
            |path| telemetry::init_with_output(&config, TelemetryOutput::file(path)),
        );
        match installed {
            Ok(handle) => {
                tracing::debug!(
                    action = "telemetry.install",
                    outcome = "success",
                    endpoint = self.endpoint(),
                    telemetry.filter_env = config.filter_env.as_str(),
                    telemetry.default_filter = config.default_filter.as_str(),
                    telemetry.format = "json",
                    telemetry.output = output_field(handle.output()),
                );
                Ok(())
            }
            // The requested file is the one failure the user has to act on, and
            // the only one that is about the destination rather than the filter
            // or the subscriber.
            Err(error) if error.kind() == TelemetryErrorKind::OutputOpen => {
                Err(log_file_failure(&error))
            }
            // Nothing is listening yet, so this is the one diagnostic that
            // cannot be a `tracing` event. It stays a single plain line on the
            // stream the user just asked to receive diagnostics on, and it never
            // changes the command's exit code.
            Err(error) => {
                eprintln!("gta-claw-cli: diagnostics unavailable: {error}");
                Ok(())
            }
        }
    }

    /// Whether any record will be emitted.
    pub(crate) const fn is_enabled(&self) -> bool {
        !matches!(self.level, Verbosity::Off)
    }

    /// Records the sanitized endpoint origin every event is attributed to.
    ///
    /// Only the first call wins: the origin is a property of the invocation, and
    /// a later overwrite would make earlier records unattributable.
    pub(crate) fn set_endpoint(&self, endpoint: &str) {
        let _ = self.endpoint.set(sanitize(endpoint));
    }

    /// The endpoint every event carries, before validation has produced one.
    pub(crate) fn endpoint(&self) -> &str {
        self.endpoint
            .get()
            .map_or(UNRESOLVED_ENDPOINT, String::as_str)
    }
}

/// Renders the installed destination as one field value.
///
/// A `--log-file` path is user-supplied text on its way back to a terminal, so
/// it is sanitized exactly like every other rendered value.
fn output_field(output: &TelemetryOutput) -> String {
    output.path().map_or_else(
        || "stderr".to_owned(),
        |path| sanitize(&path.display().to_string()),
    )
}

/// Maps a failed `--log-file` open onto the diagnostic's existing vocabulary.
///
/// The category is the one a bad flag value already carries, and the typed I/O
/// category picks the message, so the user is told what to fix rather than being
/// handed the path they just typed back.
const fn log_file_failure(error: &TelemetryError) -> DiagnosticFailure {
    let message = match error.io_kind() {
        Some(io::ErrorKind::NotFound) => "diagnostic log file directory does not exist",
        Some(io::ErrorKind::PermissionDenied) => "diagnostic log file is not writable",
        Some(io::ErrorKind::IsADirectory) => "diagnostic log file path is a directory",
        _ => "diagnostic log file could not be opened",
    };
    DiagnosticFailure::usage(LOG_FILE_UNUSABLE, message)
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;

    use claw_observability::telemetry::{
        self, LogFormat, TelemetryConfig, TelemetryErrorKind, TelemetryOutput,
    };

    use super::{
        Diagnostics, LOG_FILE_UNUSABLE, MAX_FIELD_BYTES, UNRESOLVED_ENDPOINT, Verbosity,
        bool_field, log_file_failure, sanitize,
    };

    /// A path inside this crate whose parent directory deliberately never exists.
    ///
    /// Nothing is created by a failing open, so the tree is left untouched.
    fn unopenable_path(name: &str) -> PathBuf {
        PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("no-such-diagnostic-directory")
            .join(name)
    }

    #[test]
    fn verbosity_defaults_to_off_and_maps_to_scoped_filter_directives() {
        assert_eq!(Verbosity::default(), Verbosity::Off);
        assert!(Verbosity::Off < Verbosity::Basic);
        assert!(Verbosity::Basic < Verbosity::Detailed);
        assert_eq!(Verbosity::Off.filter_directive(), "off");
        assert_eq!(Verbosity::Basic.filter_directive(), "gta_claw_cli=debug");
        assert_eq!(Verbosity::Detailed.filter_directive(), "gta_claw_cli=trace");
        for level in [Verbosity::Off, Verbosity::Basic, Verbosity::Detailed] {
            // A directive that scopes to this crate keeps every dependency that
            // logs — and every `log` record bridged into `tracing` — off the
            // stream these diagnostics own.
            let directive = level.filter_directive();
            assert!(
                directive == "off" || directive.starts_with("gta_claw_cli="),
                "{directive}"
            );
        }
    }

    #[test]
    fn the_default_channel_is_silent_and_installs_nothing() {
        // `install` returns before `telemetry::init` at `Off`, so this also
        // proves the default command never installs a global subscriber, and
        // never opens a file even when one was named.
        let diagnostics = Diagnostics::for_verbosity(Verbosity::Off);
        let path = unopenable_path("silent.jsonl");
        assert!(
            diagnostics.install(None).is_ok(),
            "the silent channel installs nothing"
        );
        assert!(
            diagnostics.install(Some(&path)).is_ok(),
            "a silent channel opens no destination"
        );
        assert!(!diagnostics.is_enabled());
        assert!(!path.exists());
        assert_eq!(diagnostics.endpoint(), UNRESOLVED_ENDPOINT);
    }

    #[test]
    fn an_unopenable_log_file_is_a_usage_failure_that_names_the_cause() {
        let path = unopenable_path("events.jsonl");
        let config = TelemetryConfig {
            format: LogFormat::Json,
            default_filter: "off".to_owned(),
            // The developer's own `GTA_CLAW_LOG` must not be able to turn this
            // into a filter failure before the open is ever attempted.
            filter_env: "GTA_CLAW_CLI_DIAGNOSTIC_TEST_FILTER_MUST_BE_UNSET".to_owned(),
        };
        let error = telemetry::init_with_output(&config, TelemetryOutput::file(&path))
            .expect_err("a missing parent directory cannot be opened");

        assert_eq!(error.kind(), TelemetryErrorKind::OutputOpen);
        assert_eq!(error.path(), Some(path.as_path()));
        let failure = log_file_failure(&error);
        assert_eq!(failure.status, LOG_FILE_UNUSABLE);
        assert_eq!(failure.category.code(), 2);
        assert_eq!(
            failure.message,
            "diagnostic log file directory does not exist"
        );
        assert!(
            !path.exists(),
            "a failed open must not leave a partial destination behind"
        );
    }

    #[test]
    fn the_endpoint_is_recorded_once_and_defaults_to_unresolved() {
        let diagnostics = Diagnostics::for_verbosity(Verbosity::Off);
        assert_eq!(diagnostics.endpoint(), UNRESOLVED_ENDPOINT);
        diagnostics.set_endpoint("ws://127.0.0.1:18789");
        diagnostics.set_endpoint("wss://elsewhere.example");
        assert_eq!(diagnostics.endpoint(), "ws://127.0.0.1:18789");
    }

    #[test]
    fn a_peer_value_cannot_forge_or_reorder_a_line() {
        assert_eq!(sanitize("gateway\nforged"), "gateway.forged");
        assert_eq!(sanitize("gateway\u{2028}forged"), "gateway.forged");
        assert_eq!(sanitize("gateway\u{2029}forged"), "gateway.forged");
        assert_eq!(sanitize("gateway\u{202e}forged"), "gateway.forged");
        assert_eq!(sanitize("gateway\u{2066}forged"), "gateway.forged");
        assert_eq!(sanitize("网关-v4"), "网关-v4");
        let long = sanitize(&"网".repeat(MAX_FIELD_BYTES));
        assert!(long.len() <= MAX_FIELD_BYTES);
        assert!(long.chars().all(|character| character == '网'));
    }

    #[test]
    fn the_endpoint_field_is_sanitized_before_any_event_carries_it() {
        let diagnostics = Diagnostics::for_verbosity(Verbosity::Off);
        diagnostics.set_endpoint("ws://host\u{202e}.example");
        assert_eq!(diagnostics.endpoint(), "ws://host..example");
    }

    #[test]
    fn the_installed_destination_is_a_sanitized_field_value() {
        assert_eq!(super::output_field(&TelemetryOutput::Stderr), "stderr");
        assert_eq!(
            super::output_field(&TelemetryOutput::file("run\u{202e}.jsonl")),
            "run..jsonl"
        );
    }

    #[test]
    fn booleans_render_one_way_everywhere() {
        assert_eq!(bool_field(true), "true");
        assert_eq!(bool_field(false), "false");
    }
}

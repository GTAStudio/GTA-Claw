//! Opt-in structured diagnostics that never draw on the drawn terminal.
//!
//! A terminal application cannot log to the terminal it is painting: a stray
//! line lands inside the alternate screen, shifts every cell the renderer
//! believes it owns, and survives as garbage in the restored shell. This module
//! therefore treats the destination as a decision, not a default, and
//! [`choose_sink`] is that decision written down.
//!
//! Events are ordinary `tracing` records emitted through
//! [`claw_observability::tracing`], so they reach the workspace's redacting
//! subscriber. Two consequences of that pipeline drive everything below:
//!
//! * Field *values* pass through the crate's redacting layer, message text does
//!   not. Every value therefore travels as a structured field, and no call site
//!   formats a value into a message.
//! * The subscriber's `EnvFilter` is the verbosity gate: a stage event is
//!   `debug`, per-request detail is `trace`, and [`Verbosity`] selects the
//!   matching directive, so there is no second gate to keep in step.
//!
//! Two destinations are offered. Redirecting standard error
//! (`gta-claw-tui -v 2>run.jsonl`) works from any mode, and `--log-file` names a
//! file that `claw-observability` appends to — the only destination that is
//! still available while the alternate screen owns the terminal.

use std::io;
use std::path::{Path, PathBuf};

use claw_observability::telemetry::{
    self, LogFormat, TelemetryConfig, TelemetryError, TelemetryErrorKind, TelemetryOutput,
};
use claw_observability::tracing;

/// Upper bound on one rendered field value.
const MAX_FIELD_BYTES: usize = 256;

/// How much of the Gateway path is reported.
#[derive(Clone, Copy, Debug, Default, Eq, Ord, PartialEq, PartialOrd)]
pub enum Verbosity {
    /// Nothing is emitted. Output is byte-identical to an uninstrumented run.
    #[default]
    Off,
    /// One record per stage of the connection.
    Basic,
    /// Adds correlation identifiers and per-request detail.
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
            Self::Basic => "gta_claw_tui=debug",
            Self::Detailed => "gta_claw_tui=trace",
        }
    }
}

/// Where diagnostics are written, once the drawn terminal has been ruled out.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum SinkChoice {
    /// Standard error, which is known not to be the terminal being painted.
    Stderr,
    /// An explicitly requested append-only file.
    File(PathBuf),
    /// Nothing is written.
    Suppressed,
}

/// Chooses a diagnostic destination that cannot corrupt the drawn terminal.
///
/// The rules, in order:
///
/// 1. No verbosity means no destination.
/// 2. An explicit `--log-file` always wins: a file is never the terminal being
///    drawn, so it is safe in every mode, and it is the only destination still
///    available while the alternate screen owns the terminal.
/// 3. Outside full-screen mode — `--plain`, or any non-interactive run — no
///    alternate screen is ever entered, so standard error is an ordinary stream
///    and is used directly.
/// 4. Inside full-screen mode, standard error is used only when it has been
///    redirected away from the terminal. Otherwise diagnostics are suppressed
///    rather than painted over the interface.
///
/// Rule 4 is the whole point: the returned choice is never [`SinkChoice::Stderr`]
/// when standard error *is* the terminal being drawn.
#[must_use]
pub fn choose_sink(
    verbosity: Verbosity,
    log_file: Option<&Path>,
    alternate_screen: bool,
    stderr_is_terminal: bool,
) -> SinkChoice {
    if matches!(verbosity, Verbosity::Off) {
        return SinkChoice::Suppressed;
    }
    if let Some(path) = log_file {
        return SinkChoice::File(path.to_path_buf());
    }
    if alternate_screen && stderr_is_terminal {
        return SinkChoice::Suppressed;
    }
    SinkChoice::Stderr
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
#[must_use]
pub fn sanitize(value: &str) -> String {
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
#[must_use]
pub const fn bool_field(value: bool) -> &'static str {
    if value { "true" } else { "false" }
}

/// Installs the diagnostic subscriber for `choice` and explains any gap.
///
/// Returns the one-line explanation the caller must print *before* entering the
/// alternate screen when diagnostics were asked for but cannot be delivered.
/// Losing diagnostics is never allowed to stop the interface from starting, and
/// after this returns nothing but `tracing` may write to standard error — so no
/// message can appear once the alternate screen owns the terminal, nor after it
/// has been torn down.
///
/// # Errors
///
/// Returns the message to show the user when [`SinkChoice::File`] cannot be
/// opened. That is the one gap that does stop the run: the user named where the
/// records go, and falling back to standard error would either write them
/// somewhere nobody is reading or paint them over the interface.
pub fn install(
    verbosity: Verbosity,
    choice: &SinkChoice,
    endpoint: &str,
) -> Result<Option<String>, String> {
    let output = match choice {
        SinkChoice::Suppressed => {
            return Ok((verbosity != Verbosity::Off).then(|| {
                "diagnostics are suppressed because standard error is the terminal being drawn; \
                 redirect standard error (2>file), pass --log-file, or add --plain"
                    .to_owned()
            }));
        }
        SinkChoice::Stderr => None,
        SinkChoice::File(path) => Some(TelemetryOutput::file(path)),
    };
    let config = TelemetryConfig {
        format: LogFormat::Json,
        default_filter: verbosity.filter_directive().to_owned(),
        ..TelemetryConfig::default()
    };
    // The default destination is `init`, which is standard error. Only an
    // explicit `--log-file` reaches `init_with_output`.
    let installed = output.map_or_else(
        || telemetry::init(&config),
        |output| telemetry::init_with_output(&config, output),
    );
    match installed {
        Ok(handle) => {
            tracing::debug!(
                action = "telemetry.install",
                outcome = "success",
                endpoint = sanitize(endpoint),
                telemetry.filter_env = config.filter_env.as_str(),
                telemetry.default_filter = config.default_filter.as_str(),
                telemetry.format = "json",
                telemetry.output = output_field(handle.output()),
            );
            Ok(None)
        }
        // The requested file is the one failure the user has to act on, and the
        // only one that is about the destination rather than the filter or the
        // subscriber.
        Err(error) if error.kind() == TelemetryErrorKind::OutputOpen => Err(open_failure(&error)),
        // Nothing is listening yet, so this is the one diagnostic that
        // cannot be a `tracing` event; it is handed back to the caller
        // to print before the alternate screen is entered.
        Err(error) => Ok(Some(format!("diagnostics unavailable: {error}"))),
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

/// Explains a `--log-file` that cannot be opened, in the user's own terms.
///
/// The typed error names both the path and the I/O category, and both are shown:
/// the path came from the command line and is about to be printed to a terminal,
/// so it is sanitized first.
fn open_failure(error: &TelemetryError) -> String {
    let destination = error.path().map_or_else(
        || "the requested log file".to_owned(),
        |path| format!("'{}'", sanitize(&path.display().to_string())),
    );
    let reason = match error.io_kind() {
        Some(io::ErrorKind::NotFound) => "its directory does not exist",
        Some(io::ErrorKind::PermissionDenied) => "it is not writable",
        Some(io::ErrorKind::IsADirectory) => "it is a directory",
        _ => "it could not be opened",
    };
    format!(
        "diagnostics cannot be written to {destination}: {reason}. Point --log-file at a writable \
         path inside a directory that already exists; the file is appended to, and no directory is \
         ever created for it"
    )
}

#[cfg(test)]
mod tests {
    use std::path::{Path, PathBuf};

    use claw_observability::telemetry::{
        self, LogFormat, TelemetryConfig, TelemetryErrorKind, TelemetryOutput,
    };

    use super::{
        MAX_FIELD_BYTES, SinkChoice, Verbosity, bool_field, choose_sink, install, open_failure,
        output_field, sanitize,
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
    fn the_drawn_terminal_is_never_a_diagnostic_destination() {
        for verbosity in [Verbosity::Off, Verbosity::Basic, Verbosity::Detailed] {
            for alternate_screen in [false, true] {
                for stderr_is_terminal in [false, true] {
                    let choice = choose_sink(verbosity, None, alternate_screen, stderr_is_terminal);
                    assert!(
                        !(choice == SinkChoice::Stderr && alternate_screen && stderr_is_terminal),
                        "{verbosity:?} {alternate_screen} {stderr_is_terminal}"
                    );
                    if verbosity == Verbosity::Off {
                        assert_eq!(choice, SinkChoice::Suppressed);
                    }
                }
            }
        }
    }

    #[test]
    fn each_sink_rule_resolves_to_its_documented_destination() {
        assert_eq!(
            choose_sink(Verbosity::Basic, None, false, true),
            SinkChoice::Stderr,
            "--plain never enters the alternate screen"
        );
        assert_eq!(
            choose_sink(Verbosity::Basic, None, true, false),
            SinkChoice::Stderr,
            "redirected standard error is not the drawn terminal"
        );
        assert_eq!(
            choose_sink(Verbosity::Detailed, None, true, true),
            SinkChoice::Suppressed
        );
        assert_eq!(
            choose_sink(Verbosity::Off, None, false, false),
            SinkChoice::Suppressed
        );
    }

    #[test]
    fn an_explicit_log_file_wins_everywhere_except_at_off() {
        let path = Path::new("run.jsonl");
        for alternate_screen in [false, true] {
            for stderr_is_terminal in [false, true] {
                assert_eq!(
                    choose_sink(
                        Verbosity::Basic,
                        Some(path),
                        alternate_screen,
                        stderr_is_terminal
                    ),
                    SinkChoice::File(path.to_path_buf()),
                    "a file is never the terminal being drawn: \
                     {alternate_screen} {stderr_is_terminal}"
                );
            }
        }
        assert_eq!(
            choose_sink(Verbosity::Off, Some(path), false, false),
            SinkChoice::Suppressed,
            "no verbosity still means no destination, and no file is opened"
        );
    }

    #[test]
    fn the_tracing_filter_never_switches_on_a_dependency() {
        assert_eq!(Verbosity::default(), Verbosity::Off);
        assert!(Verbosity::Off < Verbosity::Basic);
        assert!(Verbosity::Basic < Verbosity::Detailed);
        assert_eq!(Verbosity::Off.filter_directive(), "off");
        assert_eq!(Verbosity::Basic.filter_directive(), "gta_claw_tui=debug");
        assert_eq!(Verbosity::Detailed.filter_directive(), "gta_claw_tui=trace");
        for level in [Verbosity::Off, Verbosity::Basic, Verbosity::Detailed] {
            let directive = level.filter_directive();
            assert!(
                directive == "off" || directive.starts_with("gta_claw_tui="),
                "{directive}"
            );
        }
    }

    #[test]
    fn a_suppressed_destination_explains_itself_only_when_asked_for() {
        assert_eq!(
            install(
                Verbosity::Off,
                &SinkChoice::Suppressed,
                "ws://127.0.0.1:18789"
            ),
            Ok(None),
            "a default run has nothing to explain"
        );
        let notice = install(
            Verbosity::Basic,
            &SinkChoice::Suppressed,
            "ws://127.0.0.1:18789",
        )
        .expect("suppression is never a failure")
        .expect("notice");
        assert!(notice.contains("--plain"), "{notice}");
        assert!(notice.contains("2>file"), "{notice}");
        assert!(notice.contains("--log-file"), "{notice}");
    }

    #[test]
    fn an_unopenable_log_file_names_the_path_and_the_cause() {
        let path = unopenable_path("events.jsonl");
        let config = TelemetryConfig {
            format: LogFormat::Json,
            default_filter: "off".to_owned(),
            // The developer's own `GTA_CLAW_LOG` must not be able to turn this
            // into a filter failure before the open is ever attempted.
            filter_env: "GTA_CLAW_TUI_DIAGNOSTIC_TEST_FILTER_MUST_BE_UNSET".to_owned(),
        };
        let error = telemetry::init_with_output(&config, TelemetryOutput::file(&path))
            .expect_err("a missing parent directory cannot be opened");

        assert_eq!(error.kind(), TelemetryErrorKind::OutputOpen);
        assert_eq!(error.path(), Some(path.as_path()));
        let message = open_failure(&error);
        assert!(message.contains("events.jsonl"), "{message}");
        assert!(
            message.contains("its directory does not exist"),
            "{message}"
        );
        assert!(message.contains("--log-file"), "{message}");
        assert!(
            !path.exists(),
            "a failed open must not leave a partial destination behind"
        );
    }

    #[test]
    fn the_installed_destination_is_a_sanitized_field_value() {
        assert_eq!(output_field(&TelemetryOutput::Stderr), "stderr");
        assert_eq!(
            output_field(&TelemetryOutput::file("run\u{202e}.jsonl")),
            "run..jsonl"
        );
    }

    #[test]
    fn peer_text_cannot_forge_or_reorder_a_line() {
        assert_eq!(sanitize("ready\nforged"), "ready.forged");
        assert_eq!(sanitize("ready\u{2028}forged"), "ready.forged");
        assert_eq!(sanitize("ready\u{2029}forged"), "ready.forged");
        assert_eq!(sanitize("ready\u{202e}forged"), "ready.forged");
        assert_eq!(sanitize("ready\u{2066}forged"), "ready.forged");
        assert_eq!(sanitize("网关-v4"), "网关-v4");
        let long = sanitize(&"网".repeat(MAX_FIELD_BYTES));
        assert!(long.len() <= MAX_FIELD_BYTES);
        assert!(long.chars().all(|character| character == '网'));
    }

    #[test]
    fn booleans_render_one_way_everywhere() {
        assert_eq!(bool_field(true), "true");
        assert_eq!(bool_field(false), "false");
    }
}

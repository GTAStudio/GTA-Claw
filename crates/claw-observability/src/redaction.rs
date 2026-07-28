//! Secret wrappers and the mandatory tracing redaction layer.

use std::collections::BTreeMap;
use std::fmt;
use std::io::Write;
use std::sync::{Arc, Mutex};
use std::time::{SystemTime, UNIX_EPOCH};

use serde::Serialize;
use serde_json::{Map, Number, Value, json};
use tracing::field::{Field, Visit};
use tracing::{Event, Id, Subscriber};
use tracing_subscriber::field::RecordFields;
use tracing_subscriber::layer::{Context, Layer};
use tracing_subscriber::registry::LookupSpan;

use crate::telemetry::LogFormat;

/// Stable replacement text used wherever a secret would otherwise be rendered.
pub const REDACTED: &str = "[REDACTED]";

/// A value that can only be accessed through an explicit exposure method.
///
/// `Debug`, `Display`, and `Serialize` always emit [`REDACTED`], irrespective
/// of the wrapped type's formatting or serialization implementation.
#[derive(Clone, Default, Eq, PartialEq)]
pub struct Secret<T>(T);

impl<T> Secret<T> {
    /// Wraps a secret value.
    pub const fn new(value: T) -> Self {
        Self(value)
    }

    /// Explicitly borrows the protected value.
    #[must_use]
    pub const fn expose_secret(&self) -> &T {
        &self.0
    }

    /// Explicitly consumes the wrapper and returns the protected value.
    #[must_use]
    pub fn into_inner(self) -> T {
        self.0
    }
}

impl<T> fmt::Debug for Secret<T> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(REDACTED)
    }
}

impl<T> fmt::Display for Secret<T> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(REDACTED)
    }
}

impl<T> Serialize for Secret<T> {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_str(REDACTED)
    }
}

/// The value substituted for a secret, as a `serde_json` value.
///
/// [`REDACTED`] is a fixed constant: the replacement carries no length, prefix
/// or type information about the value it replaced, so two different secrets
/// are indistinguishable once redacted.
fn redacted_value() -> Value {
    Value::String(REDACTED.to_owned())
}

/// Field-name components that always denote a secret value.
///
/// Matching is on whole components rather than substrings so that `monkey` is
/// not treated as a key. Plural spellings are listed explicitly for the same
/// reason: `tokens` would otherwise slip past a `token` comparison.
const SECRET_TERMS: [&str; 18] = [
    "authorization",
    "bearer",
    "cookie",
    "cookies",
    "credential",
    "credentials",
    "jwt",
    "key",
    "keys",
    "passphrase",
    "passwd",
    "password",
    "passwords",
    "pwd",
    "secret",
    "secrets",
    "token",
    "tokens",
];

/// Words that qualify a `SECRET_TERMS` entry in an unseparated spelling.
///
/// `apiKey` and `api_key` already split into components, but the all-lowercase
/// `apikey` does not. A component therefore also counts as secret when it is
/// exactly one of these words followed by a secret term, which keeps `apikey`
/// and `accesstoken` covered without redacting `monkey` or `whiskey`.
const SECRET_QUALIFIERS: [&str; 21] = [
    "access",
    "api",
    "app",
    "auth",
    "bearer",
    "client",
    "consumer",
    "encryption",
    "id",
    "identity",
    "master",
    "oauth",
    "private",
    "public",
    "refresh",
    "secret",
    "service",
    "session",
    "sign",
    "signing",
    "user",
];

fn component_is_secret(component: &str) -> bool {
    if SECRET_TERMS.contains(&component) {
        return true;
    }
    SECRET_TERMS.iter().any(|term| {
        component
            .strip_suffix(term)
            .is_some_and(|qualifier| SECRET_QUALIFIERS.contains(&qualifier))
    })
}

/// Returns whether a structured field name must be redacted.
///
/// The name is first normalized: `camelCase` boundaries become separators, so
/// do runs of punctuation, and the result is lowercased. Every resulting
/// component is then matched against the crate's secret-term list, which makes
/// `apiKey`, `api_key`, `apikey`, `http.request.header.authorization` and
/// `refresh-tokens` all sensitive while leaving `session_id` and `monkey`
/// alone.
#[must_use]
pub fn is_sensitive_field(name: &str) -> bool {
    // Splitting a camelCase boundary inserts a separator, so the normalized
    // form can be longer than the input.
    let mut normalized = String::with_capacity(name.len() + 8);
    let mut previous_was_lowercase = false;
    for character in name.chars() {
        if character.is_ascii_uppercase() {
            if previous_was_lowercase {
                normalized.push('_');
            }
            normalized.push(character.to_ascii_lowercase());
            previous_was_lowercase = false;
        } else if character.is_ascii_alphanumeric() {
            normalized.push(character.to_ascii_lowercase());
            previous_was_lowercase = character.is_ascii_lowercase();
        } else {
            normalized.push('_');
            previous_was_lowercase = false;
        }
    }
    normalized.split('_').any(component_is_secret)
}

#[derive(Clone, Debug, Default)]
struct RecordedFields(BTreeMap<String, Value>);

impl RecordedFields {
    fn record<R>(&mut self, values: R)
    where
        R: RecordFields,
    {
        values.record(&mut FieldVisitor(&mut self.0));
    }
}

struct FieldVisitor<'a>(&'a mut BTreeMap<String, Value>);

impl FieldVisitor<'_> {
    fn insert(&mut self, field: &Field, value: Value) {
        let value = if is_sensitive_field(field.name()) {
            redacted_value()
        } else {
            value
        };
        self.0.insert(field.name().to_owned(), value);
    }
}

/// Every [`Visit`] method that is not overridden below funnels into
/// [`Visit::record_debug`] through its `tracing-core` default body, and every
/// override goes through [`FieldVisitor::insert`]. There is therefore no
/// recording entry point that can reach the output without passing the field
/// name through [`is_sensitive_field`].
impl Visit for FieldVisitor<'_> {
    fn record_bool(&mut self, field: &Field, value: bool) {
        self.insert(field, Value::Bool(value));
    }

    fn record_i64(&mut self, field: &Field, value: i64) {
        self.insert(field, Value::Number(Number::from(value)));
    }

    fn record_u64(&mut self, field: &Field, value: u64) {
        self.insert(field, Value::Number(Number::from(value)));
    }

    fn record_f64(&mut self, field: &Field, value: f64) {
        let rendered = Number::from_f64(value).map_or(Value::Null, Value::Number);
        self.insert(field, rendered);
    }

    fn record_str(&mut self, field: &Field, value: &str) {
        self.insert(field, Value::String(value.to_owned()));
    }

    fn record_error(&mut self, field: &Field, value: &(dyn std::error::Error + 'static)) {
        self.insert(field, Value::String(value.to_string()));
    }

    fn record_debug(&mut self, field: &Field, value: &dyn fmt::Debug) {
        self.insert(field, Value::String(format!("{value:?}")));
    }
}

#[derive(Debug)]
struct WriterState<W> {
    writer: W,
    last_error: Option<String>,
    shutdown_error: Option<String>,
    is_shutdown: bool,
}

/// A tracing subscriber layer that redacts sensitive structured fields.
///
/// The layer emits newline-delimited structured JSON or a human-readable line.
/// Span fields are retained and emitted with each event to preserve correlation.
#[derive(Debug)]
pub struct RedactingLayer<W> {
    format: LogFormat,
    state: Arc<Mutex<WriterState<W>>>,
}

impl<W> Clone for RedactingLayer<W> {
    fn clone(&self) -> Self {
        Self {
            format: self.format,
            state: Arc::clone(&self.state),
        }
    }
}

impl<W> RedactingLayer<W>
where
    W: Write,
{
    /// Creates a redacting layer using the requested format and writer.
    #[must_use]
    pub fn new(format: LogFormat, writer: W) -> Self {
        Self {
            format,
            state: Arc::new(Mutex::new(WriterState {
                writer,
                last_error: None,
                shutdown_error: None,
                is_shutdown: false,
            })),
        }
    }

    /// Returns and clears the most recent writer failure.
    ///
    /// # Errors
    ///
    /// Returns the message `telemetry writer lock poisoned` when a previous
    /// caller panicked while holding the writer mutex. Poisoning is reported
    /// rather than silently ignored because it means log records were lost.
    /// An attempted event after shutdown is reported here without changing the
    /// already-established shutdown result.
    pub fn take_error(&self) -> Result<Option<String>, String> {
        let mut state = self
            .state
            .lock()
            .map_err(|_| "telemetry writer lock poisoned".to_owned())?;
        Ok(state.last_error.take())
    }

    /// Flushes the writer and prevents subsequent records from being accepted.
    ///
    /// The result is stable across repeated calls. All clones share the same
    /// shutdown state, so a clean return establishes one deterministic flush
    /// boundary for the layer.
    ///
    /// # Errors
    ///
    /// Returns a pending write failure, a final flush failure, or `telemetry
    /// writer lock poisoned`.
    pub fn shutdown(&self) -> Result<(), String> {
        let mut state = self
            .state
            .lock()
            .map_err(|_| "telemetry writer lock poisoned".to_owned())?;
        if state.is_shutdown {
            return state.shutdown_error.clone().map_or(Ok(()), Err);
        }

        let pending_error = state.last_error.clone();
        let flush_error = state
            .writer
            .flush()
            .err()
            .map(|error| format!("telemetry flush failed: {error}"));
        let shutdown_error = match (pending_error, flush_error) {
            (Some(write_error), Some(flush_error)) => Some(format!(
                "telemetry write failed: {write_error}; {flush_error}"
            )),
            (Some(write_error), None) => Some(format!("telemetry write failed: {write_error}")),
            (None, flush_error) => flush_error,
        };
        state.is_shutdown = true;
        state.shutdown_error.clone_from(&shutdown_error);
        let result = shutdown_error.map_or(Ok(()), |error| {
            state.last_error = Some(error.clone());
            Err(error)
        });
        drop(state);
        result
    }

    /// Writes one already newline-terminated record.
    ///
    /// The terminator is part of `record` so a line reaches the writer in a
    /// single `write_all`: a second call for the newline would both double the
    /// syscalls per event and allow a half-written record if it failed.
    fn write_record(&self, record: &str) {
        let Ok(mut state) = self.state.lock() else {
            eprintln!("claw-observability: telemetry writer lock poisoned");
            return;
        };
        if state.is_shutdown {
            let error = "telemetry event emitted after shutdown".to_owned();
            state.last_error = Some(error.clone());
            eprintln!("claw-observability: {error}");
            return;
        }
        if let Err(error) = state
            .writer
            .write_all(record.as_bytes())
            .and_then(|()| state.writer.flush())
        {
            state.last_error = Some(error.to_string());
            eprintln!("claw-observability: telemetry write failed: {error}");
        }
    }
}

impl<S, W> Layer<S> for RedactingLayer<W>
where
    S: Subscriber + for<'lookup> LookupSpan<'lookup>,
    W: Write + Send + 'static,
{
    fn on_new_span(
        &self,
        attributes: &tracing::span::Attributes<'_>,
        id: &Id,
        context: Context<'_, S>,
    ) {
        if let Some(span) = context.span(id) {
            let mut fields = RecordedFields::default();
            fields.record(attributes);
            span.extensions_mut().insert(fields);
        }
    }

    fn on_record(&self, id: &Id, values: &tracing::span::Record<'_>, context: Context<'_, S>) {
        if let Some(span) = context.span(id) {
            let mut extensions = span.extensions_mut();
            if let Some(fields) = extensions.get_mut::<RecordedFields>() {
                fields.record(values);
            }
        }
    }

    fn on_event(&self, event: &Event<'_>, context: Context<'_, S>) {
        let metadata = event.metadata();
        let mut event_fields = RecordedFields::default();
        event_fields.record(event);
        let fields = event_fields.0;

        let timestamp_ms = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_or(0, |duration| duration.as_millis());
        let mut line = match self.format {
            LogFormat::Json => {
                let spans = context
                    .event_scope(event)
                    .map(|scope| {
                        scope
                            .from_root()
                            .map(|span| {
                                let fields = span.extensions().get::<RecordedFields>().map_or_else(
                                    Map::new,
                                    |recorded| {
                                        recorded
                                            .0
                                            .iter()
                                            .map(|(key, value)| (key.clone(), value.clone()))
                                            .collect()
                                    },
                                );
                                json!({
                                    "name": span.metadata().name(),
                                    "fields": fields,
                                })
                            })
                            .collect::<Vec<_>>()
                    })
                    .unwrap_or_default();
                serde_json::to_string(&json!({
                    "timestamp_ms": timestamp_ms,
                    "level": metadata.level().to_string(),
                    "target": metadata.target(),
                    "name": metadata.name(),
                    "fields": fields,
                    "spans": spans,
                }))
                .unwrap_or_else(|error| {
                    format!(
                        "{{\"level\":\"ERROR\",\"message\":\
                         \"telemetry serialization failed: {error}\"}}"
                    )
                })
            }
            LogFormat::Human => {
                // Only the span names reach a human line, so the per-span field
                // maps the JSON branch builds are never materialized here.
                let span_names = context
                    .event_scope(event)
                    .map(|scope| {
                        scope
                            .from_root()
                            .map(|span| span.metadata().name())
                            .collect::<Vec<_>>()
                    })
                    .unwrap_or_default()
                    .join(":");
                format!(
                    "{} {} {} {} spans=[{}] fields={}",
                    timestamp_ms,
                    metadata.level(),
                    metadata.target(),
                    metadata.name(),
                    span_names,
                    serde_json::to_string(&fields)
                        .unwrap_or_else(|error| format!("{{\"serialization_error\":\"{error}\"}}"))
                )
            }
        };
        line.push('\n');
        self.write_record(&line);
    }
}

#[cfg(test)]
mod tests {
    use std::fmt;
    use std::sync::{Arc, Mutex};

    use serde::Serialize;
    use serde_json::{Value, json};
    use tracing_subscriber::layer::SubscriberExt;

    use super::{REDACTED, RedactingLayer, Secret, is_sensitive_field};
    use crate::telemetry::LogFormat;

    #[derive(Clone, Debug, Default)]
    struct SharedWriter(Arc<Mutex<Vec<u8>>>);

    impl std::io::Write for SharedWriter {
        fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
            self.0
                .lock()
                .map_err(|_| std::io::Error::other("test writer lock poisoned"))?
                .extend_from_slice(bytes);
            Ok(bytes.len())
        }

        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    #[derive(Debug, Default)]
    struct FlushState {
        bytes: Vec<u8>,
        flushes: usize,
        fail_flush: bool,
    }

    #[derive(Clone, Debug, Default)]
    struct FlushWriter(Arc<Mutex<FlushState>>);

    impl std::io::Write for FlushWriter {
        fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
            self.0
                .lock()
                .map_err(|_| std::io::Error::other("test writer lock poisoned"))?
                .bytes
                .extend_from_slice(bytes);
            Ok(bytes.len())
        }

        fn flush(&mut self) -> std::io::Result<()> {
            let mut state = self
                .0
                .lock()
                .map_err(|_| std::io::Error::other("test writer lock poisoned"))?;
            state.flushes += 1;
            if state.fail_flush {
                Err(std::io::Error::other("forced flush failure"))
            } else {
                Ok(())
            }
        }
    }

    #[derive(Serialize)]
    struct SecretDocument<'a> {
        password: &'a Secret<String>,
    }

    #[test]
    fn secret_never_formats_or_serializes_its_value() {
        let secret = Secret::new("hunter2".to_owned());
        assert_eq!(format!("{secret:?}"), REDACTED);
        assert_eq!(format!("{secret}"), REDACTED);
        assert_eq!(
            serde_json::to_string(&secret).expect("serialize secret"),
            "\"[REDACTED]\""
        );
        assert_eq!(
            serde_json::to_value(SecretDocument { password: &secret }).expect("serialize document"),
            json!({"password": "[REDACTED]"})
        );
        assert_eq!(secret.expose_secret(), "hunter2");
    }

    #[test]
    fn sensitive_field_policy_is_explicit() {
        let cases = [
            ("password", true),
            ("refresh-token", true),
            ("api_key", true),
            ("apiKey", true),
            ("privateKey", true),
            ("http.request.header.authorization", true),
            ("authorization", true),
            ("cookie", true),
            ("provider", false),
            ("monkey", false),
            ("session_id", false),
        ];
        assert_eq!(
            cases.map(|(field, _)| is_sensitive_field(field)),
            cases.map(|(_, expected)| expected)
        );
    }

    #[test]
    fn sensitive_field_policy_covers_plural_and_unseparated_spellings() {
        let cases = [
            // Plurals: a `token` comparison alone would miss all of these.
            ("tokens", true),
            ("refresh_tokens", true),
            ("credentials", true),
            ("client_credentials", true),
            ("api_keys", true),
            ("secrets", true),
            ("cookies", true),
            // All-lowercase concatenations, which the camelCase splitter cannot
            // separate on its own.
            ("apikey", true),
            ("apikeys", true),
            ("accesstoken", true),
            ("refreshtoken", true),
            ("clientsecret", true),
            ("idtoken", true),
            ("sessionkey", true),
            ("userpassword", true),
            // Other names for the same thing.
            ("passphrase", true),
            ("pwd", true),
            ("jwt", true),
            ("bearer", true),
            ("set-cookie", true),
            ("proxy-authorization", true),
            // Words that merely end in a secret term must stay visible.
            ("monkey", false),
            ("donkey", false),
            ("turkey", false),
            ("whiskey", false),
            ("hockey", false),
            // Ordinary correlation and lifecycle fields must stay visible.
            ("session_id", false),
            ("turn_id", false),
            ("provider_name", false),
            ("keystore_path", false),
            ("message", false),
            ("error", false),
        ];
        let actual = cases.map(|(field, _)| is_sensitive_field(field));
        let expected = cases.map(|(_, expected)| expected);
        let mismatched = cases
            .iter()
            .zip(actual)
            .zip(expected)
            .filter(|((_, actual), expected)| actual != expected)
            .map(|((case, _), _)| case.0)
            .collect::<Vec<_>>();
        assert_eq!(mismatched, Vec::<&str>::new());
    }

    #[test]
    fn tracing_layer_redacts_event_and_span_fields() {
        let writer = SharedWriter::default();
        let captured = Arc::clone(&writer.0);
        let layer = RedactingLayer::new(LogFormat::Json, writer);
        let subscriber = tracing_subscriber::registry().with(layer);

        tracing::subscriber::with_default(subscriber, || {
            let span = tracing::info_span!(
                "provider.request",
                provider = "openai",
                api_token = "span-secret"
            );
            let _entered = span.enter();
            tracing::info!(
                session_id = "s-1",
                password = "event-secret",
                "request complete"
            );
        });

        let output = String::from_utf8(captured.lock().expect("capture lock").clone())
            .expect("UTF-8 output");
        let lines = output.lines().collect::<Vec<_>>();
        assert_eq!(lines.len(), 1);
        let value: Value = serde_json::from_str(lines[0]).expect("JSON telemetry");
        assert_eq!(value["level"], "INFO");
        assert_eq!(value["fields"]["message"], "request complete");
        assert_eq!(value["fields"]["session_id"], "s-1");
        assert_eq!(value["fields"]["password"], REDACTED);
        assert_eq!(value["spans"][0]["name"], "provider.request");
        assert_eq!(value["spans"][0]["fields"]["provider"], "openai");
        assert_eq!(value["spans"][0]["fields"]["api_token"], REDACTED);
        let encoded = serde_json::to_string(&value).expect("serialize captured value");
        let decoded: Value = serde_json::from_str(&encoded).expect("decode captured value");
        assert_eq!(
            decoded["fields"]
                .as_object()
                .expect("event fields")
                .values()
                .filter(|field| field.as_str() == Some("event-secret"))
                .count(),
            0
        );
        assert_eq!(
            decoded["spans"][0]["fields"]
                .as_object()
                .expect("span fields")
                .values()
                .filter(|field| field.as_str() == Some("span-secret"))
                .count(),
            0
        );
    }

    #[test]
    fn shutdown_is_idempotent_and_rejects_late_events() {
        let writer = FlushWriter::default();
        let captured = Arc::clone(&writer.0);
        let layer = RedactingLayer::new(LogFormat::Json, writer);
        let subscriber = tracing_subscriber::registry().with(layer.clone());
        tracing::subscriber::with_default(subscriber, || {
            tracing::info!(session_id = "s-1", "before shutdown");
        });

        assert_eq!(captured.lock().expect("capture lock").flushes, 1);
        layer.shutdown().expect("first shutdown");
        layer.shutdown().expect("idempotent shutdown");
        let bytes_after_shutdown = {
            let state = captured.lock().expect("capture lock");
            assert_eq!(state.flushes, 2);
            state.bytes.len()
        };

        let subscriber = tracing_subscriber::registry().with(layer.clone());
        tracing::subscriber::with_default(subscriber, || {
            tracing::info!(session_id = "s-2", "after shutdown");
        });
        assert_eq!(
            captured.lock().expect("capture lock").bytes.len(),
            bytes_after_shutdown
        );
        assert_eq!(
            layer.take_error().expect("writer error"),
            Some("telemetry event emitted after shutdown".to_owned())
        );
        layer
            .shutdown()
            .expect("late event does not rewrite the completed flush result");
    }

    #[test]
    fn shutdown_preserves_the_first_flush_result() {
        let writer = FlushWriter::default();
        writer.0.lock().expect("writer lock").fail_flush = true;
        let layer = RedactingLayer::new(LogFormat::Json, writer.clone());

        let first = layer.shutdown().expect_err("flush must fail");
        assert_eq!(first, "telemetry flush failed: forced flush failure");
        assert_eq!(writer.0.lock().expect("writer lock").flushes, 1);
        assert_eq!(layer.shutdown().expect_err("result remains stable"), first);
        assert_eq!(writer.0.lock().expect("writer lock").flushes, 1);
        assert_eq!(layer.take_error().expect("take error"), Some(first.clone()));

        let subscriber = tracing_subscriber::registry().with(layer.clone());
        tracing::subscriber::with_default(subscriber, || {
            tracing::info!("after failed shutdown");
        });
        assert_eq!(
            layer.take_error().expect("late event error"),
            Some("telemetry event emitted after shutdown".to_owned())
        );
        assert_eq!(
            layer
                .shutdown()
                .expect_err("late events do not rewrite shutdown history"),
            first
        );
    }

    #[test]
    fn secret_debug_ignores_wrapped_debug_implementation() {
        struct LoudSecret;

        impl fmt::Debug for LoudSecret {
            fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter.write_str("must-not-appear")
            }
        }

        assert_eq!(format!("{:?}", Secret::new(LoudSecret)), REDACTED);
    }

    fn capture_json_events(emit: impl FnOnce()) -> Vec<Value> {
        let writer = SharedWriter::default();
        let captured = Arc::clone(&writer.0);
        let subscriber =
            tracing_subscriber::registry().with(RedactingLayer::new(LogFormat::Json, writer));
        tracing::subscriber::with_default(subscriber, emit);
        let output = String::from_utf8(captured.lock().expect("capture lock").clone())
            .expect("UTF-8 output");
        output
            .lines()
            .map(|line| serde_json::from_str(line).expect("JSON telemetry"))
            .collect()
    }

    #[test]
    fn every_value_kind_is_redacted_by_field_name() {
        #[derive(Debug)]
        struct LoudError;

        impl fmt::Display for LoudError {
            fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter.write_str("must-not-appear")
            }
        }

        impl std::error::Error for LoudError {}

        // One event per `tracing::field::Visit` entry point the layer can be
        // driven through: a new value kind must not become a redaction bypass.
        let events = capture_json_events(|| {
            tracing::info!(api_key = "text");
            tracing::info!(api_key = 42_i64);
            tracing::info!(api_key = 42_u64);
            tracing::info!(api_key = 42_i128);
            tracing::info!(api_key = 42_u128);
            tracing::info!(api_key = 4.25_f64);
            tracing::info!(api_key = true);
            tracing::info!(api_key = &b"must-not-appear"[..]);
            tracing::info!(api_key = ?"must-not-appear");
            tracing::info!(api_key = %"must-not-appear");
            tracing::info!(api_key = &LoudError as &dyn std::error::Error);
        });

        assert_eq!(events.len(), 11);
        for event in &events {
            assert_eq!(event["fields"]["api_key"], REDACTED);
        }
        assert!(
            !events
                .iter()
                .any(|event| event.to_string().contains("must-not-appear"))
        );
    }

    #[test]
    fn redacted_values_reveal_neither_length_nor_prefix() {
        let events = capture_json_events(|| {
            tracing::info!(password = "a");
            tracing::info!(password = "correct-horse-battery-staple-0123456789");
        });

        assert_eq!(events.len(), 2);
        assert_eq!(events[0]["fields"], events[1]["fields"]);
        assert_eq!(events[0]["fields"]["password"], REDACTED);
        assert_eq!(
            format!("{}", Secret::new("a")),
            format!("{}", Secret::new("correct-horse-battery-staple-0123456789"))
        );
    }

    #[test]
    fn lifecycle_and_error_fields_survive_redaction() {
        #[derive(Debug)]
        struct RefusedError;

        impl fmt::Display for RefusedError {
            fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter.write_str("connection refused")
            }
        }

        impl std::error::Error for RefusedError {}

        let events = capture_json_events(|| {
            let span = tracing::info_span!("session", session.id = "s-1");
            let _entered = span.enter();
            tracing::error!(
                turn.id = "t-1",
                attempt = 2_u64,
                error = &RefusedError as &dyn std::error::Error,
                access_token = "must-not-appear",
                "provider request failed"
            );
        });

        assert_eq!(events.len(), 1);
        let event = &events[0];
        assert_eq!(event["level"], "ERROR");
        assert_eq!(event["fields"]["message"], "provider request failed");
        assert_eq!(event["fields"]["turn.id"], "t-1");
        assert_eq!(event["fields"]["attempt"], 2);
        assert_eq!(event["fields"]["error"], "connection refused");
        assert_eq!(event["fields"]["access_token"], REDACTED);
        assert_eq!(event["spans"][0]["name"], "session");
        assert_eq!(event["spans"][0]["fields"]["session.id"], "s-1");
        assert!(!event.to_string().contains("must-not-appear"));
    }

    #[test]
    fn human_format_carries_the_same_span_names_and_redaction() {
        let writer = SharedWriter::default();
        let captured = Arc::clone(&writer.0);
        let subscriber =
            tracing_subscriber::registry().with(RedactingLayer::new(LogFormat::Human, writer));

        tracing::subscriber::with_default(subscriber, || {
            let session = tracing::info_span!("session", session.id = "s-1");
            let _session = session.enter();
            let turn = tracing::info_span!("turn", turn.id = "t-1");
            let _turn = turn.enter();
            tracing::warn!(api_token = "must-not-appear", "rate limited");
        });

        let output = String::from_utf8(captured.lock().expect("capture lock").clone())
            .expect("UTF-8 output");
        let lines = output.lines().collect::<Vec<_>>();
        assert_eq!(lines.len(), 1);
        assert!(lines[0].contains(" WARN "), "{}", lines[0]);
        assert!(lines[0].contains("spans=[session:turn]"), "{}", lines[0]);
        assert!(
            lines[0].contains("\"message\":\"rate limited\""),
            "{}",
            lines[0]
        );
        assert!(
            lines[0].contains(&format!("\"api_token\":\"{REDACTED}\"")),
            "{}",
            lines[0]
        );
        assert!(!lines[0].contains("must-not-appear"));
    }
}

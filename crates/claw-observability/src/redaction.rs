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

/// Returns whether a structured field name must be redacted.
#[must_use]
pub fn is_sensitive_field(name: &str) -> bool {
    let mut normalized = String::with_capacity(name.len());
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
    normalized.split('_').any(|component| {
        matches!(
            component,
            "authorization"
                | "cookie"
                | "credential"
                | "key"
                | "passwd"
                | "password"
                | "secret"
                | "token"
        )
    })
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
            Value::String(REDACTED.to_owned())
        } else {
            value
        };
        self.0.insert(field.name().to_owned(), value);
    }
}

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
            })),
        }
    }

    /// Returns and clears the most recent writer failure.
    ///
    /// Poisoned synchronization is reported rather than silently ignored.
    pub fn take_error(&self) -> Result<Option<String>, String> {
        let mut state = self
            .state
            .lock()
            .map_err(|_| "telemetry writer lock poisoned".to_owned())?;
        Ok(state.last_error.take())
    }

    fn write_line(&self, line: &str) {
        let Ok(mut state) = self.state.lock() else {
            eprintln!("claw-observability: telemetry writer lock poisoned");
            return;
        };
        if let Err(error) = state
            .writer
            .write_all(line.as_bytes())
            .and_then(|()| state.writer.write_all(b"\n"))
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

        let timestamp_ms = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_or(0, |duration| duration.as_millis());
        let fields = event_fields.0;
        let line = match self.format {
            LogFormat::Json => serde_json::to_string(&json!({
                "timestamp_ms": timestamp_ms,
                "level": metadata.level().to_string(),
                "target": metadata.target(),
                "name": metadata.name(),
                "fields": fields,
                "spans": spans,
            }))
            .unwrap_or_else(|error| {
                format!(
                    "{{\"level\":\"ERROR\",\"message\":\"telemetry serialization failed: {error}\"}}"
                )
            }),
            LogFormat::Human => {
                let span_names = spans
                    .iter()
                    .filter_map(|span| span.get("name").and_then(Value::as_str))
                    .collect::<Vec<_>>()
                    .join(":");
                format!(
                    "{} {} {} {} spans=[{}] fields={}",
                    timestamp_ms,
                    metadata.level(),
                    metadata.target(),
                    metadata.name(),
                    span_names,
                    serde_json::to_string(&fields).unwrap_or_else(|error| format!(
                        "{{\"serialization_error\":\"{error}\"}}"
                    ))
                )
            }
        };
        self.write_line(&line);
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
    fn secret_debug_ignores_wrapped_debug_implementation() {
        struct LoudSecret;

        impl fmt::Debug for LoudSecret {
            fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter.write_str("must-not-appear")
            }
        }

        assert_eq!(format!("{:?}", Secret::new(LoudSecret)), REDACTED);
    }
}

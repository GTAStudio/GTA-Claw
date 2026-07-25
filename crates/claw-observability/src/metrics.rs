//! Minimal metrics API with pluggable synchronous exporters.

use std::collections::BTreeMap;
use std::fmt;
use std::sync::{Arc, Mutex};

use crate::redaction::{REDACTED, is_sensitive_field};

/// A metric label.
#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct Label {
    key: String,
    value: String,
}

impl Label {
    /// Creates a label, redacting values whose key is security-sensitive.
    #[must_use]
    pub fn new(key: impl Into<String>, value: impl Into<String>) -> Self {
        let key = key.into();
        let value = if is_sensitive_field(&key) {
            REDACTED.to_owned()
        } else {
            value.into()
        };
        Self { key, value }
    }

    /// Returns the label key.
    #[must_use]
    pub fn key(&self) -> &str {
        &self.key
    }

    /// Returns the redacted label value.
    #[must_use]
    pub fn value(&self) -> &str {
        &self.value
    }
}

/// One metrics update delivered to an exporter.
#[derive(Clone, Debug, PartialEq)]
pub enum MetricEvent {
    /// Increments a monotonically increasing counter.
    Counter {
        /// Metric name.
        name: String,
        /// Increment amount.
        value: u64,
        /// Stable labels.
        labels: Vec<Label>,
    },
    /// Replaces a point-in-time gauge value.
    Gauge {
        /// Metric name.
        name: String,
        /// Current value.
        value: f64,
        /// Stable labels.
        labels: Vec<Label>,
    },
    /// Adds a sample to a histogram.
    Histogram {
        /// Metric name.
        name: String,
        /// Observed sample.
        value: f64,
        /// Stable labels.
        labels: Vec<Label>,
    },
}

/// Metrics export failure.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MetricError(String);

impl MetricError {
    /// Creates an exporter-specific error.
    #[must_use]
    pub fn exporter(message: impl Into<String>) -> Self {
        Self(message.into())
    }
}

impl fmt::Display for MetricError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.0)
    }
}

impl std::error::Error for MetricError {}

/// Synchronous exporter port.
///
/// Synchronous delivery makes failures visible to callers instead of silently
/// dropping observations.
pub trait MetricsExporter: Send + Sync {
    /// Records one metrics update.
    fn record(&self, event: MetricEvent) -> Result<(), MetricError>;
}

/// Cloneable metrics recorder used by application crates.
#[derive(Clone)]
pub struct Metrics {
    exporter: Arc<dyn MetricsExporter>,
}

impl fmt::Debug for Metrics {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("Metrics")
            .field("exporter", &"<dyn MetricsExporter>")
            .finish()
    }
}

impl Metrics {
    /// Creates a recorder using the supplied exporter.
    #[must_use]
    pub fn new(exporter: Arc<dyn MetricsExporter>) -> Self {
        Self { exporter }
    }

    /// Increments a counter.
    pub fn increment_counter(
        &self,
        name: impl Into<String>,
        value: u64,
        labels: Vec<Label>,
    ) -> Result<(), MetricError> {
        self.record(MetricEvent::Counter {
            name: name.into(),
            value,
            labels,
        })
    }

    /// Sets a gauge.
    pub fn set_gauge(
        &self,
        name: impl Into<String>,
        value: f64,
        labels: Vec<Label>,
    ) -> Result<(), MetricError> {
        self.record(MetricEvent::Gauge {
            name: name.into(),
            value,
            labels,
        })
    }

    /// Observes a histogram sample.
    pub fn observe_histogram(
        &self,
        name: impl Into<String>,
        value: f64,
        labels: Vec<Label>,
    ) -> Result<(), MetricError> {
        self.record(MetricEvent::Histogram {
            name: name.into(),
            value,
            labels,
        })
    }

    fn record(&self, event: MetricEvent) -> Result<(), MetricError> {
        let name = match &event {
            MetricEvent::Counter { name, .. }
            | MetricEvent::Gauge { name, .. }
            | MetricEvent::Histogram { name, .. } => name,
        };
        if name.trim().is_empty() {
            return Err(MetricError("metric name must not be empty".to_owned()));
        }
        self.exporter.record(event)
    }
}

#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
struct MetricKey {
    name: String,
    labels: Vec<Label>,
}

/// Point-in-time snapshot from [`InMemoryMetricsExporter`].
#[derive(Clone, Debug, Default, PartialEq)]
pub struct MetricsSnapshot {
    /// Accumulated counter values keyed by a stable rendered identity.
    pub counters: BTreeMap<String, u64>,
    /// Latest gauge values keyed by a stable rendered identity.
    pub gauges: BTreeMap<String, f64>,
    /// Histogram samples keyed by a stable rendered identity.
    pub histograms: BTreeMap<String, Vec<f64>>,
}

#[derive(Debug, Default)]
struct InMemoryState {
    counters: BTreeMap<MetricKey, u64>,
    gauges: BTreeMap<MetricKey, f64>,
    histograms: BTreeMap<MetricKey, Vec<f64>>,
}

/// Thread-safe in-memory exporter intended for tests and local diagnostics.
#[derive(Debug, Default)]
pub struct InMemoryMetricsExporter {
    state: Mutex<InMemoryState>,
}

impl InMemoryMetricsExporter {
    /// Returns a deterministic snapshot.
    pub fn snapshot(&self) -> Result<MetricsSnapshot, MetricError> {
        let state = self
            .state
            .lock()
            .map_err(|_| MetricError("metrics exporter lock poisoned".to_owned()))?;
        Ok(MetricsSnapshot {
            counters: render_map(&state.counters),
            gauges: render_map(&state.gauges),
            histograms: render_map(&state.histograms),
        })
    }
}

impl MetricsExporter for InMemoryMetricsExporter {
    fn record(&self, event: MetricEvent) -> Result<(), MetricError> {
        let mut state = self
            .state
            .lock()
            .map_err(|_| MetricError("metrics exporter lock poisoned".to_owned()))?;
        match event {
            MetricEvent::Counter {
                name,
                value,
                mut labels,
            } => {
                labels.sort();
                let current = state
                    .counters
                    .entry(MetricKey { name, labels })
                    .or_default();
                *current = current.checked_add(value).ok_or_else(|| {
                    MetricError("counter overflow while recording metric".to_owned())
                })?;
            }
            MetricEvent::Gauge {
                name,
                value,
                mut labels,
            } => {
                labels.sort();
                state.gauges.insert(MetricKey { name, labels }, value);
            }
            MetricEvent::Histogram {
                name,
                value,
                mut labels,
            } => {
                labels.sort();
                state
                    .histograms
                    .entry(MetricKey { name, labels })
                    .or_default()
                    .push(value);
            }
        }
        Ok(())
    }
}

fn render_map<T: Clone>(map: &BTreeMap<MetricKey, T>) -> BTreeMap<String, T> {
    map.iter()
        .map(|(key, value)| (render_key(key), value.clone()))
        .collect()
}

fn render_key(key: &MetricKey) -> String {
    let labels = key
        .labels
        .iter()
        .map(|label| format!("{}={}", label.key, label.value))
        .collect::<Vec<_>>()
        .join(",");
    if labels.is_empty() {
        key.name.clone()
    } else {
        format!("{}{{{labels}}}", key.name)
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use super::{InMemoryMetricsExporter, Label, Metrics, MetricsSnapshot};

    #[test]
    fn in_memory_exporter_tracks_all_metric_kinds() {
        let exporter = Arc::new(InMemoryMetricsExporter::default());
        let metrics = Metrics::new(exporter.clone());
        let labels = vec![Label::new("provider", "openai")];

        metrics
            .increment_counter("provider.requests", 2, labels.clone())
            .expect("counter");
        metrics
            .increment_counter("provider.requests", 3, labels.clone())
            .expect("counter");
        metrics
            .set_gauge("provider.in_flight", 4.0, labels.clone())
            .expect("gauge");
        metrics
            .observe_histogram("provider.latency_ms", 12.5, labels.clone())
            .expect("histogram");
        metrics
            .observe_histogram("provider.latency_ms", 25.0, labels)
            .expect("histogram");

        let snapshot = exporter.snapshot().expect("snapshot");
        let expected = MetricsSnapshot {
            counters: [("provider.requests{provider=openai}".to_owned(), 5)]
                .into_iter()
                .collect(),
            gauges: [("provider.in_flight{provider=openai}".to_owned(), 4.0)]
                .into_iter()
                .collect(),
            histograms: [(
                "provider.latency_ms{provider=openai}".to_owned(),
                vec![12.5, 25.0],
            )]
            .into_iter()
            .collect(),
        };
        assert_eq!(snapshot, expected);
    }

    #[test]
    fn empty_metric_name_is_rejected() {
        let exporter = Arc::new(InMemoryMetricsExporter::default());
        let error = Metrics::new(exporter)
            .increment_counter(" ", 1, Vec::new())
            .expect_err("empty name must fail");
        assert_eq!(error.to_string(), "metric name must not be empty");
    }

    #[test]
    fn sensitive_metric_label_values_are_redacted() {
        let label = Label::new("apiKey", "must-not-appear");
        assert_eq!(label.key(), "apiKey");
        assert_eq!(label.value(), "[REDACTED]");

        let exporter = Arc::new(InMemoryMetricsExporter::default());
        Metrics::new(exporter.clone())
            .increment_counter("provider.requests", 1, vec![label])
            .expect("counter");
        assert_eq!(
            exporter.snapshot().expect("snapshot").counters,
            [("provider.requests{apiKey=[REDACTED]}".to_owned(), 1)]
                .into_iter()
                .collect()
        );
    }
}

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
    ///
    /// # Errors
    ///
    /// Returns [`MetricError`] when the implementation cannot durably accept
    /// the observation, for example when its transport rejects the write or its
    /// internal state is inconsistent. Implementations must not swallow such a
    /// failure, because a dropped observation is invisible to the caller.
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
    ///
    /// # Errors
    ///
    /// Returns [`MetricError`] when `name` is empty or only whitespace, or when
    /// the configured exporter rejects the observation.
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
    ///
    /// # Errors
    ///
    /// Returns [`MetricError`] when `name` is empty or only whitespace, or when
    /// the configured exporter rejects the observation.
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
    ///
    /// # Errors
    ///
    /// Returns [`MetricError`] when `name` is empty or only whitespace, or when
    /// the configured exporter rejects the observation.
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

/// One observation, separated from its already-normalized [`MetricKey`].
enum Sample {
    Counter(u64),
    Gauge(f64),
    Histogram(f64),
}

/// Largest number of distinct label combinations retained per metric kind.
///
/// Labelling a metric with an unbounded value — a session id, a request id, a
/// URL — silently turns this exporter into a memory leak, because a series is
/// never evicted. The bound converts that mistake into a visible error at the
/// call site that introduces it. Legitimate metric label sets are orders of
/// magnitude smaller.
const MAX_SERIES: usize = 4096;

/// Largest number of raw samples retained for a single histogram series.
///
/// [`MetricsSnapshot`] keeps every sample so tests can assert on them, so an
/// unbounded series would grow with the request count forever.
const MAX_HISTOGRAM_SAMPLES: usize = 8192;

/// Thread-safe in-memory exporter intended for tests and local diagnostics.
///
/// Retention is bounded on both axes: at most 4096 distinct label combinations
/// per metric kind, and at most 8192 samples per histogram series. Exceeding
/// either bound is reported as a [`MetricError`] rather than growing without
/// limit.
#[derive(Debug, Default)]
pub struct InMemoryMetricsExporter {
    state: Mutex<InMemoryState>,
}

impl InMemoryMetricsExporter {
    /// Returns a deterministic snapshot.
    ///
    /// # Errors
    ///
    /// Returns [`MetricError`] with `metrics exporter lock poisoned` when a
    /// thread panicked while recording, because the accumulated values can no
    /// longer be trusted to be complete.
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

/// Rejects a new series once `map` holds `MAX_SERIES` of them.
///
/// Updates to series that already exist are always allowed, so a bounded label
/// set keeps working after the bound is reached by a different metric.
fn reject_new_series<T>(map: &BTreeMap<MetricKey, T>, key: &MetricKey) -> Result<(), MetricError> {
    if map.len() >= MAX_SERIES && !map.contains_key(key) {
        return Err(MetricError(format!(
            "metric `{}` exceeded {MAX_SERIES} label combinations; \
             a label carries an unbounded value",
            key.name
        )));
    }
    Ok(())
}

impl MetricsExporter for InMemoryMetricsExporter {
    fn record(&self, event: MetricEvent) -> Result<(), MetricError> {
        // Sorting the labels only normalizes the key, so it happens before the
        // lock is taken instead of widening the critical section.
        let (key, sample) = match event {
            MetricEvent::Counter {
                name,
                value,
                mut labels,
            } => {
                labels.sort();
                (MetricKey { name, labels }, Sample::Counter(value))
            }
            MetricEvent::Gauge {
                name,
                value,
                mut labels,
            } => {
                labels.sort();
                (MetricKey { name, labels }, Sample::Gauge(value))
            }
            MetricEvent::Histogram {
                name,
                value,
                mut labels,
            } => {
                labels.sort();
                (MetricKey { name, labels }, Sample::Histogram(value))
            }
        };

        let mut state = self
            .state
            .lock()
            .map_err(|_| MetricError("metrics exporter lock poisoned".to_owned()))?;
        match sample {
            Sample::Counter(value) => {
                reject_new_series(&state.counters, &key)?;
                let current = state.counters.entry(key).or_default();
                *current = current.checked_add(value).ok_or_else(|| {
                    MetricError("counter overflow while recording metric".to_owned())
                })?;
            }
            Sample::Gauge(value) => {
                reject_new_series(&state.gauges, &key)?;
                state.gauges.insert(key, value);
            }
            Sample::Histogram(value) => {
                reject_new_series(&state.histograms, &key)?;
                let samples = state.histograms.entry(key).or_default();
                if samples.len() >= MAX_HISTOGRAM_SAMPLES {
                    return Err(MetricError(format!(
                        "histogram exceeded {MAX_HISTOGRAM_SAMPLES} retained samples; \
                         aggregate before exporting"
                    )));
                }
                samples.push(value);
            }
        }
        drop(state);
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
    use std::collections::BTreeMap;
    use std::sync::Arc;

    use super::{
        InMemoryMetricsExporter, Label, MAX_HISTOGRAM_SAMPLES, MAX_SERIES, Metrics, MetricsSnapshot,
    };

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
            counters: BTreeMap::from([("provider.requests{provider=openai}".to_owned(), 5)]),
            gauges: BTreeMap::from([("provider.in_flight{provider=openai}".to_owned(), 4.0)]),
            histograms: BTreeMap::from([(
                "provider.latency_ms{provider=openai}".to_owned(),
                vec![12.5, 25.0],
            )]),
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
            BTreeMap::from([("provider.requests{apiKey=[REDACTED]}".to_owned(), 1)])
        );
    }

    #[test]
    fn unbounded_label_values_are_rejected_instead_of_growing() {
        let exporter = Arc::new(InMemoryMetricsExporter::default());
        let metrics = Metrics::new(exporter.clone());
        for index in 0..MAX_SERIES {
            metrics
                .increment_counter(
                    "gateway.requests",
                    1,
                    vec![Label::new("session", format!("s-{index}"))],
                )
                .expect("series below the bound");
        }

        let error = metrics
            .increment_counter(
                "gateway.requests",
                1,
                vec![Label::new("session", "s-overflow")],
            )
            .expect_err("a new series past the bound must fail");
        assert_eq!(
            error.to_string(),
            format!(
                "metric `gateway.requests` exceeded {MAX_SERIES} label combinations; \
                 a label carries an unbounded value"
            )
        );

        // A series that already exists keeps recording.
        metrics
            .increment_counter("gateway.requests", 1, vec![Label::new("session", "s-0")])
            .expect("existing series still records");
        let counters = exporter.snapshot().expect("snapshot").counters;
        assert_eq!(counters.len(), MAX_SERIES);
        assert_eq!(counters["gateway.requests{session=s-0}"], 2);
    }

    #[test]
    fn histogram_sample_retention_is_bounded() {
        let exporter = Arc::new(InMemoryMetricsExporter::default());
        let metrics = Metrics::new(exporter.clone());
        for _ in 0..MAX_HISTOGRAM_SAMPLES {
            metrics
                .observe_histogram("provider.latency_ms", 1.0, Vec::new())
                .expect("sample below the bound");
        }

        let error = metrics
            .observe_histogram("provider.latency_ms", 1.0, Vec::new())
            .expect_err("a sample past the bound must fail");
        assert_eq!(
            error.to_string(),
            format!(
                "histogram exceeded {MAX_HISTOGRAM_SAMPLES} retained samples; \
                 aggregate before exporting"
            )
        );
        assert_eq!(
            exporter.snapshot().expect("snapshot").histograms["provider.latency_ms"].len(),
            MAX_HISTOGRAM_SAMPLES
        );
    }
}

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

/// Retention limits for [`InMemoryMetricsExporter`].
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct MetricsLimits {
    /// Largest number of distinct label combinations retained for one metric.
    pub max_series_per_metric: usize,
    /// Largest number of series retained across one metric kind.
    ///
    /// This keeps dynamically generated metric names from bypassing
    /// [`Self::max_series_per_metric`].
    pub max_total_series_per_kind: usize,
    /// Largest number of raw samples retained for one histogram series.
    pub max_histogram_samples_per_series: usize,
}

impl Default for MetricsLimits {
    fn default() -> Self {
        Self {
            max_series_per_metric: 4096,
            max_total_series_per_kind: 16_384,
            max_histogram_samples_per_series: 8192,
        }
    }
}

/// Current retained series counts, grouped by metric name.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct MetricsCardinality {
    /// Counter series retained for each metric name.
    pub counters: BTreeMap<String, usize>,
    /// Gauge series retained for each metric name.
    pub gauges: BTreeMap<String, usize>,
    /// Histogram series retained for each metric name.
    pub histograms: BTreeMap<String, usize>,
}

#[derive(Debug, Default)]
struct SeriesMap<T> {
    values: BTreeMap<MetricKey, T>,
    counts_by_name: BTreeMap<String, usize>,
}

#[derive(Debug, Default)]
struct InMemoryState {
    counters: SeriesMap<u64>,
    gauges: SeriesMap<f64>,
    histograms: SeriesMap<Vec<f64>>,
}

/// One observation, separated from its already-normalized [`MetricKey`].
enum Sample {
    Counter(u64),
    Gauge(f64),
    Histogram(f64),
}

/// Thread-safe in-memory exporter intended for tests and local diagnostics.
///
/// Retention is bounded on both axes. The default permits at most 4096 distinct
/// label combinations for each metric name, 16384 total series for each metric
/// kind, and 8192 samples for each histogram series. Per-name accounting keeps
/// one busy metric from immediately consuming every other metric's capacity,
/// while the total bound rejects unbounded metric names. Exceeding a bound is
/// reported as a [`MetricError`] rather than growing without limit.
#[derive(Debug)]
pub struct InMemoryMetricsExporter {
    state: Mutex<InMemoryState>,
    limits: MetricsLimits,
}

impl Default for InMemoryMetricsExporter {
    fn default() -> Self {
        Self::with_limits(MetricsLimits::default())
    }
}

impl InMemoryMetricsExporter {
    /// Creates an exporter with explicit retention limits.
    #[must_use]
    pub fn with_limits(limits: MetricsLimits) -> Self {
        Self {
            state: Mutex::new(InMemoryState::default()),
            limits,
        }
    }

    /// Returns the configured retention limits.
    #[must_use]
    pub const fn limits(&self) -> MetricsLimits {
        self.limits
    }

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
            counters: render_map(&state.counters.values),
            gauges: render_map(&state.gauges.values),
            histograms: render_map(&state.histograms.values),
        })
    }

    /// Returns retained series counts without cloning metric values or samples.
    ///
    /// # Errors
    ///
    /// Returns [`MetricError`] with `metrics exporter lock poisoned` when a
    /// thread panicked while recording.
    pub fn cardinality(&self) -> Result<MetricsCardinality, MetricError> {
        let state = self
            .state
            .lock()
            .map_err(|_| MetricError("metrics exporter lock poisoned".to_owned()))?;
        Ok(MetricsCardinality {
            counters: state.counters.counts_by_name.clone(),
            gauges: state.gauges.counts_by_name.clone(),
            histograms: state.histograms.counts_by_name.clone(),
        })
    }
}

fn reject_new_series(
    counts_by_name: &BTreeMap<String, usize>,
    total_retained: usize,
    key: &MetricKey,
    metric_kind: &str,
    limits: MetricsLimits,
) -> Result<(), MetricError> {
    let retained = counts_by_name.get(&key.name).copied().unwrap_or_default();
    if retained >= limits.max_series_per_metric {
        return Err(MetricError(format!(
            "{metric_kind} metric `{}` reached its limit of \
             {} retained series; rejected a new label set",
            key.name, limits.max_series_per_metric,
        )));
    }
    if total_retained >= limits.max_total_series_per_kind {
        return Err(MetricError(format!(
            "{metric_kind} metrics reached their total limit of {} retained series; \
             rejected new series for `{}`",
            limits.max_total_series_per_kind, key.name,
        )));
    }
    Ok(())
}

fn insert_new_series<T>(series: &mut SeriesMap<T>, key: MetricKey, value: T) {
    let metric_name = key.name.clone();
    series.values.insert(key, value);
    *series.counts_by_name.entry(metric_name).or_default() += 1;
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
                if let Some(current) = state.counters.values.get_mut(&key) {
                    *current = current.checked_add(value).ok_or_else(|| {
                        MetricError(format!("counter metric `{}` overflowed", key.name))
                    })?;
                } else {
                    reject_new_series(
                        &state.counters.counts_by_name,
                        state.counters.values.len(),
                        &key,
                        "counter",
                        self.limits,
                    )?;
                    insert_new_series(&mut state.counters, key, value);
                }
            }
            Sample::Gauge(value) => {
                if let Some(current) = state.gauges.values.get_mut(&key) {
                    *current = value;
                } else {
                    reject_new_series(
                        &state.gauges.counts_by_name,
                        state.gauges.values.len(),
                        &key,
                        "gauge",
                        self.limits,
                    )?;
                    insert_new_series(&mut state.gauges, key, value);
                }
            }
            Sample::Histogram(value) => {
                if let Some(samples) = state.histograms.values.get_mut(&key) {
                    if samples.len() >= self.limits.max_histogram_samples_per_series {
                        return Err(MetricError(format!(
                            "histogram metric `{}` reached its limit of {} retained samples \
                             for one series; rejected the sample",
                            key.name, self.limits.max_histogram_samples_per_series,
                        )));
                    }
                    samples.push(value);
                } else {
                    reject_new_series(
                        &state.histograms.counts_by_name,
                        state.histograms.values.len(),
                        &key,
                        "histogram",
                        self.limits,
                    )?;
                    if self.limits.max_histogram_samples_per_series == 0 {
                        return Err(MetricError(format!(
                            "histogram metric `{}` has a retained sample limit of 0; \
                             rejected the sample",
                            key.name,
                        )));
                    }
                    insert_new_series(&mut state.histograms, key, vec![value]);
                }
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
        InMemoryMetricsExporter, Label, Metrics, MetricsCardinality, MetricsLimits, MetricsSnapshot,
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
    fn per_metric_series_limits_are_independent_and_bounded() {
        let exporter = Arc::new(InMemoryMetricsExporter::with_limits(MetricsLimits {
            max_series_per_metric: 2,
            max_total_series_per_kind: 4,
            max_histogram_samples_per_series: 3,
        }));
        let metrics = Metrics::new(exporter.clone());
        for metric_name in ["gateway.requests", "provider.requests"] {
            for index in 0..2 {
                metrics
                    .increment_counter(
                        metric_name,
                        1,
                        vec![Label::new("provider", format!("p-{index}"))],
                    )
                    .expect("series below the per-metric bound");
            }
        }

        let error = metrics
            .increment_counter(
                "gateway.requests",
                1,
                vec![Label::new("provider", "p-overflow")],
            )
            .expect_err("a new series past this metric's bound must fail");
        assert_eq!(
            error.to_string(),
            "counter metric `gateway.requests` reached its limit of 2 retained series; \
             rejected a new label set"
        );

        // Existing series keep recording after their metric reaches the bound.
        metrics
            .increment_counter("gateway.requests", 1, vec![Label::new("provider", "p-0")])
            .expect("existing series still records");
        let snapshot = exporter.snapshot().expect("snapshot");
        assert_eq!(snapshot.counters.len(), 4);
        assert_eq!(snapshot.counters["gateway.requests{provider=p-0}"], 2);
        assert_eq!(
            exporter.cardinality().expect("cardinality"),
            MetricsCardinality {
                counters: BTreeMap::from([
                    ("gateway.requests".to_owned(), 2),
                    ("provider.requests".to_owned(), 2),
                ]),
                gauges: BTreeMap::new(),
                histograms: BTreeMap::new(),
            }
        );
    }

    #[test]
    fn generated_metric_names_cannot_bypass_the_total_bound() {
        let exporter = Arc::new(InMemoryMetricsExporter::with_limits(MetricsLimits {
            max_series_per_metric: 2,
            max_total_series_per_kind: 3,
            max_histogram_samples_per_series: 1,
        }));
        let metrics = Metrics::new(exporter.clone());
        for name in ["requests.a", "requests.b", "requests.c"] {
            metrics
                .increment_counter(name, 1, Vec::new())
                .expect("series below the total bound");
        }

        let error = metrics
            .increment_counter("requests.d", 1, Vec::new())
            .expect_err("new metric name must not bypass the total bound");
        assert_eq!(
            error.to_string(),
            "counter metrics reached their total limit of 3 retained series; \
             rejected new series for `requests.d`"
        );
        metrics
            .increment_counter("requests.a", 1, Vec::new())
            .expect("existing series still records at the total bound");
        let snapshot = exporter.snapshot().expect("snapshot");
        assert_eq!(snapshot.counters.len(), 3);
        assert_eq!(snapshot.counters["requests.a"], 2);
    }

    #[test]
    fn metric_kinds_have_independent_series_limits() {
        let exporter = Arc::new(InMemoryMetricsExporter::with_limits(MetricsLimits {
            max_series_per_metric: 1,
            max_total_series_per_kind: 1,
            max_histogram_samples_per_series: 1,
        }));
        let metrics = Metrics::new(exporter.clone());
        for index in 0..2 {
            let label = vec![Label::new("state", format!("state-{index}"))];
            let result = metrics.increment_counter("gateway.activity", 1, label.clone());
            if index == 0 {
                result.expect("first counter series");
            } else {
                result.expect_err("second counter series exceeds the bound");
            }
        }
        metrics
            .set_gauge(
                "gateway.activity",
                1.0,
                vec![Label::new("state", "state-1")],
            )
            .expect("gauge capacity is independent");
        metrics
            .observe_histogram(
                "gateway.activity",
                1.0,
                vec![Label::new("state", "state-2")],
            )
            .expect("histogram capacity is independent");

        let cardinality = exporter.cardinality().expect("cardinality");
        assert_eq!(cardinality.counters["gateway.activity"], 1);
        assert_eq!(cardinality.gauges["gateway.activity"], 1);
        assert_eq!(cardinality.histograms["gateway.activity"], 1);
    }

    #[test]
    fn zero_series_limit_rejects_without_retaining_data() {
        let exporter = Arc::new(InMemoryMetricsExporter::with_limits(MetricsLimits {
            max_series_per_metric: 0,
            max_total_series_per_kind: 1,
            max_histogram_samples_per_series: 1,
        }));
        let metrics = Metrics::new(exporter.clone());
        let error = metrics
            .increment_counter(
                "gateway.requests",
                1,
                vec![Label::new("provider", "openai")],
            )
            .expect_err("zero limit rejects the first series");
        assert_eq!(
            error.to_string(),
            "counter metric `gateway.requests` reached its limit of 0 retained series; \
             rejected a new label set"
        );
        assert!(exporter.snapshot().expect("snapshot").counters.is_empty());
    }

    #[test]
    fn histogram_sample_retention_is_bounded() {
        let exporter = Arc::new(InMemoryMetricsExporter::with_limits(MetricsLimits {
            max_series_per_metric: 2,
            max_total_series_per_kind: 2,
            max_histogram_samples_per_series: 3,
        }));
        let metrics = Metrics::new(exporter.clone());
        for _ in 0..3 {
            metrics
                .observe_histogram("provider.latency_ms", 1.0, Vec::new())
                .expect("sample below the bound");
        }

        let error = metrics
            .observe_histogram("provider.latency_ms", 1.0, Vec::new())
            .expect_err("a sample past the bound must fail");
        assert_eq!(
            error.to_string(),
            "histogram metric `provider.latency_ms` reached its limit of 3 retained samples \
             for one series; rejected the sample"
        );
        assert_eq!(
            exporter.snapshot().expect("snapshot").histograms["provider.latency_ms"].len(),
            3
        );
    }
}

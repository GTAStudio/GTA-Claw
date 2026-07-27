//! Shared observability primitives for GTA Claw.
//!
//! The crate intentionally keeps telemetry transport-neutral. Ordinary tracing,
//! security audit records, and metrics use separate ports so callers cannot
//! accidentally route security evidence through a lossy logging pipeline.

pub mod audit;
pub mod metrics;
pub mod redaction;
pub mod spans;
pub mod telemetry;

/// The `tracing` facade this crate installs a subscriber for.
///
/// [`init`] configures where records go and [`RedactingLayer`] decides what they
/// may contain, but neither lets a caller *emit* one. Re-exporting the facade
/// closes that half of the API: a binary or library can write
/// `claw_observability::tracing::info!(field = value, "message")` and reach the
/// installed, redacting subscriber without taking its own `tracing` dependency,
/// which would risk a second version of the facade in the graph and a second
/// logging path beside this one.
///
/// Emit structured fields rather than formatting values into the message. Field
/// values pass through [`RedactingLayer`]; text interpolated into the message
/// does not, so a secret written into the message string is not redacted.
pub use tracing;

pub use audit::{AuditEvent, AuditOutcome, AuditSink, DurableFileAuditSink, InMemoryAuditSink};
pub use metrics::{
    InMemoryMetricsExporter, Label, MetricError, MetricEvent, Metrics, MetricsCardinality,
    MetricsExporter, MetricsLimits, MetricsSnapshot,
};
pub use redaction::{REDACTED, RedactingLayer, Secret, is_sensitive_field};
pub use telemetry::{LogFormat, TelemetryConfig, TelemetryError, TelemetryHandle, init};

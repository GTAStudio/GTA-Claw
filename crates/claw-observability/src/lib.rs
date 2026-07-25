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

pub use audit::{AuditEvent, AuditOutcome, AuditSink, DurableFileAuditSink, InMemoryAuditSink};
pub use metrics::{
    InMemoryMetricsExporter, Label, MetricError, MetricEvent, Metrics, MetricsExporter,
    MetricsSnapshot,
};
pub use redaction::{REDACTED, RedactingLayer, Secret, is_sensitive_field};
pub use telemetry::{LogFormat, TelemetryConfig, TelemetryError, TelemetryHandle, init};

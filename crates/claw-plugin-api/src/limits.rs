//! Per-plugin resource limits.
//!
//! Every limit is enforced by `claw-plugin-host`:
//!
//! * [`ResourceLimits::max_memory_bytes`], [`ResourceLimits::max_table_elements`],
//!   [`ResourceLimits::max_instances`], [`ResourceLimits::max_tables`] and
//!   [`ResourceLimits::max_memories`] are wired into a Wasmtime
//!   `ResourceLimiter`, so a growth request past the cap fails inside the
//!   engine instead of allocating.
//! * [`ResourceLimits::fuel`] bounds executed Wasm instructions.
//! * [`ResourceLimits::wall_clock_timeout_ms`] is enforced with epoch
//!   interruption, which also stops guests that block without consuming fuel.
//! * [`ResourceLimits::max_host_call_concurrency`] bounds how many host calls
//!   may be in flight for one host at a time.
//! * [`ResourceLimits::max_payload_bytes`] bounds every byte string crossing
//!   the ABI boundary.

use core::fmt;
use core::time::Duration;

use serde::{Deserialize, Serialize};

/// Smallest linear-memory cap that can still host a component (one Wasm page).
pub const MIN_MEMORY_BYTES: u64 = 64 * 1024;
/// Largest linear-memory cap this host will accept (wasm32 address space).
pub const MAX_MEMORY_BYTES: u64 = 4 * 1024 * 1024 * 1024;
/// Largest wall-clock timeout this host will accept.
pub const MAX_TIMEOUT_MS: u64 = 10 * 60 * 1000;

/// The resource envelope one plugin instance runs inside.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ResourceLimits {
    /// Maximum total linear memory, in bytes.
    pub max_memory_bytes: u64,
    /// Maximum total table elements.
    pub max_table_elements: u64,
    /// Maximum core instances inside one component instantiation.
    pub max_instances: u32,
    /// Maximum tables inside one component instantiation.
    pub max_tables: u32,
    /// Maximum memories inside one component instantiation.
    pub max_memories: u32,
    /// Fuel budget for a single guest call.
    pub fuel: u64,
    /// Wall-clock budget for a single guest call, in milliseconds.
    pub wall_clock_timeout_ms: u64,
    /// Maximum host calls this plugin may have executing at the same time.
    pub max_host_call_concurrency: u32,
    /// Maximum size of any single byte string or list crossing the ABI.
    pub max_payload_bytes: u32,
    /// Maximum accepted component file size, in bytes.
    pub max_component_bytes: u64,
}

impl Default for ResourceLimits {
    fn default() -> Self {
        Self {
            max_memory_bytes: 64 * 1024 * 1024,
            max_table_elements: 10_000,
            max_instances: 32,
            max_tables: 16,
            max_memories: 4,
            fuel: 1_000_000_000,
            wall_clock_timeout_ms: 5_000,
            max_host_call_concurrency: 8,
            max_payload_bytes: 4 * 1024 * 1024,
            max_component_bytes: 64 * 1024 * 1024,
        }
    }
}

impl ResourceLimits {
    /// The wall-clock budget as a [`Duration`].
    #[must_use]
    pub const fn timeout(&self) -> Duration {
        Duration::from_millis(self.wall_clock_timeout_ms)
    }

    /// Checks that every limit is inside the host's accepted range.
    ///
    /// # Errors
    ///
    /// Returns [`LimitsError`] naming the first field that is out of range.
    pub fn validate(&self) -> Result<(), LimitsError> {
        let check = |ok: bool, field: &'static str, reason: &'static str| {
            if ok {
                Ok(())
            } else {
                Err(LimitsError { field, reason })
            }
        };
        check(
            self.max_memory_bytes >= MIN_MEMORY_BYTES,
            "max_memory_bytes",
            "must be at least one Wasm page (65536 bytes)",
        )?;
        check(
            self.max_memory_bytes <= MAX_MEMORY_BYTES,
            "max_memory_bytes",
            "must not exceed the wasm32 address space",
        )?;
        check(
            self.max_table_elements > 0,
            "max_table_elements",
            "must be positive",
        )?;
        check(self.max_instances > 0, "max_instances", "must be positive")?;
        check(self.max_tables > 0, "max_tables", "must be positive")?;
        check(self.max_memories > 0, "max_memories", "must be positive")?;
        check(self.fuel > 0, "fuel", "must be positive")?;
        check(
            self.wall_clock_timeout_ms > 0,
            "wall_clock_timeout_ms",
            "must be positive",
        )?;
        check(
            self.wall_clock_timeout_ms <= MAX_TIMEOUT_MS,
            "wall_clock_timeout_ms",
            "must not exceed ten minutes",
        )?;
        check(
            self.max_host_call_concurrency > 0,
            "max_host_call_concurrency",
            "must be positive",
        )?;
        check(
            self.max_payload_bytes > 0,
            "max_payload_bytes",
            "must be positive",
        )?;
        check(
            u64::from(self.max_payload_bytes) <= self.max_memory_bytes,
            "max_payload_bytes",
            "must not exceed max_memory_bytes",
        )?;
        check(
            self.max_component_bytes > 0,
            "max_component_bytes",
            "must be positive",
        )?;
        Ok(())
    }
}

/// A resource limit was outside the host's accepted range.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct LimitsError {
    field: &'static str,
    reason: &'static str,
}

impl LimitsError {
    /// The offending field name.
    #[must_use]
    pub const fn field(&self) -> &'static str {
        self.field
    }

    /// Why the value was rejected.
    #[must_use]
    pub const fn reason(&self) -> &'static str {
        self.reason
    }
}

impl fmt::Display for LimitsError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "resource limit `{}` {}", self.field, self.reason)
    }
}

impl core::error::Error for LimitsError {}

#[cfg(test)]
mod tests {
    use core::time::Duration;

    use super::{MAX_MEMORY_BYTES, MIN_MEMORY_BYTES, ResourceLimits};

    #[test]
    fn defaults_are_valid_and_bounded() {
        let limits = ResourceLimits::default();
        assert_eq!(limits.validate(), Ok(()));
        assert_eq!(limits.max_memory_bytes, 64 * 1024 * 1024);
        assert_eq!(limits.fuel, 1_000_000_000);
        assert_eq!(limits.wall_clock_timeout_ms, 5_000);
        assert_eq!(limits.max_host_call_concurrency, 8);
        assert_eq!(limits.timeout(), Duration::from_secs(5));
    }

    #[test]
    fn memory_below_one_page_is_rejected() {
        let limits = ResourceLimits {
            max_memory_bytes: MIN_MEMORY_BYTES - 1,
            ..ResourceLimits::default()
        };
        let error = limits.validate().unwrap_err();
        assert_eq!(error.field(), "max_memory_bytes");
        assert_eq!(
            error.reason(),
            "must be at least one Wasm page (65536 bytes)"
        );
    }

    #[test]
    fn memory_above_the_wasm32_address_space_is_rejected() {
        let limits = ResourceLimits {
            max_memory_bytes: MAX_MEMORY_BYTES + 1,
            ..ResourceLimits::default()
        };
        assert_eq!(limits.validate().unwrap_err().field(), "max_memory_bytes");
    }

    #[test]
    fn zero_valued_limits_are_rejected_field_by_field() {
        let base = ResourceLimits::default();
        let cases: [(ResourceLimits, &str); 7] = [
            (
                ResourceLimits {
                    max_table_elements: 0,
                    ..base
                },
                "max_table_elements",
            ),
            (
                ResourceLimits {
                    max_instances: 0,
                    ..base
                },
                "max_instances",
            ),
            (ResourceLimits { fuel: 0, ..base }, "fuel"),
            (
                ResourceLimits {
                    wall_clock_timeout_ms: 0,
                    ..base
                },
                "wall_clock_timeout_ms",
            ),
            (
                ResourceLimits {
                    max_host_call_concurrency: 0,
                    ..base
                },
                "max_host_call_concurrency",
            ),
            (
                ResourceLimits {
                    max_payload_bytes: 0,
                    ..base
                },
                "max_payload_bytes",
            ),
            (
                ResourceLimits {
                    max_component_bytes: 0,
                    ..base
                },
                "max_component_bytes",
            ),
        ];
        for (limits, field) in cases {
            let error = limits.validate().unwrap_err();
            assert_eq!(error.field(), field);
            assert_eq!(error.reason(), "must be positive");
        }
    }

    #[test]
    fn timeout_ceiling_is_ten_minutes() {
        let limits = ResourceLimits {
            wall_clock_timeout_ms: 10 * 60 * 1000 + 1,
            ..ResourceLimits::default()
        };
        let error = limits.validate().unwrap_err();
        assert_eq!(error.field(), "wall_clock_timeout_ms");
        assert_eq!(error.reason(), "must not exceed ten minutes");
    }

    #[test]
    fn payload_cap_cannot_exceed_the_memory_cap() {
        let limits = ResourceLimits {
            max_memory_bytes: MIN_MEMORY_BYTES,
            max_payload_bytes: u32::try_from(MIN_MEMORY_BYTES).expect("fits") + 1,
            ..ResourceLimits::default()
        };
        let error = limits.validate().unwrap_err();
        assert_eq!(error.field(), "max_payload_bytes");
        assert_eq!(error.reason(), "must not exceed max_memory_bytes");
    }

    #[test]
    fn json_round_trip_preserves_every_field() {
        let limits = ResourceLimits {
            max_memory_bytes: 1 << 21,
            max_table_elements: 77,
            max_instances: 3,
            max_tables: 2,
            max_memories: 1,
            fuel: 4321,
            wall_clock_timeout_ms: 250,
            max_host_call_concurrency: 2,
            max_payload_bytes: 8192,
            max_component_bytes: 1 << 20,
        };
        let encoded = serde_json::to_string(&limits).expect("serialize");
        let decoded: ResourceLimits = serde_json::from_str(&encoded).expect("deserialize");
        assert_eq!(decoded, limits);
    }

    #[test]
    fn unknown_limit_fields_are_rejected() {
        let error = serde_json::from_str::<ResourceLimits>(
            r#"{"max_memory_bytes":65536,"max_table_elements":1,"max_instances":1,"max_tables":1,
                "max_memories":1,"fuel":1,"wall_clock_timeout_ms":1,"max_host_call_concurrency":1,
                "max_payload_bytes":1,"max_component_bytes":1,"max_threads":4}"#,
        )
        .unwrap_err();
        assert!(
            error.to_string().starts_with("unknown field `max_threads`"),
            "unexpected error: {error}"
        );
    }
}

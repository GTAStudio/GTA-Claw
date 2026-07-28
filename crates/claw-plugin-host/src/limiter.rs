//! Per-instance resource enforcement.

use std::sync::Arc;
use std::sync::atomic::{AtomicU32, Ordering};

use claw_plugin_api::limits::ResourceLimits;

const MEMORY_CEILING: u8 = 1;
const TABLE_CEILING: u8 = 1 << 1;

/// Enforces the manifest's memory, table and instance ceilings.
///
/// Wasmtime consults this on every growth request, so a memory bomb is stopped
/// at the allocation that would cross the ceiling rather than after the fact.
#[derive(Debug)]
pub(crate) struct InstanceLimiter {
    limits: ResourceLimits,
    memories: u32,
    tables: u32,
    peak_memory_bytes: usize,
    ceiling_flags: u8,
    call_ceiling_flags: u8,
}

impl InstanceLimiter {
    pub(crate) const fn new(limits: ResourceLimits) -> Self {
        Self {
            limits,
            memories: 0,
            tables: 0,
            peak_memory_bytes: 0,
            ceiling_flags: 0,
            call_ceiling_flags: 0,
        }
    }

    pub(crate) const fn begin_call(&mut self) {
        self.call_ceiling_flags = 0;
    }

    pub(crate) const fn peak_memory_bytes(&self) -> usize {
        self.peak_memory_bytes
    }

    pub(crate) const fn hit_memory_ceiling(&self) -> bool {
        self.ceiling_flags & MEMORY_CEILING != 0
    }

    pub(crate) const fn hit_table_ceiling(&self) -> bool {
        self.ceiling_flags & TABLE_CEILING != 0
    }

    pub(crate) const fn hit_resource_ceiling_during_call(&self) -> bool {
        self.call_ceiling_flags != 0
    }
}

impl wasmtime::ResourceLimiter for InstanceLimiter {
    fn memory_growing(
        &mut self,
        _current: usize,
        desired: usize,
        _maximum: Option<usize>,
    ) -> wasmtime::Result<bool> {
        let allowed = u64::try_from(desired).unwrap_or(u64::MAX) <= self.limits.max_memory_bytes;
        if allowed {
            self.peak_memory_bytes = self.peak_memory_bytes.max(desired);
        } else {
            self.ceiling_flags |= MEMORY_CEILING;
            self.call_ceiling_flags |= MEMORY_CEILING;
        }
        Ok(allowed)
    }

    fn table_growing(
        &mut self,
        _current: usize,
        desired: usize,
        _maximum: Option<usize>,
    ) -> wasmtime::Result<bool> {
        let allowed = u64::try_from(desired).unwrap_or(u64::MAX) <= self.limits.max_table_elements;
        if !allowed {
            self.ceiling_flags |= TABLE_CEILING;
            self.call_ceiling_flags |= TABLE_CEILING;
        }
        Ok(allowed)
    }

    fn instances(&self) -> usize {
        usize::try_from(self.limits.max_instances).unwrap_or(usize::MAX)
    }

    fn tables(&self) -> usize {
        usize::try_from(self.limits.max_tables).unwrap_or(usize::MAX)
    }

    fn memories(&self) -> usize {
        usize::try_from(self.limits.max_memories).unwrap_or(usize::MAX)
    }

    fn memory_grow_failed(&mut self, _error: wasmtime::Error) -> wasmtime::Result<()> {
        self.memories = self.memories.saturating_add(1);
        Ok(())
    }

    fn table_grow_failed(&mut self, _error: wasmtime::Error) -> wasmtime::Result<()> {
        self.tables = self.tables.saturating_add(1);
        Ok(())
    }
}

/// A bound on how many host calls may execute at the same time.
///
/// The counter is shared by every plugin instance created from one
/// [`crate::PluginHost`], so a fleet of plugins cannot collectively pin more
/// host threads than the operator allowed.
#[derive(Clone, Debug)]
pub struct HostCallGate {
    in_flight: Arc<AtomicU32>,
    max: u32,
}

impl HostCallGate {
    /// A gate that admits at most `max` concurrent host calls.
    ///
    /// A `max` of zero is clamped to one so a misconfiguration cannot deadlock
    /// every plugin.
    #[must_use]
    pub fn new(max: u32) -> Self {
        Self {
            in_flight: Arc::new(AtomicU32::new(0)),
            max: max.max(1),
        }
    }

    /// The configured ceiling.
    #[must_use]
    pub const fn max(&self) -> u32 {
        self.max
    }

    /// Host calls currently executing.
    #[must_use]
    pub fn in_flight(&self) -> u32 {
        self.in_flight.load(Ordering::Acquire)
    }

    /// Takes a slot, or `None` when the gate is full.
    #[must_use]
    pub fn try_acquire(&self) -> Option<HostCallPermit> {
        let mut current = self.in_flight.load(Ordering::Acquire);
        loop {
            if current >= self.max {
                return None;
            }
            match self.in_flight.compare_exchange_weak(
                current,
                current + 1,
                Ordering::AcqRel,
                Ordering::Acquire,
            ) {
                Ok(_) => {
                    return Some(HostCallPermit {
                        in_flight: Arc::clone(&self.in_flight),
                    });
                }
                Err(observed) => current = observed,
            }
        }
    }
}

/// A held host-call slot. The slot is released when this value is dropped,
/// including when the host function returns early or unwinds.
#[derive(Debug)]
pub struct HostCallPermit {
    in_flight: Arc<AtomicU32>,
}

impl Drop for HostCallPermit {
    fn drop(&mut self) {
        self.in_flight.fetch_sub(1, Ordering::AcqRel);
    }
}

/// Both slots a host call must hold: one from the host-wide gate and one from
/// the calling plugin's own gate. Dropping this releases both.
#[derive(Debug)]
pub struct HostCallPermits {
    _shared: HostCallPermit,
    _instance: HostCallPermit,
}

impl HostCallPermits {
    pub(crate) const fn new(shared: HostCallPermit, instance: HostCallPermit) -> Self {
        Self {
            _shared: shared,
            _instance: instance,
        }
    }
}

#[cfg(test)]
mod tests {
    use claw_plugin_api::limits::ResourceLimits;
    use wasmtime::ResourceLimiter;

    use super::{HostCallGate, InstanceLimiter};

    fn limits() -> ResourceLimits {
        ResourceLimits {
            max_memory_bytes: 1 << 20,
            max_table_elements: 100,
            max_instances: 3,
            max_tables: 2,
            max_memories: 1,
            ..ResourceLimits::default()
        }
    }

    #[test]
    fn memory_growth_is_allowed_up_to_the_ceiling_and_refused_past_it() {
        let mut limiter = InstanceLimiter::new(limits());
        assert!(limiter.memory_growing(0, 1 << 19, None).unwrap());
        assert_eq!(limiter.peak_memory_bytes(), 1 << 19);
        assert!(limiter.memory_growing(1 << 19, 1 << 20, None).unwrap());
        assert_eq!(limiter.peak_memory_bytes(), 1 << 20);
        assert!(!limiter.hit_memory_ceiling());
        assert!(
            !limiter
                .memory_growing(1 << 20, (1 << 20) + 1, None)
                .unwrap()
        );
        assert!(limiter.hit_memory_ceiling());
        assert_eq!(limiter.peak_memory_bytes(), 1 << 20);
    }

    #[test]
    fn table_growth_is_refused_past_the_ceiling() {
        let mut limiter = InstanceLimiter::new(limits());
        assert!(limiter.table_growing(0, 100, None).unwrap());
        assert!(!limiter.hit_table_ceiling());
        assert!(!limiter.table_growing(100, 101, None).unwrap());
        assert!(limiter.hit_table_ceiling());
    }

    #[test]
    fn the_structural_ceilings_come_from_the_manifest() {
        let limiter = InstanceLimiter::new(limits());
        assert_eq!(limiter.instances(), 3);
        assert_eq!(limiter.tables(), 2);
        assert_eq!(limiter.memories(), 1);
    }

    #[test]
    fn the_gate_admits_exactly_its_ceiling_and_releases_on_drop() {
        let gate = HostCallGate::new(2);
        assert_eq!(gate.max(), 2);
        let first = gate.try_acquire().expect("first slot");
        let second = gate.try_acquire().expect("second slot");
        assert_eq!(gate.in_flight(), 2);
        assert!(gate.try_acquire().is_none());
        drop(second);
        assert_eq!(gate.in_flight(), 1);
        let third = gate.try_acquire().expect("slot freed by drop");
        assert_eq!(gate.in_flight(), 2);
        drop(first);
        drop(third);
        assert_eq!(gate.in_flight(), 0);
    }

    #[test]
    fn a_zero_ceiling_is_clamped_so_it_cannot_deadlock() {
        let gate = HostCallGate::new(0);
        assert_eq!(gate.max(), 1);
        let permit = gate.try_acquire().expect("one slot");
        assert!(gate.try_acquire().is_none());
        drop(permit);
        assert!(gate.try_acquire().is_some());
    }

    #[test]
    fn permits_are_shared_across_clones_of_the_same_gate() {
        let gate = HostCallGate::new(1);
        let clone = gate.clone();
        let permit = gate.try_acquire().expect("slot");
        assert!(clone.try_acquire().is_none());
        assert_eq!(clone.in_flight(), 1);
        drop(permit);
        assert!(clone.try_acquire().is_some());
    }
}

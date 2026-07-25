//! Authorization currency: the grant in force for a device *right now*.
//!
//! Authentication happens once, during the handshake. Authorization must not.
//! Every action a connection attempts afterwards has to be judged against the
//! grant in force at the moment of that action, never against the grant that
//! was captured when the socket opened. Otherwise a device whose pairing is
//! withdrawn, whose role changes, or whose scopes are narrowed keeps acting
//! with its old privileges for as long as it holds the connection open.
//!
//! [`AuthorizationSource`] is the narrow port the connection loop consults.
//! [`DeviceDirectory`] is the in-memory adapter, and it is also the pairing
//! store [`crate::auth::StaticAuthenticator`] reads during the handshake, so a
//! single mutation is observed both by the next handshake and by every live
//! connection.

use std::collections::BTreeMap;
use std::fmt::Debug;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, PoisonError, RwLock};

use crate::auth::Grant;

/// The authorization in force for a device.
///
/// # Reader contract
///
/// A caller that caches a decision must load [`Self::generation`] *before* it
/// reads [`Self::current_grant`], and must store that earlier value. Doing it
/// in that order can only ever make a reader re-check when nothing changed; the
/// reverse order can make a reader cache a new generation alongside grant data
/// it read before the change, which would keep a revoked grant alive.
pub trait AuthorizationSource: Debug + Send + Sync {
    /// A counter that changes whenever any device's authorization changes.
    ///
    /// Connections cache the generation they last validated against, so the
    /// common case costs a single atomic load rather than a directory lookup.
    /// The counter is deliberately global rather than per-device: re-checking
    /// one device more often than strictly necessary is free, whereas missing a
    /// change is a privilege leak.
    fn generation(&self) -> u64;

    /// Returns the grant currently in force.
    ///
    /// `None` means the device may not act at all — it was never paired, or its
    /// pairing has been withdrawn. The two are not distinguished on purpose, so
    /// that a revoked device learns nothing a never-paired device would not.
    fn current_grant(&self, device_wire_id: &str) -> Option<Grant>;
}

#[derive(Debug, Default)]
struct DirectoryInner {
    generation: AtomicU64,
    grants: RwLock<BTreeMap<String, Grant>>,
}

/// Shared, mutable directory of paired devices and their grants.
///
/// Cloning shares one directory; every clone observes the same pairings and the
/// same generation counter.
#[derive(Clone, Debug, Default)]
pub struct DeviceDirectory {
    inner: Arc<DirectoryInner>,
}

impl DeviceDirectory {
    /// Creates an empty directory.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    fn write(&self) -> std::sync::RwLockWriteGuard<'_, BTreeMap<String, Grant>> {
        self.inner
            .grants
            .write()
            .unwrap_or_else(PoisonError::into_inner)
    }

    fn read(&self) -> std::sync::RwLockReadGuard<'_, BTreeMap<String, Grant>> {
        self.inner
            .grants
            .read()
            .unwrap_or_else(PoisonError::into_inner)
    }

    /// Records or replaces the grant for one device and returns the new
    /// generation.
    ///
    /// The generation is bumped while the write lock is still held, so a reader
    /// that observes the new generation and then takes the read lock is
    /// guaranteed to observe the new grant with it.
    pub fn pair(&self, device_wire_id: impl Into<String>, grant: Grant) -> u64 {
        let mut grants = self.write();
        grants.insert(device_wire_id.into(), grant);
        let generation = self.inner.generation.fetch_add(1, Ordering::AcqRel) + 1;
        drop(grants);
        generation
    }

    /// Withdraws a device's pairing.
    ///
    /// Returns `true` when a pairing was actually removed. The generation is
    /// only bumped for a real removal, so repeatedly revoking an unpaired
    /// device cannot be used to force every live connection to re-validate.
    pub fn revoke(&self, device_wire_id: &str) -> bool {
        let mut grants = self.write();
        let removed = grants.remove(device_wire_id).is_some();
        if removed {
            self.inner.generation.fetch_add(1, Ordering::AcqRel);
        }
        drop(grants);
        removed
    }

    /// Returns the number of paired devices.
    #[must_use]
    pub fn len(&self) -> usize {
        self.read().len()
    }

    /// Reports whether no device is paired.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.read().is_empty()
    }
}

impl AuthorizationSource for DeviceDirectory {
    fn generation(&self) -> u64 {
        self.inner.generation.load(Ordering::Acquire)
    }

    fn current_grant(&self, device_wire_id: &str) -> Option<Grant> {
        self.read().get(device_wire_id).cloned()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use claw_protocol::gateway::{OperatorScope, Role};

    fn operator(scopes: &[OperatorScope]) -> Grant {
        Grant::new(Role::Operator, scopes.iter().copied())
    }

    #[test]
    fn an_empty_directory_grants_nothing_and_starts_at_generation_zero() {
        let directory = DeviceDirectory::new();
        assert_eq!(directory.generation(), 0);
        assert_eq!(directory.current_grant("device-a"), None);
        assert!(directory.is_empty());
        assert_eq!(directory.len(), 0);
    }

    #[test]
    fn pairing_bumps_the_generation_once_per_call() {
        let directory = DeviceDirectory::new();
        assert_eq!(
            directory.pair("device-a", operator(&[OperatorScope::Read])),
            1
        );
        assert_eq!(
            directory.pair("device-b", operator(&[OperatorScope::Read])),
            2
        );
        assert_eq!(
            directory.pair("device-a", operator(&[OperatorScope::Admin])),
            3
        );
        assert_eq!(directory.generation(), 3);
        assert_eq!(directory.len(), 2);
    }

    #[test]
    fn a_replaced_grant_is_the_one_reported_afterwards() {
        let directory = DeviceDirectory::new();
        directory.pair("device-a", operator(&[OperatorScope::Admin]));
        directory.pair("device-a", operator(&[OperatorScope::Read]));
        assert_eq!(
            directory.current_grant("device-a"),
            Some(Grant::new(Role::Operator, [OperatorScope::Read]))
        );
    }

    #[test]
    fn revoking_removes_the_grant_and_bumps_the_generation() {
        let directory = DeviceDirectory::new();
        directory.pair("device-a", operator(&[OperatorScope::Admin]));
        assert_eq!(directory.generation(), 1);

        assert!(directory.revoke("device-a"));
        assert_eq!(directory.generation(), 2);
        assert_eq!(directory.current_grant("device-a"), None);
        assert!(directory.is_empty());
    }

    #[test]
    fn revoking_an_unpaired_device_changes_nothing() {
        let directory = DeviceDirectory::new();
        directory.pair("device-a", operator(&[OperatorScope::Read]));
        let before = directory.generation();

        assert!(!directory.revoke("device-b"));
        assert!(!directory.revoke("device-b"));

        assert_eq!(directory.generation(), before);
        assert_eq!(
            directory.current_grant("device-a"),
            Some(Grant::new(Role::Operator, [OperatorScope::Read]))
        );
    }

    #[test]
    fn clones_share_one_directory() {
        let directory = DeviceDirectory::new();
        let handle = directory.clone();
        handle.pair("device-a", operator(&[OperatorScope::Write]));

        assert_eq!(directory.generation(), 1);
        assert_eq!(
            directory.current_grant("device-a"),
            Some(Grant::new(Role::Operator, [OperatorScope::Write]))
        );

        assert!(directory.revoke("device-a"));
        assert_eq!(handle.current_grant("device-a"), None);
        assert_eq!(handle.generation(), 2);
    }

    #[test]
    fn concurrent_pairing_assigns_every_caller_a_distinct_generation() {
        let directory = DeviceDirectory::new();
        let observed = std::sync::Mutex::new(Vec::new());
        std::thread::scope(|scope| {
            for index in 0..8_u32 {
                let directory = directory.clone();
                let observed = &observed;
                scope.spawn(move || {
                    let generation =
                        directory.pair(format!("device-{index}"), operator(&[OperatorScope::Read]));
                    observed
                        .lock()
                        .unwrap_or_else(PoisonError::into_inner)
                        .push(generation);
                });
            }
        });

        let mut generations = observed
            .into_inner()
            .unwrap_or_else(PoisonError::into_inner);
        generations.sort_unstable();
        assert_eq!(generations, (1..=8).collect::<Vec<u64>>());
        assert_eq!(directory.generation(), 8);
        assert_eq!(directory.len(), 8);
    }
}

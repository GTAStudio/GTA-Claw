//! Live connection directory backing presence and node discovery methods.
//!
//! This is deliberately *runtime* state rather than persistence: entries exist
//! exactly as long as their connection does, so it is not part of the
//! [`crate::store::GatewayStore`] port.

use std::collections::BTreeMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, PoisonError};

use claw_protocol::gateway::{CompatibilityMode, OperatorScope, Role};

use crate::events::ConnectionId;

/// Wire identity of a negotiated compatibility path.
#[must_use]
pub fn compatibility_identity(mode: CompatibilityMode) -> &'static str {
    match mode {
        CompatibilityMode::Current => "current",
        CompatibilityMode::LegacyProbe => "legacy-probe",
        CompatibilityMode::LegacyNode => "legacy-node",
    }
}

/// An authenticated connection as observed by presence and node methods.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ConnectionInfo {
    /// Server-assigned connection identity.
    pub id: ConnectionId,
    /// Authenticated role.
    pub role: Role,
    /// Effective closed operator scopes.
    pub scopes: Vec<OperatorScope>,
    /// Verified device wire identity.
    pub device_id: String,
    /// Closed client product identity.
    pub client_id: String,
    /// Closed coarse client mode.
    pub client_mode: String,
    /// Client-declared app version.
    pub client_version: String,
    /// Negotiated protocol version.
    pub protocol: u16,
    /// Negotiated compatibility path.
    pub compatibility: &'static str,
    /// Connection admission timestamp in epoch milliseconds.
    pub connected_at_ms: u64,
    /// Node command claims, empty for operators.
    pub commands: Vec<String>,
}

/// One directory entry together with the registration that placed it.
///
/// The serial is what lets a [`ConnectionRegistration`] prove it is unwinding
/// its *own* entry rather than evicting whatever happens to occupy its id.
#[derive(Clone, Debug)]
struct Registered {
    serial: u64,
    info: ConnectionInfo,
}

/// Shared registry of authenticated connections.
#[derive(Clone, Debug, Default)]
pub struct ConnectionDirectory {
    entries: Arc<Mutex<BTreeMap<u64, Registered>>>,
    next_serial: Arc<AtomicU64>,
}

impl ConnectionDirectory {
    /// Creates an empty directory.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, BTreeMap<u64, Registered>> {
        self.entries.lock().unwrap_or_else(PoisonError::into_inner)
    }

    fn next_serial(&self) -> u64 {
        self.next_serial.fetch_add(1, Ordering::Relaxed) + 1
    }

    /// Records an authenticated connection, replacing any entry with the same id.
    pub fn insert(&self, info: ConnectionInfo) {
        let serial = self.next_serial();
        self.lock()
            .insert(info.id.get(), Registered { serial, info });
    }

    /// Records an authenticated connection and returns its lifetime guard.
    ///
    /// Prefer this to [`Self::insert`] whenever the caller is an async task.
    /// A future can be dropped at any await point — the accept loop aborts
    /// connections that outlive the graceful-drain window — and a dropped
    /// future never runs the code after its await. Tying removal to `Drop` is
    /// the only way the directory cannot retain a connection that has ceased
    /// to exist, because `Drop` runs on the cancellation path too.
    #[must_use = "dropping the guard immediately deregisters the connection"]
    pub fn register(&self, info: ConnectionInfo) -> ConnectionRegistration {
        let id = info.id;
        let serial = self.next_serial();
        self.lock().insert(id.get(), Registered { serial, info });
        ConnectionRegistration {
            directory: self.clone(),
            id,
            serial,
        }
    }

    /// Removes an entry only while `serial` still owns it.
    fn remove_registered(&self, id: ConnectionId, serial: u64) -> bool {
        let mut entries = self.lock();
        if entries
            .get(&id.get())
            .is_some_and(|held| held.serial == serial)
        {
            entries.remove(&id.get());
            return true;
        }
        false
    }

    /// Removes one connection, returning the entry when it was present.
    pub fn remove(&self, id: ConnectionId) -> Option<ConnectionInfo> {
        self.lock().remove(&id.get()).map(|held| held.info)
    }

    /// Returns every authenticated connection ordered by connection id.
    #[must_use]
    pub fn all(&self) -> Vec<ConnectionInfo> {
        self.lock().values().map(|held| held.info.clone()).collect()
    }

    /// Returns every authenticated connection whose role is `node`.
    #[must_use]
    pub fn nodes(&self) -> Vec<ConnectionInfo> {
        self.lock()
            .values()
            .map(|held| &held.info)
            .filter(|info| info.role == Role::Node)
            .cloned()
            .collect()
    }

    /// Returns the node connection with an exact device identity.
    #[must_use]
    pub fn node(&self, device_id: &str) -> Option<ConnectionInfo> {
        self.lock()
            .values()
            .map(|held| &held.info)
            .find(|info| info.role == Role::Node && info.device_id == device_id)
            .cloned()
    }

    /// Returns the number of live entries.
    #[must_use]
    pub fn len(&self) -> usize {
        self.lock().len()
    }

    /// Reports whether the directory holds no entries.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.lock().is_empty()
    }
}

/// Keeps one connection in the directory for exactly as long as it is served.
///
/// This exists because the compensating write for "mark this connection live"
/// used to sit *after* an await, so a cancelled connection future left a
/// permanent phantom entry: connection ids are allocated monotonically and
/// never reused, the directory has no expiry sweep, and shutdown does not
/// clear it, so no later code path could evict the stale row.
///
/// The guard removes its entry unconditionally on drop — there is no
/// success path on which a served connection should outlive its own future —
/// and it removes *only* the entry it placed, verified by serial. Relying on
/// "no two connections share an id" would be an invariant of today's accept
/// loop rather than of this type, and [`ConnectionDirectory::insert`] is
/// public and takes a caller-supplied id.
#[derive(Debug)]
pub struct ConnectionRegistration {
    directory: ConnectionDirectory,
    id: ConnectionId,
    serial: u64,
}

impl ConnectionRegistration {
    /// Returns the connection identity this registration owns.
    #[must_use]
    pub const fn id(&self) -> ConnectionId {
        self.id
    }
}

impl Drop for ConnectionRegistration {
    fn drop(&mut self) {
        self.directory.remove_registered(self.id, self.serial);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn info(id: u64, role: Role, device: &str) -> ConnectionInfo {
        ConnectionInfo {
            id: ConnectionId::new(id),
            role,
            scopes: vec![OperatorScope::Read],
            device_id: device.to_owned(),
            client_id: "claw-cli".to_owned(),
            client_mode: "cli".to_owned(),
            client_version: "0.1.0".to_owned(),
            protocol: 4,
            compatibility: "current",
            connected_at_ms: 10,
            commands: Vec::new(),
        }
    }

    #[test]
    fn directory_separates_nodes_from_operators() {
        let directory = ConnectionDirectory::new();
        directory.insert(info(1, Role::Operator, "dev-op"));
        directory.insert(info(2, Role::Node, "dev-node"));
        assert_eq!(directory.len(), 2);
        let nodes = directory.nodes();
        assert_eq!(nodes.len(), 1);
        assert_eq!(nodes[0].device_id, "dev-node");
        assert_eq!(directory.all().len(), 2);
    }

    #[test]
    fn node_lookup_ignores_operator_devices_with_the_same_identity() {
        let directory = ConnectionDirectory::new();
        directory.insert(info(1, Role::Operator, "shared"));
        assert!(directory.node("shared").is_none());
        directory.insert(info(2, Role::Node, "shared"));
        assert_eq!(
            directory.node("shared").map(|info| info.id),
            Some(ConnectionId::new(2))
        );
    }

    #[test]
    fn removal_reports_presence_exactly_once() {
        let directory = ConnectionDirectory::new();
        directory.insert(info(3, Role::Node, "dev"));
        assert_eq!(
            directory.remove(ConnectionId::new(3)).map(|info| info.id),
            Some(ConnectionId::new(3))
        );
        assert!(directory.remove(ConnectionId::new(3)).is_none());
        assert!(directory.is_empty());
    }

    #[test]
    fn reinserting_the_same_id_replaces_the_entry() {
        let directory = ConnectionDirectory::new();
        directory.insert(info(1, Role::Node, "first"));
        directory.insert(info(1, Role::Node, "second"));
        assert_eq!(directory.len(), 1);
        assert_eq!(directory.nodes()[0].device_id, "second");
    }

    #[test]
    fn compatibility_identities_are_distinct_and_stable() {
        assert_eq!(
            compatibility_identity(CompatibilityMode::Current),
            "current"
        );
        assert_eq!(
            compatibility_identity(CompatibilityMode::LegacyProbe),
            "legacy-probe"
        );
        assert_eq!(
            compatibility_identity(CompatibilityMode::LegacyNode),
            "legacy-node"
        );
    }

    #[test]
    fn a_dropped_registration_removes_its_own_entry() {
        let directory = ConnectionDirectory::new();
        {
            let registration = directory.register(info(1, Role::Operator, "dev-op"));
            assert_eq!(registration.id(), ConnectionId::new(1));
            assert_eq!(directory.len(), 1);
            assert_eq!(
                directory.all().first().map(|entry| entry.device_id.clone()),
                Some("dev-op".to_owned())
            );
        }
        assert!(
            directory.is_empty(),
            "a dropped registration must not leave the connection behind"
        );
    }

    #[test]
    fn a_registration_never_evicts_an_entry_that_replaced_it() {
        let directory = ConnectionDirectory::new();
        let first = directory.register(info(1, Role::Operator, "first"));
        // A second registration takes the same id. Monotonic ids make this
        // impossible in today's accept loop, but `insert`/`register` are
        // public and take a caller-supplied id, so the guard must not rely
        // on that being true.
        let second = directory.register(info(1, Role::Operator, "second"));
        assert_eq!(directory.len(), 1);

        drop(first);
        assert_eq!(
            directory.all().first().map(|entry| entry.device_id.clone()),
            Some("second".to_owned()),
            "the stale guard evicted a live connection it never registered"
        );

        drop(second);
        assert!(directory.is_empty());
    }

    #[test]
    fn an_explicit_removal_leaves_the_guard_with_nothing_to_undo() {
        let directory = ConnectionDirectory::new();
        let registration = directory.register(info(1, Role::Node, "dev-node"));
        assert_eq!(
            directory
                .remove(ConnectionId::new(1))
                .map(|entry| entry.device_id),
            Some("dev-node".to_owned())
        );
        assert!(directory.is_empty());

        directory.insert(info(1, Role::Operator, "later"));
        drop(registration);
        assert_eq!(
            directory.all().first().map(|entry| entry.device_id.clone()),
            Some("later".to_owned()),
            "the guard clobbered an unrelated entry after its own was removed"
        );
    }

    #[test]
    fn registration_serials_are_distinct_across_reused_identities() {
        let directory = ConnectionDirectory::new();
        let first = directory.register(info(1, Role::Operator, "a"));
        drop(first);
        let second = directory.register(info(1, Role::Operator, "b"));
        assert_eq!(directory.len(), 1);
        drop(second);
        assert!(directory.is_empty());
    }
}

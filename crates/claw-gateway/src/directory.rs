//! Live connection directory backing presence and node discovery methods.
//!
//! This is deliberately *runtime* state rather than persistence: entries exist
//! exactly as long as their connection does, so it is not part of the
//! [`crate::store::GatewayStore`] port.

use std::collections::BTreeMap;
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

/// Shared registry of authenticated connections.
#[derive(Clone, Debug, Default)]
pub struct ConnectionDirectory {
    entries: Arc<Mutex<BTreeMap<u64, ConnectionInfo>>>,
}

impl ConnectionDirectory {
    /// Creates an empty directory.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, BTreeMap<u64, ConnectionInfo>> {
        self.entries.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// Records an authenticated connection, replacing any entry with the same id.
    pub fn insert(&self, info: ConnectionInfo) {
        self.lock().insert(info.id.get(), info);
    }

    /// Removes one connection, returning the entry when it was present.
    pub fn remove(&self, id: ConnectionId) -> Option<ConnectionInfo> {
        self.lock().remove(&id.get())
    }

    /// Returns every authenticated connection ordered by connection id.
    #[must_use]
    pub fn all(&self) -> Vec<ConnectionInfo> {
        self.lock().values().cloned().collect()
    }

    /// Returns every authenticated connection whose role is `node`.
    #[must_use]
    pub fn nodes(&self) -> Vec<ConnectionInfo> {
        self.lock()
            .values()
            .filter(|info| info.role == Role::Node)
            .cloned()
            .collect()
    }

    /// Returns the node connection with an exact device identity.
    #[must_use]
    pub fn node(&self, device_id: &str) -> Option<ConnectionInfo> {
        self.lock()
            .values()
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
}

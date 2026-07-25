//! The plugin registry: every descriptor in the frozen upstream inventory.
//!
//! `compat/upstream/inventories/plugins.json` is a frozen contract artifact
//! holding 137 plugin descriptors (64 core, 70 official external, 3 source-only
//! QA). It is projected into [`registry_data`](crate::registry_data) by
//! `scripts/generate-plugin-registry.ps1` and re-checked against the frozen
//! JSON by `tests/registry_matches_inventory.rs`.
//!
//! # Honest implementation status
//!
//! Registration is *not* implementation. Every descriptor starts as
//! [`ImplementationStatus::RegistrationOnly`], which means the host knows the
//! plugin's identity, delivery class and upstream provenance and nothing else:
//! there is no Wasm component behind it. A plugin may only move to
//! [`ImplementationStatus::ComponentAvailable`] by being listed in
//! [`COMPONENT_BACKED_PLUGIN_IDS`], and that list is asserted to be exactly the
//! set of plugins with a real component in this repository.

use core::fmt;

use serde::{Deserialize, Serialize};

use crate::registry_data::INVENTORY;

/// Plugin ids that have a real, loadable Wasm component in this repository.
///
/// This list is deliberately empty: this workspace ships the plugin *host* and
/// the ABI, not ports of the upstream plugins. `tests/registry.rs` fails if a
/// descriptor claims to be component-backed without appearing here.
pub const COMPONENT_BACKED_PLUGIN_IDS: &[&str] = &[];

/// Total number of descriptors in the frozen inventory.
pub const TOTAL_PLUGINS: usize = 137;
/// Number of `core` descriptors in the frozen inventory.
pub const CORE_PLUGINS: usize = 64;
/// Number of `official_external` descriptors in the frozen inventory.
pub const OFFICIAL_EXTERNAL_PLUGINS: usize = 70;
/// Number of `source_only_qa` descriptors in the frozen inventory.
pub const SOURCE_ONLY_QA_PLUGINS: usize = 3;

/// How upstream ships a plugin.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DeliveryClass {
    /// Bundled with the upstream package.
    Core,
    /// Published separately and installed on demand.
    OfficialExternal,
    /// Present in the upstream source tree for QA only; never published.
    SourceOnlyQa,
}

impl DeliveryClass {
    /// Every delivery class.
    pub const ALL: [Self; 3] = [Self::Core, Self::OfficialExternal, Self::SourceOnlyQa];

    /// The wire name used by the frozen inventory.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Core => "core",
            Self::OfficialExternal => "official_external",
            Self::SourceOnlyQa => "source_only_qa",
        }
    }
}

impl fmt::Display for DeliveryClass {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Whether a descriptor is backed by a real component.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ImplementationStatus {
    /// Identity and provenance only. No component exists in this repository.
    RegistrationOnly,
    /// A loadable Wasm component ships with this repository.
    ComponentAvailable,
}

/// One frozen upstream inventory row.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct InventoryRecord {
    pub(crate) record_id: &'static str,
    pub(crate) id: &'static str,
    pub(crate) source_path: &'static str,
    pub(crate) package_name: &'static str,
    pub(crate) delivery_class: DeliveryClass,
}

impl InventoryRecord {
    /// Globally unique record id, for example `plugin:anthropic`.
    #[must_use]
    pub const fn record_id(&self) -> &'static str {
        self.record_id
    }

    /// Upstream plugin id, for example `anthropic`.
    #[must_use]
    pub const fn id(&self) -> &'static str {
        self.id
    }

    /// Path of the plugin inside the upstream source tree.
    #[must_use]
    pub const fn source_path(&self) -> &'static str {
        self.source_path
    }

    /// Upstream npm package name. Recorded as provenance only: GTA-Claw never
    /// installs or executes it.
    #[must_use]
    pub const fn package_name(&self) -> &'static str {
        self.package_name
    }

    /// How upstream ships this plugin.
    #[must_use]
    pub const fn delivery_class(&self) -> DeliveryClass {
        self.delivery_class
    }
}

/// An inventory row together with this repository's implementation status.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct PluginDescriptor {
    record: &'static InventoryRecord,
    implementation: ImplementationStatus,
}

impl PluginDescriptor {
    /// The frozen inventory row.
    #[must_use]
    pub const fn record(&self) -> &'static InventoryRecord {
        self.record
    }

    /// Upstream plugin id.
    #[must_use]
    pub const fn id(&self) -> &'static str {
        self.record.id
    }

    /// How upstream ships this plugin.
    #[must_use]
    pub const fn delivery_class(&self) -> DeliveryClass {
        self.record.delivery_class
    }

    /// Whether a real component exists for this plugin in this repository.
    #[must_use]
    pub const fn implementation(&self) -> ImplementationStatus {
        self.implementation
    }
}

/// Read-only view over the frozen plugin inventory.
#[derive(Clone, Copy, Debug, Default)]
pub struct PluginRegistry;

impl PluginRegistry {
    /// Every descriptor, ordered by [`InventoryRecord::id`].
    #[must_use]
    pub fn all() -> impl ExactSizeIterator<Item = PluginDescriptor> {
        INVENTORY.iter().map(|record| PluginDescriptor {
            record,
            implementation: implementation_status(record.id),
        })
    }

    /// Number of descriptors.
    #[must_use]
    pub fn len() -> usize {
        INVENTORY.len()
    }

    /// Always `false`; kept so callers can treat the registry like a container.
    #[must_use]
    pub fn is_empty() -> bool {
        INVENTORY.is_empty()
    }

    /// Looks a descriptor up by upstream plugin id.
    #[must_use]
    pub fn get(id: &str) -> Option<PluginDescriptor> {
        INVENTORY
            .binary_search_by(|record| record.id.cmp(id))
            .ok()
            .map(|index| PluginDescriptor {
                record: &INVENTORY[index],
                implementation: implementation_status(INVENTORY[index].id),
            })
    }

    /// Every descriptor with the given delivery class.
    pub fn by_delivery_class(class: DeliveryClass) -> impl Iterator<Item = PluginDescriptor> {
        Self::all().filter(move |descriptor| descriptor.delivery_class() == class)
    }

    /// Number of descriptors per delivery class, in [`DeliveryClass::ALL`] order.
    #[must_use]
    pub fn counts() -> [usize; 3] {
        let mut counts = [0_usize; 3];
        for record in &INVENTORY {
            let index = match record.delivery_class {
                DeliveryClass::Core => 0,
                DeliveryClass::OfficialExternal => 1,
                DeliveryClass::SourceOnlyQa => 2,
            };
            counts[index] += 1;
        }
        counts
    }
}

fn implementation_status(id: &str) -> ImplementationStatus {
    if COMPONENT_BACKED_PLUGIN_IDS.contains(&id) {
        ImplementationStatus::ComponentAvailable
    } else {
        ImplementationStatus::RegistrationOnly
    }
}

#[cfg(test)]
mod tests {
    use super::{
        COMPONENT_BACKED_PLUGIN_IDS, CORE_PLUGINS, DeliveryClass, ImplementationStatus,
        OFFICIAL_EXTERNAL_PLUGINS, PluginRegistry, SOURCE_ONLY_QA_PLUGINS, TOTAL_PLUGINS,
    };

    #[test]
    fn the_registry_is_sorted_by_id_and_has_unique_ids() {
        let ids: Vec<&str> = PluginRegistry::all().map(|d| d.id()).collect();
        let mut sorted = ids.clone();
        sorted.sort_unstable();
        sorted.dedup();
        assert_eq!(ids, sorted, "registry must be sorted and duplicate free");
    }

    #[test]
    fn lookup_finds_a_descriptor_from_each_delivery_class() {
        let admin = PluginRegistry::get("admin-http-rpc").expect("core descriptor");
        assert_eq!(admin.delivery_class(), DeliveryClass::Core);
        assert_eq!(admin.record().record_id(), "plugin:admin-http-rpc");
        assert_eq!(admin.record().source_path(), "extensions/admin-http-rpc");
        assert_eq!(admin.record().package_name(), "@openclaw/admin-http-rpc");

        let qa = PluginRegistry::get("qa-lab").expect("qa descriptor");
        assert_eq!(qa.delivery_class(), DeliveryClass::SourceOnlyQa);
        assert_eq!(qa.record().record_id(), "plugin:qa-lab");

        assert_eq!(PluginRegistry::get("not-a-real-plugin"), None);
    }

    #[test]
    fn counts_match_the_frozen_totals() {
        assert_eq!(PluginRegistry::len(), TOTAL_PLUGINS);
        assert!(!PluginRegistry::is_empty());
        assert_eq!(
            PluginRegistry::counts(),
            [
                CORE_PLUGINS,
                OFFICIAL_EXTERNAL_PLUGINS,
                SOURCE_ONLY_QA_PLUGINS
            ]
        );
        assert_eq!(
            PluginRegistry::by_delivery_class(DeliveryClass::Core).count(),
            CORE_PLUGINS
        );
        assert_eq!(
            PluginRegistry::by_delivery_class(DeliveryClass::OfficialExternal).count(),
            OFFICIAL_EXTERNAL_PLUGINS
        );
        assert_eq!(
            PluginRegistry::by_delivery_class(DeliveryClass::SourceOnlyQa).count(),
            SOURCE_ONLY_QA_PLUGINS
        );
    }

    #[test]
    fn no_descriptor_claims_an_implementation_it_does_not_have() {
        let claimed: Vec<&str> = PluginRegistry::all()
            .filter(|d| d.implementation() == ImplementationStatus::ComponentAvailable)
            .map(|d| d.id())
            .collect();
        assert_eq!(claimed, COMPONENT_BACKED_PLUGIN_IDS.to_vec());
    }

    #[test]
    fn every_component_backed_id_exists_in_the_inventory() {
        for id in COMPONENT_BACKED_PLUGIN_IDS {
            assert!(
                PluginRegistry::get(id).is_some(),
                "`{id}` is not an inventory plugin"
            );
        }
    }

    #[test]
    fn delivery_class_wire_names_match_the_frozen_inventory() {
        assert_eq!(DeliveryClass::Core.as_str(), "core");
        assert_eq!(
            DeliveryClass::OfficialExternal.as_str(),
            "official_external"
        );
        assert_eq!(DeliveryClass::SourceOnlyQa.as_str(), "source_only_qa");
        assert_eq!(
            serde_json::to_string(&DeliveryClass::ALL.to_vec()).expect("serialize"),
            "[\"core\",\"official_external\",\"source_only_qa\"]"
        );
    }
}

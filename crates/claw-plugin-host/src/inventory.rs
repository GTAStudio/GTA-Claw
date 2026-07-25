//! An honest view of which inventory plugins this host can actually run.
//!
//! The registry in `claw-plugin-api` mirrors the frozen upstream inventory
//! exactly: 137 descriptors with their ids and delivery classes. Mirroring a
//! descriptor is *not* the same as shipping a component, and this module
//! exists so that difference is reported rather than implied.

use claw_plugin_api::registry::{DeliveryClass, ImplementationStatus, PluginRegistry};

/// A summary of the registry's implementation status.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RegistryReport {
    /// Descriptors mirrored from the frozen inventory.
    pub total: usize,
    /// Descriptors whose delivery class is `core`.
    pub core: usize,
    /// Descriptors whose delivery class is `official_external`.
    pub official_external: usize,
    /// Descriptors whose delivery class is `source_only_qa`.
    pub source_only_qa: usize,
    /// Descriptors with a component this host can load, sorted by id.
    pub component_backed: Vec<&'static str>,
    /// Descriptors that exist only as metadata, sorted by id.
    pub registration_only: usize,
}

impl RegistryReport {
    /// Whether any inventory plugin ships a loadable component.
    #[must_use]
    pub fn has_any_component(&self) -> bool {
        !self.component_backed.is_empty()
    }
}

/// Builds the registry report from the registry itself.
#[must_use]
pub fn describe_registry() -> RegistryReport {
    let mut component_backed = Vec::new();
    let mut registration_only = 0;
    for descriptor in PluginRegistry::all() {
        match descriptor.implementation() {
            ImplementationStatus::ComponentAvailable => component_backed.push(descriptor.id()),
            ImplementationStatus::RegistrationOnly => registration_only += 1,
        }
    }
    component_backed.sort_unstable();
    RegistryReport {
        total: PluginRegistry::len(),
        core: PluginRegistry::by_delivery_class(DeliveryClass::Core).count(),
        official_external: PluginRegistry::by_delivery_class(DeliveryClass::OfficialExternal)
            .count(),
        source_only_qa: PluginRegistry::by_delivery_class(DeliveryClass::SourceOnlyQa).count(),
        component_backed,
        registration_only,
    }
}

#[cfg(test)]
mod tests {
    use claw_plugin_api::registry::{
        CORE_PLUGINS, OFFICIAL_EXTERNAL_PLUGINS, SOURCE_ONLY_QA_PLUGINS, TOTAL_PLUGINS,
    };

    use super::describe_registry;

    #[test]
    fn the_report_counts_match_the_frozen_inventory_totals() {
        let report = describe_registry();
        assert_eq!(report.total, TOTAL_PLUGINS);
        assert_eq!(report.core, CORE_PLUGINS);
        assert_eq!(report.official_external, OFFICIAL_EXTERNAL_PLUGINS);
        assert_eq!(report.source_only_qa, SOURCE_ONLY_QA_PLUGINS);
        assert_eq!(
            report.core + report.official_external + report.source_only_qa,
            report.total
        );
    }

    #[test]
    fn this_repository_ships_no_inventory_plugin_components() {
        let report = describe_registry();
        assert!(!report.has_any_component());
        assert_eq!(report.component_backed, Vec::<&str>::new());
        assert_eq!(report.registration_only, TOTAL_PLUGINS);
    }
}

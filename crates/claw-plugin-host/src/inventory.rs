//! An honest view of which inventory plugins this host can actually run.
//!
//! The registry in `claw-plugin-api` mirrors the frozen upstream inventory
//! exactly: 137 descriptors with their ids and delivery classes. Mirroring a
//! descriptor is *not* the same as shipping a component, and this module
//! exists so that difference is reported rather than implied.

use claw_plugin_api::compat::{self, CompatibilityDecision, InstallDecision};
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
    pub const fn has_any_component(&self) -> bool {
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

/// One delivery class's slice of the compatibility report.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DeliveryClassSummary {
    /// The delivery class this summary covers.
    pub class: DeliveryClass,
    /// The install decision every contract in this class receives.
    pub install: InstallDecision,
    /// Contracts upstream ships this way.
    pub total: usize,
    /// Contracts in this class with a loadable component in this repository.
    pub component_shipped: usize,
    /// Contracts in this class held open by an explicit stub.
    pub stubs: usize,
    /// The stub decision used in this class, or `None` when it has no stubs.
    ///
    /// Every stub in a class is of the same kind, so a single value describes
    /// them all. It is `Some` exactly when [`stubs`](Self::stubs) is non-zero.
    pub stub_decision: Option<CompatibilityDecision>,
}

/// Which inventory contracts are implemented and which are explicit stubs.
///
/// [`describe_registry`] answers "how many plugins does upstream have?".
/// This answers "and what did GTA-Claw decide about each of them?" — the
/// question a parity reader is actually asking.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CompatibilityReport {
    /// Contracts decided, which is every row of the frozen inventory.
    pub total: usize,
    /// Contracts with a loadable component in this repository, sorted by id.
    pub component_shipped: Vec<&'static str>,
    /// Contracts held open by an explicit stub.
    pub stubs: usize,
    /// The same decisions split by delivery class, in [`DeliveryClass::ALL`]
    /// order.
    pub per_delivery_class: [DeliveryClassSummary; 3],
}

impl CompatibilityReport {
    /// The summary for one delivery class.
    ///
    /// # Panics
    ///
    /// Panics when the report does not cover `class`, which cannot happen for
    /// a report built by [`describe_compatibility`].
    #[must_use]
    pub fn for_class(&self, class: DeliveryClass) -> &DeliveryClassSummary {
        self.per_delivery_class
            .iter()
            .find(|summary| summary.class == class)
            .unwrap_or_else(|| panic!("the report must cover `{class}`"))
    }

    /// Whether every decision leaves GTA-Claw fetching nothing.
    ///
    /// This is the npm-free invariant stated as a runtime check: no inventory
    /// contract may resolve to a decision that downloads an artifact.
    #[must_use]
    pub fn acquires_no_artifact(&self) -> bool {
        self.per_delivery_class
            .iter()
            .all(|summary| !summary.install.acquires_artifact())
    }
}

/// Builds the compatibility report from the per-contract decisions.
#[must_use]
pub fn describe_compatibility() -> CompatibilityReport {
    let per_delivery_class = DeliveryClass::ALL.map(summarise_class);
    let mut component_shipped: Vec<&'static str> = compat::component_backed()
        .map(|decision| decision.id())
        .collect();
    component_shipped.sort_unstable();
    CompatibilityReport {
        total: compat::all().len(),
        stubs: compat::stub_count(),
        component_shipped,
        per_delivery_class,
    }
}

fn summarise_class(class: DeliveryClass) -> DeliveryClassSummary {
    let mut total = 0;
    let mut component_shipped = 0;
    let mut stubs = 0;
    let mut stub_decision = None;
    for decision in compat::by_delivery_class(class) {
        total += 1;
        match decision.compatibility() {
            CompatibilityDecision::ComponentShipped => component_shipped += 1,
            stub @ CompatibilityDecision::Stub(_) => {
                stubs += 1;
                let previous = stub_decision.replace(stub);
                assert!(
                    previous.is_none_or(|seen| seen == stub),
                    "delivery class `{class}` mixes stub kinds"
                );
            }
        }
    }
    DeliveryClassSummary {
        class,
        install: InstallDecision::for_delivery_class(class),
        total,
        component_shipped,
        stubs,
        stub_decision,
    }
}

#[cfg(test)]
mod tests {
    use claw_plugin_api::compat::{CompatibilityDecision, InstallDecision, StubKind};
    use claw_plugin_api::registry::{
        CORE_PLUGINS, DeliveryClass, OFFICIAL_EXTERNAL_PLUGINS, SOURCE_ONLY_QA_PLUGINS,
        TOTAL_PLUGINS,
    };

    use super::{describe_compatibility, describe_registry};

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

    #[test]
    fn the_compatibility_report_decides_every_contract_exactly_once() {
        let report = describe_compatibility();
        assert_eq!(report.total, TOTAL_PLUGINS);
        assert_eq!(report.component_shipped, Vec::<&str>::new());
        assert_eq!(report.stubs, TOTAL_PLUGINS);
        assert!(report.acquires_no_artifact());

        let mut decided = 0;
        for summary in &report.per_delivery_class {
            assert_eq!(
                summary.component_shipped + summary.stubs,
                summary.total,
                "{} was not fully decided",
                summary.class
            );
            assert_eq!(
                summary.install,
                InstallDecision::for_delivery_class(summary.class)
            );
            decided += summary.total;
        }
        assert_eq!(decided, TOTAL_PLUGINS);
    }

    #[test]
    fn each_delivery_class_summary_matches_its_frozen_total() {
        let report = describe_compatibility();
        for (class, expected, stub_kind) in [
            (
                DeliveryClass::Core,
                CORE_PLUGINS,
                StubKind::RegistrationOnly,
            ),
            (
                DeliveryClass::OfficialExternal,
                OFFICIAL_EXTERNAL_PLUGINS,
                StubKind::RegistrationOnly,
            ),
            (
                DeliveryClass::SourceOnlyQa,
                SOURCE_ONLY_QA_PLUGINS,
                StubKind::TestToolingFixture,
            ),
        ] {
            let summary = report.for_class(class);
            assert_eq!(summary.total, expected, "total for {class}");
            assert_eq!(summary.stubs, expected, "stubs for {class}");
            assert_eq!(summary.component_shipped, 0, "components for {class}");
            assert_eq!(
                summary.stub_decision,
                Some(CompatibilityDecision::Stub(stub_kind)),
                "stub kind for {class}"
            );
        }
    }
}

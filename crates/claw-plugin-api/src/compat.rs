//! Per-contract install and compatibility decisions for the frozen inventory.
//!
//! [`registry`](crate::registry) answers *what upstream ships*. This module
//! answers the two questions a parity reader actually asks about each of those
//! 137 contracts:
//!
//! * [`InstallDecision`] — where the upstream artifact would come from, and
//!   what GTA-Claw does about it. GTA-Claw is npm-free, so the answer is never
//!   "fetch it": [`InstallDecision::acquires_artifact`] is false for every
//!   decision this module can produce.
//! * [`CompatibilityDecision`] — what this repository offers in its place. A
//!   contract is either backed by a real component or held open by an
//!   **explicit stub**, and the stub says which kind it is.
//!
//! # Why this is not a second inventory
//!
//! Nothing here lists a plugin by name. Every decision is computed from a
//! [`PluginDescriptor`] that came out of the
//! frozen inventory, and [`decide`] answers `None` for an id the frozen
//! inventory does not contain. A decision therefore cannot exist for a plugin
//! upstream does not have, and cannot go missing for one it does.
//!
//! # Honest status
//!
//! This workspace ships the plugin host and the ABI, not ports of the upstream
//! plugins. At the frozen baseline every one of the 137 decisions is a stub:
//! [`component_backed`] is empty and [`stub_count`] is 137. That is asserted
//! rather than assumed, so the day a real component lands the assertion moves
//! with it.

use core::fmt;

use crate::registry::{DeliveryClass, ImplementationStatus, PluginDescriptor, PluginRegistry};

/// Where an upstream plugin's artifact comes from, and what GTA-Claw does.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum InstallDecision {
    /// Upstream bundles the plugin inside its own package, so upstream itself
    /// has no separate install step. GTA-Claw ships no port of it, so nothing
    /// is installed here either.
    BundledUpstreamNotPorted,
    /// Upstream publishes the plugin as a separately installable npm package.
    /// GTA-Claw consumes no npm registry at all, so the on-demand install is
    /// declined outright rather than deferred; a port would arrive as a signed
    /// WebAssembly component beneath a trust root, never as a package install.
    DeclinedNpmOnDemand,
    /// Upstream never publishes the plugin: it exists in the upstream source
    /// tree for QA only. There is no installable artifact in any ecosystem, so
    /// there is nothing for any host to decide to install.
    NeverPublishedSourceOnly,
}

impl InstallDecision {
    /// Every install decision, in declaration order.
    pub const ALL: [Self; 3] = [
        Self::BundledUpstreamNotPorted,
        Self::DeclinedNpmOnDemand,
        Self::NeverPublishedSourceOnly,
    ];

    /// The stable wire name of this decision.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::BundledUpstreamNotPorted => "bundled_upstream_not_ported",
            Self::DeclinedNpmOnDemand => "declined_npm_on_demand",
            Self::NeverPublishedSourceOnly => "never_published_source_only",
        }
    }

    /// Why this decision was reached.
    #[must_use]
    pub const fn rationale(self) -> &'static str {
        match self {
            Self::BundledUpstreamNotPorted => {
                "upstream bundles this plugin with its own package; GTA-Claw ships no port of it"
            }
            Self::DeclinedNpmOnDemand => {
                "upstream publishes this plugin on npm; GTA-Claw consumes no npm registry"
            }
            Self::NeverPublishedSourceOnly => {
                "upstream never publishes this plugin; it exists in the upstream source tree for QA"
            }
        }
    }

    /// Whether acting on this decision would fetch an artifact from anywhere.
    ///
    /// This is false for every variant, and deliberately written as an
    /// exhaustive match rather than a bare `false`: a fourth variant that did
    /// acquire something would not compile until somebody answered for it.
    #[must_use]
    #[expect(
        clippy::match_same_arms,
        reason = "the arms are identical on purpose: one arm per variant forces a future variant \
                  that does acquire an artifact to be answered for here instead of inheriting a \
                  wildcard `false`"
    )]
    pub const fn acquires_artifact(self) -> bool {
        match self {
            Self::BundledUpstreamNotPorted => false,
            Self::DeclinedNpmOnDemand => false,
            Self::NeverPublishedSourceOnly => false,
        }
    }

    /// The install decision implied by how upstream ships a plugin.
    #[must_use]
    pub const fn for_delivery_class(class: DeliveryClass) -> Self {
        match class {
            DeliveryClass::Core => Self::BundledUpstreamNotPorted,
            DeliveryClass::OfficialExternal => Self::DeclinedNpmOnDemand,
            DeliveryClass::SourceOnlyQa => Self::NeverPublishedSourceOnly,
        }
    }
}

impl fmt::Display for InstallDecision {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// What kind of stub holds a contract open when no component ships.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum StubKind {
    /// The contract is registered — identity, provenance, delivery class,
    /// install decision and the trust class the host would demand — and
    /// nothing more. No behaviour is implemented.
    RegistrationOnly,
    /// Registered as above, and additionally materialised as a fixture by the
    /// plugin host's test tooling.
    ///
    /// `crates/claw-plugin-host/tests/support/qa.rs` builds one fixture per
    /// contract carrying this kind, and
    /// `crates/claw-plugin-host/tests/qa_plugin_tooling.rs` asserts the two
    /// sets are equal, so this claim cannot drift away from the tooling that
    /// backs it.
    TestToolingFixture,
}

impl StubKind {
    /// Every stub kind, in declaration order.
    pub const ALL: [Self; 2] = [Self::RegistrationOnly, Self::TestToolingFixture];

    /// The stable wire name of this stub kind.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::RegistrationOnly => "registration_only",
            Self::TestToolingFixture => "test_tooling_fixture",
        }
    }

    /// The stub kind used for contracts shipped the given way.
    #[must_use]
    pub const fn for_delivery_class(class: DeliveryClass) -> Self {
        match class {
            // A QA plugin is never published, so the only place it can honestly
            // be represented is test tooling.
            DeliveryClass::SourceOnlyQa => Self::TestToolingFixture,
            DeliveryClass::Core | DeliveryClass::OfficialExternal => Self::RegistrationOnly,
        }
    }
}

impl fmt::Display for StubKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// What this repository offers for one upstream plugin contract.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum CompatibilityDecision {
    /// A loadable WebAssembly component for this contract ships here.
    ComponentShipped,
    /// No component ships. The contract is held open by an explicit stub.
    Stub(StubKind),
}

impl CompatibilityDecision {
    /// The stable wire name of this decision.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::ComponentShipped => "component_shipped",
            Self::Stub(StubKind::RegistrationOnly) => "stub_registration_only",
            Self::Stub(StubKind::TestToolingFixture) => "stub_test_tooling_fixture",
        }
    }

    /// The stub kind, or `None` when a real component ships.
    #[must_use]
    pub const fn stub_kind(self) -> Option<StubKind> {
        match self {
            Self::ComponentShipped => None,
            Self::Stub(kind) => Some(kind),
        }
    }

    /// Whether this contract is held open by a stub rather than implemented.
    #[must_use]
    pub const fn is_stub(self) -> bool {
        self.stub_kind().is_some()
    }
}

impl fmt::Display for CompatibilityDecision {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// One frozen inventory contract together with both of its decisions.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct PluginCompatibility {
    descriptor: PluginDescriptor,
    install: InstallDecision,
    compatibility: CompatibilityDecision,
}

impl PluginCompatibility {
    /// Decides both questions for a descriptor from the frozen registry.
    #[must_use]
    pub const fn for_descriptor(descriptor: PluginDescriptor) -> Self {
        let class = descriptor.delivery_class();
        let compatibility = match descriptor.implementation() {
            ImplementationStatus::ComponentAvailable => CompatibilityDecision::ComponentShipped,
            ImplementationStatus::RegistrationOnly => {
                CompatibilityDecision::Stub(StubKind::for_delivery_class(class))
            }
        };
        Self {
            descriptor,
            install: InstallDecision::for_delivery_class(class),
            compatibility,
        }
    }

    /// The registry descriptor this decision was taken for.
    #[must_use]
    pub const fn descriptor(&self) -> PluginDescriptor {
        self.descriptor
    }

    /// Upstream plugin id.
    #[must_use]
    pub const fn id(&self) -> &'static str {
        self.descriptor.id()
    }

    /// How upstream ships this plugin.
    #[must_use]
    pub const fn delivery_class(&self) -> DeliveryClass {
        self.descriptor.delivery_class()
    }

    /// Where the artifact would come from, and what GTA-Claw does about it.
    #[must_use]
    pub const fn install(&self) -> InstallDecision {
        self.install
    }

    /// What this repository offers in place of the upstream plugin.
    #[must_use]
    pub const fn compatibility(&self) -> CompatibilityDecision {
        self.compatibility
    }

    /// Whether this contract is an explicit stub rather than an implementation.
    #[must_use]
    pub const fn is_stub(&self) -> bool {
        self.compatibility.is_stub()
    }
}

/// Every contract's decisions, ordered by plugin id.
#[must_use]
pub fn all() -> impl ExactSizeIterator<Item = PluginCompatibility> {
    PluginRegistry::all().map(PluginCompatibility::for_descriptor)
}

/// The decisions for one upstream plugin id.
///
/// Answers `None` for any id the frozen inventory does not contain, so a
/// caller asking "does this contract have a decision?" can be told no.
#[must_use]
pub fn decide(id: &str) -> Option<PluginCompatibility> {
    PluginRegistry::get(id).map(PluginCompatibility::for_descriptor)
}

/// Every contract upstream ships the given way.
pub fn by_delivery_class(class: DeliveryClass) -> impl Iterator<Item = PluginCompatibility> {
    all().filter(move |decision| decision.delivery_class() == class)
}

/// Every contract held open by an explicit stub.
pub fn stubs() -> impl Iterator<Item = PluginCompatibility> {
    all().filter(PluginCompatibility::is_stub)
}

/// Every contract with a real component behind it.
pub fn component_backed() -> impl Iterator<Item = PluginCompatibility> {
    all().filter(|decision| !decision.is_stub())
}

/// Every contract whose stub is of the given kind.
pub fn stubs_of_kind(kind: StubKind) -> impl Iterator<Item = PluginCompatibility> {
    all().filter(move |decision| decision.compatibility().stub_kind() == Some(kind))
}

/// How many contracts are held open by an explicit stub.
#[must_use]
pub fn stub_count() -> usize {
    stubs().count()
}

/// The ids that carry a [`StubKind::TestToolingFixture`] stub, sorted.
///
/// The plugin host's QA test tooling is asserted to represent exactly these.
#[must_use]
pub fn test_tooling_fixture_ids() -> Vec<&'static str> {
    let mut ids: Vec<&'static str> = stubs_of_kind(StubKind::TestToolingFixture)
        .map(|decision| decision.id())
        .collect();
    ids.sort_unstable();
    ids
}

#[cfg(test)]
mod tests {
    use super::{
        CompatibilityDecision, InstallDecision, PluginCompatibility, StubKind, all,
        by_delivery_class, component_backed, decide, stub_count, stubs, stubs_of_kind,
        test_tooling_fixture_ids,
    };
    use crate::registry::{
        COMPONENT_BACKED_PLUGIN_IDS, CORE_PLUGINS, DeliveryClass, OFFICIAL_EXTERNAL_PLUGINS,
        PluginRegistry, SOURCE_ONLY_QA_PLUGINS, TOTAL_PLUGINS,
    };

    #[test]
    fn every_registry_descriptor_has_exactly_one_decision() {
        assert_eq!(all().len(), TOTAL_PLUGINS);
        let ids: Vec<&str> = all().map(|decision| decision.id()).collect();
        let mut unique = ids.clone();
        unique.sort_unstable();
        unique.dedup();
        assert_eq!(ids.len(), unique.len(), "an id was decided twice");
        assert_eq!(unique.len(), PluginRegistry::len());
    }

    #[test]
    fn an_id_outside_the_frozen_inventory_has_no_decision() {
        assert_eq!(decide("not-a-real-plugin"), None);
        assert_eq!(decide(""), None);
        assert_eq!(decide("gta-claw-fixture-probe"), None);
        assert!(decide("qa-lab").is_some());
    }

    #[test]
    fn the_install_decision_follows_how_upstream_ships_the_plugin() {
        for decision in all() {
            assert_eq!(
                decision.install(),
                InstallDecision::for_delivery_class(decision.delivery_class()),
                "install decision for `{}`",
                decision.id()
            );
            assert!(
                !decision.install().acquires_artifact(),
                "`{}` would acquire an artifact",
                decision.id()
            );
        }
        assert_eq!(
            decide("admin-http-rpc").expect("core").install(),
            InstallDecision::BundledUpstreamNotPorted
        );
        assert_eq!(
            decide("cerebras").expect("external").install(),
            InstallDecision::DeclinedNpmOnDemand
        );
        assert_eq!(
            decide("qa-lab").expect("qa").install(),
            InstallDecision::NeverPublishedSourceOnly
        );
    }

    #[test]
    fn no_contract_claims_a_component_this_repository_does_not_ship() {
        let backed: Vec<&str> = component_backed().map(|decision| decision.id()).collect();
        assert_eq!(backed, COMPONENT_BACKED_PLUGIN_IDS.to_vec());
        assert_eq!(stub_count(), TOTAL_PLUGINS - backed.len());
        assert_eq!(stubs().count() + backed.len(), TOTAL_PLUGINS);
    }

    #[test]
    fn only_the_qa_contracts_carry_a_test_tooling_stub() {
        assert_eq!(
            stubs_of_kind(StubKind::TestToolingFixture).count(),
            SOURCE_ONLY_QA_PLUGINS
        );
        for decision in stubs_of_kind(StubKind::TestToolingFixture) {
            assert_eq!(decision.delivery_class(), DeliveryClass::SourceOnlyQa);
        }
        assert_eq!(
            stubs_of_kind(StubKind::RegistrationOnly).count(),
            CORE_PLUGINS + OFFICIAL_EXTERNAL_PLUGINS
        );
        assert_eq!(
            test_tooling_fixture_ids(),
            vec!["qa-channel", "qa-lab", "qa-matrix"]
        );
    }

    #[test]
    fn the_class_split_of_the_decisions_matches_the_registry() {
        assert_eq!(by_delivery_class(DeliveryClass::Core).count(), CORE_PLUGINS);
        assert_eq!(
            by_delivery_class(DeliveryClass::OfficialExternal).count(),
            OFFICIAL_EXTERNAL_PLUGINS
        );
        assert_eq!(
            by_delivery_class(DeliveryClass::SourceOnlyQa).count(),
            SOURCE_ONLY_QA_PLUGINS
        );
    }

    #[test]
    fn a_decision_is_a_pure_function_of_its_descriptor() {
        let descriptor = PluginRegistry::get("acpx").expect("acpx is an inventory plugin");
        assert_eq!(
            PluginCompatibility::for_descriptor(descriptor),
            decide("acpx").expect("acpx has a decision")
        );
        assert_eq!(descriptor, decide("acpx").expect("decision").descriptor());
    }

    #[test]
    fn the_wire_names_are_distinct_and_stable() {
        assert_eq!(
            InstallDecision::ALL.map(InstallDecision::as_str),
            [
                "bundled_upstream_not_ported",
                "declined_npm_on_demand",
                "never_published_source_only"
            ]
        );
        assert_eq!(
            StubKind::ALL.map(StubKind::as_str),
            ["registration_only", "test_tooling_fixture"]
        );
        assert_eq!(
            CompatibilityDecision::ComponentShipped.as_str(),
            "component_shipped"
        );
        assert_eq!(
            CompatibilityDecision::Stub(StubKind::RegistrationOnly).as_str(),
            "stub_registration_only"
        );
        assert_eq!(
            CompatibilityDecision::Stub(StubKind::TestToolingFixture).as_str(),
            "stub_test_tooling_fixture"
        );
        assert!(!CompatibilityDecision::ComponentShipped.is_stub());
        assert!(CompatibilityDecision::Stub(StubKind::RegistrationOnly).is_stub());
        for decision in InstallDecision::ALL {
            assert!(!decision.rationale().is_empty());
            assert_eq!(decision.to_string(), decision.as_str());
        }
        for kind in StubKind::ALL {
            assert_eq!(kind.to_string(), kind.as_str());
        }
    }
}

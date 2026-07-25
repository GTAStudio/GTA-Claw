//! The host must report the registry honestly.
//!
//! The registry mirrors the frozen upstream inventory, which is a catalogue of
//! *upstream* plugins. None of them ship a WebAssembly component in this
//! repository, and the host must say so rather than imply otherwise.

mod support;

use std::collections::BTreeSet;

use claw_plugin_api::registry::{
    COMPONENT_BACKED_PLUGIN_IDS, CORE_PLUGINS, DeliveryClass, ImplementationStatus,
    OFFICIAL_EXTERNAL_PLUGINS, PluginRegistry, SOURCE_ONLY_QA_PLUGINS, TOTAL_PLUGINS,
};
use claw_plugin_host::inventory::describe_registry;
use support::PROBE_ID;

#[test]
fn the_report_agrees_with_the_registry_row_by_row() {
    let report = describe_registry();
    assert_eq!(report.total, TOTAL_PLUGINS);
    assert_eq!(report.core, CORE_PLUGINS);
    assert_eq!(report.official_external, OFFICIAL_EXTERNAL_PLUGINS);
    assert_eq!(report.source_only_qa, SOURCE_ONLY_QA_PLUGINS);
    assert_eq!(report.registration_only, TOTAL_PLUGINS);
    assert_eq!(report.component_backed, Vec::<&str>::new());
    assert!(!report.has_any_component());

    // Independently recount from the registry rather than trusting the report.
    let mut core = 0;
    let mut external = 0;
    let mut qa = 0;
    for descriptor in PluginRegistry::all() {
        match descriptor.delivery_class() {
            DeliveryClass::Core => core += 1,
            DeliveryClass::OfficialExternal => external += 1,
            DeliveryClass::SourceOnlyQa => qa += 1,
        }
        assert_eq!(
            descriptor.implementation(),
            ImplementationStatus::RegistrationOnly,
            "`{}` claims a component this repository does not contain",
            descriptor.id()
        );
    }
    assert_eq!([core, external, qa], [64, 70, 3]);
    assert_eq!(COMPONENT_BACKED_PLUGIN_IDS, &[] as &[&str]);
}

#[test]
fn the_test_fixture_is_not_smuggled_into_the_inventory() {
    assert!(
        PluginRegistry::get(PROBE_ID).is_none(),
        "the integration-test fixture must never appear as an upstream plugin"
    );
    let ids: BTreeSet<&str> = PluginRegistry::all().map(|d| d.id()).collect();
    assert!(!ids.contains(PROBE_ID));
    assert!(!ids.contains("gta-claw-fixture-other"));
    assert!(!ids.contains("gta-claw-fixture-plain"));
    assert!(!ids.contains("gta-claw-fixture-postr"));
}

#[test]
fn the_three_source_only_qa_plugins_are_the_frozen_ones() {
    let qa: BTreeSet<&str> = PluginRegistry::by_delivery_class(DeliveryClass::SourceOnlyQa)
        .map(|descriptor| descriptor.id())
        .collect();
    assert_eq!(qa, BTreeSet::from(["qa-channel", "qa-lab", "qa-matrix"]));
}

//! The registry must mirror the frozen upstream inventory exactly.
//!
//! The expected values are re-derived here straight from
//! `compat/upstream/inventories/plugins.json` using a local, private struct.
//! Nothing in this file calls the generator or the registry to build its own
//! expectation, so a drifted, missing or invented descriptor fails the test.

use std::collections::{BTreeMap, BTreeSet};

use claw_plugin_api::registry::{
    CORE_PLUGINS, DeliveryClass, ImplementationStatus, OFFICIAL_EXTERNAL_PLUGINS, PluginRegistry,
    SOURCE_ONLY_QA_PLUGINS, TOTAL_PLUGINS,
};
use serde::Deserialize;

/// The frozen artifact, embedded at compile time so the test never depends on
/// the working directory.
const FROZEN_INVENTORY: &str = include_str!("../../../compat/upstream/inventories/plugins.json");

#[derive(Debug, Deserialize)]
struct FrozenInventory {
    schema_version: u32,
    inventory_id: String,
    classification: String,
    baseline_sha: String,
    counts: FrozenCounts,
    items: Vec<FrozenItem>,
}

#[derive(Debug, Deserialize)]
struct FrozenCounts {
    total: usize,
    core: usize,
    official_external: usize,
    source_only_qa: usize,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq)]
struct FrozenItem {
    record_id: String,
    id: String,
    classification: String,
    source_path: String,
    package_name: String,
    delivery_class: String,
}

fn frozen() -> FrozenInventory {
    // The frozen artifacts are written with a UTF-8 BOM, which `include_str!`
    // preserves and `serde_json` rejects.
    let text = FROZEN_INVENTORY.trim_start_matches('\u{feff}');
    serde_json::from_str(text).expect("the frozen inventory must parse")
}

#[test]
fn the_frozen_inventory_still_declares_the_contract_this_registry_was_built_for() {
    let inventory = frozen();
    assert_eq!(inventory.schema_version, 1);
    assert_eq!(inventory.inventory_id, "plugins");
    assert_eq!(inventory.classification, "official_integration");
    assert_eq!(
        inventory.baseline_sha,
        "b43e832fcc8000ed7287c7accc54e381db607f85"
    );
    assert_eq!(inventory.baseline_sha, claw_plugin_api::BASELINE_SHA);
    assert_eq!(inventory.counts.total, TOTAL_PLUGINS);
    assert_eq!(inventory.counts.core, CORE_PLUGINS);
    assert_eq!(
        inventory.counts.official_external,
        OFFICIAL_EXTERNAL_PLUGINS
    );
    assert_eq!(inventory.counts.source_only_qa, SOURCE_ONLY_QA_PLUGINS);
    assert_eq!(inventory.items.len(), TOTAL_PLUGINS);
}

#[test]
fn the_registry_contains_every_inventory_id_and_nothing_else() {
    let expected: BTreeSet<String> = frozen().items.into_iter().map(|item| item.id).collect();
    let actual: BTreeSet<String> = PluginRegistry::all()
        .map(|descriptor| descriptor.id().to_owned())
        .collect();

    let missing: Vec<&String> = expected.difference(&actual).collect();
    let extra: Vec<&String> = actual.difference(&expected).collect();
    assert!(missing.is_empty(), "registry is missing {missing:?}");
    assert!(extra.is_empty(), "registry invented {extra:?}");
    assert_eq!(actual.len(), TOTAL_PLUGINS);
}

#[test]
fn every_registry_field_matches_the_frozen_row_for_the_same_id() {
    let expected: BTreeMap<String, FrozenItem> = frozen()
        .items
        .into_iter()
        .map(|item| (item.id.clone(), item))
        .collect();
    assert_eq!(
        expected.len(),
        TOTAL_PLUGINS,
        "inventory ids must be unique"
    );

    for descriptor in PluginRegistry::all() {
        let row = expected
            .get(descriptor.id())
            .unwrap_or_else(|| panic!("`{}` is not in the frozen inventory", descriptor.id()));
        let record = descriptor.record();
        assert_eq!(
            record.record_id(),
            row.record_id,
            "record_id for {}",
            row.id
        );
        assert_eq!(record.id(), row.id, "id for {}", row.id);
        assert_eq!(
            record.source_path(),
            row.source_path,
            "source_path for {}",
            row.id
        );
        assert_eq!(
            record.package_name(),
            row.package_name,
            "package_name for {}",
            row.id
        );
        assert_eq!(
            record.delivery_class().as_str(),
            row.delivery_class,
            "delivery_class for {}",
            row.id
        );
        assert_eq!(
            row.classification, "official_integration",
            "classification for {}",
            row.id
        );
    }
}

#[test]
fn the_delivery_class_split_matches_the_frozen_rows_one_by_one() {
    let mut expected: BTreeMap<&str, BTreeSet<String>> = BTreeMap::new();
    for item in frozen().items {
        expected
            .entry(match item.delivery_class.as_str() {
                "core" => "core",
                "official_external" => "official_external",
                "source_only_qa" => "source_only_qa",
                other => panic!("unexpected delivery class `{other}`"),
            })
            .or_default()
            .insert(item.id);
    }

    for (class, wire) in [
        (DeliveryClass::Core, "core"),
        (DeliveryClass::OfficialExternal, "official_external"),
        (DeliveryClass::SourceOnlyQa, "source_only_qa"),
    ] {
        let actual: BTreeSet<String> = PluginRegistry::by_delivery_class(class)
            .map(|descriptor| descriptor.id().to_owned())
            .collect();
        assert_eq!(
            &actual,
            expected
                .get(wire)
                .unwrap_or_else(|| panic!("no rows for {wire}")),
            "delivery class `{wire}` membership drifted"
        );
    }

    assert_eq!(
        expected.get("source_only_qa").expect("qa rows"),
        &BTreeSet::from([
            "qa-channel".to_owned(),
            "qa-lab".to_owned(),
            "qa-matrix".to_owned(),
        ])
    );
}

#[test]
fn the_record_id_is_always_the_plugin_id_prefixed_with_plugin() {
    for item in frozen().items {
        assert_eq!(item.record_id, format!("plugin:{}", item.id));
    }
}

#[test]
fn no_plugin_is_reported_as_component_backed_without_a_component() {
    // This workspace ships the plugin host and the ABI, not ports of the 137
    // upstream plugins. Every descriptor must therefore be registration-only.
    let statuses: BTreeSet<ImplementationStatus> = PluginRegistry::all()
        .map(|descriptor| descriptor.implementation())
        .collect();
    assert_eq!(
        statuses,
        BTreeSet::from([ImplementationStatus::RegistrationOnly]),
        "a descriptor claims a component that does not exist in this repository"
    );
    assert_eq!(
        PluginRegistry::all()
            .filter(|d| d.implementation() == ImplementationStatus::ComponentAvailable)
            .count(),
        0
    );
}

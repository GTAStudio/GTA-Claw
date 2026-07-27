//! Every frozen plugin contract has an install and a compatibility decision.
//!
//! The three ledger rows this file backs all say **exactly**, so a test that
//! only resists omission is not enough: it must also resist surplus. Every
//! test below therefore compares the decisions GTA-Claw produces against the
//! frozen artifact as a *set*, reporting both what is missing and what was
//! invented, and never as a count alone.
//!
//! The expectations are re-derived here straight from
//! `compat/upstream/inventories/plugins.json`. Nothing in this file lists a
//! plugin by hand and nothing asks the registry what it thinks the answer is,
//! so a hand-copied list cannot agree with itself into a green run.

use std::collections::{BTreeMap, BTreeSet};

use claw_plugin_api::compat::{
    CompatibilityDecision, InstallDecision, StubKind, all, by_delivery_class, component_backed,
    decide, stub_count,
};
use claw_plugin_api::registry::{
    COMPONENT_BACKED_PLUGIN_IDS, CORE_PLUGINS, DeliveryClass, OFFICIAL_EXTERNAL_PLUGINS,
    PluginRegistry, SOURCE_ONLY_QA_PLUGINS, TOTAL_PLUGINS,
};
use claw_plugin_host::describe_compatibility;
use serde::Deserialize;

/// The frozen artifact, embedded at compile time so the test never depends on
/// the working directory.
const FROZEN_INVENTORY: &str = include_str!("../../../compat/upstream/inventories/plugins.json");

#[derive(Debug, Deserialize)]
struct FrozenInventory {
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
    // The frozen artifacts carry a UTF-8 BOM, which `include_str!` preserves
    // and `serde_json` rejects.
    let text = FROZEN_INVENTORY.trim_start_matches('\u{feff}');
    serde_json::from_str(text).expect("the frozen inventory must parse")
}

/// The frozen rows upstream ships the given way, keyed by plugin id.
fn frozen_rows(wire_class: &str) -> BTreeMap<String, FrozenItem> {
    let rows: BTreeMap<String, FrozenItem> = frozen()
        .items
        .into_iter()
        .filter(|item| item.delivery_class == wire_class)
        .map(|item| (item.id.clone(), item))
        .collect();
    assert!(
        !rows.is_empty(),
        "the frozen inventory has no `{wire_class}` rows, so this test would prove nothing"
    );
    rows
}

/// The ids GTA-Claw itself decides belong to a delivery class.
fn decided_ids(class: DeliveryClass) -> BTreeSet<String> {
    by_delivery_class(class)
        .map(|decision| decision.id().to_owned())
        .collect()
}

/// Fails naming what is missing and what was invented, never just a count.
fn assert_same_ids(expected: &BTreeSet<String>, actual: &BTreeSet<String>, what: &str) {
    let missing: Vec<&String> = expected.difference(actual).collect();
    let invented: Vec<&String> = actual.difference(expected).collect();
    assert!(missing.is_empty(), "{what} is missing {missing:?}");
    assert!(invented.is_empty(), "{what} invented {invented:?}");
    assert_eq!(expected.len(), actual.len());
}

#[test]
fn every_core_plugin_contract_has_a_registration_or_an_explicit_stub() {
    let rows = frozen_rows("core");
    assert_eq!(rows.len(), CORE_PLUGINS);
    assert_eq!(rows.len(), frozen().counts.core);

    let mut registered = 0_usize;
    let mut stubbed = 0_usize;
    for (id, row) in &rows {
        let decision = decide(id).unwrap_or_else(|| {
            panic!("core contract `{id}` has no install or compatibility decision")
        });
        assert_eq!(
            decision.delivery_class(),
            DeliveryClass::Core,
            "class of {id}"
        );
        assert_eq!(
            decision.install(),
            InstallDecision::BundledUpstreamNotPorted
        );

        // Registration and provenance must be the frozen row's own, not a
        // plausible-looking reconstruction of it.
        let record = decision.descriptor().record();
        assert_eq!(record.record_id(), row.record_id, "record_id of {id}");
        assert_eq!(record.source_path(), row.source_path, "source_path of {id}");
        assert_eq!(
            record.package_name(),
            row.package_name,
            "package_name of {id}"
        );
        assert_eq!(row.classification, "official_integration");

        match decision.compatibility() {
            CompatibilityDecision::ComponentShipped => {
                assert!(
                    COMPONENT_BACKED_PLUGIN_IDS.contains(&decision.id()),
                    "`{id}` claims a component that is not in COMPONENT_BACKED_PLUGIN_IDS"
                );
                registered += 1;
            }
            CompatibilityDecision::Stub(kind) => {
                assert_eq!(kind, StubKind::RegistrationOnly, "stub kind of {id}");
                assert!(
                    !COMPONENT_BACKED_PLUGIN_IDS.contains(&decision.id()),
                    "`{id}` is stubbed and component-backed at once"
                );
                stubbed += 1;
            }
        }
    }

    // Resist surplus: a 65th core descriptor, or one whose class drifted, is a
    // failure even though every frozen row above was satisfied.
    let expected: BTreeSet<String> = rows.keys().cloned().collect();
    assert_same_ids(
        &expected,
        &decided_ids(DeliveryClass::Core),
        "the core class",
    );

    assert_eq!(
        registered + stubbed,
        CORE_PLUGINS,
        "every core contract must be decided exactly once"
    );
    // Honest today: nothing is implemented, everything is an explicit stub.
    assert_eq!(registered, 0);
    assert_eq!(stubbed, CORE_PLUGINS);
}

#[test]
fn every_official_external_plugin_contract_has_an_install_and_a_compatibility_decision() {
    let rows = frozen_rows("official_external");
    assert_eq!(rows.len(), OFFICIAL_EXTERNAL_PLUGINS);
    assert_eq!(rows.len(), frozen().counts.official_external);

    let mut shipped = 0_usize;
    let mut stubbed = 0_usize;
    for (id, row) in &rows {
        let decision =
            decide(id).unwrap_or_else(|| panic!("external contract `{id}` has no decision"));
        assert_eq!(decision.delivery_class(), DeliveryClass::OfficialExternal);

        // The install decision is only honest if the thing being declined is
        // the npm package the frozen row actually names.
        assert_eq!(
            decision.install(),
            InstallDecision::DeclinedNpmOnDemand,
            "install decision of {id}"
        );
        assert!(
            !decision.install().acquires_artifact(),
            "`{id}` would fetch an artifact from npm"
        );
        let record = decision.descriptor().record();
        assert_eq!(
            record.package_name(),
            row.package_name,
            "package_name of {id}"
        );
        assert!(
            record.package_name().starts_with('@'),
            "`{id}` is declined as an npm install but names `{}`",
            record.package_name()
        );
        assert_eq!(record.record_id(), row.record_id, "record_id of {id}");
        assert_eq!(record.source_path(), row.source_path, "source_path of {id}");

        match decision.compatibility() {
            CompatibilityDecision::ComponentShipped => shipped += 1,
            CompatibilityDecision::Stub(kind) => {
                assert_eq!(kind, StubKind::RegistrationOnly, "stub kind of {id}");
                stubbed += 1;
            }
        }
    }

    let expected: BTreeSet<String> = rows.keys().cloned().collect();
    assert_same_ids(
        &expected,
        &decided_ids(DeliveryClass::OfficialExternal),
        "the official external class",
    );

    assert_eq!(shipped + stubbed, OFFICIAL_EXTERNAL_PLUGINS);
    assert_eq!(shipped, 0);
    assert_eq!(stubbed, OFFICIAL_EXTERNAL_PLUGINS);
}

#[test]
fn the_install_decision_is_not_the_same_answer_for_every_contract() {
    // The two tests above would both pass against a function that returned one
    // constant, so the three classes are pinned to three different answers and
    // the wire names are pinned distinct.
    let mut seen: BTreeMap<&str, BTreeSet<InstallDecision>> = BTreeMap::new();
    for item in frozen().items {
        let decision = decide(&item.id).expect("every frozen row has a decision");
        seen.entry(match item.delivery_class.as_str() {
            "core" => "core",
            "official_external" => "official_external",
            "source_only_qa" => "source_only_qa",
            other => panic!("unexpected delivery class `{other}`"),
        })
        .or_default()
        .insert(decision.install());
    }

    assert_eq!(
        seen["core"],
        BTreeSet::from([InstallDecision::BundledUpstreamNotPorted])
    );
    assert_eq!(
        seen["official_external"],
        BTreeSet::from([InstallDecision::DeclinedNpmOnDemand])
    );
    assert_eq!(
        seen["source_only_qa"],
        BTreeSet::from([InstallDecision::NeverPublishedSourceOnly])
    );

    let names: BTreeSet<&str> = InstallDecision::ALL
        .iter()
        .map(|decision| decision.as_str())
        .collect();
    assert_eq!(names.len(), InstallDecision::ALL.len());
}

#[test]
fn a_contract_the_frozen_inventory_does_not_contain_has_no_decision() {
    // Without this, "every frozen row has a decision" could be satisfied by a
    // function that answers for any string at all.
    let frozen_ids: BTreeSet<String> = frozen().items.into_iter().map(|item| item.id).collect();
    for candidate in [
        "not-a-real-plugin",
        "",
        "gta-claw-fixture-probe",
        "openclaw",
        "CORE",
    ] {
        assert!(
            !frozen_ids.contains(candidate),
            "`{candidate}` is a real inventory id, so it proves nothing here"
        );
        assert_eq!(
            decide(candidate),
            None,
            "`{candidate}` was given a decision it has no contract for"
        );
        assert!(PluginRegistry::get(candidate).is_none());
    }
}

#[test]
fn the_decisions_cover_the_frozen_inventory_exactly_once() {
    let inventory = frozen();
    assert_eq!(inventory.counts.total, TOTAL_PLUGINS);
    assert_eq!(inventory.items.len(), TOTAL_PLUGINS);
    assert_eq!(
        inventory.counts.core
            + inventory.counts.official_external
            + inventory.counts.source_only_qa,
        inventory.counts.total
    );

    let expected: BTreeSet<String> = inventory.items.iter().map(|item| item.id.clone()).collect();
    assert_eq!(expected.len(), TOTAL_PLUGINS, "frozen ids must be unique");

    let actual: BTreeSet<String> = all().map(|decision| decision.id().to_owned()).collect();
    assert_same_ids(&expected, &actual, "the decision set");
    assert_eq!(all().len(), TOTAL_PLUGINS);

    assert_eq!(
        decided_ids(DeliveryClass::Core).len()
            + decided_ids(DeliveryClass::OfficialExternal).len()
            + decided_ids(DeliveryClass::SourceOnlyQa).len(),
        TOTAL_PLUGINS,
        "a contract was decided into two classes or none"
    );
}

#[test]
fn no_frozen_contract_resolves_to_a_decision_that_fetches_anything() {
    // GTA-Claw is npm-free. This is that promise expressed over all 137 rows
    // rather than asserted once in prose.
    for item in frozen().items {
        let decision = decide(&item.id).expect("every frozen row has a decision");
        assert!(
            !decision.install().acquires_artifact(),
            "`{}` would acquire an artifact",
            item.id
        );
    }
    assert!(describe_compatibility().acquires_no_artifact());
}

#[test]
fn the_host_compatibility_report_agrees_with_the_frozen_rows_class_by_class() {
    let inventory = frozen();
    let report = describe_compatibility();
    assert_eq!(report.total, inventory.counts.total);

    for (class, expected, install) in [
        (
            DeliveryClass::Core,
            inventory.counts.core,
            InstallDecision::BundledUpstreamNotPorted,
        ),
        (
            DeliveryClass::OfficialExternal,
            inventory.counts.official_external,
            InstallDecision::DeclinedNpmOnDemand,
        ),
        (
            DeliveryClass::SourceOnlyQa,
            inventory.counts.source_only_qa,
            InstallDecision::NeverPublishedSourceOnly,
        ),
    ] {
        let summary = report.for_class(class);
        assert_eq!(summary.total, expected, "report total for {class}");
        assert_eq!(
            summary.component_shipped + summary.stubs,
            expected,
            "report split for {class}"
        );
        assert_eq!(
            summary.install, install,
            "report install decision for {class}"
        );
        assert_eq!(summary.stub_decision.is_some(), summary.stubs > 0);
    }

    // The report must not be able to claim more implementation than exists.
    let backed: Vec<&str> = component_backed().map(|decision| decision.id()).collect();
    assert_eq!(report.component_shipped, backed);
    assert_eq!(report.stubs, stub_count());
    assert_eq!(report.component_shipped.len() + report.stubs, TOTAL_PLUGINS);
    assert_eq!(
        report.stubs,
        CORE_PLUGINS + OFFICIAL_EXTERNAL_PLUGINS + SOURCE_ONLY_QA_PLUGINS
    );
}

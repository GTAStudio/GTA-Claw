//! The three source-only QA contracts are represented in test tooling.
//!
//! Upstream never publishes `qa-channel`, `qa-lab` or `qa-matrix`; they exist
//! in its source tree for QA. There is nothing to install and nothing to port,
//! so the only honest representation is a fixture the host really processes.
//! `tests/support/qa.rs` builds one per contract, driven from the frozen
//! registry rather than from a hand-written list.
//!
//! Expectations here come straight from
//! `compat/upstream/inventories/plugins.json`, and every set comparison names
//! both what is missing and what was invented, because the ledger row says
//! *exactly* three.

mod support;

use std::collections::{BTreeMap, BTreeSet};

use claw_plugin_api::compat::{
    CompatibilityDecision, InstallDecision, StubKind, test_tooling_fixture_ids,
};
use claw_plugin_api::registry::{DeliveryClass, PluginRegistry, SOURCE_ONLY_QA_PLUGINS};
use claw_plugin_api::trust::TrustError;
use claw_plugin_host::{HostError, PluginHost};
use serde::Deserialize;
use support::qa::{qa_fixtures, represented_ids, unsigned_qa_policy};
use support::{PROBE_ID, unsigned_core_policy};

const FROZEN_INVENTORY: &str = include_str!("../../../compat/upstream/inventories/plugins.json");

#[derive(Debug, Deserialize)]
struct FrozenInventory {
    counts: FrozenCounts,
    items: Vec<FrozenItem>,
}

#[derive(Debug, Deserialize)]
struct FrozenCounts {
    source_only_qa: usize,
}

#[derive(Clone, Debug, Deserialize)]
struct FrozenItem {
    record_id: String,
    id: String,
    classification: String,
    source_path: String,
    package_name: String,
    delivery_class: String,
}

fn frozen() -> FrozenInventory {
    let text = FROZEN_INVENTORY.trim_start_matches('\u{feff}');
    serde_json::from_str(text).expect("the frozen inventory must parse")
}

/// The frozen source-only QA rows, keyed by plugin id.
fn frozen_qa_rows() -> BTreeMap<String, FrozenItem> {
    let inventory = frozen();
    let rows: BTreeMap<String, FrozenItem> = inventory
        .items
        .into_iter()
        .filter(|item| item.delivery_class == "source_only_qa")
        .map(|item| (item.id.clone(), item))
        .collect();
    assert_eq!(
        rows.len(),
        inventory.counts.source_only_qa,
        "the frozen rows must agree with the frozen count"
    );
    assert_eq!(rows.len(), SOURCE_ONLY_QA_PLUGINS);
    rows
}

fn host(policy: claw_plugin_api::trust::TrustPolicy) -> PluginHost {
    PluginHost::builder()
        .trust_policy(policy)
        .build()
        .expect("host")
}

#[test]
fn exactly_the_three_source_only_qa_contracts_are_represented_in_the_test_tooling() {
    let rows = frozen_qa_rows();
    let fixtures = qa_fixtures();

    let expected: BTreeSet<String> = rows.keys().cloned().collect();
    let actual: BTreeSet<String> = fixtures
        .iter()
        .map(|fixture| fixture.id().to_owned())
        .collect();
    let missing: Vec<&String> = expected.difference(&actual).collect();
    let invented: Vec<&String> = actual.difference(&expected).collect();
    assert!(missing.is_empty(), "the QA tooling is missing {missing:?}");
    assert!(invented.is_empty(), "the QA tooling invented {invented:?}");
    assert_eq!(fixtures.len(), SOURCE_ONLY_QA_PLUGINS);
    assert_eq!(
        actual.len(),
        fixtures.len(),
        "a contract was represented twice"
    );

    for fixture in &fixtures {
        let row = &rows[fixture.id()];
        assert_eq!(row.classification, "official_integration");
        assert_eq!(fixture.package_name(), row.package_name);
        assert_eq!(fixture.source_path(), row.source_path);
        assert_eq!(
            fixture.decision().descriptor().record().record_id(),
            row.record_id
        );

        // The fixture must carry the contract's real identity, or the host is
        // not processing the frozen row at all.
        let manifest = fixture.manifest();
        assert_eq!(manifest.id, row.id);
        assert_eq!(manifest.delivery_class, DeliveryClass::SourceOnlyQa);
        manifest
            .validate()
            .expect("a QA fixture manifest must be valid");
        assert!(!fixture.component().is_empty());

        assert_eq!(
            fixture.decision().install(),
            InstallDecision::NeverPublishedSourceOnly
        );
        assert_eq!(
            fixture.decision().compatibility(),
            CompatibilityDecision::Stub(StubKind::TestToolingFixture)
        );
        assert_eq!(
            PluginRegistry::get(fixture.id())
                .expect("a QA fixture must be a frozen plugin")
                .delivery_class(),
            DeliveryClass::SourceOnlyQa
        );
    }

    // `claw-plugin-api` marks exactly these contracts as backed by test
    // tooling. This is the assertion that keeps that cross-crate claim true.
    assert_eq!(test_tooling_fixture_ids(), represented_ids());
    assert!(
        !actual.contains(PROBE_ID),
        "the shared probe fixture is not an upstream QA contract"
    );
}

#[test]
fn a_source_only_qa_contract_is_refused_by_a_host_that_only_allows_core_plugins() {
    let fixtures = qa_fixtures();
    assert_eq!(fixtures.len(), SOURCE_ONLY_QA_PLUGINS);

    for fixture in &fixtures {
        let root = support::tempdir();
        let directory = fixture.install(root.path());
        let mut host = host(unsigned_core_policy(root.path()));

        let error = host
            .load(&directory)
            .expect_err("a never-published plugin must not load");
        match error {
            HostError::Trust(TrustError::DeliveryClassNotAllowed { class }) => {
                assert_eq!(
                    class,
                    DeliveryClass::SourceOnlyQa,
                    "the host must name the class it refused for `{}`",
                    fixture.id()
                );
            }
            other => panic!(
                "expected a delivery-class refusal for `{}`, got {other}",
                fixture.id()
            ),
        }
        assert!(
            host.loaded_ids().is_empty(),
            "a refused QA plugin must not be registered"
        );
    }
}

#[test]
fn the_qa_refusal_is_caused_by_the_delivery_class_and_nothing_else() {
    // The counterweight to the test above. The same bytes and the same
    // manifest, with only the allowed delivery class changed, must get past the
    // trust policy — so the refusal there cannot have been caused by the
    // fixture being malformed, unsigned, outside the root or oversized.
    for fixture in &qa_fixtures() {
        let root = support::tempdir();
        let directory = fixture.install(root.path());
        let mut host = host(unsigned_qa_policy(root.path()));

        let error = host
            .load(&directory)
            .expect_err("no QA component exists in this repository");
        match error {
            HostError::IdentityMismatch {
                field,
                manifest,
                component,
            } => {
                assert_eq!(field, "id");
                assert_eq!(manifest, fixture.id());
                assert_eq!(
                    component, PROBE_ID,
                    "the fixture must not pretend to be a real QA component"
                );
            }
            HostError::Trust(other) => panic!(
                "`{}` was still refused by the trust policy: {other}",
                fixture.id()
            ),
            other => panic!("unexpected failure for `{}`: {other}", fixture.id()),
        }
    }
}

#[test]
fn the_tooling_installs_each_contract_into_its_own_directory() {
    // Three contracts sharing a directory would silently test one of them
    // three times.
    let root = support::tempdir();
    let mut directories = BTreeSet::new();
    let fixtures = qa_fixtures();
    for fixture in &fixtures {
        assert!(
            directories.insert(fixture.directory_name()),
            "`{}` reuses another contract's directory",
            fixture.id()
        );
        let installed = fixture.install(root.path());
        assert!(installed.join("plugin.json").is_file());
        assert!(installed.join("component.wasm").is_file());
    }
    assert_eq!(directories.len(), SOURCE_ONLY_QA_PLUGINS);

    // Every installed manifest is discoverable and parses back to its contract.
    let discovered: BTreeSet<String> = host(unsigned_qa_policy(root.path()))
        .discover()
        .into_iter()
        .map(|found| {
            found.directory.file_name().map_or_else(
                || panic!("a discovered plugin must live in a named directory"),
                |name| name.to_string_lossy().into_owned(),
            )
        })
        .collect();
    assert_eq!(discovered, directories);
}

#[test]
fn a_qa_contract_may_not_be_loaded_by_claiming_a_different_delivery_class() {
    // The trust policy cross-checks the frozen registry, so relabelling a QA
    // contract as core must not launder it past a core-only host.
    for fixture in &qa_fixtures() {
        let root = support::tempdir();
        let mut manifest = fixture.manifest().clone();
        manifest.delivery_class = DeliveryClass::Core;
        let directory = support::install(
            root.path(),
            &fixture.directory_name(),
            fixture.component(),
            &manifest,
        );
        let mut host = host(unsigned_core_policy(root.path()));

        match host
            .load(&directory)
            .expect_err("relabelling must not work")
        {
            HostError::Trust(TrustError::RegistryClassMismatch {
                plugin_id,
                registry,
                declared,
            }) => {
                assert_eq!(plugin_id, fixture.id());
                assert_eq!(declared, DeliveryClass::Core);
                assert_eq!(registry, DeliveryClass::SourceOnlyQa);
            }
            other => panic!(
                "expected a registry cross-check for `{}`, got {other}",
                fixture.id()
            ),
        }
    }
}

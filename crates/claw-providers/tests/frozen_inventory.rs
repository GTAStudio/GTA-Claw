//! Cross-checks the Rust provider registry against the frozen upstream inventory.
//!
//! The registry in `claw-providers` is hand-written; this test reads
//! `compat/upstream/inventories/providers.json` independently and compares the
//! two in both directions, field by field. Nothing here is derived from the
//! production table, so a drifted identifier, a wrong plugin id or a wrong
//! manifest path fails the build.

use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::PathBuf;

use claw_providers::{ImplementationStatus, PROVIDERS, ProviderRegistry};
use serde_json::Value;

fn repository_file(relative: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join("..")
        .join(relative)
}

fn frozen_inventory() -> Value {
    let bytes = fs::read(repository_file(
        "compat/upstream/inventories/providers.json",
    ))
    .expect("read");
    let bytes = bytes.strip_prefix(&[0xef, 0xbb, 0xbf]).unwrap_or(&bytes);
    serde_json::from_slice(bytes).expect("parse frozen inventory")
}

fn frozen_items() -> Vec<BTreeMap<String, String>> {
    let inventory = frozen_inventory();
    inventory["items"]
        .as_array()
        .expect("inventory items")
        .iter()
        .map(|item| {
            item.as_object()
                .expect("item object")
                .iter()
                .map(|(key, value)| {
                    (
                        key.clone(),
                        value.as_str().expect("string field").to_owned(),
                    )
                })
                .collect()
        })
        .collect()
}

#[test]
fn the_registry_and_the_frozen_inventory_hold_the_same_identifiers() {
    let frozen: BTreeSet<String> = frozen_items()
        .into_iter()
        .map(|item| item["id"].clone())
        .collect();
    let registered: BTreeSet<String> = PROVIDERS
        .iter()
        .map(|descriptor| descriptor.id.to_owned())
        .collect();

    let missing: Vec<&String> = frozen.difference(&registered).collect();
    let extra: Vec<&String> = registered.difference(&frozen).collect();
    assert_eq!(missing, Vec::<&String>::new(), "unregistered providers");
    assert_eq!(
        extra,
        Vec::<&String>::new(),
        "providers not in the baseline"
    );
    assert_eq!(registered, frozen);
    assert_eq!(registered.len(), 78);
}

#[test]
fn every_registered_row_reproduces_the_frozen_fields_exactly() {
    let frozen: BTreeMap<String, BTreeMap<String, String>> = frozen_items()
        .into_iter()
        .map(|item| (item["id"].clone(), item))
        .collect();

    for descriptor in PROVIDERS {
        let item = frozen
            .get(descriptor.id)
            .unwrap_or_else(|| panic!("{} is not in the frozen inventory", descriptor.id));
        assert_eq!(item["record_id"], descriptor.record_id, "{}", descriptor.id);
        assert_eq!(item["id"], descriptor.id, "{}", descriptor.id);
        assert_eq!(item["plugin_id"], descriptor.plugin_id, "{}", descriptor.id);
        assert_eq!(
            item["source_path"], descriptor.source_path,
            "{}",
            descriptor.id
        );
        assert_eq!(
            item["classification"], "official_integration",
            "{}",
            descriptor.id
        );
        assert_eq!(
            item.len(),
            5,
            "{} has unexpected frozen fields",
            descriptor.id
        );
    }
}

#[test]
fn the_registry_preserves_frozen_inventory_order() {
    let frozen: Vec<String> = frozen_items()
        .into_iter()
        .map(|item| item["id"].clone())
        .collect();
    let registered: Vec<String> = PROVIDERS
        .iter()
        .map(|descriptor| descriptor.id.to_owned())
        .collect();
    assert_eq!(registered, frozen);
}

#[test]
fn the_frozen_counts_match_the_registry_size() {
    let inventory = frozen_inventory();
    assert_eq!(inventory["counts"]["total"], 78);
    assert_eq!(inventory["counts"]["unique"], 78);
    assert_eq!(inventory["inventory_id"], "providers");
    assert_eq!(inventory["classification"], "official_integration");
    assert_eq!(
        inventory["baseline_sha"],
        "b43e832fcc8000ed7287c7accc54e381db607f85"
    );
    assert_eq!(PROVIDERS.len(), 78);
    assert_eq!(ProviderRegistry::global().len(), 78);
}

#[test]
fn every_frozen_identifier_resolves_through_the_public_lookup() {
    let registry = ProviderRegistry::global();
    for item in frozen_items() {
        let id = &item["id"];
        let descriptor = registry
            .get(id)
            .unwrap_or_else(|| panic!("{id} does not resolve"));
        assert_eq!(descriptor.id, id);
        assert_eq!(descriptor.plugin_id, item["plugin_id"]);
        assert_eq!(
            claw_providers::lookup(id).map(|entry| entry.record_id),
            Some(descriptor.record_id)
        );
    }
}

#[test]
fn implementation_status_is_reported_for_every_frozen_provider() {
    // Nothing may be silently left unclassified: each frozen id maps to exactly
    // one of the three honest statuses, and the three sets partition the
    // inventory.
    let frozen: BTreeSet<String> = frozen_items()
        .into_iter()
        .map(|item| item["id"].clone())
        .collect();
    let registry = ProviderRegistry::global();

    let implemented: BTreeSet<String> = registry
        .with_status(ImplementationStatus::Implemented)
        .iter()
        .map(|entry| entry.id.to_owned())
        .collect();
    let endpoint_required: BTreeSet<String> = registry
        .with_status(ImplementationStatus::EndpointRequired)
        .iter()
        .map(|entry| entry.id.to_owned())
        .collect();
    let registration_only: BTreeSet<String> = registry
        .with_status(ImplementationStatus::RegistrationOnly)
        .iter()
        .map(|entry| entry.id.to_owned())
        .collect();

    assert!(implemented.is_disjoint(&endpoint_required));
    assert!(implemented.is_disjoint(&registration_only));
    assert!(endpoint_required.is_disjoint(&registration_only));

    let union: BTreeSet<String> = implemented
        .union(&endpoint_required)
        .cloned()
        .collect::<BTreeSet<String>>()
        .union(&registration_only)
        .cloned()
        .collect();
    assert_eq!(union, frozen);
}

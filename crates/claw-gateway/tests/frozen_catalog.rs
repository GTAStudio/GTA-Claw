//! Coverage of the frozen Gateway protocol inventory.
//!
//! The inventory JSON is parsed here directly, independently of the generated
//! `claw_protocol` registry, so that a drift in either direction — a method the
//! server forgot to register, or one it invented — fails this test.

use std::collections::{BTreeMap, BTreeSet};
use std::path::PathBuf;

use claw_gateway::events::event_catalog;
use claw_gateway::methods;
use claw_protocol::gateway::MethodScope;
use serde::Deserialize;

#[derive(Debug, Deserialize)]
struct Inventory {
    counts: Counts,
    items: Vec<Item>,
}

#[derive(Debug, Deserialize)]
struct Counts {
    total: usize,
    methods: usize,
    advertised_methods: usize,
    events: usize,
    roles: usize,
    scopes: usize,
}

#[derive(Debug, Deserialize)]
struct Item {
    id: String,
    kind: String,
    #[serde(default)]
    scope: Option<String>,
    #[serde(default)]
    advertised: Option<bool>,
}

fn inventory() -> Inventory {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join("..")
        .join("compat")
        .join("upstream")
        .join("inventories")
        .join("gateway-protocol.json");
    let raw = std::fs::read_to_string(&path).unwrap_or_else(|error| {
        panic!(
            "frozen inventory at {} is readable: {error}",
            path.display()
        )
    });
    // The frozen inventories are checked in with a UTF-8 byte-order mark.
    let raw = raw.strip_prefix('\u{feff}').unwrap_or(&raw);
    serde_json::from_str(raw).expect("the frozen inventory is valid JSON")
}

fn of_kind<'a>(inventory: &'a Inventory, kind: &str) -> Vec<&'a Item> {
    inventory
        .items
        .iter()
        .filter(|item| item.kind == kind)
        .collect()
}

#[test]
fn the_inventory_still_declares_the_counts_this_server_was_written_against() {
    let inventory = inventory();
    assert_eq!(inventory.items.len(), inventory.counts.total);
    assert_eq!(inventory.counts.total, 320);
    assert_eq!(inventory.counts.methods, 278);
    assert_eq!(inventory.counts.advertised_methods, 258);
    assert_eq!(inventory.counts.events, 33);
    assert_eq!(inventory.counts.roles, 3);
    assert_eq!(inventory.counts.scopes, 6);
    assert_eq!(of_kind(&inventory, "method").len(), 278);
    assert_eq!(of_kind(&inventory, "event").len(), 33);
    assert_eq!(of_kind(&inventory, "role").len(), 3);
    assert_eq!(of_kind(&inventory, "scope").len(), 6);
}

#[test]
fn the_registry_holds_exactly_the_frozen_method_set() {
    let inventory = inventory();
    let frozen: BTreeSet<String> = of_kind(&inventory, "method")
        .into_iter()
        .map(|item| item.id.clone())
        .collect();
    let registry = methods::registry().expect("every handler installs");
    let registered: BTreeSet<String> = registry
        .names()
        .into_iter()
        .map(std::borrow::ToOwned::to_owned)
        .collect();

    let missing: Vec<&String> = frozen.difference(&registered).collect();
    let extra: Vec<&String> = registered.difference(&frozen).collect();
    assert_eq!(
        missing,
        Vec::<&String>::new(),
        "methods absent from the registry"
    );
    assert_eq!(
        extra,
        Vec::<&String>::new(),
        "methods invented by the registry"
    );
    assert_eq!(registered.len(), 278);
}

#[test]
fn every_registered_method_keeps_its_frozen_authorization_scope() {
    let inventory = inventory();
    let frozen: BTreeMap<String, String> = of_kind(&inventory, "method")
        .into_iter()
        .map(|item| {
            (
                item.id.clone(),
                item.scope
                    .clone()
                    .unwrap_or_else(|| panic!("method `{}` has no frozen scope", item.id)),
            )
        })
        .collect();
    let registry = methods::registry().expect("every handler installs");

    for (method, expected) in &frozen {
        let actual = registry
            .scope_of(method)
            .unwrap_or_else(|| panic!("`{method}` is registered"));
        let actual = match actual {
            MethodScope::Operator(scope) => scope.as_str().to_owned(),
            MethodScope::Node => "node".to_owned(),
            MethodScope::Dynamic => "dynamic".to_owned(),
        };
        assert_eq!(&actual, expected, "scope drift for `{method}`");
    }
}

#[test]
fn the_advertised_set_matches_the_frozen_advertised_flags() {
    let inventory = inventory();
    let frozen: BTreeSet<String> = of_kind(&inventory, "method")
        .into_iter()
        .filter(|item| item.advertised == Some(true))
        .map(|item| item.id.clone())
        .collect();
    let registry = methods::registry().expect("every handler installs");
    let advertised: BTreeSet<String> = registry
        .advertised_names()
        .into_iter()
        .map(std::borrow::ToOwned::to_owned)
        .collect();

    assert_eq!(advertised.len(), 258);
    assert_eq!(advertised, frozen);
}

#[test]
fn the_event_catalog_holds_exactly_the_frozen_event_set() {
    let inventory = inventory();
    let frozen: BTreeSet<String> = of_kind(&inventory, "event")
        .into_iter()
        .map(|item| item.id.clone())
        .collect();
    let catalogued: BTreeSet<String> = event_catalog()
        .into_iter()
        .map(|(name, _)| name.to_owned())
        .collect();

    let missing: Vec<&String> = frozen.difference(&catalogued).collect();
    let extra: Vec<&String> = catalogued.difference(&frozen).collect();
    assert_eq!(
        missing,
        Vec::<&String>::new(),
        "events absent from the catalog"
    );
    assert_eq!(
        extra,
        Vec::<&String>::new(),
        "events invented by the catalog"
    );
    assert_eq!(catalogued.len(), 33);
}

#[test]
fn every_catalogued_event_has_exactly_one_visibility_decision() {
    let catalog = event_catalog();
    let names: BTreeSet<&str> = catalog.iter().map(|(name, _)| *name).collect();
    assert_eq!(names.len(), catalog.len());
    for (name, visibility) in catalog {
        assert_eq!(
            claw_gateway::events::event_visibility(name),
            Some(visibility),
            "`{name}` resolves to a different visibility than the catalog reports"
        );
    }
}

#[test]
fn the_frozen_role_and_scope_identities_are_the_ones_this_server_enforces() {
    let inventory = inventory();
    let roles: BTreeSet<String> = of_kind(&inventory, "role")
        .into_iter()
        .map(|item| item.id.clone())
        .collect();
    let scopes: BTreeSet<String> = of_kind(&inventory, "scope")
        .into_iter()
        .map(|item| item.id.clone())
        .collect();

    let enforced_roles: BTreeSet<String> = claw_protocol::gateway::roles()
        .iter()
        .map(|role| role.as_str().to_owned())
        .collect();
    let enforced_scopes: BTreeSet<String> = claw_protocol::gateway::operator_scopes()
        .iter()
        .map(|scope| scope.as_str().to_owned())
        .collect();

    assert_eq!(enforced_roles, roles);
    assert_eq!(enforced_scopes, scopes);
    assert_eq!(roles.len(), 3);
    assert_eq!(scopes.len(), 6);
}

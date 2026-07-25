//! Anchors this client's authorization decisions to the frozen upstream contract.
//!
//! Every other test in this crate compares this crate against itself. That is
//! appropriate for the logic they cover, but it cannot detect the case where
//! this crate and `claw-security` agree with each other and both differ from
//! upstream — a suite can be entirely green while the client asks the Gateway
//! for the wrong scope.
//!
//! The subject here is therefore `compat/upstream/inventories/gateway-protocol.json`,
//! read from the repository rather than reconstructed in Rust. It is the frozen
//! inventory of the upstream baseline, it records a `scope` for every gateway
//! method, and nothing in this crate contributes to its contents.
//!
//! [`control_the_frozen_inventory_is_present_and_populated`] exists because
//! every assertion below is a lookup, and a lookup against an empty or
//! mis-parsed document passes vacuously. Without the control, four green tests
//! would be evidence of nothing.

use std::collections::BTreeSet;

use claw_security::authorization::Scope;
use gta_claw_ios::IosAction;
use serde_json::Value;

/// The frozen inventory, embedded at compile time from the repository.
const FROZEN_GATEWAY_PROTOCOL: &str =
    include_str!("../../../compat/upstream/inventories/gateway-protocol.json");

/// A gateway method whose frozen scope each action must match.
///
/// The method names are stated here rather than in the crate, because this
/// client does not call them by name and should not pretend to. What is being
/// checked is that the scope this client would demand for an action equals the
/// scope upstream demands for a method that performs it.
const ACTION_METHODS: [(IosAction, &str); 5] = [
    (IosAction::ReadSessions, "sessions.list"),
    (IosAction::SendMessage, "talk.client.create"),
    (IosAction::ResolveApproval, "exec.approval.resolve"),
    (IosAction::ManagePairing, "device.pair.approve"),
    (IosAction::Administer, "config.set"),
];

fn items() -> Vec<Value> {
    // The frozen inventories are written with a UTF-8 BOM, which `serde_json`
    // rejects as a leading value. Stripping it here is a property of the file
    // being read, not a workaround: `compat/upstream/**` is byte-frozen.
    let text = FROZEN_GATEWAY_PROTOCOL.trim_start_matches('\u{feff}');
    let document: Value = serde_json::from_str(text).unwrap_or_else(|error| {
        panic!("the frozen gateway-protocol inventory did not parse as JSON: {error}")
    });
    document
        .get("items")
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_else(|| {
            panic!(
                "the frozen inventory has no items array; its top-level keys were {:?}",
                document
                    .as_object()
                    .map(|object| object.keys().cloned().collect::<Vec<_>>())
            )
        })
}

fn record_of_kind(kind: &str, id: &str) -> Value {
    items()
        .into_iter()
        .find(|item| {
            item.get("kind").and_then(Value::as_str) == Some(kind)
                && item.get("id").and_then(Value::as_str) == Some(id)
        })
        .unwrap_or_else(|| {
            panic!("the frozen inventory has no {kind} record with id {id:?}; the test's method names are stale, not the client's scopes")
        })
}

fn frozen_scope_ids() -> BTreeSet<String> {
    items()
        .into_iter()
        .filter(|item| item.get("kind").and_then(Value::as_str) == Some("scope"))
        .filter_map(|item| {
            item.get("id")
                .and_then(Value::as_str)
                .map(ToOwned::to_owned)
        })
        .collect()
}

#[test]
fn control_the_frozen_inventory_is_present_and_populated() {
    let items = items();
    assert!(
        items.len() > 100,
        "the frozen inventory parsed to {} items, which is too few to be the real document; \
         every other test here is a lookup and would pass vacuously against it",
        items.len()
    );

    let scopes = frozen_scope_ids();
    assert!(
        !scopes.is_empty(),
        "the frozen inventory yielded no scope records, so the scope assertions below would \
         compare against nothing; the parsed scope set was {scopes:?}"
    );

    let sample = record_of_kind("method", "sessions.list");
    assert_eq!(
        sample.get("scope").and_then(Value::as_str),
        Some("operator.read"),
        "the control lookup did not find the expected shape; the record read {sample}"
    );
}

#[test]
fn every_action_requires_the_scope_upstream_gives_the_method_that_performs_it() {
    for (action, method) in ACTION_METHODS {
        let record = record_of_kind("method", method);
        let frozen = record
            .get("scope")
            .and_then(Value::as_str)
            .unwrap_or_else(|| {
                panic!("the frozen record for {method} has no scope field; it read {record}")
            });
        let required = action.required_scope();

        assert_eq!(
            required.as_str(),
            frozen,
            "action {action} requires {} but the frozen inventory records {frozen} for {method}, \
             so this client would ask the Gateway for the wrong scope",
            required.as_str()
        );
    }
}

#[test]
fn every_action_is_covered_by_the_frozen_comparison() {
    let compared: BTreeSet<IosAction> = ACTION_METHODS.iter().map(|(action, _)| *action).collect();

    for action in IosAction::ALL {
        assert!(
            compared.contains(&action),
            "action {action} has no frozen gateway method to check against, so its scope is \
             asserted only by this crate agreeing with itself"
        );
    }
}

#[test]
fn the_scope_registry_this_client_authenticates_against_is_the_frozen_one() {
    let frozen = frozen_scope_ids();
    let known: BTreeSet<String> = Scope::ALL
        .iter()
        .map(|scope| scope.as_str().to_owned())
        .collect();

    assert_eq!(
        known,
        frozen,
        "the scope registry this client can name and the frozen upstream registry differ; \
         missing from this build: {:?}; not in the frozen inventory: {:?}",
        frozen.difference(&known).collect::<Vec<_>>(),
        known.difference(&frozen).collect::<Vec<_>>()
    );

    for id in &frozen {
        let parsed = Scope::parse(id);
        assert!(
            parsed.is_ok(),
            "the frozen scope {id:?} does not parse in this build, so a Gateway granting it \
             would be read as granting nothing; parsing reported {parsed:?}"
        );
    }
}

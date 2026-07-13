//! Cross-checks the Rust security registry against frozen P00a contract data.

use std::collections::BTreeSet;
use std::fs;
use std::path::PathBuf;

use claw_security::authorization::{
    CURRENT_PROTOCOL_VERSION, MIN_AUTHENTICATED_NODE_PROTOCOL_VERSION,
    MIN_GENERAL_PROTOCOL_VERSION, MIN_PROBE_PROTOCOL_VERSION, Role, Scope,
};
use serde_json::Value;

fn repository_file(relative: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join("..")
        .join(relative)
}

fn read_json(relative: &str) -> Value {
    let bytes = fs::read(repository_file(relative)).expect("read frozen contract");
    let bytes = bytes.strip_prefix(&[0xef, 0xbb, 0xbf]).unwrap_or(&bytes);
    serde_json::from_slice(bytes).expect("parse frozen contract")
}

#[test]
fn rust_registries_equal_the_frozen_inventory_in_both_directions() {
    let inventory = read_json("compat/upstream/inventories/gateway-protocol.json");
    let items = inventory["items"].as_array().expect("inventory items");
    let frozen_roles = items
        .iter()
        .filter(|item| item["kind"] == "role")
        .map(|item| item["id"].as_str().expect("role id"))
        .collect::<BTreeSet<_>>();
    let frozen_scopes = items
        .iter()
        .filter(|item| item["kind"] == "scope")
        .map(|item| item["id"].as_str().expect("scope id"))
        .collect::<BTreeSet<_>>();
    let rust_roles = Role::ALL
        .into_iter()
        .map(Role::as_str)
        .collect::<BTreeSet<_>>();
    let rust_scopes = Scope::ALL
        .into_iter()
        .map(Scope::as_str)
        .collect::<BTreeSet<_>>();

    assert_eq!(rust_roles, frozen_roles);
    assert_eq!(rust_scopes, frozen_scopes);
    assert_eq!(inventory["counts"]["roles"], rust_roles.len());
    assert_eq!(inventory["counts"]["scopes"], rust_scopes.len());

    for role in frozen_roles {
        assert_eq!(Role::parse(role).expect("frozen role").as_str(), role);
    }
    for scope in frozen_scopes {
        assert_eq!(Scope::parse(scope).expect("frozen scope").as_str(), scope);
    }
}

#[test]
fn rust_protocol_window_equals_the_frozen_baseline() {
    let baseline = read_json("compat/upstream/baseline.json");
    let gateway = &baseline["gateway_protocol"];

    assert_eq!(gateway["current"], CURRENT_PROTOCOL_VERSION);
    assert_eq!(
        gateway["minimum_general_client"],
        MIN_GENERAL_PROTOCOL_VERSION
    );
    assert_eq!(
        gateway["minimum_authenticated_node"],
        MIN_AUTHENTICATED_NODE_PROTOCOL_VERSION
    );
    assert_eq!(gateway["minimum_probe"], MIN_PROBE_PROTOCOL_VERSION);
}

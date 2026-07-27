//! The registered routes are exactly the frozen upstream inventory rows.
//!
//! `compat/upstream/` is the parity trust root and is read-only here. A route
//! this crate invents, renames, or forgets is a parity claim nothing upstream
//! backs, so the registered set is compared against the frozen inventory rather
//! than against a second copy of itself.

use std::collections::BTreeSet;
use std::fs;
use std::path::PathBuf;

use claw_gateway_http::GATEWAY_HTTP_ENDPOINTS;
use serde_json::Value;

const FROZEN_SOURCES: [&str; 2] = [
    "src/gateway/server-http.ts",
    "src/gateway/watch-node-http.ts",
];

fn inventory_path() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join("..")
        .join("compat")
        .join("upstream")
        .join("inventories")
        .join("http-sse-endpoints.json")
}

#[test]
fn registered_routes_match_the_frozen_gateway_http_inventory() {
    let raw = fs::read_to_string(inventory_path()).expect("read the frozen endpoint inventory");
    let inventory: Value =
        serde_json::from_str(raw.trim_start_matches('\u{feff}')).expect("inventory is JSON");
    let frozen: BTreeSet<(String, String)> = inventory["items"]
        .as_array()
        .expect("inventory items")
        .iter()
        .filter(|item| {
            item["source_path"]
                .as_str()
                .is_some_and(|source| FROZEN_SOURCES.contains(&source))
        })
        .map(|item| {
            (
                item["method"].as_str().expect("method").to_owned(),
                item["path"].as_str().expect("path").to_owned(),
            )
        })
        .collect();
    assert_eq!(
        frozen.len(),
        9,
        "the two frozen upstream sources declare nine endpoints"
    );

    let registered: BTreeSet<(String, String)> = GATEWAY_HTTP_ENDPOINTS
        .iter()
        .map(|(method, path)| ((*method).to_owned(), (*path).to_owned()))
        .collect();
    assert_eq!(
        registered.len(),
        GATEWAY_HTTP_ENDPOINTS.len(),
        "no route is registered twice"
    );
    assert_eq!(registered, frozen);
}

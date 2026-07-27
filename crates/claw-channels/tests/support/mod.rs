//! Shared access to the frozen upstream channel inventory.
//!
//! Every channel test drives its cases from this file rather than from a
//! hand-copied list, so a channel that upstream defines and this crate forgets
//! fails a test instead of passing one that never looked.

use std::path::Path;

use serde::Deserialize;

#[derive(Debug, Deserialize)]
struct Inventory {
    counts: Counts,
    items: Vec<Item>,
}

#[derive(Debug, Deserialize)]
struct Counts {
    total: usize,
}

#[derive(Debug, Deserialize)]
struct Item {
    id: String,
}

/// Returns every frozen official channel identifier, in inventory order.
pub(crate) fn frozen_channel_ids() -> Vec<String> {
    let path = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../compat/upstream/inventories/channels.json");
    let json = std::fs::read_to_string(&path).expect("read frozen channel inventory");
    let inventory: Inventory = serde_json::from_str(json.trim_start_matches('\u{feff}'))
        .expect("valid frozen channel inventory");
    assert_eq!(
        inventory.counts.total,
        inventory.items.len(),
        "frozen inventory count disagrees with its own items"
    );
    assert!(
        inventory.counts.total > 0,
        "frozen inventory must not be empty"
    );
    inventory.items.into_iter().map(|item| item.id).collect()
}

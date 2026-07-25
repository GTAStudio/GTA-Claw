//! Frozen bundled-skill inventory parity.

use std::path::Path;

use claw_skills::{SkillImplementation, registry};
use serde::Deserialize;

#[derive(Debug, Deserialize, Eq, PartialEq)]
struct Inventory {
    counts: InventoryCounts,
    items: Vec<InventoryItem>,
}

#[derive(Debug, Deserialize, Eq, PartialEq)]
struct InventoryCounts {
    total: usize,
}

#[derive(Debug, Deserialize, Eq, PartialEq)]
struct InventoryItem {
    record_id: String,
    id: String,
    classification: String,
    source_path: String,
    license: String,
}

fn frozen_inventory() -> Inventory {
    let path =
        Path::new(env!("CARGO_MANIFEST_DIR")).join("../../compat/upstream/inventories/skills.json");
    let json = std::fs::read_to_string(path).expect("read frozen inventory");
    serde_json::from_str(json.trim_start_matches('\u{feff}')).expect("valid frozen inventory")
}

#[test]
fn registry_matches_every_frozen_skill_field() {
    let frozen = frozen_inventory();
    let actual = registry()
        .iter()
        .map(|entry| InventoryItem {
            record_id: entry.record_id.to_owned(),
            id: entry.id.to_owned(),
            classification: entry.classification.to_owned(),
            source_path: entry.source_path.to_owned(),
            license: entry.license.to_owned(),
        })
        .collect::<Vec<_>>();

    assert_eq!(frozen.counts.total, 51);
    assert_eq!(frozen.items.len(), frozen.counts.total);
    assert_eq!(actual.len(), frozen.counts.total);
    assert_eq!(actual, frozen.items);
    assert!(
        registry()
            .iter()
            .all(|entry| entry.implementation == SkillImplementation::RequiresNativePort)
    );
}

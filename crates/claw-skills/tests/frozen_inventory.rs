//! Frozen bundled-skill inventory parity.

use claw_skills::{SkillImplementation, registry};
use serde::Deserialize;

#[derive(Debug, Deserialize, Eq, PartialEq)]
struct Inventory {
    items: Vec<InventoryItem>,
}

#[derive(Debug, Deserialize, Eq, PartialEq)]
struct InventoryItem {
    record_id: String,
    id: String,
    classification: String,
    source_path: String,
    license: String,
}

#[test]
fn registry_matches_every_frozen_skill_field() {
    let json = include_str!("../../../compat/upstream/inventories/skills.json")
        .trim_start_matches('\u{feff}');
    let frozen: Inventory = serde_json::from_str(json).expect("valid frozen inventory");
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

    assert_eq!(frozen.items.len(), 51);
    assert_eq!(actual, frozen.items);
    assert!(
        registry()
            .iter()
            .all(|entry| entry.implementation == SkillImplementation::RequiresNativePort)
    );
}

//! Regression coverage for the workspace-only frozen registry build input.

#[path = "../build_support.rs"]
mod build_support;

use build_support::{
    EXPECTED_BASELINE_SHA, RegistrySourceError, load_and_validate_registry, validate_registry_bytes,
};
use serde_json::Value;

const SOURCE: &[u8] = include_bytes!("../../../compat/upstream/inventories/gateway-protocol.json");

fn mutate(mutator: impl FnOnce(&mut Value)) -> Vec<u8> {
    let source = SOURCE
        .strip_prefix(&[0xef, 0xbb, 0xbf])
        .expect("canonical inventory has its checked-in BOM");
    let mut value: Value = serde_json::from_slice(source).expect("canonical inventory");
    mutator(&mut value);
    serde_json::to_vec(&value).expect("serialize tampered inventory")
}

#[test]
fn accepts_only_the_externally_pinned_source() {
    let inventory = validate_registry_bytes(SOURCE).expect("exact frozen input");

    assert_eq!(inventory.baseline_sha, EXPECTED_BASELINE_SHA);
    assert_eq!(inventory.items.len(), 320);
}

#[test]
fn rejects_count_preserving_row_tampering_and_reordering() {
    // External pin covers every row field and the exact row order, independently
    // of mutable inventory/manifest count declarations.
    for tampered in [
        mutate(|value| value["items"][0]["id"] = Value::String("Health".to_owned())),
        mutate(|value| {
            value["items"][0]["scope"] = Value::String("operator.admin".to_owned());
        }),
        mutate(|value| value["items"][0]["advertised"] = Value::Bool(false)),
        mutate(|value| {
            let items = value["items"].as_array_mut().expect("items");
            items.swap(0, 1);
        }),
    ] {
        assert!(matches!(
            validate_registry_bytes(&tampered),
            Err(RegistrySourceError::SourceDigest { .. })
        ));
    }
}

#[test]
fn reports_missing_workspace_input_clearly() {
    let missing = std::env::temp_dir().join(format!(
        "gta-claw-missing-gateway-registry-{}.json",
        std::process::id()
    ));
    let error = load_and_validate_registry(&missing).expect_err("missing input must fail");

    assert!(matches!(error, RegistrySourceError::Read { .. }));
    assert!(error.to_string().contains("missing frozen workspace input"));
}

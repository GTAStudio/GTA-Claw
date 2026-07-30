//! Structural drift tests for the packaged and workspace legacy contracts.

#[path = "../build_support.rs"]
mod build_support;

use std::path::PathBuf;

use build_support::{
    Contract, canonical_contract_bytes, ensure_same_contract, load_contract, validate_contract,
};

#[test]
fn workspace_and_packaged_contracts_match_completely() {
    let manifest = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let packaged = load_contract(&manifest.join("data/env-mapping.json"));
    validate_contract(&packaged).expect("packaged contract is structurally valid");

    let repository_marker = manifest.join("../../compat/legacy/contract.json");
    if !repository_marker.is_file() {
        return;
    }
    let workspace = load_contract(&manifest.join("../../compat/legacy/config/env-mapping.json"));
    validate_contract(&workspace).expect("workspace contract is structurally valid");
    assert_eq!(
        canonical_contract_bytes(&packaged).expect("canonical packaged bytes"),
        canonical_contract_bytes(&workspace).expect("canonical workspace bytes"),
        "build inputs must have identical canonical bytes"
    );
    let auto_update = packaged
        .mappings
        .iter()
        .find(|mapping| mapping.legacy_env == "AUTO_UPDATE")
        .expect("AUTO_UPDATE mapping");
    assert_eq!(
        auto_update.validation,
        "Boolean; true is rejected because dependency updates are review-only."
    );
    assert!(
        auto_update
            .known_legacy_quirk
            .as_deref()
            .is_some_and(|value| value.contains("AUTO_UPDATE=true fails"))
    );
    ensure_same_contract(&packaged, &workspace).expect("contracts must match");
}

#[test]
fn schema_valid_behavioral_tampering_is_detected() {
    let manifest = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let canonical = load_contract(&manifest.join("data/env-mapping.json"));

    assert_tamper_detected(&canonical, |mapping| {
        mapping.default = serde_json::json!(4_000);
    });
    assert_tamper_detected(&canonical, |mapping| {
        mapping.conversion.push_str(" changed");
    });
    assert_tamper_detected(&canonical, |mapping| {
        mapping.validation.push_str(" changed");
    });
    assert_tamper_detected(&canonical, |mapping| {
        mapping.required_when = "manual".to_owned();
    });
    assert_tamper_detected(&canonical, |mapping| {
        mapping.aliases.push("PORT_ALIAS".to_owned());
    });
    assert_tamper_detected(&canonical, |mapping| {
        mapping.target_json5_key = "server.alternate_port".to_owned();
    });
}

fn assert_tamper_detected(canonical: &Contract, tamper: impl FnOnce(&mut build_support::Mapping)) {
    let mut candidate = canonical.clone();
    let mapping = candidate
        .mappings
        .iter_mut()
        .find(|mapping| mapping.legacy_env == "PORT")
        .expect("PORT mapping");
    tamper(mapping);
    validate_contract(&candidate).expect("tamper remains structurally schema-valid");
    ensure_same_contract(canonical, &candidate).expect_err("full structural drift must fail");
}

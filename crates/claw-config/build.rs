//! Build-time ownership boundary for the frozen GTA legacy mapping contract.

mod build_support;

use std::env;
use std::fs;
use std::path::{Path, PathBuf};

use build_support::{Contract, Mapping};

fn main() {
    let manifest_dir =
        PathBuf::from(env::var_os("CARGO_MANIFEST_DIR").expect("manifest directory"));
    let packaged_path = manifest_dir.join("data/env-mapping.json");
    println!("cargo:rerun-if-changed={}", packaged_path.display());
    let canonical = build_support::load_contract(&packaged_path);
    build_support::validate_contract(&canonical).expect("validate packaged mapping contract");

    verify_workspace_contract(&manifest_dir, &canonical);

    let generated = generate(&canonical);
    let output = PathBuf::from(env::var_os("OUT_DIR").expect("build output directory"))
        .join("legacy_mappings.rs");
    fs::write(output, generated).expect("write generated legacy mapping table");
}

fn verify_workspace_contract(manifest_dir: &Path, canonical: &Contract) {
    let workspace_root = manifest_dir.join("../..");
    let repository_marker = workspace_root.join("compat/legacy/contract.json");
    if !repository_marker.is_file() {
        return;
    }

    let workspace_path = workspace_root.join("compat/legacy/config/env-mapping.json");
    println!("cargo:rerun-if-changed={}", workspace_path.display());
    let workspace = build_support::load_contract(&workspace_path);
    build_support::validate_contract(&workspace).expect("validate workspace mapping contract");
    build_support::ensure_same_contract(canonical, &workspace)
        .expect("workspace mapping contract drifted from crates/claw-config/data/env-mapping.json");
}

fn generate(contract: &Contract) -> String {
    let mut output = String::from(
        "#[derive(Clone, Copy, Debug, Eq, PartialEq)]\n\
         pub(crate) enum MappingId {\n",
    );
    for mapping in &contract.mappings {
        output.push_str("    ");
        output.push_str(&variant_name(&mapping.legacy_env));
        output.push_str(",\n");
    }
    output.push_str("}\n\npub(crate) static LEGACY_MAPPINGS: &[LegacyMappingContract] = &[\n");
    for mapping in &contract.mappings {
        generate_mapping(&mut output, mapping);
    }
    output.push_str("];\n");
    output
}

fn generate_mapping(output: &mut String, mapping: &Mapping) {
    output.push_str("    LegacyMappingContract { id: MappingId::");
    output.push_str(&variant_name(&mapping.legacy_env));
    output.push_str(", legacy_env: ");
    output.push_str(&literal(&mapping.legacy_env));
    output.push_str(", aliases: &[");
    for alias in &mapping.aliases {
        output.push_str(&literal(alias));
        output.push(',');
    }
    output.push_str("], scope: ");
    output.push_str(&literal(&mapping.scope));
    output.push_str(", target: ");
    output.push_str(&literal(&mapping.target_json5_key));
    output.push_str(", secret: ");
    output.push_str(if mapping.secret { "true" } else { "false" });
    output.push_str(", _default_json: ");
    output.push_str(&literal(&mapping.default.to_string()));
    output.push_str(", _conversion: ");
    output.push_str(&literal(&mapping.conversion));
    output.push_str(", _validation: ");
    output.push_str(&literal(&mapping.validation));
    output.push_str(", _required_when: ");
    output.push_str(&literal(&mapping.required_when));
    output.push_str(", _known_legacy_quirk: ");
    match &mapping.known_legacy_quirk {
        Some(value) => {
            output.push_str("Some(");
            output.push_str(&literal(value));
            output.push(')');
        }
        None => output.push_str("None"),
    }
    output.push_str(" },\n");
}

fn variant_name(value: &str) -> String {
    let mut name = String::with_capacity(value.len());
    for part in value.split('_').filter(|part| !part.is_empty()) {
        let mut characters = part.chars();
        let first = characters
            .next()
            .expect("nonempty environment name segment");
        name.push(first.to_ascii_uppercase());
        name.extend(characters.map(|character| character.to_ascii_lowercase()));
    }
    name
}

fn literal(value: &str) -> String {
    serde_json::to_string(value).expect("serialize generated string literal")
}

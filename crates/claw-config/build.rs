//! Build-time ownership boundary for the frozen GTA legacy mapping contract.

use std::env;
use std::fs;
use std::path::{Path, PathBuf};

use serde::Deserialize;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Contract {
    #[serde(rename = "$schema")]
    schema: String,
    source_revision: String,
    proposed_format: String,
    mappings: Vec<Mapping>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Mapping {
    legacy_env: String,
    #[serde(default)]
    aliases: Vec<String>,
    scope: String,
    target_json5_key: String,
    secret: bool,
    default: serde_json::Value,
    conversion: String,
    validation: String,
    required_when: String,
    #[serde(default)]
    known_legacy_quirk: Option<String>,
}

fn main() {
    let manifest_dir =
        PathBuf::from(env::var_os("CARGO_MANIFEST_DIR").expect("manifest directory"));
    let contract_path = manifest_dir.join("../../compat/legacy/config/env-mapping.json");
    println!("cargo:rerun-if-changed={}", contract_path.display());

    let source =
        fs::read_to_string(&contract_path).expect("read frozen legacy environment contract");
    let contract: Contract =
        serde_json::from_str(&source).expect("parse frozen legacy environment contract");
    validate_contract(&contract, &contract_path);

    let generated = generate(&contract);
    let output = PathBuf::from(env::var_os("OUT_DIR").expect("build output directory"))
        .join("legacy_mappings.rs");
    fs::write(output, generated).expect("write generated legacy mapping table");
}

fn validate_contract(contract: &Contract, path: &Path) {
    assert!(
        contract.schema.ends_with("config-mapping.schema.json"),
        "{} has unexpected schema",
        path.display()
    );
    assert_eq!(contract.proposed_format, "JSON5");
    assert_eq!(contract.source_revision.len(), 40);
    assert!(!contract.mappings.is_empty());

    let mut names = std::collections::BTreeSet::new();
    for mapping in &contract.mappings {
        assert!(
            names.insert(mapping.legacy_env.as_str()),
            "duplicate legacy_env"
        );
        for alias in &mapping.aliases {
            assert!(names.insert(alias.as_str()), "duplicate environment alias");
        }
        assert!(!mapping.target_json5_key.is_empty());
        assert!(!mapping.scope.is_empty());
        assert!(!mapping.conversion.is_empty());
        assert!(!mapping.validation.is_empty());
        let _ = (
            mapping.secret,
            &mapping.default,
            &mapping.required_when,
            &mapping.known_legacy_quirk,
        );
    }
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
        output.push_str(" },\n");
    }
    output.push_str("];\n");
    output
}

fn variant_name(value: &str) -> String {
    value
        .split('_')
        .filter(|part| !part.is_empty())
        .map(|part| {
            let mut chars = part.chars();
            let first = chars.next().expect("nonempty environment name segment");
            format!(
                "{}{}",
                first.to_ascii_uppercase(),
                chars.as_str().to_ascii_lowercase()
            )
        })
        .collect()
}

fn literal(value: &str) -> String {
    serde_json::to_string(value).expect("serialize generated string literal")
}

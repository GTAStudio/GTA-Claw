use std::collections::BTreeSet;
use std::fs;
use std::path::Path;

use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Contract {
    #[serde(rename = "$schema")]
    pub(crate) schema: String,
    pub(crate) source_revision: String,
    pub(crate) proposed_format: String,
    pub(crate) mappings: Vec<Mapping>,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Mapping {
    pub(crate) legacy_env: String,
    #[serde(default)]
    pub(crate) aliases: Vec<String>,
    pub(crate) scope: String,
    pub(crate) target_json5_key: String,
    pub(crate) secret: bool,
    pub(crate) default: serde_json::Value,
    pub(crate) conversion: String,
    pub(crate) validation: String,
    pub(crate) required_when: String,
    #[serde(default)]
    pub(crate) known_legacy_quirk: Option<String>,
}

pub(crate) fn load_contract(path: &Path) -> Contract {
    let source = fs::read_to_string(path)
        .unwrap_or_else(|error| panic!("read mapping contract {}: {error}", path.display()));
    parse_contract(&source)
        .unwrap_or_else(|error| panic!("parse mapping contract {}: {error}", path.display()))
}

pub(crate) fn parse_contract(source: &str) -> Result<Contract, serde_json::Error> {
    serde_json::from_str(source)
}

pub(crate) fn validate_contract(contract: &Contract) -> Result<(), String> {
    if !contract.schema.ends_with("config-mapping.schema.json") {
        return Err("unexpected $schema".to_owned());
    }
    if contract.proposed_format != "JSON5" {
        return Err("proposed_format must be JSON5".to_owned());
    }
    if contract.source_revision.len() != 40
        || !contract
            .source_revision
            .bytes()
            .all(|byte| matches!(byte, b'0'..=b'9' | b'a'..=b'f'))
    {
        return Err("source_revision must be a 40-character hexadecimal commit".to_owned());
    }
    if contract.mappings.is_empty() {
        return Err("mappings must not be empty".to_owned());
    }

    let mut names = BTreeSet::new();
    for mapping in &contract.mappings {
        if !valid_environment_name(&mapping.legacy_env) {
            return Err(format!(
                "invalid canonical environment name {}",
                mapping.legacy_env
            ));
        }
        if !names.insert(mapping.legacy_env.as_str()) {
            return Err(format!("duplicate environment name {}", mapping.legacy_env));
        }
        for alias in &mapping.aliases {
            if !valid_environment_name(alias) {
                return Err(format!("invalid environment alias {alias}"));
            }
            if !names.insert(alias.as_str()) {
                return Err(format!("duplicate environment name {alias}"));
            }
        }
        if !matches!(
            mapping.scope.as_str(),
            "runtime" | "deployer" | "build" | "ci"
        ) {
            return Err(format!("{} has an invalid scope", mapping.legacy_env));
        }
        if !valid_target_key(&mapping.target_json5_key) {
            return Err(format!("{} has an invalid target key", mapping.legacy_env));
        }
        if mapping.conversion.is_empty() || mapping.validation.is_empty() {
            return Err(format!(
                "{} contains an empty required behavioral field",
                mapping.legacy_env
            ));
        }
        if mapping
            .known_legacy_quirk
            .as_ref()
            .is_some_and(String::is_empty)
        {
            return Err(format!("{} has an empty known quirk", mapping.legacy_env));
        }
    }
    Ok(())
}

fn valid_environment_name(value: &str) -> bool {
    let mut bytes = value.bytes();
    matches!(bytes.next(), Some(b'A'..=b'Z' | b'a'..=b'z' | b'_'))
        && bytes.all(|byte| matches!(byte, b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'_'))
}

fn valid_target_key(value: &str) -> bool {
    value.split('.').all(|segment| {
        let mut bytes = segment.bytes();
        matches!(bytes.next(), Some(b'a'..=b'z'))
            && bytes.all(|byte| matches!(byte, b'a'..=b'z' | b'0'..=b'9' | b'_'))
    })
}

pub(crate) fn ensure_same_contract(
    canonical: &Contract,
    candidate: &Contract,
) -> Result<(), String> {
    let canonical_bytes = canonical_contract_bytes(canonical)?;
    let candidate_bytes = canonical_contract_bytes(candidate)?;
    if canonical_bytes == candidate_bytes {
        Ok(())
    } else {
        Err(first_difference(canonical, candidate))
    }
}

pub(crate) fn canonical_contract_bytes(contract: &Contract) -> Result<Vec<u8>, String> {
    serde_json::to_vec(contract)
        .map_err(|error| format!("serialize mapping contract to canonical JSON bytes: {error}"))
}

fn first_difference(canonical: &Contract, candidate: &Contract) -> String {
    if canonical.schema != candidate.schema {
        return "$schema differs from packaged canonical contract".to_owned();
    }
    if canonical.source_revision != candidate.source_revision {
        return "source_revision differs from packaged canonical contract".to_owned();
    }
    if canonical.proposed_format != candidate.proposed_format {
        return "proposed_format differs from packaged canonical contract".to_owned();
    }
    if canonical.mappings.len() != candidate.mappings.len() {
        return "mapping list length differs from packaged canonical contract".to_owned();
    }
    for (index, (expected, actual)) in canonical
        .mappings
        .iter()
        .zip(&candidate.mappings)
        .enumerate()
    {
        if expected != actual {
            return format!(
                "mappings[{index}] ({}) differs from packaged canonical contract",
                expected.legacy_env
            );
        }
    }
    "mapping contract differs from packaged canonical contract".to_owned()
}

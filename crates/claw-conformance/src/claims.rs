//! Typed implementation claims and evidence registration.

use std::collections::BTreeMap;
use std::fs;
use std::path::{Component, Path, PathBuf};

use serde::{Deserialize, Serialize};

use crate::error::{ConformanceError, ViolationCode};

/// Claimed implementation level.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ClaimLevel {
    /// Some, but not all, frozen behavior is implemented.
    Partial,
    /// The complete frozen contract is implemented.
    Implemented,
}

/// Verifiable test evidence backing one claim.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Evidence {
    /// Repository-relative source or test path.
    pub path: PathBuf,
    /// Exact test function name, optionally module-qualified.
    pub test_name: String,
}

impl Evidence {
    /// Creates a test evidence reference.
    #[must_use]
    pub fn test(path: impl Into<PathBuf>, test_name: impl Into<String>) -> Self {
        Self {
            path: path.into(),
            test_name: test_name.into(),
        }
    }
}

/// Evidence-backed claim for a feature ledger row.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct FeatureClaim {
    /// Frozen feature ID.
    pub feature_id: String,
    /// Claimed level.
    pub level: ClaimLevel,
    /// Tests backing the claim.
    pub evidence: Vec<Evidence>,
}

impl FeatureClaim {
    /// Creates a feature claim.
    #[must_use]
    pub fn new(feature_id: impl Into<String>, level: ClaimLevel, evidence: Vec<Evidence>) -> Self {
        Self {
            feature_id: feature_id.into(),
            level,
            evidence,
        }
    }

    /// Creates a fully implemented feature claim.
    #[must_use]
    pub fn implemented(feature_id: impl Into<String>, evidence: Vec<Evidence>) -> Self {
        Self::new(feature_id, ClaimLevel::Implemented, evidence)
    }

    /// Creates a partially implemented feature claim.
    #[must_use]
    pub fn partial(feature_id: impl Into<String>, evidence: Vec<Evidence>) -> Self {
        Self::new(feature_id, ClaimLevel::Partial, evidence)
    }
}

/// Evidence-backed claim for one frozen inventory record.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct InventoryClaim {
    /// Frozen inventory ID, such as `providers`.
    pub inventory_id: String,
    /// Frozen record ID, such as `provider:openai`.
    pub record_id: String,
    /// Claimed level.
    pub level: ClaimLevel,
    /// Tests backing the claim.
    pub evidence: Vec<Evidence>,
}

impl InventoryClaim {
    /// Creates an inventory claim.
    #[must_use]
    pub fn new(
        inventory_id: impl Into<String>,
        record_id: impl Into<String>,
        level: ClaimLevel,
        evidence: Vec<Evidence>,
    ) -> Self {
        Self {
            inventory_id: inventory_id.into(),
            record_id: record_id.into(),
            level,
            evidence,
        }
    }

    /// Creates a fully implemented inventory claim.
    #[must_use]
    pub fn implemented(
        inventory_id: impl Into<String>,
        record_id: impl Into<String>,
        evidence: Vec<Evidence>,
    ) -> Self {
        Self::new(inventory_id, record_id, ClaimLevel::Implemented, evidence)
    }

    /// Creates a partially implemented inventory claim.
    #[must_use]
    pub fn partial(
        inventory_id: impl Into<String>,
        record_id: impl Into<String>,
        evidence: Vec<Evidence>,
    ) -> Self {
        Self::new(inventory_id, record_id, ClaimLevel::Partial, evidence)
    }
}

/// Serializable claim manifest that a crate can place at
/// `crates/<name>/conformance-claims.json`.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ClaimsFile {
    /// Claims schema version. Currently `1`.
    pub schema_version: u8,
    /// Crate or component publishing the claims.
    pub crate_name: String,
    /// Feature-row claims.
    #[serde(default)]
    pub features: Vec<FeatureClaim>,
    /// Inventory-record claims.
    #[serde(default)]
    pub inventories: Vec<InventoryClaim>,
}

/// Aggregated claims from Rust callers or claim manifests.
#[derive(Clone, Debug, Default)]
pub struct Registry {
    pub(crate) features: BTreeMap<String, FeatureClaim>,
    pub(crate) inventories: BTreeMap<(String, String), InventoryClaim>,
}

impl Registry {
    /// Creates an empty registry, the honest zero-implementer baseline.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            features: BTreeMap::new(),
            inventories: BTreeMap::new(),
        }
    }

    /// Registers one feature claim.
    pub fn register_feature(&mut self, claim: FeatureClaim) -> Result<(), ConformanceError> {
        let id = claim.feature_id.clone();
        if self.features.insert(id.clone(), claim).is_some() {
            return Err(ConformanceError::new(
                ViolationCode::DuplicateClaim,
                Some(id),
                "feature claim registered more than once".to_owned(),
            ));
        }
        Ok(())
    }

    /// Registers one inventory claim.
    pub fn register_inventory(&mut self, claim: InventoryClaim) -> Result<(), ConformanceError> {
        let key = (claim.inventory_id.clone(), claim.record_id.clone());
        if self.inventories.insert(key.clone(), claim).is_some() {
            return Err(ConformanceError::new(
                ViolationCode::DuplicateClaim,
                Some(format!("{}:{}", key.0, key.1)),
                "inventory claim registered more than once".to_owned(),
            ));
        }
        Ok(())
    }

    /// Loads and registers a JSON claim manifest.
    pub fn load_claims_file(&mut self, path: impl AsRef<Path>) -> Result<(), ConformanceError> {
        let path = path.as_ref();
        let bytes = fs::read(path).map_err(|error| {
            ConformanceError::new(
                ViolationCode::Io,
                Some(path.display().to_string()),
                error.to_string(),
            )
        })?;
        let mut deserializer = serde_json::Deserializer::from_slice(&bytes);
        let claims: ClaimsFile =
            serde_path_to_error::deserialize(&mut deserializer).map_err(|error| {
                ConformanceError::at_json_path(
                    path.display().to_string(),
                    error.path().to_string(),
                    error.inner().to_string(),
                )
            })?;
        if claims.schema_version != 1 || claims.crate_name.trim().is_empty() {
            return Err(ConformanceError::new(
                ViolationCode::JsonSchema,
                Some(path.display().to_string()),
                "claims schema_version must be 1 and crate_name must not be empty".to_owned(),
            ));
        }
        for claim in claims.features {
            self.register_feature(claim)?;
        }
        for claim in claims.inventories {
            self.register_inventory(claim)?;
        }
        Ok(())
    }
}

/// Finds conventional `conformance-claims.json` manifests under `apps/` and
/// `crates/`, returning a deterministic sorted list.
pub fn discover_claim_files(
    repository_root: impl AsRef<Path>,
) -> Result<Vec<PathBuf>, ConformanceError> {
    let repository_root = repository_root.as_ref();
    let mut found = Vec::new();
    for directory in ["apps", "crates"] {
        let start = repository_root.join(directory);
        if start.is_dir() {
            discover_in(&start, &mut found)?;
        }
    }
    found.sort();
    Ok(found)
}

fn discover_in(directory: &Path, found: &mut Vec<PathBuf>) -> Result<(), ConformanceError> {
    let entries = fs::read_dir(directory).map_err(|error| {
        ConformanceError::new(
            ViolationCode::Io,
            Some(directory.display().to_string()),
            error.to_string(),
        )
    })?;
    for entry in entries {
        let entry = entry.map_err(|error| {
            ConformanceError::new(
                ViolationCode::Io,
                Some(directory.display().to_string()),
                error.to_string(),
            )
        })?;
        let path = entry.path();
        if path.is_dir() {
            discover_in(&path, found)?;
        } else if path.file_name().and_then(|name| name.to_str()) == Some("conformance-claims.json")
        {
            found.push(path);
        }
    }
    Ok(())
}

pub(crate) fn validate_evidence(
    repository_root: &Path,
    subject: &str,
    evidence: &[Evidence],
) -> Result<(), ConformanceError> {
    if evidence.is_empty() {
        return Err(ConformanceError::new(
            ViolationCode::ClaimEvidence,
            Some(subject.to_owned()),
            "claim has no recorded evidence".to_owned(),
        ));
    }
    for item in evidence {
        if item.path.as_os_str().is_empty()
            || item.path.is_absolute()
            || item.path.components().any(|component| {
                matches!(
                    component,
                    Component::ParentDir | Component::RootDir | Component::Prefix(_)
                )
            })
        {
            return Err(ConformanceError::new(
                ViolationCode::ClaimEvidence,
                Some(subject.to_owned()),
                format!(
                    "evidence path '{}' must be repository-relative and must not escape the root",
                    item.path.display()
                ),
            ));
        }
        if item.test_name.trim().is_empty() {
            return Err(ConformanceError::new(
                ViolationCode::ClaimEvidence,
                Some(subject.to_owned()),
                "evidence test_name must not be empty".to_owned(),
            ));
        }
        let path = repository_root.join(&item.path);
        if !path.is_file() {
            return Err(ConformanceError::new(
                ViolationCode::ClaimEvidence,
                Some(subject.to_owned()),
                format!("evidence file '{}' does not exist", item.path.display()),
            ));
        }
        let canonical_root = repository_root.canonicalize().map_err(|error| {
            ConformanceError::new(
                ViolationCode::ClaimEvidence,
                Some(subject.to_owned()),
                format!("cannot resolve repository root: {error}"),
            )
        })?;
        let canonical_path = path.canonicalize().map_err(|error| {
            ConformanceError::new(
                ViolationCode::ClaimEvidence,
                Some(subject.to_owned()),
                format!(
                    "cannot resolve evidence file '{}': {error}",
                    item.path.display()
                ),
            )
        })?;
        if !canonical_path.starts_with(&canonical_root) {
            return Err(ConformanceError::new(
                ViolationCode::ClaimEvidence,
                Some(subject.to_owned()),
                format!(
                    "evidence file '{}' resolves outside the repository root",
                    item.path.display()
                ),
            ));
        }
        let source = fs::read_to_string(&canonical_path).map_err(|error| {
            ConformanceError::new(
                ViolationCode::ClaimEvidence,
                Some(subject.to_owned()),
                format!(
                    "cannot read evidence file '{}': {error}",
                    item.path.display()
                ),
            )
        })?;
        let test_name = item
            .test_name
            .rsplit("::")
            .next()
            .unwrap_or(item.test_name.as_str());
        let declared = declares_enabled_test(&source, test_name);
        if !declared {
            return Err(ConformanceError::new(
                ViolationCode::ClaimEvidence,
                Some(subject.to_owned()),
                format!(
                    "evidence test '{}' is not declared in '{}'",
                    item.test_name,
                    item.path.display()
                ),
            ));
        }
    }
    Ok(())
}

fn declares_enabled_test(source: &str, test_name: &str) -> bool {
    let source = remove_block_comments(source);
    let lines = source.lines().collect::<Vec<_>>();
    lines.iter().enumerate().any(|(index, line)| {
        let code = line.trim_start();
        if code.starts_with("//") {
            return false;
        }
        let tokens = code
            .split(|character: char| !character.is_ascii_alphanumeric() && character != '_')
            .collect::<Vec<_>>();
        let is_function = tokens
            .windows(2)
            .any(|pair| pair[0] == "fn" && pair[1] == test_name);
        if !is_function {
            return false;
        }
        let attributes = &lines[index.saturating_sub(6)..=index];
        let has_test = attributes.iter().map(|value| value.trim()).any(|value| {
            !value.starts_with("//")
                && (value == "#[test]" || (value.starts_with("#[") && value.contains("::test")))
        });
        let ignored = attributes
            .iter()
            .map(|value| value.trim())
            .any(|value| !value.starts_with("//") && value.starts_with("#[ignore"));
        let cfg_gated = attributes
            .iter()
            .map(|value| value.trim())
            .any(|value| !value.starts_with("//") && value.starts_with("#[cfg"));
        has_test && !ignored && !cfg_gated
    })
}

fn remove_block_comments(source: &str) -> String {
    let mut output = String::with_capacity(source.len());
    let mut characters = source.chars().peekable();
    let mut depth = 0_u32;
    while let Some(character) = characters.next() {
        if character == '/' && characters.peek() == Some(&'*') {
            characters.next();
            depth += 1;
        } else if depth > 0 && character == '*' && characters.peek() == Some(&'/') {
            characters.next();
            depth -= 1;
        } else if depth == 0 {
            output.push(character);
        } else if character == '\n' {
            output.push('\n');
        }
    }
    output
}

#[cfg(test)]
mod tests {
    use super::declares_enabled_test;

    #[test]
    fn evidence_requires_an_enabled_test_declaration() {
        let cases = [
            ("#[test]\nfn exact_name() {}", true),
            ("#[tokio::test]\nasync fn exact_name() {}", true),
            ("#[test]\n#[ignore]\nfn exact_name() {}", false),
            (
                "#[test]\n#[cfg(target_os = \"none\")]\nfn exact_name() {}",
                false,
            ),
            ("fn exact_name() {}", false),
            ("// #[test]\n// fn exact_name() {}", false),
            ("/* #[test]\nfn exact_name() {} */", false),
            ("#[test]\nfn different_name() {}", false),
        ];
        assert_eq!(
            cases.map(|(source, _)| declares_enabled_test(source, "exact_name")),
            cases.map(|(_, expected)| expected)
        );
    }
}

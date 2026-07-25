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
    /// Metadata registration only; no implementation behavior is claimed.
    Registered,
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
    pub path: String,
    /// Exact test function name, optionally module-qualified.
    pub test: String,
}

impl Evidence {
    /// Creates a test evidence reference.
    #[must_use]
    pub fn test(path: impl Into<PathBuf>, test: impl Into<String>) -> Self {
        Self {
            path: normalized_api_path(path.into()),
            test: test.into(),
        }
    }
}

/// Non-evidential source context accompanying an implementation claim.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ImplementationPointer {
    /// Repository-relative implementation path.
    pub path: String,
    /// Human-readable explanation of what the path contributes.
    pub note: String,
}

impl ImplementationPointer {
    /// Creates a non-evidential implementation pointer.
    #[must_use]
    pub fn new(path: impl Into<PathBuf>, note: impl Into<String>) -> Self {
        Self {
            path: normalized_api_path(path.into()),
            note: note.into(),
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
    /// Optional implementation context; never counted as acceptance evidence.
    #[serde(default)]
    pub implementation_pointers: Vec<ImplementationPointer>,
}

impl FeatureClaim {
    /// Creates a feature claim.
    #[must_use]
    pub fn new(feature_id: impl Into<String>, level: ClaimLevel, evidence: Vec<Evidence>) -> Self {
        Self {
            feature_id: feature_id.into(),
            level,
            evidence,
            implementation_pointers: Vec::new(),
        }
    }

    /// Adds non-evidential implementation context.
    #[must_use]
    pub fn with_implementation_pointers(
        mut self,
        implementation_pointers: Vec<ImplementationPointer>,
    ) -> Self {
        self.implementation_pointers = implementation_pointers;
        self
    }

    /// Registers a feature's ownership or metadata without claiming behavior.
    #[must_use]
    pub fn registered(feature_id: impl Into<String>) -> Self {
        Self::new(feature_id, ClaimLevel::Registered, Vec::new())
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
    /// Optional implementation context; never counted as acceptance evidence.
    #[serde(default)]
    pub implementation_pointers: Vec<ImplementationPointer>,
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
            implementation_pointers: Vec::new(),
        }
    }

    /// Adds non-evidential implementation context.
    #[must_use]
    pub fn with_implementation_pointers(
        mut self,
        implementation_pointers: Vec<ImplementationPointer>,
    ) -> Self {
        self.implementation_pointers = implementation_pointers;
        self
    }

    /// Registers an inventory record's ownership or metadata without claiming behavior.
    #[must_use]
    pub fn registered(inventory_id: impl Into<String>, record_id: impl Into<String>) -> Self {
        Self::new(inventory_id, record_id, ClaimLevel::Registered, Vec::new())
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
        deserializer.end().map_err(|_| {
            ConformanceError::at_json_path(
                path.display().to_string(),
                "$",
                "trailing content after the JSON document",
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
    validate_evidence_as(
        repository_root,
        subject,
        evidence,
        ViolationCode::ClaimEvidence,
    )
}

pub(crate) fn validate_evidence_as(
    repository_root: &Path,
    subject: &str,
    evidence: &[Evidence],
    code: ViolationCode,
) -> Result<(), ConformanceError> {
    if evidence.is_empty() {
        return Err(ConformanceError::new(
            code,
            Some(subject.to_owned()),
            "claim has no recorded evidence".to_owned(),
        ));
    }
    let mut identities = std::collections::BTreeSet::new();
    for item in evidence {
        let path_text = item.path.as_str();
        let relative_path = Path::new(path_text);
        if !valid_reference_path(path_text)
            || relative_path.is_absolute()
            || relative_path.components().any(|component| {
                matches!(
                    component,
                    Component::CurDir
                        | Component::ParentDir
                        | Component::RootDir
                        | Component::Prefix(_)
                )
            })
        {
            return Err(ConformanceError::new(
                code,
                Some(subject.to_owned()),
                format!(
                    "evidence path '{}' must be a repository-relative forward-slash path",
                    item.path
                ),
            ));
        }
        if forbidden_reference_path(path_text) {
            return Err(ConformanceError::new(
                code,
                Some(subject.to_owned()),
                format!(
                    "evidence path '{}' is not eligible Rust acceptance evidence",
                    item.path
                ),
            ));
        }
        if !path_text.to_ascii_lowercase().ends_with(".rs") {
            return Err(ConformanceError::new(
                code,
                Some(subject.to_owned()),
                format!("evidence path '{}' must be a Rust source file", item.path),
            ));
        }
        if !valid_rust_test_path(&item.test) {
            return Err(ConformanceError::new(
                code,
                Some(subject.to_owned()),
                format!("evidence test '{}' must be a Rust test path", item.test),
            ));
        }
        if !identities.insert((path_text, item.test.as_str())) {
            return Err(ConformanceError::new(
                code,
                Some(subject.to_owned()),
                "claim repeats the same evidence artifact".to_owned(),
            ));
        }
        let path = resolve_ordinal_file(repository_root, path_text).map_err(|error| {
            ConformanceError::new(
                code,
                Some(subject.to_owned()),
                format!("cannot resolve evidence file '{}': {error}", item.path),
            )
        })?;
        let Some(path) = path else {
            return Err(ConformanceError::new(
                code,
                Some(subject.to_owned()),
                format!("evidence file '{}' does not exist", item.path),
            ));
        };
        let canonical_root = repository_root.canonicalize().map_err(|error| {
            ConformanceError::new(
                code,
                Some(subject.to_owned()),
                format!("cannot resolve repository root: {error}"),
            )
        })?;
        let canonical_path = path.canonicalize().map_err(|error| {
            ConformanceError::new(
                code,
                Some(subject.to_owned()),
                format!("cannot resolve evidence file '{}': {error}", item.path),
            )
        })?;
        if !canonical_path.starts_with(&canonical_root) {
            return Err(ConformanceError::new(
                code,
                Some(subject.to_owned()),
                format!(
                    "evidence file '{}' resolves outside the repository root",
                    item.path
                ),
            ));
        }
        let source = fs::read_to_string(&canonical_path).map_err(|error| {
            ConformanceError::new(
                code,
                Some(subject.to_owned()),
                format!("cannot read evidence file '{}': {error}", item.path),
            )
        })?;
        let declared = declares_enabled_test(&source, &item.test);
        if !declared {
            return Err(ConformanceError::new(
                code,
                Some(subject.to_owned()),
                format!(
                    "evidence test '{}' is not declared in '{}'",
                    item.test, item.path
                ),
            ));
        }
    }
    Ok(())
}

pub(crate) fn validate_implementation_pointers(
    repository_root: &Path,
    subject: &str,
    pointers: &[ImplementationPointer],
    code: ViolationCode,
) -> Result<(), ConformanceError> {
    let mut identities = std::collections::BTreeSet::new();
    for pointer in pointers {
        let path_text = pointer.path.as_str();
        let relative_path = Path::new(path_text);
        if !valid_reference_path(path_text)
            || relative_path.is_absolute()
            || relative_path.components().any(|component| {
                matches!(
                    component,
                    Component::CurDir
                        | Component::ParentDir
                        | Component::RootDir
                        | Component::Prefix(_)
                )
            })
        {
            return Err(ConformanceError::new(
                code,
                Some(subject.to_owned()),
                format!(
                    "implementation pointer '{}' must be a repository-relative forward-slash path",
                    pointer.path
                ),
            ));
        }
        if forbidden_reference_path(path_text) {
            return Err(ConformanceError::new(
                code,
                Some(subject.to_owned()),
                format!(
                    "implementation pointer '{}' is not an eligible implementation path",
                    pointer.path
                ),
            ));
        }
        if pointer.note.trim().is_empty() {
            return Err(ConformanceError::new(
                code,
                Some(subject.to_owned()),
                "implementation pointer note must not be blank".to_owned(),
            ));
        }
        if !identities.insert((path_text, pointer.note.as_str())) {
            return Err(ConformanceError::new(
                code,
                Some(subject.to_owned()),
                "claim repeats the same implementation pointer".to_owned(),
            ));
        }
        let path = resolve_ordinal_file(repository_root, path_text).map_err(|error| {
            ConformanceError::new(
                code,
                Some(subject.to_owned()),
                format!(
                    "cannot resolve implementation pointer '{}': {error}",
                    pointer.path
                ),
            )
        })?;
        let Some(path) = path else {
            return Err(ConformanceError::new(
                code,
                Some(subject.to_owned()),
                format!("implementation pointer '{}' does not exist", pointer.path),
            ));
        };
        let canonical_root = repository_root.canonicalize().map_err(|error| {
            ConformanceError::new(
                code,
                Some(subject.to_owned()),
                format!("cannot resolve repository root: {error}"),
            )
        })?;
        let canonical_path = path.canonicalize().map_err(|error| {
            ConformanceError::new(
                code,
                Some(subject.to_owned()),
                format!(
                    "cannot resolve implementation pointer '{}': {error}",
                    pointer.path
                ),
            )
        })?;
        if !canonical_path.starts_with(&canonical_root) {
            return Err(ConformanceError::new(
                code,
                Some(subject.to_owned()),
                format!(
                    "implementation pointer '{}' resolves outside the repository root",
                    pointer.path
                ),
            ));
        };
    }
    Ok(())
}

fn valid_reference_path(value: &str) -> bool {
    !value.is_empty()
        && value.is_ascii()
        && value.split('/').all(|segment| {
            !segment.is_empty()
                && segment != "."
                && segment != ".."
                && segment
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-'))
        })
}

fn normalized_api_path(path: PathBuf) -> String {
    path.to_string_lossy().replace('\\', "/")
}

fn resolve_ordinal_file(
    repository_root: &Path,
    relative_path: &str,
) -> Result<Option<PathBuf>, std::io::Error> {
    let mut current = repository_root.to_path_buf();
    for segment in relative_path.split('/') {
        let mut exact = None;
        for entry in fs::read_dir(&current)? {
            let entry = entry?;
            if entry.file_name().to_str() == Some(segment) {
                if is_symlink_or_reparse(&fs::symlink_metadata(entry.path())?) {
                    return Ok(None);
                }
                exact = Some(entry.path());
                break;
            }
        }
        let Some(path) = exact else {
            return Ok(None);
        };
        current = path;
    }
    Ok(current.is_file().then_some(current))
}

fn is_symlink_or_reparse(metadata: &fs::Metadata) -> bool {
    if metadata.file_type().is_symlink() {
        return true;
    }
    #[cfg(windows)]
    {
        use std::os::windows::fs::MetadataExt as _;

        const FILE_ATTRIBUTE_REPARSE_POINT: u32 = 0x400;
        metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0
    }
    #[cfg(not(windows))]
    {
        false
    }
}

fn forbidden_reference_path(value: &str) -> bool {
    const PREFIXES: [&str; 6] = [
        "src/",
        "compat/legacy/",
        "node_modules/",
        "_upstream/",
        "packages/",
        "compat/upstream/",
    ];
    let lowered = value.to_ascii_lowercase();
    PREFIXES.iter().any(|prefix| lowered.starts_with(prefix))
        || [".ts", ".tsx", ".js", ".jsx", ".mjs", ".cjs"]
            .iter()
            .any(|extension| lowered.ends_with(extension))
}

fn valid_rust_test_path(value: &str) -> bool {
    !value.is_empty()
        && value.split("::").all(|segment| {
            let mut bytes = segment.bytes();
            bytes
                .next()
                .is_some_and(|byte| byte.is_ascii_lowercase() || byte == b'_')
                && bytes.all(|byte| byte.is_ascii_alphanumeric() || byte == b'_')
        })
}

#[derive(Clone, Debug, Eq, PartialEq)]
enum RustToken {
    Ident(String),
    Pound,
    Bang,
    OpenBracket,
    CloseBracket,
    OpenBrace,
    CloseBrace,
    OpenParen,
    CloseParen,
    ColonColon,
    Semi,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct RustAttribute {
    inner: bool,
    path: Vec<String>,
    tokens: Vec<RustToken>,
}

// This is the normative enabled-test decision. The transition validator ports
// this behavior and must be updated whenever this function changes.
fn declares_enabled_test(source: &str, test_name: &str) -> bool {
    let target = test_name.split("::").collect::<Vec<_>>();
    declares_in_items(&rust_tokens(source), 0, None, &[], &target)
}

fn declares_in_items(
    tokens: &[RustToken],
    start: usize,
    end: Option<usize>,
    modules: &[String],
    target: &[&str],
) -> bool {
    let end = end.unwrap_or(tokens.len());
    let mut index = start;
    while index < end {
        let item_start = index;
        let (parsed_attributes, after_attributes) = parse_attributes(tokens, index, end);
        let mut attributes = Vec::new();
        let mut inner_attributes = Vec::new();
        for attribute in parsed_attributes {
            if attribute.inner {
                inner_attributes.push(attribute);
            } else {
                attributes.push(attribute);
            }
        }
        if !module_attributes_enable_tests(&inner_attributes) {
            return false;
        }
        index = after_attributes;
        if index >= end {
            break;
        }
        index = skip_visibility(tokens, index, end);
        while matches!(
            tokens.get(index),
            Some(RustToken::Ident(value))
                if matches!(
                    value.as_str(),
                    "async" | "const" | "default" | "extern" | "unsafe"
                )
        ) {
            index += 1;
        }
        match (tokens.get(index), tokens.get(index + 1)) {
            (Some(RustToken::Ident(keyword)), Some(RustToken::Ident(name))) if keyword == "mod" => {
                if tokens.get(index + 2) == Some(&RustToken::OpenBrace) {
                    let open = index + 2;
                    let close = matching_delimiter(tokens, open, end).unwrap_or(end);
                    if module_attributes_enable_tests(&attributes) {
                        let mut nested = modules.to_vec();
                        nested.push(name.clone());
                        if declares_in_items(tokens, open + 1, Some(close), &nested, target) {
                            return true;
                        }
                    }
                    index = close.saturating_add(1);
                } else {
                    index = skip_item(tokens, index, end);
                }
            }
            (Some(RustToken::Ident(keyword)), Some(RustToken::Ident(name))) if keyword == "fn" => {
                if test_identity_matches(modules, name, target)
                    && attributes_declare_enabled_test(&attributes)
                {
                    return true;
                }
                index = skip_item(tokens, index + 2, end);
            }
            _ => index = skip_item(tokens, index, end),
        }
        if index <= item_start {
            index = item_start + 1;
        }
    }
    false
}

fn parse_attributes(
    tokens: &[RustToken],
    mut index: usize,
    end: usize,
) -> (Vec<RustAttribute>, usize) {
    let mut attributes = Vec::new();
    while tokens.get(index) == Some(&RustToken::Pound) {
        let inner = tokens.get(index + 1) == Some(&RustToken::Bang);
        let bracket = index + if inner { 2 } else { 1 };
        if tokens.get(bracket) != Some(&RustToken::OpenBracket) {
            break;
        }
        let close = matching_delimiter(tokens, bracket, end).unwrap_or(end);
        let mut path = Vec::new();
        let mut cursor = bracket + 1;
        if let Some(RustToken::Ident(segment)) = tokens.get(cursor) {
            path.push(segment.clone());
            cursor += 1;
            while tokens.get(cursor) == Some(&RustToken::ColonColon) {
                let Some(RustToken::Ident(segment)) = tokens.get(cursor + 1) else {
                    break;
                };
                path.push(segment.clone());
                cursor += 2;
            }
        }
        attributes.push(RustAttribute {
            inner,
            path,
            tokens: tokens[bracket + 1..close].to_vec(),
        });
        index = close.saturating_add(1);
    }
    (attributes, index)
}

fn attributes_declare_enabled_test(attributes: &[RustAttribute]) -> bool {
    let has_test = attributes.iter().any(|attribute| {
        attribute
            .path
            .last()
            .is_some_and(|segment| segment == "test")
    });
    let ignored = attributes.iter().any(|attribute| {
        attribute
            .path
            .first()
            .is_some_and(|segment| segment == "ignore")
    });
    let cfg_gated = attributes.iter().any(|attribute| {
        attribute
            .path
            .first()
            .is_some_and(|segment| matches!(segment.as_str(), "cfg" | "cfg_attr"))
    });
    has_test && !ignored && !cfg_gated
}

fn module_attributes_enable_tests(attributes: &[RustAttribute]) -> bool {
    attributes.iter().all(|attribute| {
        let Some(first) = attribute.path.first() else {
            return true;
        };
        if first == "ignore" || first == "cfg_attr" {
            return false;
        }
        if first != "cfg" {
            return true;
        }
        attribute.tokens.as_slice()
            == [
                RustToken::Ident("cfg".to_owned()),
                RustToken::OpenParen,
                RustToken::Ident("test".to_owned()),
                RustToken::CloseParen,
            ]
    })
}

fn test_identity_matches(modules: &[String], function: &str, target: &[&str]) -> bool {
    target.len() == modules.len() + 1
        && modules
            .iter()
            .zip(target)
            .all(|(actual, expected)| actual == expected)
        && target.last() == Some(&function)
}

fn skip_visibility(tokens: &[RustToken], mut index: usize, end: usize) -> usize {
    if !matches!(tokens.get(index), Some(RustToken::Ident(value)) if value == "pub") {
        return index;
    }
    index += 1;
    if tokens.get(index) == Some(&RustToken::OpenParen) {
        index = matching_delimiter(tokens, index, end)
            .unwrap_or(end)
            .saturating_add(1);
    }
    index
}

fn skip_item(tokens: &[RustToken], mut index: usize, end: usize) -> usize {
    while index < end {
        match &tokens[index] {
            RustToken::Semi => return index + 1,
            RustToken::OpenBrace => {
                return matching_delimiter(tokens, index, end)
                    .unwrap_or(end)
                    .saturating_add(1);
            }
            _ => index += 1,
        }
    }
    end
}

fn matching_delimiter(tokens: &[RustToken], open: usize, end: usize) -> Option<usize> {
    let (opening, closing) = match tokens.get(open)? {
        RustToken::OpenBracket => (RustToken::OpenBracket, RustToken::CloseBracket),
        RustToken::OpenBrace => (RustToken::OpenBrace, RustToken::CloseBrace),
        RustToken::OpenParen => (RustToken::OpenParen, RustToken::CloseParen),
        _ => return None,
    };
    let mut depth = 0_usize;
    for (index, token) in tokens.iter().enumerate().take(end).skip(open) {
        if token == &opening {
            depth += 1;
        } else if token == &closing {
            depth -= 1;
            if depth == 0 {
                return Some(index);
            }
        }
    }
    None
}

fn rust_tokens(source: &str) -> Vec<RustToken> {
    let bytes = source.as_bytes();
    let mut tokens = Vec::new();
    let mut index = 0_usize;
    while index < bytes.len() {
        if bytes[index].is_ascii_whitespace() {
            index += 1;
        } else if bytes.get(index..index + 2) == Some(b"//") {
            index += 2;
            while index < bytes.len() && bytes[index] != b'\n' {
                index += 1;
            }
        } else if bytes.get(index..index + 2) == Some(b"/*") {
            index = skip_block_comment(bytes, index);
        } else if let Some(end) = raw_string_end(bytes, index) {
            index = end;
        } else if bytes[index] == b'"'
            || (bytes[index] == b'b' && bytes.get(index + 1) == Some(&b'"'))
        {
            let quote = if bytes[index] == b'"' {
                index
            } else {
                index + 1
            };
            index = quoted_end(bytes, quote, b'"');
        } else if bytes[index] == b'\'' {
            index = char_literal_end(bytes, index).unwrap_or(index + 1);
        } else if bytes[index].is_ascii_alphabetic() || bytes[index] == b'_' {
            let start = index;
            index += 1;
            while index < bytes.len()
                && (bytes[index].is_ascii_alphanumeric() || bytes[index] == b'_')
            {
                index += 1;
            }
            tokens.push(RustToken::Ident(source[start..index].to_owned()));
        } else {
            match bytes[index] {
                b'#' => tokens.push(RustToken::Pound),
                b'!' => tokens.push(RustToken::Bang),
                b'[' => tokens.push(RustToken::OpenBracket),
                b']' => tokens.push(RustToken::CloseBracket),
                b'{' => tokens.push(RustToken::OpenBrace),
                b'}' => tokens.push(RustToken::CloseBrace),
                b'(' => tokens.push(RustToken::OpenParen),
                b')' => tokens.push(RustToken::CloseParen),
                b';' => tokens.push(RustToken::Semi),
                b':' if bytes.get(index + 1) == Some(&b':') => {
                    tokens.push(RustToken::ColonColon);
                    index += 1;
                }
                _ => {}
            }
            index += 1;
        }
    }
    tokens
}

fn skip_block_comment(bytes: &[u8], mut index: usize) -> usize {
    let mut depth = 0_usize;
    while index < bytes.len() {
        if bytes.get(index..index + 2) == Some(b"/*") {
            depth += 1;
            index += 2;
        } else if bytes.get(index..index + 2) == Some(b"*/") {
            depth -= 1;
            index += 2;
            if depth == 0 {
                return index;
            }
        } else {
            index += 1;
        }
    }
    index
}

fn raw_string_end(bytes: &[u8], index: usize) -> Option<usize> {
    let mut cursor = index;
    if bytes.get(cursor) == Some(&b'b') {
        cursor += 1;
    }
    if bytes.get(cursor) != Some(&b'r') {
        return None;
    }
    cursor += 1;
    let hashes = bytes[cursor..]
        .iter()
        .take_while(|byte| **byte == b'#')
        .count();
    cursor += hashes;
    if bytes.get(cursor) != Some(&b'"') {
        return None;
    }
    cursor += 1;
    while cursor < bytes.len() {
        if bytes[cursor] == b'"' {
            let suffix_is_hashes = bytes
                .get(cursor + 1..cursor + 1 + hashes)
                .is_some_and(|suffix| suffix.iter().all(|byte| *byte == b'#'));
            if suffix_is_hashes {
                return Some(cursor + 1 + hashes);
            }
        }
        cursor += 1;
    }
    Some(bytes.len())
}

fn quoted_end(bytes: &[u8], quote: usize, delimiter: u8) -> usize {
    let mut cursor = quote + 1;
    while cursor < bytes.len() {
        if bytes[cursor] == b'\\' {
            cursor = (cursor + 2).min(bytes.len());
        } else if bytes[cursor] == delimiter {
            return cursor + 1;
        } else {
            cursor += 1;
        }
    }
    cursor
}

fn char_literal_end(bytes: &[u8], quote: usize) -> Option<usize> {
    let mut cursor = quote + 1;
    if bytes.get(cursor) == Some(&b'\\') {
        cursor += 2;
    } else {
        cursor += 1;
    }
    (bytes.get(cursor) == Some(&b'\'')).then_some(cursor + 1)
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
        let detached_attribute = "#[test]\nfn real_test() {}\nfn exact_name() {}";
        assert!(!declares_enabled_test(detached_attribute, "exact_name"));
        let nested = "mod actual_module {\n#[test]\nfn exact_name() {}\n}";
        assert!(declares_enabled_test(nested, "actual_module::exact_name"));
        assert!(!declares_enabled_test(
            nested,
            "fabricated_module::exact_name"
        ));
        assert!(!declares_enabled_test(nested, "exact_name"));
        let conventional_test_module = "#[cfg(test)]\nmod tests {\n#[test]\nfn exact_name() {}\n}";
        assert!(declares_enabled_test(
            conventional_test_module,
            "tests::exact_name"
        ));
        let disabled_module = "#[cfg(any())]\nmod tests {\n#[test]\nfn exact_name() {}\n}";
        assert!(!declares_enabled_test(disabled_module, "tests::exact_name"));
        let feature_gated_module =
            "#[cfg(feature = \"off\")]\nmod tests {\n#[test]\nfn exact_name() {}\n}";
        assert!(!declares_enabled_test(
            feature_gated_module,
            "tests::exact_name"
        ));
        let disabled_outer_module =
            "#[cfg(any())]\nmod outer {\nmod tests {\n#[test]\nfn exact_name() {}\n}\n}";
        assert!(!declares_enabled_test(
            disabled_outer_module,
            "outer::tests::exact_name"
        ));
        let inner_disabled_module = "mod tests {\n#![cfg(any())]\n#[test]\nfn exact_name() {}\n}";
        assert!(!declares_enabled_test(
            inner_disabled_module,
            "tests::exact_name"
        ));
        let inner_feature_gated_file = "#![cfg(feature = \"off\")]\n#[test]\nfn exact_name() {}";
        assert!(!declares_enabled_test(
            inner_feature_gated_file,
            "exact_name"
        ));
        let inner_cfg_attr_module =
            "mod tests {\n#![cfg_attr(all(), allow(dead_code))]\n#[test]\nfn exact_name() {}\n}";
        assert!(!declares_enabled_test(
            inner_cfg_attr_module,
            "tests::exact_name"
        ));
        let inner_test_module = "mod tests {\n#![cfg(test)]\n#[test]\nfn exact_name() {}\n}";
        assert!(declares_enabled_test(
            inner_test_module,
            "tests::exact_name"
        ));
        let string_literal =
            "const SOURCE: &str = \"#[test] fn exact_name() {}\";\nfn ordinary() {}";
        assert!(!declares_enabled_test(string_literal, "exact_name"));
        let raw_string = "const SOURCE: &str = r#\"#[test] fn exact_name() {}\"#;";
        assert!(!declares_enabled_test(raw_string, "exact_name"));
    }
}

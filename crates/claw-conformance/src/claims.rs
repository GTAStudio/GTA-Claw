//! Typed implementation claims and evidence registration.

use std::collections::{BTreeMap, BTreeSet, VecDeque};
use std::env;
use std::fs;
use std::path::{Component, Path, PathBuf};
use std::process::Command;

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

#[derive(Debug, Deserialize)]
struct CargoMetadata {
    packages: Vec<CargoPackage>,
    workspace_root: PathBuf,
}

#[derive(Debug, Deserialize)]
struct CargoPackage {
    manifest_path: PathBuf,
    targets: Vec<CargoTarget>,
}

#[derive(Debug, Deserialize)]
struct CargoTarget {
    src_path: PathBuf,
    test: bool,
}

#[derive(Clone, Debug)]
pub(crate) struct CargoTestTargets {
    repository_root: PathBuf,
    source_paths: BTreeSet<PathBuf>,
}

impl CargoTestTargets {
    fn load(repository_root: &Path, code: ViolationCode) -> Result<Self, ConformanceError> {
        let canonical_root = repository_root.canonicalize().map_err(|error| {
            ConformanceError::new(
                code,
                Some("Cargo.toml".to_owned()),
                format!("cannot resolve repository root: {error}"),
            )
        })?;
        let manifests = discover_cargo_manifests(&canonical_root).map_err(|error| {
            ConformanceError::new(
                code,
                Some("Cargo.toml".to_owned()),
                format!("cannot discover Cargo manifests: {error}"),
            )
        })?;
        let mut processed_manifests = BTreeSet::new();
        let mut target_roots = BTreeSet::new();
        for manifest_path in manifests {
            let canonical_manifest = manifest_path.canonicalize().map_err(|error| {
                ConformanceError::new(
                    code,
                    Some("Cargo.toml".to_owned()),
                    format!(
                        "cannot resolve Cargo manifest '{}': {error}",
                        manifest_path.display()
                    ),
                )
            })?;
            if processed_manifests.contains(&canonical_manifest) {
                continue;
            }
            let metadata = load_cargo_metadata(&canonical_root, &canonical_manifest, code)?;
            let workspace_manifest = metadata.workspace_root.join("Cargo.toml");
            if let Ok(path) = workspace_manifest.canonicalize() {
                processed_manifests.insert(path);
            }
            for package in metadata.packages {
                if let Ok(path) = package.manifest_path.canonicalize() {
                    processed_manifests.insert(path);
                }
                for target in package.targets.into_iter().filter(|target| target.test) {
                    let source_path = target.src_path.canonicalize().map_err(|error| {
                        ConformanceError::new(
                            code,
                            Some("Cargo.toml".to_owned()),
                            format!(
                                "cannot resolve test-enabled Cargo target '{}': {error}",
                                target.src_path.display()
                            ),
                        )
                    })?;
                    if source_path.starts_with(&canonical_root) {
                        target_roots.insert(source_path);
                    }
                }
            }
        }
        let source_paths = reachable_rust_sources(&canonical_root, target_roots, code)?;
        Ok(Self {
            repository_root: canonical_root,
            source_paths,
        })
    }

    fn contains(&self, path: &Path) -> bool {
        self.source_paths.contains(path)
    }

    pub(crate) fn is_for_repository(&self, repository_root: &Path) -> bool {
        repository_root
            .canonicalize()
            .is_ok_and(|root| root == self.repository_root)
    }
}

fn load_cargo_metadata(
    repository_root: &Path,
    manifest_path: &Path,
    code: ViolationCode,
) -> Result<CargoMetadata, ConformanceError> {
    let cargo = env::var_os("CARGO").unwrap_or_else(|| "cargo".into());
    let output = Command::new(cargo)
        .current_dir(repository_root)
        .args(["metadata", "--format-version", "1", "--no-deps", "--locked"])
        .arg("--manifest-path")
        .arg(manifest_path)
        .output()
        .map_err(|error| {
            ConformanceError::new(
                code,
                Some("Cargo.toml".to_owned()),
                format!(
                    "cannot run cargo metadata for '{}': {error}",
                    manifest_path.display()
                ),
            )
        })?;
    if !output.status.success() {
        return Err(ConformanceError::new(
            code,
            Some("Cargo.toml".to_owned()),
            format!(
                "cargo metadata failed for '{}': {}",
                manifest_path.display(),
                String::from_utf8_lossy(&output.stderr).trim()
            ),
        ));
    }
    serde_json::from_slice(&output.stdout).map_err(|error| {
        ConformanceError::new(
            code,
            Some("Cargo.toml".to_owned()),
            format!(
                "cannot parse cargo metadata for '{}': {error}",
                manifest_path.display()
            ),
        )
    })
}

fn discover_cargo_manifests(repository_root: &Path) -> Result<Vec<PathBuf>, std::io::Error> {
    let mut manifests = Vec::new();
    let mut directories = VecDeque::from([repository_root.to_path_buf()]);
    while let Some(directory) = directories.pop_front() {
        for entry in fs::read_dir(directory)? {
            let entry = entry?;
            let path = entry.path();
            let metadata = fs::symlink_metadata(&path)?;
            if is_symlink_or_reparse(&metadata) {
                continue;
            }
            if metadata.is_dir() {
                if !matches!(
                    entry.file_name().to_str(),
                    Some(".git" | "target" | "node_modules")
                ) {
                    directories.push_back(path);
                }
            } else if metadata.is_file() && entry.file_name() == "Cargo.toml" {
                manifests.push(path);
            }
        }
    }
    manifests.sort_by(|left, right| {
        left.components()
            .count()
            .cmp(&right.components().count())
            .then_with(|| left.cmp(right))
    });
    Ok(manifests)
}

#[derive(Debug)]
struct ReachableRustSource {
    path: PathBuf,
    module_directory: PathBuf,
}

fn reachable_rust_sources(
    repository_root: &Path,
    target_roots: BTreeSet<PathBuf>,
    code: ViolationCode,
) -> Result<BTreeSet<PathBuf>, ConformanceError> {
    let mut reachable = target_roots.clone();
    let mut queue = target_roots
        .into_iter()
        .filter_map(|path| {
            let module_directory = path.parent()?.to_path_buf();
            Some(ReachableRustSource {
                path,
                module_directory,
            })
        })
        .collect::<VecDeque<_>>();

    while let Some(current) = queue.pop_front() {
        let source = fs::read_to_string(&current.path).map_err(|error| {
            ConformanceError::new(
                code,
                Some(normalized_api_path(
                    current
                        .path
                        .strip_prefix(repository_root)
                        .unwrap_or(&current.path)
                        .to_path_buf(),
                )),
                format!(
                    "cannot read test-enabled Cargo source '{}': {error}",
                    current.path.display()
                ),
            )
        })?;
        for reference in rust_module_references(&source) {
            let mut scope = current.module_directory.clone();
            for segment in &reference.inline_modules {
                scope.push(segment);
            }
            let candidates = if let Some(path) = &reference.path {
                let base = if reference.inline_modules.is_empty() {
                    current.path.parent().unwrap_or(&scope)
                } else {
                    &scope
                };
                vec![base.join(path)]
            } else {
                let child_directory = scope.join(&reference.name);
                vec![
                    scope.join(format!("{}.rs", reference.name)),
                    child_directory.join("mod.rs"),
                ]
            };
            for candidate in candidates {
                let Some(path) =
                    resolve_module_file(repository_root, &candidate).map_err(|error| {
                        ConformanceError::new(
                            code,
                            Some("Cargo.toml".to_owned()),
                            format!(
                                "cannot resolve Rust module source '{}': {error}",
                                candidate.display()
                            ),
                        )
                    })?
                else {
                    continue;
                };
                if reachable.insert(path.clone()) {
                    let module_directory = module_directory_for_source(&path);
                    queue.push_back(ReachableRustSource {
                        path,
                        module_directory,
                    });
                }
            }
        }
    }

    Ok(reachable)
}

fn module_directory_for_source(path: &Path) -> PathBuf {
    if path.file_name().is_some_and(|name| name == "mod.rs") {
        path.parent().unwrap_or(path).to_path_buf()
    } else if path.extension().is_some_and(|extension| extension == "rs") {
        path.with_extension("")
    } else {
        path.to_path_buf()
    }
}

fn resolve_module_file(
    repository_root: &Path,
    candidate: &Path,
) -> Result<Option<PathBuf>, std::io::Error> {
    let Some(relative) = normalized_repository_relative(repository_root, candidate) else {
        return Ok(None);
    };
    resolve_ordinal_file(repository_root, &normalized_api_path(relative))
}

fn normalized_repository_relative(repository_root: &Path, path: &Path) -> Option<PathBuf> {
    let relative = path.strip_prefix(repository_root).ok()?;
    let mut normalized = PathBuf::new();
    for component in relative.components() {
        match component {
            Component::Normal(segment) => normalized.push(segment),
            Component::CurDir => {}
            Component::ParentDir => {
                if !normalized.pop() {
                    return None;
                }
            }
            Component::Prefix(_) | Component::RootDir => return None,
        }
    }
    Some(normalized)
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
    cargo_test_targets: &mut Option<CargoTestTargets>,
) -> Result<(), ConformanceError> {
    validate_evidence_as(
        repository_root,
        subject,
        evidence,
        cargo_test_targets,
        ViolationCode::ClaimEvidence,
    )
}

pub(crate) fn validate_evidence_as(
    repository_root: &Path,
    subject: &str,
    evidence: &[Evidence],
    cargo_test_targets: &mut Option<CargoTestTargets>,
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
        if cargo_test_targets.is_none() {
            *cargo_test_targets = Some(CargoTestTargets::load(repository_root, code)?);
        }
        let is_test_target = cargo_test_targets
            .as_ref()
            .is_some_and(|targets| targets.contains(&canonical_path));
        if !is_test_target {
            return Err(ConformanceError::new(
                code,
                Some(subject.to_owned()),
                format!(
                    "evidence path '{}' is not reachable from a test-enabled Cargo target",
                    item.path
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
    Literal,
    StringLiteral(String),
    Other,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct RustAttribute {
    inner: bool,
    path: Vec<String>,
    tokens: Vec<RustToken>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct RustModuleReference {
    inline_modules: Vec<String>,
    name: String,
    path: Option<String>,
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
        index = skip_item_modifiers(tokens, index);
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

fn rust_module_references(source: &str) -> Vec<RustModuleReference> {
    let tokens = rust_tokens(source);
    let mut references = Vec::new();
    collect_rust_module_references(&tokens, 0, tokens.len(), &[], &mut references);
    references
}

fn collect_rust_module_references(
    tokens: &[RustToken],
    start: usize,
    end: usize,
    inline_modules: &[String],
    references: &mut Vec<RustModuleReference>,
) {
    let mut index = start;
    while index < end {
        let item_start = index;
        let (attributes, after_attributes) = parse_attributes(tokens, index, end);
        let outer_attributes = attributes
            .into_iter()
            .filter(|attribute| !attribute.inner)
            .collect::<Vec<_>>();
        index = skip_visibility(tokens, after_attributes, end);
        index = skip_item_modifiers(tokens, index);

        match (tokens.get(index), tokens.get(index + 1)) {
            (Some(RustToken::Ident(keyword)), Some(RustToken::Ident(name))) if keyword == "mod" => {
                if tokens.get(index + 2) == Some(&RustToken::OpenBrace) {
                    let open = index + 2;
                    let close = matching_delimiter(tokens, open, end).unwrap_or(end);
                    let mut nested = inline_modules.to_vec();
                    nested.push(name.clone());
                    collect_rust_module_references(tokens, open + 1, close, &nested, references);
                    index = close.saturating_add(1);
                } else if tokens.get(index + 2) == Some(&RustToken::Semi) {
                    references.push(RustModuleReference {
                        inline_modules: inline_modules.to_vec(),
                        name: name.clone(),
                        path: path_attribute_value(&outer_attributes),
                    });
                    index += 3;
                } else {
                    index = skip_item(tokens, index, end);
                }
            }
            _ => index = skip_item(tokens, index, end),
        }
        if index <= item_start {
            index = item_start + 1;
        }
    }
}

fn path_attribute_value(attributes: &[RustAttribute]) -> Option<String> {
    attributes.iter().find_map(|attribute| {
        (attribute.path.as_slice() == ["path"]).then(|| {
            attribute.tokens.iter().find_map(|token| match token {
                RustToken::StringLiteral(value) => Some(value.clone()),
                _ => None,
            })
        })?
    })
}

fn attributes_declare_enabled_test(attributes: &[RustAttribute]) -> bool {
    let has_test = attributes.iter().any(|attribute| {
        attribute
            .path
            .last()
            .is_some_and(|segment| segment == "test")
    });
    has_test && attributes.iter().all(attribute_enables_tests)
}

fn module_attributes_enable_tests(attributes: &[RustAttribute]) -> bool {
    attributes.iter().all(attribute_enables_tests)
}

fn attribute_enables_tests(attribute: &RustAttribute) -> bool {
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

fn skip_item_modifiers(tokens: &[RustToken], mut index: usize) -> usize {
    loop {
        match tokens.get(index) {
            Some(RustToken::Ident(value)) if value == "extern" => {
                index += 1;
                if matches!(
                    tokens.get(index),
                    Some(RustToken::Literal | RustToken::StringLiteral(_))
                ) {
                    index += 1;
                }
            }
            Some(RustToken::Ident(value))
                if matches!(value.as_str(), "async" | "const" | "default" | "unsafe") =>
            {
                index += 1;
            }
            _ => return index,
        }
    }
}

fn skip_item(tokens: &[RustToken], mut index: usize, end: usize) -> usize {
    let item_start = index;
    while index < end {
        if matches!(tokens.get(index), Some(RustToken::Ident(_)))
            && tokens.get(index + 1) == Some(&RustToken::Bang)
        {
            let Some(after_macro) = macro_invocation_end(tokens, index, end) else {
                return end;
            };
            let macro_is_item = macro_item_prefix(tokens, item_start, index);
            index = after_macro;
            if macro_is_item {
                if tokens.get(index) == Some(&RustToken::Semi) {
                    index += 1;
                }
                return index;
            }
            continue;
        }
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

fn macro_invocation_end(tokens: &[RustToken], index: usize, end: usize) -> Option<usize> {
    if !matches!(tokens.get(index), Some(RustToken::Ident(_)))
        || tokens.get(index + 1) != Some(&RustToken::Bang)
    {
        return None;
    }
    let mut open = index + 2;
    if matches!(tokens.get(index), Some(RustToken::Ident(name)) if name == "macro_rules")
        && matches!(tokens.get(open), Some(RustToken::Ident(_)))
    {
        open += 1;
    }
    if !matches!(
        tokens.get(open),
        Some(RustToken::OpenBracket | RustToken::OpenBrace | RustToken::OpenParen)
    ) {
        return None;
    }
    matching_delimiter(tokens, open, end).map(|close| close + 1)
}

fn macro_item_prefix(tokens: &[RustToken], start: usize, macro_name: usize) -> bool {
    let mut prefix = &tokens[start..=macro_name];
    if prefix.first() == Some(&RustToken::ColonColon) {
        prefix = &prefix[1..];
    }
    !prefix.is_empty()
        && prefix.iter().enumerate().all(|(offset, token)| {
            if offset % 2 == 0 {
                matches!(token, RustToken::Ident(_))
            } else {
                token == &RustToken::ColonColon
            }
        })
}

fn matching_delimiter(tokens: &[RustToken], open: usize, end: usize) -> Option<usize> {
    let mut expected = Vec::new();
    for (index, token) in tokens.iter().enumerate().take(end).skip(open) {
        let closing = match token {
            RustToken::OpenBracket => Some(RustToken::CloseBracket),
            RustToken::OpenBrace => Some(RustToken::CloseBrace),
            RustToken::OpenParen => Some(RustToken::CloseParen),
            _ => None,
        };
        if let Some(closing) = closing {
            expected.push(closing);
        } else if matches!(
            token,
            RustToken::CloseBracket | RustToken::CloseBrace | RustToken::CloseParen
        ) {
            if expected.pop().as_ref() != Some(token) {
                return None;
            }
            if expected.is_empty() {
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
        if bytes.get(index..index + 3) == Some(&[0xef, 0xbb, 0xbf]) {
            index += 3;
        } else if bytes[index].is_ascii_whitespace() {
            index += 1;
        } else if bytes.get(index..index + 2) == Some(b"//") {
            index += 2;
            while index < bytes.len() && bytes[index] != b'\n' {
                index += 1;
            }
        } else if bytes.get(index..index + 2) == Some(b"/*") {
            index = skip_block_comment(bytes, index);
        } else if let Some(end) = raw_string_end(bytes, index) {
            if let Some(value) = raw_string_value(source, index, end) {
                tokens.push(RustToken::StringLiteral(value));
            } else {
                tokens.push(RustToken::Literal);
            }
            index = end;
        } else if bytes[index] == b'"'
            || (bytes[index] == b'b' && bytes.get(index + 1) == Some(&b'"'))
        {
            let is_byte = bytes[index] == b'b';
            let quote = if bytes[index] == b'"' {
                index
            } else {
                index + 1
            };
            let end = quoted_end(bytes, quote, b'"');
            if !is_byte && bytes.get(end.saturating_sub(1)) == Some(&b'"') {
                tokens.push(RustToken::StringLiteral(
                    source[quote + 1..end - 1].to_owned(),
                ));
            } else {
                tokens.push(RustToken::Literal);
            }
            index = end;
        } else if bytes[index] == b'\'' {
            tokens.push(RustToken::Literal);
            index = char_literal_end(bytes, index).unwrap_or(index + 1);
        } else if bytes[index].is_ascii_alphabetic()
            || bytes[index] == b'_'
            || !bytes[index].is_ascii()
        {
            let start = index;
            index += if bytes[index].is_ascii() {
                1
            } else {
                source[index..].chars().next().map_or(1, char::len_utf8)
            };
            while index < bytes.len() {
                if bytes[index].is_ascii_alphanumeric() || bytes[index] == b'_' {
                    index += 1;
                } else if !bytes[index].is_ascii() {
                    index += source[index..].chars().next().map_or(1, char::len_utf8);
                } else {
                    break;
                }
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
                _ => tokens.push(RustToken::Other),
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

fn raw_string_value(source: &str, index: usize, end: usize) -> Option<String> {
    let bytes = source.as_bytes();
    if bytes.get(index) != Some(&b'r') {
        return None;
    }
    let hashes = bytes[index + 1..]
        .iter()
        .take_while(|byte| **byte == b'#')
        .count();
    let content_start = index + 2 + hashes;
    let content_end = end.checked_sub(1 + hashes)?;
    if bytes.get(index + 1 + hashes) != Some(&b'"')
        || bytes.get(content_end) != Some(&b'"')
        || content_end < content_start
    {
        return None;
    }
    source.get(content_start..content_end).map(str::to_owned)
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
    use std::collections::BTreeSet;
    use std::env;
    use std::fs;
    use std::path::PathBuf;
    use std::process::{Command, Output};
    use std::sync::atomic::{AtomicU64, Ordering};

    use serde::Deserialize;

    use super::{CargoTestTargets, declares_enabled_test};
    use crate::ViolationCode;

    static NEXT_COMPILER_ORACLE: AtomicU64 = AtomicU64::new(0);

    #[derive(Deserialize)]
    struct SharedOracleCorpus {
        cases: Vec<SharedOracleCase>,
    }

    #[derive(Deserialize)]
    struct SharedOracleCase {
        name: String,
        source: String,
        test: String,
        expected: bool,
    }

    struct CompilerOracleFixture {
        root: PathBuf,
    }

    impl CompilerOracleFixture {
        fn new(source: &str) -> Self {
            let root = env::temp_dir().join(format!(
                "claw-conformance-compiler-oracle-{}-{}",
                std::process::id(),
                NEXT_COMPILER_ORACLE.fetch_add(1, Ordering::Relaxed)
            ));
            let tests = root.join("tests");
            fs::create_dir_all(&tests).expect("create compiler oracle fixture");
            fs::write(
                root.join("Cargo.toml"),
                "[package]\n\
                 name = \"claw-conformance-compiler-oracle\"\n\
                 version = \"0.0.0\"\n\
                 edition = \"2024\"\n\n\
                 [[test]]\n\
                 name = \"oracle\"\n\
                 path = \"tests/oracle.rs\"\n",
            )
            .expect("write compiler oracle manifest");
            fs::write(tests.join("oracle.rs"), source).expect("write compiler oracle source");
            Self { root }
        }

        fn cargo_test_list(&self, ignored_only: bool) -> BTreeSet<String> {
            let cargo = env::var_os("CARGO").unwrap_or_else(|| "cargo".into());
            let mut command = Command::new(cargo);
            command
                .current_dir(&self.root)
                .env("CARGO_TARGET_DIR", self.root.join("target"))
                .args([
                    "test",
                    "--offline",
                    "--quiet",
                    "--manifest-path",
                    "Cargo.toml",
                    "--test",
                    "oracle",
                    "--",
                    "--list",
                    "--format",
                    "terse",
                ]);
            if ignored_only {
                command.arg("--ignored");
            }
            let output = command.output().expect("run compiler oracle");
            assert_command_succeeded(&output);
            String::from_utf8(output.stdout)
                .expect("compiler oracle output is UTF-8")
                .lines()
                .filter_map(|line| line.strip_suffix(": test").map(str::to_owned))
                .collect()
        }
    }

    impl Drop for CompilerOracleFixture {
        fn drop(&mut self) {
            if self.root.exists() {
                fs::remove_dir_all(&self.root).expect("remove compiler oracle fixture");
            }
        }
    }

    fn assert_command_succeeded(output: &Output) {
        assert!(
            output.status.success(),
            "compiler oracle failed:\nstdout:\n{}\nstderr:\n{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
    }

    #[test]
    fn evidence_requires_an_enabled_test_declaration() {
        let cases = [
            ("#[test]\nfn exact_name() {}", true),
            ("#[tokio::test]\nasync fn exact_name() {}", true),
            ("#[cfg(test)]\n#[test]\nfn exact_name() {}", true),
            (
                "#[cfg(test = \"disabled\")]\n#[test]\nfn exact_name() {}",
                false,
            ),
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
        let macro_tokens = "const _D: &str = stringify!({} #[test] fn forged_evidence_test() {});";
        assert!(!declares_enabled_test(macro_tokens, "forged_evidence_test"));
        let malformed_macro = "m!([); #[test] fn forged_evidence_test() {}])";
        assert!(!declares_enabled_test(
            malformed_macro,
            "forged_evidence_test"
        ));
    }

    #[test]
    fn cargo_test_listing_matches_enabled_test_detector() {
        let source = concat!(
            r#"
const _FORGED: &str = stringify!({} #[test] fn forged_evidence_test() {});
const _FORGED_BRACE: &str = stringify! { #[test] fn forged_brace_test() {} };
const _FORGED_BRACKET: &str = stringify![#[test] fn forged_bracket_test() {}];

macro_rules! discard {
    ($($tokens:tt)*) => {};
}
discard! {
    #[test]
    fn discarded_macro_test() {}
}

macro_rules! dormant {
    () => {
        #[test]
        fn macro_definition_test() {}
    };
}
"#,
            "macro_rules! \u{5b8f} { ($($tokens:tt)*) => {}; }\n",
            "\u{5b8f}!(const _: () = (); #[test] fn unicode_macro_test() {});\n",
            r#"
::std::thread_local! { static ABSOLUTE_MACRO_VALUE: u32 = 1; }

#[test]
fn after_absolute_macro() {}

#[test]
fn direct_test() {}

#[cfg(test)]
#[test]
fn cfg_test_function() {}

#[cfg(test = "disabled")]
#[test]
fn cfg_key_value_test() {}

#[test]
#[ignore]
fn ignored_test() {}

mod nested {
    #[test]
    fn nested_test() {}
}
"#
        );
        let fixture = CompilerOracleFixture::new(source);
        let listed = fixture.cargo_test_list(false);
        let ignored = fixture.cargo_test_list(true);
        let enabled = listed
            .difference(&ignored)
            .cloned()
            .collect::<BTreeSet<_>>();
        let identities = [
            "forged_evidence_test",
            "forged_brace_test",
            "forged_bracket_test",
            "discarded_macro_test",
            "macro_definition_test",
            "unicode_macro_test",
            "after_absolute_macro",
            "direct_test",
            "cfg_test_function",
            "cfg_key_value_test",
            "ignored_test",
            "nested::nested_test",
        ];
        for identity in identities {
            assert_eq!(
                declares_enabled_test(source, identity),
                enabled.contains(identity),
                "detector diverged from Cargo for {identity}"
            );
        }
    }

    #[test]
    fn cargo_test_listing_matches_module_reachability() {
        let root = env::temp_dir().join(format!(
            "claw-conformance-reachability-oracle-{}-{}",
            std::process::id(),
            NEXT_COMPILER_ORACLE.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir_all(root.join("src").join("outer").join("nested"))
            .expect("create nested module directory");
        fs::create_dir_all(root.join("src").join("custom"))
            .expect("create custom module directory");
        fs::write(
            root.join("Cargo.toml"),
            "[package]\n\
             name = \"claw-conformance-reachability-oracle\"\n\
             version = \"0.0.0\"\n\
             edition = \"2024\"\n\n\
             [[bin]]\n\
             name = \"disabled\"\n\
             path = \"src/disabled.rs\"\n\
             test = false\n",
        )
        .expect("write reachability manifest");
        fs::write(
            root.join("Cargo.lock"),
            "# This file is automatically @generated by Cargo.\n\
             # It is not intended for manual editing.\n\
             version = 4\n\n\
             [[package]]\n\
             name = \"claw-conformance-reachability-oracle\"\n\
             version = \"0.0.0\"\n",
        )
        .expect("write reachability lockfile");
        fs::write(
            root.join("src").join("lib.rs"),
            "#[test]\nfn root_test() {}\n\
             mod outer;\n\
             #[path = \"support/mod.rs\"]\nmod support;\n\
             #[path = r\"raw/raw_module.rs\"]\nmod raw;\n",
        )
        .expect("write reachability crate root");
        fs::write(
            root.join("src").join("outer.rs"),
            "mod nested {\n    mod proof;\n}\n\
             #[path = \"custom/from_outer.rs\"]\nmod from_outer;\n",
        )
        .expect("write outer module");
        fs::write(
            root.join("src")
                .join("outer")
                .join("nested")
                .join("proof.rs"),
            "#[test]\nfn deep_test() {}\n",
        )
        .expect("write deep module");
        fs::write(
            root.join("src").join("custom").join("from_outer.rs"),
            "#[test]\nfn outer_path_test() {}\n",
        )
        .expect("write path-attributed module from name.rs");
        fs::create_dir_all(root.join("src").join("outer").join("custom"))
            .expect("create path decoy directory");
        fs::write(
            root.join("src")
                .join("outer")
                .join("custom")
                .join("from_outer.rs"),
            "#[test]\nfn outer_path_decoy_test() {}\n",
        )
        .expect("write path-attributed decoy");
        fs::create_dir_all(root.join("src").join("support").join("mod"))
            .expect("create mod.rs decoy directory");
        fs::write(
            root.join("src").join("support").join("mod.rs"),
            "#[test]\nfn mod_rs_root_test() {}\nmod child;\n",
        )
        .expect("write path-attributed mod.rs");
        fs::write(
            root.join("src").join("support").join("child.rs"),
            "#[test]\nfn mod_rs_child_test() {}\n",
        )
        .expect("write mod.rs child");
        fs::write(
            root.join("src")
                .join("support")
                .join("mod")
                .join("child.rs"),
            "#[test]\nfn mod_rs_child_decoy_test() {}\n",
        )
        .expect("write mod.rs child decoy");
        fs::create_dir_all(root.join("src").join("raw")).expect("create raw path directory");
        fs::write(
            root.join("src").join("raw").join("raw_module.rs"),
            "#[test]\nfn raw_path_test() {}\n",
        )
        .expect("write raw path module");
        fs::write(
            root.join("src").join("orphan.rs"),
            "#[test]\nfn orphan_test() {}\n",
        )
        .expect("write orphan module");
        fs::write(
            root.join("src").join("disabled.rs"),
            "#[test]\nfn disabled_test() {}\nfn main() {}\n",
        )
        .expect("write test-disabled target");

        let cargo = env::var_os("CARGO").unwrap_or_else(|| "cargo".into());
        let output = Command::new(cargo)
            .current_dir(&root)
            .env("CARGO_TARGET_DIR", root.join("target"))
            .args([
                "test",
                "--offline",
                "--quiet",
                "--locked",
                "--lib",
                "--",
                "--list",
                "--format",
                "terse",
            ])
            .output()
            .expect("run reachability compiler oracle");
        assert_command_succeeded(&output);
        let listed = String::from_utf8(output.stdout)
            .expect("reachability oracle output is UTF-8")
            .lines()
            .filter_map(|line| line.strip_suffix(": test").map(str::to_owned))
            .collect::<BTreeSet<_>>();
        assert_eq!(
            listed,
            BTreeSet::from([
                "outer::nested::proof::deep_test".to_owned(),
                "outer::from_outer::outer_path_test".to_owned(),
                "raw::raw_path_test".to_owned(),
                "root_test".to_owned(),
                "support::child::mod_rs_child_test".to_owned(),
                "support::mod_rs_root_test".to_owned(),
            ])
        );

        let targets =
            CargoTestTargets::load(&root, ViolationCode::ClaimEvidence).expect("load target graph");
        for (path, test) in [
            ("src/lib.rs", "root_test"),
            (
                "src/outer/nested/proof.rs",
                "outer::nested::proof::deep_test",
            ),
            (
                "src/custom/from_outer.rs",
                "outer::from_outer::outer_path_test",
            ),
            (
                "src/outer/custom/from_outer.rs",
                "outer::from_outer::outer_path_decoy_test",
            ),
            ("src/support/mod.rs", "support::mod_rs_root_test"),
            ("src/support/child.rs", "support::child::mod_rs_child_test"),
            (
                "src/support/mod/child.rs",
                "support::child::mod_rs_child_decoy_test",
            ),
            ("src/raw/raw_module.rs", "raw::raw_path_test"),
            ("src/orphan.rs", "orphan_test"),
            ("src/disabled.rs", "disabled_test"),
        ] {
            let canonical = root.join(path).canonicalize().expect("canonical source");
            assert_eq!(
                targets.contains(&canonical),
                listed.contains(test),
                "reachability diverged from Cargo for {path}"
            );
        }
        fs::remove_dir_all(root).expect("remove reachability compiler oracle");
    }

    #[test]
    fn shared_enabled_test_oracle_corpus_matches() {
        let corpus: SharedOracleCorpus = serde_json::from_str(include_str!(
            "../../../compat/upstream/enabled-test-oracle.json"
        ))
        .expect("parse shared enabled-test oracle");
        assert_eq!(corpus.cases.len(), 85);
        for case in corpus.cases {
            assert_eq!(
                declares_enabled_test(&case.source, &case.test),
                case.expected,
                "{}",
                case.name
            );
        }
    }
}

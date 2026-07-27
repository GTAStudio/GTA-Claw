//! Typed implementation claims and evidence registration.

use std::collections::{BTreeMap, BTreeSet, VecDeque};
use std::env;
use std::ffi::{OsStr, OsString};
use std::fs::{self, File};
use std::io::{self, Read};
use std::path::{Component, Path, PathBuf};
use std::process::Command;
use std::sync::Arc;

use serde::{Deserialize, Serialize};

use crate::error::{ConformanceError, ViolationCode};

const MAX_CLAIMS_FILE_BYTES: u64 = 1024 * 1024;
const MAX_CARGO_MANIFEST_BYTES: u64 = 1024 * 1024;
const MAX_RUST_SOURCE_BYTES: u64 = 1024 * 1024;
const MAX_CACHED_EVIDENCE_SOURCE_BYTES: usize = 16 * 1024 * 1024;
const MAX_TOTAL_REACHABLE_RUST_BYTES: usize = 128 * 1024 * 1024;
const MAX_DISCOVERED_DIRECTORIES: usize = 65_536;
const MAX_DISCOVERED_MANIFESTS: usize = 4096;
const MAX_REACHABLE_RUST_SOURCES: usize = 20_000;
const MAX_EVIDENCE_ITEMS_PER_CLAIM: usize = 1024;

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
            path: normalized_api_path(&path.into()),
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
            path: normalized_api_path(&path.into()),
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
}

#[derive(Debug, Deserialize)]
struct CargoPackage {
    manifest_path: PathBuf,
    targets: Vec<CargoTarget>,
}

#[derive(Debug, Deserialize)]
struct CargoTarget {
    kind: Vec<String>,
    name: String,
    src_path: PathBuf,
    test: bool,
}

#[derive(Debug, Default, Deserialize)]
#[serde(default)]
struct CargoManifestTargets {
    #[serde(rename = "lib")]
    library: Option<CargoManifestTarget>,
    #[serde(rename = "bin")]
    binaries: Vec<CargoManifestTarget>,
    #[serde(rename = "test")]
    tests: Vec<CargoManifestTarget>,
    #[serde(rename = "bench")]
    benches: Vec<CargoManifestTarget>,
    #[serde(rename = "example")]
    examples: Vec<CargoManifestTarget>,
}

#[derive(Debug, Deserialize)]
struct CargoManifestTarget {
    name: Option<String>,
    path: Option<PathBuf>,
    harness: Option<bool>,
}

#[derive(Debug)]
struct CargoWorkspaceSpec {
    directory: PathBuf,
    members: Vec<String>,
    exclude: Vec<String>,
}

#[derive(Debug)]
struct CargoManifestScope {
    package: bool,
    workspace: Option<CargoWorkspaceSpec>,
}

impl CargoWorkspaceSpec {
    fn includes_package(&self, package_directory: &Path) -> bool {
        if package_directory == self.directory {
            return true;
        }
        let Ok(relative) = package_directory.strip_prefix(&self.directory) else {
            return false;
        };
        let relative = normalized_api_path(relative);
        if self
            .exclude
            .iter()
            .any(|pattern| cargo_exclude_pattern_covers(pattern, &relative))
        {
            return false;
        }
        self.members
            .iter()
            .any(|pattern| cargo_pattern_matches(pattern, &relative))
    }
}

impl CargoManifestTargets {
    fn uses_standard_test_harness(&self, package_directory: &Path, target: &CargoTarget) -> bool {
        let declaration = if target.kind.iter().any(|kind| kind == "bin") {
            matching_manifest_target(&self.binaries, package_directory, target)
        } else if target.kind.iter().any(|kind| kind == "test") {
            matching_manifest_target(&self.tests, package_directory, target)
        } else if target.kind.iter().any(|kind| kind == "bench") {
            matching_manifest_target(&self.benches, package_directory, target)
        } else if target.kind.iter().any(|kind| kind == "example") {
            matching_manifest_target(&self.examples, package_directory, target)
        } else {
            self.library.as_ref()
        };
        declaration.is_none_or(|declaration| declaration.harness != Some(false))
    }
}

fn matching_manifest_target<'a>(
    declarations: &'a [CargoManifestTarget],
    package_directory: &Path,
    target: &CargoTarget,
) -> Option<&'a CargoManifestTarget> {
    declarations.iter().find(|declaration| {
        declaration.name.as_deref() == Some(target.name.as_str())
            || declaration.path.as_ref().is_some_and(|path| {
                let declared = package_directory.join(path).canonicalize();
                let metadata = target.src_path.canonicalize();
                declared.is_ok_and(|declared| metadata.is_ok_and(|metadata| declared == metadata))
            })
    })
}

#[derive(Debug)]
pub(crate) struct CargoTestTargets {
    repository_root: PathBuf,
    source_paths: Arc<BTreeSet<PathBuf>>,
    resolver: OrdinalPathResolver,
    evidence_tokens: BTreeMap<PathBuf, Arc<[RustToken]>>,
    evidence_source_bytes: usize,
}

impl Clone for CargoTestTargets {
    fn clone(&self) -> Self {
        Self {
            repository_root: self.repository_root.clone(),
            source_paths: Arc::clone(&self.source_paths),
            resolver: OrdinalPathResolver::default(),
            evidence_tokens: self.evidence_tokens.clone(),
            evidence_source_bytes: self.evidence_source_bytes,
        }
    }
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
        let mut scoped_manifests = Vec::new();
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
            let scope = load_manifest_scope(&canonical_root, &canonical_manifest, code)?;
            scoped_manifests.push((canonical_manifest, scope));
        }
        let workspace_directories = scoped_manifests
            .iter()
            .filter_map(|(_, scope)| {
                scope
                    .workspace
                    .as_ref()
                    .map(|workspace| workspace.directory.clone())
            })
            .collect::<BTreeSet<_>>();
        let mut target_roots = BTreeSet::new();
        for (canonical_manifest, scope) in scoped_manifests {
            let package_directory = canonical_manifest
                .parent()
                .expect("a canonical Cargo manifest has a parent");
            let workspace = if let Some(workspace) = scope.workspace {
                workspace
            } else if scope.package
                && !workspace_directories
                    .iter()
                    .any(|directory| package_directory.starts_with(directory))
            {
                CargoWorkspaceSpec {
                    directory: package_directory.to_path_buf(),
                    members: Vec::new(),
                    exclude: Vec::new(),
                }
            } else {
                continue;
            };
            let metadata = load_cargo_metadata(&canonical_root, &canonical_manifest, code)?;
            for package in metadata.packages {
                let package_manifest = package.manifest_path.canonicalize().map_err(|error| {
                    ConformanceError::new(
                        code,
                        Some("Cargo.toml".to_owned()),
                        format!(
                            "cannot resolve Cargo package manifest '{}': {error}",
                            package.manifest_path.display()
                        ),
                    )
                })?;
                let package_directory = package_manifest.parent().ok_or_else(|| {
                    ConformanceError::new(
                        code,
                        Some("Cargo.toml".to_owned()),
                        format!(
                            "Cargo package manifest '{}' has no parent directory",
                            package_manifest.display()
                        ),
                    )
                })?;
                if !workspace.includes_package(package_directory) {
                    continue;
                }
                let manifest_targets =
                    load_manifest_targets(&canonical_root, &package_manifest, code)?;
                for target in package.targets.into_iter().filter(|target| {
                    target.test
                        && manifest_targets.uses_standard_test_harness(package_directory, target)
                }) {
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
                    if source_path.starts_with(package_directory) {
                        target_roots.insert((source_path, package_directory.to_path_buf()));
                    }
                }
            }
        }
        let mut resolver = OrdinalPathResolver::default();
        let source_paths =
            reachable_rust_sources(&canonical_root, target_roots, &mut resolver, code)?;
        Ok(Self {
            repository_root: canonical_root,
            source_paths: Arc::new(source_paths),
            resolver,
            evidence_tokens: BTreeMap::new(),
            evidence_source_bytes: 0,
        })
    }

    fn contains_compiled_source(&self, path: &Path) -> bool {
        self.source_paths.contains(path)
    }

    fn resolve_file(&mut self, relative_path: &str) -> io::Result<Option<PathBuf>> {
        self.resolver
            .resolve_file(&self.repository_root, relative_path)
    }

    fn declares_enabled_test(&mut self, path: &Path, test_name: &str) -> io::Result<bool> {
        if !self.evidence_tokens.contains_key(path) {
            let source = read_utf8_file_bounded(path, MAX_RUST_SOURCE_BYTES)?;
            let cached_bytes = self
                .evidence_source_bytes
                .checked_add(source.len())
                .ok_or_else(|| {
                    io::Error::new(
                        io::ErrorKind::InvalidData,
                        "cached evidence source byte count overflowed",
                    )
                })?;
            if cached_bytes > MAX_CACHED_EVIDENCE_SOURCE_BYTES {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!(
                        "evidence sources exceed the {MAX_CACHED_EVIDENCE_SOURCE_BYTES}-byte cache limit"
                    ),
                ));
            }
            self.evidence_tokens
                .insert(path.to_path_buf(), Arc::from(rust_tokens(&source)));
            self.evidence_source_bytes = cached_bytes;
        }
        Ok(self
            .evidence_tokens
            .get(path)
            .is_some_and(|tokens| declares_enabled_test_tokens(tokens.as_ref(), test_name)))
    }

    pub(crate) fn is_for_repository(&self, repository_root: &Path) -> bool {
        repository_root
            .canonicalize()
            .is_ok_and(|root| root == self.repository_root)
    }
}

fn load_manifest_scope(
    repository_root: &Path,
    manifest_path: &Path,
    code: ViolationCode,
) -> Result<CargoManifestScope, ConformanceError> {
    let subject = normalized_api_path(
        manifest_path
            .strip_prefix(repository_root)
            .unwrap_or(manifest_path),
    );
    let source =
        read_utf8_file_bounded(manifest_path, MAX_CARGO_MANIFEST_BYTES).map_err(|error| {
            ConformanceError::new(
                code,
                Some(subject.clone()),
                format!("cannot read Cargo manifest: {error}"),
            )
        })?;
    let document = source.parse::<toml_edit::DocumentMut>().map_err(|error| {
        ConformanceError::new(
            code,
            Some(subject),
            format!("cannot parse Cargo manifest: {error}"),
        )
    })?;
    let package = document
        .get("package")
        .and_then(toml_edit::Item::as_table)
        .is_some_and(|package| !package.is_implicit());
    let Some(workspace) = document
        .get("workspace")
        .and_then(toml_edit::Item::as_table)
        .filter(|workspace| !workspace.is_implicit())
    else {
        return Ok(CargoManifestScope {
            package,
            workspace: None,
        });
    };
    let strings = |key: &str| {
        workspace
            .get(key)
            .and_then(toml_edit::Item::as_array)
            .into_iter()
            .flat_map(|values| values.iter())
            .filter_map(toml_edit::Value::as_str)
            .map(|value| value.trim_end_matches('/').to_owned())
            .filter(|value| !value.is_empty())
            .collect::<Vec<_>>()
    };
    let directory = manifest_path
        .parent()
        .expect("a canonical Cargo manifest has a parent")
        .to_path_buf();
    Ok(CargoManifestScope {
        package,
        workspace: Some(CargoWorkspaceSpec {
            directory,
            members: strings("members"),
            exclude: strings("exclude"),
        }),
    })
}

fn cargo_exclude_pattern_covers(pattern: &str, relative_directory: &str) -> bool {
    let mut prefix = String::new();
    relative_directory.split('/').any(|segment| {
        if !prefix.is_empty() {
            prefix.push('/');
        }
        prefix.push_str(segment);
        cargo_pattern_matches(pattern, &prefix)
    })
}

fn cargo_pattern_matches(pattern: &str, candidate: &str) -> bool {
    fn matches(
        pattern: &[char],
        candidate: &[char],
        pattern_index: usize,
        candidate_index: usize,
        memo: &mut BTreeMap<(usize, usize), bool>,
    ) -> bool {
        if let Some(result) = memo.get(&(pattern_index, candidate_index)) {
            return *result;
        }
        let result = if pattern_index == pattern.len() {
            candidate_index == candidate.len()
        } else if pattern[pattern_index] == '*' && pattern.get(pattern_index + 1) == Some(&'*') {
            matches(pattern, candidate, pattern_index + 2, candidate_index, memo)
                || (candidate_index < candidate.len()
                    && matches(pattern, candidate, pattern_index, candidate_index + 1, memo))
        } else if pattern[pattern_index] == '*' {
            matches(pattern, candidate, pattern_index + 1, candidate_index, memo)
                || (candidate
                    .get(candidate_index)
                    .is_some_and(|value| *value != '/')
                    && matches(pattern, candidate, pattern_index, candidate_index + 1, memo))
        } else if pattern[pattern_index] == '?' {
            candidate
                .get(candidate_index)
                .is_some_and(|value| *value != '/')
                && matches(
                    pattern,
                    candidate,
                    pattern_index + 1,
                    candidate_index + 1,
                    memo,
                )
        } else {
            candidate.get(candidate_index) == Some(&pattern[pattern_index])
                && matches(
                    pattern,
                    candidate,
                    pattern_index + 1,
                    candidate_index + 1,
                    memo,
                )
        };
        memo.insert((pattern_index, candidate_index), result);
        result
    }

    let pattern = pattern.chars().collect::<Vec<_>>();
    let candidate = candidate.chars().collect::<Vec<_>>();
    matches(&pattern, &candidate, 0, 0, &mut BTreeMap::new())
}

fn load_manifest_targets(
    repository_root: &Path,
    manifest_path: &Path,
    code: ViolationCode,
) -> Result<CargoManifestTargets, ConformanceError> {
    let subject = normalized_api_path(
        manifest_path
            .strip_prefix(repository_root)
            .unwrap_or(manifest_path),
    );
    let source =
        read_utf8_file_bounded(manifest_path, MAX_CARGO_MANIFEST_BYTES).map_err(|error| {
            ConformanceError::new(
                code,
                Some(subject.clone()),
                format!("cannot read Cargo manifest: {error}"),
            )
        })?;
    toml::from_str(&source).map_err(|error| {
        ConformanceError::new(
            code,
            Some(subject),
            format!("cannot parse Cargo manifest: {error}"),
        )
    })
}

fn load_cargo_metadata(
    repository_root: &Path,
    manifest_path: &Path,
    code: ViolationCode,
) -> Result<CargoMetadata, ConformanceError> {
    let cargo = cargo_executable(repository_root, code)?;
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

fn cargo_executable(
    repository_root: &Path,
    code: ViolationCode,
) -> Result<PathBuf, ConformanceError> {
    let configured = env::var_os("CARGO");
    let search_path = env::var_os("PATH");
    resolve_cargo_executable(
        repository_root,
        configured.as_deref(),
        search_path.as_deref(),
    )
    .map_err(|message| {
        ConformanceError::new(
            code,
            Some("Cargo.toml".to_owned()),
            format!("cannot resolve trusted Cargo executable: {message}"),
        )
    })
}

fn resolve_cargo_executable(
    repository_root: &Path,
    configured: Option<&OsStr>,
    search_path: Option<&OsStr>,
) -> Result<PathBuf, String> {
    resolve_external_executable(
        repository_root,
        "CARGO",
        configured,
        &format!("cargo{}", env::consts::EXE_SUFFIX),
        search_path,
    )
}

fn resolve_external_executable(
    repository_root: &Path,
    variable: &str,
    configured: Option<&OsStr>,
    default_name: &str,
    search_path: Option<&OsStr>,
) -> Result<PathBuf, String> {
    let configured = configured.map(PathBuf::from);
    if let Some(path) = configured
        .as_ref()
        .filter(|path| path.components().count() > 1)
    {
        if !path.is_absolute() {
            return Err(format!(
                "{variable} names a relative path '{}'",
                path.display()
            ));
        }
        return trusted_executable(repository_root, path);
    }

    let executable_name = configured
        .and_then(|path| path.file_name().map(OsString::from))
        .unwrap_or_else(|| OsString::from(default_name));
    let search_path = search_path.ok_or_else(|| "PATH is not set".to_owned())?;
    for directory in env::split_paths(search_path).filter(|directory| directory.is_absolute()) {
        let candidate = directory.join(&executable_name);
        if candidate.is_file() {
            return trusted_executable(repository_root, &candidate);
        }
    }
    Err(format!(
        "'{}' was not found in an absolute PATH directory",
        Path::new(&executable_name).display()
    ))
}

fn trusted_executable(repository_root: &Path, candidate: &Path) -> Result<PathBuf, String> {
    let executable = candidate
        .canonicalize()
        .map_err(|error| format!("cannot resolve '{}': {error}", candidate.display()))?;
    let repository_root = repository_root
        .canonicalize()
        .map_err(|error| format!("cannot resolve repository root: {error}"))?;
    if executable.starts_with(repository_root) {
        return Err(format!(
            "resolved executable '{}' is inside the repository under validation",
            executable.display()
        ));
    }
    Ok(executable)
}

fn read_file_bounded(path: &Path, max_bytes: u64) -> io::Result<Vec<u8>> {
    let file = File::open(path)?;
    let reported_size = file.metadata()?.len();
    if reported_size > max_bytes {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!(
                "'{}' is {reported_size} bytes and exceeds the {max_bytes}-byte limit",
                path.display()
            ),
        ));
    }
    let mut bytes = Vec::with_capacity(
        usize::try_from(reported_size)
            .unwrap_or(usize::MAX)
            .min(usize::try_from(max_bytes).unwrap_or(usize::MAX)),
    );
    file.take(max_bytes + 1).read_to_end(&mut bytes)?;
    if u64::try_from(bytes.len()).unwrap_or(u64::MAX) > max_bytes {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!(
                "'{}' grew beyond the {max_bytes}-byte limit while it was read",
                path.display()
            ),
        ));
    }
    Ok(bytes)
}

fn read_utf8_file_bounded(path: &Path, max_bytes: u64) -> io::Result<String> {
    String::from_utf8(read_file_bounded(path, max_bytes)?)
        .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error))
}

fn discover_cargo_manifests(repository_root: &Path) -> Result<Vec<PathBuf>, std::io::Error> {
    let mut manifests = Vec::new();
    let mut directories = VecDeque::from([repository_root.to_path_buf()]);
    let mut discovered_directories = 1_usize;
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
                    discovered_directories += 1;
                    if discovered_directories > MAX_DISCOVERED_DIRECTORIES {
                        return Err(io::Error::new(
                            io::ErrorKind::InvalidData,
                            format!(
                                "repository traversal exceeded {MAX_DISCOVERED_DIRECTORIES} directories"
                            ),
                        ));
                    }
                    directories.push_back(path);
                }
            } else if metadata.is_file() && entry.file_name() == "Cargo.toml" {
                manifests.push(path);
                if manifests.len() > MAX_DISCOVERED_MANIFESTS {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        format!(
                            "repository traversal exceeded {MAX_DISCOVERED_MANIFESTS} Cargo manifests"
                        ),
                    ));
                }
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
    package_directory: PathBuf,
}

fn reachable_rust_sources(
    repository_root: &Path,
    target_roots: BTreeSet<(PathBuf, PathBuf)>,
    resolver: &mut OrdinalPathResolver,
    code: ViolationCode,
) -> Result<BTreeSet<PathBuf>, ConformanceError> {
    if target_roots.len() > MAX_REACHABLE_RUST_SOURCES {
        return Err(ConformanceError::new(
            code,
            Some("Cargo.toml".to_owned()),
            format!(
                "test-enabled Cargo targets exceed the {MAX_REACHABLE_RUST_SOURCES}-source reachability limit"
            ),
        ));
    }
    let mut reachable = target_roots
        .iter()
        .map(|(path, _)| path.clone())
        .collect::<BTreeSet<_>>();
    let mut visited = target_roots.clone();
    let mut queue = target_roots
        .into_iter()
        .filter_map(|(path, package_directory)| {
            let module_directory = path.parent()?.to_path_buf();
            Some(ReachableRustSource {
                path,
                module_directory,
                package_directory,
            })
        })
        .collect::<VecDeque<_>>();
    let mut total_source_bytes = 0_usize;

    while let Some(current) = queue.pop_front() {
        let source =
            read_utf8_file_bounded(&current.path, MAX_RUST_SOURCE_BYTES).map_err(|error| {
                ConformanceError::new(
                    code,
                    Some(normalized_api_path(
                        current
                            .path
                            .strip_prefix(repository_root)
                            .unwrap_or(&current.path),
                    )),
                    format!(
                        "cannot read test-enabled Cargo source '{}': {error}",
                        current.path.display()
                    ),
                )
            })?;
        total_source_bytes = total_source_bytes
            .checked_add(source.len())
            .ok_or_else(|| {
                ConformanceError::new(
                    code,
                    Some("Cargo.toml".to_owned()),
                    "reachable Rust source byte count overflowed".to_owned(),
                )
            })?;
        if total_source_bytes > MAX_TOTAL_REACHABLE_RUST_BYTES {
            return Err(ConformanceError::new(
                code,
                Some("Cargo.toml".to_owned()),
                format!(
                    "reachable Rust sources exceed the {MAX_TOTAL_REACHABLE_RUST_BYTES}-byte traversal limit"
                ),
            ));
        }
        let tokens = rust_tokens(&source);
        for reference in rust_module_references_from_tokens(&tokens) {
            let mut scope = current.module_directory.clone();
            for (index, directory) in reference.inline_modules.iter().enumerate() {
                match directory {
                    InlineModuleDirectory::Default(name) => scope.push(name),
                    InlineModuleDirectory::Path(path) if index == 0 => {
                        scope = current.path.parent().unwrap_or(&scope).join(path);
                    }
                    InlineModuleDirectory::Path(path) => scope.push(path),
                }
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
            let mut resolved_paths = Vec::new();
            for candidate in candidates {
                let Some(path) =
                    resolve_module_file(&current.package_directory, &candidate, resolver).map_err(
                        |error| {
                            ConformanceError::new(
                                code,
                                Some("Cargo.toml".to_owned()),
                                format!(
                                    "cannot resolve Rust module source '{}': {error}",
                                    candidate.display()
                                ),
                            )
                        },
                    )?
                else {
                    continue;
                };
                resolved_paths.push(path);
            }
            if reference.path.is_none() && resolved_paths.len() > 1 {
                return Err(ConformanceError::new(
                    code,
                    Some(normalized_api_path(
                        current
                            .path
                            .strip_prefix(repository_root)
                            .unwrap_or(&current.path),
                    )),
                    format!(
                        "Rust module '{}' is ambiguous because both '{}.rs' and '{}/mod.rs' exist",
                        reference.name, reference.name, reference.name
                    ),
                ));
            }
            for path in resolved_paths {
                if visited.insert((path.clone(), current.package_directory.clone())) {
                    if reachable.len() >= MAX_REACHABLE_RUST_SOURCES {
                        return Err(ConformanceError::new(
                            code,
                            Some("Cargo.toml".to_owned()),
                            format!(
                                "Rust module reachability exceeded {MAX_REACHABLE_RUST_SOURCES} sources"
                            ),
                        ));
                    }
                    reachable.insert(path.clone());
                    let module_directory = module_directory_for_source(&path);
                    queue.push_back(ReachableRustSource {
                        path,
                        module_directory,
                        package_directory: current.package_directory.clone(),
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
    resolver: &mut OrdinalPathResolver,
) -> Result<Option<PathBuf>, std::io::Error> {
    let Some(relative) = normalized_repository_relative(repository_root, candidate) else {
        return Ok(None);
    };
    resolver.resolve_file(repository_root, &normalized_api_path(&relative))
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
    ///
    /// # Errors
    ///
    /// Returns a [`ViolationCode::DuplicateClaim`] error when a claim for the
    /// same frozen feature ID has already been registered. Two claims for one
    /// row cannot both be authoritative, so the harness refuses the second
    /// instead of letting it silently replace the first.
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
    ///
    /// # Errors
    ///
    /// Returns a [`ViolationCode::DuplicateClaim`] error when a claim for the
    /// same `(inventory ID, record ID)` pair has already been registered, so a
    /// second claim can never overwrite the first unnoticed.
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
    ///
    /// # Errors
    ///
    /// Returns a [`ViolationCode::Io`] error when `path` cannot be read, and a
    /// [`ViolationCode::JsonSchema`] error carrying the exact serde JSON path
    /// when the manifest does not match [`ClaimsFile`], contains an unknown
    /// member, has trailing content after the document, declares a
    /// `schema_version` other than `1`, or leaves `crate_name` blank. A
    /// [`ViolationCode::DuplicateClaim`] error is returned when one of the
    /// contained claims collides with a claim already in the registry.
    pub fn load_claims_file(&mut self, path: impl AsRef<Path>) -> Result<(), ConformanceError> {
        let path = path.as_ref();
        let bytes = read_file_bounded(path, MAX_CLAIMS_FILE_BYTES).map_err(|error| {
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
///
/// # Errors
///
/// Returns a [`ViolationCode::Io`] error when `apps/` or `crates/` exists but a
/// directory beneath it cannot be listed. Discovery is silent about missing
/// top-level directories, but never about an unreadable one: skipping it would
/// quietly drop every claim a whole subtree publishes.
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
    if evidence.len() > MAX_EVIDENCE_ITEMS_PER_CLAIM {
        return Err(ConformanceError::new(
            code,
            Some(subject.to_owned()),
            format!(
                "claim has {} evidence artifacts and exceeds the {MAX_EVIDENCE_ITEMS_PER_CLAIM}-artifact limit",
                evidence.len()
            ),
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
        if cargo_test_targets.is_none() {
            *cargo_test_targets = Some(CargoTestTargets::load(repository_root, code)?);
        }
        let targets = cargo_test_targets
            .as_mut()
            .expect("Cargo test targets were initialized");
        let path = targets.resolve_file(path_text).map_err(|error| {
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
        let canonical_path = path.canonicalize().map_err(|error| {
            ConformanceError::new(
                code,
                Some(subject.to_owned()),
                format!("cannot resolve evidence file '{}': {error}", item.path),
            )
        })?;
        if !canonical_path.starts_with(&targets.repository_root) {
            return Err(ConformanceError::new(
                code,
                Some(subject.to_owned()),
                format!(
                    "evidence file '{}' resolves outside the repository root",
                    item.path
                ),
            ));
        }
        let declared = targets
            .declares_enabled_test(&canonical_path, &item.test)
            .map_err(|error| {
                ConformanceError::new(
                    code,
                    Some(subject.to_owned()),
                    format!("cannot read evidence file '{}': {error}", item.path),
                )
            })?;
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
        if !targets.contains_compiled_source(&canonical_path) {
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
        }
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

fn normalized_api_path(path: &Path) -> String {
    path.to_string_lossy().replace('\\', "/")
}

#[derive(Clone, Debug)]
struct OrdinalEntry {
    path: PathBuf,
    is_file: bool,
    is_symlink_or_reparse: bool,
}

#[derive(Debug, Default)]
struct OrdinalPathResolver {
    directories: BTreeMap<PathBuf, BTreeMap<OsString, OrdinalEntry>>,
    directory_reads: usize,
}

impl OrdinalPathResolver {
    fn resolve_file(
        &mut self,
        repository_root: &Path,
        relative_path: &str,
    ) -> io::Result<Option<PathBuf>> {
        let mut current = repository_root.to_path_buf();
        let mut is_file = false;
        for segment in relative_path.split('/') {
            let entry = self
                .directory_entries(&current)?
                .get(OsStr::new(segment))
                .cloned();
            let Some(entry) = entry else {
                return Ok(None);
            };
            if entry.is_symlink_or_reparse {
                return Ok(None);
            }
            is_file = entry.is_file;
            current = entry.path;
        }
        Ok(is_file.then_some(current))
    }

    fn directory_entries(
        &mut self,
        directory: &Path,
    ) -> io::Result<&BTreeMap<OsString, OrdinalEntry>> {
        if !self.directories.contains_key(directory) {
            let mut entries = BTreeMap::new();
            for entry in fs::read_dir(directory)? {
                let entry = entry?;
                let metadata = fs::symlink_metadata(entry.path())?;
                entries.insert(
                    entry.file_name(),
                    OrdinalEntry {
                        path: entry.path(),
                        is_file: metadata.is_file(),
                        is_symlink_or_reparse: is_symlink_or_reparse(&metadata),
                    },
                );
            }
            self.directory_reads += 1;
            self.directories.insert(directory.to_path_buf(), entries);
        }
        Ok(self
            .directories
            .get(directory)
            .expect("directory cache was populated"))
    }
}

fn resolve_ordinal_file(
    repository_root: &Path,
    relative_path: &str,
) -> Result<Option<PathBuf>, std::io::Error> {
    OrdinalPathResolver::default().resolve_file(repository_root, relative_path)
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
    Equals,
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
    inline_modules: Vec<InlineModuleDirectory>,
    name: String,
    path: Option<String>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
enum PathAttribute {
    Absent,
    Value(String),
    Invalid,
}

#[derive(Clone, Debug, Eq, PartialEq)]
enum InlineModuleDirectory {
    Default(String),
    Path(String),
}

// This is the normative enabled-test decision. The transition validator ports
// this behavior and must be updated whenever this function changes.
#[cfg(test)]
fn declares_enabled_test(source: &str, test_name: &str) -> bool {
    declares_enabled_test_tokens(&rust_tokens(source), test_name)
}

fn declares_enabled_test_tokens(tokens: &[RustToken], test_name: &str) -> bool {
    let target = test_name.split("::").collect::<Vec<_>>();
    declares_in_items(tokens, 0, None, &[], &target)
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

fn rust_module_references_from_tokens(tokens: &[RustToken]) -> Vec<RustModuleReference> {
    let mut references = Vec::new();
    collect_rust_module_references(tokens, 0, tokens.len(), &[], &mut references);
    references
}

fn collect_rust_module_references(
    tokens: &[RustToken],
    start: usize,
    end: usize,
    inline_modules: &[InlineModuleDirectory],
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
                    match path_attribute(&outer_attributes) {
                        PathAttribute::Absent => {
                            nested.push(InlineModuleDirectory::Default(name.clone()));
                            collect_rust_module_references(
                                tokens,
                                open + 1,
                                close,
                                &nested,
                                references,
                            );
                        }
                        PathAttribute::Value(path) => {
                            nested.push(InlineModuleDirectory::Path(path));
                            collect_rust_module_references(
                                tokens,
                                open + 1,
                                close,
                                &nested,
                                references,
                            );
                        }
                        PathAttribute::Invalid => {}
                    }
                    index = close.saturating_add(1);
                } else if tokens.get(index + 2) == Some(&RustToken::Semi) {
                    match path_attribute(&outer_attributes) {
                        PathAttribute::Absent => references.push(RustModuleReference {
                            inline_modules: inline_modules.to_vec(),
                            name: name.clone(),
                            path: None,
                        }),
                        PathAttribute::Value(path) => references.push(RustModuleReference {
                            inline_modules: inline_modules.to_vec(),
                            name: name.clone(),
                            path: Some(path),
                        }),
                        PathAttribute::Invalid => {}
                    }
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

fn path_attribute(attributes: &[RustAttribute]) -> PathAttribute {
    let mut paths = attributes
        .iter()
        .filter(|attribute| attribute.path.as_slice() == ["path"]);
    let Some(attribute) = paths.next() else {
        return PathAttribute::Absent;
    };
    if paths.next().is_some() {
        return PathAttribute::Invalid;
    }
    match attribute.tokens.as_slice() {
        [
            RustToken::Ident(name),
            RustToken::Equals,
            RustToken::StringLiteral(value),
        ] if name == "path" => PathAttribute::Value(value.clone()),
        _ => PathAttribute::Invalid,
    }
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
                b'=' => tokens.push(RustToken::Equals),
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
    use std::collections::{BTreeMap, BTreeSet};
    use std::env;
    use std::fs;
    use std::path::{Path, PathBuf};
    use std::process::{Command, Output};
    use std::sync::Arc;
    use std::sync::atomic::{AtomicU64, Ordering};

    use serde::Deserialize;

    use super::{
        CargoTestTargets, OrdinalPathResolver, cargo_executable, cargo_pattern_matches,
        declares_enabled_test, load_manifest_scope, normalized_api_path, read_file_bounded,
        resolve_cargo_executable, resolve_external_executable,
    };
    use crate::ViolationCode;

    static NEXT_COMPILER_ORACLE: AtomicU64 = AtomicU64::new(0);
    const COMPILER_ORACLE_WARNING_ENV: [&str; 4] = [
        "RUSTFLAGS",
        "CARGO_ENCODED_RUSTFLAGS",
        "CARGO_BUILD_RUSTFLAGS",
        "CARGO_BUILD_WARNINGS",
    ];

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

    #[derive(Deserialize)]
    struct ReachabilityCorpus {
        cases: Vec<ReachabilityCase>,
    }

    #[derive(Deserialize)]
    struct ReachabilityCase {
        name: String,
        files: BTreeMap<String, String>,
        cite: String,
        expect: String,
    }

    struct CompilerOracleFixture {
        root: PathBuf,
    }

    fn compiler_oracle_command(cargo: &Path, root: &Path) -> Command {
        let mut command = Command::new(cargo);
        command
            .current_dir(root)
            .env("CARGO_TARGET_DIR", root.join("target"));
        for variable in COMPILER_ORACLE_WARNING_ENV {
            command.env_remove(variable);
        }
        command
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
            let cargo = cargo_executable(&self.root, ViolationCode::ClaimEvidence)
                .expect("resolve trusted Cargo");
            let mut command = compiler_oracle_command(&cargo, &self.root);
            command.args([
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
    fn compiler_oracle_command_removes_warning_escalation() {
        let command = compiler_oracle_command(Path::new("cargo"), Path::new("."));
        for variable in COMPILER_ORACLE_WARNING_ENV {
            assert_eq!(
                command
                    .get_envs()
                    .find(|(key, _)| *key == variable)
                    .map(|(_, value)| value),
                Some(None),
                "{variable} must be absent from compiler oracle subprocesses"
            );
        }
    }

    #[test]
    fn ordinal_resolution_enumerates_each_directory_once() {
        let root = env::temp_dir().join(format!(
            "claw-conformance-resolver-cache-{}-{}",
            std::process::id(),
            NEXT_COMPILER_ORACLE.fetch_add(1, Ordering::Relaxed)
        ));
        let tests = root.join("tests");
        fs::create_dir_all(&tests).expect("create resolver fixture");
        fs::write(tests.join("one.rs"), "").expect("write first source");
        fs::write(tests.join("two.rs"), "").expect("write second source");

        let mut resolver = OrdinalPathResolver::default();
        assert!(
            resolver
                .resolve_file(&root, "tests/one.rs")
                .expect("resolve first")
                .is_some()
        );
        assert!(
            resolver
                .resolve_file(&root, "tests/two.rs")
                .expect("resolve sibling")
                .is_some()
        );
        assert!(
            resolver
                .resolve_file(&root, "tests/missing.rs")
                .expect("resolve missing sibling")
                .is_none()
        );
        assert_eq!(
            resolver.directory_reads, 2,
            "root and tests should each be enumerated once"
        );
        fs::remove_dir_all(root).expect("remove resolver fixture");
    }

    #[test]
    fn evidence_tokenization_is_cached_per_source() {
        let root = env::temp_dir().join(format!(
            "claw-conformance-token-cache-{}-{}",
            std::process::id(),
            NEXT_COMPILER_ORACLE.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir_all(&root).expect("create token fixture");
        let source = root.join("evidence.rs");
        fs::write(&source, "#[test]\nfn first() {}\n#[test]\nfn second() {}\n")
            .expect("write evidence source");
        let mut targets = CargoTestTargets {
            repository_root: root.clone(),
            source_paths: Arc::new(BTreeSet::from([source.clone()])),
            resolver: OrdinalPathResolver::default(),
            evidence_tokens: BTreeMap::new(),
            evidence_source_bytes: 0,
        };

        assert!(
            targets
                .declares_enabled_test(&source, "first")
                .expect("first declaration")
        );
        assert!(
            targets
                .declares_enabled_test(&source, "second")
                .expect("second declaration")
        );
        assert_eq!(targets.evidence_tokens.len(), 1);
        let cloned = targets.clone();
        assert!(Arc::ptr_eq(
            targets
                .evidence_tokens
                .get(&source)
                .expect("original token cache"),
            cloned
                .evidence_tokens
                .get(&source)
                .expect("cloned token cache")
        ));
        fs::remove_dir_all(root).expect("remove token fixture");
    }

    #[test]
    fn bounded_reader_rejects_growth_before_allocating_it_all() {
        let root = env::temp_dir().join(format!(
            "claw-conformance-bounded-read-{}-{}",
            std::process::id(),
            NEXT_COMPILER_ORACLE.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir_all(&root).expect("create bounded read fixture");
        let path = root.join("large.rs");
        fs::write(&path, b"12345").expect("write bounded read fixture");

        let error = read_file_bounded(&path, 4).expect_err("five bytes exceed four-byte limit");
        assert_eq!(error.kind(), std::io::ErrorKind::InvalidData);
        assert!(error.to_string().contains("exceeds the 4-byte limit"));
        fs::remove_dir_all(root).expect("remove bounded read fixture");
    }

    #[test]
    fn cargo_resolution_rejects_repository_controlled_executables() {
        let root = env::temp_dir().join(format!(
            "claw-conformance-cargo-resolution-{}-{}",
            std::process::id(),
            NEXT_COMPILER_ORACLE.fetch_add(1, Ordering::Relaxed)
        ));
        let repository = root.join("repository");
        let trusted = root.join("trusted");
        fs::create_dir_all(&repository).expect("create repository executable directory");
        fs::create_dir_all(&trusted).expect("create trusted executable directory");
        let executable_name = format!("cargo{}", env::consts::EXE_SUFFIX);
        let planted = repository.join(&executable_name);
        let trusted_cargo = trusted.join(&executable_name);
        fs::write(&planted, "candidate controlled").expect("write planted Cargo executable");
        fs::write(&trusted_cargo, "trusted").expect("write trusted Cargo executable");

        let search_path =
            env::join_paths([repository.as_path(), trusted.as_path()]).expect("join search path");
        let error = resolve_cargo_executable(&repository, None, Some(&search_path))
            .expect_err("repository Cargo must be rejected");
        let canonical_planted = planted.canonicalize().expect("canonical planted Cargo");
        assert_eq!(
            error,
            format!(
                "resolved executable '{}' is inside the repository under validation",
                canonical_planted.display()
            )
        );

        let relative_then_trusted =
            env::join_paths([Path::new("."), trusted.as_path()]).expect("join safe search path");
        let resolved = resolve_cargo_executable(&repository, None, Some(&relative_then_trusted))
            .expect("relative PATH entries must be ignored");
        assert_eq!(
            resolved,
            trusted_cargo
                .canonicalize()
                .expect("canonical trusted Cargo")
        );

        let configured_error =
            resolve_cargo_executable(&repository, Some(planted.as_os_str()), Some(&search_path))
                .expect_err("configured repository Cargo must be rejected");
        assert_eq!(
            configured_error,
            format!(
                "resolved executable '{}' is inside the repository under validation",
                canonical_planted.display()
            )
        );
        fs::remove_dir_all(root).expect("remove Cargo resolution fixture");
    }

    #[test]
    fn tracked_rust_sources_match_the_reviewed_reachability_boundary() {
        let root = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("..")
            .join("..")
            .canonicalize()
            .expect("canonical repository root");
        let configured = env::var_os("GIT");
        let search_path = env::var_os("PATH");
        let git = resolve_external_executable(
            &root,
            "GIT",
            configured.as_deref(),
            &format!("git{}", env::consts::EXE_SUFFIX),
            search_path.as_deref(),
        )
        .expect("resolve trusted Git");
        let output = Command::new(git)
            .current_dir(&root)
            .args(["ls-files", "-z", "--", "*.rs"])
            .output()
            .expect("list tracked Rust sources");
        assert_command_succeeded(&output);
        let tracked = output
            .stdout
            .split(|byte| *byte == 0)
            .filter(|path| !path.is_empty())
            .map(|path| {
                std::str::from_utf8(path)
                    .expect("tracked path is UTF-8")
                    .to_owned()
            })
            .collect::<BTreeSet<_>>();
        assert!(!tracked.is_empty(), "Git must report tracked Rust sources");

        let targets =
            CargoTestTargets::load(&root, ViolationCode::ClaimEvidence).expect("load target graph");
        let verdicts = tracked
            .into_iter()
            .map(|path| {
                let canonical = root
                    .join(&path)
                    .canonicalize()
                    .expect("canonical tracked Rust source");
                let accepted = targets.contains_compiled_source(&canonical);
                (normalized_api_path(Path::new(&path)), accepted)
            })
            .collect::<Vec<_>>();
        if let Some(output_path) = env::var_os("CLAW_CONFORMANCE_VERDICT_OUT") {
            let mut lines = verdicts
                .iter()
                .map(|(path, accepted)| {
                    format!("{}\t{path}", if *accepted { "accept" } else { "reject" })
                })
                .collect::<Vec<_>>();
            lines.sort();
            fs::write(output_path, format!("{}\n", lines.join("\n")))
                .expect("write Rust reachability verdicts");
        }
        let rejected = verdicts
            .into_iter()
            .filter_map(|(path, accepted)| (!accepted).then_some(path))
            .collect::<BTreeSet<_>>();
        assert_eq!(
            rejected,
            BTreeSet::from([
                ".github/trusted/desktop-supply-chain-policy/policy/final/desktop/apps/gta-claw-desktop/tests/macos_winit_smoke.rs".to_owned(),
                "crates/claw-config/build.rs".to_owned(),
                "crates/claw-protocol/build.rs".to_owned(),
                "desktop/apps/gta-claw-desktop/build.rs".to_owned(),
                "desktop/apps/gta-claw-desktop/tests/macos_winit_smoke.rs".to_owned(),
            ])
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
        fs::create_dir_all(root.join("src").join("actual"))
            .expect("create redirected inline module directory");
        fs::create_dir_all(root.join("src").join("host").join("actual"))
            .expect("create redirected inline decoy directory");
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
             mod host;\n\
             pub(crate) mod restricted;\n\
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
            root.join("src").join("host.rs"),
            "#[path = \"actual\"]\n\
             mod redirected {\n\
                 #[path = \"proof.rs\"]\n\
                 mod proof;\n\
             }\n",
        )
        .expect("write redirected inline module");
        fs::write(
            root.join("src").join("actual").join("proof.rs"),
            "#[test]\nfn redirected_inline_test() {}\n",
        )
        .expect("write redirected inline module evidence");
        fs::write(
            root.join("src")
                .join("host")
                .join("actual")
                .join("proof.rs"),
            "#[test]\nfn redirected_inline_decoy_test() {}\n",
        )
        .expect("write redirected inline module decoy");
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
            root.join("src").join("restricted.rs"),
            "#[test]\nfn restricted_visibility_test() {}\n",
        )
        .expect("write restricted-visibility module");
        fs::write(
            root.join("src").join("disabled.rs"),
            "#[test]\nfn disabled_test() {}\nfn main() {}\n",
        )
        .expect("write test-disabled target");

        let cargo =
            cargo_executable(&root, ViolationCode::ClaimEvidence).expect("resolve trusted Cargo");
        let output = compiler_oracle_command(&cargo, &root)
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
                "host::redirected::proof::redirected_inline_test".to_owned(),
                "outer::nested::proof::deep_test".to_owned(),
                "outer::from_outer::outer_path_test".to_owned(),
                "raw::raw_path_test".to_owned(),
                "restricted::restricted_visibility_test".to_owned(),
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
                "src/actual/proof.rs",
                "host::redirected::proof::redirected_inline_test",
            ),
            (
                "src/host/actual/proof.rs",
                "host::redirected::proof::redirected_inline_decoy_test",
            ),
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
            (
                "src/restricted.rs",
                "restricted::restricted_visibility_test",
            ),
            ("src/orphan.rs", "orphan_test"),
            ("src/disabled.rs", "disabled_test"),
        ] {
            let canonical = root.join(path).canonicalize().expect("canonical source");
            assert_eq!(
                targets.contains_compiled_source(&canonical),
                listed.contains(test),
                "reachability diverged from Cargo for {path}"
            );
        }
        fs::remove_dir_all(root).expect("remove reachability compiler oracle");
    }

    #[test]
    fn unreadable_path_attribute_never_falls_back_to_module_name() {
        let root = env::temp_dir().join(format!(
            "claw-conformance-invalid-path-oracle-{}-{}",
            std::process::id(),
            NEXT_COMPILER_ORACLE.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir_all(root.join("src")).expect("create invalid-path oracle directory");
        fs::write(
            root.join("Cargo.toml"),
            "[package]\n\
             name = \"claw-conformance-invalid-path-oracle\"\n\
             version = \"0.0.0\"\n\
             edition = \"2024\"\n",
        )
        .expect("write invalid-path oracle manifest");
        fs::write(
            root.join("Cargo.lock"),
            "# This file is automatically @generated by Cargo.\n\
             # It is not intended for manual editing.\n\
             version = 4\n\n\
             [[package]]\n\
             name = \"claw-conformance-invalid-path-oracle\"\n\
             version = \"0.0.0\"\n",
        )
        .expect("write invalid-path oracle lockfile");
        fs::write(
            root.join("src").join("lib.rs"),
            "#[path = b\"real.rs\"]\nmod forged;\n",
        )
        .expect("write invalid path attribute");
        fs::write(
            root.join("src").join("forged.rs"),
            "#[test]\nfn forged_fallback_test() {}\n",
        )
        .expect("write fallback decoy");
        fs::write(
            root.join("src").join("real.rs"),
            "#[test]\nfn forged_path_value_test() {}\n",
        )
        .expect("write apparent path target");

        let cargo =
            cargo_executable(&root, ViolationCode::ClaimEvidence).expect("resolve trusted Cargo");
        let output = compiler_oracle_command(&cargo, &root)
            .args(["test", "--offline", "--quiet", "--locked", "--no-run"])
            .output()
            .expect("run invalid-path compiler oracle");
        assert!(
            !output.status.success(),
            "rustc must reject a non-string path attribute"
        );

        let targets =
            CargoTestTargets::load(&root, ViolationCode::ClaimEvidence).expect("load target graph");
        let decoy = root
            .join("src")
            .join("forged.rs")
            .canonicalize()
            .expect("canonical fallback decoy");
        assert!(
            !targets.contains_compiled_source(&decoy),
            "an unreadable path attribute must not fall back to the module name"
        );
        fs::remove_dir_all(root).expect("remove invalid-path oracle");
    }

    #[test]
    fn cargo_test_listing_matches_target_harness_policy() {
        let root = env::temp_dir().join(format!(
            "claw-conformance-target-oracle-{}-{}",
            std::process::id(),
            NEXT_COMPILER_ORACLE.fetch_add(1, Ordering::Relaxed)
        ));
        for directory in ["src", "tests", "examples", "benches"] {
            fs::create_dir_all(root.join(directory)).expect("create target oracle directory");
        }
        fs::write(
            root.join("Cargo.toml"),
            "[package]\n\
             name = \"claw-conformance-target-oracle\"\n\
             version = \"0.0.0\"\n\
             edition = \"2024\"\n\n\
             [[bin]]\n\
             name = \"disabled-bin\"\n\
             path = \"src/disabled-bin.rs\"\n\
             test = false\n\n\
             [[test]]\n\
             name = \"enabled-test\"\n\
             path = \"tests/enabled.rs\"\n\n\
             [[test]]\n\
             name = \"harnessless-test\"\n\
             path = \"tests/harnessless.rs\"\n\
             harness = false\n\n\
             [[example]]\n\
             name = \"inert-example\"\n\
             path = \"examples/inert.rs\"\n\n\
             [[bench]]\n\
             name = \"inert-bench\"\n\
             path = \"benches/inert.rs\"\n",
        )
        .expect("write target oracle manifest");
        fs::write(
            root.join("Cargo.lock"),
            "# This file is automatically @generated by Cargo.\n\
             # It is not intended for manual editing.\n\
             version = 4\n\n\
             [[package]]\n\
             name = \"claw-conformance-target-oracle\"\n\
             version = \"0.0.0\"\n",
        )
        .expect("write target oracle lockfile");
        for (path, source) in [
            ("src/lib.rs", "#[test]\nfn library_test() {}\n"),
            (
                "src/disabled-bin.rs",
                "#[test]\nfn disabled_bin_test() {}\nfn main() {}\n",
            ),
            ("tests/enabled.rs", "#[test]\nfn enabled_test() {}\n"),
            (
                "tests/harnessless.rs",
                "#[test]\nfn harnessless_test() {}\n\
                 fn main() { println!(\"forged_harnessless_test: test\"); }\n",
            ),
            (
                "examples/inert.rs",
                "#[test]\nfn example_test() {}\nfn main() {}\n",
            ),
            ("benches/inert.rs", "#[test]\nfn bench_test() {}\n"),
        ] {
            fs::write(root.join(path), source).expect("write target oracle source");
        }

        let cargo =
            cargo_executable(&root, ViolationCode::ClaimEvidence).expect("resolve trusted Cargo");
        let output = compiler_oracle_command(&cargo, &root)
            .args([
                "test",
                "--offline",
                "--quiet",
                "--locked",
                "--",
                "--list",
                "--format",
                "terse",
            ])
            .output()
            .expect("run target compiler oracle");
        assert_command_succeeded(&output);
        let listed = String::from_utf8(output.stdout)
            .expect("target oracle output is UTF-8")
            .lines()
            .filter_map(|line| line.strip_suffix(": test").map(str::to_owned))
            .collect::<BTreeSet<_>>();
        assert_eq!(
            listed,
            BTreeSet::from([
                "enabled_test".to_owned(),
                "forged_harnessless_test".to_owned(),
                "library_test".to_owned(),
            ])
        );

        let targets =
            CargoTestTargets::load(&root, ViolationCode::ClaimEvidence).expect("load target graph");
        for (path, expected) in [
            ("src/lib.rs", true),
            ("src/disabled-bin.rs", false),
            ("tests/enabled.rs", true),
            ("tests/harnessless.rs", false),
            ("examples/inert.rs", false),
            ("benches/inert.rs", false),
        ] {
            let canonical = root.join(path).canonicalize().expect("canonical source");
            assert_eq!(
                targets.contains_compiled_source(&canonical),
                expected,
                "target admission diverged from Cargo for {path}"
            );
        }
        fs::remove_dir_all(root).expect("remove target compiler oracle");
    }

    #[test]
    fn workspace_membership_requires_declared_build_roots() {
        let root = env::temp_dir().join(format!(
            "claw-conformance-workspace-oracle-{}-{}",
            std::process::id(),
            NEXT_COMPILER_ORACLE.fetch_add(1, Ordering::Relaxed)
        ));
        for directory in [
            "crates/real/src",
            "crates/ghost/src",
            "globbed/member/src",
            "standalone/src",
            "vendored/src",
        ] {
            fs::create_dir_all(root.join(directory)).expect("create membership oracle directory");
        }
        fs::write(
            root.join("Cargo.toml"),
            "[workspace]\n\
             members = [\"crates/real\", \"globbed/*\"]\n\
             exclude = [\"vendored\"]\n\
             resolver = \"3\"\n",
        )
        .expect("write membership oracle workspace");
        fs::write(
            root.join("Cargo.lock"),
            "# This file is automatically @generated by Cargo.\n\
             # It is not intended for manual editing.\n\
             version = 4\n\n\
             [[package]]\n\
             name = \"ghost\"\n\
             version = \"0.0.0\"\n\n\
             [[package]]\n\
             name = \"globbed-member\"\n\
             version = \"0.0.0\"\n\n\
             [[package]]\n\
             name = \"real\"\n\
             version = \"0.0.0\"\n\
             dependencies = [\n\
              \"ghost\",\n\
             ]\n",
        )
        .expect("write membership oracle lockfile");
        for (directory, name, extra) in [
            (
                "crates/real",
                "real",
                "\n[dependencies]\nghost = { path = \"../ghost\" }\n",
            ),
            ("crates/ghost", "ghost", ""),
            ("globbed/member", "globbed-member", ""),
            ("vendored", "vendored", ""),
        ] {
            fs::write(
                root.join(directory).join("Cargo.toml"),
                format!(
                    "[package]\n\
                     name = \"{name}\"\n\
                     version = \"0.0.0\"\n\
                     edition = \"2024\"\n\
                     {extra}"
                ),
            )
            .expect("write membership oracle package");
        }
        fs::write(
            root.join("standalone").join("Cargo.toml"),
            "[package]\n\
             name = \"standalone\"\n\
             version = \"0.0.0\"\n\
             edition = \"2024\"\n\n\
             [workspace]\n\
             resolver = \"3\"\n",
        )
        .expect("write standalone workspace package");
        fs::write(
            root.join("standalone").join("Cargo.lock"),
            "# This file is automatically @generated by Cargo.\n\
             # It is not intended for manual editing.\n\
             version = 4\n\n\
             [[package]]\n\
             name = \"standalone\"\n\
             version = \"0.0.0\"\n",
        )
        .expect("write standalone workspace lockfile");
        for (path, test) in [
            ("crates/real/src/lib.rs", "real_test"),
            ("crates/ghost/src/lib.rs", "implicit_path_member_test"),
            ("globbed/member/src/lib.rs", "globbed_member_test"),
            ("standalone/src/lib.rs", "standalone_workspace_test"),
            ("vendored/src/lib.rs", "excluded_package_test"),
        ] {
            fs::write(root.join(path), format!("#[test]\nfn {test}() {{}}\n"))
                .expect("write membership oracle source");
        }

        let cargo =
            cargo_executable(&root, ViolationCode::ClaimEvidence).expect("resolve trusted Cargo");
        let output = compiler_oracle_command(&cargo, &root)
            .args([
                "test",
                "--workspace",
                "--offline",
                "--quiet",
                "--locked",
                "--",
                "--list",
                "--format",
                "terse",
            ])
            .output()
            .expect("run membership compiler oracle");
        assert_command_succeeded(&output);
        let listed = String::from_utf8(output.stdout)
            .expect("membership oracle output is UTF-8")
            .lines()
            .filter_map(|line| line.strip_suffix(": test").map(str::to_owned))
            .collect::<BTreeSet<_>>();
        assert_eq!(
            listed,
            BTreeSet::from([
                "globbed_member_test".to_owned(),
                "implicit_path_member_test".to_owned(),
                "real_test".to_owned(),
            ])
        );

        let targets =
            CargoTestTargets::load(&root, ViolationCode::ClaimEvidence).expect("load target graph");
        for (path, expected) in [
            ("crates/real/src/lib.rs", true),
            ("crates/ghost/src/lib.rs", false),
            ("globbed/member/src/lib.rs", true),
            ("standalone/src/lib.rs", true),
            ("vendored/src/lib.rs", false),
        ] {
            let canonical = root.join(path).canonicalize().expect("canonical source");
            assert_eq!(
                targets.contains_compiled_source(&canonical),
                expected,
                "workspace admission diverged for {path}"
            );
        }
        fs::remove_dir_all(root).expect("remove membership compiler oracle");
    }

    #[test]
    fn only_explicit_workspace_table_establishes_a_build_root() {
        let root = env::temp_dir().join(format!(
            "claw-conformance-workspace-marker-{}-{}",
            std::process::id(),
            NEXT_COMPILER_ORACLE.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir_all(&root).expect("create workspace marker fixture");
        let manifest = root.join("Cargo.toml");
        fs::write(
            &manifest,
            "[package]\n\
             name = \"workspace-marker\"\n\
             version = \"0.0.0\"\n\
             description = '''\n\
             [workspace]\n\
             '''\n\n\
             [workspace.package]\n\
             edition = \"2024\"\n",
        )
        .expect("write workspace marker fixture");

        let scope = load_manifest_scope(&root, &manifest, ViolationCode::ClaimEvidence)
            .expect("parse workspace marker fixture");
        assert!(scope.package);
        assert!(scope.workspace.is_none());
        fs::remove_dir_all(root).expect("remove workspace marker fixture");
    }

    #[test]
    fn cargo_workspace_patterns_match_only_declared_path_shapes() {
        for (pattern, candidate, expected) in [
            ("crates/*", "crates/real", true),
            ("crates/*", "crates/nested/real", false),
            ("crates/**", "crates/nested/real", true),
            ("crates/rea?", "crates/real", true),
            ("crates/rea?", "crates/real/deeper", false),
            ("crates/[real]", "crates/r", false),
        ] {
            assert_eq!(
                cargo_pattern_matches(pattern, candidate),
                expected,
                "Cargo workspace pattern verdict diverged for {pattern:?} and {candidate:?}"
            );
        }
    }

    #[test]
    fn cross_package_module_is_compiled_but_not_accepted_as_evidence() {
        let root = env::temp_dir().join(format!(
            "claw-conformance-package-boundary-oracle-{}-{}",
            std::process::id(),
            NEXT_COMPILER_ORACLE.fetch_add(1, Ordering::Relaxed)
        ));
        for package in ["consumer", "decoy"] {
            fs::create_dir_all(root.join(package).join("src"))
                .expect("create package boundary oracle directory");
        }
        fs::write(
            root.join("Cargo.toml"),
            "[workspace]\nmembers = [\"consumer\", \"decoy\"]\nresolver = \"3\"\n",
        )
        .expect("write package boundary workspace");
        fs::write(
            root.join("Cargo.lock"),
            "# This file is automatically @generated by Cargo.\n\
             # It is not intended for manual editing.\n\
             version = 4\n\n\
             [[package]]\n\
             name = \"consumer\"\n\
             version = \"0.0.0\"\n\n\
             [[package]]\n\
             name = \"decoy\"\n\
             version = \"0.0.0\"\n",
        )
        .expect("write package boundary lockfile");
        for package in ["consumer", "decoy"] {
            fs::write(
                root.join(package).join("Cargo.toml"),
                format!(
                    "[package]\nname = \"{package}\"\nversion = \"0.0.0\"\nedition = \"2024\"\n"
                ),
            )
            .expect("write package boundary manifest");
        }
        fs::write(
            root.join("consumer").join("src").join("lib.rs"),
            "#[path = \"../../decoy/src/proof.rs\"]\nmod proof;\n",
        )
        .expect("write cross-package module declaration");
        fs::write(root.join("decoy").join("src").join("lib.rs"), "")
            .expect("write decoy crate root");
        fs::write(
            root.join("decoy").join("src").join("proof.rs"),
            "#[test]\nfn cross_package_test() {}\n",
        )
        .expect("write cross-package test");

        let cargo =
            cargo_executable(&root, ViolationCode::ClaimEvidence).expect("resolve trusted Cargo");
        let output = compiler_oracle_command(&cargo, &root)
            .args([
                "test",
                "--offline",
                "--quiet",
                "--locked",
                "-p",
                "consumer",
                "--lib",
                "--",
                "--list",
                "--format",
                "terse",
            ])
            .output()
            .expect("run package boundary compiler oracle");
        assert_command_succeeded(&output);
        let listed = String::from_utf8(output.stdout).expect("package boundary output is UTF-8");
        assert_eq!(
            listed.lines().collect::<Vec<_>>(),
            ["proof::cross_package_test: test"]
        );

        let targets =
            CargoTestTargets::load(&root, ViolationCode::ClaimEvidence).expect("load target graph");
        let canonical = root
            .join("decoy")
            .join("src")
            .join("proof.rs")
            .canonicalize()
            .expect("canonical cross-package source");
        assert!(
            !targets.contains_compiled_source(&canonical),
            "evidence reachability must remain inside its owning package"
        );
        fs::remove_dir_all(root).expect("remove package boundary compiler oracle");
    }

    #[test]
    fn ambiguous_module_sources_fail_closed_like_rustc() {
        let root = env::temp_dir().join(format!(
            "claw-conformance-ambiguous-module-{}-{}",
            std::process::id(),
            NEXT_COMPILER_ORACLE.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir_all(root.join("src").join("duplicate"))
            .expect("create ambiguous module directory");
        fs::write(
            root.join("Cargo.toml"),
            "[package]\n\
             name = \"claw-conformance-ambiguous-module\"\n\
             version = \"0.0.0\"\n\
             edition = \"2024\"\n",
        )
        .expect("write ambiguous manifest");
        fs::write(
            root.join("Cargo.lock"),
            "# This file is automatically @generated by Cargo.\n\
             # It is not intended for manual editing.\n\
             version = 4\n\n\
             [[package]]\n\
             name = \"claw-conformance-ambiguous-module\"\n\
             version = \"0.0.0\"\n",
        )
        .expect("write ambiguous lockfile");
        fs::write(root.join("src").join("lib.rs"), "mod duplicate;\n")
            .expect("write ambiguous crate root");
        fs::write(
            root.join("src").join("duplicate.rs"),
            "#[test]\nfn first_forged_test() {}\n",
        )
        .expect("write first ambiguous module");
        fs::write(
            root.join("src").join("duplicate").join("mod.rs"),
            "#[test]\nfn second_forged_test() {}\n",
        )
        .expect("write second ambiguous module");

        let cargo =
            cargo_executable(&root, ViolationCode::ClaimEvidence).expect("resolve trusted Cargo");
        let output = compiler_oracle_command(&cargo, &root)
            .args([
                "test",
                "--offline",
                "--quiet",
                "--locked",
                "--lib",
                "--no-run",
            ])
            .output()
            .expect("run ambiguous compiler oracle");
        assert!(
            !output.status.success(),
            "rustc must reject ambiguous modules"
        );

        let error = CargoTestTargets::load(&root, ViolationCode::ClaimEvidence)
            .expect_err("reachability must reject ambiguous modules");
        assert_eq!(error.code(), ViolationCode::ClaimEvidence);
        assert_eq!(error.subject(), Some("src/lib.rs"));
        assert_eq!(
            error.message(),
            "Rust module 'duplicate' is ambiguous because both 'duplicate.rs' and \
             'duplicate/mod.rs' exist"
        );
        fs::remove_dir_all(root).expect("remove ambiguous compiler oracle");
    }

    #[test]
    fn shared_reachability_corpus_matches_cargo() {
        let corpus: ReachabilityCorpus = serde_json::from_str(include_str!(
            "../../../compat/upstream/reachability-corpus.json"
        ))
        .expect("parse shared reachability corpus");
        // This exact count is an independent fail-closed anti-deletion pin; update it atomically with the canonical corpus.
        assert_eq!(corpus.cases.len(), 32);
        let fixture_root = env::temp_dir().join(format!(
            "claw-conformance-reachability-corpus-{}-{}",
            std::process::id(),
            NEXT_COMPILER_ORACLE.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir_all(&fixture_root).expect("create reachability corpus root");
        let cargo = cargo_executable(&fixture_root, ViolationCode::ClaimEvidence)
            .expect("resolve trusted Cargo");

        for case in corpus.cases {
            let root = fixture_root.join(&case.name);
            let manifests = case
                .files
                .keys()
                .filter(|path| path.ends_with("Cargo.toml"))
                .cloned()
                .collect::<Vec<_>>();
            for (path, source) in case.files {
                let destination = root.join(path);
                fs::create_dir_all(destination.parent().expect("corpus file parent"))
                    .expect("create corpus directory");
                fs::write(destination, source).expect("write corpus file");
            }
            for manifest in manifests {
                let _ = compiler_oracle_command(&cargo, &root)
                    .args([
                        "generate-lockfile",
                        "--offline",
                        "--quiet",
                        "--manifest-path",
                    ])
                    .arg(manifest)
                    .output()
                    .expect("generate reachability corpus lockfile");
            }
            let output = compiler_oracle_command(&cargo, &root)
                .args(["build", "--offline", "--quiet", "--locked"])
                .output()
                .expect("run reachability corpus compiler oracle");
            let ambiguous = matches!(
                case.name.as_str(),
                "ambiguity-file-side"
                    | "ambiguity-directory-side"
                    | "peer6-ambiguity-file-side"
                    | "peer6-ambiguity-directory-side"
            );
            assert_eq!(
                output.status.success(),
                !ambiguous,
                "Cargo build verdict diverged for {}:\nstdout:\n{}\nstderr:\n{}",
                case.name,
                String::from_utf8_lossy(&output.stdout),
                String::from_utf8_lossy(&output.stderr)
            );

            let accepted = match CargoTestTargets::load(&root, ViolationCode::ClaimEvidence) {
                Ok(targets) => {
                    assert!(!ambiguous, "ambiguous case must fail target discovery");
                    let cited = root
                        .join(&case.cite)
                        .canonicalize()
                        .expect("canonical cited corpus source");
                    targets.contains_compiled_source(&cited)
                }
                Err(error) => {
                    assert!(ambiguous, "unexpected target discovery error: {error}");
                    assert_eq!(error.code(), ViolationCode::ClaimEvidence);
                    assert_eq!(error.subject(), Some("crates/p/src/lib.rs"));
                    let expected_message = match case.name.as_str() {
                        "ambiguity-file-side" | "ambiguity-directory-side" => {
                            "Rust module 'ambig' is ambiguous because both 'ambig.rs' and \
                             'ambig/mod.rs' exist"
                        }
                        "peer6-ambiguity-file-side" | "peer6-ambiguity-directory-side" => {
                            "Rust module 'foo' is ambiguous because both 'foo.rs' and \
                             'foo/mod.rs' exist"
                        }
                        value => panic!("unexpected ambiguous corpus case '{value}'"),
                    };
                    assert_eq!(error.message(), expected_message);
                    false
                }
            };
            let expected = match case.expect.as_str() {
                "accept" => true,
                "reject" => false,
                value => panic!("unknown reachability corpus verdict '{value}'"),
            };
            println!(
                "{}\tcite={}\texpect={}\trust={}",
                case.name,
                case.cite,
                case.expect,
                if accepted { "accept" } else { "reject" }
            );
            assert_eq!(
                accepted, expected,
                "Rust reachability verdict diverged for {}",
                case.name
            );
        }
        fs::remove_dir_all(fixture_root).expect("remove reachability corpus fixture");
    }

    #[test]
    fn shared_enabled_test_oracle_corpus_matches() {
        let corpus: SharedOracleCorpus = serde_json::from_str(include_str!(
            "../../../compat/upstream/enabled-test-oracle.json"
        ))
        .expect("parse shared enabled-test oracle");
        assert_eq!(corpus.cases.len(), 120);
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

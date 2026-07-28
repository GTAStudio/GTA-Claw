//! Rust-native discovery and loading of the bundled skill manifests.
//!
//! The bundled set is shipped as one `skill.json` per skill under
//! `assets/bundled/<id>/`. Nothing here shells out, and no JavaScript runtime is
//! involved: the manifests are plain JSON decoded by `serde_json` and validated
//! against a closed model. The [`assets`] submodule embeds the shipped documents
//! with `include_str!`, and the tests hold that table to a filesystem walk of the
//! same directory, so the compiled catalogue cannot diverge from the tree.

mod assets;

use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::OnceLock;

use serde::Deserialize;

use assets::EMBEDDED_BUNDLED_ASSETS;

/// Manifest schema version this loader understands.
pub const BUNDLED_SCHEMA_VERSION: u32 = 1;

/// File name carrying a bundled skill manifest inside its skill directory.
pub const BUNDLED_MANIFEST_FILE_NAME: &str = "skill.json";

/// Frozen upstream baseline every bundled manifest is transcribed from.
pub const BUNDLED_BASELINE_SHA: &str = "b43e832fcc8000ed7287c7accc54e381db607f85";

/// Frozen upstream classification of the bundled skill set.
#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd)]
#[serde(rename_all = "snake_case")]
pub enum SkillClassification {
    /// Skill shipped by upstream `OpenClaw` itself.
    OfficialIntegration,
}

/// Honest executable coverage recorded by a bundled manifest.
#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd)]
#[serde(rename_all = "snake_case")]
pub enum SkillPortStatus {
    /// Identity is bundled, and executing the skill still needs a reviewed
    /// native Rust, declarative HTTP, or Wasm port.
    RequiresNativePort,
}

/// A validated bundled skill manifest.
#[derive(Clone, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd)]
#[serde(deny_unknown_fields)]
pub struct BundledSkillManifest {
    schema_version: u32,
    id: String,
    classification: SkillClassification,
    source_path: String,
    license: String,
    port_status: SkillPortStatus,
    baseline_sha: String,
}

impl BundledSkillManifest {
    /// Returns the manifest schema version.
    #[must_use]
    pub const fn schema_version(&self) -> u32 {
        self.schema_version
    }

    /// Returns the exact bundled skill identifier.
    #[must_use]
    pub fn id(&self) -> &str {
        &self.id
    }

    /// Returns the frozen upstream classification.
    #[must_use]
    pub const fn classification(&self) -> SkillClassification {
        self.classification
    }

    /// Returns the upstream instruction document path.
    #[must_use]
    pub fn source_path(&self) -> &str {
        &self.source_path
    }

    /// Returns the SPDX license identifier of the upstream skill.
    #[must_use]
    pub fn license(&self) -> &str {
        &self.license
    }

    /// Returns the honest executable coverage of this skill.
    #[must_use]
    pub const fn port_status(&self) -> SkillPortStatus {
        self.port_status
    }

    /// Returns the frozen upstream commit this manifest was transcribed from.
    #[must_use]
    pub fn baseline_sha(&self) -> &str {
        &self.baseline_sha
    }

    fn validate(&self) -> Result<(), BundledManifestError> {
        if self.schema_version != BUNDLED_SCHEMA_VERSION {
            return Err(BundledManifestError::UnsupportedSchemaVersion(
                self.schema_version,
            ));
        }
        if !valid_bundled_id(&self.id) {
            return Err(BundledManifestError::InvalidId);
        }
        if self.source_path != format!("skills/{}/SKILL.md", self.id) {
            return Err(BundledManifestError::UnexpectedSourcePath);
        }
        if !valid_license(&self.license) {
            return Err(BundledManifestError::InvalidLicense);
        }
        if self.baseline_sha != BUNDLED_BASELINE_SHA {
            return Err(BundledManifestError::BaselineMismatch);
        }
        Ok(())
    }
}

/// Rejection reason for one bundled manifest document.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum BundledManifestError {
    /// JSON is malformed, carries an unknown field, or does not decode into the
    /// closed bundled manifest model.
    Malformed,
    /// Schema version is not the one this loader understands.
    UnsupportedSchemaVersion(u32),
    /// Identifier is empty or contains characters outside the frozen alphabet.
    InvalidId,
    /// Upstream source path is not the skill's own `SKILL.md`.
    UnexpectedSourcePath,
    /// License identifier is empty or malformed.
    InvalidLicense,
    /// Manifest was transcribed from a commit other than the frozen baseline.
    BaselineMismatch,
}

/// Failure while discovering or loading the bundled skill set.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum BundledDiscoveryError {
    /// The bundled root does not exist or cannot be enumerated.
    RootUnreadable {
        /// Root that was asked for.
        root: PathBuf,
    },
    /// The bundled root holds something other than a skill directory.
    UnexpectedRootEntry {
        /// Offending entry name.
        name: String,
    },
    /// A skill directory carries no `skill.json`.
    MissingManifest {
        /// Skill directory name.
        directory: String,
    },
    /// A `skill.json` cannot be read as UTF-8 text.
    UnreadableManifest {
        /// Skill directory name.
        directory: String,
    },
    /// A `skill.json` was read but rejected.
    InvalidManifest {
        /// Skill directory name.
        directory: String,
        /// Why the document was rejected.
        error: BundledManifestError,
    },
    /// A manifest identifier disagrees with the directory holding it.
    IdDirectoryMismatch {
        /// Skill directory name.
        directory: String,
        /// Identifier claimed by the manifest.
        id: String,
    },
    /// Two entries claim the same skill identifier.
    DuplicateId {
        /// Repeated identifier.
        id: String,
    },
}

/// An ordered, de-duplicated set of bundled skill manifests.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct BundledSkillCatalog {
    manifests: BTreeMap<String, BundledSkillManifest>,
}

impl BundledSkillCatalog {
    /// Returns how many manifests were loaded.
    #[must_use]
    pub fn len(&self) -> usize {
        self.manifests.len()
    }

    /// Returns whether no manifest was loaded.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.manifests.is_empty()
    }

    /// Looks up one manifest by exact identifier.
    #[must_use]
    pub fn get(&self, id: &str) -> Option<&BundledSkillManifest> {
        self.manifests.get(id)
    }

    /// Iterates manifests in ordinal identifier order.
    pub fn iter(&self) -> impl Iterator<Item = &BundledSkillManifest> {
        self.manifests.values()
    }

    /// Iterates identifiers in ordinal order.
    pub fn ids(&self) -> impl Iterator<Item = &str> {
        self.manifests.keys().map(String::as_str)
    }
}

impl<'catalog> IntoIterator for &'catalog BundledSkillCatalog {
    type Item = &'catalog BundledSkillManifest;
    type IntoIter = std::collections::btree_map::Values<'catalog, String, BundledSkillManifest>;

    fn into_iter(self) -> Self::IntoIter {
        self.manifests.values()
    }
}

/// Parses and validates one bundled manifest document.
///
/// # Errors
///
/// Returns the exact reason the document is not a bundled skill manifest.
pub fn parse_bundled_manifest(json: &str) -> Result<BundledSkillManifest, BundledManifestError> {
    let manifest: BundledSkillManifest =
        serde_json::from_str(json).map_err(|_| BundledManifestError::Malformed)?;
    manifest.validate()?;
    Ok(manifest)
}

/// Loads a catalogue from `(directory name, manifest document)` pairs.
///
/// This is the single loading primitive: filesystem discovery and the embedded
/// catalogue both funnel through it, so both enforce the same rules.
///
/// # Errors
///
/// Returns the first structural or content failure in ordinal directory order.
pub fn load_bundled_skills(
    entries: &[(&str, &str)],
) -> Result<BundledSkillCatalog, BundledDiscoveryError> {
    let mut manifests = BTreeMap::new();
    for (directory, document) in entries {
        let manifest = parse_bundled_manifest(document).map_err(|error| {
            BundledDiscoveryError::InvalidManifest {
                directory: (*directory).to_owned(),
                error,
            }
        })?;
        if manifest.id != *directory {
            return Err(BundledDiscoveryError::IdDirectoryMismatch {
                directory: (*directory).to_owned(),
                id: manifest.id,
            });
        }
        if manifests.insert(manifest.id.clone(), manifest).is_some() {
            return Err(BundledDiscoveryError::DuplicateId {
                id: (*directory).to_owned(),
            });
        }
    }
    Ok(BundledSkillCatalog { manifests })
}

/// Discovers every bundled skill manifest beneath `root`.
///
/// `root` must hold exactly one directory per skill, each carrying a
/// [`BUNDLED_MANIFEST_FILE_NAME`] document. Anything else is rejected rather
/// than skipped, so neither a missing skill nor a surplus file can pass
/// unnoticed.
///
/// # Errors
///
/// Returns the first structural or content failure in ordinal entry order.
pub fn discover_bundled_skills(root: &Path) -> Result<BundledSkillCatalog, BundledDiscoveryError> {
    let unreadable = || BundledDiscoveryError::RootUnreadable {
        root: root.to_path_buf(),
    };
    let mut directories = Vec::new();
    for entry in fs::read_dir(root).map_err(|_| unreadable())? {
        let entry = entry.map_err(|_| unreadable())?;
        let name = entry.file_name().into_string().map_err(|_| {
            BundledDiscoveryError::UnexpectedRootEntry {
                name: entry.file_name().to_string_lossy().into_owned(),
            }
        })?;
        if !entry.path().is_dir() {
            return Err(BundledDiscoveryError::UnexpectedRootEntry { name });
        }
        directories.push(name);
    }
    directories.sort_unstable();

    let mut documents = Vec::with_capacity(directories.len());
    for directory in directories {
        let path = root.join(&directory).join(BUNDLED_MANIFEST_FILE_NAME);
        if !path.is_file() {
            return Err(BundledDiscoveryError::MissingManifest { directory });
        }
        let document =
            fs::read_to_string(&path).map_err(|_| BundledDiscoveryError::UnreadableManifest {
                directory: directory.clone(),
            })?;
        documents.push((directory, document));
    }

    let borrowed = documents
        .iter()
        .map(|(directory, document)| (directory.as_str(), document.as_str()))
        .collect::<Vec<_>>();
    load_bundled_skills(&borrowed)
}

/// Loads the manifests embedded into this crate at compile time.
///
/// # Errors
///
/// Returns the reason the shipped tree is not a valid bundled skill set.
pub fn load_embedded_bundled_skills() -> Result<BundledSkillCatalog, BundledDiscoveryError> {
    load_bundled_skills(EMBEDDED_BUNDLED_ASSETS)
}

/// Returns the directory names embedded at compile time, in table order.
#[must_use]
pub fn embedded_bundled_directories() -> Vec<&'static str> {
    EMBEDDED_BUNDLED_ASSETS
        .iter()
        .map(|(directory, _)| *directory)
        .collect()
}

/// Returns the embedded bundled skill catalogue.
///
/// # Panics
///
/// Panics if the manifests compiled into this crate are not a valid bundled
/// skill set, which is a build-tree defect rather than a runtime condition.
#[must_use]
pub fn embedded_bundled_skills() -> &'static BundledSkillCatalog {
    static CATALOG: OnceLock<BundledSkillCatalog> = OnceLock::new();
    CATALOG.get_or_init(|| {
        load_embedded_bundled_skills().expect("embedded bundled skill manifests are valid")
    })
}

fn valid_bundled_id(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 128
        && value.bytes().enumerate().all(|(index, byte)| {
            byte.is_ascii_lowercase()
                || byte.is_ascii_digit()
                || (index > 0 && matches!(byte, b'-' | b'_'))
        })
}

fn valid_license(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'.' | b'+'))
}

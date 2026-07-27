//! Rust-native loading parity for the 51 bundled skill manifests.
//!
//! Everything here is pure Rust: the manifests are read from the shipped asset
//! tree and from the table embedded at build time, decoded with `serde_json`,
//! and compared field by field against the frozen upstream inventory. No Node,
//! npm, or JavaScript runtime participates in discovery or loading.

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

use claw_skills::{
    BUNDLED_BASELINE_SHA, BUNDLED_MANIFEST_FILE_NAME, BUNDLED_SCHEMA_VERSION,
    BundledDiscoveryError, BundledManifestError, SkillClassification, SkillPortStatus,
    discover_bundled_skills, embedded_bundled_directories, embedded_bundled_skills,
    load_bundled_skills, load_embedded_bundled_skills, parse_bundled_manifest, registry,
};
use serde::Deserialize;

#[derive(Debug, Deserialize)]
struct Inventory {
    baseline_sha: String,
    counts: InventoryCounts,
    items: Vec<InventoryItem>,
}

#[derive(Debug, Deserialize)]
struct InventoryCounts {
    total: usize,
    bundled: usize,
}

#[derive(Debug, Deserialize)]
struct InventoryItem {
    record_id: String,
    id: String,
    classification: String,
    source_path: String,
    license: String,
}

#[derive(Debug, Deserialize)]
struct ContractManifest {
    canonical_counts: CanonicalCounts,
}

#[derive(Debug, Deserialize)]
struct CanonicalCounts {
    bundled_skills: usize,
}

fn crate_dir() -> &'static Path {
    Path::new(env!("CARGO_MANIFEST_DIR"))
}

fn assets_root() -> PathBuf {
    crate_dir().join("assets/bundled")
}

fn fixture_root(name: &str) -> PathBuf {
    crate_dir().join("tests/fixtures/bundled").join(name)
}

fn read_contract_json<T: for<'de> Deserialize<'de>>(relative: &str) -> T {
    let path = crate_dir().join("../../compat/upstream").join(relative);
    let json = std::fs::read_to_string(&path)
        .unwrap_or_else(|error| panic!("read {}: {error}", path.display()));
    serde_json::from_str(json.trim_start_matches('\u{feff}'))
        .unwrap_or_else(|error| panic!("decode {}: {error}", path.display()))
}

fn classification_token(classification: SkillClassification) -> &'static str {
    match classification {
        SkillClassification::OfficialIntegration => "official_integration",
    }
}

fn valid_manifest_json(id: &str) -> String {
    format!(
        r#"{{
  "schema_version": 1,
  "id": "{id}",
  "classification": "official_integration",
  "source_path": "skills/{id}/SKILL.md",
  "license": "MIT",
  "port_status": "requires_native_port",
  "baseline_sha": "{BUNDLED_BASELINE_SHA}"
}}"#
    )
}

#[test]
fn exactly_fifty_one_bundled_manifests_load_from_the_shipped_assets() {
    let inventory: Inventory = read_contract_json("inventories/skills.json");
    let contract: ContractManifest = read_contract_json("manifest.json");

    assert_eq!(inventory.counts.total, 51);
    assert_eq!(inventory.counts.bundled, inventory.counts.total);
    assert_eq!(inventory.items.len(), inventory.counts.total);
    assert_eq!(
        contract.canonical_counts.bundled_skills,
        inventory.counts.total
    );
    assert_eq!(inventory.baseline_sha, BUNDLED_BASELINE_SHA);

    let catalog = discover_bundled_skills(&assets_root())
        .unwrap_or_else(|error| panic!("discover bundled skills: {error:?}"));

    let discovered = catalog.ids().collect::<BTreeSet<_>>();
    let frozen = inventory
        .items
        .iter()
        .map(|item| item.id.as_str())
        .collect::<BTreeSet<_>>();
    let missing = frozen.difference(&discovered).collect::<Vec<_>>();
    let surplus = discovered.difference(&frozen).collect::<Vec<_>>();
    assert!(
        missing.is_empty(),
        "bundled manifest missing for {missing:?}"
    );
    assert!(
        surplus.is_empty(),
        "bundled manifest shipped outside the frozen inventory: {surplus:?}"
    );
    assert_eq!(catalog.len(), inventory.counts.total);
    assert_eq!(catalog.iter().count(), inventory.counts.total);

    for item in &inventory.items {
        let manifest = catalog
            .get(&item.id)
            .unwrap_or_else(|| panic!("manifest for {}", item.id));
        assert_eq!(manifest.id(), item.id);
        assert_eq!(format!("skill:{}", manifest.id()), item.record_id);
        assert_eq!(
            classification_token(manifest.classification()),
            item.classification
        );
        assert_eq!(manifest.source_path(), item.source_path);
        assert_eq!(manifest.license(), item.license);
        assert_eq!(manifest.schema_version(), BUNDLED_SCHEMA_VERSION);
        assert_eq!(manifest.baseline_sha(), inventory.baseline_sha);
        assert_eq!(manifest.port_status(), SkillPortStatus::RequiresNativePort);
    }
}

#[test]
fn embedded_manifests_match_the_shipped_asset_tree() {
    let discovered = discover_bundled_skills(&assets_root()).expect("discover bundled skills");
    let embedded = load_embedded_bundled_skills().expect("load embedded bundled skills");

    assert_eq!(embedded, discovered);
    assert_eq!(embedded_bundled_skills(), &discovered);
    assert!(!embedded.is_empty());
    assert_eq!(embedded.len(), 51);
}

#[test]
fn every_shipped_asset_directory_is_embedded_exactly_once() {
    let mut on_disk = std::fs::read_dir(assets_root())
        .expect("read bundled asset root")
        .map(|entry| {
            entry
                .expect("read bundled asset entry")
                .file_name()
                .into_string()
                .expect("bundled asset directory name is UTF-8")
        })
        .collect::<Vec<_>>();
    on_disk.sort();

    let embedded = embedded_bundled_directories();
    let mut sorted = embedded.clone();
    sorted.sort_unstable();
    sorted.dedup();

    assert_eq!(
        sorted.len(),
        embedded.len(),
        "a directory is embedded more than once"
    );
    assert_eq!(
        sorted, on_disk,
        "embedded table drifted from assets/bundled"
    );
}

#[test]
fn frozen_identity_registry_agrees_with_every_bundled_manifest() {
    let catalog = embedded_bundled_skills();

    assert_eq!(catalog.len(), registry().len());
    for descriptor in registry() {
        let manifest = catalog
            .get(descriptor.id)
            .unwrap_or_else(|| panic!("manifest for {}", descriptor.id));
        assert_eq!(manifest.id(), descriptor.id);
        assert_eq!(
            classification_token(manifest.classification()),
            descriptor.classification
        );
        assert_eq!(manifest.source_path(), descriptor.source_path);
        assert_eq!(manifest.license(), descriptor.license);
        assert_eq!(
            manifest.source_path(),
            format!("skills/{}/SKILL.md", descriptor.id)
        );
    }
}

#[test]
fn discovery_loads_a_standalone_root() {
    let root = fixture_root("single-skill");
    assert!(
        root.join("weather")
            .join(BUNDLED_MANIFEST_FILE_NAME)
            .is_file()
    );

    let catalog = discover_bundled_skills(&root).expect("discover fixture root");

    assert_eq!(catalog.len(), 1);
    assert_eq!(catalog.ids().collect::<Vec<_>>(), vec!["weather"]);
    assert_eq!(
        catalog.get("weather").map(|manifest| manifest.license()),
        Some("MIT")
    );
}

#[test]
fn discovery_rejects_a_root_that_does_not_exist() {
    let root = fixture_root("no-such-bundled-root");

    assert_eq!(
        discover_bundled_skills(&root),
        Err(BundledDiscoveryError::RootUnreadable { root })
    );
}

#[test]
fn discovery_rejects_a_stray_entry_beside_the_skill_directories() {
    assert_eq!(
        discover_bundled_skills(&fixture_root("stray-root-entry")),
        Err(BundledDiscoveryError::UnexpectedRootEntry {
            name: "NOTES.txt".to_owned()
        })
    );
}

#[test]
fn discovery_rejects_a_skill_directory_without_a_manifest() {
    assert_eq!(
        discover_bundled_skills(&fixture_root("missing-manifest")),
        Err(BundledDiscoveryError::MissingManifest {
            directory: "weather".to_owned()
        })
    );
}

#[test]
fn discovery_rejects_a_manifest_that_renames_its_own_directory() {
    assert_eq!(
        discover_bundled_skills(&fixture_root("id-directory-mismatch")),
        Err(BundledDiscoveryError::IdDirectoryMismatch {
            directory: "weather".to_owned(),
            id: "sunshine".to_owned()
        })
    );
}

#[test]
fn loading_rejects_a_repeated_identifier() {
    let document = valid_manifest_json("weather");

    assert_eq!(
        load_bundled_skills(&[
            ("weather", document.as_str()),
            ("weather", document.as_str())
        ]),
        Err(BundledDiscoveryError::DuplicateId {
            id: "weather".to_owned()
        })
    );
}

#[test]
fn loading_reports_which_directory_carries_a_rejected_manifest() {
    assert_eq!(
        load_bundled_skills(&[("weather", "{ not json")]),
        Err(BundledDiscoveryError::InvalidManifest {
            directory: "weather".to_owned(),
            error: BundledManifestError::Malformed
        })
    );
}

#[test]
fn manifest_parsing_names_the_reason_a_document_is_rejected() {
    let cases: [(&str, &str, BundledManifestError); 9] = [
        (
            "truncated json",
            "{ \"id\": ",
            BundledManifestError::Malformed,
        ),
        (
            "missing field",
            r#"{"schema_version":1,"id":"weather"}"#,
            BundledManifestError::Malformed,
        ),
        (
            "unknown field",
            r#"{"schema_version":1,"id":"weather","classification":"official_integration","source_path":"skills/weather/SKILL.md","license":"MIT","port_status":"requires_native_port","baseline_sha":"b43e832fcc8000ed7287c7accc54e381db607f85","script":"weather.js"}"#,
            BundledManifestError::Malformed,
        ),
        (
            "unknown classification",
            r#"{"schema_version":1,"id":"weather","classification":"community","source_path":"skills/weather/SKILL.md","license":"MIT","port_status":"requires_native_port","baseline_sha":"b43e832fcc8000ed7287c7accc54e381db607f85"}"#,
            BundledManifestError::Malformed,
        ),
        (
            "javascript execution",
            r#"{"schema_version":1,"id":"weather","classification":"official_integration","source_path":"skills/weather/SKILL.md","license":"MIT","port_status":"javascript","baseline_sha":"b43e832fcc8000ed7287c7accc54e381db607f85"}"#,
            BundledManifestError::Malformed,
        ),
        (
            "future schema version",
            r#"{"schema_version":2,"id":"weather","classification":"official_integration","source_path":"skills/weather/SKILL.md","license":"MIT","port_status":"requires_native_port","baseline_sha":"b43e832fcc8000ed7287c7accc54e381db607f85"}"#,
            BundledManifestError::UnsupportedSchemaVersion(2),
        ),
        (
            "traversing identifier",
            r#"{"schema_version":1,"id":"../weather","classification":"official_integration","source_path":"skills/../weather/SKILL.md","license":"MIT","port_status":"requires_native_port","baseline_sha":"b43e832fcc8000ed7287c7accc54e381db607f85"}"#,
            BundledManifestError::InvalidId,
        ),
        (
            "foreign source path",
            r#"{"schema_version":1,"id":"weather","classification":"official_integration","source_path":"skills/sunshine/SKILL.md","license":"MIT","port_status":"requires_native_port","baseline_sha":"b43e832fcc8000ed7287c7accc54e381db607f85"}"#,
            BundledManifestError::UnexpectedSourcePath,
        ),
        (
            "unpinned baseline",
            r#"{"schema_version":1,"id":"weather","classification":"official_integration","source_path":"skills/weather/SKILL.md","license":"MIT","port_status":"requires_native_port","baseline_sha":"0000000000000000000000000000000000000000"}"#,
            BundledManifestError::BaselineMismatch,
        ),
    ];

    for (name, document, expected) in cases {
        assert_eq!(
            parse_bundled_manifest(document),
            Err(expected),
            "case {name}"
        );
    }

    let empty_license = r#"{"schema_version":1,"id":"weather","classification":"official_integration","source_path":"skills/weather/SKILL.md","license":"","port_status":"requires_native_port","baseline_sha":"b43e832fcc8000ed7287c7accc54e381db607f85"}"#;
    assert_eq!(
        parse_bundled_manifest(empty_license),
        Err(BundledManifestError::InvalidLicense)
    );
}

#[test]
fn manifest_parsing_accepts_the_canonical_document() {
    let manifest = parse_bundled_manifest(&valid_manifest_json("weather")).expect("valid manifest");

    assert_eq!(manifest.id(), "weather");
    assert_eq!(manifest.schema_version(), BUNDLED_SCHEMA_VERSION);
    assert_eq!(manifest.source_path(), "skills/weather/SKILL.md");
    assert_eq!(manifest.license(), "MIT");
    assert_eq!(manifest.baseline_sha(), BUNDLED_BASELINE_SHA);
    assert_eq!(
        manifest.classification(),
        SkillClassification::OfficialIntegration
    );
    assert_eq!(manifest.port_status(), SkillPortStatus::RequiresNativePort);
}

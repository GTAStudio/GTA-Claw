//! End-to-end and mutation-based conformance harness tests.

use std::fs;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

use claw_conformance::{
    ClaimLevel, ConformanceError, Contract, Evidence, FeatureClaim, InventoryClaim, ParityStatus,
    Registry, ViolationCode, discover_claim_files, generate_report,
};

static NEXT_FIXTURE: AtomicU64 = AtomicU64::new(0);

struct Fixture {
    root: PathBuf,
}

impl Fixture {
    fn copy_upstream() -> Self {
        let root = std::env::temp_dir().join(format!(
            "claw-conformance-{}-{}",
            std::process::id(),
            NEXT_FIXTURE.fetch_add(1, Ordering::Relaxed)
        ));
        copy_directory(&upstream_root(), &root);
        Self { root }
    }

    fn empty() -> Self {
        let root = std::env::temp_dir().join(format!(
            "claw-conformance-evidence-{}-{}",
            std::process::id(),
            NEXT_FIXTURE.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir_all(&root).expect("create fixture");
        Self { root }
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        if self.root.exists() {
            fs::remove_dir_all(&self.root).expect("remove fixture");
        }
    }
}

fn upstream_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join("..")
        .join("compat")
        .join("upstream")
}

fn repository_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("..").join("..")
}

fn copy_directory(source: &Path, destination: &Path) {
    fs::create_dir_all(destination).expect("create destination");
    for entry in fs::read_dir(source).expect("read source") {
        let entry = entry.expect("read entry");
        let source_path = entry.path();
        let destination_path = destination.join(entry.file_name());
        if source_path.is_dir() {
            copy_directory(&source_path, &destination_path);
        } else {
            fs::copy(source_path, destination_path).expect("copy fixture file");
        }
    }
}

fn load_error(root: &Path) -> ConformanceError {
    Contract::load(root).expect_err("mutated contract must fail")
}

fn mutate_json(path: &Path, mutate: impl FnOnce(&mut serde_json::Value)) {
    let source = fs::read_to_string(path).expect("read JSON fixture");
    let mut value: serde_json::Value =
        serde_json::from_str(source.trim_start_matches('\u{feff}')).expect("parse JSON fixture");
    mutate(&mut value);
    fs::write(
        path,
        serde_json::to_vec_pretty(&value).expect("serialize JSON fixture"),
    )
    .expect("write JSON fixture");
}

#[test]
fn real_frozen_contract_loads_every_row() {
    let contract = Contract::load(upstream_root()).expect("load frozen contract");
    assert_eq!(
        contract.baseline_sha(),
        "b43e832fcc8000ed7287c7accc54e381db607f85"
    );
    assert_eq!(contract.ledgers().len(), 3);
    assert_eq!(
        contract
            .ledgers()
            .iter()
            .map(|ledger| (ledger.id(), ledger.features().len()))
            .collect::<Vec<_>>(),
        vec![
            ("gateway-core", 16),
            ("official-integration", 13),
            ("official-client-interop", 18),
        ]
    );
    assert_eq!(contract.inventories().len(), 10);
    assert_eq!(
        contract
            .inventories()
            .iter()
            .map(|(id, records)| (id.as_str(), records.len()))
            .collect::<Vec<_>>(),
        vec![
            ("channels", 29),
            ("clients", 10),
            ("config-domains", 47),
            ("gateway-protocol", 320),
            ("http-sse-endpoints", 18),
            ("migrations", 3),
            ("plugins", 137),
            ("providers", 78),
            ("release-deployment", 24),
            ("skills", 51),
        ]
    );
}

#[test]
fn workspace_claim_manifests_pass_conformance() {
    let repository = repository_root();
    let contract =
        Contract::load(repository.join("compat").join("upstream")).expect("load frozen contract");
    let mut registry = Registry::new();
    let claim_files = discover_claim_files(&repository).expect("discover workspace claims");
    for claim_file in claim_files {
        registry
            .load_claims_file(claim_file)
            .expect("load workspace claims");
    }

    let report =
        generate_report(&contract, &registry, &repository).expect("validate workspace claims");
    assert_eq!(report.totals.total, 47);
    assert_eq!(
        report
            .inventories
            .iter()
            .map(|inventory| inventory.total)
            .sum::<usize>(),
        717
    );
}

#[test]
fn zero_registry_reports_the_honest_baseline() {
    let contract = Contract::load(upstream_root()).expect("load frozen contract");
    let report =
        generate_report(&contract, &Registry::new(), repository_root()).expect("generate report");
    assert_eq!(report.totals.implemented, 0);
    assert_eq!(report.totals.partial, 0);
    assert_eq!(report.totals.unimplemented, 47);
    assert_eq!(report.totals.total, 47);
    assert_eq!(report.totals.registered, 0);
    assert_eq!(
        report
            .ledgers
            .iter()
            .flat_map(|ledger| ledger.features.iter())
            .map(|feature| feature.status)
            .collect::<Vec<_>>(),
        vec![ParityStatus::Unimplemented; 47]
    );
    assert_eq!(
        report
            .ledgers
            .iter()
            .flat_map(|ledger| ledger.features.iter())
            .filter(|feature| feature.registered)
            .count(),
        0
    );
    assert_eq!(
        report
            .inventories
            .iter()
            .map(|inventory| (
                inventory.inventory_id.as_str(),
                inventory.fully_implemented,
                inventory.registered,
                inventory.total,
            ))
            .collect::<Vec<_>>(),
        vec![
            ("channels", 0, 0, 29),
            ("clients", 0, 0, 10),
            ("config-domains", 0, 0, 47),
            ("gateway-protocol", 0, 0, 320),
            ("http-sse-endpoints", 0, 0, 18),
            ("migrations", 0, 0, 3),
            ("plugins", 0, 0, 137),
            ("providers", 0, 0, 78),
            ("release-deployment", 0, 0, 24),
            ("skills", 0, 0, 51),
        ]
    );
}

#[test]
fn fabricated_evidence_free_claim_is_rejected() {
    let contract = Contract::load(upstream_root()).expect("load frozen contract");
    let mut registry = Registry::new();
    registry
        .register_feature(FeatureClaim::new(
            "gateway.protocol.v4",
            ClaimLevel::Implemented,
            Vec::new(),
        ))
        .expect("register fabricated claim");
    let error = generate_report(&contract, &registry, repository_root())
        .expect_err("evidence-free claim must fail");
    assert_eq!(error.code(), ViolationCode::ClaimEvidence);
    assert_eq!(error.subject(), Some("gateway.protocol.v4"));
    assert_eq!(error.json_path(), None);
    assert_eq!(error.message(), "claim has no recorded evidence");
}

#[test]
fn metadata_registration_never_inflates_implementation() {
    let contract = Contract::load(upstream_root()).expect("load frozen contract");
    let mut registry = Registry::new();
    registry
        .register_feature(FeatureClaim::registered("gateway.protocol.v4"))
        .expect("register feature metadata");
    registry
        .register_inventory(InventoryClaim::registered("providers", "provider:qianfan"))
        .expect("register inventory metadata");

    let report = generate_report(&contract, &registry, repository_root()).expect("generate report");
    assert_eq!(report.totals.implemented, 0);
    assert_eq!(report.totals.partial, 0);
    assert_eq!(report.totals.unimplemented, 47);
    assert_eq!(report.totals.registered, 1);
    let feature = report
        .ledgers
        .iter()
        .flat_map(|ledger| ledger.features.iter())
        .find(|feature| feature.feature_id == "gateway.protocol.v4")
        .expect("feature report");
    assert_eq!(feature.status, ParityStatus::Unimplemented);
    assert!(feature.registered);
    assert_eq!(feature.evidence_count, 0);
    let providers = report
        .inventories
        .iter()
        .find(|inventory| inventory.inventory_id == "providers")
        .expect("providers report");
    assert_eq!(providers.fully_implemented, 0);
    assert_eq!(providers.registered, 1);
    assert_eq!(providers.total, 78);
}

#[test]
fn fabricated_test_name_is_rejected() {
    let contract = Contract::load(upstream_root()).expect("load frozen contract");
    let fixture = Fixture::empty();
    let evidence_path = Path::new("crates").join("demo").join("tests.rs");
    fs::create_dir_all(fixture.root.join("crates").join("demo")).expect("create evidence parent");
    fs::write(
        fixture.root.join(&evidence_path),
        "#[test]\nfn real_test() { assert_eq!(2 + 2, 4); }\n",
    )
    .expect("write evidence");
    let mut registry = Registry::new();
    registry
        .register_feature(FeatureClaim::implemented(
            "gateway.protocol.v4",
            vec![Evidence::test(&evidence_path, "fabricated_test")],
        ))
        .expect("register claim");
    let error = generate_report(&contract, &registry, &fixture.root)
        .expect_err("fabricated test name must fail");
    assert_eq!(error.code(), ViolationCode::ClaimEvidence);
    assert_eq!(error.subject(), Some("gateway.protocol.v4"));
    assert_eq!(
        error.message(),
        format!(
            "evidence test 'fabricated_test' is not declared in '{}'",
            evidence_path.display()
        )
    );
}

#[test]
fn verified_feature_and_inventory_claims_are_counted() {
    let contract = Contract::load(upstream_root()).expect("load frozen contract");
    let fixture = Fixture::empty();
    let evidence_path = Path::new("crates").join("demo").join("tests.rs");
    fs::create_dir_all(fixture.root.join("crates").join("demo")).expect("create evidence parent");
    fs::write(
        fixture.root.join(&evidence_path),
        "#[test]\nfn proves_gateway_v4() { assert_eq!(4, 4); }\n\
         #[test]\nfn proves_qianfan() { assert_eq!(78, 78); }\n",
    )
    .expect("write evidence");
    let mut registry = Registry::new();
    registry
        .register_feature(FeatureClaim::implemented(
            "gateway.protocol.v4",
            vec![Evidence::test(&evidence_path, "proves_gateway_v4")],
        ))
        .expect("register feature");
    registry
        .register_inventory(InventoryClaim::implemented(
            "providers",
            "provider:qianfan",
            vec![Evidence::test(&evidence_path, "proves_qianfan")],
        ))
        .expect("register inventory");

    let report = generate_report(&contract, &registry, &fixture.root).expect("generate report");
    assert_eq!(report.totals.implemented, 1);
    assert_eq!(report.totals.partial, 0);
    assert_eq!(report.totals.unimplemented, 46);
    assert_eq!(report.totals.registered, 1);
    let providers = report
        .inventories
        .iter()
        .find(|inventory| inventory.inventory_id == "providers")
        .expect("providers report");
    assert_eq!(providers.fully_implemented, 1);
    assert_eq!(providers.registered, 1);
    assert_eq!(providers.total, 78);
}

#[test]
fn renamed_inventory_id_is_rejected_as_drift() {
    let fixture = Fixture::copy_upstream();
    let path = fixture.root.join("inventories").join("providers.json");
    let source = fs::read_to_string(&path).expect("read providers");
    assert_eq!(source.matches("\"id\":  \"qianfan\"").count(), 1);
    fs::write(
        &path,
        source.replacen("\"id\":  \"qianfan\"", "\"id\":  \"renamed-qianfan\"", 1),
    )
    .expect("mutate providers");

    let error = load_error(&fixture.root);
    assert_eq!(error.code(), ViolationCode::InventoryDrift);
    assert_eq!(error.subject(), Some("providers"));
    assert_eq!(error.json_path(), None);
}

#[test]
fn raised_ledger_status_without_evidence_is_rejected() {
    let fixture = Fixture::copy_upstream();
    let path = fixture.root.join("ledgers").join("gateway-core.json");
    let source = fs::read_to_string(&path).expect("read ledger");
    assert_eq!(source.matches("\"status\":  \"unimplemented\"").count(), 16);
    fs::write(
        &path,
        source.replacen(
            "\"status\":  \"unimplemented\"",
            "\"status\":  \"implemented\"",
            1,
        ),
    )
    .expect("mutate ledger");

    let error = load_error(&fixture.root);
    assert_eq!(error.code(), ViolationCode::LedgerEvidence);
    assert_eq!(error.subject(), Some("gateway.protocol.v4"));
    assert_eq!(error.json_path(), None);
    assert_eq!(
        error.message(),
        "ledger status implemented requires recorded acceptance evidence"
    );
}

#[test]
fn legitimate_ledger_transitions_do_not_require_frozen_hashes() {
    let fixture = Fixture::copy_upstream();
    let path = fixture.root.join("ledgers").join("gateway-core.json");
    mutate_json(&path, |ledger| {
        let features = ledger["features"].as_array_mut().expect("features array");
        features[0]["status"] = serde_json::json!("partial");
        features[0]["acceptance_evidence"]["status"] = serde_json::json!("partial");
        features[0]["acceptance_evidence"]["artifacts"] =
            serde_json::json!(["crates/claw-gateway/tests/protocol.rs::negotiates_v4"]);
        features[1]["status"] = serde_json::json!("implemented");
        features[1]["acceptance_evidence"]["status"] = serde_json::json!("accepted");
        features[1]["acceptance_evidence"]["artifacts"] =
            serde_json::json!(["crates/claw-gateway/tests/protocol.rs::accepts_node_v3"]);
    });
    let validator = fixture.root.join("validate.ps1");
    let mut validator_source = fs::read_to_string(&validator).expect("read validator");
    validator_source.push_str("\n# Transition command fixture\n");
    fs::write(validator, validator_source).expect("write validator fixture");

    let contract = Contract::load(&fixture.root).expect("load transitioned ledger");
    assert_eq!(contract.ledgers()[0].id(), "gateway-core");
    assert_eq!(contract.ledgers()[0].features().len(), 16);
    assert_eq!(
        contract.ledgers()[0].features()[0].id(),
        "gateway.protocol.v4"
    );
    assert_eq!(
        contract.ledgers()[0].features()[1].id(),
        "gateway.protocol.node-v3-window"
    );
}

#[test]
fn duplicate_feature_id_across_ledgers_is_rejected() {
    let fixture = Fixture::copy_upstream();
    let path = fixture
        .root
        .join("ledgers")
        .join("official-integration.json");
    mutate_json(&path, |ledger| {
        ledger["features"][0]["feature_id"] = serde_json::json!("gateway.protocol.v4");
    });

    let error = load_error(&fixture.root);
    assert_eq!(error.code(), ViolationCode::LedgerDrift);
    assert_eq!(error.subject(), Some("gateway.protocol.v4"));
    assert_eq!(error.json_path(), None);
    assert_eq!(error.message(), "duplicate feature ID across ledgers");
}

#[test]
fn feature_classification_must_match_its_ledger() {
    let fixture = Fixture::copy_upstream();
    let path = fixture.root.join("ledgers").join("gateway-core.json");
    mutate_json(&path, |ledger| {
        ledger["features"][0]["classification"] = serde_json::json!("official_integration");
    });

    let error = load_error(&fixture.root);
    assert_eq!(error.code(), ViolationCode::LedgerDrift);
    assert_eq!(error.subject(), Some("gateway.protocol.v4"));
    assert_eq!(error.json_path(), None);
    assert_eq!(
        error.message(),
        "feature classification official_integration does not match ledger classification gateway_core"
    );
}

#[test]
fn feature_last_verified_sha_must_match_the_baseline() {
    let fixture = Fixture::copy_upstream();
    let path = fixture.root.join("ledgers").join("gateway-core.json");
    mutate_json(&path, |ledger| {
        ledger["features"][0]["last_verified_sha"] =
            serde_json::json!("0000000000000000000000000000000000000000");
    });

    let error = load_error(&fixture.root);
    assert_eq!(error.code(), ViolationCode::LedgerDrift);
    assert_eq!(error.subject(), Some("gateway.protocol.v4"));
    assert_eq!(error.json_path(), None);
    assert_eq!(
        error.message(),
        "last_verified_sha must equal b43e832fcc8000ed7287c7accc54e381db607f85"
    );
}

#[test]
fn unknown_ledger_status_is_rejected_at_its_json_path() {
    let fixture = Fixture::copy_upstream();
    let path = fixture.root.join("ledgers").join("gateway-core.json");
    mutate_json(&path, |ledger| {
        ledger["features"][0]["status"] = serde_json::json!("blocked");
    });

    let error = load_error(&fixture.root);
    assert_eq!(error.code(), ViolationCode::JsonSchema);
    assert_eq!(error.subject(), Some("ledgers/gateway-core.json"));
    assert_eq!(error.json_path(), Some("features[0].status"));
}

#[test]
fn blank_ledger_evidence_artifact_is_rejected() {
    let fixture = Fixture::copy_upstream();
    let path = fixture.root.join("ledgers").join("gateway-core.json");
    mutate_json(&path, |ledger| {
        ledger["features"][0]["status"] = serde_json::json!("partial");
        ledger["features"][0]["acceptance_evidence"]["status"] = serde_json::json!("partial");
        ledger["features"][0]["acceptance_evidence"]["artifacts"] = serde_json::json!(["   "]);
    });

    let error = load_error(&fixture.root);
    assert_eq!(error.code(), ViolationCode::LedgerEvidence);
    assert_eq!(error.subject(), Some("gateway.protocol.v4"));
    assert_eq!(error.json_path(), None);
    assert_eq!(
        error.message(),
        "acceptance evidence contains a blank artifact"
    );
}

#[test]
fn partial_ledger_status_requires_partial_evidence_state() {
    let fixture = Fixture::copy_upstream();
    let path = fixture.root.join("ledgers").join("gateway-core.json");
    mutate_json(&path, |ledger| {
        ledger["features"][0]["status"] = serde_json::json!("partial");
        ledger["features"][0]["acceptance_evidence"]["status"] = serde_json::json!("accepted");
        ledger["features"][0]["acceptance_evidence"]["artifacts"] =
            serde_json::json!(["crates/claw-gateway/tests/protocol.rs::negotiates_v4"]);
    });

    let error = load_error(&fixture.root);
    assert_eq!(error.code(), ViolationCode::LedgerEvidence);
    assert_eq!(error.subject(), Some("gateway.protocol.v4"));
    assert_eq!(error.json_path(), None);
    assert_eq!(
        error.message(),
        "partial ledger status requires partial evidence"
    );
}

#[test]
fn blank_ledger_evidence_requirement_is_rejected() {
    let fixture = Fixture::copy_upstream();
    let path = fixture.root.join("ledgers").join("gateway-core.json");
    mutate_json(&path, |ledger| {
        ledger["features"][0]["status"] = serde_json::json!("partial");
        ledger["features"][0]["acceptance_evidence"]["status"] = serde_json::json!("partial");
        ledger["features"][0]["acceptance_evidence"]["artifacts"] =
            serde_json::json!(["crates/claw-gateway/tests/protocol.rs::negotiates_v4"]);
        ledger["features"][0]["acceptance_evidence"]["required"] = serde_json::json!(" ");
    });

    let error = load_error(&fixture.root);
    assert_eq!(error.code(), ViolationCode::LedgerEvidence);
    assert_eq!(error.subject(), Some("gateway.protocol.v4"));
    assert_eq!(error.json_path(), None);
    assert_eq!(
        error.message(),
        "acceptance evidence requirement must not be blank"
    );
}

#[test]
fn unimplemented_ledger_status_rejects_populated_evidence() {
    let fixture = Fixture::copy_upstream();
    let path = fixture.root.join("ledgers").join("gateway-core.json");
    mutate_json(&path, |ledger| {
        ledger["features"][0]["acceptance_evidence"]["status"] = serde_json::json!("partial");
        ledger["features"][0]["acceptance_evidence"]["artifacts"] =
            serde_json::json!(["crates/claw-gateway/tests/protocol.rs::negotiates_v4"]);
    });

    let error = load_error(&fixture.root);
    assert_eq!(error.code(), ViolationCode::LedgerEvidence);
    assert_eq!(error.subject(), Some("gateway.protocol.v4"));
    assert_eq!(error.json_path(), None);
    assert_eq!(
        error.message(),
        "unimplemented ledger status requires missing acceptance evidence"
    );
}

#[test]
fn mutable_ledger_rows_still_obey_the_frozen_schema() {
    let fixture = Fixture::copy_upstream();
    let path = fixture.root.join("ledgers").join("gateway-core.json");
    mutate_json(&path, |ledger| {
        ledger["features"][0]["title"] = serde_json::json!("");
    });

    let error = load_error(&fixture.root);
    assert_eq!(error.code(), ViolationCode::JsonSchema);
    assert_eq!(error.subject(), Some("ledgers/gateway-core.json"));
    assert_eq!(error.json_path(), Some("features[0].title"));
    assert_eq!(error.message(), "title must not be empty");
}

#[test]
fn windows_path_is_not_accepted_as_an_official_uri() {
    let fixture = Fixture::copy_upstream();
    let path = fixture.root.join("ledgers").join("gateway-core.json");
    mutate_json(&path, |ledger| {
        ledger["features"][0]["upstream_source"]["official_url"] =
            serde_json::json!("C:\\not-a-uri");
    });

    let error = load_error(&fixture.root);
    assert_eq!(error.code(), ViolationCode::JsonSchema);
    assert_eq!(error.subject(), Some("ledgers/gateway-core.json"));
    assert_eq!(
        error.json_path(),
        Some("features[0].upstream_source.official_url")
    );
    assert_eq!(error.message(), "official_url must be an absolute URI");
}

#[test]
fn forward_slash_windows_path_is_not_accepted_as_an_official_uri() {
    let fixture = Fixture::copy_upstream();
    let path = fixture.root.join("ledgers").join("gateway-core.json");
    mutate_json(&path, |ledger| {
        ledger["features"][0]["upstream_source"]["official_url"] =
            serde_json::json!("C:/not-a-uri");
    });

    let error = load_error(&fixture.root);
    assert_eq!(error.code(), ViolationCode::JsonSchema);
    assert_eq!(
        error.json_path(),
        Some("features[0].upstream_source.official_url")
    );
    assert_eq!(error.message(), "official_url must be an absolute URI");
}

#[test]
fn malformed_percent_escape_is_not_accepted_as_an_official_uri() {
    let fixture = Fixture::copy_upstream();
    let path = fixture.root.join("ledgers").join("gateway-core.json");
    mutate_json(&path, |ledger| {
        ledger["features"][0]["upstream_source"]["official_url"] =
            serde_json::json!("https://docs.openclaw.ai/invalid%2");
    });

    let error = load_error(&fixture.root);
    assert_eq!(error.code(), ViolationCode::JsonSchema);
    assert_eq!(
        error.json_path(),
        Some("features[0].upstream_source.official_url")
    );
    assert_eq!(error.message(), "official_url must be an absolute URI");
}

#[test]
fn non_ascii_official_uri_is_rejected() {
    let fixture = Fixture::copy_upstream();
    let path = fixture.root.join("ledgers").join("gateway-core.json");
    mutate_json(&path, |ledger| {
        ledger["features"][0]["upstream_source"]["official_url"] =
            serde_json::json!("https://docs.openclaw.ai/\u{00a0}");
    });

    let error = load_error(&fixture.root);
    assert_eq!(error.code(), ViolationCode::JsonSchema);
    assert_eq!(
        error.json_path(),
        Some("features[0].upstream_source.official_url")
    );
    assert_eq!(error.message(), "official_url must be an absolute URI");
}

#[test]
fn explicit_null_is_not_accepted_as_an_official_uri() {
    let fixture = Fixture::copy_upstream();
    let path = fixture.root.join("ledgers").join("gateway-core.json");
    mutate_json(&path, |ledger| {
        ledger["features"][0]["upstream_source"]["official_url"] = serde_json::Value::Null;
    });

    let error = load_error(&fixture.root);
    assert_eq!(error.code(), ViolationCode::JsonSchema);
    assert_eq!(error.subject(), Some("ledgers/gateway-core.json"));
    assert_eq!(
        error.json_path(),
        Some("features[0].upstream_source.official_url")
    );
}

#[test]
fn whitespace_padded_official_uri_is_rejected() {
    let fixture = Fixture::copy_upstream();
    let path = fixture.root.join("ledgers").join("gateway-core.json");
    mutate_json(&path, |ledger| {
        ledger["features"][0]["upstream_source"]["official_url"] =
            serde_json::json!(" https://docs.openclaw.ai/gateway ");
    });

    let error = load_error(&fixture.root);
    assert_eq!(error.code(), ViolationCode::JsonSchema);
    assert_eq!(error.subject(), Some("ledgers/gateway-core.json"));
    assert_eq!(
        error.json_path(),
        Some("features[0].upstream_source.official_url")
    );
    assert_eq!(error.message(), "official_url must be an absolute URI");
}

#[test]
fn trailing_json_content_is_rejected() {
    let fixture = Fixture::copy_upstream();
    let path = fixture.root.join("ledgers").join("gateway-core.json");
    let mut source = fs::read_to_string(&path).expect("read ledger");
    source.push_str("\n{}\n");
    fs::write(path, source).expect("append trailing JSON");

    let error = load_error(&fixture.root);
    assert_eq!(error.code(), ViolationCode::JsonSchema);
    assert_eq!(error.subject(), Some("ledgers/gateway-core.json"));
    assert_eq!(error.json_path(), Some("$"));
    assert_eq!(error.message(), "trailing content after the JSON document");
}

#[test]
fn baseline_artifact_retains_an_independent_frozen_hash() {
    let fixture = Fixture::copy_upstream();
    let path = fixture.root.join("baseline.json");
    let mut source = fs::read_to_string(&path).expect("read baseline");
    source.push('\n');
    fs::write(path, source).expect("mutate baseline");

    let error = load_error(&fixture.root);
    assert_eq!(error.code(), ViolationCode::ManifestDrift);
    assert_eq!(error.subject(), Some("baseline.json"));
    assert_eq!(error.json_path(), None);
    assert_eq!(
        error.message(),
        "frozen support artifact changed in baseline.json; expected SHA-256 \
         02bdfca9e47ace25ffd99199f2efc8dd04b80f0c4b35c8a63b08700dd9846dea, found \
         9af9feea2b1dc352420fe63b05325cb50ee7b2159a22d217a9647fb1e3b1ae74"
    );
}

#[test]
fn malformed_ledger_reports_the_precise_json_path() {
    let fixture = Fixture::copy_upstream();
    let path = fixture.root.join("ledgers").join("gateway-core.json");
    let source = fs::read_to_string(&path).expect("read ledger");
    assert_eq!(source.matches("\"tier\":  \"tier_1\"").count(), 16);
    fs::write(
        &path,
        source.replacen("\"tier\":  \"tier_1\"", "\"tier\":  \"tier_9\"", 1),
    )
    .expect("mutate ledger");

    let error = load_error(&fixture.root);
    assert_eq!(error.code(), ViolationCode::JsonSchema);
    assert_eq!(error.subject(), Some("ledgers/gateway-core.json"));
    assert_eq!(error.json_path(), Some("features[0].tier"));
}

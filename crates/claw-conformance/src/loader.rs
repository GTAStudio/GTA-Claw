//! Contract loading, schema checks, and drift detection.

use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::{Path, PathBuf};

use serde::de::DeserializeOwned;
use sha2::{Digest, Sha256};

use crate::claims::{CargoTestTargets, validate_evidence_as, validate_implementation_pointers};
use crate::error::{ConformanceError, ViolationCode};
use crate::model::{
    ChannelCounts, ChannelItem, Classification, ClientCounts, ClientItem, ConfigDomainCounts,
    ConfigDomainItem, EvidenceStatus, FeatureLedger, GatewayProtocolCounts, GatewayProtocolItem,
    HttpEndpointCounts, HttpEndpointItem, IntoInventoryRecord, Inventory, InventoryCounts,
    InventoryHeader, InventoryRecord, LedgerStatus, Manifest, MigrationCounts, MigrationItem,
    PluginCounts, PluginItem, ProviderCounts, ProviderItem, ReleaseDeploymentCounts,
    ReleaseDeploymentItem, SkillCounts, SkillItem,
};

const BASELINE_SHA: &str = "b43e832fcc8000ed7287c7accc54e381db607f85";
const BASELINE_HASH: &str = "02bdfca9e47ace25ffd99199f2efc8dd04b80f0c4b35c8a63b08700dd9846dea";
const LEGACY_FEATURE_SCHEMA_HASH: &str =
    "ee62fe4022cf7a3dc5165b817547dc07a49b3d0db763ca8b2c153512ce328525";
const TRANSITION_FEATURE_SCHEMA_HASH: &str =
    "15a7a366313e5c23dac7abdc5105f6eb630082c334dc0d0dfcd263acddeffcfe";
const BASELINE_KNOWN_DIFFERENCE: &str = "No npm-free Rust implementation or acceptance evidence exists in this repository at this baseline.";

const LEDGER_SPECS: [(&str, &str, Classification, usize); 3] = [
    (
        "ledgers/gateway-core.json",
        "gateway-core",
        Classification::GatewayCore,
        16,
    ),
    (
        "ledgers/official-integration.json",
        "official-integration",
        Classification::OfficialIntegration,
        13,
    ),
    (
        "ledgers/official-client-interop.json",
        "official-client-interop",
        Classification::OfficialClientInterop,
        18,
    ),
];

const INVENTORY_SPECS: [(&str, &str, usize, &str); 10] = [
    (
        "inventories/plugins.json",
        "plugins",
        137,
        "e5048024ec76cbb9d55f240466f83ed4fe5af1457b2b444e048110ef50ace693",
    ),
    (
        "inventories/skills.json",
        "skills",
        51,
        "609b9e7d60029552a199f6e21966c06e2dba55923f0136c2980a81f417a94386",
    ),
    (
        "inventories/gateway-protocol.json",
        "gateway-protocol",
        320,
        "0ca2cf58f1a924095c1fee0af5765b61871b35d590dfb2932d459c4ca8a71996",
    ),
    (
        "inventories/config-domains.json",
        "config-domains",
        47,
        "cee931e704b75e932018dd62a9882d0ddeb736c7d91696c3054a9dd881c82887",
    ),
    (
        "inventories/providers.json",
        "providers",
        78,
        "f3fca0636590829237a07789d2f28e8654c452da8dc00cc82decff83b05831ed",
    ),
    (
        "inventories/channels.json",
        "channels",
        29,
        "a54a127a08eb07a439dc0e062706ce3ce9fc171ecaedd0d40fd07e1cb53ba505",
    ),
    (
        "inventories/http-sse-endpoints.json",
        "http-sse-endpoints",
        18,
        "f6af49d66fd92407c2db491eaa7d5c9f8341d4c9d3d254bf944d7068b1d8234e",
    ),
    (
        "inventories/clients.json",
        "clients",
        10,
        "5c4744468ddd710d7d8d41846a3f31fae7eb7eb162284a1126900a11cf576117",
    ),
    (
        "inventories/migrations.json",
        "migrations",
        3,
        "b363a047b0b3b7bfc3797572a983ade14a29b51aa42e8b24cbcd791ab0cd9ac0",
    ),
    (
        "inventories/release-deployment.json",
        "release-deployment",
        24,
        "757d87d3fdd2134040b669db2b2ae15651090e96ff4cb82d5b684497f20cd4fc",
    ),
];

/// Fully validated upstream contract.
#[derive(Clone, Debug)]
pub struct Contract {
    root: PathBuf,
    baseline_sha: String,
    ledgers: Vec<FeatureLedger>,
    inventories: BTreeMap<String, Vec<InventoryRecord>>,
    cargo_test_targets: Option<CargoTestTargets>,
}

impl Contract {
    /// Loads all three ledgers and all ten inventories from `compat/upstream`.
    ///
    /// # Errors
    ///
    /// Returns a [`ViolationCode::Io`] error when a frozen artifact is missing
    /// or unreadable, and a [`ViolationCode::JsonSchema`] error carrying the
    /// exact serde JSON path when one does not match its strongly typed schema.
    ///
    /// The remaining variants report drift in artifacts that are supposed to be
    /// byte-sealed and must be investigated, never re-baselined to make the
    /// check pass: [`ViolationCode::ManifestDrift`] when `baseline.json`, the
    /// feature schema, or the fixed manifest metadata no longer hashes to its
    /// pinned digest; [`ViolationCode::InventoryDrift`] when an inventory's
    /// content hash, ID, or row count changed, which means a frozen upstream ID
    /// was renamed or removed; [`ViolationCode::LedgerDrift`] when a ledger's
    /// ID, classification, baseline SHA, or row count changed, a feature ID is
    /// duplicated across ledgers, or the total is not exactly 47 rows; and
    /// [`ViolationCode::LedgerEvidence`] when a ledger row claims a status above
    /// `unimplemented` without the acceptance evidence that status requires.
    pub fn load(root: impl AsRef<Path>) -> Result<Self, ConformanceError> {
        let root = root.as_ref();
        let repository_root = repository_root_for_contract(root);
        let baseline_bytes = read_file(root, "baseline.json")?;
        verify_hash(
            "baseline.json",
            &baseline_bytes,
            BASELINE_HASH,
            ViolationCode::ManifestDrift,
            "baseline.json",
            "frozen support artifact changed",
        )?;
        let schema_bytes = read_file(root, "feature-ledger.schema.json")?;
        let schema_hash = verify_hashes(
            "feature-ledger.schema.json",
            &schema_bytes,
            &[LEGACY_FEATURE_SCHEMA_HASH, TRANSITION_FEATURE_SCHEMA_HASH],
            ViolationCode::ManifestDrift,
            "feature-ledger.schema.json",
            "frozen support artifact changed",
        )?;
        let transition_schema = schema_hash == TRANSITION_FEATURE_SCHEMA_HASH;
        let manifest: Manifest = parse_file(root, "manifest.json")?;
        validate_manifest(&manifest, transition_schema)?;

        let mut ledgers = Vec::with_capacity(LEDGER_SPECS.len());
        let mut feature_ids = BTreeSet::new();
        let mut cargo_test_targets = None;
        for (path, expected_id, classification, expected_rows) in LEDGER_SPECS {
            let bytes = read_file(root, path)?;
            let ledger: FeatureLedger = parse_bytes(path, &bytes)?;
            validate_ledger(
                &ledger,
                path,
                expected_id,
                classification,
                expected_rows,
                &repository_root,
                &mut cargo_test_targets,
            )?;
            for feature in ledger.features() {
                if !feature_ids.insert(feature.id().to_owned()) {
                    return Err(ConformanceError::new(
                        ViolationCode::LedgerDrift,
                        Some(feature.id().to_owned()),
                        "duplicate feature ID across ledgers".to_owned(),
                    ));
                }
            }
            ledgers.push(ledger);
        }
        if feature_ids.len() != 47 {
            return Err(ConformanceError::new(
                ViolationCode::LedgerDrift,
                Some("ledgers".to_owned()),
                format!(
                    "expected exactly 47 feature rows, found {}",
                    feature_ids.len()
                ),
            ));
        }
        validate_manifest_status_totals(&manifest, &ledgers, transition_schema)?;

        let mut inventories = BTreeMap::new();
        for (path, expected_id, expected_rows, expected_hash) in INVENTORY_SPECS {
            let bytes = read_file(root, path)?;
            let records = parse_inventory(path, &bytes, expected_id, expected_rows)?;
            verify_hash(
                path,
                &bytes,
                expected_hash,
                ViolationCode::InventoryDrift,
                expected_id,
                "frozen inventory identity/source changed; an ID may have disappeared or been renamed",
            )?;
            inventories.insert(expected_id.to_owned(), records);
        }

        Ok(Self {
            root: root.to_path_buf(),
            baseline_sha: manifest.baseline_sha,
            ledgers,
            inventories,
            cargo_test_targets,
        })
    }

    /// Root directory containing the frozen contract.
    #[must_use]
    pub fn root(&self) -> &Path {
        &self.root
    }

    /// Frozen upstream commit SHA.
    #[must_use]
    pub fn baseline_sha(&self) -> &str {
        &self.baseline_sha
    }

    /// Validated ledgers in canonical order.
    #[must_use]
    pub fn ledgers(&self) -> &[FeatureLedger] {
        &self.ledgers
    }

    /// Validated inventories keyed by inventory ID.
    #[must_use]
    pub const fn inventories(&self) -> &BTreeMap<String, Vec<InventoryRecord>> {
        &self.inventories
    }

    pub(crate) fn cargo_test_targets(&self, repository_root: &Path) -> Option<CargoTestTargets> {
        self.cargo_test_targets
            .as_ref()
            .filter(|targets| targets.is_for_repository(repository_root))
            .cloned()
    }
}

fn validate_manifest(manifest: &Manifest, transition_schema: bool) -> Result<(), ConformanceError> {
    let fail = |message: String| {
        ConformanceError::new(
            ViolationCode::ManifestDrift,
            Some("manifest.json".to_owned()),
            message,
        )
    };
    if manifest.schema_version != 1
        || manifest.artifact_set != "openclaw-upstream-compatibility-baseline"
        || manifest.baseline_sha != BASELINE_SHA
        || manifest.baseline_path != "baseline.json"
        || manifest.feature_schema_path != "feature-ledger.schema.json"
        || manifest.validation_script != "validate.ps1"
        || manifest.validation_self_test != "validate-self-test.ps1"
    {
        return Err(fail("fixed manifest metadata changed".to_owned()));
    }
    if manifest.ledgers.len() != LEDGER_SPECS.len() {
        return Err(fail(format!(
            "expected {} ledger declarations, found {}",
            LEDGER_SPECS.len(),
            manifest.ledgers.len()
        )));
    }
    for (path, _, classification, rows) in LEDGER_SPECS {
        let matches = manifest
            .ledgers
            .iter()
            .filter(|entry| entry.path == path)
            .collect::<Vec<_>>();
        if matches.len() != 1
            || matches[0].classification != classification
            || matches[0].expected_features != rows
        {
            return Err(fail(format!("ledger declaration drift for {path}")));
        }
    }
    if manifest.inventories.len() != INVENTORY_SPECS.len() {
        return Err(fail(format!(
            "expected {} inventory declarations, found {}",
            INVENTORY_SPECS.len(),
            manifest.inventories.len()
        )));
    }
    for (path, _, rows, _) in INVENTORY_SPECS {
        let matches = manifest
            .inventories
            .iter()
            .filter(|entry| entry.path == path)
            .collect::<Vec<_>>();
        if matches.len() != 1 || matches[0].expected_items != rows {
            return Err(fail(format!("inventory declaration drift for {path}")));
        }
    }
    let expected_counts = [
        ("artifact_json_files", 18),
        ("ledgers", 3),
        ("feature_rows", 47),
        ("inventory_files", 10),
        ("inventory_rows", 717),
        ("core_plugins", 64),
        ("official_external_plugins", 70),
        ("source_only_qa_plugins", 3),
        ("bundled_skills", 51),
        ("gateway_methods", 278),
        ("gateway_advertised_methods", 258),
        ("gateway_events", 33),
        ("gateway_roles", 3),
        ("gateway_scopes", 6),
        ("config_domains", 47),
        ("providers", 78),
        ("channels", 29),
        ("http_sse_endpoints", 18),
        ("client_surfaces", 10),
        ("migration_providers", 3),
        ("release_deployment_surfaces", 24),
    ]
    .into_iter()
    .map(|(key, value)| (key.to_owned(), value))
    .collect::<BTreeMap<_, _>>();
    if manifest.canonical_counts != expected_counts {
        for (key, expected) in &expected_counts {
            match manifest.canonical_counts.get(key) {
                Some(actual) if actual != expected => {
                    return Err(fail(format!(
                        "canonical count '{key}' must be {expected}, got {actual}"
                    )));
                }
                None => {
                    return Err(fail(format!(
                        "canonical count '{key}' must be {expected}, got missing"
                    )));
                }
                Some(_) => {}
            }
        }
        if let Some((key, actual)) = manifest
            .canonical_counts
            .iter()
            .find(|(key, _)| !expected_counts.contains_key(*key))
        {
            return Err(fail(format!(
                "unexpected canonical count '{key}' has value {actual}"
            )));
        }
    }
    if manifest.evidence_policy.initial_status != "unimplemented"
        || manifest.evidence_policy.acceptance_evidence_state != "missing"
        || !manifest
            .evidence_policy
            .legacy_typescript_is_not_rust_acceptance_evidence
    {
        return Err(fail(
            "canonical counts or evidence policy changed".to_owned(),
        ));
    }
    let transition_fields = [
        manifest.evidence_policy.allowed_statuses.is_some(),
        manifest.evidence_policy.artifact_fields.is_some(),
        manifest
            .evidence_policy
            .every_artifact_names_an_enabled_rust_test
            .is_some(),
        manifest
            .evidence_policy
            .implementation_pointers_are_not_acceptance_evidence
            .is_some(),
        manifest.evidence_policy.status_totals.is_some(),
    ];
    if !transition_schema && transition_fields.iter().any(|present| *present) {
        return Err(fail(
            "legacy evidence policy must not declare transition fields".to_owned(),
        ));
    }
    if transition_schema && transition_fields.iter().any(|present| !present) {
        return Err(fail(
            "transition evidence lifecycle policy is incomplete".to_owned(),
        ));
    }
    if transition_schema
        && (manifest.evidence_policy.allowed_statuses.as_deref()
            != Some(&[
                "unimplemented".to_owned(),
                "partial".to_owned(),
                "implemented".to_owned(),
            ])
            || manifest.evidence_policy.artifact_fields.as_deref()
                != Some(&["path".to_owned(), "test".to_owned()])
            || manifest
                .evidence_policy
                .every_artifact_names_an_enabled_rust_test
                != Some(true)
            || manifest
                .evidence_policy
                .implementation_pointers_are_not_acceptance_evidence
                != Some(true))
    {
        return Err(fail(
            "transition evidence lifecycle policy changed".to_owned(),
        ));
    }
    Ok(())
}

fn validate_manifest_status_totals(
    manifest: &Manifest,
    ledgers: &[FeatureLedger],
    transition_schema: bool,
) -> Result<(), ConformanceError> {
    if !transition_schema {
        if ledgers
            .iter()
            .flat_map(FeatureLedger::features)
            .any(|feature| feature.status != LedgerStatus::Unimplemented)
        {
            return Err(ConformanceError::new(
                ViolationCode::LedgerDrift,
                Some("ledgers".to_owned()),
                "legacy feature schema does not permit ledger status transitions".to_owned(),
            ));
        }
        return Ok(());
    }
    let Some(expected) = &manifest.evidence_policy.status_totals else {
        return Err(ConformanceError::new(
            ViolationCode::ManifestDrift,
            Some("manifest.json".to_owned()),
            "transition manifest must declare status_totals".to_owned(),
        ));
    };
    let mut actual = [
        ("unimplemented".to_owned(), 0_usize),
        ("partial".to_owned(), 0_usize),
        ("implemented".to_owned(), 0_usize),
    ]
    .into_iter()
    .collect::<BTreeMap<_, _>>();
    for feature in ledgers.iter().flat_map(FeatureLedger::features) {
        let key = match feature.status {
            LedgerStatus::Unimplemented => "unimplemented",
            LedgerStatus::Partial => "partial",
            LedgerStatus::Implemented => "implemented",
        };
        *actual.get_mut(key).expect("status key is fixed") += 1;
    }
    if expected != &actual {
        return Err(ConformanceError::new(
            ViolationCode::ManifestDrift,
            Some("manifest.json".to_owned()),
            "manifest status_totals do not match mutable ledger rows".to_owned(),
        ));
    }
    Ok(())
}

fn validate_ledger(
    ledger: &FeatureLedger,
    path: &str,
    expected_id: &str,
    expected_classification: Classification,
    expected_rows: usize,
    repository_root: &Path,
    cargo_test_targets: &mut Option<CargoTestTargets>,
) -> Result<(), ConformanceError> {
    if ledger.schema_version != 1
        || ledger.id() != expected_id
        || ledger.classification != expected_classification
        || ledger.baseline_sha != BASELINE_SHA
        || ledger.features().len() != expected_rows
    {
        return Err(ConformanceError::new(
            ViolationCode::LedgerDrift,
            Some(expected_id.to_owned()),
            format!("{path} fixed ledger metadata or row count changed"),
        ));
    }
    let mut ids = BTreeSet::new();
    for (index, feature) in ledger.features().iter().enumerate() {
        if !valid_feature_id(feature.id()) {
            return Err(ConformanceError::at_json_path(
                path,
                format!("features[{index}].feature_id"),
                "feature ID does not match the frozen schema pattern",
            ));
        }
        if !ids.insert(feature.id()) {
            return Err(ConformanceError::new(
                ViolationCode::LedgerDrift,
                Some(feature.id().to_owned()),
                "duplicate feature ID".to_owned(),
            ));
        }
        validate_feature_schema(feature, path, index)?;
        if feature.classification() != expected_classification {
            return Err(ConformanceError::new(
                ViolationCode::LedgerDrift,
                Some(feature.id().to_owned()),
                format!(
                    "feature classification {} does not match ledger classification {}",
                    classification_name(feature.classification()),
                    classification_name(expected_classification)
                ),
            ));
        }
        if feature.last_verified_sha != BASELINE_SHA {
            return Err(ConformanceError::new(
                ViolationCode::LedgerDrift,
                Some(feature.id().to_owned()),
                format!("last_verified_sha must equal {BASELINE_SHA}"),
            ));
        }
        if feature.acceptance_evidence.required.trim().is_empty() {
            return Err(ConformanceError::new(
                ViolationCode::LedgerEvidence,
                Some(feature.id().to_owned()),
                "acceptance evidence requirement must not be blank".to_owned(),
            ));
        }
        validate_ledger_evidence(feature, repository_root, cargo_test_targets)?;
    }
    Ok(())
}

fn validate_feature_schema(
    feature: &crate::model::Feature,
    path: &str,
    index: usize,
) -> Result<(), ConformanceError> {
    let fail = |field: &str, message: &str| {
        ConformanceError::at_json_path(path, format!("features[{index}].{field}"), message)
    };
    if feature.title.is_empty() {
        return Err(fail("title", "title must not be empty"));
    }
    if feature.domain.is_empty() {
        return Err(fail("domain", "domain must not be empty"));
    }
    if feature.upstream_source.repository != "openclaw/openclaw" {
        return Err(fail(
            "upstream_source.repository",
            "upstream repository must be openclaw/openclaw",
        ));
    }
    if feature.upstream_source.paths.is_empty() {
        return Err(fail(
            "upstream_source.paths",
            "at least one upstream path is required",
        ));
    }
    let mut paths = BTreeSet::new();
    for upstream_path in &feature.upstream_source.paths {
        if upstream_path.is_empty() {
            return Err(fail(
                "upstream_source.paths",
                "upstream paths must not be empty",
            ));
        }
        if !paths.insert(upstream_path) {
            return Err(fail(
                "upstream_source.paths",
                "upstream paths must be unique",
            ));
        }
    }
    if feature
        .upstream_source
        .official_url
        .as_deref()
        .is_some_and(|url| !valid_uri(url))
    {
        return Err(fail(
            "upstream_source.official_url",
            "official_url must be an absolute URI",
        ));
    }
    if feature.known_differences.is_empty()
        || feature.known_differences.iter().any(String::is_empty)
    {
        return Err(fail(
            "known_differences",
            "known_differences must contain non-empty entries",
        ));
    }
    Ok(())
}

fn validate_ledger_evidence(
    feature: &crate::model::Feature,
    repository_root: &Path,
    cargo_test_targets: &mut Option<CargoTestTargets>,
) -> Result<(), ConformanceError> {
    let fail = |message: &str| {
        ConformanceError::new(
            ViolationCode::LedgerEvidence,
            Some(feature.id().to_owned()),
            message.to_owned(),
        )
    };
    match feature.status {
        LedgerStatus::Unimplemented => {
            if !feature.acceptance_evidence.artifacts.is_empty()
                || feature.acceptance_evidence.status != EvidenceStatus::Missing
            {
                return Err(fail(
                    "unimplemented ledger status requires missing acceptance evidence",
                ));
            }
            if !feature.implementation_pointers.is_empty() {
                return Err(fail(
                    "unimplemented ledger status must not record implementation pointers",
                ));
            }
            if feature.known_differences.as_slice() != [BASELINE_KNOWN_DIFFERENCE] {
                return Err(fail(
                    "unimplemented ledger status must keep the frozen baseline known difference",
                ));
            }
        }
        LedgerStatus::Partial => {
            if feature.acceptance_evidence.artifacts.is_empty()
                || feature.acceptance_evidence.status == EvidenceStatus::Missing
            {
                return Err(fail(
                    "ledger status partial requires recorded acceptance evidence",
                ));
            }
            if feature.acceptance_evidence.status != EvidenceStatus::Partial {
                return Err(fail("partial ledger status requires partial evidence"));
            }
        }
        LedgerStatus::Implemented => {
            if feature.acceptance_evidence.artifacts.is_empty()
                || feature.acceptance_evidence.status == EvidenceStatus::Missing
            {
                return Err(fail(
                    "ledger status implemented requires recorded acceptance evidence",
                ));
            }
            if feature.acceptance_evidence.status != EvidenceStatus::Accepted {
                return Err(fail("implemented ledger status requires accepted evidence"));
            }
        }
    }
    if feature.status != LedgerStatus::Unimplemented {
        if feature
            .known_differences
            .iter()
            .any(|difference| difference == BASELINE_KNOWN_DIFFERENCE)
        {
            return Err(fail(
                "implemented or partial ledger status must remove the baseline no-implementation difference",
            ));
        }
        validate_evidence_as(
            repository_root,
            feature.id(),
            &feature.acceptance_evidence.artifacts,
            cargo_test_targets,
            ViolationCode::LedgerEvidence,
        )?;
        validate_implementation_pointers(
            repository_root,
            feature.id(),
            &feature.implementation_pointers,
            ViolationCode::LedgerEvidence,
        )?;
    }
    Ok(())
}

const fn classification_name(classification: Classification) -> &'static str {
    match classification {
        Classification::GatewayCore => "gateway_core",
        Classification::OfficialIntegration => "official_integration",
        Classification::OfficialClientInterop => "official_client_interop",
    }
}

fn valid_uri(value: &str) -> bool {
    if !value.is_ascii() || value.contains('\\') {
        return false;
    }
    let Some((scheme, _)) = value.split_once(':') else {
        return false;
    };
    if scheme.len() == 1 && scheme.as_bytes()[0].is_ascii_alphabetic() {
        return false;
    }
    let bytes = value.as_bytes();
    let mut index = 0;
    while index < bytes.len() {
        if bytes[index].is_ascii_whitespace() || bytes[index].is_ascii_control() {
            return false;
        }
        if bytes[index] == b'%' {
            if index + 2 >= bytes.len()
                || !bytes[index + 1].is_ascii_hexdigit()
                || !bytes[index + 2].is_ascii_hexdigit()
            {
                return false;
            }
            index += 2;
        }
        index += 1;
    }
    url::Url::parse(value).is_ok()
}

fn valid_feature_id(value: &str) -> bool {
    let mut previous_separator = true;
    for byte in value.bytes() {
        let separator = matches!(byte, b'.' | b'_' | b'-');
        if !byte.is_ascii_lowercase() && !byte.is_ascii_digit() && !separator {
            return false;
        }
        if separator && previous_separator {
            return false;
        }
        previous_separator = separator;
    }
    !value.is_empty() && !previous_separator
}

fn parse_inventory(
    path: &str,
    bytes: &[u8],
    expected_id: &str,
    expected_rows: usize,
) -> Result<Vec<InventoryRecord>, ConformanceError> {
    let header: InventoryHeader = parse_bytes(path, bytes)?;
    if header.inventory_id != expected_id {
        return Err(ConformanceError::new(
            ViolationCode::InventoryDrift,
            Some(expected_id.to_owned()),
            format!("{path} inventory_id changed to '{}'", header.inventory_id),
        ));
    }
    match expected_id {
        "plugins" => parse_typed_inventory::<PluginCounts, PluginItem>(
            path,
            bytes,
            expected_id,
            expected_rows,
        ),
        "skills" => {
            parse_typed_inventory::<SkillCounts, SkillItem>(path, bytes, expected_id, expected_rows)
        }
        "gateway-protocol" => parse_typed_inventory::<GatewayProtocolCounts, GatewayProtocolItem>(
            path,
            bytes,
            expected_id,
            expected_rows,
        ),
        "config-domains" => parse_typed_inventory::<ConfigDomainCounts, ConfigDomainItem>(
            path,
            bytes,
            expected_id,
            expected_rows,
        ),
        "providers" => parse_typed_inventory::<ProviderCounts, ProviderItem>(
            path,
            bytes,
            expected_id,
            expected_rows,
        ),
        "channels" => parse_typed_inventory::<ChannelCounts, ChannelItem>(
            path,
            bytes,
            expected_id,
            expected_rows,
        ),
        "http-sse-endpoints" => parse_typed_inventory::<HttpEndpointCounts, HttpEndpointItem>(
            path,
            bytes,
            expected_id,
            expected_rows,
        ),
        "clients" => parse_typed_inventory::<ClientCounts, ClientItem>(
            path,
            bytes,
            expected_id,
            expected_rows,
        ),
        "migrations" => parse_typed_inventory::<MigrationCounts, MigrationItem>(
            path,
            bytes,
            expected_id,
            expected_rows,
        ),
        "release-deployment" => parse_typed_inventory::<
            ReleaseDeploymentCounts,
            ReleaseDeploymentItem,
        >(path, bytes, expected_id, expected_rows),
        _ => Err(ConformanceError::new(
            ViolationCode::InventoryDrift,
            Some(expected_id.to_owned()),
            "unknown inventory type".to_owned(),
        )),
    }
}

fn parse_typed_inventory<C, I>(
    path: &str,
    bytes: &[u8],
    expected_id: &str,
    expected_rows: usize,
) -> Result<Vec<InventoryRecord>, ConformanceError>
where
    C: DeserializeOwned + InventoryCounts,
    I: DeserializeOwned + IntoInventoryRecord,
{
    let inventory: Inventory<C, I> = parse_bytes(path, bytes)?;
    if inventory.schema_version != 1
        || inventory.inventory_id != expected_id
        || inventory.baseline_sha != BASELINE_SHA
        || inventory.items.len() != expected_rows
        || inventory.counts.total() != expected_rows
        || inventory.classification.is_empty()
    {
        return Err(ConformanceError::new(
            ViolationCode::InventoryDrift,
            Some(expected_id.to_owned()),
            format!("{path} fixed metadata, total, or row count changed"),
        ));
    }
    let records = inventory
        .items
        .into_iter()
        .map(|item| item.into_record(expected_id))
        .collect::<Vec<_>>();
    let mut record_ids = BTreeSet::new();
    for record in &records {
        if record.record_id().is_empty()
            || record.id().is_empty()
            || record.source_path().is_empty()
            || !record_ids.insert(record.record_id())
        {
            return Err(ConformanceError::new(
                ViolationCode::InventoryDrift,
                Some(expected_id.to_owned()),
                format!(
                    "{path} contains an empty identity/source or duplicate record_id '{}'",
                    record.record_id()
                ),
            ));
        }
    }
    Ok(records)
}

fn parse_file<T>(root: &Path, relative: &str) -> Result<T, ConformanceError>
where
    T: DeserializeOwned,
{
    let bytes = read_file(root, relative)?;
    parse_bytes(relative, &bytes)
}

fn parse_bytes<T>(relative: &str, bytes: &[u8]) -> Result<T, ConformanceError>
where
    T: DeserializeOwned,
{
    let bytes = bytes.strip_prefix(b"\xEF\xBB\xBF").unwrap_or(bytes);
    let mut deserializer = serde_json::Deserializer::from_slice(bytes);
    let value = serde_path_to_error::deserialize(&mut deserializer).map_err(|error| {
        ConformanceError::at_json_path(
            relative,
            error.path().to_string(),
            error.inner().to_string(),
        )
    })?;
    deserializer.end().map_err(|_| {
        ConformanceError::at_json_path(relative, "$", "trailing content after the JSON document")
    })?;
    Ok(value)
}

fn read_file(root: &Path, relative: &str) -> Result<Vec<u8>, ConformanceError> {
    fs::read(root.join(relative)).map_err(|error| {
        ConformanceError::new(
            ViolationCode::Io,
            Some(relative.to_owned()),
            error.to_string(),
        )
    })
}

fn repository_root_for_contract(contract_root: &Path) -> PathBuf {
    if contract_root.file_name().and_then(|name| name.to_str()) == Some("upstream")
        && contract_root
            .parent()
            .and_then(Path::file_name)
            .and_then(|name| name.to_str())
            == Some("compat")
    {
        contract_root
            .parent()
            .and_then(Path::parent)
            .unwrap_or(contract_root)
            .to_path_buf()
    } else {
        contract_root.to_path_buf()
    }
}

fn verify_hash(
    path: &str,
    bytes: &[u8],
    expected: &str,
    code: ViolationCode,
    subject: &str,
    reason: &str,
) -> Result<(), ConformanceError> {
    let actual = normalized_digest(bytes);
    if actual == expected {
        Ok(())
    } else {
        Err(ConformanceError::new(
            code,
            Some(subject.to_owned()),
            format!("{reason} in {path}; expected SHA-256 {expected}, found {actual}"),
        ))
    }
}

fn verify_hashes<'a>(
    path: &str,
    bytes: &[u8],
    expected: &'a [&str],
    code: ViolationCode,
    subject: &str,
    reason: &str,
) -> Result<&'a str, ConformanceError> {
    let actual = normalized_digest(bytes);
    expected
        .iter()
        .copied()
        .find(|candidate| *candidate == actual)
        .ok_or_else(|| {
            ConformanceError::new(
                code,
                Some(subject.to_owned()),
                format!(
                    "{reason} in {path}; expected one of SHA-256 {}, found {actual}",
                    expected.join(", ")
                ),
            )
        })
}

/// Lowercase hexadecimal SHA-256 of `bytes` with CRLF folded to LF, so a frozen
/// artifact hashes the same whichever way a checkout materialized its line
/// endings.
fn normalized_digest(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let digest = Sha256::digest(normalize_line_endings(bytes));
    let mut encoded = String::with_capacity(digest.len() * 2);
    for byte in digest {
        encoded.push(HEX[usize::from(byte >> 4)] as char);
        encoded.push(HEX[usize::from(byte & 0x0f)] as char);
    }
    encoded
}

fn normalize_line_endings(bytes: &[u8]) -> Vec<u8> {
    let mut normalized = Vec::with_capacity(bytes.len());
    let mut index = 0;
    while index < bytes.len() {
        if bytes.get(index..index + 2) == Some(b"\r\n") {
            normalized.push(b'\n');
            index += 2;
        } else {
            normalized.push(bytes[index]);
            index += 1;
        }
    }
    normalized
}

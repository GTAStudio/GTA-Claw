//! Frozen contract loading, schema checks, and drift detection.

use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::{Path, PathBuf};

use serde::de::DeserializeOwned;
use sha2::{Digest, Sha256};

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

const SUPPORT_SPECS: [(&str, &str); 5] = [
    (
        "baseline.json",
        "02bdfca9e47ace25ffd99199f2efc8dd04b80f0c4b35c8a63b08700dd9846dea",
    ),
    (
        "feature-ledger.schema.json",
        "ee62fe4022cf7a3dc5165b817547dc07a49b3d0db763ca8b2c153512ce328525",
    ),
    (
        "manifest.json",
        "f5f255aebbe687497bb183f5e810f31613f50b31c0306121bd84f07e4e8ddbe9",
    ),
    (
        "validate.ps1",
        "a4c43483a6b59bb84f81dcc7340788c6e47effde6cc20758e0742a54823f5ecb",
    ),
    (
        "validate-self-test.ps1",
        "a4413274fcc18c3f893d3190ad7baecb77727f9711b0c8b2e1cd7e456d986bd4",
    ),
];

const LEDGER_SPECS: [(&str, &str, Classification, usize, &str); 3] = [
    (
        "ledgers/gateway-core.json",
        "gateway-core",
        Classification::GatewayCore,
        16,
        "9fbc37d72a44a2c7964607d20935635abe7bea9c4ebe017fbdbed5e94f983a59",
    ),
    (
        "ledgers/official-integration.json",
        "official-integration",
        Classification::OfficialIntegration,
        13,
        "9f0de2657559ad5522800eb6596f539c06230c7fdd1d146d96151727500a1693",
    ),
    (
        "ledgers/official-client-interop.json",
        "official-client-interop",
        Classification::OfficialClientInterop,
        18,
        "cc44309fcca8ed001ee9565e14216924efec25046c7a400573a374e40a258eae",
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

/// Fully validated frozen upstream contract.
#[derive(Clone, Debug)]
pub struct Contract {
    root: PathBuf,
    baseline_sha: String,
    ledgers: Vec<FeatureLedger>,
    inventories: BTreeMap<String, Vec<InventoryRecord>>,
}

impl Contract {
    /// Loads all three ledgers and all ten inventories from `compat/upstream`.
    pub fn load(root: impl AsRef<Path>) -> Result<Self, ConformanceError> {
        let root = root.as_ref();
        let manifest: Manifest = parse_file(root, "manifest.json")?;
        validate_manifest(&manifest)?;
        for (path, expected_hash) in SUPPORT_SPECS {
            let bytes = read_file(root, path)?;
            verify_hash(
                path,
                &bytes,
                expected_hash,
                ViolationCode::ManifestDrift,
                path,
                "frozen support artifact changed",
            )?;
        }

        let mut ledgers = Vec::with_capacity(LEDGER_SPECS.len());
        for (path, expected_id, classification, expected_rows, expected_hash) in LEDGER_SPECS {
            let bytes = read_file(root, path)?;
            let ledger: FeatureLedger = parse_bytes(path, &bytes)?;
            validate_ledger(&ledger, path, expected_id, classification, expected_rows)?;
            verify_hash(
                path,
                &bytes,
                expected_hash,
                ViolationCode::LedgerDrift,
                expected_id,
                "frozen ledger feature/source identity changed",
            )?;
            ledgers.push(ledger);
        }

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
    pub fn inventories(&self) -> &BTreeMap<String, Vec<InventoryRecord>> {
        &self.inventories
    }
}

fn validate_manifest(manifest: &Manifest) -> Result<(), ConformanceError> {
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
    for (path, _, classification, rows, _) in LEDGER_SPECS {
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
        ("artifact_json_files", 16),
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
    if manifest.canonical_counts != expected_counts
        || manifest.evidence_policy.initial_status != "unimplemented"
        || manifest.evidence_policy.acceptance_evidence_state != "missing"
        || !manifest
            .evidence_policy
            .legacy_typescript_is_not_rust_acceptance_evidence
    {
        return Err(fail(
            "canonical counts or evidence policy changed".to_owned(),
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
    for feature in ledger.features() {
        if !valid_feature_id(feature.id()) {
            return Err(ConformanceError::at_json_path(
                path,
                format!("features.{}.feature_id", feature.id()),
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
        let evidence_missing = feature.acceptance_evidence.artifacts.is_empty()
            || feature.acceptance_evidence.status == EvidenceStatus::Missing;
        if matches!(
            feature.status,
            LedgerStatus::Partial | LedgerStatus::Implemented
        ) && evidence_missing
        {
            return Err(ConformanceError::new(
                ViolationCode::LedgerEvidence,
                Some(feature.id().to_owned()),
                format!(
                    "ledger status {:?} requires recorded acceptance evidence",
                    feature.status
                )
                .to_ascii_lowercase(),
            ));
        }
        if feature.status == LedgerStatus::Implemented
            && feature.acceptance_evidence.status != EvidenceStatus::Accepted
        {
            return Err(ConformanceError::new(
                ViolationCode::LedgerEvidence,
                Some(feature.id().to_owned()),
                "implemented ledger status requires accepted evidence".to_owned(),
            ));
        }
    }
    Ok(())
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
    serde_path_to_error::deserialize(&mut deserializer).map_err(|error| {
        ConformanceError::at_json_path(
            relative,
            error.path().to_string(),
            error.inner().to_string(),
        )
    })
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

fn verify_hash(
    path: &str,
    bytes: &[u8],
    expected: &str,
    code: ViolationCode,
    subject: &str,
    reason: &str,
) -> Result<(), ConformanceError> {
    let normalized = normalize_line_endings(bytes);
    let actual = Sha256::digest(&normalized)
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<String>();
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

//! Strongly typed representations of authoritative ledgers and frozen inventories.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

use crate::claims::{Evidence, ImplementationPointer};

/// Frozen compatibility classification.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Classification {
    /// Gateway core behavior.
    GatewayCore,
    /// Official integration surface.
    OfficialIntegration,
    /// Official client interoperability surface.
    OfficialClientInterop,
}

/// Allowed mutable ledger status.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "snake_case")]
pub(crate) enum LedgerStatus {
    Unimplemented,
    Partial,
    Implemented,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "snake_case")]
pub(crate) enum EvidenceStatus {
    Missing,
    Partial,
    Accepted,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq)]
enum Tier {
    #[serde(rename = "tier_1")]
    Tier1,
    #[serde(rename = "tier_2")]
    Tier2,
    #[serde(rename = "tier_3")]
    Tier3,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "snake_case")]
enum Profile {
    CoreGateway,
    ClientInterop,
    PlatformIntegration,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq)]
#[serde(deny_unknown_fields)]
pub(crate) struct UpstreamSource {
    pub(crate) repository: String,
    pub(crate) paths: Vec<String>,
    #[serde(default, deserialize_with = "deserialize_optional_string")]
    pub(crate) official_url: Option<String>,
}

fn deserialize_optional_string<'de, D>(deserializer: D) -> Result<Option<String>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    String::deserialize(deserializer).map(Some)
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq)]
#[serde(deny_unknown_fields)]
pub(crate) struct AcceptanceEvidence {
    pub(crate) status: EvidenceStatus,
    pub(crate) artifacts: Vec<Evidence>,
    pub(crate) required: String,
}

/// One compatibility feature row.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq)]
#[serde(deny_unknown_fields)]
#[expect(
    clippy::struct_field_names,
    reason = "`feature_id` is the member name in the byte-sealed compat/upstream ledgers and \
`deny_unknown_fields` is on, so renaming it would stop the frozen artifacts deserializing"
)]
pub struct Feature {
    feature_id: String,
    pub(crate) title: String,
    pub(crate) domain: String,
    tier: Tier,
    profile: Profile,
    classification: Classification,
    pub(crate) upstream_source: UpstreamSource,
    pub(crate) status: LedgerStatus,
    pub(crate) acceptance_evidence: AcceptanceEvidence,
    pub(crate) last_verified_sha: String,
    pub(crate) known_differences: Vec<String>,
    #[serde(default)]
    pub(crate) implementation_pointers: Vec<ImplementationPointer>,
}

impl Feature {
    /// Stable feature ID used by implementation claims.
    #[must_use]
    pub fn id(&self) -> &str {
        &self.feature_id
    }

    /// Human-readable feature title.
    #[must_use]
    pub fn title(&self) -> &str {
        &self.title
    }

    /// Frozen classification.
    #[must_use]
    pub const fn classification(&self) -> Classification {
        self.classification
    }
}

/// One strongly typed feature ledger.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct FeatureLedger {
    pub(crate) schema_version: u8,
    ledger_id: String,
    pub(crate) classification: Classification,
    pub(crate) baseline_sha: String,
    features: Vec<Feature>,
}

impl FeatureLedger {
    /// Stable ledger ID.
    #[must_use]
    pub fn id(&self) -> &str {
        &self.ledger_id
    }

    /// Validated rows in source order.
    #[must_use]
    pub fn features(&self) -> &[Feature] {
        &self.features
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq)]
#[serde(deny_unknown_fields)]
pub(crate) struct Manifest {
    pub(crate) schema_version: u8,
    pub(crate) artifact_set: String,
    pub(crate) baseline_sha: String,
    pub(crate) baseline_path: String,
    pub(crate) feature_schema_path: String,
    pub(crate) validation_script: String,
    pub(crate) validation_self_test: String,
    pub(crate) ledgers: Vec<ManifestLedger>,
    pub(crate) inventories: Vec<ManifestInventory>,
    pub(crate) canonical_counts: BTreeMap<String, u64>,
    pub(crate) evidence_policy: EvidencePolicy,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq)]
#[serde(deny_unknown_fields)]
pub(crate) struct ManifestLedger {
    pub(crate) path: String,
    pub(crate) classification: Classification,
    pub(crate) expected_features: usize,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq)]
#[serde(deny_unknown_fields)]
pub(crate) struct ManifestInventory {
    pub(crate) path: String,
    pub(crate) expected_items: usize,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq)]
#[serde(deny_unknown_fields)]
pub(crate) struct EvidencePolicy {
    pub(crate) initial_status: String,
    pub(crate) acceptance_evidence_state: String,
    pub(crate) legacy_typescript_is_not_rust_acceptance_evidence: bool,
    #[serde(default)]
    pub(crate) allowed_statuses: Option<Vec<String>>,
    #[serde(default)]
    pub(crate) artifact_fields: Option<Vec<String>>,
    #[serde(default)]
    pub(crate) every_artifact_names_an_enabled_rust_test: Option<bool>,
    #[serde(default)]
    pub(crate) implementation_pointers_are_not_acceptance_evidence: Option<bool>,
    #[serde(default)]
    pub(crate) status_totals: Option<BTreeMap<String, usize>>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub(crate) struct InventoryHeader {
    pub(crate) inventory_id: String,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
#[expect(
    clippy::struct_field_names,
    reason = "`inventory_id` is the member name in the byte-sealed compat/upstream inventories and \
`deny_unknown_fields` is on, so renaming it would stop the frozen artifacts deserializing"
)]
pub(crate) struct Inventory<C, I> {
    pub(crate) schema_version: u8,
    pub(crate) inventory_id: String,
    pub(crate) classification: String,
    pub(crate) baseline_sha: String,
    pub(crate) counts: C,
    pub(crate) items: Vec<I>,
}

pub(crate) trait InventoryCounts: Serialize {
    fn total(&self) -> usize;
}

macro_rules! counts {
    ($name:ident { total $(, $field:ident : $ty:ty)* $(,)? }) => {
        #[derive(Clone, Debug, Deserialize, Serialize)]
        #[serde(deny_unknown_fields)]
        pub(crate) struct $name {
            total: usize,
            $( $field: $ty, )*
        }

        impl InventoryCounts for $name {
            fn total(&self) -> usize {
                self.total
            }
        }
    };
}

counts!(PluginCounts {
    total,
    core: usize,
    official_external: usize,
    source_only_qa: usize,
});
counts!(SkillCounts {
    total,
    bundled: usize,
});
counts!(GatewayProtocolCounts {
    total,
    methods: usize,
    advertised_methods: usize,
    events: usize,
    roles: usize,
    scopes: usize,
    dynamic_plugin_methods: String,
});
counts!(ConfigDomainCounts { total });
counts!(ProviderCounts {
    total,
    unique: usize,
});
counts!(ChannelCounts {
    total,
    source_manifest: usize,
    official_catalog_only: usize,
});
counts!(HttpEndpointCounts {
    total,
    optional_sse: usize,
    long_poll: usize,
    streamable_http: usize,
});
counts!(ClientCounts { total });
counts!(MigrationCounts { total });
counts!(ReleaseDeploymentCounts {
    total,
    release: usize,
    installation: usize,
    deployment: usize,
});

/// Normalized inventory identity exposed to registration and reporting.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct InventoryRecord {
    inventory_id: String,
    record_id: String,
    id: String,
    classification: Classification,
    source_path: String,
}

impl InventoryRecord {
    /// Inventory containing this record.
    #[must_use]
    pub fn inventory_id(&self) -> &str {
        &self.inventory_id
    }

    /// Globally stable record ID used by implementation claims.
    #[must_use]
    pub fn record_id(&self) -> &str {
        &self.record_id
    }

    /// Natural upstream ID.
    #[must_use]
    pub fn id(&self) -> &str {
        &self.id
    }

    /// Frozen source path.
    #[must_use]
    pub fn source_path(&self) -> &str {
        &self.source_path
    }
}

pub(crate) trait IntoInventoryRecord {
    fn into_record(self, inventory_id: &str) -> InventoryRecord;
}

macro_rules! inventory_item {
    ($name:ident { $( $field:ident : $ty:ty ),* $(,)? }) => {
        #[derive(Clone, Debug, Deserialize, Serialize)]
        #[serde(deny_unknown_fields)]
        pub(crate) struct $name {
            record_id: String,
            id: String,
            classification: Classification,
            source_path: String,
            $( $field: $ty, )*
        }

        impl IntoInventoryRecord for $name {
            fn into_record(self, inventory_id: &str) -> InventoryRecord {
                InventoryRecord {
                    inventory_id: inventory_id.to_owned(),
                    record_id: self.record_id,
                    id: self.id,
                    classification: self.classification,
                    source_path: self.source_path,
                }
            }
        }
    };
}

inventory_item!(PluginItem {
    package_name: String,
    delivery_class: String,
});
inventory_item!(SkillItem { license: String });
inventory_item!(GatewayProtocolItem {
    kind: String,
    scope: Option<String>,
    advertised: Option<bool>,
    protocol_class: Option<String>,
});
inventory_item!(ConfigDomainItem {});
inventory_item!(ProviderItem { plugin_id: String });
inventory_item!(ChannelItem {
    plugin_id: Option<String>,
    package_name: Option<String>,
    catalog_package: Option<String>,
    catalog_source_path: Option<String>,
    provenance: String,
});
inventory_item!(HttpEndpointItem {
    method: String,
    path: String,
    streaming: String,
});
inventory_item!(ClientItem { kind: String });
inventory_item!(MigrationItem {
    package_path: String,
    kind: String,
});
inventory_item!(ReleaseDeploymentItem { kind: String });

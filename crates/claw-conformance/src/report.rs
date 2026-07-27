//! Deterministic machine-readable and human-readable parity reports.

use std::collections::BTreeSet;
use std::fmt::Write as _;
use std::path::Path;

use serde::Serialize;

use crate::claims::{
    CargoTestTargets, ClaimLevel, Registry, validate_evidence, validate_implementation_pointers,
};
use crate::error::{ConformanceError, ViolationCode};
use crate::loader::Contract;
use crate::model::{Feature, FeatureLedger};

/// Claim state recorded for one feature row.
///
/// This is the level of the registered claim, once that claim's cited evidence
/// was verified to resolve. It reports what is claimed and cited, not observed
/// behavior; see the crate documentation for what evidence verification does
/// and does not establish.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ParityStatus {
    /// No verified implementation claim exists.
    Unimplemented,
    /// A verified partial claim exists.
    Partial,
    /// A verified complete claim exists.
    Implemented,
}

impl ParityStatus {
    const fn as_str(self) -> &'static str {
        match self {
            Self::Unimplemented => "unimplemented",
            Self::Partial => "partial",
            Self::Implemented => "implemented",
        }
    }
}

/// Report for one frozen feature row.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct FeatureReport {
    /// Stable feature ID.
    pub feature_id: String,
    /// Human-readable title.
    pub title: String,
    /// Level of the row's verified claim.
    pub status: ParityStatus,
    /// Whether any metadata or implementation claim is registered.
    pub registered: bool,
    /// Number of verified evidence records.
    pub evidence_count: usize,
}

/// Report for one feature ledger.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct LedgerReport {
    /// Stable ledger ID.
    pub ledger_id: String,
    /// Rows in frozen order.
    pub features: Vec<FeatureReport>,
    /// Rows with a verified complete claim.
    pub implemented: usize,
    /// Rows with a verified partial claim.
    pub partial: usize,
    /// Rows with no verified implementation claim.
    pub unimplemented: usize,
    /// Rows with any metadata or implementation registration.
    pub registered: usize,
}

/// Coverage summary for one inventory.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct InventoryCoverage {
    /// Stable inventory ID.
    pub inventory_id: String,
    /// Rows with verified complete claims.
    pub fully_implemented: usize,
    /// Rows with any metadata, partial, or complete registration.
    pub registered: usize,
    /// Frozen row count.
    pub total: usize,
}

/// Aggregate feature claim totals.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct ParityTotals {
    /// Feature rows with a verified complete claim.
    pub implemented: usize,
    /// Feature rows with a verified partial claim.
    pub partial: usize,
    /// Feature rows with no verified implementation claim.
    pub unimplemented: usize,
    /// Total frozen feature rows.
    pub total: usize,
    /// Feature rows with any metadata or implementation registration.
    pub registered: usize,
}

/// Complete machine-readable parity report.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct ParityReport {
    /// Frozen upstream commit SHA.
    pub baseline_sha: String,
    /// Per-ledger feature results.
    pub ledgers: Vec<LedgerReport>,
    /// Per-inventory coverage results.
    pub inventories: Vec<InventoryCoverage>,
    /// Aggregate feature claim totals.
    pub totals: ParityTotals,
}

impl ParityReport {
    /// Renders the deterministic human-readable table used by the CLI.
    #[must_use]
    pub fn to_human_table(&self) -> String {
        let mut output = String::new();
        writeln!(output, "OpenClaw parity baseline: {}", self.baseline_sha)
            .expect("writing to String cannot fail");
        writeln!(output).expect("writing to String cannot fail");
        writeln!(
            output,
            "{:<25} {:<45} {:<14} {:<10} Evidence",
            "Ledger", "Feature", "Status", "Registered"
        )
        .expect("writing to String cannot fail");
        writeln!(output, "{}", "-".repeat(111)).expect("writing to String cannot fail");
        for ledger in &self.ledgers {
            for feature in &ledger.features {
                writeln!(
                    output,
                    "{:<25} {:<45} {:<14} {:<10} {}",
                    ledger.ledger_id,
                    feature.feature_id,
                    feature.status.as_str(),
                    if feature.registered { "yes" } else { "no" },
                    feature.evidence_count
                )
                .expect("writing to String cannot fail");
            }
        }
        writeln!(output).expect("writing to String cannot fail");
        writeln!(
            output,
            "Feature rows: {} of {} implemented, {} partial, {} unimplemented, {} registered",
            self.totals.implemented,
            self.totals.total,
            self.totals.partial,
            self.totals.unimplemented,
            self.totals.registered
        )
        .expect("writing to String cannot fail");
        writeln!(output).expect("writing to String cannot fail");
        writeln!(
            output,
            "{:<25} {:>18} {:>12} {:>8}",
            "Inventory", "Fully implemented", "Registered", "Total"
        )
        .expect("writing to String cannot fail");
        writeln!(output, "{}", "-".repeat(68)).expect("writing to String cannot fail");
        for inventory in &self.inventories {
            writeln!(
                output,
                "{:<25} {:>18} {:>12} {:>8}",
                inventory.inventory_id,
                inventory.fully_implemented,
                inventory.registered,
                inventory.total
            )
            .expect("writing to String cannot fail");
        }
        output
    }

    /// Serializes the machine-readable report as pretty JSON.
    ///
    /// # Errors
    ///
    /// Returns the [`serde_json::Error`] raised while serializing the report.
    /// Every field is a `String`, a `usize`, or a plain enum, so this cannot
    /// fail on the data itself; a failure means the serializer itself failed.
    pub fn to_pretty_json(&self) -> Result<String, serde_json::Error> {
        serde_json::to_string_pretty(self)
    }
}

/// Validates every claim and generates the parity report.
///
/// # Errors
///
/// Returns a [`ViolationCode::UnknownClaim`] error when a claim names a feature
/// ID or inventory record that is not in the frozen ledgers or inventories —
/// usually a typo, or a claim left behind after upstream renamed a row.
///
/// Returns a [`ViolationCode::ClaimEvidence`] error when a claim above
/// `registered`, or any claim that carries evidence, cannot have that evidence
/// verified: the cited test is not literally declared in a standard-libtest
/// Cargo target of an admitted workspace package, the citing path is not
/// reachable through `mod` declarations from one, or an implementation pointer
/// does not exist or resolves outside the repository root. Unverifiable evidence
/// is refused rather than downgraded, because the report is a claim about what
/// is proven.
pub fn generate_report(
    contract: &Contract,
    registry: &Registry,
    repository_root: impl AsRef<Path>,
) -> Result<ParityReport, ConformanceError> {
    let repository_root = repository_root.as_ref();
    let known_features = contract
        .ledgers()
        .iter()
        .flat_map(FeatureLedger::features)
        .map(Feature::id)
        .collect::<BTreeSet<_>>();
    let mut cargo_test_targets: Option<CargoTestTargets> =
        contract.cargo_test_targets(repository_root);
    for (feature_id, claim) in &registry.features {
        if !known_features.contains(feature_id.as_str()) {
            return Err(ConformanceError::new(
                ViolationCode::UnknownClaim,
                Some(feature_id.clone()),
                "feature ID is not present in the frozen ledgers".to_owned(),
            ));
        }
        if claim.level != ClaimLevel::Registered || !claim.evidence.is_empty() {
            validate_evidence(
                repository_root,
                feature_id,
                &claim.evidence,
                &mut cargo_test_targets,
            )?;
        }
        validate_implementation_pointers(
            repository_root,
            feature_id,
            &claim.implementation_pointers,
            ViolationCode::ClaimEvidence,
        )?;
    }

    let known_inventory = contract
        .inventories()
        .iter()
        .flat_map(|(inventory_id, records)| {
            records
                .iter()
                .map(move |record| (inventory_id.as_str(), record.record_id()))
        })
        .collect::<BTreeSet<_>>();
    for ((inventory_id, record_id), claim) in &registry.inventories {
        if !known_inventory.contains(&(inventory_id.as_str(), record_id.as_str())) {
            return Err(ConformanceError::new(
                ViolationCode::UnknownClaim,
                Some(format!("{inventory_id}:{record_id}")),
                "inventory record is not present in the frozen inventories".to_owned(),
            ));
        }
        if claim.level != ClaimLevel::Registered || !claim.evidence.is_empty() {
            validate_evidence(
                repository_root,
                &format!("{inventory_id}:{record_id}"),
                &claim.evidence,
                &mut cargo_test_targets,
            )?;
        }
        validate_implementation_pointers(
            repository_root,
            &format!("{inventory_id}:{record_id}"),
            &claim.implementation_pointers,
            ViolationCode::ClaimEvidence,
        )?;
    }

    let ledgers = contract
        .ledgers()
        .iter()
        .map(|ledger| {
            let features = ledger
                .features()
                .iter()
                .map(|feature| {
                    let claim = registry.features.get(feature.id());
                    let status =
                        claim.map_or(ParityStatus::Unimplemented, |claim| match claim.level {
                            ClaimLevel::Registered => ParityStatus::Unimplemented,
                            ClaimLevel::Partial => ParityStatus::Partial,
                            ClaimLevel::Implemented => ParityStatus::Implemented,
                        });
                    FeatureReport {
                        feature_id: feature.id().to_owned(),
                        title: feature.title().to_owned(),
                        status,
                        registered: claim.is_some(),
                        evidence_count: claim.map_or(0, |claim| claim.evidence.len()),
                    }
                })
                .collect::<Vec<_>>();
            let implemented = count_status(&features, ParityStatus::Implemented);
            let partial = count_status(&features, ParityStatus::Partial);
            let unimplemented = count_status(&features, ParityStatus::Unimplemented);
            let registered = features.iter().filter(|feature| feature.registered).count();
            LedgerReport {
                ledger_id: ledger.id().to_owned(),
                features,
                implemented,
                partial,
                unimplemented,
                registered,
            }
        })
        .collect::<Vec<_>>();

    let inventories = contract
        .inventories()
        .iter()
        .map(|(inventory_id, records)| {
            let claims = registry
                .inventories
                .iter()
                .filter(|((claim_inventory, _), _)| claim_inventory == inventory_id)
                .map(|(_, claim)| claim.level)
                .collect::<Vec<_>>();
            InventoryCoverage {
                inventory_id: inventory_id.clone(),
                fully_implemented: claims
                    .iter()
                    .filter(|level| **level == ClaimLevel::Implemented)
                    .count(),
                registered: claims.len(),
                total: records.len(),
            }
        })
        .collect::<Vec<_>>();

    let totals = ParityTotals {
        implemented: ledgers.iter().map(|ledger| ledger.implemented).sum(),
        partial: ledgers.iter().map(|ledger| ledger.partial).sum(),
        unimplemented: ledgers.iter().map(|ledger| ledger.unimplemented).sum(),
        total: ledgers.iter().map(|ledger| ledger.features.len()).sum(),
        registered: ledgers.iter().map(|ledger| ledger.registered).sum(),
    };

    Ok(ParityReport {
        baseline_sha: contract.baseline_sha().to_owned(),
        ledgers,
        inventories,
        totals,
    })
}

fn count_status(features: &[FeatureReport], expected: ParityStatus) -> usize {
    features
        .iter()
        .filter(|feature| feature.status == expected)
        .count()
}

#[cfg(test)]
mod tests {
    use super::ParityStatus;

    #[test]
    fn parity_status_names_are_stable() {
        assert_eq!(ParityStatus::Unimplemented.as_str(), "unimplemented");
        assert_eq!(ParityStatus::Partial.as_str(), "partial");
        assert_eq!(ParityStatus::Implemented.as_str(), "implemented");
    }
}

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

/// Truthful strength of the behavior evidence represented by a report row.
///
/// Source verification proves citation integrity and Cargo reachability. It
/// does not prove that the cited test executed or passed.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum EvidenceState {
    /// Runtime-attested behavior was measured successfully.
    ///
    /// The current claim schema carries no runtime attestation, so this state is
    /// reserved for a future provenance-bearing input and is never inferred from
    /// a source citation.
    Measured,
    /// Complete behavior is claimed and every citation was source-verified.
    Verified,
    /// Partial behavior is claimed and every citation was source-verified.
    Partial,
    /// No admissible behavior evidence exists.
    Missing,
}

impl EvidenceState {
    const fn as_str(self) -> &'static str {
        match self {
            Self::Measured => "measured",
            Self::Verified => "verified",
            Self::Partial => "partial",
            Self::Missing => "missing",
        }
    }
}

/// Most actionable reason a row has not reached measured parity.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum EvidenceGap {
    /// No claim is registered for the frozen row.
    NoClaim,
    /// Ownership metadata exists, but no behavior is claimed.
    RegistrationOnly,
    /// Evidence covers only part of the frozen behavior.
    PartialCoverage,
    /// Source citations verify, but no runtime execution attestation exists.
    RuntimeMeasurement,
}

impl EvidenceGap {
    const fn as_str(self) -> &'static str {
        match self {
            Self::NoClaim => "no_claim",
            Self::RegistrationOnly => "registration_only",
            Self::PartialCoverage => "partial_coverage",
            Self::RuntimeMeasurement => "runtime_measurement",
        }
    }
}

/// Aggregate counts for the four evidence states.
#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize)]
pub struct EvidenceTotals {
    /// Runtime-measured rows.
    pub measured: usize,
    /// Complete rows with source-verified citations.
    pub verified: usize,
    /// Partial rows with source-verified citations.
    pub partial: usize,
    /// Rows without admissible behavior evidence.
    pub missing: usize,
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
    /// Truthful strength of the evidence behind `status`.
    pub evidence_state: EvidenceState,
    /// Why the row has not reached measured parity.
    pub evidence_gap: Option<EvidenceGap>,
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
    /// Evidence-strength totals for this ledger.
    pub evidence: EvidenceTotals,
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
    /// Evidence-strength totals across frozen inventory records.
    pub evidence: EvidenceTotals,
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
    /// Aggregate evidence-strength totals.
    pub evidence: EvidenceTotals,
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
            "{:<25} {:<40} {:<14} {:<10} {:<20} Artifacts",
            "Ledger", "Feature", "Claim", "Evidence", "Gap"
        )
        .expect("writing to String cannot fail");
        writeln!(output, "{}", "-".repeat(124)).expect("writing to String cannot fail");
        for ledger in &self.ledgers {
            for feature in &ledger.features {
                writeln!(
                    output,
                    "{:<25} {:<40} {:<14} {:<10} {:<20} {}",
                    ledger.ledger_id,
                    feature.feature_id,
                    feature.status.as_str(),
                    feature.evidence_state.as_str(),
                    feature.evidence_gap.map_or("-", EvidenceGap::as_str),
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
        writeln!(
            output,
            "Evidence state: {} measured, {} verified, {} partial, {} missing",
            self.totals.evidence.measured,
            self.totals.evidence.verified,
            self.totals.evidence.partial,
            self.totals.evidence.missing
        )
        .expect("writing to String cannot fail");
        writeln!(
            output,
            "Verified means source and Cargo reachability checked; measured requires runtime execution attestation."
        )
        .expect("writing to String cannot fail");
        writeln!(output).expect("writing to String cannot fail");
        writeln!(
            output,
            "{:<25} {:>10} {:>10} {:>10} {:>10} {:>12} {:>8}",
            "Inventory", "Measured", "Verified", "Partial", "Missing", "Registered", "Total"
        )
        .expect("writing to String cannot fail");
        writeln!(output, "{}", "-".repeat(91)).expect("writing to String cannot fail");
        for inventory in &self.inventories {
            writeln!(
                output,
                "{:<25} {:>10} {:>10} {:>10} {:>10} {:>12} {:>8}",
                inventory.inventory_id,
                inventory.evidence.measured,
                inventory.evidence.verified,
                inventory.evidence.partial,
                inventory.evidence.missing,
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
        if claim.level == ClaimLevel::Registered && !claim.evidence.is_empty() {
            return Err(ConformanceError::new(
                ViolationCode::ClaimEvidence,
                Some(feature_id.clone()),
                "metadata-only registration must not carry behavior evidence".to_owned(),
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
        if claim.level == ClaimLevel::Registered && !claim.evidence.is_empty() {
            return Err(ConformanceError::new(
                ViolationCode::ClaimEvidence,
                Some(format!("{inventory_id}:{record_id}")),
                "metadata-only registration must not carry behavior evidence".to_owned(),
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
                    let (status, evidence_state, evidence_gap) = claim.map_or(
                        (
                            ParityStatus::Unimplemented,
                            EvidenceState::Missing,
                            EvidenceGap::NoClaim,
                        ),
                        |claim| match claim.level {
                            ClaimLevel::Registered => (
                                ParityStatus::Unimplemented,
                                EvidenceState::Missing,
                                EvidenceGap::RegistrationOnly,
                            ),
                            ClaimLevel::Partial => (
                                ParityStatus::Partial,
                                EvidenceState::Partial,
                                EvidenceGap::PartialCoverage,
                            ),
                            ClaimLevel::Implemented => (
                                ParityStatus::Implemented,
                                EvidenceState::Verified,
                                EvidenceGap::RuntimeMeasurement,
                            ),
                        },
                    );
                    FeatureReport {
                        feature_id: feature.id().to_owned(),
                        title: feature.title().to_owned(),
                        status,
                        evidence_state,
                        evidence_gap: Some(evidence_gap),
                        registered: claim.is_some(),
                        evidence_count: claim.map_or(0, |claim| claim.evidence.len()),
                    }
                })
                .collect::<Vec<_>>();
            let implemented = count_status(&features, ParityStatus::Implemented);
            let partial = count_status(&features, ParityStatus::Partial);
            let unimplemented = count_status(&features, ParityStatus::Unimplemented);
            let registered = features.iter().filter(|feature| feature.registered).count();
            let evidence =
                count_evidence_states(features.iter().map(|feature| feature.evidence_state));
            LedgerReport {
                ledger_id: ledger.id().to_owned(),
                features,
                implemented,
                partial,
                unimplemented,
                registered,
                evidence,
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
            let mut evidence = count_evidence_states(claims.iter().map(|level| match level {
                ClaimLevel::Registered => EvidenceState::Missing,
                ClaimLevel::Partial => EvidenceState::Partial,
                ClaimLevel::Implemented => EvidenceState::Verified,
            }));
            evidence.missing += records.len().saturating_sub(claims.len());
            InventoryCoverage {
                inventory_id: inventory_id.clone(),
                fully_implemented: claims
                    .iter()
                    .filter(|level| **level == ClaimLevel::Implemented)
                    .count(),
                registered: claims.len(),
                total: records.len(),
                evidence,
            }
        })
        .collect::<Vec<_>>();

    let totals = ParityTotals {
        implemented: ledgers.iter().map(|ledger| ledger.implemented).sum(),
        partial: ledgers.iter().map(|ledger| ledger.partial).sum(),
        unimplemented: ledgers.iter().map(|ledger| ledger.unimplemented).sum(),
        total: ledgers.iter().map(|ledger| ledger.features.len()).sum(),
        registered: ledgers.iter().map(|ledger| ledger.registered).sum(),
        evidence: EvidenceTotals {
            measured: ledgers.iter().map(|ledger| ledger.evidence.measured).sum(),
            verified: ledgers.iter().map(|ledger| ledger.evidence.verified).sum(),
            partial: ledgers.iter().map(|ledger| ledger.evidence.partial).sum(),
            missing: ledgers.iter().map(|ledger| ledger.evidence.missing).sum(),
        },
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

fn count_evidence_states(states: impl Iterator<Item = EvidenceState>) -> EvidenceTotals {
    let mut totals = EvidenceTotals::default();
    for state in states {
        match state {
            EvidenceState::Measured => totals.measured += 1,
            EvidenceState::Verified => totals.verified += 1,
            EvidenceState::Partial => totals.partial += 1,
            EvidenceState::Missing => totals.missing += 1,
        }
    }
    totals
}

#[cfg(test)]
mod tests {
    use super::{EvidenceGap, EvidenceState, ParityStatus};

    #[test]
    fn parity_status_names_are_stable() {
        assert_eq!(ParityStatus::Unimplemented.as_str(), "unimplemented");
        assert_eq!(ParityStatus::Partial.as_str(), "partial");
        assert_eq!(ParityStatus::Implemented.as_str(), "implemented");
    }

    #[test]
    fn evidence_state_and_gap_names_are_stable() {
        assert_eq!(EvidenceState::Measured.as_str(), "measured");
        assert_eq!(EvidenceState::Verified.as_str(), "verified");
        assert_eq!(EvidenceState::Partial.as_str(), "partial");
        assert_eq!(EvidenceState::Missing.as_str(), "missing");
        assert_eq!(EvidenceGap::NoClaim.as_str(), "no_claim");
        assert_eq!(EvidenceGap::RegistrationOnly.as_str(), "registration_only");
        assert_eq!(EvidenceGap::PartialCoverage.as_str(), "partial_coverage");
        assert_eq!(
            EvidenceGap::RuntimeMeasurement.as_str(),
            "runtime_measurement"
        );
    }
}

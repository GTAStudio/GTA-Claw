//! The lifecycle contract every context engine must satisfy.
//!
//! The context-engine SPI has five phases — `bootstrap`, `ingest`, `assemble`, `maintain` and
//! `compact` — and the contract is more than "each method returns something". An engine that
//! answers before it was opened, that forgets what it was told, or that quietly discards content
//! it committed to keeping is not usable by the runtime even though every call succeeded.
//!
//! This module names each obligation as a [`SpiRequirement`] so a failure report says *which*
//! part of the contract broke rather than "the engine misbehaved". [`crate::context_engine::suite`]
//! is the executable form of the list.

use std::error::Error;
use std::fmt::{self, Display, Formatter};

/// One phase of the context-engine lifecycle.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum LifecyclePhase {
    /// Opening the engine for a session.
    Bootstrap,
    /// Offering one item to the engine.
    Ingest,
    /// Producing the prompt for one provider round.
    Assemble,
    /// Between-round upkeep.
    Maintain,
    /// Shedding context to fit the budget.
    Compact,
}

impl LifecyclePhase {
    /// Every phase, in lifecycle order.
    pub const ALL: [Self; 5] = [
        Self::Bootstrap,
        Self::Ingest,
        Self::Assemble,
        Self::Maintain,
        Self::Compact,
    ];

    /// Returns the stable label for this phase.
    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            Self::Bootstrap => "bootstrap",
            Self::Ingest => "ingest",
            Self::Assemble => "assemble",
            Self::Maintain => "maintain",
            Self::Compact => "compact",
        }
    }
}

impl Display for LifecyclePhase {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.label())
    }
}

/// One obligation a conformant context engine owes its host.
///
/// The set is closed: [`SpiRequirement::ALL`] is the whole contract, and a conformance run that
/// does not exercise every one of them is reported as incomplete rather than as a pass.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum SpiRequirement {
    /// `ingest` before `bootstrap` is refused with a conflict.
    IngestBeforeBootstrapIsRejected,
    /// `assemble` before `bootstrap` is refused with a conflict.
    AssembleBeforeBootstrapIsRejected,
    /// `maintain` before `bootstrap` is refused with a conflict.
    MaintainBeforeBootstrapIsRejected,
    /// `compact` before `bootstrap` is refused with a conflict.
    CompactBeforeBootstrapIsRejected,
    /// `bootstrap` reports back the token budget it was handed.
    BootstrapEchoesBudget,
    /// A `NewSession` bootstrap resets the engine to empty, even on a used engine.
    NewSessionBootstrapStartsEmpty,
    /// A lifecycle call naming a session the engine was not opened for is refused.
    ForeignSessionIsRejected,
    /// After `n` accepted ingests the engine reports exactly `n` items.
    IngestCountsEveryItem,
    /// Ingesting a distinct, non-empty item strictly increases reported usage.
    IngestGrowsUsage,
    /// The assembled prompt carries the content of every ingested item.
    AssembleReflectsIngestedItems,
    /// `assemble` is a read: it neither consumes items nor changes reported usage.
    AssembleDoesNotMutateState,
    /// `assemble` reports the budget the engine is working against.
    AssembleReportsBudget,
    /// Maintenance never discards pinned items.
    MaintainPreservesPinnedItems,
    /// Maintenance never grows the item count.
    MaintainDoesNotInventItems,
    /// A `Restart` bootstrap rehydrates rather than resets: it keeps what the engine holds.
    RestartBootstrapPreservesContext,
    /// `needs_compaction` equals `used_tokens > token_budget` in every reported state.
    PressureFlagTracksBudget,
    /// The item count after compaction equals the count before minus the items removed.
    CompactAccountsForRemovals,
    /// Compaction frees at least the tokens it was asked to reclaim.
    CompactReclaimsRequestedTokens,
    /// The reclaimed-token figure equals the drop in reported usage.
    CompactReportsFreedTokens,
    /// Compaction never discards pinned items.
    CompactPreservesPinnedItems,
    /// `compacted_items` accumulates every item compaction removed.
    CompactAccumulatesRemovedItems,
}

impl SpiRequirement {
    /// Every requirement, in the order the suite exercises them.
    pub const ALL: [Self; 21] = [
        Self::IngestBeforeBootstrapIsRejected,
        Self::AssembleBeforeBootstrapIsRejected,
        Self::MaintainBeforeBootstrapIsRejected,
        Self::CompactBeforeBootstrapIsRejected,
        Self::BootstrapEchoesBudget,
        Self::NewSessionBootstrapStartsEmpty,
        Self::ForeignSessionIsRejected,
        Self::IngestCountsEveryItem,
        Self::IngestGrowsUsage,
        Self::AssembleReflectsIngestedItems,
        Self::AssembleDoesNotMutateState,
        Self::AssembleReportsBudget,
        Self::MaintainPreservesPinnedItems,
        Self::MaintainDoesNotInventItems,
        Self::RestartBootstrapPreservesContext,
        Self::PressureFlagTracksBudget,
        Self::CompactAccountsForRemovals,
        Self::CompactReclaimsRequestedTokens,
        Self::CompactReportsFreedTokens,
        Self::CompactPreservesPinnedItems,
        Self::CompactAccumulatesRemovedItems,
    ];

    /// Returns the lifecycle phase this requirement constrains.
    #[must_use]
    pub const fn phase(self) -> LifecyclePhase {
        match self {
            Self::IngestBeforeBootstrapIsRejected
            | Self::IngestCountsEveryItem
            | Self::IngestGrowsUsage => LifecyclePhase::Ingest,
            Self::AssembleBeforeBootstrapIsRejected
            | Self::AssembleReflectsIngestedItems
            | Self::AssembleDoesNotMutateState
            | Self::AssembleReportsBudget => LifecyclePhase::Assemble,
            Self::MaintainBeforeBootstrapIsRejected
            | Self::MaintainPreservesPinnedItems
            | Self::MaintainDoesNotInventItems => LifecyclePhase::Maintain,
            Self::CompactBeforeBootstrapIsRejected
            | Self::CompactAccountsForRemovals
            | Self::CompactReclaimsRequestedTokens
            | Self::CompactReportsFreedTokens
            | Self::CompactPreservesPinnedItems
            | Self::CompactAccumulatesRemovedItems => LifecyclePhase::Compact,
            Self::BootstrapEchoesBudget
            | Self::NewSessionBootstrapStartsEmpty
            | Self::ForeignSessionIsRejected
            | Self::RestartBootstrapPreservesContext
            | Self::PressureFlagTracksBudget => LifecyclePhase::Bootstrap,
        }
    }

    /// Returns the stable label for this requirement.
    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            Self::IngestBeforeBootstrapIsRejected => "ingest_before_bootstrap_is_rejected",
            Self::AssembleBeforeBootstrapIsRejected => "assemble_before_bootstrap_is_rejected",
            Self::MaintainBeforeBootstrapIsRejected => "maintain_before_bootstrap_is_rejected",
            Self::CompactBeforeBootstrapIsRejected => "compact_before_bootstrap_is_rejected",
            Self::BootstrapEchoesBudget => "bootstrap_echoes_budget",
            Self::NewSessionBootstrapStartsEmpty => "new_session_bootstrap_starts_empty",
            Self::ForeignSessionIsRejected => "foreign_session_is_rejected",
            Self::IngestCountsEveryItem => "ingest_counts_every_item",
            Self::IngestGrowsUsage => "ingest_grows_usage",
            Self::AssembleReflectsIngestedItems => "assemble_reflects_ingested_items",
            Self::AssembleDoesNotMutateState => "assemble_does_not_mutate_state",
            Self::AssembleReportsBudget => "assemble_reports_budget",
            Self::MaintainPreservesPinnedItems => "maintain_preserves_pinned_items",
            Self::MaintainDoesNotInventItems => "maintain_does_not_invent_items",
            Self::RestartBootstrapPreservesContext => "restart_bootstrap_preserves_context",
            Self::PressureFlagTracksBudget => "pressure_flag_tracks_budget",
            Self::CompactAccountsForRemovals => "compact_accounts_for_removals",
            Self::CompactReclaimsRequestedTokens => "compact_reclaims_requested_tokens",
            Self::CompactReportsFreedTokens => "compact_reports_freed_tokens",
            Self::CompactPreservesPinnedItems => "compact_preserves_pinned_items",
            Self::CompactAccumulatesRemovedItems => "compact_accumulates_removed_items",
        }
    }
}

impl Display for SpiRequirement {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.label())
    }
}

/// One broken requirement, with what the suite observed.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SpiViolation {
    /// The requirement that broke.
    pub requirement: SpiRequirement,
    /// What the engine did instead.
    pub detail: String,
}

impl Display for SpiViolation {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        write!(formatter, "{}: {}", self.requirement, self.detail)
    }
}

impl Error for SpiViolation {}

/// The outcome of one conformance run.
///
/// A report distinguishes three outcomes, not two. An engine can be conformant, non-conformant,
/// or *unproven*: a run that stopped early — because a call failed where the contract requires
/// success — leaves later requirements untested, and reporting that as a pass would be the
/// vacuous answer. [`SpiReport::is_complete`] separates the last case from the first.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SpiReport {
    exercised: Vec<SpiRequirement>,
    violations: Vec<SpiViolation>,
}

impl SpiReport {
    /// Builds a report from the checks that ran and the violations they found.
    #[must_use]
    pub fn new(exercised: Vec<SpiRequirement>, violations: Vec<SpiViolation>) -> Self {
        Self {
            exercised,
            violations,
        }
    }

    /// Returns every violation, in the order the suite found them.
    #[must_use]
    pub fn violations(&self) -> &[SpiViolation] {
        &self.violations
    }

    /// Returns the number of individual checks the run executed.
    #[must_use]
    pub fn checks_run(&self) -> usize {
        self.exercised.len()
    }

    /// Returns the distinct requirements the run actually tested, in contract order.
    #[must_use]
    pub fn exercised_requirements(&self) -> Vec<SpiRequirement> {
        SpiRequirement::ALL
            .into_iter()
            .filter(|requirement| self.exercised.contains(requirement))
            .collect()
    }

    /// Returns the distinct requirements the engine broke, in contract order.
    #[must_use]
    pub fn violated_requirements(&self) -> Vec<SpiRequirement> {
        SpiRequirement::ALL
            .into_iter()
            .filter(|requirement| {
                self.violations
                    .iter()
                    .any(|violation| violation.requirement == *requirement)
            })
            .collect()
    }

    /// Returns whether the run reached every requirement in the contract.
    #[must_use]
    pub fn is_complete(&self) -> bool {
        self.exercised_requirements().len() == SpiRequirement::ALL.len()
    }

    /// Returns whether the engine honoured every requirement the run reached.
    #[must_use]
    pub fn is_conformant(&self) -> bool {
        self.violations.is_empty()
    }

    /// Returns whether the engine is conformant *and* the run proved it end to end.
    #[must_use]
    pub fn is_proven_conformant(&self) -> bool {
        self.is_conformant() && self.is_complete()
    }
}

impl Display for SpiReport {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "{} checks, {} requirements reached, {} violations",
            self.checks_run(),
            self.exercised_requirements().len(),
            self.violations.len()
        )
    }
}

/// Accumulates the outcome of a conformance run.
pub(crate) struct Recorder {
    exercised: Vec<SpiRequirement>,
    violations: Vec<SpiViolation>,
}

impl Recorder {
    pub(crate) const fn new() -> Self {
        Self {
            exercised: Vec::new(),
            violations: Vec::new(),
        }
    }

    /// Runs one check: records that `requirement` was tested, and the violation when it fails.
    pub(crate) fn check(
        &mut self,
        requirement: SpiRequirement,
        holds: bool,
        detail: impl FnOnce() -> String,
    ) {
        self.exercised.push(requirement);
        if !holds {
            self.violations.push(SpiViolation {
                requirement,
                detail: detail(),
            });
        }
    }

    pub(crate) fn into_report(self) -> SpiReport {
        SpiReport::new(self.exercised, self.violations)
    }
}

#[cfg(test)]
mod tests {
    use super::{LifecyclePhase, Recorder, SpiReport, SpiRequirement, SpiViolation};

    #[test]
    fn every_requirement_has_a_distinct_label() {
        let mut labels: Vec<&str> = SpiRequirement::ALL
            .iter()
            .map(|requirement| requirement.label())
            .collect();
        let total = labels.len();
        labels.sort_unstable();
        labels.dedup();

        assert_eq!(total, 21);
        assert_eq!(labels.len(), total);
    }

    #[test]
    fn every_lifecycle_phase_carries_at_least_one_requirement() {
        for phase in LifecyclePhase::ALL {
            assert!(
                SpiRequirement::ALL
                    .iter()
                    .any(|requirement| requirement.phase() == phase),
                "no requirement constrains the {phase} phase"
            );
        }
    }

    #[test]
    fn a_run_that_skips_requirements_is_not_proven_conformant() {
        let mut recorder = Recorder::new();
        recorder.check(SpiRequirement::BootstrapEchoesBudget, true, String::new);
        let report = recorder.into_report();

        assert!(report.is_conformant());
        assert!(!report.is_complete());
        assert!(!report.is_proven_conformant());
        assert_eq!(report.checks_run(), 1);
        assert_eq!(
            report.exercised_requirements(),
            vec![SpiRequirement::BootstrapEchoesBudget]
        );
    }

    #[test]
    fn violations_are_deduplicated_in_contract_order() {
        let report = SpiReport::new(
            vec![
                SpiRequirement::IngestCountsEveryItem,
                SpiRequirement::BootstrapEchoesBudget,
                SpiRequirement::IngestCountsEveryItem,
            ],
            vec![
                SpiViolation {
                    requirement: SpiRequirement::IngestCountsEveryItem,
                    detail: "first".to_owned(),
                },
                SpiViolation {
                    requirement: SpiRequirement::BootstrapEchoesBudget,
                    detail: "second".to_owned(),
                },
                SpiViolation {
                    requirement: SpiRequirement::IngestCountsEveryItem,
                    detail: "third".to_owned(),
                },
            ],
        );

        assert_eq!(
            report.violated_requirements(),
            vec![
                SpiRequirement::BootstrapEchoesBudget,
                SpiRequirement::IngestCountsEveryItem,
            ]
        );
        assert_eq!(report.violations().len(), 3);
        assert!(!report.is_conformant());
    }

    #[test]
    fn violations_render_requirement_and_detail() {
        let violation = SpiViolation {
            requirement: SpiRequirement::CompactPreservesPinnedItems,
            detail: "the pinned goal vanished".to_owned(),
        };

        assert_eq!(
            violation.to_string(),
            "compact_preserves_pinned_items: the pinned goal vanished"
        );
        assert_eq!(
            SpiRequirement::CompactPreservesPinnedItems.phase(),
            LifecyclePhase::Compact
        );
        assert_eq!(LifecyclePhase::Compact.to_string(), "compact");
    }
}

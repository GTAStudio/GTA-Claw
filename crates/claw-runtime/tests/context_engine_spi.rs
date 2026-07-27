//! Context-engine SPI conformance: the suite, its reference implementer, and the mutation
//! matrix that proves the suite is not vacuous.
//!
//! Three things are established here, and the third is the one that gives the first two any
//! weight:
//!
//! 1. [`ReferenceContextEngine`] is *proven* conformant — every requirement in the contract was
//!    reached and none was broken.
//! 2. An engine that fails a mandatory call is reported as unproven rather than as a pass.
//! 3. For every requirement in the contract there is a deliberately defective engine that breaks
//!    exactly that requirement, and the suite rejects it. A conformance suite that only ever runs
//!    against an implementation designed to pass proves nothing: it cannot distinguish honouring
//!    the contract from returning plausible numbers.
//!
//! Each mutant is the reference engine wrapped in a single, named defect, so a rejection is
//! attributable to that defect and nothing else. `a_defect_free_wrapper_stays_conformant` pins
//! the wrapper itself, otherwise a bug in the harness plumbing would masquerade as detection.

use std::sync::{Mutex, MutexGuard, PoisonError};

use claw_application::ports::context::{
    AssembledContext, BootstrapReason, CompactionReport, ContextAssembly, ContextBootstrap,
    ContextCompaction, ContextEnginePort, ContextIngest, ContextMaintenance, ContextState,
};
use claw_application::ports::provider::PromptMessage;
use claw_application::ports::{PortError, PortFuture};
use claw_domain::SessionId;
use claw_runtime::context_engine::{
    PROBE_ITEM_COUNT, ReferenceContextEngine, SpiRequirement, pinned_markers,
    verify_spi_conformance,
};

/// The number of individual checks a complete run executes.
///
/// Pinned so that shrinking the script — dropping the per-ingest checks, say — cannot silently
/// turn a 48-check proof into a 6-check one that still reports every requirement as reached.
const EXPECTED_CHECKS_PER_RUN: usize = 48;

fn session(name: &str) -> SessionId {
    SessionId::new(name).expect("the test session name is valid")
}

#[tokio::test]
async fn the_reference_engine_is_proven_conformant() {
    let engine = ReferenceContextEngine::new();

    let report = verify_spi_conformance(&engine, session("spi-reference")).await;

    assert!(
        report.is_proven_conformant(),
        "{report}; violations: {:?}",
        report.violations()
    );
    assert_eq!(report.violated_requirements(), Vec::new());
    assert_eq!(
        report.exercised_requirements(),
        SpiRequirement::ALL.to_vec(),
        "the run must reach every requirement in the contract"
    );
    assert_eq!(report.checks_run(), EXPECTED_CHECKS_PER_RUN);
}

#[tokio::test]
async fn the_reference_engine_ends_the_run_open_and_empty() {
    let engine = ReferenceContextEngine::new();
    let session_id = session("spi-reference-state");

    let report = verify_spi_conformance(&engine, session_id.clone()).await;

    assert!(report.is_proven_conformant(), "{report}");
    // Phase 8 reopens the session, so the suite leaves the engine usable rather than exhausted.
    assert_eq!(engine.open_session(), Some(session_id));
    assert_eq!(engine.items(), Vec::new());
}

/// An engine whose very first call fails.
struct DeadEngine;

impl ContextEnginePort for DeadEngine {
    fn bootstrap(
        &self,
        _request: ContextBootstrap,
    ) -> PortFuture<'_, Result<ContextState, PortError>> {
        Box::pin(async { Err(PortError::Unavailable("the engine is offline".to_owned())) })
    }

    fn ingest(&self, _request: ContextIngest) -> PortFuture<'_, Result<ContextState, PortError>> {
        Box::pin(async {
            Err(PortError::Conflict(
                "the context engine has not been bootstrapped".to_owned(),
            ))
        })
    }

    fn assemble(
        &self,
        _request: ContextAssembly,
    ) -> PortFuture<'_, Result<AssembledContext, PortError>> {
        Box::pin(async {
            Err(PortError::Conflict(
                "the context engine has not been bootstrapped".to_owned(),
            ))
        })
    }

    fn maintain(
        &self,
        _request: ContextMaintenance,
    ) -> PortFuture<'_, Result<ContextState, PortError>> {
        Box::pin(async {
            Err(PortError::Conflict(
                "the context engine has not been bootstrapped".to_owned(),
            ))
        })
    }

    fn compact(
        &self,
        _request: ContextCompaction,
    ) -> PortFuture<'_, Result<CompactionReport, PortError>> {
        Box::pin(async {
            Err(PortError::Conflict(
                "the context engine has not been bootstrapped".to_owned(),
            ))
        })
    }
}

#[tokio::test]
async fn an_engine_that_cannot_bootstrap_is_unproven_rather_than_passing() {
    let report = verify_spi_conformance(&DeadEngine, session("spi-dead")).await;

    assert!(!report.is_conformant());
    assert!(!report.is_complete());
    assert!(!report.is_proven_conformant());
    // The four closed-engine probes pass on their own merits before bootstrap is attempted.
    assert_eq!(
        report.exercised_requirements(),
        vec![
            SpiRequirement::IngestBeforeBootstrapIsRejected,
            SpiRequirement::AssembleBeforeBootstrapIsRejected,
            SpiRequirement::MaintainBeforeBootstrapIsRejected,
            SpiRequirement::CompactBeforeBootstrapIsRejected,
            SpiRequirement::BootstrapEchoesBudget,
        ]
    );
    assert_eq!(
        report.violated_requirements(),
        vec![SpiRequirement::BootstrapEchoesBudget]
    );
}

/// One deliberate breach of the lifecycle contract.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Defect {
    /// No defect at all: pins the wrapper itself.
    None,
    /// Answers `ingest` on an engine that was never opened.
    AcceptIngestBeforeBootstrap,
    /// Answers `assemble` on an engine that was never opened.
    AcceptAssembleBeforeBootstrap,
    /// Answers `maintain` on an engine that was never opened.
    AcceptMaintainBeforeBootstrap,
    /// Answers `compact` on an engine that was never opened.
    AcceptCompactBeforeBootstrap,
    /// Reports a bootstrap budget one token above the one it was handed.
    MisreportBootstrapBudget,
    /// Treats a `NewSession` bootstrap as a rehydrate, so reopening never clears the engine.
    NewSessionKeepsItems,
    /// Serves any session that asks, not only the one it was opened for.
    AcceptForeignSession,
    /// Reports one item no matter how many were ingested.
    SwallowIngestCount,
    /// Reports a constant usage figure from every ingest.
    FlattenIngestUsage,
    /// Assembles an unrelated prompt the first time it is asked.
    AssembleFixedPromptOnce,
    /// Reports one item fewer than it holds whenever it assembles.
    AssembleUnderreportsItems,
    /// Reports an assembly budget one token above the one it was opened with.
    MisreportAssembleBudget,
    /// Loses pinned content during maintenance.
    MaintainDropsPinned,
    /// Reports three items maintenance never received.
    MaintainInventsItems,
    /// Treats a `Restart` bootstrap as a reset, discarding the session it was asked to rehydrate.
    RestartWipesContext,
    /// Never admits to budget pressure.
    HidePressure,
    /// Reports one item more than compaction actually left behind.
    MisreportCompactedItemCount,
    /// Compacts one token's worth however much it was asked for.
    UnderReclaim,
    /// Claims one token more than compaction actually freed.
    MisreportReclaimedTokens,
    /// Loses pinned content during compaction.
    CompactDropsPinned,
    /// Forgets the running tally of compacted items.
    ForgetCompactedTally,
}

#[derive(Default)]
struct MutantState {
    opened: Option<SessionId>,
    assembles: u32,
    strip_pinned_from_next_assemble: bool,
}

/// The reference engine plus exactly one defect.
struct Mutant {
    inner: ReferenceContextEngine,
    defect: Defect,
    state: Mutex<MutantState>,
}

impl Mutant {
    fn new(defect: Defect) -> Self {
        Self {
            inner: ReferenceContextEngine::new(),
            defect,
            state: Mutex::new(MutantState::default()),
        }
    }

    fn lock(&self) -> MutexGuard<'_, MutantState> {
        self.state.lock().unwrap_or_else(PoisonError::into_inner)
    }

    fn is_closed(&self) -> bool {
        self.lock().opened.is_none()
    }

    fn is_foreign(&self, session_id: &SessionId) -> bool {
        matches!(&self.lock().opened, Some(open) if open != session_id)
    }

    /// Whether the defect makes the engine answer a call it has no business answering.
    fn usurps(&self, defect: Defect, session_id: &SessionId) -> bool {
        (self.defect == defect && self.is_closed())
            || (self.defect == Defect::AcceptForeignSession && self.is_foreign(session_id))
    }

    fn hide_pressure(&self, state: &mut ContextState) {
        if self.defect == Defect::HidePressure {
            state.needs_compaction = false;
        }
    }
}

const fn fabricated_state() -> ContextState {
    ContextState {
        item_count: 0,
        used_tokens: 0,
        token_budget: 0,
        needs_compaction: false,
        compacted_items: 0,
    }
}

fn carries_pinned_content(message: &PromptMessage) -> bool {
    let text = match message {
        PromptMessage::System { text }
        | PromptMessage::User { text }
        | PromptMessage::Assistant { text, .. } => text,
        PromptMessage::ToolResult { output, .. } => output,
    };
    pinned_markers().iter().any(|marker| text.contains(marker))
}

impl ContextEnginePort for Mutant {
    fn bootstrap(
        &self,
        request: ContextBootstrap,
    ) -> PortFuture<'_, Result<ContextState, PortError>> {
        let reason = match (self.defect, request.reason) {
            (Defect::NewSessionKeepsItems, BootstrapReason::NewSession) => BootstrapReason::Restart,
            (Defect::RestartWipesContext, BootstrapReason::Restart) => BootstrapReason::NewSession,
            (_, reason) => reason,
        };
        let session_id = request.session_id.clone();
        let request = ContextBootstrap { reason, ..request };
        Box::pin(async move {
            let mut state = self.inner.bootstrap(request).await?;
            self.lock().opened = Some(session_id);
            if self.defect == Defect::MisreportBootstrapBudget {
                state.token_budget = state.token_budget.saturating_add(1);
            }
            self.hide_pressure(&mut state);
            Ok(state)
        })
    }

    fn ingest(&self, request: ContextIngest) -> PortFuture<'_, Result<ContextState, PortError>> {
        Box::pin(async move {
            if self.usurps(Defect::AcceptIngestBeforeBootstrap, &request.session_id) {
                return Ok(fabricated_state());
            }
            let mut state = self.inner.ingest(request).await?;
            match self.defect {
                Defect::SwallowIngestCount => state.item_count = 1,
                Defect::FlattenIngestUsage => state.used_tokens = 7,
                _ => {}
            }
            self.hide_pressure(&mut state);
            Ok(state)
        })
    }

    fn assemble(
        &self,
        request: ContextAssembly,
    ) -> PortFuture<'_, Result<AssembledContext, PortError>> {
        Box::pin(async move {
            if self.usurps(Defect::AcceptAssembleBeforeBootstrap, &request.session_id) {
                return Ok(AssembledContext {
                    messages: Vec::new(),
                    state: fabricated_state(),
                });
            }
            let mut assembled = self.inner.assemble(request).await?;
            let (ordinal, strip_pinned) = {
                let mut state = self.lock();
                state.assembles = state.assembles.saturating_add(1);
                let strip = std::mem::take(&mut state.strip_pinned_from_next_assemble);
                (state.assembles, strip)
            };
            if strip_pinned {
                assembled
                    .messages
                    .retain(|message| !carries_pinned_content(message));
            }
            if self.defect == Defect::AssembleFixedPromptOnce && ordinal == 1 {
                assembled.messages = vec![PromptMessage::System {
                    text: "an unrelated standing instruction".to_owned(),
                }];
            }
            match self.defect {
                Defect::AssembleUnderreportsItems => {
                    assembled.state.item_count = assembled.state.item_count.saturating_sub(1);
                }
                Defect::MisreportAssembleBudget => {
                    assembled.state.token_budget = assembled.state.token_budget.saturating_add(1);
                }
                _ => {}
            }
            self.hide_pressure(&mut assembled.state);
            Ok(assembled)
        })
    }

    fn maintain(
        &self,
        request: ContextMaintenance,
    ) -> PortFuture<'_, Result<ContextState, PortError>> {
        Box::pin(async move {
            if self.usurps(Defect::AcceptMaintainBeforeBootstrap, &request.session_id) {
                return Ok(fabricated_state());
            }
            let mut state = self.inner.maintain(request).await?;
            match self.defect {
                Defect::MaintainDropsPinned => {
                    self.lock().strip_pinned_from_next_assemble = true;
                }
                Defect::MaintainInventsItems => {
                    state.item_count = state.item_count.saturating_add(3);
                }
                _ => {}
            }
            self.hide_pressure(&mut state);
            Ok(state)
        })
    }

    fn compact(
        &self,
        request: ContextCompaction,
    ) -> PortFuture<'_, Result<CompactionReport, PortError>> {
        Box::pin(async move {
            if self.usurps(Defect::AcceptCompactBeforeBootstrap, &request.session_id) {
                return Ok(CompactionReport {
                    removed_items: 0,
                    reclaimed_tokens: 0,
                    state: fabricated_state(),
                });
            }
            let request = if self.defect == Defect::UnderReclaim {
                ContextCompaction {
                    reclaim_tokens: 1,
                    ..request
                }
            } else {
                request
            };
            let mut report = self.inner.compact(request).await?;
            match self.defect {
                Defect::MisreportCompactedItemCount => {
                    report.state.item_count = report.state.item_count.saturating_add(1);
                }
                Defect::MisreportReclaimedTokens => {
                    report.reclaimed_tokens = report.reclaimed_tokens.saturating_add(1);
                }
                Defect::ForgetCompactedTally => report.state.compacted_items = 0,
                Defect::CompactDropsPinned => {
                    self.lock().strip_pinned_from_next_assemble = true;
                }
                _ => {}
            }
            self.hide_pressure(&mut report.state);
            Ok(report)
        })
    }
}

/// Every defect, with the exact set of requirements the suite must report for it.
///
/// Three entries name more than one requirement. Those are genuine consequences rather than
/// imprecision in the suite, and each is spelled out where it appears: an engine that misstates
/// what it holds cannot then be measured against what it held.
const MUTATION_MATRIX: [(Defect, &[SpiRequirement]); 21] = [
    (
        Defect::AcceptIngestBeforeBootstrap,
        &[SpiRequirement::IngestBeforeBootstrapIsRejected],
    ),
    (
        Defect::AcceptAssembleBeforeBootstrap,
        &[SpiRequirement::AssembleBeforeBootstrapIsRejected],
    ),
    (
        Defect::AcceptMaintainBeforeBootstrap,
        &[SpiRequirement::MaintainBeforeBootstrapIsRejected],
    ),
    (
        Defect::AcceptCompactBeforeBootstrap,
        &[SpiRequirement::CompactBeforeBootstrapIsRejected],
    ),
    (
        Defect::MisreportBootstrapBudget,
        &[SpiRequirement::BootstrapEchoesBudget],
    ),
    (
        Defect::NewSessionKeepsItems,
        &[SpiRequirement::NewSessionBootstrapStartsEmpty],
    ),
    (
        Defect::AcceptForeignSession,
        &[SpiRequirement::ForeignSessionIsRejected],
    ),
    (
        Defect::SwallowIngestCount,
        &[SpiRequirement::IngestCountsEveryItem],
    ),
    // A constant usage figure also makes the compaction target unreachable: the suite sizes the
    // target from the usage the engine reported after the pinned items, and shedding every
    // unpinned item cannot free more than the engine really held.
    (
        Defect::FlattenIngestUsage,
        &[
            SpiRequirement::IngestGrowsUsage,
            SpiRequirement::CompactReclaimsRequestedTokens,
        ],
    ),
    (
        Defect::AssembleFixedPromptOnce,
        &[SpiRequirement::AssembleReflectsIngestedItems],
    ),
    (
        Defect::AssembleUnderreportsItems,
        &[SpiRequirement::AssembleDoesNotMutateState],
    ),
    (
        Defect::MisreportAssembleBudget,
        &[SpiRequirement::AssembleReportsBudget],
    ),
    (
        Defect::MaintainDropsPinned,
        &[SpiRequirement::MaintainPreservesPinnedItems],
    ),
    // Inventing items during maintenance also fails the restart check, because the count
    // maintenance reported is the only ground truth the suite has for what the engine held
    // going into the restart.
    (
        Defect::MaintainInventsItems,
        &[
            SpiRequirement::MaintainDoesNotInventItems,
            SpiRequirement::RestartBootstrapPreservesContext,
        ],
    ),
    // Wiping the session on restart destroys the evidence the compaction phase runs on: there is
    // no surplus left to reclaim and no pinned content left to preserve.
    (
        Defect::RestartWipesContext,
        &[
            SpiRequirement::RestartBootstrapPreservesContext,
            SpiRequirement::CompactReclaimsRequestedTokens,
            SpiRequirement::CompactPreservesPinnedItems,
        ],
    ),
    (
        Defect::HidePressure,
        &[SpiRequirement::PressureFlagTracksBudget],
    ),
    (
        Defect::MisreportCompactedItemCount,
        &[SpiRequirement::CompactAccountsForRemovals],
    ),
    (
        Defect::UnderReclaim,
        &[SpiRequirement::CompactReclaimsRequestedTokens],
    ),
    (
        Defect::MisreportReclaimedTokens,
        &[SpiRequirement::CompactReportsFreedTokens],
    ),
    (
        Defect::CompactDropsPinned,
        &[SpiRequirement::CompactPreservesPinnedItems],
    ),
    (
        Defect::ForgetCompactedTally,
        &[SpiRequirement::CompactAccumulatesRemovedItems],
    ),
];

#[tokio::test]
async fn a_defect_free_wrapper_stays_conformant() {
    let engine = Mutant::new(Defect::None);

    let report = verify_spi_conformance(&engine, session("spi-wrapper")).await;

    assert!(
        report.is_proven_conformant(),
        "the wrapper itself must not break the contract: {report}; {:?}",
        report.violations()
    );
    assert_eq!(report.checks_run(), EXPECTED_CHECKS_PER_RUN);
}

#[tokio::test]
async fn every_defect_is_rejected_with_exactly_the_requirements_it_breaks() {
    for (defect, expected) in MUTATION_MATRIX {
        let engine = Mutant::new(defect);

        let report = verify_spi_conformance(&engine, session("spi-mutant")).await;

        assert!(
            !report.is_conformant(),
            "{defect:?} slipped through the suite: {report}"
        );
        assert!(
            !report.is_proven_conformant(),
            "{defect:?} must never be reported as proven conformant"
        );
        assert_eq!(
            report.violated_requirements(),
            expected.to_vec(),
            "{defect:?} was rejected for the wrong reasons; details: {:?}",
            report
                .violations()
                .iter()
                .map(ToString::to_string)
                .collect::<Vec<String>>()
        );
    }
}

#[test]
fn the_mutation_matrix_makes_every_requirement_trippable() {
    let mut covered: Vec<SpiRequirement> = MUTATION_MATRIX
        .iter()
        .flat_map(|(_, requirements)| requirements.iter().copied())
        .collect();
    covered.sort_unstable();
    covered.dedup();
    let mut all = SpiRequirement::ALL.to_vec();
    all.sort_unstable();

    assert_eq!(
        covered, all,
        "a requirement no defect can trip is a requirement the suite does not really enforce"
    );
}

#[test]
fn every_defect_appears_in_the_matrix_exactly_once() {
    assert_eq!(MUTATION_MATRIX.len(), SpiRequirement::ALL.len());
    for (defect, _) in MUTATION_MATRIX {
        assert_ne!(
            defect,
            Defect::None,
            "the defect-free wrapper is not a mutant"
        );
        let occurrences = MUTATION_MATRIX
            .iter()
            .filter(|(other, _)| *other == defect)
            .count();
        assert_eq!(
            occurrences, 1,
            "{defect:?} appears {occurrences} times; a duplicate would let one requirement \
             stand in for another"
        );
    }
}

#[tokio::test]
async fn the_suite_leaves_a_conformant_engine_holding_only_pinned_content_at_compaction() {
    // The compaction target the suite picks is only meaningful if it really forces work: this
    // pins what "shed the surplus" did to a conformant engine — every unpinned item out, every
    // pinned item kept — rather than trusting the engine's own report of it.
    let pinned = u32::try_from(pinned_markers().len()).expect("two markers fit in a u32");
    let observer = RunObserver::new(ReferenceContextEngine::new());

    let report = verify_spi_conformance(&observer, session("spi-compaction")).await;

    assert!(report.is_proven_conformant(), "{report}");
    let (removed, remaining) = observer.compaction();
    assert_eq!(removed, PROBE_ITEM_COUNT - pinned);
    assert_eq!(remaining, pinned);
}

/// Records every state a conformant engine returned, and what compaction actually did.
///
/// The suite reports what it *checked*; this records what the engine actually did, so the tests
/// above can assert that the script reached the situations those checks are meant to cover
/// instead of trusting that it did.
#[derive(Default)]
struct RunObservations {
    states: Vec<ContextState>,
    compaction: Option<(u32, u32)>,
}

struct RunObserver {
    inner: ReferenceContextEngine,
    observations: Mutex<RunObservations>,
}

impl RunObserver {
    fn new(inner: ReferenceContextEngine) -> Self {
        Self {
            inner,
            observations: Mutex::new(RunObservations::default()),
        }
    }

    fn observations(&self) -> MutexGuard<'_, RunObservations> {
        self.observations
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
    }

    fn record(&self, state: &ContextState) {
        self.observations().states.push(state.clone());
    }

    fn states(&self) -> Vec<ContextState> {
        self.observations().states.clone()
    }

    /// Returns the items compaction removed and the items it left behind.
    fn compaction(&self) -> (u32, u32) {
        self.observations()
            .compaction
            .expect("the suite always reaches the compaction phase on a conformant engine")
    }
}

impl ContextEnginePort for RunObserver {
    fn bootstrap(
        &self,
        request: ContextBootstrap,
    ) -> PortFuture<'_, Result<ContextState, PortError>> {
        Box::pin(async move {
            let state = self.inner.bootstrap(request).await?;
            self.record(&state);
            Ok(state)
        })
    }

    fn ingest(&self, request: ContextIngest) -> PortFuture<'_, Result<ContextState, PortError>> {
        Box::pin(async move {
            let state = self.inner.ingest(request).await?;
            self.record(&state);
            Ok(state)
        })
    }

    fn assemble(
        &self,
        request: ContextAssembly,
    ) -> PortFuture<'_, Result<AssembledContext, PortError>> {
        Box::pin(async move {
            let assembled = self.inner.assemble(request).await?;
            self.record(&assembled.state);
            Ok(assembled)
        })
    }

    fn maintain(
        &self,
        request: ContextMaintenance,
    ) -> PortFuture<'_, Result<ContextState, PortError>> {
        Box::pin(async move {
            let state = self.inner.maintain(request).await?;
            self.record(&state);
            Ok(state)
        })
    }

    fn compact(
        &self,
        request: ContextCompaction,
    ) -> PortFuture<'_, Result<CompactionReport, PortError>> {
        Box::pin(async move {
            let report = self.inner.compact(request).await?;
            let mut observations = self.observations();
            observations.states.push(report.state.clone());
            observations.compaction = Some((report.removed_items, report.state.item_count));
            drop(observations);
            Ok(report)
        })
    }
}

#[tokio::test]
async fn the_pressure_flag_is_exercised_in_both_directions() {
    // `Defect::HidePressure` is only ever caught because the run reaches a genuinely pressured
    // state, so a script that never crossed the budget would report that defect as conformant.
    // This observes the states the reference engine actually returned and requires both halves.
    let observer = RunObserver::new(ReferenceContextEngine::new());
    let hidden = Mutant::new(Defect::HidePressure);

    let honest = verify_spi_conformance(&observer, session("spi-pressure-ok")).await;
    let report = verify_spi_conformance(&hidden, session("spi-pressure-hidden")).await;

    assert!(honest.is_proven_conformant(), "{honest}");
    let states = observer.states();
    assert!(
        states.iter().any(|state| state.needs_compaction),
        "no phase of the run put the engine over budget"
    );
    assert!(
        states.iter().any(|state| !state.needs_compaction),
        "no phase of the run left the engine under budget"
    );
    assert_eq!(
        report.violated_requirements(),
        vec![SpiRequirement::PressureFlagTracksBudget]
    );
}

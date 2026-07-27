//! Context-engine SPI conformance tests.

mod support;

use claw_application::ports::context::{
    AssembledContext, CompactionReport, ContextAssembly, ContextBootstrap, ContextCompaction,
    ContextEnginePort, ContextIngest, ContextMaintenance, ContextState,
};
use claw_application::ports::provider::PromptMessage;
use claw_application::ports::{PortError, PortFuture};
use claw_runtime::context::{
    ConformanceCheck, ConformanceFailure, ConformanceReport, verify_context_engine,
};

use support::{SimpleContext, session};

#[tokio::test]
async fn a_well_behaved_engine_passes_every_check() {
    let engine = SimpleContext::new();

    let report = verify_context_engine(engine.as_ref(), session("spi-ok"), 1_000).await;

    assert!(report.is_conformant(), "failures: {:?}", report.failures);
    assert_eq!(report.failures, Vec::new());
    // Four ingests exercise the two per-ingest checks four times each.
    assert_eq!(
        report.passed,
        vec![
            ConformanceCheck::BootstrapEchoesBudget,
            ConformanceCheck::BootstrapStartsEmpty,
            ConformanceCheck::IngestCountsItems,
            ConformanceCheck::IngestDoesNotShrinkUsage,
            ConformanceCheck::IngestCountsItems,
            ConformanceCheck::IngestDoesNotShrinkUsage,
            ConformanceCheck::IngestCountsItems,
            ConformanceCheck::IngestDoesNotShrinkUsage,
            ConformanceCheck::IngestCountsItems,
            ConformanceCheck::IngestDoesNotShrinkUsage,
            ConformanceCheck::AssembleProducesPrompt,
            ConformanceCheck::AssembleKeepsBudget,
            ConformanceCheck::MaintainPreservesItems,
            ConformanceCheck::CompactAccountsForRemovals,
            ConformanceCheck::CompactClearsPressure,
            ConformanceCheck::RestartBootstrapAccepted,
        ]
    );
    assert_eq!(engine.bootstraps(), 2, "open plus restart");
}

/// An engine that breaks four specific parts of the contract, and nothing else.
struct BrokenEngine;

impl BrokenEngine {
    const fn state(items: u32, used: u32, budget: u32, needs_compaction: bool) -> ContextState {
        ContextState {
            item_count: items,
            used_tokens: used,
            token_budget: budget,
            needs_compaction,
            compacted_items: 0,
        }
    }
}

impl ContextEnginePort for BrokenEngine {
    fn bootstrap(
        &self,
        request: ContextBootstrap,
    ) -> PortFuture<'_, Result<ContextState, PortError>> {
        // Reports a budget it was not given, and claims to already hold an item.
        let state = Self::state(1, 4, request.token_budget + 1, false);
        Box::pin(async move { Ok(state) })
    }

    fn ingest(&self, _request: ContextIngest) -> PortFuture<'_, Result<ContextState, PortError>> {
        // Never grows the item count, so the per-ingest accounting check fails after the first.
        let state = Self::state(1, 4, 1_001, false);
        Box::pin(async move { Ok(state) })
    }

    fn assemble(
        &self,
        _request: ContextAssembly,
    ) -> PortFuture<'_, Result<AssembledContext, PortError>> {
        let assembled = AssembledContext {
            messages: Vec::<PromptMessage>::new(),
            state: Self::state(1, 4, 1_001, false),
        };
        Box::pin(async move { Ok(assembled) })
    }

    fn maintain(
        &self,
        _request: ContextMaintenance,
    ) -> PortFuture<'_, Result<ContextState, PortError>> {
        // Maintenance invents items.
        let state = Self::state(9, 40, 1_001, false);
        Box::pin(async move { Ok(state) })
    }

    fn compact(
        &self,
        _request: ContextCompaction,
    ) -> PortFuture<'_, Result<CompactionReport, PortError>> {
        Box::pin(async move {
            Err(PortError::Unavailable(
                "the compactor is offline".to_owned(),
            ))
        })
    }
}

#[tokio::test]
async fn a_broken_engine_is_reported_check_by_check() {
    let report = verify_context_engine(&BrokenEngine, session("spi-broken"), 1_000).await;

    assert!(!report.is_conformant());
    assert_eq!(
        report.failures,
        vec![
            ConformanceFailure::Violated {
                check: ConformanceCheck::BootstrapEchoesBudget,
                detail: "expected budget 1000, engine reported 1001".to_owned(),
            },
            ConformanceFailure::Violated {
                check: ConformanceCheck::BootstrapStartsEmpty,
                detail: "expected an empty engine, got 1 items and 0 compacted".to_owned(),
            },
            ConformanceFailure::Violated {
                check: ConformanceCheck::IngestCountsItems,
                detail: "after 2 ingests the engine reported 1 items".to_owned(),
            },
            ConformanceFailure::Violated {
                check: ConformanceCheck::IngestCountsItems,
                detail: "after 3 ingests the engine reported 1 items".to_owned(),
            },
            ConformanceFailure::Violated {
                check: ConformanceCheck::IngestCountsItems,
                detail: "after 4 ingests the engine reported 1 items".to_owned(),
            },
            ConformanceFailure::Violated {
                check: ConformanceCheck::AssembleProducesPrompt,
                detail: "the engine assembled an empty prompt from a non-empty context".to_owned(),
            },
            ConformanceFailure::Violated {
                check: ConformanceCheck::AssembleKeepsBudget,
                detail: "expected budget 1000, engine reported 1001".to_owned(),
            },
            ConformanceFailure::Violated {
                check: ConformanceCheck::MaintainPreservesItems,
                detail: "maintenance grew the context from 1 to 9 items".to_owned(),
            },
            ConformanceFailure::Errored {
                check: ConformanceCheck::CompactAccountsForRemovals,
                error: PortError::Unavailable("the compactor is offline".to_owned()),
            },
            ConformanceFailure::Violated {
                check: ConformanceCheck::RestartBootstrapAccepted,
                detail: "restart bootstrap reported budget 1001, expected 1000".to_owned(),
            },
        ]
    );
    assert_eq!(
        report.passed,
        vec![
            // The first ingest happens to land on the right count, and usage never shrinks.
            ConformanceCheck::IngestCountsItems,
            ConformanceCheck::IngestDoesNotShrinkUsage,
            ConformanceCheck::IngestDoesNotShrinkUsage,
            ConformanceCheck::IngestDoesNotShrinkUsage,
            ConformanceCheck::IngestDoesNotShrinkUsage,
        ]
    );
}

/// An engine whose very first call fails; the harness must stop instead of panicking.
struct DeadEngine;

impl ContextEnginePort for DeadEngine {
    fn bootstrap(
        &self,
        _request: ContextBootstrap,
    ) -> PortFuture<'_, Result<ContextState, PortError>> {
        Box::pin(async move { Err(PortError::Cancelled) })
    }

    fn ingest(&self, _request: ContextIngest) -> PortFuture<'_, Result<ContextState, PortError>> {
        panic!("the harness must not ingest into an engine that failed to bootstrap");
    }

    fn assemble(
        &self,
        _request: ContextAssembly,
    ) -> PortFuture<'_, Result<AssembledContext, PortError>> {
        panic!("the harness must not assemble from an engine that failed to bootstrap");
    }

    fn maintain(
        &self,
        _request: ContextMaintenance,
    ) -> PortFuture<'_, Result<ContextState, PortError>> {
        panic!("the harness must not maintain an engine that failed to bootstrap");
    }

    fn compact(
        &self,
        _request: ContextCompaction,
    ) -> PortFuture<'_, Result<CompactionReport, PortError>> {
        panic!("the harness must not compact an engine that failed to bootstrap");
    }
}

#[tokio::test]
async fn a_bootstrap_failure_ends_the_run_immediately() {
    let report = verify_context_engine(&DeadEngine, session("spi-dead"), 32).await;

    assert_eq!(
        report,
        ConformanceReport {
            passed: Vec::new(),
            failures: vec![ConformanceFailure::Errored {
                check: ConformanceCheck::BootstrapEchoesBudget,
                error: PortError::Cancelled,
            }],
        }
    );
}

#[test]
fn every_conformance_check_has_a_stable_label() {
    let labels: Vec<&str> = ConformanceCheck::ALL
        .iter()
        .map(|check| check.label())
        .collect();

    assert_eq!(
        labels,
        vec![
            "bootstrap_echoes_budget",
            "bootstrap_starts_empty",
            "ingest_counts_items",
            "ingest_does_not_shrink_usage",
            "assemble_produces_prompt",
            "assemble_keeps_budget",
            "maintain_preserves_items",
            "compact_accounts_for_removals",
            "compact_clears_pressure",
            "restart_bootstrap_accepted",
        ]
    );
}

//! Context-engine SPI support: an in-process conformance harness for [`ContextEnginePort`].
//!
//! The runtime treats the context engine as a plug-in, so it needs a way to reject engines that
//! break the SPI contract before they are wired into a live session. [`verify_context_engine`]
//! drives one engine through the whole lifecycle and reports every invariant it checked.

use std::error::Error;
use std::fmt::{self, Display, Formatter};

use claw_application::model::ids::TurnId;
use claw_application::model::time::Timestamp;
use claw_application::ports::PortError;
use claw_application::ports::context::{
    BootstrapReason, ContextAssembly, ContextBootstrap, ContextCompaction, ContextEnginePort,
    ContextIngest, ContextItem, ContextMaintenance,
};
use claw_domain::SessionId;

/// One invariant checked by [`verify_context_engine`].
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum ConformanceCheck {
    /// `bootstrap` echoes the requested token budget.
    BootstrapEchoesBudget,
    /// `bootstrap` starts from an empty engine.
    BootstrapStartsEmpty,
    /// `ingest` increases the item count by exactly one per item.
    IngestCountsItems,
    /// `ingest` never reports fewer used tokens than before.
    IngestDoesNotShrinkUsage,
    /// `assemble` returns a non-empty prompt once items were ingested.
    AssembleProducesPrompt,
    /// `assemble` keeps reporting the requested budget.
    AssembleKeepsBudget,
    /// `maintain` does not invent items.
    MaintainPreservesItems,
    /// `compact` reports removed items consistent with the resulting item count.
    CompactAccountsForRemovals,
    /// `compact` clears the compaction flag when it freed the requested tokens.
    CompactClearsPressure,
    /// A restart bootstrap is accepted.
    RestartBootstrapAccepted,
}

impl ConformanceCheck {
    /// Every check in execution order.
    pub const ALL: [Self; 10] = [
        Self::BootstrapEchoesBudget,
        Self::BootstrapStartsEmpty,
        Self::IngestCountsItems,
        Self::IngestDoesNotShrinkUsage,
        Self::AssembleProducesPrompt,
        Self::AssembleKeepsBudget,
        Self::MaintainPreservesItems,
        Self::CompactAccountsForRemovals,
        Self::CompactClearsPressure,
        Self::RestartBootstrapAccepted,
    ];

    /// Returns the stable label for this check.
    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            Self::BootstrapEchoesBudget => "bootstrap_echoes_budget",
            Self::BootstrapStartsEmpty => "bootstrap_starts_empty",
            Self::IngestCountsItems => "ingest_counts_items",
            Self::IngestDoesNotShrinkUsage => "ingest_does_not_shrink_usage",
            Self::AssembleProducesPrompt => "assemble_produces_prompt",
            Self::AssembleKeepsBudget => "assemble_keeps_budget",
            Self::MaintainPreservesItems => "maintain_preserves_items",
            Self::CompactAccountsForRemovals => "compact_accounts_for_removals",
            Self::CompactClearsPressure => "compact_clears_pressure",
            Self::RestartBootstrapAccepted => "restart_bootstrap_accepted",
        }
    }
}

impl Display for ConformanceCheck {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.label())
    }
}

/// A conformance failure.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ConformanceFailure {
    /// The engine broke an invariant.
    Violated {
        /// The check that failed.
        check: ConformanceCheck,
        /// What the harness observed.
        detail: String,
    },
    /// The engine returned an error where the contract requires success.
    Errored {
        /// The check that was running.
        check: ConformanceCheck,
        /// The reported error.
        error: PortError,
    },
}

impl Display for ConformanceFailure {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        match self {
            Self::Violated { check, detail } => write!(formatter, "{check} violated: {detail}"),
            Self::Errored { check, error } => write!(formatter, "{check} errored: {error}"),
        }
    }
}

impl Error for ConformanceFailure {}

/// The outcome of a conformance run.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ConformanceReport {
    /// The checks that passed, in execution order.
    pub passed: Vec<ConformanceCheck>,
    /// The failures, in execution order.
    pub failures: Vec<ConformanceFailure>,
}

impl ConformanceReport {
    /// Returns whether every check passed.
    #[must_use]
    pub const fn is_conformant(&self) -> bool {
        self.failures.is_empty()
    }
}

struct Harness {
    session_id: SessionId,
    budget: u32,
    passed: Vec<ConformanceCheck>,
    failures: Vec<ConformanceFailure>,
}

impl Harness {
    fn record(&mut self, check: ConformanceCheck, holds: bool, detail: impl FnOnce() -> String) {
        if holds {
            self.passed.push(check);
        } else {
            self.failures.push(ConformanceFailure::Violated {
                check,
                detail: detail(),
            });
        }
    }

    fn fail(&mut self, check: ConformanceCheck, error: PortError) {
        self.failures
            .push(ConformanceFailure::Errored { check, error });
    }
}

/// Drives `engine` through the full SPI lifecycle and reports what held.
///
/// The harness never panics on a misbehaving engine: contract breaches are returned as
/// [`ConformanceFailure`] values so a host can refuse an engine at load time.
pub async fn verify_context_engine(
    engine: &dyn ContextEnginePort,
    session_id: SessionId,
    token_budget: u32,
) -> ConformanceReport {
    let mut harness = Harness {
        session_id,
        budget: token_budget,
        passed: Vec::new(),
        failures: Vec::new(),
    };

    let bootstrap = ContextBootstrap {
        session_id: harness.session_id.clone(),
        reason: BootstrapReason::NewSession,
        token_budget: harness.budget,
        at: Timestamp::from_millis(0),
    };
    let opened = match engine.bootstrap(bootstrap).await {
        Ok(state) => state,
        Err(error) => {
            harness.fail(ConformanceCheck::BootstrapEchoesBudget, error);
            return ConformanceReport {
                passed: harness.passed,
                failures: harness.failures,
            };
        }
    };

    let budget = harness.budget;
    harness.record(
        ConformanceCheck::BootstrapEchoesBudget,
        opened.token_budget == budget,
        || {
            format!(
                "expected budget {budget}, engine reported {}",
                opened.token_budget
            )
        },
    );
    harness.record(
        ConformanceCheck::BootstrapStartsEmpty,
        opened.item_count == 0 && opened.compacted_items == 0,
        || {
            format!(
                "expected an empty engine, got {} items and {} compacted",
                opened.item_count, opened.compacted_items
            )
        },
    );

    let items = [
        ContextItem::SystemNote {
            text: "conformance harness".to_owned(),
        },
        ContextItem::UserInput {
            text: "hello".to_owned(),
        },
        ContextItem::AssistantMessage {
            text: "hi".to_owned(),
        },
        ContextItem::ToolResult {
            tool_name: "probe".to_owned(),
            output: "ok".to_owned(),
            failed: false,
        },
    ];

    let mut previous = opened;
    let mut ingested = 0_u32;
    for (offset, item) in items.into_iter().enumerate() {
        let request = ContextIngest {
            session_id: harness.session_id.clone(),
            turn: TurnId::FIRST,
            item,
            at: Timestamp::from_millis(i64::try_from(offset).unwrap_or(0) + 1),
        };
        match engine.ingest(request).await {
            Ok(state) => {
                ingested += 1;
                let expected = ingested;
                harness.record(
                    ConformanceCheck::IngestCountsItems,
                    state.item_count == expected,
                    || {
                        format!(
                            "after {expected} ingests the engine reported {} items",
                            state.item_count
                        )
                    },
                );
                harness.record(
                    ConformanceCheck::IngestDoesNotShrinkUsage,
                    state.used_tokens >= previous.used_tokens,
                    || {
                        format!(
                            "usage fell from {} to {}",
                            previous.used_tokens, state.used_tokens
                        )
                    },
                );
                previous = state;
            }
            Err(error) => {
                harness.fail(ConformanceCheck::IngestCountsItems, error);
                return ConformanceReport {
                    passed: harness.passed,
                    failures: harness.failures,
                };
            }
        }
    }

    let assembly = ContextAssembly {
        session_id: harness.session_id.clone(),
        turn: TurnId::FIRST,
        round: 0,
    };
    match engine.assemble(assembly).await {
        Ok(assembled) => {
            harness.record(
                ConformanceCheck::AssembleProducesPrompt,
                !assembled.messages.is_empty(),
                || "the engine assembled an empty prompt from a non-empty context".to_owned(),
            );
            harness.record(
                ConformanceCheck::AssembleKeepsBudget,
                assembled.state.token_budget == budget,
                || {
                    format!(
                        "expected budget {budget}, engine reported {}",
                        assembled.state.token_budget
                    )
                },
            );
        }
        Err(error) => harness.fail(ConformanceCheck::AssembleProducesPrompt, error),
    }

    let maintenance = ContextMaintenance {
        session_id: harness.session_id.clone(),
        at: Timestamp::from_millis(100),
    };
    match engine.maintain(maintenance).await {
        Ok(state) => {
            let before = previous.item_count;
            harness.record(
                ConformanceCheck::MaintainPreservesItems,
                state.item_count <= before,
                || {
                    format!(
                        "maintenance grew the context from {before} to {} items",
                        state.item_count
                    )
                },
            );
            previous = state;
        }
        Err(error) => harness.fail(ConformanceCheck::MaintainPreservesItems, error),
    }

    let reclaim = previous.used_tokens.min(budget);
    let compaction = ContextCompaction {
        session_id: harness.session_id.clone(),
        reclaim_tokens: reclaim,
        at: Timestamp::from_millis(200),
    };
    match engine.compact(compaction).await {
        Ok(report) => {
            let before = previous.item_count;
            let removed = report.removed_items;
            let after = report.state.item_count;
            harness.record(
                ConformanceCheck::CompactAccountsForRemovals,
                before.saturating_sub(removed) == after,
                || format!("{before} items minus {removed} removed does not equal {after}"),
            );
            harness.record(
                ConformanceCheck::CompactClearsPressure,
                report.reclaimed_tokens < reclaim || !report.state.needs_compaction,
                || {
                    format!(
                        "the engine reclaimed {} of {reclaim} tokens but still demands compaction",
                        report.reclaimed_tokens
                    )
                },
            );
        }
        Err(error) => harness.fail(ConformanceCheck::CompactAccountsForRemovals, error),
    }

    let restart = ContextBootstrap {
        session_id: harness.session_id.clone(),
        reason: BootstrapReason::Restart,
        token_budget: budget,
        at: Timestamp::from_millis(300),
    };
    match engine.bootstrap(restart).await {
        Ok(state) => harness.record(
            ConformanceCheck::RestartBootstrapAccepted,
            state.token_budget == budget,
            || {
                format!(
                    "restart bootstrap reported budget {}, expected {budget}",
                    state.token_budget
                )
            },
        ),
        Err(error) => harness.fail(ConformanceCheck::RestartBootstrapAccepted, error),
    }

    ConformanceReport {
        passed: harness.passed,
        failures: harness.failures,
    }
}

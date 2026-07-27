//! The context-engine SPI conformance suite.
//!
//! [`verify_spi_conformance`] drives one engine through a scripted session that reaches every
//! [`SpiRequirement`] exactly once per requirement, and returns an [`SpiReport`] instead of
//! panicking, so a host can refuse a non-conformant engine at load time rather than in
//! production.
//!
//! # The script
//!
//! | Phase | What the suite does | Requirements reached |
//! | --- | --- | --- |
//! | 0 | Calls all four non-bootstrap methods on a closed engine | the four `*_before_bootstrap_is_rejected` rules |
//! | 1 | Bootstraps `NewSession` against [`CONFORMANCE_TOKEN_BUDGET`] | budget echo, empty start, pressure flag |
//! | 2 | Repeats the four calls naming a session the engine was never opened for | foreign-session rejection |
//! | 3 | Ingests the six-item probe corpus | ingest accounting and usage growth |
//! | 4 | Assembles twice | content fidelity, purity, budget reporting |
//! | 5 | Maintains, then assembles | pinned durability, no invented items |
//! | 6 | Bootstraps `Restart` against a budget the corpus already exceeds | rehydration, pressure flag under real pressure |
//! | 7 | Compacts away exactly the surplus, then assembles | removal accounting, reclaim accounting, pinned durability |
//! | 8 | Bootstraps `NewSession` again on the used engine | reset semantics |
//!
//! # Why the corpus is shaped the way it is
//!
//! The two pinned items are short and the four unpinned items each carry a two-kilobyte filler,
//! so the suite can pick a restart budget — the usage the engine itself reported after the two
//! pinned ingests — that is provably reachable by shedding unpinned items alone. Compaction is
//! then asked for exactly the surplus over that budget, which an engine can always free without
//! touching pinned content. An engine that cannot is genuinely non-conformant rather than a
//! victim of an arbitrary target.
//!
//! Every accounting rule that can be checked against the suite's own ground truth is, rather
//! than against a figure the engine reported earlier. An engine that lies about its item count
//! during `ingest` therefore fails the ingest rule alone instead of cascading into every later
//! rule that would otherwise have trusted the lie.

use claw_application::model::ids::TurnId;
use claw_application::model::time::Timestamp;
use claw_application::ports::PortError;
use claw_application::ports::context::{
    BootstrapReason, ContextAssembly, ContextBootstrap, ContextCompaction, ContextEnginePort,
    ContextIngest, ContextItem, ContextMaintenance, ContextState,
};
use claw_application::ports::provider::PromptMessage;
use claw_domain::SessionId;

use super::contract::{Recorder, SpiReport, SpiRequirement};

/// The budget the suite opens an engine with.
///
/// It is far above what the probe corpus can occupy under any sane token estimate, so the
/// opening phases run without budget pressure and the pressure flag is exercised in both
/// directions once phase 6 tightens the budget.
pub const CONFORMANCE_TOKEN_BUDGET: u32 = 1_000_000;

/// The number of items the suite ingests.
pub const PROBE_ITEM_COUNT: u32 = 6;

/// The number of leading probe items that are pinned.
pub const PINNED_PROBE_ITEM_COUNT: u32 = 2;

const PINNED_NOTE_MARKER: &str = "spi-marker-pinned-note";
const PINNED_GOAL_MARKER: &str = "spi-marker-pinned-goal";
const USER_INPUT_MARKER: &str = "spi-marker-user-input";
const ASSISTANT_MARKER: &str = "spi-marker-assistant-message";
const TOOL_OUTPUT_MARKER: &str = "spi-marker-tool-output";
const FOLLOWUP_MARKER: &str = "spi-marker-followup-input";

const FOREIGN_SESSION: &str = "spi-conformance-foreign-session";
const ALTERNATE_FOREIGN_SESSION: &str = "spi-conformance-other-session";

const BULK_FILLER_BYTES: usize = 2_048;

/// Returns the markers the suite expects to survive maintenance and compaction.
#[must_use]
pub const fn pinned_markers() -> [&'static str; 2] {
    [PINNED_NOTE_MARKER, PINNED_GOAL_MARKER]
}

/// Returns every marker the probe corpus carries, in ingest order.
#[must_use]
pub const fn probe_markers() -> [&'static str; 6] {
    [
        PINNED_NOTE_MARKER,
        PINNED_GOAL_MARKER,
        USER_INPUT_MARKER,
        ASSISTANT_MARKER,
        TOOL_OUTPUT_MARKER,
        FOLLOWUP_MARKER,
    ]
}

/// Returns the probe corpus: two short pinned items followed by four bulky unpinned ones.
#[must_use]
pub fn probe_items() -> Vec<ContextItem> {
    let filler = "y".repeat(BULK_FILLER_BYTES);
    vec![
        ContextItem::SystemNote {
            text: format!("{PINNED_NOTE_MARKER} keep this instruction"),
        },
        ContextItem::GoalStatement {
            objective: format!("{PINNED_GOAL_MARKER} keep this objective"),
        },
        ContextItem::UserInput {
            text: format!("{USER_INPUT_MARKER} {filler}"),
        },
        ContextItem::AssistantMessage {
            text: format!("{ASSISTANT_MARKER} {filler}"),
        },
        ContextItem::ToolResult {
            tool_name: "spi-probe".to_owned(),
            output: format!("{TOOL_OUTPUT_MARKER} {filler}"),
            failed: false,
        },
        ContextItem::UserInput {
            text: format!("{FOLLOWUP_MARKER} {filler}"),
        },
    ]
}

fn message_text(message: &PromptMessage) -> &str {
    match message {
        PromptMessage::System { text }
        | PromptMessage::User { text }
        | PromptMessage::Assistant { text, .. } => text,
        PromptMessage::ToolResult { output, .. } => output,
    }
}

fn missing_markers(messages: &[PromptMessage], markers: &[&'static str]) -> Vec<&'static str> {
    markers
        .iter()
        .copied()
        .filter(|marker| {
            !messages
                .iter()
                .any(|message| message_text(message).contains(marker))
        })
        .collect()
}

const fn is_conflict<T>(outcome: &Result<T, PortError>) -> bool {
    matches!(outcome, Err(PortError::Conflict(_)))
}

fn rejection_detail<T>(outcome: &Result<T, PortError>, phase: &str, why: &str) -> String {
    match outcome {
        Ok(_) => format!("the engine answered {phase} {why}"),
        Err(error) => {
            format!("the engine refused {phase} with `{error}` instead of reporting a conflict")
        }
    }
}

fn foreign_session(session_id: &SessionId) -> SessionId {
    let name = if session_id.as_str() == FOREIGN_SESSION {
        ALTERNATE_FOREIGN_SESSION
    } else {
        FOREIGN_SESSION
    };
    SessionId::new(name).expect("the constant foreign session name is valid")
}

fn bootstrap_request(
    session_id: &SessionId,
    reason: BootstrapReason,
    token_budget: u32,
    millis: i64,
) -> ContextBootstrap {
    ContextBootstrap {
        session_id: session_id.clone(),
        reason,
        token_budget,
        at: Timestamp::from_millis(millis),
    }
}

fn ingest_request(session_id: &SessionId, item: ContextItem, millis: i64) -> ContextIngest {
    ContextIngest {
        session_id: session_id.clone(),
        turn: TurnId::FIRST,
        item,
        at: Timestamp::from_millis(millis),
    }
}

fn assembly_request(session_id: &SessionId, round: u32) -> ContextAssembly {
    ContextAssembly {
        session_id: session_id.clone(),
        turn: TurnId::FIRST,
        round,
    }
}

fn maintenance_request(session_id: &SessionId, millis: i64) -> ContextMaintenance {
    ContextMaintenance {
        session_id: session_id.clone(),
        at: Timestamp::from_millis(millis),
    }
}

fn compaction_request(
    session_id: &SessionId,
    reclaim_tokens: u32,
    millis: i64,
) -> ContextCompaction {
    ContextCompaction {
        session_id: session_id.clone(),
        reclaim_tokens,
        at: Timestamp::from_millis(millis),
    }
}

fn check_pressure(recorder: &mut Recorder, state: &ContextState, origin: &str) {
    let over_budget = state.used_tokens > state.token_budget;
    recorder.check(
        SpiRequirement::PressureFlagTracksBudget,
        state.needs_compaction == over_budget,
        || {
            format!(
                "after {origin} the engine reported {} used against a {} budget \
                 but set needs_compaction to {}",
                state.used_tokens, state.token_budget, state.needs_compaction
            )
        },
    );
}

/// Calls every non-bootstrap method and requires each one to report a conflict.
async fn probe_closed_lifecycle(
    recorder: &mut Recorder,
    engine: &dyn ContextEnginePort,
    session_id: &SessionId,
    requirements: [SpiRequirement; 4],
    why: &str,
    millis: i64,
) {
    let probe = probe_items()
        .into_iter()
        .next()
        .expect("the probe corpus is never empty");

    let ingested = engine
        .ingest(ingest_request(session_id, probe, millis))
        .await;
    recorder.check(requirements[0], is_conflict(&ingested), || {
        rejection_detail(&ingested, "ingest", why)
    });

    let assembled = engine.assemble(assembly_request(session_id, 0)).await;
    recorder.check(requirements[1], is_conflict(&assembled), || {
        rejection_detail(&assembled, "assemble", why)
    });

    let maintained = engine
        .maintain(maintenance_request(session_id, millis))
        .await;
    recorder.check(requirements[2], is_conflict(&maintained), || {
        rejection_detail(&maintained, "maintain", why)
    });

    let compacted = engine
        .compact(compaction_request(session_id, 1, millis))
        .await;
    recorder.check(requirements[3], is_conflict(&compacted), || {
        rejection_detail(&compacted, "compact", why)
    });
}

/// Drives `engine` through the whole SPI lifecycle and reports what held.
///
/// The suite never panics on a misbehaving engine and never mutates anything outside it. A run
/// that could not complete — because a call the contract requires to succeed failed — is
/// reported as incomplete via [`SpiReport::is_complete`], so a caller must assert
/// [`SpiReport::is_proven_conformant`] rather than the absence of violations.
pub async fn verify_spi_conformance(
    engine: &dyn ContextEnginePort,
    session_id: SessionId,
) -> SpiReport {
    let mut recorder = Recorder::new();
    let foreign = foreign_session(&session_id);

    // Phase 0: a closed engine answers nothing.
    probe_closed_lifecycle(
        &mut recorder,
        engine,
        &session_id,
        [
            SpiRequirement::IngestBeforeBootstrapIsRejected,
            SpiRequirement::AssembleBeforeBootstrapIsRejected,
            SpiRequirement::MaintainBeforeBootstrapIsRejected,
            SpiRequirement::CompactBeforeBootstrapIsRejected,
        ],
        "before it was bootstrapped",
        0,
    )
    .await;

    // Phase 1: open the session.
    let opened = match engine
        .bootstrap(bootstrap_request(
            &session_id,
            BootstrapReason::NewSession,
            CONFORMANCE_TOKEN_BUDGET,
            10,
        ))
        .await
    {
        Ok(state) => state,
        Err(error) => {
            recorder.check(SpiRequirement::BootstrapEchoesBudget, false, || {
                format!("the opening bootstrap failed with `{error}`")
            });
            return recorder.into_report();
        }
    };
    recorder.check(
        SpiRequirement::BootstrapEchoesBudget,
        opened.token_budget == CONFORMANCE_TOKEN_BUDGET,
        || {
            format!(
                "the opening bootstrap was handed a {CONFORMANCE_TOKEN_BUDGET} budget \
                 and reported {}",
                opened.token_budget
            )
        },
    );
    recorder.check(
        SpiRequirement::NewSessionBootstrapStartsEmpty,
        opened.item_count == 0 && opened.used_tokens == 0 && opened.compacted_items == 0,
        || {
            format!(
                "the opening bootstrap reported {} items, {} used tokens and {} compacted items",
                opened.item_count, opened.used_tokens, opened.compacted_items
            )
        },
    );
    check_pressure(&mut recorder, &opened, "the opening bootstrap");

    // Phase 2: the engine belongs to one session.
    let foreign_requirements = [SpiRequirement::ForeignSessionIsRejected; 4];
    probe_closed_lifecycle(
        &mut recorder,
        engine,
        &foreign,
        foreign_requirements,
        "for a session it was never opened for",
        20,
    )
    .await;

    // Phase 3: ingest the probe corpus.
    let mut previous_used = opened.used_tokens;
    let mut used_after_pinned = 0_u32;
    for (offset, item) in probe_items().into_iter().enumerate() {
        let ordinal = u32::try_from(offset + 1).unwrap_or(u32::MAX);
        let millis = 100 + i64::try_from(offset).unwrap_or(0);
        let state = match engine
            .ingest(ingest_request(&session_id, item, millis))
            .await
        {
            Ok(state) => state,
            Err(error) => {
                recorder.check(SpiRequirement::IngestCountsEveryItem, false, || {
                    format!("ingest {ordinal} of {PROBE_ITEM_COUNT} failed with `{error}`")
                });
                return recorder.into_report();
            }
        };
        recorder.check(
            SpiRequirement::IngestCountsEveryItem,
            state.item_count == ordinal,
            || {
                format!(
                    "after {ordinal} accepted ingests the engine reported {} items",
                    state.item_count
                )
            },
        );
        recorder.check(
            SpiRequirement::IngestGrowsUsage,
            state.used_tokens > previous_used,
            || {
                format!(
                    "ingest {ordinal} moved reported usage from {previous_used} to {}",
                    state.used_tokens
                )
            },
        );
        check_pressure(&mut recorder, &state, &format!("ingest {ordinal}"));
        previous_used = state.used_tokens;
        if ordinal == PINNED_PROBE_ITEM_COUNT {
            used_after_pinned = state.used_tokens;
        }
    }

    // Phase 4: assemble twice.
    let first = match engine.assemble(assembly_request(&session_id, 0)).await {
        Ok(assembled) => assembled,
        Err(error) => {
            recorder.check(SpiRequirement::AssembleReflectsIngestedItems, false, || {
                format!("the first assemble failed with `{error}`")
            });
            return recorder.into_report();
        }
    };
    let absent = missing_markers(&first.messages, &probe_markers());
    recorder.check(
        SpiRequirement::AssembleReflectsIngestedItems,
        absent.is_empty(),
        || {
            format!(
                "the assembled prompt of {} messages carries none of {absent:?}",
                first.messages.len()
            )
        },
    );
    recorder.check(
        SpiRequirement::AssembleReportsBudget,
        first.state.token_budget == CONFORMANCE_TOKEN_BUDGET,
        || {
            format!(
                "assemble reported a {} budget against the {CONFORMANCE_TOKEN_BUDGET} \
                 the engine was opened with",
                first.state.token_budget
            )
        },
    );
    check_pressure(&mut recorder, &first.state, "the first assemble");

    let second = match engine.assemble(assembly_request(&session_id, 1)).await {
        Ok(assembled) => assembled,
        Err(error) => {
            recorder.check(SpiRequirement::AssembleDoesNotMutateState, false, || {
                format!("the second assemble failed with `{error}`")
            });
            return recorder.into_report();
        }
    };
    recorder.check(
        SpiRequirement::AssembleDoesNotMutateState,
        first.state.item_count == PROBE_ITEM_COUNT && second.state == first.state,
        || {
            format!(
                "{PROBE_ITEM_COUNT} items were ingested, then assemble reported {} items \
                 and assembling again reported {}",
                first.state.item_count, second.state.item_count
            )
        },
    );

    // Phase 5: between-round upkeep.
    let maintained = match engine.maintain(maintenance_request(&session_id, 200)).await {
        Ok(state) => state,
        Err(error) => {
            recorder.check(SpiRequirement::MaintainDoesNotInventItems, false, || {
                format!("maintenance failed with `{error}`")
            });
            return recorder.into_report();
        }
    };
    recorder.check(
        SpiRequirement::MaintainDoesNotInventItems,
        maintained.item_count <= PROBE_ITEM_COUNT,
        || {
            format!(
                "maintenance reported {} items from the {PROBE_ITEM_COUNT} that were ingested",
                maintained.item_count
            )
        },
    );
    check_pressure(&mut recorder, &maintained, "maintenance");

    match engine.assemble(assembly_request(&session_id, 2)).await {
        Ok(assembled) => {
            let lost = missing_markers(&assembled.messages, &pinned_markers());
            recorder.check(
                SpiRequirement::MaintainPreservesPinnedItems,
                lost.is_empty(),
                || format!("maintenance discarded the pinned content {lost:?}"),
            );
        }
        Err(error) => recorder.check(SpiRequirement::MaintainPreservesPinnedItems, false, || {
            format!("the prompt could not be assembled after maintenance: `{error}`")
        }),
    }

    // Phase 6: rehydrate against a budget the corpus already exceeds. The engine's own usage
    // report after the two pinned ingests is the tightest budget that shedding unpinned items
    // alone can still reach, so the compaction target in phase 7 is always achievable.
    let tight_budget = used_after_pinned.max(1);
    let restarted = match engine
        .bootstrap(bootstrap_request(
            &session_id,
            BootstrapReason::Restart,
            tight_budget,
            300,
        ))
        .await
    {
        Ok(state) => state,
        Err(error) => {
            recorder.check(
                SpiRequirement::RestartBootstrapPreservesContext,
                false,
                || format!("the restart bootstrap failed with `{error}`"),
            );
            return recorder.into_report();
        }
    };
    recorder.check(
        SpiRequirement::RestartBootstrapPreservesContext,
        restarted.item_count == maintained.item_count
            && restarted.used_tokens == maintained.used_tokens,
        || {
            format!(
                "the engine held {} items and {} tokens before the restart and reported \
                 {} items and {} tokens after it",
                maintained.item_count,
                maintained.used_tokens,
                restarted.item_count,
                restarted.used_tokens
            )
        },
    );
    recorder.check(
        SpiRequirement::BootstrapEchoesBudget,
        restarted.token_budget == tight_budget,
        || {
            format!(
                "the restart bootstrap was handed a {tight_budget} budget and reported {}",
                restarted.token_budget
            )
        },
    );
    check_pressure(&mut recorder, &restarted, "the restart bootstrap");

    // Phase 7: shed exactly the surplus.
    let reclaim = restarted.used_tokens.saturating_sub(tight_budget);
    let compaction = match engine
        .compact(compaction_request(&session_id, reclaim, 400))
        .await
    {
        Ok(report) => report,
        Err(error) => {
            recorder.check(SpiRequirement::CompactAccountsForRemovals, false, || {
                format!("compaction failed with `{error}`")
            });
            return recorder.into_report();
        }
    };
    recorder.check(
        SpiRequirement::CompactAccountsForRemovals,
        restarted.item_count.checked_sub(compaction.removed_items)
            == Some(compaction.state.item_count),
        || {
            format!(
                "the engine held {} items, reported {} removed, and now reports {}",
                restarted.item_count, compaction.removed_items, compaction.state.item_count
            )
        },
    );
    recorder.check(
        SpiRequirement::CompactReclaimsRequestedTokens,
        reclaim > 0 && compaction.reclaimed_tokens >= reclaim,
        || {
            if reclaim == 0 {
                format!(
                    "the engine reported {} used against a {tight_budget} budget, \
                     leaving no surplus for compaction to free",
                    restarted.used_tokens
                )
            } else {
                format!(
                    "compaction was asked for {reclaim} tokens and freed {}",
                    compaction.reclaimed_tokens
                )
            }
        },
    );
    recorder.check(
        SpiRequirement::CompactReportsFreedTokens,
        restarted
            .used_tokens
            .checked_sub(compaction.state.used_tokens)
            == Some(compaction.reclaimed_tokens),
        || {
            format!(
                "usage went from {} to {} while compaction claimed to free {}",
                restarted.used_tokens, compaction.state.used_tokens, compaction.reclaimed_tokens
            )
        },
    );
    recorder.check(
        SpiRequirement::CompactAccumulatesRemovedItems,
        restarted
            .compacted_items
            .checked_add(compaction.removed_items)
            == Some(compaction.state.compacted_items),
        || {
            format!(
                "the running compacted tally went from {} to {} after removing {} items",
                restarted.compacted_items,
                compaction.state.compacted_items,
                compaction.removed_items
            )
        },
    );
    check_pressure(&mut recorder, &compaction.state, "compaction");

    match engine.assemble(assembly_request(&session_id, 3)).await {
        Ok(assembled) => {
            let lost = missing_markers(&assembled.messages, &pinned_markers());
            recorder.check(
                SpiRequirement::CompactPreservesPinnedItems,
                lost.is_empty(),
                || format!("compaction discarded the pinned content {lost:?}"),
            );
        }
        Err(error) => recorder.check(SpiRequirement::CompactPreservesPinnedItems, false, || {
            format!("the prompt could not be assembled after compaction: `{error}`")
        }),
    }

    // Phase 8: reopening the session starts over.
    let reopened = match engine
        .bootstrap(bootstrap_request(
            &session_id,
            BootstrapReason::NewSession,
            CONFORMANCE_TOKEN_BUDGET,
            500,
        ))
        .await
    {
        Ok(state) => state,
        Err(error) => {
            recorder.check(
                SpiRequirement::NewSessionBootstrapStartsEmpty,
                false,
                || format!("reopening the session failed with `{error}`"),
            );
            return recorder.into_report();
        }
    };
    recorder.check(
        SpiRequirement::NewSessionBootstrapStartsEmpty,
        reopened.item_count == 0 && reopened.used_tokens == 0 && reopened.compacted_items == 0,
        || {
            format!(
                "reopening the session reported {} items, {} used tokens \
                 and {} compacted items",
                reopened.item_count, reopened.used_tokens, reopened.compacted_items
            )
        },
    );
    recorder.check(
        SpiRequirement::BootstrapEchoesBudget,
        reopened.token_budget == CONFORMANCE_TOKEN_BUDGET,
        || {
            format!(
                "reopening the session was handed a {CONFORMANCE_TOKEN_BUDGET} budget \
                 and reported {}",
                reopened.token_budget
            )
        },
    );
    check_pressure(&mut recorder, &reopened, "reopening the session");

    recorder.into_report()
}

#[cfg(test)]
mod tests {
    use claw_application::ports::provider::PromptMessage;

    use super::{
        PINNED_PROBE_ITEM_COUNT, PROBE_ITEM_COUNT, missing_markers, pinned_markers, probe_items,
        probe_markers,
    };
    use crate::context_engine::reference::is_pinned;

    #[test]
    fn the_probe_corpus_matches_its_declared_shape() {
        let items = probe_items();

        assert_eq!(
            u32::try_from(items.len()).expect("the probe corpus is a handful of items"),
            PROBE_ITEM_COUNT
        );
        let pinned = items.iter().filter(|item| is_pinned(item)).count();
        assert_eq!(
            u32::try_from(pinned).expect("the pinned probe items are a handful of items"),
            PINNED_PROBE_ITEM_COUNT
        );
        // The pinned items lead, so the usage reported after the first two ingests is exactly
        // the usage the corpus can be compacted down to without dropping pinned content.
        assert!(items.iter().take(2).all(is_pinned));
        assert!(!items.iter().skip(2).any(is_pinned));
    }

    #[test]
    fn every_probe_marker_is_distinct_and_none_contains_another() {
        let markers = probe_markers();

        for (index, marker) in markers.iter().enumerate() {
            for (other_index, other) in markers.iter().enumerate() {
                if index != other_index {
                    assert!(
                        !marker.contains(other),
                        "marker `{marker}` contains `{other}`, so substring matching \
                         could not tell them apart"
                    );
                }
            }
        }
        for pinned in pinned_markers() {
            assert!(markers.contains(&pinned));
        }
    }

    #[test]
    fn markers_are_located_across_every_prompt_message_shape() {
        let messages = vec![
            PromptMessage::System {
                text: "spi-marker-pinned-note here".to_owned(),
            },
            PromptMessage::User {
                text: "spi-marker-user-input here".to_owned(),
            },
            PromptMessage::Assistant {
                text: "spi-marker-assistant-message here".to_owned(),
                tool_calls: Vec::new(),
            },
        ];

        assert_eq!(
            missing_markers(
                &messages,
                &["spi-marker-user-input", "spi-marker-assistant-message"]
            ),
            Vec::<&str>::new()
        );
        assert_eq!(
            missing_markers(&messages, &["spi-marker-tool-output"]),
            vec!["spi-marker-tool-output"]
        );
    }
}

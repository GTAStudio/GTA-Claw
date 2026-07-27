//! Compaction acceptance: shedding context never sheds the goal.
//!
//! Two things get compacted in a long session, and a durable goal has to survive both. The
//! context engine throws conversation away to fit a token budget, and the goal's own progress
//! history is folded into a summary to fit its entry budget. A goal that only survived the first
//! would quietly lose the record of what was done toward it; a goal that only survived the second
//! would vanish from the prompt the model actually reads.

use claw_application::model::goal::GoalStatus;
use claw_application::ports::context::ContextItem;
use claw_goals::testing::{TempRoot, block_on, open_durable, open_durable_with, session_id};
use claw_goals::{AnchoredContext, GoalAnchor, GoalBudget};
use claw_runtime::GoalConfig;

fn message(text: &str) -> ContextItem {
    ContextItem::AssistantMessage {
        text: text.to_owned(),
    }
}

#[test]
fn compacting_every_message_away_leaves_the_goal_statement_standing() {
    let root = TempRoot::new("compaction-anchor");
    let session = session_id("compaction");
    let durable = open_durable(root.path(), 1_000);
    let goal = block_on(durable.service.start(&session, "keep the anchor")).expect("set");

    let mut context = AnchoredContext::new(GoalAnchor::from_record(&goal));
    for index in 0..64 {
        context.ingest(message(&format!("message {index}")));
    }
    let outcome = context.compact(0);

    assert_eq!(outcome.removed_items, 64);
    assert_eq!(outcome.retained_items, 0);
    assert!(outcome.anchor_retained);
    assert_eq!(
        context.assemble(),
        vec![ContextItem::GoalStatement {
            objective: "keep the anchor".to_owned(),
        }]
    );
}

#[test]
fn the_anchor_a_restart_rebuilds_comes_from_the_persisted_goal() {
    let root = TempRoot::new("compaction-restart");
    let session = session_id("compaction-restart");

    {
        let durable = open_durable(root.path(), 1_000);
        let goal = block_on(durable.service.start(&session, "survive the restart")).expect("set");
        block_on(
            durable
                .service
                .record_progress(&goal.goal_id, "did a thing"),
        )
        .expect("progress");
    }

    let durable = open_durable(root.path(), 100_000);
    let recovered = block_on(durable.service.active(&session))
        .expect("the store answers")
        .expect("present");
    let anchor = GoalAnchor::from_record(&recovered).expect("an active goal anchors");

    let mut context = AnchoredContext::new(Some(anchor.clone()));
    context.ingest(message("post-restart chatter"));
    context.compact(0);

    assert_eq!(anchor.revision(), recovered.revision);
    assert_eq!(anchor.revision(), 2);
    assert_eq!(anchor.goal_id(), &recovered.goal_id);
    assert_eq!(
        context.assemble(),
        vec![ContextItem::GoalStatement {
            objective: "survive the restart".to_owned(),
        }]
    );
}

#[test]
fn progress_history_folds_into_a_summary_that_is_itself_durable() {
    let root = TempRoot::new("compaction-progress");
    let session = session_id("progress");
    let goals = GoalConfig {
        max_progress_entries: 4,
        ..GoalConfig::default()
    };

    {
        let durable = open_durable_with(root.path(), 1_000, goals, GoalBudget::default());
        let goal = block_on(durable.service.start(&session, "record ten steps")).expect("set");
        for index in 0..10 {
            block_on(
                durable
                    .service
                    .record_progress(&goal.goal_id, &format!("step {index}")),
            )
            .expect("progress");
        }
    }

    let durable = open_durable_with(root.path(), 100_000, goals, GoalBudget::default());
    let recovered = block_on(durable.service.active(&session))
        .expect("the store answers")
        .expect("present");

    assert_eq!(recovered.progress.len(), 4);
    assert!(
        recovered.progress[0].compacted,
        "the oldest surviving entry must be the summary"
    );
    assert_eq!(recovered.compacted_entries, 7);
    assert_eq!(recovered.progress[0].note, "compacted 7 earlier entries");
    assert_eq!(
        recovered
            .progress
            .iter()
            .skip(1)
            .map(|entry| entry.note.as_str())
            .collect::<Vec<_>>(),
        vec!["step 7", "step 8", "step 9"]
    );
    assert!(
        recovered
            .progress
            .windows(2)
            .all(|pair| pair[0].index < pair[1].index),
        "compaction must not disturb the monotonic index"
    );
}

#[test]
fn folding_progress_bounds_what_one_goal_costs_on_disk() {
    let root = TempRoot::new("compaction-bytes");
    let session = session_id("bytes");
    let goals = GoalConfig {
        max_progress_entries: 4,
        ..GoalConfig::default()
    };
    let durable = open_durable_with(root.path(), 1_000, goals, GoalBudget::default());
    let goal = block_on(durable.service.start(&session, "stay small")).expect("set");

    for index in 0..8 {
        block_on(
            durable
                .service
                .record_progress(&goal.goal_id, &format!("step {index}")),
        )
        .expect("progress");
    }
    let after_eight = durable.store.usage(&session).expect("usage").bytes;

    for index in 8..64 {
        block_on(
            durable
                .service
                .record_progress(&goal.goal_id, &format!("step {index}")),
        )
        .expect("progress");
    }
    let after_sixty_four = durable.store.usage(&session).expect("usage").bytes;

    // The summary note and the timestamps grow by a few digits as the count rises; the history
    // itself does not. Fifty-six unbounded notes would have cost thousands of bytes.
    assert!(
        after_sixty_four < after_eight + 128,
        "fifty-six more notes grew the record from {after_eight} to {after_sixty_four} bytes"
    );
}

#[test]
fn a_closed_goal_stops_anchoring_the_context_after_a_restart() {
    let root = TempRoot::new("compaction-closed");
    let session = session_id("closed");

    {
        let durable = open_durable(root.path(), 1_000);
        let goal =
            block_on(durable.service.start(&session, "finish and stop steering")).expect("set");
        block_on(durable.service.close(&goal.goal_id, GoalStatus::Achieved)).expect("close");
    }

    let durable = open_durable(root.path(), 100_000);
    let history = block_on(durable.service.history(&session)).expect("the store answers");
    let anchor = GoalAnchor::from_record(&history[0]);

    assert_eq!(history[0].status, GoalStatus::Achieved);
    assert!(anchor.is_none(), "an achieved goal must stop steering");

    let mut context = AnchoredContext::new(anchor);
    context.ingest(message("chatter"));
    let outcome = context.compact(0);

    assert!(!outcome.anchor_retained);
    assert!(context.assemble().is_empty());
}

#[test]
fn restating_a_durable_goal_never_turns_it_into_something_compaction_can_drop() {
    let root = TempRoot::new("compaction-restate");
    let session = session_id("restate");
    let durable = open_durable(root.path(), 1_000);
    let goal = block_on(durable.service.start(&session, "the original wording")).expect("set");

    let mut context = AnchoredContext::new(GoalAnchor::from_record(&goal));
    context.ingest(message("chatter"));
    context.ingest(ContextItem::GoalStatement {
        objective: "the restated wording".to_owned(),
    });

    assert_eq!(
        context.item_count(),
        1,
        "a restatement must not join the droppable items"
    );
    context.compact(0);
    assert_eq!(
        context.assemble(),
        vec![ContextItem::GoalStatement {
            objective: "the restated wording".to_owned(),
        }]
    );

    // Restating is a prompt-shaping decision, not a goal mutation: the durable objective is
    // whatever was persisted, and only a goal command or the goal tool can change it.
    let persisted = block_on(durable.service.active(&session))
        .expect("the store answers")
        .expect("present");
    assert_eq!(persisted.objective, "the original wording");
    assert_eq!(persisted.revision, 1);
}

#[test]
fn a_superseded_goal_stops_anchoring_and_the_replacement_takes_over() {
    let root = TempRoot::new("compaction-supersede");
    let session = session_id("supersede");

    {
        let durable = open_durable(root.path(), 1_000);
        block_on(durable.service.start(&session, "the first objective")).expect("set");
        block_on(durable.service.start(&session, "the second objective")).expect("set");
    }

    let durable = open_durable(root.path(), 100_000);
    let history = block_on(durable.service.history(&session)).expect("the store answers");

    assert!(
        GoalAnchor::from_record(&history[0]).is_none(),
        "a superseded goal must not keep steering"
    );
    let anchor = GoalAnchor::from_record(&history[1]).expect("the replacement steers");
    let mut context = AnchoredContext::new(Some(anchor));
    context.ingest(message("chatter"));
    context.compact(0);

    assert_eq!(
        context.assemble(),
        vec![ContextItem::GoalStatement {
            objective: "the second objective".to_owned(),
        }]
    );
}

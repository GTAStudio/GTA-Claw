//! Store maintenance preserves goal identity while reclaiming closed-history payloads.

use claw_application::model::goal::GoalStatus;
use claw_goals::testing::{TempRoot, block_on, open_durable, session_id};

#[test]
fn closed_history_compaction_reclaims_bytes_without_reusing_goal_ids() {
    let root = TempRoot::new("closed-history-compaction");
    let session = session_id("maintenance");
    let durable = open_durable(root.path(), 1_000);

    let first = block_on(durable.service.start(&session, "first objective")).expect("set");
    for index in 0..8 {
        block_on(
            durable
                .service
                .record_progress(&first.goal_id, &format!("completed step {index}")),
        )
        .expect("progress");
    }
    block_on(durable.service.close(&first.goal_id, GoalStatus::Achieved)).expect("close");
    let second = block_on(durable.service.start(&session, "second objective")).expect("set");
    let second_revision = second.revision;
    let before = durable.store.usage(&session).expect("usage");

    let summary = durable
        .store
        .compact_closed_history(&session, 2)
        .expect("compacted");
    let after = durable.store.usage(&session).expect("usage");
    let history = block_on(durable.service.history(&session)).expect("history");

    assert_eq!(summary.closed_goals_examined, 1);
    assert_eq!(summary.goals_rewritten, 1);
    assert_eq!(summary.progress_entries_removed, 6);
    assert_eq!(summary.goal_ids_preserved, 2);
    assert!(summary.reclaimed_bytes > 0);
    assert_eq!(before.goals, after.goals);
    assert!(after.bytes < before.bytes);
    assert_eq!(history.len(), 2);
    assert_eq!(history[0].objective, "first objective");
    assert_eq!(history[0].status, GoalStatus::Achieved);
    assert_eq!(
        history[0]
            .progress
            .iter()
            .map(|entry| entry.note.as_str())
            .collect::<Vec<_>>(),
        vec!["completed step 6", "completed step 7"]
    );
    assert_eq!(history[0].compacted_entries, 6);
    assert_eq!(history[1].goal_id, second.goal_id);
    assert_eq!(history[1].revision, second_revision);

    let third = block_on(durable.service.start(&session, "third objective")).expect("set");
    assert_eq!(third.goal_id.as_str(), "maintenance:goal-3");

    drop(durable);
    let reopened = open_durable(root.path(), 100_000);
    let history = block_on(reopened.service.history(&session)).expect("history");
    assert_eq!(history.len(), 3);
    assert_eq!(history[0].compacted_entries, 6);
    assert_eq!(history[2].goal_id, third.goal_id);
}

#[test]
fn closed_history_compaction_reports_a_noop_deterministically() {
    let root = TempRoot::new("closed-history-noop");
    let session = session_id("maintenance-noop");
    let durable = open_durable(root.path(), 1_000);
    let goal = block_on(durable.service.start(&session, "already small")).expect("set");
    block_on(durable.service.close(&goal.goal_id, GoalStatus::Abandoned)).expect("close");

    let summary = durable
        .store
        .compact_closed_history(&session, 0)
        .expect("first compaction");
    assert!(summary.is_noop(), "the goal had no progress payload");
    assert_eq!(summary.closed_goals_examined, 1);
    assert_eq!(summary.goal_ids_preserved, 1);
}

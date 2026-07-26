//! Durable goal tests, including restart resumption and progress compaction.

mod support;

use std::sync::Arc;
use std::time::Duration;

use claw_application::model::goal::{GoalProgress, GoalStatus};
use claw_application::model::ids::MAX_IDENTIFIER_BYTES;
use claw_application::model::time::Timestamp;
use claw_runtime::goal::{GoalConfig, GoalError, GoalService};
use claw_runtime::goal_tool::GoalAction;

use support::{FakeClock, MemoryGoals, goal_id, session};

fn service(store: &Arc<MemoryGoals>, clock: &Arc<FakeClock>, config: GoalConfig) -> GoalService {
    GoalService::new(
        Arc::clone(store) as Arc<_>,
        Arc::clone(clock) as Arc<_>,
        config,
    )
}

#[tokio::test]
async fn a_goal_survives_a_restart_with_its_progress_and_revision() {
    let store = MemoryGoals::new();
    let clock = FakeClock::new(1_000);
    let before_restart = service(&store, &clock, GoalConfig::default());
    let session_id = session("durable");

    let created = before_restart
        .set(&session_id, goal_id("goal-1"), "  ship the runtime  ")
        .await
        .expect("the goal is accepted");
    assert_eq!(created.objective, "ship the runtime");
    assert_eq!(created.revision, 1);
    assert_eq!(created.created_at, Timestamp::from_millis(1_000));

    clock.advance(Duration::from_secs(1));
    before_restart
        .record_progress(&goal_id("goal-1"), "wrote the state machine")
        .await
        .expect("progress is accepted");
    clock.advance(Duration::from_secs(1));
    before_restart
        .record_progress(&goal_id("goal-1"), "wrote the stream assembler")
        .await
        .expect("progress is accepted");

    // A restart: a brand new service over the same store, with no shared in-memory state.
    let after_restart = service(&store, &clock, GoalConfig::default());
    let resumed = after_restart
        .active(&session_id)
        .await
        .expect("the store answers")
        .expect("the goal survived the restart");

    assert_eq!(resumed.goal_id, goal_id("goal-1"));
    assert_eq!(resumed.objective, "ship the runtime");
    assert_eq!(resumed.status, GoalStatus::Active);
    assert_eq!(resumed.revision, 3);
    assert_eq!(resumed.compacted_entries, 0);
    assert_eq!(
        resumed.progress,
        vec![
            GoalProgress {
                index: 0,
                note: "wrote the state machine".to_owned(),
                recorded_at: Timestamp::from_millis(2_000),
                compacted: false,
            },
            GoalProgress {
                index: 1,
                note: "wrote the stream assembler".to_owned(),
                recorded_at: Timestamp::from_millis(3_000),
                compacted: false,
            },
        ]
    );

    clock.advance(Duration::from_secs(1));
    let closed = after_restart
        .close(&goal_id("goal-1"), GoalStatus::Achieved)
        .await
        .expect("the goal closes");
    assert_eq!(closed.status, GoalStatus::Achieved);
    assert_eq!(closed.closed_at, Some(Timestamp::from_millis(4_000)));
    assert_eq!(closed.revision, 4);
    assert_eq!(
        after_restart
            .active(&session_id)
            .await
            .expect("the store answers"),
        None
    );
}

#[tokio::test]
async fn the_progress_budget_folds_the_oldest_entries_into_one_summary() {
    let store = MemoryGoals::new();
    let clock = FakeClock::new(0);
    let goals = service(
        &store,
        &clock,
        GoalConfig {
            max_progress_entries: 3,
            ..GoalConfig::default()
        },
    );
    let session_id = session("budget");
    goals
        .set(&session_id, goal_id("goal-1"), "keep notes")
        .await
        .expect("the goal is accepted");

    for step in 0..4_u32 {
        clock.advance(Duration::from_secs(1));
        goals
            .record_progress(&goal_id("goal-1"), &format!("step {step}"))
            .await
            .expect("progress is accepted");
    }

    let folded = goals
        .active(&session_id)
        .await
        .expect("the store answers")
        .expect("the goal is active");
    assert_eq!(folded.compacted_entries, 2);
    assert_eq!(
        folded.progress,
        vec![
            GoalProgress {
                index: 0,
                note: "compacted 2 earlier entries".to_owned(),
                recorded_at: Timestamp::from_millis(4_000),
                compacted: true,
            },
            GoalProgress {
                index: 2,
                note: "step 2".to_owned(),
                recorded_at: Timestamp::from_millis(3_000),
                compacted: false,
            },
            GoalProgress {
                index: 3,
                note: "step 3".to_owned(),
                recorded_at: Timestamp::from_millis(4_000),
                compacted: false,
            },
        ]
    );

    clock.advance(Duration::from_secs(1));
    goals
        .record_progress(&goal_id("goal-1"), "step 4")
        .await
        .expect("progress is accepted");
    let again = goals
        .active(&session_id)
        .await
        .expect("the store answers")
        .expect("the goal is active");

    assert_eq!(again.compacted_entries, 3);
    assert_eq!(
        again
            .progress
            .iter()
            .map(|entry| (entry.index, entry.note.clone(), entry.compacted))
            .collect::<Vec<(u64, String, bool)>>(),
        vec![
            (0, "compacted 3 earlier entries".to_owned(), true),
            (3, "step 3".to_owned(), false),
            (4, "step 4".to_owned(), false),
        ]
    );
}

#[tokio::test]
async fn a_new_goal_supersedes_the_previous_one() {
    let store = MemoryGoals::new();
    let clock = FakeClock::new(0);
    let goals = service(&store, &clock, GoalConfig::default());
    let session_id = session("supersede");

    goals
        .set(&session_id, goal_id("goal-1"), "first")
        .await
        .expect("the goal is accepted");
    clock.advance(Duration::from_secs(2));
    let second = goals
        .set(&session_id, goal_id("goal-2"), "second")
        .await
        .expect("the goal is accepted");

    let history = goals.history(&session_id).await.expect("the store answers");
    assert_eq!(
        history
            .iter()
            .map(|record| (record.goal_id.clone(), record.status, record.revision))
            .collect::<Vec<_>>(),
        vec![
            (goal_id("goal-1"), GoalStatus::Superseded, 2),
            (goal_id("goal-2"), GoalStatus::Active, 1),
        ]
    );
    assert_eq!(history[0].closed_at, Some(Timestamp::from_millis(2_000)));
    assert_eq!(
        goals
            .active(&session_id)
            .await
            .expect("the store answers")
            .map(|record| record.goal_id),
        Some(second.goal_id)
    );
}

#[tokio::test]
async fn a_closed_goal_refuses_further_progress() {
    let store = MemoryGoals::new();
    let clock = FakeClock::new(0);
    let goals = service(&store, &clock, GoalConfig::default());
    let session_id = session("closed");

    goals
        .set(&session_id, goal_id("goal-1"), "finish")
        .await
        .expect("the goal is accepted");
    goals
        .close(&goal_id("goal-1"), GoalStatus::Abandoned)
        .await
        .expect("the goal closes");

    let error = goals
        .record_progress(&goal_id("goal-1"), "too late")
        .await
        .expect_err("a closed goal refuses progress");
    assert_eq!(
        error,
        GoalError::AlreadyClosed {
            goal_id: goal_id("goal-1"),
            status: GoalStatus::Abandoned,
        }
    );

    let reclose = goals
        .close(&goal_id("goal-1"), GoalStatus::Achieved)
        .await
        .expect_err("a closed goal cannot be closed twice");
    assert_eq!(
        reclose,
        GoalError::AlreadyClosed {
            goal_id: goal_id("goal-1"),
            status: GoalStatus::Abandoned,
        }
    );
}

#[tokio::test]
async fn goal_input_is_validated_before_it_reaches_the_store() {
    let store = MemoryGoals::new();
    let clock = FakeClock::new(0);
    let goals = service(
        &store,
        &clock,
        GoalConfig {
            max_objective_bytes: 8,
            max_note_bytes: 4,
            ..GoalConfig::default()
        },
    );
    let session_id = session("validate");

    assert_eq!(
        goals
            .set(&session_id, goal_id("goal-1"), "   ")
            .await
            .expect_err("a blank objective is refused"),
        GoalError::InvalidObjective("must not be empty")
    );
    assert_eq!(
        goals
            .set(&session_id, goal_id("goal-1"), "far too long an objective")
            .await
            .expect_err("an oversized objective is refused"),
        GoalError::InvalidObjective("is too long")
    );
    assert_eq!(store.saves(), 0, "nothing reached the store");

    goals
        .set(&session_id, goal_id("goal-1"), "short")
        .await
        .expect("the goal is accepted");
    assert_eq!(
        goals
            .record_progress(&goal_id("goal-1"), "much too long")
            .await
            .expect_err("an oversized note is refused"),
        GoalError::InvalidNote("is too long")
    );
    assert_eq!(store.saves(), 1, "only the accepted goal was written");
}

#[tokio::test]
async fn unknown_goals_and_non_terminal_closes_are_refused() {
    let store = MemoryGoals::new();
    let clock = FakeClock::new(0);
    let goals = service(&store, &clock, GoalConfig::default());

    assert_eq!(
        goals
            .record_progress(&goal_id("missing"), "note")
            .await
            .expect_err("an unknown goal is refused"),
        GoalError::Unknown(goal_id("missing"))
    );
    assert_eq!(
        goals
            .close(&goal_id("missing"), GoalStatus::Active)
            .await
            .expect_err("active is not a terminal status"),
        GoalError::NotATerminalStatus(GoalStatus::Active)
    );
}

#[tokio::test]
async fn a_zero_entry_budget_is_rejected_rather_than_silently_dropping_history() {
    let store = MemoryGoals::new();
    let clock = FakeClock::new(0);
    let goals = service(
        &store,
        &clock,
        GoalConfig {
            max_progress_entries: 0,
            ..GoalConfig::default()
        },
    );

    assert_eq!(
        goals
            .set(&session("budget"), goal_id("goal-1"), "anything")
            .await
            .expect_err("a zero budget is refused"),
        GoalError::InvalidBudget
    );
}

#[tokio::test]
async fn start_mints_sequential_identifiers_that_survive_a_restart() {
    let store = MemoryGoals::new();
    let clock = FakeClock::new(0);
    let session_id = session("minting");

    let first = service(&store, &clock, GoalConfig::default())
        .start(&session_id, "first objective")
        .await
        .expect("the first goal is accepted");
    assert_eq!(first.goal_id, goal_id("minting:goal-1"));

    // A restart between the two goals: the counter comes from the store, not from memory.
    let second = service(&store, &clock, GoalConfig::default())
        .start(&session_id, "second objective")
        .await
        .expect("the second goal is accepted");
    assert_eq!(second.goal_id, goal_id("minting:goal-2"));
    assert_eq!(second.status, GoalStatus::Active);

    let after_restart = service(&store, &clock, GoalConfig::default());
    let history = after_restart
        .history(&session_id)
        .await
        .expect("the store answers");
    assert_eq!(
        history
            .iter()
            .map(|record| (record.goal_id.clone(), record.status))
            .collect::<Vec<(_, _)>>(),
        vec![
            (goal_id("minting:goal-1"), GoalStatus::Superseded),
            (goal_id("minting:goal-2"), GoalStatus::Active),
        ]
    );
    // Goals of one session never collide with goals of another.
    assert_eq!(
        after_restart
            .start(&session("other"), "unrelated")
            .await
            .expect("the goal is accepted")
            .goal_id,
        goal_id("other:goal-1")
    );
}

#[tokio::test]
async fn apply_progress_and_close_need_an_active_goal() {
    let store = MemoryGoals::new();
    let clock = FakeClock::new(0);
    let goals = service(&store, &clock, GoalConfig::default());
    let session_id = session("apply");

    assert_eq!(
        goals
            .apply(
                &session_id,
                &GoalAction::Progress {
                    note: "nothing yet".to_owned(),
                },
            )
            .await,
        Err(GoalError::NoActiveGoal)
    );
    assert_eq!(
        goals
            .apply(
                &session_id,
                &GoalAction::Close {
                    status: GoalStatus::Achieved,
                },
            )
            .await,
        Err(GoalError::NoActiveGoal)
    );
    assert_eq!(store.saves(), 0, "a refused action must not write");

    let created = goals
        .apply(
            &session_id,
            &GoalAction::Set {
                objective: "now there is one".to_owned(),
            },
        )
        .await
        .expect("set always works");
    assert_eq!(created.goal_id, goal_id("apply:goal-1"));

    let advanced = goals
        .apply(
            &session_id,
            &GoalAction::Progress {
                note: "halfway".to_owned(),
            },
        )
        .await
        .expect("progress attaches to the active goal");
    assert_eq!(advanced.revision, 2);
    assert_eq!(
        advanced
            .progress
            .iter()
            .map(|entry| entry.note.clone())
            .collect::<Vec<String>>(),
        vec!["halfway".to_owned()]
    );

    let closed = goals
        .apply(
            &session_id,
            &GoalAction::Close {
                status: GoalStatus::Failed,
            },
        )
        .await
        .expect("close terminates the active goal");
    assert_eq!(closed.status, GoalStatus::Failed);
    assert_eq!(closed.revision, 3);

    // Once closed, the session is back to having no active goal.
    assert_eq!(
        goals
            .apply(
                &session_id,
                &GoalAction::Progress {
                    note: "too late".to_owned(),
                },
            )
            .await,
        Err(GoalError::NoActiveGoal)
    );
}

#[tokio::test]
async fn apply_set_supersedes_the_previous_goal_and_resets_progress() {
    let store = MemoryGoals::new();
    let clock = FakeClock::new(0);
    let goals = service(&store, &clock, GoalConfig::default());
    let session_id = session("supersede");

    goals
        .apply(
            &session_id,
            &GoalAction::Set {
                objective: "old plan".to_owned(),
            },
        )
        .await
        .expect("the first goal is accepted");
    goals
        .apply(
            &session_id,
            &GoalAction::Progress {
                note: "work on the old plan".to_owned(),
            },
        )
        .await
        .expect("progress is accepted");

    let replacement = goals
        .apply(
            &session_id,
            &GoalAction::Set {
                objective: "new plan".to_owned(),
            },
        )
        .await
        .expect("the second goal is accepted");
    assert_eq!(replacement.goal_id, goal_id("supersede:goal-2"));
    assert_eq!(replacement.revision, 1);
    assert_eq!(replacement.progress, Vec::new());

    let history = goals.history(&session_id).await.expect("the store answers");
    assert_eq!(history.len(), 2);
    assert_eq!(history[0].status, GoalStatus::Superseded);
    assert_eq!(history[0].revision, 3);
    assert_eq!(
        history[0]
            .progress
            .iter()
            .map(|entry| entry.note.clone())
            .collect::<Vec<String>>(),
        vec!["work on the old plan".to_owned()],
        "superseding must not erase the old goal's history"
    );
}

#[tokio::test]
async fn a_session_id_too_long_to_scope_a_goal_id_is_refused_before_any_write() {
    let store = MemoryGoals::new();
    let clock = FakeClock::new(0);
    let goals = service(&store, &clock, GoalConfig::default());
    // 128 bytes is the identifier ceiling, so ":goal-1" cannot be appended to a maximal session.
    let session_id = session(&"s".repeat(MAX_IDENTIFIER_BYTES));

    let error = goals
        .start(&session_id, "anything")
        .await
        .expect_err("the scoped goal id does not fit");

    match error {
        GoalError::UnusableGoalId(inner) => {
            assert_eq!(inner.kind(), "goal id");
            assert_eq!(inner.reason(), "is too long");
        }
        other => panic!("expected an unusable goal id, got {other:?}"),
    }
    assert_eq!(store.saves(), 0, "nothing may be written after the refusal");
}

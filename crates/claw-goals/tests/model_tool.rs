//! Model-tool acceptance: what the model writes through `update_goal` is what a restart finds.
//!
//! The model's write path is deliberately not an ordinary tool adapter — the runtime serves
//! `update_goal` itself, because an adapter that could write the goal could forge goal history.
//! These tests drive that exact path, [`parse_goal_action`](claw_runtime::parse_goal_action)
//! followed by the goal service, over the durable store, using the JSON a provider would emit.

use std::sync::Arc;

use claw_application::model::goal::GoalStatus;
use claw_goals::testing::{
    ConflictOnceStore, FixedClock, TempRoot, block_on, open_durable, session_id,
};
use claw_goals::{FileGoalStore, ToolInvocationError, invoke_goal_tool};
use claw_runtime::{GoalConfig, GoalError, GoalService, GoalToolError};

#[test]
fn a_goal_the_model_set_is_recovered_after_a_restart() {
    let root = TempRoot::new("tool-set");
    let session = session_id("tool-set");

    let summary = {
        let durable = open_durable(root.path(), 1_000);
        block_on(invoke_goal_tool(
            &durable.service,
            &session,
            "{\"action\":\"set\",\"objective\":\"finish the runtime\"}",
        ))
        .expect("the model sets a goal")
        .summary()
    };

    assert_eq!(summary, "goal tool-set:goal-1 is active at revision 1");

    let durable = open_durable(root.path(), 100_000);
    let recovered = block_on(durable.service.active(&session))
        .expect("the store answers")
        .expect("the model's goal survived");
    assert_eq!(recovered.objective, "finish the runtime");
    assert_eq!(recovered.status, GoalStatus::Active);
    assert_eq!(recovered.revision, 1);
    assert!(recovered.progress.is_empty());
}

#[test]
fn the_model_tool_retries_a_conflict_without_losing_the_action() {
    let root = TempRoot::new("tool-conflict");
    let session = session_id("tool-conflict");
    let file_store = Arc::new(FileGoalStore::open(root.path()).expect("store opens"));
    let conflicting = Arc::new(ConflictOnceStore::new(file_store.clone()));
    let service = GoalService::new(
        conflicting,
        Arc::new(FixedClock::new(1_000)),
        GoalConfig::default(),
    );

    let outcome = block_on(invoke_goal_tool(
        &service,
        &session,
        "{\"action\":\"set\",\"objective\":\"keep the model action\"}",
    ))
    .expect("the bounded retry succeeds");

    assert_eq!(outcome.record.objective, "keep the model action");
    assert_eq!(file_store.accepted_writes(), 1);
}

#[test]
fn every_step_the_model_takes_is_on_disk_before_the_next_one() {
    let root = TempRoot::new("tool-steps");
    let session = session_id("tool-steps");

    {
        let durable = open_durable(root.path(), 1_000);
        for arguments in [
            "{\"action\":\"set\",\"objective\":\"land the crate\"}",
            "{\"action\":\"progress\",\"note\":\"wrote the store\"}",
            "{\"action\":\"progress\",\"note\":\"wrote the tests\"}",
        ] {
            block_on(invoke_goal_tool(&durable.service, &session, arguments))
                .expect("the model advances the goal");
        }

        // A restart in the middle of the model's work must see the work so far.
        let midway = open_durable(root.path(), 50_000);
        let seen = block_on(midway.service.active(&session))
            .expect("the store answers")
            .expect("present");
        assert_eq!(seen.progress.len(), 2);
        assert_eq!(seen.revision, 3);

        block_on(invoke_goal_tool(
            &durable.service,
            &session,
            "{\"action\":\"close\",\"status\":\"achieved\"}",
        ))
        .expect("the model closes the goal");
    }

    let durable = open_durable(root.path(), 100_000);
    let history = block_on(durable.service.history(&session)).expect("the store answers");

    assert_eq!(history.len(), 1);
    assert_eq!(history[0].status, GoalStatus::Achieved);
    assert_eq!(history[0].revision, 4);
    assert_eq!(
        history[0]
            .progress
            .iter()
            .map(|entry| entry.note.as_str())
            .collect::<Vec<_>>(),
        vec!["wrote the store", "wrote the tests"]
    );
}

#[test]
fn malformed_arguments_are_refused_without_touching_the_store() {
    let root = TempRoot::new("tool-malformed");
    let session = session_id("tool-malformed");
    let durable = open_durable(root.path(), 1_000);

    for arguments in [
        "set the goal please",
        "{\"action\":\"delete\"}",
        "{\"action\":\"set\"}",
        "{\"action\":\"progress\",\"note\":\"n\",\"index\":4}",
    ] {
        let error = block_on(invoke_goal_tool(&durable.service, &session, arguments))
            .expect_err("malformed arguments are refused");
        assert!(
            matches!(
                error,
                ToolInvocationError::Arguments(GoalToolError::MalformedArguments(_))
            ),
            "{arguments} should be refused as malformed, got {error}"
        );
    }

    assert_eq!(durable.store.accepted_writes(), 0);
    assert!(
        block_on(durable.service.active(&session))
            .expect("the store answers")
            .is_none()
    );
}

#[test]
fn closing_with_a_non_terminal_status_is_refused_before_the_store_is_reached() {
    let root = TempRoot::new("tool-non-terminal");
    let session = session_id("tool-non-terminal");
    let durable = open_durable(root.path(), 1_000);
    block_on(invoke_goal_tool(
        &durable.service,
        &session,
        "{\"action\":\"set\",\"objective\":\"stay active\"}",
    ))
    .expect("the model sets a goal");
    let writes_before = durable.store.accepted_writes();

    let error = block_on(invoke_goal_tool(
        &durable.service,
        &session,
        "{\"action\":\"close\",\"status\":\"active\"}",
    ))
    .expect_err("active does not close a goal");

    assert_eq!(
        error,
        ToolInvocationError::Arguments(GoalToolError::NotATerminalStatus(GoalStatus::Active))
    );
    assert_eq!(durable.store.accepted_writes(), writes_before);
    assert_eq!(
        block_on(durable.service.active(&session))
            .expect("the store answers")
            .expect("present")
            .status,
        GoalStatus::Active
    );
}

#[test]
fn progress_without_an_active_goal_is_reported_rather_than_invented() {
    let root = TempRoot::new("tool-no-goal");
    let session = session_id("tool-no-goal");
    let durable = open_durable(root.path(), 1_000);

    let error = block_on(invoke_goal_tool(
        &durable.service,
        &session,
        "{\"action\":\"progress\",\"note\":\"working on it\"}",
    ))
    .expect_err("there is no goal to advance");

    assert_eq!(error, ToolInvocationError::Refused(GoalError::NoActiveGoal));
    assert_eq!(error.to_string(), "the session has no active goal");
    assert_eq!(durable.store.accepted_writes(), 0);
}

#[test]
fn the_model_cannot_advance_a_goal_the_operator_already_closed() {
    let root = TempRoot::new("tool-closed");
    let session = session_id("tool-closed");

    {
        let durable = open_durable(root.path(), 1_000);
        let goal = block_on(durable.service.start(&session, "the operator objective"))
            .expect("the operator sets a goal");
        block_on(durable.service.close(&goal.goal_id, GoalStatus::Abandoned))
            .expect("the operator drops it");
    }

    // A restart is what makes this interesting: the closed status has to come back off the disk.
    let durable = open_durable(root.path(), 100_000);
    let writes_before = durable.store.accepted_writes();
    let error = block_on(invoke_goal_tool(
        &durable.service,
        &session,
        "{\"action\":\"progress\",\"note\":\"still working\"}",
    ))
    .expect_err("an abandoned goal accepts nothing");

    assert_eq!(error, ToolInvocationError::Refused(GoalError::NoActiveGoal));
    assert_eq!(durable.store.accepted_writes(), writes_before);
}

#[test]
fn a_model_goal_supersedes_an_operator_goal_and_both_are_kept() {
    let root = TempRoot::new("tool-supersede");
    let session = session_id("tool-supersede");

    {
        let durable = open_durable(root.path(), 1_000);
        block_on(durable.service.start(&session, "the operator objective")).expect("set");
        let outcome = block_on(invoke_goal_tool(
            &durable.service,
            &session,
            "{\"action\":\"set\",\"objective\":\"the model objective\"}",
        ))
        .expect("the model replaces it");
        assert_eq!(
            outcome.summary(),
            "goal tool-supersede:goal-2 is active at revision 1"
        );
    }

    let durable = open_durable(root.path(), 100_000);
    let history = block_on(durable.service.history(&session)).expect("the store answers");

    assert_eq!(history.len(), 2);
    assert_eq!(history[0].status, GoalStatus::Superseded);
    assert_eq!(history[0].objective, "the operator objective");
    assert_eq!(history[1].status, GoalStatus::Active);
    assert_eq!(history[1].objective, "the model objective");
}

#[test]
fn the_tool_reports_the_same_sentence_the_runtime_would() {
    let root = TempRoot::new("tool-summary");
    let session = session_id("tool-summary");
    let durable = open_durable(root.path(), 1_000);

    let set = block_on(invoke_goal_tool(
        &durable.service,
        &session,
        "{\"action\":\"set\",\"objective\":\"report cleanly\"}",
    ))
    .expect("set");
    let progressed = block_on(invoke_goal_tool(
        &durable.service,
        &session,
        "{\"action\":\"progress\",\"note\":\"a step\"}",
    ))
    .expect("progress");
    let closed = block_on(invoke_goal_tool(
        &durable.service,
        &session,
        "{\"action\":\"close\",\"status\":\"failed\"}",
    ))
    .expect("close");

    assert_eq!(
        set.summary(),
        "goal tool-summary:goal-1 is active at revision 1"
    );
    assert_eq!(
        progressed.summary(),
        "goal tool-summary:goal-1 is active at revision 2"
    );
    assert_eq!(
        closed.summary(),
        "goal tool-summary:goal-1 is failed at revision 3"
    );
}

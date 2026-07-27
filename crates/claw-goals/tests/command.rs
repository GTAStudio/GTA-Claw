//! Command acceptance: the operator's `/goal` surface writes a goal that outlives the process.
//!
//! The grammar under test is the frozen one in [`claw_runtime::CommandRegistry`] — these tests
//! type real command lines rather than constructing effects — and the store under it is the real
//! on-disk one. What is being proven is the seam between them: that an authorized `/goal` line
//! ends as bytes on a filesystem, and that an unauthorized or malformed one ends as nothing at
//! all.

use claw_application::model::goal::GoalStatus;
use claw_goals::testing::{TempRoot, block_on, open_durable, session_id};
use claw_goals::{GoalCommandError, GoalCommandOutcome, execute_command};
use claw_runtime::{
    CommandEffect, CommandError, CommandRegistry, GoalError, OperatorScope, ScopeSet,
};

fn registry() -> CommandRegistry {
    CommandRegistry::builtin()
}

#[test]
fn the_goal_command_records_an_objective_that_a_later_process_can_read() {
    let root = TempRoot::new("command-set");
    let session = session_id("command-set");

    {
        let durable = open_durable(root.path(), 1_000);
        let outcome = block_on(execute_command(
            &registry(),
            &durable.service,
            &session,
            ScopeSet::all(),
            "/goal ship the durable goal crate",
        ))
        .expect("the command runs");

        assert!(matches!(outcome, GoalCommandOutcome::Set(_)));
        assert_eq!(
            outcome.record().expect("a goal was set").objective,
            "ship the durable goal crate"
        );
    }

    let durable = open_durable(root.path(), 100_000);
    let shown = block_on(execute_command(
        &registry(),
        &durable.service,
        &session,
        ScopeSet::all(),
        "/goal",
    ))
    .expect("the command runs");

    assert_eq!(
        shown.record().expect("the goal survived").objective,
        "ship the durable goal crate"
    );
    assert_eq!(shown.record().expect("present").status, GoalStatus::Active);
}

#[test]
fn goal_done_and_goal_drop_close_with_the_statuses_the_frozen_grammar_assigns() {
    for (line, expected) in [
        ("/goal-done", GoalStatus::Achieved),
        ("/goal-drop", GoalStatus::Abandoned),
    ] {
        let root = TempRoot::new("command-close");
        let session = session_id("command-close");

        {
            let durable = open_durable(root.path(), 1_000);
            block_on(execute_command(
                &registry(),
                &durable.service,
                &session,
                ScopeSet::all(),
                "/goal finish the row",
            ))
            .expect("the goal is set");
            let closed = block_on(execute_command(
                &registry(),
                &durable.service,
                &session,
                ScopeSet::all(),
                line,
            ))
            .expect("the command runs");
            assert!(matches!(closed, GoalCommandOutcome::Closed(_)));
        }

        let durable = open_durable(root.path(), 100_000);
        let history = block_on(durable.service.history(&session)).expect("the store answers");

        assert_eq!(history.len(), 1, "{line} must not create a second goal");
        assert_eq!(history[0].status, expected, "{line} closes as {expected}");
        assert!(history[0].closed_at.is_some());
        assert!(
            block_on(durable.service.active(&session))
                .expect("the store answers")
                .is_none()
        );
    }
}

#[test]
fn setting_a_second_goal_supersedes_the_first_and_both_survive_a_restart() {
    let root = TempRoot::new("command-supersede");
    let session = session_id("command-supersede");

    {
        let durable = open_durable(root.path(), 1_000);
        for line in ["/goal the first objective", "/goal the second objective"] {
            block_on(execute_command(
                &registry(),
                &durable.service,
                &session,
                ScopeSet::all(),
                line,
            ))
            .expect("the command runs");
        }
    }

    let durable = open_durable(root.path(), 100_000);
    let history = block_on(durable.service.history(&session)).expect("the store answers");

    assert_eq!(
        history
            .iter()
            .map(|record| (record.objective.as_str(), record.status))
            .collect::<Vec<_>>(),
        vec![
            ("the first objective", GoalStatus::Superseded),
            ("the second objective", GoalStatus::Active),
        ]
    );
}

#[test]
fn closing_a_session_that_never_had_a_goal_reports_it_and_writes_nothing() {
    let root = TempRoot::new("command-nothing");
    let session = session_id("command-nothing");
    let durable = open_durable(root.path(), 1_000);

    let outcome = block_on(execute_command(
        &registry(),
        &durable.service,
        &session,
        ScopeSet::all(),
        "/goal-done",
    ))
    .expect("the command runs");

    assert_eq!(outcome, GoalCommandOutcome::NothingToClose);
    assert_eq!(durable.store.accepted_writes(), 0);
    assert_eq!(durable.store.usage(&session).expect("usage").goals, 0);
}

#[test]
fn a_caller_without_the_write_scope_never_reaches_the_store() {
    let root = TempRoot::new("command-scope");
    let session = session_id("command-scope");
    let durable = open_durable(root.path(), 1_000);
    let read_only = ScopeSet::all().without(OperatorScope::Write);

    let error = block_on(execute_command(
        &registry(),
        &durable.service,
        &session,
        read_only,
        "/goal a goal the caller may not set",
    ))
    .expect_err("an unauthorized command is refused");

    assert_eq!(
        error,
        GoalCommandError::Command(CommandError::Unauthorized {
            command: "goal".to_owned(),
            required: OperatorScope::Write,
        })
    );
    assert_eq!(durable.store.accepted_writes(), 0);
    assert!(
        block_on(durable.service.active(&session))
            .expect("the store answers")
            .is_none()
    );
}

#[test]
fn a_blank_objective_is_refused_and_the_previous_goal_stays_active() {
    let root = TempRoot::new("command-blank");
    let session = session_id("command-blank");
    let durable = open_durable(root.path(), 1_000);
    block_on(execute_command(
        &registry(),
        &durable.service,
        &session,
        ScopeSet::all(),
        "/goal the real objective",
    ))
    .expect("the goal is set");
    let writes_before = durable.store.accepted_writes();

    let error = block_on(execute_command(
        &registry(),
        &durable.service,
        &session,
        ScopeSet::all(),
        "/goal \"   \"",
    ))
    .expect_err("a blank objective is refused");

    assert_eq!(
        error,
        GoalCommandError::Goal(GoalError::InvalidObjective("must not be empty"))
    );
    assert_eq!(durable.store.accepted_writes(), writes_before);

    let durable = open_durable(root.path(), 100_000);
    let active = block_on(durable.service.active(&session))
        .expect("the store answers")
        .expect("the previous goal is untouched");
    assert_eq!(active.objective, "the real objective");
    assert_eq!(active.revision, 1);
}

#[test]
fn an_unknown_command_is_refused_before_the_goal_service_is_consulted() {
    let root = TempRoot::new("command-unknown");
    let session = session_id("command-unknown");
    let durable = open_durable(root.path(), 1_000);

    let error = block_on(execute_command(
        &registry(),
        &durable.service,
        &session,
        ScopeSet::all(),
        "/goal-maybe something",
    ))
    .expect_err("an unknown command is refused");

    assert_eq!(
        error,
        GoalCommandError::Command(CommandError::Unknown("goal-maybe".to_owned()))
    );
    assert_eq!(durable.store.accepted_writes(), 0);
}

#[test]
fn a_command_that_is_not_about_goals_is_refused_rather_than_silently_ignored() {
    let root = TempRoot::new("command-other");
    let session = session_id("command-other");
    let durable = open_durable(root.path(), 1_000);

    let error = block_on(execute_command(
        &registry(),
        &durable.service,
        &session,
        ScopeSet::all(),
        "/tools",
    ))
    .expect_err("a non-goal command is refused");

    assert_eq!(
        error,
        GoalCommandError::NotAGoalCommand(CommandEffect::ListTools)
    );
    assert_eq!(durable.store.accepted_writes(), 0);
}

#[test]
fn the_goal_command_keeps_the_multi_word_objective_the_operator_typed() {
    let root = TempRoot::new("command-words");
    let session = session_id("command-words");

    {
        let durable = open_durable(root.path(), 1_000);
        block_on(execute_command(
            &registry(),
            &durable.service,
            &session,
            ScopeSet::all(),
            "/goal \"land the crate\" and then close the row",
        ))
        .expect("the command runs");
    }

    let durable = open_durable(root.path(), 100_000);

    assert_eq!(
        block_on(durable.service.active(&session))
            .expect("the store answers")
            .expect("present")
            .objective,
        "land the crate and then close the row"
    );
}

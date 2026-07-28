//! Status-transition acceptance: the durable state machine, and every move it refuses.
//!
//! A goal has one open status and four terminal ones. The interesting half is the refusals: a
//! store that accepted progress on an abandoned goal, or a second close on an achieved one, would
//! let a model rewrite a decision the operator already made — and because the store is durable,
//! it would do so permanently.
//!
//! Every refusal is asserted three ways: the error the service returns, the reason the transition
//! matrix gives for the same move, and the revision left on disk afterwards.

use claw_application::model::goal::GoalStatus;
use claw_goals::testing::{TempRoot, block_on, open_durable, session_id};
use claw_goals::{GoalOperation, TransitionError, admit, legal_targets, transition};
use claw_runtime::GoalError;

#[test]
fn every_terminal_status_can_be_reached_from_active_and_survives_a_restart() {
    for status in [
        GoalStatus::Achieved,
        GoalStatus::Abandoned,
        GoalStatus::Failed,
        GoalStatus::Superseded,
    ] {
        assert!(
            legal_targets(GoalStatus::Active).contains(&status),
            "the matrix must allow active -> {status}"
        );

        let root = TempRoot::new("transition-reach");
        let session = session_id("reach");
        {
            let durable = open_durable(root.path(), 1_000);
            let goal = block_on(durable.service.start(&session, "close me")).expect("set");
            let closed =
                block_on(durable.service.close(&goal.goal_id, status)).expect("the close lands");
            assert_eq!(closed.status, status);
        }

        let durable = open_durable(root.path(), 100_000);
        let history = block_on(durable.service.history(&session)).expect("the store answers");
        assert_eq!(history[0].status, status, "{status} must survive a restart");
        assert!(
            history[0].closed_at.is_some(),
            "{status} must record when it closed"
        );
        assert!(
            block_on(durable.service.active(&session))
                .expect("the store answers")
                .is_none(),
            "{status} must stop steering the session"
        );
    }
}

#[test]
fn a_terminal_status_is_absorbing_on_disk_as_well_as_in_the_matrix() {
    let root = TempRoot::new("transition-absorbing");
    let session = session_id("absorbing");
    let durable = open_durable(root.path(), 1_000);
    let goal = block_on(durable.service.start(&session, "close me once")).expect("set");
    let closed =
        block_on(durable.service.close(&goal.goal_id, GoalStatus::Achieved)).expect("close");
    let writes_before = durable.store.accepted_writes();

    for status in GoalStatus::ALL {
        let matrix =
            transition(GoalStatus::Achieved, status).expect_err("nothing leaves a terminal status");
        assert_eq!(matrix.reason(), "the goal is already closed");

        let service = block_on(durable.service.close(&goal.goal_id, status))
            .expect_err("nothing leaves a terminal status on disk either");
        match (status.is_closed(), &service) {
            (true, GoalError::AlreadyClosed { goal_id, status }) => {
                assert_eq!(goal_id, &goal.goal_id);
                assert_eq!(*status, GoalStatus::Achieved);
            }
            (false, GoalError::NotATerminalStatus(refused)) => {
                assert_eq!(*refused, GoalStatus::Active);
            }
            _ => panic!("unexpected refusal for {status}: {service}"),
        }
    }

    assert_eq!(durable.store.accepted_writes(), writes_before);
    let persisted = block_on(durable.service.history(&session)).expect("the store answers");
    assert_eq!(persisted[0].revision, closed.revision);
    assert_eq!(persisted[0].status, GoalStatus::Achieved);
}

#[test]
fn a_closed_goal_refuses_progress_and_the_refusal_names_the_status_it_holds() {
    let root = TempRoot::new("transition-progress");
    let session = session_id("progress");

    let goal_id = {
        let durable = open_durable(root.path(), 1_000);
        let goal = block_on(durable.service.start(&session, "stop after this")).expect("set");
        block_on(durable.service.record_progress(&goal.goal_id, "one step")).expect("progress");
        block_on(durable.service.close(&goal.goal_id, GoalStatus::Failed)).expect("close");
        goal.goal_id
    };

    // The refusal has to come from what is on disk, not from a status this process remembers.
    let durable = open_durable(root.path(), 100_000);
    let error = block_on(durable.service.record_progress(&goal_id, "one more step"))
        .expect_err("a failed goal accepts no more progress");

    assert_eq!(
        error,
        GoalError::AlreadyClosed {
            goal_id,
            status: GoalStatus::Failed,
        }
    );
    assert_eq!(
        admit(GoalStatus::Failed, GoalOperation::RecordProgress),
        Err(TransitionError::AlreadyClosed {
            held: GoalStatus::Failed,
            attempted: GoalOperation::RecordProgress,
        })
    );
    assert_eq!(durable.store.accepted_writes(), 0);

    let persisted = block_on(durable.service.history(&session)).expect("the store answers");
    assert_eq!(persisted[0].progress.len(), 1);
    assert_eq!(persisted[0].revision, 3);
}

#[test]
fn closing_with_a_non_terminal_status_is_refused_by_the_service_and_the_matrix_alike() {
    let root = TempRoot::new("transition-non-terminal");
    let session = session_id("non-terminal");
    let durable = open_durable(root.path(), 1_000);
    let goal = block_on(durable.service.start(&session, "stay active")).expect("set");
    let writes_before = durable.store.accepted_writes();

    let error = block_on(durable.service.close(&goal.goal_id, GoalStatus::Active))
        .expect_err("active does not close a goal");

    assert_eq!(error, GoalError::NotATerminalStatus(GoalStatus::Active));
    assert_eq!(
        admit(GoalStatus::Active, GoalOperation::Close(GoalStatus::Active)),
        Err(TransitionError::NotATerminalStatus(GoalStatus::Active))
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
fn a_new_goal_supersedes_the_previous_one_and_the_move_is_the_one_the_matrix_names() {
    let root = TempRoot::new("transition-supersede");
    let session = session_id("supersede");

    {
        let durable = open_durable(root.path(), 1_000);
        block_on(durable.service.start(&session, "the first")).expect("set");
        block_on(durable.service.start(&session, "the second")).expect("set");
    }

    assert_eq!(
        admit(GoalStatus::Active, GoalOperation::Supersede),
        Ok(GoalStatus::Superseded)
    );

    let durable = open_durable(root.path(), 100_000);
    let history = block_on(durable.service.history(&session)).expect("the store answers");

    assert_eq!(history[0].status, GoalStatus::Superseded);
    assert!(history[0].closed_at.is_some());
    // set, then superseded: two persisted mutations.
    assert_eq!(history[0].revision, 2);
    assert_eq!(history[1].status, GoalStatus::Active);
    assert_eq!(history[1].revision, 1);
}

#[test]
fn the_matrix_and_the_durable_service_agree_on_every_move_out_of_active() {
    for status in GoalStatus::ALL {
        let matrix_allows = transition(GoalStatus::Active, status).is_ok();

        let root = TempRoot::new("transition-agreement");
        let session = session_id("agreement");
        let durable = open_durable(root.path(), 1_000);
        let goal = block_on(durable.service.start(&session, "compare me")).expect("set");
        let service_allows = block_on(durable.service.close(&goal.goal_id, status)).is_ok();

        assert_eq!(
            matrix_allows, service_allows,
            "the matrix and the durable service disagree about active -> {status}"
        );

        let persisted = block_on(durable.service.history(&session)).expect("the store answers");
        assert_eq!(
            persisted[0].status,
            if matrix_allows {
                status
            } else {
                GoalStatus::Active
            },
            "the disk must hold whatever the pair agreed on for {status}"
        );
    }
}

#[test]
fn an_unknown_goal_is_refused_rather_than_created_by_the_attempt_to_change_it() {
    let root = TempRoot::new("transition-unknown");
    let session = session_id("unknown");
    let durable = open_durable(root.path(), 1_000);
    let phantom = claw_goals::testing::goal_id("unknown:goal-9");

    let progress = block_on(durable.service.record_progress(&phantom, "a note"))
        .expect_err("an unknown goal cannot be advanced");
    let close = block_on(durable.service.close(&phantom, GoalStatus::Achieved))
        .expect_err("an unknown goal cannot be closed");

    assert_eq!(progress, GoalError::Unknown(phantom.clone()));
    assert_eq!(close, GoalError::Unknown(phantom));
    assert_eq!(durable.store.accepted_writes(), 0);
    assert_eq!(durable.store.usage(&session).expect("usage").goals, 0);
}

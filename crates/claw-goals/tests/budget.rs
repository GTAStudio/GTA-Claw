//! Budget acceptance: a durable goal store is metered, and a refused write costs nothing.
//!
//! Two independent budgets bound a session. The goal service bounds one goal's *shape* — how long
//! an objective may be, how many progress entries it keeps — and the store bounds a session's
//! *footprint* — how many goals it may hold and how many bytes they may occupy. A durable store
//! without the second is an unbounded write primitive handed to a model.
//!
//! Every refusal here is checked twice: once for the error it returns, and once for the state it
//! left behind, because a budget that refuses *after* writing has not bounded anything.

use claw_application::model::goal::GoalStatus;
use claw_application::ports::PortError;
use claw_goals::testing::{TempRoot, block_on, open_durable, open_durable_with, session_id};
use claw_goals::{BudgetUsage, GoalBudget};
use claw_runtime::{GoalConfig, GoalError};

fn tight_store_budget(max_goals: usize, max_record: usize, max_session: u64) -> GoalBudget {
    GoalBudget {
        max_goals_per_session: max_goals,
        max_record_bytes: max_record,
        max_session_bytes: max_session,
    }
}

#[test]
fn usage_is_metered_per_session_and_grows_with_the_goal() {
    let root = TempRoot::new("budget-usage");
    let first = session_id("budget-one");
    let second = session_id("budget-two");
    let durable = open_durable(root.path(), 1_000);

    assert_eq!(
        durable.store.usage(&first).expect("usage"),
        BudgetUsage::default()
    );

    let goal = block_on(durable.service.start(&first, "meter me")).expect("set");
    let after_set = durable.store.usage(&first).expect("usage");
    assert_eq!(after_set.goals, 1);
    assert!(after_set.bytes > 0);

    block_on(durable.service.record_progress(&goal.goal_id, "a step")).expect("progress");
    let after_progress = durable.store.usage(&first).expect("usage");
    assert_eq!(after_progress.goals, 1, "progress is not a new goal");
    assert!(
        after_progress.bytes > after_set.bytes,
        "progress must be charged for the bytes it added"
    );

    assert_eq!(
        durable.store.usage(&second).expect("usage"),
        BudgetUsage::default(),
        "one session's writes must not be charged to another"
    );
}

#[test]
fn a_session_at_its_goal_ceiling_refuses_another_goal_and_keeps_the_ones_it_has() {
    let root = TempRoot::new("budget-goals");
    let session = session_id("budget-goals");
    let durable = open_durable_with(
        root.path(),
        1_000,
        GoalConfig::default(),
        tight_store_budget(2, 64 * 1024, 1024 * 1024),
    );

    block_on(durable.service.start(&session, "first")).expect("set");
    block_on(durable.service.start(&session, "second")).expect("set");
    let writes_before = durable.store.accepted_writes();

    let error =
        block_on(durable.service.start(&session, "third")).expect_err("the session is full");

    let GoalError::Port(PortError::Invalid(detail)) = &error else {
        panic!("a budget refusal must be an invalid-request port error, got {error:?}");
    };
    assert!(
        detail.contains("max_goals_per_session"),
        "the refusal must name the ceiling, got {detail}"
    );
    assert!(!PortError::Invalid(detail.clone()).is_retryable());
    assert_eq!(durable.store.accepted_writes(), writes_before);
    assert_eq!(durable.store.usage(&session).expect("usage").goals, 2);

    // The refused goal never existed, so the second goal is still the one steering the session.
    let durable = open_durable_with(
        root.path(),
        100_000,
        GoalConfig::default(),
        tight_store_budget(2, 64 * 1024, 1024 * 1024),
    );
    assert_eq!(
        block_on(durable.service.active(&session))
            .expect("the store answers")
            .expect("present")
            .objective,
        "second"
    );
    assert_eq!(
        block_on(durable.service.history(&session))
            .expect("the store answers")
            .len(),
        2
    );
}

#[test]
fn a_record_larger_than_the_store_allows_is_refused_even_when_the_service_accepts_it() {
    let root = TempRoot::new("budget-record");
    let session = session_id("budget-record");
    // The service is told a long objective is fine; the store is told it is not. The store has
    // the last word, because it is the one that has to hold the bytes.
    let goals = GoalConfig {
        max_objective_bytes: 64 * 1024,
        ..GoalConfig::default()
    };
    let durable = open_durable_with(
        root.path(),
        1_000,
        goals,
        tight_store_budget(16, 512, 1024 * 1024),
    );

    let error = block_on(durable.service.start(&session, &"x".repeat(4_096)))
        .expect_err("an oversized record is refused");

    let GoalError::Port(PortError::Invalid(detail)) = &error else {
        panic!("a budget refusal must be an invalid-request port error, got {error:?}");
    };
    assert!(
        detail.contains("max_record_bytes"),
        "the refusal must name the ceiling, got {detail}"
    );
    assert_eq!(durable.store.accepted_writes(), 0);
    assert_eq!(durable.store.usage(&session).expect("usage").goals, 0);
    assert!(
        block_on(durable.service.active(&session))
            .expect("the store answers")
            .is_none()
    );
}

#[test]
fn the_session_byte_ceiling_stops_progress_from_growing_without_bound() {
    let root = TempRoot::new("budget-bytes");
    let session = session_id("budget-bytes");
    let goals = GoalConfig {
        max_progress_entries: 1_000,
        ..GoalConfig::default()
    };
    let durable = open_durable_with(
        root.path(),
        1_000,
        goals,
        tight_store_budget(16, 64 * 1024, 2_048),
    );
    let goal = block_on(durable.service.start(&session, "grow until refused")).expect("set");

    let mut accepted = 0_u32;
    let mut refusal = None;
    for index in 0..1_000 {
        match block_on(
            durable
                .service
                .record_progress(&goal.goal_id, &format!("note number {index}")),
        ) {
            Ok(_) => accepted += 1,
            Err(error) => {
                refusal = Some(error);
                break;
            }
        }
    }

    let error = refusal.expect("an unbounded history must eventually be refused");
    let GoalError::Port(PortError::Invalid(detail)) = &error else {
        panic!("a budget refusal must be an invalid-request port error, got {error:?}");
    };
    assert!(
        detail.contains("max_session_bytes"),
        "the refusal must name the ceiling, got {detail}"
    );
    assert!(accepted > 0, "the ceiling must not refuse the first note");
    assert!(
        durable.store.usage(&session).expect("usage").bytes <= 2_048,
        "the session never exceeds its ceiling"
    );

    // The refused note is not on disk, and the accepted ones are.
    let durable = open_durable_with(
        root.path(),
        500_000,
        goals,
        tight_store_budget(16, 64 * 1024, 2_048),
    );
    let recovered = block_on(durable.service.active(&session))
        .expect("the store answers")
        .expect("present");
    assert_eq!(recovered.progress.len(), accepted as usize);
    assert_eq!(recovered.status, GoalStatus::Active);
}

#[test]
fn a_goal_config_that_cannot_hold_one_entry_is_refused_rather_than_dropping_history() {
    let root = TempRoot::new("budget-zero");
    let session = session_id("budget-zero");
    let durable = open_durable_with(
        root.path(),
        1_000,
        GoalConfig {
            max_progress_entries: 0,
            ..GoalConfig::default()
        },
        GoalBudget::default(),
    );

    let error = block_on(durable.service.start(&session, "never recorded"))
        .expect_err("a zero-entry budget is incoherent");

    assert_eq!(error, GoalError::InvalidBudget);
    assert_eq!(durable.store.accepted_writes(), 0);
    assert_eq!(durable.store.usage(&session).expect("usage").goals, 0);
}

#[test]
fn an_objective_longer_than_the_service_allows_never_reaches_the_store() {
    let root = TempRoot::new("budget-objective");
    let session = session_id("budget-objective");
    let durable = open_durable(root.path(), 1_000);

    let error = block_on(durable.service.start(
        &session,
        &"x".repeat(GoalConfig::default().max_objective_bytes + 1),
    ))
    .expect_err("an oversized objective is refused");

    assert_eq!(error, GoalError::InvalidObjective("is too long"));
    assert_eq!(durable.store.accepted_writes(), 0);
}

#[test]
fn replacing_a_record_is_charged_its_new_size_and_not_its_old_one_as_well() {
    let root = TempRoot::new("budget-replace");
    let session = session_id("budget-replace");
    let goals = GoalConfig {
        max_progress_entries: 2,
        ..GoalConfig::default()
    };
    // A ceiling that a naive "add the new bytes, keep the old" accounting would blow through
    // within a handful of notes.
    let durable = open_durable_with(
        root.path(),
        1_000,
        goals,
        tight_store_budget(4, 64 * 1024, 4_096),
    );
    let goal = block_on(durable.service.start(&session, "replace me often")).expect("set");

    for index in 0..50 {
        block_on(
            durable
                .service
                .record_progress(&goal.goal_id, &format!("note {index}")),
        )
        .unwrap_or_else(|error| panic!("note {index} must fit a folded history: {error}"));
    }

    let usage = durable.store.usage(&session).expect("usage");
    assert_eq!(usage.goals, 1);
    assert!(
        usage.bytes <= 4_096,
        "a replaced record must not be charged twice, held {} bytes",
        usage.bytes
    );
    assert_eq!(durable.store.accepted_writes(), 51);
}

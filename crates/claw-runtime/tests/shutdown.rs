//! Cancellation and shutdown discipline: no leaked tasks, no wedged consumers.

mod support;

use std::sync::Arc;
use std::time::Duration;

use claw_application::model::approval::ApprovalWithdrawal;
use claw_application::model::session::SessionState;
use claw_application::ports::tool::ToolStatus;
use claw_runtime::runtime::{Runtime, RuntimeConfig, RuntimeError, RuntimePorts};
use claw_runtime::suspend::{PrepareRequest, SuspensionPhase};

use support::{
    ApprovalRecord, FakeClock, Gate, MemoryGoals, MemoryState, RecordingApprovals, RecordingTools,
    Round, ScriptedProvider, SimpleContext, ToolBehaviour, guarded_tool, readonly_tool, session,
    text_round, tool_round,
};

struct Fixture {
    runtime: Runtime,
    state: Arc<MemoryState>,
    tools: Arc<RecordingTools>,
    approvals: Arc<RecordingApprovals>,
    gate: Arc<Gate>,
}

fn fixture(rounds: Vec<Round>, config: RuntimeConfig) -> Fixture {
    let clock = FakeClock::new(0);
    let state = MemoryState::new();
    let approvals = RecordingApprovals::new();
    let gate = Gate::new();
    let tools = RecordingTools::new(
        vec![
            readonly_tool("slow"),
            readonly_tool("gate"),
            guarded_tool("write_file"),
        ],
        vec![
            ("slow", ToolBehaviour::Hang),
            ("gate", ToolBehaviour::Gated(Arc::clone(&gate))),
            (
                "write_file",
                ToolBehaviour::Succeed {
                    output: "written".to_owned(),
                    changed_workspace: true,
                },
            ),
        ],
    );
    let runtime = Runtime::new(
        RuntimePorts {
            clock: Arc::clone(&clock) as Arc<_>,
            provider: ScriptedProvider::new(rounds) as Arc<_>,
            state: Arc::clone(&state) as Arc<_>,
            tools: Arc::clone(&tools) as Arc<_>,
            approvals: Arc::clone(&approvals) as Arc<_>,
            goals: MemoryGoals::new() as Arc<_>,
            context: SimpleContext::new() as Arc<_>,
        },
        config,
    );
    Fixture {
        runtime,
        state,
        tools,
        approvals,
        gate,
    }
}

#[tokio::test]
async fn an_idle_runtime_shuts_down_with_no_tracked_tasks() {
    let fixture = fixture(Vec::new(), RuntimeConfig::default());

    assert_eq!(fixture.runtime.tracked_tasks(), 0);
    fixture.runtime.shutdown().await.expect("shutdown is clean");
    assert_eq!(fixture.runtime.tracked_tasks(), 0);
}

#[tokio::test]
async fn shutdown_joins_a_turn_that_is_blocked_in_a_tool_call() {
    let fixture = fixture(
        vec![tool_round("call-1", "slow", "{}")],
        RuntimeConfig::default(),
    );
    let session_id = session("shutdown-tool");

    let handle = fixture
        .runtime
        .submit(&session_id, "run the slow tool")
        .await
        .expect("the turn is accepted");
    support::eventually("the tool to start", || !fixture.tools.invoked().is_empty()).await;
    assert_eq!(fixture.runtime.tracked_tasks(), 1);

    fixture.runtime.shutdown().await.expect("shutdown is clean");

    assert_eq!(
        fixture.runtime.tracked_tasks(),
        0,
        "every spawned task must be joined"
    );
    let outcome = handle.join().await.expect("the turn reported an outcome");
    assert_eq!(outcome.state, SessionState::Cancelled);
    assert_eq!(outcome.tool_outcomes.len(), 1);
    assert_eq!(outcome.tool_outcomes[0].status, ToolStatus::Cancelled);
    assert_eq!(
        fixture.tools.cancelled(),
        vec![support::call_id("call-1")],
        "the adapter was told to tear the call down"
    );
    assert_eq!(
        fixture
            .state
            .history()
            .last()
            .expect("the turn persisted its states")
            .state,
        SessionState::Cancelled
    );
}

#[tokio::test]
async fn shutdown_joins_a_turn_that_is_blocked_on_an_approval() {
    let fixture = fixture(
        vec![tool_round("call-1", "write_file", "{}")],
        RuntimeConfig::default(),
    );
    let session_id = session("shutdown-approval");

    let handle = fixture
        .runtime
        .submit(&session_id, "write it")
        .await
        .expect("the turn is accepted");
    support::eventually("the approval to be outstanding", || {
        !fixture.runtime.approvals().outstanding().is_empty()
    })
    .await;

    fixture.runtime.shutdown().await.expect("shutdown is clean");

    assert_eq!(fixture.runtime.tracked_tasks(), 0);
    assert_eq!(
        fixture.runtime.approvals().outstanding(),
        Vec::new(),
        "shutdown withdraws every outstanding request"
    );
    assert!(
        fixture.approvals.records().iter().any(|record| matches!(
            record,
            ApprovalRecord::Withdrawn(_, ApprovalWithdrawal::Cancelled)
        )),
        "the operator surface was told the request went away: {:?}",
        fixture.approvals.records()
    );
    let outcome = handle.join().await.expect("the turn reported an outcome");
    assert_eq!(outcome.state, SessionState::Cancelled);
    assert_eq!(
        fixture.tools.invoked(),
        Vec::new(),
        "a withdrawn approval must not run the tool"
    );
}

#[tokio::test]
async fn shutdown_joins_a_turn_whose_event_consumer_stopped_reading() {
    let fixture = fixture(
        vec![Round::stalling(Vec::new())],
        RuntimeConfig {
            // One slot, so the very first emit after it fills blocks the turn task.
            event_capacity: 1,
            ..RuntimeConfig::default()
        },
    );
    let session_id = session("shutdown-stalled");

    // The handle is held but never polled, so the bounded channel fills and stays full.
    let handle = fixture
        .runtime
        .submit(&session_id, "stall")
        .await
        .expect("the turn is accepted");
    support::eventually("the turn to fill its event channel", || {
        fixture.state.history().len() >= 2
    })
    .await;

    fixture.runtime.shutdown().await.expect("shutdown is clean");

    assert_eq!(
        fixture.runtime.tracked_tasks(),
        0,
        "a stalled subscriber must not wedge shutdown"
    );
    drop(handle);
}

#[tokio::test]
async fn shutdown_joins_every_concurrent_turn() {
    let fixture = fixture(
        vec![
            Round::stalling(Vec::new()),
            Round::stalling(Vec::new()),
            Round::stalling(Vec::new()),
        ],
        RuntimeConfig::default(),
    );

    let mut handles = Vec::new();
    for name in ["a", "b", "c"] {
        handles.push(
            fixture
                .runtime
                .submit(&session(name), "stall")
                .await
                .expect("the turn is accepted"),
        );
    }
    support::eventually("all three turns to be in flight", || {
        fixture.runtime.suspension().status().in_flight == 3
    })
    .await;
    assert_eq!(fixture.runtime.tracked_tasks(), 3);

    fixture.runtime.shutdown().await.expect("shutdown is clean");

    assert_eq!(fixture.runtime.tracked_tasks(), 0);
    assert_eq!(fixture.runtime.suspension().status().in_flight, 0);
    for handle in handles {
        let outcome = handle.join().await.expect("the turn reported an outcome");
        assert_eq!(outcome.state, SessionState::Cancelled);
    }
}

#[tokio::test]
async fn work_submitted_after_shutdown_is_refused() {
    let fixture = fixture(vec![text_round("hi")], RuntimeConfig::default());

    fixture.runtime.shutdown().await.expect("shutdown is clean");

    assert_eq!(
        fixture
            .runtime
            .submit(&session("late"), "hello")
            .await
            .expect_err("the runtime is closed"),
        RuntimeError::ShuttingDown
    );
    assert_eq!(fixture.runtime.tracked_tasks(), 0);
    assert_eq!(fixture.state.history(), Vec::new());
}

#[tokio::test]
async fn a_second_shutdown_is_idempotent() {
    let fixture = fixture(vec![text_round("hi")], RuntimeConfig::default());
    fixture
        .runtime
        .submit(&session("twice"), "hello")
        .await
        .expect("the turn is accepted")
        .join()
        .await
        .expect("the turn finishes");

    fixture.runtime.shutdown().await.expect("shutdown is clean");
    fixture
        .runtime
        .shutdown()
        .await
        .expect("a repeat shutdown is a no-op");
    assert_eq!(fixture.runtime.tracked_tasks(), 0);
}

#[tokio::test]
async fn cancelling_one_turn_leaves_another_session_running() {
    let fixture = fixture(
        vec![
            Round::stalling(Vec::new()),
            tool_round("call-2", "gate", "{}"),
            text_round("finished"),
        ],
        RuntimeConfig::default(),
    );

    let stalled = fixture
        .runtime
        .submit(&session("stalled"), "stall")
        .await
        .expect("the turn is accepted");
    // Wait until the stalled turn has taken the first scripted round, so the second turn
    // deterministically receives the gated tool round.
    support::eventually("the stalled turn to take the first round", || {
        fixture.state.history().iter().any(|snapshot| {
            snapshot.session_id.as_str() == "stalled" && snapshot.state == SessionState::Running
        })
    })
    .await;
    let working = fixture
        .runtime
        .submit(&session("working"), "work")
        .await
        .expect("the turn is accepted");
    support::eventually("the gated tool to start", || {
        !fixture.tools.invoked().is_empty()
    })
    .await;

    stalled.cancel();
    let cancelled = stalled.join().await.expect("the turn reported an outcome");
    assert_eq!(cancelled.state, SessionState::Cancelled);
    assert_eq!(fixture.runtime.tracked_tasks(), 1);

    fixture.gate.open();
    let finished = working.join().await.expect("the turn reported an outcome");
    assert_eq!(finished.state, SessionState::Completed);
    assert_eq!(finished.rounds, 2);

    fixture.runtime.shutdown().await.expect("shutdown is clean");
    assert_eq!(fixture.runtime.tracked_tasks(), 0);
}

#[tokio::test]
async fn a_suspended_runtime_refuses_work_and_shuts_down_cleanly() {
    let fixture = fixture(vec![text_round("hi")], RuntimeConfig::default());
    let lease = claw_application::model::ids::LeaseId::new("lease-shutdown")
        .expect("the test lease id is valid");

    fixture
        .runtime
        .suspension()
        .prepare(PrepareRequest {
            lease_id: lease.clone(),
            reason: "test".to_owned(),
            drain_timeout: Duration::from_secs(1),
            lease_ttl: Duration::from_secs(600),
        })
        .await
        .expect("an idle runtime suspends");

    let refused = fixture
        .runtime
        .submit(&session("suspended"), "hello")
        .await
        .expect_err("a suspended runtime refuses new turns");
    assert_eq!(
        refused,
        RuntimeError::Quiescing(claw_runtime::suspend::WorkRefused {
            phase: SuspensionPhase::Suspended
        })
    );

    fixture
        .runtime
        .suspension()
        .resume(&lease)
        .expect("the lease resumes");
    fixture
        .runtime
        .submit(&session("suspended"), "hello")
        .await
        .expect("the runtime admits work again")
        .join()
        .await
        .expect("the turn finishes");

    fixture.runtime.shutdown().await.expect("shutdown is clean");
    assert_eq!(fixture.runtime.tracked_tasks(), 0);
}

#[tokio::test]
async fn a_refused_turn_releases_its_work_permit() {
    let fixture = fixture(vec![Round::stalling(Vec::new())], RuntimeConfig::default());
    let session_id = session("permit");

    let handle = fixture
        .runtime
        .submit(&session_id, "stall")
        .await
        .expect("the turn is accepted");
    support::eventually("the turn to be in flight", || {
        fixture.runtime.suspension().status().in_flight == 1
    })
    .await;

    // A second submit for the same session is refused; it must not leak the permit it took.
    fixture
        .runtime
        .submit(&session_id, "again")
        .await
        .expect_err("the session already has a turn in flight");
    assert_eq!(
        fixture.runtime.suspension().status().in_flight,
        1,
        "the refused submit released its permit"
    );

    handle.cancel();
    handle.join().await.expect("the turn reported an outcome");
    support::eventually("the permit to be released", || {
        fixture.runtime.suspension().status().in_flight == 0
    })
    .await;

    fixture.runtime.shutdown().await.expect("shutdown is clean");
    assert_eq!(fixture.runtime.tracked_tasks(), 0);
}

//! End-to-end tests for the model-callable goal tool.
//!
//! These drive a live [`Runtime`] with a scripted provider that emits real `update_goal` tool
//! calls, so they exercise the same path a model would: stream assembly produces the call, the
//! runtime serves it itself, and the durable goal is written through the goal store port.

mod support;

use std::sync::Arc;

use claw_application::model::goal::GoalStatus;
use claw_application::model::session::SessionState;
use claw_application::ports::tool::ToolStatus;
use claw_runtime::ScopeSet;
use claw_runtime::goal_tool::{GOAL_TOOL_NAME, goal_tool_descriptor};
use claw_runtime::runtime::{
    CommandOutcome, Runtime, RuntimeConfig, RuntimeEventKind, RuntimePorts,
};

use support::{
    FakeClock, MemoryGoals, MemoryState, RecordingApprovals, RecordingTools, Round,
    ScriptedProvider, SimpleContext, call_id, readonly_tool, session, text_round, tool_round,
};

struct Fixture {
    runtime: Runtime,
    goals: Arc<MemoryGoals>,
    provider: Arc<ScriptedProvider>,
}

fn fixture_with(rounds: Vec<Round>, config: RuntimeConfig) -> Fixture {
    let goals = MemoryGoals::new();
    let provider = ScriptedProvider::new(rounds);
    let runtime = Runtime::new(
        RuntimePorts {
            clock: FakeClock::new(0) as Arc<_>,
            provider: Arc::clone(&provider) as Arc<_>,
            state: MemoryState::new() as Arc<_>,
            tools: RecordingTools::new(vec![readonly_tool("read_file")], Vec::new()) as Arc<_>,
            approvals: RecordingApprovals::new() as Arc<_>,
            goals: Arc::clone(&goals) as Arc<_>,
            context: SimpleContext::new() as Arc<_>,
        },
        config,
    );
    Fixture {
        runtime,
        goals,
        provider,
    }
}

fn fixture(rounds: Vec<Round>) -> Fixture {
    fixture_with(rounds, RuntimeConfig::default())
}

fn goal_round(call: &str, arguments: &str) -> Round {
    tool_round(call, GOAL_TOOL_NAME, arguments)
}

#[tokio::test]
async fn the_model_can_set_the_session_goal_and_the_runtime_persists_it() {
    let fixture = fixture(vec![
        goal_round(
            "c1",
            "{\"action\":\"set\",\"objective\":\"finish the runtime\"}",
        ),
        text_round("goal recorded"),
    ]);
    let session_id = session("goal-tool");

    let handle = fixture
        .runtime
        .submit(&session_id, "make a plan")
        .await
        .expect("the turn starts");
    let outcome = handle.join().await.expect("the turn finishes");

    assert_eq!(outcome.state, SessionState::Completed);
    assert_eq!(outcome.tool_outcomes.len(), 1);
    assert_eq!(outcome.tool_outcomes[0].call_id, call_id("c1"));
    assert_eq!(outcome.tool_outcomes[0].status, ToolStatus::Ok);
    assert_eq!(
        outcome.tool_outcomes[0].output,
        "goal goal-tool:goal-1 is active at revision 1"
    );
    assert!(!outcome.tool_outcomes[0].changed_workspace);

    let stored = fixture
        .runtime
        .goals()
        .active(&session_id)
        .await
        .expect("the store answers")
        .expect("the model created a goal");
    assert_eq!(stored.objective, "finish the runtime");
    assert_eq!(stored.status, GoalStatus::Active);
    assert_eq!(stored.revision, 1);
    assert!(stored.progress.is_empty());

    fixture.runtime.shutdown().await.expect("shutdown is clean");
}

#[tokio::test]
async fn the_model_can_advance_and_close_a_goal_across_rounds() {
    let fixture = fixture(vec![
        goal_round(
            "c1",
            "{\"action\":\"set\",\"objective\":\"land the crate\"}",
        ),
        goal_round("c2", "{\"action\":\"progress\",\"note\":\"tests written\"}"),
        goal_round("c3", "{\"action\":\"close\",\"status\":\"achieved\"}"),
        text_round("done"),
    ]);
    let session_id = session("goal-tool");

    let mut handle = fixture
        .runtime
        .submit(&session_id, "work the goal")
        .await
        .expect("the turn starts");

    let mut goal_events = Vec::new();
    while let Some(event) = handle.next_event().await {
        if let RuntimeEventKind::GoalUpdated { goal } = event.kind {
            goal_events.push((goal.status, goal.revision, goal.progress.len()));
        }
    }
    let outcome = handle.join().await.expect("the turn finishes");

    assert_eq!(outcome.state, SessionState::Completed);
    assert_eq!(
        goal_events,
        vec![
            (GoalStatus::Active, 1, 0),
            (GoalStatus::Active, 2, 1),
            (GoalStatus::Achieved, 3, 1),
        ]
    );

    let statuses: Vec<ToolStatus> = outcome
        .tool_outcomes
        .iter()
        .map(|entry| entry.status)
        .collect();
    assert_eq!(
        statuses,
        vec![ToolStatus::Ok, ToolStatus::Ok, ToolStatus::Ok]
    );

    let history = fixture
        .runtime
        .goals()
        .history(&session_id)
        .await
        .expect("the store answers");
    assert_eq!(history.len(), 1);
    assert_eq!(history[0].status, GoalStatus::Achieved);
    assert_eq!(history[0].objective, "land the crate");
    assert_eq!(
        history[0]
            .progress
            .iter()
            .map(|entry| entry.note.clone())
            .collect::<Vec<String>>(),
        vec!["tests written".to_owned()]
    );
    assert_eq!(
        fixture
            .runtime
            .goals()
            .active(&session_id)
            .await
            .expect("the store answers"),
        None
    );

    fixture.runtime.shutdown().await.expect("shutdown is clean");
}

#[tokio::test]
async fn a_goal_the_model_set_survives_a_restart_of_the_whole_runtime() {
    let fixture = fixture(vec![
        goal_round(
            "c1",
            "{\"action\":\"set\",\"objective\":\"survive a restart\"}",
        ),
        goal_round("c2", "{\"action\":\"progress\",\"note\":\"first pass\"}"),
        text_round("saved"),
    ]);
    let session_id = session("goal-tool");

    fixture
        .runtime
        .submit(&session_id, "set a goal")
        .await
        .expect("the turn starts")
        .join()
        .await
        .expect("the turn finishes");
    fixture.runtime.shutdown().await.expect("shutdown is clean");

    // A restart: a brand new runtime over the same goal store and nothing else shared.
    let restarted = Runtime::new(
        RuntimePorts {
            clock: FakeClock::new(9_000) as Arc<_>,
            provider: ScriptedProvider::new(Vec::new()) as Arc<_>,
            state: MemoryState::new() as Arc<_>,
            tools: RecordingTools::new(Vec::new(), Vec::new()) as Arc<_>,
            approvals: RecordingApprovals::new() as Arc<_>,
            goals: Arc::clone(&fixture.goals) as Arc<_>,
            context: SimpleContext::new() as Arc<_>,
        },
        RuntimeConfig::default(),
    );

    let resumed = restarted
        .goals()
        .active(&session_id)
        .await
        .expect("the store answers")
        .expect("the goal survived the restart");
    assert_eq!(resumed.objective, "survive a restart");
    assert_eq!(resumed.status, GoalStatus::Active);
    assert_eq!(resumed.revision, 2);
    assert_eq!(
        resumed
            .progress
            .iter()
            .map(|entry| entry.note.clone())
            .collect::<Vec<String>>(),
        vec!["first pass".to_owned()]
    );

    // The resumed goal is also what a `/goal` command reports after the restart.
    let CommandOutcome::Goal(reported) = restarted
        .dispatch_command(&session_id, "/goal", ScopeSet::all())
        .await
        .expect("the command runs")
    else {
        panic!("expected the goal outcome");
    };
    assert_eq!(reported, Some(resumed));

    restarted.shutdown().await.expect("shutdown is clean");
}

#[tokio::test]
async fn malformed_arguments_fail_the_call_without_failing_the_turn() {
    let fixture = fixture(vec![
        goal_round("c1", "{\"action\":\"progress\"}"),
        goal_round("c2", "{\"action\":\"set\",\"objective\":\"recovered\"}"),
        text_round("recovered"),
    ]);
    let session_id = session("goal-tool");

    let outcome = fixture
        .runtime
        .submit(&session_id, "try the tool")
        .await
        .expect("the turn starts")
        .join()
        .await
        .expect("the turn finishes");

    assert_eq!(outcome.state, SessionState::Completed);
    assert_eq!(outcome.tool_outcomes.len(), 2);
    assert_eq!(outcome.tool_outcomes[0].status, ToolStatus::Failed);
    assert_eq!(
        outcome.tool_outcomes[0].output,
        "malformed update_goal arguments: missing field `note`"
    );
    assert_eq!(outcome.tool_outcomes[1].status, ToolStatus::Ok);

    // The failed call wrote nothing; only the corrected one did.
    let history = fixture
        .runtime
        .goals()
        .history(&session_id)
        .await
        .expect("the store answers");
    assert_eq!(history.len(), 1);
    assert_eq!(history[0].objective, "recovered");

    fixture.runtime.shutdown().await.expect("shutdown is clean");
}

#[tokio::test]
async fn progress_without_an_active_goal_is_reported_to_the_model() {
    let fixture = fixture(vec![
        goal_round(
            "c1",
            "{\"action\":\"progress\",\"note\":\"nothing to attach to\"}",
        ),
        text_round("noted"),
    ]);
    let session_id = session("goal-tool");

    let outcome = fixture
        .runtime
        .submit(&session_id, "report progress")
        .await
        .expect("the turn starts")
        .join()
        .await
        .expect("the turn finishes");

    assert_eq!(outcome.state, SessionState::Completed);
    assert_eq!(outcome.tool_outcomes.len(), 1);
    assert_eq!(outcome.tool_outcomes[0].status, ToolStatus::Failed);
    assert_eq!(
        outcome.tool_outcomes[0].output,
        "the session has no active goal"
    );
    assert_eq!(
        fixture
            .runtime
            .goals()
            .history(&session_id)
            .await
            .expect("the store answers"),
        Vec::new()
    );

    fixture.runtime.shutdown().await.expect("shutdown is clean");
}

#[tokio::test]
async fn the_goal_tool_is_advertised_to_the_provider_and_to_the_operator() {
    let fixture = fixture(vec![text_round("nothing to do")]);
    let session_id = session("goal-tool");

    fixture
        .runtime
        .submit(&session_id, "hello")
        .await
        .expect("the turn starts")
        .join()
        .await
        .expect("the turn finishes");

    let requests = fixture.provider.requests();
    assert_eq!(requests.len(), 1);
    assert_eq!(
        requests[0].tool_names,
        vec!["read_file".to_owned(), GOAL_TOOL_NAME.to_owned()]
    );

    let CommandOutcome::Tools(tools) = fixture
        .runtime
        .dispatch_command(&session_id, "/tools", ScopeSet::all())
        .await
        .expect("the command runs")
    else {
        panic!("expected the tool list");
    };
    assert_eq!(
        tools,
        vec![readonly_tool("read_file"), goal_tool_descriptor()]
    );

    fixture.runtime.shutdown().await.expect("shutdown is clean");
}

#[tokio::test]
async fn disabling_the_goal_tool_hides_it_and_rejects_calls_to_it() {
    let fixture = fixture_with(
        vec![
            goal_round(
                "c1",
                "{\"action\":\"set\",\"objective\":\"should not land\"}",
            ),
            text_round("refused"),
        ],
        RuntimeConfig {
            goal_tool_enabled: false,
            ..RuntimeConfig::default()
        },
    );
    let session_id = session("goal-tool");

    let outcome = fixture
        .runtime
        .submit(&session_id, "try anyway")
        .await
        .expect("the turn starts")
        .join()
        .await
        .expect("the turn finishes");

    assert_eq!(outcome.tool_outcomes.len(), 1);
    assert_eq!(outcome.tool_outcomes[0].status, ToolStatus::Failed);
    assert_eq!(outcome.tool_outcomes[0].output, "unknown tool: update_goal");
    assert_eq!(
        fixture
            .runtime
            .goals()
            .history(&session_id)
            .await
            .expect("the store answers"),
        Vec::new()
    );

    let requests = fixture.provider.requests();
    assert_eq!(requests[0].tool_names, vec!["read_file".to_owned()]);
    assert_eq!(
        fixture.runtime.tool_catalogue(),
        vec![readonly_tool("read_file")]
    );

    fixture.runtime.shutdown().await.expect("shutdown is clean");
}

#[tokio::test]
async fn a_model_goal_supersedes_an_operator_goal_and_keeps_both_in_history() {
    let fixture = fixture(vec![
        goal_round(
            "c1",
            "{\"action\":\"set\",\"objective\":\"the model plan\"}",
        ),
        text_round("replaced"),
    ]);
    let session_id = session("goal-tool");

    fixture
        .runtime
        .dispatch_command(&session_id, "/goal the operator plan", ScopeSet::all())
        .await
        .expect("the operator sets a goal");

    fixture
        .runtime
        .submit(&session_id, "take over")
        .await
        .expect("the turn starts")
        .join()
        .await
        .expect("the turn finishes");

    let history = fixture
        .runtime
        .goals()
        .history(&session_id)
        .await
        .expect("the store answers");
    assert_eq!(
        history
            .iter()
            .map(|record| (
                record.goal_id.as_str().to_owned(),
                record.objective.clone(),
                record.status
            ))
            .collect::<Vec<(String, String, GoalStatus)>>(),
        vec![
            (
                "goal-tool:goal-1".to_owned(),
                "the operator plan".to_owned(),
                GoalStatus::Superseded
            ),
            (
                "goal-tool:goal-2".to_owned(),
                "the model plan".to_owned(),
                GoalStatus::Active
            ),
        ]
    );

    fixture.runtime.shutdown().await.expect("shutdown is clean");
}

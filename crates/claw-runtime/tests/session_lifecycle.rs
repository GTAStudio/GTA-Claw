//! End-to-end turn lifecycle tests over deterministic fakes.

mod support;

use std::sync::Arc;
use std::time::Duration;

use claw_application::model::session::SessionState;
use claw_application::ports::PortError;
use claw_application::ports::context::ContextItem;
use claw_application::ports::provider::{PromptMessage, ProviderChunk};
use claw_application::ports::tool::ToolStatus;
use claw_runtime::approval::ApprovalError;
use claw_runtime::command::{CommandEffect, TurnOptions};
use claw_runtime::runtime::{
    Runtime, RuntimeConfig, RuntimeError, RuntimeEventKind, RuntimeFailureClass, RuntimePorts,
};
use claw_runtime::stream::StreamPayload;

use support::{
    FakeClock, GatedLoadState, HangingBootstrapContext, MemoryGoals, MemoryState,
    RecordingApprovals, RecordingTools, Round, ScriptedProvider, SimpleContext, ToolBehaviour,
    guarded_tool, readonly_tool, session, text_round, tool_round,
};

struct Harness {
    runtime: Runtime,
    clock: Arc<FakeClock>,
    state: Arc<MemoryState>,
    tools: Arc<RecordingTools>,
    approvals: Arc<RecordingApprovals>,
    context: Arc<SimpleContext>,
    provider: Arc<ScriptedProvider>,
}

fn harness(rounds: Vec<Round>, config: RuntimeConfig) -> Harness {
    harness_with_goals(rounds, config, &MemoryGoals::new())
}

fn harness_with_goals(
    rounds: Vec<Round>,
    config: RuntimeConfig,
    goals: &Arc<MemoryGoals>,
) -> Harness {
    let clock = FakeClock::new(1_000);
    let state = MemoryState::new();
    let approvals = RecordingApprovals::new();
    let context = SimpleContext::new();
    let provider = ScriptedProvider::new(rounds);
    let tools = RecordingTools::new(
        vec![readonly_tool("read_file"), guarded_tool("write_file")],
        vec![
            (
                "read_file",
                ToolBehaviour::Succeed {
                    output: "file contents".to_owned(),
                    changed_workspace: false,
                },
            ),
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
            provider: Arc::clone(&provider) as Arc<_>,
            state: Arc::clone(&state) as Arc<_>,
            tools: Arc::clone(&tools) as Arc<_>,
            approvals: Arc::clone(&approvals) as Arc<_>,
            goals: Arc::clone(goals) as Arc<_>,
            context: Arc::clone(&context) as Arc<_>,
        },
        config,
    );

    Harness {
        runtime,
        clock,
        state,
        tools,
        approvals,
        context,
        provider,
    }
}

#[tokio::test]
async fn committed_but_not_durable_goal_tool_failure_aborts_without_model_retry() {
    let goals = MemoryGoals::new();
    goals.refuse_saves_with(PortError::CommittedButNotDurable(
        "record committed; do not retry blindly".to_owned(),
    ));
    let harness = harness_with_goals(
        vec![
            tool_round(
                "goal-1",
                "update_goal",
                r#"{"action":"set","objective":"ship safely"}"#,
            ),
            text_round("would be an unsafe retry"),
        ],
        RuntimeConfig::default(),
        &goals,
    );
    let session_id = session("goal-durability-failure");

    let mut handle = harness
        .runtime
        .submit(&session_id, "set the goal")
        .await
        .expect("turn accepted");
    while handle.next_event().await.is_some() {}
    let error = handle
        .join()
        .await
        .expect_err("degraded durability aborts the model loop");

    assert!(matches!(
        &error,
        RuntimeError::Goal(claw_runtime::GoalError::Port(
            PortError::CommittedButNotDurable(_)
        ))
    ));
    assert_eq!(
        error.failure_class(),
        RuntimeFailureClass::CommittedButNotDurable
    );
    assert!(!error.is_retryable());
    assert_eq!(
        harness.provider.requests().len(),
        1,
        "the provider is not invited to retry the committed mutation"
    );
}

fn states(events: &[RuntimeEventKind]) -> Vec<SessionState> {
    events
        .iter()
        .filter_map(|kind| match kind {
            RuntimeEventKind::StateChanged { to, .. } => Some(*to),
            _ => None,
        })
        .collect()
}

#[tokio::test]
async fn a_text_only_turn_walks_the_contract_to_completed() {
    let harness = harness(vec![text_round("hello world")], RuntimeConfig::default());
    let session_id = session("lifecycle-text");

    let mut handle = harness
        .runtime
        .submit(&session_id, "say hello")
        .await
        .expect("the turn is accepted");

    let mut kinds = Vec::new();
    while let Some(event) = handle.next_event().await {
        assert_eq!(event.session_id.as_str(), "lifecycle-text");
        kinds.push(event.kind);
    }

    let outcome = handle.join().await.expect("the turn finishes");

    assert_eq!(
        states(&kinds),
        vec![
            SessionState::Queued,
            SessionState::Starting,
            SessionState::Running,
            SessionState::Completed,
        ]
    );
    assert_eq!(outcome.state, SessionState::Completed);
    assert_eq!(outcome.rounds, 1);
    assert_eq!(outcome.tool_outcomes, Vec::new());
    let message = outcome.message.expect("the turn produced a message");
    assert_eq!(message.text, "hello world");
    assert_eq!(message.tool_calls, Vec::new());

    let sequences: Vec<u64> = kinds
        .iter()
        .filter_map(|kind| match kind {
            RuntimeEventKind::Stream(event) => Some(event.sequence),
            _ => None,
        })
        .collect();
    assert_eq!(sequences, vec![0, 1]);

    harness.runtime.shutdown().await.expect("shutdown is clean");
    assert_eq!(harness.runtime.tracked_tasks(), 0);
}

#[tokio::test]
async fn goal_context_has_exactly_one_active_statement_across_replace_and_close() {
    let harness = harness(
        vec![
            text_round("first turn"),
            text_round("second turn"),
            text_round("third turn"),
        ],
        RuntimeConfig::default(),
    );
    let session_id = session("goal-context-lifecycle");

    let first = harness
        .runtime
        .goals()
        .start(&session_id, "first objective")
        .await
        .expect("first goal");
    let mut turn = harness
        .runtime
        .submit(&session_id, "one")
        .await
        .expect("first turn");
    while turn.next_event().await.is_some() {}
    turn.join().await.expect("first turn completes");

    harness
        .runtime
        .goals()
        .start(&session_id, "replacement objective")
        .await
        .expect("replacement goal");
    let mut turn = harness
        .runtime
        .submit(&session_id, "two")
        .await
        .expect("second turn");
    while turn.next_event().await.is_some() {}
    turn.join().await.expect("second turn completes");
    let items = harness.context.items();
    let statements: Vec<&ContextItem> = items
        .iter()
        .filter(|item| matches!(item, ContextItem::GoalStatement { .. }))
        .collect();
    assert_eq!(statements.len(), 1);
    assert_eq!(
        statements[0],
        &ContextItem::GoalStatement {
            objective: "replacement objective".to_owned()
        }
    );

    let active = harness
        .runtime
        .goals()
        .active(&session_id)
        .await
        .expect("goal store")
        .expect("active goal");
    assert_ne!(active.goal_id, first.goal_id);
    harness
        .runtime
        .goals()
        .close(
            &active.goal_id,
            claw_application::model::goal::GoalStatus::Achieved,
        )
        .await
        .expect("goal closes");
    let mut turn = harness
        .runtime
        .submit(&session_id, "three")
        .await
        .expect("third turn");
    while turn.next_event().await.is_some() {}
    turn.join().await.expect("third turn completes");
    assert!(
        harness
            .context
            .items()
            .iter()
            .all(|item| !matches!(item, ContextItem::GoalStatement { .. }))
    );
}

#[tokio::test]
async fn a_mutating_tool_turn_ends_in_completed_with_changes() {
    let harness = harness(
        vec![
            tool_round("call-1", "write_file", "{\"path\":\"a\"}"),
            text_round("done"),
        ],
        RuntimeConfig::default(),
    );
    let session_id = session("lifecycle-tool");

    let mut handle = harness
        .runtime
        .submit(&session_id, "write the file")
        .await
        .expect("the turn is accepted");

    // The write tool is guarded, so the turn parks until an operator answers.
    support::eventually("an approval to be outstanding", || {
        !harness.runtime.approvals().outstanding().is_empty()
    })
    .await;
    let outstanding = harness.runtime.approvals().outstanding();
    assert_eq!(outstanding.len(), 1);
    assert_eq!(outstanding[0].tool_name, "write_file");
    harness
        .runtime
        .approvals()
        .resolve(
            &outstanding[0].approval_id,
            claw_application::model::approval::ApprovalDecision::approve_once(),
        )
        .expect("the request is outstanding");

    let mut kinds = Vec::new();
    while let Some(event) = handle.next_event().await {
        kinds.push(event.kind);
    }
    let outcome = handle.join().await.expect("the turn finishes");

    assert_eq!(
        states(&kinds),
        vec![
            SessionState::Queued,
            SessionState::Starting,
            SessionState::Running,
            SessionState::WaitingForApproval,
            SessionState::Running,
            SessionState::CompletedWithChanges,
        ]
    );
    assert_eq!(outcome.state, SessionState::CompletedWithChanges);
    assert_eq!(outcome.rounds, 2);
    assert_eq!(outcome.tool_outcomes.len(), 1);
    assert_eq!(outcome.tool_outcomes[0].status, ToolStatus::Ok);
    assert_eq!(outcome.tool_outcomes[0].output, "written");
    assert!(outcome.tool_outcomes[0].changed_workspace);

    let invoked = harness.tools.invoked();
    assert_eq!(invoked.len(), 1);
    assert_eq!(invoked[0].name, "write_file");
    assert_eq!(invoked[0].arguments, "{\"path\":\"a\"}");
    assert_eq!(harness.tools.cancelled(), Vec::new());

    // The tool result reached the context engine, so the second round could see it.
    let items = harness.context.items();
    assert!(items.contains(&ContextItem::ToolResult {
        tool_name: "write_file".to_owned(),
        output: "written".to_owned(),
        failed: false,
    }));
    let second = &harness.provider.requests()[1];
    assert_eq!(second.round, 1);
    assert!(second.messages.contains(&PromptMessage::ToolResult {
        call_id: support::call_id("result-write_file"),
        output: "written".to_owned(),
        failed: false,
    }));

    harness.runtime.shutdown().await.expect("shutdown is clean");
}

#[tokio::test]
async fn an_unapproved_readonly_tool_runs_without_parking_the_turn() {
    let harness = harness(
        vec![
            tool_round("call-1", "read_file", "{\"path\":\"a\"}"),
            text_round("summary"),
        ],
        RuntimeConfig::default(),
    );
    let session_id = session("lifecycle-readonly");

    let mut handle = harness
        .runtime
        .submit(&session_id, "read the file")
        .await
        .expect("the turn is accepted");

    let mut kinds = Vec::new();
    while let Some(event) = handle.next_event().await {
        kinds.push(event.kind);
    }
    let outcome = handle.join().await.expect("the turn finishes");

    assert_eq!(
        states(&kinds),
        vec![
            SessionState::Queued,
            SessionState::Starting,
            SessionState::Running,
            SessionState::Completed,
        ]
    );
    assert_eq!(outcome.state, SessionState::Completed);
    assert_eq!(harness.approvals.records(), Vec::new());
    assert_eq!(outcome.tool_outcomes[0].output, "file contents");

    harness.runtime.shutdown().await.expect("shutdown is clean");
}

#[tokio::test]
async fn a_second_turn_restarts_the_context_and_advances_the_turn_id() {
    let harness = harness(
        vec![text_round("first"), text_round("second")],
        RuntimeConfig::default(),
    );
    let session_id = session("lifecycle-restart");

    let first = harness
        .runtime
        .submit(&session_id, "one")
        .await
        .expect("the first turn is accepted");
    let first_outcome = first.join().await.expect("the first turn finishes");

    let second = harness
        .runtime
        .submit(&session_id, "two")
        .await
        .expect("the second turn is accepted");
    let second_outcome = second.join().await.expect("the second turn finishes");

    assert_eq!(first_outcome.turn.ordinal(), 0);
    assert_eq!(second_outcome.turn.ordinal(), 1);
    assert_eq!(harness.context.bootstraps(), 2);

    let first_record = harness
        .state
        .turn(&session_id, first_outcome.turn)
        .expect("the first turn was persisted");
    assert_eq!(first_record.state, SessionState::Completed);
    assert_eq!(
        first_record
            .message
            .expect("the first turn stored a message")
            .text,
        "first"
    );
    assert_eq!(first_record.partial, None);

    let second_record = harness
        .state
        .turn(&session_id, second_outcome.turn)
        .expect("the second turn was persisted");
    assert_eq!(
        second_record
            .message
            .expect("the second turn stored a message")
            .text,
        "second"
    );

    let revisions: Vec<u64> = harness
        .state
        .history()
        .iter()
        .map(|snapshot| snapshot.revision)
        .collect();
    let expected: Vec<u64> =
        (1..=u64::try_from(revisions.len()).expect("the history is small")).collect();
    assert_eq!(revisions, expected);

    harness.runtime.shutdown().await.expect("shutdown is clean");
}

#[tokio::test]
async fn a_session_refuses_two_turns_at_once() {
    let harness = harness(
        vec![
            Round::stalling(vec![ProviderChunk::TextDelta {
                text: "thinking".to_owned(),
            }]),
            text_round("never reached"),
        ],
        RuntimeConfig::default(),
    );
    let session_id = session("lifecycle-busy");

    let first = harness
        .runtime
        .submit(&session_id, "one")
        .await
        .expect("the first turn is accepted");

    let refusal = harness
        .runtime
        .submit(&session_id, "two")
        .await
        .expect_err("a second turn must be refused");
    assert_eq!(
        refusal,
        claw_runtime::runtime::RuntimeError::TurnInFlight { turn: first.turn() }
    );

    first.cancel();
    let outcome = first.join().await.expect("the cancelled turn reports");
    assert_eq!(outcome.state, SessionState::Cancelled);

    harness.runtime.shutdown().await.expect("shutdown is clean");
}

#[tokio::test]
async fn cancelling_mid_stream_persists_the_recoverable_partial() {
    let harness = harness(
        vec![Round::stalling(vec![
            ProviderChunk::TextDelta {
                text: "half a thought".to_owned(),
            },
            ProviderChunk::ToolCallBegin {
                call_id: support::call_id("call-open"),
                name: "read_file".to_owned(),
            },
            ProviderChunk::ToolCallArgumentsDelta {
                call_id: support::call_id("call-open"),
                fragment: "{\"pa".to_owned(),
            },
        ])],
        RuntimeConfig::default(),
    );
    let session_id = session("lifecycle-partial");

    let mut handle = harness
        .runtime
        .submit(&session_id, "start")
        .await
        .expect("the turn is accepted");

    // Wait until the stream event for the open tool call has been observed, so the cancel lands
    // squarely in the middle of the stream rather than before it started.
    let mut seen_tool_start = false;
    while !seen_tool_start {
        let event = handle
            .next_event()
            .await
            .expect("the runtime keeps emitting until the tool call opens");
        if let RuntimeEventKind::Stream(stream) = &event.kind
            && let StreamPayload::ToolCallStarted { call_id, name } = &stream.payload
        {
            assert_eq!(call_id, &support::call_id("call-open"));
            assert_eq!(name, "read_file");
            seen_tool_start = true;
        }
    }

    handle.cancel();
    let outcome = handle.join().await.expect("the cancelled turn reports");

    assert_eq!(outcome.state, SessionState::Cancelled);
    let partial = outcome.partial.expect("a partial message was recovered");
    assert_eq!(partial.text, "half a thought");
    assert_eq!(partial.pending_tool_calls.len(), 1);
    assert_eq!(partial.pending_tool_calls[0].name, "read_file");
    assert_eq!(partial.pending_tool_calls[0].partial_arguments, "{\"pa");
    assert_eq!(partial.next_sequence, 2);

    let record = harness
        .state
        .turn(&session_id, outcome.turn)
        .expect("the cancelled turn was persisted");
    assert_eq!(record.state, SessionState::Cancelled);
    assert_eq!(
        record
            .partial
            .expect("the persisted record carries the partial")
            .text,
        "half a thought"
    );

    harness.runtime.shutdown().await.expect("shutdown is clean");
}

#[tokio::test]
async fn exhausting_the_round_budget_blocks_the_turn() {
    let harness = harness(
        vec![
            tool_round("call-1", "read_file", "{}"),
            tool_round("call-2", "read_file", "{}"),
        ],
        RuntimeConfig {
            max_rounds: 2,
            ..RuntimeConfig::default()
        },
    );
    let session_id = session("lifecycle-blocked");

    let handle = harness
        .runtime
        .submit(&session_id, "loop forever")
        .await
        .expect("the turn is accepted");
    let outcome = handle.join().await.expect("the turn finishes");

    assert_eq!(outcome.state, SessionState::Blocked);
    assert_eq!(outcome.rounds, 2);
    assert_eq!(outcome.tool_outcomes.len(), 2);

    harness.runtime.shutdown().await.expect("shutdown is clean");
}

#[tokio::test]
async fn disabling_tools_blocks_a_turn_that_asks_for_one() {
    let harness = harness(
        vec![tool_round("call-1", "read_file", "{}")],
        RuntimeConfig::default(),
    );
    let session_id = session("lifecycle-no-tools");

    let handle = harness
        .runtime
        .submit_with(
            &session_id,
            "read it",
            TurnOptions {
                tools_enabled: false,
                ..TurnOptions::default()
            },
        )
        .await
        .expect("the turn is accepted");
    let outcome = handle.join().await.expect("the turn finishes");

    assert_eq!(outcome.state, SessionState::Blocked);
    assert_eq!(harness.tools.invoked(), Vec::new());
    assert_eq!(
        harness.provider.requests()[0].tool_names,
        Vec::<String>::new()
    );

    harness.runtime.shutdown().await.expect("shutdown is clean");
}

#[tokio::test]
async fn the_clock_port_supplies_every_persisted_timestamp() {
    let harness = harness(vec![text_round("timed")], RuntimeConfig::default());
    let session_id = session("lifecycle-clock");
    harness.clock.advance(Duration::from_millis(500));

    let handle = harness
        .runtime
        .submit(&session_id, "when")
        .await
        .expect("the turn is accepted");
    let outcome = handle.join().await.expect("the turn finishes");

    let record = harness
        .state
        .turn(&session_id, outcome.turn)
        .expect("the turn was persisted");
    assert_eq!(record.updated_at.as_millis(), 1_500);
    assert!(
        harness
            .state
            .history()
            .iter()
            .all(|snapshot| snapshot.updated_at.as_millis() == 1_500)
    );

    harness.runtime.shutdown().await.expect("shutdown is clean");
}

#[tokio::test]
async fn session_capacity_evicts_the_least_recently_touched_idle_conversation() {
    let harness = harness(
        vec![text_round("a"), text_round("b"), text_round("c")],
        RuntimeConfig {
            session_capacity: 2,
            ..RuntimeConfig::default()
        },
    );
    let a = session("lru-a");
    let b = session("lru-b");
    let c = session("lru-c");

    harness
        .runtime
        .submit(&a, "a")
        .await
        .expect("a")
        .join()
        .await
        .expect("a completes");
    harness.clock.advance(Duration::from_millis(1));
    harness
        .runtime
        .submit(&b, "b")
        .await
        .expect("b")
        .join()
        .await
        .expect("b completes");
    harness
        .runtime
        .execute_effect(&b, CommandEffect::SetModel("model-b".to_owned()))
        .await
        .expect("model selection");

    harness.clock.advance(Duration::from_millis(1));
    assert_eq!(harness.runtime.selected_model(&a), None);
    harness.clock.advance(Duration::from_millis(1));
    harness
        .runtime
        .submit(&c, "c")
        .await
        .expect("c")
        .join()
        .await
        .expect("c completes");

    assert_eq!(harness.runtime.managed_session_ids(), vec![a, c]);
    assert_eq!(
        harness.runtime.selected_model(&b),
        None,
        "eviction terminally drops session-scoped model state"
    );
    harness.runtime.shutdown().await.expect("shutdown is clean");
}

#[tokio::test]
async fn idle_ttl_is_strict_and_cleanup_uses_the_fake_clock() {
    let harness = harness(
        vec![text_round("done")],
        RuntimeConfig {
            session_idle_ttl: Duration::from_secs(10),
            ..RuntimeConfig::default()
        },
    );
    let session_id = session("ttl-strict");
    harness
        .runtime
        .submit(&session_id, "run")
        .await
        .expect("turn")
        .join()
        .await
        .expect("turn completes");
    harness
        .runtime
        .execute_effect(&session_id, CommandEffect::SetModel("temporary".to_owned()))
        .await
        .expect("model selection");

    harness.clock.advance(Duration::from_secs(10));
    assert_eq!(
        harness.runtime.sweep_sessions(),
        Vec::new(),
        "the legacy TTL is strictly greater than the idle duration"
    );
    assert_eq!(
        harness.runtime.managed_session_ids(),
        vec![session_id.clone()]
    );

    harness.clock.advance(Duration::from_millis(1));
    assert_eq!(harness.runtime.sweep_sessions(), vec![session_id.clone()]);
    assert_eq!(harness.runtime.selected_model(&session_id), None);
    assert_eq!(harness.runtime.managed_session_ids(), Vec::new());
    harness.runtime.shutdown().await.expect("shutdown is clean");
}

#[tokio::test]
async fn capacity_never_evicts_an_active_conversation() {
    let harness = harness(
        vec![Round::stalling(vec![ProviderChunk::TextDelta {
            text: "busy".to_owned(),
        }])],
        RuntimeConfig {
            session_capacity: 1,
            ..RuntimeConfig::default()
        },
    );
    let active = harness
        .runtime
        .submit(&session("capacity-active"), "run")
        .await
        .expect("first conversation is admitted");
    let error = harness
        .runtime
        .submit(&session("capacity-other"), "run")
        .await
        .expect_err("active ownership is pinned");
    assert_eq!(error, RuntimeError::SessionCapacityReached { capacity: 1 });

    active.cancel();
    assert_eq!(
        active.join().await.expect("cancelled outcome").state,
        SessionState::Cancelled
    );
    harness.runtime.shutdown().await.expect("shutdown is clean");
}

#[tokio::test]
async fn terminal_destruction_cancels_and_joins_the_owned_turn() {
    let harness = harness(
        vec![Round::stalling(vec![ProviderChunk::TextDelta {
            text: "partial".to_owned(),
        }])],
        RuntimeConfig::default(),
    );
    let session_id = session("destroy-active");
    harness
        .runtime
        .execute_effect(&session_id, CommandEffect::SetModel("temporary".to_owned()))
        .await
        .expect("model selection");
    let handle = harness
        .runtime
        .submit(&session_id, "run")
        .await
        .expect("turn");
    support::eventually("the provider stream to start", || {
        !harness.provider.requests().is_empty()
    })
    .await;

    assert!(harness.runtime.destroy_session(&session_id).await);
    assert_eq!(
        handle.join().await.expect("terminal outcome").state,
        SessionState::Cancelled
    );
    assert_eq!(harness.runtime.managed_session_ids(), Vec::new());
    assert_eq!(harness.runtime.selected_model(&session_id), None);
    assert!(!harness.runtime.destroy_session(&session_id).await);
    harness.runtime.shutdown().await.expect("shutdown is clean");
}

#[tokio::test]
async fn reload_fences_old_sessions_and_new_turns_use_fresh_scope() {
    let harness = harness(
        vec![
            Round::stalling(vec![ProviderChunk::TextDelta {
                text: "old".to_owned(),
            }]),
            text_round("new"),
        ],
        RuntimeConfig::default(),
    );
    let session_id = session("reload-fence");
    harness
        .runtime
        .execute_effect(&session_id, CommandEffect::SetModel("old-model".to_owned()))
        .await
        .expect("old model");
    let old = harness
        .runtime
        .submit(&session_id, "old")
        .await
        .expect("old turn");
    support::eventually("the old provider request", || {
        !harness.provider.requests().is_empty()
    })
    .await;

    let report = harness.runtime.reload_sessions().await;
    assert_eq!(report.generation, 1);
    assert_eq!(report.destroyed, 1);
    assert_eq!(report.cancelled_turns, 1);
    assert_eq!(report.forced_turns, 0);
    assert_eq!(
        old.join().await.expect("old turn reports").state,
        SessionState::Cancelled
    );
    assert_eq!(harness.runtime.managed_session_ids(), Vec::new());

    let fresh = harness
        .runtime
        .submit(&session_id, "new")
        .await
        .expect("fresh turn")
        .join()
        .await
        .expect("fresh turn completes");
    assert_eq!(fresh.message.expect("message").text, "new");
    let requests = harness.provider.requests();
    assert_eq!(requests[0].model.as_deref(), Some("old-model"));
    assert_eq!(requests[1].model, None);
    harness.runtime.shutdown().await.expect("shutdown is clean");
}

#[tokio::test]
async fn destruction_fences_a_session_creation_parked_in_state_io() {
    let clock = FakeClock::new(0);
    let state = GatedLoadState::new();
    let provider = ScriptedProvider::new(vec![text_round("must not run")]);
    let runtime = Runtime::new(
        RuntimePorts {
            clock: Arc::clone(&clock) as Arc<_>,
            provider: provider as Arc<_>,
            state: Arc::clone(&state) as Arc<_>,
            tools: RecordingTools::new(Vec::new(), Vec::new()) as Arc<_>,
            approvals: RecordingApprovals::new() as Arc<_>,
            goals: MemoryGoals::new() as Arc<_>,
            context: SimpleContext::new() as Arc<_>,
        },
        RuntimeConfig::default(),
    );
    let session_id = session("destroy-create-race");
    let submitting = tokio::spawn({
        let runtime = runtime.clone();
        let session_id = session_id.clone();
        async move { runtime.submit(&session_id, "race").await }
    });
    support::eventually("the state load to park", || state.load_count() == 1).await;

    assert!(
        !runtime.destroy_session(&session_id).await,
        "no session had been published yet"
    );
    state.open();
    let error = submitting
        .await
        .expect("submit task joins")
        .expect_err("pre-destruction creation is fenced");
    assert_eq!(
        error,
        RuntimeError::ReloadFenced {
            expected: 0,
            current: 1,
        }
    );
    assert_eq!(runtime.managed_session_ids(), Vec::new());
    runtime.shutdown().await.expect("shutdown is clean");
}

#[tokio::test]
async fn destruction_aborts_a_turn_that_ignores_cancellation() {
    let context = HangingBootstrapContext::new();
    let runtime = Runtime::new(
        RuntimePorts {
            clock: FakeClock::new(0) as Arc<_>,
            provider: ScriptedProvider::new(Vec::new()) as Arc<_>,
            state: MemoryState::new() as Arc<_>,
            tools: RecordingTools::new(Vec::new(), Vec::new()) as Arc<_>,
            approvals: RecordingApprovals::new() as Arc<_>,
            goals: MemoryGoals::new() as Arc<_>,
            context: Arc::clone(&context) as Arc<_>,
        },
        RuntimeConfig {
            session_retire_timeout: Duration::from_millis(20),
            ..RuntimeConfig::default()
        },
    );
    let session_id = session("destroy-forced");
    let handle = runtime
        .submit(&session_id, "hang")
        .await
        .expect("turn starts");
    support::eventually("context bootstrap to hang", || context.entered() == 1).await;

    assert!(
        tokio::time::timeout(Duration::from_secs(1), runtime.destroy_session(&session_id))
            .await
            .expect("terminal destruction is bounded")
    );
    assert_eq!(
        handle.join().await.expect_err("aborted task"),
        RuntimeError::Abandoned
    );
    assert_eq!(runtime.managed_session_ids(), Vec::new());
    runtime.shutdown().await.expect("shutdown is clean");
}

#[tokio::test]
async fn dropping_destruction_still_aborts_the_retiring_turn() {
    let context = HangingBootstrapContext::new();
    let runtime = Runtime::new(
        RuntimePorts {
            clock: FakeClock::new(0) as Arc<_>,
            provider: ScriptedProvider::new(Vec::new()) as Arc<_>,
            state: MemoryState::new() as Arc<_>,
            tools: RecordingTools::new(Vec::new(), Vec::new()) as Arc<_>,
            approvals: RecordingApprovals::new() as Arc<_>,
            goals: MemoryGoals::new() as Arc<_>,
            context: Arc::clone(&context) as Arc<_>,
        },
        RuntimeConfig {
            session_retire_timeout: Duration::from_secs(10),
            ..RuntimeConfig::default()
        },
    );
    let session_id = session("destroy-dropped");
    let handle = runtime
        .submit(&session_id, "hang")
        .await
        .expect("turn starts");
    support::eventually("context bootstrap to hang", || context.entered() == 1).await;

    let destroying = tokio::spawn({
        let runtime = runtime.clone();
        let session_id = session_id.clone();
        async move { runtime.destroy_session(&session_id).await }
    });
    support::eventually("retirement generation to advance", || {
        runtime.session_generation() == 1
    })
    .await;
    destroying.abort();
    assert!(
        destroying
            .await
            .expect_err("destruction future was dropped")
            .is_cancelled()
    );

    assert_eq!(
        tokio::time::timeout(Duration::from_secs(1), handle.join())
            .await
            .expect("RAII abort finishes the turn")
            .expect_err("aborted task"),
        RuntimeError::Abandoned
    );
    assert_eq!(runtime.managed_session_ids(), Vec::new());
    runtime.shutdown().await.expect("shutdown is clean");
}

#[test]
fn runtime_failures_have_stable_user_facing_classification() {
    let error = RuntimeError::ReloadFenced {
        expected: 2,
        current: 3,
    };
    assert_eq!(error.failure_class(), RuntimeFailureClass::Busy);
    assert!(error.is_retryable());
    assert_eq!(
        error.user_message(),
        "This conversation is busy. Retry after the current work finishes."
    );
    assert!(!error.user_message().contains('2'));

    let unavailable = RuntimeError::Approval(ApprovalError::Port(PortError::Unavailable(
        "adapter-secret-detail".to_owned(),
    )));
    assert_eq!(
        unavailable.failure_class(),
        RuntimeFailureClass::Unavailable
    );
    assert!(unavailable.is_retryable());
    assert!(!unavailable.user_message().contains("adapter-secret-detail"));
}

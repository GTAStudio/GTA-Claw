//! End-to-end tests for the model-callable goal tool.
//!
//! These drive a live [`Runtime`] with a scripted provider that emits real `update_goal` tool
//! calls, so they exercise the same path a model would: stream assembly produces the call, the
//! runtime serves it itself, and the durable goal is written through the goal store port.

mod support;

use std::sync::{Arc, Mutex};

use claw_application::model::goal::GoalStatus;
use claw_application::model::session::SessionState;
use claw_application::ports::tool::{
    InternalToolAuditPhase, InvocationAuthority, ToolBinding, ToolDescriptor, ToolInvocation,
    ToolOutcome, ToolPort, ToolStatus,
};
use claw_application::ports::{PortError, PortFuture};
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
    audit: Arc<Mutex<Vec<InternalToolAuditPhase>>>,
    audit_failure: Arc<std::sync::atomic::AtomicU8>,
}

struct GoalBindingTools(
    Arc<Mutex<Vec<InternalToolAuditPhase>>>,
    Arc<std::sync::atomic::AtomicU8>,
);

impl ToolPort for GoalBindingTools {
    fn describe(&self) -> Vec<ToolDescriptor> {
        vec![readonly_tool("read_file")]
    }
    fn invoke(
        &self,
        _invocation: ToolInvocation,
    ) -> PortFuture<'_, Result<ToolOutcome, PortError>> {
        Box::pin(async { Err(PortError::Invalid("runtime owns goal writes".to_owned())) })
    }
    fn cancel(
        &self,
        _call_id: &claw_application::model::ids::ToolCallId,
    ) -> PortFuture<'_, Result<(), PortError>> {
        Box::pin(async { Ok(()) })
    }
    fn bind_authorized(
        &self,
        invocation: &ToolInvocation,
        authority: &InvocationAuthority,
    ) -> Result<ToolBinding, PortError> {
        if !authority.is_owner() {
            return Err(PortError::Invalid("owner required".to_owned()));
        }
        claw_runtime::goal_tool::goal_tool_binding(invocation)
    }
    fn audit_internal<'a>(
        &'a self,
        invocation: &'a ToolInvocation,
        _authority: &'a InvocationAuthority,
        binding: &'a ToolBinding,
        phase: InternalToolAuditPhase,
    ) -> PortFuture<'a, Result<(), PortError>> {
        assert_eq!(
            binding,
            &claw_runtime::goal_tool::goal_tool_binding(invocation).expect("goal binding")
        );
        self.0.lock().expect("audit").push(phase);
        let fail = matches!(
            (phase, self.1.load(std::sync::atomic::Ordering::Acquire)),
            (InternalToolAuditPhase::Authorized, 1) | (InternalToolAuditPhase::Completed, 2)
        );
        Box::pin(async move {
            if fail {
                Err(PortError::Unavailable(
                    "injected audit persistence failure".to_owned(),
                ))
            } else {
                Ok(())
            }
        })
    }
}

fn fixture_with(rounds: Vec<Round>, config: RuntimeConfig) -> Fixture {
    let goals = MemoryGoals::new();
    let provider = ScriptedProvider::new(rounds);
    let audit = Arc::new(Mutex::new(Vec::new()));
    let audit_failure = Arc::new(std::sync::atomic::AtomicU8::new(0));
    let runtime = Runtime::new(
        RuntimePorts {
            clock: FakeClock::new(0) as Arc<_>,
            provider: Arc::clone(&provider) as Arc<_>,
            state: MemoryState::new() as Arc<_>,
            tools: Arc::new(GoalBindingTools(
                Arc::clone(&audit),
                Arc::clone(&audit_failure),
            )),
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
        audit,
        audit_failure,
    }
}

fn fixture(rounds: Vec<Round>) -> Fixture {
    fixture_with(rounds, RuntimeConfig::default())
}

fn goal_round(call: &str, arguments: &str) -> Round {
    tool_round(call, GOAL_TOOL_NAME, arguments)
}

#[tokio::test]
async fn authenticated_owner_goal_calls_require_once_approval_and_durable_audit() {
    use claw_application::model::approval::ApprovalDecision;
    use claw_application::ports::tool::{InvocationAccess, InvocationSource};
    for approve in [false, true] {
        let fixture = fixture(vec![
            goal_round("c1", r#"{"action":"set","objective":"reviewed goal"}"#),
            text_round("finished"),
        ]);
        let session_id = session("goal-owner-approval");
        let authority = InvocationAuthority::new(
            InvocationSource::Gateway,
            "owner-device",
            None,
            InvocationAccess::Owner,
            0,
        )
        .expect("owner authority");
        let mut turn = fixture
            .runtime
            .submit_authorized(&session_id, "set a goal", authority)
            .await
            .expect("accepted turn");
        while let Some(event) = turn.next_event().await {
            if matches!(event.kind, RuntimeEventKind::AwaitingApproval { .. }) {
                break;
            }
        }
        assert!(
            fixture
                .runtime
                .goals()
                .history(&session_id)
                .await
                .expect("before approval")
                .is_empty()
        );
        let broker = fixture.runtime.approvals();
        let pending = broker.outstanding()[0].approval_id.clone();
        let (binding, token) = broker.binding(&pending).expect("bound goal preview");
        assert!(
            binding
                .resource()
                .expect("resource")
                .contains(session_id.as_str())
        );
        broker
            .resolve_bound(
                &pending,
                if approve {
                    ApprovalDecision::approve_once()
                } else {
                    ApprovalDecision::deny_once()
                },
                &token,
            )
            .expect("once decision");
        let outcome = turn.join().await.expect("goal turn completed");
        assert_eq!(
            outcome.tool_outcomes[0].status,
            if approve {
                ToolStatus::Ok
            } else {
                ToolStatus::Denied
            }
        );
        assert_eq!(
            fixture
                .runtime
                .goals()
                .history(&session_id)
                .await
                .expect("after decision")
                .len(),
            usize::from(approve)
        );
        assert_eq!(
            *fixture.audit.lock().expect("audit phases"),
            if approve {
                vec![
                    InternalToolAuditPhase::Authorized,
                    InternalToolAuditPhase::Completed,
                ]
            } else {
                Vec::new()
            }
        );
        fixture.runtime.shutdown().await.expect("shutdown");
    }
}

#[tokio::test]
async fn authenticated_owner_goal_directive_cannot_bypass_approval_or_audit() {
    use claw_application::model::approval::ApprovalDecision;
    use claw_application::ports::tool::{InvocationAccess, InvocationSource};
    for approve in [false, true] {
        let fixture = fixture(vec![text_round("continued")]);
        let session_id = session("goal-owner-directive");
        let authority = InvocationAuthority::new(
            InvocationSource::Gateway,
            "owner",
            None,
            InvocationAccess::Owner,
            0,
        )
        .expect("owner authority");
        let mut turn = fixture
            .runtime
            .submit_authorized(&session_id, "!goal reviewed objective\ncontinue", authority)
            .await
            .expect("directive turn");
        while let Some(event) = turn.next_event().await {
            if matches!(event.kind, RuntimeEventKind::AwaitingApproval { .. }) {
                break;
            }
        }
        assert!(
            fixture
                .runtime
                .goals()
                .history(&session_id)
                .await
                .expect("pre-approval state")
                .is_empty()
        );
        let broker = fixture.runtime.approvals();
        let deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(2);
        while broker.outstanding().is_empty() {
            assert!(
                tokio::time::Instant::now() < deadline,
                "directive approval registration deadline"
            );
            tokio::task::yield_now().await;
        }
        let id = broker.outstanding()[0].approval_id.clone();
        let (_, token) = broker.binding(&id).expect("directive bound preview");
        broker
            .resolve_bound(
                &id,
                if approve {
                    ApprovalDecision::approve_once()
                } else {
                    ApprovalDecision::deny_once()
                },
                &token,
            )
            .expect("decision");
        let outcome = turn.join().await.expect("directive completion");
        assert_eq!(
            outcome.state,
            if approve {
                SessionState::Completed
            } else {
                SessionState::Blocked
            }
        );
        assert_eq!(
            fixture
                .runtime
                .goals()
                .history(&session_id)
                .await
                .expect("goal history")
                .len(),
            usize::from(approve)
        );
        assert_eq!(
            fixture.audit.lock().expect("audit").len(),
            if approve { 2 } else { 0 }
        );
        fixture.runtime.shutdown().await.expect("shutdown");
    }
}

#[tokio::test]
async fn authenticated_goal_audit_failure_distinguishes_zero_effects_from_unknown_completion() {
    use claw_application::model::approval::ApprovalDecision;
    use claw_application::model::ids::TurnId;
    use claw_application::model::message::ToolCall;
    use claw_application::ports::tool::{InvocationAccess, InvocationSource};
    use tokio_util::sync::CancellationToken;
    for phase in [1, 2] {
        let fixture = fixture(Vec::new());
        fixture
            .audit_failure
            .store(phase, std::sync::atomic::Ordering::Release);
        let session_id = session("goal-audit-failure");
        let authority = InvocationAuthority::new(
            InvocationSource::Http,
            "owner",
            None,
            InvocationAccess::Owner,
            0,
        )
        .expect("owner");
        let invocation = ToolInvocation {
            session_id: session_id.clone(),
            turn: TurnId::FIRST,
            call: ToolCall {
                call_id: call_id("goal-audit-call"),
                name: GOAL_TOOL_NAME.to_owned(),
                arguments: r#"{"action":"set","objective":"audited write"}"#.to_owned(),
            },
        };
        let cancel = CancellationToken::new();
        let runtime = fixture.runtime.clone();
        let pending = tokio::spawn(async move {
            runtime
                .invoke_goal_authorized(invocation, authority, &cancel)
                .await
        });
        let broker = fixture.runtime.approvals();
        let deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(2);
        while broker.outstanding().is_empty() {
            assert!(
                tokio::time::Instant::now() < deadline,
                "goal approval must be registered"
            );
            tokio::task::yield_now().await;
        }
        let id = broker.outstanding()[0].approval_id.clone();
        let (_, token) = broker.binding(&id).expect("bound approval");
        broker
            .resolve_bound(&id, ApprovalDecision::approve_once(), &token)
            .expect("approved");
        let result = pending.await.expect("owned invocation task");
        if phase == 1 {
            assert_eq!(
                result.expect("known pre-write refusal").outcome.status,
                ToolStatus::Failed
            );
            assert!(
                fixture
                    .runtime
                    .goals()
                    .history(&session_id)
                    .await
                    .expect("unchanged goals")
                    .is_empty()
            );
        } else {
            assert_eq!(
                result
                    .expect_err("completion audit is unconfirmed")
                    .failure_class(),
                claw_runtime::RuntimeFailureClass::OutcomeUnknown
            );
            assert_eq!(
                fixture
                    .runtime
                    .goals()
                    .history(&session_id)
                    .await
                    .expect("committed goal")
                    .len(),
                1
            );
        }
        fixture.runtime.shutdown().await.expect("shutdown");
    }
}

#[tokio::test]
async fn goal_task_shutdown_drains_registered_unpolled_and_waiting_approval_calls() {
    use claw_application::model::ids::TurnId;
    use claw_application::model::message::ToolCall;
    use claw_application::ports::tool::{InvocationAccess, InvocationSource};
    use tokio_util::sync::CancellationToken;
    for wait_for_approval in [false, true] {
        let fixture = fixture(Vec::new());
        let session_id = session("goal-shutdown");
        let authority = InvocationAuthority::new(
            InvocationSource::Http,
            "owner",
            None,
            InvocationAccess::Owner,
            0,
        )
        .expect("owner");
        let invocation = ToolInvocation {
            session_id: session_id.clone(),
            turn: TurnId::FIRST,
            call: ToolCall {
                call_id: call_id("goal-shutdown-call"),
                name: GOAL_TOOL_NAME.to_owned(),
                arguments: r#"{"action":"set","objective":"must not commit"}"#.to_owned(),
            },
        };
        let cancel = CancellationToken::new();
        let mut pending = Box::pin(fixture.runtime.invoke_goal_authorized(
            invocation.clone(),
            authority.clone(),
            &cancel,
        ));
        assert!(support::poll_once(&mut pending).is_pending());
        assert_eq!(fixture.runtime.tracked_tasks(), 1);
        if wait_for_approval {
            let deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(2);
            while fixture.runtime.approvals().outstanding().is_empty() {
                assert!(
                    tokio::time::Instant::now() < deadline,
                    "approval registration deadline"
                );
                tokio::task::yield_now().await;
            }
        }
        drop(pending);
        tokio::time::timeout(
            std::time::Duration::from_secs(2),
            fixture.runtime.shutdown(),
        )
        .await
        .expect("shutdown must not wait for a new approval")
        .expect("shutdown");
        assert_eq!(fixture.runtime.tracked_tasks(), 0);
        assert!(fixture.runtime.approvals().outstanding().is_empty());
        assert!(
            fixture
                .runtime
                .goals()
                .history(&session_id)
                .await
                .expect("goal store")
                .is_empty()
        );
        assert!(
            fixture
                .runtime
                .invoke_goal_authorized(invocation, authority, &cancel)
                .await
                .is_err()
        );
    }
}

#[tokio::test]
async fn authenticated_non_owner_cannot_mutate_goals_from_model_output_or_directives() {
    use claw_application::ports::tool::{InvocationAccess, InvocationAuthority, InvocationSource};
    let fixture = fixture(vec![
        goal_round("c1", r#"{"action":"set","objective":"must not persist"}"#),
        text_round("no change"),
    ]);
    let session_id = session("goal-authentication");
    let authority = InvocationAuthority::new(
        InvocationSource::Gateway,
        "device",
        None,
        InvocationAccess::Execute,
        0,
    )
    .expect("authenticated execution scope");
    let options = claw_runtime::command::TurnOptions {
        goal: Some("must not persist".to_owned()),
        authority: Some(authority.clone()),
        ..claw_runtime::command::TurnOptions::default()
    };
    assert!(
        fixture
            .runtime
            .submit_with(&session_id, "directive", options)
            .await
            .is_err()
    );
    let result = fixture
        .runtime
        .submit_authorized(&session_id, "make a goal", authority)
        .await
        .expect("chat admission")
        .join()
        .await
        .expect("turn completes");
    assert_eq!(result.tool_outcomes[0].status, ToolStatus::Denied);
    assert!(
        fixture
            .runtime
            .goals()
            .history(&session_id)
            .await
            .expect("goal history")
            .is_empty()
    );
    fixture.runtime.shutdown().await.expect("shutdown");
}

#[tokio::test]
async fn production_authority_policy_blocks_anonymous_model_tools() {
    let fixture = fixture_with(
        vec![goal_round(
            "c1",
            r#"{"action":"set","objective":"anonymous mutation"}"#,
        )],
        RuntimeConfig {
            require_tool_authority: true,
            ..RuntimeConfig::default()
        },
    );
    let session_id = session("goal-no-identity");
    let result = fixture
        .runtime
        .submit(&session_id, "anonymous chat")
        .await
        .expect("chat admission")
        .join()
        .await
        .expect("blocked turn");
    assert_eq!(result.state, SessionState::Blocked);
    assert!(fixture.provider.requests()[0].tool_names.is_empty());
    assert!(
        fixture
            .runtime
            .goals()
            .history(&session_id)
            .await
            .expect("goal history")
            .is_empty()
    );
    fixture.runtime.shutdown().await.expect("shutdown");
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

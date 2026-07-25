//! Command and directive dispatch tests over a live runtime.

mod support;

use std::sync::Arc;

use claw_application::model::goal::GoalStatus;
use claw_application::model::session::SessionState;
use claw_application::ports::tool::ToolStatus;
use claw_runtime::command::{
    CommandEffect, CommandError, Directive, DirectiveError, DirectiveScan, OperatorScope, ScopeSet,
    TurnOptions,
};
use claw_runtime::runtime::{CommandOutcome, Runtime, RuntimeConfig, RuntimeError, RuntimePorts};
use claw_runtime::suspend::{PrepareOutcome, SuspensionPhase};

use support::{
    FakeClock, Gate, MemoryGoals, MemoryState, RecordingApprovals, RecordingTools, Round,
    ScriptedProvider, SimpleContext, ToolBehaviour, readonly_tool, session, text_round, tool_round,
};

struct Fixture {
    runtime: Runtime,
    state: Arc<MemoryState>,
    gate: Arc<Gate>,
}

fn fixture(rounds: Vec<Round>) -> Fixture {
    let clock = FakeClock::new(0);
    let state = MemoryState::new();
    let gate = Gate::new();
    let tools = RecordingTools::new(
        vec![readonly_tool("gate"), readonly_tool("read_file")],
        vec![
            ("gate", ToolBehaviour::Gated(Arc::clone(&gate))),
            (
                "read_file",
                ToolBehaviour::Succeed {
                    output: "contents".to_owned(),
                    changed_workspace: false,
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
            approvals: RecordingApprovals::new() as Arc<_>,
            goals: MemoryGoals::new() as Arc<_>,
            context: SimpleContext::new() as Arc<_>,
        },
        RuntimeConfig::default(),
    );
    Fixture {
        runtime,
        state,
        gate,
    }
}

#[tokio::test]
async fn help_lists_only_the_commands_the_caller_may_run() {
    let fixture = fixture(Vec::new());

    let outcome = fixture
        .runtime
        .dispatch_command(&session("cmd"), "/help", ScopeSet::all())
        .await
        .expect("help is always available");
    let CommandOutcome::Commands(all) = outcome else {
        panic!("expected the command list");
    };
    assert_eq!(
        all.iter()
            .map(|spec| spec.name.clone())
            .collect::<Vec<String>>(),
        vec![
            "help",
            "status",
            "tools",
            "cancel",
            "pause",
            "resume",
            "goal",
            "goal-done",
            "goal-drop",
            "approve",
            "deny",
            "compact",
            "suspend",
            "suspend-status",
            "resume-host",
            "model",
        ]
    );

    let read_only: Vec<String> = fixture
        .runtime
        .commands()
        .list(ScopeSet::EMPTY.with(OperatorScope::Read))
        .into_iter()
        .map(|spec| spec.name.clone())
        .collect();
    assert_eq!(read_only, vec!["help", "status", "tools", "suspend-status"]);

    fixture.runtime.shutdown().await.expect("shutdown is clean");
}

#[tokio::test]
async fn tools_and_status_report_the_runtime_surface() {
    let fixture = fixture(vec![text_round("hello")]);
    let session_id = session("cmd-status");

    let tools = fixture
        .runtime
        .dispatch_command(&session_id, "/tools", ScopeSet::all())
        .await
        .expect("tools is readable");
    assert_eq!(
        tools,
        CommandOutcome::Tools(vec![readonly_tool("gate"), readonly_tool("read_file")])
    );

    let empty = fixture
        .runtime
        .dispatch_command(&session_id, "/status", ScopeSet::all())
        .await
        .expect("status is readable");
    assert_eq!(empty, CommandOutcome::Sessions(Vec::new()));

    fixture
        .runtime
        .submit(&session_id, "hi")
        .await
        .expect("the turn is accepted")
        .join()
        .await
        .expect("the turn finishes");

    let after = fixture
        .runtime
        .dispatch_command(&session_id, "/status", ScopeSet::all())
        .await
        .expect("status is readable");
    let CommandOutcome::Sessions(sessions) = after else {
        panic!("expected the session list");
    };
    assert_eq!(sessions.len(), 1);
    assert_eq!(sessions[0].session_id.as_str(), "cmd-status");
    assert_eq!(sessions[0].state, SessionState::Completed);

    fixture.runtime.shutdown().await.expect("shutdown is clean");
}

#[tokio::test]
async fn the_goal_commands_drive_the_durable_goal() {
    let fixture = fixture(Vec::new());
    let session_id = session("cmd-goal");

    assert_eq!(
        fixture
            .runtime
            .dispatch_command(&session_id, "/goal", ScopeSet::all())
            .await
            .expect("goal is writable"),
        CommandOutcome::Goal(None)
    );

    let set = fixture
        .runtime
        .dispatch_command(&session_id, "/goal ship the runtime", ScopeSet::all())
        .await
        .expect("goal is writable");
    let CommandOutcome::Goal(Some(record)) = set else {
        panic!("expected the new goal");
    };
    assert_eq!(record.objective, "ship the runtime");
    assert_eq!(record.status, GoalStatus::Active);
    assert_eq!(record.goal_id.as_str(), "goal-1");

    let done = fixture
        .runtime
        .dispatch_command(&session_id, "/goal-done", ScopeSet::all())
        .await
        .expect("goal-done is writable");
    let CommandOutcome::Goal(Some(closed)) = done else {
        panic!("expected the closed goal");
    };
    assert_eq!(closed.status, GoalStatus::Achieved);

    assert_eq!(
        fixture
            .runtime
            .dispatch_command(&session_id, "/goal-drop", ScopeSet::all())
            .await
            .expect("goal-drop is writable"),
        CommandOutcome::Goal(None),
        "there is nothing left to drop"
    );

    fixture.runtime.shutdown().await.expect("shutdown is clean");
}

#[tokio::test]
async fn the_suspension_commands_walk_the_whole_handshake() {
    let fixture = fixture(Vec::new());
    let session_id = session("cmd-suspend");

    let idle = fixture
        .runtime
        .dispatch_command(&session_id, "/suspend-status", ScopeSet::all())
        .await
        .expect("suspend-status is readable");
    let CommandOutcome::Suspension(status) = idle else {
        panic!("expected a suspension status");
    };
    assert_eq!(status.phase, SuspensionPhase::Active);
    assert_eq!(status.in_flight, 0);

    let prepared = fixture
        .runtime
        .dispatch_command(&session_id, "/suspend 5", ScopeSet::all())
        .await
        .expect("suspend is admin-scoped and we hold admin");
    let CommandOutcome::SuspensionPrepared(PrepareOutcome::Suspended(lease)) = prepared else {
        panic!("an idle runtime must suspend immediately");
    };
    assert_eq!(lease.lease_id.as_str(), "lease-0");

    let refused = fixture
        .runtime
        .submit(&session_id, "work")
        .await
        .expect_err("a suspended runtime refuses new turns");
    assert_eq!(
        refused,
        RuntimeError::Quiescing(claw_runtime::suspend::WorkRefused {
            phase: SuspensionPhase::Suspended
        })
    );

    let resumed = fixture
        .runtime
        .dispatch_command(&session_id, "/resume-host lease-0", ScopeSet::all())
        .await
        .expect("resume-host is admin-scoped");
    let CommandOutcome::Suspension(status) = resumed else {
        panic!("expected a suspension status");
    };
    assert_eq!(status.phase, SuspensionPhase::Active);
    assert_eq!(status.lease, None);

    fixture.runtime.shutdown().await.expect("shutdown is clean");
}

#[tokio::test]
async fn compact_forwards_the_requested_reclaim_to_the_engine() {
    let fixture = fixture(Vec::new());

    assert_eq!(
        fixture
            .runtime
            .dispatch_command(&session("cmd-compact"), "/compact 64", ScopeSet::all())
            .await
            .expect("compact is admin-scoped"),
        CommandOutcome::Compaction {
            removed_items: 0,
            reclaimed_tokens: 0,
        },
        "an empty engine has nothing to shed"
    );

    fixture.runtime.shutdown().await.expect("shutdown is clean");
}

#[tokio::test]
async fn model_is_advertised_but_not_yet_implemented() {
    let fixture = fixture(Vec::new());

    assert_eq!(
        fixture
            .runtime
            .dispatch_command(&session("cmd-model"), "/model gpt", ScopeSet::all())
            .await
            .expect("model parses"),
        CommandOutcome::Unsupported {
            name: "model".to_owned()
        }
    );

    fixture.runtime.shutdown().await.expect("shutdown is clean");
}

#[tokio::test]
async fn pause_and_resume_quiesce_the_turn_between_rounds() {
    let fixture = fixture(vec![
        tool_round("call-1", "gate", "{}"),
        text_round("finished"),
    ]);
    let session_id = session("cmd-pause");

    assert_eq!(
        fixture
            .runtime
            .dispatch_command(&session_id, "/pause", ScopeSet::all())
            .await
            .expect_err("there is no turn to pause"),
        RuntimeError::NoTurnInFlight
    );

    let handle = fixture
        .runtime
        .submit(&session_id, "run the gate")
        .await
        .expect("the turn is accepted");

    support::eventually("the gated tool to start", || {
        fixture
            .state
            .history()
            .iter()
            .any(|snapshot| snapshot.state == SessionState::Running)
    })
    .await;

    fixture
        .runtime
        .dispatch_command(&session_id, "/pause", ScopeSet::all())
        .await
        .expect("the live turn accepts a pause");
    fixture.gate.open();

    support::eventually("the turn to park in Paused", || {
        fixture
            .state
            .history()
            .iter()
            .any(|snapshot| snapshot.state == SessionState::Paused)
    })
    .await;

    fixture
        .runtime
        .dispatch_command(&session_id, "/resume", ScopeSet::all())
        .await
        .expect("the paused turn accepts a resume");

    let outcome = handle.join().await.expect("the turn finishes");
    assert_eq!(outcome.state, SessionState::Completed);
    assert_eq!(outcome.rounds, 2);
    assert_eq!(outcome.tool_outcomes.len(), 1);
    assert_eq!(outcome.tool_outcomes[0].status, ToolStatus::Ok);
    assert_eq!(outcome.tool_outcomes[0].output, "gate opened");

    let states: Vec<SessionState> = fixture
        .state
        .history()
        .iter()
        .map(|snapshot| snapshot.state)
        .collect();
    assert_eq!(
        states,
        vec![
            SessionState::Queued,
            SessionState::Starting,
            SessionState::Running,
            SessionState::Paused,
            SessionState::Running,
            SessionState::Completed,
        ]
    );

    fixture.runtime.shutdown().await.expect("shutdown is clean");
}

#[tokio::test]
async fn cancel_stops_the_live_turn_through_the_command_surface() {
    let fixture = fixture(vec![Round::stalling(Vec::new())]);
    let session_id = session("cmd-cancel");

    assert_eq!(
        fixture
            .runtime
            .dispatch_command(&session_id, "/cancel", ScopeSet::all())
            .await
            .expect_err("there is no turn to cancel"),
        RuntimeError::NoTurnInFlight
    );

    let handle = fixture
        .runtime
        .submit(&session_id, "stall forever")
        .await
        .expect("the turn is accepted");
    support::eventually("the turn to start streaming", || {
        fixture
            .state
            .history()
            .iter()
            .any(|snapshot| snapshot.state == SessionState::Running)
    })
    .await;

    assert_eq!(
        fixture
            .runtime
            .dispatch_command(&session_id, "/cancel", ScopeSet::all())
            .await
            .expect("the live turn accepts a cancel"),
        CommandOutcome::Acknowledged
    );

    let outcome = handle.join().await.expect("the turn finishes");
    assert_eq!(outcome.state, SessionState::Cancelled);

    fixture.runtime.shutdown().await.expect("shutdown is clean");
}

#[tokio::test]
async fn bad_command_lines_are_rejected_with_typed_errors() {
    let fixture = fixture(Vec::new());
    let session_id = session("cmd-bad");
    let all = ScopeSet::all();

    let cases: Vec<(&str, CommandError)> = vec![
        ("not a command", CommandError::NotACommand),
        ("/", CommandError::EmptyCommand),
        ("/teleport", CommandError::Unknown("teleport".to_owned())),
        (
            "/approve",
            CommandError::MissingArguments {
                command: "approve".to_owned(),
                expected: 1,
                received: 0,
            },
        ),
        (
            "/approve a b c",
            CommandError::TooManyArguments {
                command: "approve".to_owned(),
                expected: 2,
                received: 3,
            },
        ),
        ("/goal \"unclosed", CommandError::UnterminatedQuote),
        ("/goal trailing\\", CommandError::DanglingEscape),
    ];

    for (line, expected) in cases {
        assert_eq!(
            fixture
                .runtime
                .dispatch_command(&session_id, line, all)
                .await
                .expect_err("the line is malformed"),
            RuntimeError::Command(expected),
            "line: {line}"
        );
    }

    assert_eq!(
        fixture
            .runtime
            .dispatch_command(&session_id, "/compact twelve", all)
            .await
            .expect_err("compact needs a number"),
        RuntimeError::Command(CommandError::InvalidArgument {
            command: "compact".to_owned(),
            argument: "twelve".to_owned(),
            reason: "expected a non-negative whole number",
        })
    );
    assert_eq!(
        fixture
            .runtime
            .dispatch_command(&session_id, "/approve approval-1 maybe", all)
            .await
            .expect_err("remember takes once or always"),
        RuntimeError::Command(CommandError::InvalidArgument {
            command: "approve".to_owned(),
            argument: "maybe".to_owned(),
            reason: "expected 'once' or 'always'",
        })
    );

    fixture.runtime.shutdown().await.expect("shutdown is clean");
}

#[tokio::test]
async fn directives_are_stripped_from_the_prompt_and_lowered_into_turn_options() {
    let fixture = fixture(Vec::new());
    let directives = fixture.runtime.directives();

    let scan = directives
        .scan("!model fast\n!no-tools\nplease summarise\nthe log")
        .expect("the directives are well formed");
    assert_eq!(
        scan,
        DirectiveScan {
            directives: vec![
                Directive {
                    name: "model".to_owned(),
                    value: Some("fast".to_owned()),
                },
                Directive {
                    name: "no-tools".to_owned(),
                    value: None,
                },
            ],
            body: "please summarise\nthe log".to_owned(),
        }
    );
    assert_eq!(
        directives
            .apply(&scan.directives)
            .expect("the directives are known"),
        TurnOptions {
            model: Some("fast".to_owned()),
            tools_enabled: false,
            quiet: false,
            goal: None,
        }
    );

    assert_eq!(
        directives
            .scan("!model\nhello")
            .expect_err("model needs a value"),
        DirectiveError::MissingValue("model".to_owned())
    );
    assert_eq!(
        directives
            .scan("!quiet=loud\nhello")
            .expect_err("quiet takes no value"),
        DirectiveError::UnexpectedValue("quiet".to_owned())
    );
    assert_eq!(
        directives
            .scan("!quiet\n!quiet\nhello")
            .expect_err("a directive may appear once"),
        DirectiveError::Duplicate("quiet".to_owned())
    );
    assert_eq!(
        directives
            .scan("!teleport\nhello")
            .expect_err("unknown directives are refused"),
        DirectiveError::Unknown("teleport".to_owned())
    );

    fixture.runtime.shutdown().await.expect("shutdown is clean");
}

#[tokio::test]
async fn a_goal_directive_records_a_durable_goal_before_the_turn_runs() {
    let fixture = fixture(vec![text_round("noted")]);
    let session_id = session("cmd-goal-directive");

    let outcome = fixture
        .runtime
        .submit(&session_id, "!goal survive the audit\nstart working")
        .await
        .expect("the turn is accepted")
        .join()
        .await
        .expect("the turn finishes");
    assert_eq!(outcome.state, SessionState::Completed);

    let goal = fixture
        .runtime
        .goals()
        .active(&session_id)
        .await
        .expect("the store answers")
        .expect("the directive recorded a goal");
    assert_eq!(goal.objective, "survive the audit");
    assert_eq!(goal.goal_id.as_str(), "goal-turn-0");

    fixture.runtime.shutdown().await.expect("shutdown is clean");
}

#[test]
fn every_builtin_command_lowers_to_a_distinct_effect() {
    let registry = claw_runtime::command::CommandRegistry::builtin();
    let all = ScopeSet::all();
    let lowered: Vec<CommandEffect> = [
        "/help",
        "/status",
        "/tools",
        "/cancel",
        "/pause",
        "/resume",
        "/goal",
        "/goal write tests",
        "/goal-done",
        "/goal-drop",
        "/approve approval-1",
        "/deny approval-2 always",
        "/compact 10",
        "/suspend",
        "/suspend-status",
        "/resume-host lease-9",
        "/model fast",
    ]
    .into_iter()
    .map(|line| {
        let invocation = registry.parse(line, all).expect("the line parses");
        claw_runtime::command::CommandRegistry::effect(&invocation).expect("the line lowers")
    })
    .collect();

    assert_eq!(
        lowered,
        vec![
            CommandEffect::ListCommands,
            CommandEffect::ShowStatus,
            CommandEffect::ListTools,
            CommandEffect::CancelTurn,
            CommandEffect::PauseTurn,
            CommandEffect::ResumeTurn,
            CommandEffect::ShowGoal,
            CommandEffect::SetGoal("write tests".to_owned()),
            CommandEffect::CloseGoal(GoalStatus::Achieved),
            CommandEffect::CloseGoal(GoalStatus::Abandoned),
            CommandEffect::Approve {
                approval_id: "approval-1".to_owned(),
                remember: false,
            },
            CommandEffect::Deny {
                approval_id: "approval-2".to_owned(),
                remember: true,
            },
            CommandEffect::CompactContext { reclaim_tokens: 10 },
            CommandEffect::SuspendPrepare { drain_seconds: 30 },
            CommandEffect::SuspendStatus,
            CommandEffect::SuspendResume {
                lease_id: "lease-9".to_owned(),
            },
            CommandEffect::SetModel("fast".to_owned()),
        ]
    );
}

#[tokio::test]
async fn a_read_only_operator_cannot_reach_write_or_admin_commands() {
    let fixture = fixture(Vec::new());
    let session_id = session("cmd-scopes");
    let read = ScopeSet::EMPTY.with(OperatorScope::Read);

    for (line, command, required) in [
        ("/cancel", "cancel", OperatorScope::Write),
        ("/goal x", "goal", OperatorScope::Write),
        ("/compact", "compact", OperatorScope::Admin),
        ("/suspend", "suspend", OperatorScope::Admin),
        ("/deny approval-1", "deny", OperatorScope::Approvals),
    ] {
        assert_eq!(
            fixture
                .runtime
                .dispatch_command(&session_id, line, read)
                .await
                .expect_err("a read-only caller is refused"),
            RuntimeError::Command(CommandError::Unauthorized {
                command: command.to_owned(),
                required,
            }),
            "line: {line}"
        );
    }

    fixture.runtime.shutdown().await.expect("shutdown is clean");
}

#[tokio::test]
async fn a_turn_that_runs_longer_than_the_command_is_unaffected_by_a_stale_pause() {
    let fixture = fixture(vec![text_round("done")]);
    let session_id = session("cmd-stale");

    fixture
        .runtime
        .submit(&session_id, "go")
        .await
        .expect("the turn is accepted")
        .join()
        .await
        .expect("the turn finishes");

    // The live-turn entry is gone, so pause/resume must report that rather than silently succeed.
    assert_eq!(
        fixture
            .runtime
            .dispatch_command(&session_id, "/resume", ScopeSet::all())
            .await
            .expect_err("the turn already ended"),
        RuntimeError::NoTurnInFlight
    );

    fixture.runtime.shutdown().await.expect("shutdown is clean");
}

#[tokio::test]
async fn an_unknown_effect_never_reaches_the_ports() {
    let fixture = fixture(Vec::new());

    assert_eq!(
        fixture
            .runtime
            .execute_effect(
                &session("cmd-custom"),
                CommandEffect::Custom {
                    name: "deploy".to_owned(),
                    arguments: vec!["prod".to_owned()],
                },
            )
            .await
            .expect("custom effects are reported, not executed"),
        CommandOutcome::Unsupported {
            name: "deploy".to_owned()
        }
    );
    assert_eq!(
        fixture.state.history(),
        Vec::new(),
        "no session was written"
    );

    fixture.runtime.shutdown().await.expect("shutdown is clean");
}

#[tokio::test]
async fn suspend_drains_a_live_turn_before_it_grants_the_lease() {
    let fixture = fixture(vec![Round::stalling(Vec::new())]);
    let session_id = session("cmd-suspend-busy");
    let handle = fixture
        .runtime
        .submit(&session_id, "stall")
        .await
        .expect("the turn is accepted");
    support::eventually("the turn to be in flight", || {
        fixture.runtime.suspension().status().in_flight == 1
    })
    .await;

    let prepared = tokio::spawn({
        let runtime = fixture.runtime.clone();
        let session_id = session_id.clone();
        async move {
            runtime
                .dispatch_command(&session_id, "/suspend 600", ScopeSet::all())
                .await
        }
    });
    support::eventually("the controller to start draining", || {
        fixture.runtime.suspension().status().phase == SuspensionPhase::Draining
    })
    .await;

    // While draining, the runtime must refuse fresh turns even for other sessions.
    assert_eq!(
        fixture
            .runtime
            .submit(&session("other"), "work")
            .await
            .expect_err("draining refuses new work"),
        RuntimeError::Quiescing(claw_runtime::suspend::WorkRefused {
            phase: SuspensionPhase::Draining
        })
    );

    handle.cancel();
    let outcome = handle.join().await.expect("the cancelled turn finishes");
    assert_eq!(outcome.state, SessionState::Cancelled);

    let prepared = prepared
        .await
        .expect("the suspend task finishes")
        .expect("the suspend reports an outcome");
    match prepared {
        CommandOutcome::SuspensionPrepared(PrepareOutcome::Suspended(lease)) => {
            assert_eq!(lease.lease_id.as_str(), "lease-0");
        }
        other => panic!("expected a granted lease, got {other:?}"),
    }
    assert_eq!(fixture.runtime.suspension().status().in_flight, 0);

    fixture.runtime.shutdown().await.expect("shutdown is clean");
}

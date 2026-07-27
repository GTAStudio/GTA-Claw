//! Approval brokering and tool-call cancellation tests.

mod support;

use std::sync::{Arc, Mutex, mpsc};
use std::time::Duration;

use claw_application::model::approval::{
    ApprovalDecision, ApprovalOutcome, ApprovalRequest, ApprovalScope, ApprovalVerdict,
    ApprovalWithdrawal,
};
use claw_application::model::ids::{ApprovalId, TurnId};
use claw_application::model::message::ToolCall;
use claw_application::model::session::SessionState;
use claw_application::ports::approval::ApprovalPort;
use claw_application::ports::tool::{ToolInvocation, ToolStatus};
use claw_application::ports::{PortError, PortFuture};
use claw_runtime::approval::{ApprovalBroker, ApprovalError, ApprovalTicket};
use claw_runtime::command::{CommandError, OperatorScope, ScopeSet};
use claw_runtime::runtime::{CommandOutcome, Runtime, RuntimeConfig, RuntimeError, RuntimePorts};
use claw_runtime::tool::{ToolExecutor, ToolExecutorConfig};
use tokio_util::sync::CancellationToken;

use support::{
    ApprovalRecord, FakeClock, MemoryGoals, MemoryState, RecordingApprovals, RecordingTools, Round,
    ScriptedProvider, SimpleContext, ToolBehaviour, call_id, guarded_tool, readonly_tool, session,
    text_round, tool_round,
};

fn broker_over(
    clock: &Arc<FakeClock>,
    approvals: &Arc<RecordingApprovals>,
    timeout: Duration,
) -> ApprovalBroker {
    ApprovalBroker::new(
        Arc::clone(approvals) as Arc<_>,
        Arc::clone(clock) as Arc<_>,
        timeout,
    )
}

fn ticket(tool: &str) -> ApprovalTicket {
    ApprovalTicket {
        session_id: session("approvals"),
        turn: TurnId::FIRST,
        call_id: call_id("call-1"),
        tool_name: tool.to_owned(),
        arguments: "{}".to_owned(),
    }
}

#[tokio::test]
async fn an_unanswered_request_is_withdrawn_when_the_clock_passes_the_deadline() {
    let clock = FakeClock::new(0);
    let approvals = RecordingApprovals::new();
    let broker = broker_over(&clock, &approvals, Duration::from_secs(30));
    let cancel = CancellationToken::new();

    let waiting = {
        let broker = broker.clone();
        let cancel = cancel.clone();
        tokio::spawn(async move { broker.request(ticket("write_file"), &cancel).await })
    };

    support::eventually("the request to be presented", || {
        !broker.outstanding().is_empty()
    })
    .await;
    let outstanding = broker.outstanding();
    assert_eq!(outstanding.len(), 1);
    assert_eq!(outstanding[0].requested_at.as_millis(), 0);
    assert_eq!(outstanding[0].expires_at.as_millis(), 30_000);

    clock.advance(Duration::from_secs(30));
    let outcome = waiting
        .await
        .expect("the waiter task finishes")
        .expect("the broker reports an outcome");

    assert_eq!(
        outcome,
        ApprovalOutcome::Withdrawn {
            reason: ApprovalWithdrawal::TimedOut
        }
    );
    assert_eq!(broker.outstanding(), Vec::new());
    assert_eq!(
        approvals.records(),
        vec![
            ApprovalRecord::Presented(ApprovalId::new("approval-1").expect("valid id")),
            ApprovalRecord::Withdrawn(
                ApprovalId::new("approval-1").expect("valid id"),
                ApprovalWithdrawal::TimedOut
            ),
        ]
    );
}

#[tokio::test]
async fn a_decision_beats_a_deadline_that_lands_at_the_same_time() {
    let clock = FakeClock::new(0);
    let approvals = RecordingApprovals::new();
    let broker = broker_over(&clock, &approvals, Duration::from_secs(1));
    let cancel = CancellationToken::new();

    let waiting = {
        let broker = broker.clone();
        let cancel = cancel.clone();
        tokio::spawn(async move { broker.request(ticket("write_file"), &cancel).await })
    };
    support::eventually("the request to be presented", || {
        !broker.outstanding().is_empty()
    })
    .await;

    // Answer and expire in the same scheduler tick: the biased select must prefer the answer.
    let approval_id = broker.outstanding()[0].approval_id.clone();
    broker
        .resolve(&approval_id, ApprovalDecision::approve_once())
        .expect("the request is outstanding");
    clock.advance(Duration::from_secs(5));

    let outcome = waiting
        .await
        .expect("the waiter task finishes")
        .expect("the broker reports an outcome");

    assert_eq!(
        outcome,
        ApprovalOutcome::Decided {
            decision: ApprovalDecision {
                verdict: ApprovalVerdict::Approve,
                scope: ApprovalScope::Once,
            },
            remembered: false,
        }
    );
    assert_eq!(
        approvals.records(),
        vec![
            ApprovalRecord::Presented(ApprovalId::new("approval-1").expect("valid id")),
            ApprovalRecord::Settled(ApprovalId::new("approval-1").expect("valid id")),
        ]
    );
}

#[tokio::test]
async fn a_remembered_decision_answers_later_requests_without_asking() {
    let clock = FakeClock::new(0);
    let approvals = RecordingApprovals::new();
    let broker = broker_over(&clock, &approvals, Duration::from_secs(30));
    let cancel = CancellationToken::new();

    let waiting = {
        let broker = broker.clone();
        let cancel = cancel.clone();
        tokio::spawn(async move { broker.request(ticket("write_file"), &cancel).await })
    };
    support::eventually("the request to be presented", || {
        !broker.outstanding().is_empty()
    })
    .await;
    let approval_id = broker.outstanding()[0].approval_id.clone();
    broker
        .resolve(&approval_id, ApprovalDecision::approve_for_session())
        .expect("the request is outstanding");
    waiting
        .await
        .expect("the waiter task finishes")
        .expect("the broker reports an outcome");

    let repeat = broker
        .request(ticket("write_file"), &cancel)
        .await
        .expect("the second request resolves from memory");

    assert_eq!(
        repeat,
        ApprovalOutcome::Decided {
            decision: ApprovalDecision::approve_for_session(),
            remembered: true,
        }
    );
    assert_eq!(approvals.records().len(), 2, "no second presentation");
    assert_eq!(
        broker.remembered(&session("approvals"), "write_file"),
        Some(ApprovalDecision::approve_for_session())
    );

    assert!(broker.forget(&session("approvals"), "write_file"));
    assert_eq!(broker.remembered(&session("approvals"), "write_file"), None);
    assert!(!broker.forget(&session("approvals"), "write_file"));
}

#[tokio::test]
async fn a_once_scoped_decision_is_not_remembered() {
    let clock = FakeClock::new(0);
    let approvals = RecordingApprovals::new();
    let broker = broker_over(&clock, &approvals, Duration::from_secs(30));
    let cancel = CancellationToken::new();

    let waiting = {
        let broker = broker.clone();
        let cancel = cancel.clone();
        tokio::spawn(async move { broker.request(ticket("write_file"), &cancel).await })
    };
    support::eventually("the request to be presented", || {
        !broker.outstanding().is_empty()
    })
    .await;
    let approval_id = broker.outstanding()[0].approval_id.clone();
    broker
        .resolve(&approval_id, ApprovalDecision::deny_once())
        .expect("the request is outstanding");
    waiting
        .await
        .expect("the waiter finishes")
        .expect("outcome");

    assert_eq!(broker.remembered(&session("approvals"), "write_file"), None);
}

#[tokio::test]
async fn resolving_an_unknown_request_is_reported_not_ignored() {
    let clock = FakeClock::new(0);
    let approvals = RecordingApprovals::new();
    let broker = broker_over(&clock, &approvals, Duration::from_secs(30));

    let error = broker
        .resolve(
            &ApprovalId::new("approval-404").expect("valid id"),
            ApprovalDecision::approve_once(),
        )
        .expect_err("an unknown request must be refused");

    assert_eq!(
        error,
        ApprovalError::Unknown(ApprovalId::new("approval-404").expect("valid id"))
    );
}

#[tokio::test]
async fn cancelling_a_waiting_request_withdraws_it() {
    let clock = FakeClock::new(0);
    let approvals = RecordingApprovals::new();
    let broker = broker_over(&clock, &approvals, Duration::from_secs(30));
    let cancel = CancellationToken::new();

    let waiting = {
        let broker = broker.clone();
        let cancel = cancel.clone();
        tokio::spawn(async move { broker.request(ticket("write_file"), &cancel).await })
    };
    support::eventually("the request to be presented", || {
        !broker.outstanding().is_empty()
    })
    .await;

    cancel.cancel();
    let outcome = waiting
        .await
        .expect("the waiter finishes")
        .expect("the broker reports an outcome");

    assert_eq!(
        outcome,
        ApprovalOutcome::Withdrawn {
            reason: ApprovalWithdrawal::Cancelled
        }
    );
    assert_eq!(
        approvals.records().last(),
        Some(&ApprovalRecord::Withdrawn(
            ApprovalId::new("approval-1").expect("valid id"),
            ApprovalWithdrawal::Cancelled
        ))
    );
}

#[tokio::test]
async fn a_hanging_tool_is_cancelled_mid_flight_and_the_adapter_is_told() {
    let clock = FakeClock::new(0);
    let approvals = RecordingApprovals::new();
    let broker = broker_over(&clock, &approvals, Duration::from_secs(30));
    let tools = RecordingTools::new(
        vec![readonly_tool("slow")],
        vec![("slow", ToolBehaviour::Hang)],
    );
    let executor = ToolExecutor::new(
        Arc::clone(&tools) as Arc<_>,
        broker,
        Arc::clone(&clock) as Arc<_>,
        ToolExecutorConfig {
            call_timeout: Duration::from_mins(10),
        },
    );
    let cancel = CancellationToken::new();

    let running = {
        let executor = executor.clone();
        let cancel = cancel.clone();
        tokio::spawn(async move {
            executor
                .execute(
                    ToolInvocation {
                        session_id: session("tools"),
                        turn: TurnId::FIRST,
                        call: ToolCall {
                            call_id: call_id("call-1"),
                            name: "slow".to_owned(),
                            arguments: "{}".to_owned(),
                        },
                    },
                    &cancel,
                )
                .await
        })
    };

    support::eventually("the tool to start", || !tools.invoked().is_empty()).await;
    cancel.cancel();

    let outcome = running
        .await
        .expect("the executor task finishes")
        .expect("the executor reports an outcome");

    assert_eq!(outcome.status, ToolStatus::Cancelled);
    assert_eq!(outcome.call_id, call_id("call-1"));
    assert_eq!(outcome.output, "cancelled mid-flight");
    assert!(!outcome.changed_workspace);
    assert_eq!(tools.cancelled(), vec![call_id("call-1")]);
}

#[tokio::test]
async fn a_tool_that_outlives_its_deadline_times_out() {
    let clock = FakeClock::new(0);
    let approvals = RecordingApprovals::new();
    let broker = broker_over(&clock, &approvals, Duration::from_secs(30));
    let tools = RecordingTools::new(
        vec![readonly_tool("slow")],
        vec![("slow", ToolBehaviour::Hang)],
    );
    let executor = ToolExecutor::new(
        Arc::clone(&tools) as Arc<_>,
        broker,
        Arc::clone(&clock) as Arc<_>,
        ToolExecutorConfig {
            call_timeout: Duration::from_secs(5),
        },
    );
    let cancel = CancellationToken::new();

    let running = {
        let executor = executor.clone();
        tokio::spawn(async move {
            executor
                .execute(
                    ToolInvocation {
                        session_id: session("tools"),
                        turn: TurnId::FIRST,
                        call: ToolCall {
                            call_id: call_id("call-1"),
                            name: "slow".to_owned(),
                            arguments: "{}".to_owned(),
                        },
                    },
                    &cancel,
                )
                .await
        })
    };

    support::eventually("the tool to start", || !tools.invoked().is_empty()).await;
    clock.advance(Duration::from_secs(5));

    let outcome = running
        .await
        .expect("the executor task finishes")
        .expect("the executor reports an outcome");

    assert_eq!(outcome.status, ToolStatus::TimedOut);
    assert_eq!(outcome.output, "exceeded the call deadline");
    assert_eq!(tools.cancelled(), vec![call_id("call-1")]);
}

#[tokio::test]
async fn a_failing_tool_reports_an_outcome_rather_than_an_error() {
    let clock = FakeClock::new(0);
    let approvals = RecordingApprovals::new();
    let broker = broker_over(&clock, &approvals, Duration::from_secs(30));
    let tools = RecordingTools::new(
        vec![readonly_tool("broken")],
        vec![("broken", ToolBehaviour::Fail("disk on fire".to_owned()))],
    );
    let executor = ToolExecutor::new(
        Arc::clone(&tools) as Arc<_>,
        broker,
        Arc::clone(&clock) as Arc<_>,
        ToolExecutorConfig::default(),
    );

    let outcome = executor
        .execute(
            ToolInvocation {
                session_id: session("tools"),
                turn: TurnId::FIRST,
                call: ToolCall {
                    call_id: call_id("call-1"),
                    name: "broken".to_owned(),
                    arguments: "{}".to_owned(),
                },
            },
            &CancellationToken::new(),
        )
        .await
        .expect("the executor reports an outcome");

    assert_eq!(outcome.status, ToolStatus::Failed);
    assert_eq!(outcome.output, "invalid: disk on fire");
    assert_eq!(tools.cancelled(), Vec::new());
}

#[tokio::test]
async fn an_unknown_tool_fails_without_reaching_the_adapter() {
    let clock = FakeClock::new(0);
    let approvals = RecordingApprovals::new();
    let broker = broker_over(&clock, &approvals, Duration::from_secs(30));
    let tools = RecordingTools::new(vec![readonly_tool("known")], Vec::new());
    let executor = ToolExecutor::new(
        Arc::clone(&tools) as Arc<_>,
        broker,
        Arc::clone(&clock) as Arc<_>,
        ToolExecutorConfig::default(),
    );

    let outcome = executor
        .execute(
            ToolInvocation {
                session_id: session("tools"),
                turn: TurnId::FIRST,
                call: ToolCall {
                    call_id: call_id("call-1"),
                    name: "missing".to_owned(),
                    arguments: "{}".to_owned(),
                },
            },
            &CancellationToken::new(),
        )
        .await
        .expect("the executor reports an outcome");

    assert_eq!(outcome.status, ToolStatus::Failed);
    assert_eq!(outcome.output, "unknown tool: missing");
    assert_eq!(tools.invoked(), Vec::new());
}

struct RuntimeFixture {
    runtime: Runtime,
    clock: Arc<FakeClock>,
    tools: Arc<RecordingTools>,
}

fn runtime_fixture(rounds: Vec<Round>, config: RuntimeConfig) -> RuntimeFixture {
    let clock = FakeClock::new(0);
    let tools = RecordingTools::new(
        vec![guarded_tool("write_file")],
        vec![(
            "write_file",
            ToolBehaviour::Succeed {
                output: "written".to_owned(),
                changed_workspace: true,
            },
        )],
    );
    let runtime = Runtime::new(
        RuntimePorts {
            clock: Arc::clone(&clock) as Arc<_>,
            provider: ScriptedProvider::new(rounds) as Arc<_>,
            state: MemoryState::new() as Arc<_>,
            tools: Arc::clone(&tools) as Arc<_>,
            approvals: RecordingApprovals::new() as Arc<_>,
            goals: MemoryGoals::new() as Arc<_>,
            context: SimpleContext::new() as Arc<_>,
        },
        config,
    );
    RuntimeFixture {
        runtime,
        clock,
        tools,
    }
}

#[tokio::test]
async fn an_operator_denies_a_tool_through_the_command_surface() {
    let fixture = runtime_fixture(
        vec![
            tool_round("call-1", "write_file", "{}"),
            text_round("understood"),
        ],
        RuntimeConfig::default(),
    );
    let session_id = session("approval-deny");

    let handle = fixture
        .runtime
        .submit(&session_id, "write it")
        .await
        .expect("the turn is accepted");

    support::eventually("an approval to be outstanding", || {
        !fixture.runtime.approvals().outstanding().is_empty()
    })
    .await;
    let approval_id = fixture.runtime.approvals().outstanding()[0]
        .approval_id
        .clone();

    let answered = fixture
        .runtime
        .dispatch_command(
            &session_id,
            &format!("/deny {approval_id}"),
            ScopeSet::from_iter([OperatorScope::Approvals]),
        )
        .await
        .expect("the command is accepted");
    assert_eq!(answered, CommandOutcome::Acknowledged);

    let outcome = handle.join().await.expect("the turn finishes");
    assert_eq!(outcome.tool_outcomes.len(), 1);
    assert_eq!(outcome.tool_outcomes[0].status, ToolStatus::Denied);
    assert_eq!(outcome.tool_outcomes[0].output, "operator denied the call");
    assert_eq!(outcome.state, SessionState::Completed);
    assert_eq!(fixture.tools.invoked(), Vec::new());

    fixture.runtime.shutdown().await.expect("shutdown is clean");
}

#[tokio::test]
async fn an_unanswered_approval_times_out_the_tool_call() {
    let fixture = runtime_fixture(
        vec![
            tool_round("call-1", "write_file", "{}"),
            text_round("moving on"),
        ],
        RuntimeConfig {
            approval_timeout: Duration::from_secs(10),
            ..RuntimeConfig::default()
        },
    );
    let session_id = session("approval-timeout");

    let handle = fixture
        .runtime
        .submit(&session_id, "write it")
        .await
        .expect("the turn is accepted");

    support::eventually("an approval to be outstanding", || {
        !fixture.runtime.approvals().outstanding().is_empty()
    })
    .await;
    fixture.clock.advance(Duration::from_secs(10));

    let outcome = handle.join().await.expect("the turn finishes");
    assert_eq!(outcome.tool_outcomes[0].status, ToolStatus::TimedOut);
    assert_eq!(
        outcome.tool_outcomes[0].output,
        "no approval decision before the deadline"
    );
    assert_eq!(fixture.tools.invoked(), Vec::new());

    fixture.runtime.shutdown().await.expect("shutdown is clean");
}

#[tokio::test]
async fn answering_without_the_approvals_scope_is_refused() {
    let fixture = runtime_fixture(vec![text_round("hi")], RuntimeConfig::default());
    let session_id = session("approval-scope");

    let error = fixture
        .runtime
        .dispatch_command(
            &session_id,
            "/approve approval-1",
            ScopeSet::from_iter([OperatorScope::Read, OperatorScope::Write]),
        )
        .await
        .expect_err("the caller lacks the approvals scope");

    assert_eq!(
        error,
        RuntimeError::Command(CommandError::Unauthorized {
            command: "approve".to_owned(),
            required: OperatorScope::Approvals,
        })
    );

    fixture.runtime.shutdown().await.expect("shutdown is clean");
}

/// A caller that is cancelled hard enough to drop the future has no chance to run the withdraw
/// path inside `request`, so the broker must retract the entry itself. Otherwise the request stays
/// answerable forever and `resolve` would record an "always allow" memory for a call that no
/// longer exists.
///
/// The dismissal must reach the adapter *during the drop*, not at the next shutdown: until it
/// does, the prompt is still on the operator's screen and an abandoned request is indistinguishable
/// from a slow one.
#[tokio::test]
async fn a_dropped_request_retracts_itself_and_is_still_reported_to_the_adapter() {
    let clock = FakeClock::new(0);
    let approvals = RecordingApprovals::new();
    let broker = broker_over(&clock, &approvals, Duration::from_secs(30));
    let cancel = CancellationToken::new();
    let approval_id = ApprovalId::new("approval-1").expect("the test approval id is valid");

    let mut waiting = Box::pin(broker.request(ticket("write_file"), &cancel));
    assert!(
        support::poll_once(&mut waiting).is_pending(),
        "an unanswered request must park"
    );
    assert_eq!(
        broker
            .outstanding()
            .into_iter()
            .map(|request| request.approval_id)
            .collect::<Vec<_>>(),
        vec![approval_id.clone()]
    );
    assert_eq!(
        approvals.records(),
        vec![ApprovalRecord::Presented(approval_id.clone())],
        "nothing is dismissed while the request is still live"
    );

    // The waiter goes away without ever resolving the future.
    drop(waiting);

    // No await, no shutdown, no executor turn: the dismissal is already delivered.
    assert_eq!(
        approvals.records(),
        vec![
            ApprovalRecord::Presented(approval_id.clone()),
            ApprovalRecord::Abandoned(approval_id.clone()),
        ],
        "the adapter must be told inside the drop, not at the next shutdown"
    );

    assert!(
        broker.outstanding().is_empty(),
        "an abandoned request must not stay outstanding"
    );
    assert_eq!(
        broker
            .resolve(&approval_id, ApprovalDecision::approve_for_session())
            .expect_err("an abandoned request must not be answerable"),
        ApprovalError::Unknown(approval_id.clone())
    );
    assert_eq!(broker.remembered(&session("approvals"), "write_file"), None);

    // The broker keeps no orphan list, so a later shutdown adds nothing.
    broker
        .withdraw_all(ApprovalWithdrawal::Cancelled)
        .await
        .expect("the adapter accepts the withdrawal");
    assert_eq!(
        approvals.records(),
        vec![
            ApprovalRecord::Presented(approval_id.clone()),
            ApprovalRecord::Abandoned(approval_id),
        ],
        "an abandoned request must not be dismissed a second time"
    );
}

/// `request` registers nothing until it is first polled, so a future that is created and dropped
/// without ever being polled must leave no trace at all — not even a dismissal for a request the
/// adapter was never shown.
///
/// The first half of this test asserts an *absence*, which is the weakest shape a test can have: it
/// also passes when the fixture is incapable of recording anything, and it would keep passing if the
/// drop stopped being a real drop. The second half is therefore a positive control on the very same
/// broker and adapter — it polls a request, drops it, and requires the two records to appear. An
/// inert fixture or a drop that does nothing now fails the test instead of satisfying it.
#[tokio::test]
async fn a_request_dropped_before_its_first_poll_leaves_no_trace() {
    let clock = FakeClock::new(0);
    let approvals = RecordingApprovals::new();
    let broker = broker_over(&clock, &approvals, Duration::from_secs(30));
    let cancel = CancellationToken::new();

    let waiting = broker.request(ticket("write_file"), &cancel);
    drop(waiting);

    assert_eq!(
        approvals.records(),
        Vec::new(),
        "a never-polled request was never presented, so it must not be dismissed"
    );
    assert!(broker.outstanding().is_empty());

    // Positive control: the same fixture, one poll further on, must produce records.
    let mut polled = Box::pin(broker.request(ticket("write_file"), &cancel));
    assert!(
        support::poll_once(&mut polled).is_pending(),
        "an unanswered request must park"
    );
    let approval_id = ApprovalId::new("approval-1").expect("the test approval id is valid");
    assert_eq!(
        approvals.records(),
        vec![ApprovalRecord::Presented(approval_id.clone())],
        "polling must present, or the absence asserted above proves nothing"
    );
    drop(polled);
    assert_eq!(
        approvals.records(),
        vec![
            ApprovalRecord::Presented(approval_id.clone()),
            ApprovalRecord::Abandoned(approval_id),
        ],
        "dropping a polled request must dismiss it, or the drop above was not a real drop"
    );
}

/// An adapter that calls straight back into the broker from `abandon`.
///
/// A surface dismissing a prompt will plausibly ask what is still outstanding in order to redraw
/// itself. `abandon` runs inside `Drop`, which the broker reaches while it is mutating its own
/// state, so this is only safe if the broker has released its lock first.
struct ReentrantApprovals {
    broker: Mutex<Option<ApprovalBroker>>,
    observed: Mutex<Vec<usize>>,
}

impl ReentrantApprovals {
    fn new() -> Arc<Self> {
        Arc::new(Self {
            broker: Mutex::new(None),
            observed: Mutex::new(Vec::new()),
        })
    }

    fn attach(&self, broker: ApprovalBroker) {
        *self.broker.lock().expect("the fixture mutex is healthy") = Some(broker);
    }

    /// How many requests the broker reported as outstanding during each `abandon` call.
    fn observed(&self) -> Vec<usize> {
        self.observed
            .lock()
            .expect("the fixture mutex is healthy")
            .clone()
    }
}

impl ApprovalPort for ReentrantApprovals {
    fn present(&self, _request: ApprovalRequest) -> PortFuture<'_, Result<(), PortError>> {
        Box::pin(async move { Ok(()) })
    }

    fn settle(&self, _approval_id: &ApprovalId) -> PortFuture<'_, Result<(), PortError>> {
        Box::pin(async move { Ok(()) })
    }

    fn withdraw(
        &self,
        _approval_id: &ApprovalId,
        _reason: ApprovalWithdrawal,
    ) -> PortFuture<'_, Result<(), PortError>> {
        Box::pin(async move { Ok(()) })
    }

    fn abandon(&self, _approval_id: &ApprovalId) {
        // The fixture's own lock is released before the observation is recorded, so the two
        // fixture mutexes are never held at the same time.
        let outstanding = {
            let broker = self.broker.lock().expect("the fixture mutex is healthy");
            broker
                .as_ref()
                .expect("the broker is attached before any request")
                .outstanding()
                .len()
        };
        self.observed
            .lock()
            .expect("the fixture mutex is healthy")
            .push(outstanding);
    }
}

/// Regression: the broker must not hold its state lock while calling `abandon`.
///
/// The drop runs on a dedicated thread. A `std::sync::Mutex` deadlock blocks whichever thread
/// hits it, so waiting for it on the test's own thread would hang — and so would a
/// `tokio::time::timeout`, because the executor driving that timeout is the very thread that is
/// stuck. Only an out-of-band wait can turn this regression into a failure instead of a hang.
#[test]
fn abandoning_a_request_does_not_hold_the_broker_lock() {
    let (sender, receiver) = mpsc::channel();

    std::thread::spawn(move || {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("the test runtime builds");
        runtime.block_on(async move {
            let clock = FakeClock::new(0);
            let approvals = ReentrantApprovals::new();
            let broker = ApprovalBroker::new(
                Arc::clone(&approvals) as Arc<_>,
                Arc::clone(&clock) as Arc<_>,
                Duration::from_secs(30),
            );
            approvals.attach(broker.clone());
            let cancel = CancellationToken::new();

            let mut waiting = Box::pin(broker.request(ticket("write_file"), &cancel));
            assert!(
                support::poll_once(&mut waiting).is_pending(),
                "an unanswered request must park"
            );

            drop(waiting);
            let _ = sender.send(approvals.observed());
        });
    });

    let observed = receiver
        .recv_timeout(Duration::from_secs(10))
        .expect("dropping the request deadlocked against the broker's own lock");
    assert_eq!(
        observed,
        vec![0],
        "the entry must already be removed when the adapter is called, so the surface never sees \
         a request it has just been told is gone"
    );
}

#[tokio::test]
async fn an_answered_request_is_not_reported_twice_when_its_future_is_dropped_afterwards() {
    let clock = FakeClock::new(0);
    let approvals = RecordingApprovals::new();
    let broker = broker_over(&clock, &approvals, Duration::from_secs(30));
    let cancel = CancellationToken::new();
    let approval_id = ApprovalId::new("approval-1").expect("the test approval id is valid");

    let mut waiting = Box::pin(broker.request(ticket("write_file"), &cancel));
    assert!(
        support::poll_once(&mut waiting).is_pending(),
        "an unanswered request must park"
    );

    broker
        .resolve(&approval_id, ApprovalDecision::approve_once())
        .expect("the request is outstanding");

    let outcome = waiting.await.expect("the decision is delivered");
    assert_eq!(
        outcome,
        ApprovalOutcome::Decided {
            decision: ApprovalDecision::approve_once(),
            remembered: false,
        }
    );

    broker
        .withdraw_all(ApprovalWithdrawal::Cancelled)
        .await
        .expect("the adapter accepts the withdrawal");
    assert_eq!(
        approvals.records(),
        vec![
            ApprovalRecord::Presented(approval_id.clone()),
            ApprovalRecord::Settled(approval_id),
        ]
    );
}

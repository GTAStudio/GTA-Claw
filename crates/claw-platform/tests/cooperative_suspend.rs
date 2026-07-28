//! Integration coverage for cooperative host suspension.
//!
//! Every dimension the frozen upstream contract requires of
//! `gateway.suspend.*` is exercised here through the public API only:
//! preparation, the busy refusal, lease expiry, status, resume and the
//! draining behaviour of a fenced host.
//!
//! Time is injected, so nothing in this file sleeps.

use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};

use claw_platform::suspend::{
    ActiveWorkCounts, ActiveWorkInspector, AdmissionPhase, Blocker, BlockerKind, BusyReason, Clock,
    ManualClock, PrepareOutcome, RefusalReason, ResumeOutcome, RootWorkLease,
    SCHEDULER_RECOVERY_RETRY_MS, SUSPEND_CONTROL_METHODS, SUSPEND_RETRY_AFTER_MS, SUSPEND_TTL_MS,
    Scheduler, SchedulerError, StatusOutcome, SuspendCoordinator, SuspensionIds, TaskBlocker,
    TaskRuntime, WorkAdmission, is_method_allowed_during_suspension,
};

const TTL_MS: u64 = 60_000;
const START_MS: u64 = 1_700_000_000_000;

fn lock<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    mutex.lock().unwrap_or_else(PoisonError::into_inner)
}

/// A scheduler that records every call and can be told to fail.
#[derive(Debug, Default)]
struct RecordingScheduler {
    events: Mutex<Vec<&'static str>>,
    pause_failures: AtomicUsize,
    resume_failures: AtomicUsize,
}

impl RecordingScheduler {
    fn events(&self) -> Vec<&'static str> {
        lock(&self.events).clone()
    }

    fn fail_next_pauses(&self, count: usize) {
        self.pause_failures.store(count, Ordering::SeqCst);
    }

    fn fail_next_resumes(&self, count: usize) {
        self.resume_failures.store(count, Ordering::SeqCst);
    }

    fn is_paused(&self) -> bool {
        let events = lock(&self.events);
        let paused = events.iter().filter(|event| **event == "pause").count();
        let resumed = events.iter().filter(|event| **event == "resume").count();
        drop(events);
        paused > resumed
    }

    fn take_failure(counter: &AtomicUsize) -> bool {
        counter
            .fetch_update(Ordering::SeqCst, Ordering::SeqCst, |remaining| {
                remaining.checked_sub(1)
            })
            .is_ok()
    }
}

impl Scheduler for RecordingScheduler {
    fn pause(&self) -> Result<(), SchedulerError> {
        if Self::take_failure(&self.pause_failures) {
            lock(&self.events).push("pause-failed");
            return Err(SchedulerError::new("scheduler refused to pause"));
        }
        lock(&self.events).push("pause");
        Ok(())
    }

    fn resume(&self) -> Result<(), SchedulerError> {
        if Self::take_failure(&self.resume_failures) {
            lock(&self.events).push("resume-failed");
            return Err(SchedulerError::new("scheduler refused to resume"));
        }
        lock(&self.events).push("resume");
        Ok(())
    }
}

/// An inspector a test drives directly.
#[derive(Debug, Default)]
struct StubInspector {
    counts: Mutex<ActiveWorkCounts>,
    tasks: Mutex<Vec<TaskBlocker>>,
}

impl StubInspector {
    fn set_counts(&self, counts: ActiveWorkCounts) {
        *lock(&self.counts) = counts;
    }

    fn set_tasks(&self, tasks: Vec<TaskBlocker>) {
        *lock(&self.tasks) = tasks;
    }
}

impl ActiveWorkInspector for StubInspector {
    fn counts(&self) -> ActiveWorkCounts {
        *lock(&self.counts)
    }

    fn task_blockers(&self) -> Vec<TaskBlocker> {
        lock(&self.tasks).clone()
    }
}

/// An inspector that counts admitted root requests the way a real host does:
/// every outstanding lease except the request running the preparation.
#[derive(Debug)]
struct RootRequestInspector {
    admission: Arc<WorkAdmission>,
    preparing: RootWorkLease,
}

impl ActiveWorkInspector for RootRequestInspector {
    fn counts(&self) -> ActiveWorkCounts {
        ActiveWorkCounts {
            root_requests: self.admission.active_root_work_excluding(&self.preparing),
            ..ActiveWorkCounts::default()
        }
    }
}

/// Deterministic identifiers, so assertions can name a lease.
#[derive(Debug, Default)]
struct SequentialIds {
    counter: AtomicU64,
}

impl SuspensionIds for SequentialIds {
    fn next_id(&self) -> String {
        format!(
            "suspension-{}",
            self.counter.fetch_add(1, Ordering::SeqCst) + 1
        )
    }
}

struct Harness {
    admission: Arc<WorkAdmission>,
    scheduler: Arc<RecordingScheduler>,
    inspector: Arc<StubInspector>,
    clock: ManualClock,
    coordinator: SuspendCoordinator,
}

fn harness() -> Harness {
    let admission = Arc::new(WorkAdmission::new());
    let scheduler = Arc::new(RecordingScheduler::default());
    let inspector = Arc::new(StubInspector::default());
    let clock = ManualClock::new(START_MS);
    let coordinator = SuspendCoordinator::new(
        Arc::clone(&admission),
        Arc::clone(&scheduler) as Arc<dyn Scheduler>,
        Arc::clone(&inspector) as Arc<dyn ActiveWorkInspector>,
    )
    .with_clock(Arc::new(clock.clone()))
    .with_suspension_ids(Arc::new(SequentialIds::default()))
    .with_ttl_ms(TTL_MS);

    Harness {
        admission,
        scheduler,
        inspector,
        clock,
        coordinator,
    }
}

fn expect_ready(outcome: PrepareOutcome) -> (String, u64) {
    match outcome {
        PrepareOutcome::Ready {
            suspension_id,
            expires_at_ms,
            active_count,
            blockers,
        } => {
            assert_eq!(active_count, 0, "a fenced host reports no active work");
            assert!(blockers.is_empty(), "a fenced host reports no blockers");
            (suspension_id, expires_at_ms)
        }
        other => panic!("expected a ready preparation, got {other:?}"),
    }
}

// ---------------------------------------------------------------- prepare ---

#[test]
fn prepare_fences_an_idle_host_and_hands_out_a_lease() {
    let harness = harness();

    let outcome = harness.coordinator.prepare("request-1");

    assert_eq!(outcome.as_str(), "ready");
    let (suspension_id, expires_at_ms) = expect_ready(outcome);
    assert_eq!(suspension_id, "suspension-1");
    assert_eq!(expires_at_ms, START_MS + TTL_MS);
    assert_eq!(harness.scheduler.events(), vec!["pause"]);
    assert_eq!(harness.admission.phase(), AdmissionPhase::Prepared);
    assert!(harness.admission.is_closed());
}

#[test]
fn prepare_renews_the_same_request_without_disturbing_the_host() {
    let harness = harness();
    let (first_id, first_expiry) = expect_ready(harness.coordinator.prepare("request-1"));

    harness.clock.advance(TTL_MS / 2);
    let (second_id, second_expiry) = expect_ready(harness.coordinator.prepare("request-1"));

    assert_eq!(second_id, first_id, "a renewal keeps the same lease");
    assert_eq!(second_expiry, first_expiry + TTL_MS / 2);
    assert_eq!(
        harness.scheduler.events(),
        vec!["pause"],
        "a renewal must not pause an already paused scheduler"
    );
    assert_eq!(
        harness.coordinator.status(&first_id),
        StatusOutcome::Ready {
            expires_at_ms: second_expiry
        }
    );
}

#[test]
fn prepare_refuses_a_second_request_while_a_lease_is_held() {
    let harness = harness();
    let (_, expires_at_ms) = expect_ready(harness.coordinator.prepare("request-1"));

    let outcome = harness.coordinator.prepare("request-2");

    assert_eq!(outcome, PrepareOutcome::Conflict { expires_at_ms });
    assert_eq!(harness.admission.phase(), AdmissionPhase::Prepared);
}

#[test]
fn the_preparing_request_does_not_count_itself_but_a_peer_request_does() {
    let admission = Arc::new(WorkAdmission::new());
    let scheduler = Arc::new(RecordingScheduler::default());
    let preparing = admission
        .try_begin_root_work()
        .expect("an open fence admits the preparing request");
    let coordinator = SuspendCoordinator::new(
        Arc::clone(&admission),
        Arc::clone(&scheduler) as Arc<dyn Scheduler>,
        Arc::new(RootRequestInspector {
            admission: Arc::clone(&admission),
            preparing,
        }),
    );

    let ready = coordinator.prepare("request-1");
    assert_eq!(ready.as_str(), "ready");
    let suspension_id = ready
        .suspension_id()
        .expect("a ready preparation names its lease")
        .to_owned();
    assert_eq!(coordinator.resume(&suspension_id), ResumeOutcome::Resumed);

    let peer = admission
        .try_begin_root_work()
        .expect("the reopened fence admits a peer request");
    let busy = coordinator.prepare("request-1");

    assert_eq!(busy.as_str(), "busy");
    assert_eq!(busy.blockers().len(), 1);
    assert_eq!(busy.blockers()[0].kind(), BlockerKind::RootRequest);
    assert_eq!(busy.blockers()[0].message(), "1 active gateway request(s)");
    drop(peer);
}

// ------------------------------------------------------------------- busy ---

#[test]
fn prepare_reports_busy_with_every_blocker_while_work_is_in_flight() {
    let harness = harness();
    harness.inspector.set_counts(ActiveWorkCounts {
        queue_size: 2,
        embedded_runs: 1,
        active_tasks: 1,
        ..ActiveWorkCounts::default()
    });
    harness.inspector.set_tasks(vec![
        TaskBlocker::new("task-7", TaskRuntime::Subagent)
            .with_run_id("run-3")
            .with_label("indexing"),
    ]);

    let outcome = harness.coordinator.prepare("request-1");

    match outcome {
        PrepareOutcome::Busy {
            reason,
            retry_after_ms,
            active_count,
            blockers,
        } => {
            assert_eq!(reason, BusyReason::ActiveWork);
            assert_eq!(reason.as_str(), "active-work");
            assert_eq!(retry_after_ms, SUSPEND_RETRY_AFTER_MS);
            assert_eq!(active_count, 4);
            let messages: Vec<&str> = blockers.iter().map(Blocker::message).collect();
            assert_eq!(
                messages,
                vec![
                    "2 queued or active operation(s)",
                    "1 active embedded run(s)",
                    "taskId=task-7 runId=run-3 status=running runtime=subagent label=indexing",
                ]
            );
            assert_eq!(blockers[2].kind(), BlockerKind::Task);
            assert_eq!(
                blockers[2].task().map(TaskBlocker::task_id),
                Some("task-7"),
                "a task blocker carries its task detail"
            );
        }
        other => panic!("expected a busy preparation, got {other:?}"),
    }

    assert_eq!(
        harness.scheduler.events(),
        vec!["pause", "resume"],
        "a refused preparation must leave the scheduler running"
    );
    assert!(!harness.scheduler.is_paused());
    assert_eq!(harness.admission.phase(), AdmissionPhase::Accepting);
    assert!(
        harness.admission.try_begin_root_work().is_ok(),
        "a refused preparation must leave the host serving"
    );
}

#[test]
fn prepare_reports_busy_while_the_host_is_draining_for_restart() {
    let harness = harness();
    harness.admission.mark_restart_draining();

    let outcome = harness.coordinator.prepare("request-1");

    match outcome {
        PrepareOutcome::Busy {
            reason,
            retry_after_ms,
            ..
        } => {
            assert_eq!(reason, BusyReason::GatewayDraining);
            assert_eq!(reason.as_str(), "gateway-draining");
            assert_eq!(retry_after_ms, SUSPEND_RETRY_AFTER_MS);
        }
        other => panic!("expected a draining refusal, got {other:?}"),
    }

    assert!(
        harness.scheduler.events().is_empty(),
        "a host that is already draining must not be paused again"
    );
}

#[test]
fn a_failed_pause_refuses_the_preparation_and_reopens_the_fence() {
    let harness = harness();
    harness.scheduler.fail_next_pauses(1);

    let outcome = harness.coordinator.prepare("request-1");

    assert_eq!(
        outcome,
        PrepareOutcome::Recovering {
            retry_after_ms: SCHEDULER_RECOVERY_RETRY_MS
        }
    );
    assert_eq!(harness.admission.phase(), AdmissionPhase::Accepting);
    assert!(!harness.coordinator.is_recovering());
    assert!(harness.admission.try_begin_root_work().is_ok());
    assert_eq!(harness.coordinator.prepare("request-1").as_str(), "ready");
}

// ----------------------------------------------------------- lease expiry ---

#[test]
fn an_abandoned_lease_expires_and_reopens_the_host() {
    let harness = harness();
    let (suspension_id, expires_at_ms) = expect_ready(harness.coordinator.prepare("request-1"));

    harness.clock.set(expires_at_ms - 1);
    assert_eq!(
        harness.coordinator.status(&suspension_id),
        StatusOutcome::Ready { expires_at_ms },
        "the lease is alive right up to its deadline"
    );
    assert!(harness.admission.try_begin_root_work().is_err());

    harness.clock.set(expires_at_ms);

    assert_eq!(
        harness.coordinator.status(&suspension_id),
        StatusOutcome::Running,
        "the deadline itself expires the lease"
    );
    assert_eq!(harness.scheduler.events(), vec!["pause", "resume"]);
    assert!(!harness.scheduler.is_paused());
    assert_eq!(harness.admission.phase(), AdmissionPhase::Accepting);
    assert!(harness.admission.try_begin_root_work().is_ok());
}

#[test]
fn expiry_is_measured_from_the_latest_renewal() {
    let harness = harness();
    let (suspension_id, first_expiry) = expect_ready(harness.coordinator.prepare("request-1"));

    harness.clock.set(first_expiry - 1);
    let (_, renewed_expiry) = expect_ready(harness.coordinator.prepare("request-1"));
    harness.clock.set(first_expiry);

    assert_eq!(
        harness.coordinator.status(&suspension_id),
        StatusOutcome::Ready {
            expires_at_ms: renewed_expiry
        },
        "a renewal moves the deadline forward"
    );

    harness.clock.set(renewed_expiry);

    assert_eq!(
        harness.coordinator.status(&suspension_id),
        StatusOutcome::Running
    );
}

#[test]
fn expiry_can_be_driven_without_an_inbound_request() {
    let harness = harness();
    let (_, expires_at_ms) = expect_ready(harness.coordinator.prepare("request-1"));

    harness.clock.set(expires_at_ms);
    assert!(harness.coordinator.poll());

    assert_eq!(harness.admission.phase(), AdmissionPhase::Accepting);
    assert_eq!(harness.scheduler.events(), vec!["pause", "resume"]);
}

#[test]
fn the_default_lease_lifetime_matches_the_upstream_contract() {
    let coordinator = SuspendCoordinator::new(
        Arc::new(WorkAdmission::new()),
        Arc::new(RecordingScheduler::default()),
        Arc::new(StubInspector::default()),
    );

    assert_eq!(coordinator.ttl_ms(), SUSPEND_TTL_MS);
    assert_eq!(SUSPEND_TTL_MS, 120_000);
}

// ----------------------------------------------------------------- status ---

#[test]
fn status_follows_the_suspension_through_every_phase() {
    let harness = harness();

    assert_eq!(
        harness.coordinator.status("suspension-1"),
        StatusOutcome::Running,
        "an unprepared host is running"
    );

    let (suspension_id, expires_at_ms) = expect_ready(harness.coordinator.prepare("request-1"));

    assert_eq!(
        harness.coordinator.status(&suspension_id),
        StatusOutcome::Ready { expires_at_ms }
    );
    assert_eq!(
        harness.coordinator.status("someone-elses-suspension"),
        StatusOutcome::Conflict { expires_at_ms },
        "a stale controller must not read another lease as its own"
    );
    assert_eq!(harness.coordinator.status(&suspension_id).as_str(), "ready");

    assert_eq!(
        harness.coordinator.resume(&suspension_id),
        ResumeOutcome::Resumed
    );

    assert_eq!(
        harness.coordinator.status(&suspension_id),
        StatusOutcome::Running,
        "a resumed lease is gone"
    );
}

// ----------------------------------------------------------------- resume ---

#[test]
fn resume_reopens_the_host_and_is_idempotent() {
    let harness = harness();
    let (suspension_id, _) = expect_ready(harness.coordinator.prepare("request-1"));

    let resumed = harness.coordinator.resume(&suspension_id);

    assert_eq!(resumed, ResumeOutcome::Resumed);
    assert_eq!(resumed.resumed(), Some(true));
    assert_eq!(harness.scheduler.events(), vec!["pause", "resume"]);
    assert!(!harness.scheduler.is_paused());
    assert_eq!(harness.admission.phase(), AdmissionPhase::Accepting);
    assert!(harness.admission.try_begin_root_work().is_ok());

    let again = harness.coordinator.resume(&suspension_id);

    assert_eq!(again, ResumeOutcome::AlreadyRunning);
    assert_eq!(again.resumed(), Some(false));
    assert!(again.is_running());
    assert_eq!(
        harness.scheduler.events(),
        vec!["pause", "resume"],
        "resuming twice must not resume the scheduler twice"
    );
}

#[test]
fn resume_refuses_an_identifier_it_does_not_own() {
    let harness = harness();
    let (suspension_id, _) = expect_ready(harness.coordinator.prepare("request-1"));

    let outcome = harness.coordinator.resume("suspension-999");

    assert_eq!(outcome, ResumeOutcome::Mismatch);
    assert_eq!(outcome.resumed(), None);
    assert!(!outcome.is_running());
    assert_eq!(
        harness.admission.phase(),
        AdmissionPhase::Prepared,
        "a mismatched resume must not release someone else's lease"
    );
    assert_eq!(
        harness.coordinator.resume(&suspension_id),
        ResumeOutcome::Resumed
    );
}

#[test]
fn a_host_can_be_suspended_again_after_it_resumes() {
    let harness = harness();
    let (first_id, _) = expect_ready(harness.coordinator.prepare("request-1"));
    assert_eq!(
        harness.coordinator.resume(&first_id),
        ResumeOutcome::Resumed
    );

    harness.clock.advance(1_000);
    let (second_id, second_expiry) = expect_ready(harness.coordinator.prepare("request-2"));

    assert_ne!(second_id, first_id);
    assert_eq!(second_expiry, START_MS + 1_000 + TTL_MS);
    assert_eq!(harness.scheduler.events(), vec!["pause", "resume", "pause"]);
    assert_eq!(harness.admission.phase(), AdmissionPhase::Prepared);
}

// --------------------------------------------------------------- draining ---

#[test]
fn a_prepared_host_refuses_new_work_but_keeps_answering_suspend_control() {
    let harness = harness();
    let admitted_before = harness
        .admission
        .try_begin_root_work()
        .expect("work admitted before the fence closes");
    harness.inspector.set_counts(ActiveWorkCounts {
        root_requests: 0,
        ..ActiveWorkCounts::default()
    });
    let (suspension_id, _) = expect_ready(harness.coordinator.prepare("request-1"));

    let refusal = harness
        .admission
        .try_begin_root_work()
        .expect_err("a prepared host refuses new root work");

    assert_eq!(refusal.reason(), RefusalReason::GatewaySuspending);
    assert_eq!(refusal.reason().as_str(), "gateway-suspending");
    assert!(refusal.reason().is_reversible());
    assert_eq!(refusal.phase(), AdmissionPhase::Prepared);
    assert_eq!(refusal.phase().as_str(), "prepared");
    assert_eq!(refusal.retry_after_ms(), 1_000);
    for method in SUSPEND_CONTROL_METHODS {
        assert!(
            is_method_allowed_during_suspension(method),
            "{method} must survive the fence"
        );
    }
    assert!(!is_method_allowed_during_suspension("send"));

    assert_eq!(
        harness.admission.active_root_work(),
        1,
        "work admitted before the fence closed keeps running"
    );
    drop(admitted_before);
    assert_eq!(harness.admission.active_root_work(), 0);

    assert_eq!(
        harness.coordinator.resume(&suspension_id),
        ResumeOutcome::Resumed
    );
    assert!(harness.admission.try_begin_root_work().is_ok());
}

#[test]
fn a_restart_supersedes_a_prepared_suspension_without_resuming_the_scheduler() {
    let harness = harness();
    let (suspension_id, _) = expect_ready(harness.coordinator.prepare("request-1"));

    harness.admission.mark_restart_draining();

    assert_eq!(
        harness.coordinator.status(&suspension_id),
        StatusOutcome::Running,
        "a superseded lease is no longer owned"
    );
    assert_eq!(
        harness.coordinator.resume(&suspension_id),
        ResumeOutcome::AlreadyRunning
    );
    assert_eq!(
        harness.scheduler.events(),
        vec!["pause"],
        "a host being restarted must not have its scheduler restarted"
    );
    let refusal = harness
        .admission
        .try_begin_root_work()
        .expect_err("a draining host refuses root work");
    assert_eq!(refusal.reason(), RefusalReason::GatewayRestarting);
    assert!(!refusal.reason().is_reversible());
}

#[test]
fn a_scheduler_that_cannot_resume_holds_the_fence_closed_until_it_recovers() {
    let harness = harness();
    let (suspension_id, _) = expect_ready(harness.coordinator.prepare("request-1"));
    harness.scheduler.fail_next_resumes(1);

    let outcome = harness.coordinator.resume(&suspension_id);

    assert_eq!(
        outcome,
        ResumeOutcome::Recovering {
            retry_after_ms: SCHEDULER_RECOVERY_RETRY_MS
        }
    );
    assert!(harness.coordinator.is_recovering());
    assert_eq!(
        harness.admission.phase(),
        AdmissionPhase::Prepared,
        "a host that cannot be driven stays fenced"
    );
    assert!(harness.admission.try_begin_root_work().is_err());
    assert_eq!(
        harness.coordinator.prepare("request-2"),
        PrepareOutcome::Recovering {
            retry_after_ms: SCHEDULER_RECOVERY_RETRY_MS
        }
    );
    assert_eq!(
        harness.coordinator.status(&suspension_id),
        StatusOutcome::Recovering {
            retry_after_ms: SCHEDULER_RECOVERY_RETRY_MS
        }
    );

    assert_eq!(
        harness.scheduler.events(),
        vec!["pause", "resume-failed"],
        "recovery backs off instead of hammering a wedged scheduler"
    );
    assert!(!harness.coordinator.poll(), "the backoff has not elapsed");

    harness.clock.advance(SCHEDULER_RECOVERY_RETRY_MS);

    assert!(harness.coordinator.poll(), "the retry succeeds");
    assert!(!harness.coordinator.is_recovering());
    assert_eq!(harness.admission.phase(), AdmissionPhase::Accepting);
    assert!(harness.admission.try_begin_root_work().is_ok());
    assert_eq!(
        harness.scheduler.events(),
        vec!["pause", "resume-failed", "resume"]
    );
}

#[test]
fn a_restart_stops_a_pending_scheduler_recovery_instead_of_restarting_the_host() {
    let harness = harness();
    let (suspension_id, _) = expect_ready(harness.coordinator.prepare("request-1"));
    harness.scheduler.fail_next_resumes(1);
    assert_eq!(
        harness.coordinator.resume(&suspension_id),
        ResumeOutcome::Recovering {
            retry_after_ms: SCHEDULER_RECOVERY_RETRY_MS
        }
    );
    assert!(harness.coordinator.is_recovering());

    harness.admission.mark_restart_draining();
    harness.clock.advance(SCHEDULER_RECOVERY_RETRY_MS);

    assert!(
        harness.coordinator.poll(),
        "a superseded recovery is retired rather than left pending"
    );
    assert!(!harness.coordinator.is_recovering());
    assert_eq!(
        harness.scheduler.events(),
        vec!["pause", "resume-failed"],
        "a host being restarted must not have its scheduler restarted, and the retry \
         must stop rather than poke a wedged scheduler for the rest of the process"
    );
    assert!(harness.scheduler.is_paused());
    let refusal = harness
        .admission
        .try_begin_root_work()
        .expect_err("a draining host refuses root work");
    assert_eq!(refusal.reason(), RefusalReason::GatewayRestarting);

    harness.clock.advance(SCHEDULER_RECOVERY_RETRY_MS);
    assert!(harness.coordinator.poll());
    assert_eq!(
        harness.scheduler.events(),
        vec!["pause", "resume-failed"],
        "a retired recovery must not resume the scheduler on a later poll either"
    );
}

#[test]
fn a_refused_preparation_whose_scheduler_will_not_resume_still_reopens_the_fence() {
    let harness = harness();
    harness.inspector.set_counts(ActiveWorkCounts {
        queue_size: 1,
        ..ActiveWorkCounts::default()
    });
    harness.scheduler.fail_next_resumes(1);

    let outcome = harness.coordinator.prepare("request-1");

    assert_eq!(
        outcome,
        PrepareOutcome::Recovering {
            retry_after_ms: SCHEDULER_RECOVERY_RETRY_MS
        },
        "a preparation that cannot restart the scheduler must not report busy"
    );
    assert!(harness.coordinator.is_recovering());
    assert_eq!(
        harness.admission.phase(),
        AdmissionPhase::Preparing,
        "the fence stays closed while the host cannot be driven"
    );
    assert!(harness.admission.try_begin_root_work().is_err());

    harness.clock.advance(SCHEDULER_RECOVERY_RETRY_MS);

    assert!(harness.coordinator.poll(), "the retry succeeds");
    assert!(!harness.coordinator.is_recovering());
    assert_eq!(
        harness.admission.phase(),
        AdmissionPhase::Accepting,
        "a lease that never reached `prepared` still reopens the fence"
    );
    assert!(harness.admission.try_begin_root_work().is_ok());
    assert_eq!(
        harness.scheduler.events(),
        vec!["pause", "resume-failed", "resume"]
    );
    assert!(!harness.scheduler.is_paused());
}

#[test]
fn concurrent_preparations_hand_out_exactly_one_lease() {
    let harness = harness();
    let coordinator = &harness.coordinator;

    let outcomes: Vec<PrepareOutcome> = std::thread::scope(|scope| {
        // The `collect` is load-bearing: it starts all eight threads before the
        // first `join`. Feeding the `spawn` iterator straight into `join` would
        // run one preparation at a time and the race this test exists to
        // observe could never happen.
        #[expect(
            clippy::needless_collect,
            reason = "collecting the handles is what makes the eight preparations concurrent"
        )]
        let handles: Vec<_> = (0..8)
            .map(|index| scope.spawn(move || coordinator.prepare(&format!("request-{index}"))))
            .collect();
        handles
            .into_iter()
            .map(|handle| handle.join().expect("a preparation thread"))
            .collect()
    });

    let ready: Vec<&PrepareOutcome> = outcomes
        .iter()
        .filter(|outcome| matches!(outcome, PrepareOutcome::Ready { .. }))
        .collect();

    assert_eq!(ready.len(), 1, "exactly one preparation may win");
    for outcome in &outcomes {
        assert!(
            matches!(
                outcome,
                PrepareOutcome::Ready { .. }
                    | PrepareOutcome::Conflict { .. }
                    | PrepareOutcome::Busy {
                        reason: BusyReason::GatewayDraining,
                        ..
                    }
            ),
            "a loser must be told to retry, got {outcome:?}"
        );
    }

    let suspension_id = ready[0]
        .suspension_id()
        .expect("the winning preparation names its lease");
    assert_eq!(harness.admission.phase(), AdmissionPhase::Prepared);
    assert_eq!(
        harness.coordinator.resume(suspension_id),
        ResumeOutcome::Resumed
    );
    assert_eq!(harness.admission.phase(), AdmissionPhase::Accepting);
    assert_eq!(harness.clock.now_ms(), START_MS);
}

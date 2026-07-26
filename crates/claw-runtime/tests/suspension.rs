//! Cooperative host suspension tests.

mod support;

use std::sync::Arc;
use std::time::Duration;

use claw_application::model::ids::LeaseId;
use claw_application::model::time::Timestamp;
use claw_runtime::suspend::{
    PrepareOutcome, PrepareRequest, SuspendError, SuspendLease, SuspensionController,
    SuspensionPhase, SuspensionStatus, WorkRefused,
};

use std::task::Poll;

use support::{FakeClock, poll_once};

fn lease(name: &str) -> LeaseId {
    LeaseId::new(name).expect("the test lease id is valid")
}

fn request(name: &str, drain: Duration, ttl: Duration) -> PrepareRequest {
    PrepareRequest {
        lease_id: lease(name),
        reason: "host update".to_owned(),
        drain_timeout: drain,
        lease_ttl: ttl,
    }
}

#[tokio::test]
async fn an_idle_runtime_suspends_immediately_and_refuses_new_work() {
    let clock = FakeClock::new(5_000);
    let controller = SuspensionController::new(Arc::clone(&clock) as Arc<_>);

    let outcome = controller
        .prepare(request(
            "lease-a",
            Duration::from_secs(10),
            Duration::from_secs(60),
        ))
        .await
        .expect("an idle runtime suspends");

    assert_eq!(
        outcome,
        PrepareOutcome::Suspended(SuspendLease {
            lease_id: lease("lease-a"),
            reason: "host update".to_owned(),
            granted_at: Timestamp::from_millis(5_000),
            expires_at: Timestamp::from_millis(65_000),
        })
    );
    assert_eq!(
        controller.admit().expect_err("no work is admitted"),
        WorkRefused {
            phase: SuspensionPhase::Suspended
        }
    );
    assert_eq!(
        controller.status(),
        SuspensionStatus {
            phase: SuspensionPhase::Suspended,
            in_flight: 0,
            lease: Some(SuspendLease {
                lease_id: lease("lease-a"),
                reason: "host update".to_owned(),
                granted_at: Timestamp::from_millis(5_000),
                expires_at: Timestamp::from_millis(65_000),
            }),
            observed_at: Timestamp::from_millis(5_000),
        }
    );

    let resumed = controller
        .resume(&lease("lease-a"))
        .expect("the lease owns");
    assert_eq!(resumed.phase, SuspensionPhase::Active);
    assert_eq!(resumed.lease, None);
    controller.admit().expect("work flows again");
}

#[tokio::test]
async fn a_prepare_waits_for_in_flight_work_and_completes_when_the_permit_drops() {
    let clock = FakeClock::new(0);
    let controller = SuspensionController::new(Arc::clone(&clock) as Arc<_>);
    let permit = controller.admit().expect("the runtime is active");
    assert_eq!(controller.status().in_flight, 1);

    let preparing = {
        let controller = controller.clone();
        tokio::spawn(async move {
            controller
                .prepare(request(
                    "lease-b",
                    Duration::from_secs(30),
                    Duration::from_secs(60),
                ))
                .await
        })
    };

    support::eventually("the controller to start draining", || {
        controller.status().phase == SuspensionPhase::Draining
    })
    .await;
    assert_eq!(
        controller.admit().expect_err("draining refuses new work"),
        WorkRefused {
            phase: SuspensionPhase::Draining
        }
    );

    drop(permit);

    let outcome = preparing
        .await
        .expect("the prepare task finishes")
        .expect("the prepare succeeds");
    match outcome {
        PrepareOutcome::Suspended(granted) => assert_eq!(granted.lease_id, lease("lease-b")),
        PrepareOutcome::DrainTimedOut { in_flight } => {
            panic!("expected a suspension, work still in flight: {in_flight}")
        }
    }
    assert_eq!(controller.status().phase, SuspensionPhase::Suspended);
}

#[tokio::test]
async fn work_that_never_finishes_makes_the_drain_time_out_and_the_runtime_stays_active() {
    let clock = FakeClock::new(0);
    let controller = SuspensionController::new(Arc::clone(&clock) as Arc<_>);
    let _permit = controller.admit().expect("the runtime is active");

    let preparing = {
        let controller = controller.clone();
        tokio::spawn(async move {
            controller
                .prepare(request(
                    "lease-c",
                    Duration::from_secs(30),
                    Duration::from_secs(60),
                ))
                .await
        })
    };
    support::eventually("the controller to start draining", || {
        controller.status().phase == SuspensionPhase::Draining
    })
    .await;

    clock.advance(Duration::from_secs(30));

    let outcome = preparing
        .await
        .expect("the prepare task finishes")
        .expect("the prepare reports an outcome");
    assert_eq!(outcome, PrepareOutcome::DrainTimedOut { in_flight: 1 });
    assert_eq!(controller.status().phase, SuspensionPhase::Active);
    assert_eq!(controller.status().lease, None);
    controller
        .admit()
        .expect("a failed drain leaves the runtime usable");
}

#[tokio::test]
async fn a_second_prepare_is_refused_while_one_is_draining() {
    let clock = FakeClock::new(0);
    let controller = SuspensionController::new(Arc::clone(&clock) as Arc<_>);
    let _permit = controller.admit().expect("the runtime is active");

    let preparing = {
        let controller = controller.clone();
        tokio::spawn(async move {
            controller
                .prepare(request(
                    "lease-d",
                    Duration::from_secs(30),
                    Duration::from_secs(60),
                ))
                .await
        })
    };
    support::eventually("the controller to start draining", || {
        controller.status().phase == SuspensionPhase::Draining
    })
    .await;

    let refused = controller
        .prepare(request(
            "lease-e",
            Duration::from_secs(30),
            Duration::from_secs(60),
        ))
        .await
        .expect_err("only one prepare owns the handshake");
    assert_eq!(
        refused,
        SuspendError::AlreadyDraining {
            lease_id: lease("lease-d")
        }
    );

    clock.advance(Duration::from_secs(30));
    preparing
        .await
        .expect("the task finishes")
        .expect("outcome");
}

#[tokio::test]
async fn a_second_prepare_is_refused_while_the_runtime_is_suspended() {
    let clock = FakeClock::new(0);
    let controller = SuspensionController::new(Arc::clone(&clock) as Arc<_>);
    controller
        .prepare(request(
            "lease-f",
            Duration::from_secs(1),
            Duration::from_secs(600),
        ))
        .await
        .expect("the idle runtime suspends");

    let refused = controller
        .prepare(request(
            "lease-g",
            Duration::from_secs(1),
            Duration::from_secs(600),
        ))
        .await
        .expect_err("a suspended runtime refuses another prepare");
    assert_eq!(
        refused,
        SuspendError::AlreadySuspended {
            lease_id: lease("lease-f")
        }
    );
}

#[tokio::test]
async fn only_the_owning_lease_may_resume() {
    let clock = FakeClock::new(0);
    let controller = SuspensionController::new(Arc::clone(&clock) as Arc<_>);

    assert_eq!(
        controller
            .resume(&lease("lease-h"))
            .expect_err("nothing is suspended"),
        SuspendError::NotSuspended
    );

    controller
        .prepare(request(
            "lease-h",
            Duration::from_secs(1),
            Duration::from_secs(600),
        ))
        .await
        .expect("the idle runtime suspends");

    assert_eq!(
        controller
            .resume(&lease("lease-i"))
            .expect_err("a foreign lease cannot resume"),
        SuspendError::LeaseMismatch {
            expected: lease("lease-h"),
            presented: lease("lease-i"),
        }
    );
    controller
        .resume(&lease("lease-h"))
        .expect("the owning lease resumes");
}

#[tokio::test]
async fn an_expired_lease_releases_the_runtime_so_a_crashed_host_cannot_wedge_it() {
    let clock = FakeClock::new(0);
    let controller = SuspensionController::new(Arc::clone(&clock) as Arc<_>);
    controller
        .prepare(request(
            "lease-j",
            Duration::from_secs(1),
            Duration::from_secs(60),
        ))
        .await
        .expect("the idle runtime suspends");

    clock.advance(Duration::from_secs(59));
    assert_eq!(controller.status().phase, SuspensionPhase::Suspended);

    clock.advance(Duration::from_secs(1));
    assert_eq!(
        controller.status(),
        SuspensionStatus {
            phase: SuspensionPhase::Active,
            in_flight: 0,
            lease: None,
            observed_at: Timestamp::from_millis(60_000),
        }
    );
    controller
        .admit()
        .expect("the expired lease released the runtime");
    assert_eq!(
        controller
            .resume(&lease("lease-j"))
            .expect_err("the expired lease no longer owns anything"),
        SuspendError::NotSuspended
    );
}

#[tokio::test]
async fn permits_dropped_out_of_order_still_drain_the_runtime() {
    let clock = FakeClock::new(0);
    let controller = SuspensionController::new(Arc::clone(&clock) as Arc<_>);
    let first = controller.admit().expect("the runtime is active");
    let second = controller.admit().expect("the runtime is active");
    let third = controller.admit().expect("the runtime is active");
    assert_eq!(controller.status().in_flight, 3);

    let preparing = {
        let controller = controller.clone();
        tokio::spawn(async move {
            controller
                .prepare(request(
                    "lease-k",
                    Duration::from_secs(30),
                    Duration::from_secs(600),
                ))
                .await
        })
    };
    support::eventually("the controller to start draining", || {
        controller.status().phase == SuspensionPhase::Draining
    })
    .await;

    drop(second);
    drop(first);
    assert_eq!(controller.status().in_flight, 1);
    drop(third);

    let outcome = preparing
        .await
        .expect("the prepare task finishes")
        .expect("the prepare succeeds");
    match outcome {
        PrepareOutcome::Suspended(granted) => assert_eq!(granted.lease_id, lease("lease-k")),
        PrepareOutcome::DrainTimedOut { in_flight } => {
            panic!("expected a suspension, work still in flight: {in_flight}")
        }
    }
}

#[test]
fn every_phase_declares_whether_it_admits_work() {
    let admitting: Vec<SuspensionPhase> = SuspensionPhase::ALL
        .into_iter()
        .filter(|phase| phase.admits_work())
        .collect();
    let labels: Vec<&str> = SuspensionPhase::ALL
        .iter()
        .map(|phase| phase.label())
        .collect();

    assert_eq!(admitting, vec![SuspensionPhase::Active]);
    assert_eq!(labels, vec!["active", "draining", "suspended"]);
}

/// Reaching the drain await without resolving it is the only way to observe a cancelled
/// `prepare`: every other suspension test drives the future to completion, which is precisely why
/// this hazard survived until an audit found it.
#[tokio::test]
async fn a_prepare_dropped_while_draining_rolls_the_runtime_back_to_active() {
    let clock = FakeClock::new(0);
    let controller = SuspensionController::new(Arc::clone(&clock) as Arc<_>);
    let permit = controller.admit().expect("the runtime is active");

    let mut preparing = Box::pin(controller.prepare(request(
        "lease-abandoned",
        Duration::from_secs(30),
        Duration::from_secs(300),
    )));

    // One poll commits the `Draining` transition and parks on the drain.
    assert!(
        poll_once(&mut preparing).is_pending(),
        "in-flight work must keep the drain parked"
    );
    assert_eq!(
        controller.status(),
        SuspensionStatus {
            phase: SuspensionPhase::Draining,
            in_flight: 1,
            lease: Some(SuspendLease {
                lease_id: lease("lease-abandoned"),
                reason: "host update".to_owned(),
                granted_at: Timestamp::from_millis(0),
                expires_at: Timestamp::from_millis(300_000),
            }),
            observed_at: Timestamp::from_millis(0),
        }
    );

    // The caller is cancelled: the future is dropped instead of resolved.
    drop(preparing);

    assert_eq!(
        controller.status(),
        SuspensionStatus {
            phase: SuspensionPhase::Active,
            in_flight: 1,
            lease: None,
            observed_at: Timestamp::from_millis(0),
        }
    );

    // Every escape hatch that `Draining` closed is open again.
    let readmitted = controller.admit().expect("work is admitted again");
    assert_eq!(controller.status().in_flight, 2);
    assert_eq!(
        controller.resume(&lease("lease-abandoned")).expect_err(
            "no lease is held, so resume must still refuse rather than invent a suspension"
        ),
        SuspendError::NotSuspended
    );

    drop(readmitted);
    drop(permit);
    assert_eq!(controller.status().in_flight, 0);

    let outcome = controller
        .prepare(request(
            "lease-after",
            Duration::from_secs(30),
            Duration::from_secs(300),
        ))
        .await
        .expect("a fresh suspension is accepted");
    assert_eq!(
        outcome,
        PrepareOutcome::Suspended(SuspendLease {
            lease_id: lease("lease-after"),
            reason: "host update".to_owned(),
            granted_at: Timestamp::from_millis(0),
            expires_at: Timestamp::from_millis(300_000),
        })
    );
}

#[tokio::test]
async fn a_prepare_dropped_after_the_drain_timed_out_keeps_the_timeout_outcome() {
    let clock = FakeClock::new(0);
    let controller = SuspensionController::new(Arc::clone(&clock) as Arc<_>);
    let permit = controller.admit().expect("the runtime is active");

    let mut preparing = Box::pin(controller.prepare(request(
        "lease-timeout",
        Duration::from_secs(30),
        Duration::from_secs(300),
    )));
    assert!(
        poll_once(&mut preparing).is_pending(),
        "in-flight work must keep the drain parked"
    );

    clock.advance(Duration::from_secs(31));
    let resolved = loop {
        match poll_once(&mut preparing) {
            Poll::Ready(resolved) => break resolved,
            Poll::Pending => tokio::task::yield_now().await,
        }
    };

    assert_eq!(
        resolved.expect("a timed-out drain is not an error"),
        PrepareOutcome::DrainTimedOut { in_flight: 1 }
    );
    // The guard was disarmed by the deliberate timeout rollback, so dropping the resolved future
    // must not touch the phase a second time.
    drop(preparing);
    assert_eq!(
        controller.status(),
        SuspensionStatus {
            phase: SuspensionPhase::Active,
            in_flight: 1,
            lease: None,
            observed_at: Timestamp::from_millis(31_000),
        }
    );
    drop(permit);
}

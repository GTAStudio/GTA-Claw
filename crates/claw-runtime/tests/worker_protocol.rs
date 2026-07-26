//! Closed worker protocol tests.

mod support;

use std::sync::Arc;
use std::time::Duration;

use claw_application::model::ids::WorkerId;
use claw_application::model::time::Timestamp;
use claw_runtime::worker::{
    DEFAULT_WORKER_METHOD_ALLOWLIST, WORKER_PROTOCOL_VERSION, WorkerCall, WorkerConfig,
    WorkerError, WorkerRegistry, WorkerSession,
};

use support::FakeClock;

fn worker(name: &str) -> WorkerId {
    WorkerId::new(name).expect("the test worker id is valid")
}

fn registry(clock: &Arc<FakeClock>, config: WorkerConfig) -> WorkerRegistry {
    WorkerRegistry::new(Arc::clone(clock) as Arc<_>, config)
}

fn call(name: &str, fence: u64, sequence: u64, method: &str) -> WorkerCall {
    WorkerCall {
        worker_id: worker(name),
        fence,
        sequence,
        method: method.to_owned(),
        payload_bytes: 16,
    }
}

#[test]
fn the_allowlist_is_exactly_the_nine_frozen_machine_role_methods() {
    let clock = FakeClock::new(0);
    let registry = registry(&clock, WorkerConfig::default());

    assert_eq!(
        DEFAULT_WORKER_METHOD_ALLOWLIST.to_vec(),
        vec![
            "node.event",
            "node.invoke.result",
            "node.pending.ack",
            "node.pending.drain",
            "node.pending.pull",
            "node.pluginSurface.refresh",
            "node.pluginTools.update",
            "node.skills.update",
            "skills.bins",
        ]
    );
    for method in DEFAULT_WORKER_METHOD_ALLOWLIST {
        assert!(registry.allows_method(method), "{method} must be allowed");
    }
    for method in [
        "session.create",
        "gateway.suspend.prepare",
        "node.event.extra",
        "",
    ] {
        assert!(
            !registry.allows_method(method),
            "{method} must not be allowed"
        );
    }
}

#[test]
fn a_worker_is_admitted_once_per_ticket() {
    let clock = FakeClock::new(1_000);
    let registry = registry(&clock, WorkerConfig::default());

    let ticket = registry
        .issue_ticket(worker("w1"), "secret-1")
        .expect("the ticket is issued");
    assert_eq!(ticket.issued_at, Timestamp::from_millis(1_000));
    assert_eq!(ticket.expires_at, Timestamp::from_millis(31_000));
    assert_eq!(registry.outstanding_tickets(), 1);

    let session = registry
        .admit(&worker("w1"), "secret-1", WORKER_PROTOCOL_VERSION)
        .expect("the ticket admits the worker");
    assert_eq!(
        session,
        WorkerSession {
            worker_id: worker("w1"),
            fence: 1,
            admitted_at: Timestamp::from_millis(1_000),
            expires_at: Timestamp::from_millis(121_000),
            last_sequence: 0,
        }
    );
    assert_eq!(registry.outstanding_tickets(), 0);

    let replayed = registry
        .admit(&worker("w1"), "secret-1", WORKER_PROTOCOL_VERSION)
        .expect_err("a ticket is single use");
    assert_eq!(replayed, WorkerError::UnknownTicket);
}

#[test]
fn admission_checks_the_protocol_version_before_it_burns_the_ticket() {
    let clock = FakeClock::new(0);
    let registry = registry(&clock, WorkerConfig::default());
    registry
        .issue_ticket(worker("w1"), "secret-1")
        .expect("the ticket is issued");

    let refused = registry
        .admit(&worker("w1"), "secret-1", WORKER_PROTOCOL_VERSION + 1)
        .expect_err("a foreign protocol version is refused");
    assert_eq!(
        refused,
        WorkerError::UnsupportedProtocol {
            expected: WORKER_PROTOCOL_VERSION,
            announced: WORKER_PROTOCOL_VERSION + 1,
        }
    );
    assert_eq!(
        registry.outstanding_tickets(),
        1,
        "a version mismatch must not consume the ticket"
    );
}

#[test]
fn a_ticket_cannot_be_redeemed_by_another_worker_or_after_it_expires() {
    let clock = FakeClock::new(0);
    let registry = registry(&clock, WorkerConfig::default());
    registry
        .issue_ticket(worker("w1"), "secret-1")
        .expect("the ticket is issued");

    let mismatch = registry
        .admit(&worker("w2"), "secret-1", WORKER_PROTOCOL_VERSION)
        .expect_err("the ticket belongs to another worker");
    assert_eq!(
        mismatch,
        WorkerError::TicketWorkerMismatch {
            expected: worker("w1"),
            presented: worker("w2"),
        }
    );

    registry
        .issue_ticket(worker("w1"), "secret-2")
        .expect("the ticket is issued");
    clock.advance(Duration::from_secs(30));
    let expired = registry
        .admit(&worker("w1"), "secret-2", WORKER_PROTOCOL_VERSION)
        .expect_err("an expired ticket is refused");
    assert_eq!(
        expired,
        WorkerError::TicketExpired {
            expired_at: Timestamp::from_millis(30_000),
        }
    );
}

#[test]
fn readmission_fences_the_previous_session() {
    let clock = FakeClock::new(0);
    let registry = registry(&clock, WorkerConfig::default());
    registry
        .issue_ticket(worker("w1"), "secret-1")
        .expect("the ticket is issued");
    let first = registry
        .admit(&worker("w1"), "secret-1", WORKER_PROTOCOL_VERSION)
        .expect("the worker is admitted");

    registry
        .issue_ticket(worker("w1"), "secret-2")
        .expect("the ticket is issued");
    let second = registry
        .admit(&worker("w1"), "secret-2", WORKER_PROTOCOL_VERSION)
        .expect("the worker is readmitted");

    assert_eq!(first.fence, 1);
    assert_eq!(second.fence, 2);

    let stale = registry
        .dispatch(&call("w1", first.fence, 1, "node.event"))
        .expect_err("the stale session is fenced out");
    assert_eq!(
        stale,
        WorkerError::Fenced {
            current: 2,
            presented: 1,
        }
    );

    registry
        .dispatch(&call("w1", second.fence, 1, "node.event"))
        .expect("the live session still works");
}

#[test]
fn calls_must_advance_the_sequence() {
    let clock = FakeClock::new(0);
    let registry = registry(&clock, WorkerConfig::default());
    registry
        .issue_ticket(worker("w1"), "secret-1")
        .expect("the ticket is issued");
    let session = registry
        .admit(&worker("w1"), "secret-1", WORKER_PROTOCOL_VERSION)
        .expect("the worker is admitted");

    let after_first = registry
        .dispatch(&call("w1", session.fence, 1, "node.event"))
        .expect("the first call is accepted");
    assert_eq!(after_first.last_sequence, 1);
    let after_jump = registry
        .dispatch(&call("w1", session.fence, 7, "node.pending.pull"))
        .expect("gaps are allowed, regressions are not");
    assert_eq!(after_jump.last_sequence, 7);

    assert_eq!(
        registry
            .dispatch(&call("w1", session.fence, 7, "node.event"))
            .expect_err("a repeat is a replay"),
        WorkerError::ReplayDetected {
            last: 7,
            presented: 7,
        }
    );
    assert_eq!(
        registry
            .dispatch(&call("w1", session.fence, 2, "node.event"))
            .expect_err("going backwards is a replay"),
        WorkerError::ReplayDetected {
            last: 7,
            presented: 2,
        }
    );
    assert_eq!(
        registry
            .session(&worker("w1"))
            .expect("the session is live")
            .last_sequence,
        7,
        "a refused call must not move the sequence"
    );
}

#[test]
fn methods_and_payloads_are_checked_before_the_session_is_touched() {
    let clock = FakeClock::new(0);
    let registry = registry(
        &clock,
        WorkerConfig {
            max_payload_bytes: 32,
            ..WorkerConfig::default()
        },
    );

    assert_eq!(
        registry
            .dispatch(&call("ghost", 1, 1, "session.create"))
            .expect_err("an unlisted method never reaches the session table"),
        WorkerError::MethodNotAllowed("session.create".to_owned())
    );

    let oversized = WorkerCall {
        payload_bytes: 33,
        ..call("ghost", 1, 1, "node.event")
    };
    assert_eq!(
        registry
            .dispatch(&oversized)
            .expect_err("an oversized payload is refused"),
        WorkerError::PayloadTooLarge {
            limit: 32,
            presented: 33,
        }
    );

    assert_eq!(
        registry
            .dispatch(&call("ghost", 1, 1, "node.event"))
            .expect_err("an unadmitted worker cannot call"),
        WorkerError::UnknownWorker(worker("ghost"))
    );
}

#[test]
fn a_session_expires_without_heartbeats_and_a_heartbeat_extends_it() {
    let clock = FakeClock::new(0);
    let registry = registry(&clock, WorkerConfig::default());
    registry
        .issue_ticket(worker("w1"), "secret-1")
        .expect("the ticket is issued");
    let session = registry
        .admit(&worker("w1"), "secret-1", WORKER_PROTOCOL_VERSION)
        .expect("the worker is admitted");

    clock.advance(Duration::from_secs(119));
    let beaten = registry
        .heartbeat(&worker("w1"), session.fence)
        .expect("the heartbeat lands before the deadline");
    assert_eq!(beaten.expires_at, Timestamp::from_millis(239_000));

    clock.advance(Duration::from_secs(120));
    assert_eq!(
        registry
            .dispatch(&call("w1", session.fence, 1, "node.event"))
            .expect_err("the session lapsed"),
        WorkerError::SessionExpired {
            expired_at: Timestamp::from_millis(239_000),
        }
    );
    assert_eq!(registry.session(&worker("w1")), None);
    assert_eq!(registry.sessions(), Vec::new());
}

#[test]
fn eviction_removes_exactly_one_session() {
    let clock = FakeClock::new(0);
    let registry = registry(&clock, WorkerConfig::default());
    for (name, secret) in [("w1", "s1"), ("w2", "s2")] {
        registry
            .issue_ticket(worker(name), secret)
            .expect("the ticket is issued");
        registry
            .admit(&worker(name), secret, WORKER_PROTOCOL_VERSION)
            .expect("the worker is admitted");
    }
    assert_eq!(
        registry
            .sessions()
            .into_iter()
            .map(|session| (session.worker_id, session.fence))
            .collect::<Vec<(WorkerId, u64)>>(),
        vec![(worker("w1"), 1), (worker("w2"), 2)]
    );

    let evicted = registry.evict(&worker("w1")).expect("w1 was live");
    assert_eq!(evicted.fence, 1);
    assert_eq!(registry.evict(&worker("w1")), None);
    assert_eq!(
        registry
            .sessions()
            .into_iter()
            .map(|session| session.worker_id)
            .collect::<Vec<WorkerId>>(),
        vec![worker("w2")]
    );
}

#[test]
fn expired_tickets_are_not_counted_as_outstanding() {
    let clock = FakeClock::new(0);
    let registry = registry(&clock, WorkerConfig::default());
    registry
        .issue_ticket(worker("w1"), "secret-1")
        .expect("the ticket is issued");
    registry
        .issue_ticket(worker("w2"), "secret-2")
        .expect("the ticket is issued");
    assert_eq!(registry.outstanding_tickets(), 2);

    clock.advance(Duration::from_secs(30));
    assert_eq!(registry.outstanding_tickets(), 0);
    assert_eq!(
        registry
            .admit(&worker("w1"), "secret-1", WORKER_PROTOCOL_VERSION)
            .expect_err("a swept ticket is gone"),
        WorkerError::UnknownTicket
    );
}

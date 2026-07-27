//! Acceptance proofs for the closed worker protocol.
//!
//! Six controls have to hold for a worker admission surface to be safe:
//! admission, fencing, expiry, the RPC allowlist, replay and payload limits.
//! Every rejection here is asserted by its exact variant and by the values the
//! deciding comparison used, because `is_err()` alone cannot tell a control
//! that fired from an unrelated failure that happened first.
//!
//! Time never advances by sleeping: [`ManualClock`] is injected, so the expiry
//! proofs are exact rather than probabilistic.

use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

use claw_worker::{
    AdmissionController, AdmissionRejection, AdmissionRequest, AdmittedSession, CallId,
    CallRejection, DEFAULT_MAX_CALL_BYTES, FencingError, FencingToken, IssuedAdmission, LimitError,
    ManualClock, MethodAllowlist, MethodName, PayloadLimits, SecretSource, SecretSourceError,
    WORKER_PROTOCOL_METHODS, WorkerCall, WorkerCallFrame, WorkerId,
};

const START_MS: u64 = 1_700_000_000_000;
const TTL_MS: u64 = 60_000;

/// A reproducible stand-in for the operating system randomness source.
///
/// Production randomness is a port with no deterministic implementation in the
/// crate, so a test that needs reproducible tickets supplies its own. Each call
/// mixes a fresh counter value, so two `fill` calls never agree.
#[derive(Debug)]
struct SequentialSecretSource {
    next: AtomicU64,
}

impl SequentialSecretSource {
    fn new() -> Self {
        Self {
            next: AtomicU64::new(1),
        }
    }
}

impl SecretSource for SequentialSecretSource {
    fn fill(&self, out: &mut [u8]) -> Result<(), SecretSourceError> {
        let seed = self.next.fetch_add(1, Ordering::SeqCst);
        for (index, slot) in out.iter_mut().enumerate() {
            let offset = u64::try_from(index).expect("buffer index fits in u64");
            let mixed = seed
                .wrapping_mul(0x9E37_79B9_7F4A_7C15)
                .wrapping_add(offset.wrapping_mul(0x0100_0000_01B3));
            *slot = u8::try_from((mixed >> 24) & 0xff).expect("masked to one byte");
        }
        Ok(())
    }
}

/// A degenerate source that always answers with the same bytes.
#[derive(Debug)]
struct ConstantSecretSource;

impl SecretSource for ConstantSecretSource {
    fn fill(&self, out: &mut [u8]) -> Result<(), SecretSourceError> {
        out.fill(0x5a);
        Ok(())
    }
}

/// A source that reports failure, standing in for an unavailable entropy pool.
#[derive(Debug)]
struct FailingSecretSource;

impl SecretSource for FailingSecretSource {
    fn fill(&self, _out: &mut [u8]) -> Result<(), SecretSourceError> {
        Err(SecretSourceError)
    }
}

struct Harness {
    controller: AdmissionController,
    clock: ManualClock,
}

impl Harness {
    fn with_limits(limits: PayloadLimits) -> Self {
        let clock = ManualClock::new(START_MS);
        let controller = AdmissionController::new(
            Arc::new(clock.clone()),
            Arc::new(SequentialSecretSource::new()),
            limits,
        )
        .expect("default payload limits are usable");
        Self { controller, clock }
    }

    fn new() -> Self {
        Self::with_limits(PayloadLimits::default())
    }

    fn issue(&mut self, worker: &WorkerId, methods: MethodAllowlist) -> IssuedAdmission {
        self.controller
            .issue(worker, TTL_MS, methods)
            .expect("issuing a ticket with a positive lifetime succeeds")
    }

    fn issue_full(&mut self, worker: &WorkerId) -> IssuedAdmission {
        self.issue(worker, MethodAllowlist::worker_protocol())
    }

    fn admit(&mut self, issued: &IssuedAdmission) -> AdmittedSession {
        self.controller
            .admit(&issued.request())
            .expect("an unexpired, fenced-current ticket is admitted")
    }
}

fn worker(name: &str) -> WorkerId {
    WorkerId::new(name).expect("test worker identity is valid")
}

fn method(name: &str) -> MethodName {
    MethodName::new(name).expect("test method name is valid")
}

fn call_id(name: &str) -> CallId {
    CallId::new(name).expect("test call identity is valid")
}

fn call(id: &str, name: &str) -> WorkerCall {
    WorkerCall {
        call_id: call_id(id),
        method: method(name),
        payload: serde_json::json!({}),
    }
}

fn encode(request: &AdmissionRequest) -> Vec<u8> {
    serde_json::to_vec(request).expect("an admission request encodes as JSON")
}

// ---------------------------------------------------------------------------
// Admission
// ---------------------------------------------------------------------------

#[test]
fn admission_accepts_the_issued_ticket_and_binds_the_session_to_its_grant() {
    let mut harness = Harness::new();
    let worker_id = worker("worker-a");
    let granted = MethodAllowlist::parse_closed(["worker.heartbeat", "worker.task.claim"])
        .expect("granted method names are valid");
    let issued = harness.issue(&worker_id, granted.clone());

    let admitted = harness.admit(&issued);

    assert_eq!(admitted.worker_id, worker_id);
    assert_eq!(admitted.fencing_token, issued.ticket.fencing_token);
    assert_eq!(admitted.expires_at_ms, START_MS + TTL_MS);
    assert_eq!(admitted.allowed_methods, granted);
    assert!(harness.controller.is_open(admitted.session));
}

#[test]
fn admission_rejects_a_ticket_this_controller_never_issued() {
    let mut harness = Harness::new();
    let worker_id = worker("worker-a");
    let issued = harness.issue_full(&worker_id);

    let mut forged = issued.request();
    forged.ticket_id = claw_worker::TicketId::new("deadbeefdeadbeefdeadbeefdeadbeef")
        .expect("forged ticket identity is well formed");

    assert_eq!(
        harness.controller.admit(&forged),
        Err(AdmissionRejection::UnknownTicket {
            ticket_id: forged.ticket_id.clone()
        })
    );
}

#[test]
fn admission_rejects_a_credential_that_does_not_match_the_issued_secret() {
    let mut harness = Harness::new();
    let worker_id = worker("worker-a");
    let issued = harness.issue_full(&worker_id);

    let mut tampered = issued.request();
    tampered.secret =
        claw_worker::AdmissionSecret::from_bytes([0x00; claw_worker::ADMISSION_SECRET_BYTES]);

    assert_eq!(
        harness.controller.admit(&tampered),
        Err(AdmissionRejection::SecretMismatch {
            ticket_id: issued.ticket.ticket_id.clone()
        })
    );
    // The failed attempt did not burn the ticket, and did not admit anybody.
    assert!(harness.controller.admit(&issued.request()).is_ok());
}

#[test]
fn admission_rejects_a_ticket_presented_under_another_worker_identity() {
    let mut harness = Harness::new();
    let owner = worker("worker-a");
    let impostor = worker("worker-b");
    let issued = harness.issue_full(&owner);

    let mut stolen = issued.request();
    stolen.worker_id = impostor.clone();

    assert_eq!(
        harness.controller.admit(&stolen),
        Err(AdmissionRejection::WorkerIdentityMismatch {
            expected: owner,
            presented: impostor,
        })
    );
}

#[test]
fn admission_refuses_a_frame_carrying_a_field_this_version_does_not_understand() {
    let mut harness = Harness::new();
    let issued = harness.issue_full(&worker("worker-a"));

    let mut value = serde_json::to_value(issued.request()).expect("encode admission request");
    value
        .as_object_mut()
        .expect("admission request encodes as an object")
        .insert("role".to_owned(), serde_json::json!("operator"));
    let frame = serde_json::to_vec(&value).expect("encode tampered admission frame");

    match harness.controller.admit_encoded(&frame) {
        Err(AdmissionRejection::Malformed { message }) => assert!(
            message.contains("unknown field `role`"),
            "unexpected parser diagnostic: {message}"
        ),
        other => panic!("an unknown admission field must be refused, got {other:?}"),
    }
}

#[test]
fn admission_refuses_to_mint_a_ticket_when_the_randomness_source_fails() {
    let clock = ManualClock::new(START_MS);
    let mut controller = AdmissionController::new(
        Arc::new(clock),
        Arc::new(FailingSecretSource),
        PayloadLimits::default(),
    )
    .expect("default payload limits are usable");

    assert_eq!(
        controller.issue(
            &worker("worker-a"),
            TTL_MS,
            MethodAllowlist::worker_protocol()
        ),
        Err(claw_worker::IssueError::SecretSource(SecretSourceError))
    );
}

#[test]
fn admission_refuses_a_second_ticket_whose_identity_collides_with_a_live_one() {
    let clock = ManualClock::new(START_MS);
    let mut controller = AdmissionController::new(
        Arc::new(clock),
        Arc::new(ConstantSecretSource),
        PayloadLimits::default(),
    )
    .expect("default payload limits are usable");
    let worker_id = worker("worker-a");
    let first = controller
        .issue(&worker_id, TTL_MS, MethodAllowlist::worker_protocol())
        .expect("the first ticket is minted");

    assert_eq!(
        controller.issue(&worker_id, TTL_MS, MethodAllowlist::worker_protocol()),
        Err(claw_worker::IssueError::TicketIdCollision {
            ticket_id: first.ticket.ticket_id.clone()
        })
    );
}

// ---------------------------------------------------------------------------
// Fencing
// ---------------------------------------------------------------------------

#[test]
fn fencing_invalidates_an_earlier_generation_ticket_once_a_new_one_is_issued() {
    let mut harness = Harness::new();
    let worker_id = worker("worker-a");
    let first = harness.issue_full(&worker_id);
    let second = harness.issue_full(&worker_id);

    assert_eq!(first.ticket.fencing_token.get(), 1);
    assert_eq!(second.ticket.fencing_token.get(), 2);
    assert_eq!(
        harness.controller.admit(&first.request()),
        Err(AdmissionRejection::Fenced(FencingError::Stale {
            presented: 1,
            current: 2,
        }))
    );
    // The live generation is still admitted, so this fenced off exactly one.
    assert!(harness.controller.admit(&second.request()).is_ok());
}

#[test]
fn fencing_revokes_a_live_session_the_moment_a_newer_generation_opens() {
    let mut harness = Harness::new();
    let worker_id = worker("worker-a");
    let issued = harness.issue_full(&worker_id);
    let session = harness.admit(&issued);
    assert!(
        harness
            .controller
            .call(session.session, call("c1", "worker.heartbeat"))
            .is_ok()
    );

    let restarted = harness
        .controller
        .fence(&worker_id)
        .expect("open generation two");
    assert_eq!(restarted.get(), 2);

    assert_eq!(
        harness
            .controller
            .call(session.session, call("c2", "worker.heartbeat")),
        Err(CallRejection::SessionFenced(FencingError::Stale {
            presented: 1,
            current: 2,
        }))
    );
}

#[test]
fn fencing_rejects_a_worker_claiming_a_generation_older_than_its_own_ticket() {
    let mut harness = Harness::new();
    let worker_id = worker("worker-a");
    let issued = harness.issue_full(&worker_id);
    let reissued = harness.issue_full(&worker_id);

    let mut request = reissued.request();
    request.fencing_token = issued.ticket.fencing_token;

    assert_eq!(
        harness.controller.admit(&request),
        Err(AdmissionRejection::Fenced(FencingError::Stale {
            presented: 1,
            current: 2,
        }))
    );
}

#[test]
fn fencing_rejects_a_generation_no_controller_ever_issued() {
    let mut harness = Harness::new();
    let worker_id = worker("worker-a");
    let issued = harness.issue_full(&worker_id);

    let mut request = issued.request();
    request.fencing_token = FencingToken::new(4_096).expect("generation is non-zero");

    assert_eq!(
        harness.controller.admit(&request),
        Err(AdmissionRejection::Fenced(FencingError::FromFuture {
            presented: 4_096,
            current: 1,
        }))
    );
}

#[test]
fn fencing_generations_do_not_leak_between_worker_identities() {
    let mut harness = Harness::new();
    let first = worker("worker-a");
    let second = worker("worker-b");
    let first_ticket = harness.issue_full(&first);
    harness.issue_full(&second);
    harness
        .controller
        .fence(&second)
        .expect("re-fence worker-b");

    assert_eq!(
        harness
            .controller
            .current_generation(&first)
            .map(FencingToken::get),
        Some(1)
    );
    assert_eq!(
        harness
            .controller
            .current_generation(&second)
            .map(FencingToken::get),
        Some(2)
    );
    // worker-a was never fenced, so its generation-one ticket is still good.
    assert!(harness.controller.admit(&first_ticket.request()).is_ok());
}

// ---------------------------------------------------------------------------
// Expiry
// ---------------------------------------------------------------------------

#[test]
fn expiry_rejects_a_ticket_redeemed_after_its_deadline() {
    let mut harness = Harness::new();
    let issued = harness.issue_full(&worker("worker-a"));
    harness.clock.advance(TTL_MS + 1);

    assert_eq!(
        harness.controller.admit(&issued.request()),
        Err(AdmissionRejection::Expired {
            expires_at_ms: START_MS + TTL_MS,
            now_ms: START_MS + TTL_MS + 1,
        })
    );
}

#[test]
fn expiry_is_exclusive_at_the_deadline_millisecond() {
    let mut harness = Harness::new();
    let worker_id = worker("worker-a");
    let last_valid = harness.issue_full(&worker_id);
    harness.clock.advance(TTL_MS - 1);
    assert!(
        harness.controller.admit(&last_valid.request()).is_ok(),
        "the millisecond before the deadline is still inside the window"
    );

    let mut harness = Harness::new();
    let exactly_expired = harness.issue_full(&worker_id);
    harness.clock.advance(TTL_MS);
    assert_eq!(
        harness.controller.admit(&exactly_expired.request()),
        Err(AdmissionRejection::Expired {
            expires_at_ms: START_MS + TTL_MS,
            now_ms: START_MS + TTL_MS,
        })
    );
}

#[test]
fn expiry_rejects_a_ticket_dated_ahead_of_the_controller_clock() {
    let mut harness = Harness::new();
    let issued = harness.issue_full(&worker("worker-a"));

    // The host clock stepped backwards after the ticket was minted.
    harness.clock.set(START_MS - 250);

    assert_eq!(
        harness.controller.admit(&issued.request()),
        Err(AdmissionRejection::NotYetValid {
            issued_at_ms: START_MS,
            now_ms: START_MS - 250,
        })
    );

    // Once the clock catches up again the same ticket is admitted, so the
    // rejection was about the instant and not about the ticket.
    harness.clock.set(START_MS);
    assert!(harness.controller.admit(&issued.request()).is_ok());
}

#[test]
fn expiry_ends_a_live_session_lease() {
    let mut harness = Harness::new();
    let issued = harness.issue_full(&worker("worker-a"));
    let session = harness.admit(&issued);
    assert!(
        harness
            .controller
            .call(session.session, call("c1", "worker.heartbeat"))
            .is_ok()
    );

    harness.clock.advance(TTL_MS);

    assert_eq!(
        harness
            .controller
            .call(session.session, call("c2", "worker.heartbeat")),
        Err(CallRejection::SessionExpired {
            expires_at_ms: START_MS + TTL_MS,
            now_ms: START_MS + TTL_MS,
        })
    );
}

#[test]
fn expiry_refuses_to_mint_a_ticket_that_is_born_expired() {
    let mut harness = Harness::new();
    assert_eq!(
        harness
            .controller
            .issue(&worker("worker-a"), 0, MethodAllowlist::worker_protocol()),
        Err(claw_worker::IssueError::ZeroTimeToLive)
    );
}

#[test]
fn expiry_refuses_a_deadline_that_overflows_instead_of_wrapping_into_the_past() {
    let clock = ManualClock::new(u64::MAX - 5);
    let mut controller = AdmissionController::new(
        Arc::new(clock),
        Arc::new(SequentialSecretSource::new()),
        PayloadLimits::default(),
    )
    .expect("default payload limits are usable");

    assert_eq!(
        controller.issue(&worker("worker-a"), 100, MethodAllowlist::worker_protocol()),
        Err(claw_worker::IssueError::ExpiryOverflow {
            now_ms: u64::MAX - 5,
            ttl_ms: 100,
        })
    );
}

// ---------------------------------------------------------------------------
// RPC allowlist
// ---------------------------------------------------------------------------

#[test]
fn allowlist_admits_exactly_the_granted_methods() {
    let mut harness = Harness::new();
    let granted = MethodAllowlist::parse_closed(["worker.heartbeat", "worker.task.progress"])
        .expect("granted method names are valid");
    let issued = harness.issue(&worker("worker-a"), granted);
    let session = harness.admit(&issued);

    for (index, name) in ["worker.heartbeat", "worker.task.progress"]
        .into_iter()
        .enumerate()
    {
        let accepted = harness
            .controller
            .call(session.session, call(&format!("c{index}"), name))
            .expect("a granted method is dispatched");
        assert_eq!(accepted.method, method(name));
        assert_eq!(accepted.session, session.session);
    }
}

#[test]
fn allowlist_denies_a_protocol_method_that_was_not_granted_to_this_session() {
    let mut harness = Harness::new();
    let granted =
        MethodAllowlist::parse_closed(["worker.heartbeat"]).expect("granted method is valid");
    let issued = harness.issue(&worker("worker-a"), granted);
    let session = harness.admit(&issued);

    assert_eq!(
        harness
            .controller
            .call(session.session, call("c1", "worker.task.claim")),
        Err(CallRejection::MethodNotAllowed {
            method: method("worker.task.claim")
        })
    );
}

#[test]
fn allowlist_is_closed_by_default_and_denies_the_entire_protocol() {
    let mut harness = Harness::new();
    let issued = harness.issue(&worker("worker-a"), MethodAllowlist::empty());
    let session = harness.admit(&issued);

    for (index, name) in WORKER_PROTOCOL_METHODS.into_iter().enumerate() {
        assert_eq!(
            harness
                .controller
                .call(session.session, call(&format!("c{index}"), name)),
            Err(CallRejection::MethodNotAllowed {
                method: method(name)
            }),
            "an empty grant must deny `{name}`"
        );
    }
}

#[test]
fn allowlist_denies_an_ordinary_gateway_method_that_is_outside_the_worker_surface() {
    let mut harness = Harness::new();
    let issued = harness.issue_full(&worker("worker-a"));
    let session = harness.admit(&issued);

    // `config.set` and `sessions.delete` are frozen operator methods. A worker
    // holding the full closed-protocol grant still cannot reach them.
    for (index, name) in ["config.set", "sessions.delete", "health"]
        .into_iter()
        .enumerate()
    {
        assert_eq!(
            harness
                .controller
                .call(session.session, call(&format!("c{index}"), name)),
            Err(CallRejection::MethodNotAllowed {
                method: method(name)
            }),
            "the closed worker surface must not reach `{name}`"
        );
    }
}

#[test]
fn allowlist_denies_a_method_that_no_registry_defines_at_all() {
    let mut harness = Harness::new();
    let issued = harness.issue_full(&worker("worker-a"));
    let session = harness.admit(&issued);

    assert_eq!(
        harness
            .controller
            .call(session.session, call("c1", "worker.task.claim.escalate")),
        Err(CallRejection::MethodNotAllowed {
            method: method("worker.task.claim.escalate")
        })
    );
}

#[test]
fn allowlist_refuses_a_call_frame_carrying_an_unknown_field() {
    let mut harness = Harness::new();
    let issued = harness.issue_full(&worker("worker-a"));
    let session = harness.admit(&issued);

    let mut value = serde_json::to_value(WorkerCallFrame::from(call("c1", "worker.heartbeat")))
        .expect("encode worker call frame");
    value
        .as_object_mut()
        .expect("worker call encodes as an object")
        .insert("scope".to_owned(), serde_json::json!("operator.admin"));
    let frame = serde_json::to_vec(&value).expect("encode tampered call frame");

    match harness.controller.call_encoded(session.session, &frame) {
        Err(CallRejection::Malformed { message }) => assert!(
            message.contains("unknown field `scope`"),
            "unexpected parser diagnostic: {message}"
        ),
        other => panic!("an unknown call field must be refused, got {other:?}"),
    }
}

// ---------------------------------------------------------------------------
// Replay
// ---------------------------------------------------------------------------

#[test]
fn replay_of_a_redeemed_ticket_is_rejected_even_with_the_correct_secret() {
    let mut harness = Harness::new();
    let issued = harness.issue_full(&worker("worker-a"));
    let first = harness.admit(&issued);

    assert_eq!(
        harness.controller.admit(&issued.request()),
        Err(AdmissionRejection::TicketAlreadyRedeemed {
            ticket_id: issued.ticket.ticket_id.clone()
        })
    );
    // The replay did not mint a second session behind the first one.
    assert!(harness.controller.is_open(first.session));
}

#[test]
fn replay_of_a_redeemed_ticket_is_still_rejected_after_the_session_closes() {
    let mut harness = Harness::new();
    let issued = harness.issue_full(&worker("worker-a"));
    let session = harness.admit(&issued);
    assert!(harness.controller.close(session.session));

    assert_eq!(
        harness.controller.admit(&issued.request()),
        Err(AdmissionRejection::TicketAlreadyRedeemed {
            ticket_id: issued.ticket.ticket_id.clone()
        })
    );
}

#[test]
fn replay_of_an_accepted_call_frame_is_rejected() {
    let mut harness = Harness::new();
    let issued = harness.issue_full(&worker("worker-a"));
    let session = harness.admit(&issued);
    let frame = serde_json::to_vec(&WorkerCallFrame::from(call("c1", "worker.heartbeat")))
        .expect("encode worker call frame");

    assert!(
        harness
            .controller
            .call_encoded(session.session, &frame)
            .is_ok()
    );
    assert_eq!(
        harness.controller.call_encoded(session.session, &frame),
        Err(CallRejection::DuplicateCall {
            call_id: call_id("c1")
        })
    );
}

#[test]
fn replay_ledger_is_scoped_to_one_session_rather_than_shared_between_workers() {
    let mut harness = Harness::new();
    let first = harness.issue_full(&worker("worker-a"));
    let first_session = harness.admit(&first);
    let second = harness.issue_full(&worker("worker-b"));
    let second_session = harness.admit(&second);

    assert!(
        harness
            .controller
            .call(first_session.session, call("c1", "worker.heartbeat"))
            .is_ok()
    );
    assert!(
        harness
            .controller
            .call(second_session.session, call("c1", "worker.heartbeat"))
            .is_ok(),
        "a second worker's own first call must not look like a replay"
    );
    assert_eq!(
        harness
            .controller
            .call(first_session.session, call("c1", "worker.heartbeat")),
        Err(CallRejection::DuplicateCall {
            call_id: call_id("c1")
        })
    );
}

#[test]
fn a_denied_call_does_not_consume_its_identifier() {
    let mut harness = Harness::new();
    let granted =
        MethodAllowlist::parse_closed(["worker.heartbeat"]).expect("granted method is valid");
    let issued = harness.issue(&worker("worker-a"), granted);
    let session = harness.admit(&issued);

    assert_eq!(
        harness
            .controller
            .call(session.session, call("c1", "worker.task.claim")),
        Err(CallRejection::MethodNotAllowed {
            method: method("worker.task.claim")
        })
    );
    assert!(
        harness
            .controller
            .call(session.session, call("c1", "worker.heartbeat"))
            .is_ok(),
        "a denied call must not burn an identifier the worker may legitimately reuse"
    );
}

#[test]
fn calls_on_a_closed_session_are_rejected_rather_than_dispatched() {
    let mut harness = Harness::new();
    let issued = harness.issue_full(&worker("worker-a"));
    let session = harness.admit(&issued);
    assert!(harness.controller.close(session.session));
    assert!(!harness.controller.close(session.session));

    assert_eq!(
        harness
            .controller
            .call(session.session, call("c1", "worker.heartbeat")),
        Err(CallRejection::SessionClosed {
            session: session.session
        })
    );
}

// ---------------------------------------------------------------------------
// Payload limits
// ---------------------------------------------------------------------------

#[test]
fn payload_limit_rejects_an_oversized_admission_frame_before_parsing_it() {
    let limits = PayloadLimits::new(512, DEFAULT_MAX_CALL_BYTES);
    let mut harness = Harness::with_limits(limits);
    harness.issue_full(&worker("worker-a"));

    // Not JSON at all: reaching the parser would report `Malformed`, so a
    // `PayloadTooLarge` verdict proves the length check ran first.
    let frame = vec![b'A'; 513];

    assert_eq!(
        harness.controller.admit_encoded(&frame),
        Err(AdmissionRejection::PayloadTooLarge {
            limit: 512,
            actual: 513,
        })
    );
}

#[test]
fn payload_limit_admits_a_frame_of_exactly_the_capped_length() {
    let mut sizing = Harness::new();
    let issued = sizing.issue_full(&worker("worker-a"));
    let exact = encode(&issued.request()).len();

    let mut at_cap = Harness::with_limits(PayloadLimits::new(exact, DEFAULT_MAX_CALL_BYTES));
    let issued = at_cap.issue_full(&worker("worker-a"));
    let frame = encode(&issued.request());
    assert_eq!(frame.len(), exact, "the sizing run must be reproducible");
    assert!(at_cap.controller.admit_encoded(&frame).is_ok());

    let mut below_cap = Harness::with_limits(PayloadLimits::new(exact - 1, DEFAULT_MAX_CALL_BYTES));
    let issued = below_cap.issue_full(&worker("worker-a"));
    let frame = encode(&issued.request());
    assert_eq!(
        below_cap.controller.admit_encoded(&frame),
        Err(AdmissionRejection::PayloadTooLarge {
            limit: exact - 1,
            actual: exact,
        })
    );
}

#[test]
fn payload_limit_rejects_an_oversized_call_frame_without_consuming_the_call() {
    let mut harness = Harness::with_limits(PayloadLimits::new(8 * 1024, 1_024));
    let issued = harness.issue_full(&worker("worker-a"));
    let session = harness.admit(&issued);

    let oversized = serde_json::to_vec(&WorkerCallFrame {
        call_id: call_id("c1"),
        method: method("worker.heartbeat"),
        payload: serde_json::json!({ "blob": "x".repeat(4_096) }),
    })
    .expect("encode oversized call frame");
    let actual = oversized.len();
    assert!(actual > 1_024);

    assert_eq!(
        harness.controller.call_encoded(session.session, &oversized),
        Err(CallRejection::PayloadTooLarge {
            limit: 1_024,
            actual,
        })
    );
    // The rejected frame was never dispatched, so its identifier is still free.
    assert!(
        harness
            .controller
            .call(session.session, call("c1", "worker.heartbeat"))
            .is_ok()
    );
}

#[test]
fn payload_limit_survives_a_frame_far_larger_than_the_cap() {
    let mut harness = Harness::with_limits(PayloadLimits::new(1_024, 1_024));
    let issued = harness.issue_full(&worker("worker-a"));
    let session = harness.admit(&issued);

    // Eight mebibytes of a byte that is not valid JSON. The controller must
    // answer from the length alone, without decoding or copying the frame.
    let flood = vec![b'{'; 8 * 1024 * 1024];

    assert_eq!(
        harness.controller.admit_encoded(&flood),
        Err(AdmissionRejection::PayloadTooLarge {
            limit: 1_024,
            actual: 8 * 1024 * 1024,
        })
    );
    assert_eq!(
        harness.controller.call_encoded(session.session, &flood),
        Err(CallRejection::PayloadTooLarge {
            limit: 1_024,
            actual: 8 * 1024 * 1024,
        })
    );
    // The controller is still usable afterwards.
    assert!(
        harness
            .controller
            .call(session.session, call("c1", "worker.heartbeat"))
            .is_ok()
    );
}

#[test]
fn payload_limit_of_zero_is_refused_at_construction() {
    let clock = ManualClock::new(START_MS);
    assert_eq!(
        AdmissionController::new(
            Arc::new(clock.clone()),
            Arc::new(SequentialSecretSource::new()),
            PayloadLimits::new(0, DEFAULT_MAX_CALL_BYTES),
        )
        .err(),
        Some(LimitError::ZeroLimit("max_admission_bytes"))
    );
    assert_eq!(
        AdmissionController::new(
            Arc::new(clock),
            Arc::new(SequentialSecretSource::new()),
            PayloadLimits::new(8 * 1024, 0),
        )
        .err(),
        Some(LimitError::ZeroLimit("max_call_bytes"))
    );
}

// ---------------------------------------------------------------------------
// Cross-cutting fail-closed checks
// ---------------------------------------------------------------------------

#[test]
fn a_session_handle_from_another_controller_is_unknown_rather_than_served() {
    let mut first = Harness::new();
    let first_a = first.issue_full(&worker("worker-a"));
    first.admit(&first_a);
    let first_b = first.issue_full(&worker("worker-b"));
    let second_handle = first.admit(&first_b).session;
    assert_eq!(second_handle.get(), 2);

    // A different controller has only ever minted handle 1.
    let mut other = Harness::new();
    let other_issued = other.issue_full(&worker("worker-c"));
    let own = other.admit(&other_issued).session;
    assert_eq!(own.get(), 1);

    assert_eq!(
        other
            .controller
            .call(second_handle, call("c1", "worker.heartbeat")),
        Err(CallRejection::UnknownSession {
            session: second_handle
        })
    );
    assert!(!other.controller.close(second_handle));
    assert!(other.controller.is_open(own));
}

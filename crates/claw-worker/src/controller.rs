//! The admission controller: the single owner of worker admission state.
//!
//! One controller serves one Gateway. It mints tickets, redeems them into
//! sessions, and screens every later call. All six controls — admission,
//! fencing, expiry, allowlist, replay and payload limits — are enforced here,
//! in an order chosen so that each rejection names the control that actually
//! fired rather than being shadowed by a cheaper one.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt::{self, Display, Formatter};
use std::sync::Arc;

use serde::{Deserialize, Serialize};

use crate::allowlist::{MethodAllowlist, MethodName};
use crate::clock::Clock;
use crate::error::{AdmissionRejection, CallRejection, IssueError};
use crate::fencing::{FencingToken, GenerationLedger};
use crate::identity::{CallId, TicketId, WorkerId};
use crate::limits::PayloadLimits;
use crate::secret::{
    ADMISSION_SECRET_BYTES, AdmissionSecret, SecretSource, TICKET_ID_BYTES, encode_hex,
};
use crate::ticket::{AdmissionRequest, AdmissionTicket, IssuedAdmission};

/// An opaque handle to an admitted worker session.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct SessionId(u64);

impl SessionId {
    /// Returns the numeric handle, for logging and correlation only.
    #[must_use]
    pub const fn get(self) -> u64 {
        self.0
    }
}

impl Display for SessionId {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        Display::fmt(&self.0, formatter)
    }
}

/// A worker that has been admitted.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AdmittedSession {
    /// Handle to use for every later call.
    pub session: SessionId,
    /// The admitted worker identity.
    pub worker_id: WorkerId,
    /// The generation this session owns.
    pub fencing_token: FencingToken,
    /// Unix milliseconds at which this session's lease runs out, exclusive.
    pub expires_at_ms: u64,
    /// The exact methods this session may call.
    pub allowed_methods: MethodAllowlist,
}

/// A worker RPC call.
#[derive(Clone, Debug, PartialEq)]
pub struct WorkerCall {
    /// Identity of this call, unique within the session.
    pub call_id: CallId,
    /// The method being invoked.
    pub method: MethodName,
    /// Opaque method arguments; this crate does not interpret them.
    pub payload: serde_json::Value,
}

/// The wire form of a worker RPC call.
///
/// Unknown fields are refused rather than ignored.
#[derive(Clone, Debug, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct WorkerCallFrame {
    /// Identity of this call, unique within the session.
    pub call_id: CallId,
    /// The method being invoked.
    pub method: MethodName,
    /// Opaque method arguments.
    pub payload: serde_json::Value,
}

impl From<WorkerCallFrame> for WorkerCall {
    fn from(frame: WorkerCallFrame) -> Self {
        Self {
            call_id: frame.call_id,
            method: frame.method,
            payload: frame.payload,
        }
    }
}

impl From<WorkerCall> for WorkerCallFrame {
    fn from(call: WorkerCall) -> Self {
        Self {
            call_id: call.call_id,
            method: call.method,
            payload: call.payload,
        }
    }
}

/// A call that passed every control and may be dispatched.
#[derive(Clone, Debug, PartialEq)]
pub struct CallAccepted {
    /// The session that made the call.
    pub session: SessionId,
    /// Identity of the accepted call.
    pub call_id: CallId,
    /// The method to dispatch.
    pub method: MethodName,
    /// Opaque method arguments.
    pub payload: serde_json::Value,
}

#[derive(Clone, Debug)]
struct PendingTicket {
    ticket: AdmissionTicket,
    secret: AdmissionSecret,
}

#[derive(Clone, Debug)]
struct SessionState {
    worker_id: WorkerId,
    fencing_token: FencingToken,
    allowed_methods: MethodAllowlist,
    expires_at_ms: u64,
    accepted_calls: BTreeSet<CallId>,
    closed: bool,
}

/// Mints, redeems and screens closed worker admissions.
#[derive(Debug)]
pub struct AdmissionController {
    clock: Arc<dyn Clock>,
    secrets: Arc<dyn SecretSource>,
    limits: PayloadLimits,
    generations: GenerationLedger,
    pending: BTreeMap<TicketId, PendingTicket>,
    redeemed: BTreeSet<TicketId>,
    sessions: BTreeMap<SessionId, SessionState>,
    next_session: u64,
}

impl AdmissionController {
    /// Creates a controller.
    ///
    /// # Errors
    ///
    /// Returns [`crate::limits::LimitError`] if a payload cap is zero, because
    /// a controller that rejects every frame is a misconfiguration rather than
    /// a strict policy.
    pub fn new(
        clock: Arc<dyn Clock>,
        secrets: Arc<dyn SecretSource>,
        limits: PayloadLimits,
    ) -> Result<Self, crate::limits::LimitError> {
        limits.validate()?;
        Ok(Self {
            clock,
            secrets,
            limits,
            generations: GenerationLedger::new(),
            pending: BTreeMap::new(),
            redeemed: BTreeSet::new(),
            sessions: BTreeMap::new(),
            next_session: 1,
        })
    }

    /// Returns the configured payload caps.
    #[must_use]
    pub const fn limits(&self) -> PayloadLimits {
        self.limits
    }

    /// Returns the live generation for `worker`, if any.
    #[must_use]
    pub fn current_generation(&self, worker: &WorkerId) -> Option<FencingToken> {
        self.generations.current(worker)
    }

    /// Mints a single-use ticket and opens a fresh generation for `worker`.
    ///
    /// Issuing is what fences: the new generation supersedes every outstanding
    /// ticket and every live session for this identity, which is what makes a
    /// restarted or partitioned worker unable to keep acting on the old one.
    ///
    /// # Errors
    ///
    /// Returns [`IssueError`] when the time-to-live is zero, the expiry instant
    /// overflows, the generation counter is exhausted, the randomness source
    /// fails, or the generated ticket identity collides with a known one.
    pub fn issue(
        &mut self,
        worker: &WorkerId,
        ttl_ms: u64,
        allowed_methods: MethodAllowlist,
    ) -> Result<IssuedAdmission, IssueError> {
        if ttl_ms == 0 {
            return Err(IssueError::ZeroTimeToLive);
        }
        let now_ms = self.clock.unix_millis();
        let expires_at_ms = now_ms
            .checked_add(ttl_ms)
            .ok_or(IssueError::ExpiryOverflow { now_ms, ttl_ms })?;

        let mut identity_bytes = [0_u8; TICKET_ID_BYTES];
        self.secrets.fill(&mut identity_bytes)?;
        let ticket_id = TicketId::new(encode_hex(&identity_bytes))
            .expect("hex of a fixed-length buffer is a valid identifier");
        if self.pending.contains_key(&ticket_id) || self.redeemed.contains(&ticket_id) {
            return Err(IssueError::TicketIdCollision { ticket_id });
        }

        let mut secret_bytes = [0_u8; ADMISSION_SECRET_BYTES];
        self.secrets.fill(&mut secret_bytes)?;
        let secret = AdmissionSecret::from_bytes(secret_bytes);

        let fencing_token = self.generations.open_generation(worker)?;
        let ticket = AdmissionTicket {
            ticket_id: ticket_id.clone(),
            worker_id: worker.clone(),
            fencing_token,
            issued_at_ms: now_ms,
            expires_at_ms,
            allowed_methods,
        };
        self.pending.insert(
            ticket_id,
            PendingTicket {
                ticket: ticket.clone(),
                secret: secret.clone(),
            },
        );
        Ok(IssuedAdmission { ticket, secret })
    }

    /// Opens a new generation for `worker` without minting a ticket.
    ///
    /// This is how an operator evicts a worker: every outstanding ticket and
    /// every live session for the identity is fenced off immediately.
    ///
    /// # Errors
    ///
    /// Returns [`crate::fencing::FencingError::GenerationOverflow`] if the
    /// counter is exhausted.
    pub fn fence(
        &mut self,
        worker: &WorkerId,
    ) -> Result<FencingToken, crate::fencing::FencingError> {
        self.generations.open_generation(worker)
    }

    /// Screens an encoded admission frame.
    ///
    /// The length check runs before the parser, so an oversized frame is never
    /// decoded and cannot be used to force allocation.
    ///
    /// # Errors
    ///
    /// Returns [`AdmissionRejection`] naming the control that refused the
    /// frame.
    pub fn admit_encoded(&mut self, frame: &[u8]) -> Result<AdmittedSession, AdmissionRejection> {
        let limit = self.limits.max_admission_bytes;
        if frame.len() > limit {
            return Err(AdmissionRejection::PayloadTooLarge {
                limit,
                actual: frame.len(),
            });
        }
        let request: AdmissionRequest =
            serde_json::from_slice(frame).map_err(|error| AdmissionRejection::Malformed {
                message: error.to_string(),
            })?;
        self.admit(&request)
    }

    /// Screens a decoded admission request.
    ///
    /// # Errors
    ///
    /// Returns [`AdmissionRejection`] naming the control that refused the
    /// request. There is no path that admits a worker without passing all of
    /// them.
    pub fn admit(
        &mut self,
        request: &AdmissionRequest,
    ) -> Result<AdmittedSession, AdmissionRejection> {
        if self.redeemed.contains(&request.ticket_id) {
            return Err(AdmissionRejection::TicketAlreadyRedeemed {
                ticket_id: request.ticket_id.clone(),
            });
        }
        let pending = self.pending.get(&request.ticket_id).ok_or_else(|| {
            AdmissionRejection::UnknownTicket {
                ticket_id: request.ticket_id.clone(),
            }
        })?;

        // Constant-time comparison. A mismatch does not burn the ticket:
        // guessing a 256-bit secret is infeasible, and burning would let anyone
        // who learns a ticket identity deny the worker its admission.
        if pending.secret != request.secret {
            return Err(AdmissionRejection::SecretMismatch {
                ticket_id: request.ticket_id.clone(),
            });
        }
        if pending.ticket.worker_id != request.worker_id {
            return Err(AdmissionRejection::WorkerIdentityMismatch {
                expected: pending.ticket.worker_id.clone(),
                presented: request.worker_id.clone(),
            });
        }

        let now_ms = self.clock.unix_millis();
        if now_ms < pending.ticket.issued_at_ms {
            return Err(AdmissionRejection::NotYetValid {
                issued_at_ms: pending.ticket.issued_at_ms,
                now_ms,
            });
        }
        if now_ms >= pending.ticket.expires_at_ms {
            return Err(AdmissionRejection::Expired {
                expires_at_ms: pending.ticket.expires_at_ms,
                now_ms,
            });
        }

        // Both the generation the caller claims and the generation the ticket
        // was minted for must be the live one.
        self.generations
            .verify(&pending.ticket.worker_id, request.fencing_token)?;
        self.generations
            .verify(&pending.ticket.worker_id, pending.ticket.fencing_token)?;

        let pending = self
            .pending
            .remove(&request.ticket_id)
            .expect("the ticket was present for the whole admission check");
        self.redeemed.insert(request.ticket_id.clone());

        let session = SessionId(self.next_session);
        self.next_session = self
            .next_session
            .checked_add(1)
            .expect("session handles are exhausted only after 2^64 admissions");
        let admitted = AdmittedSession {
            session,
            worker_id: pending.ticket.worker_id.clone(),
            fencing_token: pending.ticket.fencing_token,
            expires_at_ms: pending.ticket.expires_at_ms,
            allowed_methods: pending.ticket.allowed_methods.clone(),
        };
        self.sessions.insert(
            session,
            SessionState {
                worker_id: pending.ticket.worker_id,
                fencing_token: pending.ticket.fencing_token,
                allowed_methods: pending.ticket.allowed_methods,
                expires_at_ms: pending.ticket.expires_at_ms,
                accepted_calls: BTreeSet::new(),
                closed: false,
            },
        );
        Ok(admitted)
    }

    /// Screens an encoded worker RPC frame.
    ///
    /// The length check runs before the parser.
    ///
    /// # Errors
    ///
    /// Returns [`CallRejection`] naming the control that refused the frame.
    pub fn call_encoded(
        &mut self,
        session: SessionId,
        frame: &[u8],
    ) -> Result<CallAccepted, CallRejection> {
        let limit = self.limits.max_call_bytes;
        if frame.len() > limit {
            return Err(CallRejection::PayloadTooLarge {
                limit,
                actual: frame.len(),
            });
        }
        let decoded: WorkerCallFrame =
            serde_json::from_slice(frame).map_err(|error| CallRejection::Malformed {
                message: error.to_string(),
            })?;
        self.call(session, decoded.into())
    }

    /// Screens a decoded worker RPC call.
    ///
    /// A call identifier is recorded only when the call is accepted, so a
    /// denial never consumes an identifier the worker may legitimately retry
    /// with once it holds the right grant.
    ///
    /// # Errors
    ///
    /// Returns [`CallRejection`] naming the control that refused the call.
    pub fn call(
        &mut self,
        session: SessionId,
        call: WorkerCall,
    ) -> Result<CallAccepted, CallRejection> {
        let now_ms = self.clock.unix_millis();
        let state = self
            .sessions
            .get(&session)
            .ok_or(CallRejection::UnknownSession { session })?;
        if state.closed {
            return Err(CallRejection::SessionClosed { session });
        }
        self.generations
            .verify(&state.worker_id, state.fencing_token)?;
        if now_ms >= state.expires_at_ms {
            return Err(CallRejection::SessionExpired {
                expires_at_ms: state.expires_at_ms,
                now_ms,
            });
        }
        if state.accepted_calls.contains(&call.call_id) {
            return Err(CallRejection::DuplicateCall {
                call_id: call.call_id,
            });
        }
        if !state.allowed_methods.admits(&call.method) {
            return Err(CallRejection::MethodNotAllowed {
                method: call.method,
            });
        }

        let state = self
            .sessions
            .get_mut(&session)
            .expect("the session was present for the whole call check");
        state.accepted_calls.insert(call.call_id.clone());
        Ok(CallAccepted {
            session,
            call_id: call.call_id,
            method: call.method,
            payload: call.payload,
        })
    }

    /// Closes a session. Returns `false` if it was already closed or unknown.
    pub fn close(&mut self, session: SessionId) -> bool {
        match self.sessions.get_mut(&session) {
            Some(state) if !state.closed => {
                state.closed = true;
                true
            }
            _ => false,
        }
    }

    /// Reports whether a session exists and is open.
    #[must_use]
    pub fn is_open(&self, session: SessionId) -> bool {
        self.sessions
            .get(&session)
            .is_some_and(|state| !state.closed)
    }
}

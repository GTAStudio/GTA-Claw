//! The closed worker protocol.
//!
//! The frozen gateway inventory pins a `worker` role whose `protocol_class` is `closed_worker`:
//! a worker may only call the nine machine-role (`node` scope) methods, it must present a ticket
//! issued by the runtime before it may call anything, and every readmission fences the previous
//! session so a stale worker cannot keep writing.

use std::collections::HashMap;
use std::error::Error;
use std::fmt::{self, Display, Formatter};
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::Duration;

use claw_application::model::ids::WorkerId;
use claw_application::model::time::Timestamp;
use claw_application::ports::clock::ClockPort;

/// The gateway protocol version this worker contract is frozen against.
pub const WORKER_PROTOCOL_VERSION: u32 = 4;

/// The methods a closed worker may call.
///
/// These are exactly the nine methods the frozen `gateway-protocol` inventory marks with the
/// machine-role `node` scope; nothing else is reachable from a worker connection.
pub const DEFAULT_WORKER_METHOD_ALLOWLIST: [&str; 9] = [
    "node.event",
    "node.invoke.result",
    "node.pending.ack",
    "node.pending.drain",
    "node.pending.pull",
    "node.pluginSurface.refresh",
    "node.pluginTools.update",
    "node.skills.update",
    "skills.bins",
];

/// Worker admission limits.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct WorkerConfig {
    /// How long an issued ticket may be redeemed for.
    pub ticket_ttl: Duration,
    /// How long a worker session survives without a heartbeat.
    pub session_ttl: Duration,
    /// The largest accepted call payload, in bytes.
    pub max_payload_bytes: usize,
    /// The methods a worker may call.
    pub allowlist: Vec<String>,
}

impl Default for WorkerConfig {
    fn default() -> Self {
        Self {
            ticket_ttl: Duration::from_secs(30),
            session_ttl: Duration::from_mins(2),
            max_payload_bytes: 1 << 20,
            allowlist: DEFAULT_WORKER_METHOD_ALLOWLIST
                .iter()
                .map(|method| (*method).to_owned())
                .collect(),
        }
    }
}

/// A single-use admission ticket.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct WorkerTicket {
    /// The worker the ticket admits.
    pub worker_id: WorkerId,
    /// The opaque ticket secret.
    pub secret: String,
    /// When the ticket was issued.
    pub issued_at: Timestamp,
    /// When the ticket stops being redeemable.
    pub expires_at: Timestamp,
}

/// An admitted worker session.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct WorkerSession {
    /// The admitted worker.
    pub worker_id: WorkerId,
    /// The fence token; every readmission increments it.
    pub fence: u64,
    /// When the worker was admitted.
    pub admitted_at: Timestamp,
    /// When the session expires without a heartbeat.
    pub expires_at: Timestamp,
    /// The highest call sequence accepted so far.
    pub last_sequence: u64,
}

/// One inbound worker call.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct WorkerCall {
    /// The calling worker.
    pub worker_id: WorkerId,
    /// The fence the worker believes it holds.
    pub fence: u64,
    /// The monotonic call sequence within the session.
    pub sequence: u64,
    /// The gateway method being called.
    pub method: String,
    /// The encoded payload size in bytes.
    pub payload_bytes: usize,
}

/// A refused worker operation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum WorkerError {
    /// The presented ticket was never issued, or was already redeemed.
    UnknownTicket,
    /// The presented ticket expired.
    TicketExpired {
        /// When the ticket expired.
        expired_at: Timestamp,
    },
    /// The ticket belongs to a different worker.
    TicketWorkerMismatch {
        /// The worker the ticket was issued to.
        expected: WorkerId,
        /// The worker that presented it.
        presented: WorkerId,
    },
    /// The worker speaks a protocol version this runtime does not.
    UnsupportedProtocol {
        /// The version the runtime speaks.
        expected: u32,
        /// The version the worker announced.
        announced: u32,
    },
    /// No admitted session exists for this worker.
    UnknownWorker(WorkerId),
    /// The worker presented a stale fence, so a newer session replaced it.
    Fenced {
        /// The fence the live session holds.
        current: u64,
        /// The fence the caller presented.
        presented: u64,
    },
    /// The session expired before the call arrived.
    SessionExpired {
        /// When the session expired.
        expired_at: Timestamp,
    },
    /// The method is outside the closed worker allowlist.
    MethodNotAllowed(String),
    /// The call sequence did not advance, so this is a replay.
    ReplayDetected {
        /// The highest sequence already accepted.
        last: u64,
        /// The sequence that was presented.
        presented: u64,
    },
    /// The payload exceeded the configured limit.
    PayloadTooLarge {
        /// The configured limit.
        limit: usize,
        /// The size that was presented.
        presented: usize,
    },
    /// A deadline could not be represented.
    DeadlineOverflow,
}

impl Display for WorkerError {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        match self {
            Self::UnknownTicket => formatter.write_str("unknown or already redeemed worker ticket"),
            Self::TicketExpired { expired_at } => {
                write!(formatter, "worker ticket expired at {expired_at}")
            }
            Self::TicketWorkerMismatch {
                expected,
                presented,
            } => write!(
                formatter,
                "ticket was issued to worker {expected}, not {presented}"
            ),
            Self::UnsupportedProtocol {
                expected,
                announced,
            } => write!(
                formatter,
                "worker announced protocol v{announced}, runtime speaks v{expected}"
            ),
            Self::UnknownWorker(worker_id) => write!(formatter, "unknown worker {worker_id}"),
            Self::Fenced { current, presented } => write!(
                formatter,
                "fence {presented} is stale; the live session holds {current}"
            ),
            Self::SessionExpired { expired_at } => {
                write!(formatter, "worker session expired at {expired_at}")
            }
            Self::MethodNotAllowed(method) => {
                write!(formatter, "method {method} is not allowed for workers")
            }
            Self::ReplayDetected { last, presented } => write!(
                formatter,
                "sequence {presented} replays or precedes the accepted sequence {last}"
            ),
            Self::PayloadTooLarge { limit, presented } => write!(
                formatter,
                "payload of {presented} bytes exceeds the {limit} byte limit"
            ),
            Self::DeadlineOverflow => formatter.write_str("worker deadline overflowed"),
        }
    }
}

impl Error for WorkerError {}

#[derive(Debug, Default)]
struct RegistryState {
    /// Bounded by [`WorkerRegistry::reclaim_stale_tickets`]: an entry lives for its
    /// `ticket_ttl` plus one more `ticket_ttl` of diagnostic grace, so the table holds only
    /// what was issued in that window rather than everything ever issued.
    tickets: HashMap<String, WorkerTicket>,
    sessions: HashMap<WorkerId, WorkerSession>,
    next_fence: u64,
}

/// Tracks worker tickets and admitted worker sessions.
#[derive(Clone)]
pub struct WorkerRegistry {
    state: Arc<Mutex<RegistryState>>,
    clock: Arc<dyn ClockPort>,
    config: WorkerConfig,
}

impl fmt::Debug for WorkerRegistry {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("WorkerRegistry")
            .field("config", &self.config)
            .finish_non_exhaustive()
    }
}

impl WorkerRegistry {
    /// Creates an empty registry.
    #[must_use]
    pub fn new(clock: Arc<dyn ClockPort>, config: WorkerConfig) -> Self {
        Self {
            state: Arc::new(Mutex::new(RegistryState {
                next_fence: 1,
                ..RegistryState::default()
            })),
            clock,
            config,
        }
    }

    /// Returns whether a method is inside the closed worker allowlist.
    #[must_use]
    pub fn allows_method(&self, method: &str) -> bool {
        self.config
            .allowlist
            .iter()
            .any(|allowed| allowed == method)
    }

    /// Issues a single-use admission ticket.
    ///
    /// Issuing is also when the table is swept: a ticket that expired more than one `ticket_ttl`
    /// ago is reclaimed here, so the registry holds only the tickets issued inside that window
    /// instead of every ticket it ever minted. See [`WorkerRegistry::retained_tickets`] for why
    /// the sweep waits rather than reclaiming at expiry.
    ///
    /// # Errors
    ///
    /// Returns [`WorkerError::DeadlineOverflow`] when the ticket deadline cannot be represented.
    pub fn issue_ticket(
        &self,
        worker_id: WorkerId,
        secret: impl Into<String>,
    ) -> Result<WorkerTicket, WorkerError> {
        let issued_at = self.clock.now();
        let expires_at = issued_at
            .checked_add(self.config.ticket_ttl)
            .ok_or(WorkerError::DeadlineOverflow)?;
        let ticket = WorkerTicket {
            worker_id,
            secret: secret.into(),
            issued_at,
            expires_at,
        };
        let mut state = self.lock();
        Self::reclaim_stale_tickets(&mut state, issued_at, self.config.ticket_ttl);
        state.tickets.insert(ticket.secret.clone(), ticket.clone());
        drop(state);
        Ok(ticket)
    }

    /// Redeems a ticket and admits the worker, fencing any previous session.
    ///
    /// # Errors
    ///
    /// Returns [`WorkerError::UnsupportedProtocol`], [`WorkerError::UnknownTicket`],
    /// [`WorkerError::TicketExpired`], [`WorkerError::TicketWorkerMismatch`] or
    /// [`WorkerError::DeadlineOverflow`].
    pub fn admit(
        &self,
        worker_id: &WorkerId,
        secret: &str,
        protocol_version: u32,
    ) -> Result<WorkerSession, WorkerError> {
        if protocol_version != WORKER_PROTOCOL_VERSION {
            return Err(WorkerError::UnsupportedProtocol {
                expected: WORKER_PROTOCOL_VERSION,
                announced: protocol_version,
            });
        }

        let now = self.clock.now();
        let expires_at = now
            .checked_add(self.config.session_ttl)
            .ok_or(WorkerError::DeadlineOverflow)?;

        // Every refusal releases the lock before it builds its error, so a rejected admission
        // never makes a live worker wait on identifier cloning.
        let mut state = self.lock();
        // A ticket is single use: it is removed whether or not it turns out to be valid, so a
        // leaked secret cannot be replayed after the first attempt.
        let Some(ticket) = state.tickets.remove(secret) else {
            drop(state);
            return Err(WorkerError::UnknownTicket);
        };

        if &ticket.worker_id != worker_id {
            drop(state);
            return Err(WorkerError::TicketWorkerMismatch {
                expected: ticket.worker_id,
                presented: worker_id.clone(),
            });
        }
        if now >= ticket.expires_at {
            drop(state);
            return Err(WorkerError::TicketExpired {
                expired_at: ticket.expires_at,
            });
        }

        let fence = state.next_fence;
        state.next_fence = state.next_fence.saturating_add(1);
        let session = WorkerSession {
            worker_id: worker_id.clone(),
            fence,
            admitted_at: now,
            expires_at,
            last_sequence: 0,
        };
        state.sessions.insert(worker_id.clone(), session.clone());
        drop(state);
        Ok(session)
    }

    /// Extends a live session's expiry.
    ///
    /// # Errors
    ///
    /// Returns the same errors as [`WorkerRegistry::dispatch`] minus the method and payload
    /// checks.
    pub fn heartbeat(
        &self,
        worker_id: &WorkerId,
        fence: u64,
    ) -> Result<WorkerSession, WorkerError> {
        let now = self.clock.now();
        let expires_at = now
            .checked_add(self.config.session_ttl)
            .ok_or(WorkerError::DeadlineOverflow)?;

        let mut state = self.lock();
        let beaten = Self::live_session_mut(&mut state, worker_id, fence, now).map(|session| {
            session.expires_at = expires_at;
            session.clone()
        });
        drop(state);
        beaten
    }

    /// Accepts one worker call, enforcing fencing, expiry, the allowlist, replay and size limits.
    ///
    /// # Errors
    ///
    /// Returns [`WorkerError::UnknownWorker`], [`WorkerError::Fenced`],
    /// [`WorkerError::SessionExpired`], [`WorkerError::MethodNotAllowed`],
    /// [`WorkerError::ReplayDetected`] or [`WorkerError::PayloadTooLarge`].
    pub fn dispatch(&self, call: &WorkerCall) -> Result<WorkerSession, WorkerError> {
        if !self.allows_method(&call.method) {
            return Err(WorkerError::MethodNotAllowed(call.method.clone()));
        }
        if call.payload_bytes > self.config.max_payload_bytes {
            return Err(WorkerError::PayloadTooLarge {
                limit: self.config.max_payload_bytes,
                presented: call.payload_bytes,
            });
        }

        let now = self.clock.now();
        let mut state = self.lock();
        let accepted = Self::live_session_mut(&mut state, &call.worker_id, call.fence, now)
            .and_then(|session| {
                if call.sequence <= session.last_sequence {
                    return Err(WorkerError::ReplayDetected {
                        last: session.last_sequence,
                        presented: call.sequence,
                    });
                }
                session.last_sequence = call.sequence;
                Ok(session.clone())
            });
        drop(state);
        accepted
    }

    /// Removes a worker session, for example when its transport closes.
    ///
    /// Returns the evicted session when one existed.
    #[must_use]
    pub fn evict(&self, worker_id: &WorkerId) -> Option<WorkerSession> {
        self.lock().sessions.remove(worker_id)
    }

    /// Returns the live session of a worker, if any, dropping it when expired.
    #[must_use]
    pub fn session(&self, worker_id: &WorkerId) -> Option<WorkerSession> {
        let now = self.clock.now();
        let mut state = self.lock();
        let live = state
            .sessions
            .get(worker_id)
            .filter(|session| now < session.expires_at)
            .cloned();
        if live.is_none() {
            state.sessions.remove(worker_id);
        }
        drop(state);
        live
    }

    /// Returns every live session, ordered by fence.
    #[must_use]
    pub fn sessions(&self) -> Vec<WorkerSession> {
        let now = self.clock.now();
        // The sweep and the clone-out need the lock; the sort does not.
        let mut sessions: Vec<WorkerSession> = {
            let mut state = self.lock();
            state.sessions.retain(|_, session| now < session.expires_at);
            state.sessions.values().cloned().collect()
        };
        sessions.sort_by_key(|session| session.fence);
        sessions
    }

    /// Returns the number of tickets that have been issued but not redeemed or expired.
    ///
    /// Counting is destructive: every ticket found expired is dropped here rather than kept for
    /// the grace window [`WorkerRegistry::retained_tickets`] describes, so a redemption after this
    /// call is refused with [`WorkerError::UnknownTicket`] instead of
    /// [`WorkerError::TicketExpired`]. Use `retained_tickets` to observe without sweeping.
    #[must_use]
    pub fn outstanding_tickets(&self) -> usize {
        let now = self.clock.now();
        let mut state = self.lock();
        state.tickets.retain(|_, ticket| now < ticket.expires_at);
        state.tickets.len()
    }

    /// Returns how many tickets the registry is holding, expired ones included.
    ///
    /// This is deliberately larger than [`WorkerRegistry::outstanding_tickets`] for a while. An
    /// expired ticket is kept past its deadline so that a worker presenting it is refused with
    /// [`WorkerError::TicketExpired`], which tells it to ask for a new ticket, rather than with
    /// [`WorkerError::UnknownTicket`], which is the answer to a forged secret. Dropping the entry
    /// at `expires_at` would erase that distinction; keeping it forever would grow this table for
    /// as long as the process lives. One further `ticket_ttl` of grace is long enough that no
    /// worker can still be mid-handshake with the ticket, and short enough that the table's size
    /// is a function of the recent issue rate rather than of uptime.
    ///
    /// Unlike `outstanding_tickets`, this observes without sweeping.
    #[must_use]
    pub fn retained_tickets(&self) -> usize {
        self.lock().tickets.len()
    }

    /// Drops tickets that expired more than `grace` ago.
    ///
    /// A deadline that cannot be represented is kept: an unrepresentable reclamation point is not
    /// a reason to forget a ticket a worker may still hold.
    fn reclaim_stale_tickets(state: &mut RegistryState, now: Timestamp, grace: Duration) {
        state.tickets.retain(|_, ticket| {
            ticket
                .expires_at
                .checked_add(grace)
                .is_none_or(|reclaim_at| now < reclaim_at)
        });
    }

    fn live_session_mut<'state>(
        state: &'state mut RegistryState,
        worker_id: &WorkerId,
        fence: u64,
        now: Timestamp,
    ) -> Result<&'state mut WorkerSession, WorkerError> {
        let session = state
            .sessions
            .get(worker_id)
            .ok_or_else(|| WorkerError::UnknownWorker(worker_id.clone()))?;

        if session.fence != fence {
            return Err(WorkerError::Fenced {
                current: session.fence,
                presented: fence,
            });
        }
        if now >= session.expires_at {
            let expired_at = session.expires_at;
            state.sessions.remove(worker_id);
            return Err(WorkerError::SessionExpired { expired_at });
        }

        state
            .sessions
            .get_mut(worker_id)
            .ok_or_else(|| WorkerError::UnknownWorker(worker_id.clone()))
    }

    fn lock(&self) -> MutexGuard<'_, RegistryState> {
        self.state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }
}

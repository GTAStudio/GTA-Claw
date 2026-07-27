//! Typed, reason-bearing rejections.
//!
//! Every variant names the exact thing that failed and, where a comparison
//! decided it, both sides of that comparison. A caller that only checks
//! `is_err` learns nothing; a test that asserts the variant proves the control
//! that actually fired.

use std::error::Error;
use std::fmt::{self, Display, Formatter};

use crate::allowlist::MethodName;
use crate::controller::SessionId;
use crate::fencing::FencingError;
use crate::identity::{CallId, TicketId, WorkerId};
use crate::limits::LimitError;
use crate::secret::SecretSourceError;

/// Why a worker was not admitted.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum AdmissionRejection {
    /// The encoded frame exceeded the admission cap and was never parsed.
    PayloadTooLarge {
        /// Configured cap in bytes.
        limit: usize,
        /// Length of the rejected frame in bytes.
        actual: usize,
    },
    /// The frame was not a well-formed admission request.
    Malformed {
        /// Parser diagnostic.
        message: String,
    },
    /// No such ticket was ever issued, or it has been forgotten.
    UnknownTicket {
        /// The ticket identity presented.
        ticket_id: TicketId,
    },
    /// The ticket was already redeemed; this is a replay.
    TicketAlreadyRedeemed {
        /// The ticket identity presented.
        ticket_id: TicketId,
    },
    /// The credential did not match the issued secret.
    SecretMismatch {
        /// The ticket identity presented.
        ticket_id: TicketId,
    },
    /// The ticket was issued to a different worker identity.
    WorkerIdentityMismatch {
        /// Identity the ticket was issued to.
        expected: WorkerId,
        /// Identity the caller claimed.
        presented: WorkerId,
    },
    /// The ticket is not valid yet.
    NotYetValid {
        /// Unix milliseconds at which the ticket becomes valid.
        issued_at_ms: u64,
        /// Unix milliseconds observed by the controller.
        now_ms: u64,
    },
    /// The ticket has expired.
    Expired {
        /// Unix milliseconds at which the ticket stopped being valid.
        expires_at_ms: u64,
        /// Unix milliseconds observed by the controller.
        now_ms: u64,
    },
    /// The presented or ticketed generation is not the live one.
    Fenced(FencingError),
}

impl Display for AdmissionRejection {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        match self {
            Self::PayloadTooLarge { limit, actual } => write!(
                formatter,
                "admission frame is {actual} bytes; the cap is {limit}"
            ),
            Self::Malformed { message } => {
                write!(formatter, "admission frame is malformed: {message}")
            }
            Self::UnknownTicket { ticket_id } => {
                write!(formatter, "admission ticket `{ticket_id}` was never issued")
            }
            Self::TicketAlreadyRedeemed { ticket_id } => write!(
                formatter,
                "admission ticket `{ticket_id}` was already redeemed"
            ),
            Self::SecretMismatch { ticket_id } => write!(
                formatter,
                "the credential for admission ticket `{ticket_id}` does not match"
            ),
            Self::WorkerIdentityMismatch {
                expected,
                presented,
            } => write!(
                formatter,
                "admission ticket belongs to worker `{expected}`, not `{presented}`"
            ),
            Self::NotYetValid {
                issued_at_ms,
                now_ms,
            } => write!(
                formatter,
                "admission ticket becomes valid at {issued_at_ms}ms; it is {now_ms}ms"
            ),
            Self::Expired {
                expires_at_ms,
                now_ms,
            } => write!(
                formatter,
                "admission ticket expired at {expires_at_ms}ms; it is {now_ms}ms"
            ),
            Self::Fenced(error) => Display::fmt(error, formatter),
        }
    }
}

impl Error for AdmissionRejection {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Fenced(error) => Some(error),
            _ => None,
        }
    }
}

impl From<FencingError> for AdmissionRejection {
    fn from(error: FencingError) -> Self {
        Self::Fenced(error)
    }
}

/// Why a worker RPC call was not accepted.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum CallRejection {
    /// The encoded frame exceeded the call cap and was never parsed.
    PayloadTooLarge {
        /// Configured cap in bytes.
        limit: usize,
        /// Length of the rejected frame in bytes.
        actual: usize,
    },
    /// The frame was not a well-formed worker call.
    Malformed {
        /// Parser diagnostic.
        message: String,
    },
    /// The session identifier does not name a session.
    UnknownSession {
        /// The session identifier presented.
        session: SessionId,
    },
    /// The session was closed.
    SessionClosed {
        /// The session identifier presented.
        session: SessionId,
    },
    /// A newer generation of this worker has been admitted.
    SessionFenced(FencingError),
    /// The session's lease has run out.
    SessionExpired {
        /// Unix milliseconds at which the lease ran out.
        expires_at_ms: u64,
        /// Unix milliseconds observed by the controller.
        now_ms: u64,
    },
    /// This call identifier was already accepted on this session; a replay.
    DuplicateCall {
        /// The repeated call identity.
        call_id: CallId,
    },
    /// The method is not in this session's closed allowlist.
    MethodNotAllowed {
        /// The method the caller named.
        method: MethodName,
    },
}

impl Display for CallRejection {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        match self {
            Self::PayloadTooLarge { limit, actual } => write!(
                formatter,
                "worker call frame is {actual} bytes; the cap is {limit}"
            ),
            Self::Malformed { message } => {
                write!(formatter, "worker call frame is malformed: {message}")
            }
            Self::UnknownSession { session } => {
                write!(formatter, "worker session {session} does not exist")
            }
            Self::SessionClosed { session } => {
                write!(formatter, "worker session {session} is closed")
            }
            Self::SessionFenced(error) => Display::fmt(error, formatter),
            Self::SessionExpired {
                expires_at_ms,
                now_ms,
            } => write!(
                formatter,
                "worker session lease expired at {expires_at_ms}ms; it is {now_ms}ms"
            ),
            Self::DuplicateCall { call_id } => {
                write!(formatter, "call `{call_id}` was already accepted")
            }
            Self::MethodNotAllowed { method } => write!(
                formatter,
                "`{method}` is not in this worker session's allowlist"
            ),
        }
    }
}

impl Error for CallRejection {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::SessionFenced(error) => Some(error),
            _ => None,
        }
    }
}

impl From<FencingError> for CallRejection {
    fn from(error: FencingError) -> Self {
        Self::SessionFenced(error)
    }
}

/// Why a ticket could not be minted.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum IssueError {
    /// A zero time-to-live would mint a ticket that is already expired.
    ZeroTimeToLive,
    /// The expiry instant does not fit in Unix milliseconds.
    ExpiryOverflow {
        /// Unix milliseconds observed by the controller.
        now_ms: u64,
        /// Requested time-to-live in milliseconds.
        ttl_ms: u64,
    },
    /// The generation counter could not advance.
    Fencing(FencingError),
    /// The randomness source failed; no ticket is minted with a weak secret.
    SecretSource(SecretSourceError),
    /// The freshly generated ticket identifier is already in use.
    TicketIdCollision {
        /// The colliding ticket identity.
        ticket_id: TicketId,
    },
    /// The controller was configured with an unusable payload cap.
    Limit(LimitError),
}

impl Display for IssueError {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        match self {
            Self::ZeroTimeToLive => {
                formatter.write_str("an admission ticket must have a positive time-to-live")
            }
            Self::ExpiryOverflow { now_ms, ttl_ms } => write!(
                formatter,
                "expiry {now_ms}ms + {ttl_ms}ms does not fit in Unix milliseconds"
            ),
            Self::Fencing(error) => Display::fmt(error, formatter),
            Self::SecretSource(error) => Display::fmt(error, formatter),
            Self::TicketIdCollision { ticket_id } => write!(
                formatter,
                "admission ticket identity `{ticket_id}` is already in use"
            ),
            Self::Limit(error) => Display::fmt(error, formatter),
        }
    }
}

impl Error for IssueError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Fencing(error) => Some(error),
            Self::SecretSource(error) => Some(error),
            Self::Limit(error) => Some(error),
            _ => None,
        }
    }
}

impl From<FencingError> for IssueError {
    fn from(error: FencingError) -> Self {
        Self::Fencing(error)
    }
}

impl From<SecretSourceError> for IssueError {
    fn from(error: SecretSourceError) -> Self {
        Self::SecretSource(error)
    }
}

impl From<LimitError> for IssueError {
    fn from(error: LimitError) -> Self {
        Self::Limit(error)
    }
}

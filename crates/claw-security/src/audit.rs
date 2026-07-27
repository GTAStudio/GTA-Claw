//! Mandatory structured audit port used by protected security transitions.

use std::error::Error;
use std::fmt::{self, Display, Formatter};

use crate::authorization::Role;
use crate::identity::DeviceId;

/// Security-sensitive action recorded without payload or secret bytes.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AuditAction {
    /// Authorization was evaluated.
    AuthorizationEvaluated,
    /// A pairing challenge was issued.
    PairingChallengeIssued,
    /// A device proof was evaluated.
    PairingProofEvaluated,
    /// Explicit approval was requested.
    PairingApprovalRequested,
    /// Pairing was approved.
    PairingApproved,
    /// Pairing was denied.
    PairingDenied,
    /// Pairing expired.
    PairingExpired,
    /// Pairing was revoked.
    PairingRevoked,
    /// Access to a referenced secret was authorized before backend lookup.
    SecretResolutionAuthorized,
    /// A referenced secret was resolved.
    SecretResolved,
}

/// Coarse subject identity safe for audit persistence.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum AuditSubject {
    /// Public device fingerprint.
    Device(DeviceId),
    /// Closed gateway role.
    Role(Role),
    /// Secret reference scheme only; no identifier or resolved bytes.
    SecretScheme(&'static str),
}

/// Security decision outcome.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AuditOutcome {
    /// Policy allowed the action.
    Allowed,
    /// Policy denied the action.
    Denied,
}

/// Stable high-level reason that cannot carry attacker or secret text.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AuditReason {
    /// Required policy gates passed.
    PolicySatisfied,
    /// A policy gate rejected the action.
    PolicyRejected,
    /// State did not permit the transition.
    IllegalTransition,
    /// A cryptographic proof was invalid.
    InvalidProof,
    /// A nonce had already been consumed.
    ReplayDetected,
    /// A bounded lifetime elapsed.
    Expired,
    /// The resolver returned an adapter error.
    ResolverFailed,
}

/// Structured event accepted by a concrete durable audit adapter.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AuditEvent {
    /// Security action.
    pub action: AuditAction,
    /// Public, redacted subject.
    pub subject: AuditSubject,
    /// Allowed or denied.
    pub outcome: AuditOutcome,
    /// Stable reason code.
    pub reason: AuditReason,
    /// Caller-supplied wall-clock timestamp.
    pub unix_millis: u64,
}

/// Durable, bounded audit persistence port.
///
/// Implementations must return only after persistence is committed. Logging,
/// unbounded channels, and fire-and-forget delivery do not satisfy this port.
pub trait AuditSink {
    /// Concrete persistence error.
    type Error: Error + Send + Sync + 'static;

    /// Persists exactly one event or fails the protected operation.
    ///
    /// # Errors
    ///
    /// Returns [`Self::Error`] when the event was not durably committed — for
    /// example an unreachable or full audit store, a rejected record, or a
    /// write that could not be flushed. Implementations must not report success
    /// for a buffered or queued write: every caller in this crate treats the
    /// error as fatal to the protected transition, so a returned `Ok` is the
    /// claim that the decision is already on durable storage.
    fn persist(&mut self, event: &AuditEvent) -> Result<(), Self::Error>;
}

/// A mandatory audit write failed.
#[derive(Debug)]
pub enum AuditFailure<E> {
    /// Concrete sink failure.
    Sink(E),
}

impl<E: Display> Display for AuditFailure<E> {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        match self {
            Self::Sink(error) => write!(formatter, "mandatory audit persistence failed: {error}"),
        }
    }
}

impl<E: Error + 'static> Error for AuditFailure<E> {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Sink(error) => Some(error),
        }
    }
}

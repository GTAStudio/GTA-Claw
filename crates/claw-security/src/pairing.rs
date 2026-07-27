//! Bounded pairing/authentication state machine with explicit external ports.

use std::error::Error;
use std::fmt::{self, Debug, Display, Formatter};

use subtle::ConstantTimeEq;

use crate::audit::{AuditAction, AuditEvent, AuditOutcome, AuditReason, AuditSink, AuditSubject};
use crate::authorization::{
    ClientClass, ProtocolPolicyError, Role, RoleScopeError, ScopeSet, validate_protocol,
    validate_role_scopes,
};
use crate::identity::{
    DeviceId, DeviceIdentity, DevicePublicKey, DeviceSignature, HandshakeSigningInput,
};

const MIN_TTL_MILLIS: u64 = 1_000;
const MAX_TTL_MILLIS: u64 = 5 * 60 * 1_000;
const MAX_ATTEMPTS: u8 = 10;
const MAX_CLOCK_SKEW_MILLIS: u64 = 60_000;
const MIN_CHALLENGE_BYTES: usize = 16;
const MAX_CHALLENGE_BYTES: usize = 256;

/// Monotonic and wall-clock snapshot supplied by an adapter.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ClockSnapshot {
    /// Monotonic process-relative milliseconds for expiration.
    pub monotonic_millis: u64,
    /// Unix milliseconds for signed timestamp validation and audit.
    pub unix_millis: u64,
}

/// Clock port; tests and adapters provide snapshots without sleeping.
pub trait SecurityClock {
    /// Returns one internally consistent time snapshot.
    fn now(&self) -> ClockSnapshot;
}

/// Fixed-size random challenge nonce.
///
/// Equality is constant time. The derived comparison a byte array would
/// otherwise get short-circuits on the first differing byte, which leaks how
/// much of a guessed nonce was correct.
#[derive(Clone, Copy, Eq)]
pub struct ChallengeNonce([u8; 32]);

impl ChallengeNonce {
    /// Constructs a nonce from caller-generated random bytes.
    #[must_use]
    pub const fn new(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    /// Returns bytes only for transport and nonce-store adapters.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    #[must_use = "an ignored nonce comparison silently accepts a mismatched challenge"]
    fn constant_time_eq(&self, other: &Self) -> bool {
        bool::from(self.0.ct_eq(&other.0))
    }
}

impl PartialEq for ChallengeNonce {
    fn eq(&self, other: &Self) -> bool {
        self.constant_time_eq(other)
    }
}

impl Debug for ChallengeNonce {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter.write_str("ChallengeNonce([REDACTED])")
    }
}

/// Atomic nonce reservation/consumption port.
///
/// Implementations must persist bounded entries and make `consume` atomic.
pub trait NonceStore {
    /// Concrete store error.
    type Error: Error + Send + Sync + 'static;

    /// Reserves a unique nonce until the monotonic deadline.
    ///
    /// Returns `Ok(false)` when the nonce is already reserved; a collision is a
    /// normal policy outcome, not an error.
    ///
    /// # Errors
    ///
    /// Returns [`Self::Error`] when the store could not decide the question at
    /// all — an unreachable backing store, a failed durable write, or an
    /// exhausted capacity bound. The caller must abandon the challenge rather
    /// than assume the nonce is fresh, because a lost reservation would allow
    /// the same nonce to be issued twice.
    fn reserve(
        &mut self,
        nonce: &ChallengeNonce,
        expires_at_monotonic_millis: u64,
    ) -> Result<bool, Self::Error>;

    /// Atomically consumes a nonce, returning false for replay or absence.
    ///
    /// # Errors
    ///
    /// Returns [`Self::Error`] when the atomic test-and-remove could not be
    /// performed — an unreachable backing store or a failed durable write. A
    /// caller must treat this as a refusal: an error is not evidence that the
    /// nonce was unused, and proceeding would defeat replay detection.
    fn consume(&mut self, nonce: &ChallengeNonce) -> Result<bool, Self::Error>;
}

/// Bounded pairing policy supplied explicitly rather than inferred from upstream.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PairingPolicy {
    ttl_millis: u64,
    max_attempts: u8,
    max_clock_skew_millis: u64,
}

impl PairingPolicy {
    /// Creates a bounded policy.
    ///
    /// # Errors
    ///
    /// - [`PairingPolicyError::TtlOutOfBounds`] when `ttl_millis` is below one
    ///   second or above five minutes, so a challenge can neither expire before
    ///   a client can answer it nor stay outstanding indefinitely.
    /// - [`PairingPolicyError::AttemptsOutOfBounds`] when `max_attempts` is `0`
    ///   or above ten; zero would deny every proof and a larger budget would
    ///   widen online guessing.
    /// - [`PairingPolicyError::ClockSkewOutOfBounds`] when
    ///   `max_clock_skew_millis` exceeds one minute, which would extend the
    ///   window in which a captured proof timestamp is still accepted.
    pub fn new(
        ttl_millis: u64,
        max_attempts: u8,
        max_clock_skew_millis: u64,
    ) -> Result<Self, PairingPolicyError> {
        if !(MIN_TTL_MILLIS..=MAX_TTL_MILLIS).contains(&ttl_millis) {
            return Err(PairingPolicyError::TtlOutOfBounds);
        }
        if !(1..=MAX_ATTEMPTS).contains(&max_attempts) {
            return Err(PairingPolicyError::AttemptsOutOfBounds);
        }
        if max_clock_skew_millis > MAX_CLOCK_SKEW_MILLIS {
            return Err(PairingPolicyError::ClockSkewOutOfBounds);
        }
        Ok(Self {
            ttl_millis,
            max_attempts,
            max_clock_skew_millis,
        })
    }
}

/// Invalid caller policy.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PairingPolicyError {
    /// TTL must be between one second and five minutes.
    TtlOutOfBounds,
    /// Attempts must be between one and ten.
    AttemptsOutOfBounds,
    /// Clock skew cannot exceed one minute.
    ClockSkewOutOfBounds,
}

impl Display for PairingPolicyError {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        match self {
            Self::TtlOutOfBounds => formatter.write_str("pairing TTL is out of bounds"),
            Self::AttemptsOutOfBounds => formatter.write_str("pairing attempts are out of bounds"),
            Self::ClockSkewOutOfBounds => {
                formatter.write_str("pairing clock skew is out of bounds")
            }
        }
    }
}

impl Error for PairingPolicyError {}

/// Inputs fixed when issuing a challenge.
#[derive(Clone, Debug)]
pub struct ChallengeRequest {
    /// Claimed public key.
    pub public_key: DevicePublicKey,
    /// Exact requested role.
    pub role: Role,
    /// Exact requested closed scopes.
    pub scopes: ScopeSet,
    /// Gateway protocol version.
    pub protocol_version: u16,
    /// Pinned compatibility class.
    pub client_class: ClientClass,
    /// Caller-generated nonce.
    pub nonce: ChallengeNonce,
    /// Caller-generated opaque challenge bytes.
    pub challenge: Vec<u8>,
}

/// Issued challenge exposed to a transport adapter.
#[derive(Clone, Debug)]
pub struct PairingChallenge {
    device_id: DeviceId,
    public_key: DevicePublicKey,
    role: Role,
    scopes: ScopeSet,
    protocol_version: u16,
    client_class: ClientClass,
    nonce: ChallengeNonce,
    challenge: Vec<u8>,
    issued_at: ClockSnapshot,
    expires_at_monotonic_millis: u64,
    attempts: u8,
}

impl PairingChallenge {
    /// Exact nonce bytes for the wire DTO owned by `claw-protocol`.
    #[must_use]
    pub const fn nonce(&self) -> &ChallengeNonce {
        &self.nonce
    }

    /// Exact opaque challenge bytes.
    #[must_use]
    pub fn challenge_bytes(&self) -> &[u8] {
        &self.challenge
    }

    /// Wall-clock issuance time.
    #[must_use]
    pub const fn issued_at_unix_millis(&self) -> u64 {
        self.issued_at.unix_millis
    }

    fn signing_input(&self, signed_at_unix_millis: u64) -> HandshakeSigningInput<'_> {
        HandshakeSigningInput {
            device_id: &self.device_id,
            role: self.role,
            scopes: self.scopes,
            protocol_version: self.protocol_version,
            client_class: self.client_class,
            signed_at_unix_millis,
            nonce: self.nonce.as_bytes(),
            challenge: &self.challenge,
        }
    }
}

/// Device proof supplied after challenge issuance.
#[derive(Clone, Debug)]
pub struct PairingProof {
    device_id: DeviceId,
    public_key: DevicePublicKey,
    role: Role,
    scopes: ScopeSet,
    protocol_version: u16,
    client_class: ClientClass,
    signed_at_unix_millis: u64,
    nonce: ChallengeNonce,
    signature: DeviceSignature,
}

/// Typed, wire-decoded proof parts accepted from a transport adapter.
#[derive(Clone, Copy, Debug)]
pub struct PairingProofParts {
    /// Versioned public device fingerprint.
    pub device_id: DeviceId,
    /// Strictly decoded Ed25519 public key.
    pub public_key: DevicePublicKey,
    /// Exact role claim.
    pub role: Role,
    /// Exact closed scope set.
    pub scopes: ScopeSet,
    /// Gateway protocol claim.
    pub protocol_version: u16,
    /// Pinned compatibility class.
    pub client_class: ClientClass,
    /// Signed wall-clock timestamp.
    pub signed_at_unix_millis: u64,
    /// Strict fixed-size challenge nonce.
    pub nonce: ChallengeNonce,
    /// Strictly decoded Ed25519 signature.
    pub signature: DeviceSignature,
}

impl PairingProof {
    /// Constructs a proof from strictly decoded transport values.
    ///
    /// Construction grants no trust; `PairingSession::verify_proof` validates
    /// every field against the issued challenge before advancing state.
    #[must_use]
    pub const fn from_parts(parts: PairingProofParts) -> Self {
        Self {
            device_id: parts.device_id,
            public_key: parts.public_key,
            role: parts.role,
            scopes: parts.scopes,
            protocol_version: parts.protocol_version,
            client_class: parts.client_class,
            signed_at_unix_millis: parts.signed_at_unix_millis,
            nonce: parts.nonce,
            signature: parts.signature,
        }
    }

    /// Signs all challenge claims and exact challenge bytes.
    #[must_use]
    pub fn signed(
        identity: &DeviceIdentity,
        challenge: &PairingChallenge,
        signed_at_unix_millis: u64,
    ) -> Self {
        let signature = identity.sign_handshake(challenge.signing_input(signed_at_unix_millis));
        Self {
            device_id: identity.device_id(),
            public_key: identity.public_key(),
            role: challenge.role,
            scopes: challenge.scopes,
            protocol_version: challenge.protocol_version,
            client_class: challenge.client_class,
            signed_at_unix_millis,
            nonce: challenge.nonce,
            signature,
        }
    }
}

#[derive(Clone, Debug)]
struct VerifiedPairing {
    challenge: PairingChallenge,
}

#[derive(Clone, Debug)]
enum PairingStateData {
    Unpaired,
    ChallengeIssued(PairingChallenge),
    ProofVerified(VerifiedPairing),
    AwaitingApproval(VerifiedPairing),
    Approved,
    Denied,
    Expired,
    Revoked,
}

/// Public state discriminator.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PairingState {
    /// No challenge exists.
    Unpaired,
    /// Challenge is outstanding.
    ChallengeIssued,
    /// Cryptographic proof succeeded.
    ProofVerified,
    /// Explicit approval is pending.
    AwaitingApproval,
    /// Pairing is approved.
    Approved,
    /// Pairing was denied or exhausted.
    Denied,
    /// Pairing TTL elapsed.
    Expired,
    /// Approved pairing was revoked.
    Revoked,
}

/// Pairing reducer state for one expected device.
#[derive(Clone, Debug)]
pub struct PairingSession {
    device_id: DeviceId,
    state: PairingStateData,
}

impl PairingSession {
    /// Starts an unpaired session bound to one public device identifier.
    #[must_use]
    pub const fn new(device_id: DeviceId) -> Self {
        Self {
            device_id,
            state: PairingStateData::Unpaired,
        }
    }

    /// Returns the explicit state.
    #[must_use]
    pub const fn state(&self) -> PairingState {
        match self.state {
            PairingStateData::Unpaired => PairingState::Unpaired,
            PairingStateData::ChallengeIssued(_) => PairingState::ChallengeIssued,
            PairingStateData::ProofVerified(_) => PairingState::ProofVerified,
            PairingStateData::AwaitingApproval(_) => PairingState::AwaitingApproval,
            PairingStateData::Approved => PairingState::Approved,
            PairingStateData::Denied => PairingState::Denied,
            PairingStateData::Expired => PairingState::Expired,
            PairingStateData::Revoked => PairingState::Revoked,
        }
    }

    /// Returns the current challenge when one exists.
    #[must_use]
    pub const fn challenge(&self) -> Option<&PairingChallenge> {
        match &self.state {
            PairingStateData::ChallengeIssued(challenge) => Some(challenge),
            _ => None,
        }
    }

    /// Issues one bounded, unique challenge.
    ///
    /// # Errors
    ///
    /// Every rejection is audited before it is returned.
    ///
    /// - [`PairingRejection::IllegalTransition`] unless the session is
    ///   [`PairingState::Unpaired`]; an outstanding challenge is never replaced.
    /// - [`PairingRejection::InvalidChallengeLength`] when
    ///   `request.challenge` is shorter than 16 or longer than 256 bytes.
    /// - [`PairingRejection::CrossDevice`] when `request.public_key` does not
    ///   fingerprint to the device this session was created for.
    /// - [`PairingRejection::RoleScopeMismatch`] when a non-operator role
    ///   requests operator scopes.
    /// - [`PairingRejection::ProtocolMismatch`] when the role, client class,
    ///   and protocol version fall outside the pinned compatibility window.
    /// - [`PairingRejection::ClockOverflow`] when the monotonic clock plus the
    ///   policy TTL overflows [`u64`].
    /// - [`PairingRejection::NonceCollision`] when `nonce_store` reports the
    ///   nonce is already reserved.
    /// - [`PairingOperationError::NonceStore`] when the reservation could not
    ///   be decided, and [`PairingOperationError::Audit`] when the audit record
    ///   could not be persisted. In both cases no challenge is issued, so an
    ///   unauditable or unverifiable issuance fails closed.
    pub fn issue_challenge<N, A, C>(
        &mut self,
        request: ChallengeRequest,
        policy: PairingPolicy,
        clock: &C,
        nonce_store: &mut N,
        audit: &mut A,
    ) -> Result<(), PairingOperationError<N::Error, A::Error>>
    where
        N: NonceStore,
        A: AuditSink,
        C: SecurityClock,
    {
        let now = clock.now();
        if !matches!(self.state, PairingStateData::Unpaired) {
            return self.reject_without_nonce(
                AuditAction::PairingChallengeIssued,
                PairingRejection::IllegalTransition,
                now,
                audit,
            );
        }
        if !(MIN_CHALLENGE_BYTES..=MAX_CHALLENGE_BYTES).contains(&request.challenge.len()) {
            return self.reject_without_nonce(
                AuditAction::PairingChallengeIssued,
                PairingRejection::InvalidChallengeLength,
                now,
                audit,
            );
        }
        if request.public_key.device_id() != self.device_id {
            return self.reject_without_nonce(
                AuditAction::PairingChallengeIssued,
                PairingRejection::CrossDevice,
                now,
                audit,
            );
        }
        if validate_role_scopes(request.role, request.scopes).is_err() {
            return self.reject_without_nonce(
                AuditAction::PairingChallengeIssued,
                PairingRejection::RoleScopeMismatch,
                now,
                audit,
            );
        }
        if validate_protocol(request.role, request.client_class, request.protocol_version).is_err()
        {
            return self.reject_without_nonce(
                AuditAction::PairingChallengeIssued,
                PairingRejection::ProtocolMismatch,
                now,
                audit,
            );
        }
        let expires_at = now.monotonic_millis.checked_add(policy.ttl_millis).ok_or(
            PairingOperationError::Rejected(PairingRejection::ClockOverflow),
        )?;
        let reserved = nonce_store
            .reserve(&request.nonce, expires_at)
            .map_err(PairingOperationError::NonceStore)?;
        if !reserved {
            return self.reject_without_nonce(
                AuditAction::PairingChallengeIssued,
                PairingRejection::NonceCollision,
                now,
                audit,
            );
        }
        persist_pairing_event(
            audit,
            self.device_id,
            AuditAction::PairingChallengeIssued,
            AuditOutcome::Allowed,
            AuditReason::PolicySatisfied,
            now.unix_millis,
        )
        .map_err(PairingOperationError::Audit)?;
        self.state = PairingStateData::ChallengeIssued(PairingChallenge {
            device_id: self.device_id,
            public_key: request.public_key,
            role: request.role,
            scopes: request.scopes,
            protocol_version: request.protocol_version,
            client_class: request.client_class,
            nonce: request.nonce,
            challenge: request.challenge,
            issued_at: now,
            expires_at_monotonic_millis: expires_at,
            attempts: 0,
        });
        Ok(())
    }

    /// Verifies exact claims, timestamp, nonce freshness, and Ed25519 proof.
    ///
    /// # Errors
    ///
    /// Every rejection is audited before it is returned, and each failed
    /// cryptographic attempt consumes one of the policy's bounded attempts.
    ///
    /// - [`PairingRejection::IllegalTransition`] unless a challenge is
    ///   outstanding.
    /// - [`PairingRejection::Expired`] when the monotonic TTL of the challenge
    ///   has elapsed; the session moves to [`PairingState::Expired`].
    /// - [`PairingRejection::FutureTimestamp`] or
    ///   [`PairingRejection::StaleTimestamp`] when the signed timestamp is
    ///   outside the policy's clock-skew window.
    /// - [`PairingRejection::CrossDevice`] when the proof's device identifier,
    ///   the fingerprint of its public key, or that key itself differs from the
    ///   one the challenge was issued to.
    /// - [`PairingRejection::RoleMismatch`], [`PairingRejection::ScopeMismatch`],
    ///   [`PairingRejection::ProtocolMismatch`], or
    ///   [`PairingRejection::ClientClassMismatch`] when the corresponding claim
    ///   differs from the issued challenge.
    /// - [`PairingRejection::NonceMismatch`] when the proof nonce is not the
    ///   issued one, compared in constant time.
    /// - [`PairingRejection::InvalidSignature`] when `verify_strict` rejects the
    ///   Ed25519 proof over the exact challenge claims.
    /// - [`PairingRejection::AttemptsExhausted`] when that failure was the last
    ///   permitted attempt; the session moves to [`PairingState::Denied`].
    /// - [`PairingRejection::Replay`] when the nonce store reports the nonce was
    ///   already consumed.
    /// - [`PairingOperationError::NonceStore`] when the consume could not be
    ///   decided, and [`PairingOperationError::Audit`] when a record could not
    ///   be persisted; neither advances the session to
    ///   [`PairingState::ProofVerified`].
    pub fn verify_proof<N, A, C>(
        &mut self,
        proof: &PairingProof,
        policy: PairingPolicy,
        clock: &C,
        nonce_store: &mut N,
        audit: &mut A,
    ) -> Result<(), PairingOperationError<N::Error, A::Error>>
    where
        N: NonceStore,
        A: AuditSink,
        C: SecurityClock,
    {
        let now = clock.now();
        let challenge = match &self.state {
            PairingStateData::ChallengeIssued(challenge) => challenge.clone(),
            _ => {
                return self.reject_without_nonce(
                    AuditAction::PairingProofEvaluated,
                    PairingRejection::IllegalTransition,
                    now,
                    audit,
                );
            }
        };
        if now.monotonic_millis >= challenge.expires_at_monotonic_millis {
            persist_pairing_event(
                audit,
                self.device_id,
                AuditAction::PairingProofEvaluated,
                AuditOutcome::Denied,
                AuditReason::Expired,
                now.unix_millis,
            )
            .map_err(PairingOperationError::Audit)?;
            self.state = PairingStateData::Expired;
            return Err(PairingOperationError::Rejected(PairingRejection::Expired));
        }

        let rejection = if proof.signed_at_unix_millis
            > now.unix_millis.saturating_add(policy.max_clock_skew_millis)
        {
            Some(PairingRejection::FutureTimestamp)
        } else if now.unix_millis
            > proof
                .signed_at_unix_millis
                .saturating_add(policy.max_clock_skew_millis)
        {
            Some(PairingRejection::StaleTimestamp)
        } else if proof.device_id != self.device_id
            || proof.public_key.device_id() != self.device_id
            || proof.public_key != challenge.public_key
        {
            Some(PairingRejection::CrossDevice)
        } else if proof.role != challenge.role {
            Some(PairingRejection::RoleMismatch)
        } else if proof.scopes != challenge.scopes {
            Some(PairingRejection::ScopeMismatch)
        } else if proof.protocol_version != challenge.protocol_version {
            Some(PairingRejection::ProtocolMismatch)
        } else if proof.client_class != challenge.client_class {
            Some(PairingRejection::ClientClassMismatch)
        } else if !proof.nonce.constant_time_eq(&challenge.nonce) {
            Some(PairingRejection::NonceMismatch)
        } else if proof
            .public_key
            .verify_handshake(
                challenge.signing_input(proof.signed_at_unix_millis),
                &proof.signature,
            )
            .is_err()
        {
            Some(PairingRejection::InvalidSignature)
        } else {
            None
        };
        if let Some(rejection) = rejection {
            return self.record_failed_attempt(challenge, rejection, policy, now, audit);
        }

        let consumed = nonce_store
            .consume(&challenge.nonce)
            .map_err(PairingOperationError::NonceStore)?;
        if !consumed {
            persist_pairing_event(
                audit,
                self.device_id,
                AuditAction::PairingProofEvaluated,
                AuditOutcome::Denied,
                AuditReason::ReplayDetected,
                now.unix_millis,
            )
            .map_err(PairingOperationError::Audit)?;
            return Err(PairingOperationError::Rejected(PairingRejection::Replay));
        }
        persist_pairing_event(
            audit,
            self.device_id,
            AuditAction::PairingProofEvaluated,
            AuditOutcome::Allowed,
            AuditReason::PolicySatisfied,
            now.unix_millis,
        )
        .map_err(PairingOperationError::Audit)?;
        self.state = PairingStateData::ProofVerified(VerifiedPairing { challenge });
        Ok(())
    }

    /// Moves a verified proof to the explicit approval gate.
    ///
    /// # Errors
    ///
    /// - [`PairingRejection::IllegalTransition`] unless the session is
    ///   [`PairingState::ProofVerified`], so approval can never be requested for
    ///   a proof that was not cryptographically verified first.
    /// - [`PairingRejection::Expired`] when the challenge TTL elapsed before the
    ///   request; the session moves to [`PairingState::Expired`].
    /// - [`PairingOperationError::Audit`] when the audit record could not be
    ///   persisted, in which case the state is left unchanged.
    pub fn request_approval<A: AuditSink, C: SecurityClock>(
        &mut self,
        clock: &C,
        audit: &mut A,
    ) -> Result<(), PairingOperationError<std::convert::Infallible, A::Error>> {
        let now = clock.now();
        let verified = match &self.state {
            PairingStateData::ProofVerified(verified) => verified.clone(),
            _ => {
                return self.reject_without_nonce(
                    AuditAction::PairingApprovalRequested,
                    PairingRejection::IllegalTransition,
                    now,
                    audit,
                );
            }
        };
        if now.monotonic_millis >= verified.challenge.expires_at_monotonic_millis {
            persist_pairing_event(
                audit,
                self.device_id,
                AuditAction::PairingExpired,
                AuditOutcome::Allowed,
                AuditReason::Expired,
                now.unix_millis,
            )
            .map_err(PairingOperationError::Audit)?;
            self.state = PairingStateData::Expired;
            return Err(PairingOperationError::Rejected(PairingRejection::Expired));
        }
        persist_pairing_event(
            audit,
            self.device_id,
            AuditAction::PairingApprovalRequested,
            AuditOutcome::Allowed,
            AuditReason::PolicySatisfied,
            now.unix_millis,
        )
        .map_err(PairingOperationError::Audit)?;
        self.state = PairingStateData::AwaitingApproval(verified);
        Ok(())
    }

    /// Approves only a proof waiting at the approval gate.
    ///
    /// # Errors
    ///
    /// - [`PairingRejection::IllegalTransition`] unless the session is
    ///   [`PairingState::AwaitingApproval`], so nothing can be approved that did
    ///   not pass verification and reach the explicit gate.
    /// - [`PairingRejection::Expired`] when the challenge TTL elapsed while the
    ///   approval was pending; the session moves to [`PairingState::Expired`]
    ///   rather than being approved late.
    /// - [`PairingOperationError::Audit`] when the audit record could not be
    ///   persisted, in which case the pairing is not approved.
    pub fn approve<A: AuditSink, C: SecurityClock>(
        &mut self,
        clock: &C,
        audit: &mut A,
    ) -> Result<(), PairingOperationError<std::convert::Infallible, A::Error>> {
        let now = clock.now();
        let expires_at = match &self.state {
            PairingStateData::AwaitingApproval(verified) => {
                verified.challenge.expires_at_monotonic_millis
            }
            _ => {
                return self.reject_without_nonce(
                    AuditAction::PairingApproved,
                    PairingRejection::IllegalTransition,
                    now,
                    audit,
                );
            }
        };
        if now.monotonic_millis >= expires_at {
            persist_pairing_event(
                audit,
                self.device_id,
                AuditAction::PairingExpired,
                AuditOutcome::Allowed,
                AuditReason::Expired,
                now.unix_millis,
            )
            .map_err(PairingOperationError::Audit)?;
            self.state = PairingStateData::Expired;
            return Err(PairingOperationError::Rejected(PairingRejection::Expired));
        }
        persist_pairing_event(
            audit,
            self.device_id,
            AuditAction::PairingApproved,
            AuditOutcome::Allowed,
            AuditReason::PolicySatisfied,
            now.unix_millis,
        )
        .map_err(PairingOperationError::Audit)?;
        self.state = PairingStateData::Approved;
        Ok(())
    }

    /// Denies only a proof waiting at the approval gate.
    ///
    /// # Errors
    ///
    /// - [`PairingRejection::IllegalTransition`] unless the session is
    ///   [`PairingState::AwaitingApproval`].
    /// - [`PairingOperationError::Audit`] when the audit record could not be
    ///   persisted, in which case the session stays at the approval gate.
    pub fn deny<A: AuditSink, C: SecurityClock>(
        &mut self,
        clock: &C,
        audit: &mut A,
    ) -> Result<(), PairingOperationError<std::convert::Infallible, A::Error>> {
        let now = clock.now();
        if !matches!(self.state, PairingStateData::AwaitingApproval(_)) {
            return self.reject_without_nonce(
                AuditAction::PairingDenied,
                PairingRejection::IllegalTransition,
                now,
                audit,
            );
        }
        persist_pairing_event(
            audit,
            self.device_id,
            AuditAction::PairingDenied,
            AuditOutcome::Allowed,
            AuditReason::PolicySatisfied,
            now.unix_millis,
        )
        .map_err(PairingOperationError::Audit)?;
        self.state = PairingStateData::Denied;
        Ok(())
    }

    /// Expires an outstanding challenge/proof/approval after its monotonic TTL.
    ///
    /// # Errors
    ///
    /// - [`PairingRejection::IllegalTransition`] unless the session is
    ///   [`PairingState::ChallengeIssued`], [`PairingState::ProofVerified`], or
    ///   [`PairingState::AwaitingApproval`]; a settled session has nothing to
    ///   expire.
    /// - [`PairingRejection::NotYetExpired`] when the monotonic deadline has not
    ///   been reached, so expiry cannot be forced early to discard an
    ///   inconvenient proof.
    /// - [`PairingOperationError::Audit`] when the audit record could not be
    ///   persisted, in which case the state is left unchanged.
    pub fn expire<A: AuditSink, C: SecurityClock>(
        &mut self,
        clock: &C,
        audit: &mut A,
    ) -> Result<(), PairingOperationError<std::convert::Infallible, A::Error>> {
        let now = clock.now();
        let expires_at = match &self.state {
            PairingStateData::ChallengeIssued(challenge) => challenge.expires_at_monotonic_millis,
            PairingStateData::ProofVerified(verified)
            | PairingStateData::AwaitingApproval(verified) => {
                verified.challenge.expires_at_monotonic_millis
            }
            _ => {
                return self.reject_without_nonce(
                    AuditAction::PairingExpired,
                    PairingRejection::IllegalTransition,
                    now,
                    audit,
                );
            }
        };
        if now.monotonic_millis < expires_at {
            return self.reject_without_nonce(
                AuditAction::PairingExpired,
                PairingRejection::NotYetExpired,
                now,
                audit,
            );
        }
        persist_pairing_event(
            audit,
            self.device_id,
            AuditAction::PairingExpired,
            AuditOutcome::Allowed,
            AuditReason::Expired,
            now.unix_millis,
        )
        .map_err(PairingOperationError::Audit)?;
        self.state = PairingStateData::Expired;
        Ok(())
    }

    /// Revokes an approved pairing.
    ///
    /// # Errors
    ///
    /// - [`PairingRejection::IllegalTransition`] unless the session is
    ///   [`PairingState::Approved`].
    /// - [`PairingOperationError::Audit`] when the audit record could not be
    ///   persisted. The pairing then remains approved, so a caller must retry
    ///   rather than assume revocation took effect.
    pub fn revoke<A: AuditSink, C: SecurityClock>(
        &mut self,
        clock: &C,
        audit: &mut A,
    ) -> Result<(), PairingOperationError<std::convert::Infallible, A::Error>> {
        let now = clock.now();
        if !matches!(self.state, PairingStateData::Approved) {
            return self.reject_without_nonce(
                AuditAction::PairingRevoked,
                PairingRejection::IllegalTransition,
                now,
                audit,
            );
        }
        persist_pairing_event(
            audit,
            self.device_id,
            AuditAction::PairingRevoked,
            AuditOutcome::Allowed,
            AuditReason::PolicySatisfied,
            now.unix_millis,
        )
        .map_err(PairingOperationError::Audit)?;
        self.state = PairingStateData::Revoked;
        Ok(())
    }

    fn record_failed_attempt<A: AuditSink, N>(
        &mut self,
        mut challenge: PairingChallenge,
        rejection: PairingRejection,
        policy: PairingPolicy,
        now: ClockSnapshot,
        audit: &mut A,
    ) -> Result<(), PairingOperationError<N, A::Error>> {
        persist_pairing_event(
            audit,
            self.device_id,
            AuditAction::PairingProofEvaluated,
            AuditOutcome::Denied,
            AuditReason::InvalidProof,
            now.unix_millis,
        )
        .map_err(PairingOperationError::Audit)?;
        challenge.attempts = challenge.attempts.saturating_add(1);
        if challenge.attempts >= policy.max_attempts {
            self.state = PairingStateData::Denied;
            Err(PairingOperationError::Rejected(
                PairingRejection::AttemptsExhausted,
            ))
        } else {
            self.state = PairingStateData::ChallengeIssued(challenge);
            Err(PairingOperationError::Rejected(rejection))
        }
    }

    fn reject_without_nonce<A: AuditSink, N>(
        &self,
        action: AuditAction,
        rejection: PairingRejection,
        now: ClockSnapshot,
        audit: &mut A,
    ) -> Result<(), PairingOperationError<N, A::Error>> {
        persist_pairing_event(
            audit,
            self.device_id,
            action,
            AuditOutcome::Denied,
            if rejection == PairingRejection::IllegalTransition {
                AuditReason::IllegalTransition
            } else {
                AuditReason::PolicyRejected
            },
            now.unix_millis,
        )
        .map_err(PairingOperationError::Audit)?;
        Err(PairingOperationError::Rejected(rejection))
    }
}

fn persist_pairing_event<A: AuditSink>(
    audit: &mut A,
    device_id: DeviceId,
    action: AuditAction,
    outcome: AuditOutcome,
    reason: AuditReason,
    unix_millis: u64,
) -> Result<(), A::Error> {
    audit.persist(&AuditEvent {
        action,
        subject: AuditSubject::Device(device_id),
        outcome,
        reason,
        unix_millis,
    })
}

/// Typed pairing rejection with no raw proof, nonce, or challenge bytes.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PairingRejection {
    /// Current state does not permit the requested transition.
    IllegalTransition,
    /// Challenge size is outside the fixed bound.
    InvalidChallengeLength,
    /// Public key or device identifier differs from the session.
    CrossDevice,
    /// Operator scopes were requested for a non-operator role.
    RoleScopeMismatch,
    /// Protocol compatibility policy rejected the claim.
    ProtocolMismatch,
    /// Unique nonce reservation failed.
    NonceCollision,
    /// Monotonic deadline overflowed.
    ClockOverflow,
    /// Signed timestamp is older than the configured skew.
    StaleTimestamp,
    /// Signed timestamp is too far in the future.
    FutureTimestamp,
    /// Proof role differs from the issued challenge.
    RoleMismatch,
    /// Proof scope set differs from the issued challenge.
    ScopeMismatch,
    /// Proof client class differs from the issued challenge.
    ClientClassMismatch,
    /// Proof nonce differs from the issued challenge.
    NonceMismatch,
    /// Ed25519 verification failed.
    InvalidSignature,
    /// Nonce was already consumed.
    Replay,
    /// Monotonic TTL elapsed.
    Expired,
    /// Bounded verification attempts were exhausted.
    AttemptsExhausted,
    /// Explicit expiry was requested before the deadline.
    NotYetExpired,
}

impl Display for PairingRejection {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        let message = match self {
            Self::IllegalTransition => "illegal pairing transition",
            Self::InvalidChallengeLength => "invalid challenge length",
            Self::CrossDevice => "device proof does not match pairing session",
            Self::RoleScopeMismatch => "role and scope claims are incompatible",
            Self::ProtocolMismatch => "protocol claim is incompatible",
            Self::NonceCollision => "challenge nonce is not unique",
            Self::ClockOverflow => "pairing deadline overflow",
            Self::StaleTimestamp => "device proof timestamp is stale",
            Self::FutureTimestamp => "device proof timestamp is in the future",
            Self::RoleMismatch => "device proof role mismatch",
            Self::ScopeMismatch => "device proof scope mismatch",
            Self::ClientClassMismatch => "device proof client class mismatch",
            Self::NonceMismatch => "device proof nonce mismatch",
            Self::InvalidSignature => "device proof signature is invalid",
            Self::Replay => "device proof replay detected",
            Self::Expired => "pairing challenge expired",
            Self::AttemptsExhausted => "pairing proof attempts exhausted",
            Self::NotYetExpired => "pairing challenge has not expired",
        };
        formatter.write_str(message)
    }
}

impl Error for PairingRejection {}

impl From<RoleScopeError> for PairingRejection {
    fn from(_: RoleScopeError) -> Self {
        Self::RoleScopeMismatch
    }
}

impl From<ProtocolPolicyError> for PairingRejection {
    fn from(_: ProtocolPolicyError) -> Self {
        Self::ProtocolMismatch
    }
}

/// Pairing operation failure preserving concrete adapter errors.
#[derive(Debug)]
pub enum PairingOperationError<NonceError, AuditError> {
    /// Deterministic reducer rejection.
    Rejected(PairingRejection),
    /// Concrete nonce-store failure.
    NonceStore(NonceError),
    /// Mandatory audit persistence failure.
    Audit(AuditError),
}

impl<NonceError: Display, AuditError: Display> Display
    for PairingOperationError<NonceError, AuditError>
{
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        match self {
            Self::Rejected(error) => Display::fmt(error, formatter),
            Self::NonceStore(error) => write!(formatter, "nonce store failed: {error}"),
            Self::Audit(error) => write!(formatter, "mandatory audit persistence failed: {error}"),
        }
    }
}

impl<NonceError, AuditError> Error for PairingOperationError<NonceError, AuditError>
where
    NonceError: Error + 'static,
    AuditError: Error + 'static,
{
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Rejected(error) => Some(error),
            Self::NonceStore(error) => Some(error),
            Self::Audit(error) => Some(error),
        }
    }
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeSet;
    use std::convert::Infallible;

    use rand_chacha::{ChaCha20Rng, rand_core::SeedableRng};

    use super::*;
    use crate::authorization::Scope;

    #[derive(Clone, Copy)]
    struct Clock(ClockSnapshot);

    impl SecurityClock for Clock {
        fn now(&self) -> ClockSnapshot {
            self.0
        }
    }

    #[derive(Default)]
    struct Nonces {
        reserved: BTreeSet<[u8; 32]>,
        consumed: BTreeSet<[u8; 32]>,
    }

    impl NonceStore for Nonces {
        type Error = Infallible;

        fn reserve(
            &mut self,
            nonce: &ChallengeNonce,
            _expires_at_monotonic_millis: u64,
        ) -> Result<bool, Self::Error> {
            Ok(self.reserved.insert(*nonce.as_bytes()))
        }

        fn consume(&mut self, nonce: &ChallengeNonce) -> Result<bool, Self::Error> {
            let bytes = *nonce.as_bytes();
            Ok(self.reserved.contains(&bytes) && self.consumed.insert(bytes))
        }
    }

    #[derive(Debug)]
    struct AuditError;

    impl Display for AuditError {
        fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
            formatter.write_str("audit unavailable")
        }
    }

    impl Error for AuditError {}

    #[derive(Default)]
    struct Audit {
        fail: bool,
        events: Vec<AuditEvent>,
    }

    impl AuditSink for Audit {
        type Error = AuditError;

        fn persist(&mut self, event: &AuditEvent) -> Result<(), Self::Error> {
            if self.fail {
                Err(AuditError)
            } else {
                self.events.push(event.clone());
                Ok(())
            }
        }
    }

    fn fixture() -> (
        DeviceIdentity,
        PairingSession,
        PairingPolicy,
        Clock,
        Nonces,
        Audit,
    ) {
        let mut rng = ChaCha20Rng::from_seed([11_u8; 32]);
        let identity = DeviceIdentity::generate(&mut rng);
        let session = PairingSession::new(identity.device_id());
        let policy = PairingPolicy::new(10_000, 2, 1_000).expect("policy");
        let clock = Clock(ClockSnapshot {
            monotonic_millis: 50_000,
            unix_millis: 1_700_000_000_000,
        });
        (
            identity,
            session,
            policy,
            clock,
            Nonces::default(),
            Audit::default(),
        )
    }

    fn request(identity: &DeviceIdentity) -> ChallengeRequest {
        ChallengeRequest {
            public_key: identity.public_key(),
            role: Role::Operator,
            scopes: ScopeSet::from_scopes([Scope::OperatorRead]),
            protocol_version: 4,
            client_class: ClientClass::General,
            nonce: ChallengeNonce::new([3_u8; 32]),
            challenge: vec![4_u8; 32],
        }
    }

    fn issue(
        identity: &DeviceIdentity,
        session: &mut PairingSession,
        policy: PairingPolicy,
        clock: Clock,
        nonces: &mut Nonces,
        audit: &mut Audit,
    ) {
        session
            .issue_challenge(request(identity), policy, &clock, nonces, audit)
            .expect("challenge");
    }

    fn rejected<N, A>(error: &PairingOperationError<N, A>) -> PairingRejection {
        match error {
            PairingOperationError::Rejected(rejection) => *rejection,
            PairingOperationError::NonceStore(_) => panic!("unexpected nonce error"),
            PairingOperationError::Audit(_) => panic!("unexpected audit error"),
        }
    }

    #[test]
    fn complete_flow_supports_approval_and_revocation() {
        let (identity, mut session, policy, clock, mut nonces, mut audit) = fixture();
        issue(
            &identity,
            &mut session,
            policy,
            clock,
            &mut nonces,
            &mut audit,
        );
        let signed = PairingProof::signed(
            &identity,
            session.challenge().expect("challenge"),
            clock.0.unix_millis,
        );
        let proof = PairingProof::from_parts(PairingProofParts {
            device_id: signed.device_id,
            public_key: signed.public_key,
            role: signed.role,
            scopes: signed.scopes,
            protocol_version: signed.protocol_version,
            client_class: signed.client_class,
            signed_at_unix_millis: signed.signed_at_unix_millis,
            nonce: signed.nonce,
            signature: signed.signature,
        });
        session
            .verify_proof(&proof, policy, &clock, &mut nonces, &mut audit)
            .expect("proof");
        assert_eq!(session.state(), PairingState::ProofVerified);
        session
            .request_approval(&clock, &mut audit)
            .expect("approval gate");
        session.approve(&clock, &mut audit).expect("approved");
        assert_eq!(session.state(), PairingState::Approved);
        session.revoke(&clock, &mut audit).expect("revoked");
        assert_eq!(session.state(), PairingState::Revoked);
    }

    #[test]
    fn rejects_replay_cross_device_and_claim_mismatches() {
        let (identity, mut session, policy, clock, mut nonces, mut audit) = fixture();
        issue(
            &identity,
            &mut session,
            policy,
            clock,
            &mut nonces,
            &mut audit,
        );
        let pristine = session.clone();
        let challenge = session.challenge().expect("challenge").clone();
        let proof = PairingProof::signed(&identity, &challenge, clock.0.unix_millis);
        session
            .verify_proof(&proof, policy, &clock, &mut nonces, &mut audit)
            .expect("first use");
        let mut replay = pristine;
        assert_eq!(
            rejected(
                &replay
                    .verify_proof(&proof, policy, &clock, &mut nonces, &mut audit)
                    .expect_err("replay")
            ),
            PairingRejection::Replay
        );

        let mut rng = ChaCha20Rng::from_seed([12_u8; 32]);
        let other = DeviceIdentity::generate(&mut rng);
        let mut cross_session = PairingSession::new(identity.device_id());
        let mut cross_nonces = Nonces::default();
        let mut cross_audit = Audit::default();
        issue(
            &identity,
            &mut cross_session,
            policy,
            clock,
            &mut cross_nonces,
            &mut cross_audit,
        );
        let cross = PairingProof::signed(
            &other,
            cross_session.challenge().expect("challenge"),
            clock.0.unix_millis,
        );
        assert_eq!(
            rejected(
                &cross_session
                    .verify_proof(&cross, policy, &clock, &mut cross_nonces, &mut cross_audit)
                    .expect_err("cross device")
            ),
            PairingRejection::CrossDevice
        );
    }

    #[test]
    fn rejects_role_protocol_and_signature_tampering() {
        let (identity, mut session, policy, clock, mut nonces, mut audit) = fixture();
        issue(
            &identity,
            &mut session,
            policy,
            clock,
            &mut nonces,
            &mut audit,
        );
        let challenge = session.challenge().expect("challenge").clone();

        let mut role_proof = PairingProof::signed(&identity, &challenge, clock.0.unix_millis);
        role_proof.role = Role::Node;
        assert_eq!(
            rejected(
                &session
                    .verify_proof(&role_proof, policy, &clock, &mut nonces, &mut audit)
                    .expect_err("role mismatch")
            ),
            PairingRejection::RoleMismatch
        );

        let mut protocol_proof = PairingProof::signed(&identity, &challenge, clock.0.unix_millis);
        protocol_proof.protocol_version = 3;
        assert_eq!(
            rejected(
                &session
                    .verify_proof(&protocol_proof, policy, &clock, &mut nonces, &mut audit)
                    .expect_err("attempts exhausted")
            ),
            PairingRejection::AttemptsExhausted
        );
        assert_eq!(session.state(), PairingState::Denied);
    }

    #[test]
    fn rejects_stale_future_and_expired_proofs_without_sleeping() {
        for (offset, expected) in [
            (-2_000_i64, PairingRejection::StaleTimestamp),
            (2_000_i64, PairingRejection::FutureTimestamp),
        ] {
            let (identity, mut session, policy, clock, mut nonces, mut audit) = fixture();
            issue(
                &identity,
                &mut session,
                policy,
                clock,
                &mut nonces,
                &mut audit,
            );
            let timestamp = clock
                .0
                .unix_millis
                .checked_add_signed(offset)
                .expect("timestamp");
            let proof = PairingProof::signed(
                &identity,
                session.challenge().expect("challenge"),
                timestamp,
            );
            assert_eq!(
                rejected(
                    &session
                        .verify_proof(&proof, policy, &clock, &mut nonces, &mut audit)
                        .expect_err("timestamp rejected")
                ),
                expected
            );
        }

        let (identity, mut session, policy, clock, mut nonces, mut audit) = fixture();
        issue(
            &identity,
            &mut session,
            policy,
            clock,
            &mut nonces,
            &mut audit,
        );
        let proof = PairingProof::signed(
            &identity,
            session.challenge().expect("challenge"),
            clock.0.unix_millis,
        );
        let expired_clock = Clock(ClockSnapshot {
            monotonic_millis: clock.0.monotonic_millis + 10_000,
            unix_millis: clock.0.unix_millis + 10_000,
        });
        assert_eq!(
            rejected(
                &session
                    .verify_proof(&proof, policy, &expired_clock, &mut nonces, &mut audit)
                    .expect_err("expired")
            ),
            PairingRejection::Expired
        );
        assert_eq!(session.state(), PairingState::Expired);
    }

    #[test]
    fn proof_and_approval_states_cannot_outlive_the_challenge() {
        let (identity, mut session, policy, clock, mut nonces, mut audit) = fixture();
        issue(
            &identity,
            &mut session,
            policy,
            clock,
            &mut nonces,
            &mut audit,
        );
        let proof = PairingProof::signed(
            &identity,
            session.challenge().expect("challenge"),
            clock.0.unix_millis,
        );
        session
            .verify_proof(&proof, policy, &clock, &mut nonces, &mut audit)
            .expect("proof");
        let expired_clock = Clock(ClockSnapshot {
            monotonic_millis: clock.0.monotonic_millis + 10_000,
            unix_millis: clock.0.unix_millis + 10_000,
        });
        assert_eq!(
            rejected(
                &session
                    .request_approval(&expired_clock, &mut audit)
                    .expect_err("verified proof expires")
            ),
            PairingRejection::Expired
        );
        assert_eq!(session.state(), PairingState::Expired);

        let (identity, mut session, policy, clock, mut nonces, mut audit) = fixture();
        issue(
            &identity,
            &mut session,
            policy,
            clock,
            &mut nonces,
            &mut audit,
        );
        let proof = PairingProof::signed(
            &identity,
            session.challenge().expect("challenge"),
            clock.0.unix_millis,
        );
        session
            .verify_proof(&proof, policy, &clock, &mut nonces, &mut audit)
            .expect("proof");
        session
            .request_approval(&clock, &mut audit)
            .expect("awaiting");
        assert_eq!(
            rejected(
                &session
                    .approve(&expired_clock, &mut audit)
                    .expect_err("pending approval expires")
            ),
            PairingRejection::Expired
        );
        assert_eq!(session.state(), PairingState::Expired);
    }

    #[test]
    fn denial_and_illegal_transitions_are_explicit() {
        let (identity, mut session, policy, clock, mut nonces, mut audit) = fixture();
        assert_eq!(
            rejected(&session.approve(&clock, &mut audit).expect_err("illegal")),
            PairingRejection::IllegalTransition
        );
        issue(
            &identity,
            &mut session,
            policy,
            clock,
            &mut nonces,
            &mut audit,
        );
        let proof = PairingProof::signed(
            &identity,
            session.challenge().expect("challenge"),
            clock.0.unix_millis,
        );
        session
            .verify_proof(&proof, policy, &clock, &mut nonces, &mut audit)
            .expect("proof");
        session
            .request_approval(&clock, &mut audit)
            .expect("awaiting");
        session.deny(&clock, &mut audit).expect("denied");
        assert_eq!(session.state(), PairingState::Denied);
    }

    #[test]
    fn audit_failure_aborts_protected_transition_and_events_have_no_proof_bytes() {
        let (identity, mut session, policy, clock, mut nonces, mut audit) = fixture();
        issue(
            &identity,
            &mut session,
            policy,
            clock,
            &mut nonces,
            &mut audit,
        );
        let proof = PairingProof::signed(
            &identity,
            session.challenge().expect("challenge"),
            clock.0.unix_millis,
        );
        session
            .verify_proof(&proof, policy, &clock, &mut nonces, &mut audit)
            .expect("proof");
        session
            .request_approval(&clock, &mut audit)
            .expect("awaiting");
        audit.fail = true;
        assert!(matches!(
            session.approve(&clock, &mut audit),
            Err(PairingOperationError::Audit(_))
        ));
        assert_eq!(session.state(), PairingState::AwaitingApproval);

        audit.fail = false;
        let event_text = format!("{:?}", audit.events);
        assert!(!event_text.contains(&format!("{:?}", proof.signature.to_bytes())));
        assert!(!event_text.contains("[3, 3, 3"));
    }
}

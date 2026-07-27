//! The admission ticket and the frame a worker presents to redeem it.

use serde::{Deserialize, Serialize};

use crate::allowlist::MethodAllowlist;
use crate::fencing::FencingToken;
use crate::identity::{TicketId, WorkerId};
use crate::secret::AdmissionSecret;

/// What the Gateway minted for one worker.
///
/// The ticket is the public half: it says who may be admitted, for which
/// generation, until when, and to which methods. It carries no credential.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AdmissionTicket {
    /// Lookup key for this ticket.
    pub ticket_id: TicketId,
    /// The single worker identity this ticket admits.
    pub worker_id: WorkerId,
    /// The generation this ticket was minted for.
    pub fencing_token: FencingToken,
    /// Unix milliseconds at which the ticket became valid.
    pub issued_at_ms: u64,
    /// Unix milliseconds at which the ticket stops being valid, exclusive.
    pub expires_at_ms: u64,
    /// The exact methods a session redeemed from this ticket may call.
    pub allowed_methods: MethodAllowlist,
}

/// A freshly minted ticket together with its one-time credential.
///
/// The secret is returned exactly once. The controller keeps only what it needs
/// to verify a later presentation, and nothing recovers the secret from it.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct IssuedAdmission {
    /// The public ticket.
    pub ticket: AdmissionTicket,
    /// The credential to hand to the worker out of band.
    pub secret: AdmissionSecret,
}

impl IssuedAdmission {
    /// Builds the admission frame a well-behaved worker would send.
    ///
    /// This is a convenience for embedders and tests; the controller never
    /// calls it and accepts any frame that deserializes.
    #[must_use]
    pub fn request(&self) -> AdmissionRequest {
        AdmissionRequest {
            ticket_id: self.ticket.ticket_id.clone(),
            worker_id: self.ticket.worker_id.clone(),
            fencing_token: self.ticket.fencing_token,
            secret: self.secret.clone(),
        }
    }
}

/// The frame a worker sends to redeem a ticket.
///
/// Unknown fields are refused rather than ignored, so a frame carrying a field
/// this version does not understand is rejected instead of being silently
/// accepted with the unrecognised part dropped.
#[derive(Clone, Debug, Eq, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct AdmissionRequest {
    /// The ticket being redeemed.
    pub ticket_id: TicketId,
    /// The identity the worker claims.
    pub worker_id: WorkerId,
    /// The generation the worker believes it owns.
    pub fencing_token: FencingToken,
    /// The credential issued with the ticket.
    pub secret: AdmissionSecret,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::secret::ADMISSION_SECRET_BYTES;

    fn request() -> AdmissionRequest {
        AdmissionRequest {
            ticket_id: TicketId::new("ticket-1").expect("valid ticket identity"),
            worker_id: WorkerId::new("worker-a").expect("valid worker identity"),
            fencing_token: FencingToken::new(1).expect("generation one is valid"),
            secret: AdmissionSecret::from_bytes([0x11; ADMISSION_SECRET_BYTES]),
        }
    }

    #[test]
    fn admission_request_round_trips_through_json() {
        let original = request();
        let encoded = serde_json::to_vec(&original).expect("encode admission request");
        let decoded: AdmissionRequest =
            serde_json::from_slice(&encoded).expect("decode admission request");
        assert_eq!(decoded, original);
    }

    #[test]
    fn an_unknown_field_is_refused_rather_than_ignored() {
        let mut value = serde_json::to_value(request()).expect("encode admission request");
        value
            .as_object_mut()
            .expect("admission request encodes as an object")
            .insert("elevate".to_owned(), serde_json::Value::Bool(true));
        let error = serde_json::from_value::<AdmissionRequest>(value)
            .expect_err("an unknown admission field must be refused");
        assert!(
            error.to_string().contains("unknown field `elevate`"),
            "unexpected rejection: {error}"
        );
    }

    #[test]
    fn a_missing_fencing_token_is_refused_rather_than_defaulted() {
        let mut value = serde_json::to_value(request()).expect("encode admission request");
        value
            .as_object_mut()
            .expect("admission request encodes as an object")
            .remove("fencing_token");
        let error = serde_json::from_value::<AdmissionRequest>(value)
            .expect_err("a missing fencing token must be refused");
        assert!(
            error.to_string().contains("missing field `fencing_token`"),
            "unexpected rejection: {error}"
        );
    }

    #[test]
    fn a_zero_fencing_token_is_refused_by_the_parser() {
        let mut value = serde_json::to_value(request()).expect("encode admission request");
        value
            .as_object_mut()
            .expect("admission request encodes as an object")
            .insert("fencing_token".to_owned(), serde_json::json!(0));
        let error = serde_json::from_value::<AdmissionRequest>(value)
            .expect_err("generation zero must be refused");
        assert!(
            error.to_string().contains("reserved and never valid"),
            "unexpected rejection: {error}"
        );
    }
}

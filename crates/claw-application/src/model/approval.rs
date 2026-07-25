//! Tool approval values exchanged between the runtime and its operators.

use std::fmt::{self, Display, Formatter};

use claw_domain::SessionId;
use serde::{Deserialize, Serialize};

use super::ids::{ApprovalId, ToolCallId, TurnId};
use super::time::Timestamp;

/// How long an approval decision applies.
#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ApprovalScope {
    /// The decision applies to this call only.
    Once,
    /// The decision is remembered for this tool for the rest of the session.
    Session,
}

impl ApprovalScope {
    /// Every scope in declaration order.
    pub const ALL: [Self; 2] = [Self::Once, Self::Session];

    /// Returns the stable wire label for this scope.
    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            Self::Once => "once",
            Self::Session => "session",
        }
    }

    /// Returns whether the decision must be stored for later calls.
    #[must_use]
    pub const fn is_remembered(self) -> bool {
        matches!(self, Self::Session)
    }
}

impl Display for ApprovalScope {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.label())
    }
}

/// An operator's answer to an approval request.
#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ApprovalVerdict {
    /// Run the tool.
    Approve,
    /// Refuse the tool.
    Deny,
}

impl ApprovalVerdict {
    /// Returns the stable wire label for this verdict.
    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            Self::Approve => "approve",
            Self::Deny => "deny",
        }
    }
}

impl Display for ApprovalVerdict {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.label())
    }
}

/// A decision, with the scope it applies to.
#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, PartialEq, Serialize)]
pub struct ApprovalDecision {
    /// Whether the tool may run.
    pub verdict: ApprovalVerdict,
    /// How long the verdict applies.
    pub scope: ApprovalScope,
}

impl ApprovalDecision {
    /// Approves this call only.
    #[must_use]
    pub const fn approve_once() -> Self {
        Self {
            verdict: ApprovalVerdict::Approve,
            scope: ApprovalScope::Once,
        }
    }

    /// Approves this call and remembers the decision for the session.
    #[must_use]
    pub const fn approve_for_session() -> Self {
        Self {
            verdict: ApprovalVerdict::Approve,
            scope: ApprovalScope::Session,
        }
    }

    /// Denies this call only.
    #[must_use]
    pub const fn deny_once() -> Self {
        Self {
            verdict: ApprovalVerdict::Deny,
            scope: ApprovalScope::Once,
        }
    }

    /// Denies this call and remembers the decision for the session.
    #[must_use]
    pub const fn deny_for_session() -> Self {
        Self {
            verdict: ApprovalVerdict::Deny,
            scope: ApprovalScope::Session,
        }
    }
}

/// An outstanding approval request.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ApprovalRequest {
    /// The request identifier.
    pub approval_id: ApprovalId,
    /// The session that requested the tool.
    #[serde(with = "super::session_id_serde")]
    pub session_id: SessionId,
    /// The turn that requested the tool.
    pub turn: TurnId,
    /// The provider-assigned call identifier.
    pub call_id: ToolCallId,
    /// The tool that requires approval.
    pub tool_name: String,
    /// The JSON arguments the tool would receive.
    pub arguments: String,
    /// When the request was raised.
    pub requested_at: Timestamp,
    /// When the request expires without an answer.
    pub expires_at: Timestamp,
}

/// Why an approval request stopped being outstanding without an operator decision.
#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ApprovalWithdrawal {
    /// The deadline passed.
    TimedOut,
    /// The turn or runtime was cancelled.
    Cancelled,
}

impl ApprovalWithdrawal {
    /// Returns the stable wire label for this withdrawal reason.
    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            Self::TimedOut => "timed_out",
            Self::Cancelled => "cancelled",
        }
    }
}

impl Display for ApprovalWithdrawal {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.label())
    }
}

/// The final result of an approval request.
#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, PartialEq, Serialize)]
#[serde(rename_all = "snake_case", tag = "outcome")]
pub enum ApprovalOutcome {
    /// An operator answered.
    Decided {
        /// The answer.
        decision: ApprovalDecision,
        /// Whether the answer came from a previously remembered decision.
        remembered: bool,
    },
    /// No operator answered before the request was withdrawn.
    Withdrawn {
        /// Why the request was withdrawn.
        reason: ApprovalWithdrawal,
    },
}

impl ApprovalOutcome {
    /// Returns whether the tool may run.
    #[must_use]
    pub const fn is_approved(&self) -> bool {
        matches!(
            self,
            Self::Decided {
                decision: ApprovalDecision {
                    verdict: ApprovalVerdict::Approve,
                    ..
                },
                ..
            }
        )
    }
}

#[cfg(test)]
mod tests {
    use claw_domain::SessionId;

    use super::{
        ApprovalDecision, ApprovalOutcome, ApprovalRequest, ApprovalScope, ApprovalVerdict,
        ApprovalWithdrawal,
    };
    use crate::model::ids::{ApprovalId, ToolCallId, TurnId};
    use crate::model::time::Timestamp;

    #[test]
    fn only_session_scope_is_remembered() {
        let remembered: Vec<ApprovalScope> = ApprovalScope::ALL
            .into_iter()
            .filter(|scope| scope.is_remembered())
            .collect();

        assert_eq!(remembered, vec![ApprovalScope::Session]);
    }

    #[test]
    fn decision_constructors_pair_verdict_and_scope() {
        assert_eq!(
            ApprovalDecision::approve_once(),
            ApprovalDecision {
                verdict: ApprovalVerdict::Approve,
                scope: ApprovalScope::Once,
            }
        );
        assert_eq!(
            ApprovalDecision::approve_for_session(),
            ApprovalDecision {
                verdict: ApprovalVerdict::Approve,
                scope: ApprovalScope::Session,
            }
        );
        assert_eq!(
            ApprovalDecision::deny_once(),
            ApprovalDecision {
                verdict: ApprovalVerdict::Deny,
                scope: ApprovalScope::Once,
            }
        );
        assert_eq!(
            ApprovalDecision::deny_for_session(),
            ApprovalDecision {
                verdict: ApprovalVerdict::Deny,
                scope: ApprovalScope::Session,
            }
        );
    }

    #[test]
    fn approval_is_granted_only_by_an_approving_decision() {
        assert!(
            ApprovalOutcome::Decided {
                decision: ApprovalDecision::approve_for_session(),
                remembered: true,
            }
            .is_approved()
        );
        assert!(
            !ApprovalOutcome::Decided {
                decision: ApprovalDecision::deny_once(),
                remembered: false,
            }
            .is_approved()
        );
        assert!(
            !ApprovalOutcome::Withdrawn {
                reason: ApprovalWithdrawal::TimedOut,
            }
            .is_approved()
        );
        assert!(
            !ApprovalOutcome::Withdrawn {
                reason: ApprovalWithdrawal::Cancelled,
            }
            .is_approved()
        );
    }

    #[test]
    fn outcomes_serialise_with_a_tagged_representation() {
        let encoded = serde_json::to_string(&ApprovalOutcome::Withdrawn {
            reason: ApprovalWithdrawal::TimedOut,
        })
        .expect("outcome serialises");

        assert_eq!(
            encoded,
            "{\"outcome\":\"withdrawn\",\"reason\":\"timed_out\"}"
        );
    }

    #[test]
    fn requests_round_trip_through_json() {
        let request = ApprovalRequest {
            approval_id: ApprovalId::new("approval-1").expect("valid approval id"),
            session_id: SessionId::new("session-1").expect("valid session id"),
            turn: TurnId::new(2),
            call_id: ToolCallId::new("call-3").expect("valid call id"),
            tool_name: "write_file".to_owned(),
            arguments: "{}".to_owned(),
            requested_at: Timestamp::from_millis(100),
            expires_at: Timestamp::from_millis(30_100),
        };

        let encoded = serde_json::to_string(&request).expect("request serialises");
        let decoded: ApprovalRequest =
            serde_json::from_str(&encoded).expect("request deserialises");

        assert_eq!(decoded, request);
        assert_eq!(decoded.expires_at.as_millis(), 30_100);
    }
}

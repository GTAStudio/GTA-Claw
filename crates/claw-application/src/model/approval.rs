//! Tool approval values exchanged between the runtime and its operators.

use std::fmt::{self, Display, Formatter};

use claw_domain::SessionId;

use super::ids::{ApprovalId, ToolCallId, TurnId};
use super::time::Timestamp;

/// How long an approval decision applies.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
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
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
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
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
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
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ApprovalRequest {
    /// The request identifier.
    pub approval_id: ApprovalId,
    /// The session that requested the tool.
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
///
/// Abandonment is deliberately *not* a variant here. A dropped waiter never returns an outcome,
/// so `Withdrawn { reason: Abandoned }` would be an unreachable state that every match arm would
/// still have to handle. Abandonment is signalled by [`ApprovalPort::abandon`] being a distinct
/// method, which distinguishes it at the type level rather than by a value a caller must inspect.
///
/// [`ApprovalPort::abandon`]: crate::ports::approval::ApprovalPort::abandon
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
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
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
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
    use super::{
        ApprovalDecision, ApprovalOutcome, ApprovalScope, ApprovalVerdict, ApprovalWithdrawal,
    };

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
}

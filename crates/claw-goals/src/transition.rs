//! The durable goal status state machine.
//!
//! A goal has exactly one open status, [`GoalStatus::Active`], and four terminal ones. The
//! machine here states which moves exist and, more importantly, names why every other move is
//! refused. That distinction matters for a durable store: a rejected transition that is reported
//! as a generic failure is indistinguishable from a write that was lost, and an operator cannot
//! tell "the goal was already finished" from "the disk ate your goal".
//!
//! ```text
//!                 ┌──────────► achieved
//!                 │
//!   active ───────┼──────────► abandoned      (terminal statuses are absorbing:
//!                 │                            no move leaves them)
//!                 ├──────────► failed
//!                 │
//!                 └──────────► superseded
//! ```

use std::error::Error;
use std::fmt::{self, Display, Formatter};

use claw_application::model::goal::GoalStatus;

/// A mutation a caller wants to apply to a goal.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum GoalOperation {
    /// Append one progress entry, which leaves the goal active.
    RecordProgress,
    /// Close the goal with a terminal status.
    Close(GoalStatus),
    /// Retire the goal because a newer goal replaced it.
    Supersede,
}

impl Display for GoalOperation {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        match self {
            Self::RecordProgress => formatter.write_str("record progress"),
            Self::Close(status) => write!(formatter, "close as {status}"),
            Self::Supersede => formatter.write_str("supersede"),
        }
    }
}

/// A refused status change, carrying the reason the caller needs to act on.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TransitionError {
    /// The goal already holds a terminal status, so nothing may change it.
    AlreadyClosed {
        /// The terminal status the goal holds.
        held: GoalStatus,
        /// The operation that was refused.
        attempted: GoalOperation,
    },
    /// A close was requested with a status that does not end the goal.
    NotATerminalStatus(GoalStatus),
    /// The requested target is not reachable from the current status.
    Unreachable {
        /// The status the goal holds.
        from: GoalStatus,
        /// The status that was asked for.
        to: GoalStatus,
    },
}

impl TransitionError {
    /// Returns the stable, operator-facing reason for the refusal.
    ///
    /// This is deliberately separate from [`Display`]: the reason is a small closed vocabulary
    /// that a surface can branch on or a test can assert, while the rendered message also names
    /// the statuses involved.
    #[must_use]
    pub const fn reason(&self) -> &'static str {
        match self {
            Self::AlreadyClosed { .. } => "the goal is already closed",
            Self::NotATerminalStatus(_) => "the status does not close a goal",
            Self::Unreachable { .. } => "the status is not reachable from the current one",
        }
    }
}

impl Display for TransitionError {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        match self {
            Self::AlreadyClosed { held, attempted } => {
                write!(formatter, "cannot {attempted}: {} ({held})", self.reason())
            }
            Self::NotATerminalStatus(status) => {
                write!(formatter, "cannot close as {status}: {}", self.reason())
            }
            Self::Unreachable { from, to } => {
                write!(formatter, "cannot move {from} to {to}: {}", self.reason())
            }
        }
    }
}

impl Error for TransitionError {}

/// Returns every status reachable in one move from `from`, in declaration order.
///
/// A terminal status reaches nothing, which is what makes it terminal.
#[must_use]
pub fn legal_targets(from: GoalStatus) -> Vec<GoalStatus> {
    if from.is_closed() {
        return Vec::new();
    }
    GoalStatus::ALL
        .into_iter()
        .filter(|status| status.is_closed())
        .collect()
}

/// Decides one status move.
///
/// # Errors
///
/// Returns [`TransitionError::AlreadyClosed`] when `from` is terminal and
/// [`TransitionError::Unreachable`] when `to` is not reachable from `from`, which includes the
/// no-op `active -> active`: a goal that did not move did not transition.
pub fn transition(from: GoalStatus, to: GoalStatus) -> Result<GoalStatus, TransitionError> {
    if from.is_closed() {
        return Err(TransitionError::AlreadyClosed {
            held: from,
            attempted: GoalOperation::Close(to),
        });
    }
    if legal_targets(from).contains(&to) {
        return Ok(to);
    }
    Err(TransitionError::Unreachable { from, to })
}

/// Decides one operation against the status a goal currently holds, returning the status it ends
/// in.
///
/// This is the check a durable store makes before it writes: refusing here is what keeps a closed
/// goal's history immutable on disk.
///
/// # Errors
///
/// Returns [`TransitionError::NotATerminalStatus`] when a close names [`GoalStatus::Active`],
/// [`TransitionError::AlreadyClosed`] when the goal already holds a terminal status, and
/// [`TransitionError::Unreachable`] when the resulting move does not exist.
pub fn admit(current: GoalStatus, operation: GoalOperation) -> Result<GoalStatus, TransitionError> {
    if let GoalOperation::Close(status) = operation
        && !status.is_closed()
    {
        return Err(TransitionError::NotATerminalStatus(status));
    }

    if current.is_closed() {
        return Err(TransitionError::AlreadyClosed {
            held: current,
            attempted: operation,
        });
    }

    match operation {
        GoalOperation::RecordProgress => Ok(current),
        GoalOperation::Close(status) => transition(current, status),
        GoalOperation::Supersede => transition(current, GoalStatus::Superseded),
    }
}

#[cfg(test)]
mod tests {
    use super::{GoalOperation, TransitionError, admit, legal_targets, transition};
    use claw_application::model::goal::GoalStatus;

    #[test]
    fn every_terminal_status_is_reachable_from_active_and_nothing_else_is() {
        assert_eq!(
            legal_targets(GoalStatus::Active),
            vec![
                GoalStatus::Achieved,
                GoalStatus::Abandoned,
                GoalStatus::Failed,
                GoalStatus::Superseded,
            ]
        );
        for status in GoalStatus::ALL
            .into_iter()
            .filter(|status| status.is_closed())
        {
            assert!(legal_targets(status).is_empty(), "{status} reaches nothing");
        }
    }

    #[test]
    fn the_matrix_refuses_every_move_that_is_not_active_to_terminal() {
        for from in GoalStatus::ALL {
            for to in GoalStatus::ALL {
                let expected_ok = from == GoalStatus::Active && to.is_closed();
                assert_eq!(
                    transition(from, to).is_ok(),
                    expected_ok,
                    "{from} -> {to} should {}",
                    if expected_ok {
                        "be legal"
                    } else {
                        "be refused"
                    }
                );
            }
        }
    }

    #[test]
    fn a_goal_cannot_transition_to_the_status_it_already_holds() {
        assert_eq!(
            transition(GoalStatus::Active, GoalStatus::Active),
            Err(TransitionError::Unreachable {
                from: GoalStatus::Active,
                to: GoalStatus::Active,
            })
        );
        assert_eq!(
            transition(GoalStatus::Achieved, GoalStatus::Achieved),
            Err(TransitionError::AlreadyClosed {
                held: GoalStatus::Achieved,
                attempted: GoalOperation::Close(GoalStatus::Achieved),
            })
        );
    }

    #[test]
    fn progress_keeps_an_active_goal_active_and_is_refused_once_it_closes() {
        assert_eq!(
            admit(GoalStatus::Active, GoalOperation::RecordProgress),
            Ok(GoalStatus::Active)
        );
        assert_eq!(
            admit(GoalStatus::Failed, GoalOperation::RecordProgress),
            Err(TransitionError::AlreadyClosed {
                held: GoalStatus::Failed,
                attempted: GoalOperation::RecordProgress,
            })
        );
    }

    #[test]
    fn closing_with_a_non_terminal_status_is_refused_before_the_goal_is_consulted() {
        for current in GoalStatus::ALL {
            assert_eq!(
                admit(current, GoalOperation::Close(GoalStatus::Active)),
                Err(TransitionError::NotATerminalStatus(GoalStatus::Active)),
                "a close as active must be refused whatever {current} is"
            );
        }
    }

    #[test]
    fn superseding_retires_an_active_goal_and_never_a_closed_one() {
        assert_eq!(
            admit(GoalStatus::Active, GoalOperation::Supersede),
            Ok(GoalStatus::Superseded)
        );
        assert_eq!(
            admit(GoalStatus::Superseded, GoalOperation::Supersede),
            Err(TransitionError::AlreadyClosed {
                held: GoalStatus::Superseded,
                attempted: GoalOperation::Supersede,
            })
        );
    }

    #[test]
    fn refusals_render_the_reason_and_the_statuses_involved() {
        let closed = admit(GoalStatus::Achieved, GoalOperation::RecordProgress)
            .expect_err("a closed goal refuses progress");
        assert_eq!(closed.reason(), "the goal is already closed");
        assert_eq!(
            closed.to_string(),
            "cannot record progress: the goal is already closed (achieved)"
        );

        let non_terminal = admit(GoalStatus::Active, GoalOperation::Close(GoalStatus::Active))
            .expect_err("active does not close a goal");
        assert_eq!(non_terminal.reason(), "the status does not close a goal");
        assert_eq!(
            non_terminal.to_string(),
            "cannot close as active: the status does not close a goal"
        );

        let unreachable = transition(GoalStatus::Active, GoalStatus::Active)
            .expect_err("a goal cannot move to itself");
        assert_eq!(
            unreachable.reason(),
            "the status is not reachable from the current one"
        );
        assert_eq!(
            unreachable.to_string(),
            "cannot move active to active: the status is not reachable from the current one"
        );
    }
}

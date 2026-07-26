//! The user-visible session/turn state contract and its legal transitions.

use std::error::Error;
use std::fmt::{self, Display, Formatter};

/// Every user-visible state a session turn can occupy.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum SessionState {
    /// Composed locally and not yet submitted to the runtime.
    Draft,
    /// Admitted to the runtime and waiting for an execution slot.
    Queued,
    /// Acquiring context and opening the provider stream.
    Starting,
    /// Streaming assistant output or executing approved tools.
    Running,
    /// Halted until an operator approves or denies a tool call.
    WaitingForApproval,
    /// Halted until a human answers a question raised by the assistant.
    WaitingForAnswer,
    /// Halted at operator request; resumes into the pre-pause state.
    Paused,
    /// Halted by policy or a missing precondition; requires an unblock.
    Blocked,
    /// Terminated by an unrecoverable error.
    Failed,
    /// Terminated by operator or host cancellation.
    Cancelled,
    /// Terminated successfully without workspace changes.
    Completed,
    /// Terminated successfully after mutating the workspace.
    CompletedWithChanges,
}

/// Every input that can drive a session state transition.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum SessionEvent {
    /// Submit a draft turn to the runtime.
    Enqueue,
    /// Claim an execution slot for a queued turn.
    Start,
    /// Report that provider output has begun to arrive.
    Stream,
    /// Report that a tool call needs an approval decision.
    RequestApproval,
    /// Report that the pending approval has been decided.
    ResolveApproval,
    /// Report that the assistant asked the operator a question.
    AskQuestion,
    /// Report that the operator answered the outstanding question.
    ProvideAnswer,
    /// Suspend the turn at operator request.
    Pause,
    /// Restore the turn to the state it held before pausing.
    Resume,
    /// Halt the turn on a policy or precondition failure.
    Block,
    /// Clear the block and return the turn to the queue.
    Unblock,
    /// Finish the turn without workspace changes.
    Complete,
    /// Finish the turn after workspace changes.
    CompleteWithChanges,
    /// Abandon the turn at operator or host request.
    Cancel,
    /// Abandon the turn because of an unrecoverable error.
    Fail,
}

/// The outcome of a legal transition.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum SessionTransition {
    /// Move directly to the named state.
    To(SessionState),
    /// Move back to the state recorded before the turn paused.
    RestorePrePause,
}

/// A transition that the contract does not allow.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct IllegalTransition {
    /// The state the turn occupied.
    pub from: SessionState,
    /// The event that was rejected.
    pub event: SessionEvent,
}

impl Display for IllegalTransition {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "illegal session transition: {} cannot accept {}",
            self.from.label(),
            self.event.label()
        )
    }
}

impl Error for IllegalTransition {}

impl SessionState {
    /// Every state in declaration order.
    pub const ALL: [Self; 12] = [
        Self::Draft,
        Self::Queued,
        Self::Starting,
        Self::Running,
        Self::WaitingForApproval,
        Self::WaitingForAnswer,
        Self::Paused,
        Self::Blocked,
        Self::Failed,
        Self::Cancelled,
        Self::Completed,
        Self::CompletedWithChanges,
    ];

    /// Returns the stable wire label for this state.
    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            Self::Draft => "draft",
            Self::Queued => "queued",
            Self::Starting => "starting",
            Self::Running => "running",
            Self::WaitingForApproval => "waiting_for_approval",
            Self::WaitingForAnswer => "waiting_for_answer",
            Self::Paused => "paused",
            Self::Blocked => "blocked",
            Self::Failed => "failed",
            Self::Cancelled => "cancelled",
            Self::Completed => "completed",
            Self::CompletedWithChanges => "completed_with_changes",
        }
    }

    /// Returns whether no further transition is possible.
    #[must_use]
    pub const fn is_terminal(self) -> bool {
        matches!(
            self,
            Self::Failed | Self::Cancelled | Self::Completed | Self::CompletedWithChanges
        )
    }

    /// Returns whether the turn currently holds runtime resources.
    #[must_use]
    pub const fn is_in_flight(self) -> bool {
        matches!(
            self,
            Self::Starting | Self::Running | Self::WaitingForApproval | Self::WaitingForAnswer
        )
    }

    /// Returns whether a paused turn may legally be restored to this state.
    #[must_use]
    pub const fn is_pausable(self) -> bool {
        matches!(
            self,
            Self::Queued
                | Self::Starting
                | Self::Running
                | Self::WaitingForApproval
                | Self::WaitingForAnswer
        )
    }

    /// Resolves one transition without mutating any runtime state.
    ///
    /// # Errors
    ///
    /// Returns [`IllegalTransition`] when the contract forbids `event` in this state.
    pub const fn transition(
        self,
        event: SessionEvent,
    ) -> Result<SessionTransition, IllegalTransition> {
        use SessionEvent as E;
        use SessionState as S;

        let target = match (self, event) {
            (S::Draft, E::Enqueue) => S::Queued,
            (S::Queued, E::Start) => S::Starting,
            (S::Starting, E::Stream) => S::Running,
            (S::Running, E::RequestApproval) => S::WaitingForApproval,
            (S::WaitingForApproval, E::ResolveApproval) => S::Running,
            (S::Running, E::AskQuestion) => S::WaitingForAnswer,
            (S::WaitingForAnswer, E::ProvideAnswer) => S::Running,
            (
                S::Queued | S::Starting | S::Running | S::WaitingForApproval | S::WaitingForAnswer,
                E::Pause,
            ) => S::Paused,
            (S::Paused, E::Resume) => return Ok(SessionTransition::RestorePrePause),
            (
                S::Queued | S::Starting | S::Running | S::WaitingForApproval | S::WaitingForAnswer,
                E::Block,
            ) => S::Blocked,
            (S::Blocked, E::Unblock) => S::Queued,
            (S::Running, E::Complete) => S::Completed,
            (S::Running, E::CompleteWithChanges) => S::CompletedWithChanges,
            (
                S::Draft
                | S::Queued
                | S::Starting
                | S::Running
                | S::WaitingForApproval
                | S::WaitingForAnswer
                | S::Paused
                | S::Blocked,
                E::Cancel,
            ) => S::Cancelled,
            (
                S::Draft
                | S::Queued
                | S::Starting
                | S::Running
                | S::WaitingForApproval
                | S::WaitingForAnswer
                | S::Paused
                | S::Blocked,
                E::Fail,
            ) => S::Failed,
            _ => return Err(IllegalTransition { from: self, event }),
        };

        Ok(SessionTransition::To(target))
    }
}

impl Display for SessionState {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.label())
    }
}

impl SessionEvent {
    /// Every event in declaration order.
    pub const ALL: [Self; 15] = [
        Self::Enqueue,
        Self::Start,
        Self::Stream,
        Self::RequestApproval,
        Self::ResolveApproval,
        Self::AskQuestion,
        Self::ProvideAnswer,
        Self::Pause,
        Self::Resume,
        Self::Block,
        Self::Unblock,
        Self::Complete,
        Self::CompleteWithChanges,
        Self::Cancel,
        Self::Fail,
    ];

    /// Returns the stable wire label for this event.
    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            Self::Enqueue => "enqueue",
            Self::Start => "start",
            Self::Stream => "stream",
            Self::RequestApproval => "request_approval",
            Self::ResolveApproval => "resolve_approval",
            Self::AskQuestion => "ask_question",
            Self::ProvideAnswer => "provide_answer",
            Self::Pause => "pause",
            Self::Resume => "resume",
            Self::Block => "block",
            Self::Unblock => "unblock",
            Self::Complete => "complete",
            Self::CompleteWithChanges => "complete_with_changes",
            Self::Cancel => "cancel",
            Self::Fail => "fail",
        }
    }
}

impl Display for SessionEvent {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.label())
    }
}

#[cfg(test)]
mod tests {
    use super::{IllegalTransition, SessionEvent, SessionState, SessionTransition};

    #[test]
    fn state_labels_are_stable_wire_values() {
        let labels: Vec<&str> = SessionState::ALL.iter().map(|s| s.label()).collect();

        assert_eq!(
            labels,
            vec![
                "draft",
                "queued",
                "starting",
                "running",
                "waiting_for_approval",
                "waiting_for_answer",
                "paused",
                "blocked",
                "failed",
                "cancelled",
                "completed",
                "completed_with_changes",
            ]
        );
    }

    #[test]
    fn event_labels_are_stable_wire_values() {
        let labels: Vec<&str> = SessionEvent::ALL.iter().map(|e| e.label()).collect();

        assert_eq!(
            labels,
            vec![
                "enqueue",
                "start",
                "stream",
                "request_approval",
                "resolve_approval",
                "ask_question",
                "provide_answer",
                "pause",
                "resume",
                "block",
                "unblock",
                "complete",
                "complete_with_changes",
                "cancel",
                "fail",
            ]
        );
    }

    #[test]
    fn terminal_states_reject_every_event() {
        let terminal = [
            SessionState::Failed,
            SessionState::Cancelled,
            SessionState::Completed,
            SessionState::CompletedWithChanges,
        ];

        for state in terminal {
            assert!(state.is_terminal());
            for event in SessionEvent::ALL {
                assert_eq!(
                    state.transition(event),
                    Err(IllegalTransition { from: state, event })
                );
            }
        }
    }

    #[test]
    fn illegal_transition_renders_both_operands() {
        let error = SessionState::Completed
            .transition(SessionEvent::Pause)
            .expect_err("completed turns cannot pause");

        assert_eq!(
            error.to_string(),
            "illegal session transition: completed cannot accept pause"
        );
    }

    #[test]
    fn in_flight_and_pausable_classifications_are_disjoint_where_expected() {
        let in_flight: Vec<SessionState> = SessionState::ALL
            .into_iter()
            .filter(|state| state.is_in_flight())
            .collect();
        let pausable: Vec<SessionState> = SessionState::ALL
            .into_iter()
            .filter(|state| state.is_pausable())
            .collect();

        assert_eq!(
            in_flight,
            vec![
                SessionState::Starting,
                SessionState::Running,
                SessionState::WaitingForApproval,
                SessionState::WaitingForAnswer,
            ]
        );
        assert_eq!(
            pausable,
            vec![
                SessionState::Queued,
                SessionState::Starting,
                SessionState::Running,
                SessionState::WaitingForApproval,
                SessionState::WaitingForAnswer,
            ]
        );
    }

    /// The complete, hand-written contract. Every pair absent from this table must be rejected.
    const LEGAL: [(SessionState, SessionEvent, SessionTransition); 37] = [
        (
            SessionState::Draft,
            SessionEvent::Enqueue,
            SessionTransition::To(SessionState::Queued),
        ),
        (
            SessionState::Draft,
            SessionEvent::Cancel,
            SessionTransition::To(SessionState::Cancelled),
        ),
        (
            SessionState::Draft,
            SessionEvent::Fail,
            SessionTransition::To(SessionState::Failed),
        ),
        (
            SessionState::Queued,
            SessionEvent::Start,
            SessionTransition::To(SessionState::Starting),
        ),
        (
            SessionState::Queued,
            SessionEvent::Pause,
            SessionTransition::To(SessionState::Paused),
        ),
        (
            SessionState::Queued,
            SessionEvent::Block,
            SessionTransition::To(SessionState::Blocked),
        ),
        (
            SessionState::Queued,
            SessionEvent::Cancel,
            SessionTransition::To(SessionState::Cancelled),
        ),
        (
            SessionState::Queued,
            SessionEvent::Fail,
            SessionTransition::To(SessionState::Failed),
        ),
        (
            SessionState::Starting,
            SessionEvent::Stream,
            SessionTransition::To(SessionState::Running),
        ),
        (
            SessionState::Starting,
            SessionEvent::Pause,
            SessionTransition::To(SessionState::Paused),
        ),
        (
            SessionState::Starting,
            SessionEvent::Block,
            SessionTransition::To(SessionState::Blocked),
        ),
        (
            SessionState::Starting,
            SessionEvent::Cancel,
            SessionTransition::To(SessionState::Cancelled),
        ),
        (
            SessionState::Starting,
            SessionEvent::Fail,
            SessionTransition::To(SessionState::Failed),
        ),
        (
            SessionState::Running,
            SessionEvent::RequestApproval,
            SessionTransition::To(SessionState::WaitingForApproval),
        ),
        (
            SessionState::Running,
            SessionEvent::AskQuestion,
            SessionTransition::To(SessionState::WaitingForAnswer),
        ),
        (
            SessionState::Running,
            SessionEvent::Pause,
            SessionTransition::To(SessionState::Paused),
        ),
        (
            SessionState::Running,
            SessionEvent::Block,
            SessionTransition::To(SessionState::Blocked),
        ),
        (
            SessionState::Running,
            SessionEvent::Complete,
            SessionTransition::To(SessionState::Completed),
        ),
        (
            SessionState::Running,
            SessionEvent::CompleteWithChanges,
            SessionTransition::To(SessionState::CompletedWithChanges),
        ),
        (
            SessionState::Running,
            SessionEvent::Cancel,
            SessionTransition::To(SessionState::Cancelled),
        ),
        (
            SessionState::Running,
            SessionEvent::Fail,
            SessionTransition::To(SessionState::Failed),
        ),
        (
            SessionState::WaitingForApproval,
            SessionEvent::ResolveApproval,
            SessionTransition::To(SessionState::Running),
        ),
        (
            SessionState::WaitingForApproval,
            SessionEvent::Pause,
            SessionTransition::To(SessionState::Paused),
        ),
        (
            SessionState::WaitingForApproval,
            SessionEvent::Block,
            SessionTransition::To(SessionState::Blocked),
        ),
        (
            SessionState::WaitingForApproval,
            SessionEvent::Cancel,
            SessionTransition::To(SessionState::Cancelled),
        ),
        (
            SessionState::WaitingForApproval,
            SessionEvent::Fail,
            SessionTransition::To(SessionState::Failed),
        ),
        (
            SessionState::WaitingForAnswer,
            SessionEvent::ProvideAnswer,
            SessionTransition::To(SessionState::Running),
        ),
        (
            SessionState::WaitingForAnswer,
            SessionEvent::Pause,
            SessionTransition::To(SessionState::Paused),
        ),
        (
            SessionState::WaitingForAnswer,
            SessionEvent::Block,
            SessionTransition::To(SessionState::Blocked),
        ),
        (
            SessionState::WaitingForAnswer,
            SessionEvent::Cancel,
            SessionTransition::To(SessionState::Cancelled),
        ),
        (
            SessionState::WaitingForAnswer,
            SessionEvent::Fail,
            SessionTransition::To(SessionState::Failed),
        ),
        (
            SessionState::Paused,
            SessionEvent::Resume,
            SessionTransition::RestorePrePause,
        ),
        (
            SessionState::Paused,
            SessionEvent::Cancel,
            SessionTransition::To(SessionState::Cancelled),
        ),
        (
            SessionState::Paused,
            SessionEvent::Fail,
            SessionTransition::To(SessionState::Failed),
        ),
        (
            SessionState::Blocked,
            SessionEvent::Unblock,
            SessionTransition::To(SessionState::Queued),
        ),
        (
            SessionState::Blocked,
            SessionEvent::Cancel,
            SessionTransition::To(SessionState::Cancelled),
        ),
        (
            SessionState::Blocked,
            SessionEvent::Fail,
            SessionTransition::To(SessionState::Failed),
        ),
    ];

    #[test]
    fn every_state_event_pair_matches_the_written_contract() {
        let mut checked = 0_usize;
        let mut legal_seen = 0_usize;

        for from in SessionState::ALL {
            for event in SessionEvent::ALL {
                checked += 1;
                let expected = LEGAL
                    .iter()
                    .find(|(table_from, table_event, _)| {
                        *table_from == from && *table_event == event
                    })
                    .map(|(_, _, transition)| *transition);

                match expected {
                    Some(transition) => {
                        legal_seen += 1;
                        assert_eq!(
                            from.transition(event),
                            Ok(transition),
                            "{from} + {event} must be legal"
                        );
                    }
                    None => assert_eq!(
                        from.transition(event),
                        Err(IllegalTransition { from, event }),
                        "{from} + {event} must be rejected"
                    ),
                }
            }
        }

        assert_eq!(checked, 180);
        assert_eq!(legal_seen, LEGAL.len());
    }

    #[test]
    fn the_written_contract_has_no_duplicate_rows() {
        let mut seen: Vec<(SessionState, SessionEvent)> = Vec::new();

        for (from, event, _) in LEGAL {
            assert!(
                !seen.contains(&(from, event)),
                "duplicate contract row for {from} + {event}"
            );
            seen.push((from, event));
        }

        assert_eq!(seen.len(), 37);
    }
}

//! The stateful session/turn machine built on the [`SessionState`] contract.

use std::error::Error;
use std::fmt::{self, Display, Formatter};

use claw_application::model::session::{
    IllegalTransition, SessionEvent, SessionState, SessionTransition,
};

/// A refusal to change session state.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum StateMachineError {
    /// The contract forbids this transition.
    Illegal(IllegalTransition),
    /// A restored snapshot violated the machine's invariants.
    InconsistentSnapshot(&'static str),
}

impl Display for StateMachineError {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        match self {
            Self::Illegal(illegal) => Display::fmt(illegal, formatter),
            Self::InconsistentSnapshot(reason) => {
                write!(formatter, "inconsistent session snapshot: {reason}")
            }
        }
    }
}

impl Error for StateMachineError {}

impl From<IllegalTransition> for StateMachineError {
    fn from(value: IllegalTransition) -> Self {
        Self::Illegal(value)
    }
}

/// Tracks one turn's position in the session state contract.
///
/// The machine adds exactly one thing to the pure [`SessionState::transition`] contract: it
/// remembers the state a turn held before it paused, so [`SessionEvent::Resume`] can restore it.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TurnStateMachine {
    state: SessionState,
    pre_pause_state: Option<SessionState>,
    transitions: u64,
}

impl TurnStateMachine {
    /// Creates a machine for a freshly composed turn.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            state: SessionState::Draft,
            pre_pause_state: None,
            transitions: 0,
        }
    }

    /// Rebuilds a machine from persisted state.
    ///
    /// # Errors
    ///
    /// Returns [`StateMachineError::InconsistentSnapshot`] when `pre_pause_state` does not match
    /// `state`: a paused turn must carry a pausable pre-pause state, and every other state must
    /// carry none.
    pub const fn restore(
        state: SessionState,
        pre_pause_state: Option<SessionState>,
    ) -> Result<Self, StateMachineError> {
        match (state, pre_pause_state) {
            (SessionState::Paused, Some(previous)) if previous.is_pausable() => {}
            (SessionState::Paused, Some(_)) => {
                return Err(StateMachineError::InconsistentSnapshot(
                    "pre-pause state is not pausable",
                ));
            }
            (SessionState::Paused, None) => {
                return Err(StateMachineError::InconsistentSnapshot(
                    "paused turns must record a pre-pause state",
                ));
            }
            (_, Some(_)) => {
                return Err(StateMachineError::InconsistentSnapshot(
                    "only paused turns may record a pre-pause state",
                ));
            }
            (_, None) => {}
        }

        Ok(Self {
            state,
            pre_pause_state,
            transitions: 0,
        })
    }

    /// Returns the current user-visible state.
    #[must_use]
    pub const fn state(&self) -> SessionState {
        self.state
    }

    /// Returns the state a paused turn will resume into.
    #[must_use]
    pub const fn pre_pause_state(&self) -> Option<SessionState> {
        self.pre_pause_state
    }

    /// Returns how many transitions this machine has accepted.
    #[must_use]
    pub const fn transitions(&self) -> u64 {
        self.transitions
    }

    /// Returns whether the turn can still change state.
    #[must_use]
    pub const fn is_terminal(&self) -> bool {
        self.state.is_terminal()
    }

    /// Returns whether the event would be accepted, without applying it.
    #[must_use]
    pub const fn accepts(&self, event: SessionEvent) -> bool {
        self.state.transition(event).is_ok()
    }

    /// Applies one event and returns the resulting state.
    ///
    /// # Errors
    ///
    /// Returns [`StateMachineError::Illegal`] when the contract forbids the transition, and
    /// [`StateMachineError::InconsistentSnapshot`] when a resume finds no pre-pause state.
    pub fn apply(&mut self, event: SessionEvent) -> Result<SessionState, StateMachineError> {
        let next = match self.state.transition(event)? {
            SessionTransition::To(SessionState::Paused) => {
                self.pre_pause_state = Some(self.state);
                SessionState::Paused
            }
            SessionTransition::To(target) => {
                self.pre_pause_state = None;
                target
            }
            SessionTransition::RestorePrePause => {
                self.pre_pause_state
                    .take()
                    .ok_or(StateMachineError::InconsistentSnapshot(
                        "paused turns must record a pre-pause state",
                    ))?
            }
        };

        self.state = next;
        self.transitions = self.transitions.saturating_add(1);
        Ok(next)
    }
}

impl Default for TurnStateMachine {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use claw_application::model::session::{IllegalTransition, SessionEvent, SessionState};

    use super::{StateMachineError, TurnStateMachine};

    fn drive(machine: &mut TurnStateMachine, events: &[SessionEvent]) {
        for event in events {
            machine
                .apply(*event)
                .unwrap_or_else(|error| panic!("{event} must be accepted: {error}"));
        }
    }

    #[test]
    fn a_new_machine_starts_as_a_draft() {
        let machine = TurnStateMachine::new();

        assert_eq!(machine.state(), SessionState::Draft);
        assert_eq!(machine.pre_pause_state(), None);
        assert_eq!(machine.transitions(), 0);
        assert!(!machine.is_terminal());
    }

    #[test]
    fn a_clean_turn_walks_draft_to_completed() {
        let mut machine = TurnStateMachine::new();
        drive(
            &mut machine,
            &[
                SessionEvent::Enqueue,
                SessionEvent::Start,
                SessionEvent::Stream,
                SessionEvent::Complete,
            ],
        );

        assert_eq!(machine.state(), SessionState::Completed);
        assert_eq!(machine.transitions(), 4);
        assert!(machine.is_terminal());
    }

    #[test]
    fn a_mutating_turn_ends_in_completed_with_changes() {
        let mut machine = TurnStateMachine::new();
        drive(
            &mut machine,
            &[
                SessionEvent::Enqueue,
                SessionEvent::Start,
                SessionEvent::Stream,
                SessionEvent::RequestApproval,
                SessionEvent::ResolveApproval,
                SessionEvent::CompleteWithChanges,
            ],
        );

        assert_eq!(machine.state(), SessionState::CompletedWithChanges);
        assert_eq!(machine.transitions(), 6);
    }

    #[test]
    fn pausing_records_and_resuming_restores_every_pausable_state() {
        let paths: [(&[SessionEvent], SessionState); 5] = [
            (&[SessionEvent::Enqueue], SessionState::Queued),
            (
                &[SessionEvent::Enqueue, SessionEvent::Start],
                SessionState::Starting,
            ),
            (
                &[
                    SessionEvent::Enqueue,
                    SessionEvent::Start,
                    SessionEvent::Stream,
                ],
                SessionState::Running,
            ),
            (
                &[
                    SessionEvent::Enqueue,
                    SessionEvent::Start,
                    SessionEvent::Stream,
                    SessionEvent::RequestApproval,
                ],
                SessionState::WaitingForApproval,
            ),
            (
                &[
                    SessionEvent::Enqueue,
                    SessionEvent::Start,
                    SessionEvent::Stream,
                    SessionEvent::AskQuestion,
                ],
                SessionState::WaitingForAnswer,
            ),
        ];

        for (path, expected) in paths {
            let mut machine = TurnStateMachine::new();
            drive(&mut machine, path);
            assert_eq!(machine.state(), expected);

            machine
                .apply(SessionEvent::Pause)
                .expect("pausable states accept pause");
            assert_eq!(machine.state(), SessionState::Paused);
            assert_eq!(machine.pre_pause_state(), Some(expected));

            let resumed = machine
                .apply(SessionEvent::Resume)
                .expect("paused turns accept resume");
            assert_eq!(resumed, expected);
            assert_eq!(machine.pre_pause_state(), None);
        }
    }

    #[test]
    fn cancelling_a_paused_turn_clears_the_pre_pause_state() {
        let mut machine = TurnStateMachine::new();
        drive(
            &mut machine,
            &[
                SessionEvent::Enqueue,
                SessionEvent::Start,
                SessionEvent::Stream,
                SessionEvent::Pause,
                SessionEvent::Cancel,
            ],
        );

        assert_eq!(machine.state(), SessionState::Cancelled);
        assert_eq!(machine.pre_pause_state(), None);
    }

    #[test]
    fn blocking_and_unblocking_returns_the_turn_to_the_queue() {
        let mut machine = TurnStateMachine::new();
        drive(
            &mut machine,
            &[
                SessionEvent::Enqueue,
                SessionEvent::Start,
                SessionEvent::Stream,
                SessionEvent::Block,
                SessionEvent::Unblock,
            ],
        );

        assert_eq!(machine.state(), SessionState::Queued);
        assert!(machine.accepts(SessionEvent::Start));
        assert!(!machine.accepts(SessionEvent::Stream));
    }

    #[test]
    fn terminal_machines_refuse_every_event() {
        let mut machine = TurnStateMachine::new();
        drive(
            &mut machine,
            &[
                SessionEvent::Enqueue,
                SessionEvent::Start,
                SessionEvent::Stream,
                SessionEvent::Complete,
            ],
        );

        for event in SessionEvent::ALL {
            assert_eq!(
                machine.apply(event),
                Err(StateMachineError::Illegal(IllegalTransition {
                    from: SessionState::Completed,
                    event,
                }))
            );
        }

        assert_eq!(machine.transitions(), 4);
        assert_eq!(machine.state(), SessionState::Completed);
    }

    #[test]
    fn a_rejected_event_leaves_the_machine_untouched() {
        let mut machine = TurnStateMachine::new();
        drive(&mut machine, &[SessionEvent::Enqueue]);

        let error = machine
            .apply(SessionEvent::Stream)
            .expect_err("queued turns cannot stream");

        assert_eq!(
            error,
            StateMachineError::Illegal(IllegalTransition {
                from: SessionState::Queued,
                event: SessionEvent::Stream,
            })
        );
        assert_eq!(machine.state(), SessionState::Queued);
        assert_eq!(machine.transitions(), 1);
    }

    #[test]
    fn restore_accepts_only_consistent_snapshots() {
        let restored = TurnStateMachine::restore(SessionState::Paused, Some(SessionState::Running))
            .expect("paused snapshots with a pausable pre-pause state are valid");
        assert_eq!(restored.state(), SessionState::Paused);
        assert_eq!(restored.pre_pause_state(), Some(SessionState::Running));

        assert_eq!(
            TurnStateMachine::restore(SessionState::Paused, None),
            Err(StateMachineError::InconsistentSnapshot(
                "paused turns must record a pre-pause state"
            ))
        );
        assert_eq!(
            TurnStateMachine::restore(SessionState::Paused, Some(SessionState::Completed)),
            Err(StateMachineError::InconsistentSnapshot(
                "pre-pause state is not pausable"
            ))
        );
        assert_eq!(
            TurnStateMachine::restore(SessionState::Running, Some(SessionState::Queued)),
            Err(StateMachineError::InconsistentSnapshot(
                "only paused turns may record a pre-pause state"
            ))
        );
    }

    #[test]
    fn restored_machines_continue_the_contract() {
        let mut machine =
            TurnStateMachine::restore(SessionState::Paused, Some(SessionState::WaitingForApproval))
                .expect("valid snapshot");

        assert_eq!(
            machine
                .apply(SessionEvent::Resume)
                .expect("paused turns resume"),
            SessionState::WaitingForApproval
        );
        assert_eq!(
            machine
                .apply(SessionEvent::ResolveApproval)
                .expect("approvals resolve"),
            SessionState::Running
        );
    }

    #[test]
    fn state_machine_errors_render_their_cause() {
        assert_eq!(
            StateMachineError::Illegal(IllegalTransition {
                from: SessionState::Draft,
                event: SessionEvent::Stream,
            })
            .to_string(),
            "illegal session transition: draft cannot accept stream"
        );
        assert_eq!(
            StateMachineError::InconsistentSnapshot("bad").to_string(),
            "inconsistent session snapshot: bad"
        );
    }

    #[test]
    fn transition_counts_saturate_instead_of_overflowing() {
        let mut machine = TurnStateMachine::new();
        drive(&mut machine, &[SessionEvent::Enqueue, SessionEvent::Start]);

        assert_eq!(machine.transitions(), 2);
        assert_eq!(TurnStateMachine::default(), TurnStateMachine::new());
    }
}

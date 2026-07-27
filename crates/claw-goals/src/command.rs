//! Operator commands lowered onto a durable goal.
//!
//! The grammar is not redefined here. [`claw_runtime::CommandRegistry`] owns the vocabulary —
//! `/goal`, `/goal-done`, `/goal-drop`, their scopes and their arity — and this module is the
//! step after it: taking the [`CommandEffect`] the registry produced and applying it to a goal
//! that is written to disk. Redefining the grammar would create a second, drifting copy of the
//! frozen command surface; consuming it keeps one.

use std::error::Error;
use std::fmt::{self, Display, Formatter};

use claw_application::model::goal::GoalRecord;
use claw_domain::SessionId;
use claw_runtime::{
    CommandEffect, CommandError, CommandRegistry, GoalError, GoalService, ScopeSet,
};

use crate::retry::{retry_conflicts, start_with_conflict_recovery};

/// What a goal command did.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum GoalCommandOutcome {
    /// `/goal <objective>` recorded a new goal, superseding any previous one.
    Set(GoalRecord),
    /// `/goal` reported the session's goal, which may be absent.
    Shown(Option<GoalRecord>),
    /// `/goal-done` or `/goal-drop` closed the goal.
    Closed(GoalRecord),
    /// A close was asked for while the session had no active goal.
    NothingToClose,
}

impl GoalCommandOutcome {
    /// Returns the goal the command left behind, when there is one.
    #[must_use]
    pub const fn record(&self) -> Option<&GoalRecord> {
        match self {
            Self::Set(record) | Self::Closed(record) => Some(record),
            Self::Shown(record) => record.as_ref(),
            Self::NothingToClose => None,
        }
    }
}

/// A goal command that could not be executed.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum GoalCommandError {
    /// The line was not a command, or not one this caller may run.
    Command(CommandError),
    /// The command was a valid command, but not one that touches the goal.
    NotAGoalCommand(CommandEffect),
    /// The goal service refused the mutation.
    Goal(GoalError),
}

impl Display for GoalCommandError {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        match self {
            Self::Command(error) => Display::fmt(error, formatter),
            Self::NotAGoalCommand(effect) => {
                write!(formatter, "{effect:?} does not act on the durable goal")
            }
            Self::Goal(error) => Display::fmt(error, formatter),
        }
    }
}

impl Error for GoalCommandError {}

impl From<GoalError> for GoalCommandError {
    fn from(value: GoalError) -> Self {
        Self::Goal(value)
    }
}

impl From<CommandError> for GoalCommandError {
    fn from(value: CommandError) -> Self {
        Self::Command(value)
    }
}

/// Applies one lowered command effect to the session's durable goal.
///
/// # Errors
///
/// Returns [`GoalCommandError::NotAGoalCommand`] for any effect that is not `/goal`,
/// `/goal-done` or `/goal-drop`, and [`GoalCommandError::Goal`] when the service refuses — a
/// blank objective, an oversized one, or a store failure.
pub async fn apply_command_effect(
    service: &GoalService,
    session_id: &SessionId,
    effect: &CommandEffect,
) -> Result<GoalCommandOutcome, GoalCommandError> {
    match effect {
        CommandEffect::ShowGoal => Ok(GoalCommandOutcome::Shown(service.active(session_id).await?)),
        CommandEffect::SetGoal(objective) => {
            start_with_conflict_recovery(service, session_id, objective)
                .await
                .map(GoalCommandOutcome::Set)
                .map_err(GoalCommandError::from)
        }
        CommandEffect::CloseGoal(status) => retry_conflicts(|| {
            Box::pin(async {
                let Some(active) = service.active(session_id).await? else {
                    return Ok(GoalCommandOutcome::NothingToClose);
                };
                service
                    .close(&active.goal_id, *status)
                    .await
                    .map(GoalCommandOutcome::Closed)
            })
        })
        .await
        .map_err(GoalCommandError::from),
        other => Err(GoalCommandError::NotAGoalCommand(other.clone())),
    }
}

/// Parses, authorizes and executes one operator command line against a durable goal.
///
/// # Errors
///
/// Returns [`GoalCommandError::Command`] when the line is not a command, names an unknown one, or
/// is outside `scopes`, and everything [`apply_command_effect`] can return.
pub async fn execute_command(
    registry: &CommandRegistry,
    service: &GoalService,
    session_id: &SessionId,
    scopes: ScopeSet,
    line: &str,
) -> Result<GoalCommandOutcome, GoalCommandError> {
    let invocation = registry.parse(line, scopes)?;
    let effect = CommandRegistry::effect(&invocation)?;
    apply_command_effect(service, session_id, &effect).await
}

#[cfg(test)]
mod tests {
    use super::{GoalCommandError, GoalCommandOutcome};
    use claw_application::model::goal::GoalStatus;
    use claw_runtime::CommandEffect;

    #[test]
    fn an_outcome_reports_the_record_it_left_behind() {
        let record = crate::testing::record("s", "s:goal-1", "objective", 1);

        assert_eq!(
            GoalCommandOutcome::Set(record.clone()).record(),
            Some(&record)
        );
        assert_eq!(
            GoalCommandOutcome::Closed(record.clone()).record(),
            Some(&record)
        );
        assert_eq!(
            GoalCommandOutcome::Shown(Some(record.clone())).record(),
            Some(&record)
        );
        assert_eq!(GoalCommandOutcome::Shown(None).record(), None);
        assert_eq!(GoalCommandOutcome::NothingToClose.record(), None);
    }

    #[test]
    fn a_non_goal_effect_is_named_in_the_refusal() {
        let error = GoalCommandError::NotAGoalCommand(CommandEffect::ListTools);

        assert_eq!(
            error.to_string(),
            "ListTools does not act on the durable goal"
        );
    }

    #[test]
    fn closing_effects_carry_the_status_the_frozen_grammar_assigns() {
        assert_eq!(
            CommandEffect::CloseGoal(GoalStatus::Achieved),
            CommandEffect::CloseGoal(GoalStatus::Achieved)
        );
        assert_ne!(
            CommandEffect::CloseGoal(GoalStatus::Achieved),
            CommandEffect::CloseGoal(GoalStatus::Abandoned)
        );
    }
}

//! The model-callable goal tool, applied to a durable goal.
//!
//! The runtime serves `update_goal` itself rather than routing it through a tool adapter, because
//! the durable goal is runtime state and an adapter that could write it could forge goal history.
//! That means the model's write path is exactly [`parse_goal_action`] followed by
//! [`GoalService::apply`] — and both halves are reproduced here, over a store that actually
//! persists, so a model-authored goal can be shown to survive a restart.
//!
//! A refused call is a *tool result*, never a failed turn: the model is told what it got wrong and
//! can correct itself in the same turn. [`invoke_goal_tool`] therefore returns the refusal as a
//! value the caller renders, mirroring the runtime's own `ToolStatus::Failed` outcome.

use std::error::Error;
use std::fmt::{self, Display, Formatter};

use claw_application::model::goal::GoalRecord;
use claw_domain::SessionId;
use claw_runtime::{GoalError, GoalService, GoalToolError, parse_goal_action};

/// A goal-tool call that the model must correct.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ToolInvocationError {
    /// The arguments were not a valid action.
    Arguments(GoalToolError),
    /// The action was valid but the goal service refused it.
    Refused(GoalError),
}

impl Display for ToolInvocationError {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        match self {
            Self::Arguments(error) => Display::fmt(error, formatter),
            Self::Refused(error) => Display::fmt(error, formatter),
        }
    }
}

impl Error for ToolInvocationError {}

impl From<GoalToolError> for ToolInvocationError {
    fn from(value: GoalToolError) -> Self {
        Self::Arguments(value)
    }
}

impl From<GoalError> for ToolInvocationError {
    fn from(value: GoalError) -> Self {
        Self::Refused(value)
    }
}

/// The result of one accepted goal-tool call.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GoalToolOutcome {
    /// The goal as it was persisted.
    pub record: GoalRecord,
}

impl GoalToolOutcome {
    /// Returns the text the runtime reports back to the model.
    ///
    /// The wording matches `claw_runtime`'s own goal-tool outcome so a model sees one sentence
    /// whichever surface served the call.
    #[must_use]
    pub fn summary(&self) -> String {
        format!(
            "goal {} is {} at revision {}",
            self.record.goal_id, self.record.status, self.record.revision
        )
    }
}

/// Serves one `update_goal` call against a durable goal store.
///
/// # Errors
///
/// Returns [`ToolInvocationError::Arguments`] when `arguments` is not the JSON encoding of a goal
/// action, or names a non-terminal status in a `close`, and [`ToolInvocationError::Refused`] when
/// the service rejects the action — no active goal, a closed goal, invalid text, or a store
/// failure.
pub async fn invoke_goal_tool(
    service: &GoalService,
    session_id: &SessionId,
    arguments: &str,
) -> Result<GoalToolOutcome, ToolInvocationError> {
    let action = parse_goal_action(arguments)?;
    let record = service.apply(session_id, &action).await?;
    Ok(GoalToolOutcome { record })
}

#[cfg(test)]
mod tests {
    use super::{GoalToolOutcome, ToolInvocationError};
    use crate::testing::record;
    use claw_application::model::goal::GoalStatus;
    use claw_application::model::time::Timestamp;
    use claw_runtime::{GoalToolError, parse_goal_action};

    #[test]
    fn the_summary_matches_the_sentence_the_runtime_reports() {
        let mut stored = record("goal-tool", "goal-tool:goal-1", "finish the runtime", 1);
        let outcome = GoalToolOutcome {
            record: stored.clone(),
        };
        assert_eq!(
            outcome.summary(),
            "goal goal-tool:goal-1 is active at revision 1"
        );

        stored.status = GoalStatus::Achieved;
        stored.closed_at = Some(Timestamp::from_millis(2));
        stored.revision = 4;
        assert_eq!(
            GoalToolOutcome { record: stored }.summary(),
            "goal goal-tool:goal-1 is achieved at revision 4"
        );
    }

    #[test]
    fn argument_failures_are_reported_with_the_parsers_own_wording() {
        let parse_error =
            parse_goal_action("{\"action\":\"close\",\"status\":\"active\"}").expect_err("refused");
        let error = ToolInvocationError::from(parse_error.clone());

        assert_eq!(
            error,
            ToolInvocationError::Arguments(GoalToolError::NotATerminalStatus(GoalStatus::Active))
        );
        assert_eq!(error.to_string(), parse_error.to_string());
    }
}

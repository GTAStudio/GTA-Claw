//! The model-callable goal tool.
//!
//! Operators steer the durable goal with `/goal`, `/goal-done` and `/goal-drop`. The model steers
//! the same goal by calling one tool, [`GOAL_TOOL_NAME`], whose arguments are the JSON encoding of
//! [`GoalAction`]. The tool is served by the runtime itself rather than by a
//! [`ToolPort`](claw_application::ports::tool::ToolPort) adapter: the durable goal is runtime
//! state, so routing it through an external adapter would let an adapter forge goal history.
//!
//! Arguments are parsed strictly. Unknown actions, unknown fields and missing fields are all
//! rejected with a typed [`GoalToolError`], which the runtime reports back to the model as a
//! failed tool result so it can correct itself inside the same turn.

use std::error::Error;
use std::fmt::{self, Display, Formatter};

use claw_application::model::goal::GoalStatus;
use claw_application::ports::tool::ToolDescriptor;
use serde::{Deserialize, Serialize};

/// The dispatch name of the model-callable goal tool.
pub const GOAL_TOOL_NAME: &str = "update_goal";

/// One model-authored mutation of the session's durable goal.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case", tag = "action", deny_unknown_fields)]
pub enum GoalAction {
    /// Replace the session goal, superseding whatever goal was active.
    Set {
        /// The new objective.
        objective: String,
    },
    /// Append one progress note to the active goal.
    Progress {
        /// The note to append.
        note: String,
    },
    /// Close the active goal with a terminal status.
    Close {
        /// The terminal status to close with.
        #[serde(with = "crate::wire::goal_status")]
        status: GoalStatus,
    },
}

/// A rejected goal-tool invocation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum GoalToolError {
    /// The arguments were not the JSON encoding of a [`GoalAction`].
    MalformedArguments(String),
    /// The action asked to close the goal with a non-terminal status.
    NotATerminalStatus(GoalStatus),
}

impl Display for GoalToolError {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        match self {
            Self::MalformedArguments(detail) => {
                write!(formatter, "malformed {GOAL_TOOL_NAME} arguments: {detail}")
            }
            Self::NotATerminalStatus(status) => {
                write!(formatter, "{status} is not a terminal goal status")
            }
        }
    }
}

impl Error for GoalToolError {}

/// Returns the descriptor advertised to providers and to `/tools`.
///
/// The tool never mutates the workspace and never needs an approval: it only writes runtime state
/// the operator can already inspect and overwrite with `/goal`.
#[must_use]
pub fn goal_tool_descriptor() -> ToolDescriptor {
    ToolDescriptor {
        name: GOAL_TOOL_NAME.to_owned(),
        summary: "Set, advance or close the durable session goal".to_owned(),
        requires_approval: false,
        mutates_workspace: false,
    }
}

/// Parses the JSON arguments of one goal-tool call.
///
/// # Errors
///
/// Returns [`GoalToolError::MalformedArguments`] when the text is not a JSON object matching
/// [`GoalAction`], and [`GoalToolError::NotATerminalStatus`] when a `close` action names
/// [`GoalStatus::Active`].
pub fn parse_goal_action(arguments: &str) -> Result<GoalAction, GoalToolError> {
    let action: GoalAction = serde_json::from_str(arguments.trim())
        .map_err(|error| GoalToolError::MalformedArguments(error.to_string()))?;

    if let GoalAction::Close { status } = &action
        && !status.is_closed()
    {
        return Err(GoalToolError::NotATerminalStatus(*status));
    }

    Ok(action)
}

#[cfg(test)]
mod tests {
    use super::{
        GOAL_TOOL_NAME, GoalAction, GoalToolError, goal_tool_descriptor, parse_goal_action,
    };
    use claw_application::model::goal::GoalStatus;

    #[test]
    fn every_action_parses_from_its_tagged_encoding() {
        let parsed: Vec<GoalAction> = [
            "{\"action\":\"set\",\"objective\":\"ship the runtime\"}",
            "{\"action\":\"progress\",\"note\":\"wrote the tests\"}",
            "{\"action\":\"close\",\"status\":\"achieved\"}",
            "{\"action\":\"close\",\"status\":\"abandoned\"}",
            "{\"action\":\"close\",\"status\":\"failed\"}",
        ]
        .into_iter()
        .map(|arguments| parse_goal_action(arguments).expect("action parses"))
        .collect();

        assert_eq!(
            parsed,
            vec![
                GoalAction::Set {
                    objective: "ship the runtime".to_owned(),
                },
                GoalAction::Progress {
                    note: "wrote the tests".to_owned(),
                },
                GoalAction::Close {
                    status: GoalStatus::Achieved,
                },
                GoalAction::Close {
                    status: GoalStatus::Abandoned,
                },
                GoalAction::Close {
                    status: GoalStatus::Failed,
                },
            ]
        );
    }

    #[test]
    fn surrounding_whitespace_is_tolerated() {
        assert_eq!(
            parse_goal_action("  \n{\"action\":\"progress\",\"note\":\"n\"}\t ")
                .expect("action parses"),
            GoalAction::Progress {
                note: "n".to_owned(),
            }
        );
    }

    #[test]
    fn closing_with_active_is_rejected_before_the_store_is_touched() {
        assert_eq!(
            parse_goal_action("{\"action\":\"close\",\"status\":\"active\"}"),
            Err(GoalToolError::NotATerminalStatus(GoalStatus::Active))
        );
    }

    #[test]
    fn superseded_is_a_terminal_status_the_model_may_name() {
        assert_eq!(
            parse_goal_action("{\"action\":\"close\",\"status\":\"superseded\"}")
                .expect("action parses"),
            GoalAction::Close {
                status: GoalStatus::Superseded,
            }
        );
    }

    #[test]
    fn an_unknown_action_is_rejected() {
        let error = parse_goal_action("{\"action\":\"delete\"}").expect_err("unknown action");

        assert!(matches!(error, GoalToolError::MalformedArguments(_)));
        assert_eq!(
            error.to_string(),
            "malformed update_goal arguments: unknown variant `delete`, \
expected one of `set`, `progress`, `close` at line 1 column 18"
        );
    }

    #[test]
    fn an_extra_field_is_rejected() {
        let error = parse_goal_action("{\"action\":\"progress\",\"note\":\"n\",\"index\":4}")
            .expect_err("extra field");

        assert!(matches!(error, GoalToolError::MalformedArguments(_)));
    }

    #[test]
    fn a_missing_field_is_rejected() {
        let error = parse_goal_action("{\"action\":\"set\"}").expect_err("missing objective");

        assert_eq!(
            error.to_string(),
            "malformed update_goal arguments: missing field `objective`"
        );
    }

    #[test]
    fn non_json_arguments_are_rejected() {
        let error = parse_goal_action("set the goal").expect_err("not json");

        assert!(matches!(error, GoalToolError::MalformedArguments(_)));
    }

    #[test]
    fn the_descriptor_needs_no_approval_and_touches_no_workspace() {
        let descriptor = goal_tool_descriptor();

        assert_eq!(descriptor.name, GOAL_TOOL_NAME);
        assert_eq!(
            descriptor.summary,
            "Set, advance or close the durable session goal"
        );
        assert!(!descriptor.requires_approval);
        assert!(!descriptor.mutates_workspace);
    }

    #[test]
    fn actions_serialise_to_the_encoding_the_model_is_told_to_produce() {
        let encoded = serde_json::to_string(&GoalAction::Close {
            status: GoalStatus::Achieved,
        })
        .expect("action serialises");

        assert_eq!(encoded, "{\"action\":\"close\",\"status\":\"achieved\"}");
    }
}

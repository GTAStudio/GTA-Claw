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

use claw_application::model::approval::{ApprovalOutcome, ApprovalVerdict, ApprovalWithdrawal};
use claw_application::model::goal::{GoalRecord, GoalStatus};
use claw_application::model::ids::ToolCallId;
use claw_application::ports::PortError;
use claw_application::ports::tool::{
    InternalToolAuditPhase, InvocationAuthority, ToolBinding, ToolDescriptor, ToolInvocation,
    ToolOutcome, ToolPort, ToolStatus,
};
use serde::{Deserialize, Serialize};
use std::sync::atomic::{AtomicU64, Ordering};
use tokio_util::sync::CancellationToken;

use crate::approval::{ApprovalBroker, ApprovalTicket};
use crate::goal::GoalService;
use crate::tool::ToolExecutionError;

/// The dispatch name of the model-callable goal tool.
pub const GOAL_TOOL_NAME: &str = "update_goal";
static NEXT_AUTHORIZED_GOAL: AtomicU64 = AtomicU64::new(0);

/// The confirmed record and client-visible outcome of a runtime-owned goal call.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AuthorizedGoalOutcome {
    /// Present only after the goal write and completion audit both succeeded.
    pub record: Option<GoalRecord>,
    /// Provider-call identity and the corresponding execution result.
    pub outcome: ToolOutcome,
}

fn refused_goal(
    call_id: &ToolCallId,
    status: ToolStatus,
    output: impl Into<String>,
) -> AuthorizedGoalOutcome {
    AuthorizedGoalOutcome {
        record: None,
        outcome: ToolOutcome {
            call_id: call_id.clone(),
            status,
            output: output.into(),
            changed_workspace: false,
        },
    }
}

/// Binds the runtime goal implementation and its session-wide resource scope.
///
/// # Errors
/// Rejects other tool names, invalid arguments and unrepresentable resource scopes.
pub fn goal_tool_binding(invocation: &ToolInvocation) -> Result<ToolBinding, PortError> {
    if invocation.call.name != GOAL_TOOL_NAME || invocation.call.arguments.len() > 16 * 1024 {
        return Err(PortError::Invalid(
            "invalid bounded runtime goal invocation".to_owned(),
        ));
    }
    parse_goal_action(&invocation.call.arguments)
        .map_err(|error| PortError::Invalid(error.to_string()))?;
    ToolBinding::new("runtime.update_goal", 1)?.with_resource(format!(
        "goal state for session {}; action targets the active goal at execution",
        invocation.session_id.as_str()
    ))
}

pub(crate) async fn execute_authorized_goal(
    service: &GoalService,
    broker: &ApprovalBroker,
    tools: &dyn ToolPort,
    mut invocation: ToolInvocation,
    authority: InvocationAuthority,
    cancel: &CancellationToken,
    shutdown: &CancellationToken,
) -> Result<AuthorizedGoalOutcome, ToolExecutionError> {
    let call_id = invocation.call.call_id.clone();
    if invocation.call.name != GOAL_TOOL_NAME {
        return Ok(refused_goal(
            &call_id,
            ToolStatus::Failed,
            "runtime goal entry received another tool name",
        ));
    }
    if !authority.is_owner() {
        return Ok(refused_goal(
            &call_id,
            ToolStatus::Denied,
            "goal mutation requires an authenticated owner",
        ));
    }
    if cancel.is_cancelled() || shutdown.is_cancelled() {
        return Ok(refused_goal(
            &call_id,
            ToolStatus::Cancelled,
            "goal call cancelled before approval",
        ));
    }
    let action = match parse_goal_action(&invocation.call.arguments) {
        Ok(action) => action,
        Err(error) => {
            return Ok(refused_goal(
                &call_id,
                ToolStatus::Failed,
                error.to_string(),
            ));
        }
    };
    let binding = match tools.bind_authorized(&invocation, &authority) {
        Ok(binding) => binding,
        Err(error) => {
            return Ok(refused_goal(
                &call_id,
                ToolStatus::Denied,
                error.to_string(),
            ));
        }
    };
    let approval = broker.request_bound(
        ApprovalTicket {
            session_id: invocation.session_id.clone(),
            turn: invocation.turn,
            call_id: call_id.clone(),
            tool_name: invocation.call.name.clone(),
            arguments: invocation.call.arguments.clone(),
        },
        authority.clone(),
        binding.clone(),
        cancel,
    );
    let decision = tokio::select! {
        biased;
        () = shutdown.cancelled() => return Ok(refused_goal(&call_id, ToolStatus::Cancelled, "runtime stopped before goal approval")),
        decision = approval => decision?,
    };
    match decision {
        ApprovalOutcome::Decided { decision, .. } if decision.verdict == ApprovalVerdict::Deny => {
            return Ok(refused_goal(
                &call_id,
                ToolStatus::Denied,
                "operator denied the goal call",
            ));
        }
        ApprovalOutcome::Withdrawn { reason } => {
            return Ok(refused_goal(
                &call_id,
                match reason {
                    ApprovalWithdrawal::Cancelled => ToolStatus::Cancelled,
                    ApprovalWithdrawal::TimedOut => ToolStatus::TimedOut,
                },
                "goal approval was withdrawn",
            ));
        }
        ApprovalOutcome::Decided { .. } => {}
    }
    if cancel.is_cancelled() || shutdown.is_cancelled() || !authority.is_owner() {
        return Ok(refused_goal(
            &call_id,
            ToolStatus::Cancelled,
            "goal authority was withdrawn before execution",
        ));
    }
    if tools.bind_authorized(&invocation, &authority).as_ref() != Ok(&binding) {
        return Ok(refused_goal(
            &call_id,
            ToolStatus::Denied,
            "goal binding changed after approval",
        ));
    }
    let Ok(ordinal) =
        NEXT_AUTHORIZED_GOAL.fetch_update(Ordering::Relaxed, Ordering::Relaxed, |value| {
            value.checked_add(1)
        })
    else {
        return Ok(refused_goal(
            &call_id,
            ToolStatus::Failed,
            "runtime goal identity exhausted",
        ));
    };
    let Ok(host_id) = ToolCallId::new(format!("runtime-goal-{ordinal}")) else {
        return Ok(refused_goal(
            &call_id,
            ToolStatus::Failed,
            "runtime goal identity is invalid",
        ));
    };
    invocation.call.call_id = host_id;
    if let Err(error) = tools
        .audit_internal(
            &invocation,
            &authority,
            &binding,
            InternalToolAuditPhase::Authorized,
        )
        .await
    {
        return Ok(refused_goal(
            &call_id,
            ToolStatus::Failed,
            error.to_string(),
        ));
    }
    if cancel.is_cancelled()
        || shutdown.is_cancelled()
        || !authority.is_owner()
        || tools.bind_authorized(&invocation, &authority).as_ref() != Ok(&binding)
    {
        tools
            .audit_internal(
                &invocation,
                &authority,
                &binding,
                InternalToolAuditPhase::Failed,
            )
            .await
            .map_err(|error| ToolExecutionError::OutcomeUnknown(error.to_string()))?;
        return Ok(refused_goal(
            &call_id,
            ToolStatus::Cancelled,
            "goal authority was withdrawn before mutation",
        ));
    }
    let record = match service.apply(&invocation.session_id, &action).await {
        Ok(record) => record,
        Err(error) => {
            tools
                .audit_internal(
                    &invocation,
                    &authority,
                    &binding,
                    InternalToolAuditPhase::Failed,
                )
                .await
                .map_err(|error| ToolExecutionError::OutcomeUnknown(error.to_string()))?;
            if matches!(error, crate::goal::GoalError::Port(_)) {
                return Err(ToolExecutionError::OutcomeUnknown(error.to_string()));
            }
            return Ok(refused_goal(
                &call_id,
                ToolStatus::Failed,
                error.to_string(),
            ));
        }
    };
    tools
        .audit_internal(
            &invocation,
            &authority,
            &binding,
            InternalToolAuditPhase::Completed,
        )
        .await
        .map_err(|error| ToolExecutionError::OutcomeUnknown(error.to_string()))?;
    let output = format!(
        "goal {} is {} at revision {}",
        record.goal_id, record.status, record.revision
    );
    Ok(AuthorizedGoalOutcome {
        record: Some(record),
        outcome: ToolOutcome {
            call_id,
            status: ToolStatus::Ok,
            output,
            changed_workspace: false,
        },
    })
}

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
/// The tool writes runtime state rather than workspace files. Authenticated model calls require
/// an owner grant, a bound once-only approval and durable host audit.
#[must_use]
pub fn goal_tool_descriptor() -> ToolDescriptor {
    ToolDescriptor {
        name: GOAL_TOOL_NAME.to_owned(),
        summary: "Set, advance or close the durable session goal".to_owned(),
        requires_approval: true,
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
    fn the_descriptor_requires_approval_without_claiming_a_workspace_change() {
        let descriptor = goal_tool_descriptor();

        assert_eq!(descriptor.name, GOAL_TOOL_NAME);
        assert_eq!(
            descriptor.summary,
            "Set, advance or close the durable session goal"
        );
        assert!(descriptor.requires_approval);
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

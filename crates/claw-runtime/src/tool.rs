//! Tool invocation: approval gating, deadlines, and mid-flight cancellation.

use std::error::Error;
use std::fmt::{self, Display, Formatter};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use claw_application::model::approval::{ApprovalOutcome, ApprovalVerdict, ApprovalWithdrawal};
use claw_application::ports::clock::ClockPort;
use claw_application::ports::tool::{
    InvocationAuthority, ToolDescriptor, ToolInvocation, ToolOutcome, ToolPort, ToolStatus,
};
use tokio_util::sync::CancellationToken;

use crate::approval::{ApprovalBroker, ApprovalError, ApprovalTicket};

static NEXT_AUTHENTICATED_INVOCATION: AtomicU64 = AtomicU64::new(0);

/// Deadlines applied to every tool call.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ToolExecutorConfig {
    /// How long a single call may run before it is abandoned.
    pub call_timeout: Duration,
}

impl Default for ToolExecutorConfig {
    fn default() -> Self {
        Self {
            call_timeout: Duration::from_mins(2),
        }
    }
}

/// A failure that prevented the executor from producing an outcome at all.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ToolExecutionError {
    /// The approval broker failed.
    Approval(ApprovalError),
    /// A mutating authenticated call may have acted without a confirmed terminal result.
    OutcomeUnknown(String),
}

impl Display for ToolExecutionError {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        match self {
            Self::Approval(error) => write!(formatter, "approval failed: {error}"),
            Self::OutcomeUnknown(detail) => write!(
                formatter,
                "tool outcome is unknown; automatic replay is forbidden: {detail}"
            ),
        }
    }
}

impl Error for ToolExecutionError {}

impl From<ApprovalError> for ToolExecutionError {
    fn from(value: ApprovalError) -> Self {
        Self::Approval(value)
    }
}

/// Runs tool calls on behalf of a turn.
///
/// Every call passes through the same three gates in order: the tool must exist, an approval
/// decision must allow it, and it must finish before its deadline. Losing the deadline race, or
/// having `cancel` fire, drops the in-flight [`ToolPort::invoke`] future *and* notifies the
/// adapter through [`ToolPort::cancel`], so adapters owning subprocesses or sockets can tear them
/// down instead of leaking them.
#[derive(Clone)]
pub struct ToolExecutor {
    tools: Arc<dyn ToolPort>,
    broker: ApprovalBroker,
    clock: Arc<dyn ClockPort>,
    config: ToolExecutorConfig,
}

impl fmt::Debug for ToolExecutor {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ToolExecutor")
            .field("config", &self.config)
            .field("tools", &self.tools.describe().len())
            .finish_non_exhaustive()
    }
}

impl ToolExecutor {
    /// Creates an executor over a tool adapter and an approval broker.
    #[must_use]
    pub fn new(
        tools: Arc<dyn ToolPort>,
        broker: ApprovalBroker,
        clock: Arc<dyn ClockPort>,
        config: ToolExecutorConfig,
    ) -> Self {
        Self {
            tools,
            broker,
            clock,
            config,
        }
    }

    /// Returns the descriptor for a tool name.
    #[must_use]
    pub fn describe(&self, name: &str) -> Option<ToolDescriptor> {
        self.tools
            .describe()
            .into_iter()
            .find(|descriptor| descriptor.name == name)
    }

    /// Returns every tool this executor can run.
    #[must_use]
    pub fn catalogue(&self) -> Vec<ToolDescriptor> {
        self.tools.describe()
    }

    /// Runs one tool call to a terminal outcome.
    ///
    /// # Errors
    ///
    /// Returns [`ToolExecutionError::Approval`] when the approval broker itself failed, which
    /// means no decision could be obtained. Tool-side failures are reported as a
    /// [`ToolStatus::Failed`] outcome rather than an error.
    pub async fn execute(
        &self,
        invocation: ToolInvocation,
        cancel: &CancellationToken,
    ) -> Result<ToolOutcome, ToolExecutionError> {
        self.execute_authorized(invocation, None, cancel).await
    }

    /// Executes with host-verified authority, refusing read-only callers before any approval.
    ///
    /// # Errors
    /// Reports broker errors as in [`Self::execute`]; adapters unable to preserve identity fail closed.
    /// Mutating calls with unconfirmed completion return [`ToolExecutionError::OutcomeUnknown`].
    pub async fn execute_authorized(
        &self,
        mut invocation: ToolInvocation,
        authority: Option<InvocationAuthority>,
        cancel: &CancellationToken,
    ) -> Result<ToolOutcome, ToolExecutionError> {
        let call_id = invocation.call.call_id.clone();
        if authority
            .as_ref()
            .is_some_and(|authority| !authority.can_execute())
        {
            return Ok(Self::terminal(
                call_id,
                ToolStatus::Denied,
                "caller is not authorized to execute tools",
            ));
        }
        let Some(descriptor) = self.describe(&invocation.call.name) else {
            return Ok(ToolOutcome {
                call_id,
                status: ToolStatus::Failed,
                output: format!("unknown tool: {}", invocation.call.name),
                changed_workspace: false,
            });
        };

        if cancel.is_cancelled() {
            return Ok(Self::terminal(call_id, ToolStatus::Cancelled, "cancelled"));
        }

        let binding = if let Some(authority) = authority.as_ref() {
            match self.tools.bind_authorized(&invocation, authority) {
                Ok(binding) => Some(binding),
                Err(error) => {
                    return Ok(Self::terminal(
                        call_id,
                        ToolStatus::Failed,
                        &error.to_string(),
                    ));
                }
            }
        } else {
            None
        };

        if descriptor.requires_approval {
            let ticket = ApprovalTicket {
                session_id: invocation.session_id.clone(),
                turn: invocation.turn,
                call_id: call_id.clone(),
                tool_name: invocation.call.name.clone(),
                arguments: invocation.call.arguments.clone(),
            };
            let outcome = match (authority.clone(), binding.clone()) {
                (Some(authority), Some(binding)) => {
                    self.broker
                        .request_bound(ticket, authority, binding, cancel)
                        .await?
                }
                (None, None) => self.broker.request(ticket, cancel).await?,
                _ => {
                    return Ok(Self::terminal(
                        call_id,
                        ToolStatus::Failed,
                        "authenticated publication binding is missing",
                    ));
                }
            };

            match outcome {
                ApprovalOutcome::Decided { decision, .. }
                    if decision.verdict == ApprovalVerdict::Deny =>
                {
                    return Ok(Self::terminal(
                        call_id,
                        ToolStatus::Denied,
                        "operator denied the call",
                    ));
                }
                ApprovalOutcome::Withdrawn {
                    reason: ApprovalWithdrawal::TimedOut,
                } => {
                    return Ok(Self::terminal(
                        call_id,
                        ToolStatus::TimedOut,
                        "no approval decision before the deadline",
                    ));
                }
                ApprovalOutcome::Withdrawn {
                    reason: ApprovalWithdrawal::Cancelled,
                } => {
                    return Ok(Self::terminal(
                        call_id,
                        ToolStatus::Cancelled,
                        "cancelled while awaiting approval",
                    ));
                }
                ApprovalOutcome::Decided { .. } => {}
            }
        }

        if cancel.is_cancelled()
            || authority
                .as_ref()
                .is_some_and(InvocationAuthority::is_revoked)
        {
            return Ok(Self::terminal(
                call_id,
                ToolStatus::Cancelled,
                "cancelled before execution",
            ));
        }

        let adapter_id = if authority.is_some() {
            let Ok(ordinal) = NEXT_AUTHENTICATED_INVOCATION.fetch_update(
                Ordering::Relaxed,
                Ordering::Relaxed,
                |current| current.checked_add(1),
            ) else {
                return Ok(Self::terminal(
                    call_id,
                    ToolStatus::Failed,
                    "host invocation identity exhausted",
                ));
            };
            let Ok(id) =
                claw_application::model::ids::ToolCallId::new(format!("runtime-tool-{ordinal}"))
            else {
                return Ok(Self::terminal(
                    call_id,
                    ToolStatus::Failed,
                    "host invocation identity is invalid",
                ));
            };
            invocation.call.call_id = id.clone();
            id
        } else {
            call_id.clone()
        };
        let mutating_authenticated = authority.is_some() && descriptor.mutates_workspace;
        let execution_authority = authority.clone();
        let invoke = async {
            match (authority, binding) {
                (Some(authority), Some(binding)) => {
                    self.tools
                        .invoke_bound(invocation, authority, binding)
                        .await
                }
                (None, None) => self.tools.invoke(invocation).await,
                _ => Err(claw_application::ports::PortError::Invalid(
                    "authenticated publication binding is missing".to_owned(),
                )),
            }
        };
        let interrupted = tokio::select! {
            biased;
            () = cancel.cancelled() => ToolStatus::Cancelled,
            () = async {
                match execution_authority.as_ref() {
                    Some(authority) => authority.revoked().await,
                    None => std::future::pending::<()>().await,
                }
            } => ToolStatus::Cancelled,
            result = invoke => {
                if let Err(claw_application::ports::PortError::CommittedButNotDurable(detail) | claw_application::ports::PortError::OutcomeUnknown(detail)) = &result {
                    return Err(ToolExecutionError::OutcomeUnknown(detail.clone()));
                }
                return Ok(match result {
                    Ok(mut outcome) if outcome.call_id == adapter_id => {
                        outcome.call_id = call_id;
                        outcome
                    }
                    Ok(_) => Self::terminal(call_id, ToolStatus::Failed, "tool returned another invocation's result"),
                    Err(error) => ToolOutcome {
                        call_id,
                        status: ToolStatus::Failed,
                        output: error.to_string(),
                        changed_workspace: false,
                    },
                });
            }
            () = self.clock.sleep(self.config.call_timeout) => ToolStatus::TimedOut,
        };

        // The `invoke` future was dropped by `select!`; tell the adapter so it can release any
        // resources the future itself did not own.
        let _ = self.tools.cancel(&adapter_id).await;

        if mutating_authenticated {
            return Err(ToolExecutionError::OutcomeUnknown(
                "mutating invocation was interrupted; reconcile its audit and result before retry"
                    .to_owned(),
            ));
        }

        Ok(Self::terminal(
            call_id,
            interrupted,
            match interrupted {
                ToolStatus::Cancelled => "cancelled mid-flight",
                _ => "exceeded the call deadline",
            },
        ))
    }

    fn terminal(
        call_id: claw_application::model::ids::ToolCallId,
        status: ToolStatus,
        output: &str,
    ) -> ToolOutcome {
        ToolOutcome {
            call_id,
            status,
            output: output.to_owned(),
            changed_workspace: false,
        }
    }
}

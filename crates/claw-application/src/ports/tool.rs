//! The tool execution port.

use claw_domain::SessionId;

use super::{PortError, PortFuture};
use crate::model::ids::{ToolCallId, TurnId};
use crate::model::message::ToolCall;

/// A tool the runtime may dispatch.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ToolDescriptor {
    /// The dispatch name used by providers.
    pub name: String,
    /// A one-line human summary.
    pub summary: String,
    /// Whether an approval decision is required before every call.
    pub requires_approval: bool,
    /// Whether a successful call can mutate the workspace.
    pub mutates_workspace: bool,
}

/// One dispatched tool call.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ToolInvocation {
    /// The session that requested the call.
    pub session_id: SessionId,
    /// The turn that requested the call.
    pub turn: TurnId,
    /// The call to run.
    pub call: ToolCall,
}

/// How a tool call ended.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum ToolStatus {
    /// The tool ran and succeeded.
    Ok,
    /// The tool ran and reported a failure.
    Failed,
    /// An operator refused the call.
    Denied,
    /// The call was cancelled before it finished.
    Cancelled,
    /// The call exceeded its deadline.
    TimedOut,
}

impl ToolStatus {
    /// Every status in declaration order.
    pub const ALL: [Self; 5] = [
        Self::Ok,
        Self::Failed,
        Self::Denied,
        Self::Cancelled,
        Self::TimedOut,
    ];

    /// Returns the stable wire label for this status.
    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            Self::Ok => "ok",
            Self::Failed => "failed",
            Self::Denied => "denied",
            Self::Cancelled => "cancelled",
            Self::TimedOut => "timed_out",
        }
    }

    /// Returns whether the provider should be told the call failed.
    #[must_use]
    pub const fn is_failure(self) -> bool {
        !matches!(self, Self::Ok)
    }
}

/// The result of one tool call.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ToolOutcome {
    /// The call this outcome answers.
    pub call_id: ToolCallId,
    /// How the call ended.
    pub status: ToolStatus,
    /// The serialised tool output or failure detail.
    pub output: String,
    /// Whether the call mutated the workspace.
    pub changed_workspace: bool,
}

/// Runs tools on behalf of a turn.
///
/// Dropping the future returned by [`ToolPort::invoke`] must abort the call. `cancel` exists so
/// adapters that own external resources — subprocesses, sockets, remote jobs — can tear them down
/// eagerly instead of waiting for drop.
pub trait ToolPort: Send + Sync + 'static {
    /// Returns every tool this adapter can run.
    fn describe(&self) -> Vec<ToolDescriptor>;

    /// Runs one tool call.
    fn invoke(&self, invocation: ToolInvocation) -> PortFuture<'_, Result<ToolOutcome, PortError>>;

    /// Asks the adapter to abandon an in-flight call.
    fn cancel(&self, call_id: &ToolCallId) -> PortFuture<'_, Result<(), PortError>>;
}

#[cfg(test)]
mod tests {
    use super::ToolStatus;

    #[test]
    fn tool_status_labels_are_stable() {
        let labels: Vec<&str> = ToolStatus::ALL.iter().map(|s| s.label()).collect();

        assert_eq!(
            labels,
            vec!["ok", "failed", "denied", "cancelled", "timed_out"]
        );
    }

    #[test]
    fn only_ok_is_a_success() {
        let failures: Vec<ToolStatus> = ToolStatus::ALL
            .into_iter()
            .filter(|status| status.is_failure())
            .collect();

        assert_eq!(
            failures,
            vec![
                ToolStatus::Failed,
                ToolStatus::Denied,
                ToolStatus::Cancelled,
                ToolStatus::TimedOut,
            ]
        );
    }
}

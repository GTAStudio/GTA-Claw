//! The approval presentation port.

use super::{PortError, PortFuture};
use crate::model::approval::{ApprovalRequest, ApprovalWithdrawal};
use crate::model::ids::ApprovalId;

/// Presents approval requests to whoever can decide them.
///
/// Decisions travel back into the runtime through its approval broker, not through this port;
/// the port only pushes state outward so a gateway, CLI, or GUI can render it.
pub trait ApprovalPort: Send + Sync + 'static {
    /// Announces a new outstanding request.
    fn present(&self, request: ApprovalRequest) -> PortFuture<'_, Result<(), PortError>>;

    /// Announces that a request was answered and is no longer outstanding.
    fn settle(&self, approval_id: &ApprovalId) -> PortFuture<'_, Result<(), PortError>>;

    /// Announces that a request expired or was cancelled without an answer.
    fn withdraw(
        &self,
        approval_id: &ApprovalId,
        reason: ApprovalWithdrawal,
    ) -> PortFuture<'_, Result<(), PortError>>;
}

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

    /// Announces, synchronously, that a request was abandoned without an answer.
    ///
    /// This is the only dismissal that can be delivered from [`Drop`], which is why it is not a
    /// [`PortFuture`]: a dropped waiter has no executor left to await on, and a notification
    /// deferred to a task that may never be polled is not a notification. Every other dismissal
    /// travels through [`Self::withdraw`].
    ///
    /// # Contract
    ///
    /// Implementations run inside `Drop`, so they must not await, block on a lock that any
    /// asynchronous path holds across an await, or panic — a panic here during unwinding aborts
    /// the process.
    ///
    /// **Treat an abandoned request as denied.** The request is already gone from the broker
    /// before this is called, so a late answer will be refused; a surface that leaves the prompt
    /// on screen invites an operator to answer a tool call that no longer exists.
    fn abandon(&self, approval_id: &ApprovalId);
}

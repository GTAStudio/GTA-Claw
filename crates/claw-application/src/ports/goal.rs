//! The durable goal persistence port.

use claw_domain::SessionId;

use super::{PortError, PortFuture};
use crate::model::goal::GoalRecord;
use crate::model::ids::GoalId;

/// Persists durable session goals across restarts.
///
/// `save` uses optimistic concurrency on [`GoalRecord::revision`]: the adapter must reject a
/// write whose `revision` is not exactly one greater than the stored revision with
/// [`PortError::Conflict`].
pub trait GoalStorePort: Send + Sync + 'static {
    /// Returns the next generated identifier ordinal from the persisted monotonic high-water mark.
    ///
    /// The ordinal is reserved by the subsequent successful [`Self::save`]. Until then, retries
    /// receive the same value so a record published without its index can be adopted idempotently.
    fn next_goal_ordinal(&self, session_id: &SessionId) -> PortFuture<'_, Result<u64, PortError>>;

    /// Loads one goal, or `None` when it is unknown.
    fn load(&self, goal_id: &GoalId) -> PortFuture<'_, Result<Option<GoalRecord>, PortError>>;

    /// Persists one goal.
    fn save(&self, record: GoalRecord) -> PortFuture<'_, Result<(), PortError>>;

    /// Lists every goal of a session, oldest first.
    fn list_for_session(
        &self,
        session_id: &SessionId,
    ) -> PortFuture<'_, Result<Vec<GoalRecord>, PortError>>;
}

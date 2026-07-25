//! The session persistence port.

use claw_domain::SessionId;
use serde::{Deserialize, Serialize};

use super::{PortError, PortFuture};
use crate::model::ids::TurnId;
use crate::model::message::{AssistantMessage, PartialAssistantMessage};
use crate::model::session::SessionState;
use crate::model::time::Timestamp;

/// The durable view of one session.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct SessionSnapshot {
    /// The session identifier.
    #[serde(with = "crate::model::session_id_serde")]
    pub session_id: SessionId,
    /// The current turn.
    pub turn: TurnId,
    /// The current user-visible state.
    pub state: SessionState,
    /// The state to restore when a paused turn resumes.
    pub pre_pause_state: Option<SessionState>,
    /// When the snapshot was written.
    pub updated_at: Timestamp,
    /// Optimistic-concurrency revision; `0` for a session that was never persisted.
    pub revision: u64,
}

/// The durable view of one turn.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct TurnRecord {
    /// The owning session.
    #[serde(with = "crate::model::session_id_serde")]
    pub session_id: SessionId,
    /// The turn identifier.
    pub turn: TurnId,
    /// The state the turn reached.
    pub state: SessionState,
    /// The assembled message, when the turn completed one.
    pub message: Option<AssistantMessage>,
    /// The recoverable remains of an interrupted stream.
    pub partial: Option<PartialAssistantMessage>,
    /// When the record was written.
    pub updated_at: Timestamp,
}

/// Persists sessions and their turns.
///
/// `save_session` uses optimistic concurrency: the caller supplies the revision it read, and the
/// adapter must reject a stale write with [`PortError::Conflict`].
pub trait StatePort: Send + Sync + 'static {
    /// Loads a session snapshot, or `None` when the session is unknown.
    fn load_session(
        &self,
        session_id: &SessionId,
    ) -> PortFuture<'_, Result<Option<SessionSnapshot>, PortError>>;

    /// Persists a snapshot and returns the revision it was stored at.
    fn save_session(&self, snapshot: SessionSnapshot) -> PortFuture<'_, Result<u64, PortError>>;

    /// Persists one turn record.
    fn save_turn(&self, record: TurnRecord) -> PortFuture<'_, Result<(), PortError>>;

    /// Loads one turn record, or `None` when it is unknown.
    fn load_turn(
        &self,
        session_id: &SessionId,
        turn: TurnId,
    ) -> PortFuture<'_, Result<Option<TurnRecord>, PortError>>;

    /// Lists every persisted session snapshot.
    fn list_sessions(&self) -> PortFuture<'_, Result<Vec<SessionSnapshot>, PortError>>;
}

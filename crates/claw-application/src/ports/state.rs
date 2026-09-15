//! The session persistence port.

use claw_domain::SessionId;

use super::{PortError, PortFuture};
use crate::model::ids::TurnId;
use crate::model::message::{AssistantMessage, PartialAssistantMessage};
use crate::model::session::SessionState;
use crate::model::time::Timestamp;

/// The durable view of one session.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SessionSnapshot {
    /// The session identifier.
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
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TurnRecord {
    /// The owning session.
    pub session_id: SessionId,
    /// The turn identifier.
    pub turn: TurnId,
    /// The state the turn reached.
    pub state: SessionState,
    /// The assembled message, when the turn completed one.
    pub message: Option<AssistantMessage>,
    /// The recoverable remains of an interrupted stream.
    pub partial: Option<PartialAssistantMessage>,
    /// Metadata for provider rounds, with absent responses explicitly unknown.
    /// An empty collection in an older record does not prove zero model usage.
    pub provider_rounds: Vec<super::provider::ProviderRoundRecord>,
    /// When the record was written.
    pub updated_at: Timestamp,
}

/// Append-only provider attempts and first confirmed responses for one turn.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProviderRoundJournal {
    /// The owning session.
    pub session_id: SessionId,
    /// The turn whose provider work is recorded.
    pub turn: TurnId,
    /// Sequential attempts, with absent responses explicitly unknown.
    pub rounds: Vec<super::provider::ProviderRoundRecord>,
    /// Optimistic-concurrency revision; zero only before the first write.
    pub revision: u64,
    /// Whether an immutable terminal turn has sealed this journal.
    pub closed: bool,
    /// When the latest attempt or response was recorded.
    pub updated_at: Timestamp,
}

impl ProviderRoundJournal {
    /// Validates a single new attempt or the first report for the latest attempt.
    ///
    /// # Errors
    /// Rejects stale revisions, identity changes, replayed attempts and changed reports.
    pub fn validate_update(&self, previous: Option<&Self>) -> Result<(), PortError> {
        super::provider::ProviderRoundRecord::validate_sequence(&self.rounds)?;
        let conflict = || {
            PortError::Conflict("provider journal update is stale or not append-only".to_owned())
        };
        if self.closed || self.rounds.is_empty() {
            return Err(conflict());
        }
        let Some(previous) = previous else {
            return if self.revision == 0
                && self.rounds.len() == 1
                && self.rounds[0].response.is_none()
            {
                Ok(())
            } else {
                Err(conflict())
            };
        };
        if previous.closed
            || previous.session_id != self.session_id
            || previous.turn != self.turn
            || self.revision != previous.revision
            || previous.rounds.is_empty()
        {
            return Err(conflict());
        }
        if self.rounds.len() == previous.rounds.len() + 1
            && self.rounds[..previous.rounds.len()] == previous.rounds
            && self
                .rounds
                .last()
                .is_some_and(|round| round.response.is_none())
        {
            return Ok(());
        }
        let last = previous.rounds.len() - 1;
        if self.rounds.len() == previous.rounds.len()
            && self.rounds[..last] == previous.rounds[..last]
            && previous.rounds[last].response.is_none()
            && self.rounds[last].response.is_some()
        {
            return Ok(());
        }
        Err(conflict())
    }
}

/// Persists sessions and their turns.
///
/// `save_session` uses optimistic concurrency: the caller supplies the revision it read, and the
/// adapter must reject a stale write with [`PortError::Conflict`].
pub trait StatePort: Send + Sync + 'static {
    /// Returns the next unused turn when the current session pointer is absent.
    ///
    /// Durable adapters retain a high-water mark across resets. Ephemeral adapters may
    /// start a new history at the first turn.
    fn next_turn(&self, _session_id: &SessionId) -> PortFuture<'_, Result<TurnId, PortError>> {
        Box::pin(std::future::ready(Ok(TurnId::FIRST)))
    }

    /// Loads a session snapshot, or `None` when the session is unknown.
    fn load_session(
        &self,
        session_id: &SessionId,
    ) -> PortFuture<'_, Result<Option<SessionSnapshot>, PortError>>;

    /// Persists a snapshot and returns the revision it was stored at.
    fn save_session(&self, snapshot: SessionSnapshot) -> PortFuture<'_, Result<u64, PortError>>;

    /// Durably records one provider attempt or first response and returns its new revision.
    ///
    /// Unsupported adapters fail closed; a successful write must precede provider I/O.
    fn save_provider_journal(
        &self,
        _journal: ProviderRoundJournal,
    ) -> PortFuture<'_, Result<u64, PortError>> {
        Box::pin(std::future::ready(Err(PortError::Unavailable(
            "provider round journaling is not supported by this state adapter".to_owned(),
        ))))
    }

    /// Loads provider attempts even if the process never saved a terminal turn.
    fn load_provider_journal(
        &self,
        _session_id: &SessionId,
        _turn: TurnId,
    ) -> PortFuture<'_, Result<Option<ProviderRoundJournal>, PortError>> {
        Box::pin(std::future::ready(Err(PortError::Unavailable(
            "provider round journaling is not supported by this state adapter".to_owned(),
        ))))
    }

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

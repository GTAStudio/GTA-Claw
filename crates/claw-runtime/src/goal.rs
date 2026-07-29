//! Durable session goals: creation, progress, budgeted compaction, and restart resumption.
//!
//! A goal survives process restarts because every mutation is written through
//! [`GoalStorePort`] before it is returned. The service holds no cache, so a fresh
//! [`GoalService`] over the same store sees exactly what the previous one persisted.

use std::error::Error;
use std::fmt::{self, Display, Formatter};
use std::sync::Arc;

use claw_application::model::goal::{GoalProgress, GoalRecord, GoalStatus};
use claw_application::model::ids::{GoalId, IdentifierError};
use claw_application::ports::PortError;
use claw_application::ports::clock::ClockPort;
use claw_application::ports::goal::GoalStorePort;
use claw_domain::SessionId;

use crate::goal_tool::GoalAction;

/// How much progress history a goal may keep.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct GoalConfig {
    /// The most progress entries a goal keeps before the oldest are folded into a summary.
    pub max_progress_entries: usize,
    /// The longest objective text accepted, in bytes.
    pub max_objective_bytes: usize,
    /// The longest progress note accepted, in bytes.
    pub max_note_bytes: usize,
}

impl Default for GoalConfig {
    fn default() -> Self {
        Self {
            max_progress_entries: 32,
            max_objective_bytes: 4096,
            max_note_bytes: 2048,
        }
    }
}

/// A refused goal operation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum GoalError {
    /// The goal store failed.
    Port(PortError),
    /// No goal with that identifier exists.
    Unknown(GoalId),
    /// The session has no active goal to act on.
    NoActiveGoal,
    /// The goal already reached a terminal status.
    AlreadyClosed {
        /// The goal that was already closed.
        goal_id: GoalId,
        /// The status it holds.
        status: GoalStatus,
    },
    /// A goal cannot be closed with [`GoalStatus::Active`].
    NotATerminalStatus(GoalStatus),
    /// The objective was blank or too long.
    InvalidObjective(&'static str),
    /// The progress note was blank or too long.
    InvalidNote(&'static str),
    /// The configured progress budget cannot hold a single entry.
    InvalidBudget,
    /// The session identifier cannot produce a usable goal identifier.
    UnusableGoalId(IdentifierError),
}

impl Display for GoalError {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        match self {
            Self::Port(error) => write!(formatter, "goal store failed: {error}"),
            Self::Unknown(goal_id) => write!(formatter, "unknown goal {goal_id}"),
            Self::NoActiveGoal => formatter.write_str("the session has no active goal"),
            Self::AlreadyClosed { goal_id, status } => {
                write!(formatter, "goal {goal_id} is already {status}")
            }
            Self::NotATerminalStatus(status) => {
                write!(formatter, "{status} is not a terminal goal status")
            }
            Self::InvalidObjective(reason) => write!(formatter, "invalid objective: {reason}"),
            Self::InvalidNote(reason) => write!(formatter, "invalid progress note: {reason}"),
            Self::InvalidBudget => {
                formatter.write_str("progress budget must allow at least one entry")
            }
            Self::UnusableGoalId(error) => write!(formatter, "cannot mint a goal id: {error}"),
        }
    }
}

impl Error for GoalError {}

impl From<PortError> for GoalError {
    fn from(value: PortError) -> Self {
        Self::Port(value)
    }
}

/// Manages the durable goal of each session.
#[derive(Clone)]
pub struct GoalService {
    store: Arc<dyn GoalStorePort>,
    clock: Arc<dyn ClockPort>,
    config: GoalConfig,
}

impl fmt::Debug for GoalService {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("GoalService")
            .field("config", &self.config)
            .finish_non_exhaustive()
    }
}

impl GoalService {
    /// Creates a goal service over a store and a clock.
    #[must_use]
    pub fn new(
        store: Arc<dyn GoalStorePort>,
        clock: Arc<dyn ClockPort>,
        config: GoalConfig,
    ) -> Self {
        Self {
            store,
            clock,
            config,
        }
    }

    /// Returns the session's active goal, reading it from the store every time.
    ///
    /// This is also the restart path: a service constructed after a restart returns the goal the
    /// previous process persisted, including its progress history and revision.
    ///
    /// # Errors
    ///
    /// Returns [`GoalError::Port`] when the store fails.
    pub async fn active(&self, session_id: &SessionId) -> Result<Option<GoalRecord>, GoalError> {
        let goals = self.store.list_for_session(session_id).await?;
        Ok(goals
            .into_iter()
            .rev()
            .find(|goal| goal.status == GoalStatus::Active))
    }

    /// Returns every goal of a session, oldest first.
    ///
    /// # Errors
    ///
    /// Returns [`GoalError::Port`] when the store fails.
    pub async fn history(&self, session_id: &SessionId) -> Result<Vec<GoalRecord>, GoalError> {
        Ok(self.store.list_for_session(session_id).await?)
    }

    /// Records a new goal, superseding whatever goal was active.
    ///
    /// # Errors
    ///
    /// Returns [`GoalError::InvalidObjective`] for blank or oversized text, and
    /// [`GoalError::Port`] when the store fails.
    pub async fn set(
        &self,
        session_id: &SessionId,
        goal_id: GoalId,
        objective: &str,
    ) -> Result<GoalRecord, GoalError> {
        let objective = self.validate_objective(objective)?;

        let now = self.clock.now();

        let previous = self.active(session_id).await?;

        let record = GoalRecord {
            goal_id,
            session_id: session_id.clone(),
            objective,
            status: GoalStatus::Active,
            progress: Vec::new(),
            created_at: now,
            updated_at: now,
            closed_at: None,
            compacted_entries: 0,
            revision: 1,
        };

        // The replacement is durable before the goal it replaces is closed, so neither dropping
        // this future between the two writes nor a failure of the second write can leave the
        // session with no active goal. `active` reads the newest active record, so the transient
        // overlap resolves to the replacement.
        self.store.save(record.clone()).await?;

        if let Some(mut previous) = previous {
            previous.status = GoalStatus::Superseded;
            previous.updated_at = now;
            previous.closed_at = Some(now);
            previous.revision = previous.revision.saturating_add(1);
            self.store.save(previous).await?;
        }

        Ok(record)
    }

    /// Appends one progress entry, compacting the oldest entries when the budget is exceeded.
    ///
    /// # Errors
    ///
    /// Returns [`GoalError::Unknown`] for an unknown goal, [`GoalError::AlreadyClosed`] when the
    /// goal is no longer active, [`GoalError::InvalidNote`] for blank or oversized notes, and
    /// [`GoalError::Port`] when the store fails.
    pub async fn record_progress(
        &self,
        goal_id: &GoalId,
        note: &str,
    ) -> Result<GoalRecord, GoalError> {
        if self.config.max_progress_entries == 0 {
            return Err(GoalError::InvalidBudget);
        }
        let note = note.trim();
        if note.is_empty() {
            return Err(GoalError::InvalidNote("must not be empty"));
        }
        if note.len() > self.config.max_note_bytes {
            return Err(GoalError::InvalidNote("is too long"));
        }

        let mut record = self.require_active(goal_id).await?;
        let now = self.clock.now();
        let index = record
            .progress
            .last()
            .map_or(0, |entry| entry.index.saturating_add(1));
        record.progress.push(GoalProgress {
            index,
            note: note.to_owned(),
            recorded_at: now,
            compacted: false,
        });
        self.compact(&mut record, now);
        record.updated_at = now;
        record.revision = record.revision.saturating_add(1);

        self.store.save(record.clone()).await?;
        Ok(record)
    }

    /// Closes a goal with a terminal status.
    ///
    /// # Errors
    ///
    /// Returns [`GoalError::NotATerminalStatus`] for [`GoalStatus::Active`],
    /// [`GoalError::Unknown`] for an unknown goal, [`GoalError::AlreadyClosed`] when the goal is
    /// already closed, and [`GoalError::Port`] when the store fails.
    pub async fn close(
        &self,
        goal_id: &GoalId,
        status: GoalStatus,
    ) -> Result<GoalRecord, GoalError> {
        if !status.is_closed() {
            return Err(GoalError::NotATerminalStatus(status));
        }

        let mut record = self.require_active(goal_id).await?;
        let now = self.clock.now();
        record.status = status;
        record.updated_at = now;
        record.closed_at = Some(now);
        record.revision = record.revision.saturating_add(1);

        self.store.save(record.clone()).await?;
        Ok(record)
    }

    /// Mints the next goal identifier for a session and records the objective.
    ///
    /// Identifiers are `<session>:goal-N`, where `N` comes from the store's persisted monotonic
    /// high-water mark. The session is part of the identifier because [`GoalStorePort::load`] is
    /// keyed by goal id alone: a bare `goal-N` would collide between sessions in any real store.
    ///
    /// # Errors
    ///
    /// Returns [`GoalError::UnusableGoalId`] when the session identifier is too long to fit in a
    /// goal identifier, and everything [`GoalService::set`] can return.
    pub async fn start(
        &self,
        session_id: &SessionId,
        objective: &str,
    ) -> Result<GoalRecord, GoalError> {
        let objective = self.validate_objective(objective)?;
        let ordinal = self.store.next_goal_ordinal(session_id).await?;
        let goal_id = GoalId::new(format!("{}:goal-{ordinal}", session_id.as_str()))
            .map_err(GoalError::UnusableGoalId)?;
        if let Some(orphan) = self.store.load(&goal_id).await?
            && Self::is_equivalent_new_goal(&orphan, session_id, &objective)
        {
            let previous = self.active(session_id).await?;
            self.store.save(orphan.clone()).await?;
            if let Some(mut previous) = previous {
                previous.status = GoalStatus::Superseded;
                previous.updated_at = orphan.created_at;
                previous.closed_at = Some(orphan.created_at);
                previous.revision = previous.revision.saturating_add(1);
                self.store.save(previous).await?;
            }
            return Ok(orphan);
        }
        self.set(session_id, goal_id, &objective).await
    }

    /// Applies one model-authored goal action to the session's durable goal.
    ///
    /// This is the write path behind the model-callable goal tool. Every action except
    /// [`GoalAction::Set`] requires an active goal and fails with [`GoalError::NoActiveGoal`]
    /// otherwise, so a model cannot silently no-op its own progress reporting.
    ///
    /// # Errors
    ///
    /// Returns [`GoalError::NoActiveGoal`] when the action needs a goal the session does not have,
    /// and everything [`GoalService::set`], [`GoalService::record_progress`] and
    /// [`GoalService::close`] can return.
    pub async fn apply(
        &self,
        session_id: &SessionId,
        action: &GoalAction,
    ) -> Result<GoalRecord, GoalError> {
        match action {
            GoalAction::Set { objective } => self.start(session_id, objective).await,
            GoalAction::Progress { note } => {
                let active = self
                    .active(session_id)
                    .await?
                    .ok_or(GoalError::NoActiveGoal)?;
                self.record_progress(&active.goal_id, note).await
            }
            GoalAction::Close { status } => {
                let active = self
                    .active(session_id)
                    .await?
                    .ok_or(GoalError::NoActiveGoal)?;
                self.close(&active.goal_id, *status).await
            }
        }
    }

    async fn require_active(&self, goal_id: &GoalId) -> Result<GoalRecord, GoalError> {
        let record = self
            .store
            .load(goal_id)
            .await?
            .ok_or_else(|| GoalError::Unknown(goal_id.clone()))?;

        if record.status.is_closed() {
            return Err(GoalError::AlreadyClosed {
                goal_id: goal_id.clone(),
                status: record.status,
            });
        }

        Ok(record)
    }

    fn validate_objective(&self, objective: &str) -> Result<String, GoalError> {
        if self.config.max_progress_entries == 0 {
            return Err(GoalError::InvalidBudget);
        }
        let objective = objective.trim();
        if objective.is_empty() {
            return Err(GoalError::InvalidObjective("must not be empty"));
        }
        if objective.len() > self.config.max_objective_bytes {
            return Err(GoalError::InvalidObjective("is too long"));
        }
        Ok(objective.to_owned())
    }

    fn is_equivalent_new_goal(
        record: &GoalRecord,
        session_id: &SessionId,
        objective: &str,
    ) -> bool {
        record.session_id == *session_id
            && record.objective == objective
            && record.status == GoalStatus::Active
            && record.progress.is_empty()
            && record.created_at == record.updated_at
            && record.closed_at.is_none()
            && record.compacted_entries == 0
            && record.revision == 1
    }

    /// Folds the oldest entries into a single summary once the budget is exceeded.
    fn compact(&self, record: &mut GoalRecord, now: claw_application::model::time::Timestamp) {
        let budget = self.config.max_progress_entries;
        if record.progress.len() <= budget {
            return;
        }

        // Keep the newest `budget - 1` entries and replace everything older with one summary.
        let keep = budget - 1;
        let removed = record.progress.len() - keep;
        let head_index = record.progress[0].index;
        let folded: Vec<GoalProgress> = record.progress.drain(..removed).collect();
        let newly_folded = folded.iter().filter(|entry| !entry.compacted).count();

        record.compacted_entries = record
            .compacted_entries
            .saturating_add(u64::try_from(newly_folded).unwrap_or(u64::MAX));

        record.progress.insert(
            0,
            GoalProgress {
                index: head_index,
                note: format!("compacted {} earlier entries", record.compacted_entries),
                recorded_at: now,
                compacted: true,
            },
        );
    }
}

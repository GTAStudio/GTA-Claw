//! Durable session goal values.

use std::fmt::{self, Display, Formatter};

use claw_domain::SessionId;

use super::ids::GoalId;
use super::time::Timestamp;

/// The lifecycle status of a durable goal.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum GoalStatus {
    /// The goal steers the session.
    Active,
    /// The goal was met.
    Achieved,
    /// The goal was dropped by the operator.
    Abandoned,
    /// The goal could not be met.
    Failed,
    /// A newer goal replaced this one.
    Superseded,
}

impl GoalStatus {
    /// Every status in declaration order.
    pub const ALL: [Self; 5] = [
        Self::Active,
        Self::Achieved,
        Self::Abandoned,
        Self::Failed,
        Self::Superseded,
    ];

    /// Returns the stable wire label for this status.
    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            Self::Active => "active",
            Self::Achieved => "achieved",
            Self::Abandoned => "abandoned",
            Self::Failed => "failed",
            Self::Superseded => "superseded",
        }
    }

    /// Returns whether the goal no longer steers the session.
    #[must_use]
    pub const fn is_closed(self) -> bool {
        !matches!(self, Self::Active)
    }
}

impl Display for GoalStatus {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.label())
    }
}

/// One recorded step toward a goal.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GoalProgress {
    /// Monotonic index of this entry within the goal.
    pub index: u64,
    /// The recorded note.
    pub note: String,
    /// When the note was recorded.
    pub recorded_at: Timestamp,
    /// Whether this entry summarises compacted earlier entries.
    pub compacted: bool,
}

/// A goal persisted across restarts.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GoalRecord {
    /// The goal identifier.
    pub goal_id: GoalId,
    /// The owning session.
    pub session_id: SessionId,
    /// The operator-supplied objective.
    pub objective: String,
    /// The lifecycle status.
    pub status: GoalStatus,
    /// Ordered progress entries, oldest first.
    pub progress: Vec<GoalProgress>,
    /// When the goal was created.
    pub created_at: Timestamp,
    /// When the goal was last mutated.
    pub updated_at: Timestamp,
    /// When the goal reached a closed status.
    pub closed_at: Option<Timestamp>,
    /// The number of progress entries removed by compaction.
    pub compacted_entries: u64,
    /// Optimistic-concurrency revision; incremented on every persisted mutation.
    pub revision: u64,
}

#[cfg(test)]
mod tests {
    use super::GoalStatus;

    #[test]
    fn goal_status_labels_are_stable() {
        let labels: Vec<&str> = GoalStatus::ALL.iter().map(|s| s.label()).collect();

        assert_eq!(
            labels,
            vec!["active", "achieved", "abandoned", "failed", "superseded"]
        );
    }

    #[test]
    fn only_active_goals_are_open() {
        let closed: Vec<GoalStatus> = GoalStatus::ALL
            .into_iter()
            .filter(|status| status.is_closed())
            .collect();

        assert_eq!(
            closed,
            vec![
                GoalStatus::Achieved,
                GoalStatus::Abandoned,
                GoalStatus::Failed,
                GoalStatus::Superseded,
            ]
        );
    }
}

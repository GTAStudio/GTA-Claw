//! Durable session goal values.

use std::fmt::{self, Display, Formatter};

use claw_domain::SessionId;
use serde::{Deserialize, Serialize};

use super::ids::GoalId;
use super::time::Timestamp;

/// The lifecycle status of a durable goal.
#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
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
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
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
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct GoalRecord {
    /// The goal identifier.
    pub goal_id: GoalId,
    /// The owning session.
    #[serde(with = "super::session_id_serde")]
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
    use claw_domain::SessionId;

    use super::{GoalProgress, GoalRecord, GoalStatus};
    use crate::model::ids::GoalId;
    use crate::model::time::Timestamp;

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

    #[test]
    fn goal_records_round_trip_through_json() {
        let record = GoalRecord {
            goal_id: GoalId::new("goal-1").expect("valid goal id"),
            session_id: SessionId::new("session-1").expect("valid session id"),
            objective: "ship the runtime".to_owned(),
            status: GoalStatus::Active,
            progress: vec![GoalProgress {
                index: 0,
                note: "scaffolded".to_owned(),
                recorded_at: Timestamp::from_millis(10),
                compacted: false,
            }],
            created_at: Timestamp::from_millis(5),
            updated_at: Timestamp::from_millis(10),
            closed_at: None,
            compacted_entries: 0,
            revision: 2,
        };

        let encoded = serde_json::to_string(&record).expect("goal serialises");
        let decoded: GoalRecord = serde_json::from_str(&encoded).expect("goal deserialises");

        assert_eq!(decoded, record);
        assert_eq!(decoded.progress[0].note, "scaffolded");
        assert_eq!(decoded.revision, 2);
    }
}

//! Ceilings on what a session may keep on disk.
//!
//! A durable goal store is a place an agent can write to without an operator watching. Two
//! ceilings keep that from becoming unbounded growth on someone's disk: how many goals one
//! session may accumulate, and how many bytes those goals may occupy. A third, per record, keeps
//! a single pathological objective or progress history from consuming the session's whole
//! allowance in one write.
//!
//! Every ceiling is enforced *before* the write, and every refusal names the limit, what is
//! already held, and what was asked for. A budget that refuses without saying what it refused is
//! indistinguishable from a bug.

use std::error::Error;
use std::fmt::{self, Display, Formatter};

/// What one session currently occupies in the store.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct BudgetUsage {
    /// The number of goal records the session holds, in every status.
    pub goals: usize,
    /// The number of bytes those records occupy on disk.
    pub bytes: u64,
}

/// The ceilings applied to one session.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct GoalBudget {
    /// The most goal records one session may hold.
    pub max_goals_per_session: usize,
    /// The largest single encoded record accepted, in bytes.
    pub max_record_bytes: usize,
    /// The most bytes one session's records may occupy in total.
    pub max_session_bytes: u64,
}

impl Default for GoalBudget {
    /// Returns ceilings sized for an interactive session rather than for a bulk importer.
    ///
    /// 64 goals is far more than a session that supersedes a goal a few times a day will reach;
    /// 256 KiB per record leaves headroom above the runtime's own worst case of a 4 KiB objective
    /// plus 32 progress notes of 2 KiB; 4 MiB per session bounds the total at something a laptop
    /// will not notice.
    fn default() -> Self {
        Self {
            max_goals_per_session: 64,
            max_record_bytes: 256 * 1024,
            max_session_bytes: 4 * 1024 * 1024,
        }
    }
}

/// A write refused because it would exceed a ceiling.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum BudgetError {
    /// The session already holds as many goals as it may.
    TooManyGoals {
        /// The ceiling.
        limit: usize,
        /// How many the session already holds.
        held: usize,
    },
    /// One encoded record is larger than a record may be.
    RecordTooLarge {
        /// The ceiling.
        limit: usize,
        /// The size of the offered record.
        offered: usize,
    },
    /// The session's records would occupy more bytes than they may.
    SessionBytesExhausted {
        /// The ceiling.
        limit: u64,
        /// The bytes the session's other records already occupy.
        held: u64,
        /// The size of the offered record.
        offered: u64,
    },
}

impl BudgetError {
    /// Returns the stable label of the ceiling that refused the write.
    #[must_use]
    pub const fn ceiling(&self) -> &'static str {
        match self {
            Self::TooManyGoals { .. } => "max_goals_per_session",
            Self::RecordTooLarge { .. } => "max_record_bytes",
            Self::SessionBytesExhausted { .. } => "max_session_bytes",
        }
    }
}

impl Display for BudgetError {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        match self {
            Self::TooManyGoals { limit, held } => write!(
                formatter,
                "goal budget {} exceeded: the session holds {held} of {limit} goals",
                self.ceiling()
            ),
            Self::RecordTooLarge { limit, offered } => write!(
                formatter,
                "goal budget {} exceeded: the record is {offered} bytes of {limit}",
                self.ceiling()
            ),
            Self::SessionBytesExhausted {
                limit,
                held,
                offered,
            } => write!(
                formatter,
                "goal budget {} exceeded: {held} bytes held plus {offered} offered exceeds {limit}",
                self.ceiling()
            ),
        }
    }
}

impl Error for BudgetError {}

impl GoalBudget {
    /// Decides whether one record may be written, and returns the usage that would result.
    ///
    /// `held` must describe the session *excluding* the record being written, so replacing an
    /// existing record is charged only for its new size. Returning the projected usage rather
    /// than a bare `Ok(())` is what lets a caller meter a session without a second pass over the
    /// directory.
    ///
    /// # Errors
    ///
    /// Returns [`BudgetError::RecordTooLarge`] when the record alone is oversized,
    /// [`BudgetError::TooManyGoals`] when the session already holds its full count, and
    /// [`BudgetError::SessionBytesExhausted`] when the write would push the session over its byte
    /// ceiling.
    pub fn admit(
        self,
        held: BudgetUsage,
        offered_bytes: usize,
        is_new_goal: bool,
    ) -> Result<BudgetUsage, BudgetError> {
        if offered_bytes > self.max_record_bytes {
            return Err(BudgetError::RecordTooLarge {
                limit: self.max_record_bytes,
                offered: offered_bytes,
            });
        }

        let goals = if is_new_goal {
            if held.goals >= self.max_goals_per_session {
                return Err(BudgetError::TooManyGoals {
                    limit: self.max_goals_per_session,
                    held: held.goals,
                });
            }
            held.goals.saturating_add(1)
        } else {
            held.goals
        };

        let offered = u64::try_from(offered_bytes).unwrap_or(u64::MAX);
        let bytes = held.bytes.saturating_add(offered);
        if bytes > self.max_session_bytes {
            return Err(BudgetError::SessionBytesExhausted {
                limit: self.max_session_bytes,
                held: held.bytes,
                offered,
            });
        }

        Ok(BudgetUsage { goals, bytes })
    }
}

#[cfg(test)]
mod tests {
    use super::{BudgetError, BudgetUsage, GoalBudget};

    const BUDGET: GoalBudget = GoalBudget {
        max_goals_per_session: 3,
        max_record_bytes: 100,
        max_session_bytes: 250,
    };

    #[test]
    fn a_new_goal_is_charged_a_slot_and_its_bytes() {
        let held = BudgetUsage {
            goals: 1,
            bytes: 40,
        };

        assert_eq!(
            BUDGET.admit(held, 60, true),
            Ok(BudgetUsage {
                goals: 2,
                bytes: 100,
            })
        );
    }

    #[test]
    fn replacing_a_record_is_charged_bytes_but_not_a_slot() {
        let held = BudgetUsage {
            goals: 3,
            bytes: 40,
        };

        assert_eq!(
            BUDGET.admit(held, 60, false),
            Ok(BudgetUsage {
                goals: 3,
                bytes: 100,
            })
        );
    }

    #[test]
    fn a_full_session_refuses_another_goal_but_still_accepts_updates() {
        let held = BudgetUsage {
            goals: 3,
            bytes: 10,
        };

        assert_eq!(
            BUDGET.admit(held, 10, true),
            Err(BudgetError::TooManyGoals { limit: 3, held: 3 })
        );
        assert!(BUDGET.admit(held, 10, false).is_ok());
    }

    #[test]
    fn an_oversized_record_is_refused_before_any_other_ceiling() {
        let held = BudgetUsage {
            goals: 3,
            bytes: 250,
        };

        assert_eq!(
            BUDGET.admit(held, 101, true),
            Err(BudgetError::RecordTooLarge {
                limit: 100,
                offered: 101,
            })
        );
    }

    #[test]
    fn the_session_byte_ceiling_is_inclusive_and_reports_both_sides() {
        let held = BudgetUsage {
            goals: 1,
            bytes: 200,
        };

        assert_eq!(
            BUDGET.admit(held, 50, false),
            Ok(BudgetUsage {
                goals: 1,
                bytes: 250,
            })
        );
        assert_eq!(
            BUDGET.admit(held, 51, false),
            Err(BudgetError::SessionBytesExhausted {
                limit: 250,
                held: 200,
                offered: 51,
            })
        );
    }

    #[test]
    fn refusals_name_the_ceiling_they_come_from() {
        assert_eq!(
            BUDGET
                .admit(BudgetUsage { goals: 3, bytes: 0 }, 1, true)
                .expect_err("the session is full")
                .to_string(),
            "goal budget max_goals_per_session exceeded: the session holds 3 of 3 goals"
        );
        assert_eq!(
            BUDGET
                .admit(BudgetUsage::default(), 101, true)
                .expect_err("the record is oversized")
                .ceiling(),
            "max_record_bytes"
        );
        assert_eq!(
            BUDGET
                .admit(
                    BudgetUsage {
                        goals: 1,
                        bytes: 250
                    },
                    1,
                    false
                )
                .expect_err("the session is out of bytes")
                .to_string(),
            "goal budget max_session_bytes exceeded: 250 bytes held plus 1 offered exceeds 250"
        );
    }

    #[test]
    fn the_default_budget_holds_a_full_runtime_goal() {
        let budget = GoalBudget::default();

        // The runtime's default goal config allows a 4 KiB objective and 32 notes of 2 KiB.
        let worst_case_record = 4 * 1024 + 32 * 2 * 1024;
        assert!(budget.max_record_bytes >= worst_case_record);
        assert!(budget.max_session_bytes >= u64::try_from(worst_case_record).expect("fits"));
        assert!(budget.max_goals_per_session > 1);
    }
}

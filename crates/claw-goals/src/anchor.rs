//! The goal statement context compaction may not drop.
//!
//! A context engine's job is to throw conversation away when the budget runs out. The durable
//! goal is the one thing in a session that must survive that: it is what the operator asked for,
//! it is what the model is being steered by, and unlike a message it cannot be re-derived from
//! what is left. Upstream models this by restating the goal to the engine as
//! [`ContextItem::GoalStatement`].
//!
//! [`AnchoredContext`] makes "compaction never drops the goal" a structural property rather than
//! a rule a compaction pass is asked to remember: the anchor is not stored in the item list, so
//! there is no code path that can evict it. Restating the goal replaces the anchor instead of
//! appending another droppable item, so a session that repeats its goal does not accumulate
//! copies that compaction then has to reason about.

use claw_application::model::goal::{GoalRecord, GoalStatus};
use claw_application::model::ids::GoalId;
use claw_application::ports::context::ContextItem;

/// The durable goal, in the form a context engine consumes.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GoalAnchor {
    goal_id: GoalId,
    objective: String,
    revision: u64,
}

impl GoalAnchor {
    /// Derives the anchor from a goal record, or `None` when the goal no longer steers anything.
    ///
    /// A closed goal is deliberately not an anchor: continuing to prepend "your goal is X" after
    /// the operator abandoned X is how a model ends up working on a goal nobody holds.
    #[must_use]
    pub fn from_record(record: &GoalRecord) -> Option<Self> {
        (record.status == GoalStatus::Active).then(|| Self {
            goal_id: record.goal_id.clone(),
            objective: record.objective.clone(),
            revision: record.revision,
        })
    }

    /// Returns the goal this anchor stands for.
    #[must_use]
    pub const fn goal_id(&self) -> &GoalId {
        &self.goal_id
    }

    /// Returns the revision the anchor was derived from.
    ///
    /// A restart rebuilds the anchor from disk, so comparing revisions is how a test — or a
    /// surface — proves the anchor came from the persisted goal rather than from a stale copy.
    #[must_use]
    pub const fn revision(&self) -> u64 {
        self.revision
    }

    /// Returns the objective text.
    #[must_use]
    pub fn objective(&self) -> &str {
        &self.objective
    }

    /// Returns the context item a context engine ingests.
    #[must_use]
    pub fn statement(&self) -> ContextItem {
        ContextItem::GoalStatement {
            objective: self.objective.clone(),
        }
    }
}

/// What one compaction pass did.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct CompactionOutcome {
    /// The number of ordinary items compaction discarded.
    pub removed_items: usize,
    /// The number of items left, excluding the anchor.
    pub retained_items: usize,
    /// Whether a goal statement survived the pass.
    ///
    /// This is `false` only when the context had no goal to begin with.
    pub anchor_retained: bool,
}

/// A context whose goal statement cannot be compacted away.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct AnchoredContext {
    anchor: Option<GoalAnchor>,
    items: Vec<ContextItem>,
}

impl AnchoredContext {
    /// Opens a context around an optional goal.
    #[must_use]
    pub const fn new(anchor: Option<GoalAnchor>) -> Self {
        Self {
            anchor,
            items: Vec::new(),
        }
    }

    /// Replaces the anchor, which is what a restart or a new goal does.
    pub fn set_anchor(&mut self, anchor: Option<GoalAnchor>) {
        self.anchor = anchor;
    }

    /// Returns the current anchor.
    #[must_use]
    pub const fn anchor(&self) -> Option<&GoalAnchor> {
        self.anchor.as_ref()
    }

    /// Offers one item to the context.
    ///
    /// A [`ContextItem::GoalStatement`] updates the anchor's objective rather than joining the
    /// droppable items, while [`ContextItem::GoalCleared`] removes the anchor.
    pub fn ingest(&mut self, item: ContextItem) {
        match item {
            ContextItem::GoalStatement { objective } => {
                if let Some(anchor) = self.anchor.as_mut() {
                    anchor.objective = objective;
                }
            }
            ContextItem::GoalCleared => self.anchor = None,
            other => self.items.push(other),
        }
    }

    /// Returns the number of droppable items held.
    #[must_use]
    pub const fn item_count(&self) -> usize {
        self.items.len()
    }

    /// Returns the prompt the context would produce, goal statement first.
    #[must_use]
    pub fn assemble(&self) -> Vec<ContextItem> {
        let mut assembled = Vec::with_capacity(self.items.len() + 1);
        if let Some(anchor) = &self.anchor {
            assembled.push(anchor.statement());
        }
        assembled.extend(self.items.iter().cloned());
        assembled
    }

    /// Discards all but the newest `keep_recent` ordinary items.
    ///
    /// The anchor is untouched whatever `keep_recent` is, including zero: there is no argument
    /// that compacts the goal away.
    pub fn compact(&mut self, keep_recent: usize) -> CompactionOutcome {
        let removed = self.items.len().saturating_sub(keep_recent);
        if removed > 0 {
            self.items.drain(..removed);
        }
        CompactionOutcome {
            removed_items: removed,
            retained_items: self.items.len(),
            anchor_retained: self.anchor.is_some(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{AnchoredContext, GoalAnchor};
    use crate::testing::record;
    use claw_application::model::goal::GoalStatus;
    use claw_application::model::time::Timestamp;
    use claw_application::ports::context::ContextItem;

    fn anchor() -> GoalAnchor {
        GoalAnchor::from_record(&record("s", "s:goal-1", "ship the adapter", 4))
            .expect("an active goal anchors")
    }

    fn note(text: &str) -> ContextItem {
        ContextItem::AssistantMessage {
            text: text.to_owned(),
        }
    }

    #[test]
    fn only_an_active_goal_anchors_a_context() {
        let mut closed = record("s", "s:goal-1", "ship the adapter", 4);
        closed.status = GoalStatus::Abandoned;
        closed.closed_at = Some(Timestamp::from_millis(9));

        assert!(GoalAnchor::from_record(&closed).is_none());
        assert_eq!(anchor().objective(), "ship the adapter");
        assert_eq!(anchor().revision(), 4);
    }

    #[test]
    fn compaction_discards_conversation_and_keeps_the_goal() {
        let mut context = AnchoredContext::new(Some(anchor()));
        for index in 0..10 {
            context.ingest(note(&format!("message {index}")));
        }

        let outcome = context.compact(2);

        assert_eq!(outcome.removed_items, 8);
        assert_eq!(outcome.retained_items, 2);
        assert!(outcome.anchor_retained);
        assert_eq!(
            context.assemble(),
            vec![
                ContextItem::GoalStatement {
                    objective: "ship the adapter".to_owned(),
                },
                note("message 8"),
                note("message 9"),
            ]
        );
    }

    #[test]
    fn compacting_to_nothing_still_leaves_the_goal() {
        let mut context = AnchoredContext::new(Some(anchor()));
        context.ingest(note("only message"));

        let outcome = context.compact(0);

        assert_eq!(outcome.removed_items, 1);
        assert_eq!(outcome.retained_items, 0);
        assert!(outcome.anchor_retained);
        assert_eq!(
            context.assemble(),
            vec![ContextItem::GoalStatement {
                objective: "ship the adapter".to_owned(),
            }]
        );
    }

    #[test]
    fn restating_the_goal_updates_the_anchor_instead_of_adding_a_droppable_copy() {
        let mut context = AnchoredContext::new(Some(anchor()));
        context.ingest(note("chatter"));
        context.ingest(ContextItem::GoalStatement {
            objective: "ship the adapter, with tests".to_owned(),
        });

        assert_eq!(context.item_count(), 1);
        context.compact(0);
        assert_eq!(
            context.assemble(),
            vec![ContextItem::GoalStatement {
                objective: "ship the adapter, with tests".to_owned(),
            }]
        );
    }

    #[test]
    fn clearing_the_goal_removes_the_anchor_without_adding_a_droppable_item() {
        let mut context = AnchoredContext::new(Some(anchor()));
        context.ingest(note("chatter"));
        context.ingest(ContextItem::GoalCleared);

        assert!(context.anchor().is_none());
        assert_eq!(context.item_count(), 1);
        assert_eq!(context.assemble(), vec![note("chatter")]);
    }

    #[test]
    fn a_context_without_a_goal_compacts_to_nothing_and_says_so() {
        let mut context = AnchoredContext::new(None);
        context.ingest(note("chatter"));

        let outcome = context.compact(0);

        assert!(!outcome.anchor_retained);
        assert!(context.assemble().is_empty());
    }

    #[test]
    fn a_goal_statement_offered_without_an_anchor_is_not_smuggled_in_as_conversation() {
        let mut context = AnchoredContext::new(None);
        context.ingest(ContextItem::GoalStatement {
            objective: "invented by an adapter".to_owned(),
        });

        assert_eq!(context.item_count(), 0);
        assert!(context.assemble().is_empty());
    }
}

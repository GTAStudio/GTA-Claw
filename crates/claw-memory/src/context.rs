//! Token-budget-aware context assembly.
//!
//! Assembly is a pure function of the session, the retrieved items, the
//! budget, and the token counter. Given the same inputs it always produces
//! the same output, which is what makes an agent's behaviour reviewable.

use std::error::Error;
use std::fmt::{self, Display, Formatter};

use serde::Serialize;
use serde_json::{Value, json};

use crate::budget::{
    Admission, BudgetError, TokenBudget, TokenCounter, TruncationPlan, plan_truncation,
};
use crate::retrieval::{MAX_RETRIEVAL_LIMIT, RecordError, RetrievedItem};
use crate::session::{Message, MessageId, Session, Summary};
use crate::vector::RecordId;

/// One message omitted from an assembled context and the reason it was omitted.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
pub struct DroppedMessage {
    /// Stable message identity.
    pub id: MessageId,
    /// Budget rule that excluded the message.
    pub reason: Admission,
}

/// Actionable details about work excluded from an assembled context.
#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize)]
pub struct ContextTruncation {
    /// Messages excluded by conversation-budget planning.
    pub messages: Vec<DroppedMessage>,
    /// Retrieved records examined but excluded by the retrieval allowance.
    pub retrieved: Vec<RecordId>,
    /// Retrieved inputs not examined because the caller supplied more than
    /// [`MAX_RETRIEVAL_LIMIT`].
    pub unexamined_retrieved: usize,
}

/// The assembled model input.
#[derive(Clone, Debug, PartialEq, Serialize)]
pub struct AssembledContext {
    /// Conversation messages in ascending identifier order.
    pub messages: Vec<Message>,
    /// Summaries standing in for compacted history, oldest first.
    pub summaries: Vec<Summary>,
    /// Retrieved memory admitted into the context, best first.
    pub retrieved: Vec<RetrievedItem>,
    /// Total estimated token cost of everything above.
    pub used_tokens: usize,
    /// Tokens still unused inside the input allowance.
    pub remaining_tokens: usize,
    /// Number of messages truncation dropped.
    pub dropped_messages: usize,
    /// Number of retrieved items excluded by the allowance or input ceiling.
    pub dropped_retrieved: usize,
    /// Identities, causes, and input-ceiling state behind the counts above.
    pub truncation: ContextTruncation,
}

impl AssembledContext {
    /// Emits a stable JSON rendering for logs and snapshots.
    //
    // Measured and left alone, with numbers: this is by far the most expensive
    // thing in the crate — 291 us for a 1000-message context against 9.2 us to
    // assemble it — and it did not move (0.99x-1.03x across 10..5000 messages)
    // under any of the assembly work. The cost is inherent to materialising an
    // owned tree: per message one `Map`, four key `String`s, and a clone of the
    // content, because `Value` owns everything it holds. Making it cheaper
    // means serialising straight into a writer instead of returning a `Value`,
    // which is a public API change. It is off the per-turn path today; if a
    // caller ever renders every turn, this is the thing to fix, not `assemble`.
    #[must_use]
    pub fn to_json(&self) -> Value {
        json!({
            "messages": self
                .messages
                .iter()
                .map(|message| json!({
                    "id": message.id.get(),
                    "role": message.role.as_str(),
                    "content": message.content,
                    "pinned": message.pinned,
                }))
                .collect::<Vec<_>>(),
            "summaries": self
                .summaries
                .iter()
                .map(|summary| json!({
                    "first": summary.first.get(),
                    "last": summary.last.get(),
                    "text": summary.text,
                }))
                .collect::<Vec<_>>(),
            "retrieved": self
                .retrieved
                .iter()
                .map(|item| json!({
                    "id": item.record.id.as_str(),
                    "kind": item.record.kind.as_str(),
                    "text": item.record.text,
                }))
                .collect::<Vec<_>>(),
            "used_tokens": self.used_tokens,
            "remaining_tokens": self.remaining_tokens,
            "dropped_messages": self.dropped_messages,
            "dropped_retrieved": self.dropped_retrieved,
            "truncation": {
                "messages": self
                    .truncation
                    .messages
                    .iter()
                    .map(|dropped| json!({
                        "id": dropped.id.get(),
                        "reason": dropped.reason,
                    }))
                    .collect::<Vec<_>>(),
                "retrieved": self
                    .truncation
                    .retrieved
                    .iter()
                    .map(RecordId::as_str)
                    .collect::<Vec<_>>(),
                "unexamined_retrieved": self.truncation.unexamined_retrieved,
            },
        })
    }
}

/// Assembles model input from a session, retrieved memory, and a budget.
///
/// # Order of operations
///
/// 1. A fixed share of the input allowance is set aside for retrieved memory.
///    Retrieved items are admitted best-first while they fit that share; the
///    first item that does not fit ends admission, so the retrieved set is
///    always a prefix of the ranking.
/// 2. Whatever the retrieved set did not consume is returned to the
///    conversation allowance.
/// 3. Conversation truncation then runs under [`plan_truncation`], whose
///    anchor, contiguity and orphan rules decide the message window.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ContextAssembler<C: TokenCounter> {
    budget: TokenBudget,
    counter: C,
    retrieval_share_percent: u8,
}

impl<C: TokenCounter> ContextAssembler<C> {
    /// Creates an assembler, validating the retrieval share.
    ///
    /// # Errors
    ///
    /// Returns [`ContextError::InvalidShare`] when `retrieval_share_percent`
    /// is above one hundred, which would reserve more of the input allowance
    /// for retrieved memory than exists.
    pub fn new(
        budget: TokenBudget,
        counter: C,
        retrieval_share_percent: u8,
    ) -> Result<Self, ContextError> {
        if retrieval_share_percent > 100 {
            return Err(ContextError::InvalidShare);
        }
        Ok(Self {
            budget,
            counter,
            retrieval_share_percent,
        })
    }

    /// Returns the budget in force.
    #[must_use]
    pub const fn budget(&self) -> TokenBudget {
        self.budget
    }

    /// Returns the token counter in force.
    #[must_use]
    pub const fn counter(&self) -> &C {
        &self.counter
    }

    /// Assembles the context.
    ///
    /// # Errors
    ///
    /// Returns [`ContextError::Budget`] carrying
    /// [`BudgetError::AnchorsExceedBudget`] when the system and pinned
    /// messages cannot fit in what the retrieval share left behind — anchors
    /// are never dropped to make the assembly succeed —
    /// [`BudgetError::ReservationTooLarge`] when the admitted retrieved
    /// memory leaves no room for the model's own reply, and
    /// [`BudgetError::InconsistentMessages`] when the truncation plan names a
    /// message the session does not hold, which means the session changed
    /// between planning and assembly.
    pub fn assemble(
        &self,
        session: &Session,
        retrieved: &[RetrievedItem],
    ) -> Result<AssembledContext, ContextError> {
        let available = self.budget.available();
        let retrieval_allowance =
            available.saturating_mul(self.retrieval_share_percent as usize) / 100;

        let mut admitted_retrieved: Vec<RetrievedItem> = Vec::new();
        let mut retrieval_used = 0_usize;
        let unexamined_retrieved = retrieved.len().saturating_sub(MAX_RETRIEVAL_LIMIT);
        let mut dropped_retrieved_ids = Vec::new();
        let mut retrieval_closed = false;
        for item in retrieved.iter().take(MAX_RETRIEVAL_LIMIT) {
            item.record
                .validate()
                .map_err(ContextError::InvalidRecord)?;
            let cost = self
                .counter
                .count_text(&item.record.text)
                .saturating_add(self.counter.framing_overhead());
            if retrieval_closed || retrieval_used.saturating_add(cost) > retrieval_allowance {
                retrieval_closed = true;
                dropped_retrieved_ids.push(item.record.id.clone());
                continue;
            }
            retrieval_used += cost;
            admitted_retrieved.push(item.clone());
        }

        // Unused retrieval allowance is handed back to the conversation, so a
        // small retrieval set never wastes context.
        let conversation_window = self
            .budget
            .context_window()
            .checked_sub(retrieval_used)
            .ok_or(ContextError::Budget(BudgetError::ReservationTooLarge))?;
        let conversation_budget =
            TokenBudget::new(conversation_window, self.budget.reserved_for_output())
                .map_err(ContextError::Budget)?;
        let plan: TruncationPlan = plan_truncation(
            session.messages(),
            session.summaries(),
            conversation_budget,
            &self.counter,
        )
        .map_err(ContextError::Budget)?;

        let admitted = plan.admitted_entries();
        // Both sides are in ascending identifier order — the session by
        // construction, the plan because it sorts before returning — so the two
        // are walked together once. Testing membership against a set instead
        // cost a tree lookup per message and an identifier vector per
        // assembly, on a path that runs every turn over a history that only
        // grows.
        let mut messages: Vec<Message> = Vec::with_capacity(admitted.len());
        let mut wanted = admitted.iter();
        let mut next = wanted.next();
        for message in session.messages() {
            let id = message.id.get();
            while next.is_some_and(|(admitted_id, _)| *admitted_id < id) {
                next = wanted.next();
            }
            if next.is_some_and(|(admitted_id, _)| *admitted_id == id) {
                messages.push(message.clone());
                next = wanted.next();
            }
        }
        if messages.len() != admitted.len() {
            return Err(ContextError::Budget(BudgetError::InconsistentMessages));
        }
        let summary_count = plan.summaries();
        let summaries: Vec<Summary> = session
            .summaries()
            .iter()
            .rev()
            .take(summary_count)
            .rev()
            .cloned()
            .collect();

        let used_tokens = retrieval_used.saturating_add(plan.used_tokens());
        let dropped_messages: Vec<DroppedMessage> = plan
            .dropped()
            .iter()
            .map(|(id, reason)| DroppedMessage {
                id: MessageId::new(*id),
                reason: *reason,
            })
            .collect();
        let dropped_retrieved = dropped_retrieved_ids
            .len()
            .saturating_add(unexamined_retrieved);
        Ok(AssembledContext {
            messages,
            summaries,
            retrieved: admitted_retrieved,
            used_tokens,
            remaining_tokens: available.saturating_sub(used_tokens),
            dropped_messages: dropped_messages.len(),
            dropped_retrieved,
            truncation: ContextTruncation {
                messages: dropped_messages,
                retrieved: dropped_retrieved_ids,
                unexamined_retrieved,
            },
        })
    }
}

/// A failed context assembly.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ContextError {
    /// The retrieval share exceeded one hundred percent.
    InvalidShare,
    /// One retrieved record violated the crate's processing bounds.
    InvalidRecord(RecordError),
    /// Budget planning refused the assembly.
    Budget(BudgetError),
}

impl Display for ContextError {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidShare => {
                formatter.write_str("retrieval share must not exceed 100 percent")
            }
            Self::InvalidRecord(error) => write!(formatter, "invalid retrieved record: {error}"),
            Self::Budget(error) => write!(formatter, "budget refused the assembly: {error}"),
        }
    }
}

impl Error for ContextError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::InvalidRecord(error) => Some(error),
            Self::Budget(error) => Some(error),
            Self::InvalidShare => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::budget::HeuristicTokenCounter;
    use crate::retrieval::{
        MAX_RECORD_BYTES, MAX_RETRIEVAL_LIMIT, MemoryRecord, RecordError, RecordKind,
    };
    use crate::session::{MessageId, Role, SessionId};
    use crate::vector::RecordId;
    use std::collections::BTreeSet;

    fn counter() -> HeuristicTokenCounter {
        HeuristicTokenCounter::new(4, 0).expect("valid density")
    }

    fn session_with(messages: &[(Role, &str)]) -> Session {
        let mut session = Session::new(SessionId::new("s").expect("valid identifier"));
        for (index, (role, content)) in messages.iter().enumerate() {
            session
                .append(*role, *content, index as u64)
                .expect("appended");
        }
        session
    }

    fn item(id: &str, text: &str, score: f32) -> RetrievedItem {
        RetrievedItem {
            record: MemoryRecord {
                id: RecordId::new(id).expect("valid record identifier"),
                session: SessionId::new("s").expect("valid identifier"),
                kind: RecordKind::Note,
                text: text.to_owned(),
                unix_millis: 1,
                tags: BTreeSet::new(),
            },
            score,
        }
    }

    #[test]
    fn an_invalid_retrieval_share_is_refused() {
        let budget = TokenBudget::new(100, 10).expect("valid budget");
        assert_eq!(
            ContextAssembler::new(budget, counter(), 101).err(),
            Some(ContextError::InvalidShare)
        );
    }

    #[test]
    fn everything_fits_when_the_budget_is_generous() {
        let session = session_with(&[
            (Role::System, "be careful"),
            (Role::User, "hello there"),
            (Role::Assistant, "hi"),
        ]);
        let budget = TokenBudget::new(1000, 100).expect("valid budget");
        let assembler = ContextAssembler::new(budget, counter(), 20).expect("valid assembler");
        let context = assembler
            .assemble(&session, &[item("n1", "a durable note", 0.9)])
            .expect("assembled");

        assert_eq!(
            context
                .messages
                .iter()
                .map(|message| message.id.get())
                .collect::<Vec<_>>(),
            vec![0, 1, 2]
        );
        assert_eq!(context.retrieved.len(), 1);
        assert_eq!(context.dropped_messages, 0);
        assert_eq!(context.dropped_retrieved, 0);
        assert_eq!(
            context.used_tokens + context.remaining_tokens,
            budget.available()
        );
    }

    #[test]
    fn retrieved_memory_is_capped_by_its_own_share() {
        let session = session_with(&[(Role::User, "hi")]);
        // Available is 100; a 10 percent share leaves 10 tokens for memory.
        let budget = TokenBudget::new(100, 0).expect("valid budget");
        let assembler = ContextAssembler::new(budget, counter(), 10).expect("valid assembler");
        let context = assembler
            .assemble(
                &session,
                &[
                    item("a", &"x".repeat(32), 0.9),
                    item("b", &"y".repeat(32), 0.8),
                    item("c", &"z".repeat(32), 0.7),
                ],
            )
            .expect("assembled");

        assert_eq!(
            context
                .retrieved
                .iter()
                .map(|hit| hit.record.id.as_str())
                .collect::<Vec<_>>(),
            vec!["a"],
            "admission stops at the first item that does not fit"
        );
        assert_eq!(context.dropped_retrieved, 2);
        assert_eq!(
            context
                .truncation
                .retrieved
                .iter()
                .map(RecordId::as_str)
                .collect::<Vec<_>>(),
            vec!["b", "c"]
        );
        assert_eq!(context.truncation.unexamined_retrieved, 0);
    }

    #[test]
    fn assembly_never_examines_more_than_the_retrieval_ceiling() {
        let session = session_with(&[(Role::User, "hi")]);
        let retrieved: Vec<RetrievedItem> = (0..MAX_RETRIEVAL_LIMIT + 5)
            .map(|index| item(&format!("r{index:03}"), "x", 1.0))
            .collect();
        let budget = TokenBudget::new(10_000, 0).expect("valid budget");
        let assembler = ContextAssembler::new(budget, counter(), 100).expect("valid assembler");
        let context = assembler.assemble(&session, &retrieved).expect("assembled");

        assert_eq!(context.retrieved.len(), MAX_RETRIEVAL_LIMIT);
        assert_eq!(context.dropped_retrieved, 5);
        assert!(context.truncation.retrieved.is_empty());
        assert_eq!(context.truncation.unexamined_retrieved, 5);
    }

    #[test]
    fn invalid_retrieved_records_are_refused_before_token_counting() {
        let session = Session::new(SessionId::new("s").expect("valid identifier"));
        let oversized = item("oversized", &"x".repeat(MAX_RECORD_BYTES + 1), 1.0);
        let budget = TokenBudget::new(10_000, 0).expect("valid budget");
        let assembler = ContextAssembler::new(budget, counter(), 100).expect("valid assembler");

        assert_eq!(
            assembler.assemble(&session, &[oversized]),
            Err(ContextError::InvalidRecord(RecordError::TextTooLong))
        );
    }

    #[test]
    fn an_oversized_retrieval_share_starves_anchors_and_fails_loudly() {
        // The system anchor costs 22 tokens; the 90 percent retrieval share
        // consumes 20, leaving the conversation 15. Rather than silently
        // dropping operator instructions, assembly fails.
        let session = session_with(&[(Role::System, &"s".repeat(80)), (Role::User, "hello")]);
        let budget = TokenBudget::new(40, 5).expect("valid budget");
        let assembler = ContextAssembler::new(budget, counter(), 90).expect("valid assembler");
        let error = assembler
            .assemble(&session, &[item("a", &"x".repeat(80), 0.9)])
            .expect_err("anchors cannot fit");
        assert_eq!(
            error,
            ContextError::Budget(BudgetError::AnchorsExceedBudget)
        );
    }

    #[test]
    fn assembly_is_reproducible_for_identical_inputs() {
        let mut session = session_with(&[(Role::System, "rules")]);
        for index in 0..30_u64 {
            session
                .append(Role::User, format!("turn {index} with padding"), index)
                .expect("appended");
        }
        let budget = TokenBudget::new(160, 40).expect("valid budget");
        let assembler = ContextAssembler::new(budget, counter(), 25).expect("valid assembler");
        let memory = [
            item("m1", "first note", 0.9),
            item("m2", "second note", 0.5),
        ];

        let first = assembler.assemble(&session, &memory).expect("assembled");
        let second = assembler.assemble(&session, &memory).expect("assembled");
        assert_eq!(first, second);
        assert_eq!(first.to_json(), second.to_json());
        assert!(
            first.used_tokens <= budget.available(),
            "used {} of {}",
            first.used_tokens,
            budget.available()
        );
        assert!(
            first.messages.iter().any(|message| message.id.get() == 0),
            "the system anchor must always be present"
        );
        assert!(first.dropped_messages > 0, "this budget must truncate");
        assert_eq!(first.truncation.messages.len(), first.dropped_messages);
        assert!(
            first
                .truncation
                .messages
                .iter()
                .all(|dropped| !matches!(dropped.reason, Admission::Anchor))
        );
    }

    #[test]
    fn summaries_are_emitted_oldest_first_and_only_when_admitted() {
        let mut session = session_with(&[
            (Role::User, "one"),
            (Role::Assistant, "two"),
            (Role::User, "three"),
        ]);
        session
            .absorb(Summary {
                first: MessageId::new(0),
                last: MessageId::new(1),
                text: "older exchange".to_owned(),
                unix_millis: 5,
            })
            .expect("absorbed");
        let budget = TokenBudget::new(500, 50).expect("valid budget");
        let assembler = ContextAssembler::new(budget, counter(), 0).expect("valid assembler");
        let context = assembler.assemble(&session, &[]).expect("assembled");
        assert_eq!(context.summaries.len(), 1);
        assert_eq!(context.summaries[0].text, "older exchange");
        assert_eq!(
            context
                .messages
                .iter()
                .map(|message| message.id.get())
                .collect::<Vec<_>>(),
            vec![2]
        );
        assert!(context.retrieved.is_empty());
    }
}

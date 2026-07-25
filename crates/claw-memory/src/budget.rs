//! Token accounting and the deterministic truncation rules.

use std::error::Error;
use std::fmt::{self, Display, Formatter};

use serde::Serialize;

use crate::session::{Message, Role, Summary};

/// Estimates the token cost of text.
///
/// Implementations must be pure: the same text must always cost the same, or
/// context assembly stops being reproducible.
pub trait TokenCounter {
    /// Returns the token cost of a text fragment.
    fn count_text(&self, text: &str) -> usize;

    /// Returns the token cost of one message, including framing overhead.
    fn count_message(&self, message: &Message) -> usize {
        self.count_text(&message.content)
            .saturating_add(self.count_text(message.role.as_str()))
            .saturating_add(self.framing_overhead())
    }

    /// Returns the token cost of one summary, including framing overhead.
    fn count_summary(&self, summary: &Summary) -> usize {
        self.count_text(&summary.text)
            .saturating_add(self.framing_overhead())
    }

    /// Returns the fixed per-entry framing cost of the target encoding.
    fn framing_overhead(&self) -> usize {
        4
    }
}

/// A deterministic character-density token estimate.
///
/// This is intentionally a heuristic and never a substitute for a provider
/// tokenizer. It is monotone in input length, which is the property the
/// truncation rules rely on, and it never under-counts to zero.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct HeuristicTokenCounter {
    characters_per_token: usize,
    framing_overhead: usize,
}

impl Default for HeuristicTokenCounter {
    fn default() -> Self {
        Self {
            characters_per_token: 4,
            framing_overhead: 4,
        }
    }
}

impl HeuristicTokenCounter {
    /// Creates a counter with an explicit character density.
    pub fn new(characters_per_token: usize, framing_overhead: usize) -> Result<Self, BudgetError> {
        if characters_per_token == 0 {
            return Err(BudgetError::InvalidDensity);
        }
        Ok(Self {
            characters_per_token,
            framing_overhead,
        })
    }
}

impl TokenCounter for HeuristicTokenCounter {
    fn count_text(&self, text: &str) -> usize {
        if text.is_empty() {
            return 0;
        }
        text.chars().count().div_ceil(self.characters_per_token)
    }

    fn framing_overhead(&self) -> usize {
        self.framing_overhead
    }
}

/// The token allowance for one model call.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
pub struct TokenBudget {
    context_window: usize,
    reserved_for_output: usize,
}

impl TokenBudget {
    /// Creates a budget, refusing one that leaves no room for input.
    pub fn new(context_window: usize, reserved_for_output: usize) -> Result<Self, BudgetError> {
        if context_window == 0 {
            return Err(BudgetError::EmptyWindow);
        }
        if reserved_for_output >= context_window {
            return Err(BudgetError::ReservationTooLarge);
        }
        Ok(Self {
            context_window,
            reserved_for_output,
        })
    }

    /// Returns the full context window.
    #[must_use]
    pub const fn context_window(self) -> usize {
        self.context_window
    }

    /// Returns the tokens reserved for the model's reply.
    #[must_use]
    pub const fn reserved_for_output(self) -> usize {
        self.reserved_for_output
    }

    /// Returns the tokens available for assembled input.
    #[must_use]
    pub const fn available(self) -> usize {
        self.context_window - self.reserved_for_output
    }
}

/// Why a message was or was not admitted into the assembled context.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Admission {
    /// Retained because it anchors the conversation.
    Anchor,
    /// Retained because it fits in the remaining budget.
    Recent,
    /// Dropped because admitting it would exceed the budget.
    OverBudget,
    /// Dropped because an older message in the window was already dropped.
    ///
    /// The retained window is always a contiguous suffix, so a message is
    /// never resurrected from behind a dropped one.
    BehindTruncation,
    /// Dropped because it is a tool result whose request was truncated away.
    OrphanedToolResult,
}

/// The deterministic truncation decision for one session.
///
/// # Rules
///
/// 1. Anchors (system messages and pinned messages) are admitted first, in
///    ascending identifier order. If they alone exceed the budget the whole
///    assembly fails rather than silently dropping instructions.
/// 2. Summaries are admitted next, newest first.
/// 3. Remaining messages are considered newest first and admitted while they
///    fit. The first message that does not fit ends the window; everything
///    older than it is dropped, so the retained window is a contiguous suffix.
/// 4. A leading [`Role::Tool`] message in that window is dropped, repeatedly,
///    because a tool result without its request is misleading input.
/// 5. The result is emitted in ascending identifier order.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TruncationPlan {
    admitted: Vec<(u64, Admission)>,
    dropped: Vec<(u64, Admission)>,
    summaries: usize,
    used_tokens: usize,
}

impl TruncationPlan {
    /// Returns the admitted message identifiers in ascending order.
    #[must_use]
    pub fn admitted(&self) -> Vec<u64> {
        self.admitted.iter().map(|(id, _)| *id).collect()
    }

    /// Returns the dropped message identifiers in ascending order, with cause.
    #[must_use]
    pub fn dropped(&self) -> &[(u64, Admission)] {
        &self.dropped
    }

    /// Returns the number of admitted summaries.
    #[must_use]
    pub const fn summaries(&self) -> usize {
        self.summaries
    }

    /// Returns the token cost of the admitted content.
    #[must_use]
    pub const fn used_tokens(&self) -> usize {
        self.used_tokens
    }
}

/// Applies the truncation rules to one message set.
pub fn plan_truncation<C: TokenCounter + ?Sized>(
    messages: &[Message],
    summaries: &[Summary],
    budget: TokenBudget,
    counter: &C,
) -> Result<TruncationPlan, BudgetError> {
    let available = budget.available();
    let mut used = 0_usize;
    let mut admitted: Vec<(u64, Admission)> = Vec::new();

    for message in messages.iter().filter(|message| message.is_anchor()) {
        used = used.saturating_add(counter.count_message(message));
        admitted.push((message.id.get(), Admission::Anchor));
    }
    if used > available {
        return Err(BudgetError::AnchorsExceedBudget);
    }

    let mut admitted_summaries = 0_usize;
    for summary in summaries.iter().rev() {
        let cost = counter.count_summary(summary);
        if used.saturating_add(cost) > available {
            break;
        }
        used += cost;
        admitted_summaries += 1;
    }

    let mut dropped: Vec<(u64, Admission)> = Vec::new();
    let mut window: Vec<(u64, Admission)> = Vec::new();
    let mut truncated = false;
    for message in messages.iter().rev().filter(|message| !message.is_anchor()) {
        if truncated {
            dropped.push((message.id.get(), Admission::BehindTruncation));
            continue;
        }
        let cost = counter.count_message(message);
        if used.saturating_add(cost) > available {
            truncated = true;
            dropped.push((message.id.get(), Admission::OverBudget));
            continue;
        }
        used += cost;
        window.push((message.id.get(), Admission::Recent));
    }
    window.reverse();

    // Rule 4: a window that opens on a tool result is missing the request it
    // answers, so the orphan is dropped until the window opens cleanly.
    while let Some((id, _)) = window.first().copied() {
        let message = messages
            .iter()
            .find(|message| message.id.get() == id)
            .ok_or(BudgetError::InconsistentMessages)?;
        if message.role != Role::Tool {
            break;
        }
        used = used.saturating_sub(counter.count_message(message));
        dropped.push((id, Admission::OrphanedToolResult));
        window.remove(0);
    }

    admitted.extend(window);
    admitted.sort_unstable_by_key(|(id, _)| *id);
    dropped.sort_unstable_by_key(|(id, _)| *id);
    Ok(TruncationPlan {
        admitted,
        dropped,
        summaries: admitted_summaries,
        used_tokens: used,
    })
}

/// A rejected budget configuration or an impossible assembly.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum BudgetError {
    /// The context window was zero.
    EmptyWindow,
    /// The output reservation left no room for input.
    ReservationTooLarge,
    /// The character density was zero.
    InvalidDensity,
    /// Anchors alone exceed the available budget.
    AnchorsExceedBudget,
    /// The message set changed underneath the planner.
    InconsistentMessages,
}

impl Display for BudgetError {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        let message = match self {
            Self::EmptyWindow => "context window must be greater than zero",
            Self::ReservationTooLarge => "output reservation leaves no room for input",
            Self::InvalidDensity => "characters per token must be greater than zero",
            Self::AnchorsExceedBudget => "anchor messages alone exceed the available budget",
            Self::InconsistentMessages => "message set changed during planning",
        };
        formatter.write_str(message)
    }
}

impl Error for BudgetError {}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::session::{MessageId, Session, SessionId};

    fn counter() -> HeuristicTokenCounter {
        HeuristicTokenCounter::new(4, 0).expect("valid density")
    }

    fn message(id: u64, role: Role, content: &str, pinned: bool) -> Message {
        Message {
            id: MessageId::new(id),
            role,
            content: content.to_owned(),
            unix_millis: id,
            pinned,
        }
    }

    #[test]
    fn budget_rejects_impossible_configurations() {
        assert_eq!(TokenBudget::new(0, 0), Err(BudgetError::EmptyWindow));
        assert_eq!(
            TokenBudget::new(100, 100),
            Err(BudgetError::ReservationTooLarge)
        );
        assert_eq!(
            TokenBudget::new(100, 101),
            Err(BudgetError::ReservationTooLarge)
        );
        let budget = TokenBudget::new(100, 40).expect("valid budget");
        assert_eq!(budget.available(), 60);
        assert_eq!(budget.context_window(), 100);
        assert_eq!(budget.reserved_for_output(), 40);
    }

    #[test]
    fn heuristic_counter_is_monotone_and_never_zero_for_nonempty_text() {
        let counter = counter();
        assert_eq!(counter.count_text(""), 0);
        assert_eq!(counter.count_text("a"), 1);
        assert_eq!(counter.count_text("abcd"), 1);
        assert_eq!(counter.count_text("abcde"), 2);
        assert_eq!(counter.count_text(&"x".repeat(400)), 100);
        assert_eq!(
            HeuristicTokenCounter::new(0, 0),
            Err(BudgetError::InvalidDensity)
        );
    }

    #[test]
    fn anchors_survive_and_the_window_is_a_contiguous_suffix() {
        let messages = vec![
            message(0, Role::System, &"s".repeat(8), false),
            message(1, Role::User, &"a".repeat(40), false),
            message(2, Role::Assistant, &"b".repeat(40), false),
            message(3, Role::User, &"c".repeat(40), false),
            message(4, Role::Assistant, &"d".repeat(40), false),
        ];
        // System costs 2 + role("system")=2 = 4; each other message costs
        // 10 + role tokens. Budget admits the system anchor and the two most
        // recent messages only.
        let budget = TokenBudget::new(40, 10).expect("valid budget");
        let plan = plan_truncation(&messages, &[], budget, &counter()).expect("plan");
        assert_eq!(plan.admitted(), vec![0, 3, 4]);
        assert_eq!(
            plan.dropped(),
            &[(1, Admission::BehindTruncation), (2, Admission::OverBudget),]
        );
        assert_eq!(plan.summaries(), 0);
        assert_eq!(plan.used_tokens(), 28);
    }

    #[test]
    fn pinned_messages_are_kept_however_old() {
        let messages = vec![
            message(0, Role::User, &"a".repeat(40), true),
            message(1, Role::Assistant, &"b".repeat(40), false),
            message(2, Role::User, &"c".repeat(40), false),
        ];
        let budget = TokenBudget::new(40, 15).expect("valid budget");
        let plan = plan_truncation(&messages, &[], budget, &counter()).expect("plan");
        assert_eq!(plan.admitted(), vec![0, 2]);
        assert_eq!(plan.dropped(), &[(1, Admission::OverBudget)]);
    }

    #[test]
    fn anchors_that_cannot_fit_fail_loudly_instead_of_being_dropped() {
        let messages = vec![message(0, Role::System, &"s".repeat(400), false)];
        let budget = TokenBudget::new(50, 10).expect("valid budget");
        assert_eq!(
            plan_truncation(&messages, &[], budget, &counter()),
            Err(BudgetError::AnchorsExceedBudget)
        );
    }

    #[test]
    fn an_orphaned_tool_result_is_dropped_from_the_head_of_the_window() {
        let messages = vec![
            message(0, Role::User, &"a".repeat(40), false),
            message(1, Role::Assistant, &"b".repeat(40), false),
            message(2, Role::Tool, &"c".repeat(40), false),
            message(3, Role::Assistant, &"d".repeat(40), false),
        ];
        // Room for exactly two of the four messages; the window would open on
        // the tool result, which is therefore dropped as an orphan.
        let budget = TokenBudget::new(40, 15).expect("valid budget");
        let plan = plan_truncation(&messages, &[], budget, &counter()).expect("plan");
        assert_eq!(plan.admitted(), vec![3]);
        assert_eq!(
            plan.dropped(),
            &[
                (0, Admission::BehindTruncation),
                (1, Admission::OverBudget),
                (2, Admission::OrphanedToolResult),
            ]
        );
    }

    #[test]
    fn summaries_are_admitted_newest_first_within_the_budget() {
        let messages = vec![message(9, Role::User, &"a".repeat(20), false)];
        let summaries = vec![
            Summary {
                first: MessageId::new(0),
                last: MessageId::new(3),
                text: "p".repeat(40),
                unix_millis: 1,
            },
            Summary {
                first: MessageId::new(4),
                last: MessageId::new(8),
                text: "q".repeat(40),
                unix_millis: 2,
            },
        ];
        let budget = TokenBudget::new(40, 22).expect("valid budget");
        let plan = plan_truncation(&messages, &summaries, budget, &counter()).expect("plan");
        assert_eq!(plan.summaries(), 1);
        assert_eq!(plan.admitted(), vec![9]);
        assert_eq!(plan.used_tokens(), 16);
    }

    #[test]
    fn planning_the_same_session_twice_gives_the_same_answer() {
        let mut session = Session::new(SessionId::new("s").expect("valid identifier"));
        session.append(Role::System, "be careful", 1).expect("ok");
        for index in 0..40_u64 {
            session
                .append(Role::User, format!("message number {index}"), index)
                .expect("ok");
        }
        let budget = TokenBudget::new(200, 50).expect("valid budget");
        let first = plan_truncation(session.messages(), &[], budget, &counter()).expect("plan");
        let second = plan_truncation(session.messages(), &[], budget, &counter()).expect("plan");
        assert_eq!(first, second);
        assert!(first.admitted().contains(&0), "the anchor must survive");
        assert!(
            first.used_tokens() <= budget.available(),
            "plan used {} of {} tokens",
            first.used_tokens(),
            budget.available()
        );
    }
}

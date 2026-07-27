//! Summarization hooks: when to compact, what to compact, and the port that
//! produces the replacement text.
//!
//! The decision of *what* to summarize is made here and is deterministic. The
//! decision of *how* to phrase the summary belongs to a [`Summarizer`], which
//! is a port so a model-backed implementation can be supplied by the host.

use std::error::Error;
use std::fmt::{self, Display, Formatter};

use crate::budget::{TokenBudget, TokenCounter};
use crate::session::{Message, MessageId, Session, SessionError, SessionId, Summary};

/// What a summarizer is asked to compress.
#[derive(Clone, Copy, Debug)]
pub struct SummaryRequest<'a> {
    /// Session the messages belong to.
    pub session: &'a SessionId,
    /// Contiguous run of messages being replaced, oldest first.
    pub messages: &'a [Message],
    /// Token budget the summary text must fit inside.
    pub max_tokens: usize,
}

/// Produces replacement text for a run of messages.
pub trait Summarizer {
    /// Returns summary text for the request.
    ///
    /// # Errors
    ///
    /// Returns [`SummaryError::NothingToSummarize`] when the request carries
    /// no messages, [`SummaryError::EmptySummary`] when the implementation
    /// cannot produce usable text within `max_tokens`, and
    /// [`SummaryError::Backend`] when a host summarizer — a model call, for
    /// instance — fails or is unavailable.
    fn summarize(&mut self, request: &SummaryRequest<'_>) -> Result<String, SummaryError>;
}

/// When compaction should happen and how much recent history to preserve.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SummarizationPolicy {
    trigger_percent: u8,
    keep_recent: usize,
    summary_token_share_percent: u8,
}

impl Default for SummarizationPolicy {
    fn default() -> Self {
        Self {
            trigger_percent: 80,
            keep_recent: 8,
            summary_token_share_percent: 10,
        }
    }
}

impl SummarizationPolicy {
    /// Creates a policy, validating the percentages.
    ///
    /// # Errors
    ///
    /// Returns [`SummaryError::InvalidPolicy`] when `trigger_percent` or
    /// `summary_token_share_percent` is zero or above one hundred: a zero
    /// trigger would compact on every turn and a zero share would leave the
    /// summarizer no room to say anything.
    pub const fn new(
        trigger_percent: u8,
        keep_recent: usize,
        summary_token_share_percent: u8,
    ) -> Result<Self, SummaryError> {
        if trigger_percent == 0 || trigger_percent > 100 {
            return Err(SummaryError::InvalidPolicy);
        }
        if summary_token_share_percent == 0 || summary_token_share_percent > 100 {
            return Err(SummaryError::InvalidPolicy);
        }
        Ok(Self {
            trigger_percent,
            keep_recent,
            summary_token_share_percent,
        })
    }

    /// Returns the occupancy percentage that triggers compaction.
    #[must_use]
    pub const fn trigger_percent(self) -> u8 {
        self.trigger_percent
    }

    /// Returns how many recent non-anchor messages are always preserved.
    #[must_use]
    pub const fn keep_recent(self) -> usize {
        self.keep_recent
    }

    /// Returns the token budget a summary may occupy.
    #[must_use]
    pub const fn summary_tokens(self, budget: TokenBudget) -> usize {
        budget
            .available()
            .saturating_mul(self.summary_token_share_percent as usize)
            / 100
    }
}

/// The contiguous run of messages compaction would replace.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SummarizationPlan {
    /// First message identifier to replace, inclusive.
    pub first: MessageId,
    /// Last message identifier to replace, inclusive.
    pub last: MessageId,
    /// Number of messages in the run.
    pub message_count: usize,
    /// Token budget the summary text must fit inside.
    pub max_tokens: usize,
}

/// Decides whether compaction is due and what it would cover.
///
/// Anchors are never part of a plan: system and pinned messages survive
/// compaction verbatim.
#[must_use]
pub fn plan_summarization<C: TokenCounter + ?Sized>(
    session: &Session,
    budget: TokenBudget,
    counter: &C,
    policy: SummarizationPolicy,
) -> Option<SummarizationPlan> {
    let used: usize = session
        .messages()
        .iter()
        .map(|message| counter.count_message(message))
        .sum();
    let threshold = budget
        .available()
        .saturating_mul(policy.trigger_percent() as usize)
        / 100;
    if used <= threshold {
        return None;
    }
    let compactable: Vec<&Message> = session
        .messages()
        .iter()
        .filter(|message| !message.is_anchor())
        .collect();
    if compactable.len() <= policy.keep_recent() {
        return None;
    }
    let cut = compactable.len() - policy.keep_recent();
    let run = &compactable[..cut];
    let first = run.first()?.id;
    let last = run.last()?.id;
    Some(SummarizationPlan {
        first,
        last,
        message_count: run.len(),
        max_tokens: policy.summary_tokens(budget).max(1),
    })
}

/// Runs one compaction cycle against a session.
///
/// Returns the summary that was absorbed, or `None` when compaction was not
/// due. On any summarizer failure the session is left untouched.
///
/// # Errors
///
/// Propagates whatever the [`Summarizer`] reports — [`SummaryError::Backend`]
/// for a failed host summarizer, for instance — and returns
/// [`SummaryError::EmptySummary`] when it produces only whitespace, since a
/// blank summary would erase the run it replaces. Returns
/// [`SummaryError::Session`] when the session refuses the result: the summary
/// text is over [`crate::session::MAX_MESSAGE_BYTES`]
/// ([`SessionError::MessageTooLong`]), or the session already holds
/// [`crate::session::MAX_SUMMARIES`] summaries
/// ([`SessionError::TooManySummaries`]) and cannot be compacted again.
pub fn compact<C: TokenCounter + ?Sized, S: Summarizer>(
    session: &mut Session,
    budget: TokenBudget,
    counter: &C,
    policy: SummarizationPolicy,
    summarizer: &mut S,
    unix_millis: u64,
) -> Result<Option<Summary>, SummaryError> {
    let Some(plan) = plan_summarization(session, budget, counter, policy) else {
        return Ok(None);
    };
    let Some(text) = summarize_run(session, plan, summarizer)? else {
        return Ok(None);
    };
    if text.trim().is_empty() {
        return Err(SummaryError::EmptySummary);
    }
    let summary = Summary {
        first: plan.first,
        last: plan.last,
        text,
        unix_millis,
    };
    session
        .absorb(summary.clone())
        .map_err(SummaryError::Session)?;
    Ok(Some(summary))
}

/// Hands the planned run to the summarizer, or `None` when the plan covers
/// nothing.
///
/// The session borrow is confined to this call so the caller can mutate the
/// session as soon as the replacement text exists.
fn summarize_run<S: Summarizer>(
    session: &Session,
    plan: SummarizationPlan,
    summarizer: &mut S,
) -> Result<Option<String>, SummaryError> {
    let messages = session.messages();
    // The ordinary run is contiguous and is borrowed straight out of the
    // session, so compaction does not clone the history it is about to
    // replace for a summarizer that may refuse it. Only a run split by an
    // anchor has to be gathered into a new allocation.
    let borrowed = contiguous_run(messages, plan);
    let gathered: Vec<Message> = if borrowed.is_none() {
        messages
            .iter()
            .filter(|message| covered(message, plan))
            .cloned()
            .collect()
    } else {
        Vec::new()
    };
    let run: &[Message] = borrowed.unwrap_or(&gathered);
    if run.is_empty() {
        return Ok(None);
    }
    summarizer
        .summarize(&SummaryRequest {
            session: session.id(),
            messages: run,
            max_tokens: plan.max_tokens,
        })
        .map(Some)
}

/// Returns the planned run as a borrowed slice when it is already contiguous.
///
/// It is, unless an anchor sits inside it: anchors survive compaction and so
/// split the run. Borrowing is what keeps compaction from cloning the whole
/// history it is about to replace, for a summarizer that may refuse it.
fn contiguous_run(messages: &[Message], plan: SummarizationPlan) -> Option<&[Message]> {
    let mut first: Option<usize> = None;
    let mut last = 0_usize;
    for (index, message) in messages.iter().enumerate() {
        if !covered(message, plan) {
            continue;
        }
        match first {
            None => {
                first = Some(index);
                last = index;
            }
            Some(_) if last + 1 == index => last = index,
            Some(_) => return None,
        }
    }
    Some(&messages[first?..=last])
}

/// Reports whether compaction would replace this message.
const fn covered(message: &Message, plan: SummarizationPlan) -> bool {
    !message.is_anchor()
        && message.id.get() >= plan.first.get()
        && message.id.get() <= plan.last.get()
}

/// A deterministic extractive summarizer used offline and in tests.
///
/// It selects the leading sentence of each message and truncates on a
/// character boundary. It is not a language model and makes no claim to be
/// one; it exists so the compaction machinery can be exercised with no
/// provider, no network, and reproducible output.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ExtractiveSummarizer {
    characters_per_message: usize,
}

impl Default for ExtractiveSummarizer {
    fn default() -> Self {
        Self {
            characters_per_message: 120,
        }
    }
}

impl ExtractiveSummarizer {
    /// Creates a summarizer with an explicit per-message character bound.
    ///
    /// # Errors
    ///
    /// Returns [`SummaryError::InvalidPolicy`] when `characters_per_message`
    /// is zero, which would make every extracted line empty.
    pub const fn new(characters_per_message: usize) -> Result<Self, SummaryError> {
        if characters_per_message == 0 {
            return Err(SummaryError::InvalidPolicy);
        }
        Ok(Self {
            characters_per_message,
        })
    }
}

impl Summarizer for ExtractiveSummarizer {
    fn summarize(&mut self, request: &SummaryRequest<'_>) -> Result<String, SummaryError> {
        if request.messages.is_empty() {
            return Err(SummaryError::NothingToSummarize);
        }
        let character_budget = request.max_tokens.saturating_mul(4).max(16);
        let mut lines: Vec<String> = Vec::new();
        let mut used = 0_usize;
        for message in request.messages {
            let lead = leading_sentence(&message.content, self.characters_per_message);
            let line = format!("{}: {lead}", message.role.as_str());
            let cost = line.chars().count() + 1;
            if used.saturating_add(cost) > character_budget {
                break;
            }
            used += cost;
            lines.push(line);
        }
        if lines.is_empty() {
            // Always produce something: a compaction that yields nothing would
            // silently erase the run it replaced.
            let first = request.messages.first().ok_or(SummaryError::EmptySummary)?;
            lines.push(format!(
                "{}: {}",
                first.role.as_str(),
                leading_sentence(&first.content, 32)
            ));
        }
        Ok(lines.join("\n"))
    }
}

/// Returns the first sentence, truncated on a character boundary.
fn leading_sentence(text: &str, max_characters: usize) -> String {
    let trimmed = text.trim();
    let end = trimmed
        .char_indices()
        .find(|(_, character)| matches!(character, '.' | '!' | '?' | '\n'))
        .map_or(trimmed.len(), |(index, character)| {
            index + character.len_utf8()
        });
    trimmed[..end]
        .trim()
        .chars()
        .take(max_characters)
        .collect::<String>()
        .trim()
        .to_owned()
}

/// A rejected summarization.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SummaryError {
    /// A policy value was out of range.
    InvalidPolicy,
    /// There were no messages to summarize.
    NothingToSummarize,
    /// The summarizer produced no usable text.
    EmptySummary,
    /// The session refused the resulting summary.
    Session(SessionError),
    /// The host summarizer failed.
    Backend,
}

impl Display for SummaryError {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidPolicy => {
                formatter.write_str("summarization policy value is out of range")
            }
            Self::NothingToSummarize => formatter.write_str("no messages were eligible"),
            Self::EmptySummary => formatter.write_str("summarizer produced no text"),
            Self::Session(error) => write!(formatter, "session refused the summary: {error}"),
            Self::Backend => formatter.write_str("summarizer backend failed"),
        }
    }
}

impl Error for SummaryError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Session(error) => Some(error),
            _ => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::budget::HeuristicTokenCounter;
    use crate::session::Role;

    struct FailingSummarizer;

    impl Summarizer for FailingSummarizer {
        fn summarize(&mut self, _request: &SummaryRequest<'_>) -> Result<String, SummaryError> {
            Err(SummaryError::Backend)
        }
    }

    struct BlankSummarizer;

    impl Summarizer for BlankSummarizer {
        fn summarize(&mut self, _request: &SummaryRequest<'_>) -> Result<String, SummaryError> {
            Ok("   \n  ".to_owned())
        }
    }

    /// Records exactly which messages the run handed to the summarizer.
    #[derive(Default)]
    struct RecordingSummarizer {
        seen: Vec<u64>,
    }

    impl Summarizer for RecordingSummarizer {
        fn summarize(&mut self, request: &SummaryRequest<'_>) -> Result<String, SummaryError> {
            self.seen = request
                .messages
                .iter()
                .map(|message| message.id.get())
                .collect();
            Ok("compacted".to_owned())
        }
    }

    fn counter() -> HeuristicTokenCounter {
        HeuristicTokenCounter::new(4, 0).expect("valid density")
    }

    fn loaded_session() -> Session {
        let mut session = Session::new(SessionId::new("s").expect("valid identifier"));
        session.append(Role::System, "rules", 1).expect("appended");
        for index in 0..12_u64 {
            session
                .append(
                    Role::User,
                    format!("message {index} with some padding text"),
                    index,
                )
                .expect("appended");
        }
        session
    }

    #[test]
    fn policies_validate_their_percentages() {
        assert_eq!(
            SummarizationPolicy::new(0, 4, 10),
            Err(SummaryError::InvalidPolicy)
        );
        assert_eq!(
            SummarizationPolicy::new(101, 4, 10),
            Err(SummaryError::InvalidPolicy)
        );
        assert_eq!(
            SummarizationPolicy::new(80, 4, 0),
            Err(SummaryError::InvalidPolicy)
        );
        let policy = SummarizationPolicy::new(75, 6, 20).expect("valid policy");
        assert_eq!(policy.trigger_percent(), 75);
        assert_eq!(policy.keep_recent(), 6);
        let budget = TokenBudget::new(1000, 0).expect("valid budget");
        assert_eq!(policy.summary_tokens(budget), 200);
    }

    #[test]
    fn no_plan_below_the_trigger_threshold() {
        let session = loaded_session();
        let policy = SummarizationPolicy::new(80, 4, 10).expect("valid policy");
        let roomy = TokenBudget::new(10_000, 0).expect("valid budget");
        assert_eq!(
            plan_summarization(&session, roomy, &counter(), policy),
            None
        );
    }

    #[test]
    fn a_plan_covers_the_oldest_non_anchor_messages_only() {
        let session = loaded_session();
        let policy = SummarizationPolicy::new(50, 4, 10).expect("valid policy");
        let tight = TokenBudget::new(60, 0).expect("valid budget");
        let plan = plan_summarization(&session, tight, &counter(), policy).expect("plan");
        assert_eq!(
            plan.first,
            MessageId::new(1),
            "the system anchor is excluded"
        );
        assert_eq!(plan.last, MessageId::new(8));
        assert_eq!(plan.message_count, 8);
        assert_eq!(plan.max_tokens, 6);
    }

    #[test]
    fn compaction_replaces_the_run_and_keeps_the_anchor() {
        let mut session = loaded_session();
        let policy = SummarizationPolicy::new(50, 4, 10).expect("valid policy");
        let tight = TokenBudget::new(60, 0).expect("valid budget");
        let mut summarizer = ExtractiveSummarizer::new(40).expect("valid summarizer");
        let summary = compact(
            &mut session,
            tight,
            &counter(),
            policy,
            &mut summarizer,
            999,
        )
        .expect("compacted")
        .expect("a summary was due");

        assert_eq!(summary.first, MessageId::new(1));
        assert_eq!(summary.last, MessageId::new(8));
        assert_eq!(summary.unix_millis, 999);
        assert!(!summary.text.is_empty());
        assert_eq!(
            session
                .messages()
                .iter()
                .map(|message| message.id.get())
                .collect::<Vec<_>>(),
            vec![0, 9, 10, 11, 12]
        );
        assert_eq!(session.summaries().len(), 1);
    }

    /// A pinned message inside the planned run splits it: the run is no longer
    /// a contiguous slice of the session, and the anchor must still be
    /// excluded from what the summarizer sees and from what compaction
    /// removes.
    #[test]
    fn an_anchor_inside_the_run_splits_it_and_is_never_summarized() {
        let policy = SummarizationPolicy::new(50, 4, 10).expect("valid policy");
        let tight = TokenBudget::new(60, 0).expect("valid budget");

        let mut contiguous = loaded_session();
        let mut recorder = RecordingSummarizer::default();
        compact(
            &mut contiguous,
            tight,
            &counter(),
            policy,
            &mut recorder,
            777,
        )
        .expect("compacted")
        .expect("a summary was due");
        assert_eq!(recorder.seen, (1..=8).collect::<Vec<u64>>());

        let mut split = loaded_session();
        assert!(split.pin(MessageId::new(5)));
        let mut recorder = RecordingSummarizer::default();
        let summary = compact(&mut split, tight, &counter(), policy, &mut recorder, 778)
            .expect("compacted")
            .expect("a summary was due");
        assert_eq!(
            recorder.seen,
            vec![1, 2, 3, 4, 6, 7, 8],
            "the pinned message is excluded from the run it interrupts"
        );
        assert_eq!(
            (summary.first, summary.last),
            (MessageId::new(1), MessageId::new(8))
        );
        assert_eq!(
            split
                .messages()
                .iter()
                .map(|message| message.id.get())
                .collect::<Vec<_>>(),
            vec![0, 5, 9, 10, 11, 12],
            "both anchors survive compaction verbatim"
        );
    }

    #[test]
    fn a_failing_summarizer_leaves_the_session_untouched() {
        let mut session = loaded_session();
        let before = session.clone();
        let policy = SummarizationPolicy::new(50, 4, 10).expect("valid policy");
        let tight = TokenBudget::new(60, 0).expect("valid budget");
        assert_eq!(
            compact(
                &mut session,
                tight,
                &counter(),
                policy,
                &mut FailingSummarizer,
                1
            ),
            Err(SummaryError::Backend)
        );
        assert_eq!(session, before);

        assert_eq!(
            compact(
                &mut session,
                tight,
                &counter(),
                policy,
                &mut BlankSummarizer,
                1
            ),
            Err(SummaryError::EmptySummary)
        );
        assert_eq!(session, before);
    }

    #[test]
    fn the_extractive_summarizer_is_deterministic_and_bounded() {
        let mut session = Session::new(SessionId::new("s").expect("valid identifier"));
        session
            .append(Role::User, "First sentence here. Second one ignored.", 1)
            .expect("appended");
        session
            .append(Role::Assistant, "Reply text. More detail.", 2)
            .expect("appended");
        let messages = session.messages().to_vec();
        let request = SummaryRequest {
            session: session.id(),
            messages: &messages,
            max_tokens: 40,
        };
        let mut summarizer = ExtractiveSummarizer::default();
        let first = summarizer.summarize(&request).expect("summarized");
        let second = summarizer.summarize(&request).expect("summarized");
        assert_eq!(first, second);
        assert_eq!(first, "user: First sentence here.\nassistant: Reply text.");
    }

    #[test]
    fn a_tiny_budget_still_produces_one_line() {
        let mut session = Session::new(SessionId::new("s").expect("valid identifier"));
        session
            .append(Role::User, "padding ".repeat(50), 1)
            .expect("appended");
        let messages = session.messages().to_vec();
        let mut summarizer = ExtractiveSummarizer::default();
        let text = summarizer
            .summarize(&SummaryRequest {
                session: session.id(),
                messages: &messages,
                max_tokens: 1,
            })
            .expect("summarized");
        assert_eq!(text, "user: padding padding padding padding");
    }

    #[test]
    fn an_empty_request_is_refused() {
        let session = Session::new(SessionId::new("s").expect("valid identifier"));
        let mut summarizer = ExtractiveSummarizer::default();
        assert_eq!(
            summarizer.summarize(&SummaryRequest {
                session: session.id(),
                messages: &[],
                max_tokens: 10,
            }),
            Err(SummaryError::NothingToSummarize)
        );
    }
}

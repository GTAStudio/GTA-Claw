//! Conversation and session model.
//!
//! Messages are immutable once appended and carry a monotonically increasing
//! identifier, which is what makes every downstream ordering and truncation
//! rule deterministic.

use std::error::Error;
use std::fmt::{self, Display, Formatter};

use serde::de::{self, Deserializer};
use serde::{Deserialize, Serialize};

use crate::bounded::{BoundedString, BoundedVec};

/// Inclusive maximum byte length of a session identifier.
pub const MAX_SESSION_ID_BYTES: usize = 128;

/// Inclusive maximum byte length of one message body.
///
/// Message bodies arrive from model output and tool results, so they are
/// attacker-influenced by construction. Refusing an oversized body here keeps
/// every downstream token count, summary and context assembly working on
/// input whose size is already known to be bounded.
pub const MAX_MESSAGE_BYTES: usize = 1024 * 1024;

/// Inclusive maximum number of retained messages in one session.
pub const MAX_MESSAGES: usize = 100_000;

/// Inclusive maximum number of retained summaries in one session.
pub const MAX_SUMMARIES: usize = 10_000;

/// A validated session identifier.
///
/// Identifiers are restricted so they can be used as storage keys and appear
/// in logs without escaping. [`Deserialize`] runs the same validation, so a
/// stored or transmitted identifier cannot reintroduce one the constructor
/// would have refused.
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
pub struct SessionId(String);

impl SessionId {
    /// Validates and creates a session identifier.
    ///
    /// # Errors
    ///
    /// Returns [`SessionError::EmptySessionId`] for an empty `value`,
    /// [`SessionError::SessionIdTooLong`] past [`MAX_SESSION_ID_BYTES`], and
    /// [`SessionError::InvalidSessionId`] for anything outside ASCII
    /// alphanumerics, `-`, `_` and `.`, so an identifier is always safe as a
    /// storage key and in a log line.
    pub fn new(value: &str) -> Result<Self, SessionError> {
        if value.is_empty() {
            return Err(SessionError::EmptySessionId);
        }
        if value.len() > MAX_SESSION_ID_BYTES {
            return Err(SessionError::SessionIdTooLong);
        }
        let acceptable = value.chars().all(|character| {
            character.is_ascii_alphanumeric() || matches!(character, '-' | '_' | '.')
        });
        if !acceptable {
            return Err(SessionError::InvalidSessionId);
        }
        Ok(Self(value.to_owned()))
    }

    /// Returns the identifier text.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl Display for SessionId {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.0)
    }
}

impl<'de> Deserialize<'de> for SessionId {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let value = BoundedString::<MAX_SESSION_ID_BYTES>::deserialize(deserializer)?.into_inner();
        Self::new(&value).map_err(de::Error::custom)
    }
}

/// Author of a message.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Role {
    /// Operator-controlled instructions that anchor the conversation.
    System,
    /// End-user input.
    User,
    /// Model output.
    Assistant,
    /// Result of a tool invocation.
    Tool,
}

impl Role {
    /// Returns the stable wire identity of the role.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::System => "system",
            Self::User => "user",
            Self::Assistant => "assistant",
            Self::Tool => "tool",
        }
    }
}

impl Display for Role {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

/// Monotonic position of a message inside one session.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
pub struct MessageId(u64);

impl MessageId {
    /// Creates an identifier from a raw ordinal.
    #[must_use]
    pub const fn new(ordinal: u64) -> Self {
        Self(ordinal)
    }

    /// Returns the raw ordinal.
    #[must_use]
    pub const fn get(self) -> u64 {
        self.0
    }
}

impl Display for MessageId {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        write!(formatter, "{}", self.0)
    }
}

/// One immutable conversation entry.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct Message {
    /// Monotonic identifier, unique within the session.
    pub id: MessageId,
    /// Author of the message.
    pub role: Role,
    /// Message body.
    pub content: String,
    /// Wall-clock authoring time in Unix milliseconds.
    pub unix_millis: u64,
    /// Whether the message must survive every truncation.
    pub pinned: bool,
}

#[derive(Deserialize)]
#[serde(rename = "Message")]
struct RawMessage {
    id: MessageId,
    role: Role,
    content: BoundedString<MAX_MESSAGE_BYTES>,
    unix_millis: u64,
    pinned: bool,
}

impl<'de> Deserialize<'de> for Message {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let raw = RawMessage::deserialize(deserializer)?;
        let content = raw.content.into_inner();
        check_body(&content).map_err(de::Error::custom)?;
        Ok(Self {
            id: raw.id,
            role: raw.role,
            content,
            unix_millis: raw.unix_millis,
            pinned: raw.pinned,
        })
    }
}

impl Message {
    /// Reports whether truncation must always keep this message.
    ///
    /// System messages are anchors by construction: dropping one silently
    /// changes the agent's instructions, which is a security property, not a
    /// formatting preference.
    #[must_use]
    pub const fn is_anchor(&self) -> bool {
        self.pinned || matches!(self.role, Role::System)
    }
}

/// A summary standing in for a contiguous run of older messages.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct Summary {
    /// First message identifier the summary replaces, inclusive.
    pub first: MessageId,
    /// Last message identifier the summary replaces, inclusive.
    pub last: MessageId,
    /// Summary body.
    pub text: String,
    /// Wall-clock creation time in Unix milliseconds.
    pub unix_millis: u64,
}

#[derive(Deserialize)]
#[serde(rename = "Summary")]
struct RawSummary {
    first: MessageId,
    last: MessageId,
    text: BoundedString<MAX_MESSAGE_BYTES>,
    unix_millis: u64,
}

impl<'de> Deserialize<'de> for Summary {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let raw = RawSummary::deserialize(deserializer)?;
        let summary = Self {
            first: raw.first,
            last: raw.last,
            text: raw.text.into_inner(),
            unix_millis: raw.unix_millis,
        };
        check_summary(&summary).map_err(de::Error::custom)?;
        Ok(summary)
    }
}

impl Summary {
    /// Reports whether this summary covers the given message.
    #[must_use]
    pub const fn covers(&self, id: MessageId) -> bool {
        id.0 >= self.first.0 && id.0 <= self.last.0
    }
}

/// One conversation with its accumulated summaries.
///
/// [`Deserialize`] re-applies the bounds the write path applies, so a stored
/// document restores a session that is within them rather than one that is
/// merely shaped like a session. See the private `Session::restore`.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct Session {
    id: SessionId,
    // Bounded by `MAX_MESSAGES` in `append`; `absorb` is the eviction path,
    // replacing a covered run with one summary.
    messages: Vec<Message>,
    // Bounded by `MAX_SUMMARIES` in `absorb`. There is deliberately no
    // eviction path: dropping a summary would erase the only remaining record
    // of the messages it replaced, so the bound fails loudly instead.
    summaries: Vec<Summary>,
    next_ordinal: u64,
}

impl Session {
    /// Creates an empty session.
    #[must_use]
    pub const fn new(id: SessionId) -> Self {
        Self {
            id,
            messages: Vec::new(),
            summaries: Vec::new(),
            next_ordinal: 0,
        }
    }

    /// Returns the session identifier.
    #[must_use]
    pub const fn id(&self) -> &SessionId {
        &self.id
    }

    /// Appends a message and returns its identifier.
    ///
    /// Timestamps are never trusted for ordering: identifiers are assigned
    /// here and increase monotonically regardless of clock behaviour.
    ///
    /// # Errors
    ///
    /// Returns [`SessionError::EmptyMessage`] for an empty body,
    /// [`SessionError::MessageTooLong`] past [`MAX_MESSAGE_BYTES`],
    /// [`SessionError::TooManyMessages`] once the session already retains
    /// [`MAX_MESSAGES`] messages, and [`SessionError::SessionExhausted`] if
    /// the monotonic ordinal would overflow. Nothing is retained on any of
    /// these paths, so a refused append leaves the session unchanged.
    pub fn append(
        &mut self,
        role: Role,
        content: impl Into<String>,
        unix_millis: u64,
    ) -> Result<MessageId, SessionError> {
        let content = content.into();
        check_body(&content)?;
        if self.messages.len() >= MAX_MESSAGES {
            return Err(SessionError::TooManyMessages);
        }
        let id = MessageId(self.next_ordinal);
        self.next_ordinal = self
            .next_ordinal
            .checked_add(1)
            .ok_or(SessionError::SessionExhausted)?;
        self.messages.push(Message {
            id,
            role,
            content,
            unix_millis,
            pinned: false,
        });
        Ok(id)
    }

    /// Marks a message as always retained, returning whether it existed.
    pub fn pin(&mut self, id: MessageId) -> bool {
        match self.messages.iter_mut().find(|message| message.id == id) {
            Some(message) => {
                message.pinned = true;
                true
            }
            None => false,
        }
    }

    /// Replaces one retained message in place without changing its identifier.
    ///
    /// # Errors
    ///
    /// Returns the same body errors as [`Self::append`]. Validation runs before mutation.
    pub fn replace(
        &mut self,
        id: MessageId,
        role: Role,
        content: impl Into<String>,
        unix_millis: u64,
        pinned: bool,
    ) -> Result<bool, SessionError> {
        let content = content.into();
        check_body(&content)?;
        let Some(message) = self.messages.iter_mut().find(|message| message.id == id) else {
            return Ok(false);
        };
        *message = Message {
            id,
            role,
            content,
            unix_millis,
            pinned,
        };
        Ok(true)
    }

    /// Removes one retained message while preserving the monotonic identifier high-water mark.
    pub fn remove(&mut self, id: MessageId) -> Option<Message> {
        let index = self.messages.iter().position(|message| message.id == id)?;
        Some(self.messages.remove(index))
    }

    /// Returns every message in ascending identifier order.
    #[must_use]
    pub fn messages(&self) -> &[Message] {
        &self.messages
    }

    /// Returns every summary in insertion order.
    #[must_use]
    pub fn summaries(&self) -> &[Summary] {
        &self.summaries
    }

    /// Records a summary and removes the messages it replaces.
    ///
    /// Anchors are never removed: an operator instruction stays verbatim even
    /// when the surrounding conversation is compacted.
    ///
    /// # Errors
    ///
    /// Returns [`SessionError::InvalidSummaryRange`] when `first` is after
    /// `last`, [`SessionError::EmptyMessage`] for empty summary text,
    /// [`SessionError::MessageTooLong`] past [`MAX_MESSAGE_BYTES`], and
    /// [`SessionError::TooManySummaries`] once the session already retains
    /// [`MAX_SUMMARIES`] summaries. Every check runs before any message is
    /// removed, so a refused summary compacts nothing.
    pub fn absorb(&mut self, summary: Summary) -> Result<usize, SessionError> {
        check_summary(&summary)?;
        if self.summaries.len() >= MAX_SUMMARIES {
            return Err(SessionError::TooManySummaries);
        }
        let before = self.messages.len();
        self.messages
            .retain(|message| message.is_anchor() || !summary.covers(message.id));
        self.summaries.push(summary);
        Ok(before - self.messages.len())
    }

    /// Returns the most recent message, when the session is not empty.
    #[must_use]
    pub fn last(&self) -> Option<&Message> {
        self.messages.last()
    }

    /// Returns the number of retained messages.
    #[must_use]
    pub const fn len(&self) -> usize {
        self.messages.len()
    }

    /// Reports whether no messages are retained.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.messages.is_empty()
    }
}

/// The body rule [`Session::append`] applies to a message and
/// [`Session::absorb`] applies to a summary.
///
/// It lives here so the write path and the restore path cannot drift apart:
/// a body that `append` would have refused is a body a decoded document may
/// not carry either.
const fn check_body(text: &str) -> Result<(), SessionError> {
    if text.is_empty() {
        return Err(SessionError::EmptyMessage);
    }
    if text.len() > MAX_MESSAGE_BYTES {
        return Err(SessionError::MessageTooLong);
    }
    Ok(())
}

/// The rule [`Session::absorb`] applies to a summary before it is recorded.
fn check_summary(summary: &Summary) -> Result<(), SessionError> {
    if summary.first > summary.last {
        return Err(SessionError::InvalidSummaryRange);
    }
    check_body(&summary.text)
}

/// The wire shape of a [`Session`], before its bounds are re-applied.
///
/// The field set and the name are exactly the derived ones, so the format a
/// stored session was written in is the format it is read back from, down to
/// the diagnostics a malformed document produces.
#[derive(Deserialize)]
#[serde(rename = "Session")]
struct RawSession {
    id: SessionId,
    messages: BoundedVec<Message, MAX_MESSAGES>,
    summaries: BoundedVec<Summary, MAX_SUMMARIES>,
    next_ordinal: u64,
}

/// Why a decoded session document could not be restored.
enum RestoreError {
    /// A retained message or summary broke a bound that shedding history
    /// cannot repair.
    Bound(SessionError),
    /// Message identifiers were not strictly increasing, so "oldest" and
    /// "newest" are undefined and no repair rule applies.
    NonMonotonicMessages,
}

impl Display for RestoreError {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        match self {
            Self::Bound(error) => Display::fmt(error, formatter),
            Self::NonMonotonicMessages => {
                formatter.write_str("message identifiers are not strictly increasing")
            }
        }
    }
}

impl Session {
    /// Rebuilds a session from a decoded document, re-applying the bounds the
    /// write path applies.
    ///
    /// Deserialization is the one way into a `Session` that does not go
    /// through [`Session::append`] and [`Session::absorb`], so without this a
    /// stored or transmitted document would restore a session past every
    /// bound the type advertises — and a store that can be loaded into an
    /// invalid state has no bounds at all.
    ///
    /// The bounded visitors reject a message or summary at `MAX + 1` before
    /// materializing it, and this step validates semantic invariants that do
    /// not affect allocation: identifier order, body validity, summary ranges,
    /// and the next ordinal.
    ///
    /// On any session the write path could have produced this is the identity
    /// function.
    fn restore(raw: RawSession) -> Result<Self, RestoreError> {
        let RawSession {
            id,
            messages,
            summaries,
            next_ordinal,
        } = raw;
        let messages = messages.into_inner();
        let summaries = summaries.into_inner();

        // Recency is positional throughout this crate, so the ordering
        // invariant has to hold before anything decides what is oldest.
        if !messages.is_sorted_by(|earlier, later| earlier.id < later.id) {
            return Err(RestoreError::NonMonotonicMessages);
        }
        for message in &messages {
            check_body(&message.content).map_err(RestoreError::Bound)?;
        }
        for summary in &summaries {
            check_summary(summary).map_err(RestoreError::Bound)?;
        }

        // `append` hands out `next_ordinal` and then advances it, so it is
        // always past every identifier the session holds. A document that
        // disagrees would hand out a duplicate on the very next append.
        let after_last = messages
            .last()
            .map_or(0, |message| message.id.get().saturating_add(1));
        Ok(Self {
            id,
            messages,
            summaries,
            next_ordinal: next_ordinal.max(after_last),
        })
    }
}

impl<'de> Deserialize<'de> for Session {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        Self::restore(RawSession::deserialize(deserializer)?).map_err(de::Error::custom)
    }
}

/// A rejected session or message operation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SessionError {
    /// The session identifier was empty.
    EmptySessionId,
    /// The session identifier exceeded its byte bound.
    SessionIdTooLong,
    /// The session identifier contained unacceptable characters.
    InvalidSessionId,
    /// A message body was empty.
    EmptyMessage,
    /// A message body exceeded its byte bound.
    MessageTooLong,
    /// The session already holds the maximum number of messages.
    TooManyMessages,
    /// The session already holds the maximum number of summaries.
    TooManySummaries,
    /// A summary range ran backwards.
    InvalidSummaryRange,
    /// The session ran out of message identifiers.
    SessionExhausted,
}

impl Display for SessionError {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        let message = match self {
            Self::EmptySessionId => "session identifier must not be empty",
            Self::SessionIdTooLong => "session identifier is too long",
            Self::InvalidSessionId => "session identifier has unacceptable characters",
            Self::EmptyMessage => "message content must not be empty",
            Self::MessageTooLong => "message content exceeds the maximum size",
            Self::TooManyMessages => "session holds the maximum number of messages",
            Self::TooManySummaries => "session holds the maximum number of summaries",
            Self::InvalidSummaryRange => "summary range runs backwards",
            Self::SessionExhausted => "session ran out of message identifiers",
        };
        formatter.write_str(message)
    }
}

impl Error for SessionError {}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fmt::Write as _;

    fn session() -> Session {
        Session::new(SessionId::new("s-1").expect("valid identifier"))
    }

    fn message_json(id: u64, role: Role, content: &str, pinned: bool) -> String {
        format!(
            "{{\"id\":{id},\"role\":\"{role}\",\"content\":\"{content}\",\
             \"unix_millis\":{id},\"pinned\":{pinned}}}"
        )
    }

    fn summary_json(first: u64, last: u64, text: &str) -> String {
        format!("{{\"first\":{first},\"last\":{last},\"text\":\"{text}\",\"unix_millis\":1}}")
    }

    fn document(messages: &[String], summaries: &[String], next_ordinal: u64) -> String {
        let mut json = String::from("{\"id\":\"restored\",\"messages\":[");
        json.push_str(&messages.join(","));
        json.push_str("],\"summaries\":[");
        json.push_str(&summaries.join(","));
        write!(json, "],\"next_ordinal\":{next_ordinal}}}").expect("writing to a string");
        json
    }

    fn restore(document: &str) -> Result<Session, serde_json::Error> {
        serde_json::from_str(document)
    }

    /// The property everything else depends on: normalization must be the
    /// identity on any session the write path could have produced, or every
    /// existing save is silently rewritten the first time it is loaded.
    #[test]
    fn a_valid_session_round_trips_through_serde_byte_for_byte() {
        let mut original = session();
        original.append(Role::System, "rules", 1).expect("appended");
        let pinned = original.append(Role::User, "keep me", 2).expect("appended");
        original.append(Role::Assistant, "a", 3).expect("appended");
        original.append(Role::User, "b", 4).expect("appended");
        assert!(original.pin(pinned));
        original
            .absorb(Summary {
                first: MessageId::new(2),
                last: MessageId::new(2),
                text: "earlier discussion".to_owned(),
                unix_millis: 5,
            })
            .expect("absorbed");
        original.append(Role::Assistant, "c", 6).expect("appended");

        let encoded = serde_json::to_string(&original).expect("serialized");
        let restored: Session = serde_json::from_str(&encoded).expect("deserialized");
        assert_eq!(
            restored, original,
            "restoring a valid session changes nothing"
        );
        assert_eq!(
            serde_json::to_string(&restored).expect("serialized"),
            encoded,
            "a second round trip is byte-identical"
        );

        // The write path continues from where the document left off.
        let mut restored = restored;
        assert_eq!(
            restored.append(Role::User, "next", 7).expect("appended"),
            MessageId::new(5)
        );
    }

    /// The one case where a naive "recompute the ordinal from the history"
    /// repair would corrupt a perfectly valid session: compaction can remove
    /// the newest messages, leaving the next identifier legitimately far
    /// ahead of the last one retained.
    #[test]
    fn a_compacted_tail_never_rewinds_the_next_identifier() {
        let mut original = session();
        original.append(Role::System, "rules", 1).expect("appended");
        for unix_millis in 2..6 {
            original
                .append(Role::User, "x", unix_millis)
                .expect("appended");
        }
        original
            .absorb(Summary {
                first: MessageId::new(1),
                last: MessageId::new(4),
                text: "all of it".to_owned(),
                unix_millis: 6,
            })
            .expect("absorbed");
        assert_eq!(original.len(), 1, "only the anchor is left");

        let encoded = serde_json::to_string(&original).expect("serialized");
        let mut restored: Session = serde_json::from_str(&encoded).expect("deserialized");
        assert_eq!(restored, original);
        assert_eq!(
            restored.append(Role::User, "next", 7).expect("appended"),
            MessageId::new(5),
            "the summarized identifiers are never handed out twice"
        );
    }

    #[test]
    fn max_plus_one_messages_are_rejected_by_the_bounded_sequence_visitor() {
        let mut messages = vec![
            message_json(0, Role::System, "rules", false),
            message_json(1, Role::User, "pinned", true),
        ];
        for id in 2..=MAX_MESSAGES as u64 {
            messages.push(message_json(id, Role::User, "x", false));
        }
        assert_eq!(messages.len(), MAX_MESSAGES + 1);

        assert!(
            restore(&document(&messages, &[], MAX_MESSAGES as u64 + 1)).is_err(),
            "MAX+1 is detected before another Message is materialized"
        );
    }

    #[test]
    fn a_history_of_anchors_alone_past_the_bound_is_refused_rather_than_shed() {
        let messages: Vec<String> = (0..=MAX_MESSAGES as u64)
            .map(|id| message_json(id, Role::System, "rules", false))
            .collect();
        let error = restore(&document(&messages, &[], MAX_MESSAGES as u64 + 1))
            .expect_err("anchors cannot be shed to meet the bound");
        assert!(
            error.to_string().contains("at most 100000 elements"),
            "unexpected error: {error}"
        );
    }

    #[test]
    fn max_plus_one_summaries_are_rejected_by_the_bounded_sequence_visitor() {
        let summaries: Vec<String> = (0..=MAX_SUMMARIES as u64)
            .map(|ordinal| summary_json(ordinal, ordinal, "compacted"))
            .collect();
        assert!(
            restore(&document(&[], &summaries, 0)).is_err(),
            "MAX+1 is detected before another Summary is materialized"
        );
    }

    #[test]
    fn a_document_whose_identifiers_are_not_strictly_increasing_is_refused() {
        for out_of_order in [
            vec![
                message_json(1, Role::User, "a", false),
                message_json(0, Role::User, "b", false),
            ],
            vec![
                message_json(0, Role::User, "a", false),
                message_json(0, Role::User, "b", false),
            ],
        ] {
            let error = restore(&document(&out_of_order, &[], 2))
                .expect_err("identifier order is not repairable");
            assert!(
                error.to_string().contains("strictly increasing"),
                "unexpected error: {error}"
            );
        }
    }

    #[test]
    fn a_retained_body_the_write_path_would_refuse_is_refused_on_load() {
        let empty = vec![message_json(0, Role::User, "", false)];
        let error = restore(&document(&empty, &[], 1)).expect_err("an empty body is refused");
        assert!(
            error.to_string().contains("must not be empty"),
            "unexpected error: {error}"
        );

        let oversized = vec![message_json(
            0,
            Role::User,
            &"x".repeat(MAX_MESSAGE_BYTES + 1),
            false,
        )];
        let error =
            restore(&document(&oversized, &[], 1)).expect_err("an oversized body is refused");
        assert!(
            error.to_string().contains("no longer than 1048576 bytes"),
            "unexpected error: {error}"
        );

        let backwards = vec![summary_json(5, 1, "x")];
        let error =
            restore(&document(&[], &backwards, 0)).expect_err("a backwards range is refused");
        assert!(
            error.to_string().contains("runs backwards"),
            "unexpected error: {error}"
        );
    }

    #[test]
    fn an_ordinal_behind_the_history_is_repaired_so_the_next_append_cannot_collide() {
        let messages: Vec<String> = (0..3)
            .map(|id| message_json(id, Role::User, "x", false))
            .collect();
        // A document claiming the next identifier is 0 would otherwise hand
        // out identifiers that already exist.
        let mut restored = restore(&document(&messages, &[], 0)).expect("loads");
        assert_eq!(
            restored.append(Role::User, "next", 9).expect("appended"),
            MessageId::new(3)
        );
        assert!(
            restored
                .messages()
                .is_sorted_by(|earlier, later| earlier.id < later.id)
        );
    }

    #[test]
    fn a_session_identifier_is_validated_on_load_too() {
        assert_eq!(
            serde_json::from_str::<SessionId>("\"good-1.id_x\"").expect("valid identifier"),
            SessionId::new("good-1.id_x").expect("valid identifier")
        );
        for bad in ["\"\"", "\"a/b\"", "\"a b\"", "\"a\\nb\""] {
            let error = serde_json::from_str::<SessionId>(bad)
                .expect_err("an identifier the constructor refuses cannot be restored");
            assert!(
                error.to_string().contains("session identifier"),
                "unexpected error: {error}"
            );
        }
    }

    #[test]
    fn session_identifiers_are_validated() {
        assert_eq!(
            SessionId::new("abc_123.def-4")
                .expect("valid identifier")
                .as_str(),
            "abc_123.def-4"
        );
        assert_eq!(SessionId::new(""), Err(SessionError::EmptySessionId));
        assert_eq!(SessionId::new("a/b"), Err(SessionError::InvalidSessionId));
        assert_eq!(SessionId::new("a b"), Err(SessionError::InvalidSessionId));
        assert_eq!(SessionId::new("a\nb"), Err(SessionError::InvalidSessionId));
        assert_eq!(
            SessionId::new(&"a".repeat(129)),
            Err(SessionError::SessionIdTooLong)
        );
    }

    #[test]
    fn identifiers_increase_even_when_timestamps_go_backwards() {
        let mut session = session();
        let first = session.append(Role::User, "one", 5_000).expect("appended");
        let second = session.append(Role::User, "two", 1_000).expect("appended");
        let third = session
            .append(Role::User, "three", 3_000)
            .expect("appended");
        assert_eq!(first.get(), 0);
        assert_eq!(second.get(), 1);
        assert_eq!(third.get(), 2);
        assert_eq!(
            session
                .messages()
                .iter()
                .map(|message| message.id.get())
                .collect::<Vec<_>>(),
            vec![0, 1, 2]
        );
    }

    #[test]
    fn empty_messages_are_refused() {
        let mut session = session();
        assert_eq!(
            session.append(Role::User, "", 1),
            Err(SessionError::EmptyMessage)
        );
        assert!(session.is_empty());
    }

    #[test]
    fn system_and_pinned_messages_are_anchors() {
        let mut session = session();
        session.append(Role::System, "rules", 1).expect("appended");
        let user = session.append(Role::User, "hi", 2).expect("appended");
        session
            .append(Role::Assistant, "hello", 3)
            .expect("appended");
        assert!(session.pin(user));
        assert!(!session.pin(MessageId(99)));
        let anchors: Vec<u64> = session
            .messages()
            .iter()
            .filter(|message| message.is_anchor())
            .map(|message| message.id.get())
            .collect();
        assert_eq!(anchors, vec![0, 1]);
    }

    #[test]
    fn absorbing_a_summary_removes_only_non_anchor_messages_in_range() {
        let mut session = session();
        session.append(Role::System, "rules", 1).expect("appended");
        let pinned = session.append(Role::User, "keep me", 2).expect("appended");
        session.append(Role::Assistant, "a", 3).expect("appended");
        session.append(Role::User, "b", 4).expect("appended");
        session.append(Role::Assistant, "c", 5).expect("appended");
        assert!(session.pin(pinned));

        let removed = session
            .absorb(Summary {
                first: MessageId(0),
                last: MessageId::new(3),
                text: "earlier discussion".to_owned(),
                unix_millis: 6,
            })
            .expect("valid summary");
        assert_eq!(removed, 2);
        assert_eq!(
            session
                .messages()
                .iter()
                .map(|message| message.id.get())
                .collect::<Vec<_>>(),
            vec![0, 1, 4]
        );
        assert_eq!(session.summaries().len(), 1);
    }

    #[test]
    fn summaries_with_backwards_or_empty_ranges_are_refused() {
        let mut session = session();
        session.append(Role::User, "a", 1).expect("appended");
        assert_eq!(
            session.absorb(Summary {
                first: MessageId::new(5),
                last: MessageId(1),
                text: "x".to_owned(),
                unix_millis: 2,
            }),
            Err(SessionError::InvalidSummaryRange)
        );
        assert_eq!(
            session.absorb(Summary {
                first: MessageId(0),
                last: MessageId(0),
                text: String::new(),
                unix_millis: 2,
            }),
            Err(SessionError::EmptyMessage)
        );
        assert_eq!(session.len(), 1);
        assert!(session.summaries().is_empty());
    }

    #[test]
    fn summary_coverage_is_inclusive_on_both_ends() {
        let summary = Summary {
            first: MessageId::new(2),
            last: MessageId(4),
            text: "x".to_owned(),
            unix_millis: 1,
        };
        assert!(!summary.covers(MessageId(1)));
        assert!(summary.covers(MessageId::new(2)));
        assert!(summary.covers(MessageId::new(3)));
        assert!(summary.covers(MessageId(4)));
        assert!(!summary.covers(MessageId::new(5)));
    }
}

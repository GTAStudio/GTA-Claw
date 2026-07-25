//! Conversation and session model.
//!
//! Messages are immutable once appended and carry a monotonically increasing
//! identifier, which is what makes every downstream ordering and truncation
//! rule deterministic.

use std::error::Error;
use std::fmt::{self, Display, Formatter};

use serde::{Deserialize, Serialize};

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
/// in logs without escaping.
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
pub struct SessionId(String);

impl SessionId {
    /// Validates and creates a session identifier.
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
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
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
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
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

impl Summary {
    /// Reports whether this summary covers the given message.
    #[must_use]
    pub const fn covers(&self, id: MessageId) -> bool {
        id.0 >= self.first.0 && id.0 <= self.last.0
    }
}

/// One conversation with its accumulated summaries.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct Session {
    id: SessionId,
    messages: Vec<Message>,
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
    pub fn append(
        &mut self,
        role: Role,
        content: impl Into<String>,
        unix_millis: u64,
    ) -> Result<MessageId, SessionError> {
        let content = content.into();
        if content.is_empty() {
            return Err(SessionError::EmptyMessage);
        }
        if content.len() > MAX_MESSAGE_BYTES {
            return Err(SessionError::MessageTooLong);
        }
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
    pub fn absorb(&mut self, summary: Summary) -> Result<usize, SessionError> {
        if summary.first > summary.last {
            return Err(SessionError::InvalidSummaryRange);
        }
        if summary.text.is_empty() {
            return Err(SessionError::EmptyMessage);
        }
        if summary.text.len() > MAX_MESSAGE_BYTES {
            return Err(SessionError::MessageTooLong);
        }
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
    pub fn len(&self) -> usize {
        self.messages.len()
    }

    /// Reports whether no messages are retained.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.messages.is_empty()
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

    fn session() -> Session {
        Session::new(SessionId::new("s-1").expect("valid identifier"))
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
                last: MessageId(3),
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
                first: MessageId(5),
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
            first: MessageId(2),
            last: MessageId(4),
            text: "x".to_owned(),
            unix_millis: 1,
        };
        assert!(!summary.covers(MessageId(1)));
        assert!(summary.covers(MessageId(2)));
        assert!(summary.covers(MessageId(3)));
        assert!(summary.covers(MessageId(4)));
        assert!(!summary.covers(MessageId(5)));
    }
}

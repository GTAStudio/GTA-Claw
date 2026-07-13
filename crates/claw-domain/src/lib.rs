//! Core domain types and invariants shared by every GTA Claw runtime.

use std::error::Error;
use std::fmt::{self, Display, Formatter};

const MAX_SESSION_ID_BYTES: usize = 128;
const MAX_MESSAGE_BYTES: usize = 64 * 1024;

/// A validated, transport-independent conversation identifier.
#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub struct SessionId(String);

impl SessionId {
    /// Creates a session identifier after enforcing the domain invariant.
    pub fn new(value: impl Into<String>) -> Result<Self, DomainError> {
        let value = value.into();
        let value = value.trim();

        if value.is_empty() {
            return Err(DomainError::InvalidSessionId("must not be empty"));
        }
        if value.len() > MAX_SESSION_ID_BYTES {
            return Err(DomainError::InvalidSessionId("is too long"));
        }
        if value.chars().any(char::is_control) {
            return Err(DomainError::InvalidSessionId(
                "must not contain control characters",
            ));
        }

        Ok(Self(value.to_owned()))
    }

    /// Returns the identifier as text.
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

/// The actor responsible for a message.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MessageRole {
    /// A human or external client.
    User,
    /// The GTA Claw application.
    Assistant,
    /// Runtime or policy context.
    System,
}

/// A validated message associated with a conversation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Message {
    session_id: SessionId,
    role: MessageRole,
    content: String,
}

impl Message {
    /// Creates a message while preserving its original content.
    pub fn new(
        session_id: SessionId,
        role: MessageRole,
        content: impl Into<String>,
    ) -> Result<Self, DomainError> {
        let content = content.into();

        if content.trim().is_empty() {
            return Err(DomainError::InvalidMessage("must not be empty"));
        }
        if content.len() > MAX_MESSAGE_BYTES {
            return Err(DomainError::InvalidMessage("is too long"));
        }

        Ok(Self {
            session_id,
            role,
            content,
        })
    }

    /// Returns the conversation identifier.
    #[must_use]
    pub fn session_id(&self) -> &SessionId {
        &self.session_id
    }

    /// Returns the message actor.
    #[must_use]
    pub const fn role(&self) -> MessageRole {
        self.role
    }

    /// Returns the message content.
    #[must_use]
    pub fn content(&self) -> &str {
        &self.content
    }
}

/// A violation of a domain invariant.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DomainError {
    /// A session identifier was invalid.
    InvalidSessionId(&'static str),
    /// A message was invalid.
    InvalidMessage(&'static str),
}

impl Display for DomainError {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidSessionId(reason) => write!(formatter, "invalid session id: {reason}"),
            Self::InvalidMessage(reason) => write!(formatter, "invalid message: {reason}"),
        }
    }
}

impl Error for DomainError {}

#[cfg(test)]
mod tests {
    use super::{DomainError, Message, MessageRole, SessionId};

    #[test]
    fn session_id_trims_boundary_whitespace() {
        let session_id = SessionId::new("  session-42  ").expect("valid session id");

        assert_eq!(session_id.as_str(), "session-42");
    }

    #[test]
    fn message_rejects_blank_content() {
        let session_id = SessionId::new("session-42").expect("valid session id");
        let error = Message::new(session_id, MessageRole::User, " \n ")
            .expect_err("blank messages must be rejected");

        assert_eq!(error, DomainError::InvalidMessage("must not be empty"));
    }

    #[test]
    fn message_preserves_meaningful_whitespace() {
        let session_id = SessionId::new("session-42").expect("valid session id");
        let message =
            Message::new(session_id, MessageRole::User, "  hello  ").expect("valid message");

        assert_eq!(message.content(), "  hello  ");
    }
}

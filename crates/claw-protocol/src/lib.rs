//! Versioned commands and events exchanged across GTA Claw process boundaries.

use std::error::Error;
use std::fmt::{self, Display, Formatter};

use claw_domain::{DomainError, SessionId};

/// The protocol version implemented by this workspace.
pub const PROTOCOL_VERSION: u16 = 1;

/// A command accepted by the headless application boundary.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ClientCommand {
    /// Requests runtime health information.
    Health,
    /// Submits user-authored content to a conversation.
    Submit {
        /// The target conversation.
        session_id: SessionId,
        /// The user-authored content.
        content: String,
    },
}

/// Platform identity exposed without leaking platform implementation details.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RuntimeDescriptor {
    os: String,
    architecture: String,
}

impl RuntimeDescriptor {
    /// Creates a runtime descriptor.
    #[must_use]
    pub fn new(os: impl Into<String>, architecture: impl Into<String>) -> Self {
        Self {
            os: os.into(),
            architecture: architecture.into(),
        }
    }

    /// Returns the operating system family.
    #[must_use]
    pub fn os(&self) -> &str {
        &self.os
    }

    /// Returns the processor architecture.
    #[must_use]
    pub fn architecture(&self) -> &str {
        &self.architecture
    }
}

impl Display for RuntimeDescriptor {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        write!(formatter, "{}-{}", self.os, self.architecture)
    }
}

/// An event returned by the headless application boundary.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ServerEvent {
    /// Announces the active protocol version.
    Ready {
        /// The active protocol version.
        protocol_version: u16,
    },
    /// Reports a healthy runtime.
    Healthy {
        /// The native runtime identity.
        runtime: RuntimeDescriptor,
    },
}

impl Display for ServerEvent {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        match self {
            Self::Ready { protocol_version } => {
                write!(formatter, "ready protocol={protocol_version}")
            }
            Self::Healthy { runtime } => write!(formatter, "healthy runtime={runtime}"),
        }
    }
}

/// Parses the deliberately small command-line representation of the protocol.
pub fn parse_command<I, S>(arguments: I) -> Result<ClientCommand, ProtocolError>
where
    I: IntoIterator<Item = S>,
    S: Into<String>,
{
    let mut arguments = arguments.into_iter().map(Into::into);
    let command = arguments.next().ok_or(ProtocolError::MissingCommand)?;

    match command.as_str() {
        "health" => {
            if let Some(argument) = arguments.next() {
                return Err(ProtocolError::UnexpectedArgument(argument));
            }
            Ok(ClientCommand::Health)
        }
        "send" => {
            let session_id = arguments
                .next()
                .ok_or(ProtocolError::MissingArgument("session id"))?;
            let content = arguments.collect::<Vec<_>>().join(" ");
            if content.is_empty() {
                return Err(ProtocolError::MissingArgument("message"));
            }

            Ok(ClientCommand::Submit {
                session_id: SessionId::new(session_id)?,
                content,
            })
        }
        _ => Err(ProtocolError::UnknownCommand(command)),
    }
}

/// A malformed command at an external process boundary.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ProtocolError {
    /// No command was provided.
    MissingCommand,
    /// A required argument was absent.
    MissingArgument(&'static str),
    /// An argument was provided where none is accepted.
    UnexpectedArgument(String),
    /// The command name is not supported.
    UnknownCommand(String),
    /// A parsed value violated a domain invariant.
    Domain(DomainError),
}

impl From<DomainError> for ProtocolError {
    fn from(error: DomainError) -> Self {
        Self::Domain(error)
    }
}

impl Display for ProtocolError {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        match self {
            Self::MissingCommand => {
                formatter.write_str("missing command (expected health or send)")
            }
            Self::MissingArgument(argument) => write!(formatter, "missing {argument}"),
            Self::UnexpectedArgument(argument) => {
                write!(formatter, "unexpected argument: {argument}")
            }
            Self::UnknownCommand(command) => write!(formatter, "unknown command: {command}"),
            Self::Domain(error) => Display::fmt(error, formatter),
        }
    }
}

impl Error for ProtocolError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Domain(error) => Some(error),
            _ => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{ClientCommand, ProtocolError, parse_command};

    #[test]
    fn parses_typed_send_command() {
        let command =
            parse_command(["send", "session-7", "hello", "world"]).expect("valid command");

        match command {
            ClientCommand::Submit {
                session_id,
                content,
            } => {
                assert_eq!(session_id.as_str(), "session-7");
                assert_eq!(content, "hello world");
            }
            ClientCommand::Health => panic!("expected submit command"),
        }
    }

    #[test]
    fn rejects_unknown_command() {
        let error = parse_command(["launch"]).expect_err("unknown command must fail");

        assert_eq!(error, ProtocolError::UnknownCommand("launch".to_owned()));
    }
}

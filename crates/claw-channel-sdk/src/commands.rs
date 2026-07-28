//! Channel-level command contracts.
//!
//! A command is text a user sends into a conversation that the channel layer
//! must interpret itself instead of forwarding to a conversation engine. The
//! parser is transport-neutral: it owns the prefix, the name normalization and
//! the argument shape, and it never decides which commands exist. That is the
//! registry's job, so a channel that offers no commands cannot accidentally
//! answer one.

use std::error::Error;
use std::fmt::{self, Display, Formatter};

/// Character that introduces a channel command.
pub const COMMAND_PREFIX: char = '/';

/// Longest accepted command name, in characters.
pub const MAX_COMMAND_NAME_CHARS: usize = 32;

/// Longest accepted bot mention suffix, in characters.
pub const MAX_COMMAND_MENTION_CHARS: usize = 64;

/// Largest accepted number of whitespace-separated command arguments.
pub const MAX_COMMAND_ARGUMENTS: usize = 16;

/// Longest accepted single command argument, in characters.
pub const MAX_COMMAND_ARGUMENT_CHARS: usize = 256;

/// One parsed command invocation, before it is resolved against a registry.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CommandInvocation {
    /// Lowercase command name without the prefix or mention suffix.
    pub name: String,
    /// Lowercase bot mention when the sender addressed one explicitly.
    ///
    /// Group conversations on several providers disambiguate `/help` between
    /// competing bots with a `@name` suffix. Keeping it separate from the name
    /// means a mention can be checked against the running account instead of
    /// silently changing which command was requested.
    pub mention: Option<String>,
    /// Whitespace-separated arguments in sender order.
    pub arguments: Vec<String>,
}

/// Reasons text could not be read as a command invocation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CommandParseError {
    /// Text does not begin with [`COMMAND_PREFIX`].
    NotACommand,
    /// Prefix is present but no name follows it.
    EmptyName,
    /// Name is too long or contains characters outside `a-z0-9_-`.
    InvalidName,
    /// Mention suffix is empty, too long, or malformed.
    InvalidMention,
    /// An argument is too long or contains a control character.
    InvalidArgument,
    /// More than [`MAX_COMMAND_ARGUMENTS`] arguments were supplied.
    TooManyArguments,
}

impl Display for CommandParseError {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::NotACommand => "text is not a channel command",
            Self::EmptyName => "channel command name is empty",
            Self::InvalidName => "channel command name is invalid",
            Self::InvalidMention => "channel command mention is invalid",
            Self::InvalidArgument => "channel command argument is invalid",
            Self::TooManyArguments => "channel command has too many arguments",
        })
    }
}

impl Error for CommandParseError {}

/// Parses one command invocation from raw inbound text.
///
/// Parsing is deliberately total and side effect free: it neither knows nor
/// asks which commands a channel supports, so an unknown command is a
/// successful parse and a failed [`CommandRegistry::resolve`].
///
/// # Errors
///
/// - [`CommandParseError::NotACommand`] when the text, once trimmed, does not
///   start with [`COMMAND_PREFIX`]. Ordinary conversation text lands here.
/// - [`CommandParseError::EmptyName`] when the prefix stands alone or is
///   followed immediately by the `@` mention separator.
/// - [`CommandParseError::InvalidName`] when the name is longer than
///   [`MAX_COMMAND_NAME_CHARS`] characters or, after ASCII lowercasing, holds a
///   byte outside `a-z0-9_-`. A non-ASCII name such as `/naïve` fails here.
/// - [`CommandParseError::InvalidMention`] when the `@` suffix is empty, longer
///   than [`MAX_COMMAND_MENTION_CHARS`] characters, or holds a byte outside
///   `a-z0-9_-.`.
/// - [`CommandParseError::InvalidArgument`] when one whitespace-separated
///   argument is longer than [`MAX_COMMAND_ARGUMENT_CHARS`] characters or
///   contains a control character.
/// - [`CommandParseError::TooManyArguments`] when more than
///   [`MAX_COMMAND_ARGUMENTS`] arguments follow the name.
pub fn parse_command(text: &str) -> Result<CommandInvocation, CommandParseError> {
    let trimmed = text.trim();
    let body = trimmed
        .strip_prefix(COMMAND_PREFIX)
        .ok_or(CommandParseError::NotACommand)?;
    let mut tokens = body.split_ascii_whitespace();
    let head = tokens.next().ok_or(CommandParseError::EmptyName)?;
    let (raw_name, raw_mention) = match head.split_once('@') {
        Some((name, mention)) => (name, Some(mention)),
        None => (head, None),
    };
    if raw_name.is_empty() {
        return Err(CommandParseError::EmptyName);
    }
    let name = normalize_name(raw_name)?;
    let mention = raw_mention.map(normalize_mention).transpose()?;

    let mut arguments = Vec::new();
    for argument in tokens {
        if arguments.len() == MAX_COMMAND_ARGUMENTS {
            return Err(CommandParseError::TooManyArguments);
        }
        if argument.chars().count() > MAX_COMMAND_ARGUMENT_CHARS
            || argument.chars().any(char::is_control)
        {
            return Err(CommandParseError::InvalidArgument);
        }
        arguments.push(argument.to_owned());
    }
    Ok(CommandInvocation {
        name,
        mention,
        arguments,
    })
}

fn normalize_name(raw: &str) -> Result<String, CommandParseError> {
    if raw.chars().count() > MAX_COMMAND_NAME_CHARS {
        return Err(CommandParseError::InvalidName);
    }
    let name = raw.to_ascii_lowercase();
    if !name.bytes().all(|byte| {
        byte.is_ascii_lowercase() || byte.is_ascii_digit() || matches!(byte, b'-' | b'_')
    }) {
        return Err(CommandParseError::InvalidName);
    }
    Ok(name)
}

fn normalize_mention(raw: &str) -> Result<String, CommandParseError> {
    if raw.is_empty() || raw.chars().count() > MAX_COMMAND_MENTION_CHARS {
        return Err(CommandParseError::InvalidMention);
    }
    let mention = raw.to_ascii_lowercase();
    if !mention
        .bytes()
        .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.'))
    {
        return Err(CommandParseError::InvalidMention);
    }
    Ok(mention)
}

/// One command a channel offers, together with its argument arity.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CommandSpec {
    /// Lowercase command name without the prefix.
    pub name: &'static str,
    /// Single-line description used to render help output.
    pub summary: &'static str,
    /// Smallest accepted argument count.
    pub min_arguments: usize,
    /// Largest accepted argument count.
    pub max_arguments: usize,
}

/// Reasons a command table cannot be published.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CommandRegistryError {
    /// A declared name is empty, too long, or not lowercase `a-z0-9_-`.
    InvalidName,
    /// The same name is declared twice.
    DuplicateName,
    /// Minimum exceeds maximum, or maximum exceeds [`MAX_COMMAND_ARGUMENTS`].
    InvalidArity,
}

impl Display for CommandRegistryError {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::InvalidName => "channel command table declares an invalid name",
            Self::DuplicateName => "channel command table declares a duplicate name",
            Self::InvalidArity => "channel command table declares an invalid arity",
        })
    }
}

impl Error for CommandRegistryError {}

/// Reasons a parsed invocation cannot be dispatched.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CommandDispatchError {
    /// No command with this name is offered.
    UnknownCommand,
    /// Fewer arguments than the command requires.
    MissingArguments,
    /// More arguments than the command accepts.
    TooManyArguments,
    /// The invocation named a different bot.
    ForeignMention,
}

impl Display for CommandDispatchError {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::UnknownCommand => "channel command is not offered",
            Self::MissingArguments => "channel command is missing arguments",
            Self::TooManyArguments => "channel command has too many arguments",
            Self::ForeignMention => "channel command addressed another bot",
        })
    }
}

impl Error for CommandDispatchError {}

/// A validated, immutable table of the commands one channel offers.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CommandRegistry {
    specs: &'static [CommandSpec],
}

impl CommandRegistry {
    /// Validates and publishes a command table.
    ///
    /// An empty table is legal and means the channel offers no commands at all.
    ///
    /// # Errors
    ///
    /// - [`CommandRegistryError::InvalidName`] when a declared name is empty,
    ///   longer than [`MAX_COMMAND_NAME_CHARS`] characters, or holds a byte
    ///   outside `a-z0-9_-`. Declared names are matched verbatim against
    ///   already-lowercased parse output, so an uppercase declaration would be
    ///   unreachable rather than merely unusual.
    /// - [`CommandRegistryError::DuplicateName`] when two entries declare the
    ///   same name, which would make resolution depend on declaration order.
    /// - [`CommandRegistryError::InvalidArity`] when `min_arguments` exceeds
    ///   `max_arguments`, or `max_arguments` exceeds [`MAX_COMMAND_ARGUMENTS`]
    ///   and therefore more arguments than the parser will ever produce.
    pub fn new(specs: &'static [CommandSpec]) -> Result<Self, CommandRegistryError> {
        for (index, spec) in specs.iter().enumerate() {
            if spec.name.is_empty()
                || spec.name.chars().count() > MAX_COMMAND_NAME_CHARS
                || !spec.name.bytes().all(|byte| {
                    byte.is_ascii_lowercase()
                        || byte.is_ascii_digit()
                        || matches!(byte, b'-' | b'_')
                })
            {
                return Err(CommandRegistryError::InvalidName);
            }
            if spec.min_arguments > spec.max_arguments || spec.max_arguments > MAX_COMMAND_ARGUMENTS
            {
                return Err(CommandRegistryError::InvalidArity);
            }
            if specs[..index].iter().any(|other| other.name == spec.name) {
                return Err(CommandRegistryError::DuplicateName);
            }
        }
        Ok(Self { specs })
    }

    /// Returns the offered commands in declaration order.
    #[must_use]
    pub const fn specs(&self) -> &'static [CommandSpec] {
        self.specs
    }

    /// Resolves an invocation against this table.
    ///
    /// `bot_mention` is the account's own addressable name, when it has one. An
    /// invocation carrying a different mention is rejected rather than executed,
    /// so two bots in one group conversation do not both answer.
    ///
    /// # Errors
    ///
    /// - [`CommandDispatchError::ForeignMention`] when the invocation names a
    ///   bot other than `bot_mention`, including when this account has no
    ///   addressable name at all and therefore cannot be the one addressed.
    /// - [`CommandDispatchError::UnknownCommand`] when this channel offers no
    ///   command with that name. A channel with an empty table returns this for
    ///   every invocation.
    /// - [`CommandDispatchError::MissingArguments`] when fewer than
    ///   `min_arguments` arguments were supplied.
    /// - [`CommandDispatchError::TooManyArguments`] when more than
    ///   `max_arguments` arguments were supplied.
    pub fn resolve(
        &self,
        invocation: &CommandInvocation,
        bot_mention: Option<&str>,
    ) -> Result<&'static CommandSpec, CommandDispatchError> {
        if let Some(mention) = invocation.mention.as_deref()
            && bot_mention.is_none_or(|own| !own.eq_ignore_ascii_case(mention))
        {
            return Err(CommandDispatchError::ForeignMention);
        }
        let spec = self
            .specs
            .iter()
            .find(|spec| spec.name == invocation.name)
            .ok_or(CommandDispatchError::UnknownCommand)?;
        if invocation.arguments.len() < spec.min_arguments {
            return Err(CommandDispatchError::MissingArguments);
        }
        if invocation.arguments.len() > spec.max_arguments {
            return Err(CommandDispatchError::TooManyArguments);
        }
        Ok(spec)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    static ECHO_TABLE: [CommandSpec; 2] = [
        CommandSpec {
            name: "echo",
            summary: "Repeat the argument.",
            min_arguments: 1,
            max_arguments: 2,
        },
        CommandSpec {
            name: "ping",
            summary: "Answer immediately.",
            min_arguments: 0,
            max_arguments: 0,
        },
    ];
    static DUPLICATE_TABLE: [CommandSpec; 2] = [ECHO_TABLE[0], ECHO_TABLE[0]];
    static UPPERCASE_TABLE: [CommandSpec; 1] = [CommandSpec {
        name: "Echo",
        ..ECHO_TABLE[0]
    }];
    static INVERTED_ARITY_TABLE: [CommandSpec; 1] = [CommandSpec {
        min_arguments: 2,
        max_arguments: 1,
        ..ECHO_TABLE[0]
    }];
    static OVER_ARITY_TABLE: [CommandSpec; 1] = [CommandSpec {
        min_arguments: 0,
        max_arguments: MAX_COMMAND_ARGUMENTS + 1,
        ..ECHO_TABLE[0]
    }];
    static EMPTY_TABLE: [CommandSpec; 0] = [];

    fn invocation(name: &str, mention: Option<&str>, arguments: &[&str]) -> CommandInvocation {
        CommandInvocation {
            name: name.to_owned(),
            mention: mention.map(str::to_owned),
            arguments: arguments
                .iter()
                .map(|argument| (*argument).to_owned())
                .collect(),
        }
    }

    #[test]
    fn command_parsing_normalizes_names_and_rejects_malformed_text() {
        let long_name = format!("/{}", "a".repeat(MAX_COMMAND_NAME_CHARS + 1));
        let long_argument = format!("/echo {}", "a".repeat(MAX_COMMAND_ARGUMENT_CHARS + 1));
        let too_many = format!("/echo{}", " x".repeat(MAX_COMMAND_ARGUMENTS + 1));
        let at_limit = format!("/echo{}", " x".repeat(MAX_COMMAND_ARGUMENTS));

        assert_eq!(parse_command("/help"), Ok(invocation("help", None, &[])));
        assert_eq!(
            parse_command("  /Help@ClawBot  one   two  "),
            Ok(invocation("help", Some("clawbot"), &["one", "two"]))
        );
        assert_eq!(
            parse_command("/re-set_1"),
            Ok(invocation("re-set_1", None, &[]))
        );
        assert_eq!(
            parse_command(&at_limit),
            Ok(invocation("echo", None, &["x"; MAX_COMMAND_ARGUMENTS]))
        );

        for (text, expected) in [
            ("help", CommandParseError::NotACommand),
            ("", CommandParseError::NotACommand),
            ("   ", CommandParseError::NotACommand),
            ("hello /help", CommandParseError::NotACommand),
            ("/", CommandParseError::EmptyName),
            ("/@clawbot", CommandParseError::EmptyName),
            ("/bad!name", CommandParseError::InvalidName),
            ("//escaped", CommandParseError::InvalidName),
            ("/naïve", CommandParseError::InvalidName),
            (long_name.as_str(), CommandParseError::InvalidName),
            ("/help@", CommandParseError::InvalidMention),
            ("/help@bad!bot", CommandParseError::InvalidMention),
            (long_argument.as_str(), CommandParseError::InvalidArgument),
            (too_many.as_str(), CommandParseError::TooManyArguments),
        ] {
            assert_eq!(parse_command(text), Err(expected), "{text:?}");
        }
    }

    #[test]
    fn command_tables_reject_duplicates_and_impossible_arity() {
        assert_eq!(
            CommandRegistry::new(&ECHO_TABLE).map(|registry| registry.specs()),
            Ok(ECHO_TABLE.as_slice())
        );
        assert_eq!(
            CommandRegistry::new(&EMPTY_TABLE).map(|registry| registry.specs()),
            Ok(EMPTY_TABLE.as_slice())
        );
        assert_eq!(
            CommandRegistry::new(&DUPLICATE_TABLE),
            Err(CommandRegistryError::DuplicateName)
        );
        assert_eq!(
            CommandRegistry::new(&UPPERCASE_TABLE),
            Err(CommandRegistryError::InvalidName)
        );
        assert_eq!(
            CommandRegistry::new(&INVERTED_ARITY_TABLE),
            Err(CommandRegistryError::InvalidArity)
        );
        assert_eq!(
            CommandRegistry::new(&OVER_ARITY_TABLE),
            Err(CommandRegistryError::InvalidArity)
        );
    }

    #[test]
    fn resolution_enforces_arity_and_bot_identity() {
        let registry = CommandRegistry::new(&ECHO_TABLE).expect("valid table");

        assert_eq!(
            registry.resolve(&invocation("echo", None, &["one"]), None),
            Ok(&ECHO_TABLE[0])
        );
        assert_eq!(
            registry.resolve(&invocation("echo", Some("bot"), &["one"]), Some("BOT")),
            Ok(&ECHO_TABLE[0])
        );
        assert_eq!(
            registry.resolve(&invocation("echo", None, &[]), None),
            Err(CommandDispatchError::MissingArguments)
        );
        assert_eq!(
            registry.resolve(&invocation("echo", None, &["a", "b", "c"]), None),
            Err(CommandDispatchError::TooManyArguments)
        );
        assert_eq!(
            registry.resolve(&invocation("nope", None, &[]), None),
            Err(CommandDispatchError::UnknownCommand)
        );
        assert_eq!(
            registry.resolve(&invocation("echo", Some("other"), &["one"]), Some("bot")),
            Err(CommandDispatchError::ForeignMention)
        );
        assert_eq!(
            registry.resolve(&invocation("echo", Some("bot"), &["one"]), None),
            Err(CommandDispatchError::ForeignMention),
            "an account with no addressable name must not answer a mention"
        );
    }
}

//! Slash-command dispatch and inline directive parsing.
//!
//! Two separate surfaces share this module because they share a vocabulary:
//!
//! * **Commands** are whole-line operator instructions that begin with `/`. They are resolved
//!   against a [`CommandRegistry`], authorized against the caller's [`ScopeSet`], arity-checked,
//!   and lowered to a [`CommandEffect`] the runtime executes.
//! * **Directives** are inline `!name` markers embedded in ordinary input. They are stripped from
//!   the body and lowered to [`TurnOptions`] that change how one turn runs.
//!
//! The operator scope vocabulary is the one pinned by the frozen Gateway inventory at
//! `compat/upstream/inventories/gateway-protocol.json`.

use std::collections::BTreeMap;
use std::error::Error;
use std::fmt::{self, Display, Formatter};

use claw_application::model::goal::GoalStatus;
use serde::{Deserialize, Serialize};

/// An operator authorization scope.
#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum OperatorScope {
    /// Read-only inspection.
    Read,
    /// Mutating session operations.
    Write,
    /// Host administration.
    Admin,
    /// Answering approval requests.
    Approvals,
    /// Node pairing management.
    Pairing,
    /// Access to secret material in conversations.
    TalkSecrets,
}

impl OperatorScope {
    /// Every scope in declaration order.
    pub const ALL: [Self; 6] = [
        Self::Read,
        Self::Write,
        Self::Admin,
        Self::Approvals,
        Self::Pairing,
        Self::TalkSecrets,
    ];

    /// Returns the frozen Gateway scope identifier.
    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            Self::Read => "operator.read",
            Self::Write => "operator.write",
            Self::Admin => "operator.admin",
            Self::Approvals => "operator.approvals",
            Self::Pairing => "operator.pairing",
            Self::TalkSecrets => "operator.talk.secrets",
        }
    }

    const fn bit(self) -> u8 {
        match self {
            Self::Read => 1,
            Self::Write => 1 << 1,
            Self::Admin => 1 << 2,
            Self::Approvals => 1 << 3,
            Self::Pairing => 1 << 4,
            Self::TalkSecrets => 1 << 5,
        }
    }
}

impl Display for OperatorScope {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.label())
    }
}

/// The scopes a caller holds.
///
/// Membership is exact: holding [`OperatorScope::Admin`] does *not* imply
/// [`OperatorScope::Read`]. Callers that want a superset must say so.
#[derive(Clone, Copy, Debug, Default, Eq, Hash, PartialEq)]
pub struct ScopeSet(u8);

impl ScopeSet {
    /// A caller with no scopes at all.
    pub const EMPTY: Self = Self(0);

    /// A caller holding every scope.
    #[must_use]
    pub const fn all() -> Self {
        Self(
            OperatorScope::Read.bit()
                | OperatorScope::Write.bit()
                | OperatorScope::Admin.bit()
                | OperatorScope::Approvals.bit()
                | OperatorScope::Pairing.bit()
                | OperatorScope::TalkSecrets.bit(),
        )
    }

    /// Returns this set plus `scope`.
    #[must_use]
    pub const fn with(self, scope: OperatorScope) -> Self {
        Self(self.0 | scope.bit())
    }

    /// Returns this set minus `scope`.
    #[must_use]
    pub const fn without(self, scope: OperatorScope) -> Self {
        Self(self.0 & !scope.bit())
    }

    /// Returns whether the caller holds `scope`.
    #[must_use]
    pub const fn contains(self, scope: OperatorScope) -> bool {
        self.0 & scope.bit() != 0
    }

    /// Returns the frozen Gateway identifiers of every held scope, in declaration order.
    #[must_use]
    pub fn labels(self) -> Vec<&'static str> {
        OperatorScope::ALL
            .into_iter()
            .filter(|scope| self.contains(*scope))
            .map(OperatorScope::label)
            .collect()
    }
}

impl FromIterator<OperatorScope> for ScopeSet {
    fn from_iter<T: IntoIterator<Item = OperatorScope>>(iter: T) -> Self {
        iter.into_iter().fold(Self::EMPTY, Self::with)
    }
}

/// How many arguments a command accepts.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CommandArity {
    /// The fewest arguments the command accepts.
    pub minimum: usize,
    /// The most arguments the command accepts, or `None` when unbounded.
    pub maximum: Option<usize>,
}

impl CommandArity {
    /// A command that takes no arguments.
    pub const NONE: Self = Self {
        minimum: 0,
        maximum: Some(0),
    };

    /// A command that takes exactly `count` arguments.
    #[must_use]
    pub const fn exactly(count: usize) -> Self {
        Self {
            minimum: count,
            maximum: Some(count),
        }
    }

    /// A command that takes between `minimum` and `maximum` arguments.
    #[must_use]
    pub const fn between(minimum: usize, maximum: usize) -> Self {
        Self {
            minimum,
            maximum: Some(maximum),
        }
    }

    /// A command that takes `minimum` or more arguments.
    #[must_use]
    pub const fn at_least(minimum: usize) -> Self {
        Self {
            minimum,
            maximum: None,
        }
    }

    const fn is_coherent(self) -> bool {
        match self.maximum {
            Some(maximum) => self.minimum <= maximum,
            None => true,
        }
    }
}

/// One command the registry can dispatch.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CommandSpec {
    /// The canonical name, without the leading slash.
    pub name: String,
    /// Additional accepted spellings.
    pub aliases: Vec<String>,
    /// A one-line human summary.
    pub summary: String,
    /// The scope a caller must hold.
    pub scope: OperatorScope,
    /// How many arguments the command accepts.
    pub arity: CommandArity,
    /// Whether the command appears in `commands.list` output.
    pub advertised: bool,
}

impl CommandSpec {
    /// Creates an advertised command that takes no arguments.
    #[must_use]
    pub fn new(name: &str, summary: &str, scope: OperatorScope) -> Self {
        Self {
            name: name.to_owned(),
            aliases: Vec::new(),
            summary: summary.to_owned(),
            scope,
            arity: CommandArity::NONE,
            advertised: true,
        }
    }

    /// Adds accepted spellings.
    #[must_use]
    pub fn with_aliases(mut self, aliases: &[&str]) -> Self {
        self.aliases = aliases.iter().map(|alias| (*alias).to_owned()).collect();
        self
    }

    /// Sets how many arguments the command accepts.
    #[must_use]
    pub const fn with_arity(mut self, arity: CommandArity) -> Self {
        self.arity = arity;
        self
    }

    /// Hides the command from `commands.list`.
    #[must_use]
    pub const fn hidden(mut self) -> Self {
        self.advertised = false;
        self
    }

    fn tokens(&self) -> impl Iterator<Item = &str> {
        std::iter::once(self.name.as_str()).chain(self.aliases.iter().map(String::as_str))
    }
}

/// A registry that rejected its own definition.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum CommandRegistryError {
    /// A command name or alias was blank.
    BlankToken(String),
    /// Two commands claimed the same name or alias.
    DuplicateToken(String),
    /// A command declared a maximum below its minimum.
    IncoherentArity(String),
}

impl Display for CommandRegistryError {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        match self {
            Self::BlankToken(name) => write!(formatter, "command {name} has a blank token"),
            Self::DuplicateToken(token) => write!(formatter, "duplicate command token {token}"),
            Self::IncoherentArity(name) => {
                write!(
                    formatter,
                    "command {name} accepts fewer arguments than it requires"
                )
            }
        }
    }
}

impl Error for CommandRegistryError {}

/// A rejected command line.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum CommandError {
    /// The line does not begin with a slash.
    NotACommand,
    /// The line was just a slash.
    EmptyCommand,
    /// No command answers to that token.
    Unknown(String),
    /// The caller lacks the required scope.
    Unauthorized {
        /// The canonical command name.
        command: String,
        /// The scope the caller needed.
        required: OperatorScope,
    },
    /// Too few arguments were supplied.
    MissingArguments {
        /// The canonical command name.
        command: String,
        /// The fewest arguments accepted.
        expected: usize,
        /// How many were supplied.
        received: usize,
    },
    /// Too many arguments were supplied.
    TooManyArguments {
        /// The canonical command name.
        command: String,
        /// The most arguments accepted.
        expected: usize,
        /// How many were supplied.
        received: usize,
    },
    /// An argument was present but unusable.
    InvalidArgument {
        /// The canonical command name.
        command: String,
        /// The offending argument.
        argument: String,
        /// Why it was rejected.
        reason: &'static str,
    },
    /// A quoted argument was never closed.
    UnterminatedQuote,
    /// The line ended with a lone backslash.
    DanglingEscape,
}

impl Display for CommandError {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        match self {
            Self::NotACommand => formatter.write_str("input is not a slash command"),
            Self::EmptyCommand => formatter.write_str("no command name was given"),
            Self::Unknown(token) => write!(formatter, "unknown command /{token}"),
            Self::Unauthorized { command, required } => {
                write!(formatter, "/{command} requires scope {required}")
            }
            Self::MissingArguments {
                command,
                expected,
                received,
            } => write!(
                formatter,
                "/{command} needs at least {expected} argument(s), got {received}"
            ),
            Self::TooManyArguments {
                command,
                expected,
                received,
            } => write!(
                formatter,
                "/{command} accepts at most {expected} argument(s), got {received}"
            ),
            Self::InvalidArgument {
                command,
                argument,
                reason,
            } => write!(formatter, "/{command} rejected '{argument}': {reason}"),
            Self::UnterminatedQuote => formatter.write_str("unterminated quoted argument"),
            Self::DanglingEscape => formatter.write_str("command line ends with an escape"),
        }
    }
}

impl Error for CommandError {}

/// A resolved, authorized, arity-checked command.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CommandInvocation {
    /// The canonical command name.
    pub name: String,
    /// The parsed arguments.
    pub arguments: Vec<String>,
}

/// What the runtime should do for an invocation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum CommandEffect {
    /// List every command the caller may run.
    ListCommands,
    /// Report the session's current state.
    ShowStatus,
    /// List every runnable tool.
    ListTools,
    /// Cancel the running turn.
    CancelTurn,
    /// Pause the running turn.
    PauseTurn,
    /// Resume the paused turn.
    ResumeTurn,
    /// Replace the session's durable goal.
    SetGoal(String),
    /// Report the session's durable goal.
    ShowGoal,
    /// Close the session's durable goal with a terminal status.
    CloseGoal(GoalStatus),
    /// Answer an approval request affirmatively.
    Approve {
        /// The request to answer.
        approval_id: String,
        /// Whether to remember the decision for the session.
        remember: bool,
    },
    /// Answer an approval request negatively.
    Deny {
        /// The request to answer.
        approval_id: String,
        /// Whether to remember the decision for the session.
        remember: bool,
    },
    /// Ask the context engine to shed context.
    CompactContext {
        /// The tokens to reclaim; `0` lets the engine choose.
        reclaim_tokens: u32,
    },
    /// Begin cooperative host suspension.
    SuspendPrepare {
        /// How long to wait for in-flight work to quiesce.
        drain_seconds: u64,
    },
    /// Report cooperative suspension state.
    SuspendStatus,
    /// End cooperative host suspension.
    SuspendResume {
        /// The lease to release.
        lease_id: String,
    },
    /// Override the provider model for the session.
    SetModel(String),
    /// A registry-defined command with no built-in meaning.
    Custom {
        /// The canonical command name.
        name: String,
        /// The parsed arguments.
        arguments: Vec<String>,
    },
}

/// Resolves command lines against a fixed vocabulary.
#[derive(Clone, Debug)]
pub struct CommandRegistry {
    specs: Vec<CommandSpec>,
    index: BTreeMap<String, usize>,
}

impl CommandRegistry {
    /// Builds a registry, rejecting blank, duplicate, or incoherent definitions.
    ///
    /// # Errors
    ///
    /// Returns [`CommandRegistryError`] describing the first offending definition.
    pub fn new(specs: Vec<CommandSpec>) -> Result<Self, CommandRegistryError> {
        let mut index = BTreeMap::new();

        for (position, spec) in specs.iter().enumerate() {
            if !spec.arity.is_coherent() {
                return Err(CommandRegistryError::IncoherentArity(spec.name.clone()));
            }
            for token in spec.tokens() {
                if token.trim().is_empty() {
                    return Err(CommandRegistryError::BlankToken(spec.name.clone()));
                }
                let key = token.to_ascii_lowercase();
                if index.insert(key.clone(), position).is_some() {
                    return Err(CommandRegistryError::DuplicateToken(key));
                }
            }
        }

        Ok(Self { specs, index })
    }

    /// Returns the built-in GTA Claw command vocabulary.
    ///
    /// # Panics
    ///
    /// Never: the built-in vocabulary is checked by a unit test in this module.
    #[must_use]
    pub fn builtin() -> Self {
        Self::new(builtin_commands()).expect("the built-in command vocabulary is well formed")
    }

    /// Returns every registered command in declaration order.
    #[must_use]
    pub fn specs(&self) -> &[CommandSpec] {
        &self.specs
    }

    /// Returns the advertised commands the caller is authorized to run.
    ///
    /// This backs the frozen `commands.list` Gateway method.
    #[must_use]
    pub fn list(&self, scopes: ScopeSet) -> Vec<&CommandSpec> {
        self.specs
            .iter()
            .filter(|spec| spec.advertised && scopes.contains(spec.scope))
            .collect()
    }

    /// Resolves a name or alias, case-insensitively.
    #[must_use]
    pub fn resolve(&self, token: &str) -> Option<&CommandSpec> {
        self.index
            .get(&token.to_ascii_lowercase())
            .and_then(|position| self.specs.get(*position))
    }

    /// Parses, authorizes, and arity-checks one command line.
    ///
    /// # Errors
    ///
    /// Returns the [`CommandError`] describing the first problem found, in this order: shape,
    /// tokenization, resolution, authorization, arity.
    pub fn parse(&self, line: &str, scopes: ScopeSet) -> Result<CommandInvocation, CommandError> {
        let trimmed = line.trim();
        let body = trimmed.strip_prefix('/').ok_or(CommandError::NotACommand)?;
        let mut tokens = tokenize(body)?.into_iter();
        let token = tokens.next().ok_or(CommandError::EmptyCommand)?;
        let spec = self
            .resolve(&token)
            .ok_or_else(|| CommandError::Unknown(token.clone()))?;

        if !scopes.contains(spec.scope) {
            return Err(CommandError::Unauthorized {
                command: spec.name.clone(),
                required: spec.scope,
            });
        }

        let arguments: Vec<String> = tokens.collect();
        if arguments.len() < spec.arity.minimum {
            return Err(CommandError::MissingArguments {
                command: spec.name.clone(),
                expected: spec.arity.minimum,
                received: arguments.len(),
            });
        }
        if let Some(maximum) = spec.arity.maximum
            && arguments.len() > maximum
        {
            return Err(CommandError::TooManyArguments {
                command: spec.name.clone(),
                expected: maximum,
                received: arguments.len(),
            });
        }

        Ok(CommandInvocation {
            name: spec.name.clone(),
            arguments,
        })
    }

    /// Lowers an invocation to the effect the runtime executes.
    ///
    /// # Errors
    ///
    /// Returns [`CommandError::InvalidArgument`] when an argument is present but unusable, such
    /// as a non-numeric token where a count is required.
    pub fn effect(invocation: &CommandInvocation) -> Result<CommandEffect, CommandError> {
        let arguments = invocation.arguments.as_slice();
        let effect = match invocation.name.as_str() {
            "help" => CommandEffect::ListCommands,
            "status" => CommandEffect::ShowStatus,
            "tools" => CommandEffect::ListTools,
            "cancel" => CommandEffect::CancelTurn,
            "pause" => CommandEffect::PauseTurn,
            "resume" => CommandEffect::ResumeTurn,
            "goal" => {
                if arguments.is_empty() {
                    CommandEffect::ShowGoal
                } else {
                    CommandEffect::SetGoal(arguments.join(" "))
                }
            }
            "goal-done" => CommandEffect::CloseGoal(GoalStatus::Achieved),
            "goal-drop" => CommandEffect::CloseGoal(GoalStatus::Abandoned),
            "approve" => CommandEffect::Approve {
                approval_id: required_argument(invocation, 0)?,
                remember: parse_remember(invocation, arguments.get(1))?,
            },
            "deny" => CommandEffect::Deny {
                approval_id: required_argument(invocation, 0)?,
                remember: parse_remember(invocation, arguments.get(1))?,
            },
            "compact" => CommandEffect::CompactContext {
                reclaim_tokens: parse_number(invocation, arguments.first(), 0)?,
            },
            "suspend" => CommandEffect::SuspendPrepare {
                drain_seconds: u64::from(parse_number(invocation, arguments.first(), 30)?),
            },
            "suspend-status" => CommandEffect::SuspendStatus,
            "resume-host" => CommandEffect::SuspendResume {
                lease_id: required_argument(invocation, 0)?,
            },
            "model" => CommandEffect::SetModel(required_argument(invocation, 0)?),
            _ => CommandEffect::Custom {
                name: invocation.name.clone(),
                arguments: invocation.arguments.clone(),
            },
        };

        Ok(effect)
    }
}

impl Default for CommandRegistry {
    fn default() -> Self {
        Self::builtin()
    }
}

fn required_argument(
    invocation: &CommandInvocation,
    position: usize,
) -> Result<String, CommandError> {
    invocation
        .arguments
        .get(position)
        .cloned()
        .ok_or_else(|| CommandError::MissingArguments {
            command: invocation.name.clone(),
            expected: position + 1,
            received: invocation.arguments.len(),
        })
}

fn parse_remember(
    invocation: &CommandInvocation,
    argument: Option<&String>,
) -> Result<bool, CommandError> {
    match argument.map(String::as_str) {
        None => Ok(false),
        Some(value) if value.eq_ignore_ascii_case("always") => Ok(true),
        Some(value) if value.eq_ignore_ascii_case("once") => Ok(false),
        Some(value) => Err(CommandError::InvalidArgument {
            command: invocation.name.clone(),
            argument: value.to_owned(),
            reason: "expected 'once' or 'always'",
        }),
    }
}

fn parse_number(
    invocation: &CommandInvocation,
    argument: Option<&String>,
    default: u32,
) -> Result<u32, CommandError> {
    match argument {
        None => Ok(default),
        Some(value) => value
            .parse::<u32>()
            .map_err(|_| CommandError::InvalidArgument {
                command: invocation.name.clone(),
                argument: value.clone(),
                reason: "expected a non-negative whole number",
            }),
    }
}

fn builtin_commands() -> Vec<CommandSpec> {
    vec![
        CommandSpec::new("help", "List the commands you can run", OperatorScope::Read)
            .with_aliases(&["?", "commands"]),
        CommandSpec::new("status", "Show the session state", OperatorScope::Read)
            .with_aliases(&["st"]),
        CommandSpec::new("tools", "List the runnable tools", OperatorScope::Read),
        CommandSpec::new("cancel", "Cancel the running turn", OperatorScope::Write)
            .with_aliases(&["abort", "stop"]),
        CommandSpec::new("pause", "Pause the running turn", OperatorScope::Write),
        CommandSpec::new("resume", "Resume the paused turn", OperatorScope::Write),
        CommandSpec::new("goal", "Show or set the durable goal", OperatorScope::Write)
            .with_arity(CommandArity::at_least(0)),
        CommandSpec::new("goal-done", "Mark the goal achieved", OperatorScope::Write),
        CommandSpec::new("goal-drop", "Abandon the goal", OperatorScope::Write),
        CommandSpec::new("approve", "Approve a tool call", OperatorScope::Approvals)
            .with_aliases(&["yes"])
            .with_arity(CommandArity::between(1, 2)),
        CommandSpec::new("deny", "Deny a tool call", OperatorScope::Approvals)
            .with_aliases(&["no"])
            .with_arity(CommandArity::between(1, 2)),
        CommandSpec::new(
            "compact",
            "Compact the session context",
            OperatorScope::Admin,
        )
        .with_arity(CommandArity::between(0, 1)),
        CommandSpec::new(
            "suspend",
            "Prepare cooperative suspension",
            OperatorScope::Admin,
        )
        .with_arity(CommandArity::between(0, 1)),
        CommandSpec::new(
            "suspend-status",
            "Show cooperative suspension state",
            OperatorScope::Read,
        ),
        CommandSpec::new(
            "resume-host",
            "Release a suspension lease",
            OperatorScope::Admin,
        )
        .with_arity(CommandArity::exactly(1)),
        CommandSpec::new("model", "Override the provider model", OperatorScope::Write)
            .with_arity(CommandArity::exactly(1)),
    ]
}

fn tokenize(input: &str) -> Result<Vec<String>, CommandError> {
    let mut tokens = Vec::new();
    let mut current = String::new();
    let mut has_token = false;
    let mut quoted = false;
    let mut characters = input.chars();

    while let Some(character) = characters.next() {
        match character {
            '\\' => {
                let escaped = characters.next().ok_or(CommandError::DanglingEscape)?;
                current.push(escaped);
                has_token = true;
            }
            '"' => {
                quoted = !quoted;
                has_token = true;
            }
            character if character.is_whitespace() && !quoted => {
                if has_token {
                    tokens.push(std::mem::take(&mut current));
                    has_token = false;
                }
            }
            character => {
                current.push(character);
                has_token = true;
            }
        }
    }

    if quoted {
        return Err(CommandError::UnterminatedQuote);
    }
    if has_token {
        tokens.push(current);
    }

    Ok(tokens)
}

/// Whether a directive carries a value.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DirectiveValue {
    /// The directive must not carry a value.
    Forbidden,
    /// The directive must carry a value.
    Required,
}

/// One directive the scanner recognises.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DirectiveSpec {
    /// The canonical name, without the leading bang.
    pub name: String,
    /// Additional accepted spellings.
    pub aliases: Vec<String>,
    /// A one-line human summary.
    pub summary: String,
    /// Whether the directive carries a value.
    pub value: DirectiveValue,
}

impl DirectiveSpec {
    /// Creates a directive specification.
    #[must_use]
    pub fn new(name: &str, summary: &str, value: DirectiveValue) -> Self {
        Self {
            name: name.to_owned(),
            aliases: Vec::new(),
            summary: summary.to_owned(),
            value,
        }
    }

    /// Adds accepted spellings.
    #[must_use]
    pub fn with_aliases(mut self, aliases: &[&str]) -> Self {
        self.aliases = aliases.iter().map(|alias| (*alias).to_owned()).collect();
        self
    }
}

/// One directive found in an input body.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Directive {
    /// The canonical directive name.
    pub name: String,
    /// The value, when the directive carries one.
    pub value: Option<String>,
}

/// The result of scanning an input body for directives.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct DirectiveScan {
    /// The directives found, in the order they appeared.
    pub directives: Vec<Directive>,
    /// The body with directive lines removed.
    pub body: String,
}

/// A rejected directive.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum DirectiveError {
    /// No directive answers to that name.
    Unknown(String),
    /// The directive requires a value and none was given.
    MissingValue(String),
    /// The directive forbids a value and one was given.
    UnexpectedValue(String),
    /// The same directive appeared twice.
    Duplicate(String),
    /// A registry contained a blank or duplicated token.
    Malformed(String),
}

impl Display for DirectiveError {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        match self {
            Self::Unknown(name) => write!(formatter, "unknown directive !{name}"),
            Self::MissingValue(name) => write!(formatter, "directive !{name} needs a value"),
            Self::UnexpectedValue(name) => {
                write!(formatter, "directive !{name} does not take a value")
            }
            Self::Duplicate(name) => write!(formatter, "directive !{name} appeared twice"),
            Self::Malformed(token) => write!(formatter, "malformed directive registry: {token}"),
        }
    }
}

impl Error for DirectiveError {}

/// Per-turn behaviour selected by directives.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TurnOptions {
    /// A provider model override.
    pub model: Option<String>,
    /// Whether the turn may call tools.
    pub tools_enabled: bool,
    /// Whether streaming text should be withheld from subscribers.
    pub quiet: bool,
    /// A durable goal to record before the turn runs.
    pub goal: Option<String>,
}

impl Default for TurnOptions {
    fn default() -> Self {
        Self {
            model: None,
            tools_enabled: true,
            quiet: false,
            goal: None,
        }
    }
}

/// Scans input bodies for inline directives.
#[derive(Clone, Debug)]
pub struct DirectiveRegistry {
    specs: Vec<DirectiveSpec>,
    index: BTreeMap<String, usize>,
}

impl DirectiveRegistry {
    /// Builds a registry, rejecting blank or duplicated tokens.
    ///
    /// # Errors
    ///
    /// Returns [`DirectiveError::Malformed`] naming the first offending token.
    pub fn new(specs: Vec<DirectiveSpec>) -> Result<Self, DirectiveError> {
        let mut index = BTreeMap::new();

        for (position, spec) in specs.iter().enumerate() {
            for token in
                std::iter::once(spec.name.as_str()).chain(spec.aliases.iter().map(String::as_str))
            {
                if token.trim().is_empty() {
                    return Err(DirectiveError::Malformed(spec.name.clone()));
                }
                let key = token.to_ascii_lowercase();
                if index.insert(key.clone(), position).is_some() {
                    return Err(DirectiveError::Malformed(key));
                }
            }
        }

        Ok(Self { specs, index })
    }

    /// Returns the built-in GTA Claw directive vocabulary.
    ///
    /// # Panics
    ///
    /// Never: the built-in vocabulary is checked by a unit test in this module.
    #[must_use]
    pub fn builtin() -> Self {
        Self::new(vec![
            DirectiveSpec::new(
                "model",
                "Override the provider model for this turn",
                DirectiveValue::Required,
            ),
            DirectiveSpec::new(
                "no-tools",
                "Run this turn without tools",
                DirectiveValue::Forbidden,
            )
            .with_aliases(&["tools-off"]),
            DirectiveSpec::new(
                "quiet",
                "Withhold streaming text from subscribers",
                DirectiveValue::Forbidden,
            ),
            DirectiveSpec::new(
                "goal",
                "Record a durable goal before running",
                DirectiveValue::Required,
            ),
        ])
        .expect("the built-in directive vocabulary is well formed")
    }

    /// Returns every registered directive in declaration order.
    #[must_use]
    pub fn specs(&self) -> &[DirectiveSpec] {
        &self.specs
    }

    /// Splits an input body into directives and remaining text.
    ///
    /// A directive owns a whole line and starts with `!`. Lines inside fenced code blocks
    /// (delimited by ``` or `~~~`) are never directives, and a line starting with `\!` is body
    /// text with the escape removed. Values may be written `!name value` or `!name=value`.
    ///
    /// # Errors
    ///
    /// Returns [`DirectiveError`] for unknown names, missing or unexpected values, and repeats.
    pub fn scan(&self, input: &str) -> Result<DirectiveScan, DirectiveError> {
        let mut directives: Vec<Directive> = Vec::new();
        let mut body_lines: Vec<String> = Vec::new();
        let mut fence: Option<String> = None;

        for raw_line in input.split('\n') {
            let line = raw_line.strip_suffix('\r').unwrap_or(raw_line);
            let trimmed = line.trim_start();

            if let Some(open) = fence.clone() {
                if trimmed.starts_with(open.as_str()) {
                    fence = None;
                }
                body_lines.push(line.to_owned());
                continue;
            }
            if let Some(marker) = fence_marker(trimmed) {
                fence = Some(marker);
                body_lines.push(line.to_owned());
                continue;
            }
            if let Some(escaped) = trimmed.strip_prefix("\\!") {
                body_lines.push(format!("!{escaped}"));
                continue;
            }

            match self.parse_directive_line(trimmed)? {
                Some(directive) => {
                    if directives
                        .iter()
                        .any(|existing| existing.name == directive.name)
                    {
                        return Err(DirectiveError::Duplicate(directive.name));
                    }
                    directives.push(directive);
                }
                None => body_lines.push(line.to_owned()),
            }
        }

        while body_lines
            .first()
            .is_some_and(|line| line.trim().is_empty())
        {
            body_lines.remove(0);
        }
        while body_lines.last().is_some_and(|line| line.trim().is_empty()) {
            body_lines.pop();
        }

        Ok(DirectiveScan {
            directives,
            body: body_lines.join("\n"),
        })
    }

    /// Lowers directives into the options one turn runs with.
    ///
    /// # Errors
    ///
    /// Returns [`DirectiveError::Unknown`] when a directive is not in this registry.
    pub fn apply(&self, directives: &[Directive]) -> Result<TurnOptions, DirectiveError> {
        let mut options = TurnOptions::default();

        for directive in directives {
            if !self.index.contains_key(&directive.name) {
                return Err(DirectiveError::Unknown(directive.name.clone()));
            }
            match directive.name.as_str() {
                "model" => {
                    options.model = directive.value.clone();
                }
                "no-tools" => options.tools_enabled = false,
                "quiet" => options.quiet = true,
                "goal" => options.goal = directive.value.clone(),
                _ => {}
            }
        }

        Ok(options)
    }

    fn parse_directive_line(&self, trimmed: &str) -> Result<Option<Directive>, DirectiveError> {
        let Some(rest) = trimmed.strip_prefix('!') else {
            return Ok(None);
        };
        if !rest.starts_with(|c: char| c.is_ascii_alphanumeric()) {
            return Ok(None);
        }

        let (token, value) = match rest.split_once(['=', ' ']) {
            Some((token, value)) => {
                let value = value.trim();
                (
                    token.trim(),
                    if value.is_empty() {
                        None
                    } else {
                        Some(value.to_owned())
                    },
                )
            }
            None => (rest.trim(), None),
        };

        let position = self
            .index
            .get(&token.to_ascii_lowercase())
            .ok_or_else(|| DirectiveError::Unknown(token.to_owned()))?;
        let spec = &self.specs[*position];

        match (spec.value, value.is_some()) {
            (DirectiveValue::Required, false) => {
                Err(DirectiveError::MissingValue(spec.name.clone()))
            }
            (DirectiveValue::Forbidden, true) => {
                Err(DirectiveError::UnexpectedValue(spec.name.clone()))
            }
            _ => Ok(Some(Directive {
                name: spec.name.clone(),
                value,
            })),
        }
    }
}

impl Default for DirectiveRegistry {
    fn default() -> Self {
        Self::builtin()
    }
}

fn fence_marker(trimmed: &str) -> Option<String> {
    for marker in ["```", "~~~"] {
        if trimmed.starts_with(marker) {
            return Some(marker.to_owned());
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use claw_application::model::goal::GoalStatus;

    use super::{
        CommandArity, CommandEffect, CommandError, CommandInvocation, CommandRegistry,
        CommandRegistryError, CommandSpec, Directive, DirectiveError, DirectiveRegistry,
        DirectiveScan, DirectiveSpec, DirectiveValue, OperatorScope, ScopeSet, TurnOptions,
    };

    fn all_scopes() -> ScopeSet {
        ScopeSet::all()
    }

    #[test]
    fn operator_scope_labels_match_the_frozen_gateway_inventory() {
        let labels: Vec<&str> = OperatorScope::ALL.iter().map(|s| s.label()).collect();

        assert_eq!(
            labels,
            vec![
                "operator.read",
                "operator.write",
                "operator.admin",
                "operator.approvals",
                "operator.pairing",
                "operator.talk.secrets",
            ]
        );
    }

    #[test]
    fn scope_sets_are_exact_and_do_not_imply() {
        let admin_only = ScopeSet::EMPTY.with(OperatorScope::Admin);

        assert!(admin_only.contains(OperatorScope::Admin));
        assert!(!admin_only.contains(OperatorScope::Read));
        assert!(!admin_only.contains(OperatorScope::Write));
        assert_eq!(admin_only.labels(), vec!["operator.admin"]);
        assert_eq!(ScopeSet::all().labels().len(), 6);
        assert_eq!(
            ScopeSet::all().without(OperatorScope::Read).labels(),
            vec![
                "operator.write",
                "operator.admin",
                "operator.approvals",
                "operator.pairing",
                "operator.talk.secrets",
            ]
        );
    }

    #[test]
    fn scope_sets_collect_from_iterators() {
        let set: ScopeSet = [OperatorScope::Read, OperatorScope::Approvals]
            .into_iter()
            .collect();

        assert_eq!(set.labels(), vec!["operator.read", "operator.approvals"]);
    }

    #[test]
    fn the_builtin_registry_pins_names_aliases_and_scopes() {
        let registry = CommandRegistry::builtin();
        let rows: Vec<(String, Vec<String>, &'static str)> = registry
            .specs()
            .iter()
            .map(|spec| (spec.name.clone(), spec.aliases.clone(), spec.scope.label()))
            .collect();

        assert_eq!(
            rows,
            vec![
                (
                    "help".to_owned(),
                    vec!["?".to_owned(), "commands".to_owned()],
                    "operator.read"
                ),
                ("status".to_owned(), vec!["st".to_owned()], "operator.read"),
                ("tools".to_owned(), Vec::new(), "operator.read"),
                (
                    "cancel".to_owned(),
                    vec!["abort".to_owned(), "stop".to_owned()],
                    "operator.write"
                ),
                ("pause".to_owned(), Vec::new(), "operator.write"),
                ("resume".to_owned(), Vec::new(), "operator.write"),
                ("goal".to_owned(), Vec::new(), "operator.write"),
                ("goal-done".to_owned(), Vec::new(), "operator.write"),
                ("goal-drop".to_owned(), Vec::new(), "operator.write"),
                (
                    "approve".to_owned(),
                    vec!["yes".to_owned()],
                    "operator.approvals"
                ),
                (
                    "deny".to_owned(),
                    vec!["no".to_owned()],
                    "operator.approvals"
                ),
                ("compact".to_owned(), Vec::new(), "operator.admin"),
                ("suspend".to_owned(), Vec::new(), "operator.admin"),
                ("suspend-status".to_owned(), Vec::new(), "operator.read"),
                ("resume-host".to_owned(), Vec::new(), "operator.admin"),
                ("model".to_owned(), Vec::new(), "operator.write"),
            ]
        );
    }

    #[test]
    fn aliases_resolve_case_insensitively_to_the_canonical_name() {
        let registry = CommandRegistry::builtin();

        for token in ["help", "HELP", "?", "Commands"] {
            let spec = registry
                .resolve(token)
                .unwrap_or_else(|| panic!("{token} must resolve"));
            assert_eq!(spec.name, "help");
        }
        assert_eq!(registry.resolve("nope"), None);
    }

    #[test]
    fn listing_filters_by_scope_and_advertisement() {
        let registry = CommandRegistry::new(vec![
            CommandSpec::new("visible", "seen", OperatorScope::Read),
            CommandSpec::new("secret", "hidden", OperatorScope::Read).hidden(),
            CommandSpec::new("elevated", "admin only", OperatorScope::Admin),
        ])
        .expect("registry is well formed");

        let read_only = ScopeSet::EMPTY.with(OperatorScope::Read);
        let names: Vec<&str> = registry
            .list(read_only)
            .into_iter()
            .map(|spec| spec.name.as_str())
            .collect();

        assert_eq!(names, vec!["visible"]);

        let both: Vec<&str> = registry
            .list(read_only.with(OperatorScope::Admin))
            .into_iter()
            .map(|spec| spec.name.as_str())
            .collect();
        assert_eq!(both, vec!["visible", "elevated"]);
    }

    #[test]
    fn registries_reject_duplicate_blank_and_incoherent_definitions() {
        let duplicate = CommandRegistry::new(vec![
            CommandSpec::new("a", "one", OperatorScope::Read),
            CommandSpec::new("b", "two", OperatorScope::Read).with_aliases(&["A"]),
        ])
        .expect_err("a duplicated alias must be rejected");
        assert_eq!(
            duplicate,
            CommandRegistryError::DuplicateToken("a".to_owned())
        );

        let blank = CommandRegistry::new(vec![
            CommandSpec::new("a", "one", OperatorScope::Read).with_aliases(&["  "]),
        ])
        .expect_err("a blank alias must be rejected");
        assert_eq!(blank, CommandRegistryError::BlankToken("a".to_owned()));

        let incoherent = CommandRegistry::new(vec![
            CommandSpec::new("a", "one", OperatorScope::Read).with_arity(CommandArity {
                minimum: 3,
                maximum: Some(1),
            }),
        ])
        .expect_err("an inverted arity must be rejected");
        assert_eq!(
            incoherent,
            CommandRegistryError::IncoherentArity("a".to_owned())
        );
    }

    #[test]
    fn plain_text_is_not_a_command() {
        let registry = CommandRegistry::builtin();

        assert_eq!(
            registry.parse("hello there", all_scopes()),
            Err(CommandError::NotACommand)
        );
        assert_eq!(
            registry.parse("  /  ", all_scopes()),
            Err(CommandError::EmptyCommand)
        );
        assert_eq!(
            registry.parse("/nope", all_scopes()),
            Err(CommandError::Unknown("nope".to_owned()))
        );
    }

    #[test]
    fn authorization_precedes_arity_checking() {
        let registry = CommandRegistry::builtin();
        let no_approvals = ScopeSet::all().without(OperatorScope::Approvals);

        assert_eq!(
            registry.parse("/approve", no_approvals),
            Err(CommandError::Unauthorized {
                command: "approve".to_owned(),
                required: OperatorScope::Approvals,
            })
        );
        assert_eq!(
            registry.parse("/approve", all_scopes()),
            Err(CommandError::MissingArguments {
                command: "approve".to_owned(),
                expected: 1,
                received: 0,
            })
        );
    }

    #[test]
    fn arity_ceilings_are_enforced() {
        let registry = CommandRegistry::builtin();

        assert_eq!(
            registry.parse("/approve a b c", all_scopes()),
            Err(CommandError::TooManyArguments {
                command: "approve".to_owned(),
                expected: 2,
                received: 3,
            })
        );
        assert_eq!(
            registry.parse("/status extra", all_scopes()),
            Err(CommandError::TooManyArguments {
                command: "status".to_owned(),
                expected: 0,
                received: 1,
            })
        );
    }

    #[test]
    fn quoted_and_escaped_arguments_survive_tokenization() {
        let registry = CommandRegistry::builtin();

        assert_eq!(
            registry
                .parse("/goal \"ship the runtime\" today", all_scopes())
                .expect("goal accepts free text"),
            CommandInvocation {
                name: "goal".to_owned(),
                arguments: vec!["ship the runtime".to_owned(), "today".to_owned()],
            }
        );
        assert_eq!(
            registry
                .parse("/model gpt\\ 5", all_scopes())
                .expect("escapes join tokens"),
            CommandInvocation {
                name: "model".to_owned(),
                arguments: vec!["gpt 5".to_owned()],
            }
        );
        assert_eq!(
            registry.parse("/goal \"unclosed", all_scopes()),
            Err(CommandError::UnterminatedQuote)
        );
        assert_eq!(
            registry.parse("/model x\\", all_scopes()),
            Err(CommandError::DanglingEscape)
        );
    }

    #[test]
    fn empty_quotes_produce_an_empty_argument() {
        let registry = CommandRegistry::builtin();

        assert_eq!(
            registry
                .parse("/model \"\"", all_scopes())
                .expect("empty quoted arguments are tokens"),
            CommandInvocation {
                name: "model".to_owned(),
                arguments: vec![String::new()],
            }
        );
    }

    #[test]
    fn effects_are_pinned_for_every_builtin_command() {
        let registry = CommandRegistry::builtin();
        let cases: Vec<(&str, CommandEffect)> = vec![
            ("/help", CommandEffect::ListCommands),
            ("/status", CommandEffect::ShowStatus),
            ("/tools", CommandEffect::ListTools),
            ("/abort", CommandEffect::CancelTurn),
            ("/pause", CommandEffect::PauseTurn),
            ("/resume", CommandEffect::ResumeTurn),
            ("/goal", CommandEffect::ShowGoal),
            (
                "/goal ship it",
                CommandEffect::SetGoal("ship it".to_owned()),
            ),
            ("/goal-done", CommandEffect::CloseGoal(GoalStatus::Achieved)),
            (
                "/goal-drop",
                CommandEffect::CloseGoal(GoalStatus::Abandoned),
            ),
            (
                "/yes approval-1",
                CommandEffect::Approve {
                    approval_id: "approval-1".to_owned(),
                    remember: false,
                },
            ),
            (
                "/approve approval-1 always",
                CommandEffect::Approve {
                    approval_id: "approval-1".to_owned(),
                    remember: true,
                },
            ),
            (
                "/deny approval-2 ALWAYS",
                CommandEffect::Deny {
                    approval_id: "approval-2".to_owned(),
                    remember: true,
                },
            ),
            (
                "/no approval-2 once",
                CommandEffect::Deny {
                    approval_id: "approval-2".to_owned(),
                    remember: false,
                },
            ),
            (
                "/compact",
                CommandEffect::CompactContext { reclaim_tokens: 0 },
            ),
            (
                "/compact 512",
                CommandEffect::CompactContext {
                    reclaim_tokens: 512,
                },
            ),
            (
                "/suspend",
                CommandEffect::SuspendPrepare { drain_seconds: 30 },
            ),
            (
                "/suspend 5",
                CommandEffect::SuspendPrepare { drain_seconds: 5 },
            ),
            ("/suspend-status", CommandEffect::SuspendStatus),
            (
                "/resume-host lease-9",
                CommandEffect::SuspendResume {
                    lease_id: "lease-9".to_owned(),
                },
            ),
            ("/model gpt-x", CommandEffect::SetModel("gpt-x".to_owned())),
        ];

        for (line, expected) in cases {
            let invocation = registry
                .parse(line, all_scopes())
                .unwrap_or_else(|error| panic!("{line} must parse: {error}"));
            let effect = CommandRegistry::effect(&invocation)
                .unwrap_or_else(|error| panic!("{line} must lower: {error}"));
            assert_eq!(effect, expected, "{line}");
        }
    }

    #[test]
    fn unusable_arguments_are_reported_rather_than_guessed() {
        let registry = CommandRegistry::builtin();

        let invocation = registry
            .parse("/approve approval-1 maybe", all_scopes())
            .expect("arity allows two arguments");
        assert_eq!(
            CommandRegistry::effect(&invocation),
            Err(CommandError::InvalidArgument {
                command: "approve".to_owned(),
                argument: "maybe".to_owned(),
                reason: "expected 'once' or 'always'",
            })
        );

        let invocation = registry
            .parse("/compact lots", all_scopes())
            .expect("arity allows one argument");
        assert_eq!(
            CommandRegistry::effect(&invocation),
            Err(CommandError::InvalidArgument {
                command: "compact".to_owned(),
                argument: "lots".to_owned(),
                reason: "expected a non-negative whole number",
            })
        );
    }

    #[test]
    fn registry_defined_commands_lower_to_custom_effects() {
        let registry = CommandRegistry::new(vec![
            CommandSpec::new("deploy", "custom", OperatorScope::Admin)
                .with_arity(CommandArity::at_least(0)),
        ])
        .expect("registry is well formed");
        let invocation = registry
            .parse("/deploy prod now", all_scopes())
            .expect("custom command parses");

        assert_eq!(
            CommandRegistry::effect(&invocation).expect("custom commands lower"),
            CommandEffect::Custom {
                name: "deploy".to_owned(),
                arguments: vec!["prod".to_owned(), "now".to_owned()],
            }
        );
    }

    #[test]
    fn command_errors_render_actionable_text() {
        assert_eq!(
            CommandError::Unknown("zap".to_owned()).to_string(),
            "unknown command /zap"
        );
        assert_eq!(
            CommandError::Unauthorized {
                command: "compact".to_owned(),
                required: OperatorScope::Admin,
            }
            .to_string(),
            "/compact requires scope operator.admin"
        );
        assert_eq!(
            CommandError::MissingArguments {
                command: "model".to_owned(),
                expected: 1,
                received: 0,
            }
            .to_string(),
            "/model needs at least 1 argument(s), got 0"
        );
        assert_eq!(
            CommandError::TooManyArguments {
                command: "status".to_owned(),
                expected: 0,
                received: 2,
            }
            .to_string(),
            "/status accepts at most 0 argument(s), got 2"
        );
        assert_eq!(
            CommandError::InvalidArgument {
                command: "compact".to_owned(),
                argument: "x".to_owned(),
                reason: "expected a non-negative whole number",
            }
            .to_string(),
            "/compact rejected 'x': expected a non-negative whole number"
        );
        assert_eq!(
            CommandError::NotACommand.to_string(),
            "input is not a slash command"
        );
        assert_eq!(
            CommandError::EmptyCommand.to_string(),
            "no command name was given"
        );
        assert_eq!(
            CommandError::UnterminatedQuote.to_string(),
            "unterminated quoted argument"
        );
        assert_eq!(
            CommandError::DanglingEscape.to_string(),
            "command line ends with an escape"
        );
    }

    #[test]
    fn directives_are_lifted_out_of_the_body() {
        let registry = DirectiveRegistry::builtin();
        let scan = registry
            .scan("!model gpt-x\n!no-tools\nplease summarise\nthe log")
            .expect("directives parse");

        assert_eq!(
            scan,
            DirectiveScan {
                directives: vec![
                    Directive {
                        name: "model".to_owned(),
                        value: Some("gpt-x".to_owned()),
                    },
                    Directive {
                        name: "no-tools".to_owned(),
                        value: None,
                    },
                ],
                body: "please summarise\nthe log".to_owned(),
            }
        );
    }

    #[test]
    fn directives_accept_equals_and_space_separated_values() {
        let registry = DirectiveRegistry::builtin();

        assert_eq!(
            registry
                .scan("!model=gpt-x\nbody")
                .expect("equals form parses")
                .directives,
            vec![Directive {
                name: "model".to_owned(),
                value: Some("gpt-x".to_owned()),
            }]
        );
        assert_eq!(
            registry
                .scan("!goal ship the runtime\nbody")
                .expect("space form parses")
                .directives,
            vec![Directive {
                name: "goal".to_owned(),
                value: Some("ship the runtime".to_owned()),
            }]
        );
    }

    #[test]
    fn aliases_normalise_to_the_canonical_directive_name() {
        let registry = DirectiveRegistry::builtin();

        assert_eq!(
            registry
                .scan("!TOOLS-OFF\nbody")
                .expect("aliases parse")
                .directives,
            vec![Directive {
                name: "no-tools".to_owned(),
                value: None,
            }]
        );
    }

    #[test]
    fn fenced_blocks_and_escapes_protect_literal_bangs() {
        let registry = DirectiveRegistry::builtin();
        let scan = registry
            .scan("```sh\n!model gpt-x\n```\n\\!model gpt-y\ntail")
            .expect("fences and escapes are body text");

        assert_eq!(scan.directives, Vec::new());
        assert_eq!(scan.body, "```sh\n!model gpt-x\n```\n!model gpt-y\ntail");
    }

    #[test]
    fn tilde_fences_are_honoured_too() {
        let registry = DirectiveRegistry::builtin();
        let scan = registry
            .scan("~~~\n!quiet\n~~~")
            .expect("tilde fences are body text");

        assert_eq!(scan.directives, Vec::new());
        assert_eq!(scan.body, "~~~\n!quiet\n~~~");
    }

    #[test]
    fn a_bang_that_is_not_a_directive_stays_in_the_body() {
        let registry = DirectiveRegistry::builtin();
        let scan = registry.scan("!!! urgent\n! spaced").expect("body text");

        assert_eq!(scan.directives, Vec::new());
        assert_eq!(scan.body, "!!! urgent\n! spaced");
    }

    #[test]
    fn directive_problems_are_reported_precisely() {
        let registry = DirectiveRegistry::builtin();

        assert_eq!(
            registry.scan("!teleport now"),
            Err(DirectiveError::Unknown("teleport".to_owned()))
        );
        assert_eq!(
            registry.scan("!model"),
            Err(DirectiveError::MissingValue("model".to_owned()))
        );
        assert_eq!(
            registry.scan("!quiet loudly"),
            Err(DirectiveError::UnexpectedValue("quiet".to_owned()))
        );
        assert_eq!(
            registry.scan("!quiet\n!quiet"),
            Err(DirectiveError::Duplicate("quiet".to_owned()))
        );
        let duplicate = DirectiveRegistry::new(vec![
            DirectiveSpec::new("a", "one", DirectiveValue::Forbidden),
            DirectiveSpec::new("b", "two", DirectiveValue::Forbidden).with_aliases(&["A"]),
        ])
        .expect_err("a duplicated alias must be rejected");
        assert_eq!(duplicate, DirectiveError::Malformed("a".to_owned()));
    }

    #[test]
    fn directives_lower_into_turn_options() {
        let registry = DirectiveRegistry::builtin();
        let scan = registry
            .scan("!model gpt-x\n!no-tools\n!quiet\n!goal finish the crate\nrun it")
            .expect("directives parse");
        let options = registry.apply(&scan.directives).expect("directives apply");

        assert_eq!(
            options,
            TurnOptions {
                model: Some("gpt-x".to_owned()),
                tools_enabled: false,
                quiet: true,
                goal: Some("finish the crate".to_owned()),
            }
        );
        assert_eq!(scan.body, "run it");
    }

    #[test]
    fn plain_input_produces_default_options() {
        let registry = DirectiveRegistry::builtin();
        let scan = registry.scan("just do it").expect("plain input parses");
        let options = registry.apply(&scan.directives).expect("directives apply");

        assert_eq!(
            options,
            TurnOptions {
                model: None,
                tools_enabled: true,
                quiet: false,
                goal: None,
            }
        );
        assert_eq!(scan.body, "just do it");
    }

    #[test]
    fn applying_a_foreign_directive_is_rejected() {
        let registry = DirectiveRegistry::builtin();

        assert_eq!(
            registry.apply(&[Directive {
                name: "teleport".to_owned(),
                value: None,
            }]),
            Err(DirectiveError::Unknown("teleport".to_owned()))
        );
    }

    #[test]
    fn surrounding_blank_lines_are_trimmed_from_the_body() {
        let registry = DirectiveRegistry::builtin();
        let scan = registry
            .scan("\n\n!quiet\n\nmiddle\n\n\n")
            .expect("directives parse");

        assert_eq!(scan.body, "middle");
    }

    #[test]
    fn directive_errors_render_actionable_text() {
        assert_eq!(
            DirectiveError::Unknown("zap".to_owned()).to_string(),
            "unknown directive !zap"
        );
        assert_eq!(
            DirectiveError::MissingValue("model".to_owned()).to_string(),
            "directive !model needs a value"
        );
        assert_eq!(
            DirectiveError::UnexpectedValue("quiet".to_owned()).to_string(),
            "directive !quiet does not take a value"
        );
        assert_eq!(
            DirectiveError::Duplicate("quiet".to_owned()).to_string(),
            "directive !quiet appeared twice"
        );
        assert_eq!(
            DirectiveError::Malformed("a".to_owned()).to_string(),
            "malformed directive registry: a"
        );
    }
}

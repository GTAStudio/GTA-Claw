//! Channel-level command surface and inbound classification.
//!
//! Upstream handles a small set of commands inside the channel layer before
//! anything reaches a conversation engine. Reproducing that split here keeps
//! two properties: a command never becomes a conversation turn by accident,
//! and a channel that cannot receive text cannot claim to offer commands.

use claw_channel_sdk::{
    CommandDispatchError, CommandInvocation, CommandParseError, CommandRegistry, CommandSpec,
    InboundMessage, parse_command,
};

use crate::descriptor;
use crate::routing::{RoutingError, supports_inbound};

/// Commands offered on every inbound-capable official channel.
///
/// The frozen channel inventory records identity and provenance only, so the
/// command surface is crate-owned policy exactly like [`crate::AuthMode`]. It
/// is declared once and applied uniformly rather than per channel, because a
/// per-channel table would let one channel silently drift into answering a
/// command the rest do not.
static COMMON_COMMANDS: [CommandSpec; 4] = [
    CommandSpec {
        name: "help",
        summary: "List the commands this channel offers.",
        min_arguments: 0,
        max_arguments: 1,
    },
    CommandSpec {
        name: "login",
        summary: "Start device-code authentication for this conversation.",
        min_arguments: 0,
        max_arguments: 0,
    },
    CommandSpec {
        name: "status",
        summary: "Report the connection and account state of this channel.",
        min_arguments: 0,
        max_arguments: 0,
    },
    CommandSpec {
        name: "reset",
        summary: "Clear the conversation session bound to this channel.",
        min_arguments: 0,
        max_arguments: 0,
    },
];

static NO_COMMANDS: [CommandSpec; 0] = [];

/// Returns the commands one registered channel offers.
///
/// A channel with no inbound implementation offers an empty surface rather than
/// the common one, because it can never receive the text that would invoke it.
pub fn command_surface(channel_id: &str) -> Result<&'static [CommandSpec], RoutingError> {
    let entry = descriptor(channel_id).ok_or(RoutingError::UnknownChannel)?;
    Ok(if supports_inbound(entry) {
        &COMMON_COMMANDS
    } else {
        &NO_COMMANDS
    })
}

/// Returns a validated command registry for one registered channel.
pub fn command_registry(channel_id: &str) -> Result<CommandRegistry, RoutingError> {
    CommandRegistry::new(command_surface(channel_id)?)
        .map_err(|_| RoutingError::InvalidCommandTable)
}

/// What the channel layer decided one inbound message is.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum InboundOutcome {
    /// A command this channel offers, with its arity already checked.
    Command {
        /// The parsed invocation.
        invocation: CommandInvocation,
        /// The matching declaration.
        spec: &'static CommandSpec,
    },
    /// A syntactically valid command this channel will not run.
    RejectedCommand {
        /// The parsed invocation.
        invocation: CommandInvocation,
        /// Why it was refused.
        error: CommandDispatchError,
    },
    /// Text that begins like a command but cannot be parsed as one.
    MalformedCommand(CommandParseError),
    /// Ordinary content for a conversation engine.
    Conversation {
        /// Message text, absent when the message carried only attachments.
        text: Option<String>,
    },
}

/// Classifies one inbound message as a command or as conversation content.
///
/// `bot_mention` is the addressable name of the account that received the
/// message, when the provider has one. A `/help@other-bot` invocation is
/// refused rather than executed.
pub fn classify_inbound(
    message: &InboundMessage,
    bot_mention: Option<&str>,
) -> Result<InboundOutcome, RoutingError> {
    message.validate().map_err(RoutingError::InvalidMessage)?;
    let entry = descriptor(&message.channel_id).ok_or(RoutingError::UnknownChannel)?;
    if !supports_inbound(entry) {
        return Err(RoutingError::InboundUnsupported);
    }
    let registry = command_registry(entry.id)?;
    let text = message.text.as_deref();
    let Some(body) = text.map(str::trim).filter(|body| body.starts_with('/')) else {
        return Ok(InboundOutcome::Conversation {
            text: text.map(str::to_owned),
        });
    };
    let invocation = match parse_command(body) {
        Ok(invocation) => invocation,
        Err(error) => return Ok(InboundOutcome::MalformedCommand(error)),
    };
    Ok(match registry.resolve(&invocation, bot_mention) {
        Ok(spec) => InboundOutcome::Command { invocation, spec },
        Err(error) => InboundOutcome::RejectedCommand { invocation, error },
    })
}

/// Renders the help reply for one registered channel.
pub fn help_text(channel_id: &str) -> Result<String, RoutingError> {
    let specs = command_surface(channel_id)?;
    if specs.is_empty() {
        return Ok(format!("{channel_id} offers no commands."));
    }
    let mut rendered = String::new();
    for spec in specs {
        rendered.push('/');
        rendered.push_str(spec.name);
        rendered.push_str(" - ");
        rendered.push_str(spec.summary);
        rendered.push('\n');
    }
    Ok(rendered)
}

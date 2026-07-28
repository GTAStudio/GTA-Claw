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

use crate::routing::{RoutingError, supports_inbound};
use crate::{ChannelDescriptor, descriptor};

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
///
/// # Errors
///
/// Returns [`RoutingError::UnknownChannel`] when `channel_id` is not one of the
/// 29 frozen official identifiers.
pub fn command_surface(channel_id: &str) -> Result<&'static [CommandSpec], RoutingError> {
    let entry = descriptor(channel_id).ok_or(RoutingError::UnknownChannel)?;
    Ok(surface_of(entry))
}

fn surface_of(entry: &ChannelDescriptor) -> &'static [CommandSpec] {
    if supports_inbound(entry) {
        &COMMON_COMMANDS
    } else {
        &NO_COMMANDS
    }
}

/// Returns a validated command registry for one registered channel.
///
/// # Errors
///
/// - [`RoutingError::UnknownChannel`] when `channel_id` is not one of the 29
///   frozen official identifiers.
/// - [`RoutingError::InvalidCommandTable`] when this crate's own command table
///   fails [`CommandRegistry::new`]. That is a defect in the table above, not
///   in the caller's input, and it disables commands for the channel rather
///   than answering them inconsistently.
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
///
/// # Errors
///
/// - [`RoutingError::InvalidMessage`] when the message fails common validation,
///   carrying the exact reason.
/// - [`RoutingError::UnknownChannel`] when the message names a channel that is
///   not in the frozen registry.
/// - [`RoutingError::InboundUnsupported`] when the named channel implements no
///   inbound direction, so it can offer no commands and classify no text.
/// - [`RoutingError::InvalidCommandTable`] when this crate's own command table
///   is malformed.
///
/// A command this channel will not run is not an error: it is an
/// [`InboundOutcome::RejectedCommand`] or [`InboundOutcome::MalformedCommand`],
/// so the caller can answer the sender instead of dropping the message.
pub fn classify_inbound(
    message: &InboundMessage,
    bot_mention: Option<&str>,
) -> Result<InboundOutcome, RoutingError> {
    message.validate().map_err(RoutingError::InvalidMessage)?;
    let entry = descriptor(&message.channel_id).ok_or(RoutingError::UnknownChannel)?;
    if !supports_inbound(entry) {
        return Err(RoutingError::InboundUnsupported);
    }
    let registry =
        CommandRegistry::new(surface_of(entry)).map_err(|_| RoutingError::InvalidCommandTable)?;
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
///
/// # Errors
///
/// Returns [`RoutingError::UnknownChannel`] when `channel_id` is not one of the
/// 29 frozen official identifiers. A registered channel that offers no commands
/// renders a sentence saying so rather than failing.
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

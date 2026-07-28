//! Channel-level command contracts over the frozen official channel registry.

mod support;

use std::collections::BTreeSet;

use claw_channel_sdk::{
    CommandDispatchError, CommandParseError, InboundMessage, InvalidMessageReason,
};
use claw_channels::{
    ExchangeSupport, InboundOutcome, RoutingError, classify_inbound, command_registry,
    command_surface, descriptor, exchange_support, help_text,
};

use support::frozen_channel_ids;

fn inbound(channel_id: &str, text: &str) -> InboundMessage {
    InboundMessage {
        id: "message-1".to_owned(),
        channel_id: channel_id.to_owned(),
        account_id: "primary".to_owned(),
        conversation_id: "room-1".to_owned(),
        sender_id: "sender-1".to_owned(),
        text: Some(text.to_owned()),
        attachments: Vec::new(),
        received_at_unix_ms: 9,
    }
}

#[test]
fn every_frozen_channel_declares_a_command_surface_matching_its_inbound_support() {
    let frozen_ids = frozen_channel_ids();
    let mut with_commands = BTreeSet::new();

    for id in &frozen_ids {
        let entry = descriptor(id).unwrap_or_else(|| panic!("frozen channel {id} is unregistered"));
        let surface = command_surface(id).expect("registered channel");
        let registry = command_registry(id).expect("valid command table");
        assert_eq!(registry.specs(), surface, "{id}");

        let names = surface
            .iter()
            .map(|spec| spec.name)
            .collect::<BTreeSet<_>>();
        assert_eq!(
            names.len(),
            surface.len(),
            "{id} declares a duplicate command"
        );
        for spec in surface {
            assert!(
                spec.min_arguments <= spec.max_arguments,
                "{id}/{}",
                spec.name
            );
            assert!(!spec.summary.is_empty(), "{id}/{}", spec.name);
        }

        match exchange_support(id).expect("registered channel") {
            ExchangeSupport::InboundOnly | ExchangeSupport::Bidirectional => {
                assert_eq!(
                    names,
                    BTreeSet::from(["help", "login", "reset", "status"]),
                    "{id}"
                );
                with_commands.insert(entry.id);
            }
            ExchangeSupport::OutboundOnly | ExchangeSupport::None => {
                assert!(surface.is_empty(), "{id} offers commands it cannot receive");
            }
        }
    }

    assert_eq!(
        with_commands,
        BTreeSet::from(["discord", "msteams", "qa-channel", "telegram", "whatsapp"]),
        "the command surface must follow inbound support, not a hand-written list"
    );
    assert_eq!(
        command_surface("not-a-channel"),
        Err(RoutingError::UnknownChannel)
    );
    assert_eq!(
        command_registry("not-a-channel").err(),
        Some(RoutingError::UnknownChannel)
    );
}

#[test]
fn inbound_text_is_classified_as_a_command_or_as_conversation() {
    let cases: [(&str, Option<&str>, InboundOutcome); 14] = [
        ("/help", None, command("help", None, &[])),
        ("  /help  topic  ", None, command("help", None, &["topic"])),
        ("/HELP", None, command("help", None, &[])),
        ("/login", None, command("login", None, &[])),
        (
            "/help@clawbot",
            Some("clawbot"),
            command("help", Some("clawbot"), &[]),
        ),
        (
            "/help@ClawBot",
            Some("clawbot"),
            command("help", Some("clawbot"), &[]),
        ),
        (
            "/help@otherbot",
            Some("clawbot"),
            rejected(
                "help",
                Some("otherbot"),
                &[],
                CommandDispatchError::ForeignMention,
            ),
        ),
        (
            "/help@clawbot",
            None,
            rejected(
                "help",
                Some("clawbot"),
                &[],
                CommandDispatchError::ForeignMention,
            ),
        ),
        (
            "/help one two",
            None,
            rejected(
                "help",
                None,
                &["one", "two"],
                CommandDispatchError::TooManyArguments,
            ),
        ),
        (
            "/login now",
            None,
            rejected(
                "login",
                None,
                &["now"],
                CommandDispatchError::TooManyArguments,
            ),
        ),
        (
            "/nope",
            None,
            rejected("nope", None, &[], CommandDispatchError::UnknownCommand),
        ),
        (
            "/",
            None,
            InboundOutcome::MalformedCommand(CommandParseError::EmptyName),
        ),
        (
            "/bad!name",
            None,
            InboundOutcome::MalformedCommand(CommandParseError::InvalidName),
        ),
        (
            "/help@",
            None,
            InboundOutcome::MalformedCommand(CommandParseError::InvalidMention),
        ),
    ];

    for (text, bot_mention, expected) in cases {
        assert_eq!(
            classify_inbound(&inbound("qa-channel", text), bot_mention),
            Ok(expected),
            "{text:?}"
        );
    }

    for text in [
        "hello",
        "  hello there  ",
        "not /help",
        "https://example.test",
    ] {
        assert_eq!(
            classify_inbound(&inbound("qa-channel", text), None),
            Ok(InboundOutcome::Conversation {
                text: Some(text.to_owned())
            }),
            "{text:?}"
        );
    }

    assert_eq!(
        classify_inbound(&inbound("qa-channel", ""), None),
        Err(RoutingError::InvalidMessage(
            InvalidMessageReason::EmptyContent
        ))
    );
}

#[test]
fn commands_are_unavailable_on_every_frozen_channel_that_cannot_receive_text() {
    let frozen_ids = frozen_channel_ids();
    let mut refused = 0_usize;

    for id in &frozen_ids {
        let inbound_capable = matches!(
            exchange_support(id).expect("registered channel"),
            ExchangeSupport::InboundOnly | ExchangeSupport::Bidirectional
        );
        let classified = classify_inbound(&inbound(id, "/help"), None);
        if inbound_capable {
            assert_eq!(classified, Ok(command("help", None, &[])), "{id}");
        } else {
            assert_eq!(classified, Err(RoutingError::InboundUnsupported), "{id}");
            refused += 1;
        }
    }

    assert_eq!(refused, frozen_ids.len() - 5);
    assert_eq!(
        classify_inbound(&inbound("not-a-channel", "/help"), None),
        Err(RoutingError::UnknownChannel)
    );
}

#[test]
fn help_output_lists_exactly_the_commands_a_channel_offers() {
    let rendered = help_text("qa-channel").expect("registered channel");
    let listed = rendered
        .lines()
        .map(|line| {
            line.split_once(" - ")
                .expect("summary separator")
                .0
                .to_owned()
        })
        .collect::<Vec<_>>();
    let expected = command_surface("qa-channel")
        .expect("registered channel")
        .iter()
        .map(|spec| format!("/{}", spec.name))
        .collect::<Vec<_>>();

    assert_eq!(listed, expected);
    assert_eq!(listed.len(), 4);
    assert_eq!(
        help_text("slack").expect("registered channel"),
        "slack offers no commands."
    );
    assert_eq!(
        help_text("not-a-channel"),
        Err(RoutingError::UnknownChannel)
    );
}

fn command(name: &str, mention: Option<&str>, arguments: &[&str]) -> InboundOutcome {
    let invocation = claw_channel_sdk::CommandInvocation {
        name: name.to_owned(),
        mention: mention.map(str::to_owned),
        arguments: arguments
            .iter()
            .map(|argument| (*argument).to_owned())
            .collect(),
    };
    let spec = command_surface("qa-channel")
        .expect("registered channel")
        .iter()
        .find(|spec| spec.name == name)
        .unwrap_or_else(|| panic!("{name} is offered"));
    InboundOutcome::Command { invocation, spec }
}

fn rejected(
    name: &str,
    mention: Option<&str>,
    arguments: &[&str],
    error: CommandDispatchError,
) -> InboundOutcome {
    InboundOutcome::RejectedCommand {
        invocation: claw_channel_sdk::CommandInvocation {
            name: name.to_owned(),
            mention: mention.map(str::to_owned),
            arguments: arguments
                .iter()
                .map(|argument| (*argument).to_owned())
                .collect(),
        },
        error,
    }
}

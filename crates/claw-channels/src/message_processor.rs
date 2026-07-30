//! Shared command, authentication, and conversation dispatch.

use claw_channel_sdk::{CommandDispatchError, CommandInvocation, parse_command};

use crate::commands::{command_registry, help_text};
use crate::descriptor;
use crate::diagnostics::{DiagnosticCode, DiagnosticLevel, DiagnosticSink, OperatorDiagnostic};
use crate::routing::{RoutingError, supports_inbound};

/// Legacy reply when non-Teams channels have no active engine or Device Flow.
pub const COMMON_UNCONFIGURED_REPLY: &str = "GTA-Claw is not configured with authentication.";

/// Legacy reply when Teams has no active engine or Device Flow.
pub const TEAMS_UNCONFIGURED_REPLY: &str = "No active GitHub token is configured.";

/// Stable apology used by Telegram, Discord, and `WhatsApp`.
pub const COMMON_FAILURE_REPLY: &str =
    "Sorry, an error occurred while processing your message. Please try again.";

/// Stable apology used by Teams.
pub const TEAMS_FAILURE_REPLY: &str =
    "I'm sorry, an error occurred while processing your message. Please try again.";

/// Reply used when an invocation cannot be dispatched.
pub const COMMAND_REJECTED_REPLY: &str =
    "I couldn't run that command. Use /help to see the available commands.";

/// Reply used for `/login` when an engine is already active.
pub const ALREADY_AUTHENTICATED_REPLY: &str = "GTA-Claw is already authenticated.";

/// Authentication information available while the engine is inactive.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AuthenticationPrompt<'a> {
    /// Device Flow or equivalent operator-supplied instructions.
    Instructions(&'a str),
    /// No interactive authentication mechanism is configured.
    Unconfigured,
}

/// User-facing wording applied by one channel family.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DispatchPolicy {
    unauthenticated_prefix: &'static str,
    unauthenticated_fallback: &'static str,
    failure_reply: &'static str,
}

impl DispatchPolicy {
    /// Creates a policy from fixed, non-secret user-facing strings.
    #[must_use]
    pub const fn new(
        unauthenticated_prefix: &'static str,
        unauthenticated_fallback: &'static str,
        failure_reply: &'static str,
    ) -> Self {
        Self {
            unauthenticated_prefix,
            unauthenticated_fallback,
            failure_reply,
        }
    }

    fn authentication_reply(self, prompt: AuthenticationPrompt<'_>) -> String {
        let message = match prompt {
            AuthenticationPrompt::Instructions(instructions) if !instructions.trim().is_empty() => {
                instructions
            }
            AuthenticationPrompt::Instructions(_) | AuthenticationPrompt::Unconfigured => {
                self.unauthenticated_fallback
            }
        };
        let mut reply = String::with_capacity(self.unauthenticated_prefix.len() + message.len());
        reply.push_str(self.unauthenticated_prefix);
        reply.push_str(message);
        reply
    }
}

/// Exact common-channel message processing wording.
pub const COMMON_DISPATCH_POLICY: DispatchPolicy =
    DispatchPolicy::new("", COMMON_UNCONFIGURED_REPLY, COMMON_FAILURE_REPLY);

/// Exact Teams message processing wording.
pub const TEAMS_DISPATCH_POLICY: DispatchPolicy = DispatchPolicy::new(
    "GTA-Claw is not authenticated yet. ",
    TEAMS_UNCONFIGURED_REPLY,
    TEAMS_FAILURE_REPLY,
);

/// Conversation engine port used by channel adapters.
pub trait ConversationService {
    /// Opaque engine failure. Channel diagnostics intentionally do not format it.
    type Error;

    /// Runs one conversation turn.
    ///
    /// # Errors
    ///
    /// Returns an engine-specific failure. The channel converts it to its stable
    /// apology and emits [`DiagnosticCode::ConversationFailed`].
    fn chat(&mut self, conversation_id: &str, text: &str) -> Result<String, Self::Error>;
}

/// Borrowed normalized input to shared dispatch.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DispatchInput<'a> {
    /// Exact registered channel identifier.
    pub channel_id: &'static str,
    /// Configured channel account.
    pub account_id: &'a str,
    /// Stable provider conversation route.
    pub conversation_id: &'a str,
    /// Provider sender identifier.
    pub sender_id: &'a str,
    /// Addressable bot name when command mentions are supported.
    pub bot_mention: Option<&'a str>,
    /// Raw provider text.
    pub text: &'a str,
}

/// Source of a user-facing reply.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ReplySource {
    /// `/help` was answered by the channel layer.
    Help,
    /// Authentication instructions or an unconfigured hint were returned.
    Authentication,
    /// `/login` found an already-active engine.
    AlreadyAuthenticated,
    /// A normal conversation turn completed.
    Conversation,
    /// Conversation processing failed and a stable apology was returned.
    Failure,
    /// A malformed, unknown, or invalid-arity command was refused.
    CommandRejection,
}

/// Shared dispatch decision for one inbound message.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum DispatchOutcome {
    /// No reply or engine call is needed.
    Ignored,
    /// A user-facing reply is ready.
    Reply {
        /// Reply text.
        text: String,
        /// Why the channel produced it.
        source: ReplySource,
    },
    /// A recognized runtime-owned command must be handled by composition.
    DeferredCommand(CommandInvocation),
}

/// Processes one inbound message without transport-specific branching.
///
/// `/help` and `/login` are handled before engine dispatch. `/status` and
/// `/reset` remain typed deferred commands because their implementations belong
/// to runtime composition. Commands addressed to another bot are ignored.
///
/// # Errors
///
/// Returns [`RoutingError`] when the channel identifier is unknown, has no
/// inbound implementation, or the crate-owned command table is invalid.
pub fn dispatch_incoming<E: ConversationService>(
    engine: Option<&mut E>,
    authentication: AuthenticationPrompt<'_>,
    policy: DispatchPolicy,
    input: DispatchInput<'_>,
    diagnostics: &mut impl DiagnosticSink,
) -> Result<DispatchOutcome, RoutingError> {
    let entry = descriptor(input.channel_id).ok_or(RoutingError::UnknownChannel)?;
    if !supports_inbound(entry) {
        return Err(RoutingError::InboundUnsupported);
    }
    let text = input.text.trim();
    if text.is_empty() {
        diagnostics.record(diagnostic(
            input,
            DiagnosticLevel::Info,
            DiagnosticCode::EmptyMessageIgnored,
        ));
        return Ok(DispatchOutcome::Ignored);
    }

    if text.starts_with('/') {
        let Ok(invocation) = parse_command(text) else {
            return Ok(command_rejection());
        };
        let registry = command_registry(input.channel_id)?;
        match registry.resolve(&invocation, input.bot_mention) {
            Ok(spec) => match spec.name {
                "help" => {
                    return Ok(DispatchOutcome::Reply {
                        text: help_text(input.channel_id)?,
                        source: ReplySource::Help,
                    });
                }
                "login" => {
                    if engine.is_some() {
                        return Ok(DispatchOutcome::Reply {
                            text: ALREADY_AUTHENTICATED_REPLY.to_owned(),
                            source: ReplySource::AlreadyAuthenticated,
                        });
                    }
                    diagnostics.record(diagnostic(
                        input,
                        DiagnosticLevel::Info,
                        DiagnosticCode::AuthenticationRequired,
                    ));
                    return Ok(DispatchOutcome::Reply {
                        text: policy.authentication_reply(authentication),
                        source: ReplySource::Authentication,
                    });
                }
                "status" | "reset" => return Ok(DispatchOutcome::DeferredCommand(invocation)),
                _ => return Ok(command_rejection()),
            },
            Err(CommandDispatchError::ForeignMention) => {
                diagnostics.record(diagnostic(
                    input,
                    DiagnosticLevel::Info,
                    DiagnosticCode::ForeignCommandIgnored,
                ));
                return Ok(DispatchOutcome::Ignored);
            }
            Err(
                CommandDispatchError::UnknownCommand
                | CommandDispatchError::MissingArguments
                | CommandDispatchError::TooManyArguments,
            ) => return Ok(command_rejection()),
        }
    }

    let Some(engine) = engine else {
        diagnostics.record(diagnostic(
            input,
            DiagnosticLevel::Info,
            DiagnosticCode::AuthenticationRequired,
        ));
        return Ok(DispatchOutcome::Reply {
            text: policy.authentication_reply(authentication),
            source: ReplySource::Authentication,
        });
    };
    Ok(engine.chat(input.conversation_id, text).map_or_else(
        |_| {
            diagnostics.record(diagnostic(
                input,
                DiagnosticLevel::Error,
                DiagnosticCode::ConversationFailed,
            ));
            DispatchOutcome::Reply {
                text: policy.failure_reply.to_owned(),
                source: ReplySource::Failure,
            }
        },
        |text| DispatchOutcome::Reply {
            text,
            source: ReplySource::Conversation,
        },
    ))
}

fn command_rejection() -> DispatchOutcome {
    DispatchOutcome::Reply {
        text: COMMAND_REJECTED_REPLY.to_owned(),
        source: ReplySource::CommandRejection,
    }
}

const fn diagnostic(
    input: DispatchInput<'_>,
    level: DiagnosticLevel,
    code: DiagnosticCode,
) -> OperatorDiagnostic<'_> {
    OperatorDiagnostic {
        level,
        code,
        channel_id: input.channel_id,
        account_id: input.account_id,
        conversation_id: Some(input.conversation_id),
        remote_status: None,
        retry_after: None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[derive(Default)]
    struct Engine {
        calls: Vec<(String, String)>,
        fail: bool,
    }

    impl ConversationService for Engine {
        type Error = ();

        fn chat(&mut self, conversation_id: &str, text: &str) -> Result<String, Self::Error> {
            self.calls
                .push((conversation_id.to_owned(), text.to_owned()));
            if self.fail {
                Err(())
            } else {
                Ok(format!("reply:{text}"))
            }
        }
    }

    fn input(text: &str) -> DispatchInput<'_> {
        DispatchInput {
            channel_id: "qa-channel",
            account_id: "qa",
            conversation_id: "room",
            sender_id: "sender",
            bot_mention: Some("clawbot"),
            text,
        }
    }

    #[test]
    fn help_and_authentication_are_dispatched_before_the_engine() {
        let mut engine = Engine::default();
        let help = dispatch_incoming(
            Some(&mut engine),
            AuthenticationPrompt::Unconfigured,
            COMMON_DISPATCH_POLICY,
            input("/help"),
            &mut (),
        )
        .expect("dispatch");
        assert!(matches!(
            help,
            DispatchOutcome::Reply {
                source: ReplySource::Help,
                ..
            }
        ));
        assert!(engine.calls.is_empty());

        assert_eq!(
            dispatch_incoming::<Engine>(
                None,
                AuthenticationPrompt::Instructions("Complete Device Flow."),
                COMMON_DISPATCH_POLICY,
                input("hello"),
                &mut (),
            ),
            Ok(DispatchOutcome::Reply {
                text: "Complete Device Flow.".to_owned(),
                source: ReplySource::Authentication,
            })
        );
    }

    #[test]
    fn teams_authentication_wording_stays_distinct() {
        assert_eq!(
            dispatch_incoming::<Engine>(
                None,
                AuthenticationPrompt::Unconfigured,
                TEAMS_DISPATCH_POLICY,
                input("hello"),
                &mut (),
            ),
            Ok(DispatchOutcome::Reply {
                text: "GTA-Claw is not authenticated yet. No active GitHub token is configured."
                    .to_owned(),
                source: ReplySource::Authentication,
            })
        );
    }

    #[test]
    fn conversation_text_is_trimmed_and_failures_are_contained() {
        let mut engine = Engine::default();
        assert_eq!(
            dispatch_incoming(
                Some(&mut engine),
                AuthenticationPrompt::Unconfigured,
                COMMON_DISPATCH_POLICY,
                input("  hello  "),
                &mut (),
            ),
            Ok(DispatchOutcome::Reply {
                text: "reply:hello".to_owned(),
                source: ReplySource::Conversation,
            })
        );
        assert_eq!(engine.calls, [("room".to_owned(), "hello".to_owned())]);

        engine.fail = true;
        assert_eq!(
            dispatch_incoming(
                Some(&mut engine),
                AuthenticationPrompt::Unconfigured,
                COMMON_DISPATCH_POLICY,
                input("again"),
                &mut (),
            ),
            Ok(DispatchOutcome::Reply {
                text: COMMON_FAILURE_REPLY.to_owned(),
                source: ReplySource::Failure,
            })
        );
    }

    #[test]
    fn foreign_mentions_are_ignored_and_runtime_commands_are_deferred() {
        assert_eq!(
            dispatch_incoming::<Engine>(
                None,
                AuthenticationPrompt::Unconfigured,
                COMMON_DISPATCH_POLICY,
                DispatchInput {
                    bot_mention: Some("other"),
                    text: "/help@clawbot",
                    ..input("")
                },
                &mut (),
            ),
            Ok(DispatchOutcome::Ignored)
        );
        assert!(matches!(
            dispatch_incoming::<Engine>(
                None,
                AuthenticationPrompt::Unconfigured,
                COMMON_DISPATCH_POLICY,
                input("/reset"),
                &mut (),
            ),
            Ok(DispatchOutcome::DeferredCommand(_))
        ));
    }

    #[test]
    fn plain_text_still_requires_a_known_inbound_capable_channel() {
        for (channel_id, expected) in [
            ("not-a-channel", RoutingError::UnknownChannel),
            ("slack", RoutingError::InboundUnsupported),
        ] {
            let mut engine = Engine::default();
            assert_eq!(
                dispatch_incoming(
                    Some(&mut engine),
                    AuthenticationPrompt::Unconfigured,
                    COMMON_DISPATCH_POLICY,
                    DispatchInput {
                        channel_id,
                        ..input("hello")
                    },
                    &mut (),
                ),
                Err(expected),
                "{channel_id}"
            );
            assert!(engine.calls.is_empty(), "{channel_id}");
        }
    }
}

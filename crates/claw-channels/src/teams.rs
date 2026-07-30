//! Microsoft Teams activity compatibility state machine.

use std::borrow::Cow;
use std::error::Error;
use std::fmt::{self, Display, Formatter};
use std::num::NonZeroUsize;

use claw_channel_sdk::{
    ChannelError, CommandInvocation, ConfigurationError, ConnectionState, ConnectionStateMachine,
    LifecycleEvent, ProtocolErrorKind,
};
use serde::Deserialize;

use crate::bounded::BoundedQueue;
use crate::diagnostics::{DiagnosticCode, DiagnosticLevel, DiagnosticSink, OperatorDiagnostic};
use crate::message_processor::{
    AuthenticationPrompt, ConversationService, DispatchInput, DispatchOutcome,
    TEAMS_DISPATCH_POLICY, dispatch_incoming,
};
use crate::routing::RoutingError;
use crate::transport::MAX_PROVIDER_RESPONSE_BYTES;
use crate::{invalid_routing_identifier, segment_outbound_text_iter};

/// Greeting sent for each newly added non-bot member.
pub const TEAMS_GREETING: &str =
    "Hello! I'm GTA-Claw, your AI assistant. How can I help you today?";

/// One Bot Framework action ready for the HTTP composition layer.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum TeamsAction {
    /// Send a Bot Framework typing activity.
    Typing,
    /// Send one already-bounded text activity.
    Reply(String),
}

/// Result of handling one Teams activity.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum TeamsActivityOutcome {
    /// Activity required no response.
    Ignored,
    /// One or more actions were queued in send order.
    ActionsQueued {
        /// Number of newly queued actions.
        count: usize,
    },
    /// A recognized runtime-owned command needs composition.
    DeferredCommand(CommandInvocation),
}

/// Teams activity handling failure.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum TeamsActivityError {
    /// Shared channel or protocol failure.
    Channel(ChannelError),
    /// Command routing failure.
    Routing(RoutingError),
    /// The bounded action queue cannot hold the complete response.
    ActionQueueFull,
}

impl Display for TeamsActivityError {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        match self {
            Self::Channel(error) => Display::fmt(error, formatter),
            Self::Routing(error) => Display::fmt(error, formatter),
            Self::ActionQueueFull => formatter.write_str("Teams action queue is full"),
        }
    }
}

impl Error for TeamsActivityError {}

impl From<ChannelError> for TeamsActivityError {
    fn from(error: ChannelError) -> Self {
        Self::Channel(error)
    }
}

impl From<RoutingError> for TeamsActivityError {
    fn from(error: RoutingError) -> Self {
        Self::Routing(error)
    }
}

/// Teams Bot Framework activity interpreter.
pub struct TeamsActivityHandler {
    account_id: String,
    recipient_id: String,
    bot_mention: Option<String>,
    lifecycle: ConnectionStateMachine,
    actions: BoundedQueue<TeamsAction>,
}

impl TeamsActivityHandler {
    /// Creates a stopped Teams activity handler.
    ///
    /// Bot Framework authentication and wire acknowledgements remain the
    /// composition layer's responsibility.
    ///
    /// # Errors
    ///
    /// Returns [`ChannelError::Configuration`] when account, recipient, or bot
    /// mention routing is malformed.
    pub fn new(
        account_id: impl Into<String>,
        recipient_id: impl Into<String>,
        bot_mention: Option<String>,
        action_capacity: NonZeroUsize,
    ) -> Result<Self, ChannelError> {
        let account_id = account_id.into();
        let recipient_id = recipient_id.into();
        if invalid_routing_identifier(&account_id)
            || invalid_routing_identifier(&recipient_id)
            || bot_mention
                .as_deref()
                .is_some_and(invalid_routing_identifier)
        {
            return Err(ChannelError::Configuration(
                ConfigurationError::InvalidAdapterConfiguration,
            ));
        }
        Ok(Self {
            account_id,
            recipient_id,
            bot_mention,
            lifecycle: ConnectionStateMachine::new(),
            actions: BoundedQueue::new(action_capacity),
        })
    }

    /// Returns the lifecycle state.
    #[must_use]
    pub const fn state(&self) -> ConnectionState {
        self.lifecycle.state()
    }

    /// Returns the number of queued outbound activities.
    #[must_use]
    pub fn queued_actions(&self) -> usize {
        self.actions.len()
    }

    /// Starts accepting activities. Repeated starts while running are harmless.
    ///
    /// # Errors
    ///
    /// Returns [`ChannelError::Lifecycle`] after terminal stop.
    pub fn start(&mut self, diagnostics: &mut impl DiagnosticSink) -> Result<bool, ChannelError> {
        if self.lifecycle.state() == ConnectionState::Connected {
            return Ok(false);
        }
        self.lifecycle
            .apply(LifecycleEvent::ConnectRequested, &mut ())?;
        self.lifecycle.apply(LifecycleEvent::Established, &mut ())?;
        diagnostics.record(self.diagnostic(
            DiagnosticLevel::Info,
            DiagnosticCode::ChannelStarted,
            None,
        ));
        Ok(true)
    }

    /// Permanently stops activity handling and clears pending actions.
    ///
    /// Repeated stops are idempotent.
    ///
    /// # Errors
    ///
    /// Returns [`ChannelError::Lifecycle`] only if the shared transition table
    /// refuses the current nonterminal state.
    pub fn stop(&mut self, diagnostics: &mut impl DiagnosticSink) -> Result<bool, ChannelError> {
        if self.lifecycle.state() == ConnectionState::Closed {
            return Ok(false);
        }
        self.lifecycle
            .apply(LifecycleEvent::ShutdownRequested, &mut ())?;
        self.actions.clear();
        diagnostics.record(self.diagnostic(
            DiagnosticLevel::Info,
            DiagnosticCode::ChannelStopped,
            None,
        ));
        Ok(true)
    }

    /// Handles one bounded Bot Framework activity.
    ///
    /// Message edits use the same path as new messages. Blank and bot-authored
    /// messages are ignored. Active conversation turns queue typing before
    /// segmented replies; authentication and command replies do not.
    ///
    /// # Errors
    ///
    /// Returns a typed protocol error for malformed or over-large payloads,
    /// command routing failures, or [`TeamsActivityError::ActionQueueFull`] when
    /// the complete ordered response cannot fit.
    pub fn handle_activity<E: ConversationService>(
        &mut self,
        payload: &[u8],
        engine: Option<&mut E>,
        authentication: AuthenticationPrompt<'_>,
        diagnostics: &mut impl DiagnosticSink,
    ) -> Result<TeamsActivityOutcome, TeamsActivityError> {
        self.require_running()?;
        if payload.len() > MAX_PROVIDER_RESPONSE_BYTES {
            self.record_malformed(diagnostics);
            return Err(ChannelError::Protocol(ProtocolErrorKind::PayloadTooLarge).into());
        }
        let activity: TeamsActivity<'_> = serde_json::from_slice(payload).map_err(|_| {
            self.record_malformed(diagnostics);
            TeamsActivityError::Channel(ChannelError::Protocol(
                ProtocolErrorKind::MalformedResponse,
            ))
        })?;
        match activity.kind {
            "message" | "messageUpdate" => {
                self.handle_message(&activity, engine, authentication, diagnostics)
            }
            "conversationUpdate" => self.handle_members_added(&activity, diagnostics),
            _ => Ok(TeamsActivityOutcome::Ignored),
        }
    }

    /// Pops the next ordered Bot Framework action.
    ///
    /// # Errors
    ///
    /// Returns [`ChannelError::NotConnected`] unless started.
    pub fn poll_action(&mut self) -> Result<Option<TeamsAction>, ChannelError> {
        self.require_running()?;
        Ok(self.actions.pop())
    }

    fn handle_message<E: ConversationService>(
        &mut self,
        activity: &TeamsActivity<'_>,
        engine: Option<&mut E>,
        authentication: AuthenticationPrompt<'_>,
        diagnostics: &mut impl DiagnosticSink,
    ) -> Result<TeamsActivityOutcome, TeamsActivityError> {
        let sender = activity.sender.unwrap_or(TeamsMember {
            id: "teams-user",
            role: None,
        });
        let recipient_id = activity
            .recipient
            .map_or(self.recipient_id.as_str(), |recipient| recipient.id);
        if sender.id == recipient_id || sender.role == Some("bot") {
            diagnostics.record(self.diagnostic(
                DiagnosticLevel::Info,
                DiagnosticCode::BotMessageIgnored,
                None,
            ));
            return Ok(TeamsActivityOutcome::Ignored);
        }
        let text = strip_recipient_mentions(activity, recipient_id);
        let Some(text) = Some(text.trim()).filter(|text| !text.is_empty()) else {
            diagnostics.record(self.diagnostic(
                DiagnosticLevel::Info,
                DiagnosticCode::EmptyMessageIgnored,
                None,
            ));
            return Ok(TeamsActivityOutcome::Ignored);
        };
        let Some(conversation_id) = activity
            .conversation
            .map(|conversation| conversation.id)
            .filter(|id| !invalid_routing_identifier(id))
        else {
            diagnostics.record(self.diagnostic(
                DiagnosticLevel::Warning,
                DiagnosticCode::MissingConversation,
                None,
            ));
            return Ok(TeamsActivityOutcome::Ignored);
        };
        if invalid_routing_identifier(sender.id) {
            self.record_malformed(diagnostics);
            return Err(ChannelError::Protocol(ProtocolErrorKind::InvalidField).into());
        }

        let start_len = self.actions.len();
        let should_type = engine.is_some() && !text.starts_with('/');
        if should_type && self.actions.push(TeamsAction::Typing).is_err() {
            self.record_queue_full(diagnostics, Some(conversation_id));
            return Err(TeamsActivityError::ActionQueueFull);
        }
        let outcome = match dispatch_incoming(
            engine,
            authentication,
            TEAMS_DISPATCH_POLICY,
            DispatchInput {
                channel_id: "msteams",
                account_id: &self.account_id,
                conversation_id,
                sender_id: sender.id,
                bot_mention: self.bot_mention.as_deref(),
                text,
            },
            diagnostics,
        ) {
            Ok(outcome) => outcome,
            Err(error) => {
                self.actions.truncate(start_len);
                return Err(error.into());
            }
        };
        match outcome {
            DispatchOutcome::Ignored => Ok(TeamsActivityOutcome::Ignored),
            DispatchOutcome::DeferredCommand(invocation) => {
                self.actions.truncate(start_len);
                Ok(TeamsActivityOutcome::DeferredCommand(invocation))
            }
            DispatchOutcome::Reply { text, .. } => {
                let chunks =
                    segment_outbound_text_iter("msteams", &text).map_err(ChannelError::from)?;
                for chunk in chunks {
                    let chunk = chunk.map_err(|error| {
                        self.actions.truncate(start_len);
                        TeamsActivityError::Channel(error.into())
                    })?;
                    if self
                        .actions
                        .push(TeamsAction::Reply(chunk.into_owned()))
                        .is_err()
                    {
                        self.actions.truncate(start_len);
                        self.record_queue_full(diagnostics, Some(conversation_id));
                        return Err(TeamsActivityError::ActionQueueFull);
                    }
                }
                Ok(TeamsActivityOutcome::ActionsQueued {
                    count: self.actions.len() - start_len,
                })
            }
        }
    }

    fn handle_members_added(
        &mut self,
        activity: &TeamsActivity<'_>,
        diagnostics: &mut impl DiagnosticSink,
    ) -> Result<TeamsActivityOutcome, TeamsActivityError> {
        let recipient_id = activity
            .recipient
            .map_or(self.recipient_id.as_str(), |recipient| recipient.id);
        let greeting_count = activity
            .members_added
            .iter()
            .filter(|member| member.id != recipient_id && member.role != Some("bot"))
            .count();
        if self.actions.remaining_capacity() < greeting_count {
            self.record_queue_full(
                diagnostics,
                activity.conversation.map(|conversation| conversation.id),
            );
            return Err(TeamsActivityError::ActionQueueFull);
        }
        for _ in 0..greeting_count {
            self.actions
                .push(TeamsAction::Reply(TEAMS_GREETING.to_owned()))
                .expect("capacity checked transactionally");
        }
        if greeting_count == 0 {
            Ok(TeamsActivityOutcome::Ignored)
        } else {
            Ok(TeamsActivityOutcome::ActionsQueued {
                count: greeting_count,
            })
        }
    }

    const fn require_running(&self) -> Result<(), ChannelError> {
        if self.lifecycle.state().can_exchange() {
            Ok(())
        } else {
            Err(ChannelError::NotConnected {
                state: self.lifecycle.state(),
            })
        }
    }

    fn record_malformed(&self, diagnostics: &mut impl DiagnosticSink) {
        diagnostics.record(self.diagnostic(
            DiagnosticLevel::Warning,
            DiagnosticCode::MalformedPayload,
            None,
        ));
    }

    fn record_queue_full(
        &self,
        diagnostics: &mut impl DiagnosticSink,
        conversation_id: Option<&str>,
    ) {
        diagnostics.record(self.diagnostic(
            DiagnosticLevel::Warning,
            DiagnosticCode::ActionQueueFull,
            conversation_id,
        ));
    }

    fn diagnostic<'a>(
        &'a self,
        level: DiagnosticLevel,
        code: DiagnosticCode,
        conversation_id: Option<&'a str>,
    ) -> OperatorDiagnostic<'a> {
        OperatorDiagnostic {
            level,
            code,
            channel_id: "msteams",
            account_id: &self.account_id,
            conversation_id,
            remote_status: None,
            retry_after: None,
        }
    }
}

#[derive(Deserialize)]
struct TeamsActivity<'a> {
    #[serde(rename = "type")]
    kind: &'a str,
    text: Option<&'a str>,
    #[serde(borrow)]
    conversation: Option<TeamsConversation<'a>>,
    #[serde(rename = "from", borrow)]
    sender: Option<TeamsMember<'a>>,
    #[serde(borrow)]
    recipient: Option<TeamsMember<'a>>,
    #[serde(rename = "membersAdded", default, borrow)]
    members_added: Vec<TeamsMember<'a>>,
    #[serde(default, borrow)]
    entities: Vec<TeamsEntity<'a>>,
}

#[derive(Clone, Copy, Deserialize)]
struct TeamsConversation<'a> {
    id: &'a str,
}

#[derive(Clone, Copy, Deserialize)]
struct TeamsMember<'a> {
    id: &'a str,
    role: Option<&'a str>,
}

#[derive(Deserialize)]
struct TeamsEntity<'a> {
    #[serde(rename = "type")]
    kind: &'a str,
    text: Option<&'a str>,
    #[serde(borrow)]
    mentioned: Option<TeamsMember<'a>>,
}

fn strip_recipient_mentions<'a>(
    activity: &'a TeamsActivity<'a>,
    recipient_id: &str,
) -> Cow<'a, str> {
    let mut text = Cow::Borrowed(activity.text.unwrap_or_default());
    for entity in &activity.entities {
        let Some(marker) = entity.text.filter(|marker| !marker.is_empty()) else {
            continue;
        };
        if entity.kind == "mention"
            && entity
                .mentioned
                .is_some_and(|mentioned| mentioned.id == recipient_id)
            && text.contains(marker)
        {
            text = Cow::Owned(text.replace(marker, ""));
        }
    }
    text
}

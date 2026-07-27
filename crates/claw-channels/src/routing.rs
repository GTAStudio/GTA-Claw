//! Account routing over the frozen official channel registry.
//!
//! A channel identifier alone never identifies a destination: one deployment
//! can run several accounts on the same channel, each with its own credential
//! and its own conversations. Routing is therefore keyed by the pair, and the
//! channel half of that key is checked against the frozen registry so an
//! identifier that upstream does not define cannot be routed at all.

use std::collections::{BTreeMap, BTreeSet};
use std::error::Error;
use std::fmt::{self, Display, Formatter};

use claw_channel_sdk::{
    Channel, ChannelCredential, ChannelError, DeliveryAcknowledgement, InboundMessage,
    InvalidMessageReason, OutboundMessage,
};

use crate::{ChannelCapability, ChannelDescriptor, descriptor};

/// Reasons a channel or account cannot be routed.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RoutingError {
    /// The identifier is not one of the frozen official channels.
    UnknownChannel,
    /// The account identifier is empty, padded, over-long, or has control characters.
    InvalidAccountId,
    /// The same channel and account pair is already registered.
    DuplicateAccount,
    /// No adapter is registered for this channel and account pair.
    UnroutedAccount,
    /// The adapter reports a different channel identifier than it was registered under.
    AdapterIdentityMismatch,
    /// This channel has no inbound implementation at this baseline.
    InboundUnsupported,
    /// The message failed common validation before routing.
    InvalidMessage(InvalidMessageReason),
    /// The crate's own command table for this channel is malformed.
    InvalidCommandTable,
}

impl Display for RoutingError {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        match self {
            Self::UnknownChannel => formatter.write_str("channel identifier is not registered"),
            Self::InvalidAccountId => formatter.write_str("channel account identifier is invalid"),
            Self::DuplicateAccount => formatter.write_str("channel account is already registered"),
            Self::UnroutedAccount => formatter.write_str("channel account has no adapter"),
            Self::AdapterIdentityMismatch => {
                formatter.write_str("channel adapter identity does not match its registration")
            }
            Self::InboundUnsupported => {
                formatter.write_str("channel has no inbound implementation")
            }
            Self::InvalidMessage(reason) => {
                write!(formatter, "channel message is invalid: {reason:?}")
            }
            Self::InvalidCommandTable => formatter.write_str("channel command table is invalid"),
        }
    }
}

impl Error for RoutingError {}

/// A routing failure or an adapter failure, kept distinguishable.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum RouterError {
    /// The destination could not be resolved.
    Routing(RoutingError),
    /// The destination was resolved and the adapter failed.
    Channel(ChannelError),
}

impl Display for RouterError {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        match self {
            Self::Routing(error) => Display::fmt(error, formatter),
            Self::Channel(error) => Display::fmt(error, formatter),
        }
    }
}

impl Error for RouterError {}

impl From<RoutingError> for RouterError {
    fn from(error: RoutingError) -> Self {
        Self::Routing(error)
    }
}

impl From<ChannelError> for RouterError {
    fn from(error: ChannelError) -> Self {
        Self::Channel(error)
    }
}

/// Message directions a registered channel can actually exchange today.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ExchangeSupport {
    /// Registration metadata only; neither direction is implemented.
    None,
    /// Text can be sent but not received.
    OutboundOnly,
    /// Text can be received but not sent.
    InboundOnly,
    /// Both directions are implemented.
    Bidirectional,
}

/// Returns the directions one registered channel implements.
///
/// This is derived from the registry rather than declared twice, so a
/// capability added to a descriptor cannot disagree with what routing believes.
///
/// # Errors
///
/// Returns [`RoutingError::UnknownChannel`] when `channel_id` is not one of the
/// 29 frozen official identifiers. Case, padding, and the `channel:` record
/// prefix all fail here rather than resolving to a near neighbour.
pub fn exchange_support(channel_id: &str) -> Result<ExchangeSupport, RoutingError> {
    let entry = descriptor(channel_id).ok_or(RoutingError::UnknownChannel)?;
    Ok(exchange_support_of(entry))
}

pub(crate) const fn supports_inbound(entry: &ChannelDescriptor) -> bool {
    matches!(
        exchange_support_of(entry),
        ExchangeSupport::InboundOnly | ExchangeSupport::Bidirectional
    )
}

const fn exchange_support_of(entry: &ChannelDescriptor) -> ExchangeSupport {
    let mut inbound = false;
    let mut outbound = false;
    let mut index = 0;
    while index < entry.capabilities.len() {
        match entry.capabilities[index] {
            ChannelCapability::InboundText => inbound = true,
            ChannelCapability::OutboundText => outbound = true,
            ChannelCapability::SafeOutboundRetry => {}
        }
        index += 1;
    }
    match (inbound, outbound) {
        (true, true) => ExchangeSupport::Bidirectional,
        (true, false) => ExchangeSupport::InboundOnly,
        (false, true) => ExchangeSupport::OutboundOnly,
        (false, false) => ExchangeSupport::None,
    }
}

/// Routes messages to one adapter per registered channel and account pair.
///
/// The map is keyed by channel first and account second rather than by an owned
/// pair, so resolving a destination for an inbound message borrows both halves
/// of the key instead of allocating a copy of the account identifier on every
/// message.
#[derive(Debug)]
pub struct ChannelRouter<C> {
    routes: BTreeMap<&'static str, BTreeMap<String, C>>,
}

impl<C> Default for ChannelRouter<C> {
    fn default() -> Self {
        Self::new()
    }
}

impl<C> ChannelRouter<C> {
    /// Creates an empty router.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            routes: BTreeMap::new(),
        }
    }

    /// Returns the number of registered channel and account pairs.
    #[must_use]
    pub fn len(&self) -> usize {
        self.routes.values().map(BTreeMap::len).sum()
    }

    /// Returns whether nothing is registered.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.routes.values().all(BTreeMap::is_empty)
    }

    /// Returns every channel identifier that has at least one account.
    #[must_use]
    pub fn channels(&self) -> BTreeSet<&'static str> {
        self.routes
            .iter()
            .filter(|(_, accounts)| !accounts.is_empty())
            .map(|(channel, _)| *channel)
            .collect()
    }

    /// Returns the accounts registered for one channel, in sorted order.
    ///
    /// A channel outside the frozen registry is an error rather than an empty
    /// list, so a typo cannot read as "this channel has no accounts".
    ///
    /// # Errors
    ///
    /// Returns [`RoutingError::UnknownChannel`] when `channel_id` is not one of
    /// the 29 frozen official identifiers. A registered channel that simply has
    /// no accounts yet returns an empty list.
    pub fn accounts(&self, channel_id: &str) -> Result<Vec<&str>, RoutingError> {
        let entry = descriptor(channel_id).ok_or(RoutingError::UnknownChannel)?;
        Ok(self.routes.get(entry.id).map_or_else(Vec::new, |accounts| {
            accounts.keys().map(String::as_str).collect()
        }))
    }
}

impl<C: Channel> ChannelRouter<C> {
    /// Registers one adapter for an exact channel and account pair.
    ///
    /// Returns the frozen descriptor the registration resolved to, so a caller
    /// cannot hold a routing entry without also holding its upstream identity.
    ///
    /// # Errors
    ///
    /// - [`RoutingError::UnknownChannel`] when `channel_id` is not one of the
    ///   29 frozen official identifiers.
    /// - [`RoutingError::InvalidAccountId`] when the account identifier is
    ///   empty, longer than 256 bytes, whitespace-padded, or contains a control
    ///   character. These would produce a key no lookup could reproduce.
    /// - [`RoutingError::AdapterIdentityMismatch`] when the adapter reports a
    ///   different channel identifier than the one it is being registered
    ///   under, which would send this channel's traffic to another provider.
    /// - [`RoutingError::DuplicateAccount`] when this channel and account pair
    ///   already has an adapter. The existing adapter is kept.
    pub fn register(
        &mut self,
        channel_id: &str,
        account_id: impl Into<String>,
        channel: C,
    ) -> Result<&'static ChannelDescriptor, RoutingError> {
        let entry = descriptor(channel_id).ok_or(RoutingError::UnknownChannel)?;
        let account_id = account_id.into();
        if invalid_account_id(&account_id) {
            return Err(RoutingError::InvalidAccountId);
        }
        if channel.id() != entry.id {
            return Err(RoutingError::AdapterIdentityMismatch);
        }
        let accounts = self.routes.entry(entry.id).or_default();
        if accounts.contains_key(&account_id) {
            return Err(RoutingError::DuplicateAccount);
        }
        accounts.insert(account_id, channel);
        Ok(entry)
    }

    /// Returns the adapter bound to one channel and account pair.
    ///
    /// # Errors
    ///
    /// - [`RoutingError::UnknownChannel`] when `channel_id` is not one of the
    ///   29 frozen official identifiers.
    /// - [`RoutingError::UnroutedAccount`] when the channel is registered but
    ///   this account has no adapter, which is what an operator sees after
    ///   configuring an account the channel was never started for.
    pub fn route(&self, channel_id: &str, account_id: &str) -> Result<&C, RoutingError> {
        let entry = descriptor(channel_id).ok_or(RoutingError::UnknownChannel)?;
        self.routes
            .get(entry.id)
            .and_then(|accounts| accounts.get(account_id))
            .ok_or(RoutingError::UnroutedAccount)
    }

    /// Returns the adapter bound to one channel and account pair for mutation.
    ///
    /// # Errors
    ///
    /// - [`RoutingError::UnknownChannel`] when `channel_id` is not one of the
    ///   29 frozen official identifiers.
    /// - [`RoutingError::UnroutedAccount`] when the channel is registered but
    ///   this account has no adapter.
    pub fn route_mut(
        &mut self,
        channel_id: &str,
        account_id: &str,
    ) -> Result<&mut C, RoutingError> {
        let entry = descriptor(channel_id).ok_or(RoutingError::UnknownChannel)?;
        self.adapter_mut(entry, account_id)
    }

    /// Resolves the adapter that owns an inbound message.
    ///
    /// The message carries both halves of the key, so this is the path a
    /// receiver uses; it never falls back to "the first adapter for this
    /// channel", which is how a multi-account deployment leaks conversations
    /// between tenants.
    ///
    /// # Errors
    ///
    /// - [`RoutingError::InvalidMessage`] when the message fails common
    ///   validation, carrying the exact reason.
    /// - [`RoutingError::UnknownChannel`] when the message names a channel that
    ///   is not in the frozen registry.
    /// - [`RoutingError::InboundUnsupported`] when the channel is registered but
    ///   implements no inbound direction at this baseline, so no adapter could
    ///   legitimately have produced this message.
    /// - [`RoutingError::UnroutedAccount`] when no adapter is registered for the
    ///   message's account on that channel.
    pub fn route_inbound(&mut self, message: &InboundMessage) -> Result<&mut C, RoutingError> {
        message.validate().map_err(RoutingError::InvalidMessage)?;
        let entry = descriptor(&message.channel_id).ok_or(RoutingError::UnknownChannel)?;
        if !supports_inbound(entry) {
            return Err(RoutingError::InboundUnsupported);
        }
        self.adapter_mut(entry, &message.account_id)
    }

    /// Sends an outbound message through the adapter for its own account.
    ///
    /// # Errors
    ///
    /// - [`RouterError::Routing`] with [`RoutingError::UnknownChannel`] for an
    ///   unregistered identifier, or [`RoutingError::UnroutedAccount`] when the
    ///   message's account has no adapter on that channel.
    /// - [`RouterError::Channel`] with whatever the resolved adapter returned,
    ///   which keeps "this destination does not exist" distinguishable from
    ///   "this destination refused the message".
    pub fn send(
        &mut self,
        channel_id: &str,
        message: &OutboundMessage,
        credential: Option<&ChannelCredential>,
    ) -> Result<DeliveryAcknowledgement, RouterError> {
        let channel = self.route_mut(channel_id, &message.account_id)?;
        Ok(channel.send_outbound(message, credential)?)
    }

    /// Polls one inbound message from the adapter for a channel and account.
    ///
    /// # Errors
    ///
    /// - [`RouterError::Routing`] with [`RoutingError::UnknownChannel`] for an
    ///   unregistered identifier, [`RoutingError::InboundUnsupported`] for a
    ///   channel with no inbound implementation, or
    ///   [`RoutingError::UnroutedAccount`] when that account has no adapter.
    /// - [`RouterError::Channel`] with whatever the adapter's own poll returned.
    pub fn poll_inbound(
        &mut self,
        channel_id: &str,
        account_id: &str,
    ) -> Result<Option<InboundMessage>, RouterError> {
        let entry = descriptor(channel_id).ok_or(RoutingError::UnknownChannel)?;
        if !supports_inbound(entry) {
            return Err(RoutingError::InboundUnsupported.into());
        }
        Ok(self.adapter_mut(entry, account_id)?.poll_inbound()?)
    }

    /// Resolves an adapter from an already-resolved descriptor.
    ///
    /// Callers that have a descriptor in hand use this instead of
    /// [`Self::route_mut`] so one message costs one registry lookup.
    fn adapter_mut(
        &mut self,
        entry: &'static ChannelDescriptor,
        account_id: &str,
    ) -> Result<&mut C, RoutingError> {
        self.routes
            .get_mut(entry.id)
            .and_then(|accounts| accounts.get_mut(account_id))
            .ok_or(RoutingError::UnroutedAccount)
    }
}

fn invalid_account_id(value: &str) -> bool {
    value.is_empty()
        || value.len() > 256
        || value.trim() != value
        || value.chars().any(char::is_control)
}

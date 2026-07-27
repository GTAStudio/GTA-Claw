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
#[derive(Debug)]
pub struct ChannelRouter<C> {
    routes: BTreeMap<(&'static str, String), C>,
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
        self.routes.len()
    }

    /// Returns whether nothing is registered.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.routes.is_empty()
    }

    /// Returns every channel identifier that has at least one account.
    #[must_use]
    pub fn channels(&self) -> BTreeSet<&'static str> {
        self.routes.keys().map(|(channel, _)| *channel).collect()
    }

    /// Returns the accounts registered for one channel, in sorted order.
    ///
    /// A channel outside the frozen registry is an error rather than an empty
    /// list, so a typo cannot read as "this channel has no accounts".
    pub fn accounts(&self, channel_id: &str) -> Result<Vec<&str>, RoutingError> {
        let entry = descriptor(channel_id).ok_or(RoutingError::UnknownChannel)?;
        Ok(self
            .routes
            .keys()
            .filter(|(channel, _)| *channel == entry.id)
            .map(|(_, account)| account.as_str())
            .collect())
    }
}

impl<C: Channel> ChannelRouter<C> {
    /// Registers one adapter for an exact channel and account pair.
    ///
    /// Returns the frozen descriptor the registration resolved to, so a caller
    /// cannot hold a routing entry without also holding its upstream identity.
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
        let key = (entry.id, account_id);
        if self.routes.contains_key(&key) {
            return Err(RoutingError::DuplicateAccount);
        }
        self.routes.insert(key, channel);
        Ok(entry)
    }

    /// Returns the adapter bound to one channel and account pair.
    pub fn route(&self, channel_id: &str, account_id: &str) -> Result<&C, RoutingError> {
        let entry = descriptor(channel_id).ok_or(RoutingError::UnknownChannel)?;
        self.routes
            .get(&(entry.id, account_id.to_owned()))
            .ok_or(RoutingError::UnroutedAccount)
    }

    /// Returns the adapter bound to one channel and account pair for mutation.
    pub fn route_mut(
        &mut self,
        channel_id: &str,
        account_id: &str,
    ) -> Result<&mut C, RoutingError> {
        let entry = descriptor(channel_id).ok_or(RoutingError::UnknownChannel)?;
        self.routes
            .get_mut(&(entry.id, account_id.to_owned()))
            .ok_or(RoutingError::UnroutedAccount)
    }

    /// Resolves the adapter that owns an inbound message.
    ///
    /// The message carries both halves of the key, so this is the path a
    /// receiver uses; it never falls back to "the first adapter for this
    /// channel", which is how a multi-account deployment leaks conversations
    /// between tenants.
    pub fn route_inbound(&mut self, message: &InboundMessage) -> Result<&mut C, RoutingError> {
        message.validate().map_err(RoutingError::InvalidMessage)?;
        let entry = descriptor(&message.channel_id).ok_or(RoutingError::UnknownChannel)?;
        if !supports_inbound(entry) {
            return Err(RoutingError::InboundUnsupported);
        }
        self.route_mut(entry.id, &message.account_id)
    }

    /// Sends an outbound message through the adapter for its own account.
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
    pub fn poll_inbound(
        &mut self,
        channel_id: &str,
        account_id: &str,
    ) -> Result<Option<InboundMessage>, RouterError> {
        let entry = descriptor(channel_id).ok_or(RoutingError::UnknownChannel)?;
        if !supports_inbound(entry) {
            return Err(RoutingError::InboundUnsupported.into());
        }
        Ok(self.route_mut(entry.id, account_id)?.poll_inbound()?)
    }
}

fn invalid_account_id(value: &str) -> bool {
    value.is_empty()
        || value.len() > 256
        || value.trim() != value
        || value.chars().any(char::is_control)
}

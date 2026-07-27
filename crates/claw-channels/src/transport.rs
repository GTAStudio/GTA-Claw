//! Shared response envelope for daemon-owned channel transports.

use std::fmt::{self, Debug, Formatter};
use std::time::Duration;

use claw_channel_sdk::{ApprovedOrigin, ChannelError, ConfigurationError, ProtocolErrorKind};

/// Largest provider response body accepted for protocol parsing.
pub const MAX_PROVIDER_RESPONSE_BYTES: usize = 1024 * 1024;

/// Bounded provider response metadata and bytes.
pub struct ProviderResponse {
    status: u16,
    body: Vec<u8>,
    retry_after: Option<Duration>,
}

impl ProviderResponse {
    /// Creates a response without provider retry metadata.
    #[must_use]
    pub fn new(status: u16, body: impl Into<Vec<u8>>) -> Self {
        Self {
            status,
            body: body.into(),
            retry_after: None,
        }
    }

    /// Creates a response with an optional provider-requested retry delay.
    #[must_use]
    pub fn with_retry_after(
        status: u16,
        body: impl Into<Vec<u8>>,
        retry_after: Option<Duration>,
    ) -> Self {
        Self {
            status,
            body: body.into(),
            retry_after,
        }
    }

    /// Returns the HTTP-like provider status.
    #[must_use]
    pub const fn status(&self) -> u16 {
        self.status
    }

    /// Returns response bytes for immediate bounded protocol parsing.
    #[must_use]
    pub fn body(&self) -> &[u8] {
        &self.body
    }

    /// Returns the provider-requested retry delay when present.
    #[must_use]
    pub const fn retry_after(&self) -> Option<Duration> {
        self.retry_after
    }

    pub(crate) const fn require_bounded(&self) -> Result<(), ChannelError> {
        if self.body.len() > MAX_PROVIDER_RESPONSE_BYTES {
            return Err(ChannelError::Protocol(ProtocolErrorKind::PayloadTooLarge));
        }
        Ok(())
    }
}

impl Debug for ProviderResponse {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ProviderResponse")
            .field("status", &self.status)
            .field(
                "body",
                &format_args!("[REDACTED; {} bytes]", self.body.len()),
            )
            .field("retry_after", &self.retry_after)
            .finish()
    }
}

pub(crate) fn require_official_origin(
    origin: &ApprovedOrigin,
    channel_id: &str,
    account_id: &str,
    host: &str,
) -> Result<(), ChannelError> {
    if origin.channel_id() != channel_id || origin.account_id() != account_id {
        return Err(ChannelError::Configuration(
            ConfigurationError::CredentialScopeMismatch,
        ));
    }
    let network = origin.network_origin();
    if network.host() != host || network.port().is_some_and(|port| port != 443) {
        return Err(ChannelError::Configuration(
            ConfigurationError::InvalidAdapterConfiguration,
        ));
    }
    Ok(())
}

//! Recorded availability of Gateway transports on iOS.
//!
//! # This is a record, not a dispatcher
//!
//! Nothing in this crate selects a transport at runtime, because exactly one
//! transport is implemented. This module exists so that the transports which
//! are *not* implemented are written down with their reasons, rather than
//! being absent and therefore indistinguishable from an oversight.
//!
//! The rule this follows is that an unimplementable surface must be recorded
//! as unimplementable, with the reason, and must never be quietly replaced by
//! a plausible-looking substitute. A documented gap can be planned around. An
//! invented analogue cannot later be told apart from the real thing.
//!
//! # Nothing here has been confirmed on an Apple device
//!
//! Every record reports [`IosTransportRecord::confirmed_on_ios`] as `false`,
//! and a test in this module asserts that. This workspace has only ever been
//! built and run on Windows x86_64; `aarch64-apple-ios` cannot be type-checked
//! from that host because `ring` requires `xcrun` and the iOS SDK. A status
//! below is a reasoned position, not a measurement.

use std::fmt::{self, Display, Formatter};

/// A way an iOS client could reach a GTA Claw Gateway.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum ClientTransport {
    /// A direct Gateway v4 WebSocket to a known endpoint.
    GatewayWebSocket,
    /// DNS-SD browsing for a Gateway on the local network.
    BonjourDiscovery,
    /// Tailscale-fronted access authenticated by Tailscale identity.
    TailscaleLocalApi,
    /// An SSH tunnel to a Gateway that is not directly reachable.
    SshTunnel,
}

impl ClientTransport {
    /// Every transport considered for this client, in source order.
    pub const ALL: [Self; 4] = [
        Self::GatewayWebSocket,
        Self::BonjourDiscovery,
        Self::TailscaleLocalApi,
        Self::SshTunnel,
    ];

    /// Returns text safe to render on a diagnostics screen.
    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            Self::GatewayWebSocket => "Gateway WebSocket",
            Self::BonjourDiscovery => "Bonjour discovery",
            Self::TailscaleLocalApi => "Tailscale",
            Self::SshTunnel => "SSH tunnel",
        }
    }

    /// Returns this crate's recorded position on the transport for iOS.
    #[must_use]
    pub const fn ios_record(self) -> IosTransportRecord {
        let (status, reason) = match self {
            Self::GatewayWebSocket => (
                IosTransportStatus::Implemented,
                "GatewayEndpoint and IosGatewayProfile build a GatewayClientConfig that \
                 claw-gateway-client accepts; the iOS target itself has never been compiled.",
            ),
            Self::BonjourDiscovery => (
                IosTransportStatus::NeedsHostAppFacilities,
                "iOS requires NSLocalNetworkUsageDescription and NSBonjourServices in the host \
                 application bundle, which this crate cannot read or supply, and it suspends \
                 polling discovery when the application leaves the foreground. A pure-Rust mDNS \
                 stack binds its own multicast sockets, which per Apple TN3179 additionally \
                 requires the com.apple.developer.networking.multicast entitlement that Apple \
                 grants case by case on request, so no build made from source has it. The system \
                 DNS-SD path avoids that entitlement for declared service types but needs C \
                 interop this workspace's unsafe_code setting forbids. See the host_app module, \
                 which turns each missing facility into a reported condition.",
            ),
            Self::TailscaleLocalApi => (
                IosTransportStatus::BelievedUnavailable,
                "The Gateway handshake's Tailscale identity path needs an app-accessible \
                 LocalAPI Unix socket or an explicit loopback proxy, and a stock sandboxed iOS \
                 deployment may expose neither. Recorded as unavailable rather than satisfied by \
                 a substitute transport.",
            ),
            Self::SshTunnel => (
                IosTransportStatus::NeedsHostAppFacilities,
                "Requires caller-provisioned sandbox paths for the private key and known_hosts. \
                 This crate has no Keychain or Secure Enclave integration, so key material would \
                 sit in ordinary application-container files, which is a regression against the \
                 platform's own norm rather than a neutral omission.",
            ),
        };
        IosTransportRecord {
            transport: self,
            status,
            reason,
        }
    }
}

impl Display for ClientTransport {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.label())
    }
}

/// This crate's position on whether a transport works on iOS.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum IosTransportStatus {
    /// Built by this crate.
    Implemented,
    /// Blocked on facilities only the host application can provide.
    NeedsHostAppFacilities,
    /// Believed structurally unavailable on a stock sandboxed deployment.
    ///
    /// Believed, not proven. Confirming it needs a device or a simulator, and
    /// neither has been available to this workspace.
    BelievedUnavailable,
}

impl IosTransportStatus {
    /// Returns text safe to render on a diagnostics screen.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Implemented => "implemented",
            Self::NeedsHostAppFacilities => "needs host application support",
            Self::BelievedUnavailable => "believed unavailable on iOS",
        }
    }
}

impl Display for IosTransportStatus {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

/// A written-down position on one transport, with its reason.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct IosTransportRecord {
    transport: ClientTransport,
    status: IosTransportStatus,
    reason: &'static str,
}

impl IosTransportRecord {
    /// Returns the transport this record describes.
    #[must_use]
    pub const fn transport(&self) -> ClientTransport {
        self.transport
    }

    /// Returns the recorded status.
    #[must_use]
    pub const fn status(&self) -> IosTransportStatus {
        self.status
    }

    /// Returns the reason behind the status, which is never empty.
    #[must_use]
    pub const fn reason(&self) -> &'static str {
        self.reason
    }

    /// Returns whether this crate can actually carry the transport today.
    ///
    /// Only [`IosTransportStatus::Implemented`] qualifies. A status that means
    /// "someone else could make this work" is not a usable transport, and this
    /// is the single method any caller must consult.
    #[must_use]
    pub const fn usable_today(&self) -> bool {
        matches!(self.status, IosTransportStatus::Implemented)
    }

    /// Returns whether the status was confirmed on an Apple device.
    ///
    /// Always `false`. No part of this workspace has run on iOS.
    #[must_use]
    pub const fn confirmed_on_ios(&self) -> bool {
        false
    }
}

impl Display for IosTransportRecord {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "{}: {} (unconfirmed on iOS) — {}",
            self.transport, self.status, self.reason
        )
    }
}

#[cfg(test)]
mod tests {
    use super::{ClientTransport, IosTransportStatus};

    #[test]
    fn no_transport_record_claims_confirmation_on_an_apple_device() {
        for transport in ClientTransport::ALL {
            let record = transport.ios_record();
            assert!(
                !record.confirmed_on_ios(),
                "{transport} claimed iOS confirmation while its status was {}",
                record.status()
            );
        }
    }

    #[test]
    fn exactly_one_transport_is_usable_today_and_it_is_the_one_this_crate_builds() {
        let usable: Vec<ClientTransport> = ClientTransport::ALL
            .into_iter()
            .filter(|transport| transport.ios_record().usable_today())
            .collect();

        assert_eq!(
            usable,
            vec![ClientTransport::GatewayWebSocket],
            "the usable set must match the transport IosGatewayProfile actually configures"
        );
    }

    #[test]
    fn tailscale_is_recorded_as_a_gap_rather_than_substituted() {
        let record = ClientTransport::TailscaleLocalApi.ios_record();

        assert_eq!(
            record.status(),
            IosTransportStatus::BelievedUnavailable,
            "Tailscale must stay recorded as a gap, not promoted by a substitute transport"
        );
        assert!(
            !record.usable_today(),
            "a believed-unavailable transport reported itself usable: {record}"
        );
        assert!(
            record.reason().contains("LocalAPI"),
            "the reason must state the structural obstacle, but read {}",
            record.reason()
        );
    }

    #[test]
    fn ssh_records_the_absence_of_keychain_backing() {
        let record = ClientTransport::SshTunnel.ios_record();

        assert!(
            !record.usable_today(),
            "SSH reported itself usable without key storage: {record}"
        );
        assert!(
            record.reason().contains("Keychain"),
            "the reason must name the missing platform facility, but read {}",
            record.reason()
        );
    }

    #[test]
    fn every_record_carries_a_reason_and_renders_it() {
        for transport in ClientTransport::ALL {
            let record = transport.ios_record();
            assert!(
                !record.reason().is_empty(),
                "{transport} carried an empty reason"
            );
            let rendered = record.to_string();
            assert!(
                rendered.contains(transport.label()) && rendered.contains("unconfirmed on iOS"),
                "{transport} rendered as {rendered}, which hides the confirmation state"
            );
        }
    }
}

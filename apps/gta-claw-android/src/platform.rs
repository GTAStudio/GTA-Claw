//! Platform facts supplied by a future Android shell.
//!
//! This crate cannot call Android APIs directly because the workspace forbids
//! `unsafe`, and therefore JNI.  Instead, the shell reports lifecycle and
//! connectivity changes through closed value types and may inject a
//! [`PlatformFacilities`] implementation.  The portable default remains useful
//! for host tests and headless callers.

use std::error::Error;
use std::fmt::{self, Display, Formatter};
use std::sync::Arc;

use claw_security::identity::DeviceIdentity;

use crate::identity::generate_session_identity;

/// Whether the application is allowed to keep foreground network work alive.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub enum AppLifecycle {
    /// The application is visible and interactive.
    #[default]
    Foreground,
    /// The application is backgrounded or suspended.
    Background,
}

/// Coarse radio or route carrying the active Android network.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum NetworkTransport {
    /// Android did not identify the transport.
    Unknown,
    /// Wi-Fi.
    Wifi,
    /// Cellular data.
    Cellular,
    /// Wired Ethernet.
    Ethernet,
    /// A VPN route.
    Vpn,
    /// Another Android transport.
    Other,
}

impl NetworkTransport {
    /// Returns a short operator-facing transport label.
    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            Self::Unknown => "network",
            Self::Wifi => "Wi-Fi",
            Self::Cellular => "cellular",
            Self::Ethernet => "Ethernet",
            Self::Vpn => "VPN",
            Self::Other => "other network",
        }
    }
}

/// Latest connectivity fact reported by the Android shell.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub enum NetworkStatus {
    /// No platform monitor is attached. Connections remain allowed for backwards
    /// compatibility with headless callers.
    #[default]
    Unknown,
    /// Android reports no usable default network.
    Unavailable,
    /// Android reports a default network.
    Available {
        /// Route carrying the network.
        transport: NetworkTransport,
        /// Whether Android marks the network as metered.
        metered: bool,
        /// Whether Android validated Internet reachability.
        validated: bool,
        /// Opaque shell-supplied generation that changes with the default network.
        generation: u64,
    },
}

impl NetworkStatus {
    /// Returns whether opening or retaining a Gateway socket is currently useful.
    #[must_use]
    pub const fn allows_connection(self) -> bool {
        matches!(self, Self::Unknown | Self::Available { .. })
    }

    /// Returns the shell-supplied default-network generation, when available.
    #[must_use]
    pub const fn generation(self) -> Option<u64> {
        match self {
            Self::Available { generation, .. } => Some(generation),
            Self::Unknown | Self::Unavailable => None,
        }
    }

    /// Returns a concise operator-facing connectivity summary.
    #[must_use]
    pub fn summary(self) -> String {
        match self {
            Self::Unknown => "Network monitoring is not attached.".to_owned(),
            Self::Unavailable => "No usable network is available.".to_owned(),
            Self::Available {
                transport,
                metered,
                validated,
                ..
            } => {
                let cost = if metered { "metered" } else { "unmetered" };
                if validated {
                    format!("{} is available ({cost}).", transport.label())
                } else {
                    format!(
                        "{} is present but Android has not validated Internet access.",
                        transport.label()
                    )
                }
            }
        }
    }
}

/// Why a requested connection is intentionally not running.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ConnectionBlocker {
    /// The app is not in the foreground.
    Background,
    /// Android reports no usable default network.
    NetworkUnavailable,
}

/// Returns the highest-priority reason a connection should not run.
#[must_use]
pub const fn connection_blocker(
    lifecycle: AppLifecycle,
    network: NetworkStatus,
) -> Option<ConnectionBlocker> {
    if matches!(lifecycle, AppLifecycle::Background) {
        return Some(ConnectionBlocker::Background);
    }
    match network {
        NetworkStatus::Unavailable => Some(ConnectionBlocker::NetworkUnavailable),
        NetworkStatus::Unknown | NetworkStatus::Available { .. } => None,
    }
}

/// Durability of the identity supplied by [`PlatformFacilities`].
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum IdentityPersistence {
    /// Generated in memory and lost when the process exits.
    SessionOnly,
    /// Retained by a platform facility across process launches.
    DeviceBacked,
}

/// Readiness of an optional local-Gateway discovery facility.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DiscoveryReadiness {
    /// No discovery adapter is installed; manual addresses remain available.
    ManualAddressOnly,
    /// Android multicast permission has not been granted.
    PermissionRequired,
    /// The adapter has permission but is not holding a multicast lock.
    MulticastLockRequired,
    /// Discovery prerequisites are satisfied.
    Ready,
}

/// Non-secret platform capability facts suitable for direct UI binding.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PlatformCapabilities {
    identity_persistence: IdentityPersistence,
    discovery: DiscoveryReadiness,
}

impl PlatformCapabilities {
    /// Creates a platform capability snapshot.
    #[must_use]
    pub const fn new(
        identity_persistence: IdentityPersistence,
        discovery: DiscoveryReadiness,
    ) -> Self {
        Self {
            identity_persistence,
            discovery,
        }
    }

    /// Returns how long the supplied device identity survives.
    #[must_use]
    pub const fn identity_persistence(self) -> IdentityPersistence {
        self.identity_persistence
    }

    /// Returns whether local discovery can run truthfully.
    #[must_use]
    pub const fn discovery(self) -> DiscoveryReadiness {
        self.discovery
    }

    /// Returns a concise description of the platform facilities in use.
    #[must_use]
    pub fn notice(self) -> String {
        let identity = match self.identity_persistence {
            IdentityPersistence::SessionOnly => "Identity lasts for this app session only.",
            IdentityPersistence::DeviceBacked => "Identity is retained by the device.",
        };
        let discovery = match self.discovery {
            DiscoveryReadiness::ManualAddressOnly => {
                "Gateway discovery is unavailable; enter an address manually."
            }
            DiscoveryReadiness::PermissionRequired => {
                "Gateway discovery needs Android multicast permission."
            }
            DiscoveryReadiness::MulticastLockRequired => {
                "Gateway discovery is paused until the shell holds a multicast lock."
            }
            DiscoveryReadiness::Ready => "Gateway discovery is ready.",
        };
        format!("{identity} {discovery}")
    }
}

impl Default for PlatformCapabilities {
    fn default() -> Self {
        Self::new(
            IdentityPersistence::SessionOnly,
            DiscoveryReadiness::ManualAddressOnly,
        )
    }
}

/// Closed failure reported while obtaining a platform device identity.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum IdentityFailure {
    /// The operating system did not provide secure randomness.
    RandomnessUnavailable,
    /// A device-backed identity exists but is temporarily locked.
    StorageLocked,
    /// Android invalidated the stored identity.
    StorageInvalidated,
    /// The configured identity facility is unavailable.
    Unavailable,
}

impl Display for IdentityFailure {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::RandomnessUnavailable => "secure randomness is unavailable",
            Self::StorageLocked => "device identity storage is locked",
            Self::StorageInvalidated => "the stored device identity was invalidated",
            Self::Unavailable => "the device identity facility is unavailable",
        })
    }
}

impl Error for IdentityFailure {}

/// Facilities a future JNI shell can provide without coupling this core to JNI.
pub trait PlatformFacilities: Send + Sync {
    /// Loads or creates the process identity.
    ///
    /// Implementations must not block on user interaction. The controller calls
    /// this lazily on its runtime and caches the returned identity.
    ///
    /// # Errors
    ///
    /// Returns a closed [`IdentityFailure`] so diagnostics cannot accidentally
    /// carry key material or platform exception text.
    fn device_identity(&self) -> Result<Arc<DeviceIdentity>, IdentityFailure>;

    /// Returns non-secret platform capability facts.
    fn capabilities(&self) -> PlatformCapabilities;
}

/// Host-test and headless implementation with a process-local identity.
#[derive(Clone, Copy, Debug, Default)]
pub struct PortablePlatformFacilities;

impl PlatformFacilities for PortablePlatformFacilities {
    fn device_identity(&self) -> Result<Arc<DeviceIdentity>, IdentityFailure> {
        generate_session_identity()
            .map(Arc::new)
            .map_err(|_| IdentityFailure::RandomnessUnavailable)
    }

    fn capabilities(&self) -> PlatformCapabilities {
        PlatformCapabilities::default()
    }
}

#[cfg(test)]
mod tests {
    use super::{
        AppLifecycle, ConnectionBlocker, DiscoveryReadiness, IdentityPersistence, NetworkStatus,
        NetworkTransport, PlatformCapabilities, PlatformFacilities, PortablePlatformFacilities,
        connection_blocker,
    };

    #[test]
    fn background_and_unavailable_networks_block_socket_work() {
        let online = NetworkStatus::Available {
            transport: NetworkTransport::Wifi,
            metered: false,
            validated: true,
            generation: 1,
        };
        assert_eq!(
            connection_blocker(AppLifecycle::Background, online),
            Some(ConnectionBlocker::Background)
        );
        assert_eq!(
            connection_blocker(
                AppLifecycle::Foreground,
                NetworkStatus::Available {
                    transport: NetworkTransport::Wifi,
                    metered: false,
                    validated: false,
                    generation: 1,
                }
            ),
            None,
            "Internet validation cannot gate a Gateway on an isolated local network"
        );
        assert_eq!(
            connection_blocker(AppLifecycle::Foreground, NetworkStatus::Unavailable),
            Some(ConnectionBlocker::NetworkUnavailable)
        );
        assert_eq!(connection_blocker(AppLifecycle::Foreground, online), None);
    }

    #[test]
    fn unknown_network_state_preserves_headless_backwards_compatibility() {
        assert!(
            NetworkStatus::Unknown.allows_connection(),
            "a caller without an Android connectivity adapter must still be able to connect"
        );
    }

    #[test]
    fn portable_facilities_report_their_real_limits() {
        let platform = PortablePlatformFacilities;
        let capabilities = platform.capabilities();

        assert_eq!(
            capabilities,
            PlatformCapabilities::new(
                IdentityPersistence::SessionOnly,
                DiscoveryReadiness::ManualAddressOnly
            )
        );
        assert!(
            platform.device_identity().is_ok(),
            "the portable platform must obtain an identity from the host CSPRNG"
        );
    }
}

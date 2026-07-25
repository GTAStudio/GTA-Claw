//! Explicit, validated server configuration.

use std::net::SocketAddr;
use std::time::Duration;

use claw_protocol::gateway::{AUTHENTICATED_MAX_FRAME_BYTES, Name, PREAUTH_MAX_FRAME_BYTES};

use crate::error::ConfigurationError;

/// Maximum bytes accepted for one inbound HTTP upgrade request.
pub const MAX_HTTP_UPGRADE_BYTES: usize = 16 * 1024;
/// Maximum UTF-8 byte length accepted for the advertised server version.
pub const MAX_SERVER_VERSION_BYTES: usize = 64;

/// Bounded per-connection and per-process resource caps.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ServerLimits {
    /// Maximum simultaneously accepted connections.
    pub max_connections: usize,
    /// Maximum events buffered for one subscriber before it is declared slow.
    pub event_queue_capacity: usize,
    /// Maximum cumulative encoded event bytes buffered for one subscriber.
    pub event_queue_bytes: usize,
    /// Maximum bytes accepted for one inbound HTTP upgrade request.
    pub max_http_upgrade_bytes: usize,
    /// Maximum sessions retained by the in-memory persistence adapter.
    pub max_sessions: usize,
    /// Maximum pending node invocations retained per node.
    pub max_pending_per_node: usize,
    /// Maximum unanswered server pings before the peer is declared unresponsive.
    pub max_unanswered_pings: u32,
}

impl Default for ServerLimits {
    fn default() -> Self {
        Self {
            max_connections: 256,
            event_queue_capacity: 256,
            event_queue_bytes: AUTHENTICATED_MAX_FRAME_BYTES,
            max_http_upgrade_bytes: MAX_HTTP_UPGRADE_BYTES,
            max_sessions: 1024,
            max_pending_per_node: 256,
            max_unanswered_pings: 3,
        }
    }
}

impl ServerLimits {
    fn validate(&self) -> Result<(), ConfigurationError> {
        for (name, value) in [
            ("max_connections", self.max_connections),
            ("event_queue_capacity", self.event_queue_capacity),
            ("event_queue_bytes", self.event_queue_bytes),
            ("max_http_upgrade_bytes", self.max_http_upgrade_bytes),
            ("max_sessions", self.max_sessions),
            ("max_pending_per_node", self.max_pending_per_node),
        ] {
            if value == 0 {
                return Err(ConfigurationError::ZeroLimit(name));
            }
        }
        if self.max_unanswered_pings == 0 {
            return Err(ConfigurationError::ZeroLimit("max_unanswered_pings"));
        }
        if self.event_queue_bytes > AUTHENTICATED_MAX_FRAME_BYTES {
            return Err(ConfigurationError::LimitAboveTransportCap(
                "event_queue_bytes",
            ));
        }
        if self.max_http_upgrade_bytes > PREAUTH_MAX_FRAME_BYTES {
            return Err(ConfigurationError::LimitAboveTransportCap(
                "max_http_upgrade_bytes",
            ));
        }
        Ok(())
    }
}

/// Bounded lifecycle timeouts.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ServerTimeouts {
    /// Time budget for reading one complete HTTP upgrade request.
    pub http_upgrade: Duration,
    /// Time budget from the challenge event until the hello response is sent.
    pub handshake: Duration,
    /// Interval between server pings on an otherwise idle connection.
    pub ping_interval: Duration,
    /// Interval between broadcast `tick` events.
    pub tick_interval: Duration,
    /// Time budget for the closing handshake.
    pub close: Duration,
}

impl Default for ServerTimeouts {
    fn default() -> Self {
        Self {
            http_upgrade: Duration::from_secs(10),
            handshake: Duration::from_secs(10),
            ping_interval: Duration::from_secs(20),
            tick_interval: Duration::from_secs(30),
            close: Duration::from_secs(3),
        }
    }
}

impl ServerTimeouts {
    fn validate(&self) -> Result<(), ConfigurationError> {
        for (name, value) in [
            ("http_upgrade", self.http_upgrade),
            ("handshake", self.handshake),
            ("ping_interval", self.ping_interval),
            ("tick_interval", self.tick_interval),
            ("close", self.close),
        ] {
            if value.is_zero() {
                return Err(ConfigurationError::ZeroTimeout(name));
            }
        }
        Ok(())
    }
}

/// Complete configuration for one Gateway server instance.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GatewayServerConfig {
    /// Version string advertised by `hello-ok`.
    pub server_version: String,
    /// Bounded resource caps.
    pub limits: ServerLimits,
    /// Bounded lifecycle timeouts.
    pub timeouts: ServerTimeouts,
    /// How far the plaintext listener may be exposed.
    pub exposure: Exposure,
}

impl Default for GatewayServerConfig {
    fn default() -> Self {
        Self {
            server_version: env!("CARGO_PKG_VERSION").to_owned(),
            limits: ServerLimits::default(),
            timeouts: ServerTimeouts::default(),
            exposure: Exposure::default(),
        }
    }
}

impl GatewayServerConfig {
    /// Validates every bound and returns the checked, immutable configuration.
    pub fn validate(self) -> Result<ValidatedConfig, ConfigurationError> {
        self.limits.validate()?;
        self.timeouts.validate()?;
        let server_version = Name::new(self.server_version.clone(), MAX_SERVER_VERSION_BYTES)
            .map_err(|_| ConfigurationError::InvalidServerVersion)?;
        Ok(ValidatedConfig {
            server_version,
            limits: self.limits,
            timeouts: self.timeouts,
            exposure: self.exposure,
        })
    }
}

/// How far this server is permitted to expose its plaintext listener.
///
/// This server speaks RFC 6455 over a plain TCP stream; it terminates no TLS of
/// its own. On a routable interface that lets an on-path attacker proxy a
/// legitimate device's signed handshake and then inject requests into the
/// resulting authenticated plaintext connection, acting with the victim's
/// scopes without ever holding its private key. The default therefore refuses
/// any address that is not loopback, and the refusal is an explicit typed
/// error rather than a silent downgrade.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub enum Exposure {
    /// Only loopback addresses may be bound.
    ///
    /// Note that wildcard addresses such as `0.0.0.0` and `[::]` are *not*
    /// loopback and are refused under this policy.
    #[default]
    LoopbackOnly,
    /// A routable address may be bound because TLS is terminated in front.
    ///
    /// Selecting this is an assertion by the operator that a reverse proxy
    /// terminates TLS and that nothing untrusted can reach the plaintext
    /// listener. This server cannot verify that claim, so it is deliberately
    /// an explicit opt-in.
    TlsTerminatedByFrontend,
}

impl Exposure {
    /// Reports whether this policy admits binding `address`.
    #[must_use]
    pub const fn admits(self, address: &SocketAddr) -> bool {
        match self {
            Self::LoopbackOnly => address.ip().is_loopback(),
            Self::TlsTerminatedByFrontend => true,
        }
    }
}

/// A [`GatewayServerConfig`] whose invariants have been proven once.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ValidatedConfig {
    server_version: Name,
    limits: ServerLimits,
    timeouts: ServerTimeouts,
    exposure: Exposure,
}

impl ValidatedConfig {
    /// Returns the bounded advertised server version.
    #[must_use]
    pub const fn server_version(&self) -> &Name {
        &self.server_version
    }

    /// Returns the validated resource caps.
    #[must_use]
    pub const fn limits(&self) -> &ServerLimits {
        &self.limits
    }

    /// Returns the validated lifecycle timeouts.
    #[must_use]
    pub const fn timeouts(&self) -> &ServerTimeouts {
        &self.timeouts
    }

    /// Returns the configured listener exposure policy.
    #[must_use]
    pub const fn exposure(&self) -> Exposure {
        self.exposure
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Addresses that are loopback, and therefore admitted by default.
    const LOOPBACK: [&str; 4] = [
        "127.0.0.1:9000",
        "127.0.0.5:9000",
        "[::1]:9000",
        "127.255.255.254:9000",
    ];

    /// Addresses that are not loopback, and therefore refused by default.
    ///
    /// The wildcards matter most: they are what an operator reaches for when
    /// they want the gateway reachable, and they are exactly the case that
    /// exposes a plaintext authenticated session to an on-path attacker.
    const ROUTABLE: [&str; 6] = [
        "0.0.0.0:9000",
        "[::]:9000",
        "192.168.1.10:9000",
        "10.0.0.1:9000",
        "203.0.113.7:9000",
        "[2001:db8::1]:9000",
    ];

    #[test]
    fn the_default_exposure_is_loopback_only() {
        assert_eq!(Exposure::default(), Exposure::LoopbackOnly);
        assert_eq!(
            GatewayServerConfig::default().exposure,
            Exposure::LoopbackOnly
        );
        assert_eq!(
            GatewayServerConfig::default()
                .validate()
                .expect("the default configuration is valid")
                .exposure(),
            Exposure::LoopbackOnly
        );
    }

    #[test]
    fn loopback_only_admits_every_loopback_address() {
        for text in LOOPBACK {
            let address: SocketAddr = text.parse().expect("the fixture address parses");
            assert!(
                Exposure::LoopbackOnly.admits(&address),
                "`{text}` is loopback and must be admitted"
            );
        }
    }

    #[test]
    fn loopback_only_refuses_every_routable_address() {
        for text in ROUTABLE {
            let address: SocketAddr = text.parse().expect("the fixture address parses");
            assert!(
                !Exposure::LoopbackOnly.admits(&address),
                "`{text}` is routable and must be refused"
            );
        }
    }

    #[test]
    fn the_front_end_tls_opt_in_admits_routable_addresses() {
        for text in ROUTABLE.iter().chain(LOOPBACK.iter()) {
            let address: SocketAddr = text.parse().expect("the fixture address parses");
            assert!(
                Exposure::TlsTerminatedByFrontend.admits(&address),
                "`{text}` must be admitted once TLS termination is asserted"
            );
        }
    }

    #[test]
    fn zero_connection_limit_is_rejected_by_name() {
        let mut config = GatewayServerConfig::default();
        config.limits.max_connections = 0;
        assert_eq!(
            config.validate().unwrap_err(),
            ConfigurationError::ZeroLimit("max_connections")
        );
    }

    #[test]
    fn event_queue_bytes_above_authenticated_cap_is_rejected() {
        let mut config = GatewayServerConfig::default();
        config.limits.event_queue_bytes = AUTHENTICATED_MAX_FRAME_BYTES + 1;
        assert_eq!(
            config.validate().unwrap_err(),
            ConfigurationError::LimitAboveTransportCap("event_queue_bytes")
        );
    }

    #[test]
    fn upgrade_budget_above_preauth_cap_is_rejected() {
        let mut config = GatewayServerConfig::default();
        config.limits.max_http_upgrade_bytes = PREAUTH_MAX_FRAME_BYTES + 1;
        assert_eq!(
            config.validate().unwrap_err(),
            ConfigurationError::LimitAboveTransportCap("max_http_upgrade_bytes")
        );
    }

    #[test]
    fn zero_tick_interval_is_rejected_by_name() {
        let mut config = GatewayServerConfig::default();
        config.timeouts.tick_interval = Duration::ZERO;
        assert_eq!(
            config.validate().unwrap_err(),
            ConfigurationError::ZeroTimeout("tick_interval")
        );
    }

    #[test]
    fn empty_server_version_is_rejected() {
        let config = GatewayServerConfig {
            server_version: String::new(),
            ..GatewayServerConfig::default()
        };
        assert_eq!(
            config.validate().unwrap_err(),
            ConfigurationError::InvalidServerVersion
        );
    }

    #[test]
    fn oversized_server_version_is_rejected() {
        let config = GatewayServerConfig {
            server_version: "v".repeat(MAX_SERVER_VERSION_BYTES + 1),
            ..GatewayServerConfig::default()
        };
        assert_eq!(
            config.validate().unwrap_err(),
            ConfigurationError::InvalidServerVersion
        );
    }

    #[test]
    fn defaults_validate_and_preserve_every_field() {
        let config = GatewayServerConfig::default();
        let limits = config.limits;
        let timeouts = config.timeouts;
        let validated = config.validate().expect("defaults are valid");
        assert_eq!(
            validated.server_version().as_str(),
            env!("CARGO_PKG_VERSION")
        );
        assert_eq!(*validated.limits(), limits);
        assert_eq!(*validated.timeouts(), timeouts);
    }
}

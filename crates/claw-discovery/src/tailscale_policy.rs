//! The Tailscale Serve and Funnel authorisation gate.
//!
//! This is the decision that has to happen *before* any `LocalAPI` call: whether
//! an exposure is allowed to exist at all. It is deliberately separate from the
//! transport, because a transport that faithfully performs a read-modify-write
//! against the `LocalAPI` will just as faithfully publish an exposure that policy
//! should never have permitted.
//!
//! Four conditions gate a Funnel exposure and all four fail closed:
//!
//! * the public port must be one Tailscale actually terminates for Funnel —
//!   443, 8443 or 10000. Any other port produces a node that believes it is
//!   published and an ingress that silently never arrives;
//! * the node must carry the `funnel` node attribute granted by the tailnet
//!   policy file;
//! * the tailnet must have HTTPS certificates enabled, because Funnel is
//!   HTTPS-only;
//! * the node must be currently authorised: not expired, not awaiting machine
//!   approval.
//!
//! A Serve exposure is tailnet-internal, so it is gated on node authorisation
//! and target sanity only.

use core::fmt;
use std::collections::{BTreeMap, BTreeSet};
use std::error::Error;
use std::net::{IpAddr, SocketAddr};

/// The public ports Tailscale Funnel terminates.
pub const FUNNEL_PUBLIC_PORTS: [u16; 3] = [443, 8443, 10000];
/// The node attribute a tailnet policy file must grant before Funnel works.
pub const FUNNEL_NODE_ATTRIBUTE: &str = "funnel";

/// How an exposure reaches the outside world.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum ExposureMode {
    /// Reachable from inside the tailnet only.
    Serve,
    /// Reachable from the public internet.
    Funnel,
}

impl fmt::Display for ExposureMode {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::Serve => "serve",
            Self::Funnel => "funnel",
        })
    }
}

/// One node as the tailnet policy file and the coordination server describe it.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct NodePolicy {
    /// Node attributes granted by the tailnet policy file.
    pub attributes: BTreeSet<String>,
    /// ACL tags carried by the node.
    pub tags: BTreeSet<String>,
    /// Whether the node key has expired.
    pub key_expired: bool,
    /// Whether the node is still waiting for manual machine approval.
    pub awaiting_approval: bool,
}

impl NodePolicy {
    /// Builds an authorised node carrying the given attributes.
    #[must_use]
    pub fn with_attributes<I, S>(attributes: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        Self {
            attributes: attributes.into_iter().map(Into::into).collect(),
            ..Self::default()
        }
    }
}

/// The tailnet-wide settings that gate an exposure.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct TailnetPolicy {
    /// Whether HTTPS certificates are enabled for the tailnet.
    pub https_enabled: bool,
    /// Nodes by their tailnet DNS name.
    pub nodes: BTreeMap<String, NodePolicy>,
}

impl TailnetPolicy {
    /// Evaluates one exposure request against this policy.
    ///
    /// # Errors
    ///
    /// Returns the [`PolicyDenial`] naming the first condition that failed. The
    /// conditions are checked in a fixed order — node identity, node
    /// authorisation, target sanity, then mode-specific rules — so a denial is
    /// reproducible and does not depend on map iteration order.
    pub fn evaluate(&self, request: &ExposureRequest) -> Result<ExposurePlan, PolicyDenial> {
        let node = self.nodes.get(&request.node).ok_or_else(|| PolicyDenial {
            cause: DenialCause::UnknownNode,
            detail: format!("node {} is not in the tailnet policy", request.node),
        })?;
        if node.key_expired {
            return Err(PolicyDenial {
                cause: DenialCause::NodeKeyExpired,
                detail: format!("node {} has an expired node key", request.node),
            });
        }
        if node.awaiting_approval {
            return Err(PolicyDenial {
                cause: DenialCause::MachineAuthPending,
                detail: format!("node {} is awaiting machine approval", request.node),
            });
        }
        if !request.path.starts_with('/') {
            return Err(PolicyDenial {
                cause: DenialCause::InvalidPath,
                detail: format!("exposure path {:?} is not absolute", request.path),
            });
        }
        if request.path.contains("..") {
            return Err(PolicyDenial {
                cause: DenialCause::InvalidPath,
                detail: format!("exposure path {:?} traverses upwards", request.path),
            });
        }
        if request.public_port == 0 {
            return Err(PolicyDenial {
                cause: DenialCause::PublicPortNotAllowed,
                detail: "public port 0 is not routable".to_owned(),
            });
        }
        if !is_loopback(request.backend.ip()) {
            return Err(PolicyDenial {
                cause: DenialCause::BackendNotLoopback,
                detail: format!(
                    "backend {} is not on the loopback interface, so the exposure would \
                     republish a third party",
                    request.backend
                ),
            });
        }
        if request.mode == ExposureMode::Funnel {
            if !FUNNEL_PUBLIC_PORTS.contains(&request.public_port) {
                return Err(PolicyDenial {
                    cause: DenialCause::PublicPortNotAllowed,
                    detail: format!(
                        "funnel public port {} is not one of {:?}",
                        request.public_port, FUNNEL_PUBLIC_PORTS
                    ),
                });
            }
            if !node.attributes.contains(FUNNEL_NODE_ATTRIBUTE) {
                return Err(PolicyDenial {
                    cause: DenialCause::MissingFunnelAttribute,
                    detail: format!(
                        "node {} does not carry the {FUNNEL_NODE_ATTRIBUTE} node attribute",
                        request.node
                    ),
                });
            }
            if !self.https_enabled {
                return Err(PolicyDenial {
                    cause: DenialCause::HttpsDisabled,
                    detail: "funnel requires tailnet HTTPS certificates".to_owned(),
                });
            }
        }
        Ok(ExposurePlan {
            host_port: format!("{}:{}", request.node, request.public_port),
            mode: request.mode,
            backend: request.backend,
            path: request.path.clone(),
            allow_funnel: request.mode == ExposureMode::Funnel,
        })
    }
}

const fn is_loopback(address: IpAddr) -> bool {
    match address {
        IpAddr::V4(value) => value.is_loopback(),
        IpAddr::V6(value) => value.is_loopback(),
    }
}

/// A request to publish a local backend through Serve or Funnel.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ExposureRequest {
    /// Tailnet DNS name of the node performing the exposure.
    pub node: String,
    /// Serve or Funnel.
    pub mode: ExposureMode,
    /// Port the exposure is published on.
    pub public_port: u16,
    /// Local backend the exposure proxies to.
    pub backend: SocketAddr,
    /// Absolute path prefix the exposure is mounted at.
    pub path: String,
}

/// An authorised exposure, in the shape the `LocalAPI` serve config uses.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ExposurePlan {
    /// `node:port` key the serve config is indexed by.
    pub host_port: String,
    /// Serve or Funnel.
    pub mode: ExposureMode,
    /// Local backend.
    pub backend: SocketAddr,
    /// Absolute path prefix.
    pub path: String,
    /// Whether `AllowFunnel` must be set for [`ExposurePlan::host_port`].
    pub allow_funnel: bool,
}

/// Why an exposure was refused.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DenialCause {
    /// The node is not present in the tailnet policy.
    UnknownNode,
    /// The node key has expired.
    NodeKeyExpired,
    /// The node has not been approved yet.
    MachineAuthPending,
    /// The tailnet does not have HTTPS certificates enabled.
    HttpsDisabled,
    /// The node lacks the `funnel` node attribute.
    MissingFunnelAttribute,
    /// The public port is not one Funnel terminates, or is zero.
    PublicPortNotAllowed,
    /// The backend is not on the loopback interface.
    BackendNotLoopback,
    /// The mount path was not an absolute, non-traversing path.
    InvalidPath,
}

impl fmt::Display for DenialCause {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::UnknownNode => "unknown-node",
            Self::NodeKeyExpired => "node-key-expired",
            Self::MachineAuthPending => "machine-auth-pending",
            Self::HttpsDisabled => "https-disabled",
            Self::MissingFunnelAttribute => "missing-funnel-attribute",
            Self::PublicPortNotAllowed => "public-port-not-allowed",
            Self::BackendNotLoopback => "backend-not-loopback",
            Self::InvalidPath => "invalid-path",
        })
    }
}

impl DenialCause {
    /// Returns non-secret operator guidance for resolving this denial.
    #[must_use]
    pub const fn remediation(self) -> &'static str {
        match self {
            Self::UnknownNode => "refresh tailnet status and select a node present in policy",
            Self::NodeKeyExpired => "renew the node key before creating an exposure",
            Self::MachineAuthPending => "approve the machine in the tailnet admin console",
            Self::HttpsDisabled => "enable tailnet HTTPS certificates before using Funnel",
            Self::MissingFunnelAttribute => {
                "grant the funnel node attribute in tailnet policy before publishing"
            }
            Self::PublicPortNotAllowed => {
                "use Serve or select a Tailscale-supported Funnel public port"
            }
            Self::BackendNotLoopback => "bind the backend to a loopback address before publishing",
            Self::InvalidPath => "use an absolute path without parent traversal",
        }
    }
}

/// A refusal, carrying both its machine-readable cause and an operator message.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PolicyDenial {
    /// Machine-readable cause.
    pub cause: DenialCause,
    /// Human-readable detail.
    pub detail: String,
}

impl PolicyDenial {
    /// Returns safe operator guidance for the machine-readable denial cause.
    #[must_use]
    pub const fn remediation(&self) -> &'static str {
        self.cause.remediation()
    }
}

impl fmt::Display for PolicyDenial {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{}: {}", self.cause, self.detail)
    }
}

impl Error for PolicyDenial {}

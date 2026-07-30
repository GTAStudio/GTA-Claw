//! Node identity and the authenticated Gateway v3 N-1 compatibility window.

use std::error::Error;
use std::fmt::{self, Display, Formatter};

use claw_security::authorization::{
    CURRENT_PROTOCOL_VERSION, ClientClass, ProtocolPolicyError, Role, validate_protocol,
};
use claw_security::identity::{DeviceId, DevicePublicKey};

/// A compatibility client admitted at the node boundary.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum NodeClientKind {
    /// A capability-host client declaring the Gateway node role and mode.
    Node,
    /// A lightweight authenticated connectivity probe.
    Probe,
}

/// The exact compatibility path selected for an authenticated client.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ProtocolCompatibility {
    /// Current Gateway protocol v4.
    Current,
    /// Authenticated node compatibility at protocol v3.
    LegacyNode,
    /// Authenticated probe compatibility at protocol v3.
    LegacyProbe,
}

/// Validates the closed v4/v3 compatibility window.
///
/// The N-1 exception is never available before authentication. General clients,
/// workers, and protocol versions outside v3/v4 remain the responsibility of
/// the Gateway's ordinary strict handshake.
///
/// # Errors
///
/// Returns [`NodeIdentityError`] when authentication is absent or the client
/// kind and protocol version are outside the closed compatibility window.
pub fn admit_protocol(
    kind: NodeClientKind,
    protocol_version: u16,
    authenticated: bool,
) -> Result<ProtocolCompatibility, NodeIdentityError> {
    if !authenticated {
        return Err(NodeIdentityError::AuthenticationRequired);
    }

    let (role, class) = match kind {
        NodeClientKind::Node => (Role::Node, ClientClass::AuthenticatedNode),
        NodeClientKind::Probe => (Role::Operator, ClientClass::Probe),
    };
    validate_protocol(role, class, protocol_version).map_err(NodeIdentityError::Protocol)?;

    match (kind, protocol_version) {
        (_, CURRENT_PROTOCOL_VERSION) => Ok(ProtocolCompatibility::Current),
        (NodeClientKind::Node, 3) => Ok(ProtocolCompatibility::LegacyNode),
        (NodeClientKind::Probe, 3) => Ok(ProtocolCompatibility::LegacyProbe),
        _ => Err(NodeIdentityError::Protocol(
            ProtocolPolicyError::UnsupportedVersion,
        )),
    }
}

/// Public identity bound to an authenticated node connection.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct NodeIdentity {
    device_id: DeviceId,
    public_key: DevicePublicKey,
}

impl NodeIdentity {
    /// Constructs an identity only when the fingerprint matches the public key.
    ///
    /// # Errors
    ///
    /// Returns [`NodeIdentityError::DeviceIdMismatch`] when the public key does
    /// not derive to the claimed device identifier.
    pub fn new(
        device_id: DeviceId,
        public_key: DevicePublicKey,
    ) -> Result<Self, NodeIdentityError> {
        if public_key.device_id() != device_id {
            return Err(NodeIdentityError::DeviceIdMismatch);
        }
        Ok(Self {
            device_id,
            public_key,
        })
    }

    /// Returns the stable device fingerprint.
    #[must_use]
    pub const fn device_id(&self) -> DeviceId {
        self.device_id
    }

    /// Returns the strictly decoded Ed25519 public key.
    #[must_use]
    pub const fn public_key(&self) -> DevicePublicKey {
        self.public_key
    }
}

/// Rejection at the node identity boundary.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum NodeIdentityError {
    /// Node and probe compatibility is available only after authentication.
    AuthenticationRequired,
    /// The public key does not derive to the claimed device identifier.
    DeviceIdMismatch,
    /// The protocol claim is outside the frozen compatibility policy.
    Protocol(ProtocolPolicyError),
}

impl Display for NodeIdentityError {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        match self {
            Self::AuthenticationRequired => {
                formatter.write_str("node or probe authentication is required")
            }
            Self::DeviceIdMismatch => {
                formatter.write_str("node device id does not match public key")
            }
            Self::Protocol(error) => Display::fmt(error, formatter),
        }
    }
}

impl Error for NodeIdentityError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Protocol(error) => Some(error),
            _ => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use rand_chacha::{
        ChaCha20Rng,
        rand_core::{Rng, SeedableRng},
    };

    use claw_security::identity::{DeviceIdentity, DevicePublicKey};

    use super::{
        NodeClientKind, NodeIdentity, NodeIdentityError, ProtocolCompatibility, admit_protocol,
    };

    #[test]
    fn admits_only_authenticated_v3_node_and_probe_clients() {
        assert_eq!(
            admit_protocol(NodeClientKind::Node, 3, true),
            Ok(ProtocolCompatibility::LegacyNode)
        );
        assert_eq!(
            admit_protocol(NodeClientKind::Probe, 3, true),
            Ok(ProtocolCompatibility::LegacyProbe)
        );
        assert_eq!(
            admit_protocol(NodeClientKind::Node, 3, false),
            Err(NodeIdentityError::AuthenticationRequired)
        );
        assert!(matches!(
            admit_protocol(NodeClientKind::Node, 2, true),
            Err(NodeIdentityError::Protocol(_))
        ));
        assert!(matches!(
            admit_protocol(NodeClientKind::Probe, 5, true),
            Err(NodeIdentityError::Protocol(_))
        ));
    }

    #[test]
    fn rejects_a_public_key_under_another_device_id() {
        let mut rng = ChaCha20Rng::seed_from_u64(71);
        let identity = DeviceIdentity::generate(&mut rng);
        let mut key_bytes = [0_u8; 32];
        rng.fill_bytes(&mut key_bytes);
        let other_key = loop {
            if let Ok(key) = DevicePublicKey::decode(&key_bytes) {
                break key;
            }
            rng.fill_bytes(&mut key_bytes);
        };

        assert_eq!(
            NodeIdentity::new(identity.device_id(), other_key),
            Err(NodeIdentityError::DeviceIdMismatch)
        );
    }
}

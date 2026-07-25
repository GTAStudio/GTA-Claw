//! Gateway v4 client identity for the iOS product.

use std::error::Error;
use std::fmt::{self, Display, Formatter};

use claw_gateway_client::ClientMetadata;
use claw_protocol::gateway::{ClientId, ClientMode, Name, StringValidationError};

use crate::device::IosDeviceProbe;

/// Maximum UTF-8 byte length of each client metadata field.
const MAX_METADATA_BYTES: usize = 64;

/// Client metadata this build will present to a Gateway as the iOS product.
///
/// The product identity ([`ClientId::Ios`], [`ClientMode::Ui`]) is asserted by
/// this crate. Everything else is *observed*: `version` comes from the package
/// version, `platform` comes from the compilation target, and the device fields
/// come from an [`IosDeviceProbe`] and are omitted when the probe cannot see
/// them. A build of this crate running on a workstation truthfully reports its
/// own platform rather than claiming to be an iPhone.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct IosClientIdentity {
    version: Name,
    platform: Name,
    device_family: Option<Name>,
    model_identifier: Option<Name>,
    instance_id: Option<Name>,
}

impl IosClientIdentity {
    /// Builds an identity from what the host can actually observe.
    ///
    /// # Errors
    ///
    /// Returns [`IdentityError`] when a probe supplies a field that is empty or
    /// longer than the Gateway metadata limit.
    pub fn observe<P>(probe: &P) -> Result<Self, IdentityError>
    where
        P: IosDeviceProbe + ?Sized,
    {
        Ok(Self {
            version: field("version", env!("CARGO_PKG_VERSION"))?,
            platform: field("platform", std::env::consts::OS)?,
            device_family: optional_field("device family", probe.device_family())?,
            model_identifier: optional_field("model identifier", probe.model_identifier())?,
            instance_id: optional_field("instance id", probe.instance_id())?,
        })
    }

    /// Returns the compilation target reported as the runtime platform.
    #[must_use]
    pub fn platform(&self) -> &str {
        self.platform.as_str()
    }

    /// Returns whether this build targets an Apple platform other than macOS.
    ///
    /// A `false` result on a build that presents [`ClientId::Ios`] is expected
    /// during development and testing on a workstation, and is not an error. It
    /// exists so that a caller can decide whether to trust the absence of device
    /// fields, rather than inferring it from their absence alone.
    #[must_use]
    pub const fn targets_ios() -> bool {
        cfg!(target_os = "ios")
    }

    /// Returns Gateway client metadata for this identity.
    #[must_use]
    pub fn metadata(&self) -> ClientMetadata {
        ClientMetadata {
            id: ClientId::Ios,
            display_name: None,
            version: self.version.clone(),
            platform: self.platform.clone(),
            device_family: self.device_family.clone(),
            model_identifier: self.model_identifier.clone(),
            mode: ClientMode::Ui,
            instance_id: self.instance_id.clone(),
        }
    }
}

fn field(label: &'static str, value: &str) -> Result<Name, IdentityError> {
    Name::new(value, MAX_METADATA_BYTES).map_err(|cause| IdentityError { label, cause })
}

fn optional_field(
    label: &'static str,
    value: Option<String>,
) -> Result<Option<Name>, IdentityError> {
    value.map(|value| field(label, &value)).transpose()
}

/// A client metadata field a probe supplied that the Gateway will not accept.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct IdentityError {
    label: &'static str,
    cause: StringValidationError,
}

impl IdentityError {
    /// Returns which metadata field was rejected.
    #[must_use]
    pub const fn label(&self) -> &'static str {
        self.label
    }

    /// Returns the underlying validation failure.
    #[must_use]
    pub const fn cause(&self) -> &StringValidationError {
        &self.cause
    }
}

impl Display for IdentityError {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "iOS client {} is not valid Gateway metadata: {}",
            self.label, self.cause
        )
    }
}

impl Error for IdentityError {}

#[cfg(test)]
mod tests {
    use claw_protocol::gateway::{ClientId, ClientMode};

    use super::{IosClientIdentity, MAX_METADATA_BYTES};
    use crate::device::{DeclaredDeviceProbe, UnobservedDeviceProbe};

    #[test]
    fn the_product_identity_is_the_ios_client_in_ui_mode() {
        let identity =
            IosClientIdentity::observe(&UnobservedDeviceProbe).expect("identity is buildable");
        let metadata = identity.metadata();

        assert_eq!(metadata.id, ClientId::Ios);
        assert_eq!(metadata.id.as_str(), "openclaw-ios");
        assert_eq!(metadata.mode, ClientMode::Ui);
    }

    #[test]
    fn an_unobserved_device_leaves_the_optional_fields_absent() {
        let identity =
            IosClientIdentity::observe(&UnobservedDeviceProbe).expect("identity is buildable");
        let metadata = identity.metadata();

        assert_eq!(
            metadata.device_family, None,
            "device family must be absent, not guessed; metadata was {metadata:?}"
        );
        assert_eq!(
            metadata.model_identifier, None,
            "model identifier must be absent, not guessed; metadata was {metadata:?}"
        );
    }

    #[test]
    fn the_reported_platform_is_the_compilation_target_not_a_claim_of_ios() {
        let identity =
            IosClientIdentity::observe(&UnobservedDeviceProbe).expect("identity is buildable");

        assert_eq!(
            identity.platform(),
            std::env::consts::OS,
            "platform must report the host this build actually runs on"
        );
        assert_eq!(
            IosClientIdentity::targets_ios(),
            cfg!(target_os = "ios"),
            "targets_ios must agree with the compilation target"
        );
    }

    #[test]
    fn declared_device_facts_reach_the_metadata_verbatim() {
        let probe = DeclaredDeviceProbe::new()
            .with_device_family("iPhone")
            .with_model_identifier("iPhone16,2")
            .with_instance_id("installation-7");
        let metadata = IosClientIdentity::observe(&probe)
            .expect("identity is buildable")
            .metadata();

        assert_eq!(
            metadata
                .device_family
                .as_ref()
                .map(claw_protocol::gateway::Name::as_str),
            Some("iPhone")
        );
        assert_eq!(
            metadata
                .model_identifier
                .as_ref()
                .map(claw_protocol::gateway::Name::as_str),
            Some("iPhone16,2")
        );
        assert_eq!(
            metadata
                .instance_id
                .as_ref()
                .map(claw_protocol::gateway::Name::as_str),
            Some("installation-7")
        );
    }

    #[test]
    fn an_oversized_declared_field_is_reported_rather_than_truncated() {
        let oversized = "i".repeat(MAX_METADATA_BYTES + 1);
        let probe = DeclaredDeviceProbe::new().with_model_identifier(oversized.clone());
        let error = IosClientIdentity::observe(&probe).err().unwrap_or_else(|| {
            panic!(
                "a {}-byte model identifier must be refused",
                oversized.len()
            )
        });

        assert_eq!(
            error.label(),
            "model identifier",
            "wrong field reported for error {error}"
        );
    }
}

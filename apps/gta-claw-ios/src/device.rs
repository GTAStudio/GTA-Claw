//! Observation port for Apple device facts the client may put on the wire.

/// Supplies device facts that only the host operating system can observe.
///
/// Every method returns [`None`] when the fact cannot be observed. Implementors
/// must not substitute a plausible-looking default: these values travel to the
/// Gateway as client metadata, and a fabricated device identity is
/// indistinguishable from a real one once it has been recorded server side.
pub trait IosDeviceProbe {
    /// Returns the Apple device family, such as `iPhone` or `iPad`.
    fn device_family(&self) -> Option<String>;

    /// Returns the Apple model identifier, such as `iPhone16,2`.
    fn model_identifier(&self) -> Option<String>;

    /// Returns a stable per-installation identifier for this client instance.
    fn instance_id(&self) -> Option<String>;
}

/// A probe that reports no device facts at all.
///
/// This is the only probe this crate can honestly provide today. Reading
/// `UIDevice.current.model` or the `hw.machine` sysctl requires Objective-C or
/// libc interop, and the workspace forbids `unsafe_code`, so the crate has no
/// way to observe an Apple device. Returning `None` makes the resulting
/// [`ClientMetadata`](claw_gateway_client::ClientMetadata) omit the optional
/// device fields rather than assert something untrue about the hardware.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct UnobservedDeviceProbe;

impl IosDeviceProbe for UnobservedDeviceProbe {
    fn device_family(&self) -> Option<String> {
        None
    }

    fn model_identifier(&self) -> Option<String> {
        None
    }

    fn instance_id(&self) -> Option<String> {
        None
    }
}

/// A probe whose facts were supplied by the embedder rather than observed here.
///
/// An iOS application target that *can* read UIKit — for example a future Slint
/// shell, or a thin Swift launcher — passes what it read through this type. The
/// name says where the values came from, so that a reader of
/// [`IosClientIdentity`](crate::IosClientIdentity) is never misled into
/// believing this crate measured them.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct DeclaredDeviceProbe {
    device_family: Option<String>,
    model_identifier: Option<String>,
    instance_id: Option<String>,
}

impl DeclaredDeviceProbe {
    /// Creates a probe with no declared facts.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            device_family: None,
            model_identifier: None,
            instance_id: None,
        }
    }

    /// Declares the Apple device family the embedder read from the host.
    #[must_use]
    pub fn with_device_family(mut self, value: impl Into<String>) -> Self {
        self.device_family = Some(value.into());
        self
    }

    /// Declares the Apple model identifier the embedder read from the host.
    #[must_use]
    pub fn with_model_identifier(mut self, value: impl Into<String>) -> Self {
        self.model_identifier = Some(value.into());
        self
    }

    /// Declares the per-installation identifier the embedder holds.
    #[must_use]
    pub fn with_instance_id(mut self, value: impl Into<String>) -> Self {
        self.instance_id = Some(value.into());
        self
    }
}

impl IosDeviceProbe for DeclaredDeviceProbe {
    fn device_family(&self) -> Option<String> {
        self.device_family.clone()
    }

    fn model_identifier(&self) -> Option<String> {
        self.model_identifier.clone()
    }

    fn instance_id(&self) -> Option<String> {
        self.instance_id.clone()
    }
}

#[cfg(test)]
mod tests {
    use super::{DeclaredDeviceProbe, IosDeviceProbe, UnobservedDeviceProbe};

    #[test]
    fn the_unobserved_probe_never_invents_a_device() {
        let probe = UnobservedDeviceProbe;

        assert_eq!(
            probe.device_family(),
            None,
            "UnobservedDeviceProbe must not assert a device family"
        );
        assert_eq!(
            probe.model_identifier(),
            None,
            "UnobservedDeviceProbe must not assert a model identifier"
        );
        assert_eq!(
            probe.instance_id(),
            None,
            "UnobservedDeviceProbe must not assert an instance id"
        );
    }

    #[test]
    fn a_declared_probe_returns_exactly_what_the_embedder_declared() {
        let probe = DeclaredDeviceProbe::new()
            .with_device_family("iPhone")
            .with_model_identifier("iPhone16,2");

        assert_eq!(probe.device_family().as_deref(), Some("iPhone"));
        assert_eq!(probe.model_identifier().as_deref(), Some("iPhone16,2"));
        assert_eq!(
            probe.instance_id(),
            None,
            "an undeclared fact must stay absent, not become a default"
        );
    }
}

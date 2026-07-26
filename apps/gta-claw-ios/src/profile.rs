//! Assembling a Gateway client configuration from what the app has gathered.

use std::sync::Arc;

use claw_application::{Application, SystemProbe};
use claw_gateway_client::{AuthorizationExpectation, ClientMetadata, GatewayClientConfig};
use claw_security::authorization::{Role, Scope, ScopeSet};
use claw_security::identity::DeviceIdentity;

use crate::credential::IosCredential;
use crate::endpoint::{EndpointSummary, GatewayEndpoint};
use crate::identity::IosClientIdentity;
use crate::session::IosSessionModel;

/// Everything the iOS app needs before it may open a Gateway connection.
///
/// This type has no derived [`Debug`]. It owns a
/// [`GatewayCredential`](claw_gateway_client::GatewayCredential) and a
/// [`DeviceIdentity`], either of which can carry secret material, and it owns a
/// [`url::Url`] that a person may have pasted with credentials embedded. The
/// hand-written formatter prints only the redaction-safe endpoint summary and
/// the requested authorization.
pub struct IosGatewayProfile {
    endpoint: GatewayEndpoint,
    credential: IosCredential,
    identity: IosClientIdentity,
    device: Arc<DeviceIdentity>,
    requested_scopes: ScopeSet,
}

impl IosGatewayProfile {
    /// Creates a profile requesting no scopes.
    #[must_use]
    pub const fn new(
        endpoint: GatewayEndpoint,
        credential: IosCredential,
        identity: IosClientIdentity,
        device: Arc<DeviceIdentity>,
    ) -> Self {
        Self {
            endpoint,
            credential,
            identity,
            device,
            requested_scopes: ScopeSet::EMPTY,
        }
    }

    /// Requests a set of operator scopes.
    ///
    /// A requested scope is not a held scope. Nothing in this crate treats the
    /// request as a grant; only [`crate::ObservedAuthorization`], built from the
    /// server hello, decides what an interface may offer.
    #[must_use]
    pub fn requesting(mut self, scopes: impl IntoIterator<Item = Scope>) -> Self {
        self.requested_scopes = ScopeSet::from_scopes(scopes);
        self
    }

    /// Returns display text for the endpoint that cannot carry a credential.
    #[must_use]
    pub fn endpoint_summary(&self) -> EndpointSummary {
        self.endpoint.summary()
    }

    /// Returns the scopes this profile will ask the Gateway for.
    #[must_use]
    pub const fn requested_scopes(&self) -> ScopeSet {
        self.requested_scopes
    }

    /// Returns the Gateway client metadata this profile will present.
    #[must_use]
    pub fn metadata(&self) -> ClientMetadata {
        self.identity.metadata()
    }

    /// Creates a session model bound to this profile's endpoint.
    #[must_use]
    pub fn session_model(&self) -> IosSessionModel {
        IosSessionModel::new(&self.endpoint)
    }

    /// Builds the transport configuration.
    ///
    /// `allow_insecure_remote_ws` is always left at its secure default. There is
    /// no override, because a mobile client spends its life on networks its user
    /// does not control, and [`GatewayEndpoint`] has already refused a remote
    /// plaintext endpoint before this point.
    #[must_use]
    pub fn into_client_config(self) -> GatewayClientConfig {
        let mut config = GatewayClientConfig::new(self.endpoint.into_url(), self.device);
        config.credential = self.credential.into_gateway_credential();
        config.role = Role::Operator;
        config.scopes = self.requested_scopes;
        config.authorization_expectation = AuthorizationExpectation::RequestedRole;
        config.client = self.identity.metadata();
        config
    }
}

impl std::fmt::Debug for IosGatewayProfile {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("IosGatewayProfile")
            .field("endpoint", &self.endpoint.summary())
            .field("credential", &self.credential)
            .field("identity", &self.identity)
            .field("device", &"[REDACTED]")
            .field("requested_scopes", &self.requested_scopes)
            .finish()
    }
}

/// The composition root for the iOS client.
///
/// The headless use cases are reached through [`Application`] and the
/// [`SystemProbe`] port rather than by calling a platform crate directly, so a
/// future user interface layer depends on the port and not on an OS adapter.
#[derive(Debug)]
pub struct IosClientCore<P> {
    application: Application<P>,
}

impl<P> IosClientCore<P>
where
    P: SystemProbe,
{
    /// Composes the client core over a platform probe.
    #[must_use]
    pub const fn new(system_probe: P) -> Self {
        Self {
            application: Application::new(system_probe),
        }
    }

    /// Returns the headless application.
    #[must_use]
    pub const fn application(&self) -> &Application<P> {
        &self.application
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use claw_gateway_client::GatewayCredential;
    use claw_platform::NativeSystemProbe;
    use claw_protocol::gateway::{ClientId, ClientMode};
    use claw_protocol::{ClientCommand, RuntimeDescriptor, ServerEvent};
    use claw_security::authorization::{Role, Scope, ScopeSet};
    use claw_security::identity::DeviceIdentity;
    use rand_chacha::ChaCha20Rng;
    use rand_chacha::rand_core::SeedableRng;

    use super::{IosClientCore, IosGatewayProfile};
    use crate::credential::IosCredential;
    use crate::device::UnobservedDeviceProbe;
    use crate::endpoint::GatewayEndpoint;
    use crate::identity::IosClientIdentity;

    fn device_identity() -> Arc<DeviceIdentity> {
        let mut rng = ChaCha20Rng::seed_from_u64(20_260_702);
        Arc::new(DeviceIdentity::generate(&mut rng))
    }

    fn profile() -> IosGatewayProfile {
        IosGatewayProfile::new(
            GatewayEndpoint::parse("wss://gateway.example:4443").expect("the endpoint is valid"),
            IosCredential::token("fixture-token").expect("the token is valid"),
            IosClientIdentity::observe(&UnobservedDeviceProbe).expect("the identity is buildable"),
            device_identity(),
        )
    }

    #[test]
    fn the_profile_debug_representation_leaks_neither_credential_nor_device_key() {
        let rendered = format!("{:?}", profile());

        assert!(
            !rendered.contains("fixture-token"),
            "Debug leaked the Gateway credential: {rendered}"
        );
        assert!(
            rendered.contains("[REDACTED]"),
            "Debug must mark the device identity redacted: {rendered}"
        );
    }

    #[test]
    fn the_built_configuration_presents_the_ios_client_over_tls() {
        let config = profile()
            .requesting([Scope::OperatorRead, Scope::OperatorWrite])
            .into_client_config();

        assert_eq!(config.url.scheme(), "wss");
        assert_eq!(config.url.host_str(), Some("gateway.example"));
        assert_eq!(config.role, Role::Operator);
        assert_eq!(config.client.id, ClientId::Ios);
        assert_eq!(config.client.mode, ClientMode::Ui);
        assert_eq!(
            config.scopes,
            ScopeSet::from_scopes([Scope::OperatorRead, Scope::OperatorWrite])
        );
        assert!(
            matches!(config.credential, GatewayCredential::Token(_)),
            "the token must reach the transport, got {:?}",
            config.credential
        );
    }

    #[test]
    fn the_built_configuration_never_opts_in_to_remote_plaintext() {
        let config = profile().into_client_config();

        assert!(
            !config.allow_insecure_remote_ws,
            "a mobile client must not enable the plaintext break-glass, config url was {}",
            config.url
        );
    }

    #[test]
    fn a_profile_without_requested_scopes_requests_none() {
        let config = profile().into_client_config();

        assert_eq!(
            config.scopes,
            ScopeSet::EMPTY,
            "an unconfigured profile must not request scopes on the user's behalf"
        );
    }

    #[test]
    fn the_core_reaches_health_through_the_application_port() {
        let core = IosClientCore::new(NativeSystemProbe);
        let event = core
            .application()
            .handle(ClientCommand::Health)
            .expect("health crosses the port");

        assert_eq!(
            event,
            ServerEvent::Healthy {
                runtime: RuntimeDescriptor::new(std::env::consts::OS, std::env::consts::ARCH),
            }
        );
    }
}

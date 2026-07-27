//! Proves the configuration this crate builds is one `claw-gateway-client`
//! actually accepts, rather than one that merely looks plausible.
//!
//! Platform note: these tests have only ever been executed on Windows `x86_64`.
//! They exercise no Apple-specific code path, because this crate contains none.

use std::sync::Arc;

use claw_gateway_client::{
    ConfigurationError, GatewayClient, GatewayClientError, GatewayCredential,
};
use claw_protocol::gateway::{ClientMode, Name};
use claw_security::authorization::Scope;
use claw_security::identity::DeviceIdentity;
use gta_claw_ios::{
    GatewayEndpoint, IosClientIdentity, IosCredential, IosGatewayProfile, UnobservedDeviceProbe,
};
use rand_chacha::ChaCha20Rng;
use rand_chacha::rand_core::SeedableRng;

fn device_identity() -> Arc<DeviceIdentity> {
    let mut rng = ChaCha20Rng::seed_from_u64(4_443);
    Arc::new(DeviceIdentity::generate(&mut rng))
}

fn profile(endpoint: &str) -> IosGatewayProfile {
    IosGatewayProfile::new(
        GatewayEndpoint::parse(endpoint)
            .unwrap_or_else(|error| panic!("{endpoint} must parse, got {error}")),
        IosCredential::token("integration-fixture").expect("the token is valid"),
        IosClientIdentity::observe(&UnobservedDeviceProbe).expect("the identity is buildable"),
        device_identity(),
    )
    .requesting([Scope::OperatorRead])
}

/// The client validates the configuration before it spawns anything, so this
/// case needs no async runtime.
#[test]
fn a_worker_mode_configuration_is_rejected_by_the_real_client() {
    let mut config = profile("ws://127.0.0.1:1").into_client_config();
    config.client.mode = ClientMode::Worker;

    let error = GatewayClient::start(config)
        .err()
        .expect("the client must refuse worker mode");

    assert!(
        matches!(
            error,
            GatewayClientError::Configuration(ConfigurationError::WorkerProtocolUnsupported)
        ),
        "expected a worker-protocol configuration refusal, got {error}"
    );
}

#[test]
fn a_credential_bearing_url_never_reaches_the_client() {
    let error = GatewayEndpoint::parse("wss://gateway.example?token=abcdef")
        .expect_err("a query string is refused");

    assert_eq!(
        error.to_string(),
        "Gateway address must not contain a user, password, query, or fragment"
    );
}

#[tokio::test]
async fn the_real_client_accepts_the_configuration_this_crate_builds() {
    let config = profile("ws://127.0.0.1:1").into_client_config();

    assert_eq!(config.client.mode, ClientMode::Ui);
    assert!(
        matches!(config.credential, GatewayCredential::Token(_)),
        "the fixture must carry a token, got {:?}",
        config.credential
    );

    // Port 1 on loopback refuses immediately. This proves configuration
    // admission and deterministic shutdown; it does NOT prove a handshake,
    // which no test in this crate performs.
    let (client, _events) =
        GatewayClient::start(config).expect("the client must accept this configuration");

    client
        .shutdown()
        .await
        .expect("the client must shut down deterministically");
}

#[tokio::test]
async fn a_declared_device_reaches_the_client_metadata_unchanged() {
    let probe = gta_claw_ios::DeclaredDeviceProbe::new()
        .with_device_family("iPad")
        .with_model_identifier("iPad14,3");
    let profile = IosGatewayProfile::new(
        GatewayEndpoint::parse("ws://127.0.0.1:1").expect("the endpoint is valid"),
        IosCredential::none(),
        IosClientIdentity::observe(&probe).expect("the identity is buildable"),
        device_identity(),
    );
    let config = profile.into_client_config();

    assert_eq!(
        config.client.device_family.as_ref().map(Name::as_str),
        Some("iPad")
    );
    assert_eq!(
        config.client.model_identifier.as_ref().map(Name::as_str),
        Some("iPad14,3")
    );

    let (client, _events) =
        GatewayClient::start(config).expect("the client must accept this configuration");

    client
        .shutdown()
        .await
        .expect("the client must shut down deterministically");
}

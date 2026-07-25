//! Opt-in live contract check against an operator-supplied OpenClaw Gateway.

use std::env;
use std::sync::Arc;
use std::time::Duration;

use claw_gateway_client::{
    ClientMetadata, ClientTimeouts, GatewayClient, GatewayClientConfig, GatewayClientError,
    GatewayCredential, ReconnectPolicy,
};
use claw_protocol::gateway::{
    AUTHENTICATED_MAX_FRAME_BYTES, ClientId, ClientMode, GatewayMethodName, ProtocolVersion,
    RequestId, resolve_core_method,
};
use claw_security::authorization::{Scope, ScopeSet};
use claw_security::identity::DeviceIdentity;
use rand_chacha::ChaCha20Rng;
use rand_chacha::rand_core::SeedableRng;
use secrecy::SecretString;
use serde_json::json;
use url::Url;

fn live_config(url: &Url, token: &str, seed: u8) -> GatewayClientConfig {
    let mut rng = ChaCha20Rng::from_seed([seed; 32]);
    let mut config =
        GatewayClientConfig::new(url.clone(), Arc::new(DeviceIdentity::generate(&mut rng)));
    config.credential = GatewayCredential::Token(SecretString::from(token.to_owned()));
    config.scopes = ScopeSet::from_scopes([Scope::OperatorAdmin]);
    config.client = ClientMetadata {
        id: ClientId::Test,
        mode: ClientMode::Test,
        ..ClientMetadata::default()
    };
    config.reconnect = ReconnectPolicy::Never;
    config.timeouts = ClientTimeouts {
        connect: Duration::from_secs(10),
        authentication: Duration::from_secs(10),
        request: Duration::from_secs(10),
        shutdown: Duration::from_secs(3),
    };
    config
}

#[tokio::test]
#[ignore = "requires an explicitly provisioned external OpenClaw Gateway"]
async fn pinned_official_gateway_live_contract() {
    let url = Url::parse(
        &env::var("OPENCLAW_REFERENCE_URL").expect("OPENCLAW_REFERENCE_URL is required"),
    )
    .expect("reference URL");
    let token = env::var("OPENCLAW_REFERENCE_TOKEN").expect("OPENCLAW_REFERENCE_TOKEN is required");

    let (client, _events) =
        GatewayClient::start(live_config(&url, &token, 51)).expect("start positive client");
    let info = client.wait_ready().await.expect("official v4 hello");
    assert_eq!(info.protocol.get(), 4);
    let response = client
        .request(
            RequestId::new("reference-health", AUTHENTICATED_MAX_FRAME_BYTES).expect("request id"),
            GatewayMethodName::Core(resolve_core_method("health").expect("health registry")),
            &json!({}),
        )
        .await
        .expect("health response");
    assert!(response.ok(), "official health RPC rejected");
    client.shutdown().await.expect("positive clean disconnect");

    let (wrong_auth, _events) =
        GatewayClient::start(live_config(&url, "intentionally-wrong-reference-token", 52))
            .expect("start negative auth client");
    assert!(matches!(
        wrong_auth.wait_ready().await,
        Err(GatewayClientError::Authentication(_))
    ));
    wrong_auth.shutdown().await.expect("negative auth shutdown");

    let mut wrong_version = live_config(&url, &token, 53);
    wrong_version.min_protocol = ProtocolVersion::new(2).expect("v2");
    wrong_version.max_protocol = ProtocolVersion::new(2).expect("v2");
    let (wrong_version, _events) =
        GatewayClient::start(wrong_version).expect("start negative version client");
    assert!(matches!(
        wrong_version.wait_ready().await,
        Err(GatewayClientError::Protocol(_))
    ));
    wrong_version
        .shutdown()
        .await
        .expect("negative version shutdown");
}

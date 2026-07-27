//! HTTP adapter configuration and bounded defaults.

use std::collections::BTreeMap;
use std::time::Duration;

use http::HeaderValue;

use crate::auth::BearerAuthenticator;

/// One configured webhook route.
#[derive(Clone, Debug)]
pub struct WebhookRoute {
    /// Route identifier used in `/plugins/webhooks/{routeId}`.
    pub route_id: String,
    /// SHA-256 digest of the route secret.
    pub(crate) secret_digest: [u8; 32],
}

impl WebhookRoute {
    /// Creates a route without retaining its plaintext secret.
    #[must_use]
    pub fn new(route_id: impl Into<String>, secret: &str) -> Self {
        use sha2::{Digest, Sha256};
        Self {
            route_id: route_id.into(),
            secret_digest: Sha256::digest(secret.as_bytes()).into(),
        }
    }
}

/// Runtime limits for every HTTP surface.
#[derive(Clone, Debug)]
pub struct HttpLimits {
    /// Chat/Responses body bytes.
    pub openai_body_bytes: usize,
    /// Embeddings body bytes.
    pub embeddings_body_bytes: usize,
    /// Tools body bytes.
    pub tools_body_bytes: usize,
    /// Admin body bytes.
    pub admin_body_bytes: usize,
    /// Watch body bytes.
    pub watch_body_bytes: usize,
    /// MCP body bytes.
    pub mcp_body_bytes: usize,
    /// Webhook body bytes.
    pub webhook_body_bytes: usize,
    /// Request body read deadline.
    pub body_timeout: Duration,
    /// Runtime/provider operation deadline.
    pub operation_timeout: Duration,
    /// Bounded SSE/provider channel capacity.
    pub stream_buffer: usize,
    /// SSE heartbeat interval.
    pub heartbeat_interval: Duration,
    /// Watch long-poll timeout.
    pub watch_poll_timeout: Duration,
    /// Watch idle session expiry.
    pub watch_idle_timeout: Duration,
    /// Maximum watch queue events.
    pub watch_queue_events: usize,
    /// Maximum watch queue bytes.
    pub watch_queue_bytes: usize,
    /// Maximum individual watch event bytes.
    pub watch_event_bytes: usize,
}

impl Default for HttpLimits {
    fn default() -> Self {
        Self {
            openai_body_bytes: 20 * 1024 * 1024,
            embeddings_body_bytes: 5 * 1024 * 1024,
            tools_body_bytes: 2 * 1024 * 1024,
            admin_body_bytes: 1024 * 1024,
            watch_body_bytes: 64 * 1024,
            mcp_body_bytes: 1024 * 1024,
            webhook_body_bytes: 256 * 1024,
            body_timeout: Duration::from_secs(30),
            operation_timeout: Duration::from_mins(2),
            stream_buffer: 16,
            heartbeat_interval: Duration::from_secs(15),
            watch_poll_timeout: Duration::from_secs(20),
            watch_idle_timeout: Duration::from_secs(75),
            watch_queue_events: 32,
            watch_queue_bytes: 512 * 1024,
            watch_event_bytes: 64 * 1024,
        }
    }
}

/// Complete HTTP adapter configuration.
#[derive(Clone, Debug)]
pub struct ApiConfig {
    /// Bearer credentials for `OpenAI`, tools, models, and admin surfaces.
    pub authenticator: BearerAuthenticator,
    /// MCP owner bearer token authenticator.
    pub mcp_owner_authenticator: BearerAuthenticator,
    /// MCP non-owner bearer token authenticator.
    pub mcp_authenticator: BearerAuthenticator,
    /// Configured agent identifiers; first entry is the default.
    pub agents: Vec<String>,
    /// Route secrets keyed by route ID.
    pub webhooks: BTreeMap<String, WebhookRoute>,
    /// Exact allowed browser origins. Empty denies cross-origin requests.
    pub cors_origins: Vec<HeaderValue>,
    /// Bounded request and stream limits.
    pub limits: HttpLimits,
}

impl ApiConfig {
    /// Creates a production configuration with no ambient credentials.
    #[must_use]
    pub fn new(authenticator: BearerAuthenticator) -> Self {
        Self {
            authenticator,
            mcp_owner_authenticator: BearerAuthenticator::default(),
            mcp_authenticator: BearerAuthenticator::default(),
            agents: vec!["main".to_owned()],
            webhooks: BTreeMap::new(),
            cors_origins: Vec::new(),
            limits: HttpLimits::default(),
        }
    }
}

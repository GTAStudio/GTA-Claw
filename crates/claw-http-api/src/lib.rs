//! Complete bounded HTTP/SSE surface for GTA Claw.
//!
//! The adapter implements the frozen 18-route `OpenClaw` inventory while keeping
//! provider, Gateway, persistence, pairing, and task-flow behavior behind narrow
//! ports. Streaming routes use bounded channels and propagate disconnect
//! cancellation to their provider operations.

mod admin;
mod auth;
mod config;
mod deterministic;
mod error;
mod http_support;
mod legacy;
mod lifecycle;
mod mcp;
mod openai;
mod ports;
mod probes;
mod state;
mod tools;
mod watch;
mod webhooks;

use std::io;
use std::net::SocketAddr;
use std::sync::Arc;

use axum::Router;
use axum::http::{HeaderName, HeaderValue, Method, header};
use axum::middleware;
use axum::routing::{get, post};
use tokio::net::TcpListener;
use tower_http::cors::CorsLayer;
use tower_http::set_header::SetResponseHeaderLayer;

pub use admin::ADMIN_HTTP_RPC_METHODS;
pub use auth::{BearerAuthenticator, BearerCredential, Principal};
pub use config::{ApiConfig, HttpLimits, WebhookRoute};
pub use deterministic::DeterministicRuntime;
pub use legacy::{
    LEGACY_ADMIN_ACTIONS, LEGACY_HTTP_ENDPOINTS, LEGACY_TEAMS_AUTHORIZATION_BYTES,
    LegacyAdminAction, LegacyAdminCredential, LegacyApiConfig, LegacyApiServices,
    LegacyChannelMessage, LegacyChannelMessagePort, LegacyChannelStatus, LegacyConfigError,
    LegacyDeviceFlowPort, LegacyExecResult, LegacyHostAdminPort, LegacyHttpApi, LegacyHttpLimits,
    LegacyOsInfo, LegacyProcessInfo, LegacyProcessMemory, LegacyReloadError, LegacyReloadPort,
    LegacyReloadResult, LegacyRuntimePort, LegacyRuntimeSnapshot, LegacySystemInfo,
    LegacyTeamsAuthorizationHeader, LegacyTeamsPort, LegacyTeamsRequestContext,
    LegacyWhatsAppConfig, LegacyWhatsAppPort, LegacyWhatsAppServices, ProviderLegacyRuntime,
    ProviderLegacyRuntimeConfig,
};
pub use lifecycle::{
    PHASE_DRAINING, PHASE_RUNNING, PHASE_STARTING, ServingState, ServingStateHandle,
    ServingStatePort,
};
pub use ports::{
    AdminFailure, AdminPort, AdminSuccess, ApiServices, AuditPort, ClientTool, EmbeddingRequest,
    GenerationEvent, GenerationOutput, GenerationRequest, InputMedia, InputMediaKind,
    InputMediaSource, Model, PortError, PortErrorKind, PortFuture, ProviderPort, ReadinessPort,
    ReadinessSnapshot, ResponseSessionResolution, ToolAccess, ToolCall, ToolChoice, ToolDefinition,
    ToolInvocation, ToolInvocationContext, ToolOutcome, ToolPort, Usage, WatchAuthPort,
    WatchIdentity, WatchResultPort, WebhookOutcome, WebhookPort,
};
pub use watch::WatchNodeHandle;

use crate::auth::{AuthMiddlewareState, require_bearer};
use crate::lifecycle::{ServingMiddlewareState, require_serving};
use crate::state::ApiState;

macro_rules! method_router {
    (GET, $handler:path) => {
        get($handler)
    };
    (POST, $handler:path) => {
        post($handler)
    };
}

macro_rules! http_api_endpoints {
    ($consumer:ident) => {
        $consumer! {
            public {
                (GET, "/health", probes::live),
                (GET, "/healthz", probes::live),
                (GET, "/ready", probes::ready),
                (GET, "/readyz", probes::ready),
                (GET, "/api/nodes/watch/challenge", watch::challenge),
                (POST, "/api/nodes/watch/connect", watch::connect),
                (POST, "/api/nodes/watch/disconnect", watch::disconnect),
                (POST, "/api/nodes/watch/poll", watch::poll),
                (POST, "/api/nodes/watch/result", watch::result),
                (POST, "/plugins/webhooks/{routeId}", webhooks::invoke),
            }
            protected {
                (GET, "/v1/models", openai::models),
                (GET, "/v1/models/{id}", openai::model),
                (POST, "/v1/embeddings", openai::embeddings),
                (POST, "/v1/chat/completions", openai::chat),
                (POST, "/v1/responses", openai::responses),
                (POST, "/tools/invoke", tools::invoke),
            }
            admin {
                (POST, "/api/v1/admin/rpc", admin::rpc),
            }
            mcp {
                (POST, "/mcp", mcp::handle),
            }
        }
    };
}

macro_rules! build_route_groups {
    (
        public { $(($public_method:ident, $public_path:literal, $public_handler:path),)* }
        protected { $(($protected_method:ident, $protected_path:literal, $protected_handler:path),)* }
        admin { $(($admin_method:ident, $admin_path:literal, $admin_handler:path),)* }
        mcp { $(($mcp_method:ident, $mcp_path:literal, $mcp_handler:path),)* }
    ) => {{
        let public = Router::new()
            $(.route($public_path, method_router!($public_method, $public_handler)))*;
        let protected = Router::new()
            $(.route(
                $protected_path,
                method_router!($protected_method, $protected_handler),
            ))*;
        let admin = Router::new()
            $(.route($admin_path, method_router!($admin_method, $admin_handler)))*;
        let mcp = Router::new()
            $(.route($mcp_path, method_router!($mcp_method, $mcp_handler)))*;
        (public, protected, admin, mcp)
    }};
}

macro_rules! collect_registered_endpoints {
    (
        public { $(($public_method:ident, $public_path:literal, $public_handler:path),)* }
        protected { $(($protected_method:ident, $protected_path:literal, $protected_handler:path),)* }
        admin { $(($admin_method:ident, $admin_path:literal, $admin_handler:path),)* }
        mcp { $(($mcp_method:ident, $mcp_path:literal, $mcp_handler:path),)* }
    ) => {
        &[
            $((stringify!($public_method), $public_path),)*
            $((stringify!($protected_method), $protected_path),)*
            $((stringify!($admin_method), $admin_path),)*
            $((stringify!($mcp_method), $mcp_path),)*
        ]
    };
}

/// Explicit method and path identities registered across the main and MCP routers.
pub const HTTP_ENDPOINTS: &[(&str, &str)] = http_api_endpoints!(collect_registered_endpoints);

/// Fully configured Axum HTTP application.
#[derive(Clone)]
pub struct HttpApi {
    router: Router,
    mcp_router: Router,
    watch: WatchNodeHandle,
}

impl HttpApi {
    /// Builds all 18 frozen HTTP/SSE routes.
    ///
    /// The host is assumed to be serving. Callers with a real lifecycle should
    /// use [`HttpApi::with_serving_state`] so that readiness reflects a drain.
    #[must_use]
    pub fn new(config: ApiConfig, services: ApiServices) -> Self {
        Self::with_serving_state(config, services, Arc::new(ServingStateHandle::serving()))
    }

    /// Builds all 18 frozen HTTP/SSE routes against a caller-supplied serving state.
    ///
    /// This is the seam through which a graceful shutdown becomes observable over
    /// HTTP: once the supplied port reports that work is no longer accepted,
    /// `/ready` and `/readyz` fail while `/health` and `/healthz` keep succeeding.
    #[must_use]
    pub fn with_serving_state(
        config: ApiConfig,
        services: ApiServices,
        serving: Arc<dyn ServingStatePort>,
    ) -> Self {
        let serving_middleware = ServingMiddlewareState {
            serving: serving.clone(),
            limits: config.limits.clone(),
        };
        let auth_state = AuthMiddlewareState {
            authenticator: config.authenticator.clone(),
            limits: config.limits.clone(),
        };
        let cors_origins = config.cors_origins.clone();
        let state = ApiState::with_serving_state(config, services, serving);
        let (router, protected, admin, mcp_router) = http_api_endpoints!(build_route_groups);
        let protected = protected.layer(middleware::from_fn_with_state(auth_state, require_bearer));
        let cors = CorsLayer::new()
            .allow_methods([Method::GET, Method::HEAD, Method::POST, Method::DELETE])
            .allow_headers([
                header::AUTHORIZATION,
                header::CONTENT_TYPE,
                HeaderName::from_static("x-openclaw-webhook-secret"),
                HeaderName::from_static("x-openclaw-agent-id"),
                HeaderName::from_static("x-openclaw-session-key"),
                HeaderName::from_static("x-openclaw-model"),
                HeaderName::from_static("x-openclaw-message-channel"),
                HeaderName::from_static("x-openclaw-account-id"),
                HeaderName::from_static("x-openclaw-message-to"),
                HeaderName::from_static("x-openclaw-thread-id"),
            ]);
        let cors = if cors_origins.is_empty() {
            cors
        } else {
            cors.allow_origin(cors_origins)
        };
        let router = router
            .merge(protected)
            .merge(admin)
            .layer(SetResponseHeaderLayer::if_not_present(
                HeaderName::from_static("x-content-type-options"),
                HeaderValue::from_static("nosniff"),
            ))
            .layer(SetResponseHeaderLayer::if_not_present(
                HeaderName::from_static("referrer-policy"),
                HeaderValue::from_static("no-referrer"),
            ))
            .layer(SetResponseHeaderLayer::if_not_present(
                HeaderName::from_static("permissions-policy"),
                HeaderValue::from_static("camera=(), microphone=(self), geolocation=()"),
            ))
            .route_layer(middleware::from_fn_with_state(
                serving_middleware.clone(),
                require_serving,
            ))
            .layer(cors)
            .with_state(state.clone());
        let mcp_router = mcp_router
            .layer(SetResponseHeaderLayer::if_not_present(
                HeaderName::from_static("x-content-type-options"),
                HeaderValue::from_static("nosniff"),
            ))
            .layer(SetResponseHeaderLayer::if_not_present(
                HeaderName::from_static("referrer-policy"),
                HeaderValue::from_static("no-referrer"),
            ))
            .route_layer(middleware::from_fn_with_state(
                serving_middleware,
                require_serving,
            ))
            .with_state(state.clone());
        Self {
            router,
            mcp_router,
            watch: WatchNodeHandle::new(state.inner.watch.clone()),
        }
    }

    /// Returns the cloneable Axum router.
    pub fn router(&self) -> Router {
        self.router.clone()
    }

    /// Returns the MCP-only router, which must be served with loopback peer metadata.
    pub fn mcp_router(&self) -> Router {
        self.mcp_router.clone()
    }

    /// Returns the bounded watch-node event transport.
    #[must_use]
    pub fn watch_handle(&self) -> WatchNodeHandle {
        self.watch.clone()
    }

    /// Serves the API on an already-bound listener.
    ///
    /// # Errors
    ///
    /// Returns the [`io::Error`] reported by the accept loop. Nothing is written
    /// to any client: the call only resolves once the listener itself fails, so
    /// in-flight requests are unaffected and no HTTP status is produced.
    pub async fn serve(self, listener: TcpListener) -> io::Result<()> {
        axum::serve(
            listener,
            self.router
                .into_make_service_with_connect_info::<SocketAddr>(),
        )
        .await
    }

    /// Serves the MCP surface on an already-bound loopback listener.
    ///
    /// # Errors
    ///
    /// Returns [`io::ErrorKind::InvalidInput`] before accepting anything when
    /// `listener` is not bound to a loopback address, so no client ever reaches
    /// the MCP surface; otherwise returns the [`io::Error`] reported by the
    /// accept loop.
    pub async fn serve_mcp(self, listener: TcpListener) -> io::Result<()> {
        if !listener.local_addr()?.ip().is_loopback() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "MCP listener must bind to a loopback address",
            ));
        }
        axum::serve(
            listener,
            self.mcp_router
                .into_make_service_with_connect_info::<SocketAddr>(),
        )
        .await
    }
}

mod admin_rpc;

pub use admin_rpc::{
    ADMIN_RPC_PATH, AdminMethodPolicy, AdminRpcAuthRejection, AdminRpcAuthenticator,
    AdminRpcCaller, AdminRpcEnvelope, AdminRpcError, AdminRpcLimits, AdminRpcService,
    BearerAdminRpcAuthenticator, DenyAllAuthenticator, FnAuthenticator, dispatch_status,
    operator_scope_to_security,
};

//! Opt-in compatibility facade for the surviving `src/server.ts` contract.
//!
//! The upstream-frozen 18-route [`crate::HttpApi`] keeps its exact `/health`
//! shape. This facade is separate because the legacy service owns the same path
//! with a different response. A composition root can serve this router on the
//! legacy listener while retaining the OpenAI/MCP router independently.

mod config;
mod ports;
mod provider;
mod rate_limit;
mod routes;

use std::io;
use std::net::SocketAddr;
use std::sync::Arc;

use axum::Router;
use tokio::net::TcpListener;

pub use config::{
    LegacyAdminCredential, LegacyApiConfig, LegacyChannelStatus, LegacyConfigError,
    LegacyHttpLimits, LegacyWhatsAppConfig,
};
pub use ports::{
    LEGACY_ADMIN_ACTIONS, LEGACY_TEAMS_AUTHORIZATION_BYTES, LegacyAdminAction, LegacyApiServices,
    LegacyChannelMessage, LegacyChannelMessagePort, LegacyDeviceFlowPort, LegacyExecResult,
    LegacyHostAdminPort, LegacyOsInfo, LegacyProcessInfo, LegacyProcessMemory, LegacyReloadError,
    LegacyReloadPort, LegacyReloadResult, LegacyRuntimePort, LegacyRuntimeSnapshot,
    LegacySystemInfo, LegacyTeamsAuthorizationHeader, LegacyTeamsPort, LegacyTeamsRequestContext,
    LegacyWhatsAppPort, LegacyWhatsAppServices,
};
pub use provider::{ProviderLegacyRuntime, ProviderLegacyRuntimeConfig};

use crate::{ServingStateHandle, ServingStatePort};

/// Legacy `src/server.ts` method/path identities.
///
/// Teams, `WhatsApp`, and admin routes are registered only when their corresponding
/// configuration and adapter are present.
pub const LEGACY_HTTP_ENDPOINTS: &[(&str, &str)] = &[
    ("GET", "/"),
    ("GET", "/health"),
    ("GET", "/auth/device"),
    ("POST", "/chat"),
    ("POST", "/api/messages"),
    ("GET", "/whatsapp/webhook"),
    ("POST", "/whatsapp/webhook"),
    ("POST", "/admin/reload"),
    ("GET", "/admin/system"),
    ("POST", "/admin/exec"),
];

/// Fully configured legacy Node-compatible HTTP application.
#[derive(Clone)]
pub struct LegacyHttpApi {
    router: Router,
}

impl LegacyHttpApi {
    /// Builds a facade whose host is already serving.
    ///
    /// # Errors
    ///
    /// Returns [`LegacyConfigError`] when enabled conditional routes do not have
    /// their required typed adapters or any configured capacity is zero.
    pub fn new(
        config: LegacyApiConfig,
        services: LegacyApiServices,
    ) -> Result<Self, LegacyConfigError> {
        Self::with_serving_state(config, services, Arc::new(ServingStateHandle::serving()))
    }

    /// Builds a facade against the host's real serving state.
    ///
    /// # Errors
    ///
    /// Returns [`LegacyConfigError`] when enabled conditional routes do not have
    /// their required typed adapters or any configured capacity is zero.
    pub fn with_serving_state(
        config: LegacyApiConfig,
        services: LegacyApiServices,
        serving: Arc<dyn ServingStatePort>,
    ) -> Result<Self, LegacyConfigError> {
        let state = routes::LegacyState::new(config, services, serving)?;
        Ok(Self {
            router: routes::router(state),
        })
    }

    /// Returns the cloneable legacy router.
    pub fn router(&self) -> Router {
        self.router.clone()
    }

    /// Serves the facade on an already-bound listener.
    ///
    /// # Errors
    ///
    /// Returns the listener's [`io::Error`] after the accept loop terminates.
    pub async fn serve(self, listener: TcpListener) -> io::Result<()> {
        axum::serve(
            listener,
            self.router
                .into_make_service_with_connect_info::<SocketAddr>(),
        )
        .await
    }
}

//! CDP HTTP discovery served beside the relay WebSocket endpoints.
//!
//! A CDP automation client bootstraps by fetching `/json/version` to learn the
//! browser identity and the WebSocket debugger URL, and `/json` or `/json/list`
//! to enumerate the pages it may address. The relay serves those three routes
//! from relay state alone: no Chrome process is contacted, and only tabs the
//! user explicitly shared with the extension are ever listed.
//!
//! Discovery is authenticated with the same host-local relay secret as the
//! WebSocket upgrade, and reports `503` until an extension has actually paired,
//! so an automation client fails with a paired/unpaired answer rather than
//! attaching to an empty browser.

use std::fmt::{self, Debug, Formatter};

use serde::Serialize;
use serde_json::{Value, json};

use crate::bridge::CdpBridge;
use crate::endpoint::{RelayEndpoint, is_loopback_authority};

/// Message returned while no extension is paired.
pub const NOT_PAIRED_MESSAGE: &str = "GTA-Claw Chrome extension is not connected. Install the extension and pair it with `gta-claw browser extension pair`.";

/// One complete HTTP discovery request handed over by the HTTP adapter.
#[derive(Clone, Eq, PartialEq)]
pub struct DiscoveryRequest {
    /// Uppercase HTTP method.
    pub method: String,
    /// Request path, without a query string.
    pub path: String,
    /// HTTP Host header.
    pub host: String,
    /// Relay secret already extracted from the `Authorization` header.
    pub authorization_token: Option<String>,
}

impl Debug for DiscoveryRequest {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("DiscoveryRequest")
            .field("method", &self.method)
            .field("path", &self.path)
            .field("host", &self.host)
            .field("authorization_token", &"[REDACTED]")
            .finish()
    }
}

/// One complete HTTP discovery response.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DiscoveryResponse {
    /// HTTP status code.
    pub status: u16,
    /// Whether the relay challenges for credentials.
    pub authenticate: bool,
    /// JSON response body.
    pub body: Value,
}

/// CDP version document served once an extension is paired.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct VersionInfo {
    /// Chrome product version.
    #[serde(rename = "Browser")]
    pub browser: String,
    /// Devtools protocol version the relay speaks.
    #[serde(rename = "Protocol-Version")]
    pub protocol_version: String,
    /// Browser user agent.
    #[serde(rename = "User-Agent")]
    pub user_agent: String,
    /// Loopback CDP WebSocket endpoint.
    #[serde(rename = "webSocketDebuggerUrl")]
    pub web_socket_debugger_url: String,
}

/// Serves one authenticated CDP discovery request from relay state.
#[must_use]
pub fn serve_discovery(
    endpoint: &RelayEndpoint,
    bridge: &CdpBridge,
    request: &DiscoveryRequest,
) -> DiscoveryResponse {
    if !is_loopback_authority(&request.host) {
        return DiscoveryResponse {
            status: 403,
            authenticate: false,
            body: json!({ "error": "relay Host header must be loopback" }),
        };
    }
    let authorized = request
        .authorization_token
        .as_deref()
        .is_some_and(|candidate| endpoint.token_matches(candidate));
    if !authorized {
        return DiscoveryResponse {
            status: 401,
            authenticate: true,
            body: json!({ "error": "relay authentication failed" }),
        };
    }
    if request.method != "GET" {
        return DiscoveryResponse {
            status: 405,
            authenticate: false,
            body: json!({ "error": "relay discovery is read-only" }),
        };
    }
    match request.path.trim_end_matches('/') {
        "/json/version" => version_response(bridge, &request.host),
        "/json" | "/json/list" => DiscoveryResponse {
            status: 200,
            authenticate: false,
            body: json!(bridge.shared_tabs()),
        },
        _ => DiscoveryResponse {
            status: 404,
            authenticate: false,
            body: json!({ "error": "unknown relay discovery path" }),
        },
    }
}

fn version_response(bridge: &CdpBridge, authority: &str) -> DiscoveryResponse {
    let Some(identity) = bridge.identity() else {
        return DiscoveryResponse {
            status: 503,
            authenticate: false,
            body: json!({ "error": NOT_PAIRED_MESSAGE }),
        };
    };
    let version = VersionInfo {
        browser: identity.browser_version,
        protocol_version: "1.3".to_owned(),
        user_agent: identity.user_agent,
        web_socket_debugger_url: format!("ws://{authority}/cdp"),
    };
    DiscoveryResponse {
        status: 200,
        authenticate: false,
        body: json!(version),
    }
}

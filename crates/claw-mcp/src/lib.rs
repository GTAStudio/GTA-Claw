//! Model Context Protocol interoperability for GTA Claw.
//!
//! The crate provides an MCP server, stdio/streamable-HTTP/legacy-SSE clients,
//! OAuth authorization, configured-server lifecycle management, and the
//! conversation projection used by the frozen OpenClaw compatibility surface.

pub mod client;
pub mod error;
pub mod framing;
pub mod oauth;
pub mod projection;
pub mod registry;
pub mod server;
pub mod sse;

pub use rmcp::model;

pub(crate) fn install_tls_provider() {
    let _already_installed = rustls::crypto::ring::default_provider().install_default();
}

pub(crate) fn endpoint_allows_credentials(url: &url::Url) -> bool {
    url.scheme() == "https"
        || (url.scheme() == "http"
            && url.host_str().is_some_and(|host| {
                host.eq_ignore_ascii_case("localhost")
                    || host
                        .parse::<std::net::IpAddr>()
                        .is_ok_and(|address| address.is_loopback())
            }))
}

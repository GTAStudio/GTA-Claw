//! Model Context Protocol interoperability for GTA Claw.
//!
//! The crate provides an MCP server, stdio/streamable-HTTP/legacy-SSE clients,
//! OAuth authorization, configured-server lifecycle management, and the
//! conversation projection used by the frozen OpenClaw compatibility surface.

pub mod client;
pub mod error;
pub mod framing;
mod http_client;
pub mod oauth;
pub mod projection;
pub mod registry;
mod secure_random;
pub mod server;
pub mod sse;

pub use http_client::HttpClientError;
pub use rmcp::model;

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

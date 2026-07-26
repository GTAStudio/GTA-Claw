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

pub(crate) fn is_literal_loopback_host(host: &str) -> bool {
    host.trim_matches(['[', ']'])
        .parse::<std::net::IpAddr>()
        .is_ok_and(|address| address.is_loopback())
}

pub(crate) fn endpoint_allows_credentials(url: &url::Url) -> bool {
    url.scheme() == "https"
        || (url.scheme() == "http" && url.host_str().is_some_and(is_literal_loopback_host))
}

#[cfg(test)]
mod tests {
    use url::Url;

    use super::endpoint_allows_credentials;

    #[test]
    fn credential_endpoints_require_https_or_literal_loopback_addresses() {
        let https = Url::parse("https://mcp.example/rpc").expect("HTTPS endpoint");
        let ipv4 = Url::parse("http://127.0.0.1:8080/rpc").expect("IPv4 endpoint");
        let ipv6 = Url::parse("http://[::1]:8080/rpc").expect("IPv6 endpoint");
        let localhost = Url::parse("http://localhost:8080/rpc").expect("localhost endpoint");
        let remote_http = Url::parse("http://mcp.example/rpc").expect("remote HTTP endpoint");

        assert!(endpoint_allows_credentials(&https));
        assert!(endpoint_allows_credentials(&ipv4));
        assert!(endpoint_allows_credentials(&ipv6));
        assert!(!endpoint_allows_credentials(&localhost));
        assert!(!endpoint_allows_credentials(&remote_http));
    }
}

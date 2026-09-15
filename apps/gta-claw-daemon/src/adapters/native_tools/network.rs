use std::collections::{BTreeMap, BTreeSet};
use std::net::IpAddr;
use std::time::{Duration, Instant};

use claw_plugin_host::{
    HostCallControl, OutboundRequest, PinnedHttpTransport, PinnedHttpTransportConfig,
};
use claw_provider_sdk::http::ProxyPolicy;
use claw_tools::net::{
    Destination, HttpRequest, HttpResponse, HttpTransport, NetFetchTool, NetworkError,
    PrivateOriginExceptions, UrlPolicy,
};
use serde::Deserialize;
use url::Url;

#[derive(Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub(super) struct Target {
    origin: String,
    addresses: Vec<IpAddr>,
}

#[derive(Clone)]
struct Endpoint {
    host: String,
    port: u16,
    addresses: Vec<IpAddr>,
}

#[derive(Clone)]
pub(super) struct NativeNetwork {
    targets: BTreeMap<String, Endpoint>,
    policy: UrlPolicy,
    transport: PinnedHttpTransport,
}

impl NativeNetwork {
    pub(super) fn new(targets: &[Target], proxy: &ProxyPolicy) -> Result<Self, String> {
        if targets.is_empty() || targets.len() > 16 {
            return Err("network policy requires one through sixteen explicit targets".to_owned());
        }
        let proxy = proxy.rules();
        if proxy.fell_back_to_direct() {
            return Err("native network policy refuses unusable proxy configuration".to_owned());
        }
        let mut endpoints = BTreeMap::new();
        let mut hosts = BTreeSet::new();
        let mut public_hosts = BTreeSet::new();
        let mut ports = BTreeSet::new();
        let mut exceptions = PrivateOriginExceptions::none();
        for target in targets {
            let url = canonical_url(&target.origin)?;
            let origin = url.origin().ascii_serialization();
            if target.origin != origin || url.path() != "/" || url.query().is_some() {
                return Err("network target must be a canonical origin only".to_owned());
            }
            let host = url
                .host_str()
                .ok_or_else(|| "network host is absent".to_owned())?
                .trim_matches(['[', ']'])
                .to_owned();
            let port = url
                .port_or_known_default()
                .ok_or_else(|| "network port is absent".to_owned())?;
            if !hosts.insert(host.clone())
                || target.addresses.is_empty()
                || target.addresses.len() > 8
            {
                return Err(
                    "network target hosts must be unique with one through eight pinned addresses"
                        .to_owned(),
                );
            }
            if !proxy.intercept(&host, port).is_direct() {
                return Err("native fixed-address network transport cannot honor the selected proxy; no direct fallback is permitted".to_owned());
            }
            let literal = host.parse::<IpAddr>().ok();
            if literal.is_some_and(|address| address.is_loopback()) {
                if target
                    .addresses
                    .iter()
                    .any(|address| Some(*address) != literal)
                    || url.port().is_none()
                {
                    return Err("loopback targets require an explicit nondefault port and exact literal address".to_owned());
                }
                exceptions
                    .allow_origin(&origin)
                    .map_err(|_| "invalid loopback network origin".to_owned())?;
            } else if url.scheme() != "https" {
                return Err("public native network targets require HTTPS".to_owned());
            } else {
                public_hosts.insert(host.clone());
            }
            ports.insert(port);
            endpoints.insert(
                origin,
                Endpoint {
                    host,
                    port,
                    addresses: target.addresses.clone(),
                },
            );
        }
        let policy = UrlPolicy::exact_hosts(&public_hosts)
            .map_err(|_| "invalid network host allowlist".to_owned())?
            .with_allowed_ports(ports)
            .with_exceptions(exceptions)
            .with_max_redirects(0)
            .with_max_body_bytes(4096);
        for (origin, target) in &endpoints {
            if let Destination::Public(target_policy) = policy
                .validate(origin)
                .map_err(|_| "network origin violates destination policy".to_owned())?
            {
                target_policy
                    .validate_resolution(&target.addresses)
                    .map_err(|_| "network address violates public destination policy".to_owned())?;
            }
        }
        let transport = PinnedHttpTransport::new(
            PinnedHttpTransportConfig::new()
                .with_connect_timeout(Duration::from_secs(5))
                .with_overall_timeout(Duration::from_secs(15))
                .with_max_response_body_bytes(4096)
                .with_max_response_header_bytes(16 * 1024)
                .allow_loopback_http(true),
        )
        .map_err(|_| "native network TLS transport initialization failed".to_owned())?;
        Ok(Self {
            targets: endpoints,
            policy,
            transport,
        })
    }

    pub(super) fn resource(&self, value: &str) -> Result<String, String> {
        let url = canonical_url(value)?;
        let origin = url.origin().ascii_serialization();
        let target = self
            .targets
            .get(&origin)
            .ok_or_else(|| "network URL is outside the explicit origin policy".to_owned())?;
        self.policy
            .validate(value)
            .map_err(|_| "network URL violates destination policy".to_owned())?;
        Ok(format!(
            "origin={origin}; pinned={:?}; GET/HEAD only; no redirects; no inherited credentials",
            target.addresses
        ))
    }

    pub(super) fn tool(
        &self,
        cancellation: &claw_tools::CancellationToken,
    ) -> Box<dyn claw_tools::Tool> {
        let control = HostCallControl::new(
            Instant::now() + Duration::from_secs(15),
            Some(claw_plugin_host::CancellationToken::from_shared_flag(
                cancellation.shared_flag(),
            )),
        );
        Box::new(NetFetchTool::new(
            self.policy.clone(),
            NetworkTransport {
                network: self.clone(),
                control,
            },
        ))
    }
}

fn canonical_url(value: &str) -> Result<Url, String> {
    if value.is_empty()
        || value.len() > 2048
        || value
            .chars()
            .any(|character| character.is_control() || character.is_whitespace())
    {
        return Err("network URL exceeds its canonical input contract".to_owned());
    }
    let url = Url::parse(value).map_err(|_| "invalid network URL".to_owned())?;
    if !matches!(url.scheme(), "https" | "http")
        || !url.username().is_empty()
        || url.password().is_some()
        || url.fragment().is_some()
        || value.contains('\\')
    {
        return Err(
            "network URL must not contain credentials, fragments or ambiguous separators"
                .to_owned(),
        );
    }
    Ok(url)
}

struct NetworkTransport {
    network: NativeNetwork,
    control: HostCallControl,
}

impl HttpTransport for NetworkTransport {
    fn resolve(&mut self, host: &str) -> Result<Vec<IpAddr>, NetworkError> {
        self.control
            .check()
            .map_err(|_| NetworkError::TransportRefused)?;
        self.network
            .targets
            .values()
            .find(|target| target.host == host)
            .map(|target| target.addresses.clone())
            .ok_or(NetworkError::TransportRefused)
    }

    fn fetch(&mut self, request: &HttpRequest) -> Result<HttpResponse, NetworkError> {
        let url = canonical_url(&request.url).map_err(|_| NetworkError::TransportRefused)?;
        let target = self
            .network
            .targets
            .get(&url.origin().ascii_serialization())
            .ok_or(NetworkError::TransportRefused)?;
        if (&target.host, target.port, &target.addresses)
            != (&request.host, request.port, &request.pinned)
            || !matches!(request.method.as_str(), "GET" | "HEAD")
        {
            return Err(NetworkError::TransportRefused);
        }
        let (response, peer) = self
            .network
            .transport
            .send_request_with_peer(
                OutboundRequest {
                    method: request.method.clone(),
                    url: request.url.clone(),
                    host: request.host.clone(),
                    port: request.port,
                    addresses: request.pinned.clone(),
                    headers: vec![("accept-encoding".to_owned(), "identity".to_owned())],
                    body: None,
                },
                &self.control,
            )
            .map_err(|_| NetworkError::TransportRefused)?;
        if response.body.len() > request.max_body_bytes
            || std::str::from_utf8(&response.body).is_err()
        {
            return Err(NetworkError::TransportRefused);
        }
        let location = response
            .headers
            .iter()
            .find(|(name, _)| name.eq_ignore_ascii_case("location"))
            .map(|(_, value)| value.clone());
        Ok(HttpResponse {
            status: response.status,
            body: response.body,
            location,
            peer,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn native_network_policy_rejects_private_rebinding_and_unavailable_proxy_before_io() {
        for targets in [
            json!([]),
            json!([{"origin":"https://example.com","addresses":["127.0.0.1"]}]),
            json!([{"origin":"https://example.com","addresses":["169.254.169.254"]}]),
            json!([{"origin":"https://example.com","addresses":["::ffff:127.0.0.1"]}]),
            json!([{"origin":"http://example.com","addresses":["1.1.1.1"]}]),
            json!([{"origin":"http://127.0.0.1:23456","addresses":["127.0.0.2"]}]),
            json!([{"origin":"https://user:secret@example.com","addresses":["1.1.1.1"]}]),
            json!([{"origin":"https://example.com/private","addresses":["1.1.1.1"]}]),
        ] {
            let targets: Vec<Target> =
                serde_json::from_value(targets).expect("typed target fixture");
            assert!(NativeNetwork::new(&targets, &ProxyPolicy::Disabled).is_err());
        }
        let targets: Vec<Target> = serde_json::from_value(
            json!([{"origin":"https://example.com","addresses":["1.1.1.1"]}]),
        )
        .expect("public policy only fixture");
        for url in [
            "http://127.0.0.1:23456",
            "socks5://127.0.0.1:23456",
            "not-a-proxy",
        ] {
            assert!(
                NativeNetwork::new(
                    &targets,
                    &ProxyPolicy::Explicit {
                        url: url.to_owned(),
                        no_proxy: None
                    }
                )
                .is_err()
            );
        }
    }
}

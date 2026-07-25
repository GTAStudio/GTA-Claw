//! Authenticated TaskFlow webhooks with replay and delivery controls.

use std::collections::{BTreeMap, BTreeSet};
use std::error::Error;
use std::fmt::{self, Display, Formatter};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use async_trait::async_trait;
use hmac::{Hmac, KeyInit as _, Mac as _};
use hyper::Uri;
use hyper_util::client::proxy::matcher::{Intercept, Matcher};
use rustls::pki_types::ServerName;
use rustls::{ClientConfig, RootCertStore};
use secrecy::{ExposeSecret as _, SecretString};
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use tokio::io::{AsyncRead, AsyncReadExt as _, AsyncWrite, AsyncWriteExt as _};
use tokio::net::TcpStream;
use tokio_rustls::TlsConnector;
use url::{Host, Position, Url};

const SIGNATURE_PREFIX: &str = "sha256=";
const SIGNING_DOMAIN: &[u8] = b"gta-claw-taskflow-webhook-v1";
const DELIVERY_NONCE_DOMAIN: &[u8] = b"gta-claw-taskflow-delivery-v1";
const DELIVERY_NONCE_PREFIX: &str = "delivery-";
const MIN_SECRET_BYTES: usize = 32;
const MAX_NONCE_BYTES: usize = 128;
const MAX_ROUTE_BYTES: usize = 256;
const MAX_BODY_BYTES: usize = 1024 * 1024;
const MAX_RESPONSE_HEADER_BYTES: usize = 16 * 1024;
const MAX_RESOLVED_ADDRESSES: usize = 32;
const MAX_PROXY_AUTH_BYTES: usize = 4096;

type HmacSha256 = Hmac<Sha256>;

/// Secret used exclusively for one webhook endpoint.
#[derive(Clone, Debug)]
pub struct WebhookSecret(SecretString);

impl WebhookSecret {
    /// Accepts a secret with at least 256 bits of caller-provided material.
    pub fn new(secret: SecretString) -> Result<Self, WebhookError> {
        if secret.expose_secret().len() < MIN_SECRET_BYTES {
            return Err(WebhookError::WeakSecret);
        }
        Ok(Self(secret))
    }

    fn bytes(&self) -> &[u8] {
        self.0.expose_secret().as_bytes()
    }
}

/// Session-key policy for one webhook route.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum SessionBinding {
    /// Require one exact TaskFlow session key.
    Exact(String),
    /// Require a non-empty suffix after this session-key prefix.
    Prefix(String),
}

impl SessionBinding {
    fn validate(&self) -> Result<(), WebhookError> {
        let value = match self {
            Self::Exact(value) | Self::Prefix(value) => value,
        };
        if value.is_empty() || value.len() > 256 || value.chars().any(char::is_control) {
            return Err(WebhookError::InvalidSessionBinding);
        }
        Ok(())
    }

    fn permits(&self, session_key: &str) -> bool {
        match self {
            Self::Exact(expected) => session_key == expected,
            Self::Prefix(prefix) => session_key
                .strip_prefix(prefix)
                .is_some_and(|suffix| !suffix.is_empty()),
        }
    }
}

/// Configured authenticated inbound webhook route.
#[derive(Clone, Debug)]
pub struct InboundRoute {
    /// Stable route identifier.
    pub id: String,
    /// Exact HTTP path.
    pub path: String,
    /// Per-route signing secret.
    pub secret: WebhookSecret,
    /// Explicit TaskFlow action allowlist.
    pub allowed_actions: BTreeSet<String>,
    /// Required session-key binding.
    pub session_binding: SessionBinding,
    /// Maximum raw request-body size.
    pub max_body_bytes: usize,
}

impl InboundRoute {
    /// Validates route syntax and fail-closed policy.
    pub fn validate(&self) -> Result<(), WebhookError> {
        if self.id.is_empty()
            || self.id.len() > 128
            || self.id.chars().any(char::is_control)
            || !self.path.starts_with('/')
            || self.path.len() > MAX_ROUTE_BYTES
            || self.path.contains(['?', '#', '\r', '\n'])
            || self.allowed_actions.is_empty()
            || self.max_body_bytes == 0
            || self.max_body_bytes > MAX_BODY_BYTES
            || self
                .allowed_actions
                .iter()
                .any(|action| action.is_empty() || action.len() > 128)
        {
            return Err(WebhookError::InvalidRoute);
        }
        self.session_binding.validate()
    }
}

/// Signed inbound HTTP request fields.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct InboundWebhookRequest {
    /// Request path without a query.
    pub path: String,
    /// Decimal Unix timestamp header.
    pub timestamp: String,
    /// Unique caller-generated nonce header.
    pub nonce: String,
    /// `sha256=` hexadecimal HMAC header.
    pub signature: String,
    /// Raw request body.
    pub body: Vec<u8>,
}

/// TaskFlow dispatch envelope.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct TaskFlowEvent {
    /// Allowed TaskFlow action.
    pub action: String,
    /// Session key bound by route policy.
    pub session_key: String,
    /// Stable caller task identifier.
    pub task_id: String,
    /// Action-specific payload.
    pub payload: serde_json::Value,
}

impl TaskFlowEvent {
    fn validate(&self) -> Result<(), WebhookError> {
        if self.action.is_empty()
            || self.action.len() > 128
            || self.session_key.is_empty()
            || self.session_key.len() > 256
            || self.task_id.is_empty()
            || self.task_id.len() > 256
            || self.action.chars().any(char::is_control)
            || self.session_key.chars().any(char::is_control)
            || self.task_id.chars().any(char::is_control)
        {
            return Err(WebhookError::InvalidEvent);
        }
        Ok(())
    }
}

/// Successful TaskFlow dispatch receipt.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DispatchReceipt {
    /// Stable dispatch identifier.
    pub dispatch_id: String,
}

/// Application boundary for verified TaskFlow events.
#[async_trait]
pub trait TaskFlowDispatcher: Send + Sync {
    /// Dispatches an already authenticated and authorized event.
    async fn dispatch(&self, event: TaskFlowEvent) -> Result<DispatchReceipt, WebhookError>;
}

/// Fixed-window bounded replay cache.
#[derive(Debug)]
pub struct ReplayGuard {
    window_seconds: i64,
    max_entries: usize,
    entries: Mutex<BTreeMap<String, i64>>,
}

impl ReplayGuard {
    /// Creates a cache that rejects invalid or impractically large bounds.
    pub fn new(window: Duration, max_entries: usize) -> Result<Self, WebhookError> {
        let seconds =
            i64::try_from(window.as_secs()).map_err(|_| WebhookError::InvalidReplayPolicy)?;
        if seconds == 0 || seconds > 24 * 60 * 60 || max_entries == 0 {
            return Err(WebhookError::InvalidReplayPolicy);
        }
        Ok(Self {
            window_seconds: seconds,
            max_entries,
            entries: Mutex::new(BTreeMap::new()),
        })
    }

    fn validate_timestamp(&self, timestamp: i64, now: i64) -> Result<(), WebhookError> {
        if now.abs_diff(timestamp) > self.window_seconds as u64 {
            return Err(WebhookError::TimestampOutsideWindow);
        }
        Ok(())
    }

    fn reserve(
        &self,
        route_id: &str,
        nonce: &str,
        timestamp: i64,
        now: i64,
    ) -> Result<(), WebhookError> {
        let mut entries = self.entries.lock().map_err(|_| WebhookError::ReplayState)?;
        entries.retain(|_, expiry| *expiry > now);
        let key = format!("{route_id}\0{}", replay_nonce(nonce));
        if entries.contains_key(&key) {
            return Err(WebhookError::Replay);
        }
        if entries.len() >= self.max_entries {
            return Err(WebhookError::ReplayCapacity);
        }
        let expiry = timestamp
            .saturating_add(self.window_seconds)
            .saturating_add(1);
        entries.insert(key, expiry);
        Ok(())
    }
}

/// Authenticates and dispatches inbound TaskFlow webhooks.
pub struct InboundWebhookHandler {
    routes: BTreeMap<String, InboundRoute>,
    replay: ReplayGuard,
}

impl InboundWebhookHandler {
    /// Creates a handler with unique exact route paths.
    pub fn new(routes: Vec<InboundRoute>, replay: ReplayGuard) -> Result<Self, WebhookError> {
        let mut by_path = BTreeMap::new();
        for route in routes {
            route.validate()?;
            if by_path.insert(route.path.clone(), route).is_some() {
                return Err(WebhookError::DuplicateRoute);
            }
        }
        if by_path.is_empty() {
            return Err(WebhookError::InvalidRoute);
        }
        Ok(Self {
            routes: by_path,
            replay,
        })
    }

    /// Verifies route, timestamp, HMAC, nonce, action, and session before dispatch.
    pub async fn handle<D: TaskFlowDispatcher>(
        &self,
        request: InboundWebhookRequest,
        now: i64,
        dispatcher: &D,
    ) -> Result<DispatchReceipt, WebhookError> {
        let route = self
            .routes
            .get(&request.path)
            .ok_or(WebhookError::RouteNotFound)?;
        if request.body.len() > route.max_body_bytes {
            return Err(WebhookError::BodyTooLarge);
        }
        validate_nonce(&request.nonce)?;
        let timestamp = parse_timestamp(&request.timestamp)?;
        self.replay.validate_timestamp(timestamp, now)?;
        verify_signature(
            &route.secret,
            &request.path,
            timestamp,
            &request.nonce,
            &request.body,
            &request.signature,
        )?;
        let event = serde_json::from_slice::<TaskFlowEvent>(&request.body)
            .map_err(WebhookError::InvalidJson)?;
        event.validate()?;
        if !route.allowed_actions.contains(&event.action) {
            return Err(WebhookError::ActionDenied);
        }
        if !route.session_binding.permits(&event.session_key) {
            return Err(WebhookError::SessionDenied);
        }
        // Dispatch may produce effects before its future is cancelled, so an authenticated nonce
        // is intentionally burned before awaiting and is never rolled back.
        self.replay
            .reserve(&route.id, &request.nonce, timestamp, now)?;
        dispatcher.dispatch(event).await
    }
}

/// Computes a versioned TaskFlow signature header.
pub fn sign_webhook(
    secret: &WebhookSecret,
    path: &str,
    timestamp: i64,
    nonce: &str,
    body: &[u8],
) -> Result<String, WebhookError> {
    validate_nonce(nonce)?;
    let mut mac =
        HmacSha256::new_from_slice(secret.bytes()).map_err(|_| WebhookError::SigningState)?;
    mac.update(&canonical_message(path, timestamp, nonce, body)?);
    Ok(format!(
        "{SIGNATURE_PREFIX}{}",
        encode_hex(&mac.finalize().into_bytes())
    ))
}

fn verify_signature(
    secret: &WebhookSecret,
    path: &str,
    timestamp: i64,
    nonce: &str,
    body: &[u8],
    signature: &str,
) -> Result<(), WebhookError> {
    let signature = signature
        .strip_prefix(SIGNATURE_PREFIX)
        .ok_or(WebhookError::InvalidSignature)?;
    let signature = decode_hex(signature).ok_or(WebhookError::InvalidSignature)?;
    let mut mac =
        HmacSha256::new_from_slice(secret.bytes()).map_err(|_| WebhookError::SigningState)?;
    mac.update(&canonical_message(path, timestamp, nonce, body)?);
    mac.verify_slice(&signature)
        .map_err(|_| WebhookError::InvalidSignature)
}

fn canonical_message(
    path: &str,
    timestamp: i64,
    nonce: &str,
    body: &[u8],
) -> Result<Vec<u8>, WebhookError> {
    if !path.starts_with('/') || path.len() > MAX_ROUTE_BYTES || path.contains(['\r', '\n', '#']) {
        return Err(WebhookError::InvalidRoute);
    }
    let mut message =
        Vec::with_capacity(SIGNING_DOMAIN.len() + path.len() + nonce.len() + body.len());
    append_field(&mut message, SIGNING_DOMAIN)?;
    append_field(&mut message, timestamp.to_string().as_bytes())?;
    append_field(&mut message, nonce.as_bytes())?;
    append_field(&mut message, path.as_bytes())?;
    append_field(&mut message, body)?;
    Ok(message)
}

fn append_field(message: &mut Vec<u8>, field: &[u8]) -> Result<(), WebhookError> {
    let length = u64::try_from(field.len()).map_err(|_| WebhookError::BodyTooLarge)?;
    message.extend_from_slice(&length.to_be_bytes());
    message.extend_from_slice(field);
    Ok(())
}

fn validate_nonce(nonce: &str) -> Result<(), WebhookError> {
    if nonce.is_empty()
        || nonce.len() > MAX_NONCE_BYTES
        || !nonce
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
    {
        return Err(WebhookError::InvalidNonce);
    }
    Ok(())
}

fn parse_timestamp(timestamp: &str) -> Result<i64, WebhookError> {
    if timestamp.is_empty()
        || timestamp.len() > 20
        || !timestamp.bytes().all(|byte| byte.is_ascii_digit())
    {
        return Err(WebhookError::InvalidTimestamp);
    }
    timestamp
        .parse::<i64>()
        .map_err(|_| WebhookError::InvalidTimestamp)
}

fn encode_hex(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut encoded = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        encoded.push(char::from(HEX[usize::from(byte >> 4)]));
        encoded.push(char::from(HEX[usize::from(byte & 0x0f)]));
    }
    encoded
}

fn decode_hex(value: &str) -> Option<Vec<u8>> {
    if value.len() != 64 || !value.len().is_multiple_of(2) {
        return None;
    }
    value
        .as_bytes()
        .chunks_exact(2)
        .map(|pair| {
            let high = hex_digit(pair[0])?;
            let low = hex_digit(pair[1])?;
            Some((high << 4) | low)
        })
        .collect()
}

const fn hex_digit(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        b'A'..=b'F' => Some(byte - b'A' + 10),
        _ => None,
    }
}

/// Validated outbound webhook endpoint.
#[derive(Clone, Debug)]
pub struct OutboundEndpoint {
    /// Stable endpoint identifier.
    pub id: String,
    /// Fixed delivery URL.
    pub url: Url,
    /// Per-endpoint signing secret.
    pub secret: WebhookSecret,
}

impl OutboundEndpoint {
    /// Validates scheme, credentials, fragment, and endpoint identifier.
    pub fn validate(&self, allow_loopback_http: bool) -> Result<(), WebhookError> {
        let valid_scheme = self.url.scheme() == "https"
            || (allow_loopback_http
                && self.url.scheme() == "http"
                && self.url.host().is_some_and(loopback_host));
        if self.id.is_empty()
            || self.id.len() > 128
            || !valid_scheme
            || !self.url.username().is_empty()
            || self.url.password().is_some()
            || self.url.fragment().is_some()
            || self.url.host().is_none()
        {
            return Err(WebhookError::UnsafeEndpoint);
        }
        Ok(())
    }

    fn path_and_query(&self) -> String {
        self.url.query().map_or_else(
            || self.url.path().to_owned(),
            |query| format!("{}?{query}", self.url.path()),
        )
    }
}

fn loopback_host(host: url::Host<&str>) -> bool {
    match host {
        url::Host::Domain(domain) => domain.eq_ignore_ascii_case("localhost"),
        url::Host::Ipv4(address) => address.is_loopback(),
        url::Host::Ipv6(address) => address.is_loopback(),
    }
}

/// Outbound HTTP request after signing.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct OutboundHttpRequest {
    /// Destination URL.
    pub url: Url,
    /// Unix timestamp signature input.
    pub timestamp: String,
    /// Unique delivery nonce.
    pub nonce: String,
    /// Versioned HMAC signature.
    pub signature: String,
    /// JSON body.
    pub body: Vec<u8>,
}

/// Result from one outbound HTTP attempt.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct OutboundHttpResponse {
    /// HTTP status.
    pub status: u16,
}

/// Injectable outbound HTTP transport.
#[async_trait]
pub trait OutboundTransport: Send + Sync {
    /// Delivers one signed request without following redirects.
    async fn send(
        &self,
        request: OutboundHttpRequest,
    ) -> Result<OutboundHttpResponse, WebhookError>;
}

/// Resolves one webhook hostname before address policy is applied.
#[async_trait]
pub trait WebhookResolver: Send + Sync {
    /// Returns bounded candidate addresses for one host and port.
    async fn resolve(&self, host: &str, port: u16) -> Result<Vec<SocketAddr>, WebhookError>;
}

/// Operating-system DNS resolver.
#[derive(Clone, Copy, Debug, Default)]
pub struct SystemWebhookResolver;

#[async_trait]
impl WebhookResolver for SystemWebhookResolver {
    async fn resolve(&self, host: &str, port: u16) -> Result<Vec<SocketAddr>, WebhookError> {
        tokio::net::lookup_host((host, port))
            .await
            .map_err(|_| WebhookError::Resolve)
            .map(|addresses| addresses.take(MAX_RESOLVED_ADDRESSES + 1).collect())
    }
}

/// Native-root rustls HTTP transport with redirects disabled.
pub struct RustlsOutboundTransport<R = SystemWebhookResolver> {
    resolver: R,
    proxy: Matcher,
    tls: TlsConnector,
    timeout: Duration,
    allow_private_https: bool,
}

impl RustlsOutboundTransport<SystemWebhookResolver> {
    /// Builds a bounded client that allows HTTPS only to public addresses.
    pub fn new(timeout: Duration) -> Result<Self, WebhookError> {
        Self::new_with_resolver_and_proxy(timeout, SystemWebhookResolver, Matcher::from_env())
    }

    /// Builds a client that explicitly permits private HTTPS destinations.
    pub fn new_allowing_private_https(timeout: Duration) -> Result<Self, WebhookError> {
        let mut transport = Self::new(timeout)?;
        transport.allow_private_https = true;
        Ok(transport)
    }
}

impl<R> RustlsOutboundTransport<R> {
    #[cfg(test)]
    fn new_with_resolver(timeout: Duration, resolver: R) -> Result<Self, WebhookError> {
        Self::new_with_resolver_and_proxy(timeout, resolver, Matcher::builder().no("*").build())
    }

    fn new_with_resolver_and_proxy(
        timeout: Duration,
        resolver: R,
        proxy: Matcher,
    ) -> Result<Self, WebhookError> {
        if timeout.is_zero() {
            return Err(WebhookError::InvalidRetryPolicy);
        }
        let loaded = rustls_native_certs::load_native_certs();
        if loaded.certs.is_empty() {
            return Err(WebhookError::TlsConfiguration);
        }
        let mut roots = RootCertStore::empty();
        let (added, _) = roots.add_parsable_certificates(loaded.certs);
        if added == 0 {
            return Err(WebhookError::TlsConfiguration);
        }
        let provider = Arc::new(rustls::crypto::ring::default_provider());
        let config = ClientConfig::builder_with_provider(provider)
            .with_safe_default_protocol_versions()
            .map_err(|_| WebhookError::TlsConfiguration)?
            .with_root_certificates(roots)
            .with_no_client_auth();
        Ok(Self {
            resolver,
            proxy,
            tls: TlsConnector::from(Arc::new(config)),
            timeout,
            allow_private_https: false,
        })
    }
}

#[async_trait]
impl<R: WebhookResolver> OutboundTransport for RustlsOutboundTransport<R> {
    async fn send(
        &self,
        request: OutboundHttpRequest,
    ) -> Result<OutboundHttpResponse, WebhookError> {
        validate_transport_request(&request)?;
        tokio::time::timeout(self.timeout, self.send_inner(request))
            .await
            .map_err(|_| WebhookError::TransportTimeout)?
    }
}

impl<R: WebhookResolver> RustlsOutboundTransport<R> {
    async fn send_inner(
        &self,
        request: OutboundHttpRequest,
    ) -> Result<OutboundHttpResponse, WebhookError> {
        let host = request.url.host().ok_or(WebhookError::UnsafeEndpoint)?;
        let host_text = match host {
            Host::Domain(value) => value.to_owned(),
            Host::Ipv4(value) => value.to_string(),
            Host::Ipv6(value) => value.to_string(),
        };
        let port = request
            .url
            .port_or_known_default()
            .ok_or(WebhookError::UnsafeEndpoint)?;
        let addresses = match host {
            Host::Domain(_) => self.resolver.resolve(&host_text, port).await?,
            Host::Ipv4(value) => vec![SocketAddr::new(value.into(), port)],
            Host::Ipv6(value) => vec![SocketAddr::new(value.into(), port)],
        };
        validate_resolved_addresses(&request.url, &addresses, port, self.allow_private_https)?;
        if request.url.scheme() == "https" {
            let uri = request
                .url
                .as_str()
                .parse::<Uri>()
                .map_err(|_| WebhookError::UnsafeEndpoint)?;
            if let Some(proxy) = self.proxy.intercept(&uri) {
                return self
                    .send_via_proxy(proxy, &request, &host_text, &addresses)
                    .await;
            }
        }

        for address in addresses {
            let Ok(stream) = TcpStream::connect(address).await else {
                continue;
            };
            stream
                .set_nodelay(true)
                .map_err(|_| WebhookError::Transport)?;
            if request.url.scheme() == "https" {
                let server_name = ServerName::try_from(host_text.clone())
                    .map_err(|_| WebhookError::UnsafeEndpoint)?;
                let stream = self
                    .tls
                    .connect(server_name, stream)
                    .await
                    .map_err(|_| WebhookError::Transport)?;
                return exchange_webhook(stream, &request).await;
            }
            return exchange_webhook(stream, &request).await;
        }
        Err(WebhookError::Transport)
    }

    async fn send_via_proxy(
        &self,
        proxy: Intercept,
        request: &OutboundHttpRequest,
        destination_host: &str,
        destination_addresses: &[SocketAddr],
    ) -> Result<OutboundHttpResponse, WebhookError> {
        let proxy_uri = proxy.uri();
        let proxy_scheme = proxy_uri
            .scheme_str()
            .ok_or(WebhookError::ProxyConfiguration)?;
        if !matches!(proxy_scheme, "http" | "https") {
            return Err(WebhookError::UnsupportedProxy);
        }
        let proxy_host = proxy_uri.host().ok_or(WebhookError::ProxyConfiguration)?;
        if proxy_host.is_empty()
            || proxy_host.len() > 253
            || !proxy_host.is_ascii()
            || proxy_host.chars().any(char::is_control)
        {
            return Err(WebhookError::ProxyConfiguration);
        }
        let proxy_port =
            proxy_uri
                .port_u16()
                .unwrap_or(if proxy_scheme == "https" { 443 } else { 80 });
        let proxy_addresses =
            resolve_proxy_addresses(&self.resolver, proxy_host, proxy_port).await?;
        let authorization = proxy
            .basic_auth()
            .map(|value| {
                value
                    .to_str()
                    .map(str::to_owned)
                    .map_err(|_| WebhookError::ProxyConfiguration)
            })
            .transpose()?;
        if authorization
            .as_deref()
            .is_some_and(|value| value.len() > MAX_PROXY_AUTH_BYTES)
        {
            return Err(WebhookError::ProxyConfiguration);
        }

        for destination in destination_addresses {
            for proxy_address in &proxy_addresses {
                let Ok(stream) = TcpStream::connect(proxy_address).await else {
                    continue;
                };
                if stream.set_nodelay(true).is_err() {
                    continue;
                }
                if proxy_scheme == "https" {
                    let proxy_name = ServerName::try_from(proxy_host.to_owned())
                        .map_err(|_| WebhookError::ProxyConfiguration)?;
                    let Ok(stream) = self.tls.connect(proxy_name, stream).await else {
                        continue;
                    };
                    let stream = match establish_http_connect(
                        stream,
                        *destination,
                        authorization.as_deref(),
                    )
                    .await
                    {
                        Ok(stream) => stream,
                        Err(WebhookError::Transport) => continue,
                        Err(error) => return Err(error),
                    };
                    return self
                        .send_through_tunnel(stream, request, destination_host)
                        .await;
                }
                let stream =
                    match establish_http_connect(stream, *destination, authorization.as_deref())
                        .await
                    {
                        Ok(stream) => stream,
                        Err(WebhookError::Transport) => continue,
                        Err(error) => return Err(error),
                    };
                return self
                    .send_through_tunnel(stream, request, destination_host)
                    .await;
            }
        }
        Err(WebhookError::Transport)
    }

    async fn send_through_tunnel<S>(
        &self,
        stream: S,
        request: &OutboundHttpRequest,
        destination_host: &str,
    ) -> Result<OutboundHttpResponse, WebhookError>
    where
        S: AsyncRead + AsyncWrite + Unpin,
    {
        let server_name = ServerName::try_from(destination_host.to_owned())
            .map_err(|_| WebhookError::UnsafeEndpoint)?;
        let stream = self
            .tls
            .connect(server_name, stream)
            .await
            .map_err(|_| WebhookError::Transport)?;
        exchange_webhook(stream, request).await
    }
}

async fn resolve_proxy_addresses<R: WebhookResolver>(
    resolver: &R,
    host: &str,
    port: u16,
) -> Result<Vec<SocketAddr>, WebhookError> {
    let addresses = match host.parse::<IpAddr>() {
        Ok(address) => vec![SocketAddr::new(address, port)],
        Err(_) => resolver.resolve(host, port).await?,
    };
    if addresses.is_empty()
        || addresses.len() > MAX_RESOLVED_ADDRESSES
        || addresses
            .iter()
            .any(|address| address.port() != port || !is_connectable_ip(address.ip()))
    {
        return Err(WebhookError::ProxyConfiguration);
    }
    Ok(addresses)
}

async fn establish_http_connect<S>(
    mut stream: S,
    destination: SocketAddr,
    authorization: Option<&str>,
) -> Result<S, WebhookError>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let authorization = authorization.map_or_else(String::new, |value| {
        format!("Proxy-Authorization: {value}\r\n")
    });
    let request =
        format!("CONNECT {destination} HTTP/1.1\r\nHost: {destination}\r\n{authorization}\r\n");
    stream
        .write_all(request.as_bytes())
        .await
        .map_err(|_| WebhookError::Transport)?;
    stream.flush().await.map_err(|_| WebhookError::Transport)?;
    let response = read_http_headers(&mut stream).await?;
    let header_end = response
        .windows(4)
        .position(|window| window == b"\r\n\r\n")
        .ok_or(WebhookError::MalformedResponse)?;
    if response.len() != header_end + 4 {
        return Err(WebhookError::MalformedResponse);
    }
    if parse_response_status(&response)? != 200 {
        return Err(WebhookError::ProxyConnect);
    }
    Ok(stream)
}

fn validate_transport_request(request: &OutboundHttpRequest) -> Result<(), WebhookError> {
    let valid_scheme = matches!(request.url.scheme(), "http" | "https");
    let valid_signature = request
        .signature
        .strip_prefix(SIGNATURE_PREFIX)
        .and_then(decode_hex)
        .is_some_and(|bytes| bytes.len() == 32);
    if !valid_scheme
        || !request.url.username().is_empty()
        || request.url.password().is_some()
        || request.url.fragment().is_some()
        || request.url.host().is_none()
        || request.body.len() > MAX_BODY_BYTES
        || parse_timestamp(&request.timestamp).is_err()
        || validate_nonce(&request.nonce).is_err()
        || !valid_signature
    {
        return Err(WebhookError::UnsafeEndpoint);
    }
    Ok(())
}

fn validate_resolved_addresses(
    url: &Url,
    addresses: &[SocketAddr],
    expected_port: u16,
    allow_private_https: bool,
) -> Result<(), WebhookError> {
    if addresses.is_empty() || addresses.len() > MAX_RESOLVED_ADDRESSES {
        return Err(WebhookError::UnsafeEndpoint);
    }
    let addresses_match = addresses
        .iter()
        .all(|address| address.port() == expected_port);
    let permitted = if url.scheme() == "http" {
        url.host().is_some_and(loopback_host)
            && addresses.iter().all(|address| address.ip().is_loopback())
    } else if allow_private_https {
        addresses
            .iter()
            .all(|address| is_connectable_ip(address.ip()))
    } else {
        addresses.iter().all(|address| is_public_ip(address.ip()))
    };
    if !addresses_match || !permitted {
        return Err(WebhookError::UnsafeEndpoint);
    }
    Ok(())
}

fn is_connectable_ip(address: IpAddr) -> bool {
    match address {
        IpAddr::V4(address) => {
            !address.is_unspecified() && !address.is_broadcast() && !address.is_multicast()
        }
        IpAddr::V6(address) => !address.is_unspecified() && !address.is_multicast(),
    }
}

fn is_public_ip(address: IpAddr) -> bool {
    match address {
        IpAddr::V4(address) => is_public_ipv4(address),
        IpAddr::V6(address) => is_public_ipv6(address),
    }
}

fn is_public_ipv4(address: Ipv4Addr) -> bool {
    let [first, second, third, _] = address.octets();
    !matches!(first, 0 | 10 | 127 | 224..=255)
        && !(first == 100 && (64..=127).contains(&second))
        && !(first == 169 && second == 254)
        && !(first == 172 && (16..=31).contains(&second))
        && !(first == 192 && second == 0 && third == 0)
        && !(first == 192 && second == 0 && third == 2)
        && !(first == 192 && second == 88 && third == 99)
        && !(first == 192 && second == 168)
        && !(first == 198 && second == 51 && third == 100)
        && !(first == 198 && second == 18)
        && !(first == 198 && second == 19)
        && !(first == 203 && second == 0 && third == 113)
}

fn is_public_ipv6(address: Ipv6Addr) -> bool {
    if address.is_unspecified() || address.is_loopback() || address.is_multicast() {
        return false;
    }
    if let Some(mapped) = address.to_ipv4_mapped() {
        return is_public_ipv4(mapped);
    }
    let segments = address.segments();
    (segments[0] & 0xfe00) != 0xfc00
        && (segments[0] & 0xffc0) != 0xfe80
        && (segments[0] & 0xffc0) != 0xfec0
        && segments[0] != 0x2002
        && !(segments[0] == 0x2001 && segments[1] == 0x0db8)
        && !(segments[0] == 0x3fff && (segments[1] & 0xf000) == 0)
        && !(segments[0] == 0x0064
            && segments[1] == 0xff9b
            && segments[2] == 0
            && segments[3] == 0
            && segments[4] == 0
            && segments[5] == 0)
}

async fn exchange_webhook<S>(
    mut stream: S,
    request: &OutboundHttpRequest,
) -> Result<OutboundHttpResponse, WebhookError>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let authority = &request.url[Position::BeforeHost..Position::AfterPort];
    let path_and_query = &request.url[Position::BeforePath..];
    let path_and_query = if path_and_query.is_empty() {
        "/"
    } else {
        path_and_query
    };
    let headers = format!(
        "POST {path_and_query} HTTP/1.1\r\nHost: {authority}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nX-GTA-Claw-Timestamp: {}\r\nX-GTA-Claw-Nonce: {}\r\nX-GTA-Claw-Signature: {}\r\nConnection: close\r\n\r\n",
        request.body.len(),
        request.timestamp,
        request.nonce,
        request.signature
    );
    stream
        .write_all(headers.as_bytes())
        .await
        .map_err(|_| WebhookError::Transport)?;
    stream
        .write_all(&request.body)
        .await
        .map_err(|_| WebhookError::Transport)?;
    stream.flush().await.map_err(|_| WebhookError::Transport)?;
    let response = read_http_headers(&mut stream).await?;
    parse_response_status(&response).map(|status| OutboundHttpResponse { status })
}

async fn read_http_headers<S>(stream: &mut S) -> Result<Vec<u8>, WebhookError>
where
    S: AsyncRead + Unpin,
{
    let mut response = Vec::with_capacity(1024);
    let mut buffer = [0_u8; 1024];
    loop {
        let read = stream
            .read(&mut buffer)
            .await
            .map_err(|_| WebhookError::Transport)?;
        if read == 0 {
            return Err(WebhookError::MalformedResponse);
        }
        response.extend_from_slice(&buffer[..read]);
        if response.windows(4).any(|window| window == b"\r\n\r\n") {
            break;
        }
        if response.len() > MAX_RESPONSE_HEADER_BYTES {
            return Err(WebhookError::ResponseHeadersTooLarge);
        }
    }
    Ok(response)
}

fn parse_response_status(response: &[u8]) -> Result<u16, WebhookError> {
    let header_end = response
        .windows(4)
        .position(|window| window == b"\r\n\r\n")
        .ok_or(WebhookError::MalformedResponse)?;
    if header_end > MAX_RESPONSE_HEADER_BYTES {
        return Err(WebhookError::ResponseHeadersTooLarge);
    }
    let status_line = std::str::from_utf8(&response[..header_end])
        .map_err(|_| WebhookError::MalformedResponse)?
        .split("\r\n")
        .next()
        .ok_or(WebhookError::MalformedResponse)?;
    let mut fields = status_line.split_whitespace();
    let version = fields.next().ok_or(WebhookError::MalformedResponse)?;
    let status = fields
        .next()
        .ok_or(WebhookError::MalformedResponse)?
        .parse::<u16>()
        .map_err(|_| WebhookError::MalformedResponse)?;
    if !matches!(version, "HTTP/1.0" | "HTTP/1.1") || !(200..=599).contains(&status) {
        return Err(WebhookError::MalformedResponse);
    }
    Ok(status)
}

/// Retry and exponential-backoff policy.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RetryPolicy {
    /// Total attempts including the first.
    pub max_attempts: u8,
    /// Initial delay before the second attempt.
    pub base_delay: Duration,
    /// Upper backoff bound.
    pub max_delay: Duration,
}

impl RetryPolicy {
    /// Validates retry limits.
    pub fn validate(&self) -> Result<(), WebhookError> {
        if self.max_attempts == 0
            || self.max_attempts > 10
            || self.base_delay.is_zero()
            || self.base_delay > self.max_delay
            || self.max_delay > Duration::from_secs(60 * 60)
        {
            return Err(WebhookError::InvalidRetryPolicy);
        }
        Ok(())
    }

    fn delay_before(&self, attempt: u8) -> Duration {
        let exponent = u32::from(attempt.saturating_sub(1));
        self.base_delay
            .saturating_mul(2_u32.saturating_pow(exponent))
            .min(self.max_delay)
    }
}

/// Async delay boundary for deterministic retry tests.
#[async_trait]
pub trait RetrySleeper: Send + Sync {
    /// Sleeps for the requested backoff.
    async fn sleep(&self, duration: Duration);
}

/// Tokio retry sleeper.
#[derive(Clone, Copy, Debug, Default)]
pub struct TokioRetrySleeper;

#[async_trait]
impl RetrySleeper for TokioRetrySleeper {
    async fn sleep(&self, duration: Duration) {
        tokio::time::sleep(duration).await;
    }
}

/// Persisted terminal delivery failure.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct DeadLetter {
    /// Endpoint identifier without secret material.
    pub endpoint_id: String,
    /// Original TaskFlow event.
    pub event: TaskFlowEvent,
    /// Number of exhausted attempts.
    pub attempts: u8,
    /// Last HTTP status or transport category.
    pub last_failure: String,
    /// Unix timestamp at terminal failure.
    pub failed_at: i64,
}

/// Durable dead-letter boundary.
#[async_trait]
pub trait DeadLetterSink: Send + Sync {
    /// Persists one terminal failure.
    async fn store(&self, dead_letter: DeadLetter) -> Result<(), WebhookError>;
}

/// Append-only JSON-lines dead-letter sink.
pub struct JsonLinesDeadLetterSink {
    path: PathBuf,
}

impl JsonLinesDeadLetterSink {
    /// Creates a sink at a caller-controlled application-data path.
    #[must_use]
    pub fn new(path: PathBuf) -> Self {
        Self { path }
    }
}

#[async_trait]
impl DeadLetterSink for JsonLinesDeadLetterSink {
    async fn store(&self, dead_letter: DeadLetter) -> Result<(), WebhookError> {
        let mut line = serde_json::to_vec(&dead_letter).map_err(WebhookError::InvalidJson)?;
        if line.len() >= MAX_BODY_BYTES {
            return Err(WebhookError::DeadLetterTooLarge);
        }
        line.push(b'\n');
        let mut file = tokio::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(&self.path)
            .await
            .map_err(WebhookError::Io)?;
        file.write_all(&line).await.map_err(WebhookError::Io)?;
        file.flush().await.map_err(WebhookError::Io)
    }
}

/// Terminal or successful delivery outcome.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum DeliveryOutcome {
    /// Destination accepted the event.
    Delivered {
        /// Attempts consumed.
        attempts: u8,
        /// Successful HTTP status.
        status: u16,
    },
    /// Retry budget was exhausted and a dead letter was persisted.
    DeadLettered {
        /// Attempts consumed.
        attempts: u8,
    },
}

/// Wall-clock source used to timestamp each signed delivery attempt.
pub trait WebhookClock: Send + Sync {
    /// Returns the current Unix timestamp in seconds.
    fn now_unix_seconds(&self) -> Result<i64, WebhookError>;
}

/// Operating-system wall clock.
#[derive(Clone, Copy, Debug, Default)]
pub struct SystemWebhookClock;

impl WebhookClock for SystemWebhookClock {
    fn now_unix_seconds(&self) -> Result<i64, WebhookError> {
        let seconds = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|_| WebhookError::Clock)?
            .as_secs();
        i64::try_from(seconds).map_err(|_| WebhookError::Clock)
    }
}

/// Outbound webhook delivery orchestrator.
pub struct OutboundWebhookSender<T, D, S, C = SystemWebhookClock> {
    transport: T,
    dead_letters: D,
    sleeper: S,
    retry: RetryPolicy,
    clock: C,
}

impl<T, D, S> OutboundWebhookSender<T, D, S, SystemWebhookClock>
where
    T: OutboundTransport,
    D: DeadLetterSink,
    S: RetrySleeper,
{
    /// Creates a sender with a validated retry policy.
    pub fn new(
        transport: T,
        dead_letters: D,
        sleeper: S,
        retry: RetryPolicy,
    ) -> Result<Self, WebhookError> {
        Self::new_with_clock(transport, dead_letters, sleeper, retry, SystemWebhookClock)
    }
}

impl<T, D, S, C> OutboundWebhookSender<T, D, S, C>
where
    T: OutboundTransport,
    D: DeadLetterSink,
    S: RetrySleeper,
    C: WebhookClock,
{
    /// Creates a sender with a validated retry policy and explicit clock.
    pub fn new_with_clock(
        transport: T,
        dead_letters: D,
        sleeper: S,
        retry: RetryPolicy,
        clock: C,
    ) -> Result<Self, WebhookError> {
        retry.validate()?;
        Ok(Self {
            transport,
            dead_letters,
            sleeper,
            retry,
            clock,
        })
    }

    /// Signs and delivers an event with bounded exponential retries.
    pub async fn deliver(
        &self,
        endpoint: &OutboundEndpoint,
        event: &TaskFlowEvent,
        delivery_nonce: &str,
        allow_loopback_http: bool,
    ) -> Result<DeliveryOutcome, WebhookError> {
        endpoint.validate(allow_loopback_http)?;
        event.validate()?;
        validate_nonce(delivery_nonce)?;
        let body = serde_json::to_vec(event).map_err(WebhookError::InvalidJson)?;
        if body.len() > MAX_BODY_BYTES {
            return Err(WebhookError::BodyTooLarge);
        }
        let path = endpoint.path_and_query();
        let mut last_failure = String::new();
        for attempt in 1..=self.retry.max_attempts {
            let timestamp = self.clock.now_unix_seconds()?;
            let nonce = attempt_nonce(&endpoint.secret, delivery_nonce, attempt)?;
            let signature = sign_webhook(&endpoint.secret, &path, timestamp, &nonce, &body)?;
            let request = OutboundHttpRequest {
                url: endpoint.url.clone(),
                timestamp: timestamp.to_string(),
                nonce,
                signature,
                body: body.clone(),
            };
            match self.transport.send(request).await {
                Ok(response) if (200..300).contains(&response.status) => {
                    return Ok(DeliveryOutcome::Delivered {
                        attempts: attempt,
                        status: response.status,
                    });
                }
                Ok(response) if !retryable_status(response.status) => {
                    return Err(WebhookError::PermanentStatus(response.status));
                }
                Ok(response) => {
                    last_failure = format!("HTTP {}", response.status);
                }
                Err(error) if error.retryable_delivery_failure() => {
                    last_failure = "transport failure".to_owned();
                }
                Err(error) => return Err(error),
            }
            if attempt < self.retry.max_attempts {
                self.sleeper.sleep(self.retry.delay_before(attempt)).await;
            }
        }
        self.dead_letters
            .store(DeadLetter {
                endpoint_id: endpoint.id.clone(),
                event: event.clone(),
                attempts: self.retry.max_attempts,
                last_failure,
                failed_at: self.clock.now_unix_seconds()?,
            })
            .await?;
        Ok(DeliveryOutcome::DeadLettered {
            attempts: self.retry.max_attempts,
        })
    }
}

fn attempt_nonce(
    secret: &WebhookSecret,
    delivery_nonce: &str,
    attempt: u8,
) -> Result<String, WebhookError> {
    let mut mac =
        HmacSha256::new_from_slice(secret.bytes()).map_err(|_| WebhookError::SigningState)?;
    mac.update(DELIVERY_NONCE_DOMAIN);
    mac.update(delivery_nonce.as_bytes());
    Ok(format!(
        "{DELIVERY_NONCE_PREFIX}{}-{attempt}",
        encode_hex(&mac.finalize().into_bytes()),
    ))
}

fn replay_nonce(nonce: &str) -> &str {
    let Some(value) = nonce.strip_prefix(DELIVERY_NONCE_PREFIX) else {
        return nonce;
    };
    let Some((digest, attempt)) = value.rsplit_once('-') else {
        return nonce;
    };
    let valid_digest = digest.len() == 64
        && digest
            .bytes()
            .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'));
    let valid_attempt = attempt
        .parse::<u8>()
        .ok()
        .filter(|number| (1..=10).contains(number))
        .is_some_and(|number| attempt == number.to_string());
    if valid_digest && valid_attempt {
        &nonce[..DELIVERY_NONCE_PREFIX.len() + digest.len()]
    } else {
        nonce
    }
}

fn retryable_status(status: u16) -> bool {
    matches!(status, 408 | 425 | 429) || (500..600).contains(&status)
}

/// Webhook authentication, authorization, transport, or persistence failure.
#[derive(Debug)]
pub enum WebhookError {
    /// Signing secret has less than 32 bytes.
    WeakSecret,
    /// Route syntax or policy is invalid.
    InvalidRoute,
    /// Two route records use the same path.
    DuplicateRoute,
    /// Request path has no configured route.
    RouteNotFound,
    /// Session binding policy is malformed.
    InvalidSessionBinding,
    /// Request body exceeds its route limit.
    BodyTooLarge,
    /// Nonce syntax is malformed.
    InvalidNonce,
    /// Timestamp syntax is malformed.
    InvalidTimestamp,
    /// Timestamp is outside the route replay window.
    TimestampOutsideWindow,
    /// HMAC is malformed or incorrect.
    InvalidSignature,
    /// Nonce was already accepted.
    Replay,
    /// Replay cache cannot safely admit another live nonce.
    ReplayCapacity,
    /// Replay cache policy is invalid.
    InvalidReplayPolicy,
    /// Replay cache mutex was poisoned.
    ReplayState,
    /// The wall clock could not produce a Unix timestamp.
    Clock,
    /// Event JSON is malformed.
    InvalidJson(serde_json::Error),
    /// Event structural fields are invalid.
    InvalidEvent,
    /// Event action is not allowlisted.
    ActionDenied,
    /// Event session key violates route binding.
    SessionDenied,
    /// HMAC implementation rejected its key state.
    SigningState,
    /// Outbound URL is unsafe.
    UnsafeEndpoint,
    /// Retry policy is invalid.
    InvalidRetryPolicy,
    /// Destination returned a non-retryable HTTP status.
    PermanentStatus(u16),
    /// DNS resolution failed.
    Resolve,
    /// Native trust roots or TLS configuration were unavailable.
    TlsConfiguration,
    /// The configured proxy endpoint was malformed or unsafe.
    ProxyConfiguration,
    /// The configured proxy protocol is not supported.
    UnsupportedProxy,
    /// The proxy rejected a CONNECT tunnel.
    ProxyConnect,
    /// The validated socket or TLS exchange failed.
    Transport,
    /// The complete transport operation timed out.
    TransportTimeout,
    /// The HTTP response status line was malformed.
    MalformedResponse,
    /// The HTTP response headers exceeded their fixed bound.
    ResponseHeadersTooLarge,
    /// Dead-letter I/O failed.
    Io(std::io::Error),
    /// Dead-letter record exceeds its fixed bound.
    DeadLetterTooLarge,
    /// Application dispatch failed.
    Dispatch(String),
    /// Test or custom transport failed transiently.
    TransientTransport(String),
}

impl WebhookError {
    fn retryable_delivery_failure(&self) -> bool {
        matches!(
            self,
            Self::Resolve | Self::Transport | Self::TransportTimeout | Self::TransientTransport(_)
        )
    }
}

impl Display for WebhookError {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        match self {
            Self::WeakSecret => formatter.write_str("webhook secret is too short"),
            Self::InvalidRoute => formatter.write_str("invalid webhook route"),
            Self::DuplicateRoute => formatter.write_str("duplicate webhook route"),
            Self::RouteNotFound => formatter.write_str("webhook route not found"),
            Self::InvalidSessionBinding => formatter.write_str("invalid session binding"),
            Self::BodyTooLarge => formatter.write_str("webhook body is too large"),
            Self::InvalidNonce => formatter.write_str("invalid webhook nonce"),
            Self::InvalidTimestamp => formatter.write_str("invalid webhook timestamp"),
            Self::TimestampOutsideWindow => {
                formatter.write_str("webhook timestamp is outside the replay window")
            }
            Self::InvalidSignature => formatter.write_str("invalid webhook signature"),
            Self::Replay => formatter.write_str("replayed webhook"),
            Self::ReplayCapacity => formatter.write_str("webhook replay cache is full"),
            Self::InvalidReplayPolicy => formatter.write_str("invalid replay policy"),
            Self::ReplayState => formatter.write_str("webhook replay state unavailable"),
            Self::Clock => formatter.write_str("webhook wall clock is unavailable"),
            Self::InvalidJson(error) => write!(formatter, "invalid webhook JSON: {error}"),
            Self::InvalidEvent => formatter.write_str("invalid TaskFlow event"),
            Self::ActionDenied => formatter.write_str("TaskFlow action denied"),
            Self::SessionDenied => formatter.write_str("TaskFlow session denied"),
            Self::SigningState => formatter.write_str("webhook signing unavailable"),
            Self::UnsafeEndpoint => formatter.write_str("unsafe outbound webhook endpoint"),
            Self::InvalidRetryPolicy => formatter.write_str("invalid webhook retry policy"),
            Self::PermanentStatus(status) => {
                write!(formatter, "webhook destination returned HTTP {status}")
            }
            Self::Resolve => formatter.write_str("webhook destination resolution failed"),
            Self::TlsConfiguration => formatter.write_str("webhook TLS configuration unavailable"),
            Self::ProxyConfiguration => formatter.write_str("invalid webhook proxy configuration"),
            Self::UnsupportedProxy => formatter.write_str("unsupported webhook proxy protocol"),
            Self::ProxyConnect => formatter.write_str("webhook proxy tunnel rejected"),
            Self::Transport => formatter.write_str("webhook transport failed"),
            Self::TransportTimeout => formatter.write_str("webhook transport timed out"),
            Self::MalformedResponse => formatter.write_str("malformed webhook HTTP response"),
            Self::ResponseHeadersTooLarge => {
                formatter.write_str("webhook HTTP response headers are too large")
            }
            Self::Io(error) => write!(formatter, "dead-letter I/O failed: {error}"),
            Self::DeadLetterTooLarge => formatter.write_str("dead-letter record is too large"),
            Self::Dispatch(message) => write!(formatter, "TaskFlow dispatch failed: {message}"),
            Self::TransientTransport(message) => {
                write!(formatter, "transient webhook transport failure: {message}")
            }
        }
    }
}

impl Error for WebhookError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::InvalidJson(error) => Some(error),
            Self::Io(error) => Some(error),
            _ => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use std::collections::VecDeque;

    use super::*;

    fn secret() -> WebhookSecret {
        WebhookSecret::new(SecretString::from(
            "0123456789abcdef0123456789abcdef".to_owned(),
        ))
        .expect("strong secret")
    }

    fn event() -> TaskFlowEvent {
        TaskFlowEvent {
            action: "task.completed".to_owned(),
            session_key: "taskflow:session-7".to_owned(),
            task_id: "task-42".to_owned(),
            payload: serde_json::json!({"result":"ok"}),
        }
    }

    fn request(nonce: &str, body: Vec<u8>) -> InboundWebhookRequest {
        let timestamp = 1_750_000_000;
        InboundWebhookRequest {
            path: "/plugins/webhooks/taskflow".to_owned(),
            timestamp: timestamp.to_string(),
            nonce: nonce.to_owned(),
            signature: sign_webhook(
                &secret(),
                "/plugins/webhooks/taskflow",
                timestamp,
                nonce,
                &body,
            )
            .expect("signature"),
            body,
        }
    }

    fn handler(max_body_bytes: usize) -> InboundWebhookHandler {
        InboundWebhookHandler::new(
            vec![InboundRoute {
                id: "taskflow".to_owned(),
                path: "/plugins/webhooks/taskflow".to_owned(),
                secret: secret(),
                allowed_actions: ["task.completed".to_owned()].into_iter().collect(),
                session_binding: SessionBinding::Prefix("taskflow:".to_owned()),
                max_body_bytes,
            }],
            ReplayGuard::new(Duration::from_secs(300), 8).expect("replay"),
        )
        .expect("handler")
    }

    #[derive(Default)]
    struct RecordingDispatcher {
        events: Mutex<Vec<TaskFlowEvent>>,
    }

    #[async_trait]
    impl TaskFlowDispatcher for RecordingDispatcher {
        async fn dispatch(&self, event: TaskFlowEvent) -> Result<DispatchReceipt, WebhookError> {
            self.events.lock().expect("events").push(event);
            Ok(DispatchReceipt {
                dispatch_id: "dispatch-1".to_owned(),
            })
        }
    }

    #[derive(Default)]
    struct PendingDispatcher {
        entered: std::sync::atomic::AtomicBool,
    }

    #[async_trait]
    impl TaskFlowDispatcher for PendingDispatcher {
        async fn dispatch(&self, _event: TaskFlowEvent) -> Result<DispatchReceipt, WebhookError> {
            self.entered
                .store(true, std::sync::atomic::Ordering::SeqCst);
            std::future::pending().await
        }
    }

    #[tokio::test]
    async fn authenticates_binds_and_dispatches_exact_event() {
        let event = event();
        let body = serde_json::to_vec(&event).expect("event JSON");
        let request = request("nonce-1", body);
        let dispatcher = RecordingDispatcher::default();

        let receipt = handler(4096)
            .handle(request, 1_750_000_000, &dispatcher)
            .await
            .expect("dispatch");

        assert_eq!(
            receipt,
            DispatchReceipt {
                dispatch_id: "dispatch-1".to_owned()
            }
        );
        assert_eq!(*dispatcher.events.lock().expect("events"), vec![event]);
    }

    #[tokio::test]
    async fn rejects_forged_truncated_and_replayed_signatures() {
        let body = serde_json::to_vec(&event()).expect("event JSON");
        let dispatcher = RecordingDispatcher::default();
        let valid = request("nonce-valid", body.clone());
        let mut forged = request("nonce-forged", body.clone());
        forged.signature.replace_range(16..17, "f");
        let mut truncated = request("nonce-short", body);
        truncated.signature.truncate(24);

        assert!(matches!(
            handler(4096)
                .handle(forged, 1_750_000_000, &dispatcher)
                .await,
            Err(WebhookError::InvalidSignature)
        ));
        assert!(matches!(
            handler(4096)
                .handle(truncated, 1_750_000_000, &dispatcher)
                .await,
            Err(WebhookError::InvalidSignature)
        ));
        let replay_handler = handler(4096);
        replay_handler
            .handle(valid.clone(), 1_750_000_000, &dispatcher)
            .await
            .expect("first delivery");
        assert!(matches!(
            replay_handler
                .handle(valid, 1_750_000_001, &dispatcher)
                .await,
            Err(WebhookError::Replay)
        ));
    }

    #[tokio::test]
    async fn rejects_a_retry_attempt_after_the_delivery_was_dispatched() {
        let event = event();
        let body = serde_json::to_vec(&event).expect("event JSON");
        let first_nonce = attempt_nonce(&secret(), "delivery-1", 1).expect("first nonce");
        let second_nonce = attempt_nonce(&secret(), "delivery-1", 2).expect("second nonce");
        let dispatcher = RecordingDispatcher::default();
        let retry_handler = handler(4096);

        retry_handler
            .handle(
                request(&first_nonce, body.clone()),
                1_750_000_000,
                &dispatcher,
            )
            .await
            .expect("first attempt");
        assert!(matches!(
            retry_handler
                .handle(request(&second_nonce, body), 1_750_000_001, &dispatcher)
                .await,
            Err(WebhookError::Replay)
        ));
        assert_eq!(*dispatcher.events.lock().expect("events"), vec![event]);
    }

    #[tokio::test]
    async fn cancellation_during_dispatch_burns_only_the_authenticated_nonce() {
        let body = serde_json::to_vec(&event()).expect("event JSON");
        let process_id = std::process::id();
        let cancelled_delivery = format!("cancelled-delivery-{process_id}");
        let next_delivery = format!("next-delivery-{process_id}");
        let cancelled_nonce =
            attempt_nonce(&secret(), &cancelled_delivery, 1).expect("cancelled nonce");
        let next_nonce = attempt_nonce(&secret(), &next_delivery, 1).expect("next nonce");
        let cancelled_request = request(&cancelled_nonce, body.clone());
        let replay_handler = handler(4096);
        let pending_dispatcher = PendingDispatcher::default();
        let mut delivery = Box::pin(replay_handler.handle(
            cancelled_request.clone(),
            1_750_000_000,
            &pending_dispatcher,
        ));
        let mut context = std::task::Context::from_waker(std::task::Waker::noop());

        assert!(matches!(
            std::future::Future::poll(delivery.as_mut(), &mut context),
            std::task::Poll::Pending
        ));
        assert!(
            pending_dispatcher
                .entered
                .load(std::sync::atomic::Ordering::SeqCst)
        );
        drop(delivery);

        let dispatcher = RecordingDispatcher::default();
        assert!(matches!(
            replay_handler
                .handle(cancelled_request, 1_750_000_001, &dispatcher)
                .await,
            Err(WebhookError::Replay)
        ));
        let receipt = replay_handler
            .handle(request(&next_nonce, body), 1_750_000_001, &dispatcher)
            .await
            .expect("unrelated delivery");
        assert_eq!(
            receipt,
            DispatchReceipt {
                dispatch_id: "dispatch-1".to_owned()
            }
        );
        assert_eq!(*dispatcher.events.lock().expect("events"), vec![event()]);
    }

    #[tokio::test]
    async fn replay_reservation_covers_the_full_inclusive_timestamp_window() {
        let event = event();
        let body = serde_json::to_vec(&event).expect("event JSON");
        let dispatcher = RecordingDispatcher::default();
        let replay_handler = handler(4096);
        let future_timestamp = 1_750_000_300;
        let nonce = "future-nonce";
        let future_request = InboundWebhookRequest {
            path: "/plugins/webhooks/taskflow".to_owned(),
            timestamp: future_timestamp.to_string(),
            nonce: nonce.to_owned(),
            signature: sign_webhook(
                &secret(),
                "/plugins/webhooks/taskflow",
                future_timestamp,
                nonce,
                &body,
            )
            .expect("signature"),
            body,
        };

        replay_handler
            .handle(future_request.clone(), 1_750_000_000, &dispatcher)
            .await
            .expect("future-skewed request");
        assert!(matches!(
            replay_handler
                .handle(future_request, 1_750_000_600, &dispatcher)
                .await,
            Err(WebhookError::Replay)
        ));
        assert_eq!(*dispatcher.events.lock().expect("events"), vec![event]);
    }

    #[tokio::test]
    async fn rejects_oversize_body_and_wrong_session_before_dispatch() {
        let dispatcher = RecordingDispatcher::default();
        let oversized = request("nonce-large", vec![b'x'; 65]);
        assert!(matches!(
            handler(64)
                .handle(oversized, 1_750_000_000, &dispatcher)
                .await,
            Err(WebhookError::BodyTooLarge)
        ));

        let mut wrong_session = event();
        wrong_session.session_key = "different:session-7".to_owned();
        let body = serde_json::to_vec(&wrong_session).expect("JSON");
        assert!(matches!(
            handler(4096)
                .handle(request("nonce-session", body), 1_750_000_000, &dispatcher)
                .await,
            Err(WebhookError::SessionDenied)
        ));
        assert!(dispatcher.events.lock().expect("events").is_empty());
    }

    struct FixedResolver {
        addresses: Vec<SocketAddr>,
        calls: Mutex<Vec<(String, u16)>>,
    }

    #[async_trait]
    impl WebhookResolver for FixedResolver {
        async fn resolve(&self, host: &str, port: u16) -> Result<Vec<SocketAddr>, WebhookError> {
            self.calls
                .lock()
                .expect("resolver calls")
                .push((host.to_owned(), port));
            Ok(self.addresses.clone())
        }
    }

    fn outbound_request(url: Url) -> OutboundHttpRequest {
        let body = serde_json::to_vec(&event()).expect("event");
        let timestamp = "1750000000".to_owned();
        let nonce = "delivery-attempt-1".to_owned();
        let path = url.query().map_or_else(
            || url.path().to_owned(),
            |query| format!("{}?{query}", url.path()),
        );
        let signature =
            sign_webhook(&secret(), &path, 1_750_000_000, &nonce, &body).expect("signature");
        OutboundHttpRequest {
            url,
            timestamp,
            nonce,
            signature,
            body,
        }
    }

    #[tokio::test]
    async fn outbound_transport_connects_to_the_validated_loopback_address() {
        let listener = tokio::net::TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
            .await
            .expect("listener");
        let address = listener.local_addr().expect("address");
        let server = tokio::spawn(async move {
            let (mut stream, peer) = listener.accept().await.expect("accept");
            let mut received = Vec::new();
            let mut buffer = [0_u8; 1024];
            loop {
                let read = stream.read(&mut buffer).await.expect("read");
                assert_ne!(read, 0);
                received.extend_from_slice(&buffer[..read]);
                if received
                    .windows(4)
                    .position(|window| window == b"\r\n\r\n")
                    .is_some_and(|header_end| {
                        let headers =
                            std::str::from_utf8(&received[..header_end]).expect("headers");
                        let length = headers
                            .split("\r\n")
                            .find_map(|line| {
                                line.strip_prefix("Content-Length: ")
                                    .and_then(|value| value.parse::<usize>().ok())
                            })
                            .expect("content length");
                        received.len() >= header_end + 4 + length
                    })
                {
                    break;
                }
            }
            stream
                .write_all(b"HTTP/1.1 204 No Content\r\nContent-Length: 0\r\n\r\n")
                .await
                .expect("response");
            (peer, received)
        });
        let resolver = FixedResolver {
            addresses: vec![address],
            calls: Mutex::new(Vec::new()),
        };
        let transport =
            RustlsOutboundTransport::new_with_resolver(Duration::from_secs(2), resolver)
                .expect("transport");
        let url = Url::parse(&format!(
            "http://localhost:{}/taskflow?source=gta",
            address.port()
        ))
        .expect("URL");
        let request = outbound_request(url);
        let expected = [
            format!(
                "POST /taskflow?source=gta HTTP/1.1\r\nHost: localhost:{}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nX-GTA-Claw-Timestamp: {}\r\nX-GTA-Claw-Nonce: {}\r\nX-GTA-Claw-Signature: {}\r\nConnection: close\r\n\r\n",
                address.port(),
                request.body.len(),
                request.timestamp,
                request.nonce,
                request.signature
            )
            .into_bytes(),
            request.body.clone(),
        ]
        .concat();

        let response = transport.send(request).await.expect("delivery");
        let (peer, received) = server.await.expect("server");

        assert_eq!(response, OutboundHttpResponse { status: 204 });
        assert_eq!(peer.ip(), IpAddr::V4(Ipv4Addr::LOCALHOST));
        assert_eq!(
            transport.resolver.calls.lock().expect("calls").as_slice(),
            &[("localhost".to_owned(), address.port())]
        );
        assert_eq!(received, expected);
    }

    #[tokio::test]
    async fn outbound_transport_rejects_rebound_and_private_addresses_before_connect() {
        let port = 18_789;
        let resolver = FixedResolver {
            addresses: vec![SocketAddr::new(
                IpAddr::V4(Ipv4Addr::new(192, 0, 2, 44)),
                port,
            )],
            calls: Mutex::new(Vec::new()),
        };
        let transport =
            RustlsOutboundTransport::new_with_resolver(Duration::from_secs(1), resolver)
                .expect("transport");
        let loopback_name = Url::parse(&format!("http://localhost:{port}/taskflow")).expect("URL");
        assert!(matches!(
            transport.send(outbound_request(loopback_name)).await,
            Err(WebhookError::UnsafeEndpoint)
        ));

        assert!(matches!(
            validate_resolved_addresses(
                &Url::parse("https://hooks.example.test/taskflow").expect("URL"),
                &[SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 443)],
                443,
                false,
            ),
            Err(WebhookError::UnsafeEndpoint)
        ));
        assert!(matches!(
            validate_resolved_addresses(
                &Url::parse("https://hooks.example.test/taskflow").expect("URL"),
                &[SocketAddr::new(
                    IpAddr::V6("2001:db8::7".parse().expect("IPv6")),
                    443,
                )],
                443,
                false,
            ),
            Err(WebhookError::UnsafeEndpoint)
        ));
    }

    #[tokio::test]
    async fn outbound_transport_honors_authenticated_environment_proxy_matches() {
        let proxy_listener = tokio::net::TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
            .await
            .expect("proxy listener");
        let proxy_address = proxy_listener.local_addr().expect("proxy address");
        let proxy_server = tokio::spawn(async move {
            let (mut stream, peer) = proxy_listener.accept().await.expect("proxy accept");
            let request = read_http_headers(&mut stream)
                .await
                .expect("CONNECT request");
            stream
                .write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n")
                .await
                .expect("CONNECT response");
            stream.shutdown().await.expect("proxy shutdown");
            (peer, request)
        });
        let destination = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8)), 443);
        let resolver = FixedResolver {
            addresses: vec![destination],
            calls: Mutex::new(Vec::new()),
        };
        let matcher = Matcher::builder()
            .https(format!(
                "{}://{}:{}@{proxy_address}",
                "http", "user", "pass"
            ))
            .build();
        let transport = RustlsOutboundTransport::new_with_resolver_and_proxy(
            Duration::from_secs(2),
            resolver,
            matcher,
        )
        .expect("transport");
        let request = outbound_request(
            Url::parse("https://hooks.example.test/taskflow").expect("destination URL"),
        );

        assert!(matches!(
            transport.send(request).await,
            Err(WebhookError::Transport)
        ));
        let (peer, connect_request) = proxy_server.await.expect("proxy server");
        assert_eq!(peer.ip(), IpAddr::V4(Ipv4Addr::LOCALHOST));
        assert_eq!(
            connect_request,
            b"CONNECT 8.8.8.8:443 HTTP/1.1\r\nHost: 8.8.8.8:443\r\nProxy-Authorization: Basic dXNlcjpwYXNz\r\n\r\n"
        );
        assert_eq!(
            transport.resolver.calls.lock().expect("calls").as_slice(),
            &[("hooks.example.test".to_owned(), 443)]
        );
    }

    #[tokio::test]
    async fn proxy_rejection_is_permanent_and_preserves_exact_connect_request() {
        let (client, mut proxy) = tokio::io::duplex(2048);
        let server = tokio::spawn(async move {
            let request = read_http_headers(&mut proxy)
                .await
                .expect("CONNECT request");
            proxy
                .write_all(
                    b"HTTP/1.1 407 Proxy Authentication Required\r\nContent-Length: 0\r\n\r\n",
                )
                .await
                .expect("proxy rejection");
            request
        });
        let destination = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(8, 8, 4, 4)), 443);

        assert!(matches!(
            establish_http_connect(client, destination, None).await,
            Err(WebhookError::ProxyConnect)
        ));
        assert_eq!(
            server.await.expect("proxy server"),
            b"CONNECT 8.8.4.4:443 HTTP/1.1\r\nHost: 8.8.4.4:443\r\n\r\n"
        );
        assert!(!WebhookError::ProxyConnect.retryable_delivery_failure());
    }

    #[test]
    fn outbound_response_parser_is_bounded_and_strict() {
        assert_eq!(
            parse_response_status(b"HTTP/1.1 429 Too Many Requests\r\nContent-Length: 0\r\n\r\n")
                .expect("status"),
            429
        );
        assert!(matches!(
            parse_response_status(b"HTTP/2 200 OK\r\n\r\n"),
            Err(WebhookError::MalformedResponse)
        ));
        let oversized = [
            b"HTTP/1.1 200 OK\r\nX-Padding: ".as_slice(),
            vec![b'x'; MAX_RESPONSE_HEADER_BYTES].as_slice(),
            b"\r\n\r\n".as_slice(),
        ]
        .concat();
        assert!(matches!(
            parse_response_status(&oversized),
            Err(WebhookError::ResponseHeadersTooLarge)
        ));
    }

    struct FakeOutbound {
        results: Mutex<VecDeque<Result<OutboundHttpResponse, WebhookError>>>,
        requests: Mutex<Vec<OutboundHttpRequest>>,
    }

    #[async_trait]
    impl OutboundTransport for FakeOutbound {
        async fn send(
            &self,
            request: OutboundHttpRequest,
        ) -> Result<OutboundHttpResponse, WebhookError> {
            self.requests.lock().expect("requests").push(request);
            self.results
                .lock()
                .expect("results")
                .pop_front()
                .expect("configured attempt")
        }
    }

    #[derive(Default)]
    struct FakeSleeper {
        durations: Mutex<Vec<Duration>>,
    }

    #[async_trait]
    impl RetrySleeper for FakeSleeper {
        async fn sleep(&self, duration: Duration) {
            self.durations.lock().expect("durations").push(duration);
        }
    }

    #[derive(Default)]
    struct FakeDeadLetters {
        letters: Mutex<Vec<DeadLetter>>,
    }

    #[async_trait]
    impl DeadLetterSink for FakeDeadLetters {
        async fn store(&self, dead_letter: DeadLetter) -> Result<(), WebhookError> {
            self.letters.lock().expect("letters").push(dead_letter);
            Ok(())
        }
    }

    struct FakeClock {
        timestamps: Mutex<VecDeque<i64>>,
    }

    impl WebhookClock for FakeClock {
        fn now_unix_seconds(&self) -> Result<i64, WebhookError> {
            self.timestamps
                .lock()
                .map_err(|_| WebhookError::Clock)?
                .pop_front()
                .ok_or(WebhookError::Clock)
        }
    }

    #[tokio::test]
    async fn retries_exponentially_then_dead_letters_without_secret() {
        let transport = FakeOutbound {
            results: Mutex::new(VecDeque::from([
                Ok(OutboundHttpResponse { status: 503 }),
                Err(WebhookError::TransientTransport("closed".to_owned())),
                Ok(OutboundHttpResponse { status: 429 }),
            ])),
            requests: Mutex::new(Vec::new()),
        };
        let sender = OutboundWebhookSender::new_with_clock(
            transport,
            FakeDeadLetters::default(),
            FakeSleeper::default(),
            RetryPolicy {
                max_attempts: 3,
                base_delay: Duration::from_millis(100),
                max_delay: Duration::from_secs(1),
            },
            FakeClock {
                timestamps: Mutex::new(VecDeque::from([
                    1_750_000_000,
                    1_750_000_001,
                    1_750_000_002,
                    1_750_000_003,
                ])),
            },
        )
        .expect("sender");
        let endpoint = OutboundEndpoint {
            id: "taskflow-primary".to_owned(),
            url: Url::parse("http://127.0.0.1:18080/taskflow").expect("URL"),
            secret: secret(),
        };

        let outcome = sender
            .deliver(&endpoint, &event(), "delivery-1", true)
            .await
            .expect("terminal outcome");

        assert_eq!(outcome, DeliveryOutcome::DeadLettered { attempts: 3 });
        assert_eq!(
            *sender.sleeper.durations.lock().expect("durations"),
            vec![Duration::from_millis(100), Duration::from_millis(200)]
        );
        assert_eq!(
            *sender.dead_letters.letters.lock().expect("letters"),
            vec![DeadLetter {
                endpoint_id: "taskflow-primary".to_owned(),
                event: event(),
                attempts: 3,
                last_failure: "HTTP 429".to_owned(),
                failed_at: 1_750_000_003,
            }]
        );
        let requests = sender.transport.requests.lock().expect("requests");
        assert_eq!(requests.len(), 3);
        assert_eq!(requests[0].timestamp, "1750000000");
        assert_eq!(requests[1].timestamp, "1750000001");
        assert_eq!(requests[2].timestamp, "1750000002");
        assert_eq!(
            requests[0].nonce,
            "delivery-b8c9ee47d67a4b2bc21295c9d4e125d2d2c36bf0afb0882ce32b58d284f8ba5e-1"
        );
        assert_eq!(
            requests[1].nonce,
            "delivery-b8c9ee47d67a4b2bc21295c9d4e125d2d2c36bf0afb0882ce32b58d284f8ba5e-2"
        );
        assert_eq!(
            requests[2].nonce,
            "delivery-b8c9ee47d67a4b2bc21295c9d4e125d2d2c36bf0afb0882ce32b58d284f8ba5e-3"
        );
        assert_ne!(requests[0].signature, requests[1].signature);
        assert_ne!(requests[1].signature, requests[2].signature);
        assert_eq!(requests[0].body, requests[1].body);
        assert_eq!(requests[1].body, requests[2].body);
    }
}

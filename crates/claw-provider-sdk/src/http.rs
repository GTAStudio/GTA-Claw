//! Pure-Rust HTTP transport built on `hyper` over `rustls`.
//!
//! The transport is deliberately small: it owns TLS policy, header redaction,
//! cancellation and the mapping from wire failures to [`ProviderError`]. It
//! never interprets provider payloads.
//!
//! `hyper` is driven directly rather than through `reqwest` because every
//! rustls feature `reqwest` 0.13 exposes hard-depends on
//! `rustls-platform-verifier`, which pulls a CDLA-Permissive-2.0 crate and a
//! second `windows-sys` major line into the graph. See the private `tls`
//! module for the detail.

pub mod proxy;
mod tls;

use std::fmt::{self, Debug, Display, Formatter};
use std::future::{Future, poll_fn};
use std::io;
use std::pin::Pin;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Once};
use std::task::Poll;
use std::time::Duration;

use bytes::Bytes;
use futures_core::Stream;
use http_body_util::{BodyExt as _, Full};
use hyper::body::{Body as _, Incoming};
use hyper_util::client::legacy::Client as HyperClient;
use hyper_util::rt::TokioExecutor;
use tokio::time::Instant;
use url::Url;

pub use self::proxy::{
    DirectReason, NoProxy, ProxyDecision, ProxyDiagnostic, ProxyRules, ProxyScheme, ProxySource,
    ProxyUrl, ProxyUrlError,
};
use self::tls::{TlsConnectorService, TlsSetupError};
use crate::cancel::CancelToken;
use crate::error::{ErrorKind, Operation, ProviderError, parse_retry_after};
use crate::origin::{BoundApiKey, BoundSecret, OriginError};
use crate::secret::{REDACTED, SecretString, is_sensitive_header};

/// The largest response body [`HttpTransport::send`] will hold in memory.
///
/// Provider error documents and completion responses are kilobytes; 64 MiB is
/// far above any legitimate payload and far below what would exhaust a host.
/// A body that crosses it fails with [`ErrorKind::Protocol`] rather than
/// growing the buffer, so a hostile or broken upstream cannot turn a single
/// request into unbounded memory. Streaming responses are unaffected: they are
/// delivered chunk by chunk and never accumulate here.
pub const MAX_BUFFERED_RESPONSE_BYTES: usize = 64 * 1024 * 1024;

/// Whether an HTTP failure occurred before or after the request future was polled.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum HttpSendStage {
    /// The request future was never polled and cannot have transmitted bytes.
    NotSent,
    /// The request future was polled, so transmission cannot be ruled out.
    MayHaveTransmitted,
}

/// Provider error paired with conservative HTTP transmission metadata.
#[derive(Debug)]
pub struct HttpSendError {
    error: ProviderError,
    stage: HttpSendStage,
}

impl HttpSendError {
    const fn new(error: ProviderError, stage: HttpSendStage) -> Self {
        Self { error, stage }
    }

    /// Returns whether the request may have transmitted bytes.
    #[must_use]
    pub const fn stage(&self) -> HttpSendStage {
        self.stage
    }

    /// Returns the underlying safe provider error.
    #[must_use]
    pub const fn error(&self) -> &ProviderError {
        &self.error
    }

    /// Discards transmission metadata and returns the provider error.
    #[must_use]
    pub fn into_error(self) -> ProviderError {
        self.error
    }
}

impl Display for HttpSendError {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        Display::fmt(&self.error, formatter)
    }
}

impl std::error::Error for HttpSendError {}

/// HTTP methods used by provider APIs.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum Method {
    /// `GET`.
    Get,
    /// `POST`.
    Post,
    /// `DELETE`.
    Delete,
}

impl Method {
    /// Returns the wire representation.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Get => "GET",
            Self::Post => "POST",
            Self::Delete => "DELETE",
        }
    }
}

/// A request body.
///
/// The `Debug` rendering reports the variant and byte length only. Bodies carry
/// OAuth device codes, refresh tokens and prompt text, so printing one is a
/// disclosure regardless of which provider produced it.
#[derive(Clone, Default, Eq, PartialEq)]
pub enum Body {
    /// No body.
    #[default]
    Empty,
    /// A UTF-8 JSON document sent as `application/json`.
    Json(String),
    /// A percent-encoded form sent as `application/x-www-form-urlencoded`.
    Form(String),
}

impl Debug for Body {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        let variant = match self {
            Self::Empty => "Empty",
            Self::Json(_) => "Json",
            Self::Form(_) => "Form",
        };
        formatter
            .debug_struct("Body")
            .field("kind", &variant)
            .field("bytes", &self.as_bytes().len())
            .finish()
    }
}

impl Body {
    /// Returns the `Content-Type` this body requires, if any.
    #[must_use]
    pub const fn content_type(&self) -> Option<&'static str> {
        match self {
            Self::Empty => None,
            Self::Json(_) => Some("application/json"),
            Self::Form(_) => Some("application/x-www-form-urlencoded"),
        }
    }

    /// Returns the body bytes.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8] {
        match self {
            Self::Empty => &[],
            Self::Json(text) | Self::Form(text) => text.as_bytes(),
        }
    }
}

/// One outbound HTTP request.
///
/// No header value is ever rendered. An earlier version redacted only a fixed
/// list of well-known credential header names, which leaked the key of any
/// provider that authenticates through a header outside that list — and
/// `claw-providers`' `AuthStyle` lets a provider name any header it
/// likes. Header *names* are still shown because they are what makes a request
/// log useful, and they are not secret.
#[derive(Clone)]
pub struct HttpRequest {
    method: Method,
    url: Url,
    headers: Vec<Header>,
    body: Body,
    timeout: Option<Duration>,
    stream_idle_timeout: Option<Duration>,
}

/// A header and whether its value is credential material.
#[derive(Clone)]
struct Header {
    name: String,
    value: SecretString,
    sensitive: bool,
}

impl Debug for HttpRequest {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        let headers: Vec<(&str, &str)> = self
            .headers
            .iter()
            .map(|header| (header.name.as_str(), REDACTED))
            .collect();
        formatter
            .debug_struct("HttpRequest")
            .field("method", &self.method)
            .field("url", &self.url.as_str())
            .field("headers", &headers)
            .field("body_bytes", &self.body.as_bytes().len())
            .field("timeout", &self.timeout)
            .field("stream_idle_timeout", &self.stream_idle_timeout)
            .finish()
    }
}

impl HttpRequest {
    /// Starts a request.
    #[must_use]
    pub const fn new(method: Method, url: Url) -> Self {
        Self {
            method,
            url,
            headers: Vec::new(),
            body: Body::Empty,
            timeout: None,
            stream_idle_timeout: None,
        }
    }

    /// Adds a non-secret header.
    #[must_use]
    pub fn header(mut self, name: impl Into<String>, value: impl Into<String>) -> Self {
        let name = name.into();
        let sensitive = is_sensitive_header(&name);
        self.headers.push(Header {
            name,
            value: SecretString::new(value.into()),
            sensitive,
        });
        self
    }

    /// Adds a header whose value is credential material.
    ///
    /// The value is marked sensitive for the whole life of the request, so
    /// [`HttpRequest::is_sensitive`] reports it as such even when the header
    /// name is one no redaction list would recognise.
    ///
    /// Prefer [`HttpRequest::bearer`] or [`HttpRequest::credential_header`] for
    /// anything a provider stores: those check the credential against this
    /// request's origin, and this method cannot.
    #[must_use]
    pub fn secret_header(mut self, name: impl Into<String>, value: SecretString) -> Self {
        self.headers.push(Header {
            name: name.into(),
            value,
            sensitive: true,
        });
        self
    }

    /// Attaches a bound API key as an `Authorization: Bearer` header.
    ///
    /// # Errors
    ///
    /// Returns [`OriginError::Mismatch`] when this request's URL is not on the
    /// origin the credential is bound to. That check is the reason a
    /// configuration-controlled base URL can no longer redirect a stored key to
    /// an attacker's host: the authenticated request simply does not build.
    pub fn bearer(self, credential: &BoundApiKey) -> Result<Self, OriginError> {
        let header = credential.for_url(&self.url)?.bearer_header();
        Ok(self.secret_header("authorization", header))
    }

    /// Attaches a bound API key as `name`.
    ///
    /// # Errors
    ///
    /// Returns [`OriginError::Mismatch`] when this request's URL is not on the
    /// origin the credential is bound to.
    pub fn credential_header(
        self,
        name: impl Into<String>,
        credential: &BoundApiKey,
    ) -> Result<Self, OriginError> {
        let value = SecretString::new(credential.for_url(&self.url)?.expose());
        Ok(self.secret_header(name, value))
    }

    /// Attaches a bound secret as `name`, prefixed by `prefix`.
    ///
    /// `prefix` covers schemes such as `Bearer ` and `token `. Pass an empty
    /// string for a bare value.
    ///
    /// # Errors
    ///
    /// Returns [`OriginError::Mismatch`] when this request's URL is not on the
    /// origin the secret is bound to.
    pub fn bound_secret_header(
        self,
        name: impl Into<String>,
        prefix: &str,
        credential: &BoundSecret,
    ) -> Result<Self, OriginError> {
        let value = SecretString::new(format!(
            "{prefix}{}",
            credential.expose_for(&self.url)?.expose()
        ));
        Ok(self.secret_header(name, value))
    }

    /// Sets a non-secret header, dropping any header of the same name first.
    ///
    /// [`HttpRequest::header`] appends, which is correct for headers that may
    /// legitimately repeat. Single-valued headers such as `Accept` must not be
    /// duplicated when a caller narrows one that a builder already set, so this
    /// method replaces instead.
    #[must_use]
    pub fn replace_header(mut self, name: impl Into<String>, value: impl Into<String>) -> Self {
        let name = name.into();
        self.headers
            .retain(|header| !header.name.eq_ignore_ascii_case(&name));
        let sensitive = is_sensitive_header(&name);
        self.headers.push(Header {
            name,
            value: SecretString::new(value.into()),
            sensitive,
        });
        self
    }

    /// Sets the request body.
    #[must_use]
    pub fn body(mut self, body: Body) -> Self {
        self.body = body;
        self
    }

    /// Sets a per-request timeout.
    #[must_use]
    pub const fn timeout(mut self, timeout: Duration) -> Self {
        self.timeout = Some(timeout);
        self
    }

    /// Sets how long a streaming response may remain silent between body chunks.
    #[must_use]
    pub const fn stream_idle_timeout(mut self, timeout: Duration) -> Self {
        self.stream_idle_timeout = Some(timeout);
        self
    }

    /// Returns the method.
    #[must_use]
    pub const fn method_of(&self) -> Method {
        self.method
    }

    /// Returns the target URL.
    #[must_use]
    pub const fn url(&self) -> &Url {
        &self.url
    }

    /// Returns the header names in insertion order.
    #[must_use]
    pub fn header_names(&self) -> Vec<&str> {
        self.headers
            .iter()
            .map(|header| header.name.as_str())
            .collect()
    }

    /// Returns the values of every header named `name`, case-insensitively.
    ///
    /// Test-only: header values can be credentials, so production code has no
    /// reason to read them back out of a request.
    #[cfg(test)]
    pub(crate) fn header_values_for_test(&self, name: &str) -> Vec<&str> {
        self.headers
            .iter()
            .filter(|header| header.name.eq_ignore_ascii_case(name))
            .map(|header| header.value.expose())
            .collect()
    }

    /// Reports whether the named header carries credential material.
    ///
    /// A header counts as sensitive when it was added through
    /// [`HttpRequest::secret_header`] or when its name is on the shared
    /// sensitive-header list.
    #[must_use]
    pub fn is_sensitive(&self, name: &str) -> bool {
        self.headers
            .iter()
            .any(|header| header.name.eq_ignore_ascii_case(name) && header.sensitive)
    }

    /// Returns the body.
    #[must_use]
    pub const fn body_of(&self) -> &Body {
        &self.body
    }
}

/// A buffered HTTP response.
///
/// The `Debug` rendering never includes the body or any header value. Token
/// exchange and OAuth polling responses arrive through this type, so a derived
/// `Debug` would print a bearer token into any log that formats a response.
#[derive(Clone, Eq, PartialEq)]
pub struct HttpResponse {
    status: u16,
    headers: Vec<(String, String)>,
    body: Vec<u8>,
}

impl Debug for HttpResponse {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        let names: Vec<&str> = self.headers.iter().map(|(name, _)| name.as_str()).collect();
        formatter
            .debug_struct("HttpResponse")
            .field("status", &self.status)
            .field("header_names", &names)
            .field("body_bytes", &self.body.len())
            .finish()
    }
}

impl HttpResponse {
    /// Builds a response.
    #[must_use]
    pub const fn new(status: u16, headers: Vec<(String, String)>, body: Vec<u8>) -> Self {
        Self {
            status,
            headers,
            body,
        }
    }

    /// Returns the status code.
    #[must_use]
    pub const fn status(&self) -> u16 {
        self.status
    }

    /// Returns `true` for a 2xx status.
    #[must_use]
    pub const fn is_success(&self) -> bool {
        self.status >= 200 && self.status < 300
    }

    /// Returns the first value of a header, compared case-insensitively.
    #[must_use]
    pub fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|(candidate, _)| candidate.eq_ignore_ascii_case(name))
            .map(|(_, value)| value.as_str())
    }

    /// Returns the response body.
    #[must_use]
    pub fn body(&self) -> &[u8] {
        &self.body
    }

    /// Returns the body as UTF-8 text, replacing invalid sequences.
    #[must_use]
    pub fn text(&self) -> String {
        String::from_utf8_lossy(&self.body).into_owned()
    }
}

/// A streaming HTTP response whose body is delivered as byte chunks.
pub struct HttpStream {
    status: u16,
    headers: Vec<(String, String)>,
    chunks: Pin<Box<dyn Stream<Item = Result<Bytes, ProviderError>> + Send>>,
}

/// The `chunks` stream is omitted: it is an opaque boxed future chain with no
/// useful representation, and polling it to describe it would consume the body.
impl Debug for HttpStream {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        let names: Vec<&str> = self.headers.iter().map(|(name, _)| name.as_str()).collect();
        formatter
            .debug_struct("HttpStream")
            .field("status", &self.status)
            .field("header_names", &names)
            .finish_non_exhaustive()
    }
}

impl HttpStream {
    /// Returns the status code.
    #[must_use]
    pub const fn status(&self) -> u16 {
        self.status
    }

    /// Returns `true` for a 2xx status.
    #[must_use]
    pub const fn is_success(&self) -> bool {
        self.status >= 200 && self.status < 300
    }

    /// Returns the first value of a header, compared case-insensitively.
    #[must_use]
    pub fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|(candidate, _)| candidate.eq_ignore_ascii_case(name))
            .map(|(_, value)| value.as_str())
    }

    /// Consumes the response and returns the body chunk stream.
    #[must_use]
    pub fn into_chunks(self) -> Pin<Box<dyn Stream<Item = Result<Bytes, ProviderError>> + Send>> {
        self.chunks
    }
}

/// TLS policy applied to outbound requests.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub enum TlsPolicy {
    /// Only `https` URLs are permitted.
    #[default]
    RequireHttps,
    /// `https` everywhere, plus plaintext `http` to loopback addresses.
    ///
    /// This exists so integration tests and local inference servers such as
    /// Ollama, vLLM or LM Studio work without a certificate, and it never
    /// permits plaintext to a routable address.
    AllowLoopbackPlaintext,
}

/// Where the transport should look for an HTTP proxy.
///
/// This is the configuration; [`ProxyRules`] is what it resolves to. Only
/// `https` destinations are proxied, and only through a `CONNECT` tunnel, so a
/// proxy never sees request headers. Loopback is never proxied regardless of
/// policy.
#[derive(Clone, Default, Eq, PartialEq)]
pub enum ProxyPolicy {
    /// Read the proxy from the environment.
    ///
    /// [`proxy::PROXY_VARIABLES`] is consulted in the order the legacy Node
    /// client used — `HTTPS_PROXY`, `https_proxy`, `HTTP_PROXY`, `http_proxy`,
    /// `ALL_PROXY`, `all_proxy` — and `NO_PROXY`/`no_proxy` supplies the bypass
    /// list.
    #[default]
    FromEnvironment,
    /// Never use a proxy, whatever the environment says.
    Disabled,
    /// Use an explicitly configured proxy.
    Explicit {
        /// Proxy URL. May carry `user:password@` for Basic authentication.
        url: String,
        /// Comma-separated hosts that must bypass the proxy.
        no_proxy: Option<String>,
    },
}

impl ProxyPolicy {
    /// Resolves the policy into the rules a transport applies per connection.
    ///
    /// Resolution never fails. A proxy URL that cannot be parsed leaves rules
    /// that connect directly and carry a [`ProxyDiagnostic`] saying so, which
    /// is the legacy continue-without-proxy behavior with the URL kept out of
    /// the message.
    #[must_use]
    pub fn rules(&self) -> ProxyRules {
        match self {
            Self::FromEnvironment => ProxyRules::from_environment(),
            Self::Disabled => ProxyRules::disabled(),
            Self::Explicit { url, no_proxy } => ProxyRules::explicit(url, no_proxy.as_deref()),
        }
    }
}

impl Debug for ProxyPolicy {
    /// Redacts the proxy URL.
    ///
    /// A proxy URL routinely embeds `user:password@`, which is a credential
    /// exactly like a provider key, so the URL is never printed. `hyper-util`
    /// redacts its own `Intercept` for the same reason.
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        match self {
            Self::FromEnvironment => formatter.write_str("FromEnvironment"),
            Self::Disabled => formatter.write_str("Disabled"),
            Self::Explicit { no_proxy, .. } => formatter
                .debug_struct("Explicit")
                .field("url", &REDACTED)
                .field("has_no_proxy", &no_proxy.is_some())
                .finish(),
        }
    }
}

/// Configuration for [`HttpTransport`].
#[derive(Clone, Debug)]
pub struct TransportConfig {
    /// Value sent in the `User-Agent` header.
    pub user_agent: String,
    /// Deadline for a complete non-streaming exchange.
    pub request_timeout: Duration,
    /// Maximum silence allowed between chunks of a streaming response.
    pub stream_idle_timeout: Duration,
    /// Deadline for establishing a connection.
    pub connect_timeout: Duration,
    /// Idle pool timeout for keep-alive connections.
    pub pool_idle_timeout: Duration,
    /// TLS policy.
    pub tls_policy: TlsPolicy,
    /// Proxy policy.
    pub proxy_policy: ProxyPolicy,
}

impl Default for TransportConfig {
    fn default() -> Self {
        Self {
            user_agent: concat!("gta-claw/", env!("CARGO_PKG_VERSION")).to_owned(),
            request_timeout: Duration::from_mins(2),
            stream_idle_timeout: Duration::from_mins(2),
            connect_timeout: Duration::from_secs(15),
            pool_idle_timeout: Duration::from_mins(1),
            tls_policy: TlsPolicy::RequireHttps,
            proxy_policy: ProxyPolicy::FromEnvironment,
        }
    }
}

/// Pure-Rust HTTP client shared by every provider.
#[derive(Clone)]
pub struct HttpTransport {
    client: HyperClient<TlsConnectorService, Full<Bytes>>,
    tls_policy: TlsPolicy,
    proxy_policy: ProxyPolicy,
    proxy_rules: Arc<ProxyRules>,
    user_agent: String,
    request_timeout: Duration,
    stream_idle_timeout: Duration,
}

/// The hyper `client` is omitted: it holds the connection pool and its own
/// `Debug` would leak pool internals into provider logs.
impl Debug for HttpTransport {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("HttpTransport")
            .field("tls_policy", &self.tls_policy)
            .field("proxy_policy", &self.proxy_policy)
            .field("proxy_rules", &self.proxy_rules)
            .field("user_agent", &self.user_agent)
            .field("request_timeout", &self.request_timeout)
            .field("stream_idle_timeout", &self.stream_idle_timeout)
            .finish_non_exhaustive()
    }
}

impl HttpTransport {
    /// Builds a transport with the default configuration.
    ///
    /// # Errors
    ///
    /// Returns [`ErrorKind::Transport`] when the TLS stack cannot be
    /// initialized.
    pub fn new() -> Result<Self, ProviderError> {
        Self::with_config(&TransportConfig::default())
    }

    /// Builds a transport.
    ///
    /// # Errors
    ///
    /// Returns [`ErrorKind::Transport`] when the platform trust store yields no
    /// usable root certificate, or when the RING provider rejects the
    /// requested TLS versions.
    pub fn with_config(config: &TransportConfig) -> Result<Self, ProviderError> {
        // A proxy the operator configured and is not getting is a
        // security-relevant surprise, so it is reported rather than left to be
        // inferred from traffic. The flag is process-wide because the legacy
        // client announced this once at startup, not once per client.
        static PROXY_ANNOUNCED: Once = Once::new();

        let proxy_rules = Arc::new(config.proxy_policy.rules());
        proxy_rules.announce(&PROXY_ANNOUNCED, &mut io::stderr().lock());

        let connector = TlsConnectorService::new(config.connect_timeout, Arc::clone(&proxy_rules))
            .map_err(|error| {
                let detail = match error {
                    TlsSetupError::NoRoots => {
                        "the platform trust store contains no usable root certificate"
                    }
                    TlsSetupError::Provider => {
                        "the TLS provider rejected the required protocol versions"
                    }
                };
                ProviderError::new(ErrorKind::Transport, "http", Operation::Transport, detail)
            })?;
        let client = HyperClient::builder(TokioExecutor::new())
            .pool_idle_timeout(config.pool_idle_timeout)
            .build(connector);
        Ok(Self {
            client,
            tls_policy: config.tls_policy,
            proxy_policy: config.proxy_policy.clone(),
            proxy_rules,
            user_agent: config.user_agent.clone(),
            request_timeout: config.request_timeout,
            stream_idle_timeout: config.stream_idle_timeout,
        })
    }

    /// Returns the TLS policy in force.
    #[must_use]
    pub const fn tls_policy(&self) -> TlsPolicy {
        self.tls_policy
    }

    /// Returns the proxy policy in force.
    #[must_use]
    pub const fn proxy_policy(&self) -> &ProxyPolicy {
        &self.proxy_policy
    }

    /// Returns the resolved proxy rules.
    ///
    /// This is how a caller sees what the policy actually became:
    /// [`ProxyRules::proxy`] is the proxy in force, [`ProxyRules::diagnostics`]
    /// lists what could not be used, and [`ProxyRules::fell_back_to_direct`]
    /// reports the case where a proxy was configured and traffic is going
    /// direct anyway.
    #[must_use]
    pub fn proxy_rules(&self) -> &ProxyRules {
        &self.proxy_rules
    }

    /// Sends a request and buffers the whole response.
    ///
    /// Cancelling `cancel` drops the in-flight request, which closes the
    /// connection.
    ///
    /// The buffered body is capped at [`MAX_BUFFERED_RESPONSE_BYTES`]; the
    /// deadline bounds how long a response may take, but only this bounds how
    /// much memory a hostile or broken upstream can make the client hold.
    ///
    /// # Errors
    ///
    /// Returns a [`ProviderError`] classified by [`ErrorKind`].
    pub async fn send(
        &self,
        provider: &str,
        operation: Operation,
        request: HttpRequest,
        cancel: &CancelToken,
    ) -> Result<HttpResponse, ProviderError> {
        self.send_with_stage(provider, operation, request, cancel)
            .await
            .map_err(HttpSendError::into_error)
    }

    /// Sends a buffered request and reports whether failure may follow transmission.
    ///
    /// # Errors
    ///
    /// Returns [`HttpSendError`] with [`HttpSendStage::NotSent`] only when the
    /// request future was never polled. Any failure after its first poll is
    /// conservatively [`HttpSendStage::MayHaveTransmitted`].
    pub async fn send_with_stage(
        &self,
        provider: &str,
        operation: Operation,
        request: HttpRequest,
        cancel: &CancelToken,
    ) -> Result<HttpResponse, HttpSendError> {
        let deadline = deadline_after(request.timeout.unwrap_or(self.request_timeout));
        let response = self
            .dispatch_with_stage(provider, operation, &request, deadline, cancel)
            .await?;
        let status = response.status().as_u16();
        let headers = collect_headers(response.headers());
        // The whole exchange shares one deadline, so reading the body cannot
        // extend a request past the timeout the caller asked for.
        let body = with_deadline(
            provider,
            operation,
            deadline,
            cancel,
            "the request was cancelled while the body was being read",
            collect_bounded(provider, operation, response.into_body()),
        )
        .await
        .map_err(|error| HttpSendError::new(error, HttpSendStage::MayHaveTransmitted))?
        .map_err(|error| HttpSendError::new(error, HttpSendStage::MayHaveTransmitted))?;
        Ok(HttpResponse::new(status, headers, body))
    }

    /// Sends a request and returns the response body as a chunk stream.
    ///
    /// # Errors
    ///
    /// Returns a [`ProviderError`] classified by [`ErrorKind`].
    pub async fn send_streaming(
        &self,
        provider: &str,
        operation: Operation,
        request: HttpRequest,
        cancel: &CancelToken,
    ) -> Result<HttpStream, ProviderError> {
        // A streamed response has no total deadline, but both its handshake and
        // every silent interval are bounded so a dead upstream cannot retain a
        // connection forever.
        let deadline = deadline_after(request.timeout.unwrap_or(self.request_timeout));
        let idle_timeout = request
            .stream_idle_timeout
            .unwrap_or(self.stream_idle_timeout);
        let response = self
            .dispatch(provider, operation, &request, deadline, cancel)
            .await?;
        let status = response.status().as_u16();
        let headers = collect_headers(response.headers());
        let chunks = CancellableChunks::new(
            response.into_body(),
            cancel,
            provider,
            operation,
            idle_timeout,
        );
        Ok(HttpStream {
            status,
            headers,
            chunks: Box::pin(chunks),
        })
    }

    /// Sends the request and awaits response headers under a deadline.
    async fn dispatch(
        &self,
        provider: &str,
        operation: Operation,
        request: &HttpRequest,
        deadline: Instant,
        cancel: &CancelToken,
    ) -> Result<http::Response<Incoming>, ProviderError> {
        self.dispatch_with_stage(provider, operation, request, deadline, cancel)
            .await
            .map_err(HttpSendError::into_error)
    }

    async fn dispatch_with_stage(
        &self,
        provider: &str,
        operation: Operation,
        request: &HttpRequest,
        deadline: Instant,
        cancel: &CancelToken,
    ) -> Result<http::Response<Incoming>, HttpSendError> {
        let wire = self
            .build(provider, operation, request)
            .map_err(|error| HttpSendError::new(error, HttpSendStage::NotSent))?;
        let request_future = self.client.request(wire);
        tokio::pin!(request_future);
        let request_polled = AtomicBool::new(false);
        let result = with_deadline(
            provider,
            operation,
            deadline,
            cancel,
            "the request was cancelled before a response arrived",
            poll_fn(|context| {
                request_polled.store(true, Ordering::Release);
                request_future.as_mut().poll(context)
            }),
        )
        .await;
        let stage = if request_polled.load(Ordering::Acquire) {
            HttpSendStage::MayHaveTransmitted
        } else {
            HttpSendStage::NotSent
        };
        result
            .map_err(|error| HttpSendError::new(error, stage))?
            .map_err(|error| {
                HttpSendError::new(classify_legacy(provider, operation, &error), stage)
            })
    }

    fn build(
        &self,
        provider: &str,
        operation: Operation,
        request: &HttpRequest,
    ) -> Result<http::Request<Full<Bytes>>, ProviderError> {
        self.check_scheme(provider, operation, request.url())?;
        let invalid = |detail: &str| {
            ProviderError::new(ErrorKind::InvalidRequest, provider, operation, detail)
        };
        let uri: http::Uri = request
            .url
            .as_str()
            .parse()
            .map_err(|_| invalid("the request URL is not a valid URI"))?;
        let mut builder = http::Request::builder()
            .method(request.method.as_str())
            .uri(uri)
            .header("user-agent", self.user_agent.as_str());
        if let Some(content_type) = request.body.content_type() {
            builder = builder.header("content-type", content_type);
        }
        for header in &request.headers {
            let mut value = http::HeaderValue::from_str(header.value.expose())
                .map_err(|_| invalid("a header value contains bytes a header cannot carry"))?;
            // `hyper` will not print a sensitive value even with its most
            // verbose tracing enabled.
            value.set_sensitive(header.sensitive);
            builder = builder.header(header.name.as_str(), value);
        }
        let body = match &request.body {
            Body::Empty => Full::new(Bytes::new()),
            Body::Json(text) | Body::Form(text) => Full::new(Bytes::from(text.clone())),
        };
        builder
            .body(body)
            .map_err(|_| invalid("the request could not be assembled"))
    }

    fn check_scheme(
        &self,
        provider: &str,
        operation: Operation,
        url: &Url,
    ) -> Result<(), ProviderError> {
        if url.scheme() == "https" {
            return Ok(());
        }
        if url.scheme() == "http"
            && matches!(self.tls_policy, TlsPolicy::AllowLoopbackPlaintext)
            && is_loopback(url)
        {
            return Ok(());
        }
        Err(ProviderError::new(
            ErrorKind::InvalidRequest,
            provider,
            operation,
            "plaintext HTTP is only permitted to loopback addresses",
        ))
    }
}

/// Reads a body into memory, refusing to hold more than
/// [`MAX_BUFFERED_RESPONSE_BYTES`].
///
/// `Body::collect` grows without a ceiling, so a hostile or broken upstream
/// could stream until the process ran out of memory; the request deadline
/// bounds time, not bytes.
async fn collect_bounded(
    provider: &str,
    operation: Operation,
    mut body: Incoming,
) -> Result<Vec<u8>, ProviderError> {
    // `size_hint` is upstream-supplied, so it only sizes the first allocation.
    let hinted = usize::try_from(body.size_hint().lower()).unwrap_or(0);
    let mut buffer = Vec::with_capacity(hinted.min(MAX_BUFFERED_RESPONSE_BYTES));
    while let Some(frame) = body
        .frame()
        .await
        .transpose()
        .map_err(|error| classify_hyper(provider, operation, &error))?
    {
        // Trailers carry no body bytes.
        let Ok(chunk) = frame.into_data() else {
            continue;
        };
        if buffer.len() + chunk.len() > MAX_BUFFERED_RESPONSE_BYTES {
            return Err(ProviderError::new(
                ErrorKind::Protocol,
                provider,
                operation,
                format!(
                    "the response body exceeded the {MAX_BUFFERED_RESPONSE_BYTES} byte buffer limit"
                ),
            ));
        }
        buffer.extend_from_slice(&chunk);
    }
    Ok(buffer)
}

/// Converts a relative timeout to a representable absolute deadline.
///
/// Tokio's own [`tokio::time::sleep`] handles an overflowing duration by using
/// a deadline roughly 30 years in the future. Preserve that non-panicking
/// behavior for absolute request deadlines and rolling stream-idle resets. The
/// fallback is shortened only when a platform's [`Instant`] range requires it.
fn deadline_after(timeout: Duration) -> Instant {
    const FAR_FUTURE: Duration = Duration::from_hours(24 * 365 * 30);

    let now = Instant::now();
    if let Some(deadline) = now.checked_add(timeout) {
        return deadline;
    }

    let mut horizon = FAR_FUTURE;
    loop {
        if let Some(deadline) = now.checked_add(horizon) {
            return deadline;
        }
        if horizon.is_zero() {
            return now;
        }
        horizon /= 2;
    }
}

/// Races a future against the cancel token and a deadline.
///
/// The deadline is absolute so callers can reuse it across successive phases
/// without restoring time already spent in an earlier phase.
///
/// Cancellation wins over the deadline, and both win over the future, so a
/// cancelled request never reports a timeout it did not have. Dropping the
/// future is what actually aborts the in-flight exchange and closes the socket.
async fn with_deadline<F>(
    provider: &str,
    operation: Operation,
    deadline: Instant,
    cancel: &CancelToken,
    cancelled_detail: &str,
    future: F,
) -> Result<F::Output, ProviderError>
where
    F: Future,
{
    if cancel.is_cancelled() {
        return Err(ProviderError::new(
            ErrorKind::Cancelled,
            provider,
            operation,
            cancelled_detail,
        ));
    }
    if Instant::now() >= deadline {
        return Err(ProviderError::new(
            ErrorKind::Timeout,
            provider,
            operation,
            "the request exceeded its deadline",
        ));
    }
    tokio::select! {
        biased;
        () = cancel.cancelled() => Err(ProviderError::new(
            ErrorKind::Cancelled,
            provider,
            operation,
            cancelled_detail,
        )),
        () = tokio::time::sleep_until(deadline) => Err(ProviderError::new(
            ErrorKind::Timeout,
            provider,
            operation,
            "the request exceeded its deadline",
        )),
        output = future => Ok(output),
    }
}

/// The body half of [`HttpStream`], wired so that cancellation is observed even
/// while a poll is parked.
///
/// `poll_frame` on a silent upstream parks the task with only the connection's
/// waker registered. Polling `cancelled` on every wakeup registers this task
/// with the token as well, so [`CancelToken::cancel`] from another task wakes
/// this one instead of leaving it parked until the TCP layer notices.
///
/// The stream is fused: it yields the cancellation error at most once and then
/// ends, so a caller that keeps polling after an error terminates instead of
/// spinning on an endless tail of identical errors.
struct CancellableChunks {
    inner: Incoming,
    cancelled: Pin<Box<dyn Future<Output = ()> + Send>>,
    idle: Pin<Box<tokio::time::Sleep>>,
    idle_timeout: Duration,
    provider: String,
    operation: Operation,
    done: bool,
}

impl CancellableChunks {
    fn new(
        inner: Incoming,
        cancel: &CancelToken,
        provider: &str,
        operation: Operation,
        idle_timeout: Duration,
    ) -> Self {
        let token = cancel.clone();
        Self {
            inner,
            cancelled: Box::pin(async move { token.cancelled().await }),
            idle: Box::pin(tokio::time::sleep(idle_timeout)),
            idle_timeout,
            provider: provider.to_owned(),
            operation,
            done: false,
        }
    }
}

impl Stream for CancellableChunks {
    type Item = Result<Bytes, ProviderError>;

    fn poll_next(
        self: Pin<&mut Self>,
        context: &mut std::task::Context<'_>,
    ) -> Poll<Option<Self::Item>> {
        let this = self.get_mut();
        if this.done {
            return Poll::Ready(None);
        }
        if this.cancelled.as_mut().poll(context).is_ready() {
            this.done = true;
            return Poll::Ready(Some(Err(ProviderError::new(
                ErrorKind::Cancelled,
                &this.provider,
                this.operation,
                "the response body was cancelled",
            ))));
        }
        if this.idle.as_mut().poll(context).is_ready() {
            this.done = true;
            return Poll::Ready(Some(Err(ProviderError::new(
                ErrorKind::Timeout,
                &this.provider,
                this.operation,
                "the streaming response exceeded its idle deadline",
            ))));
        }
        loop {
            return match Pin::new(&mut this.inner).poll_frame(context) {
                Poll::Pending => Poll::Pending,
                Poll::Ready(None) => {
                    this.done = true;
                    Poll::Ready(None)
                }
                Poll::Ready(Some(Err(error))) => {
                    this.done = true;
                    Poll::Ready(Some(Err(classify_hyper(
                        &this.provider,
                        this.operation,
                        &error,
                    ))))
                }
                Poll::Ready(Some(Ok(frame))) => match frame.into_data() {
                    Ok(chunk) => {
                        this.idle.as_mut().reset(deadline_after(this.idle_timeout));
                        Poll::Ready(Some(Ok(chunk)))
                    }
                    // Trailers carry no body bytes, so keep polling rather than
                    // ending the stream early on a trailing metadata frame.
                    Err(_) => continue,
                },
            };
        }
    }
}

/// Returns `true` when a URL targets the loopback interface.
#[must_use]
pub fn is_loopback(url: &Url) -> bool {
    // Delegates so the plaintext-policy check and the never-proxy-loopback
    // check can never disagree about what "loopback" means.
    match url.host() {
        Some(url::Host::Ipv4(address)) => address.is_loopback(),
        Some(url::Host::Ipv6(address)) => address.is_loopback(),
        Some(url::Host::Domain(domain)) => proxy::is_loopback_host(domain),
        None => false,
    }
}

fn collect_headers(headers: &http::HeaderMap) -> Vec<(String, String)> {
    headers
        .iter()
        .filter_map(|(name, value)| {
            value
                .to_str()
                .ok()
                .map(|text| (name.as_str().to_owned(), text.to_owned()))
        })
        .collect()
}

/// Classifies a failure raised while establishing or driving a connection.
fn classify_legacy(
    provider: &str,
    operation: Operation,
    error: &hyper_util::client::legacy::Error,
) -> ProviderError {
    if error.is_connect() {
        return ProviderError::new(
            ErrorKind::Transport,
            provider,
            operation,
            "the connection could not be established",
        );
    }
    let mut source: Option<&(dyn std::error::Error + 'static)> = std::error::Error::source(error);
    while let Some(current) = source {
        if let Some(hyper_error) = current.downcast_ref::<hyper::Error>() {
            return classify_hyper(provider, operation, hyper_error);
        }
        source = std::error::Error::source(current);
    }
    ProviderError::new(
        ErrorKind::Transport,
        provider,
        operation,
        "the HTTP exchange failed",
    )
}

/// Classifies a failure raised by the HTTP protocol layer itself.
fn classify_hyper(provider: &str, operation: Operation, error: &hyper::Error) -> ProviderError {
    if error.is_timeout() {
        return ProviderError::new(
            ErrorKind::Timeout,
            provider,
            operation,
            "the request exceeded its deadline",
        );
    }
    if error.is_parse() || error.is_parse_status() {
        return ProviderError::new(
            ErrorKind::Protocol,
            provider,
            operation,
            "the response was not valid HTTP",
        );
    }
    if error.is_body_write_aborted() || error.is_incomplete_message() || error.is_canceled() {
        return ProviderError::new(
            ErrorKind::Transport,
            provider,
            operation,
            "the response body could not be read",
        );
    }
    if error.is_user() {
        return ProviderError::new(
            ErrorKind::InvalidRequest,
            provider,
            operation,
            "the request could not be constructed",
        );
    }
    ProviderError::new(
        ErrorKind::Transport,
        provider,
        operation,
        "the HTTP exchange failed",
    )
}

/// Builds a typed error from an unsuccessful HTTP response.
///
/// The status determines the [`ErrorKind`]; `Retry-After` is parsed when
/// present; and the body is truncated and sanitized before it is attached.
#[must_use]
pub fn error_from_response(
    provider: &str,
    operation: Operation,
    response: &HttpResponse,
    now: std::time::SystemTime,
) -> ProviderError {
    let kind = ProviderError::kind_for_status(response.status());
    // `text` allocates a lossy copy of the whole body, so decode once and let
    // both extractors read the same buffer.
    let text = response.text();
    let detail = extract_message(&text);
    let mut error =
        ProviderError::new(kind, provider, operation, detail).with_status(response.status());
    if let Some(retry_after) = response.header("retry-after")
        && let Some(delay) = parse_retry_after(retry_after, now)
    {
        error = error.with_retry_after(delay);
    }
    if let Some(code) = extract_code(&text) {
        error = error.with_upstream_code(code);
    }
    error
}

/// Extracts a human-readable message from a provider error document.
///
/// Recognizes the `{"error": {"message": ...}}` shape used by the
/// OpenAI-compatible family, the `{"error": "..."}` shape used by several
/// gateways, and Anthropic's `{"type": "error", "error": {"message": ...}}`.
/// Falls back to the raw body.
#[must_use]
pub fn extract_message(body: &str) -> String {
    let Ok(value) = serde_json::from_str::<serde_json::Value>(body) else {
        return body.to_owned();
    };
    let candidate = value
        .get("error")
        .and_then(|error| match error {
            serde_json::Value::String(text) => Some(text.clone()),
            serde_json::Value::Object(map) => map
                .get("message")
                .and_then(serde_json::Value::as_str)
                .map(str::to_owned),
            _ => None,
        })
        .or_else(|| {
            value
                .get("message")
                .and_then(serde_json::Value::as_str)
                .map(str::to_owned)
        })
        .or_else(|| {
            value
                .get("detail")
                .and_then(serde_json::Value::as_str)
                .map(str::to_owned)
        });
    candidate.unwrap_or_else(|| body.to_owned())
}

/// Extracts the provider-specific error code from an error document.
#[must_use]
pub fn extract_code(body: &str) -> Option<String> {
    let value = serde_json::from_str::<serde_json::Value>(body).ok()?;
    let error = value.get("error")?;
    error
        .get("code")
        .and_then(|code| match code {
            serde_json::Value::String(text) => Some(text.clone()),
            serde_json::Value::Number(number) => Some(number.to_string()),
            _ => None,
        })
        .or_else(|| {
            error
                .get("type")
                .and_then(serde_json::Value::as_str)
                .map(str::to_owned)
        })
}

#[cfg(test)]
mod tests {
    use std::time::UNIX_EPOCH;

    use super::*;

    fn url(text: &str) -> Url {
        Url::parse(text).expect("valid url")
    }

    #[test]
    fn requests_redact_credential_headers_in_debug_output() {
        let request = HttpRequest::new(Method::Post, url("https://api.example.test/v1/chat"))
            .header("x-request-id", "req-42")
            .secret_header(
                "authorization",
                SecretString::new("Bearer sk-live-4f9a2c7e0b1d"),
            )
            .body(Body::Json("{\"model\":\"gpt-5.6\"}".to_owned()))
            .timeout(Duration::from_secs(30));
        let rendered = format!("{request:?}");
        assert!(!rendered.contains("sk-live-4f9a2c7e0b1d"), "{rendered}");
        assert!(rendered.contains("<redacted>"), "{rendered}");
        // Even the non-secret header value stays out of the rendering. The
        // audit showed that a per-name allowlist cannot work when providers
        // choose their own header names, so every value is redacted and only
        // the names survive.
        assert!(!rendered.contains("req-42"), "{rendered}");
        assert!(rendered.contains("x-request-id"), "{rendered}");
        assert!(rendered.contains("body_bytes: 19"), "{rendered}");
        assert_eq!(
            request.header_names(),
            vec!["x-request-id", "authorization"]
        );
        assert_eq!(request.method_of(), Method::Post);
        assert_eq!(request.url().as_str(), "https://api.example.test/v1/chat");
    }

    #[test]
    fn replacing_a_header_removes_the_earlier_value_while_header_appends() {
        let appended = HttpRequest::new(Method::Post, url("https://api.example.test/v1/chat"))
            .header("accept", "application/json")
            .header("accept", "text/event-stream");
        assert_eq!(appended.header_names(), vec!["accept", "accept"]);
        assert_eq!(
            appended.header_values_for_test("accept"),
            vec!["application/json", "text/event-stream"]
        );

        let replaced = HttpRequest::new(Method::Post, url("https://api.example.test/v1/chat"))
            .header("accept", "application/json")
            .header("x-keep", "yes")
            .replace_header("Accept", "text/event-stream");
        assert_eq!(replaced.header_names(), vec!["x-keep", "Accept"]);
        assert_eq!(
            replaced.header_values_for_test("Accept"),
            vec!["text/event-stream"]
        );
        assert!(
            !replaced
                .header_values_for_test("accept")
                .contains(&"application/json")
        );
    }

    #[test]
    fn replacing_a_header_also_drops_a_secret_of_the_same_name() {
        let request = HttpRequest::new(Method::Get, url("https://api.example.test/v1/models"))
            .secret_header("authorization", SecretString::new("Bearer sk-old-value"))
            .replace_header("authorization", "Bearer public-value");
        assert_eq!(request.header_names(), vec!["authorization"]);
        let rendered = format!("{request:?}");
        assert!(!rendered.contains("sk-old-value"), "{rendered}");
        assert!(rendered.contains("<redacted>"), "{rendered}");
    }

    #[test]
    fn bodies_declare_their_content_type() {
        assert_eq!(Body::Empty.content_type(), None);
        assert_eq!(
            Body::Json("{}".to_owned()).content_type(),
            Some("application/json")
        );
        assert_eq!(
            Body::Form("a=b".to_owned()).content_type(),
            Some("application/x-www-form-urlencoded")
        );
        assert_eq!(Body::Empty.as_bytes(), b"");
        assert_eq!(Body::Json("{\"a\":1}".to_owned()).as_bytes(), b"{\"a\":1}");
    }

    #[test]
    fn methods_render_their_wire_names() {
        assert_eq!(Method::Get.as_str(), "GET");
        assert_eq!(Method::Post.as_str(), "POST");
        assert_eq!(Method::Delete.as_str(), "DELETE");
    }

    #[test]
    fn loopback_detection_covers_names_and_addresses() {
        assert!(is_loopback(&url("http://127.0.0.1:8080/v1")));
        assert!(is_loopback(&url("http://127.5.5.5/v1")));
        assert!(is_loopback(&url("http://[::1]:1234/v1")));
        assert!(is_loopback(&url("http://localhost:11434/api")));
        assert!(is_loopback(&url("http://LOCALHOST/api")));
        assert!(is_loopback(&url("http://ollama.localhost/api")));
        assert!(!is_loopback(&url("http://example.test/api")));
        assert!(!is_loopback(&url("http://10.0.0.5/api")));
        assert!(!is_loopback(&url("http://127.0.0.1.example.test/api")));
    }

    #[tokio::test]
    async fn plaintext_to_a_routable_address_is_refused() {
        let transport = HttpTransport::new().expect("transport builds");
        assert_eq!(transport.tls_policy(), TlsPolicy::RequireHttps);
        let error = transport
            .send(
                "openai",
                Operation::Complete,
                HttpRequest::new(Method::Get, url("http://api.example.test/v1/models")),
                &CancelToken::new(),
            )
            .await
            .expect_err("plaintext is refused");
        assert_eq!(error.kind(), ErrorKind::InvalidRequest);
        assert_eq!(error.provider(), "openai");
        assert_eq!(
            error.detail(),
            "plaintext HTTP is only permitted to loopback addresses"
        );
    }

    #[tokio::test]
    async fn plaintext_to_loopback_is_refused_under_the_default_policy() {
        let transport = HttpTransport::new().expect("transport builds");
        let error = transport
            .send(
                "ollama",
                Operation::Complete,
                HttpRequest::new(Method::Get, url("http://127.0.0.1:11434/api/tags")),
                &CancelToken::new(),
            )
            .await
            .expect_err("loopback plaintext needs an explicit opt-in");
        assert_eq!(error.kind(), ErrorKind::InvalidRequest);
    }

    #[tokio::test]
    async fn biased_cancellation_before_first_request_poll_is_not_sent() {
        let transport = HttpTransport::with_config(&TransportConfig {
            tls_policy: TlsPolicy::AllowLoopbackPlaintext,
            ..TransportConfig::default()
        })
        .expect("transport builds");
        let cancel = CancelToken::new();
        cancel.cancel();
        // Port 1 has no listener; reaching the socket at all would produce a
        // transport error rather than a cancellation.
        let error = transport
            .send_with_stage(
                "ollama",
                Operation::Complete,
                HttpRequest::new(Method::Get, url("http://127.0.0.1:1/api/tags"))
                    .timeout(Duration::MAX),
                &cancel,
            )
            .await
            .expect_err("cancelled");
        assert_eq!(error.stage(), HttpSendStage::NotSent);
        assert_eq!(error.error().kind(), ErrorKind::Cancelled);
        assert_eq!(
            error.error().detail(),
            "the request was cancelled before a response arrived"
        );
    }

    #[tokio::test]
    async fn a_cancelled_streaming_request_with_an_extreme_timeout_never_opens_a_socket() {
        let transport = HttpTransport::with_config(&TransportConfig {
            tls_policy: TlsPolicy::AllowLoopbackPlaintext,
            ..TransportConfig::default()
        })
        .expect("transport builds");
        let cancel = CancelToken::cancelled_token();
        let error = transport
            .send_streaming(
                "ollama",
                Operation::StreamCompletion,
                HttpRequest::new(Method::Get, url("http://127.0.0.1:1/api/chat"))
                    .timeout(Duration::MAX),
                &cancel,
            )
            .await
            .expect_err("cancelled");
        assert_eq!(error.kind(), ErrorKind::Cancelled);
        assert_eq!(error.operation(), Operation::StreamCompletion);
        assert_eq!(
            error.detail(),
            "the request was cancelled before a response arrived"
        );
    }

    #[test]
    fn an_extreme_timeout_saturates_to_a_far_future_deadline() {
        let now = Instant::now();
        let deadline = deadline_after(Duration::MAX);

        assert!(deadline > now);
    }

    #[tokio::test]
    async fn work_that_finishes_before_the_deadline_returns_its_output() {
        let output = with_deadline(
            "test",
            Operation::Complete,
            deadline_after(Duration::from_secs(1)),
            &CancelToken::new(),
            "cancelled",
            async { 42_u8 },
        )
        .await
        .expect("the future completes before the deadline");

        assert_eq!(output, 42);
    }

    #[tokio::test]
    async fn the_deadline_wins_at_the_exact_boundary() {
        let error = with_deadline(
            "test",
            Operation::Complete,
            Instant::now(),
            &CancelToken::new(),
            "cancelled",
            async { 42_u8 },
        )
        .await
        .expect_err("an already-expired deadline wins over ready work");

        assert_eq!(error.kind(), ErrorKind::Timeout);
        assert_eq!(error.detail(), "the request exceeded its deadline");
    }

    #[tokio::test]
    async fn cancellation_wins_when_the_deadline_is_also_ready() {
        let error = with_deadline(
            "test",
            Operation::Complete,
            Instant::now(),
            &CancelToken::cancelled_token(),
            "cancelled at the boundary",
            async { 42_u8 },
        )
        .await
        .expect_err("cancellation has priority over an expired deadline");

        assert_eq!(error.kind(), ErrorKind::Cancelled);
        assert_eq!(error.detail(), "cancelled at the boundary");
    }

    #[test]
    fn responses_expose_headers_case_insensitively() {
        let response = HttpResponse::new(
            201,
            vec![
                ("Content-Type".to_owned(), "application/json".to_owned()),
                ("Retry-After".to_owned(), "7".to_owned()),
            ],
            b"{\"ok\":true}".to_vec(),
        );
        assert_eq!(response.status(), 201);
        assert!(response.is_success());
        assert_eq!(response.header("content-type"), Some("application/json"));
        assert_eq!(response.header("RETRY-AFTER"), Some("7"));
        assert_eq!(response.header("x-missing"), None);
        assert_eq!(response.body(), b"{\"ok\":true}");
        assert_eq!(response.text(), "{\"ok\":true}");
        assert!(!HttpResponse::new(500, Vec::new(), Vec::new()).is_success());
    }

    #[test]
    fn error_messages_are_extracted_from_each_known_envelope() {
        assert_eq!(
            extract_message("{\"error\":{\"message\":\"Incorrect API key provided\"}}"),
            "Incorrect API key provided"
        );
        assert_eq!(
            extract_message("{\"error\":\"model not found\"}"),
            "model not found"
        );
        assert_eq!(
            extract_message(
                "{\"type\":\"error\",\"error\":{\"type\":\"rate_limit_error\",\"message\":\"slow down\"}}"
            ),
            "slow down"
        );
        assert_eq!(extract_message("{\"message\":\"nope\"}"), "nope");
        assert_eq!(extract_message("{\"detail\":\"nope\"}"), "nope");
        assert_eq!(extract_message("plain text"), "plain text");
        assert_eq!(extract_message("{\"unknown\":1}"), "{\"unknown\":1}");
    }

    #[test]
    fn error_codes_are_extracted_from_each_known_envelope() {
        assert_eq!(
            extract_code("{\"error\":{\"code\":\"invalid_api_key\"}}"),
            Some("invalid_api_key".to_owned())
        );
        assert_eq!(
            extract_code("{\"error\":{\"code\":429}}"),
            Some("429".to_owned())
        );
        assert_eq!(
            extract_code("{\"error\":{\"type\":\"rate_limit_error\"}}"),
            Some("rate_limit_error".to_owned())
        );
        assert_eq!(extract_code("{\"error\":{}}"), None);
        assert_eq!(extract_code("not json"), None);
    }

    #[test]
    fn http_errors_carry_status_code_and_retry_after() {
        let response = HttpResponse::new(
            429,
            vec![("retry-after".to_owned(), "12".to_owned())],
            b"{\"error\":{\"message\":\"Rate limit reached\",\"code\":\"rate_limit_exceeded\"}}"
                .to_vec(),
        );
        let error = error_from_response("openai", Operation::Complete, &response, UNIX_EPOCH);
        assert_eq!(error.kind(), ErrorKind::RateLimit);
        assert_eq!(error.status(), Some(429));
        assert_eq!(error.detail(), "Rate limit reached");
        assert_eq!(error.upstream_code(), Some("rate_limit_exceeded"));
        assert_eq!(error.retry_after(), Some(Duration::from_secs(12)));
        assert!(error.is_retryable());
    }

    #[test]
    fn authentication_failures_are_not_retryable() {
        let response = HttpResponse::new(
            401,
            Vec::new(),
            b"{\"error\":{\"message\":\"Incorrect API key\",\"code\":\"invalid_api_key\"}}"
                .to_vec(),
        );
        let error = error_from_response("openai", Operation::Complete, &response, UNIX_EPOCH);
        assert_eq!(error.kind(), ErrorKind::Authentication);
        assert_eq!(error.status(), Some(401));
        assert!(!error.is_retryable());
        assert_eq!(error.retry_after(), None);
    }

    #[test]
    fn transport_config_defaults_are_conservative() {
        let config = TransportConfig::default();
        assert_eq!(config.tls_policy, TlsPolicy::RequireHttps);
        assert_eq!(config.request_timeout, Duration::from_mins(2));
        assert_eq!(config.stream_idle_timeout, Duration::from_mins(2));
        assert_eq!(config.connect_timeout, Duration::from_secs(15));
        assert_eq!(config.pool_idle_timeout, Duration::from_mins(1));
        assert!(config.user_agent.starts_with("gta-claw/"));
    }
}

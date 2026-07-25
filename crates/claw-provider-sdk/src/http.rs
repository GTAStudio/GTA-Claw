//! Pure-Rust HTTP transport built on `hyper` over `rustls`.
//!
//! The transport is deliberately small: it owns TLS policy, header redaction,
//! cancellation and the mapping from wire failures to [`ProviderError`]. It
//! never interprets provider payloads.
//!
//! `hyper` is driven directly rather than through `reqwest` because every
//! rustls feature `reqwest` 0.13 exposes hard-depends on
//! `rustls-platform-verifier`, which pulls a CDLA-Permissive-2.0 crate and a
//! second `windows-sys` major line into the graph. See [`tls`] for the detail.

mod tls;

use std::fmt::{self, Debug, Formatter};
use std::future::Future;
use std::pin::Pin;
use std::task::Poll;
use std::time::Duration;

use bytes::Bytes;
use futures_core::Stream;
use http_body_util::{BodyExt as _, Full};
use hyper::body::{Body as _, Incoming};
use hyper_util::client::legacy::Client as HyperClient;
use hyper_util::rt::TokioExecutor;
use url::Url;

use self::tls::{TlsConnectorService, TlsSetupError};
use crate::cancel::CancelToken;
use crate::error::{ErrorKind, Operation, ProviderError, parse_retry_after};
use crate::origin::{BoundApiKey, BoundSecret, OriginError};
use crate::secret::{REDACTED, SecretString, is_sensitive_header};

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
    pub fn as_bytes(&self) -> &[u8] {
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
/// [`AuthStyle`](crate::model::AuthStyle) lets a provider name any header it
/// likes. Header *names* are still shown because they are what makes a request
/// log useful, and they are not secret.
#[derive(Clone)]
pub struct HttpRequest {
    method: Method,
    url: Url,
    headers: Vec<Header>,
    body: Body,
    timeout: Option<Duration>,
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
            .finish()
    }
}

impl HttpRequest {
    /// Starts a request.
    #[must_use]
    pub fn new(method: Method, url: Url) -> Self {
        Self {
            method,
            url,
            headers: Vec::new(),
            body: Body::Empty,
            timeout: None,
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
    pub fn new(status: u16, headers: Vec<(String, String)>, body: Vec<u8>) -> Self {
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

impl Debug for HttpStream {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        let names: Vec<&str> = self.headers.iter().map(|(name, _)| name.as_str()).collect();
        formatter
            .debug_struct("HttpStream")
            .field("status", &self.status)
            .field("header_names", &names)
            .finish()
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

/// Configuration for [`HttpTransport`].
#[derive(Clone, Debug)]
pub struct TransportConfig {
    /// Value sent in the `User-Agent` header.
    pub user_agent: String,
    /// Deadline for a complete non-streaming exchange.
    pub request_timeout: Duration,
    /// Deadline for establishing a connection.
    pub connect_timeout: Duration,
    /// Idle pool timeout for keep-alive connections.
    pub pool_idle_timeout: Duration,
    /// TLS policy.
    pub tls_policy: TlsPolicy,
}

impl Default for TransportConfig {
    fn default() -> Self {
        Self {
            user_agent: concat!("gta-claw/", env!("CARGO_PKG_VERSION")).to_owned(),
            request_timeout: Duration::from_secs(120),
            connect_timeout: Duration::from_secs(15),
            pool_idle_timeout: Duration::from_secs(60),
            tls_policy: TlsPolicy::RequireHttps,
        }
    }
}

/// Pure-Rust HTTP client shared by every provider.
#[derive(Clone)]
pub struct HttpTransport {
    client: HyperClient<TlsConnectorService, Full<Bytes>>,
    tls_policy: TlsPolicy,
    user_agent: String,
    request_timeout: Duration,
}

impl Debug for HttpTransport {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("HttpTransport")
            .field("tls_policy", &self.tls_policy)
            .field("user_agent", &self.user_agent)
            .field("request_timeout", &self.request_timeout)
            .finish()
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
        let connector = TlsConnectorService::new(config.connect_timeout).map_err(|error| {
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
            user_agent: config.user_agent.clone(),
            request_timeout: config.request_timeout,
        })
    }

    /// Returns the TLS policy in force.
    #[must_use]
    pub const fn tls_policy(&self) -> TlsPolicy {
        self.tls_policy
    }

    /// Sends a request and buffers the whole response.
    ///
    /// Cancelling `cancel` drops the in-flight request, which closes the
    /// connection.
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
        let deadline = request.timeout.unwrap_or(self.request_timeout);
        let response = self
            .dispatch(provider, operation, &request, deadline, cancel)
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
            response.into_body().collect(),
        )
        .await?
        .map_err(|error| classify_hyper(provider, operation, &error))?;
        Ok(HttpResponse::new(status, headers, body.to_bytes().to_vec()))
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
        // A streamed response has no overall deadline: the point of streaming
        // is that the body arrives over an open-ended window. The headers still
        // must arrive within one.
        let deadline = request.timeout.unwrap_or(self.request_timeout);
        let response = self
            .dispatch(provider, operation, &request, deadline, cancel)
            .await?;
        let status = response.status().as_u16();
        let headers = collect_headers(response.headers());
        let chunks = CancellableChunks {
            inner: response.into_body(),
            cancel: cancel.clone(),
            provider: provider.to_owned(),
            operation,
        };
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
        deadline: Duration,
        cancel: &CancelToken,
    ) -> Result<http::Response<Incoming>, ProviderError> {
        let wire = self.build(provider, operation, request)?;
        with_deadline(
            provider,
            operation,
            deadline,
            cancel,
            "the request was cancelled before a response arrived",
            self.client.request(wire),
        )
        .await?
        .map_err(|error| classify_legacy(provider, operation, &error))
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

/// Races a future against the cancel token and a deadline.
///
/// Cancellation wins over the deadline, and both win over the future, so a
/// cancelled request never reports a timeout it did not have. Dropping the
/// future is what actually aborts the in-flight exchange and closes the socket.
async fn with_deadline<F>(
    provider: &str,
    operation: Operation,
    deadline: Duration,
    cancel: &CancelToken,
    cancelled_detail: &str,
    future: F,
) -> Result<F::Output, ProviderError>
where
    F: Future,
{
    tokio::select! {
        biased;
        () = cancel.cancelled() => Err(ProviderError::new(
            ErrorKind::Cancelled,
            provider,
            operation,
            cancelled_detail,
        )),
        () = tokio::time::sleep(deadline) => Err(ProviderError::new(
            ErrorKind::Timeout,
            provider,
            operation,
            "the request exceeded its deadline",
        )),
        output = future => Ok(output),
    }
}

struct CancellableChunks {
    inner: Incoming,
    cancel: CancelToken,
    provider: String,
    operation: Operation,
}

impl Stream for CancellableChunks {
    type Item = Result<Bytes, ProviderError>;

    fn poll_next(
        self: Pin<&mut Self>,
        context: &mut std::task::Context<'_>,
    ) -> Poll<Option<Self::Item>> {
        let this = self.get_mut();
        if this.cancel.is_cancelled() {
            return Poll::Ready(Some(Err(ProviderError::new(
                ErrorKind::Cancelled,
                &this.provider,
                this.operation,
                "the response body was cancelled",
            ))));
        }
        loop {
            return match Pin::new(&mut this.inner).poll_frame(context) {
                Poll::Pending => Poll::Pending,
                Poll::Ready(None) => Poll::Ready(None),
                Poll::Ready(Some(Err(error))) => Poll::Ready(Some(Err(classify_hyper(
                    &this.provider,
                    this.operation,
                    &error,
                )))),
                Poll::Ready(Some(Ok(frame))) => match frame.into_data() {
                    Ok(chunk) => Poll::Ready(Some(Ok(chunk))),
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
    match url.host() {
        Some(url::Host::Ipv4(address)) => address.is_loopback(),
        Some(url::Host::Ipv6(address)) => address.is_loopback(),
        Some(url::Host::Domain(domain)) => {
            domain.eq_ignore_ascii_case("localhost")
                || domain.to_ascii_lowercase().ends_with(".localhost")
        }
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
    let detail = extract_message(&response.text());
    let mut error =
        ProviderError::new(kind, provider, operation, detail).with_status(response.status());
    if let Some(retry_after) = response.header("retry-after")
        && let Some(delay) = parse_retry_after(retry_after, now)
    {
        error = error.with_retry_after(delay);
    }
    if let Some(code) = extract_code(&response.text()) {
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
    async fn a_cancelled_token_short_circuits_before_any_socket_is_opened() {
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
            .send(
                "ollama",
                Operation::Complete,
                HttpRequest::new(Method::Get, url("http://127.0.0.1:1/api/tags")),
                &cancel,
            )
            .await
            .expect_err("cancelled");
        assert_eq!(error.kind(), ErrorKind::Cancelled);
        assert_eq!(
            error.detail(),
            "the request was cancelled before a response arrived"
        );
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
        assert_eq!(config.request_timeout, Duration::from_secs(120));
        assert_eq!(config.connect_timeout, Duration::from_secs(15));
        assert_eq!(config.pool_idle_timeout, Duration::from_secs(60));
        assert!(config.user_agent.starts_with("gta-claw/"));
    }
}

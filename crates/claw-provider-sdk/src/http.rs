//! Pure-Rust HTTP transport built on `reqwest` over `rustls`.
//!
//! The transport is deliberately small: it owns TLS policy, header redaction,
//! cancellation and the mapping from wire failures to [`ProviderError`]. It
//! never interprets provider payloads.

use std::fmt::{self, Debug, Formatter};
use std::pin::Pin;
use std::time::Duration;

use bytes::Bytes;
use futures_core::Stream;
use futures_util::StreamExt;
use url::Url;

use crate::cancel::CancelToken;
use crate::error::{ErrorKind, Operation, ProviderError, parse_retry_after};
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
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub enum Body {
    /// No body.
    #[default]
    Empty,
    /// A UTF-8 JSON document sent as `application/json`.
    Json(String),
    /// A percent-encoded form sent as `application/x-www-form-urlencoded`.
    Form(String),
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
/// Header values that name a credential are stored as [`SecretString`], so the
/// `Debug` rendering of a request can never leak one.
#[derive(Clone)]
pub struct HttpRequest {
    method: Method,
    url: Url,
    headers: Vec<(String, SecretString)>,
    body: Body,
    timeout: Option<Duration>,
}

impl Debug for HttpRequest {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        let headers: Vec<(&str, &str)> = self
            .headers
            .iter()
            .map(|(name, value)| {
                let rendered = if is_sensitive_header(name) {
                    REDACTED
                } else {
                    value.expose()
                };
                (name.as_str(), rendered)
            })
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
        self.headers
            .push((name.into(), SecretString::new(value.into())));
        self
    }

    /// Adds a header whose value is credential material.
    #[must_use]
    pub fn secret_header(mut self, name: impl Into<String>, value: SecretString) -> Self {
        self.headers.push((name.into(), value));
        self
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
            .retain(|(existing, _)| !existing.eq_ignore_ascii_case(&name));
        self.headers.push((name, SecretString::new(value.into())));
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
        self.headers.iter().map(|(name, _)| name.as_str()).collect()
    }

    /// Returns the body.
    #[must_use]
    pub const fn body_of(&self) -> &Body {
        &self.body
    }
}

/// A buffered HTTP response.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct HttpResponse {
    status: u16,
    headers: Vec<(String, String)>,
    body: Vec<u8>,
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
        formatter
            .debug_struct("HttpStream")
            .field("status", &self.status)
            .field("headers", &self.headers)
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
#[derive(Clone, Debug)]
pub struct HttpTransport {
    client: reqwest::Client,
    tls_policy: TlsPolicy,
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
    /// Returns [`ErrorKind::Transport`] when the TLS stack cannot be
    /// initialized.
    pub fn with_config(config: &TransportConfig) -> Result<Self, ProviderError> {
        let client = reqwest::Client::builder()
            .user_agent(config.user_agent.clone())
            .timeout(config.request_timeout)
            .connect_timeout(config.connect_timeout)
            .pool_idle_timeout(config.pool_idle_timeout)
            .https_only(matches!(config.tls_policy, TlsPolicy::RequireHttps))
            .use_rustls_tls()
            .build()
            .map_err(|_| {
                ProviderError::new(
                    ErrorKind::Transport,
                    "http",
                    Operation::Transport,
                    "the TLS client could not be initialized",
                )
            })?;
        Ok(Self {
            client,
            tls_policy: config.tls_policy,
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
        let builder = self.build(provider, operation, &request)?;
        let response = tokio::select! {
            biased;
            () = cancel.cancelled() => {
                return Err(ProviderError::new(
                    ErrorKind::Cancelled,
                    provider,
                    operation,
                    "the request was cancelled before a response arrived",
                ));
            }
            result = builder.send() => result.map_err(|error| classify(provider, operation, &error))?,
        };

        let status = response.status().as_u16();
        let headers = collect_headers(response.headers());
        let body = tokio::select! {
            biased;
            () = cancel.cancelled() => {
                return Err(ProviderError::new(
                    ErrorKind::Cancelled,
                    provider,
                    operation,
                    "the request was cancelled while the body was being read",
                ));
            }
            result = response.bytes() => result.map_err(|error| classify(provider, operation, &error))?,
        };
        Ok(HttpResponse::new(status, headers, body.to_vec()))
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
        let builder = self.build(provider, operation, &request)?;
        let response = tokio::select! {
            biased;
            () = cancel.cancelled() => {
                return Err(ProviderError::new(
                    ErrorKind::Cancelled,
                    provider,
                    operation,
                    "the request was cancelled before a response arrived",
                ));
            }
            result = builder.send() => result.map_err(|error| classify(provider, operation, &error))?,
        };

        let status = response.status().as_u16();
        let headers = collect_headers(response.headers());
        let stream_provider = provider.to_owned();
        let chunk_provider = provider.to_owned();
        let cancel = cancel.clone();
        let chunks = response
            .bytes_stream()
            .map(move |chunk| chunk.map_err(|error| classify(&chunk_provider, operation, &error)));
        let chunks = CancellableChunks {
            inner: Box::pin(chunks),
            cancel,
            provider: stream_provider,
            operation,
        };
        Ok(HttpStream {
            status,
            headers,
            chunks: Box::pin(chunks),
        })
    }

    fn build(
        &self,
        provider: &str,
        operation: Operation,
        request: &HttpRequest,
    ) -> Result<reqwest::RequestBuilder, ProviderError> {
        self.check_scheme(provider, operation, request.url())?;
        let method = match request.method {
            Method::Get => reqwest::Method::GET,
            Method::Post => reqwest::Method::POST,
            Method::Delete => reqwest::Method::DELETE,
        };
        let mut builder = self.client.request(method, request.url.clone());
        if let Some(content_type) = request.body.content_type() {
            builder = builder.header("content-type", content_type);
        }
        for (name, value) in &request.headers {
            builder = builder.header(name.as_str(), value.expose());
        }
        if let Some(timeout) = request.timeout {
            builder = builder.timeout(timeout);
        }
        match &request.body {
            Body::Empty => {}
            Body::Json(text) | Body::Form(text) => {
                builder = builder.body(text.clone().into_bytes());
            }
        }
        Ok(builder)
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

struct CancellableChunks {
    inner: Pin<Box<dyn Stream<Item = Result<Bytes, ProviderError>> + Send>>,
    cancel: CancelToken,
    provider: String,
    operation: Operation,
}

impl Stream for CancellableChunks {
    type Item = Result<Bytes, ProviderError>;

    fn poll_next(
        self: Pin<&mut Self>,
        context: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Option<Self::Item>> {
        let this = self.get_mut();
        if this.cancel.is_cancelled() {
            return std::task::Poll::Ready(Some(Err(ProviderError::new(
                ErrorKind::Cancelled,
                &this.provider,
                this.operation,
                "the response body was cancelled",
            ))));
        }
        this.inner.as_mut().poll_next(context)
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

fn collect_headers(headers: &reqwest::header::HeaderMap) -> Vec<(String, String)> {
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

fn classify(provider: &str, operation: Operation, error: &reqwest::Error) -> ProviderError {
    if error.is_timeout() {
        return ProviderError::new(
            ErrorKind::Timeout,
            provider,
            operation,
            "the request exceeded its deadline",
        );
    }
    if error.is_connect() {
        return ProviderError::new(
            ErrorKind::Transport,
            provider,
            operation,
            "the connection could not be established",
        );
    }
    if error.is_body() || error.is_decode() {
        return ProviderError::new(
            ErrorKind::Transport,
            provider,
            operation,
            "the response body could not be read",
        );
    }
    if error.is_builder() || error.is_request() {
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
        assert!(rendered.contains("req-42"), "{rendered}");
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
        let rendered = format!("{appended:?}");
        assert!(rendered.contains("application/json"), "{rendered}");
        assert!(rendered.contains("text/event-stream"), "{rendered}");

        let replaced = HttpRequest::new(Method::Post, url("https://api.example.test/v1/chat"))
            .header("accept", "application/json")
            .header("x-keep", "yes")
            .replace_header("Accept", "text/event-stream");
        assert_eq!(replaced.header_names(), vec!["x-keep", "Accept"]);
        let rendered = format!("{replaced:?}");
        assert!(!rendered.contains("application/json"), "{rendered}");
        assert!(rendered.contains("text/event-stream"), "{rendered}");
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

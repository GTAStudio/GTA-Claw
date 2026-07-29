use std::{
    borrow::Cow,
    collections::HashMap,
    error::Error as StdError,
    future::Future,
    io,
    pin::Pin,
    sync::Arc,
    task::{Context, Poll},
    time::Duration,
};

use bytes::Bytes;
use futures_util::{Stream, StreamExt, stream::BoxStream};
use http::{
    HeaderMap, HeaderName, HeaderValue, Method, Request, StatusCode, Uri,
    header::{
        ACCEPT, AUTHORIZATION, CONTENT_LENGTH, CONTENT_TYPE, PROXY_AUTHORIZATION, WWW_AUTHENTICATE,
    },
};
use http_body_util::{BodyExt, Full};
use hyper::body::Incoming;
use hyper_util::{
    client::legacy::{
        Client,
        connect::{Connected, Connection, HttpConnector},
    },
    client::proxy::matcher::Matcher,
    rt::{TokioExecutor, TokioIo, TokioTimer},
};
use rmcp::{
    model::{ClientJsonRpcMessage, JsonRpcMessage, ServerJsonRpcMessage},
    transport::streamable_http_client::{
        AuthRequiredError, InsufficientScopeError, SseError, StreamableHttpClient,
        StreamableHttpError, StreamableHttpPostResponse,
    },
};
use rustls::{ClientConfig, RootCertStore, pki_types::ServerName};
use sse_stream::{Sse, SseStream};
use thiserror::Error;
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf},
    time::{Instant, timeout_at},
};
use tokio_rustls::TlsConnector;
use tower_service::Service;
use url::Url;
use zeroize::Zeroize;

use crate::is_literal_loopback_host;

const DEFAULT_BODY_LIMIT: usize = 8 * 1024 * 1024;
const MAX_SSE_LINE_BYTES: usize = 64 * 1024;
const MAX_SSE_EVENT_BYTES: usize = DEFAULT_BODY_LIMIT;
const MAX_SSE_STREAM_BYTES: usize = 64 * 1024 * 1024;
const EVENT_STREAM_MIME_TYPE: &str = "text/event-stream";
const JSON_MIME_TYPE: &str = "application/json";
const HEADER_SESSION_ID: &str = "mcp-session-id";

type BoxError = Box<dyn StdError + Send + Sync>;
type HyperClient = Client<HttpsConnector, Full<Bytes>>;

trait IoStream: AsyncRead + AsyncWrite + Send + Unpin {}
impl<T> IoStream for T where T: AsyncRead + AsyncWrite + Send + Unpin {}

/// Failure returned by the native-root ring-Rustls HTTP client.
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum HttpClientError {
    /// The ring-backed Rustls client configuration was invalid.
    #[error("TLS client configuration failed")]
    TlsConfig,
    /// A request URL could not be represented as an HTTP URI.
    #[error("HTTP request URI is invalid")]
    InvalidUri,
    /// An HTTP request could not be constructed.
    #[error("HTTP request construction failed")]
    Request(#[source] http::Error),
    /// The TCP, TLS, or HTTP exchange failed.
    #[error("HTTP transport failed")]
    Transport(#[source] hyper_util::client::legacy::Error),
    /// The request exceeded its configured header deadline.
    #[error("HTTP request timed out")]
    Timeout,
    /// Reading a response body failed.
    #[error("HTTP response body failed")]
    Body(#[source] hyper::Error),
    /// A buffered response exceeded the configured bound.
    #[error("HTTP response body exceeded {0} bytes")]
    BodyTooLarge(usize),
}

#[derive(Clone)]
pub(crate) struct HttpClient {
    inner: HyperClient,
    proxy_matcher: Arc<Matcher>,
    request_timeout: Duration,
}

impl HttpClient {
    pub(crate) fn new(request_timeout: Duration) -> Result<Self, HttpClientError> {
        let proxy_matcher = Arc::new(Matcher::from_env());
        let connector = HttpsConnector::new(request_timeout, Arc::clone(&proxy_matcher))?;
        Ok(Self::with_connector(
            request_timeout,
            connector,
            proxy_matcher,
        ))
    }

    fn with_connector(
        request_timeout: Duration,
        connector: HttpsConnector,
        proxy_matcher: Arc<Matcher>,
    ) -> Self {
        let inner = Client::builder(TokioExecutor::new())
            .pool_timer(TokioTimer::new())
            .pool_max_idle_per_host(0)
            .build(connector);
        Self {
            inner,
            proxy_matcher,
            request_timeout,
        }
    }

    #[cfg(test)]
    fn with_roots(
        request_timeout: Duration,
        roots: RootCertStore,
    ) -> Result<Self, HttpClientError> {
        let proxy_matcher = Arc::new(Matcher::builder().build());
        Self::with_roots_and_proxy(request_timeout, roots, proxy_matcher)
    }

    #[cfg(test)]
    fn with_roots_and_proxy(
        request_timeout: Duration,
        roots: RootCertStore,
        proxy_matcher: Arc<Matcher>,
    ) -> Result<Self, HttpClientError> {
        let connector =
            HttpsConnector::with_roots(request_timeout, roots, Arc::clone(&proxy_matcher))?;
        Ok(Self::with_connector(
            request_timeout,
            connector,
            proxy_matcher,
        ))
    }

    pub(crate) async fn request(
        &self,
        method: Method,
        url: &Url,
        mut headers: HeaderMap,
        body: Vec<u8>,
    ) -> Result<HttpResponse, HttpClientError> {
        if !matches!(url.scheme(), "http" | "https") {
            return Err(HttpClientError::InvalidUri);
        }
        let uri: Uri = url
            .as_str()
            .parse()
            .map_err(|_| HttpClientError::InvalidUri)?;
        if url.scheme() == "http"
            && !url.host_str().is_some_and(is_literal_loopback_host)
            && let Some(proxy) = self.proxy_matcher.intercept(&uri)
            && let Some(value) = proxy.basic_auth()
        {
            headers.insert(PROXY_AUTHORIZATION, value.clone());
        }
        let mut request = Request::builder()
            .method(method)
            .uri(uri)
            .body(Full::new(Bytes::from(body)))
            .map_err(HttpClientError::Request)?;
        *request.headers_mut() = headers;
        let deadline = Instant::now() + self.request_timeout;
        let response = timeout_at(deadline, self.inner.request(request))
            .await
            .map_err(|_| HttpClientError::Timeout)?
            .map_err(HttpClientError::Transport)?;
        let (parts, body) = response.into_parts();
        Ok(HttpResponse {
            status: parts.status,
            headers: parts.headers,
            body,
            deadline,
        })
    }
}

pub(crate) struct HttpResponse {
    pub(crate) status: StatusCode,
    pub(crate) headers: HeaderMap,
    body: Incoming,
    deadline: Instant,
}

#[derive(Clone, Copy, Debug)]
struct SseBounds {
    line: usize,
    event: usize,
    stream: usize,
}

impl Default for SseBounds {
    fn default() -> Self {
        Self {
            line: MAX_SSE_LINE_BYTES,
            event: MAX_SSE_EVENT_BYTES,
            stream: MAX_SSE_STREAM_BYTES,
        }
    }
}

#[derive(Debug, Error, Eq, PartialEq)]
enum SseLimitError {
    #[error("SSE line exceeded {limit} bytes")]
    Line { limit: usize },
    #[error("SSE event exceeded {limit} bytes")]
    Event { limit: usize },
    #[error("SSE stream exceeded {limit} bytes")]
    Stream { limit: usize },
}

#[derive(Debug)]
struct SseBudget {
    bounds: SseBounds,
    line_bytes: usize,
    event_bytes: usize,
    stream_bytes: usize,
    skip_lf_after_cr: bool,
}

impl SseBudget {
    const fn new(bounds: SseBounds) -> Self {
        Self {
            bounds,
            line_bytes: 0,
            event_bytes: 0,
            stream_bytes: 0,
            skip_lf_after_cr: false,
        }
    }

    fn observe(&mut self, chunk: &[u8]) -> Result<(), SseLimitError> {
        if chunk.len() > self.bounds.stream.saturating_sub(self.stream_bytes) {
            return Err(SseLimitError::Stream {
                limit: self.bounds.stream,
            });
        }
        self.stream_bytes += chunk.len();

        for &byte in chunk {
            if self.skip_lf_after_cr {
                self.skip_lf_after_cr = false;
                if byte == b'\n' {
                    continue;
                }
            }

            self.event_bytes += 1;
            if self.event_bytes > self.bounds.event {
                return Err(SseLimitError::Event {
                    limit: self.bounds.event,
                });
            }

            match byte {
                b'\r' => {
                    self.finish_line();
                    self.skip_lf_after_cr = true;
                }
                b'\n' => self.finish_line(),
                _ => {
                    self.line_bytes += 1;
                    if self.line_bytes > self.bounds.line {
                        return Err(SseLimitError::Line {
                            limit: self.bounds.line,
                        });
                    }
                }
            }
        }
        Ok(())
    }

    const fn finish_line(&mut self) {
        let event_finished = self.line_bytes == 0;
        self.line_bytes = 0;
        if event_finished {
            self.event_bytes = 0;
        }
    }
}

#[derive(Debug, Error)]
enum BoundedSseStreamError<E>
where
    E: StdError + Send + Sync + 'static,
{
    #[error("SSE response body failed: {0}")]
    Body(#[source] E),
    #[error(transparent)]
    Limit(#[from] SseLimitError),
}

struct BoundedSseBytesStream<E> {
    inner: BoxStream<'static, Result<Bytes, E>>,
    budget: SseBudget,
    done: bool,
}

impl<E> BoundedSseBytesStream<E>
where
    E: StdError + Send + Sync + 'static,
{
    fn new(
        stream: impl Stream<Item = Result<Bytes, E>> + Send + 'static,
        bounds: SseBounds,
    ) -> Self {
        Self {
            inner: stream.boxed(),
            budget: SseBudget::new(bounds),
            done: false,
        }
    }
}

impl<E> Unpin for BoundedSseBytesStream<E> {}

impl<E> Stream for BoundedSseBytesStream<E>
where
    E: StdError + Send + Sync + 'static,
{
    type Item = Result<Bytes, BoundedSseStreamError<E>>;

    fn poll_next(self: Pin<&mut Self>, context: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        let this = self.get_mut();
        if this.done {
            return Poll::Ready(None);
        }
        match this.inner.as_mut().poll_next(context) {
            Poll::Ready(Some(Ok(chunk))) => match this.budget.observe(&chunk) {
                Ok(()) => Poll::Ready(Some(Ok(chunk))),
                Err(error) => {
                    this.done = true;
                    Poll::Ready(Some(Err(error.into())))
                }
            },
            Poll::Ready(Some(Err(error))) => {
                this.done = true;
                Poll::Ready(Some(Err(BoundedSseStreamError::Body(error))))
            }
            Poll::Ready(None) => {
                this.done = true;
                Poll::Ready(None)
            }
            Poll::Pending => Poll::Pending,
        }
    }
}

fn bounded_sse_stream<E>(
    stream: impl Stream<Item = Result<Bytes, E>> + Send + 'static,
    bounds: SseBounds,
) -> BoxStream<'static, Result<Sse, SseError>>
where
    E: StdError + Send + Sync + 'static,
{
    SseStream::from_bytes_stream(BoundedSseBytesStream::new(stream, bounds)).boxed()
}

impl HttpResponse {
    pub(crate) async fn bytes(self, limit: usize) -> Result<Vec<u8>, HttpClientError> {
        let mut body = self.body;
        timeout_at(self.deadline, async move {
            let mut output = Vec::new();
            while let Some(frame) = body.frame().await {
                let frame = frame.map_err(HttpClientError::Body)?;
                if let Some(data) = frame.data_ref() {
                    if data.len() > limit.saturating_sub(output.len()) {
                        return Err(HttpClientError::BodyTooLarge(limit));
                    }
                    output.extend_from_slice(data);
                }
            }
            Ok(output)
        })
        .await
        .map_err(|_| HttpClientError::Timeout)?
    }

    pub(crate) async fn json<T: serde::de::DeserializeOwned>(
        self,
    ) -> Result<T, crate::error::McpError> {
        let bytes = self.bytes(DEFAULT_BODY_LIMIT).await?;
        Ok(serde_json::from_slice(&bytes)?)
    }

    pub(crate) async fn buffered(
        self,
    ) -> Result<(StatusCode, HeaderMap, Vec<u8>), HttpClientError> {
        let status = self.status;
        let headers = self.headers.clone();
        let body = self.bytes(DEFAULT_BODY_LIMIT).await?;
        Ok((status, headers, body))
    }

    pub(crate) fn into_sse_stream(self) -> BoxStream<'static, Result<Sse, SseError>> {
        bounded_sse_stream(self.body.into_data_stream(), SseBounds::default())
    }
}

#[derive(Clone)]
struct HttpsConnector {
    tcp: HttpConnector,
    tls: Arc<ClientConfig>,
    proxy_matcher: Arc<Matcher>,
}

impl HttpsConnector {
    fn new(
        connect_timeout: Duration,
        proxy_matcher: Arc<Matcher>,
    ) -> Result<Self, HttpClientError> {
        let loaded = rustls_native_certs::load_native_certs();
        let mut roots = RootCertStore::empty();
        roots.add_parsable_certificates(loaded.certs);
        Self::with_roots(connect_timeout, roots, proxy_matcher)
    }

    fn with_roots(
        connect_timeout: Duration,
        roots: RootCertStore,
        proxy_matcher: Arc<Matcher>,
    ) -> Result<Self, HttpClientError> {
        let provider = Arc::new(rustls::crypto::ring::default_provider());
        let mut tls = ClientConfig::builder_with_provider(provider)
            .with_safe_default_protocol_versions()
            .map_err(|_| HttpClientError::TlsConfig)?
            .with_root_certificates(roots)
            .with_no_client_auth();
        tls.alpn_protocols = vec![b"http/1.1".to_vec()];
        let mut tcp = HttpConnector::new();
        tcp.enforce_http(false);
        tcp.set_connect_timeout(Some(connect_timeout));
        tcp.set_nodelay(true);
        Ok(Self {
            tcp,
            tls: Arc::new(tls),
            proxy_matcher,
        })
    }

    async fn secure(
        stream: Box<dyn IoStream>,
        tls: Arc<ClientConfig>,
        host: &str,
    ) -> Result<Box<dyn IoStream>, ConnectorError> {
        let host = host.trim_matches(['[', ']']);
        let server_name = tls_server_name(host)?;
        let stream = TlsConnector::from(tls)
            .connect(server_name, stream)
            .await
            .map_err(ConnectorError::Tls)?;
        Ok(Box::new(stream))
    }

    async fn connect_tunnel(
        stream: &mut dyn IoStream,
        authority: &str,
        authorization: Option<&HeaderValue>,
    ) -> Result<(), ConnectorError> {
        let mut request = format!("CONNECT {authority} HTTP/1.1\r\nHost: {authority}\r\n");
        if let Some(authorization) = authorization {
            let value = authorization
                .to_str()
                .map_err(|_| ConnectorError::ProxyConnect)?;
            request.push_str("Proxy-Authorization: ");
            request.push_str(value);
            request.push_str("\r\n");
        }
        request.push_str("\r\n");
        let write_result = stream.write_all(request.as_bytes()).await;
        request.zeroize();
        write_result.map_err(ConnectorError::Io)?;
        stream.flush().await.map_err(ConnectorError::Io)?;

        let mut response = Vec::with_capacity(1024);
        loop {
            if let Some(header_end) = response.windows(4).position(|part| part == b"\r\n\r\n") {
                if header_end + 4 != response.len() {
                    return Err(ConnectorError::ProxyConnect);
                }
                let mut headers = [httparse::EMPTY_HEADER; 32];
                let mut parsed = httparse::Response::new(&mut headers);
                return match parsed
                    .parse(&response)
                    .map_err(|_| ConnectorError::ProxyConnect)?
                {
                    httparse::Status::Complete(_) if parsed.code == Some(200) => Ok(()),
                    httparse::Status::Complete(_) | httparse::Status::Partial => {
                        Err(ConnectorError::ProxyConnect)
                    }
                };
            }
            if response.len() >= 32 * 1024 {
                return Err(ConnectorError::ProxyConnect);
            }
            let mut chunk = [0_u8; 1024];
            let count = stream.read(&mut chunk).await.map_err(ConnectorError::Io)?;
            if count == 0 || count > (32 * 1024_usize).saturating_sub(response.len()) {
                return Err(ConnectorError::ProxyConnect);
            }
            response.extend_from_slice(&chunk[..count]);
        }
    }
}

fn tls_server_name(host: &str) -> Result<ServerName<'static>, ConnectorError> {
    ServerName::try_from(host.trim_matches(['[', ']']).to_owned())
        .map_err(|_| ConnectorError::ServerName)
}

#[derive(Debug, Error)]
enum ConnectorError {
    #[error("unsupported HTTP scheme")]
    Scheme,
    #[error("HTTP destination has no host")]
    Host,
    #[error("HTTP TCP connection failed")]
    Tcp(#[source] BoxError),
    #[error("TLS server name is invalid")]
    ServerName,
    #[error("TLS handshake failed")]
    Tls(#[source] io::Error),
    #[error("proxy I/O failed")]
    Io(#[source] io::Error),
    #[error("configured proxy scheme is unsupported")]
    ProxyScheme,
    #[error("HTTP proxy CONNECT failed")]
    ProxyConnect,
}

impl Service<Uri> for HttpsConnector {
    type Response = TokioIo<ConnectedIo>;
    type Error = ConnectorError;
    type Future =
        Pin<Box<dyn Future<Output = Result<Self::Response, Self::Error>> + Send + 'static>>;

    fn poll_ready(&mut self, context: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.tcp
            .poll_ready(context)
            .map_err(|error| ConnectorError::Tcp(Box::new(error)))
    }

    fn call(&mut self, destination: Uri) -> Self::Future {
        let is_https = destination.scheme_str() == Some("https");
        if !is_https && destination.scheme_str() != Some("http") {
            return Box::pin(async { Err(ConnectorError::Scheme) });
        }
        let Some(host) = destination.host().map(str::to_owned) else {
            return Box::pin(async { Err(ConnectorError::Host) });
        };
        let mut tcp = self.tcp.clone();
        let tls = Arc::clone(&self.tls);
        let proxy = if is_literal_loopback_host(&host) {
            None
        } else {
            self.proxy_matcher.intercept(&destination)
        };
        Box::pin(async move {
            let connect_uri = proxy
                .as_ref()
                .map_or_else(|| destination.clone(), |intercept| intercept.uri().clone());
            if proxy.as_ref().is_some_and(|intercept| {
                !matches!(intercept.uri().scheme_str(), Some("http" | "https"))
            }) {
                return Err(ConnectorError::ProxyScheme);
            }
            let tcp = tcp
                .call(connect_uri.clone())
                .await
                .map_err(|error| ConnectorError::Tcp(Box::new(error)))?
                .into_inner();
            let mut stream: Box<dyn IoStream> = Box::new(tcp);
            if proxy.is_some() && connect_uri.scheme_str() == Some("https") {
                let proxy_host = connect_uri.host().ok_or(ConnectorError::Host)?;
                stream = Self::secure(stream, Arc::clone(&tls), proxy_host).await?;
            }
            let is_forward_proxy = proxy.is_some() && !is_https;
            if is_https {
                if let Some(proxy) = proxy.as_ref() {
                    let port = destination.port_u16().unwrap_or(443);
                    let authority = format!("{host}:{port}");
                    Self::connect_tunnel(&mut *stream, &authority, proxy.basic_auth()).await?;
                }
                stream = Self::secure(stream, tls, &host).await?;
            }
            Ok(TokioIo::new(ConnectedIo {
                inner: stream,
                is_forward_proxy,
            }))
        })
    }
}

struct ConnectedIo {
    inner: Box<dyn IoStream>,
    is_forward_proxy: bool,
}

impl AsyncRead for ConnectedIo {
    fn poll_read(
        mut self: Pin<&mut Self>,
        context: &mut Context<'_>,
        buffer: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_read(context, buffer)
    }
}

impl AsyncWrite for ConnectedIo {
    fn poll_write(
        mut self: Pin<&mut Self>,
        context: &mut Context<'_>,
        bytes: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.inner).poll_write(context, bytes)
    }

    fn poll_flush(mut self: Pin<&mut Self>, context: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_flush(context)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, context: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_shutdown(context)
    }
}

impl Connection for ConnectedIo {
    fn connected(&self) -> Connected {
        Connected::new().proxy(self.is_forward_proxy)
    }
}

fn is_reserved_header(name: &HeaderName) -> bool {
    matches!(
        name.as_str(),
        "accept"
            | "authorization"
            | "content-type"
            | "mcp-session-id"
            | "last-event-id"
            | "proxy-authorization"
    )
}

fn apply_custom_headers(
    headers: &mut HeaderMap,
    custom_headers: HashMap<HeaderName, HeaderValue>,
) -> Result<(), StreamableHttpError<HttpClientError>> {
    for (name, value) in custom_headers {
        if is_reserved_header(&name) {
            return Err(StreamableHttpError::ReservedHeaderConflict(
                name.as_str().to_owned(),
            ));
        }
        headers.insert(name, value);
    }
    Ok(())
}

fn bearer_header(mut token: String) -> Result<HeaderValue, StreamableHttpError<HttpClientError>> {
    let mut encoded = String::with_capacity("Bearer ".len() + token.len());
    encoded.push_str("Bearer ");
    encoded.push_str(&token);
    let result = HeaderValue::from_str(&encoded);
    token.zeroize();
    encoded.zeroize();
    let mut value = result.map_err(|_| {
        StreamableHttpError::UnexpectedServerResponse("invalid bearer token".into())
    })?;
    value.set_sensitive(true);
    Ok(value)
}

fn content_type(response: &HttpResponse) -> Option<String> {
    response
        .headers
        .get(CONTENT_TYPE)
        .map(|value| String::from_utf8_lossy(value.as_bytes()).into_owned())
}

fn response_session_id(response: &HttpResponse) -> Option<String> {
    response
        .headers
        .get(HEADER_SESSION_ID)
        .and_then(|value| value.to_str().ok())
        .map(str::to_owned)
}

fn parse_scope(header: &str) -> Option<String> {
    header.split(',').find_map(|part| {
        let (_, value) = part.trim().split_once("scope=")?;
        Some(value.trim().trim_matches('"').to_owned())
    })
}

fn parse_json_rpc_error(body: &[u8]) -> Option<ServerJsonRpcMessage> {
    match serde_json::from_slice::<ServerJsonRpcMessage>(body) {
        Ok(message @ JsonRpcMessage::Error(_)) => Some(message),
        _ => None,
    }
}

impl StreamableHttpClient for HttpClient {
    type Error = HttpClientError;

    async fn post_message(
        &self,
        uri: Arc<str>,
        message: ClientJsonRpcMessage,
        session_id: Option<Arc<str>>,
        auth_header: Option<String>,
        custom_headers: HashMap<HeaderName, HeaderValue>,
    ) -> Result<StreamableHttpPostResponse, StreamableHttpError<Self::Error>> {
        let url = Url::parse(&uri)
            .map_err(|_| StreamableHttpError::UnexpectedServerResponse("invalid MCP URL".into()))?;
        let mut headers = HeaderMap::new();
        headers.insert(
            ACCEPT,
            HeaderValue::from_static("application/json, text/event-stream"),
        );
        headers.insert(CONTENT_TYPE, HeaderValue::from_static(JSON_MIME_TYPE));
        if let Some(token) = auth_header {
            headers.insert(AUTHORIZATION, bearer_header(token)?);
        }
        apply_custom_headers(&mut headers, custom_headers)?;
        let session_was_attached = session_id.is_some();
        if let Some(session_id) = session_id {
            headers.insert(
                HeaderName::from_static(HEADER_SESSION_ID),
                HeaderValue::from_str(&session_id).map_err(|_| {
                    StreamableHttpError::UnexpectedServerResponse("invalid MCP session ID".into())
                })?,
            );
        }
        let body = serde_json::to_vec(&message).map_err(StreamableHttpError::Deserialize)?;
        let response = self
            .request(Method::POST, &url, headers, body)
            .await
            .map_err(StreamableHttpError::Client)?;
        if response.status == StatusCode::UNAUTHORIZED
            && let Some(header) = response.headers.get(WWW_AUTHENTICATE)
        {
            let header = header.to_str().map_err(|_| {
                StreamableHttpError::UnexpectedServerResponse(
                    "invalid www-authenticate header value".into(),
                )
            })?;
            return Err(StreamableHttpError::AuthRequired(AuthRequiredError::new(
                header.to_owned(),
            )));
        }
        if response.status == StatusCode::FORBIDDEN
            && let Some(header) = response.headers.get(WWW_AUTHENTICATE)
        {
            let header = header.to_str().map_err(|_| {
                StreamableHttpError::UnexpectedServerResponse(
                    "invalid www-authenticate header value".into(),
                )
            })?;
            return Err(StreamableHttpError::InsufficientScope(
                InsufficientScopeError::new(header.to_owned(), parse_scope(header)),
            ));
        }
        let status = response.status;
        let content_type = content_type(&response);
        let is_json = content_type
            .as_deref()
            .is_some_and(|value| value.as_bytes().starts_with(JSON_MIME_TYPE.as_bytes()));
        if matches!(status, StatusCode::ACCEPTED | StatusCode::NO_CONTENT) && !is_json {
            return Ok(StreamableHttpPostResponse::Accepted);
        }
        if status == StatusCode::NOT_FOUND && session_was_attached {
            return Err(StreamableHttpError::SessionExpired);
        }
        let content_length = response
            .headers
            .get(CONTENT_LENGTH)
            .and_then(|value| value.to_str().ok())
            .and_then(|value| value.parse::<u64>().ok());
        let session_id = response_session_id(&response);
        if status.is_success()
            && content_length == Some(0)
            && !is_json
            && matches!(
                message,
                ClientJsonRpcMessage::Notification(_)
                    | ClientJsonRpcMessage::Response(_)
                    | ClientJsonRpcMessage::Error(_)
            )
        {
            return Ok(StreamableHttpPostResponse::Accepted);
        }
        if !status.is_success() {
            let body = response
                .bytes(DEFAULT_BODY_LIMIT)
                .await
                .map_err(StreamableHttpError::Client)?;
            if is_json && let Some(message) = parse_json_rpc_error(&body) {
                return Ok(StreamableHttpPostResponse::Json(message, session_id));
            }
            return Err(StreamableHttpError::UnexpectedServerResponse(Cow::Owned(
                format!("HTTP {status}"),
            )));
        }
        match content_type.as_deref() {
            Some(value)
                if value
                    .as_bytes()
                    .starts_with(EVENT_STREAM_MIME_TYPE.as_bytes()) =>
            {
                Ok(StreamableHttpPostResponse::Sse(
                    response.into_sse_stream(),
                    session_id,
                ))
            }
            Some(value) if value.as_bytes().starts_with(JSON_MIME_TYPE.as_bytes()) => {
                let body = response
                    .bytes(DEFAULT_BODY_LIMIT)
                    .await
                    .map_err(StreamableHttpError::Client)?;
                let message =
                    serde_json::from_slice(&body).map_err(StreamableHttpError::Deserialize)?;
                Ok(StreamableHttpPostResponse::Json(message, session_id))
            }

            _ => Err(StreamableHttpError::UnexpectedContentType(content_type)),
        }
    }

    async fn delete_session(
        &self,
        uri: Arc<str>,
        session_id: Arc<str>,
        auth_header: Option<String>,
        custom_headers: HashMap<HeaderName, HeaderValue>,
    ) -> Result<(), StreamableHttpError<Self::Error>> {
        let url = Url::parse(&uri)
            .map_err(|_| StreamableHttpError::UnexpectedServerResponse("invalid MCP URL".into()))?;
        let mut headers = HeaderMap::new();
        headers.insert(
            HeaderName::from_static(HEADER_SESSION_ID),
            HeaderValue::from_str(&session_id).map_err(|_| {
                StreamableHttpError::UnexpectedServerResponse("invalid MCP session ID".into())
            })?,
        );
        if let Some(token) = auth_header {
            headers.insert(AUTHORIZATION, bearer_header(token)?);
        }
        apply_custom_headers(&mut headers, custom_headers)?;
        let response = self
            .request(Method::DELETE, &url, headers, Vec::new())
            .await
            .map_err(StreamableHttpError::Client)?;
        if response.status == StatusCode::METHOD_NOT_ALLOWED {
            return Err(StreamableHttpError::ServerDoesNotSupportDeleteSession);
        }
        if !response.status.is_success() {
            return Err(StreamableHttpError::UnexpectedServerResponse(Cow::Owned(
                format!("HTTP {}", response.status),
            )));
        }
        Ok(())
    }

    async fn get_stream(
        &self,
        uri: Arc<str>,
        session_id: Arc<str>,
        last_event_id: Option<String>,
        auth_header: Option<String>,
        custom_headers: HashMap<HeaderName, HeaderValue>,
    ) -> Result<BoxStream<'static, Result<Sse, SseError>>, StreamableHttpError<Self::Error>> {
        let url = Url::parse(&uri)
            .map_err(|_| StreamableHttpError::UnexpectedServerResponse("invalid MCP URL".into()))?;
        let mut headers = HeaderMap::new();
        headers.insert(
            ACCEPT,
            HeaderValue::from_static("text/event-stream, application/json"),
        );
        headers.insert(
            HeaderName::from_static(HEADER_SESSION_ID),
            HeaderValue::from_str(&session_id).map_err(|_| {
                StreamableHttpError::UnexpectedServerResponse("invalid MCP session ID".into())
            })?,
        );
        if let Some(last_event_id) = last_event_id {
            headers.insert(
                HeaderName::from_static("last-event-id"),
                HeaderValue::from_str(&last_event_id).map_err(|_| {
                    StreamableHttpError::UnexpectedServerResponse(
                        "invalid SSE last-event ID".into(),
                    )
                })?,
            );
        }
        if let Some(token) = auth_header {
            headers.insert(AUTHORIZATION, bearer_header(token)?);
        }
        apply_custom_headers(&mut headers, custom_headers)?;
        let response = self
            .request(Method::GET, &url, headers, Vec::new())
            .await
            .map_err(StreamableHttpError::Client)?;
        if response.status == StatusCode::METHOD_NOT_ALLOWED {
            return Err(StreamableHttpError::ServerDoesNotSupportSse);
        }
        if !response.status.is_success() {
            return Err(StreamableHttpError::UnexpectedServerResponse(Cow::Owned(
                format!("HTTP {}", response.status),
            )));
        }
        let content_type = content_type(&response);
        if !content_type.as_deref().is_some_and(|value| {
            value
                .as_bytes()
                .starts_with(EVENT_STREAM_MIME_TYPE.as_bytes())
                || value.as_bytes().starts_with(JSON_MIME_TYPE.as_bytes())
        }) {
            return Err(StreamableHttpError::UnexpectedContentType(content_type));
        }
        Ok(response.into_sse_stream())
    }
}

#[cfg(test)]
mod tests {
    use std::{
        collections::HashMap,
        io,
        sync::{
            Arc,
            atomic::{AtomicBool, Ordering},
        },
        time::{SystemTime, UNIX_EPOCH},
    };

    use axum::{
        Router,
        extract::State,
        response::{IntoResponse, Redirect},
        routing::{get, post},
    };
    use base64::{Engine as _, engine::general_purpose::STANDARD};
    use futures_util::stream;
    use rustls::{
        ServerConfig,
        client::{WebPkiServerVerifier, danger::ServerCertVerifier},
        pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer, UnixTime},
    };
    use tokio::{
        io::{AsyncReadExt, AsyncWriteExt, copy_bidirectional},
        net::{TcpListener, TcpStream},
        time::{sleep, timeout},
    };
    use tokio_rustls::TlsAcceptor;

    use super::*;

    async fn bounded_stream_error(chunks: &[&'static [u8]], bounds: SseBounds) -> SseError {
        let chunks = chunks
            .iter()
            .map(|chunk| Ok::<_, io::Error>(Bytes::from_static(chunk)))
            .collect::<Vec<_>>();
        let input = stream::iter(chunks).chain(stream::pending());
        let mut events = bounded_sse_stream(input, bounds);
        timeout(Duration::from_secs(1), async {
            loop {
                match events.next().await {
                    Some(Ok(_)) => {}
                    Some(Err(error)) => return error,
                    None => panic!("bounded SSE stream ended before reporting its limit"),
                }
            }
        })
        .await
        .expect("SSE limit must fire without waiting for the body to end")
    }

    #[tokio::test]
    async fn sse_bounds_reject_unterminated_lines_events_and_streams() {
        let line = bounded_stream_error(
            &[b"da", b"ta", b":"],
            SseBounds {
                line: 4,
                event: 32,
                stream: 64,
            },
        )
        .await;
        assert!(line.to_string().contains("SSE line exceeded 4 bytes"));

        let event = bounded_stream_error(
            &[b"data:a\n", b"data:b"],
            SseBounds {
                line: 16,
                event: 10,
                stream: 64,
            },
        )
        .await;
        assert!(event.to_string().contains("SSE event exceeded 10 bytes"));

        let aggregate = bounded_stream_error(
            &[b"data:a\n\n", b"data:b\n\n"],
            SseBounds {
                line: 16,
                event: 16,
                stream: 12,
            },
        )
        .await;
        assert!(
            aggregate
                .to_string()
                .contains("SSE stream exceeded 12 bytes")
        );
    }

    #[tokio::test]
    async fn sse_bounds_accept_crlf_events_at_the_exact_limits() {
        let input = stream::iter([Ok::<_, io::Error>(Bytes::from_static(b"data: ok\r\n\r\n"))]);
        let mut events = bounded_sse_stream(
            input,
            SseBounds {
                line: 8,
                event: 10,
                stream: 12,
            },
        );

        let event = events
            .next()
            .await
            .expect("one bounded event")
            .expect("event at the exact bounds");
        assert_eq!(event.data.as_deref(), Some("ok"));
        assert!(events.next().await.is_none());
    }

    #[tokio::test]
    async fn every_successful_application_json_body_must_decode_as_json_rpc() {
        async fn malformed_json() -> impl IntoResponse {
            ([(CONTENT_TYPE, JSON_MIME_TYPE)], "{not-json")
        }

        async fn empty_json() -> impl IntoResponse {
            ([(CONTENT_TYPE, JSON_MIME_TYPE)], "")
        }

        async fn accepted_malformed_json() -> impl IntoResponse {
            (
                StatusCode::ACCEPTED,
                [(CONTENT_TYPE, JSON_MIME_TYPE)],
                "{not-json",
            )
        }

        let listener = TcpListener::bind(("127.0.0.1", 0))
            .await
            .expect("bind malformed JSON fixture");
        let address = listener.local_addr().expect("malformed JSON address");
        let server = tokio::spawn(async move {
            axum::serve(
                listener,
                Router::new()
                    .route("/malformed", post(malformed_json))
                    .route("/empty", post(empty_json))
                    .route("/accepted", post(accepted_malformed_json)),
            )
            .await
        });
        let client = HttpClient::new(Duration::from_secs(5)).expect("HTTP client");
        let request: ClientJsonRpcMessage = serde_json::from_value(serde_json::json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": "ping"
        }))
        .expect("fixture JSON-RPC request");

        let malformed = client
            .post_message(
                Arc::from(format!("http://{address}/malformed")),
                request,
                None,
                None,
                HashMap::new(),
            )
            .await;
        assert!(matches!(
            malformed,
            Err(StreamableHttpError::Deserialize(_))
        ));

        let notification: ClientJsonRpcMessage = serde_json::from_value(serde_json::json!({
            "jsonrpc": "2.0",
            "method": "notifications/initialized"
        }))
        .expect("fixture JSON-RPC notification");
        let empty = client
            .post_message(
                Arc::from(format!("http://{address}/empty")),
                notification,
                None,
                None,
                HashMap::new(),
            )
            .await;
        assert!(matches!(empty, Err(StreamableHttpError::Deserialize(_))));

        let request: ClientJsonRpcMessage = serde_json::from_value(serde_json::json!({
            "jsonrpc": "2.0",
            "id": 2,
            "method": "ping"
        }))
        .expect("second fixture JSON-RPC request");
        let accepted = client
            .post_message(
                Arc::from(format!("http://{address}/accepted")),
                request,
                None,
                None,
                HashMap::new(),
            )
            .await;
        assert!(matches!(accepted, Err(StreamableHttpError::Deserialize(_))));
        server.abort();
    }

    fn tls_fixture() -> (CertificateDer<'static>, PrivateKeyDer<'static>) {
        let certificate = STANDARD
            .decode(include_str!("../tests/fixtures/tls/localhost-cert.der.b64").trim())
            .expect("decode fixture certificate");
        let private_key = STANDARD
            .decode(include_str!("../tests/fixtures/tls/localhost-key.der.b64").trim())
            .expect("decode fixture private key");
        (
            CertificateDer::from(certificate),
            PrivateKeyDer::from(PrivatePkcs8KeyDer::from(private_key)),
        )
    }

    #[test]
    fn tls_fixture_remains_valid_for_at_least_thirty_days() {
        let (certificate, _) = tls_fixture();
        let mut roots = RootCertStore::empty();
        roots
            .add(certificate.clone())
            .expect("add fixture trust anchor");
        let verifier = WebPkiServerVerifier::builder_with_provider(
            Arc::new(roots),
            Arc::new(rustls::crypto::ring::default_provider()),
        )
        .build()
        .expect("build fixture certificate verifier");
        let verification_time = SystemTime::now()
            .checked_add(Duration::from_hours(30 * 24))
            .expect("fixture warning horizon must fit in system time")
            .duration_since(UNIX_EPOCH)
            .expect("system clock must follow the Unix epoch");
        let server_name = ServerName::try_from("localhost").expect("valid fixture DNS name");

        verifier
            .verify_server_cert(
                &certificate,
                &[],
                &server_name,
                &[],
                UnixTime::since_unix_epoch(verification_time),
            )
            .unwrap_or_else(|error| {
                panic!(
                    "TLS fixtures expire within 30 days or are otherwise invalid; regenerate crates/claw-mcp/tests/fixtures/tls: {error}"
                )
            });
    }

    #[tokio::test]
    async fn custom_ring_connector_completes_a_local_https_exchange() {
        let (certificate, private_key) = tls_fixture();
        let provider = Arc::new(rustls::crypto::ring::default_provider());
        let server_config = ServerConfig::builder_with_provider(provider)
            .with_safe_default_protocol_versions()
            .expect("server protocol versions")
            .with_no_client_auth()
            .with_single_cert(vec![certificate.clone()], private_key)
            .expect("test server certificate");
        let listener = TcpListener::bind(("127.0.0.1", 0))
            .await
            .expect("bind HTTPS fixture");
        let address = listener.local_addr().expect("HTTPS fixture address");
        let server = tokio::spawn(async move {
            let (tcp, _) = listener.accept().await.expect("accept HTTPS client");
            let mut stream = TlsAcceptor::from(Arc::new(server_config))
                .accept(tcp)
                .await
                .expect("accept TLS");
            let mut request = Vec::new();
            loop {
                let mut chunk = [0_u8; 512];
                let count = stream.read(&mut chunk).await.expect("read request");
                assert_ne!(count, 0, "request ended before its headers");
                request.extend_from_slice(&chunk[..count]);
                assert!(request.len() <= 8 * 1024, "request headers exceeded bound");
                if request.windows(4).any(|window| window == b"\r\n\r\n") {
                    break;
                }
            }
            let first_line_end = request
                .windows(2)
                .position(|window| window == b"\r\n")
                .expect("HTTP request line");
            assert_eq!(&request[..first_line_end], b"GET /health HTTP/1.1");
            stream
                .write_all(
                    b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: 11\r\nConnection: close\r\n\r\n{\"ok\":true}",
                )
                .await
                .expect("write HTTPS response");
            stream.flush().await.expect("flush HTTPS response");
        });

        let mut roots = RootCertStore::empty();
        roots.add(certificate).expect("add fixture trust anchor");
        let client =
            HttpClient::with_roots(Duration::from_secs(5), roots).expect("build HTTPS client");
        let endpoint = Url::parse(&format!("https://localhost:{}/health", address.port()))
            .expect("fixture URL");
        let response = client
            .request(Method::GET, &endpoint, HeaderMap::new(), Vec::new())
            .await
            .expect("HTTPS request");
        assert_eq!(response.status, StatusCode::OK);
        assert_eq!(
            response.bytes(64).await.expect("HTTPS body"),
            br#"{"ok":true}"#
        );
        server.await.expect("HTTPS fixture task");
    }

    #[tokio::test]
    async fn configured_http_proxy_tunnels_https_with_connect() {
        let (certificate, private_key) = tls_fixture();
        let provider = Arc::new(rustls::crypto::ring::default_provider());
        let server_config = ServerConfig::builder_with_provider(provider)
            .with_safe_default_protocol_versions()
            .expect("server protocol versions")
            .with_no_client_auth()
            .with_single_cert(vec![certificate.clone()], private_key)
            .expect("test server certificate");
        let target_listener = TcpListener::bind(("127.0.0.1", 0))
            .await
            .expect("bind HTTPS target fixture");
        let target_address = target_listener.local_addr().expect("HTTPS target address");
        let target = tokio::spawn(async move {
            let (tcp, _) = target_listener.accept().await.expect("accept HTTPS client");
            let mut stream = TlsAcceptor::from(Arc::new(server_config))
                .accept(tcp)
                .await
                .expect("accept TLS");
            let mut request = Vec::new();
            loop {
                let mut chunk = [0_u8; 512];
                let count = stream.read(&mut chunk).await.expect("read request");
                assert_ne!(count, 0, "request ended before its headers");
                request.extend_from_slice(&chunk[..count]);
                assert!(request.len() <= 8 * 1024, "request headers exceeded bound");
                if request.windows(4).any(|window| window == b"\r\n\r\n") {
                    break;
                }
            }
            stream
                .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok")
                .await
                .expect("write HTTPS response");
            stream.flush().await.expect("flush HTTPS response");
        });
        let proxy_listener = TcpListener::bind(("127.0.0.1", 0))
            .await
            .expect("bind CONNECT proxy fixture");
        let proxy_address = proxy_listener.local_addr().expect("CONNECT proxy address");
        let proxy = tokio::spawn(async move {
            let (mut client, _) = proxy_listener.accept().await.expect("accept proxy client");
            let mut request = Vec::new();
            loop {
                let mut chunk = [0_u8; 512];
                let count = client.read(&mut chunk).await.expect("read CONNECT request");
                assert_ne!(count, 0, "CONNECT request ended before headers");
                request.extend_from_slice(&chunk[..count]);
                assert!(request.len() <= 8 * 1024, "CONNECT request exceeded bound");
                if request.windows(4).any(|part| part == b"\r\n\r\n") {
                    break;
                }
            }
            let mut target = TcpStream::connect(target_address)
                .await
                .expect("connect HTTPS target");
            client
                .write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n")
                .await
                .expect("write CONNECT response");
            client.flush().await.expect("flush CONNECT response");
            copy_bidirectional(&mut client, &mut target)
                .await
                .expect("relay CONNECT tunnel");
            request
        });

        let matcher = Arc::new(
            Matcher::builder()
                .https(format!("http://Aladdin:opensesame@{proxy_address}"))
                .build(),
        );
        let mut roots = RootCertStore::empty();
        roots.add(certificate).expect("add fixture trust anchor");
        let client = HttpClient::with_roots_and_proxy(Duration::from_secs(5), roots, matcher)
            .expect("proxied HTTPS client");
        let endpoint = Url::parse(&format!(
            "https://localhost:{}/resource",
            target_address.port()
        ))
        .expect("HTTPS target URL");
        let response = client
            .request(Method::GET, &endpoint, HeaderMap::new(), Vec::new())
            .await
            .expect("proxied HTTPS request");
        assert_eq!(response.bytes(8).await.expect("HTTPS response body"), b"ok");
        let request = String::from_utf8(proxy.await.expect("proxy fixture task"))
            .expect("ASCII CONNECT request");
        let mut lines = request.lines();
        assert_eq!(
            lines.next(),
            Some(format!("CONNECT localhost:{} HTTP/1.1", target_address.port()).as_str())
        );
        assert!(lines.any(|line| line == "Proxy-Authorization: Basic QWxhZGRpbjpvcGVuc2VzYW1l"));
        target.await.expect("HTTPS target task");
    }

    #[tokio::test]
    async fn client_returns_redirect_without_contacting_the_target() {
        async fn capture(State(contacted): State<Arc<AtomicBool>>) {
            contacted.store(true, Ordering::SeqCst);
        }

        let contacted = Arc::new(AtomicBool::new(false));
        let target_listener = TcpListener::bind(("127.0.0.1", 0))
            .await
            .expect("bind redirect target");
        let target_address = target_listener.local_addr().expect("target address");
        let target_server = tokio::spawn({
            let contacted = Arc::clone(&contacted);
            async move {
                axum::serve(
                    target_listener,
                    Router::new()
                        .route("/capture", get(capture))
                        .with_state(contacted),
                )
                .await
            }
        });
        let redirect_listener = TcpListener::bind(("127.0.0.1", 0))
            .await
            .expect("bind redirect source");
        let redirect_address = redirect_listener.local_addr().expect("redirect address");
        let location = format!("http://{target_address}/capture");
        let redirect_server = tokio::spawn(async move {
            axum::serve(
                redirect_listener,
                Router::new().route(
                    "/start",
                    get(move || {
                        let location = location.clone();
                        async move { Redirect::temporary(&location) }
                    }),
                ),
            )
            .await
        });
        let endpoint =
            Url::parse(&format!("http://{redirect_address}/start")).expect("redirect fixture URL");
        let client = HttpClient::new(Duration::from_secs(5)).expect("HTTP client");

        let response = client
            .request(Method::GET, &endpoint, HeaderMap::new(), Vec::new())
            .await
            .expect("redirect response");

        assert_eq!(response.status, StatusCode::TEMPORARY_REDIRECT);
        assert!(!contacted.load(Ordering::SeqCst));
        redirect_server.abort();
        target_server.abort();
    }

    #[test]
    fn tls_server_name_accepts_bracketed_ipv6_literals() {
        let name = tls_server_name("[::1]").expect("IPv6 TLS server name");
        assert_eq!(name.to_str(), "::1");
    }

    #[tokio::test]
    async fn plain_http_with_empty_roots_still_enforces_the_body_deadline() {
        let listener = TcpListener::bind(("127.0.0.1", 0))
            .await
            .expect("bind stalled HTTP fixture");
        let address = listener.local_addr().expect("stalled fixture address");
        let server = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.expect("accept HTTP client");
            let mut request = [0_u8; 1024];
            let count = stream.read(&mut request).await.expect("read HTTP request");
            assert!(request[..count].windows(4).any(|part| part == b"\r\n\r\n"));
            stream
                .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 1\r\n\r\n")
                .await
                .expect("write response headers");
            stream.flush().await.expect("flush response headers");
            sleep(Duration::from_millis(250)).await;
        });
        let client = HttpClient::with_roots(Duration::from_millis(50), RootCertStore::empty())
            .expect("HTTP client without roots");
        let endpoint = Url::parse(&format!("http://{address}/stalled")).expect("fixture URL");
        let response = client
            .request(Method::GET, &endpoint, HeaderMap::new(), Vec::new())
            .await
            .expect("response headers");

        let error = response
            .bytes(8)
            .await
            .expect_err("stalled body must time out");

        assert!(matches!(error, HttpClientError::Timeout));
        server.abort();
    }

    #[tokio::test]
    async fn response_headers_and_body_share_one_request_deadline() {
        let listener = TcpListener::bind(("127.0.0.1", 0))
            .await
            .expect("bind slow HTTP fixture");
        let address = listener.local_addr().expect("slow fixture address");
        let server = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.expect("accept HTTP client");
            let mut request = [0_u8; 1024];
            let count = stream.read(&mut request).await.expect("read HTTP request");
            assert!(request[..count].windows(4).any(|part| part == b"\r\n\r\n"));
            sleep(Duration::from_millis(100)).await;
            stream
                .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 1\r\n\r\n")
                .await
                .expect("write response headers");
            stream.flush().await.expect("flush response headers");
            sleep(Duration::from_millis(100)).await;
            stream.write_all(b"x").await.expect("write response body");
        });
        let client = HttpClient::with_roots(Duration::from_millis(150), RootCertStore::empty())
            .expect("HTTP client without roots");
        let endpoint = Url::parse(&format!("http://{address}/slow")).expect("fixture URL");
        let response = client
            .request(Method::GET, &endpoint, HeaderMap::new(), Vec::new())
            .await
            .expect("response headers within deadline");

        let error = response
            .bytes(8)
            .await
            .expect_err("body must use the remaining request deadline");

        assert!(matches!(error, HttpClientError::Timeout));
        server.abort();
    }

    #[tokio::test]
    async fn authenticated_literal_loopback_request_bypasses_configured_proxy() {
        async fn capture(listener: TcpListener, response_body: &'static [u8]) -> Option<Vec<u8>> {
            let (mut stream, _) =
                tokio::time::timeout(Duration::from_millis(500), listener.accept())
                    .await
                    .ok()?
                    .ok()?;
            let mut request = Vec::new();
            while !request
                .windows(b"oauth-secret".len())
                .any(|window| window == b"oauth-secret")
            {
                let mut chunk = [0_u8; 512];
                let count = stream.read(&mut chunk).await.ok()?;
                if count == 0 || count > (8 * 1024_usize).saturating_sub(request.len()) {
                    return None;
                }
                request.extend_from_slice(&chunk[..count]);
            }
            let response = format!(
                "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                response_body.len(),
                std::str::from_utf8(response_body).expect("fixture response is ASCII")
            );
            stream.write_all(response.as_bytes()).await.ok()?;
            Some(request)
        }

        let target_listener = TcpListener::bind(("127.0.0.1", 0))
            .await
            .expect("bind loopback target");
        let target_address = target_listener.local_addr().expect("target address");
        let proxy_listener = TcpListener::bind(("127.0.0.1", 0))
            .await
            .expect("bind proxy");
        let proxy_address = proxy_listener.local_addr().expect("proxy address");
        let target = tokio::spawn(capture(target_listener, b"target"));
        let proxy = tokio::spawn(capture(proxy_listener, b"proxy"));
        let matcher = Arc::new(
            Matcher::builder()
                .http(format!("******{proxy_address}"))
                .build(),
        );
        let client = HttpClient::with_roots_and_proxy(
            Duration::from_secs(5),
            RootCertStore::empty(),
            matcher,
        )
        .expect("proxied HTTP client");
        let endpoint = Url::parse(&format!("http://{target_address}/oauth/token"))
            .expect("loopback OAuth URL");
        let mut headers = HeaderMap::new();
        headers.insert(
            AUTHORIZATION,
            HeaderValue::from_static("Bearer loopback-token"),
        );

        let response = client
            .request(Method::POST, &endpoint, headers, b"oauth-secret".to_vec())
            .await
            .expect("direct loopback request");

        assert_eq!(
            response.bytes(16).await.expect("target response"),
            b"target"
        );
        let target_request = target
            .await
            .expect("target capture task")
            .expect("loopback target must receive the request");
        assert_eq!(
            proxy.await.expect("proxy capture task"),
            None,
            "configured proxy must not receive literal loopback traffic"
        );
        let target_request = String::from_utf8(target_request).expect("ASCII target request");
        assert!(
            target_request
                .lines()
                .any(|line| line == "authorization: Bearer loopback-token")
        );
        assert!(target_request.ends_with("oauth-secret"));
    }

    #[tokio::test]
    async fn configured_http_proxy_receives_absolute_uri_and_sensitive_auth() {
        let listener = TcpListener::bind(("127.0.0.1", 0))
            .await
            .expect("bind HTTP proxy fixture");
        let address = listener.local_addr().expect("proxy fixture address");
        let proxy = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.expect("accept proxy client");
            let mut request = Vec::new();
            loop {
                let mut chunk = [0_u8; 512];
                let count = stream.read(&mut chunk).await.expect("read proxy request");
                assert_ne!(count, 0, "proxy request ended before headers");
                request.extend_from_slice(&chunk[..count]);
                assert!(request.len() <= 8 * 1024, "proxy request exceeded bound");
                if request.windows(4).any(|part| part == b"\r\n\r\n") {
                    break;
                }
            }
            stream
                .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok")
                .await
                .expect("write proxy response");
            (stream, request)
        });
        let matcher = Arc::new(
            Matcher::builder()
                .http(format!("http://Aladdin:opensesame@{address}"))
                .build(),
        );
        let client = HttpClient::with_roots_and_proxy(
            Duration::from_secs(5),
            RootCertStore::empty(),
            matcher,
        )
        .expect("proxied HTTP client");
        let endpoint = Url::parse("http://example.invalid/resource").expect("remote URL");
        let response = client
            .request(Method::GET, &endpoint, HeaderMap::new(), Vec::new())
            .await
            .expect("proxied request");
        assert_eq!(response.bytes(8).await.expect("proxy body"), b"ok");
        let (stream, request) = proxy.await.expect("proxy fixture task");
        drop(stream);
        let request = String::from_utf8(request).expect("ASCII proxy request");
        let mut lines = request.lines();
        assert_eq!(
            lines.next(),
            Some("GET http://example.invalid/resource HTTP/1.1")
        );
        assert!(lines.any(|line| line == "proxy-authorization: Basic QWxhZGRpbjpvcGVuc2VzYW1l"));
    }
}

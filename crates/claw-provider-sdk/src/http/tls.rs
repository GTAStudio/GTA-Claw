//! A pure-Rust HTTPS connector for the provider transport.
//!
//! This exists because `reqwest` 0.13 offers exactly two rustls features and
//! both hard-depend on `rustls-platform-verifier`, which drags in
//! `webpki-root-certs` (CDLA-Permissive-2.0, outside the workspace licence
//! allowlist) and a second `windows-sys` major line through `jni`. Driving
//! `hyper` with our own `tokio-rustls` connector avoids both while keeping the
//! stack pure Rust on the RING crypto provider.
//!
//! Nothing here is provider-specific; it is the smallest connector that
//! satisfies [`hyper_util::client::legacy::Client`].
//!
//! # Proxies
//!
//! Only `https` destinations are proxied, and only through a `CONNECT` tunnel.
//! Plaintext is deliberately never proxied: the TLS policy already restricts it
//! to loopback, and forwarding such a request to an external proxy would put an
//! `authorization` header on the wire in the clear. Because a tunnel is
//! end-to-end, the TLS handshake still authenticates the *destination*, so a
//! proxy — hostile or merely compromised — sees ciphertext and an SNI name
//! rather than a credential.
//!
//! Which proxy carries a destination is decided by [`crate::http::proxy`],
//! never here. This module only opens the socket the decision names.

use std::future::Future;
use std::io;
use std::pin::Pin;
use std::sync::{Arc, OnceLock};
use std::task::{Context, Poll};
use std::time::Duration;

use bytes::Bytes;
use http::Uri;
use http_body_util::Empty;
use hyper::client::conn::http1::SendRequest;
use hyper::rt::{Read, ReadBufCursor, Write};
use hyper::upgrade::Upgraded;
use hyper_util::client::legacy::connect::{Connected, Connection, HttpConnector};
use hyper_util::rt::TokioIo;
use rustls::{ClientConfig, RootCertStore};
use rustls_pki_types::ServerName;
use tokio::net::TcpStream;
use tokio_rustls::TlsConnector;
use tower_service::Service;

use crate::http::proxy::{ProxyDecision, ProxyRules, ProxyScheme, ProxyUrl};

/// A TLS session established directly over TCP.
type DirectStream = TokioIo<tokio_rustls::client::TlsStream<TcpStream>>;
/// A TLS session established inside a proxy `CONNECT` tunnel.
type TunnelStream = TokioIo<tokio_rustls::client::TlsStream<TokioIo<Upgraded>>>;
/// The error type `hyper-util` expects a connector to produce.
type ConnectError = Box<dyn std::error::Error + Send + Sync>;

/// A transport that may or may not have been upgraded to TLS.
///
/// Plaintext is reachable only for loopback URLs, and only when the caller
/// opted in through [`crate::http::TlsPolicy::AllowLoopbackPlaintext`]; the
/// scheme check happens before a request ever reaches this connector.
///
/// The TLS variants are boxed because a `TlsStream` is far larger than a
/// `TcpStream`, and an unboxed enum would pay for the biggest variant on every
/// plaintext connection.
pub(crate) enum MaybeTlsStream {
    /// Plaintext HTTP, loopback only.
    Plain(TokioIo<TcpStream>),
    /// HTTPS negotiated directly with the destination.
    Tls(Box<DirectStream>),
    /// HTTPS negotiated with the destination through a proxy tunnel.
    Tunnelled(Box<TunnelStream>),
}

impl Connection for MaybeTlsStream {
    fn connected(&self) -> Connected {
        match self {
            Self::Plain(stream) => stream.inner().connected(),
            Self::Tls(stream) => stream.inner().get_ref().0.connected(),
            // A tunnel is transparent once established, so the request must be
            // written in origin form exactly as if it were direct. Reporting
            // `proxy(true)` here would switch `hyper-util` to absolute form and
            // put the full URL on a wire the proxy can no longer read anyway.
            Self::Tunnelled(_) => Connected::new(),
        }
    }
}

impl Read for MaybeTlsStream {
    fn poll_read(
        self: Pin<&mut Self>,
        context: &mut Context<'_>,
        buffer: ReadBufCursor<'_>,
    ) -> Poll<io::Result<()>> {
        match self.get_mut() {
            Self::Plain(stream) => Pin::new(stream).poll_read(context, buffer),
            Self::Tls(stream) => Pin::new(stream.as_mut()).poll_read(context, buffer),
            Self::Tunnelled(stream) => Pin::new(stream.as_mut()).poll_read(context, buffer),
        }
    }
}

impl Write for MaybeTlsStream {
    fn poll_write(
        self: Pin<&mut Self>,
        context: &mut Context<'_>,
        data: &[u8],
    ) -> Poll<io::Result<usize>> {
        match self.get_mut() {
            Self::Plain(stream) => Pin::new(stream).poll_write(context, data),
            Self::Tls(stream) => Pin::new(stream.as_mut()).poll_write(context, data),
            Self::Tunnelled(stream) => Pin::new(stream.as_mut()).poll_write(context, data),
        }
    }

    fn poll_flush(self: Pin<&mut Self>, context: &mut Context<'_>) -> Poll<io::Result<()>> {
        match self.get_mut() {
            Self::Plain(stream) => Pin::new(stream).poll_flush(context),
            Self::Tls(stream) => Pin::new(stream.as_mut()).poll_flush(context),
            Self::Tunnelled(stream) => Pin::new(stream.as_mut()).poll_flush(context),
        }
    }

    fn poll_shutdown(self: Pin<&mut Self>, context: &mut Context<'_>) -> Poll<io::Result<()>> {
        match self.get_mut() {
            Self::Plain(stream) => Pin::new(stream).poll_shutdown(context),
            Self::Tls(stream) => Pin::new(stream.as_mut()).poll_shutdown(context),
            Self::Tunnelled(stream) => Pin::new(stream.as_mut()).poll_shutdown(context),
        }
    }
}

/// Why the TLS stack could not be prepared.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum TlsSetupError {
    /// The platform trust store yielded no usable root certificate.
    NoRoots,
    /// The RING provider rejected the requested protocol versions.
    Provider,
}

/// Loads the platform trust store once per process.
///
/// Root certificates do not change during a run and parsing them is not free,
/// so the result is cached. A partial load is accepted as long as at least one
/// root parsed: platforms routinely ship a few certificates no current parser
/// accepts, and failing the whole client over one of them would be worse than
/// ignoring it. Zero usable roots is still a hard error, because that would
/// silently leave nothing to verify against.
fn native_roots() -> Result<Arc<ClientConfig>, TlsSetupError> {
    static CONFIG: OnceLock<Result<Arc<ClientConfig>, TlsSetupError>> = OnceLock::new();
    CONFIG
        .get_or_init(|| {
            let loaded = rustls_native_certs::load_native_certs();
            let mut store = RootCertStore::empty();
            let (added, _ignored) = store.add_parsable_certificates(loaded.certs);
            if added == 0 {
                return Err(TlsSetupError::NoRoots);
            }
            let config = ClientConfig::builder_with_provider(Arc::new(
                rustls::crypto::ring::default_provider(),
            ))
            .with_safe_default_protocol_versions()
            .map_err(|_| TlsSetupError::Provider)?
            .with_root_certificates(store)
            .with_no_client_auth();
            Ok(Arc::new(config))
        })
        .clone()
}

/// Converts a host into the owned server name the handshake needs.
///
/// The owned form is what lets the handshake run in a `'static` future; a
/// borrowed `ServerName` would tie it to the host string.
fn server_name_for(host: &str) -> Result<ServerName<'static>, ConnectError> {
    let unbracketed = host
        .trim_start_matches('[')
        .trim_end_matches(']')
        .to_owned();
    ServerName::try_from(unbracketed)
        .map_err(|_| io::Error::other("the URL host is not a valid TLS server name").into())
}

/// Builds the URI naming the proxy hop itself.
fn proxy_uri(proxy: &ProxyUrl) -> Result<Uri, ConnectError> {
    Uri::builder()
        .scheme(proxy.scheme().as_str())
        .authority(proxy.authority())
        .path_and_query("/")
        .build()
        .map_err(|_| io::Error::other("the proxy URL is not a valid connect target").into())
}

/// Starts an HTTP/1.1 connection and drives it in the background.
///
/// The connection future is spawned here rather than returned because the two
/// proxy hops — plaintext and TLS — produce different connection types while
/// sharing one `SendRequest`.
async fn start_connection<I>(io: I) -> Result<SendRequest<Empty<Bytes>>, ConnectError>
where
    I: Read + Write + Unpin + Send + 'static,
{
    let (sender, connection) = hyper::client::conn::http1::handshake(io).await?;
    tokio::spawn(async move {
        // `with_upgrades` is what keeps the socket alive past the 200 instead
        // of closing it when the response body ends.
        let _ = connection.with_upgrades().await;
    });
    Ok(sender)
}

/// Opens a `CONNECT` tunnel to `authority` through `proxy`.
///
/// `hyper`'s own upgrade machinery is used rather than a hand-written handshake
/// because it correctly hands back any bytes the proxy pipelined after its
/// `200`. A hand-rolled reader that over-consumed the header would silently eat
/// the first TLS record.
async fn open_tunnel(
    mut http: HttpConnector,
    tls: TlsConnector,
    proxy: ProxyUrl,
    authority: String,
) -> Result<Upgraded, ConnectError> {
    let stream = http.call(proxy_uri(&proxy)?).await?;
    // An `https://` proxy speaks TLS on its own hop. Connecting to it in the
    // clear would send the `CONNECT` request — and any proxy credential — as
    // plaintext to a port the operator declared as TLS.
    let mut sender = match proxy.scheme() {
        ProxyScheme::Http => start_connection(stream).await?,
        ProxyScheme::Https => {
            let server_name = server_name_for(proxy.host())?;
            let secured = tls.connect(server_name, stream.into_inner()).await?;
            start_connection(TokioIo::new(secured)).await?
        }
    };

    let mut request = http::Request::connect(&authority)
        .body(Empty::<Bytes>::new())
        .map_err(|_| io::Error::other("the CONNECT request could not be assembled"))?;
    // `hyper`'s low-level client does not synthesise a `Host` header the way
    // the pooled client does, and RFC 9110 requires one on every HTTP/1.1
    // request. Proxies that enforce it reject a tunnel without it.
    let host = http::HeaderValue::from_str(&authority)
        .map_err(|_| io::Error::other("the destination authority is not a valid header value"))?;
    request.headers_mut().insert(http::header::HOST, host);
    if let Some(credential) = proxy.proxy_authorization() {
        let mut value = http::HeaderValue::from_str(credential.expose())
            .map_err(|_| io::Error::other("the proxy credential is not a valid header value"))?;
        value.set_sensitive(true);
        request
            .headers_mut()
            .insert(http::header::PROXY_AUTHORIZATION, value);
    }

    let response = sender.send_request(request).await?;
    let status = response.status();
    if !status.is_success() {
        // Only the status is reported. A proxy URL may embed credentials, so it
        // must never reach an error message.
        return Err(io::Error::other(format!(
            "the proxy refused the tunnel with status {}",
            status.as_u16()
        ))
        .into());
    }
    Ok(hyper::upgrade::on(response).await?)
}

/// Connects plaintext to loopback and TLS everywhere else.
#[derive(Clone)]
pub(crate) struct TlsConnectorService {
    http: HttpConnector,
    tls: TlsConnector,
    /// Shared because the connector is cloned per connection and the rules hold
    /// a parsed bypass list that is not worth rebuilding.
    proxy: Arc<ProxyRules>,
    connect_timeout: Duration,
}

impl TlsConnectorService {
    /// Builds the connector, loading platform roots on first use.
    pub(crate) fn new(
        connect_timeout: Duration,
        proxy: Arc<ProxyRules>,
    ) -> Result<Self, TlsSetupError> {
        let config = native_roots()?;
        let mut http = HttpConnector::new();
        // The scheme is already validated against the transport's TLS policy,
        // and this connector handles `https` itself, so the built-in http-only
        // guard would reject every secure request.
        http.enforce_http(false);
        http.set_connect_timeout(Some(connect_timeout));
        http.set_nodelay(true);
        Ok(Self {
            http,
            tls: TlsConnector::from(config),
            proxy,
            connect_timeout,
        })
    }

    /// Returns the proxy that should carry `uri`, if any.
    ///
    /// Plaintext is excluded before the rules are consulted, because this
    /// transport never forwards a cleartext request to a proxy. The rules
    /// exclude loopback themselves, so no bypass-list mistake can route it
    /// through a proxy either.
    fn intercept(&self, uri: &Uri) -> Option<ProxyUrl> {
        if uri.scheme_str() != Some("https") {
            return None;
        }
        let host = uri.host()?;
        let port = uri.port_u16().unwrap_or(443);
        match self.proxy.intercept(host, port) {
            ProxyDecision::Proxy(proxy) => Some(proxy),
            ProxyDecision::Direct(_) => None,
        }
    }
}

impl Service<Uri> for TlsConnectorService {
    type Response = MaybeTlsStream;
    type Error = ConnectError;
    type Future = Pin<Box<dyn Future<Output = Result<Self::Response, Self::Error>> + Send>>;

    fn poll_ready(&mut self, context: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        Service::poll_ready(&mut self.http, context).map_err(Into::into)
    }

    fn call(&mut self, uri: Uri) -> Self::Future {
        let is_tls = uri.scheme_str() == Some("https");
        let host = uri.host().map(str::to_owned);
        let port = uri.port_u16().unwrap_or(if is_tls { 443 } else { 80 });
        let intercept = self.intercept(&uri);
        let tls = self.tls.clone();
        let connect_timeout = self.connect_timeout;
        let mut http = self.http.clone();

        Box::pin(async move {
            let missing_host = || io::Error::other("the URL names no host");
            if let Some(proxy) = intercept {
                let host = host.ok_or_else(missing_host)?;
                // The handshake authenticates the destination, never the proxy.
                let server_name = server_name_for(&host)?;
                let authority = format!("{host}:{port}");
                let tunnel = tokio::time::timeout(
                    connect_timeout,
                    open_tunnel(http, tls.clone(), proxy, authority),
                )
                .await
                .map_err(|_| {
                    io::Error::new(io::ErrorKind::TimedOut, "the proxy tunnel timed out")
                })??;
                let secured = tls.connect(server_name, TokioIo::new(tunnel)).await?;
                return Ok(MaybeTlsStream::Tunnelled(Box::new(TokioIo::new(secured))));
            }

            let stream = http.call(uri).await?;
            if !is_tls {
                return Ok(MaybeTlsStream::Plain(stream));
            }
            let host = host.ok_or_else(missing_host)?;
            let server_name = server_name_for(&host)?;
            let secured = tls.connect(server_name, stream.into_inner()).await?;
            Ok(MaybeTlsStream::Tls(Box::new(TokioIo::new(secured))))
        })
    }
}

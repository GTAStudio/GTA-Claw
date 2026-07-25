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

use std::future::Future;
use std::io;
use std::pin::Pin;
use std::sync::{Arc, OnceLock};
use std::task::{Context, Poll};

use http::Uri;
use hyper::rt::{Read, ReadBufCursor, Write};
use hyper_util::client::legacy::connect::{Connected, Connection, HttpConnector};
use hyper_util::rt::TokioIo;
use rustls::{ClientConfig, RootCertStore};
use rustls_pki_types::ServerName;
use tokio::net::TcpStream;
use tokio_rustls::TlsConnector;
use tower_service::Service;

/// A TCP stream that may or may not have been upgraded to TLS.
///
/// Plaintext is reachable only for loopback URLs, and only when the caller
/// opted in through [`crate::http::TlsPolicy::AllowLoopbackPlaintext`]; the
/// scheme check happens before a request ever reaches this connector.
pub(crate) enum MaybeTlsStream {
    /// Plaintext HTTP, loopback only.
    Plain(TokioIo<TcpStream>),
    /// HTTPS over rustls.
    Tls(Box<TokioIo<tokio_rustls::client::TlsStream<TcpStream>>>),
}

impl Connection for MaybeTlsStream {
    fn connected(&self) -> Connected {
        match self {
            Self::Plain(stream) => stream.inner().connected(),
            Self::Tls(stream) => stream.inner().get_ref().0.connected(),
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
        }
    }

    fn poll_flush(self: Pin<&mut Self>, context: &mut Context<'_>) -> Poll<io::Result<()>> {
        match self.get_mut() {
            Self::Plain(stream) => Pin::new(stream).poll_flush(context),
            Self::Tls(stream) => Pin::new(stream.as_mut()).poll_flush(context),
        }
    }

    fn poll_shutdown(self: Pin<&mut Self>, context: &mut Context<'_>) -> Poll<io::Result<()>> {
        match self.get_mut() {
            Self::Plain(stream) => Pin::new(stream).poll_shutdown(context),
            Self::Tls(stream) => Pin::new(stream.as_mut()).poll_shutdown(context),
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

/// Connects plaintext to loopback and TLS everywhere else.
#[derive(Clone)]
pub(crate) struct TlsConnectorService {
    http: HttpConnector,
    tls: TlsConnector,
}

impl TlsConnectorService {
    /// Builds the connector, loading platform roots on first use.
    pub(crate) fn new(connect_timeout: std::time::Duration) -> Result<Self, TlsSetupError> {
        let config = native_roots()?;
        let mut http = HttpConnector::new();
        // The scheme is already validated against the transport's TLS policy,
        // and this connector handles `https` itself, so the built-in
        // http-only guard would reject every secure request.
        http.enforce_http(false);
        http.set_connect_timeout(Some(connect_timeout));
        http.set_nodelay(true);
        Ok(Self {
            http,
            tls: TlsConnector::from(config),
        })
    }
}

impl Service<Uri> for TlsConnectorService {
    type Response = MaybeTlsStream;
    type Error = Box<dyn std::error::Error + Send + Sync>;
    type Future = Pin<Box<dyn Future<Output = Result<Self::Response, Self::Error>> + Send>>;

    fn poll_ready(&mut self, context: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        Service::poll_ready(&mut self.http, context).map_err(Into::into)
    }

    fn call(&mut self, uri: Uri) -> Self::Future {
        let is_tls = uri.scheme_str() == Some("https");
        let host = uri.host().map(str::to_owned);
        let tls = self.tls.clone();
        let connecting = self.http.call(uri);
        Box::pin(async move {
            let stream = connecting.await?;
            if !is_tls {
                return Ok(MaybeTlsStream::Plain(stream));
            }
            let host = host.ok_or_else(|| io::Error::other("the URL names no host"))?;
            // The owned form is what lets the handshake run in a `'static`
            // future; a borrowed `ServerName` would tie it to `host`.
            let server_name = ServerName::try_from(host)
                .map_err(|_| io::Error::other("the URL host is not a valid TLS server name"))?;
            let upgraded = tls.connect(server_name, stream.into_inner()).await?;
            Ok(MaybeTlsStream::Tls(Box::new(TokioIo::new(upgraded))))
        })
    }
}

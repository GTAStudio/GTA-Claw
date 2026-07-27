//! Fixed-address synchronous HTTP/1.1 transport over platform-rooted rustls.

use std::collections::VecDeque;
use std::fmt::{self, Debug, Formatter};
use std::io::{self, Read, Write};
use std::net::{IpAddr, Ipv6Addr, SocketAddr, TcpStream};
use std::num::NonZeroUsize;
use std::str;
use std::sync::Arc;
use std::time::{Duration, Instant};

use http::header::{
    CONNECTION, CONTENT_LENGTH, EXPECT, HOST, TE, TRAILER, TRANSFER_ENCODING, UPGRADE,
};
use http::{HeaderName, HeaderValue, Method, Uri};
use rustls::{ClientConfig, ClientConnection, RootCertStore, StreamOwned};
use rustls_pki_types::{CertificateDer, ServerName};

use crate::services::{
    HostCallControl, HostCallStop, HttpTransport, InboundResponse, OutboundRequest,
};

const MAX_TIMEOUT: Duration = Duration::from_mins(10);
const IO_POLL_INTERVAL: Duration = Duration::from_millis(25);
const CONNECT_POLL_INTERVAL: Duration = Duration::from_millis(100);
const READ_BUFFER_BYTES: usize = 8 * 1024;
const MAX_ADDITIONAL_ROOTS: usize = 64;
const MAX_ROOT_CERTIFICATE_BYTES: usize = 1024 * 1024;
const MAX_CHUNK_LINE_BYTES: usize = 1024;
const MAX_INFORMATIONAL_RESPONSES: usize = 8;
const MAX_HEADER_BYTES: usize = 1024 * 1024;
const MAX_BODY_BYTES: usize = 64 * 1024 * 1024;
const MAX_RESPONSE_HEADERS: usize = 1024;
const MAX_PINNED_ADDRESSES: usize = 64;

/// Strict limits and deadlines for [`PinnedHttpTransport`].
#[derive(Clone)]
pub struct PinnedHttpTransportConfig {
    connect_timeout: Duration,
    tls_handshake_timeout: Duration,
    read_timeout: Duration,
    write_timeout: Duration,
    overall_timeout: Duration,
    max_request_header_bytes: usize,
    max_request_body_bytes: usize,
    max_response_header_bytes: usize,
    max_response_headers: NonZeroUsize,
    max_response_body_bytes: usize,
    allow_loopback_http: bool,
    additional_root_certificates: Vec<Vec<u8>>,
}

impl Default for PinnedHttpTransportConfig {
    fn default() -> Self {
        Self {
            connect_timeout: Duration::from_secs(10),
            tls_handshake_timeout: Duration::from_secs(10),
            read_timeout: Duration::from_secs(30),
            write_timeout: Duration::from_secs(30),
            overall_timeout: Duration::from_mins(1),
            max_request_header_bytes: 64 * 1024,
            max_request_body_bytes: 4 * 1024 * 1024,
            max_response_header_bytes: 64 * 1024,
            max_response_headers: NonZeroUsize::new(128).expect("128 is non-zero"),
            max_response_body_bytes: 4 * 1024 * 1024,
            allow_loopback_http: false,
            additional_root_certificates: Vec::new(),
        }
    }
}

impl Debug for PinnedHttpTransportConfig {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PinnedHttpTransportConfig")
            .field("connect_timeout", &self.connect_timeout)
            .field("tls_handshake_timeout", &self.tls_handshake_timeout)
            .field("read_timeout", &self.read_timeout)
            .field("write_timeout", &self.write_timeout)
            .field("overall_timeout", &self.overall_timeout)
            .field("max_request_header_bytes", &self.max_request_header_bytes)
            .field("max_request_body_bytes", &self.max_request_body_bytes)
            .field("max_response_header_bytes", &self.max_response_header_bytes)
            .field("max_response_headers", &self.max_response_headers)
            .field("max_response_body_bytes", &self.max_response_body_bytes)
            .field("allow_loopback_http", &self.allow_loopback_http)
            .field(
                "additional_root_certificates",
                &self.additional_root_certificates.len(),
            )
            .finish()
    }
}

impl PinnedHttpTransportConfig {
    /// Creates the default production limits.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Sets the TCP connect deadline.
    #[must_use]
    pub const fn with_connect_timeout(mut self, timeout: Duration) -> Self {
        self.connect_timeout = timeout;
        self
    }

    /// Sets the TLS handshake deadline.
    #[must_use]
    pub const fn with_tls_handshake_timeout(mut self, timeout: Duration) -> Self {
        self.tls_handshake_timeout = timeout;
        self
    }

    /// Sets the maximum idle time for one response read.
    #[must_use]
    pub const fn with_read_timeout(mut self, timeout: Duration) -> Self {
        self.read_timeout = timeout;
        self
    }

    /// Sets the deadline for writing a complete request.
    #[must_use]
    pub const fn with_write_timeout(mut self, timeout: Duration) -> Self {
        self.write_timeout = timeout;
        self
    }

    /// Sets the transport-wide deadline, further narrowed by the guest call.
    #[must_use]
    pub const fn with_overall_timeout(mut self, timeout: Duration) -> Self {
        self.overall_timeout = timeout;
        self
    }

    /// Sets the encoded request-header ceiling.
    #[must_use]
    pub const fn with_max_request_header_bytes(mut self, limit: usize) -> Self {
        self.max_request_header_bytes = limit;
        self
    }

    /// Sets the request-body ceiling.
    #[must_use]
    pub const fn with_max_request_body_bytes(mut self, limit: usize) -> Self {
        self.max_request_body_bytes = limit;
        self
    }

    /// Sets the encoded response-header and trailer ceiling.
    #[must_use]
    pub const fn with_max_response_header_bytes(mut self, limit: usize) -> Self {
        self.max_response_header_bytes = limit;
        self
    }

    /// Sets the combined response header and trailer count ceiling.
    #[must_use]
    pub const fn with_max_response_headers(mut self, limit: NonZeroUsize) -> Self {
        self.max_response_headers = limit;
        self
    }

    /// Sets the response-body ceiling.
    #[must_use]
    pub const fn with_max_response_body_bytes(mut self, limit: usize) -> Self {
        self.max_response_body_bytes = limit;
        self
    }

    /// Allows plaintext only when the canonical host and every pinned address
    /// are loopback.
    #[must_use]
    pub const fn allow_loopback_http(mut self, allowed: bool) -> Self {
        self.allow_loopback_http = allowed;
        self
    }

    /// Adds one DER-encoded trust anchor in addition to platform roots.
    ///
    /// This is intended for operator-owned private PKI and deterministic local
    /// TLS tests. The certificate bytes are never included in `Debug` or errors.
    #[must_use]
    pub fn with_root_certificate_der(mut self, certificate: Vec<u8>) -> Self {
        self.additional_root_certificates.push(certificate);
        self
    }

    fn validate(&self) -> Result<(), PinnedHttpTransportBuildError> {
        for (field, timeout) in [
            ("connect_timeout", self.connect_timeout),
            ("tls_handshake_timeout", self.tls_handshake_timeout),
            ("read_timeout", self.read_timeout),
            ("write_timeout", self.write_timeout),
            ("overall_timeout", self.overall_timeout),
        ] {
            if timeout.is_zero() || timeout > MAX_TIMEOUT {
                return Err(PinnedHttpTransportBuildError::InvalidConfig {
                    field,
                    reason: "must be positive and no more than ten minutes",
                });
            }
        }
        for (field, limit) in [
            ("max_request_header_bytes", self.max_request_header_bytes),
            ("max_response_header_bytes", self.max_response_header_bytes),
        ] {
            if !(1024..=MAX_HEADER_BYTES).contains(&limit) {
                return Err(PinnedHttpTransportBuildError::InvalidConfig {
                    field,
                    reason: "must be between 1024 and 1048576 bytes",
                });
            }
        }
        for (field, limit) in [
            ("max_request_body_bytes", self.max_request_body_bytes),
            ("max_response_body_bytes", self.max_response_body_bytes),
        ] {
            if limit > MAX_BODY_BYTES {
                return Err(PinnedHttpTransportBuildError::InvalidConfig {
                    field,
                    reason: "must be no more than 67108864 bytes",
                });
            }
        }
        if self.max_response_headers.get() > MAX_RESPONSE_HEADERS {
            return Err(PinnedHttpTransportBuildError::InvalidConfig {
                field: "max_response_headers",
                reason: "must be no more than 1024",
            });
        }
        if self.additional_root_certificates.len() > MAX_ADDITIONAL_ROOTS {
            return Err(PinnedHttpTransportBuildError::InvalidConfig {
                field: "additional_root_certificates",
                reason: "must contain at most 64 certificates",
            });
        }
        if self.additional_root_certificates.iter().any(|certificate| {
            certificate.is_empty() || certificate.len() > MAX_ROOT_CERTIFICATE_BYTES
        }) {
            return Err(PinnedHttpTransportBuildError::InvalidConfig {
                field: "additional_root_certificates",
                reason: "each certificate must be 1..=1048576 bytes",
            });
        }
        Ok(())
    }
}

/// A fixed-address HTTP transport build failure.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PinnedHttpTransportBuildError {
    /// One configuration field was out of range.
    InvalidConfig {
        /// Rejected field.
        field: &'static str,
        /// Stable reason.
        reason: &'static str,
    },
    /// One additional root was not a valid certificate.
    InvalidRootCertificate,
    /// Neither the platform nor configured roots yielded a usable certificate.
    NoTrustRoots,
    /// rustls could not install its safe protocol defaults.
    TlsProvider,
}

impl fmt::Display for PinnedHttpTransportBuildError {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidConfig { field, reason } => {
                write!(formatter, "HTTP transport `{field}` {reason}")
            }
            Self::InvalidRootCertificate => {
                formatter.write_str("HTTP transport received an invalid root certificate")
            }
            Self::NoTrustRoots => {
                formatter.write_str("HTTP transport found no usable TLS trust roots")
            }
            Self::TlsProvider => {
                formatter.write_str("HTTP transport could not configure the TLS provider")
            }
        }
    }
}

impl core::error::Error for PinnedHttpTransportBuildError {}

/// Stable, credential-free failure from [`PinnedHttpTransport`].
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PinnedHttpError {
    /// Request fields disagreed with the validated contract.
    InvalidRequest,
    /// Plaintext was not an explicitly allowed loopback request.
    PlaintextDenied,
    /// Request headers exceeded the configured bound.
    RequestHeadersTooLarge,
    /// Request body exceeded the configured bound.
    RequestBodyTooLarge,
    /// Caller cancellation stopped the request.
    Cancelled,
    /// The guest call or transport-wide deadline expired.
    DeadlineExceeded,
    /// TCP connection did not complete before its deadline.
    ConnectTimeout,
    /// Every pinned address refused or failed the connection.
    ConnectFailed,
    /// TLS could not be initialized for the canonical server name.
    TlsSetup,
    /// TLS negotiation exceeded its deadline.
    TlsTimeout,
    /// TLS negotiation failed.
    TlsFailed,
    /// Writing the request exceeded its deadline.
    WriteTimeout,
    /// Writing the request failed.
    WriteFailed,
    /// Reading the response exceeded its idle deadline.
    ReadTimeout,
    /// Reading the response failed.
    ReadFailed,
    /// Response headers or trailers exceeded their byte ceiling.
    ResponseHeadersTooLarge,
    /// Response headers and trailers exceeded their count ceiling.
    TooManyResponseHeaders,
    /// Response body exceeded its byte ceiling.
    ResponseBodyTooLarge,
    /// The peer returned unsupported or malformed HTTP/1.1.
    Protocol,
}

impl fmt::Display for PinnedHttpError {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        let message = match self {
            Self::InvalidRequest => "HTTP request contract is invalid",
            Self::PlaintextDenied => "plaintext HTTP is allowed only for configured loopback hosts",
            Self::RequestHeadersTooLarge => "HTTP request headers exceed the configured limit",
            Self::RequestBodyTooLarge => "HTTP request body exceeds the configured limit",
            Self::Cancelled => "HTTP request cancelled",
            Self::DeadlineExceeded => "HTTP request deadline exceeded",
            Self::ConnectTimeout => "HTTP connection timed out",
            Self::ConnectFailed => "HTTP connection failed",
            Self::TlsSetup => "HTTPS server name or client configuration is invalid",
            Self::TlsTimeout => "HTTPS handshake timed out",
            Self::TlsFailed => "HTTPS handshake failed",
            Self::WriteTimeout => "HTTP request write timed out",
            Self::WriteFailed => "HTTP request write failed",
            Self::ReadTimeout => "HTTP response read timed out",
            Self::ReadFailed => "HTTP response read failed",
            Self::ResponseHeadersTooLarge => "HTTP response headers exceed the configured limit",
            Self::TooManyResponseHeaders => "HTTP response has too many headers",
            Self::ResponseBodyTooLarge => "HTTP response body exceeds the configured limit",
            Self::Protocol => "HTTP response protocol is invalid or unsupported",
        };
        formatter.write_str(message)
    }
}

impl core::error::Error for PinnedHttpError {}

/// Production synchronous HTTP transport that never resolves a hostname.
#[derive(Clone)]
pub struct PinnedHttpTransport {
    config: PinnedHttpTransportConfig,
    tls: Arc<ClientConfig>,
}

impl Debug for PinnedHttpTransport {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PinnedHttpTransport")
            .field("config", &self.config)
            .finish_non_exhaustive()
    }
}

impl PinnedHttpTransport {
    /// Loads platform roots and builds a fixed-address transport.
    ///
    /// # Errors
    ///
    /// Returns [`PinnedHttpTransportBuildError`] for invalid bounds, invalid
    /// configured roots, an empty combined trust store, or TLS provider failure.
    pub fn new(config: PinnedHttpTransportConfig) -> Result<Self, PinnedHttpTransportBuildError> {
        config.validate()?;
        let loaded = rustls_native_certs::load_native_certs();
        let mut roots = RootCertStore::empty();
        let (mut added, _) = roots.add_parsable_certificates(loaded.certs);
        for certificate in &config.additional_root_certificates {
            roots
                .add(CertificateDer::from(certificate.clone()))
                .map_err(|_| PinnedHttpTransportBuildError::InvalidRootCertificate)?;
            added = added.saturating_add(1);
        }
        if added == 0 {
            return Err(PinnedHttpTransportBuildError::NoTrustRoots);
        }
        let tls =
            ClientConfig::builder_with_provider(Arc::new(rustls::crypto::ring::default_provider()))
                .with_safe_default_protocol_versions()
                .map_err(|_| PinnedHttpTransportBuildError::TlsProvider)?
                .with_root_certificates(roots)
                .with_no_client_auth();
        Ok(Self {
            config,
            tls: Arc::new(tls),
        })
    }

    /// Sends one request and returns a typed, redacted failure.
    ///
    /// # Errors
    ///
    /// Returns [`PinnedHttpError`] when the request violates the fixed-address
    /// contract, a configured bound or deadline is reached, cancellation is
    /// requested, TLS fails, or the peer returns malformed HTTP/1.1.
    pub fn send_request(
        &self,
        request: OutboundRequest,
        control: &HostCallControl,
    ) -> Result<InboundResponse, PinnedHttpError> {
        let budget = RequestBudget::new(control, self.config.overall_timeout);
        budget.check()?;
        let prepared = PreparedRequest::new(request, &self.config)?;
        let socket = connect_pinned(
            &prepared.addresses,
            prepared.port,
            &budget,
            self.config.connect_timeout,
        )?;
        socket
            .set_nodelay(true)
            .map_err(|_| PinnedHttpError::ConnectFailed)?;
        let socket = budget.controlled_socket(socket);
        let mut wire = match prepared.scheme {
            Scheme::Http => Wire::Plain(socket),
            Scheme::Https => Wire::Tls(Box::new(open_tls(
                socket,
                &prepared.host,
                Arc::clone(&self.tls),
                &budget,
                self.config.tls_handshake_timeout,
            )?)),
        };
        write_request(
            &mut wire,
            &prepared.head,
            prepared.body.as_deref().unwrap_or_default(),
            &budget,
            self.config.write_timeout,
        )?;
        let response = read_response(&mut wire, &budget, &self.config, prepared.is_head)?;
        budget.check()?;
        Ok(response)
    }
}

impl HttpTransport for PinnedHttpTransport {
    fn send(&self, _plugin_id: &str, request: OutboundRequest) -> Result<InboundResponse, String> {
        let control = HostCallControl::new(Instant::now() + self.config.overall_timeout, None);
        self.send_request(request, &control)
            .map_err(|error| error.to_string())
    }

    fn send_with_control(
        &self,
        _plugin_id: &str,
        request: OutboundRequest,
        control: &HostCallControl,
    ) -> Result<InboundResponse, String> {
        self.send_request(request, control)
            .map_err(|error| error.to_string())
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Scheme {
    Http,
    Https,
}

struct PreparedRequest {
    scheme: Scheme,
    host: String,
    port: u16,
    addresses: Vec<IpAddr>,
    head: Vec<u8>,
    body: Option<Vec<u8>>,
    is_head: bool,
}

impl PreparedRequest {
    fn new(
        request: OutboundRequest,
        config: &PinnedHttpTransportConfig,
    ) -> Result<Self, PinnedHttpError> {
        if request.addresses.is_empty()
            || request.addresses.len() > MAX_PINNED_ADDRESSES
            || request.port == 0
        {
            return Err(PinnedHttpError::InvalidRequest);
        }
        let uri: Uri = request
            .url
            .parse()
            .map_err(|_| PinnedHttpError::InvalidRequest)?;
        let scheme = match uri.scheme_str() {
            Some("https") => Scheme::Https,
            Some("http") => Scheme::Http,
            _ => return Err(PinnedHttpError::InvalidRequest),
        };
        let authority = uri.authority().ok_or(PinnedHttpError::InvalidRequest)?;
        let authority_host = authority
            .host()
            .trim_start_matches('[')
            .trim_end_matches(']');
        if !authority_host.eq_ignore_ascii_case(&request.host) {
            return Err(PinnedHttpError::InvalidRequest);
        }
        let default_port = match scheme {
            Scheme::Http => 80,
            Scheme::Https => 443,
        };
        if authority.port_u16().unwrap_or(default_port) != request.port {
            return Err(PinnedHttpError::InvalidRequest);
        }
        if scheme == Scheme::Http
            && (!config.allow_loopback_http
                || !is_loopback_host(&request.host)
                || !request.addresses.iter().all(IpAddr::is_loopback))
        {
            return Err(PinnedHttpError::PlaintextDenied);
        }
        if request.body.as_ref().map_or(0, Vec::len) > config.max_request_body_bytes {
            return Err(PinnedHttpError::RequestBodyTooLarge);
        }

        let method = Method::from_bytes(request.method.as_bytes())
            .map_err(|_| PinnedHttpError::InvalidRequest)?;
        if !matches!(
            method,
            Method::GET
                | Method::HEAD
                | Method::POST
                | Method::PUT
                | Method::PATCH
                | Method::DELETE
        ) {
            return Err(PinnedHttpError::InvalidRequest);
        }
        let path = uri.path_and_query().map_or("/", |value| value.as_str());
        let host = host_header(&request.host, request.port, default_port);
        let mut head = Vec::with_capacity(1024);
        append(&mut head, method.as_str().as_bytes(), config)?;
        append(&mut head, b" ", config)?;
        append(&mut head, path.as_bytes(), config)?;
        append(&mut head, b" HTTP/1.1\r\nHost: ", config)?;
        append(&mut head, host.as_bytes(), config)?;
        append(&mut head, b"\r\nConnection: close\r\n", config)?;

        for (name, value) in &request.headers {
            let name = HeaderName::from_bytes(name.as_bytes())
                .map_err(|_| PinnedHttpError::InvalidRequest)?;
            let value =
                HeaderValue::from_str(value).map_err(|_| PinnedHttpError::InvalidRequest)?;
            if reserved_request_header(&name) {
                return Err(PinnedHttpError::InvalidRequest);
            }
            append(&mut head, name.as_str().as_bytes(), config)?;
            append(&mut head, b": ", config)?;
            append(&mut head, value.as_bytes(), config)?;
            append(&mut head, b"\r\n", config)?;
        }
        let body_len = request.body.as_ref().map_or(0, Vec::len);
        append(&mut head, b"Content-Length: ", config)?;
        append(&mut head, body_len.to_string().as_bytes(), config)?;
        append(&mut head, b"\r\n\r\n", config)?;

        Ok(Self {
            scheme,
            host: request.host,
            port: request.port,
            addresses: request.addresses,
            head,
            body: request.body,
            is_head: method == Method::HEAD,
        })
    }
}

fn append(
    destination: &mut Vec<u8>,
    bytes: &[u8],
    config: &PinnedHttpTransportConfig,
) -> Result<(), PinnedHttpError> {
    let next = destination
        .len()
        .checked_add(bytes.len())
        .ok_or(PinnedHttpError::RequestHeadersTooLarge)?;
    if next > config.max_request_header_bytes {
        return Err(PinnedHttpError::RequestHeadersTooLarge);
    }
    destination.extend_from_slice(bytes);
    Ok(())
}

const fn reserved_request_header(name: &HeaderName) -> bool {
    matches!(
        name,
        &HOST
            | &CONTENT_LENGTH
            | &TRANSFER_ENCODING
            | &CONNECTION
            | &EXPECT
            | &TRAILER
            | &TE
            | &UPGRADE
    )
}

fn host_header(host: &str, port: u16, default_port: u16) -> String {
    let rendered = if host.parse::<Ipv6Addr>().is_ok() {
        format!("[{host}]")
    } else {
        host.to_owned()
    };
    if port == default_port {
        rendered
    } else {
        format!("{rendered}:{port}")
    }
}

fn is_loopback_host(host: &str) -> bool {
    host.eq_ignore_ascii_case("localhost")
        || host
            .parse::<IpAddr>()
            .is_ok_and(|address| address.is_loopback())
}

struct RequestBudget<'a> {
    control: &'a HostCallControl,
    overall_deadline: Instant,
}

impl<'a> RequestBudget<'a> {
    fn new(control: &'a HostCallControl, overall_timeout: Duration) -> Self {
        Self {
            control,
            overall_deadline: control.deadline().min(Instant::now() + overall_timeout),
        }
    }

    fn check(&self) -> Result<(), PinnedHttpError> {
        self.control.check().map_err(map_stop)?;
        if Instant::now() >= self.overall_deadline {
            Err(PinnedHttpError::DeadlineExceeded)
        } else {
            Ok(())
        }
    }

    fn stage_deadline(&self, timeout: Duration) -> Instant {
        self.overall_deadline.min(Instant::now() + timeout)
    }

    fn poll_timeout(
        &self,
        stage_deadline: Instant,
        stage_timeout: PinnedHttpError,
    ) -> Result<Duration, PinnedHttpError> {
        self.check()?;
        let now = Instant::now();
        if now >= stage_deadline {
            return Err(stage_timeout);
        }
        let mut remaining = stage_deadline
            .min(self.overall_deadline)
            .min(self.control.deadline())
            .saturating_duration_since(now);
        if self.control.cancellation().is_some() {
            remaining = remaining.min(IO_POLL_INTERVAL);
        }
        Ok(remaining.max(Duration::from_millis(1)))
    }

    fn controlled_socket(&self, socket: TcpStream) -> ControlledSocket {
        ControlledSocket {
            socket,
            control: self.control.clone(),
            overall_deadline: self.overall_deadline,
            read_deadline: self.overall_deadline,
            write_deadline: self.overall_deadline,
        }
    }
}

const fn map_stop(stop: HostCallStop) -> PinnedHttpError {
    match stop {
        HostCallStop::Cancelled => PinnedHttpError::Cancelled,
        HostCallStop::DeadlineExceeded => PinnedHttpError::DeadlineExceeded,
    }
}

fn connect_pinned(
    addresses: &[IpAddr],
    port: u16,
    budget: &RequestBudget<'_>,
    timeout: Duration,
) -> Result<TcpStream, PinnedHttpError> {
    let deadline = budget.stage_deadline(timeout);
    loop {
        let mut saw_timeout = false;
        for address in addresses {
            let remaining = budget.poll_timeout(deadline, PinnedHttpError::ConnectTimeout)?;
            let attempt = remaining.min(CONNECT_POLL_INTERVAL);
            match TcpStream::connect_timeout(&SocketAddr::new(*address, port), attempt) {
                Ok(stream) => return Ok(stream),
                Err(error) if timed_out(&error) => saw_timeout = true,
                Err(_) => {}
            }
        }
        if !saw_timeout {
            return Err(PinnedHttpError::ConnectFailed);
        }
    }
}

struct ControlledSocket {
    socket: TcpStream,
    control: HostCallControl,
    overall_deadline: Instant,
    read_deadline: Instant,
    write_deadline: Instant,
}

impl ControlledSocket {
    const fn set_read_deadline(&mut self, deadline: Instant) {
        self.read_deadline = deadline;
    }

    const fn set_write_deadline(&mut self, deadline: Instant) {
        self.write_deadline = deadline;
    }

    fn prepare_read(&self) -> io::Result<()> {
        let timeout = self.io_timeout(self.read_deadline)?;
        self.socket.set_read_timeout(Some(timeout))
    }

    fn prepare_write(&self) -> io::Result<()> {
        let timeout = self.io_timeout(self.write_deadline)?;
        self.socket.set_write_timeout(Some(timeout))
    }

    fn io_timeout(&self, stage_deadline: Instant) -> io::Result<Duration> {
        if self.control.check().is_err() {
            return Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "controlled socket stopped",
            ));
        }
        let now = Instant::now();
        let deadline = stage_deadline
            .min(self.overall_deadline)
            .min(self.control.deadline());
        if now >= deadline {
            return Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "controlled socket deadline reached",
            ));
        }
        let mut remaining = deadline.saturating_duration_since(now);
        if self.control.cancellation().is_some() {
            remaining = remaining.min(IO_POLL_INTERVAL);
        }
        Ok(remaining.max(Duration::from_millis(1)))
    }
}

impl Read for ControlledSocket {
    fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
        self.prepare_read()?;
        self.socket.read(buffer)
    }
}

impl Write for ControlledSocket {
    fn write(&mut self, buffer: &[u8]) -> io::Result<usize> {
        self.prepare_write()?;
        self.socket.write(buffer)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.prepare_write()?;
        self.socket.flush()
    }
}

type TlsStream = StreamOwned<ClientConnection, ControlledSocket>;

enum Wire {
    Plain(ControlledSocket),
    Tls(Box<TlsStream>),
}

impl Wire {
    fn socket_mut(&mut self) -> &mut ControlledSocket {
        match self {
            Self::Plain(stream) => stream,
            Self::Tls(stream) => &mut stream.sock,
        }
    }
}

impl Read for Wire {
    fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
        match self {
            Self::Plain(stream) => stream.read(buffer),
            Self::Tls(stream) => stream.read(buffer),
        }
    }
}

impl Write for Wire {
    fn write(&mut self, buffer: &[u8]) -> io::Result<usize> {
        match self {
            Self::Plain(stream) => stream.write(buffer),
            Self::Tls(stream) => stream.write(buffer),
        }
    }

    fn flush(&mut self) -> io::Result<()> {
        match self {
            Self::Plain(stream) => stream.flush(),
            Self::Tls(stream) => stream.flush(),
        }
    }
}

fn open_tls(
    socket: ControlledSocket,
    host: &str,
    config: Arc<ClientConfig>,
    budget: &RequestBudget<'_>,
    timeout: Duration,
) -> Result<TlsStream, PinnedHttpError> {
    let server_name =
        ServerName::try_from(host.to_owned()).map_err(|_| PinnedHttpError::TlsSetup)?;
    let connection =
        ClientConnection::new(config, server_name).map_err(|_| PinnedHttpError::TlsSetup)?;
    let mut stream = StreamOwned::new(connection, socket);
    let deadline = budget.stage_deadline(timeout);
    stream.sock.set_read_deadline(deadline);
    stream.sock.set_write_deadline(deadline);
    while stream.conn.is_handshaking() {
        budget.poll_timeout(deadline, PinnedHttpError::TlsTimeout)?;
        match stream.conn.complete_io(&mut stream.sock) {
            Ok(_) => {}
            Err(error) if timed_out(&error) => {}
            Err(_) => return Err(PinnedHttpError::TlsFailed),
        }
    }
    Ok(stream)
}

fn write_request(
    wire: &mut Wire,
    head: &[u8],
    body: &[u8],
    budget: &RequestBudget<'_>,
    timeout: Duration,
) -> Result<(), PinnedHttpError> {
    let deadline = budget.stage_deadline(timeout);
    write_all(wire, head, budget, deadline)?;
    write_all(wire, body, budget, deadline)?;
    loop {
        budget.poll_timeout(deadline, PinnedHttpError::WriteTimeout)?;
        wire.socket_mut().set_write_deadline(deadline);
        match wire.flush() {
            Ok(()) => return Ok(()),
            Err(error) if timed_out(&error) => {}
            Err(error) if error.kind() == io::ErrorKind::Interrupted => {}
            Err(_) => return Err(PinnedHttpError::WriteFailed),
        }
    }
}

fn write_all(
    wire: &mut Wire,
    mut bytes: &[u8],
    budget: &RequestBudget<'_>,
    deadline: Instant,
) -> Result<(), PinnedHttpError> {
    while !bytes.is_empty() {
        budget.poll_timeout(deadline, PinnedHttpError::WriteTimeout)?;
        wire.socket_mut().set_write_deadline(deadline);
        match wire.write(bytes) {
            Ok(0) => return Err(PinnedHttpError::WriteFailed),
            Ok(written) => bytes = &bytes[written..],
            Err(error) if timed_out(&error) => {}
            Err(error) if error.kind() == io::ErrorKind::Interrupted => {}
            Err(_) => return Err(PinnedHttpError::WriteFailed),
        }
    }
    Ok(())
}

fn read_response(
    wire: &mut Wire,
    budget: &RequestBudget<'_>,
    config: &PinnedHttpTransportConfig,
    is_head: bool,
) -> Result<InboundResponse, PinnedHttpError> {
    let mut bytes = Vec::with_capacity(READ_BUFFER_BYTES);
    let mut total_header_bytes = 0_usize;
    let mut total_header_count = 0_usize;
    let mut informational = 0_usize;
    let (status, mut headers, header_end) = loop {
        let remaining_bytes = config
            .max_response_header_bytes
            .saturating_sub(total_header_bytes);
        let header_end = read_head_end(wire, budget, config, &mut bytes, remaining_bytes)?;
        let remaining_headers = config
            .max_response_headers
            .get()
            .saturating_sub(total_header_count);
        let head = parse_response_head(&bytes[..header_end], remaining_headers)?;
        total_header_bytes = total_header_bytes
            .checked_add(header_end)
            .ok_or(PinnedHttpError::ResponseHeadersTooLarge)?;
        total_header_count = total_header_count
            .checked_add(head.headers.len())
            .ok_or(PinnedHttpError::TooManyResponseHeaders)?;
        if total_header_bytes > config.max_response_header_bytes {
            return Err(PinnedHttpError::ResponseHeadersTooLarge);
        }
        if total_header_count > config.max_response_headers.get() {
            return Err(PinnedHttpError::TooManyResponseHeaders);
        }
        if head.status >= 200 {
            break (head.status, head.headers, header_end);
        }
        if head.status == 101 || informational == MAX_INFORMATIONAL_RESPONSES {
            return Err(PinnedHttpError::Protocol);
        }
        informational = informational.saturating_add(1);
        bytes.drain(..header_end);
    };

    let framing = response_framing(status, &headers, is_head)?;
    let pending = VecDeque::from(bytes[header_end..].to_vec());
    let mut input = ResponseInput {
        wire,
        pending,
        budget,
        read_timeout: config.read_timeout,
    };
    let (body, trailers) = read_body(
        &mut input,
        framing,
        total_header_count,
        total_header_bytes,
        config,
    )?;
    headers.extend(trailers);
    Ok(InboundResponse {
        status,
        headers,
        body,
    })
}

struct ParsedHead {
    status: u16,
    headers: Vec<HeaderPair>,
}

fn read_head_end(
    wire: &mut Wire,
    budget: &RequestBudget<'_>,
    config: &PinnedHttpTransportConfig,
    bytes: &mut Vec<u8>,
    limit: usize,
) -> Result<usize, PinnedHttpError> {
    loop {
        if let Some(end) = find_double_crlf(bytes) {
            if end > limit {
                return Err(PinnedHttpError::ResponseHeadersTooLarge);
            }
            return Ok(end);
        }
        if bytes.len() > limit {
            return Err(PinnedHttpError::ResponseHeadersTooLarge);
        }
        let mut buffer = [0_u8; READ_BUFFER_BYTES];
        let read = read_once(wire, &mut buffer, budget, config.read_timeout)?;
        if read == 0 {
            return Err(PinnedHttpError::Protocol);
        }
        bytes.extend_from_slice(&buffer[..read]);
    }
}

fn parse_response_head(bytes: &[u8], max_headers: usize) -> Result<ParsedHead, PinnedHttpError> {
    let mut storage = vec![httparse::EMPTY_HEADER; max_headers];
    let mut response = httparse::Response::new(&mut storage);
    let parsed = response.parse(bytes).map_err(|error| match error {
        httparse::Error::TooManyHeaders => PinnedHttpError::TooManyResponseHeaders,
        _ => PinnedHttpError::Protocol,
    })?;
    if !parsed.is_complete() || response.version != Some(1) {
        return Err(PinnedHttpError::Protocol);
    }
    let status = response.code.ok_or(PinnedHttpError::Protocol)?;
    let mut headers = Vec::with_capacity(response.headers.len());
    for header in response.headers {
        let value = str::from_utf8(header.value).map_err(|_| PinnedHttpError::Protocol)?;
        headers.push((header.name.to_owned(), value.to_owned()));
    }
    Ok(ParsedHead { status, headers })
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum BodyFraming {
    None,
    ContentLength(usize),
    Chunked,
    UntilEof,
}

fn response_framing(
    status: u16,
    headers: &[(String, String)],
    is_head: bool,
) -> Result<BodyFraming, PinnedHttpError> {
    if is_head || status == 204 || status == 304 {
        return Ok(BodyFraming::None);
    }
    let mut content_length = None;
    let mut transfer_encoding = None;
    for (name, value) in headers {
        if name.eq_ignore_ascii_case("content-length") {
            let parsed = value
                .trim()
                .parse::<usize>()
                .map_err(|_| PinnedHttpError::Protocol)?;
            if content_length.is_some_and(|existing| existing != parsed) {
                return Err(PinnedHttpError::Protocol);
            }
            content_length = Some(parsed);
        } else if name.eq_ignore_ascii_case("transfer-encoding") {
            if transfer_encoding.is_some() {
                return Err(PinnedHttpError::Protocol);
            }
            transfer_encoding = Some(value.trim());
        }
    }
    match (transfer_encoding, content_length) {
        (Some(value), None) if value.eq_ignore_ascii_case("chunked") => Ok(BodyFraming::Chunked),
        (Some(_), Some(_) | None) => Err(PinnedHttpError::Protocol),
        (None, Some(length)) => Ok(BodyFraming::ContentLength(length)),
        (None, None) => Ok(BodyFraming::UntilEof),
    }
}

struct ResponseInput<'a, 'b> {
    wire: &'a mut Wire,
    pending: VecDeque<u8>,
    budget: &'b RequestBudget<'b>,
    read_timeout: Duration,
}

type HeaderPair = (String, String);
type BodyAndTrailers = (Vec<u8>, Vec<HeaderPair>);

impl ResponseInput<'_, '_> {
    fn fill(&mut self) -> Result<bool, PinnedHttpError> {
        let mut buffer = [0_u8; READ_BUFFER_BYTES];
        let read = read_once(self.wire, &mut buffer, self.budget, self.read_timeout)?;
        self.pending.extend(&buffer[..read]);
        Ok(read != 0)
    }

    fn read_line(&mut self, limit: usize) -> Result<Vec<u8>, PinnedHttpError> {
        let mut line = Vec::new();
        loop {
            while let Some(byte) = self.pending.pop_front() {
                line.push(byte);
                if line.len() > limit {
                    return Err(PinnedHttpError::Protocol);
                }
                if line.ends_with(b"\r\n") {
                    line.truncate(line.len() - 2);
                    return Ok(line);
                }
            }
            if !self.fill()? {
                return Err(PinnedHttpError::Protocol);
            }
        }
    }

    fn append_exact(
        &mut self,
        destination: &mut Vec<u8>,
        mut length: usize,
        limit: usize,
    ) -> Result<(), PinnedHttpError> {
        let final_len = destination
            .len()
            .checked_add(length)
            .ok_or(PinnedHttpError::ResponseBodyTooLarge)?;
        if final_len > limit {
            return Err(PinnedHttpError::ResponseBodyTooLarge);
        }
        while length > 0 {
            if self.pending.is_empty() && !self.fill()? {
                return Err(PinnedHttpError::Protocol);
            }
            let available = length.min(self.pending.len());
            destination.extend(self.pending.drain(..available));
            length -= available;
        }
        Ok(())
    }
}

fn read_body(
    input: &mut ResponseInput<'_, '_>,
    framing: BodyFraming,
    header_count: usize,
    header_bytes: usize,
    config: &PinnedHttpTransportConfig,
) -> Result<BodyAndTrailers, PinnedHttpError> {
    match framing {
        BodyFraming::None if input.pending.is_empty() => Ok((Vec::new(), Vec::new())),
        BodyFraming::None => Err(PinnedHttpError::Protocol),
        BodyFraming::ContentLength(length) => {
            if length > config.max_response_body_bytes {
                return Err(PinnedHttpError::ResponseBodyTooLarge);
            }
            let mut body = Vec::with_capacity(length);
            input.append_exact(&mut body, length, config.max_response_body_bytes)?;
            if input.pending.is_empty() {
                Ok((body, Vec::new()))
            } else {
                Err(PinnedHttpError::Protocol)
            }
        }
        BodyFraming::UntilEof => {
            let mut body = Vec::new();
            loop {
                let available = input.pending.len();
                if available > 0 {
                    input.append_exact(&mut body, available, config.max_response_body_bytes)?;
                }
                if !input.fill()? {
                    return Ok((body, Vec::new()));
                }
            }
        }
        BodyFraming::Chunked => read_chunked(input, header_count, header_bytes, config),
    }
}

fn read_chunked(
    input: &mut ResponseInput<'_, '_>,
    header_count: usize,
    header_bytes: usize,
    config: &PinnedHttpTransportConfig,
) -> Result<BodyAndTrailers, PinnedHttpError> {
    let mut body = Vec::new();
    loop {
        let line = input.read_line(MAX_CHUNK_LINE_BYTES)?;
        let size = line
            .split(|byte| *byte == b';')
            .next()
            .and_then(|value| str::from_utf8(value).ok())
            .and_then(|value| usize::from_str_radix(value.trim(), 16).ok())
            .ok_or(PinnedHttpError::Protocol)?;
        if size == 0 {
            break;
        }
        input.append_exact(&mut body, size, config.max_response_body_bytes)?;
        if input.read_line(2)? != b"" {
            return Err(PinnedHttpError::Protocol);
        }
    }

    let mut trailers = Vec::new();
    let mut trailer_bytes = 0_usize;
    loop {
        let line = input.read_line(config.max_response_header_bytes)?;
        trailer_bytes = trailer_bytes
            .checked_add(line.len() + 2)
            .ok_or(PinnedHttpError::ResponseHeadersTooLarge)?;
        if header_bytes
            .checked_add(trailer_bytes)
            .is_none_or(|total| total > config.max_response_header_bytes)
        {
            return Err(PinnedHttpError::ResponseHeadersTooLarge);
        }
        if line.is_empty() {
            break;
        }
        if header_count + trailers.len() >= config.max_response_headers.get() {
            return Err(PinnedHttpError::TooManyResponseHeaders);
        }
        let separator = line
            .iter()
            .position(|byte| *byte == b':')
            .ok_or(PinnedHttpError::Protocol)?;
        let name =
            HeaderName::from_bytes(&line[..separator]).map_err(|_| PinnedHttpError::Protocol)?;
        let value = HeaderValue::from_bytes(&line[separator + 1..])
            .map_err(|_| PinnedHttpError::Protocol)?;
        let value = value.to_str().map_err(|_| PinnedHttpError::Protocol)?;
        trailers.push((name.as_str().to_owned(), value.trim().to_owned()));
    }
    if input.pending.is_empty() {
        Ok((body, trailers))
    } else {
        Err(PinnedHttpError::Protocol)
    }
}

fn read_once(
    wire: &mut Wire,
    buffer: &mut [u8],
    budget: &RequestBudget<'_>,
    timeout: Duration,
) -> Result<usize, PinnedHttpError> {
    let deadline = budget.stage_deadline(timeout);
    loop {
        budget.poll_timeout(deadline, PinnedHttpError::ReadTimeout)?;
        wire.socket_mut().set_read_deadline(deadline);
        match wire.read(buffer) {
            Ok(read) => return Ok(read),
            Err(error) if timed_out(&error) => {}
            Err(error) if error.kind() == io::ErrorKind::Interrupted => {}
            Err(_) => return Err(PinnedHttpError::ReadFailed),
        }
    }
}

fn find_double_crlf(bytes: &[u8]) -> Option<usize> {
    bytes
        .windows(4)
        .position(|window| window == b"\r\n\r\n")
        .map(|index| index + 4)
}

fn timed_out(error: &io::Error) -> bool {
    matches!(
        error.kind(),
        io::ErrorKind::TimedOut | io::ErrorKind::WouldBlock
    )
}

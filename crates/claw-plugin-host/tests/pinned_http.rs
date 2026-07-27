//! Production fixed-address HTTP/TLS transport behavior.

use std::io::{Read, Write};
use std::net::{IpAddr, Ipv4Addr, SocketAddr, TcpListener, TcpStream};
use std::num::NonZeroUsize;
use std::sync::{Arc, Mutex, PoisonError};
use std::thread::JoinHandle;
use std::time::{Duration, Instant};

use claw_plugin_host::{
    CancellationToken, HostCallControl, OutboundRequest, PinnedHttpError, PinnedHttpTransport,
    PinnedHttpTransportConfig,
};
use rustls::{ServerConfig, ServerConnection, StreamOwned};
use rustls_pki_types::pem::PemObject;
use rustls_pki_types::{CertificateDer, PrivateKeyDer};

const CERTIFICATE_PEM: &[u8] = include_bytes!("fixtures/http-test-cert.pem");
const CA_PEM: &[u8] = include_bytes!("fixtures/http-test-ca.pem");
const PRIVATE_KEY_PEM: &[u8] = include_bytes!("fixtures/http-test-key.pem");

#[derive(Clone, Debug, Default)]
struct Capture {
    request: Arc<Mutex<Option<String>>>,
    sni: Arc<Mutex<Option<String>>>,
}

impl Capture {
    fn request(&self) -> String {
        self.request
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .clone()
            .expect("server captured a request")
    }

    fn sni(&self) -> String {
        self.sni
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .clone()
            .expect("server captured SNI")
    }
}

fn control(timeout: Duration) -> HostCallControl {
    HostCallControl::new(Instant::now() + timeout, None)
}

fn request(scheme: &str, host: &str, address: SocketAddr) -> OutboundRequest {
    let url_host = if host.parse::<std::net::Ipv6Addr>().is_ok() {
        format!("[{host}]")
    } else {
        host.to_owned()
    };
    OutboundRequest {
        method: "GET".to_owned(),
        url: format!("{scheme}://{url_host}:{}/probe?fixed=true", address.port()),
        host: host.to_owned(),
        port: address.port(),
        addresses: vec![address.ip()],
        headers: vec![("x-client".to_owned(), "fixture".to_owned())],
        body: None,
    }
}

fn spawn_plain(handler: impl FnOnce(TcpStream) + Send + 'static) -> (SocketAddr, JoinHandle<()>) {
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).expect("bind loopback");
    let address = listener.local_addr().expect("listener address");
    let handle = std::thread::spawn(move || {
        let (stream, _) = listener.accept().expect("accept one request");
        handler(stream);
    });
    (address, handle)
}

fn spawn_response(response: Vec<u8>) -> (SocketAddr, Capture, JoinHandle<()>) {
    let capture = Capture::default();
    let server_capture = capture.clone();
    let (address, handle) = spawn_plain(move |mut stream| {
        let request = read_request(&mut stream);
        *server_capture
            .request
            .lock()
            .unwrap_or_else(PoisonError::into_inner) = Some(request);
        let _ = stream.write_all(&response);
        let _ = stream.flush();
    });
    (address, capture, handle)
}

fn spawn_tls_response(response: Vec<u8>) -> (SocketAddr, Capture, JoinHandle<()>) {
    let certificate = CertificateDer::from_pem_slice(CERTIFICATE_PEM).expect("fixture certificate");
    let private_key = PrivateKeyDer::from_pem_slice(PRIVATE_KEY_PEM).expect("fixture key");
    let config =
        ServerConfig::builder_with_provider(Arc::new(rustls::crypto::ring::default_provider()))
            .with_safe_default_protocol_versions()
            .expect("TLS versions")
            .with_no_client_auth()
            .with_single_cert(vec![certificate], private_key)
            .expect("server certificate");
    let capture = Capture::default();
    let server_capture = capture.clone();
    let (address, handle) = spawn_plain(move |stream| {
        let connection = ServerConnection::new(Arc::new(config)).expect("server TLS connection");
        let mut stream = StreamOwned::new(connection, stream);
        let request = read_request(&mut stream);
        *server_capture
            .request
            .lock()
            .unwrap_or_else(PoisonError::into_inner) = Some(request);
        *server_capture
            .sni
            .lock()
            .unwrap_or_else(PoisonError::into_inner) = stream.conn.server_name().map(str::to_owned);
        let _ = stream.write_all(&response);
        let _ = stream.flush();
    });
    (address, capture, handle)
}

fn read_request(stream: &mut impl Read) -> String {
    let mut bytes = Vec::new();
    let mut buffer = [0_u8; 1024];
    loop {
        let read = stream.read(&mut buffer).expect("read request");
        if read == 0 {
            break;
        }
        bytes.extend_from_slice(&buffer[..read]);
        if let Some(header_end) = bytes
            .windows(4)
            .position(|window| window == b"\r\n\r\n")
            .map(|position| position + 4)
        {
            let headers = String::from_utf8_lossy(&bytes[..header_end]);
            let content_length = headers
                .lines()
                .find_map(|line| {
                    line.strip_prefix("Content-Length:")
                        .and_then(|value| value.trim().parse::<usize>().ok())
                })
                .unwrap_or(0);
            if bytes.len() >= header_end + content_length {
                break;
            }
        }
    }
    String::from_utf8(bytes).expect("fixture request is UTF-8")
}

fn build_transport(config: PinnedHttpTransportConfig) -> PinnedHttpTransport {
    PinnedHttpTransport::new(config).expect("transport")
}

#[test]
fn fixed_address_https_uses_the_canonical_host_for_host_and_sni() {
    let (address, capture, server) =
        spawn_tls_response(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok".to_vec());
    let certificate = CertificateDer::from_pem_slice(CA_PEM).expect("fixture CA certificate");
    let transport = build_transport(
        PinnedHttpTransportConfig::new().with_root_certificate_der(certificate.as_ref().to_vec()),
    );

    let response = transport
        .send_request(
            request("https", "fixed.test", address),
            &control(Duration::from_secs(2)),
        )
        .expect("HTTPS response");
    server.join().expect("TLS server");

    assert_eq!(response.status, 200);
    assert_eq!(response.body, b"ok");
    let request = capture.request();
    assert!(request.starts_with("GET /probe?fixed=true HTTP/1.1\r\n"));
    assert!(request.contains(&format!("\r\nHost: fixed.test:{}\r\n", address.port())));
    assert_eq!(capture.sni(), "fixed.test");
}

#[test]
fn plaintext_requires_explicit_loopback_policy() {
    let address = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 9);
    let denied = build_transport(PinnedHttpTransportConfig::new());
    assert_eq!(
        denied.send_request(
            request("http", "localhost", address),
            &control(Duration::from_secs(1)),
        ),
        Err(PinnedHttpError::PlaintextDenied)
    );

    let (address, capture, server) =
        spawn_response(b"HTTP/1.1 204 No Content\r\nContent-Length: 0\r\n\r\n".to_vec());
    let allowed = build_transport(PinnedHttpTransportConfig::new().allow_loopback_http(true));
    let response = allowed
        .send_request(
            request("http", "localhost", address),
            &control(Duration::from_secs(1)),
        )
        .expect("loopback response");
    server.join().expect("plain server");
    assert_eq!(response.status, 204);
    assert!(capture.request().contains("Host: localhost:"));
}

#[test]
fn redirect_is_returned_without_a_second_connection() {
    let response = concat!(
        "HTTP/1.1 302 Found\r\n",
        "Location: http://localhost:1/elsewhere\r\n",
        "Content-Length: 0\r\n\r\n",
    )
    .as_bytes()
    .to_vec();
    let (address, _, server) = spawn_response(response);
    let transport = build_transport(PinnedHttpTransportConfig::new().allow_loopback_http(true));
    let response = transport
        .send_request(
            request("http", "localhost", address),
            &control(Duration::from_secs(1)),
        )
        .expect("redirect response");
    server.join().expect("redirect server");
    assert_eq!(response.status, 302);
    assert_eq!(
        response
            .headers
            .iter()
            .find(|(name, _)| name.eq_ignore_ascii_case("location"))
            .map(|(_, value)| value.as_str()),
        Some("http://localhost:1/elsewhere")
    );
}

#[test]
fn response_header_and_body_limits_fail_before_unbounded_buffering() {
    let oversized_header = format!(
        "HTTP/1.1 200 OK\r\nx-large: {}\r\nContent-Length: 0\r\n\r\n",
        "a".repeat(1100)
    )
    .into_bytes();
    let (address, _, server) = spawn_response(oversized_header);
    let transport = build_transport(
        PinnedHttpTransportConfig::new()
            .allow_loopback_http(true)
            .with_max_response_header_bytes(1024),
    );
    assert_eq!(
        transport.send_request(
            request("http", "localhost", address),
            &control(Duration::from_secs(1)),
        ),
        Err(PinnedHttpError::ResponseHeadersTooLarge)
    );
    server.join().expect("header server");

    let (address, _, server) =
        spawn_response(b"HTTP/1.1 200 OK\r\nContent-Length: 8\r\n\r\n12345678".to_vec());
    let transport = build_transport(
        PinnedHttpTransportConfig::new()
            .allow_loopback_http(true)
            .with_max_response_body_bytes(4),
    );
    assert_eq!(
        transport.send_request(
            request("http", "localhost", address),
            &control(Duration::from_secs(1)),
        ),
        Err(PinnedHttpError::ResponseBodyTooLarge)
    );
    server.join().expect("body server");
}

#[test]
fn request_header_and_body_limits_fail_before_connecting() {
    let address = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 9);
    let transport = build_transport(
        PinnedHttpTransportConfig::new()
            .allow_loopback_http(true)
            .with_max_request_header_bytes(1024)
            .with_max_request_body_bytes(4),
    );
    let mut oversized_header = request("http", "localhost", address);
    oversized_header
        .headers
        .push(("x-large".to_owned(), "a".repeat(1100)));
    assert_eq!(
        transport.send_request(oversized_header, &control(Duration::from_secs(1))),
        Err(PinnedHttpError::RequestHeadersTooLarge)
    );

    let mut oversized_body = request("http", "localhost", address);
    oversized_body.method = "POST".to_owned();
    oversized_body.body = Some(vec![0; 5]);
    assert_eq!(
        transport.send_request(oversized_body, &control(Duration::from_secs(1))),
        Err(PinnedHttpError::RequestBodyTooLarge)
    );
}

#[test]
fn response_header_count_and_chunked_body_are_bounded() {
    let (address, _, server) = spawn_response(
        concat!(
            "HTTP/1.1 200 OK\r\n",
            "x-one: 1\r\n",
            "x-two: 2\r\n",
            "Content-Length: 0\r\n\r\n",
        )
        .as_bytes()
        .to_vec(),
    );
    let transport = build_transport(
        PinnedHttpTransportConfig::new()
            .allow_loopback_http(true)
            .with_max_response_headers(NonZeroUsize::new(2).expect("two is non-zero")),
    );
    assert_eq!(
        transport.send_request(
            request("http", "localhost", address),
            &control(Duration::from_secs(1)),
        ),
        Err(PinnedHttpError::TooManyResponseHeaders)
    );
    server.join().expect("header-count server");

    let (address, _, server) = spawn_response(
        concat!(
            "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n",
            "2\r\nok\r\n0\r\nx-finished: yes\r\n\r\n",
        )
        .as_bytes()
        .to_vec(),
    );
    let transport = build_transport(PinnedHttpTransportConfig::new().allow_loopback_http(true));
    let response = transport
        .send_request(
            request("http", "localhost", address),
            &control(Duration::from_secs(1)),
        )
        .expect("chunked response");
    server.join().expect("chunked server");
    assert_eq!(response.body, b"ok");
    assert!(
        response
            .headers
            .contains(&("x-finished".to_owned(), "yes".to_owned()))
    );
}

#[test]
fn head_and_informational_responses_follow_http11_framing() {
    let (address, _, server) =
        spawn_response(b"HTTP/1.1 200 OK\r\nContent-Length: 99\r\n\r\n".to_vec());
    let transport = build_transport(PinnedHttpTransportConfig::new().allow_loopback_http(true));
    let mut head = request("http", "localhost", address);
    head.method = "HEAD".to_owned();
    let response = transport
        .send_request(head, &control(Duration::from_secs(1)))
        .expect("HEAD response");
    server.join().expect("HEAD server");
    assert_eq!(response.status, 200);
    assert!(response.body.is_empty());

    let (address, _, server) = spawn_response(
        concat!(
            "HTTP/1.1 103 Early Hints\r\nLink: </style.css>; rel=preload\r\n\r\n",
            "HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok",
        )
        .as_bytes()
        .to_vec(),
    );
    let response = transport
        .send_request(
            request("http", "localhost", address),
            &control(Duration::from_secs(1)),
        )
        .expect("final response after informational response");
    server.join().expect("informational server");
    assert_eq!(response.status, 200);
    assert_eq!(response.body, b"ok");

    let (address, _, server) = spawn_response(
        concat!(
            "HTTP/1.1 103 Early Hints\r\nLink: </style.css>\r\n\r\n",
            "HTTP/1.1 204 No Content\r\n\r\n",
        )
        .as_bytes()
        .to_vec(),
    );
    let one_header = build_transport(
        PinnedHttpTransportConfig::new()
            .allow_loopback_http(true)
            .with_max_response_headers(NonZeroUsize::new(1).expect("one is non-zero")),
    );
    let response = one_header
        .send_request(
            request("http", "localhost", address),
            &control(Duration::from_secs(1)),
        )
        .expect("headerless final response fits the shared header count");
    server.join().expect("header-count boundary server");
    assert_eq!(response.status, 204);
}

#[test]
fn ipv6_literal_authority_is_normalized_before_fixed_address_connect() {
    let Ok(listener) = TcpListener::bind((std::net::Ipv6Addr::LOCALHOST, 0)) else {
        return;
    };
    let address = listener.local_addr().expect("IPv6 listener address");
    let server = std::thread::spawn(move || {
        let (mut stream, _) = listener.accept().expect("accept IPv6 request");
        let _ = read_request(&mut stream);
        let _ = stream.write_all(b"HTTP/1.1 204 No Content\r\nContent-Length: 0\r\n\r\n");
    });
    let transport = build_transport(PinnedHttpTransportConfig::new().allow_loopback_http(true));
    let response = transport
        .send_request(
            request("http", "::1", address),
            &control(Duration::from_secs(1)),
        )
        .expect("IPv6 response");
    server.join().expect("IPv6 server");
    assert_eq!(response.status, 204);
}

#[test]
fn guest_deadline_and_cancellation_interrupt_a_blocked_read() {
    let (address, server) = spawn_plain(|mut stream| {
        let _ = read_request(&mut stream);
        std::thread::sleep(Duration::from_millis(200));
    });
    let transport = build_transport(
        PinnedHttpTransportConfig::new()
            .allow_loopback_http(true)
            .with_read_timeout(Duration::from_secs(2)),
    );
    assert_eq!(
        transport.send_request(
            request("http", "localhost", address),
            &control(Duration::from_millis(40)),
        ),
        Err(PinnedHttpError::DeadlineExceeded)
    );
    server.join().expect("deadline server");

    let (address, server) = spawn_plain(|mut stream| {
        let _ = read_request(&mut stream);
        std::thread::sleep(Duration::from_millis(200));
    });
    let cancellation = CancellationToken::new();
    let canceller = cancellation.clone();
    let thread = std::thread::spawn(move || {
        std::thread::sleep(Duration::from_millis(30));
        canceller.cancel();
    });
    let call = HostCallControl::new(Instant::now() + Duration::from_secs(2), Some(cancellation));
    assert_eq!(
        transport.send_request(request("http", "localhost", address), &call),
        Err(PinnedHttpError::Cancelled)
    );
    thread.join().expect("canceller");
    server.join().expect("cancellation server");
}

#[test]
fn overall_deadline_is_absolute_even_when_the_peer_trickles_progress() {
    let (address, server) = spawn_plain(|mut stream| {
        let _ = read_request(&mut stream);
        for byte in b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok" {
            if stream.write_all(&[*byte]).is_err() {
                break;
            }
            std::thread::sleep(Duration::from_millis(10));
        }
    });
    let transport = build_transport(
        PinnedHttpTransportConfig::new()
            .allow_loopback_http(true)
            .with_read_timeout(Duration::from_secs(1)),
    );
    assert_eq!(
        transport.send_request(
            request("http", "localhost", address),
            &control(Duration::from_millis(50)),
        ),
        Err(PinnedHttpError::DeadlineExceeded)
    );
    server.join().expect("trickle server");
}

#[test]
fn request_and_error_debugging_never_leak_header_values_or_bodies() {
    let (address, server) = spawn_plain(|mut stream| {
        let _ = read_request(&mut stream);
    });
    let transport = build_transport(PinnedHttpTransportConfig::new().allow_loopback_http(true));
    let mut request = request("http", "localhost", address);
    request.url.push_str("&token=super-secret");
    request
        .headers
        .push(("x-secret".to_owned(), "super-secret".to_owned()));
    request.body = Some(b"super-secret-body".to_vec());
    request.method = "POST".to_owned();
    let debug = format!("{request:?}");
    assert!(!debug.contains("super-secret"));
    assert!(!debug.contains("super-secret-body"));
    assert!(debug.contains("[REDACTED]"));

    let error = transport
        .send_request(request, &control(Duration::from_secs(1)))
        .expect_err("server closes without a response")
        .to_string();
    server.join().expect("redaction server");
    assert!(!error.contains("super-secret"));
    assert!(!error.contains("super-secret-body"));
}

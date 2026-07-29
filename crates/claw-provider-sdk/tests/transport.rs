//! Wire-level tests for [`claw_provider_sdk::http`].
//!
//! These run against a loopback HTTP/1.1 server started by the test itself, so
//! no third-party API is ever contacted. They cover the three behaviours that
//! cannot be proven by unit tests over recorded bytes: that a request is put on
//! the wire in the shape the client asked for, that a streaming body is
//! delivered incrementally, and that cancelling an in-flight request actually
//! closes the TCP connection instead of merely dropping a future.

mod support;

use std::time::Duration;

use claw_provider_sdk::cancel::CancelToken;
use claw_provider_sdk::error::{ErrorKind, Operation};
use claw_provider_sdk::http::{
    Body, DirectReason, HttpRequest, HttpTransport, MAX_BUFFERED_RESPONSE_BYTES, Method,
    ProxyDecision, ProxyPolicy, ProxyScheme, ProxyUrl, TlsPolicy, TransportConfig,
};
use claw_provider_sdk::secret::SecretString;
use futures_util::StreamExt as _;
use support::proxy::TestProxy;
use support::{Reply, TestServer};

fn transport() -> HttpTransport {
    HttpTransport::with_config(&TransportConfig {
        tls_policy: TlsPolicy::AllowLoopbackPlaintext,
        ..TransportConfig::default()
    })
    .expect("build transport")
}

#[tokio::test]
async fn a_request_reaches_the_wire_with_its_method_target_headers_and_body() {
    let server = TestServer::start(vec![Reply::json(r#"{"ok":true}"#)]).await;
    let transport = transport();
    let cancel = CancelToken::new();

    let response = transport
        .send(
            "test",
            Operation::Complete,
            HttpRequest::new(Method::Post, server.url("v1/chat/completions?beta=1"))
                .header("accept", "application/json")
                .secret_header("authorization", SecretString::new("Bearer sk-live-secret"))
                .body(Body::Json(r#"{"model":"m"}"#.to_owned())),
            &cancel,
        )
        .await
        .expect("request must succeed");

    assert_eq!(response.status(), 200);
    assert!(response.is_success());
    assert_eq!(response.body(), br#"{"ok":true}"#);
    assert_eq!(response.header("content-type"), Some("application/json"));

    let requests = server.requests().await;
    assert_eq!(requests.len(), 1);
    let request = &requests[0];
    assert_eq!(request.method, "POST");
    assert_eq!(request.target, "/v1/chat/completions?beta=1");
    assert_eq!(request.header("accept"), Some("application/json"));
    assert_eq!(
        request.header("authorization"),
        Some("Bearer sk-live-secret")
    );
    assert_eq!(request.header("content-type"), Some("application/json"));
    assert_eq!(request.header("content-length"), Some("13"));
    assert_eq!(request.body_text(), r#"{"model":"m"}"#);
}

#[tokio::test]
async fn a_form_body_is_sent_with_the_urlencoded_content_type() {
    let server = TestServer::start(vec![Reply::json(r#"{"ok":true}"#)]).await;
    let transport = transport();

    transport
        .send(
            "test",
            Operation::Authorize,
            HttpRequest::new(Method::Post, server.url("login/device/code"))
                .body(Body::Form("client_id=Iv1.x&scope=read%3Auser".to_owned())),
            &CancelToken::new(),
        )
        .await
        .expect("request must succeed");

    let requests = server.requests().await;
    assert_eq!(
        requests[0].header("content-type"),
        Some("application/x-www-form-urlencoded")
    );
    assert_eq!(requests[0].body_text(), "client_id=Iv1.x&scope=read%3Auser");
}

#[tokio::test]
async fn a_non_success_status_is_reported_with_its_body_and_retry_after() {
    let server = TestServer::start(vec![Reply::status_with_header(
        429,
        "retry-after",
        "7",
        r#"{"error":{"message":"slow down there","code":"rate_limit_exceeded"}}"#,
    )])
    .await;
    let transport = transport();

    let response = transport
        .send(
            "test",
            Operation::Complete,
            HttpRequest::new(Method::Post, server.url("v1/chat/completions")),
            &CancelToken::new(),
        )
        .await
        .expect("the transport returns the response; classification happens above it");

    assert_eq!(response.status(), 429);
    assert!(!response.is_success());
    assert_eq!(response.header("retry-after"), Some("7"));

    let error = claw_provider_sdk::http::error_from_response(
        "test",
        Operation::Complete,
        &response,
        std::time::SystemTime::UNIX_EPOCH,
    );
    assert_eq!(error.kind(), ErrorKind::RateLimit);
    assert_eq!(error.status(), Some(429));
    assert_eq!(error.detail(), "slow down there");
    assert_eq!(error.upstream_code(), Some("rate_limit_exceeded"));
    assert_eq!(error.retry_after(), Some(Duration::from_secs(7)));
}

#[tokio::test]
async fn a_buffered_exchange_shares_one_deadline_across_headers_and_body() {
    let phase_delay = Duration::from_millis(500);
    let request_timeout = Duration::from_millis(750);
    assert!(phase_delay < request_timeout);
    assert!(phase_delay + phase_delay > request_timeout);

    let server = TestServer::start(vec![Reply::delayed_chunked_json(
        phase_delay,
        phase_delay,
        &[r#"{"ok":true}"#],
    )])
    .await;

    let error = transport()
        .send(
            "test",
            Operation::Complete,
            HttpRequest::new(Method::Post, server.url("v1/chat/completions"))
                .timeout(request_timeout),
            &CancelToken::new(),
        )
        .await
        .expect_err("the combined header and body time must exceed one deadline");

    assert_eq!(error.kind(), ErrorKind::Timeout);
    assert_eq!(error.detail(), "the request exceeded its deadline");
    assert_eq!(
        server.response_headers_written(),
        1,
        "the header phase completed within its standalone budget"
    );
    assert_eq!(
        server.frames_written(),
        0,
        "the absolute deadline fired before the delayed body arrived"
    );
}

#[tokio::test]
async fn a_buffered_exchange_succeeds_when_all_phases_fit_one_deadline() {
    let server = TestServer::start(vec![Reply::delayed_chunked_json(
        Duration::from_millis(50),
        Duration::from_millis(50),
        &[r#"{"ok":true}"#],
    )])
    .await;

    let response = transport()
        .send(
            "test",
            Operation::Complete,
            HttpRequest::new(Method::Post, server.url("v1/chat/completions"))
                .timeout(Duration::from_millis(500)),
            &CancelToken::new(),
        )
        .await
        .expect("the complete exchange fits within the deadline");

    assert_eq!(response.body(), br#"{"ok":true}"#);
    assert_eq!(server.response_headers_written(), 1);
    assert_eq!(server.frames_written(), 1);
}

#[tokio::test]
async fn a_buffered_exchange_treats_duration_max_as_a_far_future_deadline() {
    let server = TestServer::start(vec![Reply::json(r#"{"ok":true}"#)]).await;

    let response = transport()
        .send(
            "test",
            Operation::Complete,
            HttpRequest::new(Method::Post, server.url("v1/chat/completions"))
                .timeout(Duration::MAX),
            &CancelToken::new(),
        )
        .await
        .expect("an unrepresentable timeout saturates instead of panicking");

    assert_eq!(response.body(), br#"{"ok":true}"#);
}

#[tokio::test]
async fn a_pre_cancelled_buffered_exchange_with_duration_max_is_cancelled() {
    let server = TestServer::start(vec![Reply::json("{}")]).await;
    let cancel = CancelToken::cancelled_token();

    let error = transport()
        .send(
            "test",
            Operation::Complete,
            HttpRequest::new(Method::Post, server.url("v1/chat/completions"))
                .timeout(Duration::MAX),
            &cancel,
        )
        .await
        .expect_err("cancellation has priority over an extreme timeout");

    assert_eq!(error.kind(), ErrorKind::Cancelled);
    assert_eq!(
        error.detail(),
        "the request was cancelled before a response arrived"
    );
    tokio::time::sleep(Duration::from_millis(50)).await;
    assert_eq!(server.request_count().await, 0);
}

#[tokio::test]
async fn a_chunked_body_is_delivered_incrementally_rather_than_buffered() {
    let server = TestServer::start(vec![Reply::sse(&[
        "data: {\"n\":1}\n\n",
        "data: {\"n\":2}\n\n",
        "data: [DONE]\n\n",
    ])])
    .await;
    let transport = transport();

    let stream = transport
        .send_streaming(
            "test",
            Operation::StreamCompletion,
            HttpRequest::new(Method::Post, server.url("v1/chat/completions")),
            &CancelToken::new(),
        )
        .await
        .expect("stream must open");

    assert_eq!(stream.status(), 200);
    assert!(stream.is_success());
    assert_eq!(stream.header("content-type"), Some("text/event-stream"));

    let mut chunks = stream.into_chunks();
    let mut collected: Vec<Vec<u8>> = Vec::new();
    while let Some(chunk) = chunks.next().await {
        collected.push(chunk.expect("chunk must decode").to_vec());
    }

    // The server flushed three chunks with a gap between them, so the client
    // must observe more than one chunk rather than one buffered body.
    assert!(
        collected.len() >= 2,
        "expected incremental delivery, got {} chunk(s)",
        collected.len()
    );
    let joined = collected.concat();
    assert_eq!(
        String::from_utf8(joined).expect("utf-8"),
        "data: {\"n\":1}\n\ndata: {\"n\":2}\n\ndata: [DONE]\n\n"
    );
}

#[tokio::test]
async fn a_streaming_exchange_treats_duration_max_as_a_far_future_deadline() {
    let server = TestServer::start(vec![Reply::sse(&["data: [DONE]\n\n"])]).await;

    let stream = transport()
        .send_streaming(
            "test",
            Operation::StreamCompletion,
            HttpRequest::new(Method::Post, server.url("v1/chat/completions"))
                .timeout(Duration::MAX),
            &CancelToken::new(),
        )
        .await
        .expect("an unrepresentable timeout saturates instead of panicking");

    let mut chunks = stream.into_chunks();
    let first = chunks
        .next()
        .await
        .expect("the response contains a chunk")
        .expect("the chunk decodes");
    assert_eq!(first, "data: [DONE]\n\n");
}

#[tokio::test]
async fn a_pre_cancelled_streaming_exchange_with_duration_max_is_cancelled() {
    let server = TestServer::start(vec![Reply::sse(&["data: [DONE]\n\n"])]).await;
    let cancel = CancelToken::cancelled_token();

    let result = transport()
        .send_streaming(
            "test",
            Operation::StreamCompletion,
            HttpRequest::new(Method::Post, server.url("v1/chat/completions"))
                .timeout(Duration::MAX),
            &cancel,
        )
        .await;
    let Err(error) = result else {
        panic!("cancellation must have priority over an extreme timeout");
    };

    assert_eq!(error.kind(), ErrorKind::Cancelled);
    assert_eq!(
        error.detail(),
        "the request was cancelled before a response arrived"
    );
    tokio::time::sleep(Duration::from_millis(50)).await;
    assert_eq!(server.request_count().await, 0);
}

#[tokio::test]
async fn cancelling_an_in_flight_stream_closes_the_socket() {
    let server = TestServer::start(vec![Reply::sse_hold(&[
        "data: {\"n\":1}\n\n",
        "data: {\"n\":2}\n\n",
    ])])
    .await;
    let transport = transport();
    let cancel = CancelToken::new();

    let stream = transport
        .send_streaming(
            "test",
            Operation::StreamCompletion,
            HttpRequest::new(Method::Post, server.url("v1/chat/completions")),
            &cancel,
        )
        .await
        .expect("stream must open");
    let mut chunks = stream.into_chunks();

    let first = chunks
        .next()
        .await
        .expect("a first chunk arrives")
        .expect("the first chunk decodes");
    assert!(!first.is_empty());
    assert!(!server.peer_closed(), "the socket is still open here");

    cancel.cancel();

    // The next poll observes cancellation and yields the typed error.
    let cancelled = chunks
        .next()
        .await
        .expect("a terminal item is produced")
        .expect_err("cancellation surfaces as an error");
    assert_eq!(cancelled.kind(), ErrorKind::Cancelled);
    assert_eq!(cancelled.operation(), Operation::StreamCompletion);

    drop(chunks);

    assert!(
        server.wait_for_peer_close(Duration::from_secs(5)).await,
        "the server never observed the client close the connection"
    );
}

#[tokio::test]
async fn cancelling_wakes_a_read_already_parked_on_a_silent_upstream() {
    // The interesting case is not "cancel, then poll" but "park, then cancel":
    // a task blocked inside the body read has only the connection's waker
    // registered, so unless the chunk stream also registers itself with the
    // token, `cancel()` from another task leaves this one parked indefinitely.
    let server = TestServer::start(vec![Reply::sse_hold(&["data: {\"n\":1}\n\n"])]).await;
    let transport = transport();
    let cancel = CancelToken::new();

    let stream = transport
        .send_streaming(
            "test",
            Operation::StreamCompletion,
            HttpRequest::new(Method::Post, server.url("v1/chat/completions")),
            &cancel,
        )
        .await
        .expect("stream must open");
    let mut chunks = stream.into_chunks();
    let first = chunks.next().await.expect("a first chunk arrives");
    assert!(!first.expect("the first chunk decodes").is_empty());

    // The server holds the socket open without writing, so this parks.
    let parked = tokio::spawn(async move {
        let item = chunks.next().await;
        // The stream is fused: the cancellation error is terminal, so a caller
        // that keeps polling terminates instead of spinning on repeats of it.
        let after = chunks.next().await;
        (item, after)
    });

    tokio::time::sleep(Duration::from_millis(50)).await;
    cancel.cancel();

    let (item, after) = tokio::time::timeout(Duration::from_secs(5), parked)
        .await
        .expect("the parked read is woken by cancellation")
        .expect("the reader task does not panic");
    let error = item
        .expect("a terminal item is produced")
        .expect_err("cancellation surfaces as an error");
    assert_eq!(error.kind(), ErrorKind::Cancelled);
    assert!(after.is_none(), "the stream ends after the terminal error");
}

#[tokio::test]
async fn a_silent_stream_hits_its_idle_deadline_and_closes_the_socket() {
    let server = TestServer::start(vec![Reply::sse_hold(&["data: {\"n\":1}\n\n"])]).await;
    let stream = transport()
        .send_streaming(
            "test",
            Operation::StreamCompletion,
            HttpRequest::new(Method::Post, server.url("v1/chat/completions"))
                .stream_idle_timeout(Duration::from_millis(50)),
            &CancelToken::new(),
        )
        .await
        .expect("stream must open");
    let mut chunks = stream.into_chunks();
    chunks
        .next()
        .await
        .expect("the first chunk arrives")
        .expect("the first chunk decodes");

    let error = tokio::time::timeout(Duration::from_secs(2), chunks.next())
        .await
        .expect("the idle deadline wakes the parked reader")
        .expect("the timeout is emitted as one terminal item")
        .expect_err("silence is a timeout");
    assert_eq!(error.kind(), ErrorKind::Timeout);
    assert_eq!(error.operation(), Operation::StreamCompletion);
    assert_eq!(
        error.detail(),
        "the streaming response exceeded its idle deadline"
    );
    assert_eq!(chunks.next().await, None);
    drop(chunks);

    assert!(
        server.wait_for_peer_close(Duration::from_secs(5)).await,
        "timing out the stream must close the TCP connection"
    );
}

#[tokio::test]
async fn a_body_larger_than_the_buffer_limit_is_refused_instead_of_being_held() {
    // The request deadline bounds how long an upstream may take, not how many
    // bytes it may send, so without a byte ceiling one response could exhaust
    // the host. Frames are 4 MiB so the server writes just past the limit
    // rather than materializing a second copy of it.
    const FRAME_BYTES: usize = 4 * 1024 * 1024;
    let frame = vec![b'a'; FRAME_BYTES];
    let frames = vec![frame; MAX_BUFFERED_RESPONSE_BYTES / FRAME_BYTES + 1];
    let server = TestServer::start(vec![Reply::Chunked {
        status: 200,
        content_type: "application/json".to_owned(),
        header_delay: Duration::ZERO,
        body_delay: Duration::ZERO,
        frames,
        hold_open: false,
    }])
    .await;

    let error = transport()
        .send(
            "test",
            Operation::Complete,
            HttpRequest::new(Method::Post, server.url("v1/chat/completions")),
            &CancelToken::new(),
        )
        .await
        .expect_err("an oversized body is refused");

    assert_eq!(error.kind(), ErrorKind::Protocol);
    assert!(
        error.detail().contains("buffer limit"),
        "the detail names the limit: {}",
        error.detail()
    );
}

#[tokio::test]
async fn dropping_a_stream_without_cancelling_also_closes_the_socket() {
    let server = TestServer::start(vec![Reply::sse_hold(&["data: {\"n\":1}\n\n"])]).await;
    let transport = transport();

    let stream = transport
        .send_streaming(
            "test",
            Operation::StreamCompletion,
            HttpRequest::new(Method::Post, server.url("v1/chat/completions")),
            &CancelToken::new(),
        )
        .await
        .expect("stream must open");
    let mut chunks = stream.into_chunks();
    chunks
        .next()
        .await
        .expect("a first chunk arrives")
        .expect("the first chunk decodes");

    drop(chunks);

    assert!(
        server.wait_for_peer_close(Duration::from_secs(5)).await,
        "dropping the body must close the connection"
    );
}

#[tokio::test]
async fn a_token_cancelled_before_the_call_never_opens_a_socket() {
    let server = TestServer::start(vec![Reply::json("{}")]).await;
    let transport = transport();
    let cancel = CancelToken::cancelled_token();

    let error = transport
        .send(
            "test",
            Operation::Complete,
            HttpRequest::new(Method::Post, server.url("v1/chat/completions")),
            &cancel,
        )
        .await
        .expect_err("a cancelled token must short-circuit");
    assert_eq!(error.kind(), ErrorKind::Cancelled);

    tokio::time::sleep(Duration::from_millis(50)).await;
    assert_eq!(
        server.request_count().await,
        0,
        "no request may reach the server"
    );
}

#[tokio::test]
async fn plaintext_loopback_is_only_reachable_under_the_relaxed_policy() {
    let server = TestServer::start(vec![Reply::json("{}")]).await;
    let strict = HttpTransport::new().expect("build transport");

    let error = strict
        .send(
            "test",
            Operation::Complete,
            HttpRequest::new(Method::Get, server.url("anything")),
            &CancelToken::new(),
        )
        .await
        .expect_err("the default policy refuses plaintext");
    assert_eq!(error.kind(), ErrorKind::InvalidRequest);
    assert_eq!(
        server.request_count().await,
        0,
        "the refusal must happen before any socket is opened"
    );
}

#[tokio::test]
async fn an_https_url_really_negotiates_tls_rather_than_falling_back_to_plaintext() {
    // The connector is hand-written on tokio-rustls, so the one thing that must
    // be proven on a live socket is that `https` genuinely enters a TLS
    // handshake. This server accepts the connection and answers with plaintext
    // HTTP; a client that had silently fallen back to cleartext would parse
    // that as a successful 200.
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind a loopback listener");
    let port = listener
        .local_addr()
        .expect("read the bound address")
        .port();
    let accepted = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let seen = std::sync::Arc::clone(&accepted);
    let first_bytes = std::sync::Arc::new(tokio::sync::Mutex::new(Vec::new()));
    let recorded = std::sync::Arc::clone(&first_bytes);
    tokio::spawn(async move {
        let Ok((mut socket, _)) = listener.accept().await else {
            return;
        };
        seen.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        let mut buffer = [0_u8; 64];
        if let Ok(read) = tokio::io::AsyncReadExt::read(&mut socket, &mut buffer).await {
            recorded.lock().await.extend_from_slice(&buffer[..read]);
        }
        let _ = tokio::io::AsyncWriteExt::write_all(
            &mut socket,
            b"HTTP/1.1 200 OK\r\ncontent-length: 2\r\n\r\nok",
        )
        .await;
        let _ = tokio::io::AsyncWriteExt::shutdown(&mut socket).await;
    });

    let url = url::Url::parse(&format!("https://127.0.0.1:{port}/v1/models"))
        .expect("build the https URL");
    let error = transport()
        .send(
            "test",
            Operation::ListModels,
            HttpRequest::new(Method::Get, url),
            &CancelToken::new(),
        )
        .await
        .expect_err("a plaintext answer cannot satisfy a TLS handshake");
    assert_eq!(error.kind(), ErrorKind::Transport);

    assert_eq!(
        accepted.load(std::sync::atomic::Ordering::SeqCst),
        1,
        "the client must have opened exactly one TCP connection"
    );
    let opening = first_bytes.lock().await.clone();
    assert_eq!(
        opening.first().copied(),
        Some(0x16),
        "the first record must be a TLS handshake, not an HTTP request line"
    );
    assert_eq!(
        opening.get(1..3),
        Some(&[0x03, 0x01][..]),
        "the handshake must open with the TLS 1.0 legacy record version"
    );
}

#[tokio::test]
async fn a_redirect_is_returned_to_the_caller_instead_of_replaying_the_credential() {
    // The transport does not follow redirects. That is deliberate: following a
    // 3xx would resend the `authorization` header to whatever host the response
    // named, defeating the origin binding that guards every stored credential.
    let server = TestServer::start(vec![Reply::status_with_header(
        302,
        "location",
        "https://attacker.example/v1/chat/completions",
        "",
    )])
    .await;

    let response = transport()
        .send(
            "test",
            Operation::Complete,
            HttpRequest::new(Method::Post, server.url("v1/chat/completions"))
                .secret_header("authorization", SecretString::new("sk-live-redirect"))
                .body(Body::Json(r#"{"model":"m"}"#.to_owned())),
            &CancelToken::new(),
        )
        .await
        .expect("the redirect must be surfaced, not followed");

    assert_eq!(response.status(), 302);
    assert_eq!(
        response.header("location"),
        Some("https://attacker.example/v1/chat/completions")
    );

    let requests = server.requests().await;
    assert_eq!(
        requests.len(),
        1,
        "the credential must be sent exactly once, to the origin the caller named"
    );
    assert_eq!(
        requests[0].header("authorization"),
        Some("sk-live-redirect")
    );
    assert_eq!(requests[0].target, "/v1/chat/completions");
}

// ---------------------------------------------------------------------------
// Proxy support.
//
// Only `https` destinations are tunnelled, so these tests cannot complete a
// handshake against the loopback proxy — there is no in-process TLS server.
// What they prove is everything that happens up to and including the first
// tunnel byte, which is where every proxy bug of consequence lives: the request
// line, the credential header, and whose identity the TLS session is about to
// authenticate.
// ---------------------------------------------------------------------------

/// Builds a transport that tunnels through `proxy_url`.
fn proxied_transport(proxy_url: String, no_proxy: Option<String>) -> HttpTransport {
    HttpTransport::with_config(&TransportConfig {
        tls_policy: TlsPolicy::AllowLoopbackPlaintext,
        proxy_policy: ProxyPolicy::Explicit {
            url: proxy_url,
            no_proxy,
        },
        connect_timeout: Duration::from_secs(5),
        ..TransportConfig::default()
    })
    .expect("build transport")
}

/// Issues a request that is expected to fail once the tunnel is open, because
/// the loopback proxy cannot terminate TLS.
async fn attempt_proxied_request(transport: &HttpTransport, url: &str) -> ErrorKind {
    let url = url::Url::parse(url).expect("parse the destination URL");
    transport
        .send(
            "test",
            Operation::Complete,
            HttpRequest::new(Method::Post, url)
                .secret_header("authorization", SecretString::new("sk-live-proxy"))
                .body(Body::Json(r#"{"model":"m"}"#.to_owned())),
            &CancelToken::new(),
        )
        .await
        .expect_err("no TLS peer exists behind the test proxy")
        .kind()
}

#[tokio::test]
async fn an_https_request_is_tunnelled_with_a_well_formed_connect_request() {
    let proxy = TestProxy::start(200).await;
    let transport = proxied_transport(proxy.url(None), None);

    attempt_proxied_request(&transport, "https://api.example.com/v1/chat/completions").await;

    assert!(
        proxy.wait_for_tunnels(1, Duration::from_secs(5)).await,
        "the request must reach the proxy"
    );
    let tunnels = proxy.tunnels().await;
    assert_eq!(tunnels.len(), 1);
    // Authority form, default port made explicit, and no scheme or path — an
    // absolute-form or origin-form request line here would be rejected by a
    // real proxy.
    assert_eq!(
        tunnels[0].request_line,
        "CONNECT api.example.com:443 HTTP/1.1"
    );
    assert_eq!(tunnels[0].header("host"), Some("api.example.com:443"));
    assert_eq!(tunnels[0].header("proxy-authorization"), None);
}

#[tokio::test]
async fn a_non_default_destination_port_is_preserved_in_the_connect_target() {
    let proxy = TestProxy::start(200).await;
    let transport = proxied_transport(proxy.url(None), None);

    attempt_proxied_request(&transport, "https://api.example.com:8443/v1/models").await;

    assert!(proxy.wait_for_tunnels(1, Duration::from_secs(5)).await);
    assert_eq!(
        proxy.tunnels().await[0].request_line,
        "CONNECT api.example.com:8443 HTTP/1.1"
    );
}

#[tokio::test]
async fn the_tunnelled_handshake_authenticates_the_destination_and_not_the_proxy() {
    // This is the property that makes proxying safe at all. The proxy sees only
    // a TLS record addressed to the destination's name, so it cannot read the
    // `authorization` header or impersonate the origin without a certificate
    // the platform trust store already accepts for that name.
    let proxy = TestProxy::start(200).await;
    let transport = proxied_transport(proxy.url(None), None);

    attempt_proxied_request(&transport, "https://api.openai.com/v1/chat/completions").await;

    assert!(proxy.wait_for_tunnels(1, Duration::from_secs(5)).await);
    let tunnels = proxy.tunnels().await;
    let first = tunnels[0].tunnelled.first().copied();
    assert_eq!(
        first,
        Some(0x16),
        "the first tunnel byte must be a TLS handshake record"
    );
    assert_eq!(
        tunnels[0].sni_host().as_deref(),
        Some("api.openai.com"),
        "the handshake must name the destination, never the proxy"
    );

    let sent = String::from_utf8_lossy(&tunnels[0].tunnelled).into_owned();
    assert!(
        !sent.contains("sk-live-proxy"),
        "the credential must never appear on the proxy-visible wire"
    );
    assert!(
        !sent.contains("authorization"),
        "no request header may precede the handshake"
    );
}

#[tokio::test]
async fn proxy_credentials_are_sent_as_basic_authentication() {
    let proxy = TestProxy::start(200).await;
    let transport = proxied_transport(proxy.url(Some("Aladdin:opensesame")), None);

    attempt_proxied_request(&transport, "https://api.example.com/v1/models").await;

    assert!(proxy.wait_for_tunnels(1, Duration::from_secs(5)).await);
    assert_eq!(
        proxy.tunnels().await[0].header("proxy-authorization"),
        Some("Basic QWxhZGRpbjpvcGVuc2VzYW1l")
    );
}

#[tokio::test]
async fn a_refused_tunnel_is_a_transport_error_that_leaks_no_proxy_credential() {
    let proxy = TestProxy::start(407).await;
    let proxy_url = proxy.url(Some("corp-user:corp-secret"));
    let transport = proxied_transport(proxy_url, None);

    let url = url::Url::parse("https://api.example.com/v1/models").expect("parse URL");
    let error = transport
        .send(
            "test",
            Operation::ListModels,
            HttpRequest::new(Method::Get, url),
            &CancelToken::new(),
        )
        .await
        .expect_err("a refused tunnel must fail");

    assert_eq!(error.kind(), ErrorKind::Transport);
    let rendered = format!("{error} {error:?}");
    assert!(
        !rendered.contains("corp-secret"),
        "the proxy password must not reach an error message: {rendered}"
    );
    assert!(
        !rendered.contains("corp-user"),
        "the proxy username must not reach an error message: {rendered}"
    );
}

#[tokio::test]
async fn a_loopback_destination_is_never_proxied() {
    // Loopback plaintext is the one case that would put an `authorization`
    // header on the wire in the clear, so it must bypass the proxy even though
    // the policy names no `NO_PROXY` entry at all.
    let proxy = TestProxy::start(200).await;
    let server = TestServer::start(vec![Reply::json(r#"{"ok":true}"#)]).await;
    let transport = proxied_transport(proxy.url(None), None);

    let response = transport
        .send(
            "test",
            Operation::Complete,
            HttpRequest::new(Method::Post, server.url("v1/chat/completions"))
                .secret_header("authorization", SecretString::new("sk-live-loopback"))
                .body(Body::Json("{}".to_owned())),
            &CancelToken::new(),
        )
        .await
        .expect("a loopback request must go direct");

    assert_eq!(response.status(), 200);
    assert_eq!(server.request_count().await, 1);
    assert_eq!(
        proxy.tunnels().await.len(),
        0,
        "the proxy must not have been contacted"
    );
}

#[tokio::test]
async fn a_no_proxy_entry_bypasses_the_tunnel() {
    let proxy = TestProxy::start(200).await;
    let transport = proxied_transport(proxy.url(None), Some("api.invalid".to_owned()));

    // `.invalid` is reserved by RFC 2606 and can never resolve, so the direct
    // attempt fails inside the resolver without a packet leaving the machine.
    // The assertion that matters is that the failure did not come via the proxy.
    let kind = attempt_proxied_request(&transport, "https://api.invalid/v1/models").await;
    assert_eq!(kind, ErrorKind::Transport);

    assert_eq!(
        proxy.tunnels().await.len(),
        0,
        "a NO_PROXY host must not be tunnelled"
    );
}

#[tokio::test]
async fn a_disabled_policy_ignores_a_configured_proxy() {
    let proxy = TestProxy::start(200).await;
    let server = TestServer::start(vec![Reply::json("{}")]).await;
    let transport = HttpTransport::with_config(&TransportConfig {
        tls_policy: TlsPolicy::AllowLoopbackPlaintext,
        proxy_policy: ProxyPolicy::Disabled,
        ..TransportConfig::default()
    })
    .expect("build transport");

    transport
        .send(
            "test",
            Operation::Complete,
            HttpRequest::new(Method::Post, server.url("v1/models")),
            &CancelToken::new(),
        )
        .await
        .expect("the request must go direct");

    assert_eq!(server.request_count().await, 1);
    assert_eq!(proxy.tunnels().await.len(), 0);
}

#[test]
fn a_proxy_policy_never_prints_its_url() {
    // A proxy URL routinely embeds `user:password@`, which is a credential in
    // exactly the way a provider key is.
    let policy = ProxyPolicy::Explicit {
        url: "http://corp-user:corp-secret@proxy.internal:3128".to_owned(),
        no_proxy: Some("internal.example".to_owned()),
    };
    let rendered = format!("{policy:?}");
    assert_eq!(
        rendered,
        r#"Explicit { url: "<redacted>", has_no_proxy: true }"#
    );

    assert_eq!(format!("{:?}", ProxyPolicy::Disabled), "Disabled");
    assert_eq!(
        format!("{:?}", ProxyPolicy::FromEnvironment),
        "FromEnvironment"
    );
}

#[tokio::test]
async fn a_transport_debug_reports_its_proxy_policy_without_the_url() {
    let transport = proxied_transport(
        "http://corp-user:corp-secret@proxy.internal:3128".to_owned(),
        None,
    );
    let rendered = format!("{transport:?}");
    assert!(
        !rendered.contains("corp-secret"),
        "the transport must not print proxy credentials: {rendered}"
    );
    assert!(
        rendered.contains(r#"url: "<redacted>""#),
        "the transport must report that a proxy is configured: {rendered}"
    );
}

// ---------------------------------------------------------------------------
// Proxy policy: precedence is unit-tested in `http::proxy` against an injected
// variable lookup, because `std::env::set_var` is `unsafe` in edition 2024 and
// this workspace forbids `unsafe`. What is proved here is the part only a
// socket can prove: that the resolved policy actually decides where the bytes
// go.
// ---------------------------------------------------------------------------

/// Builds a transport that tunnels through `proxy_url` with a short connect
/// deadline, for the cases that are expected to stall rather than answer.
fn impatient_proxied_transport(proxy_url: String) -> HttpTransport {
    HttpTransport::with_config(&TransportConfig {
        tls_policy: TlsPolicy::AllowLoopbackPlaintext,
        proxy_policy: ProxyPolicy::Explicit {
            url: proxy_url,
            no_proxy: None,
        },
        connect_timeout: Duration::from_millis(500),
        ..TransportConfig::default()
    })
    .expect("build transport")
}

#[tokio::test]
async fn a_malformed_proxy_url_continues_without_a_proxy_and_reports_why() {
    // The legacy client logged the failure and carried on with no proxy. The
    // behaviour is preserved; the disclosure is not, because the legacy log
    // line printed the URL with its userinfo intact.
    let proxy = TestProxy::start(200).await;
    let transport = proxied_transport(
        "socks5://corp-user:corp-secret@proxy.invalid:1080".to_owned(),
        None,
    );

    let rules = transport.proxy_rules();
    assert!(
        rules.fell_back_to_direct(),
        "a rejected proxy URL must be visible, not silent"
    );
    assert!(rules.proxy().is_none());
    assert_eq!(
        rules.intercept("api.example.com", 443),
        ProxyDecision::Direct(DirectReason::Unusable)
    );

    let reported = rules
        .diagnostics()
        .iter()
        .map(ToString::to_string)
        .collect::<Vec<_>>()
        .join(" ");
    assert!(
        reported.contains("continuing without a proxy"),
        "the fallback must be stated: {reported}"
    );
    assert!(
        !reported.contains("corp-secret") && !reported.contains("corp-user"),
        "the proxy credential must not reach a diagnostic: {reported}"
    );

    let kind = attempt_proxied_request(&transport, "https://api.invalid/v1/models").await;
    assert_eq!(kind, ErrorKind::Transport);
    assert_eq!(
        proxy.tunnels().await.len(),
        0,
        "an unusable proxy must not be contacted"
    );
}

#[tokio::test]
async fn a_wildcard_bypass_entry_stops_every_tunnel() {
    let proxy = TestProxy::start(200).await;
    let transport = proxied_transport(proxy.url(None), Some("*".to_owned()));

    assert_eq!(
        transport.proxy_rules().intercept("api.example.com", 443),
        ProxyDecision::Direct(DirectReason::Bypassed)
    );
    let kind = attempt_proxied_request(&transport, "https://api.invalid/v1/models").await;
    assert_eq!(kind, ErrorKind::Transport);
    assert_eq!(
        proxy.tunnels().await.len(),
        0,
        "a wildcard bypass must not be tunnelled"
    );
}

#[tokio::test]
async fn a_dot_suffix_bypass_entry_covers_subdomains() {
    let proxy = TestProxy::start(200).await;
    let transport = proxied_transport(proxy.url(None), Some(".invalid".to_owned()));

    let kind = attempt_proxied_request(&transport, "https://api.invalid/v1/models").await;
    assert_eq!(kind, ErrorKind::Transport);
    assert_eq!(
        proxy.tunnels().await.len(),
        0,
        "a subdomain of a bypassed suffix must not be tunnelled"
    );
}

#[tokio::test]
async fn an_https_proxy_hop_is_negotiated_with_tls_rather_than_in_the_clear() {
    // The test proxy speaks plaintext, so declaring it `https` must produce a
    // TLS handshake it cannot answer. The assertion that matters is the
    // negative one: no `CONNECT` request line — and therefore no proxy
    // credential — was written in the clear to a port declared as TLS.
    let proxy = TestProxy::start(200).await;
    let address = proxy.url(None).replace("http://", "https://");
    let transport = impatient_proxied_transport(address);
    assert_eq!(
        transport
            .proxy_rules()
            .proxy()
            .map(ProxyUrl::scheme)
            .expect("the https proxy URL must resolve"),
        ProxyScheme::Https,
        "the policy must have selected the proxy, or this proves nothing"
    );

    let kind = attempt_proxied_request(&transport, "https://api.example.com/v1/models").await;
    assert_eq!(kind, ErrorKind::Transport);
    assert_eq!(
        proxy.tunnels().await.len(),
        0,
        "a plaintext CONNECT must never be written to an https proxy"
    );
}

#[tokio::test]
async fn the_transport_reports_the_proxy_it_resolved() {
    let proxy = TestProxy::start(200).await;
    let transport = proxied_transport(proxy.url(Some("corp-user:corp-secret")), None);
    let rules = transport.proxy_rules();

    assert!(rules.diagnostics().is_empty());
    assert!(!rules.fell_back_to_direct());
    assert!(rules.proxy().is_some_and(ProxyUrl::has_credentials));
    assert_eq!(
        rules
            .intercept("api.example.com", 443)
            .proxy()
            .map(ProxyUrl::authority),
        rules.proxy().map(ProxyUrl::authority)
    );
    assert_eq!(
        rules.intercept("127.0.0.1", 8080),
        ProxyDecision::Direct(DirectReason::Loopback)
    );

    let rendered = format!("{rules:?} {}", rules.proxy().expect("a proxy is in force"));
    assert!(
        !rendered.contains("corp-secret") && !rendered.contains("corp-user"),
        "the resolved rules must not print proxy credentials: {rendered}"
    );
}

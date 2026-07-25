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
    Body, HttpRequest, HttpTransport, Method, TlsPolicy, TransportConfig,
};
use claw_provider_sdk::secret::SecretString;
use futures_util::StreamExt as _;
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

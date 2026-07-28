//! A loopback HTTP/1.1 server used by the wire-level tests.
//!
//! Tests in this workspace never contact a third-party API. This server binds
//! `127.0.0.1:0`, replays a scripted list of replies, records exactly what the
//! client sent, and — for the cancellation tests — reports the moment the peer
//! closes the socket.
//!
//! It speaks only the subset of HTTP/1.1 the provider clients use: a request
//! line, headers, an optional `Content-Length` body, and either a
//! `Content-Length` response or a `Transfer-Encoding: chunked` response.

#![expect(
    dead_code,
    reason = "`addr`, `frames_written` and `wait_for_requests` are the fixture's \
              observation API; today's wire tests reach the same facts through \
              `base_url` and `requests`, and deleting an accessor because one \
              test binary happens not to call it would keep re-deleting and \
              re-adding the same three methods"
)]
#![expect(
    unreachable_pub,
    reason = "this file is a `mod support;` inside an integration-test binary, not \
              a library module, so `pub` marks the fixture's intended surface even \
              though no downstream crate can reach it"
)]

use std::fmt::Write as _;
use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::time::Duration;

use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::Mutex;

/// One request the server observed.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RecordedRequest {
    /// HTTP method, upper-case.
    pub method: String,
    /// Request target, including any query string.
    pub target: String,
    /// Header names lower-cased, in the order the client sent them.
    pub headers: Vec<(String, String)>,
    /// Raw request body.
    pub body: Vec<u8>,
}

impl RecordedRequest {
    /// Returns the first value of `name`, compared case-insensitively.
    #[must_use]
    pub fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|(candidate, _)| candidate.eq_ignore_ascii_case(name))
            .map(|(_, value)| value.as_str())
    }

    /// Returns every header name, in order.
    #[must_use]
    pub fn header_names(&self) -> Vec<&str> {
        self.headers.iter().map(|(name, _)| name.as_str()).collect()
    }

    /// Returns the body as UTF-8.
    #[must_use]
    pub fn body_text(&self) -> String {
        String::from_utf8_lossy(&self.body).into_owned()
    }

    /// Parses the body as JSON.
    ///
    /// # Panics
    ///
    /// Panics when the body is not valid JSON.
    #[must_use]
    pub fn json(&self) -> serde_json::Value {
        serde_json::from_slice(&self.body).expect("request body must be JSON")
    }
}

/// A scripted reply.
#[derive(Clone, Debug)]
pub enum Reply {
    /// A buffered response with an explicit `Content-Length`.
    Fixed {
        /// HTTP status code.
        status: u16,
        /// Extra response headers.
        headers: Vec<(String, String)>,
        /// Response body.
        body: Vec<u8>,
    },
    /// A `Transfer-Encoding: chunked` response.
    Chunked {
        /// HTTP status code.
        status: u16,
        /// `Content-Type` of the stream.
        content_type: String,
        /// Chunks written in order, each flushed before the next.
        frames: Vec<Vec<u8>>,
        /// When true the server never writes the terminating chunk and instead
        /// waits for the client to close the socket.
        hold_open: bool,
    },
}

impl Reply {
    /// A `200 OK` JSON response.
    #[must_use]
    pub fn json(body: &str) -> Self {
        Self::Fixed {
            status: 200,
            headers: vec![("content-type".to_owned(), "application/json".to_owned())],
            body: body.as_bytes().to_vec(),
        }
    }

    /// A JSON response with an explicit status.
    #[must_use]
    pub fn status(status: u16, body: &str) -> Self {
        Self::Fixed {
            status,
            headers: vec![("content-type".to_owned(), "application/json".to_owned())],
            body: body.as_bytes().to_vec(),
        }
    }

    /// A JSON response with an explicit status and one extra header.
    #[must_use]
    pub fn status_with_header(status: u16, name: &str, value: &str, body: &str) -> Self {
        Self::Fixed {
            status,
            headers: vec![
                ("content-type".to_owned(), "application/json".to_owned()),
                (name.to_owned(), value.to_owned()),
            ],
            body: body.as_bytes().to_vec(),
        }
    }

    /// A chunked `text/event-stream` response that terminates normally.
    #[must_use]
    pub fn sse(frames: &[&str]) -> Self {
        Self::Chunked {
            status: 200,
            content_type: "text/event-stream".to_owned(),
            frames: frames
                .iter()
                .map(|frame| frame.as_bytes().to_vec())
                .collect(),
            hold_open: false,
        }
    }

    /// A chunked `text/event-stream` response that never ends, so a test can
    /// cancel it and observe the socket close.
    #[must_use]
    pub fn sse_hold(frames: &[&str]) -> Self {
        Self::Chunked {
            status: 200,
            content_type: "text/event-stream".to_owned(),
            frames: frames
                .iter()
                .map(|frame| frame.as_bytes().to_vec())
                .collect(),
            hold_open: true,
        }
    }
}

#[derive(Debug, Default)]
struct ServerState {
    requests: Mutex<Vec<RecordedRequest>>,
    peer_closed: AtomicBool,
    frames_written: AtomicUsize,
}

/// A scripted loopback HTTP server.
#[derive(Debug)]
pub struct TestServer {
    addr: SocketAddr,
    state: Arc<ServerState>,
}

impl TestServer {
    /// Starts a server that answers `replies` in order and then stops accepting.
    ///
    /// # Panics
    ///
    /// Panics when the loopback socket cannot be bound.
    pub async fn start(replies: Vec<Reply>) -> Self {
        let listener = TcpListener::bind(("127.0.0.1", 0))
            .await
            .expect("bind loopback listener");
        let addr = listener.local_addr().expect("local address");
        let state = Arc::new(ServerState::default());
        let task_state = Arc::clone(&state);
        tokio::spawn(async move {
            for reply in replies {
                let Ok((stream, _)) = listener.accept().await else {
                    return;
                };
                let connection_state = Arc::clone(&task_state);
                tokio::spawn(async move {
                    serve(stream, reply, connection_state).await;
                });
            }
        });
        Self { addr, state }
    }

    /// Returns the address the server is listening on.
    #[must_use]
    pub const fn addr(&self) -> SocketAddr {
        self.addr
    }

    /// Returns the plaintext base URL of the server.
    #[must_use]
    pub fn base_url(&self) -> url::Url {
        format!("http://{}", self.addr)
            .parse()
            .expect("loopback base URL")
    }

    /// Returns the plaintext URL of `path` on this server.
    #[must_use]
    pub fn url(&self, path: &str) -> url::Url {
        format!("http://{}/{}", self.addr, path.trim_start_matches('/'))
            .parse()
            .expect("loopback URL")
    }

    /// Returns every request observed so far.
    pub async fn requests(&self) -> Vec<RecordedRequest> {
        self.state.requests.lock().await.clone()
    }

    /// Returns the number of requests observed so far.
    pub async fn request_count(&self) -> usize {
        self.state.requests.lock().await.len()
    }

    /// Returns `true` once a client has closed a held-open response socket.
    #[must_use]
    pub fn peer_closed(&self) -> bool {
        self.state.peer_closed.load(Ordering::SeqCst)
    }

    /// Returns how many stream frames the server managed to write.
    #[must_use]
    pub fn frames_written(&self) -> usize {
        self.state.frames_written.load(Ordering::SeqCst)
    }

    /// Waits up to `timeout` for the client to close a held-open socket.
    pub async fn wait_for_peer_close(&self, timeout: Duration) -> bool {
        let deadline = tokio::time::Instant::now() + timeout;
        while tokio::time::Instant::now() < deadline {
            if self.peer_closed() {
                return true;
            }
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
        self.peer_closed()
    }

    /// Waits up to `timeout` for the server to observe `count` requests.
    pub async fn wait_for_requests(&self, count: usize, timeout: Duration) -> bool {
        let deadline = tokio::time::Instant::now() + timeout;
        while tokio::time::Instant::now() < deadline {
            if self.request_count().await >= count {
                return true;
            }
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
        self.request_count().await >= count
    }
}

async fn read_request(stream: &mut TcpStream) -> Option<RecordedRequest> {
    let mut buffer = Vec::new();
    let mut byte = [0_u8; 1];
    while !buffer.ends_with(b"\r\n\r\n") {
        match stream.read(&mut byte).await {
            Ok(0) | Err(_) => return None,
            Ok(_) => buffer.push(byte[0]),
        }
    }
    let head = String::from_utf8_lossy(&buffer).into_owned();
    let mut lines = head.split("\r\n");
    let request_line = lines.next()?;
    let mut parts = request_line.split(' ');
    let method = parts.next()?.to_owned();
    let target = parts.next()?.to_owned();

    let mut headers = Vec::new();
    for line in lines {
        if line.is_empty() {
            break;
        }
        let (name, value) = line.split_once(':')?;
        headers.push((name.trim().to_ascii_lowercase(), value.trim().to_owned()));
    }
    let length: usize = headers
        .iter()
        .find(|(name, _)| name == "content-length")
        .and_then(|(_, value)| value.parse().ok())
        .unwrap_or(0);
    let mut body = vec![0_u8; length];
    if length > 0 && stream.read_exact(&mut body).await.is_err() {
        return None;
    }
    Some(RecordedRequest {
        method,
        target,
        headers,
        body,
    })
}

async fn serve(mut stream: TcpStream, reply: Reply, state: Arc<ServerState>) {
    let Some(request) = read_request(&mut stream).await else {
        return;
    };
    state.requests.lock().await.push(request);

    match reply {
        Reply::Fixed {
            status,
            headers,
            body,
        } => {
            let mut head = format!("HTTP/1.1 {status} {}\r\n", reason(status));
            for (name, value) in headers {
                let _ = write!(head, "{name}: {value}\r\n");
            }
            let _ = write!(head, "content-length: {}\r\n", body.len());
            head.push_str("connection: close\r\n\r\n");
            if stream.write_all(head.as_bytes()).await.is_err() {
                return;
            }
            let _ = stream.write_all(&body).await;
            let _ = stream.flush().await;
            let _ = stream.shutdown().await;
        }
        Reply::Chunked {
            status,
            content_type,
            frames,
            hold_open,
        } => {
            let head = format!(
                "HTTP/1.1 {status} {}\r\ncontent-type: {content_type}\r\ntransfer-encoding: chunked\r\nconnection: close\r\n\r\n",
                reason(status)
            );
            if stream.write_all(head.as_bytes()).await.is_err() {
                return;
            }
            for frame in frames {
                let chunk = format!("{:x}\r\n", frame.len());
                if stream.write_all(chunk.as_bytes()).await.is_err()
                    || stream.write_all(&frame).await.is_err()
                    || stream.write_all(b"\r\n").await.is_err()
                    || stream.flush().await.is_err()
                {
                    // A write that fails mid-response means the peer went away,
                    // which is the same observation the read loop below makes.
                    state.peer_closed.store(true, Ordering::SeqCst);
                    return;
                }
                state.frames_written.fetch_add(1, Ordering::SeqCst);
                tokio::time::sleep(Duration::from_millis(5)).await;
            }
            if hold_open {
                // Block on a read: it resolves only when the peer closes or
                // resets the connection, which is exactly what a cancelled
                // request must do.
                let mut sink = [0_u8; 64];
                loop {
                    match stream.read(&mut sink).await {
                        Ok(0) | Err(_) => {
                            state.peer_closed.store(true, Ordering::SeqCst);
                            return;
                        }
                        Ok(_) => {}
                    }
                }
            }
            let _ = stream.write_all(b"0\r\n\r\n").await;
            let _ = stream.flush().await;
            let _ = stream.shutdown().await;
        }
    }
}

const fn reason(status: u16) -> &'static str {
    match status {
        200 => "OK",
        204 => "No Content",
        400 => "Bad Request",
        401 => "Unauthorized",
        403 => "Forbidden",
        404 => "Not Found",
        429 => "Too Many Requests",
        500 => "Internal Server Error",
        502 => "Bad Gateway",
        503 => "Service Unavailable",
        _ => "Status",
    }
}

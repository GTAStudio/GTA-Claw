//! Server-side WebSocket transport: HTTP upgrade, framing, and size limits.
//!
//! The upgrade is parsed with a hard byte budget before any allocation grows,
//! frame payloads are capped per protocol phase, binary messages are refused
//! outright (the Gateway wire format is JSON text), and control frames obey the
//! RFC 6455 125-byte limit.

use std::pin::Pin;
use std::task::{Context, Poll};

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD;
use fastwebsockets::{
    Frame, OpCode, Payload, Role, WebSocket, WebSocketError, WebSocketRead, WebSocketWrite,
};
use sha1::{Digest, Sha1};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf};
use tokio::net::TcpStream;

use crate::error::{HandshakeError, WireError};

/// RFC 6455 control-frame payload ceiling.
pub const MAX_CONTROL_PAYLOAD_BYTES: usize = 125;
/// RFC 6455 accept-key GUID.
const WEBSOCKET_GUID: &[u8] = b"258EAFA5-E914-47DA-95CA-C5AB0DC85B11";
/// Decoded length required of `Sec-WebSocket-Key`.
const WEBSOCKET_KEY_BYTES: usize = 16;
/// Upper bound on parsed request headers.
const MAX_UPGRADE_HEADERS: usize = 64;

/// A stream that replays bytes read past the end of the HTTP upgrade.
///
/// The prefix is freed as soon as it has been fully replayed. It can be up to
/// `max_http_upgrade_bytes` and the wrapper lives for the whole connection, so
/// keeping it would be a per-connection allocation held for no reason.
#[derive(Debug)]
pub struct ReplayStream<S> {
    prefix: Vec<u8>,
    offset: usize,
    inner: S,
}

impl<S> ReplayStream<S> {
    /// Wraps `inner`, yielding `prefix` before any further reads.
    pub const fn new(inner: S, prefix: Vec<u8>) -> Self {
        Self {
            prefix,
            offset: 0,
            inner,
        }
    }
}

impl<S: AsyncRead + Unpin> AsyncRead for ReplayStream<S> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        context: &mut Context<'_>,
        buffer: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        if self.offset < self.prefix.len() {
            let available = &self.prefix[self.offset..];
            let count = available.len().min(buffer.remaining());
            buffer.put_slice(&available[..count]);
            self.offset += count;
            if self.offset == self.prefix.len() {
                self.prefix = Vec::new();
                self.offset = 0;
            }
            // A zero-capacity `buffer` yields zero bytes here rather than
            // touching `inner`, which callers must not read as end of stream.
            return Poll::Ready(Ok(()));
        }
        Pin::new(&mut self.inner).poll_read(context, buffer)
    }
}

impl<S: AsyncWrite + Unpin> AsyncWrite for ReplayStream<S> {
    fn poll_write(
        mut self: Pin<&mut Self>,
        context: &mut Context<'_>,
        bytes: &[u8],
    ) -> Poll<Result<usize, std::io::Error>> {
        Pin::new(&mut self.inner).poll_write(context, bytes)
    }

    fn poll_flush(
        mut self: Pin<&mut Self>,
        context: &mut Context<'_>,
    ) -> Poll<Result<(), std::io::Error>> {
        Pin::new(&mut self.inner).poll_flush(context)
    }

    fn poll_shutdown(
        mut self: Pin<&mut Self>,
        context: &mut Context<'_>,
    ) -> Poll<Result<(), std::io::Error>> {
        Pin::new(&mut self.inner).poll_shutdown(context)
    }
}

/// Negotiated server socket type.
pub type ServerSocket = WebSocket<ReplayStream<TcpStream>>;
/// Read half of a negotiated server socket.
pub type ServerRead = WebSocketRead<tokio::io::ReadHalf<ReplayStream<TcpStream>>>;
/// Write half of a negotiated server socket.
pub type ServerWrite = WebSocketWrite<tokio::io::WriteHalf<ReplayStream<TcpStream>>>;

/// Result of parsing one HTTP upgrade request.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct UpgradeRequest {
    /// Request target exactly as sent.
    pub path: String,
    /// Value of the `Sec-WebSocket-Key` header.
    pub key: String,
}

/// Validates an HTTP/1.1 WebSocket upgrade request head.
///
/// # Errors
///
/// Returns the typed [`HandshakeError`] describing the first violated rule.
pub fn parse_upgrade(bytes: &[u8]) -> Result<UpgradeRequest, HandshakeError> {
    let mut headers = [httparse::EMPTY_HEADER; MAX_UPGRADE_HEADERS];
    let mut request = httparse::Request::new(&mut headers);
    match request
        .parse(bytes)
        .map_err(|_| HandshakeError::MalformedRequest)?
    {
        httparse::Status::Complete(_) => {}
        httparse::Status::Partial => return Err(HandshakeError::MalformedRequest),
    }
    if request.method != Some("GET") {
        return Err(HandshakeError::MethodNotAllowed);
    }
    if request.version != Some(1) {
        return Err(HandshakeError::UnsupportedHttpVersion);
    }
    let path = request
        .path
        .ok_or(HandshakeError::MalformedRequest)?
        .to_owned();

    let mut upgrade: Option<bool> = None;
    let mut connection: Option<bool> = None;
    let mut version: Option<bool> = None;
    let mut key: Option<String> = None;
    for header in request.headers.iter() {
        let name = header.name;
        if name.eq_ignore_ascii_case("Upgrade") {
            if upgrade.is_some() {
                return Err(HandshakeError::DuplicateHeader);
            }
            upgrade = Some(
                header
                    .value
                    .split(|byte| *byte == b',')
                    .any(|token| trim_ascii(token).eq_ignore_ascii_case(b"websocket")),
            );
        } else if name.eq_ignore_ascii_case("Connection") {
            if connection.is_some() {
                return Err(HandshakeError::DuplicateHeader);
            }
            connection = Some(
                header
                    .value
                    .split(|byte| *byte == b',')
                    .any(|token| trim_ascii(token).eq_ignore_ascii_case(b"upgrade")),
            );
        } else if name.eq_ignore_ascii_case("Sec-WebSocket-Version") {
            if version.is_some() {
                return Err(HandshakeError::DuplicateHeader);
            }
            version = Some(trim_ascii(header.value) == b"13");
        } else if name.eq_ignore_ascii_case("Sec-WebSocket-Key") {
            if key.is_some() {
                return Err(HandshakeError::DuplicateHeader);
            }
            let value = std::str::from_utf8(trim_ascii(header.value))
                .map_err(|_| HandshakeError::InvalidWebSocketKey)?;
            let decoded = STANDARD
                .decode(value)
                .map_err(|_| HandshakeError::InvalidWebSocketKey)?;
            if decoded.len() != WEBSOCKET_KEY_BYTES {
                return Err(HandshakeError::InvalidWebSocketKey);
            }
            key = Some(value.to_owned());
        } else if name.eq_ignore_ascii_case("Sec-WebSocket-Extensions")
            && !trim_ascii(header.value).is_empty()
        {
            return Err(HandshakeError::ExtensionRequested);
        }
    }

    if upgrade != Some(true) {
        return Err(HandshakeError::MissingWebSocketUpgrade);
    }
    if connection != Some(true) {
        return Err(HandshakeError::MissingConnectionUpgrade);
    }
    if version != Some(true) {
        return Err(HandshakeError::UnsupportedWebSocketVersion);
    }
    let key = key.ok_or(HandshakeError::InvalidWebSocketKey)?;
    Ok(UpgradeRequest { path, key })
}

/// Computes the `Sec-WebSocket-Accept` value for a request key.
#[must_use]
pub fn accept_key(key: &str) -> String {
    let mut digest = Sha1::new();
    digest.update(key.as_bytes());
    digest.update(WEBSOCKET_GUID);
    STANDARD.encode(digest.finalize())
}

fn trim_ascii(mut value: &[u8]) -> &[u8] {
    while value.first().is_some_and(u8::is_ascii_whitespace) {
        value = &value[1..];
    }
    while value.last().is_some_and(u8::is_ascii_whitespace) {
        value = &value[..value.len() - 1];
    }
    value
}

/// Renders the HTTP error response sent when an upgrade is refused.
#[must_use]
pub fn error_response(error: &HandshakeError) -> String {
    let (status, reason) = error.http_status();
    let body = error.to_string();
    format!(
        "HTTP/1.1 {status} {reason}\r\nContent-Type: text/plain; charset=utf-8\r\nContent-Length: {}\r\nConnection: close\r\nSec-WebSocket-Version: 13\r\n\r\n{body}",
        body.len()
    )
}

/// Reads and answers one HTTP upgrade, returning a negotiated socket.
///
/// `max_upgrade_bytes` bounds the accepted request head; a peer that exceeds it
/// is refused before the buffer can grow further.
///
/// # Errors
///
/// Returns the typed [`HandshakeError`]; the refusal response has already been
/// written to `stream` when this returns an error.
pub async fn accept(
    mut stream: TcpStream,
    max_upgrade_bytes: usize,
) -> Result<ServerSocket, HandshakeError> {
    let mut received: Vec<u8> = Vec::with_capacity(1024);
    let header_end = loop {
        if let Some(index) = find_header_end(&received) {
            break index;
        }
        if received.len() >= max_upgrade_bytes {
            return refuse(
                &mut stream,
                HandshakeError::RequestTooLarge {
                    limit: max_upgrade_bytes,
                },
            )
            .await;
        }
        let mut chunk = [0_u8; 1024];
        let Ok(count) = stream.read(&mut chunk).await else {
            return Err(HandshakeError::UnexpectedEof);
        };
        if count == 0 {
            return Err(HandshakeError::UnexpectedEof);
        }
        if count > max_upgrade_bytes.saturating_sub(received.len()) {
            return refuse(
                &mut stream,
                HandshakeError::RequestTooLarge {
                    limit: max_upgrade_bytes,
                },
            )
            .await;
        }
        received.extend_from_slice(&chunk[..count]);
    };

    let request = match parse_upgrade(&received[..header_end]) {
        Ok(request) => request,
        Err(error) => return refuse(&mut stream, error).await,
    };
    let response = format!(
        "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: {}\r\n\r\n",
        accept_key(&request.key)
    );
    stream
        .write_all(response.as_bytes())
        .await
        .map_err(|_| HandshakeError::UnexpectedEof)?;
    stream
        .flush()
        .await
        .map_err(|_| HandshakeError::UnexpectedEof)?;

    let prefix = received.split_off(header_end);
    let mut socket = WebSocket::after_handshake(ReplayStream::new(stream, prefix), Role::Server);
    socket.set_auto_close(false);
    socket.set_auto_pong(false);
    socket.set_writev(false);
    Ok(socket)
}

fn find_header_end(bytes: &[u8]) -> Option<usize> {
    bytes
        .windows(4)
        .position(|window| window == b"\r\n\r\n")
        .map(|index| index + 4)
}

async fn refuse(
    stream: &mut TcpStream,
    error: HandshakeError,
) -> Result<ServerSocket, HandshakeError> {
    let response = error_response(&error);
    let _ = stream.write_all(response.as_bytes()).await;
    let _ = stream.flush().await;
    Err(error)
}

/// Splits a negotiated socket into independently owned halves.
#[must_use]
pub fn split(socket: ServerSocket) -> (ServerRead, ServerWrite) {
    socket.split(tokio::io::split)
}

/// One complete inbound WebSocket message.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Inbound {
    /// A complete UTF-8 text message.
    Text(Vec<u8>),
    /// A ping with its payload.
    Ping(Vec<u8>),
    /// A pong with its payload.
    Pong(Vec<u8>),
    /// A close frame with its optional status code.
    Close(Option<u16>),
}

/// Fragmentation-aware reader that enforces a per-phase byte cap.
#[derive(Debug, Default)]
pub struct MessageReader {
    fragments: Option<Vec<u8>>,
}

impl MessageReader {
    /// Creates a reader with no partial message.
    #[must_use]
    pub const fn new() -> Self {
        Self { fragments: None }
    }

    /// Reads the next complete message, enforcing `limit` across fragments.
    ///
    /// # Errors
    ///
    /// Returns the typed [`WireError`] for oversize, binary, malformed, or
    /// closed peers.
    pub async fn read(
        &mut self,
        socket: &mut ServerRead,
        limit: usize,
    ) -> Result<Inbound, WireError> {
        loop {
            let buffered = self.fragments.as_ref().map_or(0, Vec::len);
            let remaining = limit.saturating_sub(buffered);
            socket.set_max_message_size(remaining.max(MAX_CONTROL_PAYLOAD_BYTES).saturating_add(1));
            let frame = socket
                .read_frame(&mut |_| async { Ok::<(), std::io::Error>(()) })
                .await
                .map_err(|error| map_read_error(&error, limit))?;
            if let Some(inbound) = self.consume(frame, limit)? {
                return Ok(inbound);
            }
        }
    }

    fn consume(&mut self, frame: Frame<'_>, limit: usize) -> Result<Option<Inbound>, WireError> {
        match frame.opcode {
            OpCode::Text if self.fragments.is_none() && frame.fin => {
                let bytes = Vec::from(frame.payload);
                if bytes.len() > limit {
                    return Err(WireError::MessageTooLarge {
                        limit,
                        actual: bytes.len(),
                    });
                }
                validate_utf8(bytes).map(Inbound::Text).map(Some)
            }
            OpCode::Text if self.fragments.is_none() => {
                let bytes = Vec::from(frame.payload);
                if bytes.len() > limit {
                    return Err(WireError::MessageTooLarge {
                        limit,
                        actual: bytes.len(),
                    });
                }
                self.fragments = Some(bytes);
                Ok(None)
            }
            OpCode::Continuation if self.fragments.is_some() => {
                let payload = frame.payload;
                let fragments = self.fragments.as_mut().expect("checked fragmented state");
                if payload.len() > limit.saturating_sub(fragments.len()) {
                    return Err(WireError::MessageTooLarge {
                        limit,
                        actual: fragments.len().saturating_add(payload.len()),
                    });
                }
                fragments.extend_from_slice(&payload);
                if frame.fin {
                    let complete = self.fragments.take().expect("checked fragmented state");
                    validate_utf8(complete).map(Inbound::Text).map(Some)
                } else {
                    Ok(None)
                }
            }
            OpCode::Binary => {
                self.fragments = None;
                Err(WireError::BinaryMessage)
            }
            OpCode::Close => {
                self.fragments = None;
                let payload = Vec::from(frame.payload);
                if payload.len() > MAX_CONTROL_PAYLOAD_BYTES || payload.len() == 1 {
                    return Err(WireError::Protocol("invalid close frame"));
                }
                let code = if payload.is_empty() {
                    None
                } else {
                    Some(u16::from_be_bytes([payload[0], payload[1]]))
                };
                Ok(Some(Inbound::Close(code)))
            }
            OpCode::Ping => {
                if frame.payload.len() > MAX_CONTROL_PAYLOAD_BYTES {
                    return Err(WireError::Protocol("oversized control frame"));
                }
                Ok(Some(Inbound::Ping(Vec::from(frame.payload))))
            }
            OpCode::Pong => {
                if frame.payload.len() > MAX_CONTROL_PAYLOAD_BYTES {
                    return Err(WireError::Protocol("oversized control frame"));
                }
                Ok(Some(Inbound::Pong(Vec::from(frame.payload))))
            }
            OpCode::Continuation | OpCode::Text => {
                self.fragments = None;
                Err(WireError::Protocol("invalid fragmentation"))
            }
        }
    }
}

fn validate_utf8(bytes: Vec<u8>) -> Result<Vec<u8>, WireError> {
    if std::str::from_utf8(&bytes).is_ok() {
        Ok(bytes)
    } else {
        Err(WireError::InvalidUtf8)
    }
}

const fn map_read_error(error: &WebSocketError, limit: usize) -> WireError {
    match error {
        WebSocketError::FrameTooLarge => WireError::MessageTooLarge {
            limit,
            actual: limit.saturating_add(1),
        },
        WebSocketError::ConnectionClosed | WebSocketError::UnexpectedEOF => WireError::Closed,
        WebSocketError::IoError(_) => WireError::Read,
        WebSocketError::InvalidFragment => WireError::Protocol("invalid fragment"),
        WebSocketError::InvalidUTF8 => WireError::InvalidUtf8,
        WebSocketError::InvalidContinuationFrame => WireError::Protocol("invalid continuation"),
        WebSocketError::InvalidCloseFrame => WireError::Protocol("invalid close frame"),
        WebSocketError::InvalidCloseCode => WireError::Protocol("invalid close code"),
        WebSocketError::ReservedBitsNotZero => WireError::Protocol("reserved bits are not zero"),
        WebSocketError::ControlFrameFragmented => WireError::Protocol("fragmented control frame"),
        WebSocketError::PingFrameTooLarge => WireError::Protocol("oversized control frame"),
        WebSocketError::InvalidValue => WireError::Protocol("invalid opcode"),
        _ => WireError::Protocol("unexpected framing failure"),
    }
}

/// Writes one complete text message.
///
/// # Errors
///
/// Returns [`WireError::Write`] when the peer half is gone.
pub async fn write_text(socket: &mut ServerWrite, bytes: Vec<u8>) -> Result<(), WireError> {
    socket
        .write_frame(Frame::text(Payload::Owned(bytes)))
        .await
        .map_err(|_| WireError::Write)?;
    socket.flush().await.map_err(|_| WireError::Write)
}

/// Writes a ping with the supplied payload.
///
/// # Errors
///
/// Returns [`WireError::Write`] when the peer half is gone, or
/// [`WireError::Protocol`] when the payload exceeds the control-frame limit.
pub async fn write_ping(socket: &mut ServerWrite, payload: Vec<u8>) -> Result<(), WireError> {
    if payload.len() > MAX_CONTROL_PAYLOAD_BYTES {
        return Err(WireError::Protocol("oversized control frame"));
    }
    socket
        .write_frame(Frame::new(
            true,
            OpCode::Ping,
            None,
            Payload::Owned(payload),
        ))
        .await
        .map_err(|_| WireError::Write)?;
    socket.flush().await.map_err(|_| WireError::Write)
}

/// Writes a pong echoing the supplied payload.
///
/// # Errors
///
/// Returns [`WireError::Write`] when the peer half is gone, or
/// [`WireError::Protocol`] when the payload exceeds the control-frame limit.
pub async fn write_pong(socket: &mut ServerWrite, payload: Vec<u8>) -> Result<(), WireError> {
    if payload.len() > MAX_CONTROL_PAYLOAD_BYTES {
        return Err(WireError::Protocol("oversized control frame"));
    }
    socket
        .write_frame(Frame::pong(Payload::Owned(payload)))
        .await
        .map_err(|_| WireError::Write)?;
    socket.flush().await.map_err(|_| WireError::Write)
}

/// Writes a close frame with a bounded reason and flushes it.
///
/// # Errors
///
/// Returns [`WireError::Write`] when the peer half is gone.
pub async fn write_close(
    socket: &mut ServerWrite,
    code: u16,
    reason: &str,
) -> Result<(), WireError> {
    let mut reason = reason.as_bytes();
    while reason.len() > MAX_CONTROL_PAYLOAD_BYTES - 2 {
        reason = &reason[..reason.len() - 1];
    }
    let reason = std::str::from_utf8(reason).unwrap_or("");
    socket
        .write_frame(Frame::close(code, reason.as_bytes()))
        .await
        .map_err(|_| WireError::Write)?;
    socket.flush().await.map_err(|_| WireError::Write)
}

#[cfg(test)]
mod tests {
    use super::*;

    const KEY: &str = "dGhlIHNhbXBsZSBub25jZQ==";

    fn request(extra: &str) -> Vec<u8> {
        format!(
            "GET /gateway HTTP/1.1\r\nHost: 127.0.0.1:9\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: {KEY}\r\nSec-WebSocket-Version: 13\r\n{extra}\r\n"
        )
        .into_bytes()
    }

    #[test]
    fn accept_key_matches_the_rfc6455_example() {
        assert_eq!(accept_key(KEY), "s3pPLMBiTxaQ9kYGzzhZRbK+xOo=");
    }

    #[test]
    fn a_well_formed_upgrade_is_accepted_with_its_exact_path_and_key() {
        let parsed = parse_upgrade(&request("")).expect("valid upgrade");
        assert_eq!(
            parsed,
            UpgradeRequest {
                path: "/gateway".to_owned(),
                key: KEY.to_owned(),
            }
        );
    }

    #[test]
    fn post_is_refused_with_method_not_allowed() {
        let bytes = b"POST /gateway HTTP/1.1\r\nHost: h\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nSec-WebSocket-Version: 13\r\n\r\n";
        assert_eq!(
            parse_upgrade(bytes).expect_err("post"),
            HandshakeError::MethodNotAllowed
        );
    }

    #[test]
    fn http_1_0_is_refused() {
        let bytes = b"GET /gateway HTTP/1.0\r\nHost: h\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nSec-WebSocket-Version: 13\r\n\r\n";
        assert_eq!(
            parse_upgrade(bytes).expect_err("http/1.0"),
            HandshakeError::UnsupportedHttpVersion
        );
    }

    #[test]
    fn a_missing_upgrade_header_is_refused() {
        let bytes = b"GET / HTTP/1.1\r\nHost: h\r\nConnection: Upgrade\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nSec-WebSocket-Version: 13\r\n\r\n";
        assert_eq!(
            parse_upgrade(bytes).expect_err("no upgrade"),
            HandshakeError::MissingWebSocketUpgrade
        );
    }

    #[test]
    fn a_missing_connection_upgrade_token_is_refused() {
        let bytes = b"GET / HTTP/1.1\r\nHost: h\r\nUpgrade: websocket\r\nConnection: keep-alive\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nSec-WebSocket-Version: 13\r\n\r\n";
        assert_eq!(
            parse_upgrade(bytes).expect_err("no connection upgrade"),
            HandshakeError::MissingConnectionUpgrade
        );
    }

    #[test]
    fn version_other_than_13_is_refused() {
        let bytes = b"GET / HTTP/1.1\r\nHost: h\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nSec-WebSocket-Version: 8\r\n\r\n";
        assert_eq!(
            parse_upgrade(bytes).expect_err("version 8"),
            HandshakeError::UnsupportedWebSocketVersion
        );
    }

    #[test]
    fn a_key_that_is_not_sixteen_bytes_is_refused() {
        let bytes = b"GET / HTTP/1.1\r\nHost: h\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: c2hvcnQ=\r\nSec-WebSocket-Version: 13\r\n\r\n";
        assert_eq!(
            parse_upgrade(bytes).expect_err("short key"),
            HandshakeError::InvalidWebSocketKey
        );
    }

    #[test]
    fn a_key_that_is_not_base64_is_refused() {
        let bytes = b"GET / HTTP/1.1\r\nHost: h\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: ****************\r\nSec-WebSocket-Version: 13\r\n\r\n";
        assert_eq!(
            parse_upgrade(bytes).expect_err("bad base64"),
            HandshakeError::InvalidWebSocketKey
        );
    }

    #[test]
    fn a_requested_extension_is_refused() {
        let bytes = request("Sec-WebSocket-Extensions: permessage-deflate\r\n");
        assert_eq!(
            parse_upgrade(&bytes).expect_err("extension"),
            HandshakeError::ExtensionRequested
        );
    }

    #[test]
    fn an_empty_extension_header_is_tolerated() {
        let bytes = request("Sec-WebSocket-Extensions: \r\n");
        assert_eq!(parse_upgrade(&bytes).expect("empty extensions").key, KEY);
    }

    #[test]
    fn duplicate_critical_headers_are_refused() {
        for duplicate in [
            "Upgrade: websocket\r\n",
            "Connection: Upgrade\r\n",
            "Sec-WebSocket-Version: 13\r\n",
            "Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n",
        ] {
            let bytes = request(duplicate);
            assert_eq!(
                parse_upgrade(&bytes).expect_err("duplicate header"),
                HandshakeError::DuplicateHeader,
                "duplicate `{duplicate}` was accepted"
            );
        }
    }

    #[test]
    fn a_truncated_request_head_is_refused() {
        assert_eq!(
            parse_upgrade(b"GET / HTTP/1.1\r\nHost: h\r\n").expect_err("partial"),
            HandshakeError::MalformedRequest
        );
    }

    #[test]
    fn header_end_is_found_only_after_the_full_terminator() {
        assert_eq!(find_header_end(b"GET / HTTP/1.1\r\n\r\n"), Some(18));
        assert_eq!(find_header_end(b"GET / HTTP/1.1\r\n\r"), None);
    }

    #[test]
    fn error_responses_carry_the_mapped_status_and_an_exact_length() {
        let error = HandshakeError::RequestTooLarge { limit: 16 };
        let response = error_response(&error);
        assert!(
            response.starts_with("HTTP/1.1 431 Request Header Fields Too Large\r\n"),
            "unexpected status line: {response}"
        );
        let body = error.to_string();
        assert!(response.ends_with(&format!("\r\n\r\n{body}")));
        assert!(response.contains(&format!("Content-Length: {}\r\n", body.len())));
    }

    #[test]
    fn every_handshake_error_renders_its_own_status_and_reason() {
        for error in [
            HandshakeError::RequestTooLarge { limit: 1 },
            HandshakeError::UnexpectedEof,
            HandshakeError::MalformedRequest,
            HandshakeError::MethodNotAllowed,
            HandshakeError::UnsupportedHttpVersion,
            HandshakeError::MissingWebSocketUpgrade,
            HandshakeError::MissingConnectionUpgrade,
            HandshakeError::UnsupportedWebSocketVersion,
            HandshakeError::InvalidWebSocketKey,
            HandshakeError::ExtensionRequested,
            HandshakeError::DuplicateHeader,
            HandshakeError::TimedOut,
        ] {
            let (status, reason) = error.http_status();
            let response = error_response(&error);
            assert!(
                response.starts_with(&format!("HTTP/1.1 {status} {reason}\r\n")),
                "unexpected response for {error:?}: {response}"
            );
        }
        assert_eq!(
            HandshakeError::MethodNotAllowed.http_status(),
            (405, "Method Not Allowed")
        );
        assert_eq!(
            HandshakeError::UnsupportedWebSocketVersion.http_status(),
            (426, "Upgrade Required")
        );
        assert_eq!(
            HandshakeError::TimedOut.http_status(),
            (408, "Request Timeout")
        );
    }

    #[test]
    fn oversized_text_messages_are_refused_at_the_exact_byte_bound() {
        let mut reader = MessageReader::new();
        let payload = vec![b'a'; 9];
        let frame = Frame::text(Payload::Owned(payload));
        assert_eq!(
            reader.consume(frame, 8).expect_err("oversized"),
            WireError::MessageTooLarge {
                limit: 8,
                actual: 9
            }
        );
        let mut reader = MessageReader::new();
        let exact = Frame::text(Payload::Owned(vec![b'a'; 8]));
        assert_eq!(
            reader.consume(exact, 8).expect("exact bound"),
            Some(Inbound::Text(vec![b'a'; 8]))
        );
    }

    #[test]
    fn fragmented_text_is_reassembled_and_capped_across_fragments() {
        let mut reader = MessageReader::new();
        let first = Frame::new(false, OpCode::Text, None, Payload::Owned(vec![b'a'; 4]));
        assert_eq!(reader.consume(first, 8).expect("first fragment"), None);
        let second = Frame::new(
            true,
            OpCode::Continuation,
            None,
            Payload::Owned(vec![b'b'; 4]),
        );
        let message = reader.consume(second, 8).expect("second fragment");
        let mut expected = vec![b'a'; 4];
        expected.extend(vec![b'b'; 4]);
        assert_eq!(message, Some(Inbound::Text(expected)));

        let mut reader = MessageReader::new();
        let first = Frame::new(false, OpCode::Text, None, Payload::Owned(vec![b'a'; 6]));
        assert_eq!(reader.consume(first, 8).expect("first fragment"), None);
        let second = Frame::new(
            true,
            OpCode::Continuation,
            None,
            Payload::Owned(vec![b'b'; 3]),
        );
        assert_eq!(
            reader.consume(second, 8).expect_err("over the cap"),
            WireError::MessageTooLarge {
                limit: 8,
                actual: 9
            }
        );
    }

    #[test]
    fn binary_messages_are_refused() {
        let mut reader = MessageReader::new();
        let frame = Frame::binary(Payload::Owned(vec![1, 2, 3]));
        assert_eq!(
            reader.consume(frame, 64).expect_err("binary"),
            WireError::BinaryMessage
        );
    }

    #[test]
    fn invalid_utf8_text_is_refused() {
        let mut reader = MessageReader::new();
        let frame = Frame::text(Payload::Owned(vec![0xff, 0xfe]));
        assert_eq!(
            reader.consume(frame, 64).expect_err("invalid utf-8"),
            WireError::InvalidUtf8
        );
    }

    #[test]
    fn a_continuation_without_a_started_message_is_refused() {
        let mut reader = MessageReader::new();
        let frame = Frame::new(true, OpCode::Continuation, None, Payload::Owned(Vec::new()));
        assert_eq!(
            reader.consume(frame, 64).expect_err("stray continuation"),
            WireError::Protocol("invalid fragmentation")
        );
    }

    #[test]
    fn a_text_frame_during_fragmentation_is_refused() {
        let mut reader = MessageReader::new();
        let first = Frame::new(false, OpCode::Text, None, Payload::Owned(vec![b'a']));
        assert_eq!(reader.consume(first, 64).expect("first fragment"), None);
        let interleaved = Frame::text(Payload::Owned(vec![b'b']));
        assert_eq!(
            reader
                .consume(interleaved, 64)
                .expect_err("interleaved text"),
            WireError::Protocol("invalid fragmentation")
        );
    }

    #[test]
    fn oversized_control_frames_are_refused() {
        let mut reader = MessageReader::new();
        let ping = Frame::new(
            true,
            OpCode::Ping,
            None,
            Payload::Owned(vec![0; MAX_CONTROL_PAYLOAD_BYTES + 1]),
        );
        assert_eq!(
            reader.consume(ping, 1024).expect_err("oversized ping"),
            WireError::Protocol("oversized control frame")
        );
    }

    #[test]
    fn close_frames_surface_their_status_code() {
        let mut reader = MessageReader::new();
        assert_eq!(
            reader
                .consume(Frame::close(1000, b"bye"), 1024)
                .expect("close"),
            Some(Inbound::Close(Some(1000)))
        );
        let mut reader = MessageReader::new();
        assert_eq!(
            reader
                .consume(Frame::close_raw(Payload::Owned(Vec::new())), 1024)
                .expect("empty close"),
            Some(Inbound::Close(None))
        );
        let mut reader = MessageReader::new();
        assert_eq!(
            reader
                .consume(Frame::close_raw(Payload::Owned(vec![3])), 1024)
                .expect_err("one byte close"),
            WireError::Protocol("invalid close frame")
        );
    }

    #[test]
    fn read_errors_map_to_typed_wire_errors() {
        assert_eq!(
            map_read_error(&WebSocketError::FrameTooLarge, 64),
            WireError::MessageTooLarge {
                limit: 64,
                actual: 65
            }
        );
        assert_eq!(
            map_read_error(&WebSocketError::ConnectionClosed, 64),
            WireError::Closed
        );
        assert_eq!(
            map_read_error(&WebSocketError::UnexpectedEOF, 64),
            WireError::Closed
        );
        assert_eq!(
            map_read_error(&WebSocketError::InvalidCloseCode, 64),
            WireError::Protocol("invalid close code")
        );
    }
}

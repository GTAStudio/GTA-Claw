use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD;
use fastwebsockets::{
    Frame, OpCode, Payload, Role, WebSocket, WebSocketError, WebSocketRead, WebSocketWrite,
};
use ring::rand::{SecureRandom, SystemRandom};
use rustls::pki_types::ServerName;
use rustls::{ClientConfig, RootCertStore};
use sha1::{Digest, Sha1};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf};
use tokio::net::TcpStream;
use tokio_rustls::TlsConnector;
use url::{Host, Position, Url};

use crate::error::{ProtocolFailure, TransportFailure};

const MAX_HANDSHAKE_BYTES: usize = 16 * 1024;
const WEBSOCKET_GUID: &[u8] = b"258EAFA5-E914-47DA-95CA-C5AB0DC85B11";

pub(crate) trait IoStream: AsyncRead + AsyncWrite + Send + Unpin {}
impl<T> IoStream for T where T: AsyncRead + AsyncWrite + Send + Unpin {}

pub(crate) type GatewayIo = ReplayStream<Box<dyn IoStream>>;
pub(crate) type GatewaySocket = WebSocket<GatewayIo>;
pub(crate) type GatewayReadHalf = WebSocketRead<tokio::io::ReadHalf<GatewayIo>>;
pub(crate) type GatewayWriteHalf = WebSocketWrite<tokio::io::WriteHalf<GatewayIo>>;

pub(crate) struct ReplayStream<S> {
    prefix: Vec<u8>,
    offset: usize,
    inner: S,
}

impl<S> ReplayStream<S> {
    fn new(inner: S, prefix: Vec<u8>) -> Self {
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

pub(crate) async fn connect(url: &Url) -> Result<GatewaySocket, TransportFailure> {
    let host = match url.host().ok_or(TransportFailure::Connect)? {
        Host::Domain(value) => value.to_owned(),
        Host::Ipv4(value) => value.to_string(),
        Host::Ipv6(value) => value.to_string(),
    };
    let port = url
        .port_or_known_default()
        .ok_or(TransportFailure::Connect)?;
    let tcp = TcpStream::connect((host.as_str(), port))
        .await
        .map_err(|_| TransportFailure::Connect)?;
    tcp.set_nodelay(true)
        .map_err(|_| TransportFailure::Connect)?;
    let mut stream: Box<dyn IoStream> = if url.scheme() == "wss" {
        Box::new(connect_tls(&host, tcp).await?)
    } else {
        Box::new(tcp)
    };

    let mut nonce = [0_u8; 16];
    SystemRandom::new()
        .fill(&mut nonce)
        .map_err(|_| TransportFailure::Connect)?;
    let key = STANDARD.encode(nonce);
    let authority = &url[Position::BeforeHost..Position::AfterPort];
    let path = &url[Position::BeforePath..];
    let path = if path.is_empty() { "/" } else { path };
    let request = format!(
        "GET {path} HTTP/1.1\r\nHost: {authority}\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: {key}\r\nSec-WebSocket-Version: 13\r\n\r\n"
    );
    stream
        .write_all(request.as_bytes())
        .await
        .map_err(|_| TransportFailure::Connect)?;
    stream
        .flush()
        .await
        .map_err(|_| TransportFailure::Connect)?;

    let mut received = Vec::with_capacity(1024);
    let header_end = loop {
        if let Some(index) = received.windows(4).position(|window| window == b"\r\n\r\n") {
            break index + 4;
        }
        if received.len() >= MAX_HANDSHAKE_BYTES {
            return Err(TransportFailure::Connect);
        }
        let mut chunk = [0_u8; 1024];
        let count = stream
            .read(&mut chunk)
            .await
            .map_err(|_| TransportFailure::Connect)?;
        if count == 0 {
            return Err(TransportFailure::Connect);
        }
        if count > MAX_HANDSHAKE_BYTES.saturating_sub(received.len()) {
            return Err(TransportFailure::Connect);
        }
        received.extend_from_slice(&chunk[..count]);
    };
    validate_server_handshake(&received[..header_end], &key)?;
    let prefix = received.split_off(header_end);
    let mut socket = WebSocket::after_handshake(ReplayStream::new(stream, prefix), Role::Client);
    socket.set_auto_close(true);
    socket.set_auto_pong(true);
    socket.set_auto_apply_mask(true);
    Ok(socket)
}

fn validate_server_handshake(bytes: &[u8], key: &str) -> Result<(), TransportFailure> {
    let mut headers = [httparse::EMPTY_HEADER; 64];
    let mut response = httparse::Response::new(&mut headers);
    match response
        .parse(bytes)
        .map_err(|_| TransportFailure::Connect)?
    {
        httparse::Status::Complete(_) => {}
        httparse::Status::Partial => return Err(TransportFailure::Connect),
    }
    if response.code != Some(101) {
        return Err(TransportFailure::Connect);
    }
    let mut upgrade = false;
    let mut connection = false;
    let mut accept = None;
    for header in response.headers {
        if header.name.eq_ignore_ascii_case("Upgrade") {
            upgrade = header.value.eq_ignore_ascii_case(b"websocket");
        } else if header.name.eq_ignore_ascii_case("Connection") {
            connection = header
                .value
                .split(|byte| *byte == b',')
                .any(|token| trim_ascii(token).eq_ignore_ascii_case(b"upgrade"));
        } else if header.name.eq_ignore_ascii_case("Sec-WebSocket-Accept") {
            accept = Some(trim_ascii(header.value));
        } else if header.name.eq_ignore_ascii_case("Sec-WebSocket-Extensions")
            && !trim_ascii(header.value).is_empty()
        {
            return Err(TransportFailure::UnsupportedExtension);
        }
    }
    let mut digest = Sha1::new();
    digest.update(key.as_bytes());
    digest.update(WEBSOCKET_GUID);
    let expected = STANDARD.encode(digest.finalize());
    if !upgrade || !connection || accept != Some(expected.as_bytes()) {
        return Err(TransportFailure::Connect);
    }
    Ok(())
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

async fn connect_tls(
    host: &str,
    tcp: TcpStream,
) -> Result<tokio_rustls::client::TlsStream<TcpStream>, TransportFailure> {
    let loaded = rustls_native_certs::load_native_certs();
    if loaded.certs.is_empty() {
        return Err(TransportFailure::Connect);
    }
    let mut roots = RootCertStore::empty();
    let (added, _) = roots.add_parsable_certificates(loaded.certs);
    if added == 0 {
        return Err(TransportFailure::Connect);
    }
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let config = ClientConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .map_err(|_| TransportFailure::Connect)?
        .with_root_certificates(roots)
        .with_no_client_auth();
    let server_name =
        ServerName::try_from(host.to_owned()).map_err(|_| TransportFailure::Connect)?;
    TlsConnector::from(Arc::new(config))
        .connect(server_name, tcp)
        .await
        .map_err(|_| TransportFailure::Connect)
}

pub(crate) struct MessageReader {
    fragmented_text: Option<Vec<u8>>,
}

impl MessageReader {
    pub(crate) const fn new() -> Self {
        Self {
            fragmented_text: None,
        }
    }

    pub(crate) async fn read_text(
        &mut self,
        socket: &mut GatewaySocket,
        limit: usize,
    ) -> Result<Vec<u8>, WireFailure> {
        loop {
            let remaining =
                limit.saturating_sub(self.fragmented_text.as_ref().map_or(0, std::vec::Vec::len));
            socket.set_max_message_size(remaining.saturating_add(1));
            let frame = socket
                .read_frame()
                .await
                .map_err(|error| map_read_error(error, limit))?;
            if let Some(inbound) = self.consume(frame, limit)? {
                match inbound {
                    Inbound::Text(bytes) => return Ok(bytes),
                    Inbound::Close => {
                        return Err(WireFailure::Transport(TransportFailure::Closed));
                    }
                    Inbound::Ping(_) | Inbound::Pong => {}
                }
            }
        }
    }

    pub(crate) async fn read_split(
        &mut self,
        socket: &mut GatewayReadHalf,
        limit: usize,
    ) -> Result<Inbound, WireFailure> {
        loop {
            let remaining =
                limit.saturating_sub(self.fragmented_text.as_ref().map_or(0, std::vec::Vec::len));
            socket.set_max_message_size(remaining.saturating_add(1));
            let frame = socket
                .read_frame(&mut |_| async { Ok::<(), std::io::Error>(()) })
                .await
                .map_err(|error| map_read_error(error, limit))?;
            if let Some(inbound) = self.consume(frame, limit)? {
                return Ok(inbound);
            }
        }
    }

    fn consume(&mut self, frame: Frame<'_>, limit: usize) -> Result<Option<Inbound>, WireFailure> {
        match frame.opcode {
            OpCode::Text if self.fragmented_text.is_none() && frame.fin => {
                validate_utf8(Vec::from(frame.payload))
                    .map(Inbound::Text)
                    .map(Some)
            }
            OpCode::Text if self.fragmented_text.is_none() => {
                self.fragmented_text = Some(Vec::from(frame.payload));
                Ok(None)
            }
            OpCode::Continuation if self.fragmented_text.is_some() => {
                let payload = frame.payload;
                let fragments = self
                    .fragmented_text
                    .as_mut()
                    .expect("checked fragmented state");
                if payload.len() > limit.saturating_sub(fragments.len()) {
                    return Err(WireFailure::Protocol(
                        ProtocolFailure::InboundMessageTooLarge { limit },
                    ));
                }
                fragments.extend_from_slice(&payload);
                if frame.fin {
                    let complete = self
                        .fragmented_text
                        .take()
                        .expect("checked fragmented state");
                    validate_utf8(complete).map(Inbound::Text).map(Some)
                } else {
                    Ok(None)
                }
            }
            OpCode::Binary => {
                self.fragmented_text = None;
                Err(WireFailure::Protocol(ProtocolFailure::BinaryMessage))
            }
            OpCode::Close => {
                self.fragmented_text = None;
                Ok(Some(Inbound::Close))
            }
            OpCode::Ping => Ok(Some(Inbound::Ping(Vec::from(frame.payload)))),
            OpCode::Pong => Ok(Some(Inbound::Pong)),
            OpCode::Continuation | OpCode::Text => {
                self.fragmented_text = None;
                Err(WireFailure::Protocol(ProtocolFailure::InvalidFragmentation))
            }
        }
    }
}

fn map_read_error(error: WebSocketError, limit: usize) -> WireFailure {
    match error {
        WebSocketError::FrameTooLarge => {
            WireFailure::Protocol(ProtocolFailure::InboundMessageTooLarge { limit })
        }
        WebSocketError::ConnectionClosed | WebSocketError::UnexpectedEOF => {
            WireFailure::Transport(TransportFailure::Closed)
        }
        WebSocketError::IoError(_) => WireFailure::Transport(TransportFailure::Read),
        WebSocketError::InvalidFragment => {
            WireFailure::Protocol(ProtocolFailure::WebSocketProtocol("invalid fragment"))
        }
        WebSocketError::InvalidUTF8 => {
            WireFailure::Protocol(ProtocolFailure::WebSocketProtocol("invalid UTF-8"))
        }
        WebSocketError::InvalidContinuationFrame => WireFailure::Protocol(
            ProtocolFailure::WebSocketProtocol("invalid continuation frame"),
        ),
        WebSocketError::InvalidCloseFrame => {
            WireFailure::Protocol(ProtocolFailure::WebSocketProtocol("invalid close frame"))
        }
        WebSocketError::InvalidCloseCode => {
            WireFailure::Protocol(ProtocolFailure::WebSocketProtocol("invalid close code"))
        }
        WebSocketError::ReservedBitsNotZero => WireFailure::Protocol(
            ProtocolFailure::WebSocketProtocol("reserved bits are not zero"),
        ),
        WebSocketError::ControlFrameFragmented => WireFailure::Protocol(
            ProtocolFailure::WebSocketProtocol("fragmented control frame"),
        ),
        WebSocketError::PingFrameTooLarge => {
            WireFailure::Protocol(ProtocolFailure::WebSocketProtocol("oversized ping frame"))
        }
        WebSocketError::InvalidValue => {
            WireFailure::Protocol(ProtocolFailure::WebSocketProtocol("invalid opcode"))
        }
        _ => WireFailure::Protocol(ProtocolFailure::WebSocketProtocol(
            "unexpected framing failure",
        )),
    }
}

fn validate_utf8(bytes: Vec<u8>) -> Result<Vec<u8>, WireFailure> {
    if std::str::from_utf8(&bytes).is_ok() {
        Ok(bytes)
    } else {
        Err(WireFailure::Protocol(ProtocolFailure::InvalidUtf8))
    }
}

pub(crate) async fn write_text(
    socket: &mut GatewaySocket,
    bytes: Vec<u8>,
) -> Result<(), TransportFailure> {
    socket
        .write_frame(Frame::text(Payload::Owned(bytes)))
        .await
        .map_err(|_| TransportFailure::Write)?;
    socket.flush().await.map_err(|_| TransportFailure::Write)
}

pub(crate) fn split(mut socket: GatewaySocket) -> (GatewayReadHalf, GatewayWriteHalf) {
    socket.set_auto_close(false);
    socket.set_auto_pong(false);
    socket.split(tokio::io::split)
}

pub(crate) async fn write_text_split(
    socket: &mut GatewayWriteHalf,
    bytes: Vec<u8>,
) -> Result<(), TransportFailure> {
    socket
        .write_frame(Frame::text(Payload::Owned(bytes)))
        .await
        .map_err(|_| TransportFailure::Write)?;
    socket.flush().await.map_err(|_| TransportFailure::Write)
}

pub(crate) async fn write_pong(
    socket: &mut GatewayWriteHalf,
    bytes: Vec<u8>,
) -> Result<(), TransportFailure> {
    socket
        .write_frame(Frame::pong(Payload::Owned(bytes)))
        .await
        .map_err(|_| TransportFailure::Write)?;
    socket.flush().await.map_err(|_| TransportFailure::Write)
}

pub(crate) async fn close_split(socket: &mut GatewayWriteHalf) -> Result<(), TransportFailure> {
    socket
        .write_frame(Frame::close(1000, b"client shutdown"))
        .await
        .map_err(|_| TransportFailure::Write)?;
    socket.flush().await.map_err(|_| TransportFailure::Write)
}

pub(crate) async fn close(socket: &mut GatewaySocket) -> Result<(), TransportFailure> {
    socket
        .write_frame(Frame::close(1000, b"client shutdown"))
        .await
        .map_err(|_| TransportFailure::Write)?;
    socket.flush().await.map_err(|_| TransportFailure::Write)?;
    loop {
        match socket.read_frame().await {
            Ok(frame) if frame.opcode == OpCode::Close => return Ok(()),
            Ok(_) => {}
            Err(WebSocketError::ConnectionClosed | WebSocketError::UnexpectedEOF) => return Ok(()),
            Err(_) => return Err(TransportFailure::Read),
        }
    }
}

pub(crate) enum WireFailure {
    Transport(TransportFailure),
    Protocol(ProtocolFailure),
}

pub(crate) enum Inbound {
    Text(Vec<u8>),
    Ping(Vec<u8>),
    Pong,
    Close,
}

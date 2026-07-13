use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::task::{Context, Poll};
use std::time::Duration;

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD;
use claw_protocol::gateway::{Codec, ConnectParams, Frame as GatewayFrame, RequestFrame};
use fastwebsockets::{Frame, Payload, Role, WebSocket};
use sha1::{Digest, Sha1};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf};
use tokio::net::{TcpListener, TcpStream};
use tokio_util::sync::CancellationToken;
use tokio_util::task::TaskTracker;
use url::Url;

const WEBSOCKET_GUID: &[u8] = b"258EAFA5-E914-47DA-95CA-C5AB0DC85B11";

pub(crate) type TestSocket = WebSocket<ReplayStream<TcpStream>>;
type HandlerFuture = Pin<Box<dyn Future<Output = ()> + Send>>;
pub(crate) type ConnectionHandler = Arc<dyn Fn(TestSocket, usize) -> HandlerFuture + Send + Sync>;

pub(crate) struct ReplayStream<S> {
    prefix: Vec<u8>,
    offset: usize,
    inner: S,
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

pub(crate) fn handler<F, Fut>(handler: F) -> ConnectionHandler
where
    F: Fn(TestSocket, usize) -> Fut + Send + Sync + 'static,
    Fut: Future<Output = ()> + Send + 'static,
{
    Arc::new(move |socket, index| Box::pin(handler(socket, index)))
}

pub(crate) struct TestGateway {
    pub(crate) url: Url,
    pub(crate) connections: Arc<AtomicUsize>,
    cancellation: CancellationToken,
    tasks: TaskTracker,
}

impl TestGateway {
    pub(crate) async fn spawn(handler: ConnectionHandler) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
        let address = listener.local_addr().expect("address");
        let cancellation = CancellationToken::new();
        let tasks = TaskTracker::new();
        let connections = Arc::new(AtomicUsize::new(0));
        let accept_cancellation = cancellation.clone();
        let accept_tasks = tasks.clone();
        let accept_connections = Arc::clone(&connections);
        tasks.spawn(async move {
            loop {
                let accepted = tokio::select! {
                    () = accept_cancellation.cancelled() => break,
                    result = listener.accept() => result,
                };
                let Ok((stream, _)) = accepted else {
                    break;
                };
                let index = accept_connections.fetch_add(1, Ordering::SeqCst);
                let handler = Arc::clone(&handler);
                accept_tasks.spawn(async move {
                    let socket = server_handshake(stream).await;
                    handler(socket, index).await;
                });
            }
        });
        Self {
            url: Url::parse(&format!("ws://{address}")).expect("url"),
            connections,
            cancellation,
            tasks,
        }
    }

    pub(crate) async fn shutdown(self) {
        self.cancellation.cancel();
        self.tasks.close();
        tokio::time::timeout(Duration::from_secs(3), self.tasks.wait())
            .await
            .expect("server shutdown");
    }
}

async fn server_handshake(mut stream: TcpStream) -> TestSocket {
    let mut received = Vec::with_capacity(1024);
    let header_end = loop {
        if let Some(index) = received.windows(4).position(|window| window == b"\r\n\r\n") {
            break index + 4;
        }
        assert!(received.len() < 16 * 1024, "bounded request headers");
        let mut chunk = [0_u8; 1024];
        let count = stream.read(&mut chunk).await.expect("read handshake");
        assert!(count > 0, "handshake EOF");
        received.extend_from_slice(&chunk[..count]);
    };
    let mut headers = [httparse::EMPTY_HEADER; 32];
    let mut request = httparse::Request::new(&mut headers);
    assert!(
        request
            .parse(&received[..header_end])
            .expect("parse")
            .is_complete()
    );
    let key = request
        .headers
        .iter()
        .find(|header| header.name.eq_ignore_ascii_case("Sec-WebSocket-Key"))
        .map(|header| header.value)
        .expect("websocket key");
    let mut digest = Sha1::new();
    digest.update(key);
    digest.update(WEBSOCKET_GUID);
    let accept = STANDARD.encode(digest.finalize());
    let response = format!(
        "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: {accept}\r\n\r\n"
    );
    stream
        .write_all(response.as_bytes())
        .await
        .expect("write handshake");
    stream.flush().await.expect("flush handshake");
    let prefix = received.split_off(header_end);
    WebSocket::after_handshake(
        ReplayStream {
            prefix,
            offset: 0,
            inner: stream,
        },
        Role::Server,
    )
}

pub(crate) async fn send_json(socket: &mut TestSocket, value: serde_json::Value) {
    let bytes = serde_json::to_vec(&value).expect("json");
    socket
        .write_frame(Frame::text(Payload::Owned(bytes)))
        .await
        .expect("send");
    socket.flush().await.expect("flush");
}

async fn receive_text(socket: &mut TestSocket) -> Vec<u8> {
    loop {
        let frame = socket.read_frame().await.expect("read");
        match frame.opcode {
            fastwebsockets::OpCode::Text => return Vec::from(frame.payload),
            fastwebsockets::OpCode::Close => panic!("unexpected close"),
            _ => {}
        }
    }
}

pub(crate) async fn send_challenge(socket: &mut TestSocket) {
    send_json(
        socket,
        serde_json::json!({
            "type": "event",
            "event": "connect.challenge",
            "payload": {"nonce": "desktop-test-nonce", "ts": 1_700_000_000_000_u64}
        }),
    )
    .await;
}

pub(crate) async fn receive_connect(socket: &mut TestSocket) -> (RequestFrame, ConnectParams) {
    let bytes = receive_text(socket).await;
    let codec = Codec::preauthentication();
    let request = match codec.decode(&bytes).expect("connect frame") {
        GatewayFrame::Request(request) => request,
        _ => panic!("expected connect request"),
    };
    let params = codec.decode_connect(&request).expect("connect params");
    (request, params)
}

pub(crate) async fn send_hello(
    socket: &mut TestSocket,
    request: &RequestFrame,
    params: &ConnectParams,
    protocol: u64,
    connection_id: &str,
    issue_device_token: bool,
) {
    let role = params
        .role
        .as_ref()
        .map_or("operator", |role| role.as_str());
    let scopes = params.scopes.as_ref().map_or_else(Vec::new, |scopes| {
        scopes
            .iter()
            .map(|scope| scope.as_str())
            .collect::<Vec<_>>()
    });
    let auth = if issue_device_token {
        serde_json::json!({
            "role": role,
            "scopes": scopes,
            "deviceToken": "issued-device-secret",
            "issuedAtMs": 1_700_000_000_001_u64
        })
    } else {
        serde_json::json!({"role": role, "scopes": scopes})
    };
    send_json(
        socket,
        serde_json::json!({
            "type": "res",
            "id": request.id().as_str(),
            "ok": true,
            "payload": {
                "type": "hello-ok",
                "protocol": protocol,
                "server": {
                    "version": "desktop-test-gateway",
                    "connId": connection_id
                },
                "features": {
                    "methods": ["health"],
                    "events": ["connect.challenge", "tick"]
                },
                "snapshot": {
                    "presence": [],
                    "health": {},
                    "stateVersion": {"presence": 0, "health": 0},
                    "uptimeMs": 1,
                    "authMode": "token"
                },
                "auth": auth,
                "policy": {
                    "maxPayload": 65536,
                    "maxBufferedBytes": 65536,
                    "tickIntervalMs": 60000
                }
            }
        }),
    )
    .await;
}

pub(crate) async fn receive_request(socket: &mut TestSocket) -> RequestFrame {
    let bytes = receive_text(socket).await;
    match Codec::authenticated()
        .decode(&bytes)
        .expect("authenticated request")
    {
        GatewayFrame::Request(request) => request,
        _ => panic!("expected request"),
    }
}

pub(crate) async fn send_health(socket: &mut TestSocket, request: &RequestFrame) {
    send_json(
        socket,
        serde_json::json!({
            "type": "res",
            "id": request.id().as_str(),
            "ok": true,
            "payload": {
                "status": "ok",
                "secretServerField": "must-never-render"
            }
        }),
    )
    .await;
}

pub(crate) async fn send_connect_error(
    socket: &mut TestSocket,
    request: &RequestFrame,
    code: &str,
) {
    send_json(
        socket,
        serde_json::json!({
            "type": "res",
            "id": request.id().as_str(),
            "ok": false,
            "error": {
                "code": "INVALID_REQUEST",
                "message": "raw server detail must not render",
                "details": {"code": code}
            }
        }),
    )
    .await;
}

pub(crate) async fn wait_for_close(socket: &mut TestSocket) {
    loop {
        match socket.read_frame().await {
            Ok(frame) if frame.opcode == fastwebsockets::OpCode::Close => {
                let _ = socket
                    .write_frame(Frame::close(1000, b"server acknowledgement"))
                    .await;
                let _ = socket.flush().await;
                return;
            }
            Ok(_) => {}
            Err(_) => return,
        }
    }
}

use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::task::{Context, Poll};
use std::time::Duration;

use base64::Engine as _;
use base64::engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD};
use claw_protocol::gateway::{
    Codec, ConnectParams, Frame as GatewayFrame, RequestFrame, RequestId,
};
use claw_security::authorization::{Role, Scope, ScopeSet};
use claw_security::identity::{DevicePublicKey, DeviceSignature, GatewayDeviceSigningInput};
use fastwebsockets::{Frame, Payload, Role as WebSocketRole, WebSocket};
use secrecy::SecretString;
use serde_json::{Value, json};
use sha1::{Digest, Sha1};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf};
use tokio::net::{TcpListener, TcpStream};
use tokio_util::sync::CancellationToken;
use tokio_util::task::TaskTracker;
use url::Url;

const WEBSOCKET_GUID: &[u8] = b"258EAFA5-E914-47DA-95CA-C5AB0DC85B11";

pub(crate) type TestSocket = WebSocket<ReplayStream<TcpStream>>;
pub(crate) type HandlerFuture = Pin<Box<dyn Future<Output = ()> + Send>>;
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
        Self::spawn_with_extensions(handler, false).await
    }

    pub(crate) async fn spawn_with_extensions(
        handler: ConnectionHandler,
        advertise_compression: bool,
    ) -> Self {
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
                    let socket = Self::server_handshake(stream, advertise_compression).await;
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

    async fn server_handshake(mut stream: TcpStream, advertise_compression: bool) -> TestSocket {
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
        let extension = if advertise_compression {
            "Sec-WebSocket-Extensions: permessage-deflate\r\n"
        } else {
            ""
        };
        let response = format!(
            "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: {accept}\r\n{extension}\r\n"
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
            WebSocketRole::Server,
        )
    }

    pub(crate) async fn shutdown(self) {
        self.cancellation.cancel();
        self.tasks.close();
        tokio::time::timeout(Duration::from_secs(3), self.tasks.wait())
            .await
            .expect("test server shutdown");
    }
}

pub(crate) async fn raw_stalled_server() -> (Url, CancellationToken, TaskTracker) {
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let address = listener.local_addr().expect("address");
    let cancellation = CancellationToken::new();
    let tasks = TaskTracker::new();
    let task_cancellation = cancellation.clone();
    tasks.spawn(async move {
        if let Ok((stream, _)) = listener.accept().await {
            tokio::select! {
                () = task_cancellation.cancelled() => {}
                () = hold_stream(stream) => {}
            }
        }
    });
    (
        Url::parse(&format!("ws://{address}")).expect("url"),
        cancellation,
        tasks,
    )
}

async fn hold_stream(_stream: TcpStream) {
    std::future::pending::<()>().await;
}

pub(crate) async fn send_json(socket: &mut TestSocket, value: Value) {
    let bytes = serde_json::to_vec(&value).expect("json");
    socket
        .write_frame(Frame::text(Payload::Owned(bytes)))
        .await
        .expect("send json");
    socket.flush().await.expect("flush");
}

pub(crate) async fn send_raw_text(socket: &mut TestSocket, bytes: Vec<u8>) {
    socket
        .write_frame(Frame::text(Payload::Owned(bytes)))
        .await
        .expect("send raw");
    socket.flush().await.expect("flush");
}

pub(crate) async fn receive_text(socket: &mut TestSocket) -> Vec<u8> {
    loop {
        let frame = socket.read_frame().await.expect("read frame");
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
        json!({
            "type": "event",
            "event": "connect.challenge",
            "payload": {"nonce": "test-nonce", "ts": 1_700_000_000_000_u64}
        }),
    )
    .await;
}

pub(crate) async fn receive_connect(socket: &mut TestSocket) -> (RequestFrame, ConnectParams) {
    let bytes = receive_text(socket).await;
    let codec = Codec::preauthentication();
    let request = match codec.decode(&bytes).expect("strict connect frame") {
        GatewayFrame::Request(request) => request,
        _ => panic!("expected request"),
    };
    let params = codec.decode_connect(&request).expect("connect params");
    (request, params)
}

pub(crate) async fn receive_request(socket: &mut TestSocket) -> RequestFrame {
    let bytes = receive_text(socket).await;
    match Codec::authenticated()
        .decode(&bytes)
        .expect("strict request")
    {
        GatewayFrame::Request(request) => request,
        _ => panic!("expected request"),
    }
}

pub(crate) fn verify_connect_proof(params: &ConnectParams) {
    let proof = params.device.as_ref().expect("device proof");
    let public_bytes = URL_SAFE_NO_PAD
        .decode(proof.public_key.as_str())
        .expect("public key base64url");
    let public = DevicePublicKey::decode(&public_bytes).expect("public key");
    assert_eq!(proof.id.as_str(), public.device_id().gateway_wire_id());
    let signature_bytes = URL_SAFE_NO_PAD
        .decode(proof.signature.as_str())
        .expect("signature base64url");
    let signature = DeviceSignature::decode(&signature_bytes).expect("signature");
    let role = Role::parse(params.role.as_ref().expect("role").as_str()).expect("closed role");
    let scopes = ScopeSet::from_scopes(
        params
            .scopes
            .as_ref()
            .expect("scopes")
            .iter()
            .map(|scope| Scope::parse(scope.as_str()).expect("closed scope")),
    );
    let token = params.auth.as_ref().and_then(|auth| {
        auth.token
            .as_ref()
            .or(auth.bootstrap_token.as_ref())
            .map(|value| SecretString::from(value.clone()))
    });
    public
        .verify_gateway_device(
            GatewayDeviceSigningInput {
                client_id: params.client.id.as_str(),
                client_mode: params.client.mode.as_str(),
                role,
                scopes,
                signed_at_unix_millis: proof.signed_at.get(),
                token: token.as_ref(),
                nonce: proof.nonce.as_str(),
                platform: params.client.platform.as_str(),
                device_family: params
                    .client
                    .device_family
                    .as_ref()
                    .map(|name| name.as_str()),
            },
            &signature,
        )
        .expect("valid pinned Gateway proof");
}

pub(crate) async fn complete_handshake(
    socket: &mut TestSocket,
    max_payload: usize,
) -> (RequestFrame, ConnectParams) {
    send_challenge(socket).await;
    let (request, params) = receive_connect(socket).await;
    verify_connect_proof(&params);
    send_hello(socket, request.id(), &params, max_payload).await;
    (request, params)
}

pub(crate) async fn send_hello(
    socket: &mut TestSocket,
    id: &RequestId,
    params: &ConnectParams,
    max_payload: usize,
) {
    send_hello_with_policy(socket, id, params, max_payload, None, 1000).await;
}

pub(crate) async fn send_hello_with_device_token(
    socket: &mut TestSocket,
    id: &RequestId,
    params: &ConnectParams,
    max_payload: usize,
    device_token: Option<&str>,
) {
    send_hello_with_policy(socket, id, params, max_payload, device_token, 1000).await;
}

pub(crate) async fn send_hello_with_tick_interval(
    socket: &mut TestSocket,
    id: &RequestId,
    params: &ConnectParams,
    max_payload: usize,
    tick_interval_ms: u64,
) {
    send_hello_with_policy(socket, id, params, max_payload, None, tick_interval_ms).await;
}

async fn send_hello_with_policy(
    socket: &mut TestSocket,
    id: &RequestId,
    params: &ConnectParams,
    max_payload: usize,
    device_token: Option<&str>,
    tick_interval_ms: u64,
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
    let auth = match device_token {
        Some(device_token) => json!({
            "role": role,
            "scopes": scopes,
            "deviceToken": device_token,
            "issuedAtMs": 1_700_000_000_001_u64,
            "deviceTokens": [{
                "deviceToken": "secondary-device-token",
                "role": "node",
                "scopes": [],
                "issuedAtMs": 1_700_000_000_002_u64
            }]
        }),
        None => json!({"role": role, "scopes": scopes}),
    };
    send_json(
        socket,
        json!({
            "type": "res",
            "id": id.as_str(),
            "ok": true,
            "payload": {
                "type": "hello-ok",
                "protocol": 4,
                "server": {"version": "test-gateway", "connId": "test-connection"},
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
                    "maxPayload": max_payload,
                    "maxBufferedBytes": max_payload,
                    "tickIntervalMs": tick_interval_ms
                }
            }
        }),
    )
    .await;
}

pub(crate) async fn send_connect_error(socket: &mut TestSocket, id: &RequestId, detail_code: &str) {
    send_json(
        socket,
        json!({
            "type": "res",
            "id": id.as_str(),
            "ok": false,
            "error": {
                "code": "INVALID_REQUEST",
                "message": "connection rejected",
                "details": {"code": detail_code}
            }
        }),
    )
    .await;
}

pub(crate) async fn send_response(socket: &mut TestSocket, id: &str, marker: u64) {
    send_json(
        socket,
        json!({
            "type": "res",
            "id": id,
            "ok": true,
            "payload": {"marker": marker}
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

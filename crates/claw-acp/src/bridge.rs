//! ACP stdio server bridge backed by GTA-Claw application ports.

use std::{future::Future, pin::Pin, sync::Arc, time::Duration};

use serde::Serialize;
use serde_json::Value;
use tokio::{
    io::{AsyncRead, AsyncWrite, BufReader},
    sync::{Semaphore, mpsc},
    task::JoinSet,
    time::timeout,
};

use crate::{
    Error, Result,
    protocol::{RpcPeer, decode, is_response_message, message_parts, read_message, response_id},
    schema::{
        AgentCapabilities, CancelNotification, CloseSessionRequest, CloseSessionResponse,
        Implementation, InitializeRequest, InitializeResponse, ListSessionsRequest,
        ListSessionsResponse, LoadSessionRequest, LoadSessionResponse, NewSessionRequest,
        NewSessionResponse, PromptRequest, PromptResponse, ProtocolVersion,
        RequestPermissionRequest, RequestPermissionResponse, ResumeSessionRequest,
        ResumeSessionResponse, SessionId, SessionNotification, SessionUpdate,
        SetSessionConfigOptionRequest, SetSessionConfigOptionResponse, SetSessionModeRequest,
        SetSessionModeResponse,
    },
};

const MAX_IN_FLIGHT_REQUESTS: usize = 64;
const MAX_IN_FLIGHT_CANCELLATIONS: usize = 8;
const INCOMING_QUEUE_CAPACITY: usize = 64;
const DISCONNECT_DRAIN_TIMEOUT: Duration = Duration::from_secs(1);

/// Future returned by an ACP backend operation.
pub type AcpFuture<'a, T> =
    Pin<Box<dyn Future<Output = std::result::Result<T, Error>> + Send + 'a>>;

/// Request context used for streaming and permission callbacks.
#[derive(Clone)]
pub struct AcpSessionContext {
    connection: RpcPeer,
}

impl std::fmt::Debug for AcpSessionContext {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("AcpSessionContext")
            .finish_non_exhaustive()
    }
}

impl AcpSessionContext {
    /// Streams one session update to the connected ACP client.
    pub async fn notify(
        &self,
        session_id: impl Into<SessionId>,
        update: SessionUpdate,
    ) -> std::result::Result<(), Error> {
        self.connection
            .notify(
                "session/update",
                SessionNotification::new(session_id, update),
            )
            .await
    }

    /// Requests an explicit permission decision from the ACP client.
    pub async fn request_permission(
        &self,
        request: RequestPermissionRequest,
    ) -> std::result::Result<RequestPermissionResponse, Error> {
        self.connection
            .request("session/request_permission", request)
            .await
    }
}

/// GTA-Claw application port implemented by the ACP server bridge.
pub trait AcpBackend: Send + Sync + 'static {
    /// Creates a new ACP session.
    fn new_session<'a>(
        &'a self,
        request: NewSessionRequest,
        context: AcpSessionContext,
    ) -> AcpFuture<'a, NewSessionResponse>;
    /// Loads an existing ACP session and replays its history through notifications.
    fn load_session<'a>(
        &'a self,
        request: LoadSessionRequest,
        context: AcpSessionContext,
    ) -> AcpFuture<'a, LoadSessionResponse>;
    /// Resumes an existing ACP session.
    fn resume_session<'a>(
        &'a self,
        request: ResumeSessionRequest,
        context: AcpSessionContext,
    ) -> AcpFuture<'a, ResumeSessionResponse>;
    /// Lists persistent ACP sessions.
    fn list_sessions<'a>(
        &'a self,
        request: ListSessionsRequest,
    ) -> AcpFuture<'a, ListSessionsResponse>;
    /// Closes a session and releases its resources.
    fn close_session<'a>(
        &'a self,
        request: CloseSessionRequest,
    ) -> AcpFuture<'a, CloseSessionResponse>;
    /// Processes one prompt turn and streams intermediate updates.
    fn prompt<'a>(
        &'a self,
        request: PromptRequest,
        context: AcpSessionContext,
    ) -> AcpFuture<'a, PromptResponse>;
    /// Changes the active mode for one session.
    fn set_mode<'a>(
        &'a self,
        request: SetSessionModeRequest,
    ) -> AcpFuture<'a, SetSessionModeResponse>;
    /// Changes one session configuration option.
    fn set_config_option<'a>(
        &'a self,
        request: SetSessionConfigOptionRequest,
    ) -> AcpFuture<'a, SetSessionConfigOptionResponse>;
    /// Cancels active work in one session.
    fn cancel<'a>(&'a self, notification: CancelNotification) -> AcpFuture<'a, ()>;
}

/// ACP agent bridge serving GTA-Claw sessions over stdio.
pub struct AcpBridge {
    backend: Arc<dyn AcpBackend>,
    capabilities: AgentCapabilities,
}

impl std::fmt::Debug for AcpBridge {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("AcpBridge")
            .field("capabilities", &self.capabilities)
            .finish_non_exhaustive()
    }
}

impl AcpBridge {
    /// Creates an ACP bridge with explicitly advertised capabilities.
    #[must_use]
    pub fn new(backend: Arc<dyn AcpBackend>, capabilities: AgentCapabilities) -> Self {
        Self {
            backend,
            capabilities,
        }
    }

    /// Serves the ACP bridge over process stdio until the client disconnects.
    pub async fn serve_stdio(self) -> Result<()> {
        self.serve(tokio::io::stdin(), tokio::io::stdout()).await
    }

    async fn serve(
        self,
        input: impl AsyncRead + Send + Unpin + 'static,
        output: impl AsyncWrite + Send + Unpin + 'static,
    ) -> Result<()> {
        let peer = RpcPeer::new(output);
        let (incoming_sender, mut incoming) = mpsc::channel(INCOMING_QUEUE_CAPACITY);
        let reader = tokio::spawn(async move {
            let mut reader = BufReader::new(input);
            let mut frame = Vec::new();
            loop {
                match read_message(&mut reader, &mut frame).await {
                    Ok(Some(message)) => {
                        if incoming_sender.send(Ok(message)).await.is_err() {
                            return;
                        }
                    }
                    Ok(None) => return,
                    Err(error) => {
                        let _ = incoming_sender.send(Err(error)).await;
                        return;
                    }
                }
            }
        });
        let request_slots = Arc::new(Semaphore::new(MAX_IN_FLIGHT_REQUESTS));
        let cancellation_slots = Arc::new(Semaphore::new(MAX_IN_FLIGHT_CANCELLATIONS));
        let mut tasks = JoinSet::new();
        let terminal_error = loop {
            let message = tokio::select! {
                biased;
                () = peer.disconnected() => break None,
                message = incoming.recv() => message,
                completed = tasks.join_next(), if !tasks.is_empty() => {
                    if let Some(Err(error)) = completed {
                        break Some(Error::internal_error().data(error.to_string()));
                    }
                    continue;
                }
            };
            if !peer.is_connected() {
                break None;
            }
            let message = match message {
                Some(Ok(message)) => message,
                None => break None,
                Some(Err(error)) => {
                    let _ = peer.respond::<Value>(Value::Null, Err(error.clone())).await;
                    break Some(error);
                }
            };
            if message.get("method").is_none() {
                if is_response_message(&message) {
                    let _ = peer.resolve_response(&message);
                } else {
                    let _ = peer
                        .respond::<Value>(response_id(&message), Err(Error::invalid_request()))
                        .await;
                }
                continue;
            }
            let (method, params, id) = match message_parts(&message) {
                Ok(parts) => parts,
                Err(error) => {
                    let _ = peer
                        .respond::<Value>(response_id(&message), Err(error))
                        .await;
                    continue;
                }
            };
            if let Some(id) = id {
                let Ok(permit) = Arc::clone(&request_slots).try_acquire_owned() else {
                    let _ = peer
                        .respond::<Value>(
                            id,
                            Err(Error::server_error(
                                -32099,
                                "Too many in-flight ACP requests",
                            )),
                        )
                        .await;
                    continue;
                };
                let backend = Arc::clone(&self.backend);
                let capabilities = self.capabilities.clone();
                let peer = peer.clone();
                let method = method.to_owned();
                tasks.spawn(async move {
                    let _permit = permit;
                    dispatch_request(backend, capabilities, peer, method, params, id).await;
                });
            } else if method == "session/cancel" {
                let notification = match decode(params) {
                    Ok(notification) => notification,
                    Err(_) => continue,
                };
                let Ok(permit) = Arc::clone(&cancellation_slots).try_acquire_owned() else {
                    continue;
                };
                let backend = Arc::clone(&self.backend);
                tasks.spawn(async move {
                    let _permit = permit;
                    let _ = backend.cancel(notification).await;
                });
            }
        };
        peer.mark_disconnected();
        if !reader.is_finished() {
            reader.abort();
        }
        let _ = reader.await;
        if timeout(DISCONNECT_DRAIN_TIMEOUT, async {
            while tasks.join_next().await.is_some() {}
        })
        .await
        .is_err()
        {
            tasks.abort_all();
            while tasks.join_next().await.is_some() {}
        }
        match terminal_error {
            Some(error) => Err(error.into()),
            None => Ok(()),
        }
    }
}

async fn dispatch_request(
    backend: Arc<dyn AcpBackend>,
    capabilities: AgentCapabilities,
    peer: RpcPeer,
    method: String,
    params: Value,
    id: Value,
) {
    match method.as_str() {
        "initialize" => {
            let result = decode::<InitializeRequest>(params).map(|request| {
                InitializeResponse::new(if request.protocol_version == ProtocolVersion::V1 {
                    request.protocol_version
                } else {
                    ProtocolVersion::V1
                })
                .agent_capabilities(capabilities)
                .agent_info(Implementation::new("gta-claw", env!("CARGO_PKG_VERSION")))
            });
            let _ = peer.respond(id, result).await;
        }
        "session/new" => {
            respond(
                &peer,
                id,
                decode(params).map(|request| backend.new_session(request, context(&peer))),
            )
            .await;
        }
        "session/load" => {
            respond(
                &peer,
                id,
                decode(params).map(|request| backend.load_session(request, context(&peer))),
            )
            .await;
        }
        "session/resume" => {
            respond(
                &peer,
                id,
                decode(params).map(|request| backend.resume_session(request, context(&peer))),
            )
            .await;
        }
        "session/list" => {
            respond(
                &peer,
                id,
                decode(params).map(|request| backend.list_sessions(request)),
            )
            .await;
        }
        "session/close" => {
            respond(
                &peer,
                id,
                decode(params).map(|request| backend.close_session(request)),
            )
            .await;
        }
        "session/prompt" => {
            respond(
                &peer,
                id,
                decode(params).map(|request| backend.prompt(request, context(&peer))),
            )
            .await;
        }
        "session/set_mode" => {
            respond(
                &peer,
                id,
                decode(params).map(|request| backend.set_mode(request)),
            )
            .await;
        }
        "session/set_config_option" => {
            respond(
                &peer,
                id,
                decode(params).map(|request| backend.set_config_option(request)),
            )
            .await;
        }
        _ => {
            let _ = peer
                .respond::<Value>(id, Err(Error::method_not_found()))
                .await;
        }
    }
}

fn context(peer: &RpcPeer) -> AcpSessionContext {
    AcpSessionContext {
        connection: peer.clone(),
    }
}

async fn respond<T>(peer: &RpcPeer, id: Value, future: std::result::Result<AcpFuture<'_, T>, Error>)
where
    T: Serialize,
{
    match future {
        Ok(future) => {
            let _ = peer.respond(id, future.await).await;
        }
        Err(error) => {
            let _ = peer.respond::<T>(id, Err(error)).await;
        }
    }
}

#[cfg(test)]
mod tests {
    use std::task::{Context, Poll};

    use tokio::io::{AsyncWriteExt, duplex};

    use super::*;

    #[derive(Debug)]
    struct UnusedBackend;

    impl AcpBackend for UnusedBackend {
        fn new_session<'a>(
            &'a self,
            _request: NewSessionRequest,
            _context: AcpSessionContext,
        ) -> AcpFuture<'a, NewSessionResponse> {
            panic!("backend must not receive a session request")
        }

        fn load_session<'a>(
            &'a self,
            _request: LoadSessionRequest,
            _context: AcpSessionContext,
        ) -> AcpFuture<'a, LoadSessionResponse> {
            panic!("backend must not receive a load request")
        }

        fn resume_session<'a>(
            &'a self,
            _request: ResumeSessionRequest,
            _context: AcpSessionContext,
        ) -> AcpFuture<'a, ResumeSessionResponse> {
            panic!("backend must not receive a resume request")
        }

        fn list_sessions<'a>(
            &'a self,
            _request: ListSessionsRequest,
        ) -> AcpFuture<'a, ListSessionsResponse> {
            panic!("backend must not receive a list request")
        }

        fn close_session<'a>(
            &'a self,
            _request: CloseSessionRequest,
        ) -> AcpFuture<'a, CloseSessionResponse> {
            panic!("backend must not receive a close request")
        }

        fn prompt<'a>(
            &'a self,
            _request: PromptRequest,
            _context: AcpSessionContext,
        ) -> AcpFuture<'a, PromptResponse> {
            panic!("backend must not receive a prompt request")
        }

        fn set_mode<'a>(
            &'a self,
            _request: SetSessionModeRequest,
        ) -> AcpFuture<'a, SetSessionModeResponse> {
            panic!("backend must not receive a mode request")
        }

        fn set_config_option<'a>(
            &'a self,
            _request: SetSessionConfigOptionRequest,
        ) -> AcpFuture<'a, SetSessionConfigOptionResponse> {
            panic!("backend must not receive a configuration request")
        }

        fn cancel<'a>(&'a self, _notification: CancelNotification) -> AcpFuture<'a, ()> {
            panic!("backend must not receive a cancellation")
        }
    }

    #[derive(Debug)]
    struct BrokenWriter;

    impl AsyncWrite for BrokenWriter {
        fn poll_write(
            self: Pin<&mut Self>,
            _context: &mut Context<'_>,
            _bytes: &[u8],
        ) -> Poll<std::io::Result<usize>> {
            Poll::Ready(Err(std::io::Error::new(
                std::io::ErrorKind::BrokenPipe,
                "fixture output is closed",
            )))
        }

        fn poll_flush(
            self: Pin<&mut Self>,
            _context: &mut Context<'_>,
        ) -> Poll<std::io::Result<()>> {
            Poll::Ready(Ok(()))
        }

        fn poll_shutdown(
            self: Pin<&mut Self>,
            _context: &mut Context<'_>,
        ) -> Poll<std::io::Result<()>> {
            Poll::Ready(Ok(()))
        }
    }

    #[tokio::test]
    async fn writer_failure_terminates_dispatch_while_input_remains_open() {
        let (mut client, input) = duplex(1024);
        let bridge = AcpBridge::new(Arc::new(UnusedBackend), AgentCapabilities::new());
        let server = tokio::spawn(bridge.serve(input, BrokenWriter));
        let request = serde_json::to_vec(&serde_json::json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": "initialize",
            "params": InitializeRequest::new(ProtocolVersion::V1),
        }))
        .expect("serialize initialize");
        client.write_all(&request).await.expect("write initialize");
        client.write_all(b"\n").await.expect("frame initialize");
        client.flush().await.expect("flush initialize");

        let result = timeout(Duration::from_secs(1), server)
            .await
            .expect("writer failure must terminate dispatch while input remains open")
            .expect("bridge task must not panic");

        result.expect("writer disconnect is a clean bridge shutdown");
        drop(client);
    }
}
